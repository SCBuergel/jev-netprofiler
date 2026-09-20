"""nfstream capture: one NFStreamer per vif*, one thread each; pcap replay.

eth0 (the upstream link) is never opened. Interfaces are rediscovered every
few seconds so a qube that attaches later gets its own streamer and pane.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Callable

from .config import (
    ACTIVE_TIMEOUT,
    FORBIDDEN_INTERFACES,
    HEARTBEAT_GROUP,
    HEARTBEAT_PORT,
    HEARTBEAT_SECONDS,
    IDLE_TIMEOUT,
    SPLT_ANALYSIS,
    VIF_PREFIX,
    VIF_SCAN_SECONDS,
)
from .flows import FlowSeg, RollingWindow

log = logging.getLogger("netprofiler.capture")

SYS_NET = Path("/sys/class/net")


def discover_vifs(explicit: list[str] | None = None) -> list[str]:
    """Return capturable interfaces. Never eth0, never lo, only vif* unless
    an explicit list is given (which is still filtered)."""
    if explicit:
        names = list(explicit)
    else:
        try:
            names = sorted(p.name for p in SYS_NET.iterdir())
        except FileNotFoundError:
            names = []
        names = [n for n in names if n.startswith(VIF_PREFIX)]
    out = []
    for n in names:
        if n in FORBIDDEN_INTERFACES or n.startswith("eth"):
            log.warning("refusing to capture on %s", n)
            continue
        out.append(n)
    return out


def _streamer_kwargs() -> dict:
    return dict(
        active_timeout=ACTIVE_TIMEOUT,
        idle_timeout=IDLE_TIMEOUT,
        statistical_analysis=True,
        splt_analysis=SPLT_ANALYSIS,
        n_dissections=0,  # no L7 dissection: shape only, and cheaper
        decode_tunnels=False,
        promiscuous_mode=False,
    )


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class Orienter:
    """Decide which side of a flow is the downstream qube ("local").

    nfstream names the first packet's sender `src`; after an active-timeout cut
    the next segment may start with a packet from the other side, flipping
    src2dst/dst2src. We fix the orientation per unordered 5-tuple once, from
    the SYN direction or from which address is private, and reuse it.
    """

    def __init__(self, local_nets: list[str] | None = None) -> None:
        self._local_addr: dict[str, str] = {}  # key -> "ip:port" of the local side
        # explicit downstream networks win over the SYN / private-address heuristics
        self._local_nets = [ipaddress.ip_network(n, strict=False) for n in (local_nets or [])]

    def _in_local_nets(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self._local_nets)

    @staticmethod
    def key(f) -> str:
        a = f"{f.src_ip}:{f.src_port}"
        b = f"{f.dst_ip}:{f.dst_port}"
        lo, hi = sorted((a, b))
        return f"{lo}<>{hi}/{f.protocol}"

    def local_is_src(self, f, key: str) -> bool:
        src = f"{f.src_ip}:{f.src_port}"
        dst = f"{f.dst_ip}:{f.dst_port}"
        syn_s2d = int(getattr(f, "src2dst_syn_packets", 0) or 0)
        syn_d2s = int(getattr(f, "dst2src_syn_packets", 0) or 0)
        ls, ld = self._in_local_nets(f.src_ip), self._in_local_nets(f.dst_ip)
        if ls != ld:
            local = src if ls else dst
        elif syn_s2d and not syn_d2s:
            local = src
        elif syn_d2s and not syn_s2d:
            local = dst
        else:
            cached = self._local_addr.get(key)
            if cached is not None:
                return cached == src
            sp, dp = _is_private(f.src_ip), _is_private(f.dst_ip)
            local = src if (sp and not dp) else dst if (dp and not sp) else src
        if len(self._local_addr) > 50_000:  # bound memory on very busy links
            self._local_addr.clear()
        self._local_addr[key] = local
        return local == src


def is_heartbeat(f) -> bool:
    return f.protocol == 17 and f.dst_port == HEARTBEAT_PORT and f.dst_ip == HEARTBEAT_GROUP


def nflow_to_seg(f, orienter: Orienter | None = None) -> FlowSeg:
    """Project an nfstream NFlow onto the shape-only FlowSeg, oriented so that
    `up` always means the downstream qube sending outwards."""
    orienter = orienter or Orienter()
    key = orienter.key(f)
    local_src = orienter.local_is_src(f, key)
    s2d_piat = (float(getattr(f, "src2dst_mean_piat_ms", 0) or 0.0), float(getattr(f, "src2dst_stddev_piat_ms", 0) or 0.0))
    d2s_piat = (float(getattr(f, "dst2src_mean_piat_ms", 0) or 0.0), float(getattr(f, "dst2src_stddev_piat_ms", 0) or 0.0))
    if local_src:
        up_p, down_p = f.src2dst_packets, f.dst2src_packets
        up_b, down_b = f.src2dst_bytes, f.dst2src_bytes
        up_piat, down_piat = s2d_piat, d2s_piat
        endpoint = f"{f.dst_ip}:{f.dst_port}/{f.protocol}"
        splt_dir = list(f.splt_direction or [])
    else:
        up_p, down_p = f.dst2src_packets, f.src2dst_packets
        up_b, down_b = f.dst2src_bytes, f.src2dst_bytes
        up_piat, down_piat = d2s_piat, s2d_piat
        endpoint = f"{f.src_ip}:{f.src_port}/{f.protocol}"
        splt_dir = [1 - d if d in (0, 1) else d for d in (f.splt_direction or [])]
    return FlowSeg(
        key=key,
        endpoint=endpoint,
        first_ms=int(f.bidirectional_first_seen_ms),
        last_ms=int(f.bidirectional_last_seen_ms),
        up_packets=int(up_p),
        down_packets=int(down_p),
        up_bytes=int(up_b),
        down_bytes=int(down_b),
        mean_ps=float(f.bidirectional_mean_ps or 0.0),
        stddev_ps=float(f.bidirectional_stddev_ps or 0.0),
        min_ps=int(f.bidirectional_min_ps or 0),
        max_ps=int(f.bidirectional_max_ps or 0),
        mean_piat_ms=float(f.bidirectional_mean_piat_ms or 0.0),
        stddev_piat_ms=float(f.bidirectional_stddev_piat_ms or 0.0),
        max_piat_ms=float(f.bidirectional_max_piat_ms or 0.0),
        up_mean_piat_ms=up_piat[0],
        up_stddev_piat_ms=up_piat[1],
        down_mean_piat_ms=down_piat[0],
        down_stddev_piat_ms=down_piat[1],
        protocol=int(f.protocol),
        syn=int(f.bidirectional_syn_packets or 0),
        fin=int(f.bidirectional_fin_packets or 0),
        rst=int(f.bidirectional_rst_packets or 0),
        splt_direction=splt_dir,
        splt_ps=list(f.splt_ps or []),
        splt_piat_ms=list(f.splt_piat_ms or []),
    )


class Heartbeat:
    """Sends one small multicast UDP packet per second out of `iface` so the
    nfstream meter on that interface keeps scanning for idle flows."""

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self.error: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"heartbeat-{iface}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        try:
            idx = socket.if_nametoindex(self.iface)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface.encode())
            # ip_mreqn: pick the egress interface by index (vifs may share one IP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, struct.pack("=4s4si", b"\0" * 4, b"\0" * 4, idx))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        except OSError as e:
            self.error = str(e)
            log.warning("heartbeat on %s disabled: %s", self.iface, e)
            return
        while not self._stop.wait(HEARTBEAT_SECONDS):
            try:
                s.sendto(b"np", (HEARTBEAT_GROUP, HEARTBEAT_PORT))
            except OSError as e:  # interface gone
                self.error = str(e)
                break
        s.close()


class VifCapture:
    """One NFStreamer on one vif, iterated in a daemon thread into a window."""

    def __init__(self, iface: str, window: RollingWindow, local_nets: list[str] | None = None, heartbeat: bool = True) -> None:
        if iface in FORBIDDEN_INTERFACES or iface.startswith("eth"):
            raise ValueError(f"refusing to capture on {iface}")
        self.iface = iface
        self.window = window
        self.local_nets = local_nets
        self.error: str | None = None
        self.alive = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"nfstream-{iface}", daemon=True)
        self._heartbeat = Heartbeat(iface) if heartbeat else None

    def start(self) -> None:
        self._thread.start()
        if self._heartbeat:
            self._heartbeat.start()

    def stop(self) -> None:
        self._stop.set()
        if self._heartbeat:
            self._heartbeat.stop()

    def _run(self) -> None:
        from nfstream import NFStreamer  # imported here so tests need no libpcap

        self.alive = True
        orienter = Orienter(self.local_nets)
        try:
            streamer = NFStreamer(source=self.iface, **_streamer_kwargs())
            for flow in streamer:
                if self._stop.is_set():
                    break
                if is_heartbeat(flow):
                    continue
                self.window.add(nflow_to_seg(flow, orienter))
        except Exception as e:  # interface vanished, permission, libpcap...
            self.error = str(e)
            log.warning("capture on %s stopped: %s", self.iface, e)
        finally:
            self.alive = False


class PcapReplay:
    """Replay a pcap as if it were one vif, pacing flow expiry to wall-clock.

    Flow timestamps are shifted so the first flow starts "now"; each flow is
    handed to the window when its (shifted) last-seen time has passed, divided
    by `speed`. The rest of the pipeline sees ordinary wall-clock timestamps.
    """

    def __init__(self, pcap: Path, window: RollingWindow, speed: float = 1.0, loop: bool = False, local_nets: list[str] | None = None) -> None:
        self.pcap = pcap
        self.window = window
        self.local_nets = local_nets
        self.speed = max(0.01, speed)
        self.loop = loop
        self.error: str | None = None
        self.alive = False
        self.done = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="pcap-replay", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        from nfstream import NFStreamer

        self.alive = True
        try:
            while not self._stop.is_set():
                # nfstream emits flows in expiry order; sort by last_seen to be safe
                orienter = Orienter(self.local_nets)
                segs = [nflow_to_seg(f, orienter) for f in NFStreamer(source=str(self.pcap), **_streamer_kwargs())]
                segs.sort(key=lambda s: s.last_ms)
                if not segs:
                    self.error = "pcap produced no flows"
                    return
                origin = min(s.first_ms for s in segs)
                wall0 = int(time.time() * 1000)
                for s in segs:
                    if self._stop.is_set():
                        return
                    rel_last = (s.last_ms - origin) / self.speed
                    due = wall0 + rel_last
                    delay = (due - time.time() * 1000) / 1000
                    if delay > 0:
                        time.sleep(min(delay, 5.0))
                    shift = int(time.time() * 1000) - s.last_ms
                    dur = int(s.duration_ms / self.speed)
                    s.last_ms += shift
                    s.first_ms = s.last_ms - dur
                    self.window.add(s)
                if not self.loop:
                    break
        except Exception as e:
            self.error = str(e)
            log.warning("pcap replay stopped: %s", e)
        finally:
            self.alive = False
            self.done = True


class CaptureManager:
    """Owns windows and captures; rescans for new vifs on demand."""

    def __init__(self, explicit: list[str] | None = None, local_nets: list[str] | None = None, heartbeat: bool = True) -> None:
        self.explicit = explicit or None
        self.local_nets = local_nets or None
        self.heartbeat = heartbeat
        self.windows: dict[str, RollingWindow] = {}
        self.captures: dict[str, VifCapture | PcapReplay] = {}
        self._last_scan = 0.0
        self.on_new_vif: Callable[[str], None] | None = None

    def add_pcap(self, pcap: Path, speed: float, loop: bool, name: str = "pcap") -> None:
        w = RollingWindow()
        self.windows[name] = w
        cap = PcapReplay(pcap, w, speed=speed, loop=loop, local_nets=self.local_nets)
        self.captures[name] = cap
        cap.start()
        if self.on_new_vif:
            self.on_new_vif(name)

    def scan(self, force: bool = False) -> list[str]:
        now = time.monotonic()
        if not force and now - self._last_scan < VIF_SCAN_SECONDS:
            return []
        self._last_scan = now
        added = []
        for iface in discover_vifs(self.explicit):
            cap = self.captures.get(iface)
            if cap is not None and (cap.alive or cap.error is None):
                continue
            if cap is not None and cap.error is not None:
                log.info("restarting capture on %s after error", iface)
            w = self.windows.setdefault(iface, RollingWindow())
            vc = VifCapture(iface, w, local_nets=self.local_nets, heartbeat=self.heartbeat)
            self.captures[iface] = vc
            vc.start()
            added.append(iface)
            if self.on_new_vif:
                self.on_new_vif(iface)
        return added

    def stop_all(self) -> None:
        for c in self.captures.values():
            c.stop()
