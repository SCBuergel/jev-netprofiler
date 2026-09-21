"""nfstream capture: one NFStreamer per vif*, one thread each; pcap replay.

eth0 (the upstream link) is never opened. Interfaces are rediscovered every
few seconds so a qube that attaches later gets its own streamer and pane.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import psutil

from .anon import endpoint_id, flow_id, host_id
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
        n_meters=1,  # one forked meter per interface, not one per CPU
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
        return host_id(f"{lo}<>{hi}/{f.protocol}")  # digest: the cache never holds addresses

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
                return cached == host_id(src)
            sp, dp = _is_private(f.src_ip), _is_private(f.dst_ip)
            local = src if (sp and not dp) else dst if (dp and not sp) else src
        if len(self._local_addr) > 50_000:  # bound memory on very busy links
            self._local_addr.clear()
        self._local_addr[key] = host_id(local)  # which side is local, stored as a digest
        return local == src


def is_heartbeat(f) -> bool:
    return f.protocol == 17 and f.dst_port == HEARTBEAT_PORT and f.dst_ip == HEARTBEAT_GROUP


def is_probe(f, local_is_src: bool) -> bool:
    """Unsolicited inbound noise a public address attracts: port scans that
    get a reset, lone inbound UDP packets nobody answered, and pings. None of
    it is the machine's own activity, so it is dropped before the window."""
    if f.protocol in (1, 58):  # ICMP / ICMPv6
        return True
    packets = int(f.bidirectional_packets or 0)
    syn_local = int((f.src2dst_syn_packets if local_is_src else f.dst2src_syn_packets) or 0)
    syn_remote = int((f.dst2src_syn_packets if local_is_src else f.src2dst_syn_packets) or 0)
    local_packets = int(f.src2dst_packets if local_is_src else f.dst2src_packets)
    if f.protocol == 6:
        remote_initiated = syn_remote > 0 and syn_local == 0
        # SYN retries answered by resets carry no payload however many there are:
        # every packet is header-sized (a 60-byte SYN, a 40-byte RST)
        tiny = packets > 0 and int(f.bidirectional_bytes or 0) / packets < 80
        return remote_initiated and int(f.bidirectional_rst_packets or 0) > 0 and tiny
    if packets > 4:
        return False
    if f.protocol == 17:
        remote_first = not local_is_src  # src is whoever sent the first packet
        return remote_first and local_packets == 0
    return False


def nflow_to_seg(f, orienter: Orienter | None = None) -> FlowSeg:
    """Project an nfstream NFlow onto the shape-only FlowSeg, oriented so that
    `up` always means the downstream qube sending outwards."""
    orienter = orienter or Orienter()
    key = orienter.key(f)
    local_src = orienter.local_is_src(f, key)
    s2d_piat = (float(getattr(f, "src2dst_mean_piat_ms", 0) or 0.0), float(getattr(f, "src2dst_stddev_piat_ms", 0) or 0.0))
    d2s_piat = (float(getattr(f, "dst2src_mean_piat_ms", 0) or 0.0), float(getattr(f, "dst2src_stddev_piat_ms", 0) or 0.0))
    proto = int(f.protocol)
    if local_src:
        up_p, down_p = f.src2dst_packets, f.dst2src_packets
        up_b, down_b = f.src2dst_bytes, f.dst2src_bytes
        up_piat, down_piat = s2d_piat, d2s_piat
        local_port, remote_ip, remote_port = int(f.src_port), f.dst_ip, int(f.dst_port)
        splt_dir = list(f.splt_direction or [])
    else:
        up_p, down_p = f.dst2src_packets, f.src2dst_packets
        up_b, down_b = f.dst2src_bytes, f.src2dst_bytes
        up_piat, down_piat = d2s_piat, s2d_piat
        local_port, remote_ip, remote_port = int(f.dst_port), f.src_ip, int(f.src_port)
        splt_dir = [1 - d if d in (0, 1) else d for d in (f.splt_direction or [])]
    # addresses and ports stop here: only salted digests are kept
    return FlowSeg(
        key=flow_id(proto, local_port, remote_ip, remote_port),
        endpoint=endpoint_id(proto, remote_ip, remote_port),
        host=host_id(remote_ip),
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


class OwnTraffic:
    """Knows which flows belong to this process, so a capture of the qube's
    own uplink can leave the profiler's Jev calls out.

    Three sources: every socket this process connects (hooked at connect
    time, so even a short-lived connection is recorded), a periodic snapshot
    of open sockets, and the resolved addresses of the API host. Entries are
    remembered for a while because a flow segment arrives after its socket
    may have closed. DNS lookups go through the C resolver and are not seen;
    they are rare (one per new connection) and tiny.
    """

    REMEMBER_S = 600.0
    SNAPSHOT_S = 0.5
    RESOLVE_S = 300.0

    def __init__(self, api_host: str | None = None) -> None:
        self.api_host = api_host or urlparse(os.environ.get("TYPESAFE_BASE_URL", "https://api.typesafe.ai")).hostname or "api.typesafe.ai"
        self._seen: dict[str, float] = {}  # flow digest -> last seen
        self._api_endpoints: set[str] = set()  # endpoint digests of the API host on 443
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="own-traffic", daemon=True)
        self.excluded = 0

    _hooked = False

    def start(self) -> None:
        self._install_connect_hook()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _record(self, sock: socket.socket) -> None:
        try:
            if sock.family not in (socket.AF_INET, socket.AF_INET6):
                return
            proto = 6 if sock.type == socket.SOCK_STREAM else 17
            lport = sock.getsockname()[1]
            rip, rport = sock.getpeername()[:2]
        except OSError:
            return
        with self._lock:
            self._seen[flow_id(proto, lport, rip, rport)] = time.time()

    def _install_connect_hook(self) -> None:
        """Wrap socket.connect/connect_ex process-wide (asyncio's sock_connect
        ends up here too). Only the profiler's own process is affected."""
        if OwnTraffic._hooked:
            return
        OwnTraffic._hooked = True
        me = self
        orig_connect, orig_connect_ex = socket.socket.connect, socket.socket.connect_ex

        def connect(sock, address):
            try:
                return orig_connect(sock, address)
            finally:
                me._record(sock)

        def connect_ex(sock, address):
            try:
                return orig_connect_ex(sock, address)
            finally:
                me._record(sock)

        socket.socket.connect = connect  # type: ignore[method-assign]
        socket.socket.connect_ex = connect_ex  # type: ignore[method-assign]

    def _run(self) -> None:
        proc = psutil.Process()
        next_resolve = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now >= next_resolve:
                try:
                    eps = {endpoint_id(6, ai[4][0], 443) for ai in socket.getaddrinfo(self.api_host, 443, proto=socket.IPPROTO_TCP)}
                    with self._lock:
                        self._api_endpoints = eps
                except OSError:
                    pass
                next_resolve = now + self.RESOLVE_S
            try:
                conns = proc.net_connections(kind="inet")
            except (psutil.Error, OSError):
                conns = []
            with self._lock:
                for c in conns:
                    if not c.raddr or not c.laddr:
                        continue
                    proto = 6 if c.type == socket.SOCK_STREAM else 17
                    self._seen[flow_id(proto, c.laddr.port, c.raddr.ip, c.raddr.port)] = now
                if len(self._seen) > 10_000:
                    cutoff = now - self.REMEMBER_S
                    self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
            self._stop.wait(self.SNAPSHOT_S)

    def is_own(self, seg: FlowSeg) -> bool:
        with self._lock:
            return seg.tuple4 in self._seen or seg.endpoint in self._api_endpoints


class SharedFlows:
    """Flows seen on vif captures, so a simultaneous eth0 capture can drop the
    NAT'd copies of downstream traffic and keep only the qube's own."""

    REMEMBER_S = 300.0

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def note(self, seg: FlowSeg) -> None:
        with self._lock:
            self._seen[seg.tuple4] = time.time()
            if len(self._seen) > 50_000:
                cutoff = time.time() - self.REMEMBER_S
                self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}

    def seen(self, seg: FlowSeg) -> bool:
        with self._lock:
            ts = self._seen.get(seg.tuple4)
        return ts is not None and time.time() - ts <= self.REMEMBER_S


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

    def __init__(self, iface: str, window: RollingWindow, local_nets: list[str] | None = None, heartbeat: bool = True, shared: SharedFlows | None = None) -> None:
        if iface in FORBIDDEN_INTERFACES or iface.startswith("eth"):
            raise ValueError(f"refusing to capture on {iface}")
        self.iface = iface
        self.window = window
        self.local_nets = local_nets
        self.shared = shared
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
                if is_heartbeat(flow) or is_probe(flow, orienter.local_is_src(flow, orienter.key(flow))):
                    continue
                seg = nflow_to_seg(flow, orienter)
                if self.shared is not None:
                    self.shared.note(seg)
                self.window.add(seg)
        except Exception as e:  # interface vanished, permission, libpcap...
            self.error = str(e)
            log.warning("capture on %s stopped: %s", self.iface, e)
        finally:
            self.alive = False


class SelfCapture:
    """Capture the qube's own uplink (eth0) for the qube's own applications.

    Opt-in only. The profiler's own flows are excluded via `OwnTraffic`; when
    vif captures run at the same time, flows they have seen are excluded too,
    so downstream NAT'd traffic is not counted twice. Segments are held for
    HOLD_S before entering the window so the vif copy has time to register.
    No heartbeat: the profiler's own calls keep the meter clock moving.
    """

    HOLD_S = 1.5

    def __init__(self, window: RollingWindow, own: OwnTraffic, shared: SharedFlows | None, iface: str = "eth0", include_own: bool = False) -> None:
        self.iface = iface
        self.window = window
        self.own = own
        self.shared = shared
        self.include_own = include_own
        self.error: str | None = None
        self.alive = False
        self.excluded_own = 0
        self.excluded_downstream = 0
        self.excluded_probes = 0
        self._pending: deque[tuple[float, FlowSeg]] = deque()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"nfstream-self-{iface}", daemon=True)

    @staticmethod
    def local_addresses(iface: str) -> list[str]:
        out = []
        for a in psutil.net_if_addrs().get(iface, []):
            if a.family in (socket.AF_INET, socket.AF_INET6) and a.address:
                out.append(a.address.split("%")[0] + ("/32" if a.family == socket.AF_INET else "/128"))
        return out

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        from nfstream import NFStreamer

        self.alive = True
        orienter = Orienter(self.local_addresses(self.iface))
        try:
            for flow in NFStreamer(source=self.iface, **_streamer_kwargs()):
                if self._stop.is_set():
                    break
                if is_heartbeat(flow):
                    continue
                if is_probe(flow, orienter.local_is_src(flow, orienter.key(flow))):
                    self.excluded_probes += 1
                    continue
                seg = nflow_to_seg(flow, orienter)
                if not self.include_own and self.own.is_own(seg):
                    self.excluded_own += 1
                    continue
                with self._lock:
                    self._pending.append((time.time(), seg))
        except Exception as e:
            self.error = str(e)
            log.warning("self capture on %s stopped: %s", self.iface, e)
        finally:
            self.alive = False

    def flush(self, hold: bool) -> None:
        """Move held segments into the window; called on every engine tick.
        Holding (and the matching extra window lag) is only needed while vif
        captures run alongside, so their copy of a flow can register first."""
        from .config import TICK_SECONDS

        extra = int((self.HOLD_S + TICK_SECONDS) * 1000) if hold else 0
        self.window.lag_ms = RollingWindow.LAG_MS + extra
        cutoff = time.time() - (self.HOLD_S if hold else 0.0)
        with self._lock:
            while self._pending and self._pending[0][0] <= cutoff:
                _, seg = self._pending.popleft()
                if hold and self.shared is not None and self.shared.seen(seg):
                    self.excluded_downstream += 1
                    continue
                self.window.add(seg)


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
                segs = [
                    nflow_to_seg(f, orienter)
                    for f in NFStreamer(source=str(self.pcap), **_streamer_kwargs())
                    if not is_probe(f, orienter.local_is_src(f, orienter.key(f)))
                ]
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

    SELF_NAME = "self"

    def __init__(self, explicit: list[str] | None = None, local_nets: list[str] | None = None, heartbeat: bool = True) -> None:
        self.explicit = explicit or None
        self.local_nets = local_nets or None
        self.heartbeat = heartbeat
        self.windows: dict[str, RollingWindow] = {}
        self.captures: dict[str, VifCapture | PcapReplay | SelfCapture] = {}
        self.shared = SharedFlows()
        self.own: OwnTraffic | None = None
        self._last_scan = 0.0
        self.on_new_vif: Callable[[str], None] | None = None

    def add_self(self, include_own: bool = False, iface: str = "eth0") -> None:
        """Profile this qube's own applications on its uplink."""
        self.own = OwnTraffic()
        self.own.start()
        w = RollingWindow()
        self.windows[self.SELF_NAME] = w
        cap = SelfCapture(w, self.own, self.shared, iface=iface, include_own=include_own)
        self.captures[self.SELF_NAME] = cap
        cap.start()
        log.info("capturing this qube's own traffic on %s (profiler's own flows excluded: %s)", iface, not include_own)
        if self.on_new_vif:
            self.on_new_vif(self.SELF_NAME)

    def flush(self) -> None:
        has_vifs = any(isinstance(c, VifCapture) for c in self.captures.values())
        for c in self.captures.values():
            if isinstance(c, SelfCapture):
                c.flush(hold=has_vifs)

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
            vc = VifCapture(iface, w, local_nets=self.local_nets, heartbeat=self.heartbeat, shared=self.shared)
            self.captures[iface] = vc
            vc.start()
            log.info("capturing on %s", iface)
            added.append(iface)
            if self.on_new_vif:
                self.on_new_vif(iface)
        return added

    def stop_all(self) -> None:
        for c in self.captures.values():
            c.stop()
        if self.own:
            self.own.stop()
