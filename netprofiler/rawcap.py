"""Raw-packet mode: a filtered packet log instead of a reduced description.

`tcpdump -nn -tt -q -l -s 96` records headers only (payload is never even
captured) and prints one line per packet. Each line is parsed into a
`Packet` (time, direction, flow, protocol, remote port, length). Every
batch period the packets are encoded into a compact text under a token
budget and sent to Jev as the state. Remote addresses never leave the
process: each remote host becomes an opaque per-batch endpoint index.

Size ladder, applied until the text fits the budget:
  1. one line per packet
  2. run-length encode consecutive same-flow, same-direction, same-size packets
  3. 100 ms per-flow bins
  4. 500 ms per-flow bins
  5. truncate with a count of omitted lines
"""

from __future__ import annotations

import logging
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass

from .capture import OwnTraffic, SelfCapture
from .flows import FlowSeg

log = logging.getLogger("netprofiler.rawcap")

# 1758412345.123456 IP 10.0.0.1.443 > 10.0.0.2.51000: tcp 1448
# 1758412345.123456 IP 10.0.0.1.53 > 10.0.0.2.5555: UDP, length 56
# 1758412345.123456 IP6 fe80::1.546 > ff02::1:2.547: UDP, length 100
_LINE = re.compile(
    r"^(?P<ts>\d+\.\d+) IP6? (?P<src>[0-9a-f.:]+)\.(?P<sport>\d+) > (?P<dst>[0-9a-f.:]+)\.(?P<dport>\d+): "
    r"(?:(?P<tcp>tcp) (?P<tlen>\d+)|(?P<udp>UDP), length (?P<ulen>\d+))"
)
_ICMP = re.compile(r"^(?P<ts>\d+\.\d+) IP6? [0-9a-f.:]+ > [0-9a-f.:]+: ICMP")


@dataclass(slots=True)
class Packet:
    t_ms: int
    out: bool  # local -> remote
    proto: int  # 6 / 17
    local_port: int
    remote_ip: str
    remote_port: int
    length: int  # payload-ish length as tcpdump reports it (tcp: payload bytes; udp: length)

    @property
    def endpoint(self) -> str:
        return f"{self.remote_ip}:{self.remote_port}/{self.proto}"

    @property
    def tuple4(self) -> tuple[int, int, str]:
        return (self.proto, self.local_port, self.endpoint)


def parse_line(line: str, local_ips: set[str]) -> Packet | None:
    m = _LINE.match(line)
    if not m:
        return None
    src, dst = m.group("src"), m.group("dst")
    if src in local_ips:
        out, lport, rip, rport = True, int(m.group("sport")), dst, int(m.group("dport"))
    elif dst in local_ips:
        out, lport, rip, rport = False, int(m.group("dport")), src, int(m.group("sport"))
    else:
        return None  # not ours (multicast chatter, other hosts on the segment)
    proto = 6 if m.group("tcp") else 17
    length = int(m.group("tlen") or m.group("ulen") or 0)
    return Packet(int(float(m.group("ts")) * 1000), out, proto, lport, rip, rport, length)


class TcpdumpCapture:
    """One tcpdump per interface, lines parsed in a thread into a buffer."""

    def __init__(self, iface: str, local_ips: set[str], own: OwnTraffic | None, keep_seconds: float = 30.0) -> None:
        self.iface = iface
        self.local_ips = local_ips
        self.own = own
        self.keep_ms = int(keep_seconds * 1000)
        self.error: str | None = None
        self.alive = False
        self.excluded_own = 0
        self.dropped_probes = 0
        self._buf: deque[Packet] = deque()
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"tcpdump-{iface}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()

    def _run(self) -> None:
        self.alive = True
        cmd = ["tcpdump", "-i", self.iface, "-nn", "-tt", "-q", "-l", "-s", "96", "-U", "ip or ip6"]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                p = parse_line(line, self.local_ips)
                if p is None:
                    continue
                if self.own is not None and self.own.is_own(_as_seg_like(p)):
                    self.excluded_own += 1
                    continue
                with self._lock:
                    self._buf.append(p)
                    cutoff = p.t_ms - self.keep_ms
                    while self._buf and self._buf[0].t_ms < cutoff:
                        self._buf.popleft()
        except Exception as e:
            self.error = str(e)
            log.warning("tcpdump on %s stopped: %s", self.iface, e)
        finally:
            self.alive = False

    def batch(self, since_ms: int, until_ms: int) -> list[Packet]:
        with self._lock:
            return [p for p in self._buf if since_ms <= p.t_ms < until_ms]


class _SegLike:
    """Just enough of FlowSeg for OwnTraffic.is_own (tuple4 + endpoint)."""

    __slots__ = ("tuple4", "endpoint")

    def __init__(self, p: Packet) -> None:
        self.tuple4 = p.tuple4
        self.endpoint = p.endpoint


def _as_seg_like(p: Packet) -> FlowSeg:  # type: ignore[return-value]
    return _SegLike(p)  # type: ignore[return-value]


# --------------------------------------------------------------- encoding --
def estimate_tokens(text: str) -> int:
    # digits-heavy text tokenizes worse than prose; ~3.2 chars per token
    return int(len(text) / 3.2) + 1


def drop_probes(packets: list[Packet]) -> tuple[list[Packet], int]:
    """Remove flows that only ever received packets (nothing sent back) with
    at most two packets, i.e. scans and stray inbound UDP."""
    by_flow: dict[tuple, list[Packet]] = {}
    for p in packets:
        by_flow.setdefault(p.tuple4, []).append(p)
    keep, dropped = [], 0
    for pk in by_flow.values():
        if len(pk) <= 2 and not any(p.out for p in pk):
            dropped += len(pk)
            continue
        keep.extend(pk)
    keep.sort(key=lambda p: p.t_ms)
    return keep, dropped


def encode(packets: list[Packet], start_ms: int, budget_tokens: int) -> tuple[str, dict]:
    """Encode a batch as text under a token budget. Returns (text, stats)."""
    packets, dropped = drop_probes(packets)
    stats = {"packets": len(packets), "probes_dropped": dropped, "level": 0}
    if not packets:
        return "no packets in this batch", stats

    # flow and endpoint tables
    flows: dict[tuple, int] = {}
    endpoints: dict[str, int] = {}
    for p in packets:
        endpoints.setdefault(p.remote_ip, len(endpoints) + 1)
        flows.setdefault(p.tuple4, len(flows) + 1)
    header = ["flows (id proto endpoint:port):"]
    for (proto, _lport, _ep), fid in flows.items():
        p0 = next(p for p in packets if p.tuple4 == (proto, _lport, _ep))
        header.append(f"f{fid} {'tcp' if proto == 6 else 'udp'} e{endpoints[p0.remote_ip]}:{p0.remote_port}")
    head = "\n".join(header) + "\npackets (ms flow dir len; dir > out < in):\n"
    stats["flows"] = len(flows)
    stats["endpoints"] = len(endpoints)

    def line_plain(p: Packet) -> str:
        return f"{p.t_ms - start_ms} f{flows[p.tuple4]}{'>' if p.out else '<'} {p.length}"

    # level 0: verbatim
    body = "\n".join(line_plain(p) for p in packets)
    if estimate_tokens(head + body) <= budget_tokens:
        return head + body, stats

    # level 1: run-length encode same flow/dir/size runs
    stats["level"] = 1
    runs: list[str] = []
    i = 0
    while i < len(packets):
        p = packets[i]
        j = i + 1
        while j < len(packets) and packets[j].tuple4 == p.tuple4 and packets[j].out == p.out and packets[j].length == p.length:
            j += 1
        n = j - i
        if n == 1:
            runs.append(line_plain(p))
        else:
            span = packets[j - 1].t_ms - p.t_ms
            runs.append(f"{p.t_ms - start_ms} f{flows[p.tuple4]}{'>' if p.out else '<'} {p.length} x{n} over {span}ms")
        i = j
    body = "\n".join(runs)
    if estimate_tokens(head + body) <= budget_tokens:
        return head + body, stats

    # levels 2/3: per-flow bins
    for level, bin_ms in ((2, 100), (3, 500)):
        stats["level"] = level
        bins: dict[tuple[int, int, bool], list[int]] = {}
        for p in packets:
            k = ((p.t_ms - start_ms) // bin_ms, flows[p.tuple4], p.out)
            bins.setdefault(k, []).append(p.length)
        lines = [f"{b * bin_ms} f{fid}{'>' if out else '<'} {len(ls)}p {sum(ls)}B" for (b, fid, out), ls in sorted(bins.items())]
        body = "\n".join(lines)
        head2 = head.replace("packets (ms flow dir len; dir > out < in):", f"packets binned per {bin_ms}ms (ms flow dir count bytes; dir > out < in):")
        if estimate_tokens(head2 + body) <= budget_tokens:
            return head2 + body, stats
    # level 4: truncate
    stats["level"] = 4
    keep_chars = max(0, int(budget_tokens * 3.2) - len(head2) - 60)
    cut = body[:keep_chars].rsplit("\n", 1)[0]
    omitted = body.count("\n") - cut.count("\n")
    return head2 + cut + f"\n... {omitted} more lines omitted", stats


RAW_LEGEND = (
    "A headers-only packet log of one network link over a few seconds. No payload, no addresses: "
    "endpoints are opaque ids, flows are numbered, ports are real. Each packet line is milliseconds "
    "since the batch start, the flow id with direction (> sent by this machine, < received), and the "
    "payload length in bytes; 'x N over M ms' means N identical packets back to back; binned lines give "
    "packet count and bytes per time bin. Judge the activity from timing, sizes, directions and flow structure."
)


class RawCaptureManager:
    """tcpdump captures per interface, sharing the own-traffic filter."""

    def __init__(self, own: OwnTraffic | None) -> None:
        self.own = own
        self.captures: dict[str, TcpdumpCapture] = {}
        self.on_new_vif = None

    def add(self, name: str, iface: str) -> None:
        local_ips = {a.split("/")[0] for a in SelfCapture.local_addresses(iface)}
        cap = TcpdumpCapture(iface, local_ips, self.own)
        self.captures[name] = cap
        cap.start()
        log.info("raw capture on %s (local %s)", iface, ", ".join(sorted(local_ips)) or "?")
        if self.on_new_vif:
            self.on_new_vif(name)

    def stop_all(self) -> None:
        for c in self.captures.values():
            c.stop()
        if self.own:
            self.own.stop()
