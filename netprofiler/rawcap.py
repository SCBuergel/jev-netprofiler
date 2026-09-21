"""Raw-packet mode: a filtered packet log instead of a reduced description.

`tcpdump -nn -tt -q -l -s 96` records headers only (payload is never even
captured) and prints one line per packet. Each line is parsed into a
`Packet` (time, direction, flow digest, protocol, length). Addresses and
ports are hashed with a per-process salt while the line is parsed and are
never stored; the log shows flows and endpoints as small per-batch indices.

Size ladder, applied until the text fits the budget:
  1. one line per packet
  2. run-length encode consecutive same-flow, same-direction, same-size packets
  3. 100 ms per-flow bins
  4. 500 ms per-flow bins
  5. truncate with a count of omitted lines
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import shutil
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass

from .anon import endpoint_id, flow_id
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
    flow: str  # salted digest of (proto, local port, remote ip, remote port)
    endpoint: str  # salted digest of (proto, remote ip, remote port)
    length: int  # payload-ish length as tcpdump reports it (tcp: payload bytes; udp: length)
    label: str | None = None  # "local:port > remote:port", only in the opt-in --raw-ips mode

    @property
    def tuple4(self) -> str:
        return self.flow


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def parse_line(line: str, local_ips: set[str], keep_ips: bool = False) -> Packet | None:
    """One tcpdump line -> Packet, or None for lines that are not this
    link's traffic. `local_ips` is the side being profiled (the interface's
    own address on eth0, the downstream qube on a vif); when neither address
    matches, a private-to-public packet counts as outbound and the reverse
    as inbound."""
    m = _LINE.match(line)
    if not m:
        return None
    src, dst = m.group("src"), m.group("dst")
    if src in local_ips:
        out, lport, rip, rport = True, int(m.group("sport")), dst, int(m.group("dport"))
    elif dst in local_ips:
        out, lport, rip, rport = False, int(m.group("dport")), src, int(m.group("sport"))
    elif _is_private(src) and not _is_private(dst):
        out, lport, rip, rport = True, int(m.group("sport")), dst, int(m.group("dport"))
    elif _is_private(dst) and not _is_private(src):
        out, lport, rip, rport = False, int(m.group("dport")), src, int(m.group("sport"))
    else:
        return None  # multicast chatter, link-local, other hosts on the segment
    proto = 6 if m.group("tcp") else 17
    length = int(m.group("tlen") or m.group("ulen") or 0)
    label = f"{'?' if not keep_ips else (src if out else dst)}:{lport} > {rip}:{rport}" if keep_ips else None
    # addresses and ports stop here unless --raw-ips asked for them
    return Packet(int(float(m.group("ts")) * 1000), out, proto, flow_id(proto, lport, rip, rport), endpoint_id(proto, rip, rport), length, label)


class TcpdumpCapture:
    """One tcpdump per interface, lines parsed in a thread into a buffer."""

    def __init__(self, iface: str, local_ips: set[str], own: OwnTraffic | None, keep_seconds: float = 30.0, keep_ips: bool = False) -> None:
        self.iface = iface
        self.local_ips = local_ips
        self.keep_ips = keep_ips
        self.own = own
        self.keep_ms = int(keep_seconds * 1000)
        self.error: str | None = None
        self.alive = False
        self.excluded_own = 0
        self.dropped_probes = 0
        self.skipped_lines = 0  # lines that were not this link's traffic
        self.total_lines = 0
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
                self.total_lines += 1
                p = parse_line(line, self.local_ips, self.keep_ips)
                if p is None:
                    self.skipped_lines += 1
                    continue
                if self.own is not None and self.own.is_own(p):  # type: ignore[arg-type]
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




# --------------------------------------------------------------- encoding --
def estimate_tokens(text: str) -> int:
    # measured on jev-1.13.0: packet logs tokenize at about 1.07 chars per token
    return int(len(text) / 1.05) + 1


def drop_probes(packets: list[Packet]) -> tuple[list[Packet], int]:
    """Remove flows that are not activity: flows that never carry payload in
    either direction (SYN retries answered by resets, however many), and
    inbound-only flows of at most two packets (scans, stray UDP)."""
    by_flow: dict[str, list[Packet]] = {}
    for p in packets:
        by_flow.setdefault(p.tuple4, []).append(p)
    keep, dropped = [], 0
    for pk in by_flow.values():
        no_payload = all(p.length == 0 for p in pk)
        inbound_only = not any(p.out for p in pk)
        if no_payload or (len(pk) <= 2 and inbound_only):
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

    # flow and endpoint tables; zero-length TCP packets (pure acks) are only counted
    flows: dict[str, int] = {}
    endpoints: dict[str, int] = {}
    protos: dict[str, int] = {}
    acks: dict[str, int] = {}
    for p in packets:
        endpoints.setdefault(p.endpoint, len(endpoints) + 1)
        flows.setdefault(p.flow, len(flows) + 1)
        protos.setdefault(p.flow, p.proto)
        if p.proto == 6 and p.length == 0:
            acks[p.flow] = acks.get(p.flow, 0) + 1
    data = [p for p in packets if not (p.proto == 6 and p.length == 0)]
    bytes_in = sum(p.length for p in data if not p.out)
    bytes_out = sum(p.length for p in data if p.out)
    span_ms = packets[-1].t_ms - packets[0].t_ms
    gaps = sum(1 for a, b in zip(packets, packets[1:]) if b.t_ms - a.t_ms >= 1000)
    longest_pause = max((b.t_ms - a.t_ms for a, b in zip(packets, packets[1:])), default=0)
    first_seen = {}
    last_seen = {}
    flow_bytes: dict[str, int] = {}
    for p in packets:
        first_seen.setdefault(p.flow, p.t_ms)
        last_seen[p.flow] = p.t_ms
        flow_bytes[p.flow] = flow_bytes.get(p.flow, 0) + p.length
    new_flows = sum(1 for k in flows if first_seen[k] - start_ms > 200)  # opened inside the window, not at its edge
    short_flows = sum(1 for k in flows if last_seen[k] - first_seen[k] < 2000)
    total_b = sum(flow_bytes.values())
    top_share = int(100 * max(flow_bytes.values()) / total_b) if total_b else 0
    with_ips = packets[0].label is not None
    header = [
        f"summary: {len(flows)} flows to {len(endpoints)} endpoints ({new_flows} opened during the window, {short_flows} lived under 2 s), "
        f"{len(packets)} packets over {span_ms} ms, {bytes_in} B in, {bytes_out} B out, largest flow carries {top_share}% of bytes, "
        f"{gaps} pauses of a second or more, longest pause {longest_pause} ms",
        "flows (id proto local:port > remote:port, pure-ack count):" if with_ips else "flows (id proto endpoint, pure-ack count):",
    ]
    for key, fid in flows.items():
        p0 = next(p for p in packets if p.flow == key)
        where = p0.label if with_ips else f"e{endpoints[p0.endpoint]}"
        header.append(f"f{fid} {'tcp' if protos[key] == 6 else 'udp'} {where} acks={acks.get(key, 0)}")
    head = "\n".join(header) + "\npackets (+ms since previous line, flow, dir > out < in, len):\n"
    stats["flows"] = len(flows)
    stats["endpoints"] = len(endpoints)

    def lines_plain(pk: list[Packet]) -> list[str]:
        out, prev = [], start_ms
        for p in pk:
            out.append(f"+{p.t_ms - prev} f{flows[p.tuple4]}{'>' if p.out else '<'} {p.length}")
            prev = p.t_ms
        return out

    # level 0: verbatim data packets
    body = "\n".join(lines_plain(data))
    if estimate_tokens(head + body) <= budget_tokens:
        return head + body, stats

    # level 1: run-length encode same flow/dir/size runs
    stats["level"] = 1
    runs: list[str] = []
    i, prev = 0, start_ms
    while i < len(data):
        p = data[i]
        j = i + 1
        while j < len(data) and data[j].tuple4 == p.tuple4 and data[j].out == p.out and data[j].length == p.length:
            j += 1
        n = j - i
        if n == 1:
            runs.append(f"+{p.t_ms - prev} f{flows[p.tuple4]}{'>' if p.out else '<'} {p.length}")
        else:
            runs.append(f"+{p.t_ms - prev} f{flows[p.tuple4]}{'>' if p.out else '<'} {p.length} x{n} over {data[j - 1].t_ms - p.t_ms}ms")
        prev = data[j - 1].t_ms
        i = j
    body = "\n".join(runs)
    if estimate_tokens(head + body) <= budget_tokens:
        return head + body, stats

    # levels 2/3: per-flow bins
    head2 = head
    for level, bin_ms in ((2, 100), (3, 500)):
        stats["level"] = level
        bins: dict[tuple[int, int, bool], list[int]] = {}
        for p in data:
            k = ((p.t_ms - start_ms) // bin_ms, flows[p.tuple4], p.out)
            bins.setdefault(k, []).append(p.length)
        lines = [f"{b * bin_ms} f{fid}{'>' if out else '<'} {len(ls)}p {sum(ls)}B" for (b, fid, out), ls in sorted(bins.items())]
        body = "\n".join(lines)
        head2 = head.replace(
            "packets (+ms since previous line, flow, dir > out < in, len):",
            f"packets binned per {bin_ms} ms (bin start ms, flow, dir > out < in, packet count, bytes):",
        )
        if estimate_tokens(head2 + body) <= budget_tokens:
            return head2 + body, stats
    # level 4: truncate
    stats["level"] = 4
    keep_chars = max(0, int(budget_tokens * 1.05) - len(head2) - 60)
    cut = body[:keep_chars].rsplit("\n", 1)[0]
    omitted = body.count("\n") - cut.count("\n")
    return head2 + cut + f"\n... {omitted} more lines omitted", stats


RAW_LEGEND = (
    "A headers-only packet log of one network link over the last few seconds. No payload, no addresses, no ports: "
    "endpoints and flows are just numbered. Pure TCP acks are not listed, only counted per flow. "
    "Each packet line is the delay in ms since the previous line, the flow id with direction (> sent by this machine, "
    "< received), and the payload length in bytes; 'x N over M ms' means N identical packets back to back; binned lines "
    "give packet count and bytes per time bin. Judge the activity from timing, sizes, directions and flow structure."
)


RAW_LEGEND_IPS = (
    "A headers-only packet log of one network link over the last few seconds. No payload. The flow table gives the real "
    "local and remote addresses and ports of each flow. Pure TCP acks are not listed, only counted per flow. "
    "Each packet line is the delay in ms since the previous line, the flow id with direction (> sent by this machine, "
    "< received), and the payload length in bytes; 'x N over M ms' means N identical packets back to back; binned lines "
    "give packet count and bytes per time bin. Judge the activity from timing, sizes, directions, flow structure and endpoints."
)


def downstream_addresses(iface: str) -> set[str]:
    """Addresses routed through `iface`: on a Qubes net-qube the host route
    to the downstream qube (`10.137.0.23 dev vif12.0`). Empty if none."""
    try:
        out = subprocess.run(["ip", "-j", "route", "show", "dev", iface], capture_output=True, text=True, timeout=5).stdout
        return routed_hosts(json.loads(out or "[]"))
    except (OSError, ValueError, subprocess.SubprocessError):
        return set()


def routed_hosts(routes: list[dict]) -> set[str]:
    hosts = set()
    for r in routes:
        dst = str(r.get("dst", ""))
        if dst and dst != "default" and "/" not in dst:
            hosts.add(dst)
        elif dst.endswith("/32") or dst.endswith("/128"):
            hosts.add(dst.split("/")[0])
    return hosts


class RawCaptureManager:
    """tcpdump captures per interface, sharing the own-traffic filter."""

    def __init__(self, own: OwnTraffic | None, keep_ips: bool = False) -> None:
        self.own = own
        self.keep_ips = keep_ips
        self.captures: dict[str, TcpdumpCapture] = {}
        self.on_new_vif = None

    def add(self, name: str, iface: str, local_nets: list[str] | None = None) -> None:
        if shutil.which("tcpdump") is None:
            raise SystemExit("tcpdump not found: install it (apt install tcpdump) or use --mode shape")
        if name == "self":
            local_ips = {a.split("/")[0] for a in SelfCapture.local_addresses(iface)}
        else:  # a vif: the profiled side is the downstream qube, not this host
            local_ips = downstream_addresses(iface)
        for net in local_nets or []:
            if "/" not in net or net.endswith(("/32", "/128")):
                local_ips.add(net.split("/")[0])
        cap = TcpdumpCapture(iface, local_ips, self.own, keep_ips=self.keep_ips)
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
