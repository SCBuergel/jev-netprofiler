"""nfstream-independent flow record and the per-vif rolling window.

`FlowSeg` is one expired flow *segment* as nfstream emits it. With
active_timeout=2 a long-lived flow is re-emitted every two seconds, so the
window sees a fresh segment per flow per tick. Only shape fields are kept; the
endpoint key is used solely to count distinct/new endpoints and never leaves
this process.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from .config import ACTIVE_TIMEOUT, WINDOW_SECONDS


@dataclass(slots=True)
class FlowSeg:
    key: str  # 5-tuple identity (internal only)
    endpoint: str  # remote (ip, port, proto) identity (internal only)
    first_ms: int
    last_ms: int
    up_packets: int  # src2dst: the downstream qube sending outwards
    down_packets: int  # dst2src
    up_bytes: int
    down_bytes: int
    mean_ps: float  # bidirectional mean packet size (bytes)
    stddev_ps: float
    min_ps: int
    max_ps: int
    mean_piat_ms: float  # bidirectional mean packet inter-arrival time
    stddev_piat_ms: float
    max_piat_ms: float
    up_mean_piat_ms: float  # per-direction spacing (immune to interleaving phase)
    up_stddev_piat_ms: float
    down_mean_piat_ms: float
    down_stddev_piat_ms: float
    protocol: int  # 6 tcp, 17 udp, other
    syn: int  # bidirectional SYN count (0 => continuation of an older flow)
    fin: int
    rst: int
    splt_direction: list[int] = field(default_factory=list)  # 0 up, 1 down
    splt_ps: list[int] = field(default_factory=list)
    splt_piat_ms: list[int] = field(default_factory=list)
    local_port: int = 0

    @property
    def tuple4(self) -> tuple[int, int, str]:
        """(protocol, local port, remote endpoint): stable across NAT in the
        common case where masquerade keeps the source port."""
        return (self.protocol, self.local_port, self.endpoint)

    @property
    def packets(self) -> int:
        return self.up_packets + self.down_packets

    @property
    def bytes(self) -> int:
        return self.up_bytes + self.down_bytes

    @property
    def duration_ms(self) -> int:
        return max(0, self.last_ms - self.first_ms)


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(slots=True)
class WindowView:
    segs: list[FlowSeg]
    new_endpoints: int
    end_ms: int
    flow_first_seen: dict[str, int]  # key -> first_ms of the flow's first segment this session

    def __iter__(self):  # allow `segs, new_eps, end = window.snapshot()`
        return iter((self.segs, self.new_endpoints, self.end_ms))


class RollingWindow:
    """Thread-safe deque of FlowSeg, pruned to WINDOW_SECONDS by `last_ms`.

    Also remembers every endpoint seen during the session so the reducer can
    report how many endpoints in the window are *new* (first contact).
    """

    def add(self, seg: FlowSeg) -> None:
        with self._lock:
            self._segs.append(seg)
            self.total_segments += 1
            if seg.endpoint not in self._seen_endpoints:
                self._seen_endpoints.add(seg.endpoint)
                self._new_in_window[seg.endpoint] = seg.last_ms
            if seg.key not in self._flow_first_seen:
                self._flow_first_seen[seg.key] = seg.first_ms
            self._flow_last_seen[seg.key] = max(self._flow_last_seen.get(seg.key, 0), seg.last_ms)

    # nfstream only hands over a segment once it expires, so an ongoing flow's
    # newest ACTIVE_TIMEOUT seconds are always still in flight. The analysed
    # window therefore ends that far behind "now"; otherwise every continuous
    # activity would appear to have a trailing idle gap.
    LAG_MS = int(ACTIVE_TIMEOUT * 1000) + 250

    def __init__(self, seconds: float = WINDOW_SECONDS) -> None:
        self.seconds = seconds
        self.lag_ms = self.LAG_MS  # a capture that holds segments back adds to this
        self._segs: deque[FlowSeg] = deque()
        self._lock = threading.Lock()
        self._seen_endpoints: set[str] = set()
        self._new_in_window: dict[str, int] = {}  # endpoint -> first-seen ms
        self._flow_first_seen: dict[str, int] = {}  # key -> first_ms of its first segment ever
        self._flow_last_seen: dict[str, int] = {}
        self.total_segments = 0

    def snapshot(self, at_ms: int | None = None) -> "WindowView":
        """Return the segments in the window plus session-level context."""
        end = at_ms if at_ms is not None else now_ms() - self.lag_ms
        start = end - int(self.seconds * 1000)
        with self._lock:
            while self._segs and self._segs[0].last_ms < start:
                self._segs.popleft()
            # deque is appended in arrival order; segments can arrive slightly
            # out of order, so filter rather than trust the prune alone
            segs = [s for s in self._segs if s.last_ms >= start]
            for ep, ts in list(self._new_in_window.items()):
                if ts < start:
                    del self._new_in_window[ep]
            new_eps = len(self._new_in_window)
            # forget flows that have left the window (bounded memory; a flow
            # that resumes after a long silence simply counts as new again)
            stale_grace = start - int(self.seconds * 1000)
            for k, ts in list(self._flow_last_seen.items()):
                if ts < stale_grace:
                    del self._flow_last_seen[k]
                    self._flow_first_seen.pop(k, None)
            first_seen = {s.key: self._flow_first_seen.get(s.key, s.first_ms) for s in segs}
        return WindowView(segs=segs, new_endpoints=new_eps, end_ms=end, flow_first_seen=first_seen)
