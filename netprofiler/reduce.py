"""Reduce a 10-second window of flow segments into a numbers-free text block.

Two stages:
  1. `measure()` computes raw statistics (internal; never leaves the process).
  2. `describe()` maps each statistic to a named level via `levels` and renders
     the prose that becomes Jev's state.

The prose is ~700 tokens and describes shape only: concurrency, direction,
burst structure, size and inter-arrival distributions, idle gaps, endpoint
novelty and transport mix. No counts, timestamps or byte totals appear in it.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field, asdict

from . import levels as L
from .config import WINDOW_SECONDS
from .flows import FlowSeg

BIN_MS = 250  # burst/idle analysis resolution
TINY_PS = 100  # <= this is a "tiny" packet (acks, keystrokes, keepalives)
LARGE_PS = 1000  # >= this is a "full-size" data packet
ACK_PS = 64  # <= this is a payload-less ack; ignored for exchange-pattern analysis


@dataclass
class Measures:
    """Raw window statistics. Internal only."""

    flows: int = 0
    endpoints: int = 0
    new_endpoints: int = 0
    up_bytes: int = 0
    down_bytes: int = 0
    up_packets: int = 0
    down_packets: int = 0
    bytes_per_s: float = 0.0
    packets_per_s: float = 0.0
    mean_ps: float = 0.0
    ps_cv: float = 0.0
    tiny_frac: float = 0.0
    large_frac: float = 0.0
    mean_piat_ms: float = 0.0
    piat_cv: float = 0.0
    active_bin_frac: float = 0.0
    bursts: int = 0
    longest_burst_ms: float = 0.0
    typical_burst_ms: float = 0.0
    longest_gap_ms: float = 0.0
    gaps_over_1s: int = 0
    tcp_frac: float = 0.0
    udp_frac: float = 0.0
    mean_lifetime_ms: float = 0.0
    new_flow_frac: float = 0.0
    top_flow_share: float = 0.0
    up_bin_count_cv: float = 0.0  # variability of outbound packet counts across bins
    burst_gap_cv: float = -1.0  # variability of the gaps between bursts; -1 = fewer than two gaps
    dominant_dir_alternation: float = 0.0  # fraction of splt direction changes


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = statistics.fmean(values)
    if m <= 0:
        return 0.0
    return statistics.pstdev(values) / m


def measure(segs: list[FlowSeg], new_endpoints: int, end_ms: int, window_s: float = WINDOW_SECONDS, flow_first_seen: dict[str, int] | None = None) -> Measures:
    m = Measures()
    if not segs:
        m.new_endpoints = new_endpoints
        m.longest_gap_ms = window_s * 1000
        m.gaps_over_1s = 1
        return m

    start_ms = end_ms - int(window_s * 1000)
    keys = {s.key for s in segs}
    m.flows = len(keys)
    m.endpoints = len({s.endpoint for s in segs})
    m.new_endpoints = new_endpoints
    m.up_bytes = sum(s.up_bytes for s in segs)
    m.down_bytes = sum(s.down_bytes for s in segs)
    m.up_packets = sum(s.up_packets for s in segs)
    m.down_packets = sum(s.down_packets for s in segs)
    total_packets = m.up_packets + m.down_packets
    m.bytes_per_s = (m.up_bytes + m.down_bytes) / window_s
    m.packets_per_s = total_packets / window_s

    # Packet sizes: packet-weighted mean of per-segment means; distribution
    # tails from the per-packet SPLT samples (first 10 packets of every segment)
    if total_packets:
        m.mean_ps = sum(s.mean_ps * s.packets for s in segs) / total_packets
        seg_var = sum((s.stddev_ps**2 + (s.mean_ps - m.mean_ps) ** 2) * s.packets for s in segs) / total_packets
        m.ps_cv = math.sqrt(max(seg_var, 0.0)) / m.mean_ps if m.mean_ps > 0 else 0.0
    # Each segment's SPLT sample estimates that segment's tiny/large share;
    # weight by the segment's packet count so a 3000-packet download is not
    # outvoted by ten keepalive segments.
    tiny_w = large_w = tot_w = 0.0
    for s in segs:
        sample = [p for p in s.splt_ps if p > 0]
        if sample:
            tf = sum(1 for p in sample if p <= TINY_PS) / len(sample)
            lf = sum(1 for p in sample if p >= LARGE_PS) / len(sample)
        else:
            tf = 1.0 if s.mean_ps <= TINY_PS else 0.0
            lf = 1.0 if s.mean_ps >= LARGE_PS else 0.0
        tiny_w += tf * s.packets
        large_w += lf * s.packets
        tot_w += s.packets
    if tot_w:
        m.tiny_frac = tiny_w / tot_w
        m.large_frac = large_w / tot_w

    # Inter-arrival level: bidirectional, packet-weighted (a rate-like feature).
    multi = [s for s in segs if s.packets > 1]
    if multi:
        w = sum(s.packets - 1 for s in multi)
        m.mean_piat_ms = sum(s.mean_piat_ms * (s.packets - 1) for s in multi) / w
    # Regularity: judged per direction, because two interleaved streams make
    # bidirectional spacing alternate short/long however regular each one is.
    # Take the packet-weighted CV over both directions.
    cv_w = tot = 0.0
    for s in segs:
        for n, mean, sd in ((s.up_packets, s.up_mean_piat_ms, s.up_stddev_piat_ms), (s.down_packets, s.down_mean_piat_ms, s.down_stddev_piat_ms)):
            if n > 1 and mean > 0:
                cv_w += (sd / mean) * (n - 1)
                tot += n - 1
    m.piat_cv = cv_w / tot if tot else 0.0

    # Burst / idle structure: spread each segment's packets evenly over its
    # lifetime into fixed bins, then look at runs of active and empty bins.
    n_bins = max(1, int(window_s * 1000 / BIN_MS))
    bins = [0.0] * n_bins
    up_bins = [0.0] * n_bins
    for s in segs:
        a = max(s.first_ms, start_ms)
        b = min(max(s.last_ms, a), end_ms)
        # only the part of the segment inside the window carries packets here
        frac = (b - a) / s.duration_ms if s.duration_ms > 0 else 1.0
        frac = min(1.0, max(0.0, frac)) if s.duration_ms > 0 else 1.0
        i0 = min(n_bins - 1, max(0, (a - start_ms) // BIN_MS))
        i1 = min(n_bins - 1, max(0, (b - start_ms) // BIN_MS))
        span = i1 - i0 + 1
        for i in range(i0, i1 + 1):
            bins[i] += s.packets * frac / span
            up_bins[i] += s.up_packets * frac / span
    active = [b >= 0.5 for b in bins]
    m.active_bin_frac = sum(active) / n_bins
    runs: list[int] = []
    gaps: list[int] = []
    cur, cur_active = 0, active[0]
    for a in active:
        if a == cur_active:
            cur += 1
        else:
            (runs if cur_active else gaps).append(cur)
            cur, cur_active = 1, a
    (runs if cur_active else gaps).append(cur)
    m.bursts = len(runs)
    m.longest_burst_ms = max(runs, default=0) * BIN_MS
    m.typical_burst_ms = statistics.median(runs) * BIN_MS if runs else 0.0
    m.longest_gap_ms = max(gaps, default=0) * BIN_MS
    m.gaps_over_1s = sum(1 for g in gaps if g * BIN_MS >= 1000)
    m.up_bin_count_cv = _cv(up_bins)
    # gaps that separate bursts (not the leading/trailing edge of the window)
    inner_gaps = gaps[1:-1] if len(gaps) >= 2 and not active[0] and not active[-1] else (gaps[1:] if gaps and not active[0] else (gaps[:-1] if gaps and not active[-1] else gaps))
    m.burst_gap_cv = _cv([float(g) for g in inner_gaps]) if len(inner_gaps) >= 2 else -1.0

    # Transport, lifetimes, churn, concentration
    tcp = sum(s.packets for s in segs if s.protocol == 6)
    udp = sum(s.packets for s in segs if s.protocol == 17)
    if total_packets:
        m.tcp_frac = tcp / total_packets
        m.udp_frac = udp / total_packets
    first_seen = flow_first_seen or {}
    per_key_first = {}
    per_key_last = {}
    per_key_bytes: dict[str, int] = {}
    per_key_syn: dict[str, int] = {}
    for s in segs:
        per_key_first[s.key] = min(per_key_first.get(s.key, s.first_ms), s.first_ms, first_seen.get(s.key, s.first_ms))
        per_key_last[s.key] = max(per_key_last.get(s.key, s.last_ms), s.last_ms)
        per_key_bytes[s.key] = per_key_bytes.get(s.key, 0) + s.bytes
        per_key_syn[s.key] = per_key_syn.get(s.key, 0) + s.syn
    m.mean_lifetime_ms = statistics.fmean(per_key_last[k] - per_key_first[k] for k in keys)
    # a flow is "new" if it handshook in the window or its first segment ever started in it
    opened = sum(1 for k in keys if per_key_syn[k] > 0 or per_key_first[k] >= start_ms)
    m.new_flow_frac = opened / m.flows
    tot = sum(per_key_bytes.values())
    m.top_flow_share = max(per_key_bytes.values()) / tot if tot else 0.0

    # Direction alternation in the first packets of each flow: request/response
    # ping-pong vs one-way streaming. Pure acks are skipped so a download with
    # an ack every other packet does not read as ping-pong.
    changes, pairs = 0, 0
    for s in segs:
        d = [x for x, ps in zip(s.splt_direction, s.splt_ps) if x in (0, 1) and ps > ACK_PS]
        for i in range(1, len(d)):
            pairs += 1
            if d[i] != d[i - 1]:
                changes += 1
    m.dominant_dir_alternation = changes / pairs if pairs else 0.0
    return m


@dataclass
class Shape:
    """Named levels only. This is what gets rendered for Jev."""

    concurrency: str
    endpoints: str
    new_endpoints: str
    volume: str
    packet_rate: str
    direction_bytes: str
    direction_packets: str
    occupancy: str
    burst_count: str
    burst_length: str
    typical_burst: str
    idle_gap: str
    idle_gap_count: str
    burst_spacing: str
    packet_size: str
    size_spread: str
    size_mix: str
    inter_arrival: str
    regularity: str
    cadence: str
    exchange_pattern: str
    outbound_evenness: str
    transport: str
    lifetime: str
    churn: str
    concentration: str
    trend_volume: str
    trend_flows: str
    trend_packets: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def describe(m: Measures, prev: Measures | None = None) -> Shape:
    alt = m.dominant_dir_alternation
    if m.flows == 0:
        exchange = "no exchanges"
    elif alt > 0.6:
        exchange = "tight request/response ping-pong"
    elif alt > 0.3:
        exchange = "requests answered by multi-packet replies"
    else:
        exchange = "one-way streaming with sparse acknowledgements"
    ev = m.up_bin_count_cv
    if m.up_packets == 0:
        evenness = "no outbound traffic"
    elif ev < 0.4:
        evenness = "outbound packets spread evenly over time"
    elif ev < 1.0:
        evenness = "outbound packets clustered into groups"
    else:
        evenness = "outbound packets concentrated in a few spikes"
    p = prev or Measures()
    total_bytes = m.up_bytes + m.down_bytes
    return Shape(
        concurrency=L.flow_count(m.flows),
        endpoints=L.endpoint_count(m.endpoints),
        new_endpoints=L.new_endpoint_count(m.new_endpoints),
        volume=L.volume(m.bytes_per_s),
        packet_rate=L.packet_rate(m.packets_per_s),
        direction_bytes=L.direction(m.up_bytes / total_bytes) if total_bytes else "no bytes moved",
        direction_packets=L.packet_direction(m.up_packets / (m.up_packets + m.down_packets)) if (m.up_packets + m.down_packets) else "no packets",
        occupancy=L.occupancy(m.active_bin_frac),
        burst_count=L.burst_count(m.bursts),
        burst_length=L.burst_length(m.longest_burst_ms),
        typical_burst=L.burst_length(m.typical_burst_ms),
        idle_gap=L.idle_gap(m.longest_gap_ms),
        idle_gap_count=L.idle_gap_count(m.gaps_over_1s),
        burst_spacing=L.burst_spacing(m.burst_gap_cv, m.bursts),
        packet_size=L.packet_size(m.mean_ps) if m.flows else "no packets",
        size_spread=L.size_spread(m.ps_cv),
        size_mix=L.size_mix(m.tiny_frac, m.large_frac) if m.flows else "no packets",
        inter_arrival=L.inter_arrival(m.mean_piat_ms) if m.mean_piat_ms > 0 else "no measurable spacing",
        regularity=L.regularity(m.piat_cv) if m.mean_piat_ms > 0 else "no measurable rhythm",
        cadence=L.human_cadence(m.mean_piat_ms, m.piat_cv, m.tiny_frac) if m.flows else "no activity",
        exchange_pattern=exchange,
        outbound_evenness=evenness,
        transport=L.transport_mix(m.tcp_frac, m.udp_frac) if m.flows else "none",
        lifetime=L.flow_lifetime(m.mean_lifetime_ms) if m.flows else "none",
        churn=L.churn(m.new_flow_frac) if m.flows else "no connections",
        concentration=L.concentration(m.top_flow_share) if m.flows else "none",
        trend_volume=L.trend(p.bytes_per_s, m.bytes_per_s),
        trend_flows=L.trend(p.flows, m.flows),
        trend_packets=L.trend(p.packets_per_s, m.packets_per_s),
    )


def render(s: Shape) -> str:
    """Prose block for Jev. Every clause is a level name; no digits appear."""
    lines = [
        "Traffic shape on one virtual machine's network link, observed over a short rolling window a few seconds long. "
        "Only shape is described: nothing about content, addresses, ports or amounts.",
        "",
        "CONCURRENCY. Active flows in the window: {concurrency}. Distinct remote endpoints: {endpoints}. "
        "Endpoints contacted for the first time this session: {new_endpoints}. Connection churn: {churn}. "
        "Flow lifetimes are {lifetime}. Traffic is {concentration}.".format(**s.as_dict()),
        "",
        "VOLUME AND DIRECTION. Overall throughput level: {volume}. Packet rate level: {packet_rate}. "
        "By bytes the link is {direction_bytes}; by packet count it shows {direction_packets}. "
        "Exchange pattern within flows: {exchange_pattern}.".format(**s.as_dict()),
        "",
        "BURST STRUCTURE. The window is {occupancy}, with {burst_count} distinct bursts. The longest burst is {burst_length} "
        "and the typical burst is {typical_burst}. There are {idle_gap}; count of pauses long enough to notice: {idle_gap_count}. "
        "Bursts arrive {burst_spacing}. Outbound timing: {outbound_evenness}.".format(**s.as_dict()),
        "",
        "PACKET SIZES. Typical packet size is {packet_size}; the size distribution is {size_spread} and {size_mix}.".format(**s.as_dict()),
        "",
        "INTER-ARRIVAL TIMES. Packets arrive {inter_arrival}; spacing is {regularity}. Cadence reads as {cadence}.".format(**s.as_dict()),
        "",
        "TRANSPORT. Packets are {transport}.".format(**s.as_dict()),
        "",
        "TREND VERSUS THE PREVIOUS WINDOW. Volume is {trend_volume}; the number of flows is {trend_flows}; packet rate is {trend_packets}.".format(**s.as_dict()),
        "",
        "LEVEL GLOSSARY. Throughput and packet-rate levels run negligible, low, moderate, high, very high. "
        "Burst lengths run brief, short, sustained, continuous. Occupancy runs silent, sporadic, intermittent, mostly active, continuously active. "
        "Packet sizes run tiny, small, medium, large, MTU-sized. Inter-arrival runs back-to-back, rapid, steady, paced, slow, very sparse. "
        "Trends run dropped to nothing, falling sharply, falling, steady, rising, rising sharply, started from nothing.",
    ]
    return "\n".join(lines)


def estimate_tokens(text: str) -> int:
    """Rough tokenizer-free estimate used only for sanity checks."""
    return max(1, round(len(text) / 4))


def assert_numbers_free(text: str) -> None:
    """Guard: the rendered state must contain no digits."""
    if any(ch.isdigit() for ch in text):
        raise ValueError("rendered shape contains digits")
