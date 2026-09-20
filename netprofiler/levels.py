"""Number -> named level. This is the only place raw quantities are looked at
before they are turned into words; nothing numeric crosses to the model.

Every function takes a number and returns a short label. Thresholds are
deliberately coarse: the point is to describe *shape*, not to measure.
"""

from __future__ import annotations


def _bucket(x: float, edges: list[tuple[float, str]], top: str) -> str:
    for edge, label in edges:
        if x < edge:
            return label
    return top


def flow_count(n: int) -> str:
    return _bucket(n, [(1, "none"), (2, "a single flow"), (5, "a few"), (15, "moderate"), (40, "many")], "a very large number")


def endpoint_count(n: int) -> str:
    return _bucket(n, [(1, "none"), (2, "one"), (4, "a few"), (10, "several")], "many")


def new_endpoint_count(n: int) -> str:
    return _bucket(n, [(1, "none"), (2, "one"), (4, "a few"), (10, "several")], "a burst of many")


def direction(up_fraction: float) -> str:
    """up_fraction = upstream bytes / total bytes (downstream qube -> internet)."""
    return _bucket(
        up_fraction,
        [
            (0.05, "almost entirely download"),
            (0.2, "download-dominated"),
            (0.4, "download-leaning"),
            (0.6, "roughly balanced"),
            (0.8, "upload-leaning"),
            (0.95, "upload-dominated"),
        ],
        "almost entirely upload",
    )


def packet_direction(up_fraction: float) -> str:
    """Same idea but by packet count; separates request/ack patterns from bulk."""
    return _bucket(
        up_fraction,
        [(0.25, "mostly inbound packets"), (0.45, "more inbound than outbound"), (0.55, "packet counts balanced"), (0.75, "more outbound than inbound")],
        "mostly outbound packets",
    )


def volume(bytes_per_second: float) -> str:
    """Throughput level over the window (never the number itself)."""
    return _bucket(
        bytes_per_second,
        [(200, "negligible"), (5_000, "low"), (100_000, "moderate"), (1_000_000, "high")],
        "very high",
    )


def packet_rate(pps: float) -> str:
    return _bucket(pps, [(0.5, "near-zero"), (5, "low"), (50, "moderate"), (500, "high")], "very high")


def packet_size(mean_bytes: float) -> str:
    return _bucket(mean_bytes, [(90, "tiny"), (200, "small"), (600, "medium"), (1200, "large")], "MTU-sized")


def size_spread(cv: float) -> str:
    """Coefficient of variation of packet sizes."""
    return _bucket(cv, [(0.15, "uniform"), (0.5, "narrow"), (1.0, "mixed")], "widely spread")


def size_mix(small_frac: float, large_frac: float) -> str:
    if small_frac > 0.7:
        return "dominated by tiny packets"
    if large_frac > 0.7:
        return "dominated by full-size packets"
    if small_frac > 0.3 and large_frac > 0.3:
        return "bimodal: tiny control packets alongside full-size data packets"
    if small_frac < 0.15 and large_frac < 0.15:
        return "almost all mid-sized packets"
    if large_frac > small_frac:
        return "leaning to large packets with some small ones"
    return "leaning to small packets with some large ones"


def inter_arrival(mean_ms: float) -> str:
    return _bucket(mean_ms, [(2, "back-to-back"), (20, "rapid"), (100, "steady"), (500, "paced"), (2000, "slow")], "very sparse")


def regularity(cv: float) -> str:
    """Coefficient of variation of inter-arrival times."""
    return _bucket(cv, [(0.3, "clock-like regular"), (0.8, "fairly regular"), (1.5, "irregular")], "highly bursty")


def burst_count(n: int) -> str:
    return _bucket(n, [(1, "no"), (2, "a single"), (4, "a few"), (8, "several")], "many")


def burst_length(ms: float) -> str:
    return _bucket(ms, [(300, "brief"), (1500, "short"), (5000, "sustained")], "continuous")


def occupancy(active_fraction: float) -> str:
    """Fraction of time bins with any packets."""
    return _bucket(
        active_fraction,
        [(0.02, "silent"), (0.15, "sporadic"), (0.4, "intermittent"), (0.8, "mostly active")],
        "continuously active",
    )


def idle_gap(ms: float) -> str:
    return _bucket(ms, [(250, "no idle gaps"), (1000, "brief idle gaps"), (3000, "noticeable idle gaps"), (7000, "long idle gaps")], "almost entirely idle")


def idle_gap_count(n: int) -> str:
    return _bucket(n, [(1, "none"), (2, "one"), (4, "a few")], "many")


def transport_mix(tcp_frac: float, udp_frac: float) -> str:
    if tcp_frac > 0.9:
        return "almost all TCP"
    if udp_frac > 0.9:
        return "almost all UDP"
    if tcp_frac > 0.6:
        return "mostly TCP with some UDP"
    if udp_frac > 0.6:
        return "mostly UDP with some TCP"
    return "an even TCP/UDP mix"


def flow_lifetime(mean_ms: float) -> str:
    return _bucket(mean_ms, [(200, "very short-lived"), (1500, "short-lived"), (6000, "medium-lived")], "long-lived")


def churn(new_flows_frac: float) -> str:
    """Fraction of flows in the window that opened during the window."""
    return _bucket(new_flows_frac, [(0.05, "no new connections"), (0.3, "few new connections"), (0.7, "steady connection churn")], "almost all connections are new")


def concentration(top_share: float) -> str:
    """Share of bytes carried by the single largest flow."""
    return _bucket(top_share, [(0.3, "spread across many flows"), (0.6, "led by one flow with others"), (0.9, "concentrated in one dominant flow")], "a single flow carries nearly everything")


def trend(previous: float, current: float) -> str:
    """Compare two like quantities; returns a word, never the values."""
    if previous <= 0 and current <= 0:
        return "still quiet"
    if previous <= 0:
        return "started from nothing"
    if current <= 0:
        return "dropped to nothing"
    ratio = current / previous
    return _bucket(ratio, [(0.33, "falling sharply"), (0.75, "falling"), (1.33, "steady"), (3.0, "rising")], "rising sharply")


def human_cadence(mean_piat_ms: float, cv: float, tiny_frac: float) -> str:
    """Heuristic description of whether timing looks like a person's hands."""
    if tiny_frac > 0.5 and 50 <= mean_piat_ms <= 600 and cv > 0.4:
        return "keystroke-like: tiny packets at an uneven human rhythm"
    if cv < 0.3 and mean_piat_ms < 100:
        return "machine-like: even pacing"
    if cv > 1.2 and mean_piat_ms > 300:
        return "click-like: bursts separated by pauses"
    return "no distinct human rhythm"
