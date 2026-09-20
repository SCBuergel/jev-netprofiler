import math
import random

import pytest

from netprofiler import levels as L
from netprofiler.analysis import VifAnalysis, anonymity_set, identifying_bits, shannon_entropy_bits
from netprofiler.catalog import load_catalog
from netprofiler.config import CATALOG_PATH_DEFAULT
from netprofiler.flows import FlowSeg, RollingWindow
from netprofiler.jev import Answer, build_questions
from netprofiler.reduce import assert_numbers_free, describe, estimate_tokens, measure, render

END = 1_700_000_010_000
START = END - 10_000


def seg(key, first, last, up_p, down_p, up_b, down_b, mean_ps=500, piat=50.0, proto=6, syn=1, endpoint=None, splt_ps=None, splt_dir=None):
    return FlowSeg(
        key=key,
        endpoint=endpoint or key.split(">")[1],
        first_ms=first,
        last_ms=last,
        up_packets=up_p,
        down_packets=down_p,
        up_bytes=up_b,
        down_bytes=down_b,
        mean_ps=mean_ps,
        stddev_ps=mean_ps * 0.2,
        min_ps=60,
        max_ps=1500,
        mean_piat_ms=piat,
        stddev_piat_ms=piat * 0.5,
        max_piat_ms=piat * 4,
        up_mean_piat_ms=piat * 2,
        up_stddev_piat_ms=piat,
        down_mean_piat_ms=piat * 2,
        down_stddev_piat_ms=piat,
        protocol=proto,
        syn=syn,
        fin=0,
        rst=0,
        splt_direction=splt_dir or [0, 1] * 5,
        splt_ps=splt_ps or [mean_ps] * 10,
        splt_piat_ms=[int(piat)] * 10,
    )


def bulk_download():
    return [seg("a>1.1.1.1:443/6", START + 2000 * i, START + 2000 * (i + 1), 300, 8000, 20_000, 11_000_000, mean_ps=1400, piat=0.3, syn=int(i == 0), splt_ps=[1450] * 10) for i in range(5)]


def ssh_typing():
    out = []
    for i in range(5):
        out.append(seg("b>2.2.2.2:22/6", START + 2000 * i, START + 2000 * (i + 1), 12, 12, 1200, 1300, mean_ps=85, piat=250.0, syn=int(i == 0), splt_ps=[80, 90, 70, 88, 95, 84, 79, 91, 86, 90]))
    return out


def test_empty_window_renders_and_has_no_numbers():
    m = measure([], 0, END)
    s = describe(m)
    text = render(s)
    assert_numbers_free(text)
    assert s.concurrency == "none"
    assert s.occupancy == "silent"
    assert "almost entirely idle" in s.idle_gap


def test_bulk_download_shape():
    m = measure(bulk_download(), 1, END)
    s = describe(m)
    assert s.direction_bytes == "almost entirely download"
    assert s.packet_size == "MTU-sized"
    assert s.volume in ("high", "very high")
    assert s.occupancy == "continuously active"
    assert s.concurrency == "a single flow"
    assert s.concentration == "a single flow carries nearly everything"
    text = render(s)
    assert_numbers_free(text)


def test_ssh_shape_reads_as_keystrokes():
    m = measure(ssh_typing(), 0, END)
    s = describe(m)
    assert s.packet_size == "tiny"
    assert s.direction_bytes == "roughly balanced"
    assert "keystroke" in s.cadence
    assert s.exchange_pattern == "tight request/response ping-pong"


def test_render_token_budget():
    for segs in ([], bulk_download(), ssh_typing()):
        text = render(describe(measure(segs, 2, END)))
        n = estimate_tokens(text)
        assert 350 <= n <= 900, n


def test_trend_words():
    prev = measure([], 0, END - 2000)
    cur = measure(bulk_download(), 0, END)
    s = describe(cur, prev)
    assert s.trend_volume == "started from nothing"
    s2 = describe(prev, cur)
    assert s2.trend_volume == "dropped to nothing"


def test_burst_and_gap_detection():
    # two short bursts separated by a long gap
    segs = [
        seg("c>3.3.3.3:443/6", START, START + 500, 10, 30, 2000, 30000),
        seg("d>3.3.3.3:443/6", START + 7000, START + 7500, 10, 30, 2000, 30000, syn=1),
    ]
    m = measure(segs, 0, END)
    assert m.bursts == 2
    assert m.longest_gap_ms >= 6000
    s = describe(m)
    assert s.burst_count == "a few" or s.burst_count == "a single"
    assert "long idle gaps" in s.idle_gap


def test_no_digits_in_all_level_words():
    # every label from levels must be digit-free, including the sweep of edges
    for fn in (L.flow_count, L.endpoint_count, L.new_endpoint_count, L.burst_count, L.idle_gap_count):
        for n in range(0, 100):
            assert not any(c.isdigit() for c in fn(n))
    for fn in (L.direction, L.packet_direction, L.size_spread, L.regularity, L.occupancy, L.churn, L.concentration):
        for x in [i / 20 for i in range(0, 41)]:
            assert not any(c.isdigit() for c in fn(x))
    for fn in (L.volume, L.packet_rate, L.packet_size, L.inter_arrival, L.burst_length, L.idle_gap, L.flow_lifetime):
        for x in [0, 1, 10, 100, 1000, 10_000, 10_000_000]:
            assert not any(c.isdigit() for c in fn(x))


def test_rolling_window_prunes_and_counts_new_endpoints():
    w = RollingWindow(seconds=10)
    w.add(seg("a>1.1.1.1:443/6", START - 20000, START - 15000, 1, 1, 1, 1))  # too old
    w.add(seg("b>2.2.2.2:443/6", START + 1000, START + 2000, 1, 1, 1, 1))
    w.add(seg("c>2.2.2.2:443/6", START + 3000, START + 4000, 1, 1, 1, 1))  # same endpoint
    segs, new_eps, _ = w.snapshot(at_ms=END)
    assert len(segs) == 2
    assert new_eps == 1  # 1.1.1.1 was new but has aged out of the window


def test_entropy_and_bits():
    n = 30
    uniform = {str(i): 1 / n for i in range(n)}
    assert math.isclose(shannon_entropy_bits(uniform), math.log2(n))
    assert identifying_bits(uniform, n) == pytest.approx(0.0)
    peaked = {str(i): (1.0 if i == 0 else 0.0) for i in range(n)}
    assert identifying_bits(peaked, n) == pytest.approx(math.log2(n))
    assert anonymity_set(8_000_000_000, 30) == pytest.approx(8_000_000_000 / 2**30)
    assert anonymity_set(10, 40) == 1.0


def _answer(top, n=30, p_top=0.8, nouls=None):
    keys = [f"k{i}" for i in range(n)]
    probs = {k: (1 - p_top) / (n - 1) for k in keys}
    probs[top] = p_top
    return Answer(probabilities=probs, top=top, confidence=0.7, intensity=0.5, interactivity=0.4, nouls=nouls or {"just_started": 0.1, "just_ended": 0.1, "automated": 0.2, "someone_is_typing": 0.1}, latency_s=0.1)


def test_analysis_smoothing_and_episode_bits():
    a = VifAnalysis(n_options=30, population=8_000_000_000)
    a.ingest(_answer("k0"), 0.6)
    first_bits = a.total_bits
    assert first_bits > 0
    assert a.smoothed["k0"] == pytest.approx(0.4 * 0.8)  # alpha=0.4 from zero
    a.ingest(_answer("k0"), 0.6)  # same episode, same confidence: nothing new
    assert a.total_bits == pytest.approx(first_bits)
    a.ingest(_answer("k0", p_top=0.95), 0.6)  # same episode, sharper: only the gain
    assert a.total_bits == pytest.approx(a.tick_bits)
    before = a.total_bits
    a.ingest(_answer("k1"), 0.6)  # a single flap: smoothed top is still k0, no new episode
    assert a.episodes == 1
    assert a.total_bits == pytest.approx(before)
    for _ in range(3):  # k1 persists: smoothed top flips, a new episode opens once
        a.ingest(_answer("k1"), 0.6)
    assert a.episodes == 2
    assert a.total_bits > before
    assert a.raw_total_bits > a.total_bits
    assert a.top_smoothed(1)[0][0] == "k1"


def test_events_fire_on_rising_edge_only():
    a = VifAnalysis(n_options=30, population=1000)
    ev = a.ingest(_answer("k0", nouls={"just_started": 0.9, "just_ended": 0.0, "automated": 0.0, "someone_is_typing": 0.0}), 0.6)
    assert [e.kind for e in ev] == ["just_started"]
    ev = a.ingest(_answer("k0", nouls={"just_started": 0.9, "just_ended": 0.0, "automated": 0.0, "someone_is_typing": 0.0}), 0.6)
    assert ev == []
    ev = a.ingest(_answer("k0", nouls={"just_started": 0.1, "just_ended": 0.8, "automated": 0.0, "someone_is_typing": 0.0}), 0.6)
    assert [e.kind for e in ev] == ["just_ended"]


def test_catalog_and_questions():
    cat = load_catalog(CATALOG_PATH_DEFAULT)
    assert len(cat) == 11
    assert {a.key for a in cat} >= {"idle", "unknown"}
    q = build_questions(cat)
    assert set(q) == {"activity", "intensity", "interactivity", "just_started", "just_ended", "automated", "someone_is_typing"}
    assert len(q["activity"].criteria) == 11


class _FakeNFlow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, s2d_syn=0, d2s_syn=0, s2d_bytes=100, d2s_bytes=1000):
        self.src_ip, self.dst_ip, self.src_port, self.dst_port = src_ip, dst_ip, src_port, dst_port
        self.protocol = 6
        self.src2dst_syn_packets, self.dst2src_syn_packets = s2d_syn, d2s_syn
        self.src2dst_packets, self.dst2src_packets = 10, 20
        self.src2dst_bytes, self.dst2src_bytes = s2d_bytes, d2s_bytes
        self.bidirectional_first_seen_ms, self.bidirectional_last_seen_ms = START, START + 1000
        self.bidirectional_mean_ps = self.bidirectional_stddev_ps = 500.0
        self.bidirectional_min_ps = self.bidirectional_max_ps = 500
        self.bidirectional_mean_piat_ms = self.bidirectional_stddev_piat_ms = self.bidirectional_max_piat_ms = 10.0
        self.src2dst_mean_piat_ms = self.src2dst_stddev_piat_ms = 20.0
        self.dst2src_mean_piat_ms = self.dst2src_stddev_piat_ms = 20.0
        self.bidirectional_syn_packets = s2d_syn + d2s_syn
        self.bidirectional_fin_packets = self.bidirectional_rst_packets = 0
        self.splt_direction, self.splt_ps, self.splt_piat_ms = [0, 1, 1], [100, 1400, 1400], [0, 1, 1]


def test_orientation_is_stable_across_active_timeout_cuts():
    from netprofiler.capture import Orienter, nflow_to_seg

    o = Orienter()
    first = nflow_to_seg(_FakeNFlow("10.137.0.10", "198.51.100.7", 40001, 443, s2d_syn=1, d2s_syn=1, s2d_bytes=100, d2s_bytes=10_000), o)
    # nfstream re-emits the continuation with the server as src
    cont = nflow_to_seg(_FakeNFlow("198.51.100.7", "10.137.0.10", 443, 40001, s2d_bytes=10_000, d2s_bytes=100), o)
    assert first.key == cont.key
    assert first.endpoint == cont.endpoint == "198.51.100.7:443/6"
    assert first.up_bytes == cont.up_bytes == 100
    assert first.down_bytes == cont.down_bytes == 10_000
    assert cont.splt_direction == [1, 0, 0]  # flipped back to local-relative
    # private/public heuristic when there is no SYN and no cache
    udp = nflow_to_seg(_FakeNFlow("8.8.8.8", "10.137.0.10", 53, 5555, s2d_bytes=500, d2s_bytes=60), Orienter())
    assert udp.up_bytes == 60 and udp.down_bytes == 500


def test_local_net_override_beats_heuristics():
    from netprofiler.capture import Orienter, nflow_to_seg

    # both sides private, no SYN: heuristic alone would pick src; override picks the qube side
    seg = nflow_to_seg(_FakeNFlow("10.137.99.1", "10.137.99.2", 8080, 5555, s2d_bytes=9000, d2s_bytes=100), Orienter(["10.137.99.2/32"]))
    assert seg.endpoint == "10.137.99.1:8080/6"
    assert seg.up_bytes == 100 and seg.down_bytes == 9000


def test_heartbeat_flows_are_filtered():
    from netprofiler.capture import is_heartbeat
    from netprofiler.config import HEARTBEAT_GROUP, HEARTBEAT_PORT

    hb = _FakeNFlow("10.137.0.10", HEARTBEAT_GROUP, 40000, HEARTBEAT_PORT)
    hb.protocol = 17
    assert is_heartbeat(hb)
    assert not is_heartbeat(_FakeNFlow("10.137.0.10", "1.1.1.1", 40000, HEARTBEAT_PORT))


def test_own_traffic_and_shared_flow_filters():
    import time as _t
    from netprofiler.capture import OwnTraffic, SharedFlows, nflow_to_seg, Orienter

    own = OwnTraffic(api_host="localhost")
    own._api_ips = {"198.51.100.9"}
    own._seen[(6, 40001, "203.0.113.5:443/6")] = _t.time()
    mine = nflow_to_seg(_FakeNFlow("10.137.0.10", "203.0.113.5", 40001, 443, s2d_syn=1), Orienter(["10.137.0.10/32"]))
    api = nflow_to_seg(_FakeNFlow("10.137.0.10", "198.51.100.9", 40002, 443, s2d_syn=1), Orienter(["10.137.0.10/32"]))
    other = nflow_to_seg(_FakeNFlow("10.137.0.10", "203.0.113.5", 40003, 443, s2d_syn=1), Orienter(["10.137.0.10/32"]))
    assert mine.local_port == 40001 and mine.tuple4 == (6, 40001, "203.0.113.5:443/6")
    assert own.is_own(mine) and own.is_own(api) and not own.is_own(other)

    shared = SharedFlows()
    shared.note(other)
    assert shared.seen(other) and not shared.seen(mine)


def test_probe_filter():
    from netprofiler.capture import is_probe

    scan = _FakeNFlow("185.139.214.221", "10.137.0.10", 47173, 27017, s2d_syn=1)
    scan.src2dst_packets, scan.dst2src_packets, scan.bidirectional_rst_packets = 1, 1, 1
    scan.bidirectional_packets = 2
    assert is_probe(scan, local_is_src=False)
    login = _FakeNFlow("203.0.113.5", "10.137.0.10", 50000, 22, s2d_syn=1)
    login.bidirectional_packets = 400
    assert not is_probe(login, local_is_src=False)
    ping = _FakeNFlow("3.249.179.191", "10.137.0.10", 0, 0)
    ping.protocol = 1
    assert is_probe(ping, local_is_src=False)
    udp_lone = _FakeNFlow("198.51.100.1", "10.137.0.10", 5000, 5060)
    udp_lone.protocol, udp_lone.bidirectional_packets, udp_lone.src2dst_packets, udp_lone.dst2src_packets = 17, 1, 1, 0
    assert is_probe(udp_lone, local_is_src=False)
    own_udp = _FakeNFlow("10.137.0.10", "198.51.100.1", 5000, 53)
    own_udp.protocol, own_udp.bidirectional_packets = 17, 2
    assert not is_probe(own_udp, local_is_src=True)


def test_burst_spacing_levels():
    # four bursts 2 s apart -> regular; then uneven -> irregular
    regular = [seg(f"r{i}>1.1.1.1:443/6", START + 2000 * i, START + 2000 * i + 300, 5, 5, 500, 500) for i in range(4)]
    m = measure(regular, 0, END)
    assert m.bursts == 4 and 0 <= m.burst_gap_cv < 0.25
    assert "clock-like" in describe(m).burst_spacing
    uneven = [seg(f"u{i}>1.1.1.1:443/6", START + t, START + t + 300, 5, 5, 500, 500) for i, t in enumerate((0, 700, 4200, 5000, 9000))]
    m2 = measure(uneven, 0, END)
    assert m2.burst_gap_cv >= 0.6
    assert "irregular" in describe(m2).burst_spacing
