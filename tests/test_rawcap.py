import random

from netprofiler.rawcap import Packet, drop_probes, encode, estimate_tokens, parse_line

LOCAL = {"10.137.0.10"}


def test_parse_tcpdump_lines():
    p = parse_line("1758412345.123456 IP 10.137.0.10.51000 > 203.0.113.5.443: tcp 1448", LOCAL)
    assert p and p.out and p.proto == 6 and p.local_port == 51000 and p.remote_port == 443 and p.length == 1448
    q = parse_line("1758412345.223456 IP 203.0.113.5.443 > 10.137.0.10.51000: tcp 0", LOCAL)
    assert q and not q.out and q.length == 0 and q.tuple4 == p.tuple4
    u = parse_line("1758412346.000000 IP 10.137.0.10.5555 > 10.139.1.1.53: UDP, length 56", LOCAL)
    assert u and u.proto == 17 and u.remote_port == 53 and u.length == 56
    assert parse_line("1758412346.000000 IP 10.137.0.10 > 8.8.8.8: ICMP echo request, id 1, seq 1, length 64", LOCAL) is None
    assert parse_line("garbage", LOCAL) is None
    assert parse_line("1758412346.000000 IP 1.1.1.1.53 > 2.2.2.2.5555: UDP, length 56", LOCAL) is None  # not ours


def _pk(t, out, lport, rip, rport, length, proto=6):
    return Packet(t, out, proto, lport, rip, rport, length)


def test_probe_filter_and_verbatim_encoding():
    pk = [
        _pk(1000, True, 40000, "203.0.113.5", 443, 517),
        _pk(1030, False, 40000, "203.0.113.5", 443, 1448),
        _pk(1500, False, 27017, "185.1.1.1", 47173, 0),  # scan: inbound only
    ]
    kept, dropped = drop_probes(pk)
    assert dropped == 1 and len(kept) == 2
    text, stats = encode(pk, 1000, budget_tokens=2000)
    assert stats["level"] == 0 and stats["probes_dropped"] == 1
    assert "f1 tcp e1:443 acks=0" in text and "\n+0 f1> 517\n+30 f1< 1448" in text and "summary: 1 flows to 1 endpoints" in text
    assert "203.0.113.5" not in text and "185.1.1.1" not in text  # addresses never appear


def test_encoding_ladder_respects_budget():
    random.seed(3)
    # a 5 s download: 6000 identical inbound packets plus acks, and a chat flow
    pk = []
    t = 0
    for i in range(6000):
        t += 1
        pk.append(_pk(t, False, 40001, "198.51.100.7", 443, 1448))
        if i % 2 == 0:
            pk.append(_pk(t, True, 40001, "198.51.100.7", 443, 0))
    for k in range(12):
        pk.append(_pk(400 * k + 7, True, 40002, "203.0.113.9", 6697, random.randint(20, 60)))
    pk.sort(key=lambda p: p.t_ms)
    verbatim, s0 = encode(pk, 0, budget_tokens=10**9)
    assert s0["level"] == 0 and estimate_tokens(verbatim) > 20000
    for budget in (12000, 4000, 1500, 600):
        text, stats = encode(pk, 0, budget_tokens=budget)
        assert estimate_tokens(text) <= budget, (budget, estimate_tokens(text), stats)
    rle, s1 = encode(pk, 0, budget_tokens=12000)
    assert s1["level"] in (1, 2) and ("x" in rle or "p " in rle)
    assert "f2" in rle  # the small chat flow survives compression
