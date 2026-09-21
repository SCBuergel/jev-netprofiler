import random
import re

from netprofiler.anon import endpoint_id, flow_id
from netprofiler.rawcap import Packet, drop_probes, encode, estimate_tokens, parse_line

LOCAL = {"10.137.0.10"}


def test_parse_tcpdump_lines():
    p = parse_line("1758412345.123456 IP 10.137.0.10.51000 > 203.0.113.5.443: tcp 1448", LOCAL)
    assert p and p.out and p.proto == 6 and p.length == 1448
    assert p.flow == flow_id(6, 51000, "203.0.113.5", 443) and p.endpoint == endpoint_id(6, "203.0.113.5", 443)
    q = parse_line("1758412345.223456 IP 203.0.113.5.443 > 10.137.0.10.51000: tcp 0", LOCAL)
    assert q and not q.out and q.length == 0 and q.tuple4 == p.tuple4
    u = parse_line("1758412346.000000 IP 10.137.0.10.5555 > 10.139.1.1.53: UDP, length 56", LOCAL)
    assert u and u.proto == 17 and u.length == 56
    for pk in (p, q, u):  # only 16-hex-char digests are stored, no address or port fields
        assert re.fullmatch(r"[0-9a-f]{16}", pk.flow) and re.fullmatch(r"[0-9a-f]{16}", pk.endpoint)
        assert pk.label is None
        assert not hasattr(pk, "remote_ip") and not hasattr(pk, "remote_port") and not hasattr(pk, "local_port")
    assert parse_line("1758412346.000000 IP 10.137.0.10 > 8.8.8.8: ICMP echo request, id 1, seq 1, length 64", LOCAL) is None
    assert parse_line("garbage", LOCAL) is None
    assert parse_line("1758412346.000000 IP 1.1.1.1.53 > 2.2.2.2.5555: UDP, length 56", LOCAL) is None  # not ours


def _pk(t, out, lport, rip, rport, length, proto=6):
    return Packet(t, out, proto, flow_id(proto, lport, rip, rport), endpoint_id(proto, rip, rport), length)


def test_probe_filter_and_verbatim_encoding():
    pk = [
        _pk(1000, True, 40000, "203.0.113.5", 443, 517),
        _pk(1030, False, 40000, "203.0.113.5", 443, 1448),
        _pk(1500, False, 27017, "185.1.1.1", 47173, 0),  # scan: inbound only
    ]
    for i in range(3):  # peer retrying against a closed port: SYN in, RST out, no payload ever
        pk.append(_pk(2000 + 1000 * i, False, 6998, "178.202.239.20", 61640, 0))
        pk.append(_pk(2000 + 1000 * i, True, 6998, "178.202.239.20", 61640, 0))
    kept, dropped = drop_probes(pk)
    assert dropped == 7 and len(kept) == 2
    text, stats = encode(pk, 1000, budget_tokens=2000)
    assert stats["level"] == 0 and stats["probes_dropped"] == 7
    assert "f1 tcp e1 acks=0" in text and "\n+0 f1> 517\n+30 f1< 1448" in text and "summary: 1 flows to 1 endpoints" in text
    assert "203.0.113.5" not in text and "185.1.1.1" not in text and "443" not in text  # neither addresses nor ports appear


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


def test_raw_ips_mode_is_opt_in():
    line = "1758412345.123456 IP 10.137.0.10.51000 > 203.0.113.5.443: tcp 517"
    assert parse_line(line, LOCAL).label is None
    p = parse_line(line, LOCAL, keep_ips=True)
    assert p.label == "10.137.0.10:51000 > 203.0.113.5:443"
    text, _ = encode([p, parse_line("1758412345.2 IP 203.0.113.5.443 > 10.137.0.10.51000: tcp 1448", LOCAL, keep_ips=True)], 1758412345123, 5000)
    assert "f1 tcp 10.137.0.10:51000 > 203.0.113.5:443 acks=0" in text


def test_mode_defaults():
    from netprofiler.config import Settings

    s = Settings()
    assert s.mode == "raw" and s.raw and not s.raw_ips and s.raw_batch_s == 2.0 and s.raw_window_s == 10.0
    assert Settings(mode="raw-ips").raw_ips and not Settings(mode="shape").raw
