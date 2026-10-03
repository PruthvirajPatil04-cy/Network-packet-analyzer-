from __future__ import annotations
import pytest
import random
from detector import AnomalyDetector, analyze_pps

import typing

def _make_pkt(source: str, ts: str, port: typing.Any = 80, protocol: str = "TCP", flags: str = "S",
              filename=None, file_size=None, file_hash=None, file_ext=None) -> dict:
    """Minimal packet dict."""
    return {"source": source, "timestamp": ts,
            "destination": "10.0.0.5", "protocol": protocol,
            "size": 60, "flags": flags, "port": port,
            "filename": filename, "file_size": file_size,
            "file_hash": file_hash, "file_ext": file_ext}

def test_no_alert_on_normal_traffic():
    d = AnomalyDetector()
    for i in range(10):
        assert d.analyze(_make_pkt(f"192.168.1.{i}", "00:00:00.000")) is None
    assert d.alerts == []
    assert d.risk_score == 0.0

def test_burst_triggers_alert():
    d = AnomalyDetector()
    fired = []
    for i in range(1, 31):
        a = d.analyze(_make_pkt("192.168.1.99", "00:00:00.000"))
        if a and not a.get("_cooldown"):
            fired.append((i, a))
            
    assert len(fired) == 1
    idx, a = fired[0]
    assert idx == 15
    assert a["severity"] == "HIGH"
    assert a["ip"] == "192.168.1.99"
    assert a["type"] == "DoS / FLOOD"
    assert d.risk_score == 20.0

def test_window_expiry():
    d = AnomalyDetector()
    for _ in range(10):
        assert d.analyze(_make_pkt("10.0.0.1", "00:00:00.000")) is None
    # 4.0s > 3.0s window; do not use exactly 3.000s.
    for _ in range(10):
        assert d.analyze(_make_pkt("10.0.0.1", "00:00:04.000")) is None
    assert d.alerts == []
    assert d.risk_score == 0.0

def test_risk_score_decay():
    d = AnomalyDetector()
    for _ in range(15):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000"))
    assert d.risk_score == 20.0
    
    prev = d.risk_score
    for i in range(40):
        d.analyze(_make_pkt(f"10.0.1.{i}", "00:00:00.000"))
        assert d.risk_score <= prev, f"score rose at packet {i}"
        prev = d.risk_score
    assert d.risk_score == 0.0

def test_reset():
    d = AnomalyDetector()
    for _ in range(15):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000"))
    assert d.risk_score == 20.0
    
    d.reset()
    assert d.alerts == []
    assert d.risk_score == 0.0
    assert len(d._state) == 0
    
    fired = []
    for _ in range(20):
        a = d.analyze(_make_pkt("10.0.0.2", "00:00:00.000"))
        if a and not a.get("_cooldown"):
            fired.append(a)
    assert len(fired) == 1

def test_analyze_pps_empty():
    assert analyze_pps([]) == 0.0

def test_analyze_pps_single():
    assert analyze_pps([_make_pkt("1.1.1.1", "00:00:00.000")]) == 0.0

def test_analyze_pps_normal():
    pkts = [_make_pkt("1.1.1.1", "00:00:00.000"),
            _make_pkt("1.1.1.1", "00:00:01.000")]
    assert analyze_pps(pkts) == 2.0

def test_analyze_pps_zero_duration():
    pkts = [_make_pkt("1.1.1.1", "00:00:00.000"),
            _make_pkt("1.1.1.1", "00:00:00.000")]
    assert analyze_pps(pkts) == 0.0

def test_port_scan_rule_fires():
    d = AnomalyDetector()
    for i in range(10):
        a = d.analyze(_make_pkt("192.168.1.98", "00:00:00.000", port=i+1000))
        if a and not a.get("_cooldown"):
            assert a["type"] == "PORT SCAN"
            return
    assert False, "Port scan alert did not fire"

def test_brute_force_rule_fires():
    d = AnomalyDetector()
    for i in range(8):
        a = d.analyze(_make_pkt("192.168.1.97", "00:00:00.000", port=22, flags="S"))
        if a and not a.get("_cooldown"):
            assert a["type"] == "SSH BRUTE FORCE"
            return
    assert False, "Brute force alert did not fire"

def test_no_false_positive_on_normal_traffic():
    """30 packets from 30 unique IPs on random ports — no alert must fire."""
    d = AnomalyDetector()
    rng = random.Random(0)
    for i in range(30):
        pkt = {"source": f"10.0.{i//10}.{i%10}", "timestamp": "00:00:00.000",
               "destination": "10.0.0.5", "protocol": "TCP",
               "size": 60, "flags": "A",
               "port": rng.choice([80, 443, 8080, 53, 22, 3306])}
        assert d.analyze(pkt) is None
    assert d.alerts == []
    assert d.risk_score == 0.0

def test_rules_are_isolated():
    """Flood traffic must NOT trigger the port-scan rule."""
    d = AnomalyDetector()
    for _ in range(20):  # 20 SYNs, all to port 80
        pkt = _make_pkt("192.168.1.99", "00:00:00.000", port=80, flags="S")
        alert = d.analyze(pkt)
    assert any(a.get("type") == "DoS / FLOOD" for a in d.alerts)
    assert not any(a.get("type") == "PORT SCAN" for a in d.alerts)

def test_icmp_flood_rule_fires():
    d = AnomalyDetector()
    for _ in range(15):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000",
                            protocol="ICMP", flags="-", port="-"))
    assert any(a["type"] == "ICMP FLOOD" for a in d.alerts)
    assert d.risk_score >= 20.0

def test_null_scan_rule_fires():
    d = AnomalyDetector()
    for _ in range(3):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000",
                            flags="0", port=80))
    assert any(a["type"] == "NULL SCAN" for a in d.alerts)

def test_xmas_scan_rule_fires():
    d = AnomalyDetector()
    for _ in range(3):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000",
                            flags="FPU", port=80))
    assert any(a["type"] == "XMAS SCAN" for a in d.alerts)

def test_icmp_rule_ignores_tcp():
    d = AnomalyDetector()
    for _ in range(20):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000",
                            protocol="TCP", flags="S", port=80))
    assert not any(a["type"] == "ICMP FLOOD" for a in d.alerts)

def test_null_scan_ignores_normal_tcp():
    d = AnomalyDetector()
    for _ in range(20):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000",
                            flags="S", port=80))
    assert not any(a["type"] == "NULL SCAN" for a in d.alerts)

def test_xmas_scan_ignores_partial_flags():
    # flags "FU" has only 2 of the 3 required (missing P)
    d = AnomalyDetector()
    for _ in range(5):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000",
                            flags="FU", port=80))
    assert not any(a["type"] == "XMAS SCAN" for a in d.alerts)

def test_reset_clears_cooldowns():
    """After reset, a fresh burst must fire immediately (no stale cooldown)."""
    d = AnomalyDetector()
    for _ in range(15):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000", port=80, flags="S"))
    assert len(d.alerts) >= 1
    
    # Pre-populate state for new rules
    d._state["icmp_flood"] = {"deques": {}}
    d._state["null_scan"] = {"deques": {}}
    d._state["xmas_scan"] = {"deques": {}}
    
    d.reset()
    for _ in range(15):
        d.analyze(_make_pkt("10.0.0.1", "00:00:00.000", port=80, flags="S"))
    assert len(d.alerts) >= 1  # proves cooldown didn't survive the reset
    
    assert "icmp_flood" not in d._state
    assert "null_scan" not in d._state
    assert "xmas_scan" not in d._state

def test_malicious_file_rule_fires_on_dangerous_ext():
    d = AnomalyDetector()
    pkt = _make_pkt("10.0.0.1", "00:00:00.000",
                    filename="virus.exe", file_ext="exe",
                    file_size=1024, file_hash="0"*64)
    alert = d.analyze(pkt)
    assert alert is not None
    assert alert["type"] == "MALICIOUS FILE"
    assert "exe" in alert["detail"]

def test_malicious_file_rule_fires_on_bad_hash():
    d = AnomalyDetector()
    pkt = _make_pkt("10.0.0.1", "00:00:00.000",
                    filename="document.pdf", file_ext="pdf",
                    file_size=1024, file_hash="a3c5e7f9b1d20000000000000000000000000000000000000000malwarehash1")
    alert = d.analyze(pkt)
    assert alert is not None
    assert alert["type"] == "MALICIOUS FILE"
    assert "signature" in alert["detail"].lower()

def test_malicious_file_rule_fires_on_suspicious_filename():
    d = AnomalyDetector()
    pkt = _make_pkt("10.0.0.1", "00:00:00.000",
                    filename="invoice.pdf.exe", file_ext="pdf",
                    file_size=1024, file_hash="0"*64)
    alert = d.analyze(pkt)
    assert alert is not None
    assert alert["type"] == "MALICIOUS FILE"

def test_malicious_file_rule_ignores_benign():
    d = AnomalyDetector()
    pkt = _make_pkt("10.0.0.1", "00:00:00.000",
                    filename="report.pdf", file_ext="pdf",
                    file_size=50000, file_hash="deadbeef"*8)
    alert = d.analyze(pkt)
    assert alert is None
