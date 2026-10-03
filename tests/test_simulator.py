import time
import pytest
# pyrefly: ignore [missing-import]
from simulator import generate_packets, simulate_traffic

@pytest.fixture(scope="module")
def packets():
    return list(generate_packets(seed=42, realtime=False))

def test_packet_count(packets):
    """Verify exactly 91 packets are generated."""
    assert len(packets) == 91

def test_all_attackers_present(packets):
    """Verify all 6 attacker IPs are present and burst sizes are correct."""
    attacker_flood = [p for p in packets if p["source"] == "192.168.1.99"]
    assert len(attacker_flood) == 25
    
    sources = {p["source"] for p in packets}
    expected_attackers = {"192.168.1.99", "192.168.1.98", "192.168.1.97",
                          "192.168.1.96", "192.168.1.95", "192.168.1.94"}
    assert expected_attackers.issubset(sources)

def test_attacker_burst_properties(packets):
    """Verify attacker packets have the correct properties."""
    attacker = [p for p in packets if p["source"] == "192.168.1.99"]
    for p in attacker:
        assert p["protocol"] == "TCP"
        assert p["flags"] == "S"
        assert p["destination"] == "10.0.0.5"

def test_icmp_packets_have_correct_schema(packets):
    attacker = [p for p in packets if p["source"] == "192.168.1.96"]
    assert len(attacker) > 0
    for p in attacker:
        assert p["protocol"] == "ICMP"
        assert p["flags"] == "-"
        assert p["port"] == "-"

def test_null_scan_flags(packets):
    attacker = [p for p in packets if p["source"] == "192.168.1.95"]
    assert len(attacker) > 0
    for p in attacker:
        assert p["flags"] == "0"

def test_xmas_scan_flags(packets):
    attacker = [p for p in packets if p["source"] == "192.168.1.94"]
    assert len(attacker) > 0
    for p in attacker:
        flags = p["flags"]
        assert "F" in flags and "P" in flags and "U" in flags

def test_schema_on_every_packet(packets):
    """Verify every packet matches the 11-key schema."""
    expected_keys = {"timestamp", "source", "destination", "protocol", "size", "flags", "port",
                     "filename", "file_size", "file_hash", "file_ext"}
    for p in packets:
        assert set(p.keys()) == expected_keys, f"Packet schema mismatch: {p}"

def test_exactly_three_suspicious_files(packets):
    suspicious = [p for p in packets
                  if p["file_ext"] in {"exe","scr","bat","ps1","vbs"}
                  or (p["file_hash"] or "").startswith(("a3c5","b4d6","c5e7"))
                  or "invoice" in (p["filename"] or "").lower()]
    assert len(suspicious) == 3

def test_benign_files_have_safe_extensions(packets):
    suspicious = [p for p in packets
                  if p["file_ext"] in {"exe","scr","bat","ps1","vbs"}
                  or (p["file_hash"] or "").startswith(("a3c5","b4d6","c5e7"))
                  or "invoice" in (p["filename"] or "").lower()]
    benign = [p for p in packets if p["filename"] and p not in suspicious]
    assert all(p["file_ext"] in {"pdf","docx","txt","png","jpg","csv"} for p in benign)

def test_chronological_order(packets):
    """Verify packets are yielded in chronological order."""
    ts = [p["timestamp"] for p in packets]
    assert ts == sorted(ts)

def test_determinism_across_runs():
    """Verify that using the same seed produces the same packets."""
    run1 = list(generate_packets(seed=42, realtime=False))
    run2 = list(generate_packets(seed=42, realtime=False))
    
    # Strip timestamp before comparing
    for p in run1:
        p.pop("timestamp", None)
    for p in run2:
        p.pop("timestamp", None)
        
    assert run1 == run2

def test_simulate_traffic_wrapper_populates_buffer():
    """Verify the blocking wrapper appends packets to the buffer."""
    buf = []
    simulate_traffic(buf, seed=42, realtime=False)
    assert len(buf) == 91
    assert any(p["source"] == "192.168.1.99" for p in buf)

@pytest.mark.slow
def test_realtime_mode_runs_in_expected_window():
    """Verify realtime mode delays packets to match expected window."""
    buf = []
    t0 = time.monotonic()
    simulate_traffic(buf, seed=42, realtime=True)
    elapsed = time.monotonic() - t0
    
    assert 40 <= elapsed <= 60, f"realtime took {elapsed:.1f}s"
    assert len(buf) == 91

def test_scenario_isolation():
    """Each scenario must emit ONLY its own attack type."""
    import simulator

    pkts = list(simulator.generate_packets(
        seed=42, realtime=False, scenario="flood_only"))
    # No brute-force SYNs to port 22
    assert not any(p.get("port") == 22 and p.get("flags") == "S"
                   for p in pkts if p["source"] == "192.168.1.97")

    pkts = list(simulator.generate_packets(
        seed=42, realtime=False, scenario="files_only"))
    # No flood packets
    assert not any(p["source"] == "192.168.1.99" for p in pkts)

    pkts = list(simulator.generate_packets(
        seed=42, realtime=False, scenario="scan_only"))
    # No ICMP flood packets
    assert all(p["protocol"] != "ICMP" for p in pkts)
