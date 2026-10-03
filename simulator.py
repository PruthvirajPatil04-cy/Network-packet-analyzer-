"""Packet simulator for demo constraints."""

from __future__ import annotations
import random
import time
from datetime import datetime
from typing import Generator, List, Dict, Any
from packet_buffer import PacketSink

def generate_packets(seed: int = 42, realtime: bool = True, scenario: str = "full") -> Generator[Dict[str, Any], None, None]:
    """Generates a scheduled stream of packets including anomalies."""
    rng = random.Random(seed)
    schedule: List[tuple[float, Dict[str, Any]]] = []
    
    t = 0.0
    # Normal traffic: 25 packets spread across the full ~60s window.
    for _ in range(25):
        src = f"192.168.1.{rng.randint(10, 24)}"
        proto_choice = rng.choices(["TCP", "UDP", "ICMP"], weights=[70, 25, 5])[0]
        
        flags = "-"
        port = "-"
        if proto_choice == "TCP":
            port = rng.choice([80, 443, 8080])
            flags = rng.choice(["S", "SA", "A", "PA"])
        elif proto_choice == "UDP":
            port = 53
            
        dst = rng.choices(["10.0.0.5", "10.0.0.6", "10.0.0.7"], weights=[60, 25, 15])[0]
        pkt = {
            "source": src,
            "destination": dst,
            "protocol": proto_choice,
            "size": rng.randint(60, 1500),
            "flags": flags,
            "port": port
        }
        schedule.append((t, pkt))
        # Spreading 25 packets over ~60s means a gap of roughly 2.4s.
        t += rng.uniform(2.0, 2.8)
        
    if scenario in ("full", "flood_only", "chaos"):
        # Attack 1: Flood (t=10s)
        t = 10.0
        for _ in range(25):
            pkt = {
                "source": "192.168.1.99",
                "destination": "10.0.0.5",
                "protocol": "TCP",
                "size": rng.randint(40, 80),
                "flags": "S",
                "port": 80
            }
            schedule.append((t, pkt))
            t += rng.uniform(0.05, 0.12)
        
    if scenario in ("full", "scan_only", "chaos"):
        # Attack 2: Port Scan (t=18s)
        t = 18.0
        ports = [20, 21, 22, 23, 25, 80, 139, 443, 445, 3389]  # 10 distinct
        for p in ports:
            pkt = {
                "source": "192.168.1.98",
                "destination": "10.0.0.6",
                "protocol": "TCP",
                "size": rng.randint(40, 80),
                "flags": "S",
                "port": p
            }
            schedule.append((t, pkt))
            t += rng.uniform(0.2, 0.3)

    if scenario in ("full", "brute_only", "chaos"):
        # Attack 3: Brute Force (t=26s)
        t = 26.0
        for _ in range(8):
            pkt = {
                "source": "192.168.1.97",
                "destination": "10.0.0.7",
                "protocol": "TCP",
                "size": rng.randint(40, 80),
                "flags": "S",
                "port": 22
            }
            schedule.append((t, pkt))
            t += rng.uniform(0.25, 0.4)

    if scenario in ("full", "chaos"):
        # Attack 4: ICMP Flood (t=34s)
        t = 34.0
        for _ in range(15):
            pkt = {
                "source": "192.168.1.96",
                "destination": "10.0.0.5",
                "protocol": "ICMP",
                "size": rng.randint(64, 128),
                "flags": "-",
                "port": "-"
            }
            schedule.append((t, pkt))
            t += rng.uniform(0.1, 0.2)

    if scenario in ("full", "chaos"):
        # Attack 5: NULL Scan (t=42s)
        t = 42.0
        scan_ports = [22, 80, 443, 8080]
        for p in scan_ports:
            pkt = {
                "source": "192.168.1.95",
                "destination": "10.0.0.6",
                "protocol": "TCP",
                "size": rng.randint(40, 80),
                "flags": "0",
                "port": p
            }
            schedule.append((t, pkt))
            t += rng.uniform(0.3, 0.5)

    if scenario in ("full", "chaos"):
        # Attack 6: XMAS Scan (t=50s)
        t = 50.0
        for p in scan_ports:
            pkt = {
                "source": "192.168.1.94",
                "destination": "10.0.0.7",
                "protocol": "TCP",
                "size": rng.randint(40, 80),
                "flags": "FPU",
                "port": p
            }
            schedule.append((t, pkt))
            t += rng.uniform(0.3, 0.5)

    if scenario == "chaos":
        times = [x[0] for x in schedule]
        pkts = [x[1] for x in schedule]
        rng.shuffle(pkts)
        schedule = list(zip(times, pkts))

    # Sort by schedule time
    schedule.sort(key=lambda x: x[0])
    
    import hashlib
    file_rng = random.Random(seed + 999)
    suspicious_targets = [
        (8.0, "exe", None, "update.exe"),
        (22.0, "pdf", "a3c5e7f9b1d2" + "0"*40 + "malwarehash1", "document.pdf"),
        (38.0, "exe", None, "invoice.pdf.exe")
    ]
    
    benign_exts = ["pdf", "docx", "txt", "png", "jpg", "csv"]
    benign_assigned = 0
    
    for offset, pkt in schedule:
        pkt["filename"] = None
        pkt["file_size"] = None
        pkt["file_hash"] = None
        pkt["file_ext"] = None
        
        if pkt["protocol"] == "TCP" and pkt["port"] in (80, 443, 8080):
            is_normal = pkt["source"].startswith("192.168.1.") and 10 <= int(pkt["source"].split(".")[3]) <= 24
            if is_normal:
                if suspicious_targets and offset >= suspicious_targets[0][0]:
                    target_time, ext, bad_hash, filename = suspicious_targets.pop(0)
                    pkt["file_ext"] = ext
                    pkt["filename"] = filename
                    if bad_hash:
                        pkt["file_hash"] = bad_hash
                    else:
                        pkt["file_hash"] = hashlib.sha256(filename.encode()).hexdigest()
                    pkt["file_size"] = file_rng.randint(50000, 5000000)
                elif benign_assigned < 7:
                    n = benign_assigned
                    ext = file_rng.choice(benign_exts)
                    pkt["file_ext"] = ext
                    pkt["filename"] = f"report_{n}.{ext}"
                    pkt["file_hash"] = hashlib.sha256(f"benign{n}".encode()).hexdigest()
                    pkt["file_size"] = file_rng.randint(50000, 5000000)
                    benign_assigned += 1

    t0 = time.monotonic()
    for offset, pkt in schedule:
        if realtime:
            target = t0 + offset
            now = time.monotonic()
            if target > now:
                time.sleep(target - now)
                
        # Set real timestamp just before yield
        pkt["timestamp"] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        yield pkt

def simulate_traffic(buffer: PacketSink, seed: int = 42, realtime: bool = True, scenario: str = "full") -> None:
    """Blocking: consume generate_packets and append each to buffer."""
    for pkt in generate_packets(seed=seed, realtime=realtime, scenario=scenario):
        # INVARIANT: callers must read via buffer.snapshot(), never index
        # the raw container. See packet_buffer.py.
        buffer.append(pkt)

if __name__ == "__main__":
    test_buffer: List[Dict[str, Any]] = []
    simulate_traffic(test_buffer, seed=42, realtime=False, scenario="full")
    
    assert len(test_buffer) == 91
    expected_keys = {"timestamp", "source", "destination", "protocol", "size", "flags", "port", "filename", "file_size", "file_hash", "file_ext"}
    assert all(set(p.keys()) == expected_keys for p in test_buffer)
    
    timestamps = [p["timestamp"] for p in test_buffer]
    assert sorted(timestamps) == timestamps, "not chronologically ordered"
    
    sources = {p["source"] for p in test_buffer}
    attackers = {"192.168.1.99", "192.168.1.98", "192.168.1.97",
                 "192.168.1.96", "192.168.1.95", "192.168.1.94"}
    assert attackers.issubset(sources)
    
    destinations = [p["destination"] for p in test_buffer]
    from collections import Counter
    dest_counts = Counter(destinations)
    for dst in ["10.0.0.5", "10.0.0.6", "10.0.0.7"]:
        assert dest_counts[dst] >= 10, f"Server {dst} got {dest_counts[dst]} packets (needed >=10)"
    
    suspicious_exts = {"exe", "scr", "bat", "ps1", "vbs", "jar"}
    bad_hashes = {
        "a3c5e7f9b1d2" + "0"*40 + "malwarehash1",
        "b4d6e8f0c2e3" + "0"*40 + "malwarehash2",
        "c5e7f9b1d3f4" + "0"*40 + "malwarehash3"
    }
    
    suspicious_count = sum(1 for p in test_buffer if p["file_ext"] in suspicious_exts or p["file_hash"] in bad_hashes)
    assert suspicious_count == 3
    assert any(p["file_ext"] == "exe" for p in test_buffer)
    
    print("OK — 91 packets, 3 suspicious files")
