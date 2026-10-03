import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from simulator import generate_packets
from detector import AnomalyDetector

def main():
    packets = list(generate_packets(seed=42, realtime=False))
    d = AnomalyDetector()
    types_seen = set()
    first_alert_idx = -1
    attackers = set()
    peak_risk = 0.0

    for i, p in enumerate(packets, 1):
        a = d.analyze(p)
        if a and not a.get("_cooldown"):
            print(f"  # {i:<4} {a['type']:<18} {a['ip']:<13} {a['detail']}")
            types_seen.add(a["type"])
            attackers.add(a["ip"])
            if first_alert_idx == -1:
                first_alert_idx = i
        if d.risk_score > peak_risk:
            peak_risk = d.risk_score

    files_blocked = sum(1 for a in d.alerts if a.get("type") == "MALICIOUS FILE")

    print(f"Total packets: {len(packets)}")
    print(f"Alerts: {len(d.alerts)}")
    print(f"Types seen: {len(types_seen)} distinct")
    print(f"Files blocked: {files_blocked}")
    print(f"Peak risk: {peak_risk:.0f}")

if __name__ == "__main__":
    main()
