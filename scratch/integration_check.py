import sys; sys.path.insert(0, '.')
from simulator import generate_packets
from detector import AnomalyDetector
pkts = list(generate_packets(seed=42, realtime=False))
d = AnomalyDetector()
for i, p in enumerate(pkts, 1):
    a = d.analyze(p)
    if a and not a.get("_cooldown"):
        print(f'  #{i:>3} {a["type"]:>18}  {a["ip"]}  {a["detail"]}')
print(f'Total: {len(d.alerts)} alerts, peak risk {d.risk_score}')
