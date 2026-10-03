from packet_buffer import PacketBuffer
from detector import AnomalyDetector
from simulator import simulate_traffic
from agent import start_agent, AGENT
import time, threading

buf = PacketBuffer(); det = AnomalyDetector()
# Feed the buffer + detector in a background thread
def feed():
    for pkt in __import__('simulator').generate_packets(seed=42, realtime=True):
        buf.append(pkt); det.analyze(pkt)
threading.Thread(target=feed, daemon=True).start()

start_agent(buf, det, poll_interval=3.0)
time.sleep(30)
print('blocked:', AGENT.snapshot_blocked())
print('state:', AGENT.snapshot_state())
for entry in AGENT.snapshot_log():
    print(entry)
