import app
import time

app.start_agent_once()
app.start_simulator_once()
print("Running...", flush=True)

for _ in range(60):
    time.sleep(1)
