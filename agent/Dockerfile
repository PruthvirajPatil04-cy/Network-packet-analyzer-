# Standalone Packet Capture Agent Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install libpcap and networking utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/
COPY detector.py packet_buffer.py simulator.py ./

# Required capability: NET_RAW, NET_ADMIN
ENV BACKEND_URL=http://backend:8000
ENV INGEST_API_KEY=packet-analyzer-secret-key-2026
ENV SAMPLING_RATE=1.0

CMD ["python", "-m", "agent.capture"]
