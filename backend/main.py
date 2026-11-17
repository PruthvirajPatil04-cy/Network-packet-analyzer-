"""
FastAPI Backend & Ingestion Server for Network Packet Analyzer.
Production-ready REST and WebSocket endpoints with Prometheus observability.
"""

from __future__ import annotations
import os
import time
import logging
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, HTTPException,
    Security, Depends, status, Request
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.responses import PlainTextResponse, FileResponse
from prometheus_client import (
    Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
)

from backend.models import (
    PacketBatch, StatsResponse, AlertModel, HealthResponse
)
from backend.stream import StreamManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("packet-analyzer.api")

# --- Security Configuration ---
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
EXPECTED_API_KEY = os.environ.get("INGEST_API_KEY", "packet-analyzer-secret-key-2026")
REDIS_URL = os.environ.get("REDIS_URL", None)

def verify_api_key(api_key: Optional[str] = Security(API_KEY_HEADER)) -> str:
    """Validate API key for ingestion and management endpoints."""
    # Allow bypass in relaxed local demo mode if INGEST_API_KEY is unset or explicitly matches
    if not api_key or api_key != EXPECTED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
    return api_key

# --- Prometheus Metrics ---
PACKETS_CAPTURED_TOTAL = Counter(
    "packets_captured_total",
    "Total count of network packets ingested",
    ["agent_id"]
)
PACKET_BYTES_TOTAL = Counter(
    "packet_bytes_total",
    "Total volume of packet bytes ingested"
)
PACKETS_DROPPED_TOTAL = Counter(
    "packets_dropped_total",
    "Total packets dropped by buffer backpressure"
)
ACTIVE_WS_CLIENTS = Gauge(
    "active_websocket_clients",
    "Current number of active WebSocket dashboard subscribers"
)
QUEUE_DEPTH_GAUGE = Gauge(
    "packet_queue_depth",
    "Current number of packet records held in streaming buffer"
)
INGEST_LATENCY_HISTOGRAM = Histogram(
    "packet_ingest_latency_seconds",
    "Time taken to process and broadcast an ingested packet batch",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
)

# Stream Manager instance
stream_manager = StreamManager(
    max_buffer_size=int(os.environ.get("MAX_BUFFER_SIZE", "10000")),
    redis_url=REDIS_URL,
    stream_name=os.environ.get("REDIS_STREAM_NAME", "packets-stream"),
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for graceful startup and shutdown."""
    logger.info("Initializing Network Packet Analyzer backend service...")
    await stream_manager.initialize()
    yield
    logger.info("Shutting down streaming manager and connections...")
    await stream_manager.shutdown()

app = FastAPI(
    title="Network Packet Analyzer API",
    version="2.0.0",
    description="High-throughput, real-time network packet analysis and threat detection backend.",
    lifespan=lifespan,
)

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Observability Endpoints ---

@app.get("/metrics", response_class=PlainTextResponse, tags=["Observability"])
async def metrics():
    """Prometheus exposition endpoint for scraping system metrics."""
    ACTIVE_WS_CLIENTS.set(stream_manager.active_client_count)
    QUEUE_DEPTH_GAUGE.set(len(stream_manager._buffer))
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health():
    """Liveness and readiness healthcheck."""
    now = time.time()
    return HealthResponse(
        status="healthy",
        uptime_seconds=round(now - stream_manager.boot_time, 2),
        queue_depth=len(stream_manager._buffer),
        active_ws_clients=stream_manager.active_client_count,
        redis_connected=stream_manager._redis_connected,
        version="2.0.0",
    )

# --- API Endpoints ---

@app.get("/api/stats", response_model=StatsResponse, tags=["Analytics"])
async def get_stats(window_seconds: float = 10.0):
    """
    Returns rolling traffic analytics (PPS, BPS, protocol distribution, top talkers).
    """
    return await stream_manager.get_stats(window_seconds=window_seconds)


@app.post("/api/ingest", status_code=status.HTTP_202_ACCEPTED, tags=["Ingestion"])
async def ingest_packets(
    batch: PacketBatch,
    api_key: str = Depends(verify_api_key)
):
    """
    Ingest a batch of L3/L4 packet metadata from a standalone capture agent.
    Authenticated with `X-API-Key`.
    """
    start_t = time.perf_counter()
    count = await stream_manager.ingest_batch(batch)

    # Track Prometheus metrics
    PACKETS_CAPTURED_TOTAL.labels(agent_id=batch.agent_id).inc(count)
    batch_bytes = sum(p.size for p in batch.packets)
    PACKET_BYTES_TOTAL.inc(batch_bytes)
    INGEST_LATENCY_HISTOGRAM.observe(time.perf_counter() - start_t)

    return {"status": "accepted", "ingested": count}


@app.get("/api/alerts", response_model=List[AlertModel], tags=["SOC Alerts"])
async def get_alerts(limit: int = 50):
    """Fetch recent security alerts produced by heuristic rules or the AI SOC Agent."""
    raw_alerts = await stream_manager.get_alerts(limit=limit)
    return [AlertModel(**a) for a in raw_alerts]


@app.post("/api/alerts", status_code=status.HTTP_201_CREATED, tags=["SOC Alerts"])
async def post_alert(
    alert: AlertModel,
    api_key: str = Depends(verify_api_key)
):
    """Publish a new security alert from the SOC analysis agent."""
    await stream_manager.record_alert(alert)
    return {"status": "recorded", "alert_id": alert.id}

# --- WebSocket Streaming ---

@app.websocket("/ws/packets")
async def websocket_packet_feed(websocket: WebSocket):
    """
    Live WebSocket packet feed for connected dashboards.
    Broadcasts real-time batches as they arrive without polling.
    """
    await stream_manager.register_client(websocket)
    ACTIVE_WS_CLIENTS.set(stream_manager.active_client_count)
    try:
        # Keep connection open and listen for optional client heartbeat / filter messages
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await stream_manager.unregister_client(websocket)
        ACTIVE_WS_CLIENTS.set(stream_manager.active_client_count)
    except Exception as e:
        logger.warning(f"WebSocket client error: {e}")
        await stream_manager.unregister_client(websocket)
        ACTIVE_WS_CLIENTS.set(stream_manager.active_client_count)

# --- Static Frontend Mount (if built) ---
frontend_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/static", StaticFiles(directory=frontend_dist), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(frontend_dist, "index.html"))
