"""
Streaming layer for Network Packet Analyzer.
Implements Path A (In-memory ring buffer + WebSocket fan-out) and
Path B (Redis Streams consumer/producer) with automatic fallback.
"""

from __future__ import annotations
import asyncio
import json
import logging
import time
from collections import deque, Counter
from typing import Set, Dict, List, Any, Optional
from fastapi import WebSocket

from backend.models import (
    PacketMetadata, PacketBatch, StatsResponse, TopTalker, AlertModel
)

logger = logging.getLogger("packet-analyzer.stream")


class StreamManager:
    """
    Decoupled streaming message layer.
    Thread-safe & async-compatible ingestion, sliding-window analytics,
    and fan-out to connected WebSocket dashboards.
    """

    def __init__(
        self,
        max_buffer_size: int = 10_000,
        redis_url: Optional[str] = None,
        stream_name: str = "packets-stream",
    ):
        self.max_buffer_size = max_buffer_size
        self.redis_url = redis_url
        self.stream_name = stream_name

        # In-memory sliding buffer for real-time stats & fanout
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_buffer_size)
        self._lock = asyncio.Lock()

        # WebSocket subscribers
        self._active_connections: Set[WebSocket] = set()

        # Cumulative counters
        self.total_packets_ingested = 0
        self.total_bytes_ingested = 0
        self.total_packets_dropped = 0
        self.boot_time = time.time()

        # SOC Alerts storage
        self._alerts: deque[dict[str, Any]] = deque(maxlen=500)

        # Redis client reference
        self._redis: Optional[Any] = None
        self._redis_connected = False
        self._redis_consumer_task: Optional[asyncio.Task] = None

    async def initialize(self) -> None:
        """Connect to Redis if configured, or stay in in-memory mode."""
        if self.redis_url:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(
                    self.redis_url, encoding="utf-8", decode_responses=True
                )
                await self._redis.ping()
                self._redis_connected = True
                logger.info(f"Connected to Redis Stream at {self.redis_url}")
                # Start background Redis stream consumer
                self._redis_consumer_task = asyncio.create_task(self._consume_redis_stream())
            except Exception as e:
                logger.warning(
                    f"Could not connect to Redis ({e}). Running in-memory mode (Path A)."
                )
                self._redis_connected = False
                self._redis = None
        else:
            logger.info("Running in lightweight in-memory streaming mode (Path A).")

    async def shutdown(self) -> None:
        """Gracefully close WebSocket connections and Redis client."""
        if self._redis_consumer_task:
            self._redis_consumer_task.cancel()
        if self._redis:
            await self._redis.close()
            self._redis_connected = False

        # Close all active websockets
        for ws in list(self._active_connections):
            try:
                await ws.close(code=1001, reason="Server shutting down")
            except Exception:
                pass
        self._active_connections.clear()

    # --- WebSocket Client Management ---

    async def register_client(self, websocket: WebSocket) -> None:
        """Accept and register a new dashboard WebSocket subscriber."""
        await websocket.accept()
        async with self._lock:
            self._active_connections.add(websocket)
        logger.info(f"Client connected. Active clients: {len(self._active_connections)}")

    async def unregister_client(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket client."""
        async with self._lock:
            self._active_connections.discard(websocket)
        logger.info(f"Client disconnected. Active clients: {len(self._active_connections)}")

    @property
    def active_client_count(self) -> int:
        return len(self._active_connections)

    # --- Ingestion & Broadcast ---

    async def ingest_batch(self, batch: PacketBatch) -> int:
        """
        Ingest a packet batch, update metrics, append to sliding window,
        publish to Redis Stream (if enabled), and broadcast to WebSockets.
        """
        raw_packets = [pkt.model_dump() for pkt in batch.packets]
        count = len(raw_packets)
        if count == 0:
            return 0

        batch_bytes = sum(pkt.get("size", 0) for pkt in raw_packets)
        arrival_time = time.time()

        # Update in-memory sliding buffer
        async with self._lock:
            self.total_packets_ingested += count
            self.total_bytes_ingested += batch_bytes
            for pkt in raw_packets:
                pkt["_ingested_at"] = arrival_time
                self._buffer.append(pkt)

        # Path B: Push to Redis Stream if connected
        if self._redis_connected and self._redis:
            try:
                # Add each or serialized batch to stream
                await self._redis.xadd(
                    self.stream_name,
                    {"data": json.dumps(raw_packets), "agent": batch.agent_id},
                    maxlen=self.max_buffer_size,
                )
            except Exception as e:
                logger.error(f"Failed to publish to Redis stream: {e}")
                self._redis_connected = False

        # Broadcast to all connected dashboard WebSockets
        await self._broadcast_packets(raw_packets)
        return count

    async def _broadcast_packets(self, packets: List[Dict[str, Any]]) -> None:
        """Broadcast packet batch JSON to all active WebSocket connections."""
        if not self._active_connections:
            return

        payload = json.dumps({"type": "packet_batch", "data": packets})
        stale_clients = []

        for ws in list(self._active_connections):
            try:
                await ws.send_text(payload)
            except Exception:
                stale_clients.append(ws)

        if stale_clients:
            async with self._lock:
                for ws in stale_clients:
                    self._active_connections.discard(ws)

    async def _consume_redis_stream(self) -> None:
        """Background task: Reads from Redis stream and pushes to WebSockets."""
        last_id = "$"
        while self._redis_connected and self._redis:
            try:
                entries = await self._redis.xread(
                    {self.stream_name: last_id}, count=100, block=1000
                )
                if entries:
                    for stream, messages in entries:
                        for msg_id, data in messages:
                            last_id = msg_id
                            if "data" in data:
                                raw = json.loads(data["data"])
                                await self._broadcast_packets(raw)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in Redis consumer: {e}")
                await asyncio.sleep(1.0)

    # --- Analytics & Aggregates ---

    async def get_stats(self, window_seconds: float = 10.0) -> StatsResponse:
        """Compute rolling window PPS, BPS, protocol distribution, and top talkers."""
        now = time.time()
        cutoff = now - window_seconds

        async with self._lock:
            # Filter packets inside sliding window
            window_pkts = [p for p in self._buffer if p.get("_ingested_at", 0) >= cutoff]
            total_pkts = self.total_packets_ingested
            total_bytes = self.total_bytes_ingested
            depth = len(self._buffer)
            dropped = self.total_packets_dropped

        n_pkts = len(window_pkts)
        pps = (n_pkts / window_seconds) if window_seconds > 0 else 0.0
        bytes_in_window = sum(p.get("size", 0) for p in window_pkts)
        bps = (bytes_in_window / window_seconds) if window_seconds > 0 else 0.0

        # Protocol distribution
        proto_counts = Counter(p.get("protocol", "OTHER") for p in window_pkts)
        distribution = {
            "TCP": proto_counts.get("TCP", 0),
            "UDP": proto_counts.get("UDP", 0),
            "ICMP": proto_counts.get("ICMP", 0),
            "OTHER": proto_counts.get("OTHER", 0),
        }

        # Top talkers
        src_pkts = Counter()
        src_bytes = Counter()
        dst_pkts = Counter()
        dst_bytes = Counter()

        for p in window_pkts:
            s_ip = p.get("source", "")
            d_ip = p.get("destination", "")
            sz = p.get("size", 0)
            if s_ip:
                src_pkts[s_ip] += 1
                src_bytes[s_ip] += sz
            if d_ip:
                dst_pkts[d_ip] += 1
                dst_bytes[d_ip] += sz

        top_sources = [
            TopTalker(ip=ip, packet_count=src_pkts[ip], byte_count=src_bytes[ip])
            for ip, _ in src_pkts.most_common(10)
        ]
        top_destinations = [
            TopTalker(ip=ip, packet_count=dst_pkts[ip], byte_count=dst_bytes[ip])
            for ip, _ in dst_pkts.most_common(10)
        ]

        return StatsResponse(
            pps=round(pps, 2),
            bps=round(bps, 2),
            total_packets=total_pkts,
            total_bytes=total_bytes,
            protocol_distribution=distribution,
            top_sources=top_sources,
            top_destinations=top_destinations,
            queue_depth=depth,
            packets_dropped=dropped,
            window_seconds=window_seconds,
        )

    # --- SOC Alert Management ---

    async def record_alert(self, alert: AlertModel) -> None:
        """Store a new SOC alert and broadcast to dashboard clients."""
        alert_dict = alert.model_dump()
        async with self._lock:
            self._alerts.append(alert_dict)

        # Broadcast alert to all WebSocket clients
        payload = json.dumps({"type": "soc_alert", "data": alert_dict})
        for ws in list(self._active_connections):
            try:
                await ws.send_text(payload)
            except Exception:
                pass

    async def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent alerts."""
        async with self._lock:
            return list(self._alerts)[-limit:]
