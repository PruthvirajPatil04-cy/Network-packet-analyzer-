"""
Tests for live WebSocket packet streaming and broadcast.
"""

import json
import pytest
from starlette.testclient import TestClient
from backend.main import app, stream_manager
from backend.models import PacketBatch, PacketMetadata


def test_websocket_connection_and_ping():
    client = TestClient(app)
    with client.websocket_connect("/ws/packets") as ws:
        ws.send_text("ping")
        data = ws.receive_text()
        assert data == "pong"


@pytest.mark.asyncio
async def test_websocket_broadcast_delivery():
    # Use TestClient websocket context to test broadcast receiving
    client = TestClient(app)
    with client.websocket_connect("/ws/packets") as ws:
        # Ingest a batch directly via stream_manager
        batch = PacketBatch(
            agent_id="test-ws-agent",
            sent_at=1700000000.0,
            packets=[
                PacketMetadata(
                    timestamp="12:00:00.999",
                    source="10.10.10.10",
                    destination="10.10.10.20",
                    protocol="ICMP",
                    size=64,
                )
            ]
        )
        await stream_manager.ingest_batch(batch)

        # Receive broadcast on websocket
        msg = ws.receive_text()
        data = json.loads(msg)
        assert data["type"] == "packet_batch"
        assert len(data["data"]) == 1
        assert data["data"][0]["source"] == "10.10.10.10"
        assert data["data"][0]["protocol"] == "ICMP"
