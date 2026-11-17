"""
Integration tests for FastAPI REST endpoints and Prometheus metrics.
"""

import pytest
import httpx
from backend.main import app, EXPECTED_API_KEY


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data
        assert "queue_depth" in data


@pytest.mark.asyncio
async def test_metrics_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert "packets_captured_total" in resp.text
        assert "active_websocket_clients" in resp.text


@pytest.mark.asyncio
async def test_ingest_unauthorized():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"agent_id": "bad-agent", "sent_at": 1000.0, "packets": []}
        # Request without header
        resp = await client.post("/api/ingest", json=payload)
        assert resp.status_code == 401

        # Request with incorrect header
        resp = await client.post(
            "/api/ingest",
            json=payload,
            headers={"X-API-Key": "wrong-key"}
        )
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_and_stats():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "agent_id": "test-agent-01",
            "sent_at": 1700000000.0,
            "packets": [
                {
                    "timestamp": "12:00:00.100",
                    "source": "192.168.1.10",
                    "destination": "10.0.0.1",
                    "protocol": "TCP",
                    "size": 500,
                    "src_port": 12345,
                    "dst_port": 80,
                    "port": 80,
                    "flags": "S",
                },
                {
                    "timestamp": "12:00:00.200",
                    "source": "192.168.1.11",
                    "destination": "10.0.0.1",
                    "protocol": "UDP",
                    "size": 200,
                    "src_port": 5353,
                    "dst_port": 53,
                    "port": 53,
                    "flags": "-",
                },
            ]
        }
        resp = await client.post(
            "/api/ingest",
            json=payload,
            headers={"X-API-Key": EXPECTED_API_KEY}
        )
        assert resp.status_code == 202
        assert resp.json()["ingested"] == 2

        # Check stats reflection
        stats_resp = await client.get("/api/stats?window_seconds=10")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_packets"] >= 2
        assert stats["protocol_distribution"]["TCP"] >= 1
        assert stats["protocol_distribution"]["UDP"] >= 1


@pytest.mark.asyncio
async def test_post_and_get_alerts():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        alert = {
            "id": "alert-test-1",
            "time": "12:05:00",
            "type": "DoS / FLOOD",
            "ip": "192.168.1.200",
            "detail": "100 packets in 2s",
            "severity": "HIGH",
            "confidence": 95,
            "timestamp_ms": 1700000000000.0,
            "recommendation": "Block source IP immediately.",
        }
        resp = await client.post(
            "/api/alerts",
            json=alert,
            headers={"X-API-Key": EXPECTED_API_KEY}
        )
        assert resp.status_code == 201

        # Fetch alerts
        get_resp = await client.get("/api/alerts")
        assert get_resp.status_code == 200
        alerts = get_resp.json()
        assert any(a["id"] == "alert-test-1" for a in alerts)
