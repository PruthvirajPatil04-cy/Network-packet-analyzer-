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


@pytest.mark.asyncio
async def test_server_event_ingest_bridges_to_packet_stream():
    """Verify that student portal events are bridged to the main L4 packet stream and alerts."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest a real login event
        login_event = {
            "ts": 1700001000.0,
            "src_ip": "10.0.0.42",
            "dst": "student.college.edu",
            "path": "/login",
            "method": "POST",
            "status": 303,
            "decision": "allow",
            "score": 0.0,
            "reasons": [],
            "severity": "LOW",
            "bytes_in": 37,
            "bytes_out": 0,
        }
        resp = await client.post(
            "/api/server/event-ingest",
            json=login_event,
            headers={"X-API-Key": EXPECTED_API_KEY},
        )
        assert resp.status_code == 202

        # Verify it reflected in packet stream statistics
        stats_resp = await client.get("/api/stats?window_seconds=10")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_packets"] >= 1
        assert stats["protocol_distribution"]["TCP"] >= 1

        # Verify it is returned in live-events
        events_resp = await client.get("/api/server/live-events?limit=50")
        assert events_resp.status_code == 200
        events_data = events_resp.json()
        assert any(e.get("path") == "/login" and e.get("src_ip") == "10.0.0.42" for e in events_data["events"])

        # Ingest a blocked honeypot event
        blocked_event = {
            "ts": 1700001005.0,
            "src_ip": "10.0.9.99",
            "dst": "student.college.edu",
            "path": "/admin",
            "method": "GET",
            "status": 403,
            "decision": "block",
            "score": 0.95,
            "reasons": ["Administrative honeypot access"],
            "severity": "CRITICAL",
            "bytes_in": 0,
            "bytes_out": 120,
        }
        b_resp = await client.post(
            "/api/server/event-ingest",
            json=blocked_event,
            headers={"X-API-Key": EXPECTED_API_KEY},
        )
        assert b_resp.status_code == 202

        # Verify an alert was generated and is accessible via /api/alerts
        alerts_resp = await client.get("/api/alerts?limit=50")
        assert alerts_resp.status_code == 200
        all_alerts = alerts_resp.json()
        assert any(a.get("ip") == "10.0.9.99" for a in all_alerts)

