"""
Integration tests for Simulated Student Portal demo server.
"""

import pytest
import httpx
from demo_server.main import app, blocklist


@pytest.mark.asyncio
async def test_demo_server_health():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "online"
        assert "domain" in data


@pytest.mark.asyncio
async def test_demo_server_courses():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        resp = await client.get("/courses", headers={"Accept": "application/json"})
        assert resp.status_code == 200
        data = resp.json()
        assert "courses" in data
        assert len(data["courses"]) >= 4


@pytest.mark.asyncio
async def test_demo_server_admin_honeypot():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        # Without token -> 403 Forbidden
        resp = await client.get("/admin", headers={"X-Forwarded-For": "10.0.9.99"})
        assert resp.status_code == 403

        # With token from clean IP -> 200 OK
        resp_auth = await client.get(
            "/admin",
            headers={"X-Forwarded-For": "10.0.9.100", "x-admin-token": "super-secret-admin-token-2026"}
        )
        assert resp_auth.status_code == 200
        assert resp_auth.json()["authorized"] is True

        blocklist.unblock_ip("10.0.9.99")


@pytest.mark.asyncio
async def test_demo_server_dynamic_blocking():
    transport = httpx.ASGITransport(app=app)
    attacker_ip = "10.0.7.77"
    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        # First request: send SQL injection
        resp = await client.post(
            "/login",
            data={"username": "admin' OR '1'='1", "password": "xyz"},
            headers={"X-Forwarded-For": attacker_ip},
        )
        assert resp.status_code == 403
        assert "Forbidden" in resp.text

        # Second request: benign request from same IP is dropped by fast-path firewall
        resp_fastpath = await client.get(
            "/courses",
            headers={"X-Forwarded-For": attacker_ip},
        )
        assert resp_fastpath.status_code == 403
        assert "Application Firewall" in resp_fastpath.text

        # Cleanup
        blocklist.unblock_ip(attacker_ip)
