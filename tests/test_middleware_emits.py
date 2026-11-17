"""
Tests ensuring that EVERY real HTTP request to the student portal produces
exactly ONE event emitted through the ASGI middleware, and zero events for internal health/mgmt.
"""

import pytest
import httpx
from demo_server.main import app, blocklist, _recent_events, _stats_lock


@pytest.mark.asyncio
async def test_middleware_emits_one_event_per_request():
    """
    Hit each student portal route once and assert exactly one event is emitted per request.
    """
    transport = httpx.ASGITransport(app=app)
    base_url = "http://student.college.edu"
    clean_ip = "10.0.8.20"

    async with _stats_lock:
        _recent_events.clear()

    async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
        # 1. GET / (login page)
        r1 = await client.get("/", headers={"X-Forwarded-For": clean_ip})
        assert r1.status_code == 200
        assert len(_recent_events) == 1
        assert _recent_events[-1]["path"] == "/"
        assert _recent_events[-1]["decision"] == "allow"

        # 2. POST /login (valid credentials)
        r2 = await client.post(
            "/login",
            data={"username": "student", "password": "college2026"},
            headers={"X-Forwarded-For": clean_ip},
        )
        assert r2.status_code in (200, 303)
        assert len(_recent_events) == 2
        assert _recent_events[-1]["path"] == "/login"
        assert _recent_events[-1]["decision"] == "allow"

        # 3. POST /login (wrong password)
        r3 = await client.post(
            "/login",
            data={"username": "student", "password": "badpassword1"},
            headers={"X-Forwarded-For": clean_ip},
        )
        assert r3.status_code == 401
        assert len(_recent_events) == 3
        assert _recent_events[-1]["path"] == "/login"

        # 4. GET /dashboard
        r4 = await client.get("/dashboard", headers={"X-Forwarded-For": clean_ip})
        assert r4.status_code == 200
        assert len(_recent_events) == 4
        assert _recent_events[-1]["path"] == "/dashboard"

        # 5. GET /courses
        r5 = await client.get("/courses", headers={"X-Forwarded-For": clean_ip})
        assert r5.status_code == 200
        assert len(_recent_events) == 5
        assert _recent_events[-1]["path"] == "/courses"

        # 6. POST /courses/enroll
        r6 = await client.post(
            "/courses/enroll",
            data={"course_id": "CS401"},
            headers={"X-Forwarded-For": clean_ip},
        )
        assert r6.status_code == 200
        assert len(_recent_events) == 6
        assert _recent_events[-1]["path"] == "/courses/enroll"

        # 7. GET /results
        r7 = await client.get("/results", headers={"X-Forwarded-For": clean_ip})
        assert r7.status_code == 200
        assert len(_recent_events) == 7
        assert _recent_events[-1]["path"] == "/results"

        # 8. GET /fees
        r8 = await client.get("/fees", headers={"X-Forwarded-For": clean_ip})
        assert r8.status_code == 200
        assert len(_recent_events) == 8
        assert _recent_events[-1]["path"] == "/fees"

        # 9. GET /admin (unauthorized probe -> honeypot BLOCK)
        attacker_ip = "10.0.8.99"
        r9 = await client.get("/admin", headers={"X-Forwarded-For": attacker_ip})
        assert r9.status_code == 403
        assert len(_recent_events) == 9
        assert _recent_events[-1]["path"] == "/admin"
        assert _recent_events[-1]["decision"] == "block"

        # 10. Subsequent request from blocked IP -> fast-path BLOCK
        r10 = await client.get("/courses", headers={"X-Forwarded-For": attacker_ip})
        assert r10.status_code == 403
        assert len(_recent_events) == 10
        assert _recent_events[-1]["decision"] == "block"
        assert "previously blocked" in _recent_events[-1]["reasons"][0]

        # 11. Internal health check & sync APIs must NOT emit to the student event stream
        r_health = await client.get("/health")
        assert r_health.status_code == 200
        assert len(_recent_events) == 10  # Untouched!

        r_blocked = await client.get("/api/blocked")
        assert r_blocked.status_code == 200
        assert len(_recent_events) == 10  # Untouched!

        # Cleanup
        blocklist.unblock_ip(attacker_ip)


@pytest.mark.asyncio
async def test_brute_force_real_user_actions():
    """
    Asserts that 6 consecutive wrong password submissions from a single IP
    trigger a brute force BLOCK on the 6th attempt.
    """
    transport = httpx.ASGITransport(app=app)
    base_url = "http://student.college.edu"
    bf_ip = "10.0.8.55"

    blocklist.unblock_ip(bf_ip)

    async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
        # First 5 wrong logins
        for i in range(5):
            r = await client.post(
                "/login",
                data={"username": "student", "password": f"wrong_{i}"},
                headers={"X-Forwarded-For": bf_ip},
            )
            assert r.status_code == 401

        # 6th attempt -> Brute-force threshold breached, returns 403
        r6 = await client.post(
            "/login",
            data={"username": "student", "password": "wrong_6"},
            headers={"X-Forwarded-For": bf_ip},
        )
        assert r6.status_code == 403
        assert blocklist.is_blocked(bf_ip)[0] is True

        # Cleanup
        blocklist.unblock_ip(bf_ip)
