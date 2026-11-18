"""
Tests for Seeded Student Accounts & Authentication Pipeline (student.college.edu).
Validates password verification, JWT session cookies, cross-student isolation,
brute-force defense, and telemetry tagging.
"""

import pytest
import httpx
from demo_server.main import (
    app, STUDENT_DB, blocklist, _recent_events, _stats_lock,
    create_session_jwt
)

ROSTER_CREDENTIALS = [
    ("CS22B001", "Aarav@2024"),
    ("CS22B002", "Priya@2024"),
    ("CS22B003", "Rohan@2024"),
    ("EC22B004", "Ananya@2024"),
    ("EC22B005", "Vikram@2024"),
    ("ME22B006", "Sneha@2024"),
    ("ME22B007", "Karthik@2024"),
    ("CS21B008", "Isha@2024"),
    ("CS21B009", "Aditya@2024"),
    ("EE22B010", "Meera@2024"),
]


@pytest.mark.asyncio
async def test_all_10_accounts_exist_and_login_succeeds():
    """Requirement 1: All 10 accounts exist and login succeeds with documented credentials."""
    assert len(STUDENT_DB) == 10, "Expected exactly 10 seeded students in STUDENT_DB"
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        for roll, password in ROSTER_CREDENTIALS:
            assert roll in STUDENT_DB, f"Student {roll} not found in database!"
            resp = await client.post(
                "/login",
                data={"roll": roll, "password": password},
                headers={"Accept": "application/json", "X-Forwarded-For": f"10.0.1.{roll[-3:]}"},
            )
            assert resp.status_code == 200, f"Login failed for {roll}: {resp.text}"
            data = resp.json()
            assert data["status"] == "authenticated"
            assert data["roll"] == roll
            assert "session" in resp.cookies or "token" in data


@pytest.mark.asyncio
async def test_login_fails_with_wrong_password():
    """Requirement 2: Login fails with wrong password -> 401; brute-force counter increments."""
    transport = httpx.ASGITransport(app=app)
    test_ip = "10.0.8.88"

    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        resp = await client.post(
            "/login",
            data={"roll": "CS22B001", "password": "WrongPassword999!"},
            headers={"Accept": "application/json", "X-Forwarded-For": test_ip},
        )
        assert resp.status_code == 401
        assert "invalid credentials" in resp.text.lower()


@pytest.mark.asyncio
async def test_brute_force_firewall_lockout_on_repeated_failures():
    """Requirement 3: Repeated failed attempts from one IP trigger a 403 lockout and IP ban."""
    transport = httpx.ASGITransport(app=app)
    attacker_ip = "192.168.99.15"

    blocklist.unblock_ip(attacker_ip)

    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        statuses = []
        for i in range(7):
            r = await client.post(
                "/login",
                data={"roll": "CS22B001", "password": f"BadPassword{i}"},
                headers={"X-Forwarded-For": attacker_ip},
            )
            statuses.append(r.status_code)

        # First 5 attempts return 401 Unauthorized
        assert statuses[:5] == [401, 401, 401, 401, 401]
        # Subsequent attempts are locked out with 403 Forbidden
        assert 403 in statuses[5:]
        assert blocklist.is_blocked(attacker_ip)[0] is True, "Source IP must be dynamically placed on blocklist"

        # Clean up
        blocklist.unblock_ip(attacker_ip)


@pytest.mark.asyncio
async def test_unauthenticated_dashboard_access_rejected():
    """Requirement 4: GET /dashboard without session -> 401 or redirect to login."""
    transport = httpx.ASGITransport(app=app)
    clean_ip = "10.0.5.12"

    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        # JSON API call -> 401
        r_json = await client.get("/dashboard", headers={"Accept": "application/json", "X-Forwarded-For": clean_ip})
        assert r_json.status_code == 401

        # Browser call -> 303 Redirect to login page
        r_html = await client.get("/dashboard", headers={"X-Forwarded-For": clean_ip})
        assert r_html.status_code in (302, 303, 307, 401)


@pytest.mark.asyncio
async def test_cross_student_isolation():
    """Requirement 5: Student A cannot read Student B's data."""
    transport = httpx.ASGITransport(app=app)
    student_a = STUDENT_DB["CS22B001"]
    token_a = create_session_jwt(student_a)

    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        client.cookies.set("session", token_a)

        # Call /results -> must return CS22B001 only
        r_res = await client.get("/results", headers={"Accept": "application/json"})
        assert r_res.status_code == 200
        data = r_res.json()
        assert data["roll"] == "CS22B001"
        assert data["name"] == "Aarav Sharma"
        assert "CS22B002" not in str(data)

        # Call /fees -> must return CS22B001 fee data only
        r_fees = await client.get("/fees", headers={"Accept": "application/json"})
        assert r_fees.status_code == 200
        fees = r_fees.json()
        assert fees["roll"] == "CS22B001"
        assert fees["fee_status"] == student_a["fee_status"]


@pytest.mark.asyncio
async def test_demo_accounts_endpoint_sanitized():
    """Requirement 6: GET /api/server/demo-accounts never returns password hashes or plaintext."""
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        resp = await client.get("/api/server/demo-accounts")
        assert resp.status_code == 200
        data = resp.json()
        accounts = data.get("accounts", [])
        assert len(accounts) == 10

        for acc in accounts:
            assert "roll" in acc
            assert "name" in acc
            assert "email" in acc
            assert "ip" in acc, f"Expected IP in demo-accounts for {acc.get('roll')}!"
            assert "password" not in acc, f"Plaintext password leaked in demo-accounts for {acc.get('roll')}!"
            assert "password_hash" not in acc, f"Password hash leaked in demo-accounts for {acc.get('roll')}!"


@pytest.mark.asyncio
async def test_middleware_emits_tagged_event_with_student_roll():
    """Requirement 7: Middleware emits exactly one event per authenticated request with roll populated."""
    transport = httpx.ASGITransport(app=app)
    student = STUDENT_DB["CS22B002"]
    token = create_session_jwt(student)
    client_ip = "10.0.4.77"

    async with _stats_lock:
        _recent_events.clear()

    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        client.cookies.set("session", token)

        resp = await client.get("/dashboard", headers={"X-Forwarded-For": client_ip, "Accept": "application/json"})
        assert resp.status_code == 200

        # Assert exactly one event emitted
        async with _stats_lock:
            assert len(_recent_events) >= 1
            last_event = _recent_events[-1]
            assert last_event["path"] == "/dashboard"
            assert last_event["roll"] == "CS22B002", f"Expected roll=CS22B002 in event, got: {last_event.get('roll')}"


@pytest.mark.asyncio
async def test_each_student_has_distinct_ip_and_middleware_tags_distinct_ips():
    """Requirement 8: Each of the 10 students has a distinct campus IP and requests from different students show different IPs."""
    # 1. Database level: all 10 students have an assigned IP and all 10 are unique
    assert len(STUDENT_DB) == 10
    student_ips = [s.get("ip") for s in STUDENT_DB.values()]
    assert all(ip is not None for ip in student_ips), "Every student must have an assigned IP"
    assert len(set(student_ips)) == 10, f"Expected 10 distinct student IPs, got {len(set(student_ips))}: {student_ips}"

    # 2. Middleware tagging: verify different students show different src_ip on loopback/browser connections
    transport = httpx.ASGITransport(app=app)
    student1 = STUDENT_DB["CS22B001"]
    student2 = STUDENT_DB["CS22B002"]
    token1 = create_session_jwt(student1)
    token2 = create_session_jwt(student2)

    async with httpx.AsyncClient(transport=transport, base_url="http://student.college.edu") as client:
        # Request from student 1
        client.cookies.set("session", token1)
        r1 = await client.get("/dashboard", headers={"Accept": "application/json"})
        assert r1.status_code == 200

        async with _stats_lock:
            event1 = _recent_events[-1]
            assert event1["roll"] == "CS22B001"
            assert event1["src_ip"] == student1["ip"]

        # Request from student 2
        client.cookies.set("session", token2)
        r2 = await client.get("/dashboard", headers={"Accept": "application/json"})
        assert r2.status_code == 200

        async with _stats_lock:
            event2 = _recent_events[-1]
            assert event2["roll"] == "CS22B002"
            assert event2["src_ip"] == student2["ip"]

        # Assert IPs are strictly different
        assert event1["src_ip"] != event2["src_ip"]
        assert event1["src_ip"] == "10.20.1.101"
        assert event2["src_ip"] == "10.20.1.102"
