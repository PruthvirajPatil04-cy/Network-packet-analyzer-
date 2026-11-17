"""
Unit tests for the Threat Analysis Engine (Tier 1 & Tier 2 detection rules).
"""

import time
import pytest
from demo_server.threat_engine import ThreatEngine


@pytest.fixture
def engine():
    return ThreatEngine()


# --- Tier 1 Deterministic Signatures ---

def test_sqli_union_select(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.1",
        path="/courses",
        method="GET",
        headers={"user-agent": "Mozilla/5.0"},
        query_str="q=CS' UNION SELECT null,username,password FROM users--",
    )
    assert decision == "block"
    assert score >= 0.8
    assert severity == "CRITICAL"
    assert any("SQL Injection" in r for r in reasons)


def test_sqli_auth_bypass(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.2",
        path="/login",
        method="POST",
        headers={"user-agent": "Mozilla/5.0"},
        body_str="username=admin' OR '1'='1&password=foo",
    )
    assert decision == "block"
    assert severity == "CRITICAL"
    assert any("SQL Injection" in r for r in reasons)


def test_path_traversal(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.3",
        path="/results",
        method="GET",
        headers={"user-agent": "Mozilla/5.0"},
        query_str="file=../../../../etc/passwd",
    )
    assert decision == "block"
    assert severity == "CRITICAL"
    assert any("Path traversal" in r for r in reasons)


def test_path_traversal_encoded(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.4",
        path="/courses",
        method="GET",
        headers={"user-agent": "Mozilla/5.0"},
        query_str="doc=..%2f..%2fwindows%2fwin.ini",
    )
    assert decision == "block"
    assert severity == "CRITICAL"
    assert any("Path traversal" in r for r in reasons)


def test_command_injection(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.5",
        path="/results",
        method="GET",
        headers={"user-agent": "Mozilla/5.0"},
        query_str="id=101; whoami",
    )
    assert decision == "block"
    assert severity == "CRITICAL"
    assert any("OS command injection" in r for r in reasons)


def test_xss_payload(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.6",
        path="/courses/enroll",
        method="POST",
        headers={"user-agent": "Mozilla/5.0"},
        body_str="course_code=<script>alert('pwned')</script>",
    )
    assert decision == "block"
    assert score >= 0.8
    assert any("XSS" in r for r in reasons)


def test_known_bad_user_agent(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.7",
        path="/",
        method="GET",
        headers={"user-agent": "sqlmap/1.7#stable"},
    )
    assert decision == "block"
    assert any("Automated exploit/scanner" in r for r in reasons)


def test_honeypot_admin_without_token(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.8",
        path="/admin",
        method="GET",
        headers={"user-agent": "Mozilla/5.0"},
    )
    assert decision == "block"
    assert any("honeypot" in r.lower() for r in reasons)


def test_honeypot_scanning_path(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="10.0.5.9",
        path="/wp-admin",
        method="GET",
        headers={"user-agent": "Mozilla/5.0"},
    )
    # Score 0.70 -> throttle
    assert decision in ("throttle", "block")
    assert any("Reconnaissance probe" in r for r in reasons)


# --- Tier 2 Behavioral Heuristics ---

def test_credential_brute_force(engine):
    attacker_ip = "10.0.9.1"
    # Record 5 failed logins
    for _ in range(5):
        engine.record_failed_login(attacker_ip)

    # Next request triggers brute force rule
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip=attacker_ip,
        path="/login",
        method="POST",
        headers={"user-agent": "Mozilla/5.0"},
        body_str="username=student&password=bad",
    )
    assert decision == "block"
    assert any("brute force" in r.lower() for r in reasons)


def test_rate_flood_heuristic(engine):
    flooder_ip = "10.0.9.2"
    # Send 105 rapid requests
    for _ in range(105):
        engine.evaluate_request(
            src_ip=flooder_ip,
            path="/courses",
            method="GET",
            headers={"user-agent": "Mozilla/5.0"},
        )

    decision, score, reasons, severity = engine.evaluate_request(
        src_ip=flooder_ip,
        path="/courses",
        method="GET",
        headers={"user-agent": "Mozilla/5.0"},
    )
    assert decision == "block"
    assert any("request flood" in r.lower() for r in reasons)


def test_port_scan_heuristic(engine):
    scanner_ip = "10.0.9.3"
    # Hit 16 distinct ports
    for port in range(1000, 1016):
        engine.evaluate_request(
            src_ip=scanner_ip,
            path="/",
            method="GET",
            headers={"user-agent": "Mozilla/5.0"},
            dest_port=port,
        )

    decision, score, reasons, severity = engine.evaluate_request(
        src_ip=scanner_ip,
        path="/",
        method="GET",
        headers={"user-agent": "Mozilla/5.0"},
        dest_port=1020,
    )
    assert any("port scan" in r.lower() for r in reasons)


def test_benign_traffic_allowed(engine):
    decision, score, reasons, severity = engine.evaluate_request(
        src_ip="192.168.1.50",
        path="/courses",
        method="GET",
        headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0)"},
        query_str="page=1",
    )
    assert decision == "allow"
    assert score < 0.4
    assert len(reasons) == 0
