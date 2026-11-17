"""
Unit tests for SimulatedFirewallBlocklist (fast path, TTL auto-eviction, hit counters, unblock).
"""

import time
import pytest
from demo_server.blocklist import SimulatedFirewallBlocklist


def test_block_and_fast_path():
    bl = SimulatedFirewallBlocklist(default_ttl=10)
    ip = "10.0.5.1"

    is_blocked, entry = bl.is_blocked(ip)
    assert is_blocked is False

    bl.block_ip(ip, reason="SQL Injection", score=1.0)

    is_blocked, entry = bl.is_blocked(ip)
    assert is_blocked is True
    assert entry.ip == ip
    assert entry.reason == "SQL Injection"
    assert entry.hits == 2  # Block increment + is_blocked increment


def test_blocklist_ttl_expiry():
    bl = SimulatedFirewallBlocklist(default_ttl=1)
    ip = "10.0.5.2"

    bl.block_ip(ip, reason="Temporary Ban", score=0.8, ttl=1)
    is_blocked, _ = bl.is_blocked(ip)
    assert is_blocked is True

    # Sleep past TTL
    time.sleep(1.1)

    is_blocked, _ = bl.is_blocked(ip)
    assert is_blocked is False
    assert bl.count() == 0


def test_manual_unblock():
    bl = SimulatedFirewallBlocklist(default_ttl=100)
    ip = "10.0.5.3"

    bl.block_ip(ip, reason="XSS", score=0.9)
    assert bl.is_blocked(ip)[0] is True

    unblocked = bl.unblock_ip(ip)
    assert unblocked is True
    assert bl.is_blocked(ip)[0] is False


def test_blocklist_clear():
    bl = SimulatedFirewallBlocklist(default_ttl=100)
    bl.block_ip("10.0.0.1", "Reason 1", 1.0)
    bl.block_ip("10.0.0.2", "Reason 2", 1.0)
    assert bl.count() == 2

    bl.clear()
    assert bl.count() == 0
