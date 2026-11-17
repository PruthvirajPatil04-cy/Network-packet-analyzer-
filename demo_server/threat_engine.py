"""
Threat Analysis Engine for Simulated Student Portal.
Implements Tier 1 Deterministic Signatures and Tier 2 Behavioral Heuristics.
Evaluates every incoming request and yields (decision, score, reasons, severity).
"""

from __future__ import annotations
import re
import time
import threading
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import unquote, unquote_plus

# --- Tier 1 Regex Patterns ---

# SQL Injection
SQLI_PATTERNS = [
    re.compile(r"(\bunion\b.*\bselect\b)", re.IGNORECASE),
    re.compile(r"('\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1)", re.IGNORECASE),
    re.compile(r"(;\s*drop\s+table)", re.IGNORECASE),
    re.compile(r"(--|#|/\*).*(or|and|select|drop)", re.IGNORECASE),
    re.compile(r"('\s*or\s+1\s*=\s*1)", re.IGNORECASE),
    re.compile(r"(\bwaitfor\s+delay\b)", re.IGNORECASE),
    re.compile(r"(\bexec(\s|\+)+(s|x)p\w+)", re.IGNORECASE),
]

# Path Traversal
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\)"),
    re.compile(r"(\.\.%2f|%2e%2e%2f|%2e%2e/)", re.IGNORECASE),
    re.compile(r"(%252e%252e%252f)", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|c:\\windows)", re.IGNORECASE),
]

# Cross-Site Scripting (XSS)
XSS_PATTERNS = [
    re.compile(r"(<script\b[^>]*>)", re.IGNORECASE),
    re.compile(r"(onerror\s*=)", re.IGNORECASE),
    re.compile(r"(javascript\s*:)", re.IGNORECASE),
    re.compile(r"(onload\s*=)", re.IGNORECASE),
    re.compile(r"(<svg\b[^>]*onload\b)", re.IGNORECASE),
    re.compile(r"(<img\b[^>]*src\s*=\s*x)", re.IGNORECASE),
]

# Command Injection
CMD_INJECTION_PATTERNS = [
    re.compile(r"(;\s*(ls|cat|whoami|id|rm|curl|wget|sh|bash)\b)", re.IGNORECASE),
    re.compile(r"(\|\s*(cat|ls|id|whoami|sh)\b)", re.IGNORECASE),
    re.compile(r"(\$\(.*\))"),
    re.compile(r"(`.*`)"),
    re.compile(r"(&&\s*(cat|ls|whoami|id)\b)", re.IGNORECASE),
]

# Bad User Agents
KNOWN_BAD_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "curl/0.", "zgrab",
    "gobuster", "dirbuster", "wpscan", "metasploit", "nuclei"
]

# Honeypot Target Endpoints
HONEYPOT_PATHS = {
    "/wp-admin", "/phpmyadmin", "/.env", "/.git", "/backup.sql",
    "/server-status", "/config.json", "/aws.credentials"
}


class ThreatEngine:
    """
    Real-time defensive security engine evaluating HTTP traffic.
    Combines deterministic signatures (instant block) with sliding-window
    behavioral heuristics (brute-force, rate flooding, port scanning).
    """

    def __init__(self):
        self._lock = threading.Lock()
        # Behavioral tracking: ip -> deque of timestamps
        self._request_history: Dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=300))
        self._failed_logins: Dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._ports_seen: Dict[str, Dict[int, float]] = defaultdict(dict)
        self._fuzz_404s: Dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=50))

    def evaluate_request(
        self,
        src_ip: str,
        path: str,
        method: str,
        headers: Dict[str, str],
        body_str: str = "",
        query_str: str = "",
        dest_port: int = 8001,
        admin_token: Optional[str] = None,
    ) -> Tuple[str, float, List[str], str]:
        """
        Evaluate an incoming HTTP request.
        Returns:
            (decision: 'allow'|'throttle'|'block', score: float, reasons: list[str], severity: str)
        """
        now = time.time()
        score = 0.0
        reasons = []
        highest_severity = "LOW"

        # Combine text surfaces for signature matching (URL-decoded with plus-to-space normalization)
        full_path = unquote_plus(path)
        full_query = unquote_plus(query_str)
        full_body = unquote_plus(body_str)
        text_surface = f"{full_path} ?{full_query} \n{full_body}".lower()

        user_agent = headers.get("user-agent", "").lower()

        # ==========================================
        # TIER 1: DETERMINISTIC SIGNATURES
        # ==========================================

        # 1. SQL Injection (CRITICAL -> Instant Block)
        for pat in SQLI_PATTERNS:
            if pat.search(text_surface):
                score += 1.0
                reasons.append("SQL Injection signature detected in request body/query")
                highest_severity = "CRITICAL"
                break

        # 2. Path Traversal (CRITICAL -> Instant Block)
        for pat in PATH_TRAVERSAL_PATTERNS:
            if pat.search(text_surface):
                score += 1.0
                reasons.append("Path traversal sequence detected (../ or encoded bypass)")
                highest_severity = "CRITICAL"
                break

        # 3. Command Injection (CRITICAL -> Instant Block)
        for pat in CMD_INJECTION_PATTERNS:
            if pat.search(text_surface):
                score += 1.0
                reasons.append("OS command injection syntax detected")
                highest_severity = "CRITICAL"
                break

        # 4. XSS Payloads (HIGH -> 0.85)
        for pat in XSS_PATTERNS:
            if pat.search(text_surface):
                score += 0.85
                reasons.append("Cross-Site Scripting (XSS) payload in parameter")
                if highest_severity != "CRITICAL":
                    highest_severity = "HIGH"
                break

        # 5. Known-bad User-Agents (HIGH -> 0.85)
        for bad_ua in KNOWN_BAD_USER_AGENTS:
            if bad_ua in user_agent:
                score += 0.85
                reasons.append(f"Automated exploit/scanner tool detected: {bad_ua}")
                if highest_severity != "CRITICAL":
                    highest_severity = "HIGH"
                break

        # 6. Honeypot Hit on /admin (HIGH -> 0.90)
        if full_path == "/admin" or full_path.startswith("/admin/"):
            if not admin_token or admin_token != "super-secret-admin-token-2026":
                score += 0.90
                reasons.append("Unauthorized access attempt to administrative honeypot /admin")
                if highest_severity != "CRITICAL":
                    highest_severity = "HIGH"

        # 7. Known scanning endpoints (MEDIUM -> 0.70)
        if any(full_path.startswith(hp) for hp in HONEYPOT_PATHS):
            score += 0.70
            reasons.append(f"Reconnaissance probe against sensitive path: {full_path}")
            if highest_severity == "LOW":
                highest_severity = "MEDIUM"

        # ==========================================
        # TIER 2: BEHAVIORAL HEURISTICS
        # ==========================================
        with self._lock:
            req_deque = self._request_history[src_ip]
            req_deque.append(now)

            # Evict timestamps older than 60s
            while req_deque and now - req_deque[0] > 60.0:
                req_deque.popleft()

            # A. Rate Flood Check (>100 requests in 10s)
            recent_10s = sum(1 for t in req_deque if now - t <= 10.0)
            if recent_10s > 100:
                score += 0.85
                reasons.append(f"High-frequency request flood: {recent_10s} reqs in 10s")
                if highest_severity != "CRITICAL":
                    highest_severity = "HIGH"
            elif recent_10s > 50:
                score += 0.45
                reasons.append(f"Elevated request rate: {recent_10s} reqs in 10s")
                if highest_severity == "LOW":
                    highest_severity = "MEDIUM"

            # B. Burst / SYN-flood pattern (>50 requests in 5s)
            recent_5s = sum(1 for t in req_deque if now - t <= 5.0)
            if recent_5s > 50:
                score += 0.80
                reasons.append(f"Traffic burst anomaly: {recent_5s} reqs in 5s")
                if highest_severity != "CRITICAL":
                    highest_severity = "HIGH"

            # C. Port Scanning Heuristic (>15 distinct destination ports in 30s)
            ports_map = self._ports_seen[src_ip]
            ports_map[dest_port] = now
            # Clean ports older than 30s
            expired_ports = [p for p, ts in ports_map.items() if now - ts > 30.0]
            for p in expired_ports:
                del ports_map[p]
            if len(ports_map) >= 15:
                score += 0.65
                reasons.append(f"Horizontal port scan detected across {len(ports_map)} ports")
                if highest_severity == "LOW":
                    highest_severity = "MEDIUM"

            # D. Brute Force Login Check (>5 failed logins in 60s)
            failed_deque = self._failed_logins[src_ip]
            while failed_deque and now - failed_deque[0] > 60.0:
                failed_deque.popleft()
            if len(failed_deque) >= 5:
                score += 0.85
                reasons.append(f"Credential brute force detected: {len(failed_deque)} failed logins in 60s")
                if highest_severity != "CRITICAL":
                    highest_severity = "HIGH"

            # E. Path Fuzzing Check (>20 404s in 60s)
            fuzz_deque = self._fuzz_404s[src_ip]
            while fuzz_deque and now - fuzz_deque[0] > 60.0:
                fuzz_deque.popleft()
            if len(fuzz_deque) >= 20:
                score += 0.60
                reasons.append(f"Suspicious path fuzzing: {len(fuzz_deque)} not-found requests")
                if highest_severity == "LOW":
                    highest_severity = "MEDIUM"

        # ==========================================
        # DECISION LOGIC
        # ==========================================
        final_score = min(1.0, round(score, 2))

        if final_score >= 0.8 or highest_severity == "CRITICAL":
            decision = "block"
        elif 0.4 <= final_score < 0.8:
            decision = "throttle"
        else:
            decision = "allow"

        return decision, final_score, reasons, highest_severity

    def record_failed_login(self, src_ip: str) -> None:
        """Call this when a login attempt fails for credential brute-force tracking."""
        with self._lock:
            self._failed_logins[src_ip].append(time.time())

    def record_404(self, src_ip: str) -> None:
        """Call this on 404 response to track path fuzzing attacks."""
        with self._lock:
            self._fuzz_404s[src_ip].append(time.time())


# Singleton instance for demo server
threat_engine = ThreatEngine()
