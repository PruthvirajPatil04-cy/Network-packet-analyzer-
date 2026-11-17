"""
Antigravity AI SOC Advisory Agent for Live Demo Server.
Asynchronously analyzes suspicious security events (score >= 0.4) using Gemini AI,
rate-limited to <= 10 calls/min, cached per signature for 60s, and completely decoupled
from the hot request path.
"""

from __future__ import annotations
import os
import time
import json
import asyncio
import logging
from typing import Dict, Any, Optional, Tuple
from collections import deque

logger = logging.getLogger("backend.antigravity.soc_server_agent")

# Optional Google Antigravity SDK
try:
    from google.antigravity import Agent, LocalAgentConfig
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False
    Agent = None
    LocalAgentConfig = None


SYSTEM_PROMPT = """You are a senior Tier-3 SOC Security Analyst at a university campus.
Review this suspicious HTTP telemetry event and matched threat rules.
You MUST respond with valid JSON containing exactly three keys:
1. "classification": "benign" | "suspicious" | "malicious"
2. "explanation": A single clear, concise sentence explaining the attack nature.
3. "recommended_action": A concrete tactical mitigation (e.g. Block source IP, quarantine session, inspect firewall ACL).
No Markdown formatting, no code blocks, just raw JSON.
"""


class SOCServerAgent:
    """
    Advisory SOC agent for Live Server events.
    Enriches suspicious events with Gemini AI forensic analysis.
    """

    def __init__(self, max_calls_per_minute: int = 10, cache_ttl: float = 60.0):
        self.max_calls_per_minute = max_calls_per_minute
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._call_timestamps: deque[float] = deque(maxlen=max_calls_per_minute * 2)
        self._lock = asyncio.Lock()
        self.total_explanations_generated = 0

    async def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a suspicious event (score >= 0.4).
        Returns enriched dict or cached response.
        """
        reasons = event.get("reasons", [])
        sig_key = ";".join(reasons) if reasons else event.get("path", "")
        now = time.time()

        # Check Cache
        async with self._lock:
            if sig_key in self._cache:
                cached_time, cached_result = self._cache[sig_key]
                if now - cached_time < self.cache_ttl:
                    return cached_result

            # Rate Limit Check (<= 10 calls per minute)
            while self._call_timestamps and now - self._call_timestamps[0] > 60.0:
                self._call_timestamps.popleft()

            if len(self._call_timestamps) >= self.max_calls_per_minute:
                logger.debug("Antigravity rate limit reached, returning heuristic advisory")
                return self._fallback_advisory(event)

            self._call_timestamps.append(now)

        # Call Gemini via Antigravity SDK if available
        api_key = os.environ.get("GEMINI_API_KEY")
        if SDK_AVAILABLE and api_key:
            try:
                config = LocalAgentConfig(
                    system_instructions=SYSTEM_PROMPT,
                    api_key=api_key,
                )
                async with Agent(config) as agent:
                    prompt = (
                        f"HTTP Event: Method={event.get('method')}, Path={event.get('path')}, "
                        f"IP={event.get('src_ip')}, Score={event.get('score')}, "
                        f"Rules Matched={json.dumps(reasons)}"
                    )
                    resp = await agent.chat(prompt)
                    raw_text = (await resp.text()).strip()
                    # Strip any markdown fences if model returned them
                    if raw_text.startswith("```"):
                        raw_text = raw_text.split("```")[1]
                        if raw_text.startswith("json"):
                            raw_text = raw_text[4:]
                    parsed = json.loads(raw_text.strip())
                    async with self._lock:
                        self._cache[sig_key] = (now, parsed)
                        self.total_explanations_generated += 1
                    return parsed
            except Exception as e:
                logger.debug(f"Antigravity SDK call failed: {e}")

        # Fallback heuristic explanation
        result = self._fallback_advisory(event)
        async with self._lock:
            self._cache[sig_key] = (now, result)
        return result

    def _fallback_advisory(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic heuristic explanation when AI SDK is offline."""
        reasons = event.get("reasons", [])
        path = event.get("path", "")
        reason_str = "; ".join(reasons) if reasons else f"Anomalous activity on {path}"

        if "SQL Injection" in reason_str:
            return {
                "classification": "malicious",
                "explanation": "Detected classic SQL injection syntax attempting to bypass login authentication or extract database tables.",
                "recommended_action": "Block source IP immediately and sanitize query parameters via prepared statements.",
            }
        elif "Path traversal" in reason_str:
            return {
                "classification": "malicious",
                "explanation": "Directory traversal sequence detected attempting unauthorized read of sensitive host operating system files.",
                "recommended_action": "Reject path parameter and enforce strict chroot canonical path validation.",
            }
        elif "XSS" in reason_str:
            return {
                "classification": "malicious",
                "explanation": "Cross-Site Scripting vector detected attempting to execute unauthorized JavaScript in client browsers.",
                "recommended_action": "Sanitize input forms and deploy strict Content-Security-Policy (CSP) headers.",
            }
        elif "brute force" in reason_str.lower():
            return {
                "classification": "malicious",
                "explanation": "High-velocity credential stuffing attack targeting student portal accounts.",
                "recommended_action": "Enforce temporary IP lockout, require CAPTCHA, and reset compromised account credentials.",
            }
        elif "admin" in path.lower() or "honeypot" in reason_str.lower():
            return {
                "classification": "suspicious",
                "explanation": "Host reconnaissance detected targeting administrative honeypot endpoints without authorization.",
                "recommended_action": "Maintain active block on source IP and alert security operations of enumeration probe.",
            }

        return {
            "classification": "suspicious" if event.get("score", 0) >= 0.4 else "benign",
            "explanation": f"Network security rule match: {reason_str}.",
            "recommended_action": "Block source IP if score exceeds threshold; otherwise throttle connection.",
        }


# Global singleton instance
soc_server_agent = SOCServerAgent()
