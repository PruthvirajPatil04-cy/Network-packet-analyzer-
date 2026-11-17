"""
Decoupled SOC Detection Agent.
Consumes packets from the backend stream / WebSocket, applies anomaly detection
rules, leverages Google Antigravity SDK for Gemini-driven triage, and posts alerts.
"""

from __future__ import annotations
import os
import sys
import time
import json
import signal
import uuid
import asyncio
import logging
from typing import Optional, Dict, Any

import httpx
import websockets

from detector import AnomalyDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [soc-agent] %(message)s"
)
logger = logging.getLogger("soc-agent")

# Optional Antigravity SDK
try:
    from google.antigravity import Agent, LocalAgentConfig
    ANTIGRAVITY_AVAILABLE = True
except ImportError:
    ANTIGRAVITY_AVAILABLE = False
    Agent = None
    LocalAgentConfig = None


PLAYBOOKS = {
    "DoS / FLOOD": "Initiate rate limiting on ingress firewall and isolate source subnet.",
    "PORT SCAN": "Block scanning source IP and inspect targeted service ports for vulnerabilities.",
    "SSH BRUTE FORCE": "Enforce fail2ban rule, block source IP, and expire targeted credentials.",
    "ICMP FLOOD": "Throttle ICMP echo requests and drop malformed ping packets at edge gateway.",
    "NULL SCAN": "Block stealth scan origin and audit TCP stack configuration.",
    "XMAS SCAN": "Drop invalid TCP flag combinations and register source in threat intel list.",
    "MALICIOUS FILE": "Quarantine transferred file hash and alert endpoint detection response (EDR).",
}


class SOCAgentConsumer:
    """
    Decoupled SOC consumer service.
    Consumes live packets from backend WebSocket, applies detection rules,
    enriches with AI reasoning, and publishes alerts to /api/alerts.
    """

    def __init__(
        self,
        backend_url: str = "http://localhost:8000",
        ws_url: Optional[str] = None,
        api_key: str = "packet-analyzer-secret-key-2026",
    ):
        self.backend_url = backend_url.rstrip("/")
        if ws_url:
            self.ws_url = ws_url
        else:
            base_ws = self.backend_url.replace("http://", "ws://").replace("https://", "wss://")
            self.ws_url = f"{base_ws}/ws/packets"

        self.api_key = api_key
        self.detector = AnomalyDetector()
        self._stop_event = asyncio.Event()
        self._http_client = httpx.AsyncClient(
            headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
            timeout=10.0,
        )

    async def start(self) -> None:
        """Connect to WebSocket stream and process incoming packets."""
        logger.info(f"SOC Agent starting. Subscribing to live stream at {self.ws_url}")
        retry_delay = 2.0

        while not self._stop_event.is_set():
            try:
                async with websockets.connect(self.ws_url) as ws:
                    logger.info("Connected to packet stream WebSocket.")
                    retry_delay = 2.0
                    while not self._stop_event.is_set():
                        msg = await ws.recv()
                        data = json.loads(msg)
                        if data.get("type") == "packet_batch":
                            packets = data.get("data", [])
                            for pkt in packets:
                                await self._analyze_packet(pkt)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"WebSocket connection error ({e}). Retrying in {retry_delay:.1f}s...")
                await asyncio.sleep(retry_delay)
                retry_delay = min(15.0, retry_delay * 1.5)

    async def stop(self) -> None:
        """Gracefully terminate agent."""
        logger.info("Stopping SOC Agent...")
        self._stop_event.set()
        await self._http_client.aclose()

    async def _analyze_packet(self, packet: Dict[str, Any]) -> None:
        """Run anomaly detection and dispatch alert on threat detection."""
        alert = self.detector.analyze(packet)
        if alert:
            alert_type = alert.get("type", "UNKNOWN")
            ip = alert.get("ip", "unknown")
            detail = alert.get("detail", "")
            severity = alert.get("severity", "HIGH")

            logger.info(f"🚨 Threat detected: {alert_type} from {ip}")

            # AI triage or playbook recommendation
            recommendation = await self._generate_recommendation(alert_type, ip, detail)

            alert_payload = {
                "id": str(uuid.uuid4()),
                "time": alert.get("time", datetime.now().strftime("%H:%M:%S")),
                "type": alert_type,
                "ip": ip,
                "detail": detail,
                "severity": severity,
                "confidence": 90,
                "timestamp_ms": time.time() * 1000,
                "recommendation": recommendation,
            }

            try:
                resp = await self._http_client.post(
                    f"{self.backend_url}/api/alerts", json=alert_payload
                )
                if resp.status_code == 201:
                    logger.info(f"Successfully published alert {alert_payload['id']} to backend")
            except Exception as e:
                logger.error(f"Failed to publish alert to backend: {e}")

    async def _generate_recommendation(self, alert_type: str, ip: str, detail: str) -> str:
        """Use Google Antigravity SDK if configured, or fall back to playbook."""
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if ANTIGRAVITY_AVAILABLE and gemini_key:
            try:
                config = LocalAgentConfig(
                    system_instructions="You are a network security SOC analyst. Provide a one-sentence tactical mitigation."
                )
                async with Agent(config) as agent:
                    prompt = f"Mitigate {alert_type} from {ip}. Detail: {detail}."
                    resp = await agent.chat(prompt)
                    text = await resp.text()
                    return text.strip()
            except Exception as e:
                logger.debug(f"Antigravity SDK call skipped: {e}")

        return PLAYBOOKS.get(alert_type, "Inspect traffic logs and enforce firewall ACL rule.")


def main() -> None:
    """CLI Entrypoint for running the decoupled SOC agent."""
    backend_url = os.environ.get("BACKEND_URL", "http://localhost:8000")
    api_key = os.environ.get("INGEST_API_KEY", "packet-analyzer-secret-key-2026")

    soc_agent = SOCAgentConsumer(backend_url=backend_url, api_key=api_key)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def handle_signal():
        logger.info("Signal received, stopping SOC agent...")
        loop.create_task(soc_agent.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_signal)
        except NotImplementedError:
            # Windows signal handler fallback
            pass

    try:
        loop.run_until_complete(soc_agent.start())
    except KeyboardInterrupt:
        loop.run_until_complete(soc_agent.stop())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
