import threading
import time
import json
import os
import urllib.request
import pathlib
from datetime import datetime
from collections import deque
try:
    from google.antigravity import Agent, LocalAgentConfig
    _SDK_AVAILABLE = True
except ImportError:
    Agent = None
    LocalAgentConfig = None
    _SDK_AVAILABLE = False

WEBHOOK_URL = os.environ.get("SOC_WEBHOOK_URL", "")
MEMORY_FILE = pathlib.Path("agent_memory.jsonl")

PLAYBOOKS = {
    "PORT SCAN": [
        ("BLOCK_IP", "block the scanning source"),
        ("RATE_LIMIT", "rate-limit destination port"),
        ("NOTIFY", "alert the analyst team"),
    ],
    "SSH BRUTE FORCE": [
        ("BLOCK_IP", "block the brute-force source"),
        ("LOCK_ACCOUNT", "force password reset on targeted account"),
        ("NOTIFY", "escalate to Tier 3"),
    ],
    "MALICIOUS FILE": [
        ("BLOCK_IP", "block the file source"),
        ("QUARANTINE", "mark the file for quarantine"),
        ("NOTIFY", "alert the analyst team"),
    ],
    "DEFAULT": [
        ("BLOCK_IP", "block the source"),
        ("NOTIFY", "log for review"),
    ],
}

def _notify_webhook(event: str, ip: str, reason: str, confidence: int = None) -> None:
    """Fire-and-forget POST. Silently no-op if no URL configured."""
    if not WEBHOOK_URL:
        return
    payload = {
        "text": f"🚨 SOC Agent {event}: `{ip}` — {reason}",
        "event": event,
        "ip": ip,
        "reason": reason,
        "confidence": confidence,
        "time": datetime.now().isoformat(),
    }
    try:
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=3.0)
    except Exception:
        pass

class AgentService:
    """Thread-safe state shared between the agent and any observer."""
    def __init__(self):
        self._lock = threading.Lock()
        self.blocked_ips: set[str] = set()
        self.decision_log: deque = deque(maxlen=200)
        self.verified_ips: dict[str, float] = {}
        self.agent_state: str = "IDLE"       # IDLE | MONITORING | INVESTIGATING | BLOCKING | ERROR
        self.current_task: str = "Waiting for suspicious activity..."
        self.actions_taken: int = 0
        self.verifications: int = 0
        self.tier_states = {"tier1": "IDLE", "tier2": "IDLE", "tier3": "IDLE"}
        self.tier_counts = {"tier1": 0, "tier2": 0, "tier3": 0}
        self._stop = threading.Event()
        self._history_path = MEMORY_FILE
        
        # Load any previously blocked IPs
        if self._history_path.exists():
            try:
                for line in self._history_path.read_text().splitlines():
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if entry.get("event") == "BLOCKED":
                        self.blocked_ips.add(entry["ip"])
            except Exception:
                pass   # corrupt file → start fresh

    def set_tier_state(self, tier: str, state: str) -> None:
        with self._lock:
            self.tier_states[tier] = state

    def bump_tier_count(self, tier: str) -> None:
        with self._lock:
            self.tier_counts[tier] += 1

    def should_verify(self, ip: str, cooldown_s: int = 60) -> bool:
        """Return True if we haven't verified this IP recently."""
        with self._lock:
            now_ms = time.time() * 1000
            last = self.verified_ips.get(ip, 0)
            if now_ms - last < cooldown_s * 1000:
                return False
            self.verified_ips[ip] = now_ms
            return True

    # Read-only accessors for the dashboard (thread-safe)
    def snapshot_log(self) -> list[dict]:
        with self._lock:
            return list(self.decision_log)

    def snapshot_blocked(self) -> set[str]:
        with self._lock:
            return set(self.blocked_ips)

    def snapshot_state(self) -> dict:
        with self._lock:
            return {
                "agent_state": self.agent_state,
                "current_task": self.current_task,
                "actions_taken": self.actions_taken,
                "verifications": self.verifications,
            }

    def block_ip(self, ip: str, reason: str, confidence: int = None, self_critique: str = None) -> None:
        with self._lock:
            self.blocked_ips.add(ip)
            self.decision_log.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "event": "BLOCKED",
                "ip": ip,
                "reason": reason,
                "confidence": confidence,
                "self_critique": self_critique,
            })
            self.actions_taken += 1
        
        try:
            with open(self._history_path, "a") as f:
                f.write(json.dumps({
                    "time": datetime.now().isoformat(),
                    "event": "BLOCKED", "ip": ip,
                    "reason": reason,
                    "confidence": confidence,
                }) + "\n")
        except Exception:
            pass

        _notify_webhook("BLOCKED", ip, reason, confidence)

    def log_decision(self, event: str, ip: str, reason: str, confidence: int = None, self_critique: str = None) -> None:
        with self._lock:
            self.decision_log.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "event": event,
                "ip": ip,
                "reason": reason,
                "confidence": confidence,
                "self_critique": self_critique,
            })
            if event == "VERIFIED":
                self.verifications += 1
                
        try:
            with open(self._history_path, "a") as f:
                f.write(json.dumps({
                    "time": datetime.now().isoformat(),
                    "event": event, "ip": ip,
                    "reason": reason,
                    "confidence": confidence,
                }) + "\n")
        except Exception:
            pass

        if event in ("TIER3_IGNORED", "IGNORED"):
            _notify_webhook(event, ip, reason, confidence)

    def set_state(self, state: str, task: str = None) -> None:
        with self._lock:
            self.agent_state = state
            if task is not None:
                self.current_task = task

    def reset(self) -> None:
        with self._lock:
            self.blocked_ips.clear()
            self.decision_log.clear()
            self.verified_ips.clear()
            self.actions_taken = 0
            self.verifications = 0
            self.agent_state = "IDLE"
            self.current_task = "Waiting for suspicious activity..."

    def memory_summary(self) -> dict:
        return {
            "blocked_from_history": sorted(self.blocked_ips),
            "history_file": str(self._history_path),
            "history_entries": (self._history_path.stat().st_size
                                if self._history_path.exists() else 0),
        }

    def execute_playbook(self, alert_type: str, ip: str) -> list:
        """Simulate executing a playbook. Returns the list of actions."""
        steps = PLAYBOOKS.get(alert_type, PLAYBOOKS["DEFAULT"])
        results = []
        for action, desc in steps:
            result = {"action": action, "description": desc,
                      "status": "SIMULATED"}
            results.append(result)
            self.log_decision("PLAYBOOK_STEP", ip,
                              f"{action} — {desc}")
        return results

# A single global instance — imported by anyone who needs it
AGENT = AgentService()


def tool_get_recent_alerts(detector, limit: int = 10) -> list[dict]:
    """Return the most recent alerts from the detector."""
    return list(detector.alerts[-limit:])

def tool_inspect_ip_traffic(buffer, ip: str, limit: int = 30) -> dict:
    """Return a summary of recent packets from a specific IP."""
    packets = [p for p in buffer.snapshot() if p.get("source") == ip]
    packets = packets[-limit:]
    if not packets:
        return {"ip": ip, "packet_count": 0}
    protocols = {}
    ports = set()
    total_bytes = 0
    for p in packets:
        protocols[p.get("protocol", "?")] = protocols.get(p.get("protocol", "?"), 0) + 1
        if p.get("port") not in (None, "-"):
            ports.add(p["port"])
        total_bytes += p.get("size", 0)
    return {
        "ip": ip,
        "packet_count": len(packets),
        "protocols": protocols,
        "unique_ports": sorted(ports),
        "unique_port_count": len(ports),
        "total_bytes": total_bytes,
        "first_seen": packets[0].get("timestamp"),
        "last_seen": packets[-1].get("timestamp"),
    }

def tool_check_blocklist(agent_service, ip: str) -> dict:
    """Return whether this IP is already blocked."""
    return {"ip": ip, "already_blocked": ip in agent_service.snapshot_blocked()}

def tool_block_ip(agent_service, ip: str, reason: str, confidence: int = None, self_critique: str = None) -> dict:
    """Perform the block. The agent must call this only after verification."""
    agent_service.block_ip(ip, reason, confidence, self_critique)
    return {"status": "blocked", "ip": ip, "reason": reason}

def tool_log_agent_decision(agent_service, event: str, ip: str, reason: str, confidence: int = None, self_critique: str = None) -> dict:
    """Record a non-block decision (e.g., 'VERIFIED' or 'IGNORED')."""
    agent_service.log_decision(event, ip, reason, confidence, self_critique)
    return {"logged": True}

def tool_get_buffer_summary(buffer) -> dict:
    """Return overall traffic stats — helps the agent size the environment."""
    packets = buffer.snapshot()
    return {
        "total_packets": len(packets),
        "unique_sources": len({p.get("source") for p in packets}),
    }


THREAT_INTEL_DB = {
    "192.168.1.99": {"country": "UA", "reputation": "MALICIOUS",
                     "tags": ["ssh-bruteforce", "flood",
                              "known-botnet-c2"]},
    "192.168.1.98": {"country": "RU", "reputation": "MALICIOUS",
                     "tags": ["port-scanner", "recon"]},
    "192.168.1.97": {"country": "CN", "reputation": "SUSPICIOUS",
                     "tags": ["bruteforce"]},
    "192.168.1.96": {"country": "BR", "reputation": "SUSPICIOUS",
                     "tags": ["icmp-flood"]},
    "192.168.1.95": {"country": "NG", "reputation": "MALICIOUS",
                     "tags": ["null-scan", "nmap"]},
    "192.168.1.94": {"country": "IN", "reputation": "MALICIOUS",
                     "tags": ["xmas-scan", "nmap"]},
}

def tool_threat_intel_lookup(ip: str) -> dict:
    """Return threat-intel data for an IP. Empty dict if unknown."""
    entry = THREAT_INTEL_DB.get(ip)
    if not entry:
        return {"ip": ip, "known": False}
    return {"ip": ip, "known": True, **entry}

def tool_predict_next_action(detector, ip: str) -> dict:
    """Predict whether an IP is likely to escalate."""
    alerts = [a for a in detector.alerts if a.get("ip") == ip]
    if len(alerts) < 2:
        return {"ip": ip, "prediction": "insufficient_data"}
    types = {a["type"] for a in alerts}
    # Heuristic: multiple attack types = imminent escalation
    if len(types) >= 2:
        return {"ip": ip, "prediction": "likely_escalation",
                "attack_types": sorted(types)}
    return {"ip": ip, "prediction": "unclear"}


TIER1_SYSTEM = """You are Tier 1 — SOC triage analyst.
Decide whether to escalate a raw alert to Tier 2.
- Escalate: PORT SCAN, SSH BRUTE FORCE, MALICIOUS FILE, KILL CHAIN
- Dismiss: single low-signal FLOOD or ICMP alert
- Never dismiss MALICIOUS FILE or KILL CHAIN
Return JSON: {"escalate": bool, "reason": "..."}"""

TIER2_SYSTEM = """You are Tier 2 — SOC investigation analyst.
Given the alert + targeted traffic for the source IP, assess severity.
You are given threat-intel data. IPs marked MALICIOUS should be
treated with high suspicion. Unknown IPs require stronger evidence.
Return JSON: {"severity": "LOW|MEDIUM|HIGH|CRITICAL",
              "context_summary": "...",
              "recommend_block": bool}"""

TIER3_SYSTEM = """You are Tier 3 — SOC incident responder.
Given context from Tiers 1 and 2, make the final block/ignore decision.
Return JSON: {"action": "block" | "ignore", "reason": "...",
              "confidence": integer 0-100, "self_critique": "..."}
Never block below confidence 80."""


def start_agent(buffer, detector, poll_interval: float = 4.0) -> threading.Thread:
    """Start the agent's daemon thread. Returns the thread handle."""
    t = threading.Thread(
        target=_agent_loop,
        args=(buffer, detector, poll_interval),
        daemon=True,
        name="soc-agent",
    )
    t.start()
    return t

# CONTRACT: The agent consumes `detector.alerts` only. It never
# iterates over `buffer.snapshot()` on its own. The only traffic
# it ever sees is the targeted `tool_inspect_ip_traffic(buffer, ip)`
# call for a specific alert's source IP.
def _agent_loop(buffer, detector, poll_interval):
    """The autonomous agent's main loop. Never touches Streamlit."""
    if not _SDK_AVAILABLE:
        AGENT.set_state("IDLE", "Agent offline (SDK unavailable)")
        return
    seen_alert_count = 0

    AGENT.set_state("MONITORING", "Watching traffic for anomalies…")

    while not AGENT._stop.is_set():
        try:
            # 1. Read alerts the detector has produced
            with detector._lock:
                alerts = list(detector.alerts)
            new_alerts = alerts[seen_alert_count:]
            seen_alert_count = len(alerts)

            # 2. For each new alert, ask the LLM to verify and act
            for alert in new_alerts:
                ip = alert.get("ip")
                if not ip:
                    continue

                # GUARD 1: Skip if already blocked
                if ip in AGENT.snapshot_blocked():
                    continue

                # GUARD 2: Cooldown — don't re-verify the same IP within 60s
                if not AGENT.should_verify(ip, cooldown_s=60):
                    continue

                AGENT.set_state("INVESTIGATING",
                                f"Verifying alert from {ip}…")

                # TIER 1
                AGENT.set_tier_state("tier1", "TRIAGING")
                t1 = _ask_tier(TIER1_SYSTEM, {"alert": alert})
                AGENT.bump_tier_count("tier1")
                AGENT.set_tier_state("tier1", "IDLE")
                if not t1.get("escalate"):
                    AGENT.log_decision("TIER1_DISMISSED", ip, t1.get("reason", ""))
                    continue

                # TIER 2
                AGENT.set_tier_state("tier2", "INVESTIGATING")
                t2 = _ask_tier(TIER2_SYSTEM, {
                    "alert": alert, "tier1_reason": t1.get("reason"),
                    "targeted_traffic": tool_inspect_ip_traffic(buffer, ip, 30),
                    "threat_intel": tool_threat_intel_lookup(ip)})
                AGENT.bump_tier_count("tier2")
                AGENT.set_tier_state("tier2", "IDLE")

                # TIER 3
                AGENT.set_tier_state("tier3", "DECIDING")
                t3 = _ask_tier(TIER3_SYSTEM, {
                    "alert": alert, "tier1_reason": t1.get("reason"),
                    "tier2_context": t2})
                AGENT.bump_tier_count("tier3")
                AGENT.set_tier_state("tier3", "IDLE")

                conf = int(t3.get("confidence", 0))
                if t3.get("action") == "block" and conf >= 80:
                    tool_block_ip(AGENT, ip, t3.get("reason"),
                                  confidence=conf, self_critique=t3.get("self_critique"))
                    AGENT.set_state("BLOCKING", f"Blocked {ip} — {t3.get('reason')}")
                    AGENT.execute_playbook(alert["type"], ip)
                else:
                    AGENT.log_decision("TIER3_IGNORED", ip,
                                       t3.get("reason", "below threshold"),
                                       confidence=conf,
                                       self_critique=t3.get("self_critique"))
                    AGENT.set_state("MONITORING", f"Cleared {ip} — below threshold")
                    
                # Predictive check — even if the agent didn't block, forecast
                pred = tool_predict_next_action(detector, ip)
                if pred.get("prediction") == "likely_escalation":
                    AGENT.log_decision("PREDICTED", ip,
                                       f"forecast escalation: {pred['attack_types']}")

            # 4. Back to monitoring
            if not new_alerts:
                AGENT.set_state("MONITORING",
                                "Watching traffic for anomalies…")

        except Exception as e:
            AGENT.set_state("ERROR", f"Agent error: {type(e).__name__}: {e}")

        time.sleep(poll_interval)

def _ask_tier(system: str, context: dict) -> dict:
    """Ask a specific tier to make a decision based on its context.

    Returns the parsed JSON response.
    Falls back to a default "ignore"/"dismiss" on error.
    """
    if not _SDK_AVAILABLE:
        return {"action": "ignore", "escalate": False, "reason": "SDK unavailable", "confidence": 0, "self_critique": ""}
    import asyncio, json as _json

    prompt = (
        f"CONTEXT:\n{_json.dumps(context, indent=2)}\n\n"
        f"Follow your system instructions strictly and return only JSON."
    )

    async def _run():
        config = LocalAgentConfig(system_instructions=system)
        async with Agent(config) as agent:
            resp = await agent.chat(prompt)
            return await resp.text()

    try:
        loop = asyncio.new_event_loop()
        text = loop.run_until_complete(
            asyncio.wait_for(_run(), timeout=8.0))
        loop.close()
    except Exception as e:
        return {"action": "ignore", "escalate": False,
                "reason": f"agent unavailable: {type(e).__name__}",
                "confidence": 0,
                "self_critique": "API failure"}

    # Parse the JSON from the response (LLM may wrap it in prose)
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        parsed = _json.loads(text[start:end])
        return parsed
    except Exception:
        return {"action": "ignore", "escalate": False,
                "reason": "unparseable decision", "confidence": 0, "self_critique": "parse error"}

def answer_analyst_question(question: str) -> str:
    """Answer a question using the agent's recent decision log."""
    if not _SDK_AVAILABLE:
        return "(agent unavailable in this environment)"
    import asyncio

    log = AGENT.snapshot_log()[-20:]
    blocked = sorted(AGENT.snapshot_blocked())
    state = AGENT.snapshot_state()

    context = {
        "recent_decisions": log,
        "blocked_ips": blocked,
        "agent_state": state,
    }

    prompt = (
        f"An analyst is asking about the SOC agent's current state.\n\n"
        f"CONTEXT:\n{json.dumps(context, indent=2)}\n\n"
        f"QUESTION: {question}\n\n"
        f"Answer in 2-3 sentences. Be specific, cite the IPs and "
        f"reasons from the log. If you don't have enough information, "
        f"say so."
    )

    async def _run():
        config = LocalAgentConfig(
            system_instructions=(
                "You are a SOC analyst explaining your own recent "
                "decisions. Be concise, factual, no speculation."
            )
        )
        async with Agent(config) as a:
            resp = await a.chat(prompt)
            return await resp.text()

    try:
        loop = asyncio.new_event_loop()
        answer = loop.run_until_complete(
            asyncio.wait_for(_run(), timeout=8.0))
        loop.close()
        return answer
    except Exception as e:
        return f"(agent unavailable: {type(e).__name__})"

def generate_attack_narrative() -> str:
    """Ask the LLM to write a narrative of the session so far."""
    import asyncio, json
    log = AGENT.snapshot_log()
    blocked = sorted(AGENT.snapshot_blocked())
    state = AGENT.snapshot_state()

    prompt = (
        f"Write a 3-paragraph incident narrative for this SOC session.\n\n"
        f"DECISION LOG:\n{json.dumps(log, indent=2)}\n\n"
        f"BLOCKED IPs: {blocked}\n\n"
        f"AGENT STATE: {json.dumps(state, indent=2)}\n\n"
        f"Format:\n"
        f"Paragraph 1: What happened (attacks observed, in order)\n"
        f"Paragraph 2: How the agent responded (blocks, reasons)\n"
        f"Paragraph 3: Current risk posture and recommendation\n\n"
        f"Write for a security manager. No jargon. Be specific."
    )
    async def _run():
        config = LocalAgentConfig(system_instructions=(
            "You are a senior SOC analyst writing an after-action "
            "report. Concise, factual, 3 paragraphs max."))
        async with Agent(config) as a:
            resp = await a.chat(prompt)
            return await resp.text()
    try:
        loop = asyncio.new_event_loop()
        text = loop.run_until_complete(
            asyncio.wait_for(_run(), timeout=12.0))
        loop.close()
        return text
    except Exception as e:
        return f"(narrative unavailable: {type(e).__name__})"
