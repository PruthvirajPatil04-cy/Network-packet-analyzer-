"""Anomaly detection logic."""

from __future__ import annotations
import threading
import re
from collections import defaultdict, deque
from datetime import datetime

def _to_ms(ts: str) -> float:
    """Parse 'HH:MM:SS.mmm' -> milliseconds since midnight (float)."""
    h, m, rest = ts.split(":")
    s, ms = rest.split(".")
    return (int(h) * 3600 + int(m) * 60 + int(s)) * 1000 + int(ms)

def analyze_pps(packets: list[dict]) -> float:
    """Returns packets-per-second over the timestamps present."""
    if len(packets) < 2:
        return 0.0
    first = _to_ms(packets[0]["timestamp"])
    last  = _to_ms(packets[-1]["timestamp"])
    diff_s = (last - first) / 1000.0
    return 0.0 if diff_s <= 0 else len(packets) / diff_s

class Rule:
    """A single detection rule. Subclass per attack type."""
    name = "UNKNOWN"
    severity = "HIGH"

    def check(self, packet: dict, now_ms: float, state: dict) -> dict | None:
        raise NotImplementedError

class FloodRule(Rule):
    name = "DoS / FLOOD"
    def __init__(self, threshold=15, window_s=3, cooldown_s=3.0):
        self.threshold = threshold
        self.window_ms = window_s * 1000
        self.cooldown_ms = cooldown_s * 1000

    def check(self, packet, now_ms, state):
        src = packet["source"]
        s = state.setdefault("flood", {})
        dq = s.setdefault("deques", {}).setdefault(src, deque(maxlen=self.threshold * 4))
        last = s.setdefault("last_alert_ms", {}).get(src, float("-inf"))
        
        dq.append(now_ms)
        while dq and now_ms - dq[0] > self.window_ms:
            dq.popleft()
            
        if len(dq) >= self.threshold:
            if now_ms - last >= self.cooldown_ms:
                s["last_alert_ms"][src] = now_ms
                return {
                    "time": packet["timestamp"][:8],
                    "type": self.name,
                    "ip": src,
                    "detail": f"{len(dq)} packets in {self.window_ms//1000}s",
                    "severity": self.severity,
                }
            else:
                return {"_cooldown": True}
        return None

class PortScanRule(Rule):
    name = "PORT SCAN"
    def __init__(self, unique_ports=10, window_s=5, cooldown_s=1.0):
        self.unique_ports = unique_ports
        self.window_ms = window_s * 1000
        self.cooldown_ms = cooldown_s * 1000

    def check(self, packet, now_ms, state):
        src = packet["source"]
        dport = packet.get("port")
        if dport in (None, "-"):
            return None
            
        s = state.setdefault("scan", {})
        dq = s.setdefault("deques", {}).setdefault(src, deque(maxlen=200))
        last = s.setdefault("last_alert_ms", {}).get(src, float("-inf"))
        
        dq.append((now_ms, dport))
        while dq and now_ms - dq[0][0] > self.window_ms:
            dq.popleft()
            
        ports = {p for _, p in dq}
        if len(ports) >= self.unique_ports:
            if now_ms - last >= self.cooldown_ms:
                s["last_alert_ms"][src] = now_ms
                return {
                    "time": packet["timestamp"][:8],
                    "type": self.name,
                    "ip": src,
                    "detail": f"{len(ports)} unique ports in {self.window_ms//1000}s",
                    "severity": self.severity,
                }
            else:
                return {"_cooldown": True}
        return None

class BruteForceRule(Rule):
    name = "SSH BRUTE FORCE"
    def __init__(self, threshold=8, window_s=5, target_port=22, cooldown_s=2.0):
        self.threshold = threshold
        self.window_ms = window_s * 1000
        self.target_port = target_port
        self.cooldown_ms = cooldown_s * 1000

    def check(self, packet, now_ms, state):
        if packet.get("port") != self.target_port:
            return None
        if packet.get("flags") != "S":     # only SYN attempts count
            return None
            
        src = packet["source"]
        s = state.setdefault("brute", {})
        dq = s.setdefault("deques", {}).setdefault(src, deque(maxlen=self.threshold * 4))
        last = s.setdefault("last_alert_ms", {}).get(src, float("-inf"))
        
        dq.append(now_ms)
        while dq and now_ms - dq[0] > self.window_ms:
            dq.popleft()
            
        if len(dq) >= self.threshold:
            if now_ms - last >= self.cooldown_ms:
                s["last_alert_ms"][src] = now_ms
                return {
                    "time": packet["timestamp"][:8],
                    "type": self.name,
                    "ip": src,
                    "detail": f"{len(dq)} SYN attempts on port {self.target_port}",
                    "severity": self.severity,
                }
            else:
                return {"_cooldown": True}
        return None

class IcmpFloodRule(Rule):
    name = "ICMP FLOOD"
    def __init__(self, threshold=15, window_s=3, cooldown_s=3.0):
        self.threshold = threshold
        self.window_ms = window_s * 1000
        self.cooldown_ms = cooldown_s * 1000

    def check(self, packet, now_ms, state):
        if packet.get("protocol") != "ICMP":
            return None
        src = packet["source"]
        s = state.setdefault("icmp_flood", {})
        dq = s.setdefault("deques", {}).setdefault(src, deque(maxlen=self.threshold * 4))
        last = s.setdefault("last_alert_ms", {}).get(src, float("-inf"))
        
        dq.append(now_ms)
        while dq and now_ms - dq[0] > self.window_ms:
            dq.popleft()
            
        if len(dq) >= self.threshold:
            if now_ms - last >= self.cooldown_ms:
                s["last_alert_ms"][src] = now_ms
                return {
                    "time": packet["timestamp"][:8],
                    "type": self.name,
                    "ip": src,
                    "detail": f"{len(dq)} ICMP packets in {self.window_ms//1000}s",
                    "severity": self.severity,
                }
            else:
                return {"_cooldown": True}
        return None

class NullScanRule(Rule):
    name = "NULL SCAN"
    def __init__(self, threshold=3, window_s=5, cooldown_s=5.0):
        self.threshold = threshold
        self.window_ms = window_s * 1000
        self.cooldown_ms = cooldown_s * 1000

    def check(self, packet, now_ms, state):
        if packet.get("protocol") != "TCP":
            return None
        flags = packet.get("flags", "")
        if str(flags).upper() not in ["", "0", "NULL"]:
            return None
            
        src = packet["source"]
        s = state.setdefault("null_scan", {})
        dq = s.setdefault("deques", {}).setdefault(src, deque(maxlen=self.threshold * 4))
        last = s.setdefault("last_alert_ms", {}).get(src, float("-inf"))
        
        dq.append(now_ms)
        while dq and now_ms - dq[0] > self.window_ms:
            dq.popleft()
            
        if len(dq) >= self.threshold:
            if now_ms - last >= self.cooldown_ms:
                s["last_alert_ms"][src] = now_ms
                return {
                    "time": packet["timestamp"][:8],
                    "type": self.name,
                    "ip": src,
                    "detail": f"{len(dq)} NULL-flag TCP packets in {self.window_ms//1000}s",
                    "severity": self.severity,
                }
            else:
                return {"_cooldown": True}
        return None

class XmasScanRule(Rule):
    name = "XMAS SCAN"
    def __init__(self, threshold=3, window_s=5, cooldown_s=5.0):
        self.threshold = threshold
        self.window_ms = window_s * 1000
        self.cooldown_ms = cooldown_s * 1000

    def check(self, packet, now_ms, state):
        if packet.get("protocol") != "TCP":
            return None
        flags = str(packet.get("flags", "")).upper()
        if not ("F" in flags and "P" in flags and "U" in flags):
            return None
            
        src = packet["source"]
        s = state.setdefault("xmas_scan", {})
        dq = s.setdefault("deques", {}).setdefault(src, deque(maxlen=self.threshold * 4))
        last = s.setdefault("last_alert_ms", {}).get(src, float("-inf"))
        
        dq.append(now_ms)
        while dq and now_ms - dq[0] > self.window_ms:
            dq.popleft()
            
        if len(dq) >= self.threshold:
            if now_ms - last >= self.cooldown_ms:
                s["last_alert_ms"][src] = now_ms
                return {
                    "time": packet["timestamp"][:8],
                    "type": self.name,
                    "ip": src,
                    "detail": f"{len(dq)} XMAS-flag TCP packets in {self.window_ms//1000}s",
                    "severity": self.severity,
                }
            else:
                return {"_cooldown": True}
        return None

class MaliciousFileRule(Rule):
    name = "MALICIOUS FILE"

    DANGEROUS_EXTS = {"exe", "scr", "bat", "ps1", "vbs", "jar",
                      "cmd", "com", "pif", "hta"}
    BAD_HASHES = {
        "a3c5e7f9b1d20000000000000000000000000000000000000000malwarehash1",
        "b4d6e8f0c2e30000000000000000000000000000000000000000malwarehash2",
        "c5e7f9b1d3f40000000000000000000000000000000000000000malwarehash3",
    }
    SUSPICIOUS_PATTERNS = (
        r"\.pdf\.exe$",
        r"\.docx\.scr$",
        r"^invoice.*",
        r"^update\..*",
        r"^payload.*",
    )

    def __init__(self, cooldown_s=5):
        self.cooldown_s = cooldown_s

    def check(self, packet, now_ms, state):
        filename = packet.get("filename")
        if not filename:
            return None

        ext = (packet.get("file_ext") or "").lower()
        file_hash = packet.get("file_hash") or ""
        fn_lower = filename.lower()

        reasons = []
        if ext in self.DANGEROUS_EXTS:
            reasons.append(f"dangerous extension .{ext}")
        if file_hash in self.BAD_HASHES:
            reasons.append("hash matches known-malware signature")
        for pat in self.SUSPICIOUS_PATTERNS:
            if re.search(pat, fn_lower):
                reasons.append(f"filename pattern match")
                break

        if not reasons:
            return None

        key = (packet["source"], filename)
        last = state.setdefault("malicious_file", {}).get(key, float("-inf"))
        if now_ms - last < self.cooldown_s * 1000:
            return None
        state["malicious_file"][key] = now_ms

        return {
            "time": packet["timestamp"][:8],
            "type": self.name,
            "ip": packet["source"],
            "detail": f"{filename} ({packet.get('file_size', 0)} B) — "
                      + "; ".join(reasons),
            "severity": "HIGH",
            "filename": filename,
            "file_hash": file_hash,
        }

class AnomalyDetector:
    """Multi-rule anomaly detector coordinator."""
    def __init__(self, rules=None, max_alerts=50, risk_per_alert=20.0, decay_per_clean=0.5):
        self._lock = threading.Lock()
        self.rules = rules or [IcmpFloodRule(), NullScanRule(), XmasScanRule(),
                               FloodRule(), PortScanRule(), BruteForceRule(),
                               MaliciousFileRule()]
        self.max_alerts = max_alerts
        self.risk_per_alert = risk_per_alert
        self.decay_per_clean = decay_per_clean
        self.alerts: list[dict] = []
        self.risk_score: float = 0.0
        self._state: dict = {}

    def analyze(self, packet: dict) -> dict | None:
        """Analyzes a packet against all rules and updates risk score."""
        now_ms = _to_ms(packet["timestamp"])
        with self._lock:
            under_attack = False
            for rule in self.rules:
                alert = rule.check(packet, now_ms, self._state)
                if alert:
                    if alert.get("_cooldown"):
                        under_attack = True
                    else:
                        self.alerts.append(alert)
                        if len(self.alerts) > self.max_alerts:
                            self.alerts = self.alerts[-self.max_alerts:]
                        self.risk_score = min(100.0, self.risk_score + self.risk_per_alert)
                        return alert
            
            if not under_attack:
                self.risk_score = max(0.0, self.risk_score - self.decay_per_clean)
            return None

    def reset(self) -> None:
        """Resets the detector state."""
        with self._lock:
            self.alerts.clear()
            self.risk_score = 0.0
            self._state.clear()
