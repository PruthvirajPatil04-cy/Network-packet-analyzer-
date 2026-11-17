"""
Application-Layer Blocklist (Simulated Firewall Rules).
Maintains in-memory blocked IPs with automatic TTL eviction, hit counters,
and optional Redis synchronization.
"""

from __future__ import annotations
import time
import threading
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger("demo_server.blocklist")


@dataclass
class BlockEntry:
    ip: str
    reason: str
    score: float
    blocked_at: float
    expires_at: float
    hits: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "score": round(self.score, 2),
            "blocked_at": round(self.blocked_at, 3),
            "expires_at": round(self.expires_at, 3),
            "ttl_remaining": max(0, int(self.expires_at - time.time())),
            "hits": self.hits,
        }


class SimulatedFirewallBlocklist:
    """
    Thread-safe in-memory blocklist with TTL and optional Redis persistence.
    Operates strictly at the application layer of the demo server.
    """

    def __init__(self, default_ttl: int = 300, redis_client: Optional[Any] = None):
        self.default_ttl = default_ttl
        self.redis_client = redis_client
        self._entries: Dict[str, BlockEntry] = {}
        self._lock = threading.Lock()

    def is_blocked(self, ip: str) -> Tuple[bool, Optional[BlockEntry]]:
        """
        Fast-path check. Returns (True, entry) if IP is currently blocked and unexpired.
        Increments hit counter upon blocked request.
        """
        now = time.time()
        with self._lock:
            # Check if exists and not expired
            entry = self._entries.get(ip)
            if not entry:
                return False, None

            if now >= entry.expires_at:
                # Expired -> auto-evict
                del self._entries[ip]
                self._sync_redis_remove(ip)
                return False, None

            # Still blocked -> register violation hit
            entry.hits += 1
            return True, entry

    def block_ip(
        self, ip: str, reason: str, score: float, ttl: Optional[int] = None
    ) -> BlockEntry:
        """
        Add or update an IP in the blocklist with a TTL.
        """
        now = time.time()
        actual_ttl = ttl if ttl is not None else self.default_ttl
        expires_at = now + actual_ttl

        with self._lock:
            existing = self._entries.get(ip)
            if existing:
                existing.reason = reason
                existing.score = max(existing.score, score)
                existing.expires_at = max(existing.expires_at, expires_at)
                existing.hits += 1
                entry = existing
            else:
                entry = BlockEntry(
                    ip=ip,
                    reason=reason,
                    score=score,
                    blocked_at=now,
                    expires_at=expires_at,
                    hits=1,
                )
                self._entries[ip] = entry

            self._sync_redis_add(entry)
            logger.info(f"🚫 [FIREWALL] Blocked IP {ip} for {actual_ttl}s (Score: {score:.2f}, Reason: {reason})")
            return entry

    def unblock_ip(self, ip: str) -> bool:
        """
        Manually remove an IP from the blocklist.
        """
        with self._lock:
            if ip in self._entries:
                del self._entries[ip]
                self._sync_redis_remove(ip)
                logger.info(f"✅ [FIREWALL] Unblocked IP {ip}")
                return True
            return False

    def get_all(self) -> List[Dict[str, Any]]:
        """
        Return all currently active blocked entries, filtering out expired ones.
        """
        now = time.time()
        with self._lock:
            expired_keys = [k for k, v in self._entries.items() if now >= v.expires_at]
            for k in expired_keys:
                del self._entries[k]
                self._sync_redis_remove(k)

            return [entry.to_dict() for entry in self._entries.values()]

    def count(self) -> int:
        now = time.time()
        with self._lock:
            return sum(1 for v in self._entries.values() if now < v.expires_at)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            if self.redis_client:
                try:
                    self.redis_client.delete("blocklist:ips")
                except Exception:
                    pass

    # --- Redis mirror helpers ---
    def _sync_redis_add(self, entry: BlockEntry) -> None:
        if not self.redis_client:
            return
        try:
            self.redis_client.zadd("blocklist:ips", {entry.ip: entry.score})
            self.redis_client.hset(f"blocklist:{entry.ip}", mapping=entry.to_dict())
            self.redis_client.expire(f"blocklist:{entry.ip}", int(entry.expires_at - time.time()))
        except Exception as e:
            logger.debug(f"Redis blocklist sync error: {e}")

    def _sync_redis_remove(self, ip: str) -> None:
        if not self.redis_client:
            return
        try:
            self.redis_client.zrem("blocklist:ips", ip)
            self.redis_client.delete(f"blocklist:{ip}")
        except Exception:
            pass


# Global singleton instance for demo server
blocklist = SimulatedFirewallBlocklist(default_ttl=300)
