import threading
from typing import Protocol, Any

class PacketSink(Protocol):
    """Anything with an .append(dict) method — list or PacketBuffer."""
    def append(self, item: dict[str, Any]) -> None: ...

class PacketBuffer:
    """
    Thread-safe buffer for network packets.
    INVARIANT: readers MUST use snapshot(), never index the raw list.
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buffer: list[dict[str, Any]] = []

    def append(self, item: dict[str, Any]) -> None:
        with self._lock:
            self._buffer.append(item)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._buffer)

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)
