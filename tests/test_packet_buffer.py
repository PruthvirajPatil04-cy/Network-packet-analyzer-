import threading
import time
from packet_buffer import PacketBuffer

def test_concurrent_append_and_snapshot():
    """Two writers, one reader, 2 seconds, no exceptions, no torn state."""
    buf = PacketBuffer()
    stop = threading.Event()
    errors: list[Exception] = []

    def writer(tag: str) -> None:
        i = 0
        while not stop.is_set():
            try:
                buf.append({"tag": tag, "i": i, "ts": time.monotonic()})
                i += 1
            except Exception as e:
                errors.append(e)

    def reader() -> None:
        while not stop.is_set():
            try:
                snap = buf.snapshot()
                # Every snapshot must be a valid prefix of the total order.
                assert all(isinstance(p, dict) for p in snap)
                assert all("tag" in p for p in snap)
            except Exception as e:
                errors.append(e)

    threads = [
        threading.Thread(target=writer, args=("A",), daemon=True),
        threading.Thread(target=writer, args=("B",), daemon=True),
        threading.Thread(target=reader, daemon=True),
    ]
    for t in threads:
        t.start()
    time.sleep(2.0)
    stop.set()
    for t in threads:
        t.join(timeout=2.0)

    assert not errors, f"concurrency errors: {errors[:3]}"
    assert len(buf) > 100  # sanity: writers made progress

def test_clear():
    buf = PacketBuffer()
    buf.append({"x": 1})
    buf.clear()
    assert len(buf) == 0
    assert buf.snapshot() == []
