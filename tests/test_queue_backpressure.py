"""
Tests for BoundedPacketQueue backpressure and drop behavior.
"""

import time
import pytest
from agent.capture import BoundedPacketQueue


def test_queue_enqueue_and_get_batch():
    q = BoundedPacketQueue(maxsize=10, strategy="drop_oldest")
    for i in range(5):
        assert q.put({"id": i, "size": 100}) is True

    assert len(q) == 5
    batch = q.get_batch(max_batch=3)
    assert len(batch) == 3
    assert [item["id"] for item in batch] == [0, 1, 2]
    assert len(q) == 2


def test_queue_drop_oldest_backpressure():
    q = BoundedPacketQueue(maxsize=5, strategy="drop_oldest")
    # Enqueue 8 items into a queue of size 5
    for i in range(8):
        q.put({"id": i})

    assert len(q) == 5
    assert q.total_enqueued == 8
    assert q.dropped_count == 3

    # Ensure oldest 3 (0, 1, 2) were dropped and items (3, 4, 5, 6, 7) remain
    batch = q.get_batch(max_batch=10)
    assert len(batch) == 5
    assert [item["id"] for item in batch] == [3, 4, 5, 6, 7]


def test_queue_blocking_timeout_backpressure():
    q = BoundedPacketQueue(maxsize=2, strategy="block")
    assert q.put({"id": 1}) is True
    assert q.put({"id": 2}) is True

    # Third item should timeout and increment dropped_count
    start_t = time.time()
    res = q.put({"id": 3}, timeout=0.05)
    elapsed = time.time() - start_t

    assert res is False
    assert elapsed >= 0.04
    assert q.dropped_count == 1
    assert len(q) == 2
