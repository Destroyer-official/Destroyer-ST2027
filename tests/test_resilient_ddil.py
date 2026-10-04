"""DDIL resilient-communication gates (Tier-1 tactical credibility).

resilient_communication.py (738 lines: store-and-forward queues, dedup,
backoff) previously had ZERO test coverage. Covers:

  1. Backoff schedule pins [1,2,4,8,16,32,60] then caps at 60 (incl. the
     first-retry-is-1s fix: mark_failed must schedule INTERVALS[0]).
  2. Queue bound 1000 with lowest-priority-first eviction + stats.
  3. Priority ordering on dequeue; duplicate message_id refused.
  4. Expiry cleanup removes + counts expired.
  5. mark_sent removes + frees the id for reuse.
  6. Deduplicator: same (session,seq) dupes; distinct sessions isolated;
     window eviction bounds memory (small max_ids).
  7. Manager: queue_message returns stable ids; duplicate seq refused;
     processed-mark makes later arrivals dupes (DDIL replays).

Fast, deterministic, no network/clocks except TTL math.
"""

import time

import pytest

from resilient_communication import (
    ExponentialBackoff,
    MessageDeduplicator,
    MessagePriority,
    MessageQueue,
    MessageStatus,
    QueuedMessage,
    ResilientCommunicationManager,
)


def _msg(mid, peer="peer", seq=1, pri=MessagePriority.NORMAL, ttl=3600):
    return QueuedMessage(message_id=mid, peer_id=peer, session_id="sess",
                         sequence_number=seq, payload=b"x",
                         priority=pri, expires_at=time.time() + ttl)


def test_backoff_schedule_pinned():
    assert (  # nosec: B101
        [ExponentialBackoff.get_delay(i) for i in range(7)]
        == [1, 2, 4, 8, 16, 32, 60]
    )
    assert ExponentialBackoff.get_delay(7) == 60  # nosec: B101
    assert ExponentialBackoff.get_delay(10 ** 6) == 60  # nosec: B101


def test_first_retry_waits_one_second():
    q = MessageQueue("p")
    m = _msg("m1")
    assert q.enqueue(m) is True  # nosec: B101
    got = q.dequeue()
    assert got is not None and got.status == MessageStatus.SENDING  # nosec: B101
    before = time.time()
    assert q.mark_failed("m1") is True  # nosec: B101
    # INTERVALS[0] == 1s for retry #1 (off-by-one fix; was 2s).
    assert abs((m.next_retry_at - before) - 1.0) < 0.5  # nosec: B101
    assert m.status == MessageStatus.PENDING  # nosec: B101


def test_queue_bound_evicts_lowest_priority_first():
    q = MessageQueue("p")
    for i in range(MessageQueue.MAX_MESSAGES_PER_PEER):
        assert q.enqueue(_msg(f"low-{i}", pri=MessagePriority.LOW)) is True  # nosec: B101
    # Full: a CRITICAL insert evicts a LOW (returns True), never grows past cap.
    assert q.enqueue(_msg("crit", pri=MessagePriority.CRITICAL)) is True  # nosec: B101
    assert len(q._queue) == MessageQueue.MAX_MESSAGES_PER_PEER  # nosec: B101
    assert q.get_stats()["dropped"] >= 1  # nosec: B101
    # A duplicate id is refused even with room pressure elsewhere.
    assert q.enqueue(_msg("crit", pri=MessagePriority.CRITICAL)) is False  # nosec: B101


def test_priority_order_on_dequeue():
    q = MessageQueue("p")
    q.enqueue(_msg("normal", pri=MessagePriority.NORMAL))
    q.enqueue(_msg("low", pri=MessagePriority.LOW))
    q.enqueue(_msg("crit", pri=MessagePriority.CRITICAL))
    first = q.dequeue()
    assert first is not None and first.message_id == "crit"  # nosec: B101


def test_expiry_cleanup_counts():
    q = MessageQueue("p")
    q.enqueue(_msg("old", ttl=-1))  # already expired
    q.enqueue(_msg("fresh", ttl=3600))
    assert q.dequeue() is not None  # triggers cleanup; returns fresh  # nosec: B101
    assert q.get_stats()["expired"] == 1  # nosec: B101
    assert q.dequeue() is None  # nosec: B101


def test_mark_sent_frees_id():
    q = MessageQueue("p")
    q.enqueue(_msg("m1"))
    assert q.mark_sent("m1") is True  # nosec: B101
    assert q.mark_sent("m1") is False  # gone: no double-ack  # nosec: B101
    assert q.enqueue(_msg("m1")) is True  # id reusable after completion  # nosec: B101


def test_deduplicator_window_and_isolation():
    d = MessageDeduplicator(max_ids=4)
    assert d.is_duplicate("s", 1) is False  # nosec: B101
    d.mark_processed("s", 1)
    assert d.is_duplicate("s", 1) is True  # nosec: B101
    assert d.is_duplicate("other-session", 1) is False  # sessions isolated  # nosec: B101
    # Window evicts oldest: fill past max_ids, oldest drops out.
    d.mark_processed("s", 2)
    d.mark_processed("s", 3)
    d.mark_processed("s", 4)
    d.mark_processed("s", 5)
    assert len(d._processed_ids) <= 4  # nosec: B101


def test_manager_queue_duplicate_and_replay():
    mgr = ResilientCommunicationManager()
    mid1 = mgr.queue_message("peer", "sess", 1, b"hello")
    assert isinstance(mid1, str) and mid1  # nosec: B101
    # Same (session, seq) -> same id -> refused as duplicate.
    assert mgr.queue_message("peer", "sess", 1, b"hello-again") is None  # nosec: B101
    assert mgr.check_duplicate("sess", 2) is False  # nosec: B101
    mgr.mark_message_processed("sess", 2)
    assert mgr.check_duplicate("sess", 2) is True  # DDIL replay dropped  # nosec: B101
    stats = mgr.get_queue_stats("peer")
    assert stats is not None and stats["current_size"] >= 1  # nosec: B101

