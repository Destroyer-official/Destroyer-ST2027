"""
Resilient Communication Module

Implements reliable message delivery for military-grade P2P communications:
- Message queuing for offline peers (max 1000 messages per peer)
- Exponential backoff retry: 1s, 2s, 4s, 8s, 16s, 32s, 60s max
- Message deduplication using SHA3-256(session_id + sequence_number)

**Feature: military-p2p-2026-enhancement**
**Validates: Requirements 10.1, 10.2, 10.3, 10.4**

Author: Security Team
License: MIT
"""

import asyncio
import hashlib
import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta

# Configure logging
log = logging.getLogger(__name__)


class MessagePriority(Enum):
    """Message priority levels for queue ordering."""
    CRITICAL = 0  # System messages, key rotation
    HIGH = 1      # Important user messages
    NORMAL = 2    # Regular messages
    LOW = 3       # Non-urgent messages


class MessageStatus(Enum):
    """Status of a queued message."""
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class QueuedMessage:
    """
    Represents a message queued for delivery to an offline peer.
    
    **Validates: Requirements 10.1**
    """
    message_id: str
    peer_id: str
    session_id: str
    sequence_number: int
    payload: bytes
    priority: MessagePriority = MessagePriority.NORMAL
    status: MessageStatus = MessageStatus.PENDING
    created_at: float = field(default_factory=time.time)
    retry_count: int = 0
    last_retry_at: Optional[float] = None
    next_retry_at: Optional[float] = None
    expires_at: Optional[float] = None
    
    def __post_init__(self):
        """Initialize computed fields."""
        if self.expires_at is None:
            # Default expiry: 24 hours
            self.expires_at = self.created_at + 86400
        if self.next_retry_at is None:
            self.next_retry_at = self.created_at
    
    def is_expired(self) -> bool:
        """Check if message has expired."""
        return time.time() > self.expires_at
    
    def compute_dedup_id(self) -> str:
        """
        Compute deduplication ID using SHA3-256(session_id + sequence_number).
        
        **Validates: Requirements 10.3**
        """
        data = f"{self.session_id}:{self.sequence_number}".encode('utf-8')
        return hashlib.sha3_256(data).hexdigest()


class ExponentialBackoff:
    """
    Implements exponential backoff retry strategy.
    
    Retry intervals: 1s, 2s, 4s, 8s, 16s, 32s, 60s max
    
    **Validates: Requirements 10.2**
    """
    
    # Backoff intervals in seconds
    INTERVALS = [1, 2, 4, 8, 16, 32, 60]
    MAX_INTERVAL = 60
    
    @classmethod
    def get_delay(cls, retry_count: int) -> float:
        """
        Get the delay for the given retry count.
        
        Args:
            retry_count: Number of retries attempted (0-indexed)
            
        Returns:
            Delay in seconds before next retry
        """
        if retry_count < len(cls.INTERVALS):
            return float(cls.INTERVALS[retry_count])
        return float(cls.MAX_INTERVAL)
    
    @classmethod
    def get_next_retry_time(cls, retry_count: int) -> float:
        """
        Get the timestamp for the next retry.
        
        Args:
            retry_count: Number of retries attempted
            
        Returns:
            Unix timestamp for next retry
        """
        delay = cls.get_delay(retry_count)
        return time.time() + delay


class MessageQueue:
    """
    Thread-safe message queue for a single peer.
    
    Implements:
    - Max 1000 messages per peer
    - Priority-based ordering
    - Automatic expiry cleanup
    
    **Validates: Requirements 10.1**
    """
    
    MAX_MESSAGES_PER_PEER = 1000
    
    def __init__(self, peer_id: str):
        """
        Initialize message queue for a peer.
        
        Args:
            peer_id: Identifier of the peer
        """
        self.peer_id = peer_id
        self._queue: deque = deque(maxlen=self.MAX_MESSAGES_PER_PEER)
        self._lock = threading.RLock()
        self._message_ids: Set[str] = set()
        self._stats = {
            'enqueued': 0,
            'sent': 0,
            'failed': 0,
            'expired': 0,
            'dropped': 0
        }
    
    def enqueue(self, message: QueuedMessage) -> bool:
        """
        Add a message to the queue.
        
        Args:
            message: Message to enqueue
            
        Returns:
            True if enqueued, False if queue full or duplicate
        """
        with self._lock:
            # Check for duplicate
            if message.message_id in self._message_ids:
                log.debug(f"Duplicate message {message.message_id} rejected")
                return False
            
            # Check queue capacity
            if len(self._queue) >= self.MAX_MESSAGES_PER_PEER:
                # Remove oldest low-priority message
                removed = self._remove_lowest_priority()
                if not removed:
                    log.warning(f"Queue full for peer {self.peer_id}, dropping message")
                    self._stats['dropped'] += 1
                    return False
            
            # Add to queue
            self._queue.append(message)
            self._message_ids.add(message.message_id)
            self._stats['enqueued'] += 1
            
            # Sort by priority and creation time
            self._sort_queue()
            
            log.debug(f"Enqueued message {message.message_id} for peer {self.peer_id}")
            return True
    
    def _remove_lowest_priority(self) -> bool:
        """Remove the lowest priority, oldest message."""
        if not self._queue:
            return False
        
        # Find lowest priority message
        lowest_idx = -1
        lowest_priority = MessagePriority.CRITICAL
        oldest_time = float('inf')
        
        for i, msg in enumerate(self._queue):
            if msg.priority.value > lowest_priority.value or \
               (msg.priority.value == lowest_priority.value and msg.created_at < oldest_time):
                lowest_idx = i
                lowest_priority = msg.priority
                oldest_time = msg.created_at
        
        if lowest_idx >= 0:
            removed = self._queue[lowest_idx]
            del self._queue[lowest_idx]
            self._message_ids.discard(removed.message_id)
            self._stats['dropped'] += 1
            log.debug(f"Dropped message {removed.message_id} to make room")
            return True
        
        return False
    
    def _sort_queue(self):
        """Sort queue by priority (ascending) and creation time."""
        sorted_msgs = sorted(
            self._queue,
            key=lambda m: (m.priority.value, m.created_at)
        )
        self._queue.clear()
        self._queue.extend(sorted_msgs)
    
    def dequeue(self) -> Optional[QueuedMessage]:
        """
        Get the next message ready for sending.
        
        Returns:
            Next message to send, or None if queue empty or no messages ready
        """
        with self._lock:
            self._cleanup_expired()
            
            current_time = time.time()
            for i, msg in enumerate(self._queue):
                if msg.status == MessageStatus.PENDING and \
                   msg.next_retry_at <= current_time:
                    msg.status = MessageStatus.SENDING
                    return msg
            
            return None
    
    def mark_sent(self, message_id: str) -> bool:
        """
        Mark a message as successfully sent.
        
        Args:
            message_id: ID of the sent message
            
        Returns:
            True if message found and marked
        """
        with self._lock:
            for i, msg in enumerate(self._queue):
                if msg.message_id == message_id:
                    del self._queue[i]
                    self._message_ids.discard(message_id)
                    self._stats['sent'] += 1
                    log.debug(f"Message {message_id} sent successfully")
                    return True
            return False
    
    def mark_failed(self, message_id: str) -> bool:
        """
        Mark a message as failed and schedule retry.
        
        Args:
            message_id: ID of the failed message
            
        Returns:
            True if message found and rescheduled
        """
        with self._lock:
            for msg in self._queue:
                if msg.message_id == message_id:
                    msg.retry_count += 1
                    msg.last_retry_at = time.time()
                    # Retry #N waits INTERVALS[N-1] (first retry waits 1s):
                    # retry_count was just incremented, so index -1.
                    msg.next_retry_at = ExponentialBackoff.get_next_retry_time(
                        msg.retry_count - 1)
                    msg.status = MessageStatus.PENDING

                    log.debug(
                        f"Message {message_id} failed, retry {msg.retry_count} "
                        f"scheduled in {ExponentialBackoff.get_delay(msg.retry_count - 1)}s"
                    )
                    return True
            return False
    
    def _cleanup_expired(self):
        """Remove expired messages from the queue."""
        current_time = time.time()
        expired = [msg for msg in self._queue if msg.is_expired()]
        
        for msg in expired:
            self._queue.remove(msg)
            self._message_ids.discard(msg.message_id)
            self._stats['expired'] += 1
            log.debug(f"Message {msg.message_id} expired and removed")
    
    def get_pending_count(self) -> int:
        """Get count of pending messages."""
        with self._lock:
            return sum(1 for msg in self._queue if msg.status == MessageStatus.PENDING)
    
    def get_stats(self) -> Dict[str, int]:
        """Get queue statistics."""
        with self._lock:
            return {
                **self._stats,
                'current_size': len(self._queue),
                'pending': self.get_pending_count()
            }
    
    def clear(self):
        """Clear all messages from the queue."""
        with self._lock:
            self._queue.clear()
            self._message_ids.clear()



class MessageDeduplicator:
    """
    Tracks processed message IDs to prevent duplicate processing.
    
    Uses SHA3-256(session_id + sequence_number) for deduplication.
    
    **Validates: Requirements 10.3, 10.4**
    """
    
    # Maximum number of message IDs to track
    MAX_TRACKED_IDS = 100000
    
    def __init__(self, max_ids: int = MAX_TRACKED_IDS):
        """
        Initialize the deduplicator.
        
        Args:
            max_ids: Maximum number of IDs to track
        """
        self._max_ids = max_ids
        self._processed_ids: Dict[str, float] = {}  # id -> timestamp
        self._lock = threading.RLock()
        self._stats = {
            'processed': 0,
            'duplicates_rejected': 0
        }
    
    def compute_message_id(self, session_id: str, sequence_number: int) -> str:
        """
        Compute deduplication ID using SHA3-256.
        
        **Validates: Requirements 10.3**
        
        Args:
            session_id: Session identifier
            sequence_number: Message sequence number
            
        Returns:
            SHA3-256 hash as hex string
        """
        data = f"{session_id}:{sequence_number}".encode('utf-8')
        return hashlib.sha3_256(data).hexdigest()
    
    def is_duplicate(self, session_id: str, sequence_number: int) -> bool:
        """
        Check if a message is a duplicate.
        
        **Validates: Requirements 10.3, 10.4**
        
        Args:
            session_id: Session identifier
            sequence_number: Message sequence number
            
        Returns:
            True if duplicate, False if new message
        """
        msg_id = self.compute_message_id(session_id, sequence_number)
        
        with self._lock:
            if msg_id in self._processed_ids:
                self._stats['duplicates_rejected'] += 1
                log.info(f"Duplicate message detected: session={session_id[:16]}..., seq={sequence_number}")
                return True
            return False
    
    def mark_processed(self, session_id: str, sequence_number: int) -> str:
        """
        Mark a message as processed.
        
        Args:
            session_id: Session identifier
            sequence_number: Message sequence number
            
        Returns:
            The computed message ID
        """
        msg_id = self.compute_message_id(session_id, sequence_number)
        
        with self._lock:
            # Cleanup if at capacity
            if len(self._processed_ids) >= self._max_ids:
                self._cleanup_oldest()
            
            self._processed_ids[msg_id] = time.time()
            self._stats['processed'] += 1
            
        return msg_id
    
    def _cleanup_oldest(self):
        """Remove oldest entries to make room."""
        if not self._processed_ids:
            return
        
        # Remove oldest 10%
        to_remove = max(1, len(self._processed_ids) // 10)
        sorted_ids = sorted(self._processed_ids.items(), key=lambda x: x[1])
        
        for msg_id, _ in sorted_ids[:to_remove]:
            del self._processed_ids[msg_id]
    
    def get_stats(self) -> Dict[str, int]:
        """Get deduplication statistics."""
        with self._lock:
            return {
                **self._stats,
                'tracked_ids': len(self._processed_ids)
            }
    
    def clear(self):
        """Clear all tracked IDs."""
        with self._lock:
            self._processed_ids.clear()


class ResilientCommunicationManager:
    """
    Main manager for resilient communication features.
    
    Provides:
    - Message queuing for offline peers (max 1000 per peer)
    - Exponential backoff retry (1s, 2s, 4s, 8s, 16s, 32s, 60s max)
    - Message deduplication using SHA3-256
    
    **Feature: military-p2p-2026-enhancement**
    **Validates: Requirements 10.1, 10.2, 10.3, 10.4**
    """
    
    def __init__(
        self,
        send_callback: Optional[Callable[[str, bytes], asyncio.Future]] = None,
        on_duplicate: Optional[Callable[[str, int], None]] = None
    ):
        """
        Initialize the resilient communication manager.
        
        Args:
            send_callback: Async function to send message to peer
            on_duplicate: Callback when duplicate detected
        """
        self._queues: Dict[str, MessageQueue] = {}
        self._deduplicator = MessageDeduplicator()
        self._send_callback = send_callback
        self._on_duplicate = on_duplicate
        self._lock = threading.RLock()
        self._running = False
        self._retry_task: Optional[asyncio.Task] = None
        self._stats = {
            'total_queued': 0,
            'total_sent': 0,
            'total_failed': 0,
            'total_duplicates': 0
        }
    
    def get_or_create_queue(self, peer_id: str) -> MessageQueue:
        """
        Get or create a message queue for a peer.
        
        Args:
            peer_id: Peer identifier
            
        Returns:
            MessageQueue for the peer
        """
        with self._lock:
            if peer_id not in self._queues:
                self._queues[peer_id] = MessageQueue(peer_id)
                log.debug(f"Created message queue for peer {peer_id}")
            return self._queues[peer_id]
    
    def queue_message(
        self,
        peer_id: str,
        session_id: str,
        sequence_number: int,
        payload: bytes,
        priority: MessagePriority = MessagePriority.NORMAL,
        ttl_seconds: int = 86400
    ) -> Optional[str]:
        """
        Queue a message for delivery to an offline peer.
        
        **Validates: Requirements 10.1, 10.2**
        
        Args:
            peer_id: Target peer identifier
            session_id: Session identifier
            sequence_number: Message sequence number
            payload: Message payload bytes
            priority: Message priority
            ttl_seconds: Time-to-live in seconds
            
        Returns:
            Message ID if queued, None if failed
        """
        # Create message
        message = QueuedMessage(
            message_id=self._deduplicator.compute_message_id(session_id, sequence_number),
            peer_id=peer_id,
            session_id=session_id,
            sequence_number=sequence_number,
            payload=payload,
            priority=priority,
            expires_at=time.time() + ttl_seconds
        )
        
        # Get queue and enqueue
        queue = self.get_or_create_queue(peer_id)
        if queue.enqueue(message):
            self._stats['total_queued'] += 1
            log.info(f"Queued message for peer {peer_id}: seq={sequence_number}")
            return message.message_id
        
        return None
    
    def check_duplicate(self, session_id: str, sequence_number: int) -> bool:
        """
        Check if a message is a duplicate.
        
        **Validates: Requirements 10.3, 10.4**
        
        Args:
            session_id: Session identifier
            sequence_number: Message sequence number
            
        Returns:
            True if duplicate (should be discarded)
        """
        is_dup = self._deduplicator.is_duplicate(session_id, sequence_number)
        
        if is_dup:
            self._stats['total_duplicates'] += 1
            if self._on_duplicate:
                self._on_duplicate(session_id, sequence_number)
        
        return is_dup
    
    def mark_message_processed(self, session_id: str, sequence_number: int) -> str:
        """
        Mark a message as processed for deduplication.
        
        Args:
            session_id: Session identifier
            sequence_number: Message sequence number
            
        Returns:
            Message ID
        """
        return self._deduplicator.mark_processed(session_id, sequence_number)
    
    async def process_queued_messages(self, peer_id: str) -> int:
        """
        Process queued messages for a peer that is now online.
        
        Args:
            peer_id: Peer identifier
            
        Returns:
            Number of messages sent
        """
        if not self._send_callback:
            log.warning("No send callback configured")
            return 0
        
        queue = self.get_or_create_queue(peer_id)
        sent_count = 0
        
        while True:
            message = queue.dequeue()
            if not message:
                break
            
            try:
                await self._send_callback(peer_id, message.payload)
                queue.mark_sent(message.message_id)
                self._stats['total_sent'] += 1
                sent_count += 1
                log.debug(f"Sent queued message {message.message_id} to {peer_id}")
                
            except Exception as e:
                log.error(f"Failed to send message {message.message_id}: {e}")
                queue.mark_failed(message.message_id)
                self._stats['total_failed'] += 1
                # Stop processing on failure - will retry later
                break
        
        return sent_count
    
    async def start_retry_loop(self):
        """Start the background retry loop."""
        if self._running:
            return
        
        self._running = True
        self._retry_task = asyncio.create_task(self._retry_loop())
        log.info("Started resilient communication retry loop")
    
    async def stop_retry_loop(self):
        """Stop the background retry loop."""
        self._running = False
        if self._retry_task:
            self._retry_task.cancel()
            try:
                await self._retry_task
            except asyncio.CancelledError:
                import logging; logging.getLogger(__name__).debug("Ignored exception")
        log.info("Stopped resilient communication retry loop")
    
    async def _retry_loop(self):
        """Background loop to retry failed messages."""
        while self._running:
            try:
                # Check each peer's queue
                with self._lock:
                    peer_ids = list(self._queues.keys())
                
                for peer_id in peer_ids:
                    if not self._running:
                        break
                    
                    # Try to send pending messages
                    await self.process_queued_messages(peer_id)
                
                # Sleep before next check
                await asyncio.sleep(1.0)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Error in retry loop: {e}")
                await asyncio.sleep(5.0)
    
    def get_queue_stats(self, peer_id: str) -> Optional[Dict[str, int]]:
        """Get statistics for a peer's queue."""
        with self._lock:
            if peer_id in self._queues:
                return self._queues[peer_id].get_stats()
            return None
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get overall statistics."""
        with self._lock:
            queue_stats = {
                peer_id: queue.get_stats()
                for peer_id, queue in self._queues.items()
            }
        
        return {
            'manager': self._stats,
            'deduplicator': self._deduplicator.get_stats(),
            'queues': queue_stats,
            'total_peers_with_queues': len(queue_stats)
        }
    
    def clear_queue(self, peer_id: str):
        """Clear the queue for a specific peer."""
        with self._lock:
            if peer_id in self._queues:
                self._queues[peer_id].clear()
                log.info(f"Cleared queue for peer {peer_id}")
    
    def clear_all(self):
        """Clear all queues and deduplication state."""
        with self._lock:
            for queue in self._queues.values():
                queue.clear()
            self._queues.clear()
        self._deduplicator.clear()
        log.info("Cleared all resilient communication state")


# Global instance for convenience
_global_manager: Optional[ResilientCommunicationManager] = None


def get_resilient_manager() -> ResilientCommunicationManager:
    """Get the global resilient communication manager."""
    global _global_manager
    if _global_manager is None:
        _global_manager = ResilientCommunicationManager()
    return _global_manager


def initialize_resilient_manager(
    send_callback: Optional[Callable[[str, bytes], asyncio.Future]] = None,
    on_duplicate: Optional[Callable[[str, int], None]] = None
) -> ResilientCommunicationManager:
    """
    Initialize the global resilient communication manager.
    
    Args:
        send_callback: Async function to send message to peer
        on_duplicate: Callback when duplicate detected
        
    Returns:
        The initialized manager
    """
    global _global_manager
    _global_manager = ResilientCommunicationManager(
        send_callback=send_callback,
        on_duplicate=on_duplicate
    )
    return _global_manager
