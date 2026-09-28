"""
Connection health monitoring.

Provides connection quality assessment and heartbeat management with detailed logging.
"""

import asyncio
import json
import time
import logging
from typing import Optional, Dict, Any

try:
    from ..base import BaseModule, NetworkError
except (ImportError, ValueError):
    from base import BaseModule, NetworkError


class ConnectionMonitoring(BaseModule):
    """
    Connection health monitoring.
    
    Provides connection quality assessment and heartbeat management including:
    - Periodic heartbeat sending and receiving
    - Connection quality metrics (latency, failed heartbeats)
    - Automatic reconnection on failure
    - Detailed logging of connection events
    """
    
    # Monitoring configuration constants
    HEARTBEAT_INTERVAL = 30.0  # seconds
    HEARTBEAT_TIMEOUT = 10.0  # seconds
    MISSED_HEARTBEATS_THRESHOLD = 3
    HEALTH_CHECK_INTERVAL = 5.0  # seconds
    MAX_RECONNECT_ATTEMPTS = 5
    
    # Connection quality thresholds
    EXCELLENT_LATENCY = 100  # ms
    GOOD_LATENCY = 250  # ms
    FAIR_LATENCY = 500  # ms
    
    def __init__(self, orchestrator):
        """
        Initialize connection monitoring.
        
        Args:
            orchestrator: Reference to main SecureP2PChat orchestrator
        """
        super().__init__(orchestrator)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Connection health metrics
        self.connection_health = {
            'last_heartbeat': time.time(),
            'failed_heartbeats': 0,
            'latency_ms': 0.0,
            'connection_quality': 'unknown',
            'reconnect_attempts': 0,
            'max_reconnect_attempts': self.MAX_RECONNECT_ATTEMPTS
        }
        
        # Connection statistics
        self.connection_stats = {
            'connection_start': time.time(),
            'connection_uptime': 0.0,
            'last_activity': time.time(),
            'messages_sent': 0,
            'messages_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0
        }
        
        self._heartbeat_sequence = 0
        self._monitoring_task = None
    
    async def monitor_connection_health(self) -> None:
        """
        Monitor connection health and automatically handle reconnection.
        
        This method continuously monitors the connection quality and handles:
        - Heartbeat monitoring
        - Latency measurement
        - Automatic reconnection on failure
        - Connection quality assessment
        """
        self.logger.info("[MONITOR] Starting connection health monitoring")
        
        try:
            while not (self.orchestrator and hasattr(self.orchestrator, 'stop_event') and self.orchestrator.stop_event.is_set()):
                try:
                    if self.orchestrator and hasattr(self.orchestrator, 'is_connected') and self.orchestrator.is_connected:
                        # Check heartbeat status
                        current_time = time.time()
                        time_since_heartbeat = current_time - self.connection_health['last_heartbeat']
                        
                        if time_since_heartbeat > self.HEARTBEAT_INTERVAL * 2:
                            # Missed heartbeat - connection may be degraded
                            self.connection_health['failed_heartbeats'] += 1
                            self.logger.warning(
                                f"[MONITOR] Missed heartbeat - failed count: {self.connection_health['failed_heartbeats']}"
                            )
                            
                            if self.connection_health['failed_heartbeats'] >= self.MISSED_HEARTBEATS_THRESHOLD:
                                # Connection is likely dead
                                self.logger.error("[MONITOR] Connection appears to be dead - initiating reconnection")
                                await self._handle_connection_failure()
                                continue
                        
                        # Update connection quality
                        self._assess_connection_quality()
                        
                        # Update uptime
                        self.connection_stats['connection_uptime'] = current_time - self.connection_stats.get('connection_start', current_time)
                    
                    # Sleep before next check
                    await asyncio.sleep(self.HEALTH_CHECK_INTERVAL)
                
                except asyncio.CancelledError:
                    self.logger.info("[MONITOR] Connection monitoring cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"[MONITOR] Error in connection monitoring: {e}", exc_info=True)
                    await asyncio.sleep(self.HEALTH_CHECK_INTERVAL)
        
        finally:
            self.logger.info("[MONITOR] Connection health monitoring stopped")
    
    async def send_heartbeat(self, peer_id: Optional[str] = None) -> bool:
        """
        Send heartbeat message to peer.
        
        Args:
            peer_id: Optional peer identifier (for logging)
        
        Returns:
            True if heartbeat sent successfully, False otherwise
        """
        try:
            if not self.orchestrator:
                self.logger.error("[HEARTBEAT] Orchestrator not available")
                return False
            
            if not hasattr(self.orchestrator, 'tcp_socket') or not self.orchestrator.tcp_socket:
                self.logger.error("[HEARTBEAT] TCP socket not available")
                return False
            
            if not hasattr(self.orchestrator, '_encrypt_message'):
                self.logger.error("[HEARTBEAT] Encryption not available")
                return False
            
            # Create heartbeat message
            heartbeat_time = time.time()
            self._heartbeat_sequence += 1
            
            heartbeat_msg = "HEARTBEAT"
            
            # Encrypt heartbeat
            encrypted_heartbeat = await self.orchestrator._encrypt_message(heartbeat_msg)
            
            if not encrypted_heartbeat:
                self.logger.error("[HEARTBEAT] Failed to encrypt heartbeat")
                return False
            
            # Send heartbeat
            if hasattr(self.orchestrator, 'p2p') and hasattr(self.orchestrator.p2p, 'send_framed'):
                success = await self.orchestrator.p2p.send_framed(self.orchestrator.tcp_socket, encrypted_heartbeat)
            else:
                # Fallback: send directly
                try:
                    await asyncio.get_event_loop().sock_sendall(self.orchestrator.tcp_socket, encrypted_heartbeat)
                    success = True
                except Exception as e:
                    self.logger.error(f"[HEARTBEAT] Failed to send: {e}")
                    success = False
            
            if success:
                self.logger.debug(f"[HEARTBEAT] Sent heartbeat #{self._heartbeat_sequence}")
                self.connection_health['last_heartbeat'] = heartbeat_time
                self.connection_stats['last_activity'] = heartbeat_time
                return True
            else:
                self.logger.warning("[HEARTBEAT] Failed to send heartbeat")
                return False
        
        except Exception as e:
            self.logger.error(f"[HEARTBEAT] Error sending heartbeat: {e}", exc_info=True)
            return False
    
    async def handle_heartbeat_response(self, heartbeat_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Handle incoming heartbeat response and update connection metrics.
        
        Args:
            heartbeat_data: Optional heartbeat message data with timestamp
        """
        try:
            current_time = time.time()
            
            if heartbeat_data and isinstance(heartbeat_data, dict) and 'timestamp' in heartbeat_data:
                # Calculate latency
                latency_ms = (current_time - heartbeat_data['timestamp']) * 1000
                self.connection_health['latency_ms'] = latency_ms
                self.logger.debug(f"[HEARTBEAT] Latency: {latency_ms:.2f}ms")
            
            # Update last heartbeat time
            self.connection_health['last_heartbeat'] = current_time
            self.connection_health['failed_heartbeats'] = 0  # Reset failed counter
            
            # Update activity timestamp
            self.connection_stats['last_activity'] = current_time
            self.connection_stats['messages_received'] += 1
            
            self.logger.debug("[HEARTBEAT] Heartbeat response handled")
        
        except Exception as e:
            self.logger.error(f"[HEARTBEAT] Error handling heartbeat response: {e}", exc_info=True)
    
    def _assess_connection_quality(self) -> str:
        """
        Assess and update connection quality based on various metrics.
        
        Returns:
            Connection quality string: 'excellent', 'good', 'fair', or 'poor'
        """
        try:
            failed_heartbeats = self.connection_health['failed_heartbeats']
            latency = self.connection_health['latency_ms']
            
            if failed_heartbeats == 0 and latency < self.EXCELLENT_LATENCY:
                quality = 'excellent'
            elif failed_heartbeats <= 1 and latency < self.GOOD_LATENCY:
                quality = 'good'
            elif failed_heartbeats <= 2 and latency < self.FAIR_LATENCY:
                quality = 'fair'
            else:
                quality = 'poor'
            
            if quality != self.connection_health['connection_quality']:
                self.logger.info(
                    f"[MONITOR] Connection quality changed: {self.connection_health['connection_quality']} -> {quality}"
                )
                self.connection_health['connection_quality'] = quality
            
            return quality
        
        except Exception as e:
            self.logger.error(f"[MONITOR] Error assessing connection quality: {e}", exc_info=True)
            return 'unknown'
    
    def assess_connection_quality(self, peer_id: Optional[str] = None) -> float:
        """
        Assess connection quality as a float (0.0-1.0).
        
        Args:
            peer_id: Optional peer identifier (for logging)
        
        Returns:
            Connection quality as float: 1.0 (excellent) to 0.0 (poor)
        """
        quality_str = self._assess_connection_quality()
        
        quality_map = {
            'excellent': 1.0,
            'good': 0.75,
            'fair': 0.5,
            'poor': 0.25,
            'unknown': 0.0
        }
        
        return quality_map.get(quality_str, 0.0)
    
    async def _handle_connection_failure(self) -> None:
        """
        Handle connection failure with intelligent reconnection strategy.
        """
        try:
            self.logger.warning("[MONITOR] Handling connection failure")
            
            if not self.orchestrator:
                return
            
            # Mark as disconnected
            if hasattr(self.orchestrator, 'is_connected'):
                self.orchestrator.is_connected = False
            
            # Increment reconnect attempts
            self.connection_health['reconnect_attempts'] += 1
            
            # Check if we should attempt reconnection
            if self.connection_health['reconnect_attempts'] > self.connection_health['max_reconnect_attempts']:
                self.logger.error("[MONITOR] Maximum reconnection attempts exceeded - giving up")
                if hasattr(self.orchestrator, '_close_connection'):
                    await self.orchestrator._close_connection(attempt_reconnect=False)
                return
            
            # Close current connection
            if hasattr(self.orchestrator, 'tcp_socket') and self.orchestrator.tcp_socket:
                try:
                    self.orchestrator.tcp_socket.close()
                except Exception as _sock_err:
                    self.orchestrator.logger.debug(f"Socket cleanup suppressed: {_sock_err}")
                self.orchestrator.tcp_socket = None
            
            # Wait before reconnection (exponential backoff)
            backoff_time = min(2 ** self.connection_health['reconnect_attempts'], 60)  # Max 60 seconds
            self.logger.info(
                f"[MONITOR] Waiting {backoff_time}s before reconnection attempt {self.connection_health['reconnect_attempts']}"
            )
            await asyncio.sleep(backoff_time)
            
            # Attempt reconnection
            if hasattr(self.orchestrator, 'peer_ip') and hasattr(self.orchestrator, 'peer_port'):
                self.logger.info(
                    f"[MONITOR] Attempting to reconnect to {self.orchestrator.peer_ip}:{self.orchestrator.peer_port}"
                )
                if hasattr(self.orchestrator, '_connect_to_peer'):
                    success = await self.orchestrator._connect_to_peer(
                        self.orchestrator.peer_ip,
                        self.orchestrator.peer_port
                    )
                    
                    if success:
                        self.logger.info("[MONITOR] Reconnection successful")
                        self.connection_health['reconnect_attempts'] = 0  # Reset counter
                        self.connection_health['failed_heartbeats'] = 0
                        self.connection_health['last_heartbeat'] = time.time()
                    else:
                        self.logger.error("[MONITOR] Reconnection failed")
        
        except Exception as e:
            self.logger.error(f"[MONITOR] Error handling connection failure: {e}", exc_info=True)
    
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Get comprehensive connection status information.
        
        Returns:
            Dictionary with connection status and health metrics
        """
        current_time = time.time()
        
        return {
            'connected': self.orchestrator.is_connected if self.orchestrator and hasattr(self.orchestrator, 'is_connected') else False,
            'quality': self.connection_health['connection_quality'],
            'latency_ms': self.connection_health['latency_ms'],
            'failed_heartbeats': self.connection_health['failed_heartbeats'],
            'uptime': self.connection_stats['connection_uptime'],
            'last_activity': current_time - self.connection_stats['last_activity'],
            'messages_sent': self.connection_stats['messages_sent'],
            'messages_received': self.connection_stats['messages_received'],
            'bytes_sent': self.connection_stats['bytes_sent'],
            'bytes_received': self.connection_stats['bytes_received']
        }
    
    async def cleanup(self) -> None:
        """Cleanup monitoring resources."""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                self.logger.debug("Monitoring task cancelled cleanly")
        
        self.logger.debug("Connection monitoring cleaned up")
        await super().cleanup()
