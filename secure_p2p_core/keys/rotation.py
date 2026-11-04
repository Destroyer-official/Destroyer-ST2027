"""
Key rotation operations.

Provides key rotation and lifecycle management for cryptographic keys.
"""

import asyncio
import logging
import threading
import time
from typing import Dict, Optional

from ..base import BaseModule, KeyManagementError


class KeyRotation(BaseModule):
    """
    Key rotation operations.
    
    Manages the lifecycle and rotation of cryptographic keys to maintain
    forward secrecy and security over time.
    """
    
    def __init__(self, orchestrator):
        """
        Initialize key rotation module.
        
        Args:
            orchestrator: Reference to the main orchestrator
        """
        super().__init__(orchestrator)
        self.logger = logging.getLogger(__name__)
        self._rotation_timer = None
        self._rotation_interval = None
        
    async def rotate_keys(self) -> bool:
        """
        Manually rotate all cryptographic keys.
        
        This delegates to the hybrid key exchange module to perform
        the actual key rotation, which includes:
        - Securely erasing old keys
        - Generating new identity keys
        - Updating key creation timestamps
        
        Returns:
            bool: True if rotation was successful
        """
        try:
            # If _rotate_keys was explicitly set on orchestrator (e.g. in unit tests)
            if self.orchestrator and '_rotate_keys' in getattr(self.orchestrator, '__dict__', {}):
                res = self.orchestrator._rotate_keys()
                if asyncio.iscoroutine(res):
                    return bool(await res)
                return bool(res)

            # Check if hybrid_kex is available and has rotate_keys
            if (self.orchestrator and hasattr(self.orchestrator, 'hybrid_kex') and 
                self.orchestrator.hybrid_kex and hasattr(self.orchestrator.hybrid_kex, 'rotate_keys')):
                result = self.orchestrator.hybrid_kex.rotate_keys()
                if asyncio.iscoroutine(result):
                    result = await result
                return bool(result)

            if self.orchestrator and hasattr(self.orchestrator, '_rotate_keys'):
                res = self.orchestrator._rotate_keys()
                if asyncio.iscoroutine(res):
                    return bool(await res)
                return bool(res)

            self.logger.warning("Hybrid key exchange not available for key rotation")
            return False
                
            # Delegate to hybrid_kex for actual rotation
            if hasattr(self.orchestrator.hybrid_kex, 'rotate_keys'):
                result = self.orchestrator.hybrid_kex.rotate_keys()
                if asyncio.iscoroutine(result):
                    result = await result
                if result:
                    self.logger.info("Key rotation completed successfully")
                else:
                    self.logger.warning("Key rotation returned False")
                return bool(result)
            else:
                self.logger.error("rotate_keys method not available in hybrid_kex")
                return False

                
        except Exception as e:
            self.logger.error(f"Key rotation failed: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to rotate keys: {e}",
                category="KEY_MGMT",
                severity="HIGH",
                module="keys.rotation",
                function="rotate_keys"
            )

    def derive_auth_key(self, shared_secret: bytes) -> bytes:
        """Derive authentication key from shared secret."""
        if self.orchestrator and hasattr(self.orchestrator, '_derive_auth_key'):
            return self.orchestrator._derive_auth_key(shared_secret)
        import hashlib
        return hashlib.sha3_256(shared_secret).digest()

    
    def _check_key_rotation_status(self) -> Dict:
        """
        Check cryptographic key rotation status.
        
        Returns:
            dict: Status information including whether rotation is needed
        """
        try:
            status = {
                'needs_rotation': False,
                'rotation_available': False,
                'next_rotation_time': None,
                'key_age': None
            }
            
            if hasattr(self.orchestrator, 'hybrid_kex') and self.orchestrator.hybrid_kex:
                status['rotation_available'] = True
                
                # Check if keys need rotation
                if hasattr(self.orchestrator.hybrid_kex, 'needs_rotation'):
                    needs_rotation = self.orchestrator.hybrid_kex.needs_rotation()
                    status['needs_rotation'] = needs_rotation
                    
                    if needs_rotation:
                        self.logger.info("Cryptographic keys require rotation")
                        
                # Get next rotation time if available
                if hasattr(self.orchestrator.hybrid_kex, 'next_rotation_time'):
                    status['next_rotation_time'] = self.orchestrator.hybrid_kex.next_rotation_time
                    
                # Calculate key age if creation time is available
                if hasattr(self.orchestrator.hybrid_kex, 'key_creation_time'):
                    key_age = time.time() - self.orchestrator.hybrid_kex.key_creation_time
                    status['key_age'] = key_age
                    
            return status

        except Exception as e:
            self.logger.error(f"Key rotation status check failed: {e}", exc_info=True)
            return {
                'needs_rotation': False,
                'rotation_available': False,
                'error': str(e)
            }
    
    def schedule_key_rotation(self, interval: int) -> None:
        """
        Schedule automatic key rotation at specified interval.
        
        Args:
            interval: Rotation interval in seconds
        """
        try:
            if interval <= 0:
                self.logger.warning(f"Invalid rotation interval: {interval}")
                return
                
            self._rotation_interval = interval
            
            # Cancel existing timer if any
            if self._rotation_timer:
                self._rotation_timer.cancel()
                
            # Schedule new rotation
            self._rotation_timer = threading.Timer(interval, self._perform_scheduled_rotation)
            self._rotation_timer.daemon = True
            self._rotation_timer.start()
            
            self.logger.info(f"Key rotation scheduled every {interval} seconds")
            
        except Exception as e:
            self.logger.error(f"Failed to schedule key rotation: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to schedule key rotation: {e}",
                category="KEY_MGMT",
                severity="MEDIUM",
                module="keys.rotation",
                function="schedule_key_rotation"
            )
    
    def _perform_scheduled_rotation(self):
        """
        Perform scheduled key rotation.
        
        This is called by the rotation timer and reschedules itself
        after completion.
        """
        try:
            self.logger.info("Performing scheduled key rotation")
            
            # Perform rotation (synchronous call to async method)
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If loop is running, schedule as task
                    asyncio.create_task(self.rotate_keys())
                else:
                    # If no loop, run in new loop
                    asyncio.run(self.rotate_keys())
            except RuntimeError:
                # Fallback if no event loop
                asyncio.run(self.rotate_keys())
                
            # Reschedule next rotation
            if self._rotation_interval:
                self._rotation_timer = threading.Timer(
                    self._rotation_interval,
                    self._perform_scheduled_rotation
                )
                self._rotation_timer.daemon = True
                self._rotation_timer.start()
                
        except Exception as e:
            self.logger.error(f"Scheduled key rotation failed: {e}", exc_info=True)
    
    def cancel_scheduled_rotation(self):
        """Cancel any scheduled key rotation."""
        if self._rotation_timer:
            self._rotation_timer.cancel()
            self._rotation_timer = None
            self.logger.info("Scheduled key rotation cancelled")
