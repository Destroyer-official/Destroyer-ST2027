"""
System cleanup operations.

Provides resource cleanup and graceful shutdown.
"""

import logging
from typing import Optional

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule
from .memory import KeyEraser

log = logging.getLogger(__name__)


class Cleanup(BaseModule):
    """System cleanup operations."""
    
    async def cleanup(self) -> None:
        """
        Perform comprehensive system cleanup.
        
        This method orchestrates the cleanup of all system resources including:
        - Security monitoring threads
        - Cryptographic resources
        - Network connections
        - File handles
        """
        try:
            self.logger.info("Starting system cleanup")
            
            # Stop monitoring first
            await self.stop_monitoring()
            
            # Cleanup resources
            await self.cleanup_resources()
            
            self.logger.info("System cleanup completed successfully")
            
        except Exception as e:
            self.logger.error(f"System cleanup failed: {e}")
            raise
    
    async def cleanup_resources(self) -> None:
        """
        Cleanup all system resources.
        
        This includes:
        - TLS channel cleanup
        - Key manager cleanup
        - CA exchange cleanup
        - Hybrid key exchange cleanup
        - Double ratchet cleanup
        - Enhanced P2P system cleanup
        """
        try:
            self.logger.info("Cleaning up system resources")
            
            # Access orchestrator to cleanup components
            orchestrator = self.orchestrator
            
            # Clean up TLS channel
            if hasattr(orchestrator, 'tls_channel') and orchestrator.tls_channel is not None:
                try:
                    if hasattr(orchestrator.tls_channel, 'cleanup'):
                        self.logger.debug("Cleaning up TLS channel")
                        orchestrator.tls_channel.cleanup()
                except Exception as e:
                    self.logger.error(f"Error during TLS channel cleanup: {e}")
                finally:
                    orchestrator.tls_channel = None
            
            # Clean up SecureKeyManager
            if hasattr(orchestrator, 'key_manager') and orchestrator.key_manager:
                try:
                    if hasattr(orchestrator.key_manager, 'cleanup'):
                        self.logger.debug("Cleaning up key manager")
                        orchestrator.key_manager.cleanup()
                except Exception as e:
                    self.logger.error(f"Error during key manager cleanup: {e}")
                finally:
                    orchestrator.key_manager = None
            
            # Clean up hybrid root key
            if hasattr(orchestrator, 'hybrid_root_key') and orchestrator.hybrid_root_key:
                with KeyEraser(orchestrator.hybrid_root_key, "cleanup hybrid root key") as ke:
                    ke.secure_erase()
                orchestrator.hybrid_root_key = None
            
            # Clean up Double Ratchet state
            if hasattr(orchestrator, 'ratchet') and orchestrator.ratchet:
                with KeyEraser(orchestrator.ratchet, "cleanup Double Ratchet state") as ke:
                    if hasattr(orchestrator.ratchet, 'secure_cleanup'):
                        try:
                            orchestrator.ratchet.secure_cleanup()
                        except Exception as e:
                            self.logger.error(f"Error during Double Ratchet secure_cleanup: {e}")
                orchestrator.ratchet = None
            
            # Clean up Hybrid Key Exchange state
            if hasattr(orchestrator, 'hybrid_kex') and orchestrator.hybrid_kex:
                try:
                    if hasattr(orchestrator.hybrid_kex, 'secure_cleanup'):
                        self.logger.debug("Cleaning up hybrid key exchange")
                        orchestrator.hybrid_kex.secure_cleanup()
                except Exception as e:
                    self.logger.error(f"Error during Hybrid Key Exchange cleanup: {e}")
                finally:
                    orchestrator.hybrid_kex = None
            
            # Clean up libsodium resources
            if hasattr(orchestrator, 'libsodium_handle') and orchestrator.libsodium_handle is not None:
                try:
                    import libsodium_manager
                    if hasattr(libsodium_manager, 'cleanup_libsodium'):
                        self.logger.debug("Cleaning up libsodium")
                        libsodium_manager.cleanup_libsodium()
                    orchestrator.libsodium_handle = None
                except Exception as e:
                    self.logger.error(f"Error during libsodium cleanup: {e}")
            
            # Clean up Enhanced P2P System components
            if hasattr(orchestrator, 'enhanced_p2p_system') and orchestrator.enhanced_p2p_system:
                try:
                    if hasattr(orchestrator.enhanced_p2p_system, 'cleanup'):
                        self.logger.debug("Cleaning up enhanced P2P system")
                        orchestrator.enhanced_p2p_system.cleanup()
                    orchestrator.enhanced_p2p_system = None
                except Exception as e:
                    self.logger.error(f"Error during Enhanced P2P System cleanup: {e}")
            
            # Clean up enhanced managers
            if hasattr(orchestrator, 'enhanced_user_manager') and orchestrator.enhanced_user_manager:
                try:
                    if hasattr(orchestrator.enhanced_user_manager, 'cleanup'):
                        orchestrator.enhanced_user_manager.cleanup()
                    orchestrator.enhanced_user_manager = None
                except Exception as e:
                    self.logger.error(f"Error during enhanced user manager cleanup: {e}")
            
            if hasattr(orchestrator, 'enhanced_peer_manager') and orchestrator.enhanced_peer_manager:
                try:
                    if hasattr(orchestrator.enhanced_peer_manager, 'cleanup'):
                        orchestrator.enhanced_peer_manager.cleanup()
                    orchestrator.enhanced_peer_manager = None
                except Exception as e:
                    self.logger.error(f"Error during enhanced peer manager cleanup: {e}")
            
            self.logger.debug("Resource cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Resource cleanup failed: {e}")
            raise
    
    async def stop_monitoring(self) -> None:
        """
        Stop all security monitoring threads.
        
        This includes:
        - Security monitoring
        - Runtime integrity checks
        - Intrusion detection
        - Secure memory regions cleanup
        """
        try:
            self.logger.info("Stopping security monitoring")
            
            orchestrator = self.orchestrator
            
            # Stop threat detection
            if hasattr(orchestrator, 'threat_engine') and orchestrator.threat_engine:
                try:
                    orchestrator.threat_engine.stop_threat_detection()
                except Exception as e:
                    self.logger.error(f"Error stopping threat detection: {e}")
            
            # Stop security monitor
            if hasattr(orchestrator, 'security_monitor') and orchestrator.security_monitor:
                try:
                    orchestrator.security_monitor.stop_monitoring()
                    if hasattr(orchestrator.security_monitor, 'export_status_report'):
                        orchestrator.security_monitor.export_status_report("final_security_status.json")
                        self.logger.info("Final security status report exported")
                except Exception as e:
                    self.logger.error(f"Error stopping security monitor: {e}")
            
            # Stop recovery manager
            if hasattr(orchestrator, 'recovery_manager') and orchestrator.recovery_manager:
                try:
                    orchestrator.recovery_manager.stop_recovery_monitoring()
                    if hasattr(orchestrator.recovery_manager, 'export_recovery_report'):
                        orchestrator.recovery_manager.export_recovery_report("final_recovery_report.json")
                        self.logger.info("Final recovery report exported")
                except Exception as e:
                    self.logger.error(f"Error stopping recovery manager: {e}")
            
            # Stop security monitoring flags
            if hasattr(orchestrator, 'security_monitoring_active'):
                orchestrator.security_monitoring_active = False
            
            if hasattr(orchestrator, 'runtime_integrity_checks'):
                orchestrator.runtime_integrity_checks = False
            
            if hasattr(orchestrator, 'intrusion_detection_active'):
                orchestrator.intrusion_detection_active = False
            
            # Clean up secure memory regions
            if hasattr(orchestrator, 'secure_memory_regions'):
                for region in orchestrator.secure_memory_regions:
                    try:
                        if 'memory' in region and hasattr(region['memory'], 'cleanup'):
                            region['memory'].cleanup()
                    except Exception as e:
                        self.logger.error(f"Failed to cleanup secure memory region {region.get('name', 'unknown')}: {e}")
                
                orchestrator.secure_memory_regions.clear()
            
            self.logger.info("Security monitoring stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Stop monitoring failed: {e}")
            raise
    
    async def shutdown_gracefully(self) -> None:
        """
        Perform graceful system shutdown.
        
        This method ensures all resources are properly cleaned up and
        the system shuts down in a controlled manner.
        """
        try:
            self.logger.info("Starting graceful shutdown")
            
            # Perform full cleanup
            await self.cleanup()
            
            self.logger.info("Graceful shutdown completed successfully")
            
        except Exception as e:
            self.logger.error(f"Graceful shutdown failed: {e}")
            raise
