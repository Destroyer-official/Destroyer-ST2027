"""
HSM/TPM integration operations.
Provides hardware security module and trusted platform module integration
for hardware-backed cryptographic operations.
"""
import logging
from typing import Optional
try:
    from base import BaseModule, KeyManagementError
except ImportError:
    from ..base import BaseModule, KeyManagementError

# Import platform HSM interface
try:
    import platform_hsm_interface as cphs
    HSM_AVAILABLE = True
except ImportError:
    HSM_AVAILABLE = False

class HSMIntegration(BaseModule):
    """
    HSM/TPM integration operations.
    Provides integration with hardware security modules (HSM) and trusted
    platform modules (TPM) for hardware-backed key storage and cryptographic operations.
    """

    def __init__(self, orchestrator):
        """
        Initialize HSM integration module.
        Args:
            orchestrator: Reference to the main orchestrator
        """
        super().__init__(orchestrator)
        self.logger = logging.getLogger(__name__)
        self._hsm_initialized = False

    # AUDITED (B107): fail-closed PIN policy or no-default factor, verified individually 2026-09
    def initialize_hsm(self, lib_path: str = "", pin: str = "", token_label: str = "", slot_id: int = 0, use_quantum_resistant: bool = True, force_software: bool = False) -> bool:  # nosec: B107
        """
        Initialize hardware security module (HSM) with post-quantum cryptography.
        This function establishes a secure hardware-backed cryptographic environment
        with comprehensive protection against both classical and quantum threats.
        Args:
            lib_path: Path to PKCS#11 library (optional)
            pin: PIN or password for the HSM. B107 note: "" is NOT a
                default credential -- it delegates to
                platform_hsm_interface.init_hsm, which fails closed
                (refuses token login) without an explicit operator PIN
                unless lab opt-in P2P_HSM_TEST_DEFAULT_PINS=1.
            token_label: Label of the token to use (optional)
            slot_id: Slot ID to use (optional)
            use_quantum_resistant: Enable post-quantum cryptography (default: True)
            force_software: Force software implementation (default: False)
        Returns:
            bool: True if initialization was successful
        """
        try:
            if not HSM_AVAILABLE:
                self.logger.warning("Platform HSM interface not available")
                return False
                
            # Delegate to platform HSM interface
            result = cphs.init_hsm(
                lib_path=lib_path,
                pin=pin,
                token_label=token_label,
                slot_id=slot_id,
                use_quantum_resistant=use_quantum_resistant,
                force_software=force_software
            )
            
            if result:
                self._hsm_initialized = True
                self.logger.info("HSM initialized successfully")
            else:
                self.logger.warning("HSM initialization returned False")
                
            return result
        except Exception as e:
            self.logger.error(f"HSM initialization failed: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to initialize HSM: {e}",
                category="KEY_MGMT",
                severity="HIGH",
                module="keys.hsm_integration",
                function="initialize_hsm"
            )

    def store_key_in_hsm(self, key_id: str, key_material: bytes) -> bool:
        """
        Store key in HSM with hardware-backed protection.
        Args:
            key_id: Identifier for the key
            key_material: The key material to store
        Returns:
            bool: True if storage was successful
        """
        try:
            if not HSM_AVAILABLE:
                self.logger.warning("Platform HSM interface not available for key storage")
                return False
                
            if not self._hsm_initialized:
                self.logger.warning("HSM not initialized, attempting initialization")
                if not self.initialize_hsm():
                    return False
                    
            # Check if store function is available
            if hasattr(cphs, 'store_key_in_tpm'):
                result = cphs.store_key_in_tpm(key_id, key_material)
                if result:
                    self.logger.debug(f"Key '{key_id}' stored in HSM successfully")
                return result
            elif hasattr(cphs, 'store_key_file_secure'):
                result = cphs.store_key_file_secure(key_id, key_material)
                if result:
                    self.logger.debug(f"Key '{key_id}' stored securely")
                return result
            else:
                self.logger.warning("No HSM key storage method available")
                return False
                
        except Exception as e:
            self.logger.error(f"HSM key storage failed: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to store key in HSM: {e}",
                category="KEY_MGMT",
                severity="HIGH",
                module="keys.hsm_integration",
                function="store_key_in_hsm"
            )

    def retrieve_key_from_hsm(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve key from HSM.
        Args:
            key_id: Identifier for the key to retrieve
        Returns:
            bytes: The retrieved key material, or None if not found
        """
        try:
            if not HSM_AVAILABLE:
                self.logger.warning("Platform HSM interface not available for key retrieval")
                return None
                
            if not self._hsm_initialized:
                self.logger.warning("HSM not initialized")
                return None
                
            # Check if retrieve function is available
            if hasattr(cphs, 'retrieve_key_file_secure'):
                key_material = cphs.retrieve_key_file_secure(key_id)
                if key_material:
                    self.logger.debug(f"Key '{key_id}' retrieved from HSM successfully")
                return key_material
            else:
                self.logger.warning("No HSM key retrieval method available")
                return None
                
        except Exception as e:
            self.logger.error(f"HSM key retrieval failed: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to retrieve key from HSM: {e}",
                category="KEY_MGMT",
                severity="HIGH",
                module="keys.hsm_integration",
                function="retrieve_key_from_hsm"
            )

    async def hsm_sign(self, message: bytes, key_id: str) -> Optional[bytes]:
        """
        Sign message using HSM-backed key.
        Args:
            message: The message to sign
            key_id: Identifier for the signing key
        Returns:
            bytes: The signature, or None if signing failed
        """
        try:
            if not HSM_AVAILABLE:
                self.logger.warning("Platform HSM interface not available for signing")
                return None
                
            if not self._hsm_initialized:
                self.logger.warning("HSM not initialized")
                return None
                
            # Check if signing function is available.
            # needs-manual-review: platform exposes sign_with_hsm_key(handle,
            # data) and sign_with_tpm_key(key_id, data) — key_id-first order
            # assumed here; verify against hardware (old code called a
            # non-existent 'sign_with_hsm' with (message, key_id) order).
            if hasattr(cphs, 'sign_with_hsm_key'):
                signature = cphs.sign_with_hsm_key(key_id, message)
                if signature:
                    self.logger.debug(f"Message signed with HSM key '{key_id}'")
                    return signature
                # Fall through to TPM path when HSM path yields nothing.
            if hasattr(cphs, 'sign_with_tpm_key'):
                signature = cphs.sign_with_tpm_key(key_id, message)
                if signature:
                    self.logger.debug(f"Message signed with TPM key '{key_id}'")
                return signature
            self.logger.debug("No HSM signing method available")
            return None
                
        except Exception as e:
            self.logger.error(f"HSM signing failed: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to sign with HSM: {e}",
                category="KEY_MGMT",
                severity="HIGH",
                module="keys.hsm_integration",
                function="hsm_sign"
            )

    def is_hsm_available(self) -> bool:
        """
        Check if HSM is available and initialized.
        Returns:
            bool: True if HSM is available and initialized
        """
        return HSM_AVAILABLE and self._hsm_initialized

    def get_hsm_info(self) -> dict:
        """
        Get information about the HSM.
        Returns:
            dict: HSM information including provider type and capabilities
        """
        info = {
            'available': HSM_AVAILABLE,
            'initialized': self._hsm_initialized,
            'provider_type': None,
            'hardware_active': False
        }
        
        if HSM_AVAILABLE and self._hsm_initialized:
            try:
                if hasattr(cphs, '_hsm_provider_type'):
                    info['provider_type'] = cphs._hsm_provider_type
                if hasattr(cphs, '_hardware_security_active'):
                    info['hardware_active'] = cphs._hardware_security_active
            except Exception as e:
                self.logger.debug(f"Could not retrieve HSM info: {e}")
                
        return info