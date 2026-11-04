"""
Secure P2P Core - secure Modular Architecture

This package provides a complete modular implementation of the secure
secure P2P communication system. All functionality is organized into focused,
single-responsibility modules.

Module Structure:
- core/: Orchestration and configuration
- crypto/: Cryptographic operations (padding, signatures, KEM, auth tags)
- network/: Network operations (handshake, I/O, monitoring, connection)
- security/: Security operations (hardening, integrity, monitoring, validation)
- keys/: Key management (storage, rotation, generation, HSM integration)
- data/: Data management (user, peer, file transfer)
- messaging/: Message handling (handler, encryption, commands)
- ui/: User interface (display, prompts, menus)
- utils/: Utilities (initialization, cleanup, memory, helpers)
"""

__version__ = "1.0.0"
__author__ = "secure P2P Team"

# Import base classes and error types for public API
from .base import BaseModule, ModuleError, CryptoError, HandshakeError, ValidationError
from .data_models import HandshakeState, HandshakeContext, SecurityEvent, UserProfile, PeerInfo

__all__ = [
    "BaseModule",
    "ModuleError",
    "CryptoError",
    "HandshakeError",
    "ValidationError",
    "HandshakeState",
    "HandshakeContext",
    "SecurityEvent",
    "UserProfile",
    "PeerInfo",
]
