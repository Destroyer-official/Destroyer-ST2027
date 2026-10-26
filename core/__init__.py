# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""
Core orchestration module.

Provides the main SecureP2PChat orchestrator class and configuration management.
"""

from .orchestrator import SecureP2PChat
from .config import ConfigManager

__all__ = ["SecureP2PChat", "ConfigManager"]
