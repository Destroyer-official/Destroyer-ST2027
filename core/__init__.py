"""
Core orchestration module.

Provides the main SecureP2PChat orchestrator class and configuration management.
"""

from .orchestrator import SecureP2PChat
from .config import ConfigManager

__all__ = ["SecureP2PChat", "ConfigManager"]
