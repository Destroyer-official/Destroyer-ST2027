"""
Messaging operations coordinator.

Coordinates all messaging operations through sub-modules.
"""

from ..base import BaseModule


class MessagingManager(BaseModule):
    """Coordinator for all messaging operations."""
    
    def __init__(self, orchestrator):
        """Initialize messaging manager."""
        super().__init__(orchestrator)
        self._handler = None
        self._encryption = None
        self._commands = None
    
    @property
    def handler(self):
        """Lazy load message handler module."""
        if self._handler is None:
            from .handler import MessageHandler
            self._handler = MessageHandler(self.orchestrator)
        return self._handler
    
    @property
    def encryption(self):
        """Lazy load message encryption module."""
        if self._encryption is None:
            from .encryption import MessageEncryption
            self._encryption = MessageEncryption(self.orchestrator)
        return self._encryption
    
    @property
    def commands(self):
        """Lazy load command processor module."""
        if self._commands is None:
            from .commands import CommandProcessor
            self._commands = CommandProcessor(self.orchestrator)
        return self._commands
