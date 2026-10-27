"""
Messaging operations coordinator.

Coordinates all messaging operations through sub-modules.
"""

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule

# Optional group-key hook (additive only; 1:1 flow untouched).
# Pairwise-distributed group messaging skeleton lives in group_key_manager.py.
# Imported lazily/guarded so 1:1 paths work when the module is absent.
try:
    from ..group_key_manager import GroupKeyManager  # type: ignore
except (ImportError, ValueError):
    try:
        from group_key_manager import GroupKeyManager  # type: ignore
    except ImportError:
        GroupKeyManager = None  # type: ignore


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

    @property
    def group_manager(self):
        """Lazy, optional GroupKeyManager (None when unavailable).

        Additive hook only: never used by the 1:1 flow. Group traffic
        fans out over existing pairwise channels; see group_key_manager.py.
        """
        if GroupKeyManager is None:
            return None
        if self.__dict__.get("_group_manager") is None:
            try:
                self.__dict__["_group_manager"] = GroupKeyManager(
                    orchestrator=self.orchestrator
                )
            except Exception:
                return None
        return self.__dict__.get("_group_manager")
