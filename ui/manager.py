"""
UI operations coordinator.

Coordinates all UI operations through sub-modules.
"""

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


class UIManager(BaseModule):
    """Coordinator for all UI operations."""
    
    def __init__(self, orchestrator):
        """Initialize UI manager."""
        super().__init__(orchestrator)
        self._display = None
        self._prompts = None
        self._menus = None
        self._feedback = None
    
    @property
    def display(self):
        """Lazy load display module."""
        if self._display is None:
            from .display import DisplayManager
            self._display = DisplayManager(self.orchestrator)
        return self._display
    
    @property
    def prompts(self):
        """Lazy load prompts module."""
        if self._prompts is None:
            from .prompts import PromptManager
            self._prompts = PromptManager(self.orchestrator)
        return self._prompts
    
    @property
    def menus(self):
        """Lazy load menus module."""
        if self._menus is None:
            from .menus import MenuManager
            self._menus = MenuManager(self.orchestrator)
        return self._menus
    
    @property
    def feedback(self):
        """Lazy load feedback module."""
        if self._feedback is None:
            from .feedback import FeedbackManager
            self._feedback = FeedbackManager(self.orchestrator)
        return self._feedback
    
    async def cleanup(self) -> None:
        """Cleanup UI manager and sub-modules."""
        # UI modules don't need async cleanup currently
        self.logger.debug("UI Manager cleanup complete")
