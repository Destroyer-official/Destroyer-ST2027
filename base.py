"""
Base module class for all P2P modules.

This module provides a common base class that all P2P modules inherit from,
ensuring consistent initialization, cleanup, and logging patterns.
"""

import logging
from typing import Optional, Any


class BaseModule:
    """
    Base class for all P2P modules.

    Provides common functionality including:
    - Logging setup with module-specific logger
    - Reference to main orchestrator
    - Initialization and cleanup lifecycle methods
    - Consistent error handling patterns
    """

    def __init__(self, orchestrator: Optional[Any] = None):
        """
        Initialize the base module.

        Args:
            orchestrator: Reference to the main SecureP2PChat orchestrator.
                         Can be None for standalone module usage.
        """
        self.orchestrator = orchestrator
        self.logger = self._setup_logging()
        self._initialized = False

    def _setup_logging(self) -> logging.Logger:
        """
        Set up module-specific logging.

        Returns:
            Logger instance configured for this module.
        """
        module_name = self.__class__.__module__
        class_name = self.__class__.__name__
        logger_name = f"{module_name}.{class_name}"
        logger = logging.getLogger(logger_name)
        return logger

    def initialize(self) -> None:
        """
        Initialize module resources.

        This method should be overridden by subclasses to perform
        module-specific initialization. Always call super().initialize()
        when overriding.

        Raises:
            RuntimeError: If module is already initialized.
        """
        if self._initialized:
            self.logger.warning(f"{self.__class__.__name__} already initialized")
            return
        self.logger.debug(f"Initializing {self.__class__.__name__}")
        self._initialized = True

    def cleanup(self) -> None:
        """
        Cleanup module resources.

        This method should be overridden by subclasses to perform
        module-specific cleanup. Always call super().cleanup() when overriding.
        """
        if not self._initialized:
            self.logger.warning(f"{self.__class__.__name__} not initialized, skipping cleanup")
            return
        self.logger.debug(f"Cleaning up {self.__class__.__name__}")
        self._initialized = False

    @property
    def is_initialized(self) -> bool:
        """
        Check if module is initialized.

        Returns:
            True if module is initialized, False otherwise.
        """
        return self._initialized

    def log_error(self, message: str, exception: Optional[Exception] = None) -> None:
        """
        Log an error with consistent formatting.

        Args:
            message: Error message to log.
            exception: Optional exception to include in log.
        """
        if exception:
            self.logger.error(f"{message}: {str(exception)}", exc_info=True)
        else:
            self.logger.error(message)

    def log_warning(self, message: str) -> None:
        """
        Log a warning with consistent formatting.

        Args:
            message: Warning message to log.
        """
        self.logger.warning(message)

    def log_info(self, message: str) -> None:
        """
        Log an info message with consistent formatting.

        Args:
            message: Info message to log.
        """
        self.logger.info(message)

    def log_debug(self, message: str) -> None:
        """
        Log a debug message with consistent formatting.

        Args:
            message: Debug message to log.
        """
        self.logger.debug(message)


class ModuleError(Exception):
    """
    Base exception for module errors.

    Provides structured error information including category, severity,
    module name, function name, and stable error code.
    """

    def __init__(self, message: str, category: str = "GENERAL",
                 severity: str = "MEDIUM", module: str = "unknown",
                 function: str = "unknown", error_code: Optional[str] = None):
        """
        Initialize module error.

        Args:
            message: Error message describing what went wrong.
            category: Error category (CRYPTO, HANDSHAKE, VALIDATION, MEMORY, KEY_MGMT, etc.)
            severity: Error severity (LOW, MEDIUM, HIGH, CRITICAL)
            module: Module name where error occurred
            function: Function name where error occurred
            error_code: Optional stable error code for tracking
        """
        self.message = message
        self.category = category
        self.severity = severity
        self.module = module
        self.function = function
        self.error_code = error_code or self._generate_error_code()
        super().__init__(self.format_error())

    def _generate_error_code(self) -> str:
        """Generate stable error code from category and function."""
        return f"{self.category}_{self.function.upper()}_{hash(self.message) % 1000:03d}"

    def format_error(self) -> str:
        """Format error message with all context."""
        return (f"[{self.severity}] [{self.category}] "
                f"{self.module}.{self.function}: {self.message} "
                f"(Code: {self.error_code})")


class CryptoError(ModuleError):
    """Cryptographic operation error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'CRYPTO')
        kwargs.setdefault('severity', 'HIGH')
        super().__init__(message, **kwargs)


class HandshakeError(ModuleError):
    """Handshake protocol error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'HANDSHAKE')
        kwargs.setdefault('severity', 'CRITICAL')
        super().__init__(message, **kwargs)


class ValidationError(ModuleError):
    """Input validation error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'VALIDATION')
        kwargs.setdefault('severity', 'MEDIUM')
        super().__init__(message, **kwargs)


class KeyManagementError(ModuleError):
    """Key management operation error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'KEY_MGMT')
        kwargs.setdefault('severity', 'HIGH')
        super().__init__(message, **kwargs)


class NetworkError(ModuleError):
    """Network operation error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'NETWORK')
        kwargs.setdefault('severity', 'MEDIUM')
        super().__init__(message, **kwargs)


class SecurityError(ModuleError):
    """Security policy violation error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'SECURITY')
        kwargs.setdefault('severity', 'CRITICAL')
        super().__init__(message, **kwargs)


class AuditError(ModuleError):
    """Audit logging error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'AUDIT')
        kwargs.setdefault('severity', 'HIGH')
        super().__init__(message, **kwargs)


class FileTransferError(ModuleError):
    """File transfer operation error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'FILE_TRANSFER')
        kwargs.setdefault('severity', 'MEDIUM')
        super().__init__(message, **kwargs)


class UserManagementError(ModuleError):
    """User management operation error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'USER_MGMT')
        kwargs.setdefault('severity', 'MEDIUM')
        super().__init__(message, **kwargs)


class MemoryError(ModuleError):
    """Memory management error."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', 'MEMORY')
        kwargs.setdefault('severity', 'HIGH')
        super().__init__(message, **kwargs)
