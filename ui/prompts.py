"""
Prompt operations.

Provides user prompts and input handling with enhanced user feedback.
"""

import asyncio
import getpass
import logging
import time
from typing import Optional, Callable
try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule

log = logging.getLogger(__name__)


class ProgressIndicator:
    """
    Progress indicator for long-running operations.
    
    Provides visual feedback to users during operations that take time.
    Requirements: 1.7, 14.1, 14.2, 14.3, 14.4
    """
    
    def __init__(self, message: str, total: Optional[int] = None):
        """
        Initialize progress indicator.
        
        Args:
            message: Message to display
            total: Total number of steps (None for indeterminate progress)
        """
        self.message = message
        self.total = total
        self.current = 0
        self.start_time = time.time()
        self._spinner_chars = ['|', '/', '-', '\\']
        self._spinner_index = 0
    
    def update(self, current: Optional[int] = None, message: Optional[str] = None):
        """
        Update progress indicator.
        
        Args:
            current: Current step number
            message: Optional updated message
        """
        if current is not None:
            self.current = current
        else:
            self.current += 1
        
        if message:
            self.message = message
        
        # Display progress
        if self.total:
            percentage = (self.current / self.total) * 100
            bar_length = 40
            filled = int(bar_length * self.current / self.total)
            bar = '#' * filled + '-' * (bar_length - filled)
            print(f"\r{self.message}: [{bar}] {percentage:.1f}% ({self.current}/{self.total})", end='', flush=True)
        else:
            # Indeterminate progress with spinner
            spinner = self._spinner_chars[self._spinner_index % len(self._spinner_chars)]
            self._spinner_index += 1
            elapsed = time.time() - self.start_time
            print(f"\r{spinner} {self.message}... ({elapsed:.1f}s)", end='', flush=True)
    
    def complete(self, message: Optional[str] = None):
        """
        Mark progress as complete.
        
        Args:
            message: Optional completion message
        """
        elapsed = time.time() - self.start_time
        if message:
            print(f"\r {message} (completed in {elapsed:.1f}s)")
        else:
            print(f"\r {self.message} - Complete (completed in {elapsed:.1f}s)")
    
    def error(self, message: Optional[str] = None):
        """
        Mark progress as failed.
        
        Args:
            message: Optional error message
        """
        if message:
            print(f"\r[FAIL] {message}")
        else:
            print(f"\r[FAIL] {self.message} - Failed")


class PromptManager(BaseModule):
    """Prompt operations for user input and interaction."""
    
    async def async_input(self, prompt: str) -> str:
        """
        Get user input asynchronously without blocking the event loop.

        This method allows the application to receive user input while
        continuing to process network events and messages.

        Args:
            prompt: Text prompt to display to the user

        Returns:
            User input string

        Security notes:
        - Input is not validated here, validation happens at usage sites
        - Handles Ctrl+C and Ctrl+D gracefully to prevent unexpected exits
        """
        print(prompt, end='', flush=True)

        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, input)
        except EOFError:
            # Handle Ctrl+D
            print("\nEOF detected")
            return "exit"
        except KeyboardInterrupt:
            # Handle Ctrl+C
            print("\nInput interrupted")
            return "exit"
        except Exception as e:
            log.error(f"Error getting input: {e}", exc_info=True)
            return ""
    
    def prompt_user(self, prompt: str) -> str:
        """
        Prompt user for input (synchronous).
        
        Args:
            prompt: Text prompt to display to the user
            
        Returns:
            User input string
        """
        try:
            return input(prompt)
        except EOFError:
            print("\nEOF detected")
            return "exit"
        except KeyboardInterrupt:
            print("\nInput interrupted")
            return "exit"
        except Exception as e:
            log.error(f"Error prompting user: {e}", exc_info=True)
            return ""
    
    def get_user_input(self, prompt: str, validator: Optional[Callable[[str], bool]] = None) -> str:
        """
        Get user input with optional validation.
        
        Args:
            prompt: Text prompt to display to the user
            validator: Optional validation function that returns True if input is valid
            
        Returns:
            Validated user input string
        """
        try:
            while True:
                user_input = input(prompt)
                
                if validator is None:
                    return user_input
                
                if validator(user_input):
                    return user_input
                else:
                    print("Invalid input. Please try again.")
        except EOFError:
            print("\nEOF detected")
            return "exit"
        except KeyboardInterrupt:
            print("\nInput interrupted")
            return "exit"
        except Exception as e:
            log.error(f"Error getting user input: {e}", exc_info=True)
            return ""
    
    def confirm_action(self, prompt: str) -> bool:
        """
        Confirm action with user (yes/no prompt).
        
        Args:
            prompt: Text prompt to display to the user
            
        Returns:
            True if user confirms (yes), False otherwise
        """
        try:
            response = input(f"{prompt} (yes/no): ").strip().lower()
            return response in ['yes', 'y']
        except EOFError:
            print("\nEOF detected")
            return False
        except KeyboardInterrupt:
            print("\nInput interrupted")
            return False
        except Exception as e:
            log.error(f"Error confirming action: {e}", exc_info=True)
            return False
    
    def get_secure_input(self, prompt: str) -> str:
        """
        Get secure input (password) without echoing to screen.
        
        Args:
            prompt: Text prompt to display to the user
            
        Returns:
            User input string (password)
        """
        try:
            return getpass.getpass(prompt)
        except EOFError:
            print("\nEOF detected")
            return ""
        except KeyboardInterrupt:
            print("\nInput interrupted")
            return ""
        except Exception as e:
            log.error(f"Error getting secure input: {e}", exc_info=True)
            return ""
    
    def show_success(self, message: str):
        """
        Display a success message with visual indicator.
        
        Args:
            message: Success message to display
            
        Requirements: 1.7, 14.1, 14.2
        """
        print(f" {message}")
    
    def show_error(self, message: str, details: Optional[str] = None):
        """
        Display an error message with visual indicator and optional details.
        
        Args:
            message: Error message to display
            details: Optional detailed error information
            
        Requirements: 1.7, 14.1, 14.2
        """
        print(f"[FAIL] {message}")
        if details:
            print(f"   Details: {details}")
    
    def show_warning(self, message: str):
        """
        Display a warning message with visual indicator.
        
        Args:
            message: Warning message to display
            
        Requirements: 1.7, 14.1, 14.2
        """
        print(f"[WARNING]  {message}")
    
    def show_info(self, message: str):
        """
        Display an informational message with visual indicator.
        
        Args:
            message: Info message to display
            
        Requirements: 1.7, 14.1, 14.2
        """
        print(f"[INFO] {message}")
    
    def show_status(self, message: str):
        """
        Display a status message.
        
        Args:
            message: Status message to display
            
        Requirements: 1.7, 14.1, 14.2
        """
        print(f"[STATUS] {message}")
    
    def create_progress(self, message: str, total: Optional[int] = None) -> ProgressIndicator:
        """
        Create a progress indicator for long-running operations.
        
        Args:
            message: Message to display
            total: Total number of steps (None for indeterminate progress)
            
        Returns:
            ProgressIndicator instance
            
        Requirements: 1.7, 14.1, 14.2, 14.3, 14.4
        """
        return ProgressIndicator(message, total)
    
    def display_helpful_prompt(self, context: str):
        """
        Display context-sensitive helpful prompts to guide users.
        
        Args:
            context: Context identifier for the prompt
            
        Requirements: 1.7, 14.1, 14.2
        """
        prompts = {
            'server_start': (
                "\n[TIP] After starting the server, share your IPv6 address with peers.\n"
                "   They can connect using option 2 (Connect to Peer)."
            ),
            'connect_peer': (
                "\n[TIP] You can connect by username (for known peers) or by IP address.\n"
                "   For local testing, use '::1' as the IPv6 address."
            ),
            'security_status': (
                "\n[TIP] Review this status regularly to ensure all security features are active.\n"
                "   Green checkmarks () indicate operational features."
            ),
            'system_tests': (
                "\n[TIP] Run system tests after configuration changes or before deployment.\n"
                "   All tests should pass for production use."
            ),
            'file_transfer': (
                "\n[TIP] File transfers are encrypted and integrity-verified.\n"
                "   Use the /file command in chat mode to send files."
            ),
            'chat': (
                "\n[TIP] All messages are end-to-end encrypted with forward secrecy.\n"
                "   Type /exit to leave chat, /file <path> to send a file."
            ),
            'menu': (
                "\n[TIP] Use options 3 and 4 to verify system status and run tests.\n"
                "   Option 5 performs graceful shutdown with resource cleanup."
            )
        }
        
        if context in prompts:
            print(prompts[context])
    
    def format_error_message(self, error: Exception, user_friendly: bool = True) -> str:
        """
        Format error messages in a user-friendly way.
        
        Args:
            error: Exception object
            user_friendly: If True, provide simplified message; if False, include technical details
            
        Returns:
            Formatted error message
            
        Requirements: 1.7, 14.1, 14.2
        """
        error_type = type(error).__name__
        error_msg = str(error)
        
        if user_friendly:
            # Map common errors to user-friendly messages
            friendly_messages = {
                'ConnectionRefusedError': 'Could not connect to peer. Ensure the peer is running and accepting connections.',
                'TimeoutError': 'Connection timed out. Check network connectivity and try again.',
                'FileNotFoundError': 'File not found. Please check the file path and try again.',
                'PermissionError': 'Permission denied. Try running with administrator privileges.',
                'ValueError': 'Invalid input. Please check your input and try again.',
                'KeyError': 'Configuration error. Please check your configuration file.',
                'ImportError': 'Missing dependency. Please install required packages.',
                'OSError': 'System error. Check system resources and permissions.',
            }
            
            return friendly_messages.get(error_type, f"An error occurred: {error_msg}")
        else:
            return f"{error_type}: {error_msg}"
