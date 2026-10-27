"""
User feedback operations.

Provides progress indicators, status messages, and enhanced error messages
for better user experience.

Requirements: 1.7, 14.1, 14.2, 14.3, 14.4
"""

import sys
import time
import asyncio
import logging
from typing import Optional, List
try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule

log = logging.getLogger(__name__)


class FeedbackManager(BaseModule):
    """User feedback operations for progress and status display."""
    
    def __init__(self, orchestrator):
        """Initialize feedback manager."""
        super().__init__(orchestrator)
        self._spinner_task = None
        self._progress_bar_active = False
    
    def show_progress_bar(self, current: int, total: int, prefix: str = '', 
                         suffix: str = '', length: int = 50, fill: str = '#') -> None:
        """
        Display a progress bar.
        
        Args:
            current: Current progress value
            total: Total value for 100% completion
            prefix: Prefix string before progress bar
            suffix: Suffix string after progress bar
            length: Length of progress bar in characters
            fill: Character to use for filled portion
            
        Requirements: 14.4 (display progress indicators)
        """
        try:
            percent = 100 * (current / float(total))
            filled_length = int(length * current // total)
            bar = fill * filled_length + '-' * (length - filled_length)
            
            # Use \r to overwrite the same line
            sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}')
            sys.stdout.flush()
            
            # Print newline when complete
            if current == total:
                print()
                
        except Exception as e:
            log.error(f"Error showing progress bar: {e}", exc_info=True)
    
    async def show_spinner(self, message: str, duration: Optional[float] = None) -> None:
        """
        Display an animated spinner with message.
        
        Args:
            message: Message to display with spinner
            duration: Optional duration in seconds (None = indefinite)
            
        Requirements: 14.4 (display progress indicators)
        """
        try:
            spinner_chars = ['|', '/', '-', '\\']
            idx = 0
            start_time = time.time()
            
            while True:
                # Check if duration exceeded
                if duration and (time.time() - start_time) > duration:
                    break
                
                # Display spinner
                sys.stdout.write(f'\r{spinner_chars[idx]} {message}')
                sys.stdout.flush()
                
                idx = (idx + 1) % len(spinner_chars)
                await asyncio.sleep(0.1)
            
            # Clear spinner line
            sys.stdout.write('\r' + ' ' * (len(message) + 3) + '\r')
            sys.stdout.flush()
            
        except Exception as e:
            log.error(f"Error showing spinner: {e}", exc_info=True)
    
    def show_success(self, message: str) -> None:
        """
        Display a success message with checkmark.
        
        Args:
            message: Success message to display
            
        Requirements: 1.7 (clear prompts and feedback)
        """
        print(f" {message}")
    
    def show_error(self, message: str, details: Optional[str] = None) -> None:
        """
        Display an error message with details.
        
        Args:
            message: Error message to display
            details: Optional detailed error information
            
        Requirements: 1.7 (clear prompts and feedback)
        """
        print(f"[FAIL] {message}")
        if details:
            print(f"   Details: {details}")
    
    def show_warning(self, message: str) -> None:
        """
        Display a warning message.
        
        Args:
            message: Warning message to display
            
        Requirements: 1.7 (clear prompts and feedback)
        """
        print(f"[WARNING]  {message}")
    
    def show_info(self, message: str) -> None:
        """
        Display an informational message.
        
        Args:
            message: Info message to display
            
        Requirements: 1.7 (clear prompts and feedback)
        """
        print(f"[INFO] {message}")
    
    def show_status(self, message: str, status: str = "info") -> None:
        """
        Display a status message with appropriate icon.
        
        Args:
            message: Status message to display
            status: Status type ('success', 'error', 'warning', 'info')
            
        Requirements: 14.1, 14.2 (system responds within 1 second)
        """
        icons = {
            'success': '',
            'error': '[FAIL]',
            'warning': '[WARNING] ',
            'info': '[INFO] ',
            'loading': '[BUSY]',
            'complete': '[OK] '
        }
        icon = icons.get(status, '[INFO] ')
        print(f"{icon} {message}")
    
    def show_operation_start(self, operation: str) -> None:
        """
        Display operation start message.
        
        Args:
            operation: Name of operation starting
            
        Requirements: 14.1 (respond within 1 second)
        """
        print(f"\n {operation}...")
    
    def show_operation_complete(self, operation: str, duration: Optional[float] = None) -> None:
        """
        Display operation completion message.
        
        Args:
            operation: Name of operation completed
            duration: Optional duration in seconds
            
        Requirements: 14.1 (respond within 1 second)
        """
        if duration:
            print(f" {operation} complete ({duration:.2f}s)")
        else:
            print(f" {operation} complete")
    
    def show_connection_status(self, peer: str, status: str, details: Optional[str] = None) -> None:
        """
        Display connection status message.
        
        Args:
            peer: Peer identifier
            status: Connection status ('connecting', 'connected', 'disconnected', 'failed')
            details: Optional additional details
            
        Requirements: 14.1, 14.2 (responsive feedback)
        """
        status_messages = {
            'connecting': f"[CONNECTING] Connecting to {peer}...",
            'connected': f" Connected to {peer}",
            'disconnected': f"[DISCONNECTED] Disconnected from {peer}",
            'failed': f"[FAIL] Connection to {peer} failed"
        }
        
        message = status_messages.get(status, f"Status: {status} - {peer}")
        print(message)
        
        if details:
            print(f"   {details}")
    
    def show_handshake_progress(self, step: str) -> None:
        """
        Display handshake progress.
        
        Args:
            step: Current handshake step
            
        Requirements: 14.4 (progress indicators)
        """
        steps = {
            'init': '[KEY] Initiating handshake...',
            'kem': '[SECURE] Performing quantum-resistant key exchange...',
            'sign': '[KEY] Verifying digital signatures...',
            'derive': '[KEY] Deriving session keys...',
            'complete': ' Handshake complete - encrypted session established'
        }
        
        message = steps.get(step, f"[KEY] {step}")
        print(message)
    
    def show_file_transfer_progress(self, filename: str, current: int, total: int, 
                                   speed: Optional[float] = None) -> None:
        """
        Display file transfer progress.
        
        Args:
            filename: Name of file being transferred
            current: Current bytes transferred
            total: Total file size in bytes
            speed: Optional transfer speed in bytes/second
            
        Requirements: 14.4 (progress indicators for long operations)
        """
        try:
            # Calculate progress
            percent = 100 * (current / float(total))
            
            # Format sizes
            current_mb = current / (1024 * 1024)
            total_mb = total / (1024 * 1024)
            
            # Format speed
            speed_str = ""
            if speed:
                speed_mb = speed / (1024 * 1024)
                speed_str = f" - {speed_mb:.2f} MB/s"
            
            # Show progress bar
            length = 40
            filled_length = int(length * current // total)
            bar = '#' * filled_length + '-' * (length - filled_length)
            
            sys.stdout.write(
                f'\r[TRANSFER] {filename}: |{bar}| {percent:.1f}% '
                f'({current_mb:.2f}/{total_mb:.2f} MB){speed_str}'
            )
            sys.stdout.flush()
            
            if current == total:
                print()  # Newline when complete
                
        except Exception as e:
            log.error(f"Error showing file transfer progress: {e}", exc_info=True)
    
    def show_helpful_prompt(self, context: str) -> None:
        """
        Display context-sensitive helpful prompts.
        
        Args:
            context: Context for which to show help
            
        Requirements: 1.7 (helpful prompts)
        """
        prompts = {
            'menu': "\n[TIP] Enter a number (1-5) to select an option",
            'connect': "\n[TIP] You can connect by username or IP address",
            'chat': "\n[TIP] Type /exit to leave chat, /file <path> to send a file",
            'server': "\n[TIP] Share your address with peers so they can connect",
            'error': "\n[TIP] Check logs/ directory for detailed error information",
            'security': "\n[TIP] All connections use quantum-resistant encryption",
            'file': "\n[TIP] Large files are sent in chunks with integrity verification"
        }
        
        prompt = prompts.get(context, "")
        if prompt:
            print(prompt)
    
    def show_enhanced_error(self, error_type: str, error: Exception, 
                           context: Optional[str] = None) -> None:
        """
        Display enhanced error message with troubleshooting guidance.
        
        Args:
            error_type: Type of error ('connection', 'handshake', 'crypto', 'file', 'network')
            error: The exception that occurred
            context: Optional context information
            
        Requirements: 1.7 (improve error messages)
        """
        print(f"\n[FAIL] {error_type.upper()} ERROR")
        print(f"   {str(error)}")
        
        if context:
            print(f"   Context: {context}")
        
        # Provide troubleshooting guidance
        guidance = self._get_error_guidance(error_type, error)
        if guidance:
            print(f"\n[TIP] Troubleshooting:")
            for tip in guidance:
                print(f"   * {tip}")
        
        print(f"\n[LOG] For more details, check: logs/secure_p2p.log")
    
    def _get_error_guidance(self, error_type: str, error: Exception) -> List[str]:
        """
        Get troubleshooting guidance for error type.
        
        Args:
            error_type: Type of error
            error: The exception
            
        Returns:
            List of troubleshooting tips
        """
        guidance = {
            'connection': [
                "Verify the peer is running and listening for connections",
                "Check that the IP address and port are correct",
                "Ensure your firewall allows Python network connections",
                "Try connecting to localhost (::1) for testing"
            ],
            'handshake': [
                "Ensure both peers are using the same version",
                "Verify cryptographic libraries are installed (liboqs, libsodium)",
                "Check that system time is synchronized",
                "Review security logs for specific handshake errors"
            ],
            'crypto': [
                "Verify liboqs-python is installed: pip install liboqs-python",
                "Check that oqs.dll and libsodium.dll are present",
                "Ensure cryptographic algorithms are configured correctly",
                "Try running as Administrator for hardware security access"
            ],
            'file': [
                "Verify the file exists and is readable",
                "Check available disk space",
                "Ensure file path does not contain invalid characters",
                "Try with a smaller file first to test"
            ],
            'network': [
                "Check network connectivity",
                "Verify IPv6 is enabled on your system",
                "Test with ping -6 <address>",
                "Check router/firewall IPv6 settings"
            ]
        }
        
        return guidance.get(error_type, [
            "Check logs/secure_p2p.log for detailed error information",
            "Run system tests (option 4) to diagnose issues",
            "View security status (option 3) for configuration"
        ])
    
    def show_table(self, headers: List[str], rows: List[List[str]], title: Optional[str] = None) -> None:
        """
        Display data in a formatted table.
        
        Args:
            headers: Column headers
            rows: List of rows (each row is a list of values)
            title: Optional table title
            
        Requirements: 14.2 (display menu options immediately)
        """
        try:
            if title:
                print(f"\n{title}")
                print("=" * len(title))
            
            # Calculate column widths
            col_widths = [len(h) for h in headers]
            for row in rows:
                for i, cell in enumerate(row):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
            
            # Print header
            header_row = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
            print(header_row)
            print("-" * len(header_row))
            
            # Print rows
            for row in rows:
                row_str = " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
                print(row_str)
            
            print()
            
        except Exception as e:
            log.error(f"Error showing table: {e}", exc_info=True)
    
    async def show_countdown(self, seconds: int, message: str = "Starting in") -> None:
        """
        Display a countdown timer.
        
        Args:
            seconds: Number of seconds to count down
            message: Message to display with countdown
            
        Requirements: 14.4 (progress indicators)
        """
        try:
            for i in range(seconds, 0, -1):
                sys.stdout.write(f'\r{message} {i}s...')
                sys.stdout.flush()
                await asyncio.sleep(1)
            
            sys.stdout.write('\r' + ' ' * (len(message) + 10) + '\r')
            sys.stdout.flush()
            
        except Exception as e:
            log.error(f"Error showing countdown: {e}", exc_info=True)
    
    def clear_line(self) -> None:
        """Clear the current line."""
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()
    
    def show_separator(self, char: str = '=', length: int = 70) -> None:
        """
        Display a separator line.
        
        Args:
            char: Character to use for separator
            length: Length of separator line
        """
        print(char * length)
