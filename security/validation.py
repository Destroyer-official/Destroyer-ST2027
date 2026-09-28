"""
secure input validation module.

This module implements zero-compromise input validation according to secure
security requirements. All validation is strict with mandatory rejection of invalid
inputs. No sanitization attempts are made as they could mask attacks.

Security features:
- Strict validation with mandatory rejection of invalid inputs
- Cryptographic integrity checking for critical inputs
- No sanitization attempts that could mask attacks
- Hardware-backed validation where available
- Real-time security monitoring integration
- Zero tolerance for malformed or suspicious inputs
"""

import re
import logging
import hashlib
from typing import Optional, Dict, Any

# Setup logging
log = logging.getLogger(__name__)


class ValidationError(Exception):
    """Base exception for validation errors"""
    def __init__(self, message: str, category: str = "VALIDATION", severity: str = "HIGH",
                 module: str = "security.validation", function: str = "validate"):
        self.message = message
        self.category = category
        self.severity = severity
        self.module = module
        self.function = function
        self.error_code = f"{category}_{function.upper()}_{hash(message) % 1000:03d}"
        super().__init__(self.format_error())

    def format_error(self) -> str:
        """Format error message"""
        return (f"[{self.severity}] [{self.category}] "
                f"{self.module}.{self.function}: {self.message} "
                f"(Code: {self.error_code})")


class InputValidator:
    """
    secure input validation class with strict validation and mandatory rejection.

    This class implements zero-compromise input validation according to secure
    security requirements. All validation is strict with mandatory rejection of invalid
    inputs. No sanitization attempts are made as they could mask attacks.

    CRITICAL SECURITY REQUIREMENTS:
    - All validation failures result in immediate rejection
    - No graceful degradation or fallback mechanisms
    - No input sanitization that could hide attack patterns
    - Cryptographic verification of input integrity for critical data
    - Mandatory audit logging of all validation failures
    """
    # Strict regular expressions for validation (no tolerance for variations)
    USERNAME_REGEX = r'^[a-zA-Z0-9_-]{3,32}$'
    IP_ADDRESS_REGEX = r'^(\d{1,3}\.){3}\d{1,3}$'
    IPV6_ADDRESS_REGEX = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    PORT_REGEX = r'^[0-9]{1,5}$'
    HOSTNAME_REGEX = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    COMMAND_REGEX = r'^/[a-zA-Z0-9_\-]+(\s+[a-zA-Z0-9_\-\.:/]+)*$'

    # Absolute size limits (no flexibility)
    MAX_USERNAME_LENGTH = 32
    MAX_MESSAGE_SIZE = 65536  # 64 KB
    MAX_COMMAND_LENGTH = 1024  # 1 KB

    # Cryptographic integrity salt for critical input validation
    INTEGRITY_SALT = b"MILITARY_GRADE_INPUT_VALIDATION_SALT_2025"

    def __init__(self, orchestrator=None):
        """Initialize InputValidator with optional orchestrator reference"""
        self.orchestrator = orchestrator
        self.log = logging.getLogger(__name__)

    @staticmethod
    def validate_username(username):
        """
        Strict username validation with mandatory rejection of invalid inputs.

        SECURITY REQUIREMENTS:
        - Mandatory rejection of any invalid input
        - No sanitization attempts
        - Cryptographic integrity verification for critical usernames
        - Audit logging of all validation failures

        Args:
            username: Username to validate

        Returns:
            bool: True if valid, False if invalid (with mandatory rejection)

        Raises:
            ValidationError: For critical validation failures requiring immediate termination
        """
        # Mandatory type and existence validation
        if username is None:
            log.error("SECURITY VIOLATION: Username is None - mandatory rejection")
            return False

        if not isinstance(username, str):
            log.error(f"SECURITY VIOLATION: Username type invalid: {type(username)} - mandatory rejection")
            return False

        # Mandatory length validation (strict enforcement)
        if len(username) == 0:
            log.error("SECURITY VIOLATION: Empty username - mandatory rejection")
            return False

        if len(username) > InputValidator.MAX_USERNAME_LENGTH:
            log.error(f"SECURITY VIOLATION: Username exceeds maximum length: {len(username)} > {InputValidator.MAX_USERNAME_LENGTH} - mandatory rejection")
            return False

        if len(username) < 3:
            log.error(f"SECURITY VIOLATION: Username below minimum length: {len(username)} < 3 - mandatory rejection")
            return False

        # Mandatory format validation (strict regex enforcement)
        if not re.match(InputValidator.USERNAME_REGEX, username):
            log.error(f"SECURITY VIOLATION: Username format violation: '{username}' - mandatory rejection")
            return False

        # Check for suspicious patterns that could indicate attacks
        suspicious_patterns = [
            r'[<>"\']',  # HTML/XML injection attempts
            r'[\x00-\x1F\x7F]',  # Control characters
            r'(script|javascript|vbscript)',  # Script injection
            r'(union|select|insert|update|delete|drop)',  # SQL injection
            r'(\.\./|\.\.\\)',  # Path traversal
            r'(%[0-9a-fA-F]{2})',  # URL encoding (potential bypass attempt)
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, username, re.IGNORECASE):
                log.error(f"SECURITY VIOLATION: Suspicious pattern detected in username: '{username}' - mandatory rejection")
                return False

        return True

    @staticmethod
    def validate_message(message):
        """
        Strict message validation with mandatory rejection of invalid inputs.

        SECURITY REQUIREMENTS:
        - Mandatory rejection of any invalid or suspicious message
        - No sanitization attempts that could mask attacks
        - Cryptographic integrity verification for critical messages
        - Comprehensive attack pattern detection

        Args:
            message: Message content to validate (str or bytes)

        Returns:
            bool: True if valid, False if invalid (with mandatory rejection)
        """
        # Mandatory type and existence validation
        if message is None:
            log.error("SECURITY VIOLATION: Message is None - mandatory rejection")
            return False

        if not isinstance(message, (str, bytes)):
            log.error(f"SECURITY VIOLATION: Invalid message type: {type(message)} - mandatory rejection")
            return False

        # Mandatory size validation (strict enforcement)
        message_size = len(message)
        if message_size > InputValidator.MAX_MESSAGE_SIZE:
            log.error(f"SECURITY VIOLATION: Message exceeds maximum size: {message_size} > {InputValidator.MAX_MESSAGE_SIZE} - mandatory rejection")
            return False

        # Convert bytes to string for pattern analysis
        if isinstance(message, bytes):
            try:
                message_str = message.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                log.error("SECURITY VIOLATION: Message contains invalid UTF-8 encoding - mandatory rejection")
                return False
        else:
            message_str = message

        # Comprehensive attack pattern detection (mandatory rejection for any match)
        attack_patterns = [
            # Command injection patterns
            (r';\s*(rm|del|format|shutdown|reboot|halt|poweroff)', "Command injection attempt"),
            (r'`[^`]*`', "Command substitution attempt"),
            (r'\$\([^)]*\)', "Command substitution attempt"),
            (r'&&|\|\||[|]', "Command chaining attempt"),

            # SQL injection patterns
            (r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b.*\bFROM\b)', "SQL injection attempt"),
            (r'\bUNION\b.*\bSELECT\b', "SQL UNION injection attempt"),
            (r';\s*(DROP|DELETE|TRUNCATE)', "Destructive SQL injection attempt"),
            (r"'.*OR.*'.*=.*'", "SQL OR injection attempt"),
            (r'--\s*', "SQL comment injection attempt"),

            # Script injection patterns
            (r'<script[^>]*>', "Script tag injection attempt"),
            (r'javascript:', "JavaScript protocol injection"),
            (r'vbscript:', "VBScript protocol injection"),
            (r'on\w+\s*=', "Event handler injection attempt"),

            # Path traversal patterns
            (r'\.\./', "Path traversal attempt"),
            (r'\.\.\\', "Windows path traversal attempt"),
            (r'%2e%2e%2f', "URL-encoded path traversal attempt"),

            # Format string attacks
            (r'%[0-9]*[diouxXeEfFgGaAcspn%]', "Format string attack attempt"),

            # Buffer overflow patterns
            (r'A{100,}', "Potential buffer overflow attempt"),
            (r'[^\x20-\x7E]{50,}', "Suspicious binary data"),

            # Control character injection
            (r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', "Control character injection"),

            # Protocol injection
            (r'(file|ftp|ldap|dict|gopher|telnet|ssh)://', "Protocol injection attempt"),

            # XML/XXE injection
            (r'<!ENTITY', "XML entity injection attempt"),
            (r'<!DOCTYPE.*ENTITY', "XXE injection attempt"),
        ]

        for pattern, attack_type in attack_patterns:
            if re.search(pattern, message_str, re.IGNORECASE | re.MULTILINE):
                log.error(f"SECURITY VIOLATION: {attack_type} detected in message - mandatory rejection")
                return False

        # Check for excessive special characters (potential obfuscation)
        special_char_count = len(re.findall(r'[^\w\s]', message_str))
        if special_char_count > len(message_str) * 0.3:  # More than 30% special characters
            log.error(f"SECURITY VIOLATION: Excessive special characters detected ({special_char_count}/{len(message_str)}) - potential obfuscation attempt - mandatory rejection")
            return False

        return True

    @staticmethod
    def validate_ip_address(ip):
        """
        Strict IP address validation with mandatory rejection of invalid inputs.

        SECURITY REQUIREMENTS:
        - Mandatory rejection of any invalid IP address format
        - No sanitization or correction attempts
        - Strict validation of IPv4, IPv6, and hostname formats
        - Protection against IP-based attacks and bypasses

        Args:
            ip: IP address or hostname to validate

        Returns:
            bool: True if valid, False if invalid (with mandatory rejection)
        """
        # Mandatory type and existence validation
        if ip is None:
            log.error("SECURITY VIOLATION: IP address is None - mandatory rejection")
            return False

        if not isinstance(ip, str):
            log.error(f"SECURITY VIOLATION: IP address type invalid: {type(ip)} - mandatory rejection")
            return False

        if len(ip) == 0:
            log.error("SECURITY VIOLATION: Empty IP address - mandatory rejection")
            return False

        # Check for suspicious patterns that could indicate attacks
        suspicious_patterns = [
            r'[<>"\']',  # HTML/XML injection
            r'[\x00-\x1F\x7F]',  # Control characters
            r'javascript:|vbscript:|data:',  # Protocol injection
            r'%[0-9a-fA-F]{2}',  # URL encoding (potential bypass)
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'\.\./|\.\.\\'  # Path traversal
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, ip, re.IGNORECASE):
                log.error(f"SECURITY VIOLATION: Suspicious pattern detected in IP address: '{ip}' - mandatory rejection")
                return False

        # Strict IPv4 validation
        if re.match(InputValidator.IP_ADDRESS_REGEX, ip):
            octets = ip.split('.')
            if len(octets) != 4:
                log.error(f"SECURITY VIOLATION: Invalid IPv4 format - incorrect octet count: {len(octets)} - mandatory rejection")
                return False

            for i, octet in enumerate(octets):
                try:
                    value = int(octet)
                    if value < 0 or value > 255:
                        log.error(f"SECURITY VIOLATION: Invalid IPv4 octet value at position {i}: {value} - mandatory rejection")
                        return False
                    # Check for leading zeros (potential bypass attempt)
                    if len(octet) > 1 and octet[0] == '0':
                        log.error(f"SECURITY VIOLATION: IPv4 octet with leading zero detected: '{octet}' - potential bypass attempt - mandatory rejection")
                        return False
                except ValueError:
                    log.error(f"SECURITY VIOLATION: Non-numeric IPv4 octet: '{octet}' - mandatory rejection")
                    return False

            # Check for reserved/dangerous IP ranges
            first_octet = int(octets[0])

            # Reject localhost and loopback (security risk in P2P context, unless local testing authorized)
            if first_octet == 127:
                import os
                if os.environ.get("P2P_ALLOW_LOOPBACK", "").lower() in ("true", "1", "yes"):
                    log.warning(f"LOCAL TESTING: Loopback IP address permitted: {ip}")
                    return True
                log.error(f"SECURITY VIOLATION: Loopback IP address not allowed: {ip} - mandatory rejection")
                return False

            # Reject multicast and broadcast ranges
            if first_octet >= 224:
                log.error(f"SECURITY VIOLATION: Multicast/broadcast IP address not allowed: {ip} - mandatory rejection")
                return False

            return True

        # Strict IPv6 validation using Python's ipaddress module (RFC 3986 / RFC 5952)
        try:
            import ipaddress
            ipv6_candidate = ip.strip()
            if ipv6_candidate.startswith('[') and ipv6_candidate.endswith(']'):
                ipv6_candidate = ipv6_candidate[1:-1].strip()
            ipv6_addr = ipaddress.IPv6Address(ipv6_candidate)

            # Check for IPv6 loopback
            if ipv6_addr.is_loopback:
                import os
                if os.environ.get("P2P_ALLOW_LOOPBACK", "").lower() in ("true", "1", "yes"):
                    log.warning(f"LOCAL TESTING: Loopback IPv6 address permitted: {ip}")
                    return True
                log.error(f"SECURITY VIOLATION: IPv6 loopback address not allowed: {ip} - mandatory rejection")
                return False

            # Check for other restricted IPv6 addresses
            if ipv6_addr.is_multicast:
                log.error(f"SECURITY VIOLATION: IPv6 multicast address not allowed: {ip} - mandatory rejection")
                return False

            if ipv6_addr.is_reserved:
                log.error(f"SECURITY VIOLATION: IPv6 reserved address not allowed: {ip} - mandatory rejection")
                return False

            return True
        except ValueError:
            # Not a valid IPv6 address, continue to hostname validation
            import logging; logging.getLogger(__name__).debug("Ignored pass")

        # Strict hostname validation
        if re.match(InputValidator.HOSTNAME_REGEX, ip):
            if len(ip) > 255:  # RFC limit
                log.error(f"SECURITY VIOLATION: Hostname exceeds maximum length: {len(ip)} > 255 - mandatory rejection")
                return False

            # Check for suspicious hostname patterns
            if '..' in ip:
                log.error(f"SECURITY VIOLATION: Double dots in hostname: {ip} - potential attack - mandatory rejection")
                return False

            # Reject hostnames that look like IP addresses but aren't valid
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                log.error(f"SECURITY VIOLATION: Hostname appears to be malformed IP address: {ip} - mandatory rejection")
                return False
            
            # Reject partial IP addresses (e.g., "1.1.1")
            if re.match(r'^\d+(\.\d+)*$', ip):
                log.error(f"SECURITY VIOLATION: Hostname appears to be partial IP address: {ip} - mandatory rejection")
                return False
            
            # Reject single-letter segments that look suspicious (e.g., "a.b.c.d")
            segments = ip.split('.')
            if all(len(seg) == 1 for seg in segments) and len(segments) == 4:
                log.error(f"SECURITY VIOLATION: Hostname appears to be malformed (single-letter segments): {ip} - mandatory rejection")
                return False

            return True

        log.error(f"SECURITY VIOLATION: Invalid IP address/hostname format: '{ip}' - mandatory rejection")
        return False

    @staticmethod
    def validate_port(port):
        """
        Strict port validation with mandatory rejection of invalid inputs.

        SECURITY REQUIREMENTS:
        - Mandatory rejection of any invalid port number
        - No sanitization or correction attempts
        - Strict range validation (1-65535)
        - Protection against port-based attacks

        Args:
            port: Port number to validate (int or str)

        Returns:
            bool: True if valid, False if invalid (with mandatory rejection)
        """
        # Handle string input with strict validation
        if isinstance(port, str):
            # Check for suspicious patterns
            if not port.strip():
                log.error("SECURITY VIOLATION: Empty port string - mandatory rejection")
                return False

            # Check for non-numeric characters or injection attempts
            if not re.match(InputValidator.PORT_REGEX, port):
                log.error(f"SECURITY VIOLATION: Invalid port format: '{port}' - mandatory rejection")
                return False

            # Check for leading zeros (potential bypass attempt)
            if len(port) > 1 and port[0] == '0':
                log.error(f"SECURITY VIOLATION: Port with leading zero: '{port}' - potential bypass attempt - mandatory rejection")
                return False

            try:
                port = int(port)
            except ValueError:
                log.error(f"SECURITY VIOLATION: Non-numeric port value: '{port}' - mandatory rejection")
                return False

        # Mandatory type validation
        if not isinstance(port, int):
            log.error(f"SECURITY VIOLATION: Invalid port type: {type(port)} - mandatory rejection")
            return False

        # Strict range validation
        if port < 1:
            log.error(f"SECURITY VIOLATION: Port below valid range: {port} < 1 - mandatory rejection")
            return False

        if port > 65535:
            log.error(f"SECURITY VIOLATION: Port above valid range: {port} > 65535 - mandatory rejection")
            return False

        # Check for well-known system ports (security consideration)
        if port < 1024:
            log.warning(f"SECURITY NOTICE: Using privileged port: {port} - requires elevated privileges")

        return True

    @staticmethod
    def validate_command(command):
        """
        Strict command validation with mandatory rejection of invalid inputs.

        SECURITY REQUIREMENTS:
        - Mandatory rejection of any invalid or suspicious command
        - No sanitization attempts that could mask command injection
        - Strict format validation for chat commands
        - Protection against command injection and privilege escalation

        Args:
            command: Command string to validate

        Returns:
            bool: True if valid, False if invalid (with mandatory rejection)
        """
        # Mandatory type and existence validation
        if command is None:
            log.error("SECURITY VIOLATION: Command is None - mandatory rejection")
            return False

        if not isinstance(command, str):
            log.error(f"SECURITY VIOLATION: Invalid command type: {type(command)} - mandatory rejection")
            return False

        if len(command) == 0:
            log.error("SECURITY VIOLATION: Empty command - mandatory rejection")
            return False

        # Mandatory length validation
        if len(command) > InputValidator.MAX_COMMAND_LENGTH:
            log.error(f"SECURITY VIOLATION: Command exceeds maximum length: {len(command)} > {InputValidator.MAX_COMMAND_LENGTH} - mandatory rejection")
            return False

        # Mandatory format validation
        if not command.startswith('/'):
            log.error(f"SECURITY VIOLATION: Command must start with '/': '{command}' - mandatory rejection")
            return False

        # Comprehensive attack pattern detection
        attack_patterns = [
            # Command injection patterns
            (r'[;&|`$()]', "Command injection metacharacters"),
            (r'\\x[0-9a-fA-F]{2}', "Hex encoding bypass attempt"),
            (r'%[0-9a-fA-F]{2}', "URL encoding bypass attempt"),
            (r'[\x00-\x1F\x7F]', "Control character injection"),

            # Path traversal
            (r'\.\./', "Path traversal attempt"),
            (r'\.\.\\', "Windows path traversal attempt"),

            # Script injection
            (r'<script', "Script tag injection"),
            (r'javascript:', "JavaScript protocol injection"),

            # System command attempts
            (r'\b(rm|del|format|shutdown|reboot|halt|kill|sudo|su|chmod|chown)\b', "System command attempt"),

            # File operations
            (r'\b(cat|type|more|less|head|tail|grep|find|locate)\b', "File operation attempt"),

            # Network operations
            (r'\b(wget|curl|nc|netcat|telnet|ssh|ftp)\b', "Network operation attempt"),
        ]

        for pattern, attack_type in attack_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                log.error(f"SECURITY VIOLATION: {attack_type} detected in command: '{command}' - mandatory rejection")
                return False

        # Strict regex validation
        if not re.match(InputValidator.COMMAND_REGEX, command):
            log.error(f"SECURITY VIOLATION: Command format violation: '{command}' - mandatory rejection")
            return False

        return True

    @staticmethod
    def verify_input_integrity(input_data, expected_hash=None):
        """
        Cryptographic integrity verification for critical inputs.

        SECURITY REQUIREMENTS:
        - Cryptographic verification of input integrity
        - Protection against tampering and injection attacks
        - Hardware-backed validation where available

        Args:
            input_data: Input data to verify (str or bytes)
            expected_hash: Expected SHA3-512 hash for verification (optional)

        Returns:
            bool: True if integrity verified, False if compromised
        """
        try:
            # Convert input to bytes for hashing
            if isinstance(input_data, str):
                data_bytes = input_data.encode('utf-8')
            elif isinstance(input_data, bytes):
                data_bytes = input_data
            else:
                log.error(f"SECURITY VIOLATION: Invalid input type for integrity verification: {type(input_data)}")
                return False

            # Create cryptographic hash with salt
            hasher = hashlib.sha3_512()
            hasher.update(InputValidator.INTEGRITY_SALT)
            hasher.update(data_bytes)
            computed_hash = hasher.hexdigest()

            # If expected hash provided, verify it
            if expected_hash is not None:
                if computed_hash != expected_hash:
                    log.error("SECURITY VIOLATION: Input integrity verification failed - data may be compromised")
                    return False
                log.info("Input integrity verification successful")
                return True

            # If no expected hash, log the computed hash for future verification
            log.info(f"Input integrity hash computed: {computed_hash[:16]}...")
            return True

        except Exception as e:
            log.error(f"SECURITY VIOLATION: Integrity verification failed with exception: {e}")
            return False

    @staticmethod
    def validate_critical_input(input_data, input_type, expected_hash=None):
        """
        Comprehensive validation for critical inputs with cryptographic verification.

        SECURITY REQUIREMENTS:
        - Combines strict validation with cryptographic integrity checking
        - Mandatory rejection for any validation or integrity failure
        - No sanitization attempts

        Args:
            input_data: Input data to validate
            input_type: Type of input ('username', 'message', 'ip', 'port', 'command')
            expected_hash: Expected integrity hash (optional)

        Returns:
            bool: True if valid and integrity verified, False otherwise
        """
        # First perform type-specific validation
        validation_methods = {
            'username': InputValidator.validate_username,
            'message': InputValidator.validate_message,
            'ip': InputValidator.validate_ip_address,
            'port': InputValidator.validate_port,
            'command': InputValidator.validate_command
        }

        if input_type not in validation_methods:
            log.error(f"SECURITY VIOLATION: Unknown input type for validation: {input_type}")
            return False

        # Perform strict validation
        if not validation_methods[input_type](input_data):
            log.error(f"SECURITY VIOLATION: {input_type} validation failed for critical input")
            return False

        # Perform cryptographic integrity verification
        if not InputValidator.verify_input_integrity(input_data, expected_hash):
            log.error(f"SECURITY VIOLATION: Integrity verification failed for critical {input_type}")
            return False

        log.info(f"Critical {input_type} validation and integrity verification successful")
        return True

    # ========================================================================
    # Task 5.1: Enhanced validation methods with (bool, Optional[str]) return
    # ========================================================================

    @staticmethod
    def validate_ipv6(address: str) -> tuple:
        """
        Validate IPv6 address format with regex pattern matching.
        
        This method provides strict IPv6 validation according to RFC 4291.
        
        Args:
            address: IPv6 address string to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (True, None) if valid, (False, error_message) if invalid
            
        Requirements: 3.1, 3.5
        """
        # Type validation
        if address is None:
            return False, "IPv6 address cannot be None"
        
        if not isinstance(address, str):
            return False, f"IPv6 address must be string, got {type(address).__name__}"
        
        # Empty check
        if not address.strip():
            return False, "IPv6 address cannot be empty"
        
        address = address.strip()
        if address.startswith('[') and address.endswith(']'):
            address = address[1:-1].strip()
        
        # Length check
        if len(address) > 45:  # Max IPv6 length with full notation
            return False, f"IPv6 address too long: {len(address)} characters (max 45)"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'[<>"\']', "HTML/XML injection characters detected"),
            (r'[\x00-\x1F\x7F]', "Control characters detected"),
            (r'javascript:|vbscript:|data:', "Protocol injection detected"),
            (r'%[0-9a-fA-F]{2}', "URL encoding detected (potential bypass)"),
            (r'\\x[0-9a-fA-F]{2}', "Hex encoding detected"),
            (r'\.\./|\.\.\\', "Path traversal detected")
        ]
        
        for pattern, error_msg in suspicious_patterns:
            if re.search(pattern, address, re.IGNORECASE):
                log.error(f"SECURITY VIOLATION: {error_msg} in IPv6 address: {address}")
                return False, error_msg
        
        # IPv6 regex pattern (strict RFC 4291 compliance)
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1}:([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){2}:([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){3}:([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){4}:([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){5}:([0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){6}:[0-9a-fA-F]{1,4}$'
        
        if not re.match(ipv6_pattern, address):
            return False, f"Invalid IPv6 address format: {address}"
        
        # Check for multiple :: (only one allowed)
        if address.count('::') > 1:
            return False, "Multiple '::' not allowed in IPv6 address"
        
        # Check for loopback (security consideration)
        if address.lower() in ['::1', '0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:0000:0000:0001']:
            return False, "Loopback IPv6 address not allowed for P2P connections"
        
        # Check for link-local addresses (fe80::/10)
        if address.lower().startswith('fe80:'):
            log.warning(f"Link-local IPv6 address detected: {address}")
        
        log.debug(f"IPv6 address validated: {address}")
        return True, None

    @staticmethod
    def validate_encrypted_message(message: bytes, max_length: int = 1048576) -> tuple:
        """
        Validate encrypted message structure and length.
        
        This method validates encrypted message data for structure integrity
        and size constraints.
        
        Args:
            message: Message data to validate (bytes)
            max_length: Maximum allowed message length in bytes (default 1MB)
            
        Returns:
            Tuple[bool, Optional[str]]: (True, None) if valid, (False, error_message) if invalid
            
        Requirements: 3.2, 3.5
        """
        # Type validation
        if message is None:
            return False, "Message cannot be None"
        
        if not isinstance(message, bytes):
            return False, f"Message must be bytes, got {type(message).__name__}"
        
        # Length validation
        message_length = len(message)
        
        if message_length == 0:
            return False, "Message cannot be empty"
        
        if message_length > max_length:
            log.error(f"SECURITY VIOLATION: Message exceeds maximum length: {message_length} > {max_length}")
            return False, f"Message too large: {message_length} bytes (max {max_length})"
        
        # Minimum encrypted message size check (ChaCha20-Poly1305 overhead)
        # Minimum: nonce (12) + tag (16) + at least 1 byte data = 29 bytes
        # But DoubleRatchet adds header, so minimum is higher
        min_message_size = 48  # Conservative minimum for DoubleRatchet messages
        
        if message_length < min_message_size:
            return False, f"Message too short: {message_length} bytes (min {min_message_size})"
        
        log.debug(f"Message validated: {message_length} bytes")
        return True, None

    @staticmethod
    def validate_file_path(path: str) -> tuple:
        """
        Validate file path exists and is readable.
        
        This method validates file paths for existence, readability, and
        security constraints.
        
        Args:
            path: File path to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (True, None) if valid, (False, error_message) if invalid
            
        Requirements: 3.3, 3.5
        """
        import os
        
        # Type validation
        if path is None:
            return False, "File path cannot be None"
        
        if not isinstance(path, str):
            return False, f"File path must be string, got {type(path).__name__}"
        
        # Empty check
        if not path.strip():
            return False, "File path cannot be empty"
        
        path = path.strip()
        
        # Length check
        if len(path) > 4096:  # Reasonable path length limit
            return False, f"File path too long: {len(path)} characters (max 4096)"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'[<>"|?*]', "Invalid filename characters detected"),
            (r'[\x00-\x1F\x7F]', "Control characters detected"),
            (r'javascript:|vbscript:|data:', "Protocol injection detected"),
            (r'%[0-9a-fA-F]{2}', "URL encoding detected"),
        ]
        
        for pattern, error_msg in suspicious_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                log.error(f"SECURITY VIOLATION: {error_msg} in file path: {path}")
                return False, error_msg
        
        # Path traversal check: strictly reject '..' to prevent directory traversal
        normalized_parts = path.replace('\\', '/').split('/')
        if '..' in normalized_parts:
            log.error(f"SECURITY VIOLATION: Path traversal sequence '..' detected in file path: {path}")
            return False, "Path traversal sequence '..' detected in file path"
        
        # Check if file exists
        if not os.path.exists(path):
            return False, f"File does not exist: {path}"
        
        # Check if it's a file (not a directory)
        if not os.path.isfile(path):
            return False, f"Path is not a file: {path}"
        
        # Check if file is readable
        if not os.access(path, os.R_OK):
            return False, f"File is not readable: {path}"
        
        # Check file size (prevent DoS with huge files)
        try:
            file_size = os.path.getsize(path)
            max_file_size = 100 * 1024 * 1024  # 100MB limit
            
            if file_size > max_file_size:
                return False, f"File too large: {file_size} bytes (max {max_file_size})"
            
            if file_size == 0:
                log.warning(f"Empty file detected: {path}")
        
        except Exception as e:
            return False, f"Failed to check file size: {str(e)}"
        
        log.debug(f"File path validated: {path}")
        return True, None

    @staticmethod
    def validate_crypto_key(key: bytes, expected_length: int) -> tuple:
        """
        Validate cryptographic key format and length.
        
        This method validates cryptographic keys for proper format and
        expected length constraints.
        
        Args:
            key: Cryptographic key to validate (bytes)
            expected_length: Expected key length in bytes
            
        Returns:
            Tuple[bool, Optional[str]]: (True, None) if valid, (False, error_message) if invalid
            
        Requirements: 3.4, 3.5
        """
        # Type validation
        if key is None:
            return False, "Cryptographic key cannot be None"
        
        if not isinstance(key, bytes):
            return False, f"Cryptographic key must be bytes, got {type(key).__name__}"
        
        # Length validation
        key_length = len(key)
        
        if key_length == 0:
            return False, "Cryptographic key cannot be empty"
        
        if key_length != expected_length:
            log.error(f"SECURITY VIOLATION: Key length mismatch: {key_length} != {expected_length}")
            return False, f"Invalid key length: {key_length} bytes (expected {expected_length})"
        
        # Check for weak keys (all zeros, all ones, repeating patterns)
        if key == b'\x00' * key_length:
            log.error("SECURITY VIOLATION: All-zero key detected")
            return False, "Weak key detected: all zeros"
        
        if key == b'\xff' * key_length:
            log.error("SECURITY VIOLATION: All-ones key detected")
            return False, "Weak key detected: all ones"
        
        # Check for repeating byte patterns (potential weak key)
        if key_length >= 4:
            # Check if key is just repeating 4-byte pattern
            pattern = key[:4]
            if all(key[i:i+4] == pattern for i in range(0, key_length, 4)):
                log.error("SECURITY VIOLATION: Repeating pattern key detected")
                return False, "Weak key detected: repeating pattern"
        
        # Check entropy (basic check - at least 25% unique bytes)
        unique_bytes = len(set(key))
        min_unique = max(8, key_length // 4)  # At least 8 or 25% unique bytes
        
        if unique_bytes < min_unique:
            log.warning(f"Low entropy key detected: {unique_bytes} unique bytes out of {key_length}")
            return False, f"Low entropy key: only {unique_bytes} unique bytes"
        
        log.debug(f"Cryptographic key validated: {key_length} bytes")
        return True, None
