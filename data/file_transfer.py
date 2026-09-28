"""
File transfer operations.

Provides secure file transfer functionality with chunking, integrity verification,
and progress tracking.
"""

import os
import asyncio
import base64
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

try:
    from ..base import BaseModule, FileTransferError
except (ImportError, ValueError):
    from base import BaseModule, FileTransferError

# Import file transfer components
try:
    from secure_file_sharing import (
        FileMessage,
        FileMessageType,
        FileTransferStatus,
        SecureFileHandler,
        SecureFileTransferManager
    )
    FILE_SHARING_AVAILABLE = True
except ImportError:
    FILE_SHARING_AVAILABLE = False
    FileMessage = None
    FileMessageType = None
    FileTransferStatus = None
    SecureFileHandler = None
    SecureFileTransferManager = None

# Import audit logging
try:
    from audit_logging_system import log_event, AuditEventType, AuditSeverity
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    def log_event(*args, **kwargs):
        logging.getLogger("file_transfer").debug(f"Audit event fallback: {args}")
    class AuditEventType:
        DATA_EXPORT = "DATA_EXPORT"
        DATA_IMPORT = "DATA_IMPORT"
        SECURITY_VIOLATION = "SECURITY_VIOLATION"
        MESSAGE_RECEIVED = "MESSAGE_RECEIVED"
    class AuditSeverity:
        INFO = "INFO"
        MEDIUM = "MEDIUM"
        HIGH = "HIGH"

# Color codes for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'


class FileTransferManager(BaseModule):
    """
    File transfer operations with secure chunking and integrity verification.
    
    Provides comprehensive file transfer capabilities including:
    - Secure file chunking and reassembly
    - Integrity verification with checksums
    - Progress tracking and status updates
    - Error handling and recovery
    - Audit logging for all file operations
    """
    
    def __init__(self, orchestrator=None):
        """Initialize the file transfer manager."""
        super().__init__(orchestrator)
        
        # Initialize file transfer components if available
        if FILE_SHARING_AVAILABLE:
            self.file_handler = SecureFileHandler()
            self.file_transfer_manager = SecureFileTransferManager()
            self.log.info("File transfer components initialized")
        else:
            self.file_handler = None
            self.file_transfer_manager = None
            self.log.warning("File transfer components not available")
        
        # Active file transfers tracking
        self.active_file_transfers: Dict[str, Dict] = {}

    async def send_file(self, file_path: str) -> bool:
        """
        Send a file to the connected peer.
        
        Args:
            file_path: Path to the file to send
            
        Returns:
            True if file offer was sent successfully, False otherwise
            
        Requirements: 3.3, 3.5
        """
        try:
            if not FILE_SHARING_AVAILABLE:
                self.log.error("File sharing not available")
                print(f"{RED}File sharing functionality not available{RESET}")
                return False
            
            # Check if connected to peer
            if not self.orchestrator or not getattr(self.orchestrator, 'is_connected', False):
                self.log.error("Cannot send file: not connected to a peer")
                print(f"{RED}Cannot send file: not connected to a peer{RESET}")
                return False

            # Task 5.4: Validate file path before transfer.
            # Live validator first (scanned, maintained, strict: rejects
            # '..'); legacy snapshot only as fallback. Fixed 2026-09-24:
            # validation must not depend solely on unscanned code.
            try:
                from security.validation import InputValidator
            except ImportError:
                from secure_p2p_core.security.validation import InputValidator

            is_valid, error_msg = InputValidator.validate_file_path(file_path)
            if not is_valid:
                self.log.error(f"File path validation failed: {error_msg}")
                print(f"{RED}Invalid file path: {error_msg}{RESET}")
                return False
            
            self.log.info(f"File path validated: {file_path}")

            file_path = Path(file_path)
            if not file_path.exists():
                self.log.error(f"File not found: {file_path}")
                print(f"{RED}File not found: {file_path}{RESET}")
                return False

            # Validate file security
            is_safe, mime_type, warnings = self.file_transfer_manager.validate_file_security(file_path)
            if not is_safe:
                self.log.warning(f"File rejected for security reasons: {file_path}")
                print(f"{RED}File rejected for security reasons:{RESET}")
                for warning in warnings:
                    print(f"  - {warning}")
                return False

            if warnings:
                print(f"{YELLOW}Security warnings:{RESET}")
                for warning in warnings:
                    print(f"  - {warning}")

            # Create file metadata
            local_username = getattr(self.orchestrator, 'local_username', 'unknown')
            metadata = self.file_handler.create_file_metadata(file_path, local_username)

            # Create file offer message
            offer_message = FileMessage(FileMessageType.FILE_OFFER, metadata=metadata)

            # Store the outgoing transfer
            self.active_file_transfers[metadata.file_id] = {
                'type': 'outgoing_offer',
                'metadata': metadata,
                'file_path': str(file_path),
                'status': FileTransferStatus.PENDING,
                'created_at': datetime.now()
            }

            # Send the offer
            success = await self._send_file_message(offer_message)

            if success:
                self.log.info(f"File offer sent: {file_path.name}")
                print(f"{GREEN}[SEND] File offer sent: {file_path.name} ({metadata.file_size:,} bytes){RESET}")

                # Log the file offer
                if AUDIT_AVAILABLE:
                    log_event(
                        AuditEventType.DATA_EXPORT,
                        f"File offer sent: {file_path.name}",
                        AuditSeverity.INFO,
                        {
                            'file_id': metadata.file_id,
                            'filename': file_path.name,
                            'file_size': metadata.file_size,
                            'file_type': metadata.file_type,
                            'peer': getattr(self.orchestrator, 'peer_username', 'unknown')
                        }
                    )

                return True
            else:
                # Clean up failed transfer
                del self.active_file_transfers[metadata.file_id]
                self.log.error("Failed to send file offer")
                print(f"{RED}Failed to send file offer{RESET}")
                return False

        except Exception as e:
            self.log.error(f"Error sending file: {e}", exc_info=True)
            print(f"{RED}Error sending file: {str(e)}{RESET}")
            raise FileTransferError(
                f"Failed to send file: {e}",
                severity="HIGH",
                module="data.file_transfer",
                function="send_file"
            )

    async def receive_file(self, file_id: str) -> bool:
        """
        Accept and receive a file from peer.
        
        Args:
            file_id: File transfer ID
            
        Returns:
            True if file acceptance was sent successfully, False otherwise
        """
        try:
            if file_id not in self.active_file_transfers:
                self.log.error(f"Unknown file transfer: {file_id}")
                return False

            transfer = self.active_file_transfers[file_id]
            if transfer['type'] != 'incoming_offer':
                self.log.error(f"Invalid transfer type for receive: {transfer['type']}")
                return False

            # Update status
            transfer['status'] = FileTransferStatus.ACCEPTED
            
            # Send acceptance message
            accept_message = FileMessage(FileMessageType.FILE_ACCEPT, file_id=file_id)
            success = await self._send_file_message(accept_message)

            if success:
                self.log.info(f"File acceptance sent: {transfer['metadata'].filename}")
                print(f"{GREEN}[OK] Accepting file: {transfer['metadata'].filename}{RESET}")
                return True
            else:
                self.log.error("Failed to send file acceptance")
                return False

        except Exception as e:
            self.log.error(f"Error receiving file: {e}", exc_info=True)
            raise FileTransferError(
                f"Failed to receive file: {e}",
                severity="MEDIUM",
                module="data.file_transfer",
                function="receive_file"
            )

    async def handle_file_message(self, file_message_data: str) -> None:
        """
        Handle file sharing messages from peers.
        
        Args:
            file_message_data: The decrypted file message data starting with 'FILE:'
        """
        try:
            # Parse the file message format: FILE:<base64_encoded_file_message>
            if not file_message_data.startswith('FILE:'):
                self.log.warning(f"Invalid file message format: {file_message_data[:50]}...")
                return

            # Extract and decode the file message
            encoded_data = file_message_data[5:]  # Remove 'FILE:' prefix
            try:
                file_message_bytes = base64.b64decode(encoded_data)
                file_message = FileMessage.from_bytes(file_message_bytes)
            except Exception as e:
                self.log.error(f"Failed to decode file message: {e}")
                return

            # Log the file message event
            if AUDIT_AVAILABLE:
                log_event(
                    AuditEventType.MESSAGE_RECEIVED,
                    f"File message received: {file_message.message_type.name}",
                    AuditSeverity.INFO,
                    {
                        'message_type': file_message.message_type.name,
                        'peer': getattr(self.orchestrator, 'peer_username', 'unknown'),
                        'timestamp': file_message.timestamp.isoformat()
                    }
                )

            # Handle different file message types
            if file_message.message_type == FileMessageType.FILE_OFFER:
                await self._handle_file_offer(file_message)
            elif file_message.message_type == FileMessageType.FILE_ACCEPT:
                await self._handle_file_accept(file_message)
            elif file_message.message_type == FileMessageType.FILE_REJECT:
                await self._handle_file_reject(file_message)
            elif file_message.message_type == FileMessageType.FILE_CHUNK:
                await self.handle_file_chunk(file_message)
            elif file_message.message_type == FileMessageType.FILE_COMPLETE:
                await self._handle_file_complete(file_message)
            elif file_message.message_type == FileMessageType.FILE_ERROR:
                await self._handle_file_error(file_message)
            elif file_message.message_type == FileMessageType.FILE_CANCEL:
                await self._handle_file_cancel(file_message)
            else:
                self.log.warning(f"Unknown file message type: {file_message.message_type}")

        except Exception as e:
            self.log.error(f"Error handling file message: {e}", exc_info=True)
            # Log security event for potential attack
            if AUDIT_AVAILABLE:
                log_event(
                    AuditEventType.SECURITY_VIOLATION,
                    f"File message processing error: {str(e)}",
                    AuditSeverity.MEDIUM,
                    {
                        'error': str(e),
                        'peer': getattr(self.orchestrator, 'peer_username', 'unknown'),
                        'message_data': file_message_data[:100]
                    }
                )

    async def handle_file_chunk(self, file_message: FileMessage) -> None:
        """
        Handle incoming file chunk from peer.
        
        Args:
            file_message: File message containing chunk data
        """
        try:
            chunk = file_message.chunk
            file_id = chunk.file_id

            if file_id not in self.active_file_transfers:
                self.log.warning(f"Received chunk for unknown file transfer: {file_id}")
                return

            transfer = self.active_file_transfers[file_id]
            if transfer['type'] != 'incoming_offer' or transfer['status'] != FileTransferStatus.ACCEPTED:
                self.log.warning(f"Received chunk for invalid transfer state: {file_id}")
                return

            # Store the chunk
            if 'chunks_received' not in transfer:
                transfer['chunks_received'] = {}
            transfer['chunks_received'][chunk.chunk_number] = chunk

            # Update progress
            total_chunks = transfer['metadata'].total_chunks
            received_chunks = len(transfer['chunks_received'])
            progress = (received_chunks / total_chunks) * 100

            print(f"\r{BLUE}[RECV] Receiving {transfer['metadata'].filename}: {progress:.1f}% ({received_chunks}/{total_chunks} chunks){RESET}", end='', flush=True)

            # Check if transfer is complete
            if chunk.is_final or received_chunks == total_chunks:
                await self._complete_file_reception(file_id)

        except Exception as e:
            self.log.error(f"Error handling file chunk: {e}", exc_info=True)
            raise FileTransferError(
                f"Failed to handle file chunk: {e}",
                severity="MEDIUM",
                module="data.file_transfer",
                function="handle_file_chunk"
            )

    async def _handle_file_offer(self, file_message: FileMessage):
        """Handle incoming file offer from peer."""
        try:
            metadata = file_message.metadata

            # Display file offer to user
            print("\r" + " " * 100 + "\r", end='')
            print(f"\n{YELLOW}[FILE] File Offer from {getattr(self.orchestrator, 'peer_username', 'unknown')}:{RESET}")
            print(f"  File: {metadata.filename}")
            print(f"  Size: {metadata.file_size:,} bytes ({metadata.file_size / (1024*1024):.2f} MB)")
            print(f"  Type: {metadata.file_type}")
            print(f"  Chunks: {metadata.total_chunks}")
            print(f"  Created: {metadata.created_at.strftime('%Y-%m-%d %H:%M:%S')}")

            # Store the offer for user decision
            self.active_file_transfers[metadata.file_id] = {
                'type': 'incoming_offer',
                'metadata': metadata,
                'status': FileTransferStatus.PENDING,
                'chunks_received': {},
                'created_at': datetime.now()
            }

            print(f"\n{CYAN}Accept file? (y/n): {RESET}", end='', flush=True)

            # Log the file offer
            if AUDIT_AVAILABLE:
                log_event(
                    AuditEventType.DATA_IMPORT,
                    f"File offer received: {metadata.filename}",
                    AuditSeverity.INFO,
                    {
                        'file_id': metadata.file_id,
                        'filename': metadata.filename,
                        'file_size': metadata.file_size,
                        'file_type': metadata.file_type,
                        'sender': metadata.sender_id,
                        'peer': getattr(self.orchestrator, 'peer_username', 'unknown')
                    }
                )

        except Exception as e:
            self.log.error(f"Error handling file offer: {e}", exc_info=True)

    async def _handle_file_accept(self, file_message: FileMessage):
        """Handle file accept response from peer."""
        try:
            file_id = file_message.file_id

            if file_id in self.active_file_transfers:
                transfer = self.active_file_transfers[file_id]
                if transfer['type'] == 'outgoing_offer':
                    transfer['status'] = FileTransferStatus.ACCEPTED
                    peer_username = getattr(self.orchestrator, 'peer_username', 'unknown')
                    print(f"\n{GREEN}[OK] {peer_username} accepted your file: {transfer['metadata'].filename}{RESET}")

                    # Start sending file chunks
                    await self._start_file_transfer(file_id)

        except Exception as e:
            self.log.error(f"Error handling file accept: {e}", exc_info=True)

    async def _handle_file_reject(self, file_message: FileMessage):
        """Handle file reject response from peer."""
        try:
            file_id = file_message.file_id

            if file_id in self.active_file_transfers:
                transfer = self.active_file_transfers[file_id]
                transfer['status'] = FileTransferStatus.REJECTED
                peer_username = getattr(self.orchestrator, 'peer_username', 'unknown')
                print(f"\n{YELLOW}[FAIL] {peer_username} rejected your file: {transfer['metadata'].filename}{RESET}")

                # Clean up the transfer
                del self.active_file_transfers[file_id]

        except Exception as e:
            self.log.error(f"Error handling file reject: {e}", exc_info=True)

    async def _handle_file_complete(self, file_message: FileMessage):
        """Handle file transfer completion notification."""
        try:
            file_id = file_message.file_id

            if file_id in self.active_file_transfers:
                transfer = self.active_file_transfers[file_id]
                transfer['status'] = FileTransferStatus.COMPLETED
                print(f"\n{GREEN}[OK] File transfer completed: {transfer['metadata'].filename}{RESET}")

                # Clean up
                del self.active_file_transfers[file_id]

        except Exception as e:
            self.log.error(f"Error handling file complete: {e}", exc_info=True)

    async def _handle_file_error(self, file_message: FileMessage):
        """Handle file transfer error notification."""
        try:
            file_id = file_message.file_id
            error_msg = getattr(file_message, 'error_message', 'Unknown error')

            if file_id in self.active_file_transfers:
                transfer = self.active_file_transfers[file_id]
                transfer['status'] = FileTransferStatus.FAILED
                print(f"\n{RED}[FAIL] File transfer error: {error_msg}{RESET}")

                # Clean up
                del self.active_file_transfers[file_id]

        except Exception as e:
            self.log.error(f"Error handling file error: {e}", exc_info=True)

    async def _handle_file_cancel(self, file_message: FileMessage):
        """Handle file transfer cancellation."""
        try:
            file_id = file_message.file_id

            if file_id in self.active_file_transfers:
                transfer = self.active_file_transfers[file_id]
                transfer['status'] = FileTransferStatus.CANCELLED
                peer_username = getattr(self.orchestrator, 'peer_username', 'unknown')
                print(f"\n{YELLOW}[WARNING] File transfer cancelled by {peer_username}: {transfer['metadata'].filename}{RESET}")

                # Clean up
                del self.active_file_transfers[file_id]

        except Exception as e:
            self.log.error(f"Error handling file cancel: {e}", exc_info=True)

    async def _start_file_transfer(self, file_id: str):
        """Start sending file chunks to peer."""
        try:
            if file_id not in self.active_file_transfers:
                return

            transfer = self.active_file_transfers[file_id]
            metadata = transfer['metadata']
            file_path = transfer.get('file_path')

            if not file_path or not os.path.exists(file_path):
                await self._send_file_error(file_id, "Source file not found")
                return

            # Update status
            transfer['status'] = FileTransferStatus.TRANSFERRING

            # Create chunks and send them
            chunks = self.file_handler.chunk_file(file_path, metadata)

            for i, chunk in enumerate(chunks):
                # Create file message for chunk
                chunk_message = FileMessage(FileMessageType.FILE_CHUNK, chunk=chunk)
                await self._send_file_message(chunk_message)

                # Update progress
                progress = ((i + 1) / len(chunks)) * 100
                print(f"\r{BLUE}[SEND] Sending {metadata.filename}: {progress:.1f}% ({i + 1}/{len(chunks)} chunks){RESET}", end='', flush=True)

                # Small delay to prevent overwhelming the connection
                await asyncio.sleep(0.01)

            # Send completion notification
            complete_message = FileMessage(FileMessageType.FILE_COMPLETE, file_id=file_id)
            await self._send_file_message(complete_message)

            print(f"\n{GREEN}[OK] File sent successfully: {metadata.filename}{RESET}")

            # Update status
            transfer['status'] = FileTransferStatus.COMPLETED

            # Clean up after successful transfer
            del self.active_file_transfers[file_id]

        except Exception as e:
            self.log.error(f"Error during file transfer: {e}", exc_info=True)
            await self._send_file_error(file_id, f"Transfer error: {str(e)}")

    async def _complete_file_reception(self, file_id: str):
        """Complete the reception of a file transfer."""
        try:
            if file_id not in self.active_file_transfers:
                return

            transfer = self.active_file_transfers[file_id]
            metadata = transfer['metadata']
            chunks = transfer['chunks_received']

            # Strictly sanitize filename against path traversal (Directory Traversal / CWE-22)
            raw_filename = os.path.basename(str(metadata.filename).replace('\\', '/'))
            safe_filename = "".join(c for c in raw_filename if c.isalnum() or c in "._-").strip("._")
            if not safe_filename:
                safe_filename = f"received_file_{file_id[:8]}.dat"

            # Create strictly bounded output file path
            downloads_dir = Path("downloads").resolve()
            downloads_dir.mkdir(parents=True, exist_ok=True)
            output_path = (downloads_dir / safe_filename).resolve()

            # Enforce path containment
            try:
                if not output_path.is_relative_to(downloads_dir):
                    raise FileTransferError(f"Path traversal attempt rejected: {metadata.filename}")
            except AttributeError:
                if not str(output_path).startswith(str(downloads_dir)):
                    raise FileTransferError(f"Path traversal attempt rejected: {metadata.filename}")

            # Make filename unique if it already exists
            counter = 1
            while output_path.exists():
                name_parts = safe_filename.rsplit('.', 1)
                if len(name_parts) == 2:
                    output_path = (downloads_dir / f"{name_parts[0]}_{counter}.{name_parts[1]}").resolve()
                else:
                    output_path = (downloads_dir / f"{safe_filename}_{counter}").resolve()
                counter += 1

            # Reassemble file
            chunk_list = [chunks[i] for i in sorted(chunks.keys())]
            success = self.file_handler.reassemble_file(chunk_list, output_path, metadata.checksum)

            if success:
                print(f"\n{GREEN}[OK] File received successfully: {output_path}{RESET}")

                # Update status
                transfer['status'] = FileTransferStatus.COMPLETED
                transfer['output_path'] = str(output_path)

                # Send completion acknowledgment
                complete_message = FileMessage(FileMessageType.FILE_COMPLETE, file_id=file_id)
                await self._send_file_message(complete_message)

            else:
                print(f"\n{RED}[FAIL] File integrity check failed: {metadata.filename}{RESET}")
                await self._send_file_error(file_id, "File integrity verification failed")

            # Clean up
            del self.active_file_transfers[file_id]

        except Exception as e:
            self.log.error(f"Error completing file reception: {e}", exc_info=True)
            await self._send_file_error(file_id, f"Reception error: {str(e)}")

    async def _send_file_message(self, file_message: FileMessage):
        """Send a file message to the peer."""
        try:
            # Serialize and encode the file message
            file_message_bytes = file_message.to_bytes()
            encoded_data = base64.b64encode(file_message_bytes).decode('ascii')

            # Format as encrypted message
            msg_data = f"FILE:{encoded_data}"
            
            # Delegate to orchestrator for encryption and sending
            if self.orchestrator and hasattr(self.orchestrator, '_encrypt_message'):
                encrypted_msg = await self.orchestrator._encrypt_message(msg_data)
                
                # Send via orchestrator's network layer
                if hasattr(self.orchestrator, 'tcp_socket'):
                    import p2p_core as p2p
                    success = await p2p.send_framed(self.orchestrator.tcp_socket, encrypted_msg)
                    return success
            
            self.log.error("Cannot send file message: orchestrator not properly configured")
            return False

        except Exception as e:
            self.log.error(f"Error sending file message: {e}", exc_info=True)
            return False

    async def _send_file_error(self, file_id: str, error_message: str):
        """Send a file error message to the peer."""
        try:
            error_msg = FileMessage(FileMessageType.FILE_ERROR, file_id=file_id, error_message=error_message)
            await self._send_file_message(error_msg)
            self.log.warning(f"File error sent: {error_message}")
        except Exception as e:
            self.log.error(f"Error sending file error message: {e}", exc_info=True)
