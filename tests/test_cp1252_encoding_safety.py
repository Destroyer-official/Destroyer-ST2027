"""
Tests for Windows CP1252 Console Encoding Safety.
Verifies that all display, prompts, feedback, error handler, and banner
strings can be encoded in cp1252 and ascii without raising UnicodeEncodeError.
"""

import io
import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from ui.display import DisplayManager
from ui.feedback import FeedbackManager
from ui.prompts import PromptManager, ProgressIndicator
from utils.error_handler import SecurityErrorHandler


class CP1252Enforcer(io.TextIOBase):
    """A stream that strictly enforces cp1252 encoding, raising UnicodeEncodeError on violation."""
    def __init__(self):
        super().__init__()
        self.buffer = io.BytesIO()

    def write(self, s):
        # Strict cp1252 encoding check
        s.encode("cp1252", errors="strict")
        self.buffer.write(s.encode("cp1252"))
        return len(s)


def test_ui_display_cp1252_compatibility(monkeypatch):
    """Test that all DisplayManager methods succeed on a strict cp1252 stream."""
    stream = CP1252Enforcer()
    monkeypatch.setattr(sys, "stdout", stream)

    mock_orch = MagicMock()
    mock_orch.hsm_initialized = True
    mock_orch.hardware_security_active = True
    mock_orch.hsm_provider_type = "TPM_2_0"
    mock_orch.strict_auth = True
    mock_orch.ephemeral_key_lifetime = 3072

    dm = DisplayManager(mock_orch)
    dm.display_banner()
    dm.print_security_summary()
    dm.display_message("Peer1", "Operational message test", 1234567.8)
    dm.display_menu(["1. Connect", "2. Disconnect", "3. Exit"])
    dm.display_status({"Status": "Active", "Peers": 3})
    dm.view_security_status()
    dm.display_security_recommendations()


def test_ui_feedback_cp1252_compatibility(monkeypatch):
    """Test that all FeedbackManager methods succeed on a strict cp1252 stream."""
    stream = CP1252Enforcer()
    monkeypatch.setattr(sys, "stdout", stream)

    mock_orch = MagicMock()
    fb = FeedbackManager(mock_orch)

    fb.show_progress_bar(50, 100, prefix="Transferring")
    fb.show_success("Handshake established with sovereign PKI")
    fb.show_error("Connection timeout", "Target peer unreachable")
    fb.show_warning("High latency detected on link")
    fb.show_info("Double Ratchet key step 42 rotated")
    fb.show_status("Syncing routing table", status="info")
    fb.show_operation_start("Post-Quantum Key Exchange")
    fb.show_operation_complete("Post-Quantum Key Exchange", duration=0.045)
    fb.show_connection_status("PeerAlpha", "Connected", "ML-KEM-1024 established")
    fb.show_handshake_progress("PQC_ENCAPSULATION")
    fb.show_file_transfer_progress("tactical_manifest.bin", 512, 1024, speed=102400.0)
    fb.show_helpful_prompt("connection_failed")
    fb.show_enhanced_error("NetworkError", ConnectionResetError("Connection reset"), context="Sync")
    fb.show_table(["Header A", "Header B"], [["Row 1", "Value 1"], ["Row 2", "Value 2"]], title="Status")
    fb.show_separator()


def test_ui_prompts_cp1252_compatibility(monkeypatch):
    """Test that PromptManager and ProgressIndicator succeed on a strict cp1252 stream."""
    stream = CP1252Enforcer()
    monkeypatch.setattr(sys, "stdout", stream)

    mock_orch = MagicMock()
    pm = PromptManager(mock_orch)

    pm.show_success("Action successful")
    pm.show_error("Validation error", details="Invalid IP format")
    pm.show_warning("Disk cache low")
    pm.show_info("Configuration reloaded")
    pm.show_status("Ready")
    pm.display_helpful_prompt("first_time")

    indicator = ProgressIndicator("Testing Spinner", total=10)
    indicator.update(1, "Step 1 complete")
    indicator.complete("All done")
    indicator.error("Failed at step 3")


def test_error_handler_cp1252_compatibility(monkeypatch):
    """Test that SecurityErrorHandler console outputs succeed on a strict cp1252 stream."""
    stream = CP1252Enforcer()
    monkeypatch.setattr(sys, "stdout", stream)

    seh = SecurityErrorHandler()
    # Test error formatting and guidance
    seh.log_and_notify(
        ValueError("Decryption failed"),
        {'peer_id': 'PeerAlpha', 'operation': 'decrypt_packet'}
    )


def test_no_forbidden_unicode_symbols_in_core_modules():
    """Verify that core files have zero non-ASCII emojis or symbols that break Windows CP1252."""
    import re
    emoji_regex = re.compile(
        r'[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]|[\u203c-\u2049]'
    )
    core_files = [
        Path("archive/legacy_prototype/secure_p2.py"),
        Path("archive/legacy_prototype/secure_p2p.py"),
        Path("ui/display.py"),
        Path("ui/feedback.py"),
        Path("ui/prompts.py"),
        Path("ui/menus.py"),
        Path("utils/error_handler.py"),
        Path("secure_p2p_core/ui/display.py"),
        Path("secure_p2p_core/ui/feedback.py"),
        Path("secure_p2p_core/ui/prompts.py"),
        Path("secure_p2p_core/ui/menus.py"),
        Path("secure_p2p_core/utils/error_handler.py"),
    ]

    for p in core_files:
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8")
        matches = emoji_regex.findall(text)
        assert len(matches) == 0, f"Found non-ASCII emojis {matches} in {p}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
