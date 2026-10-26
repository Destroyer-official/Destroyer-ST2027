# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""Static and architectural security regression tests for notupload/ components.

Checks:
1. No `SET LOCAL` f-strings / raw interpolation in SQL queries.
2. No `DO UPDATE SET pubkey` in user UPSERT queries (prevents pubkey hijacking).
3. Debug endpoints gated with constant-time token validation.
4. HMAC cipher derivations require real secrets (no static 'fallback-secret').
5. Update nonce caching and skew limits exist for replay protection.
"""

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NOTUPLOAD_ANO = REPO_ROOT / "notupload" / "fastapi-neon-ano"
NOTUPLOAD_NEW = REPO_ROOT / "notupload" / "fastapi-neon-ano-new"


def test_no_set_local_fstrings():
    """Ensure no SQL f-string injection with SET LOCAL myapp.user_id exists."""
    for base in (NOTUPLOAD_ANO, NOTUPLOAD_NEW):
        if not base.exists():
            continue
        for py_path in base.rglob("*.py"):
            text = py_path.read_text(encoding="utf-8", errors="ignore")
            # Prohibit f"SET LOCAL ... {user_id}" or similar interpolations
            match = re.search(r'f["\'].*SET\s+LOCAL\s+myapp\.user_id\s*=', text, re.IGNORECASE)
            assert match is None, f"Found SET LOCAL f-string in {py_path}: {match.group(0)}"


def test_no_do_update_set_pubkey():
    """Ensure ON CONFLICT DO UPDATE never allows overwriting user pubkey in SET clause."""
    for base in (NOTUPLOAD_ANO, NOTUPLOAD_NEW):
        if not base.exists():
            continue
        for py_path in base.rglob("*.py"):
            text = py_path.read_text(encoding="utf-8", errors="ignore")
            # Look for DO UPDATE SET ... pubkey = ... before any WHERE clause
            match = re.search(r"DO\s+UPDATE\s+SET\s+(?:(?!\bWHERE\b)[^;])*\bpubkey\s*=", text, re.IGNORECASE | re.DOTALL)
            assert match is None, f"Found prohibited pubkey mutation in {py_path}: {match.group(0)}"  # nosec: B608


def test_debug_endpoint_gating():
    """Ensure debug endpoints are gated by constant-time token comparison."""
    for base in (NOTUPLOAD_ANO, NOTUPLOAD_NEW):
        main_py = base / "app" / "main.py"
        if not main_py.exists():
            continue
        text = main_py.read_text(encoding="utf-8", errors="ignore")
        assert "_require_debug_token" in text, f"Missing debug token gate in {main_py}"
        assert "compare_digest" in text, f"Debug token gate must use constant-time compare_digest in {main_py}"
        assert "DEBUG_TOKEN" in text, f"Debug gate must read DEBUG_TOKEN in {main_py}"


def test_hmac_no_fallback_secret():
    """Ensure cipher derivation does not contain static 'fallback-secret'."""
    for base in (NOTUPLOAD_ANO, NOTUPLOAD_NEW):
        db_core = base / "Neon_PostgreSQL" / "core" / "database.py"
        if not db_core.exists():
            continue
        text = db_core.read_text(encoding="utf-8", errors="ignore")
        assert "fallback-secret" not in text, f"Found hardcoded 'fallback-secret' in {db_core}"
        assert "HMAC_SECRET_KEY" in text, f"Expected HMAC_SECRET_KEY in {db_core}"


def test_replay_cache_and_nonce_validation():
    """Ensure replay cache and timestamp skew validation exist for updates."""
    for base in (NOTUPLOAD_ANO, NOTUPLOAD_NEW):
        main_py = base / "app" / "main.py"
        if not main_py.exists():
            continue
        text = main_py.read_text(encoding="utf-8", errors="ignore")
        assert "_claim_update_nonce" in text, f"Missing nonce claim function in {main_py}"
        assert "UPDATE_MAX_SKEW_SECONDS" in text, f"Missing timestamp skew constant in {main_py}"
        assert "_update_nonces" in text, f"Missing update nonce cache dictionary in {main_py}"
