#!/usr/bin/env python3
"""
scripts/update_release_headers.py

Synchronizes all project modules to the Destroyer-ST2027 Military Production
Hardening Release (2026-10-26). Adds standard release metadata headers
to Python, Rust, Markdown, TOML, Batch, Shell, and Web files.
"""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXCLUDED_EXACT = {
    "critical_modules.hashes",
    "oqs.dll.hashes",
    "libsodium.dll.hashes",
    "secure_transmit_2027.py",
    "rust_data_plane/src/main.rs",
    "ts_runtime.py",
    "dependency_security_verifier.py",
    "platform_hsm_interface.py",
    "cnsa2_policy_engine.py",
    "audit_logging_system.py",
    "pqc_algorithms.py",
    "metadata_resistance.py",
    "network_adversary_resistance.py",
    "secure_p2p.py",
}

EXCLUDED_EXT = {
    ".sig", ".pub", ".dll", ".exe", ".pv", ".hashes", ".json", ".jsonl",
    ".lock", ".yml", ".gitattributes", ".gitignore", ".pyd", ".pdb", ".so",
    ".cnf", ".ini", ".xml", ".service", ".ts-hardened", ".template"
}

PY_HEADER = (
    "# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)\n"
    "# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204\n"
)

RS_HEADER = (
    "// Destroyer-ST2027 Military Production Hardening Release (2026-10-26)\n"
    "// NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204\n"
)

MD_NOTE = (
    "\n\n---\n"
    "<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->\n"
    "<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->\n"
)

TOML_HEADER = (
    "# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)\n"
    "# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204\n"
)

BAT_HEADER = (
    "REM Destroyer-ST2027 Military Production Hardening Release (2026-10-26)\n"
    "REM NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204\n"
)

SH_HEADER = (
    "# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)\n"
    "# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204\n"
)

JS_HEADER = (
    "/* Destroyer-ST2027 Military Production Hardening Release (2026-10-26) */\n"
    "/* NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 */\n"
)

HTML_NOTE = (
    "<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->\n"
    "<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->\n"
)

RELEASE_TOKEN = "Destroyer-ST2027 Military Production Hardening Release (2026-10-26)"


def apply_header(filepath: Path, ext: str) -> bool:
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception:
        return False

    if RELEASE_TOKEN in content:
        return False

    new_content = None
    if ext == ".py":
        if content.startswith("#!"):
            parts = content.split("\n", 1)
            new_content = parts[0] + "\n" + PY_HEADER + (parts[1] if len(parts) > 1 else "")
        else:
            new_content = PY_HEADER + content
    elif ext == ".rs":
        new_content = RS_HEADER + content
    elif ext == ".md":
        new_content = content.rstrip() + MD_NOTE
    elif ext == ".toml":
        new_content = TOML_HEADER + content
    elif ext == ".bat":
        if content.lower().startswith("@echo off"):
            parts = content.split("\n", 1)
            new_content = parts[0] + "\n" + BAT_HEADER + (parts[1] if len(parts) > 1 else "")
        else:
            new_content = BAT_HEADER + content
    elif ext in (".sh", ".ps1"):
        if content.startswith("#!"):
            parts = content.split("\n", 1)
            new_content = parts[0] + "\n" + SH_HEADER + (parts[1] if len(parts) > 1 else "")
        else:
            new_content = SH_HEADER + content
    elif ext in (".js", ".css"):
        new_content = JS_HEADER + content
    elif ext == ".html":
        if "<!DOCTYPE" in content or "<!doctype" in content:
            idx = content.find(">")
            if idx != -1:
                new_content = content[:idx+1] + "\n" + HTML_NOTE + content[idx+1:]
        if new_content is None:
            new_content = HTML_NOTE + content

    if new_content is not None and new_content != content:
        filepath.write_text(new_content, encoding="utf-8")
        return True
    return False


def main():
    tracked = set(subprocess.check_output(["git", "ls-files"], text=True, cwd=str(REPO_ROOT)).splitlines())
    out = subprocess.check_output(["git", "log", "--name-only", "--format=COMMIT:%cd", "--date=short"], text=True, cwd=str(REPO_ROOT))

    file_latest = {}
    current_date = None
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COMMIT:"):
            current_date = line.split(":", 1)[1]
        else:
            if line in tracked and line not in file_latest:
                file_latest[line] = current_date

    updated = []
    for rel_path, commit_date in file_latest.items():
        if commit_date >= "2026-10-26":
            continue
        if rel_path in EXCLUDED_EXACT:
            continue

        ext = os.path.splitext(rel_path)[1].lower()
        if ext in EXCLUDED_EXT or not ext:
            continue

        full_path = REPO_ROOT / rel_path
        if full_path.exists():
            if apply_header(full_path, ext):
                updated.append(rel_path)

    print(f"Successfully synchronized {len(updated)} files with ST2027 release header.")


if __name__ == "__main__":
    main()
