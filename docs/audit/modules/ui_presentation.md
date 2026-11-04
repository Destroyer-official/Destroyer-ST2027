# Module Documentation: ui_presentation

## 1. Purpose
The `ui_presentation` module provides terminal user interface formatting, status presentation, user input dialogues, and Trust-On-First-Use (TOFU) identity key verification (`ui/display.py:1-785`, `ui/safety_numbers.py:1-246`, `ui/manager.py:1-59`). It ensures deterministic rendering across constrained terminal environments (Windows CP1252 / UTF-8) without emitting unsupported control sequences (`ui/display.py:45-70`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `ui.safety_numbers.fingerprint_bundle` (`ui/safety_numbers.py:40-75`)
- `fingerprint_bundle(bundle: dict) -> str`: Extracts 7 canonical identity public key fields (`identity`, `static_key`, `signing_key`, `signed_prekey`, `prekey_signature`, `kem_public_key`, `falcon_public_key`) (`ui/safety_numbers.py:45-55`). Serializes to canonical JSON (`sort_keys=True`) and returns 128-character hexadecimal SHA3-512 string (`:60`).
- `safety_numbers(key_a: bytes, key_b: bytes) -> str`: Sorts public keys lexicographically and computes SHA3-512 over concatenated keys (`ui/safety_numbers.py:65-95`). Derives a grouped 48-digit decimal safety string (`:80-92`). Returns formatted string: `"XXXXX XXXXX XXXXX ... XXXXX"` (8 blocks of 6 digits).
- `pin_safety_number(peer_id: str, safety_num: str) -> bool`: Stores safety number in local persistent storage (`~/.secure_p2p/pinned_keys.json`) authenticated with HMAC-SHA256 (`ui/safety_numbers.py:120-165`).
- `verify_pinned_safety_number(peer_id: str, current_safety_num: str) -> bool`: Checks incoming safety number against pinned record (`ui/safety_numbers.py:170-205`). Returns `True` if matches; raises `SafetyNumberMismatchError` on divergence (`:195`).

#### `ui.display.DisplayManager` (`ui/display.py:80-320`)
- `print_banner(callsign: str, role: str, local_ep: str, peer_ep: str) -> None`: Renders station header with active endpoints, crypto engines, and classification labels (`ui/display.py:95-140`).
- `format_chat_message(sender: str, text: str, timestamp: float) -> str`: Formats chat message with timestamp and sender callsign (`ui/display.py:150-185`). Strips unprintable ANSI escape codes.

#### `ui.prompts.PromptManager` (`ui/prompts.py:60-220`)
- `prompt_passphrase(prompt_text: str = "Enter passphrase: ") -> str`: Uses `getpass.getpass` to accept masked passphrase input from the user (`ui/prompts.py:75-110`).
- `confirm_action(prompt_text: str, default: bool = False) -> bool`: Prompts operator for `[y/N]` confirmation (`ui/prompts.py:120-155`).

## 3. Data Formats and Byte Layouts

### 3.1 Grouped 48-Digit Decimal Safety Number Layout (`ui/safety_numbers.py:65-95`)
- Derived from SHA3-512 digest (64 bytes):
  - Take the first 32 bytes of the digest.
  - Partition into 8 slices of 4 bytes (uint32 big-endian).
  - Each 4-byte slice $V_i$ is mapped to a 6-digit integer: $D_i = V_i \pmod{10^6}$.
  - Formatted as 6 zero-padded decimal digits: `f"{D_i:06d}"`.
- Arithmetic Verification:
  - Total slices: 8 slices $\times$ 6 digits = 48 decimal digits.
  - Display layout: 8 blocks of 6 digits separated by single spaces: $8 \times 6 + 7 = 55$ characters total string length. Arithmetic matches code implementation.

### 3.2 Persistent Pin Store HMAC Envelope (`ui/safety_numbers.py:120-165`)
- File format in `~/.secure_p2p/pinned_keys.json`:
  - `peer_id`: String peer callsign or public key digest.
  - `safety_number`: 55-character formatted safety string.
  - `pinned_at`: IEEE 754 float timestamp.
  - `hmac`: 64-character hexadecimal HMAC-SHA256 computed over `peer_id || safety_number || pinned_at` using key derived from `P2P_PIN_KEK`.

## 4. Algorithms and Pinned Libraries
- SHA3-512: NIST FIPS 202. Safety number digest computation provided by standard library `hashlib.sha3_512` (`ui/safety_numbers.py:22`).
- HMAC-SHA256: IETF RFC 2104. Pin store tamper authentication provided by standard library `hmac` and `hashlib.sha256` (`ui/safety_numbers.py:25`).

## 5. Dependencies and Hardware Requirements
- Native Operating System APIs: Terminal TTY interfaces via `sys.stdin`, `sys.stdout`, and `getpass` (`ui/prompts.py:25`).
- Character encoding: Compatible with standard Windows consoles (CP1252 or UTF-8).

## 6. Failure Behavior
- Pinned safety number mismatch raises `ui.safety_numbers.SafetyNumberMismatchError` and blocks connection (`ui/safety_numbers.py:195`).
- Pin store HMAC corruption raises `ui.safety_numbers.TamperedStoreError` (`ui/safety_numbers.py:155`).
- User input abort (`Ctrl+C` / `Ctrl+D`) raises `KeyboardInterrupt` or `EOFError` caught cleanly by console supervisors (`ui/prompts.py:105`).

## 7. Configuration and Environment Variables
- `P2P_PIN_KEK`: Hexadecimal key encryption key protecting pinned identity store. Default: auto-derived from machine GUID (`ui/safety_numbers.py:125`).
- `P2P_NO_COLOR`: Disables ANSI color sequences in terminal display. Default: `0` (`ui/display.py:50`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - 48-digit decimal safety number determinism: verified in `tests/test_production_tier4_tactical_commands.py` (6 tests).
  - Terminal display banner rendering and character escaping: verified in `tests/test_defensive_audit_targets.py` (4 tests).
  - Masked passphrase handling and confirmation prompts: verified in `tests/test_security_audit_remediations.py` (2 tests).
- NOT Covered:
  - Braille terminal accessibility displays.
  - High-DPI hardware font scaling artifacts in legacy Windows command prompts.

## 9. Not Implemented / External Dependencies
- Graphical User Interface: Native desktop GUI windows (Qt, GTK) are not implemented; interfaces are limited to terminal consoles and web browsers.

## 10. Known Limitations and Residual Risks
- Terminal Scrollback Snooping: Plaintext messages rendered to an interactive terminal remain in terminal scrollback buffers until cleared or the terminal window is closed.

## 11. Discrepancies
- Promotional terms in console banners: ANSI banner templates contain operational labels cataloged in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Should `ui/display.py` provide an automatic screen-clearing command on operator disconnect to purge terminal scrollback buffers?
