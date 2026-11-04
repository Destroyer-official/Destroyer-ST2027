# Module Audit: ui_presentation

## 1. Module Overview and Scope
The `ui_presentation` subsystem provides user interaction facilities across two distinct presentation layers:
1. Terminal User Interface (TUI) components (`ui/display.py`, `ui/feedback.py`, `ui/manager.py`, `ui/menus.py`, `ui/prompts.py`, `ui/safety_numbers.py`).
2. Local diagnostic web telemetry console (`tactical_web_console.py` and static frontend assets in `tactical_web/`).

The subsystem coordinates status rendering, cryptographic identity verification interfaces, interactive prompts, and diagnostic HTTP endpoints without introducing external network service dependencies.

---

## 2. Terminal UI Architecture and Component Breakdown

### 2.1 Facade Coordinator: `UIManager` (`ui/manager.py:13-60`)
The `UIManager` class subclasses `BaseModule` (`ui/manager.py:13`) and exposes lazy-loaded properties delegating to specialized presentation modules:
- `display`: Instantiates and returns `DisplayManager` (`ui/manager.py:25-30`).
- `prompts`: Instantiates and returns `PromptManager` (`ui/manager.py:33-38`).
- `menus`: Instantiates and returns `MenuManager` (`ui/manager.py:41-46`).
- `feedback`: Instantiates and returns `FeedbackManager` (`ui/manager.py:49-54`).
- `cleanup()`: Async lifecycle method completing module tear-down (`ui/manager.py:56-59`).

### 2.2 Status and Report Rendering: `DisplayManager` (`ui/display.py:19-785`)
`DisplayManager` coordinates application banners, hardware attestation telemetry, memory protection status, and comprehensive security configuration tables:
- `display_banner()` (`ui/display.py:22-42`): Sets default environment flag `P2P_DISABLE_DANE="false"` (`:30`), logs hardware security diagnostic states (`:33-36`), and invokes `print_security_summary()`.
- `print_security_summary()` (`ui/display.py:44-71`): Emits structured informational log lines to logger `security_summary` detailing post-quantum cryptographic primitives (`ML-KEM-1024`, `ML-DSA-87`, `SLH-DSA-256f`), transport protocol (`TLS 1.3 + AES-256-GCM`), ratchet forward secrecy, hardware security, memory mitigation status, and authentication mode.
- `get_hw_security_status()` (`ui/display.py:73-86`): Inspects `platform_hsm_interface._hardware_security_active` and `_hsm_provider_type`. Returns `"[OK] Windows TPM"` when configured for `windows_cng_chunked` (`:79-81`), `"[OK] <provider>"` for other active providers, or `"[--] Software Only"` (`:82`).
- `get_memory_protection_status()` (`ui/display.py:87-98`): Inspects `dep_instance` or `dep` on the orchestrator; returns `"[OK] Enhanced DEP + CFG + ACG"` when active or `"[OK] Basic Protection"` (`:90-94`).
- `get_dep_details()` (`ui/display.py:99-148`): Formats diagnostic list of Data Execution Prevention (DEP), Control Flow Guard (CFG), Arbitrary Code Guard (ACG), and stack canary counters from `orchestrator.dep.get_security_status()`.
- `get_additional_security_features()` (`ui/display.py:150-200`): Reports canary count (`:156-163`), ASLR operating system default (`:165-168`), Secure Boot detection (`:171`), TPM detection (`:175`), Libsodium presence (`:179-183`), and automatic key rotation interval (`:191-195`).
- `check_secure_boot_status()` (`ui/display.py:202-226`): On Windows, executes list-form subprocess `["powershell", "-Command", "Confirm-SecureBootUEFI"]` with 10s timeout (`:209-212`). On Linux, probes `/sys/firmware/efi/efivars/SecureBoot-*` (`:219`).
- `check_tpm_status()` (`ui/display.py:227-279`): Probes TPM availability via `platform_hsm_interface.is_tpm_available()` or Windows TBS device info (`:231-237`), falling back to PowerShell `Get-PnpDevice` and `Get-Tpm` (`:247-269`), or `/dev/tpm0` / `/dev/tpmrm0` on Linux (`:272-275`).
- `display_security_recommendations()` (`ui/display.py:280-363`): Prints diagnostic recommendations for certificate exchange secrets, hardware DEP BIOS configuration, CFG compiler flags, and TPM setup.
- `display_message(sender: str, message: str, timestamp: float)` (`ui/display.py:365-375`): Formats incoming chat messages with UTC/local timestamp `[%H:%M:%S]` and sender identifier.
- `display_menu(options: list)` (`ui/display.py:376-385`): Emits tabular menu choices bounded by 60-character `=` separator rules.
- `display_status(status: dict)` (`ui/display.py:386-395`): Renders key-value status maps.
- `view_security_status()` (`ui/display.py:396-469`): Renders a 70-character wide tabular status report incorporating algorithm state (`:411`), active security modules (`:417`), active peer connections (`:423`), security level (`:429`), HSM/TPM telemetry (`:435`), memory protection (`:441`), additional features (`:447`), lifecycle telemetry (`:453`), and multi-level data guard status (`:459`).

### 2.3 Progress Indicators and Feedback: `FeedbackManager` (`ui/feedback.py:23-452`)
`FeedbackManager` implements terminal status signals and progress bars:
- `show_progress_bar(current: int, total: int, prefix: str = '', suffix: str = '', length: int = 50, fill: str = '#')` (`ui/feedback.py:32-62`): Renders a proportional progress bar using `\r` carriage return to overwrite line state on `sys.stdout` (`:53`). Emits trailing newline upon completion (`:57-58`).
- `show_spinner(message: str, duration: Optional[float] = None)` (`ui/feedback.py:63-96`): Async coroutine cycling ASCII glyph sequence `['|', '/', '-', '\\']` (`:74`) at 100 ms intervals (`:88`). Clears the spinner line upon exit (`:91`).
- Text Alert Methods:
  - `show_success(message: str)` (`ui/feedback.py:97-106`): Prepends standard check indicator.
  - `show_error(message: str, details: Optional[str] = None)` (`ui/feedback.py:108-121`): Prepends `[FAIL]`.
  - `show_warning(message: str)` (`ui/feedback.py:122-132`): Prepends `[WARNING] `.
  - `show_info(message: str)` (`ui/feedback.py:133-142`): Prepends `[INFO]`.
  - `show_status(message: str, status: str = "info")` (`ui/feedback.py:144-164`): Maps status string to ASCII badges: `'success': ''`, `'error': '[FAIL]'`, `'warning': '[WARNING] '`, `'info': '[INFO] '`, `'loading': '[BUSY]'`, `'complete': '[OK] '` (`:154-161`).
- Operational Status Tracking:
  - `show_operation_start()` (`ui/feedback.py:165-174`) and `show_operation_complete()` (`:176-190`).
  - `show_connection_status()` (`ui/feedback.py:191-214`): Formats `'connecting'`, `'connected'`, `'disconnected'`, `'failed'`.
  - `show_handshake_progress()` (`ui/feedback.py:215-234`): Formats `'init'`, `'kem'`, `'sign'`, `'derive'`, `'complete'`.
  - `show_file_transfer_progress()` (`ui/feedback.py:235-278`): Computes percentage and megabyte throughput (`current_mb / total_mb`) with optional transfer speed rendering (`:253-270`).
  - `show_table(headers, rows, title=None)` (`ui/feedback.py:379-415`): Computes dynamic column widths via `max(len(cell))` and renders standard ASCII pipe-delimited table rows (`:396-410`).
  - `show_countdown(seconds: int, message: str)` (`ui/feedback.py:416-437`): Async 1-second interval decremental counter overwriting terminal buffer line via `\r`.
  - `clear_line()` (`ui/feedback.py:438-442`): Overwrites terminal line with 80 space characters (`\r` + `' ' * 80 + '\r'`).

### 2.4 User Prompts and Input Handling: `PromptManager` (`ui/prompts.py:99-383`)
`PromptManager` provides synchronous and asynchronous user interaction routines:
- `async_input(prompt: str) -> str` (`ui/prompts.py:102-135`): Flushes prompt string and delegates synchronous `input()` to default executor `loop.run_in_executor(None, input)` (`:123`). Catches `EOFError` (`Ctrl+D`) and `KeyboardInterrupt` (`Ctrl+C`), returning `"exit"` to prevent unhandled runtime termination (`:124-131`).
- `prompt_user(prompt: str) -> str` (`ui/prompts.py:136-157`): Synchronous console input handling `EOFError` and `KeyboardInterrupt` returning `"exit"`.
- `get_user_input(prompt: str, validator: Optional[Callable[[str], bool]] = None) -> str` (`ui/prompts.py:158-189`): Evaluates operator input against predicate validator in a `while True` loop until validation returns `True`.
- `confirm_action(prompt: str) -> bool` (`ui/prompts.py:190-212`): Prompts user with `(yes/no)` and returns `True` if stripped lower-case response is in `['yes', 'y']`.
- `get_secure_input(prompt: str) -> str` (`ui/prompts.py:213-234`): Calls standard library `getpass.getpass(prompt)` to read passphrase input without local echo. Returns empty string on `EOFError` or `KeyboardInterrupt`.
- `ProgressIndicator` (`ui/prompts.py:20-97`): Standalone progress helper supporting determinate progress (40-character bar `[###---]`) and indeterminate progress (rotating ASCII spinner `['|', '/', '-', '\\']` with elapsed seconds calculation) (`:60-72`).

### 2.5 Menu Navigation: `MenuManager` (`ui/menus.py:17-386`)
`MenuManager` coordinates interactive console workflows:
- Main Connection Loop (`ui/menus.py:20-32`): Delegates connection menu processing to `orchestrator.handle_connections()`.
- Peer Resolution and Connection:
  - `connect_by_username()` (`ui/menus.py:33-73`): Prompts for peer username, queries `orchestrator.data.peer_mgmt.lookup_peer_by_username()`, and establishes connection via `orchestrator.network.connection.connect_to_peer()`.
  - `connect_by_ip()` (`ui/menus.py:74-229`): Parses endpoint strings using `network_endpoint_discovery.parse_endpoint` (`:100-104`). Validates IPv6 addresses via `InputValidator.validate_ipv6()` and IPv4/hostnames via `InputValidator.validate_ip_address()` (`:113-132`). Opens TCP socket via `asyncio.open_connection()` (`:157`), performs session handshake via `simple_chat_implementation.initialize_session()` (`:174-180`), and spawns background message receiver task (`:192-194`).
  - `show_stored_peers()` (`ui/menus.py:230-268`): Retrieves stored peer records from `orchestrator.data.peer_mgmt.list_peers()` and renders callsign, IPv6 address, port, status, and last seen timestamps.
- Profile Management Workflows (`ui/menus.py:269-366`):
  - `_create_user_profile()` (`:305-333`): Collects username and display name, invoking `orchestrator.data.user_mgmt.create_new_user()`.
  - `_view_user_profile()` (`:340-360`): Renders active profile parameters from `orchestrator.data.user_mgmt.load_profile()`.
  - `_switch_user_profile()` (`:334-339`) and `_delete_user_profile()` (`:361-366`): Explicitly unhandled stubs emitting `"This feature is not yet implemented."` (cataloged under Not Implemented).
- Diagnostic Execution (`ui/menus.py:367-386`): `run_system_tests()` triggers `orchestrator.system_tests.run_system_tests()`.

---

## 3. Terminal Control Sequence and Encoding Analysis

### 3.1 Encoding Standards: CP1252 and ASCII Safety
The terminal presentation layer does not emit ANSI color escape sequences (such as `\033[31m` or `\x1b[`). It relies entirely on printable ASCII bracketed badges:
- `[OK]`, `[FAIL]`, `[WARNING] `, `[INFO]`, `[BUSY]`, `[KEY]`, `[TRANSFER]`, `[STATUS]`.
- Banners and framing use pure ASCII character sequences (`=`, `-`, `|`, `#`).
- Verification: Verified in `tests/test_cp1252_encoding_safety.py` (5 tests passing in 0.82s). When stdout is piped to a stream enforcing strict `cp1252` encoding, zero `UnicodeEncodeError` exceptions are raised across all display, prompt, feedback, and error rendering routines (`tests/test_cp1252_encoding_safety.py:32-98`).

### 3.2 Emoji Elimination Property
Unicode emoji glyphs (ranges `U+1F600-U+1F64F`, `U+1F300-U+1F5FF`, `U+1F680-U+1F6FF`, `U+2600-U+26FF`, `U+2700-U+27BF`) are eliminated from production console files to prevent rendering buffer misalignment on legacy Windows consoles.
- Verification: Verified via property-based testing in `tests/test_no_emoji_property.py` (5 tests passing in 8.45s).

### 3.3 Dynamic Line Overwriting
Interactive progress displays utilize standard ASCII carriage return (`\r`) to overwrite the active console line without vertical scrolling:
- Progress bar updates: `sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}')` (`ui/feedback.py:53`).
- Spinner updates: `sys.stdout.write(f'\r{spinner_chars[idx]} {message}')` (`ui/feedback.py:84`).
- Line clearing: `sys.stdout.write('\r' + ' ' * 80 + '\r')` (`ui/feedback.py:440`).

---

## 4. Trust-On-First-Use (TOFU) Safety Numbers and Pin Store (`ui/safety_numbers.py`)

### 4.1 Canonical Identity Fingerprinting: `fingerprint_bundle` (`ui/safety_numbers.py:40-63`)
Computes an identity fingerprint over 7 canonical public key fields, excluding ephemeral session keys, nonces, timestamps, and handshake signatures:
```python
fp_fields = {
    k: str(bundle.get(k, ''))
    for k in ('identity', 'static_key', 'signing_key',
              'signed_prekey', 'prekey_signature',
              'kem_public_key', 'falcon_public_key')
}
fp_src = json.dumps(fp_fields, sort_keys=True).encode('utf-8')
return hashlib.sha3_512(fp_src).hexdigest()
```
- Output: 128-character hexadecimal string representing the SHA3-512 digest (NIST FIPS 202).

### 4.2 Grouped 48-Digit Decimal Safety Number Derivation (`ui/safety_numbers.py:65-75`)
Computes symmetric safety numbers between peer key bundles:
1. Inputs $K_A, K_B$ are sorted lexicographically: `first_pk, second_pk = sorted([key_a, key_b])` (`ui/safety_numbers.py:70`).
2. Concatenated with delimiter: `digest = hashlib.sha3_512(first_pk + b"||" + second_pk).digest()` (`:71`).
3. The 64-byte digest is converted to a big-endian unsigned integer: `value = int.from_bytes(digest, "big")` (`:72`).
4. The integer is formatted as a zero-filled decimal string and the last 48 digits are sliced:
   `digits = str(value).zfill(GROUP * GROUPS)[-GROUP * GROUPS:]` where `GROUP = 4` and `GROUPS = 12` ($4 \times 12 = 48$ digits) (`:25-30, 73`).
5. Grouped into 12 blocks of 4 digits separated by single spaces:
   `" ".join(digits[i:i + GROUP] for i in range(0, len(digits), GROUP))` (`:74`).
- Arithmetic verification:
  - Digits: 12 blocks $\times$ 4 decimal digits = 48 digits.
  - Spacers: 11 single spaces.
  - Total string length: $48 + 11 = 59$ characters.
  - Verified by test assertion `self.assertEqual(len(num_ab), 59)` in `tests/test_production_tier4_tactical_commands.py:97`.

### 4.3 Unpinnable Target Detection (`ui/safety_numbers.py:77-102`)
`is_unpinnable_target(target: str) -> bool` enforces a fail-closed blacklist preventing the persistent pinning of loopback, unspecified, and wildcard network targets:
- Prohibited targets (`_INVALID_PIN_HOSTS`): `"::"`, `"0.0.0.0"`, `"127.0.0.1"`, `"::1"`, `"localhost"`, `"*"`, `"0"`, `""`, and `"cert_tofu_*"` prefixed equivalents (`ui/safety_numbers.py:77-81`).
- IP inspection: Parses target via standard library `ipaddress.ip_address()`, rejecting addresses where `ip.is_loopback`, `ip.is_unspecified`, or `ip.is_link_local` evaluates to `True` (`:96-99`).

### 4.4 Persistent Pin Store Architecture and Cryptographic Sealing (`ui/safety_numbers.py:105-245`)
- Storage Path: `Path.home() / ".secure_p2p" / "pins.json"` (`ui/safety_numbers.py:24`).
- Key Encryption Key (KEK): Derived from `os.environ.get("P2P_PIN_KEK")` or `os.environ.get("P2P_STORAGE_PASSPHRASE")` (`:37`).
- Key Derivation Function (`_pins_envelope_key`): Uses scrypt (IETF RFC 7914):
  `hashlib.scrypt(pw, salt=b"PinsStore::Envelope::v1", n=32768, r=8, p=1, maxmem=64*1024*1024, dklen=32)` (`:108-115`).
- AEAD Sealing Format (`_atomic_write_json`):
  - When KEK is present: Generates a 12-byte random nonce via `secrets.token_bytes(12)` (`:195`). Encrypts formatted JSON payload with AES-256-GCM (`AESGCM(key)`) with Additional Authenticated Data (AAD) `b"PinsStore::v1"` (`:197`).
  - Disk format: Magic prefix `b"PINENC_V1:"` (10 bytes) + Nonce (12 bytes) + Ciphertext + Tag (`:105, 198`).
  - Atomic writing: Writes to temporary file (`tempfile.mkstemp(prefix=".pins-")`), applies POSIX mode `0o600` via `os.chmod`, flushes, calls `os.fsync(fileno)`, and atomically replaces the destination via `os.replace` (`:199-210`).
- Fail-Closed Production Guard: If no KEK is configured in a production environment (`production_gate.is_production() == True`), writing plaintext pins raises `ValueError("FAIL-CLOSED: refusing plaintext pins.json write in production...")` (`:221-224`).
- Record Authentication: When KEK is configured, each peer entry is MACed via `hmac.new(_PIN_KEK, f"{peer_id}||{fingerprint}".encode('utf-8'), hashlib.sha512).hexdigest()` (HMAC-SHA512) (`:137-139`).
- Verification States (`check_pin`):
  - `"unpinnable"`: Target matched loopback/wildcard check (`ui/safety_numbers.py:158-159`).
  - `"new"`: Peer ID not present in store (`:161-162`).
  - `"match"`: Stored record matches current fingerprint and valid HMAC (`:163`).
  - `"CHANGED"`: Stored record differs or HMAC comparison fails (`:163`).

---

## 5. Web Telemetry Console Architecture (`tactical_web_console.py` and `tactical_web/`)

### 5.1 Server Architecture and Daemon Configuration
- Binding: Binds strictly to `127.0.0.1:8443` (`tactical_web_console.py:11, 650`).
- Process Architecture: `ThreadedHTTPServer(ThreadingMixIn, HTTPServer)` with `daemon_threads = True` (`tactical_web_console.py:118-120`).
- Handler: `TacticalWebHandler(SimpleHTTPRequestHandler)` serving assets from `tactical_web/` (`:121-125`).

### 5.2 HTTP Response Security Headers (`tactical_web_console.py:127-142`)
In `end_headers()`, every HTTP response injects security headers:
- `Content-Security-Policy`: `"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"` (`:130-134`).
- `X-Frame-Options`: `"DENY"` (`:135`).
- `X-Content-Type-Options`: `"nosniff"` (`:136`).
- `Strict-Transport-Security`: `"max-age=63072000; includeSubDomains; preload"` (`:137`).
- `Referrer-Policy`: `"strict-origin-when-cross-origin"` (`:138`).
- `Permissions-Policy`: `"geolocation=(), camera=(), microphone=(), payment=()"` (`:139`).
- `Cache-Control`: `"no-store, no-cache, must-revalidate, private"` (`:140`).
- `Access-Control-Allow-Origin`: `"http://127.0.0.1:8443"` (strictly origin-bound, not wildcard `*`) (`:213`).

### 5.3 Request Protection Guards
1. Cross-Origin Request Forgery (CSRF) Guard (`tactical_web_console.py:160-167`):
   Inspects incoming `Origin` header on state-changing `POST` requests. If `Origin` is present and not contained within `ALLOWED_ORIGINS` (`http://127.0.0.1:8443`, `http://localhost:8443`, `https://127.0.0.1:8443`, `https://localhost:8443`), execution is aborted with `403 Forbidden` (`{"error": "Cross-origin POST rejected"}`).
2. Maximum Body Size Guard (`tactical_web_console.py:169-180`):
   Enforces `MAX_POST_BODY = 1048576` bytes (1 MiB). Rejects non-integer or negative `Content-Length` headers with `400 Bad Request`, and requests exceeding 1 MiB with `413 Payload Too Large` prior to buffer allocation.

### 5.4 HTTP API Routes Specification

| Method | Path | Authentication / Authorization | Parameters / Body | Response Payload / Behavior | Implementation Source |
|---|---|---|---|---|---|
| `GET` | `/` or `""` | Localhost bind | None | Rewrites path to `/index.html` and streams static asset. | `tactical_web_console.py:144-146` |
| `GET` | `/api/status` | Localhost bind | None | Returns JSON status: PCR measurements (`0`, `7`, `11`), hardware TPM lock state, pacing cadence (20 ms), quantum frame size (1232 B), and five pillars telemetry. | `tactical_web_console.py:217-306` |
| `GET` | `/api/sovereignty` | Localhost bind | None | Returns benchmark comparison matrix comparing prototype parameters against commercial platforms. | `tactical_web_console.py:637-647` |
| `POST` | `/api/send` | Same-origin guard | `{"sender": str, "message": str}` | Formats simulated loopback message cell with acknowledgment; returns `status: "TRANSMITTED_SIMULATED"`, `simulated: true`. | `tactical_web_console.py:307-319` |
| `POST` | `/api/eam` | Dual ML-DSA-87 signatures | `directive`, `originator`, `officer_1_id`, `officer_2_id`, `officer_1_pk_b64`, `officer_2_pk_b64`, `officer_1_sig_b64`, `officer_2_sig_b64`, `timestamp_utc`, `expires_at` | Verifies dual-custody authorization. Validates freshness ($\pm 120$s), distinct custodians, ML-DSA-87 public keys (2592 bytes), and signatures. Detects replay. | `tactical_web_console.py:320-493` |
| `POST` | `/api/zgdp` | Same-origin guard | `{"message": str}` | Instantiates zero-gap session pipeline roundtrip (`PIPELINE_TYPE_NC3`), seals message, computes Shannon entropy, and verifies decryption match. | `tactical_web_console.py:494-535` |
| `POST` | `/api/cot` | Same-origin guard | `{"callsign": str, "lat": float, "lon": float, "type": str}` | Emits Cursor-on-Target compact beacon. Explicitly marked `signature: "NOT_SIGNED_LOCAL_DEMO"`, `signature_verified: false`. | `tactical_web_console.py:536-569` |
| `POST` | `/api/diode/send` | Same-origin guard | `{"fileName": str}` | Software emulation fixture for Cauchy-Reed-Solomon GF($2^8$) unidirectional framing (10 data + 3 parity chunks). Marked `simulated: true`. | `tactical_web_console.py:570-582` |
| `POST` | `/api/zeroize` | Token: `confirm: "ZEROIZE-ALL"` | `{"confirm": "ZEROIZE-ALL"}` | Two-person authorization check. If token is invalid, returns 400. If valid, invokes `secure_shred_file("monotonic.state")` (3-pass overwrite). | `tactical_web_console.py:583-627` |
| `POST` | `/api/drill` | Same-origin guard | None | Executes automated two-terminal diagnostic drill via `secure_p2p.run_automated_two_terminal_drill()`. | `tactical_web_console.py:628-636` |

### 5.5 Dual-Custody Verification Workflow (`tactical_web_console.py:59-95, 320-493`)
The Emergency Action Message (EAM) endpoint enforces two-party verification:
1. Canonical Serialization (`canonical_web_eam_bytes`):
   ```python
   material = {
       "preamble": EAM_PREAMBLE,
       "classification": EAM_CLASSIFICATION,
       "directive": directive,
       "originator": originator,
       "officer_1": officer_1_id,
       "officer_2": officer_2_id,
       "timestamp_utc": round(float(timestamp_utc), 3),
       "expires_at": round(float(expires_at), 3),
   }
   return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
   ```
2. Validation Gates:
   - Simulation Fallback: If no custody fields are supplied, returns `status: "EAM_SIMULATED_DEMO_FIXTURE"`, `dual_custody: "UNVERIFIED_NO_CUSTODY_PACKAGE_SUPPLIED"` (`:343-359`).
   - Incomplete Package: If partial custody fields are provided, returns `400 Bad Request` with `status: "EAM_REJECTED_INCOMPLETE_CUSTODY_PACKAGE"` (`:363-369`).
   - Single Custodian Rejection: If `officer_1_id == officer_2_id`, returns `403 Forbidden` (`:383-389`).
   - Freshness & Expiry Window: Requires `abs(now - ts) <= 120.0` and `expires_at > now`; returns `403 Forbidden` (`:391-398`).
   - Key Decoding: Requires 2592-byte base64-decoded public keys (`expected_len=2592`); returns `400 Bad Request` on invalid length or base64 decoding errors (`:400-410`).
   - Provisioned Key Binding: Resolves IDs via `load_officer_public_key()`. Rejects self-asserted key mismatches (`:417-437`). In production mode, unprovisioned custodians trigger `403 Forbidden` (`:438-444`).
   - Signature Verification: Uses `liboqs_wrapper.LibOQS_MLDSA_87().verify()` (NIST FIPS 204) to verify signatures against canonical bytes. Returns `403 Forbidden` on verification failure (`:450-470`).
   - Replay Suppression: Computes SHA3-512 over canonical bytes. Stores digest with timestamp under `_eam_replay_lock`. Enforces `_EAM_REPLAY_TTL_SECONDS = 3600.0`. Replays return `409 Conflict` with `status: "EAM_REPLAY_REJECTED"` (`:85-95, 472-478`).

---

## 6. Data Formats and Byte Layouts

### 6.1 Safety Number Decimal String Representation
- Digest: 64-byte SHA3-512 digest ($512$ bits).
- Number Value: $V = \sum_{j=0}^{63} \text{byte}[j] \cdot 256^{63-j}$.
- Decimal String: $D = \text{str}(V)\text{.zfill}(48)[-48:]$.
- Grouping: 12 blocks of 4 digits:
  ```
  DDDD DDDD DDDD DDDD DDDD DDDD DDDD DDDD DDDD DDDD DDDD DDDD
  ```
- Total Length: 59 ASCII characters.

### 6.2 Sealed Pin Store Envelope Layout
```
+-------------------------------------------------------------+
| Magic Header: "PINENC_V1:" (10 bytes ASCII)                 |
+-------------------------------------------------------------+
| Initialization Vector / Nonce: 12 bytes CSPRNG random bytes |
+-------------------------------------------------------------+
| AES-256-GCM Ciphertext: Variable length JSON payload        |
+-------------------------------------------------------------+
| GCM Authentication Tag: 16 bytes                            |
+-------------------------------------------------------------+
```
- Additional Authenticated Data (AAD): `b"PinsStore::v1"`.

---

## 7. Cryptographic Algorithms and Standards References

| Algorithm | Standards Reference | Exact Implementation Location | Verification Evidence |
|---|---|---|---|
| SHA3-512 | NIST FIPS 202 | `hashlib.sha3_512` (`ui/safety_numbers.py:62, 71`, `tactical_web_console.py:88, 332`) | `tests/test_production_tier4_tactical_commands.py:85` |
| ML-DSA-87 | NIST FIPS 204 | `liboqs_wrapper.LibOQS_MLDSA_87` (`tactical_web_console.py:451-454`) | `tests/test_audit4_remediations_2026_10_17.py:232` |
| AES-256-GCM | NIST SP 800-38D | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` (`ui/safety_numbers.py:126, 194`) | `tests/test_f01_identity_anchor.py:66` |
| scrypt | IETF RFC 7914 | `hashlib.scrypt` ($N=32768, r=8, p=1, dklen=32$) (`ui/safety_numbers.py:112-115`) | Code Inspection (`ui/safety_numbers.py:112`) |
| HMAC-SHA512 | IETF RFC 2104 | `hmac.new(..., hashlib.sha512)` (`ui/safety_numbers.py:138-139`) | Code Inspection (`ui/safety_numbers.py:138`) |
| Cauchy-Reed-Solomon GF($2^8$) | Simulated Fixture | Parameterized fixture ($10$ data, $3$ parity) (`tactical_web_console.py:570-582`) | Code Inspection (`tactical_web_console.py:577`) |

---

## 8. Dependencies and Environment Variables

### 8.1 Runtime Environment Variables
- `P2P_PIN_KEK`: String / hex passphrase used to derive the 256-bit AES-GCM envelope key via scrypt for `pins.json` (`ui/safety_numbers.py:37`).
- `P2P_STORAGE_PASSPHRASE`: Fallback storage passphrase if `P2P_PIN_KEK` is unset (`ui/safety_numbers.py:37`).
- `P2P_DISABLE_DANE`: Set to `"false"` by default during banner rendering (`ui/display.py:30`).

### 8.2 Software Dependencies
- Python 3 Standard Library: `hashlib`, `hmac`, `json`, `os`, `secrets`, `tempfile`, `http.server`, `socketserver`, `getpass`, `asyncio`, `platform`, `subprocess`, `ipaddress`.
- Third-Party Libraries:
  - `cryptography` (for `AESGCM` envelope encryption).
  - `liboqs` / `liboqs_wrapper` (for native ML-DSA-87 signature verification).

---

## 9. Failure Modes and Resilience Behavior

- Sealed Pin Store Without Passphrase: If `pins.json` begins with `b"PINENC_V1:"` and neither `P2P_PIN_KEK` nor `P2P_STORAGE_PASSPHRASE` is set, `load_pins()` raises `ValueError("pins.json is sealed but P2P_PIN_KEK / P2P_STORAGE_PASSPHRASE is not set (fail-closed)")` (`ui/safety_numbers.py:125`).
- Unsealed Pin Store in Production: In production environments, attempting to save unencrypted pins raises `ValueError("FAIL-CLOSED: refusing plaintext pins.json write in production...")` (`ui/safety_numbers.py:223`).
- Stale or Expired EAM Directives: Timestamps with deviation $> 120$ seconds or expiry $\le$ current time are rejected with `403 Forbidden` (`tactical_web_console.py:394`).
- Duplicate or Single Custodians: Dual-custody requests with identical officer identifiers are rejected with `403 Forbidden` (`tactical_web_console.py:384`).
- Replay Attempts: Replayed dual-custody packages within the 3600-second TTL return `409 Conflict` (`tactical_web_console.py:474`).
- Request Overflows: Web requests exceeding 1 MiB return `413 Payload Too Large` without reading the full socket buffer (`tactical_web_console.py:176`).

---

## 10. Test Coverage and Verification Evidence

Automated test execution commands and results verifying the `ui_presentation` subsystem:

1. Windows CP1252 Terminal Compatibility:
   - Command: `pytest tests/test_cp1252_encoding_safety.py`
   - Output: 5 passed in 0.82s.
   - Verified: All banner, display, prompt, feedback, and error strings encode cleanly into `cp1252` without raising `UnicodeEncodeError`.
2. No-Emoji Formatting Verification:
   - Command: `pytest tests/test_no_emoji_property.py`
   - Output: 5 passed in 8.45s.
   - Verified: Production Python files contain zero unicode emojis.
3. Web Telemetry Console REST Endpoints & Security Headers:
   - Command: `pytest tests/test_tactical_web_console.py`
   - Output: 8 passed in 0.95s.
   - Verified: `/api/status`, `/api/sovereignty`, `/api/send`, `/api/eam` (signature string rejection and incomplete package rejection), `/api/zgdp`, `/api/cot`, and DISA ASD STIG compliant security headers.
4. Web Console Hardening & Dual-Custody Signature Verification:
   - Command: `pytest tests/test_audit4_remediations_2026_10_17.py -k TestA4WebConsole`
   - Output: 6 passed, 20 deselected in 1.35s.
   - Verified: Real dual-officer ML-DSA-87 signature verification and replay rejection (`test_a4_09_eam_real_dual_verification_and_replay`), forged signature rejection (`test_a4_09_eam_forged_signature_rejected`), single-custodian rejection (`test_a4_09_eam_single_custodian_rejected`), cross-origin CSRF guard (`test_a4_09_post_origin_guard`), 1 MiB body cap (`test_a4_09_post_body_cap`), and zeroization confirmation requirement (`test_a4_09_zeroize_requires_confirmation`).
5. Symmetric Safety Number Calculation:
   - Command: `pytest tests/test_production_tier4_tactical_commands.py -k test_safety_numbers_generation_and_symmetry`
   - Output: 1 passed, 12 deselected in 0.82s.
   - Verified: Symmetric agreement `safety_numbers(A, B) == safety_numbers(B, A)`, exact 59-character length, 12 groups of 4 decimal digits.
6. TOFU Pinning and Loopback Rejection:
   - Command: `pytest tests/test_audit_confirmed_regressions.py -k "safety or pin or finding_12 or finding_47"`
   - Output: 3 passed, 10 deselected in 5.91s.
   - Verified: TOFU first-contact fails closed on unverified keys (`test_finding_12_tofu_blocks_pinning_unverified`), loopback host pinning is rejected (`test_finding_47_tls_hostname_check_and_loopback_pinning`).

---

## 11. Not Implemented / External Dependencies / Simulated Behavior

1. Unimplemented Profile Switching and Deletion:
   `ui/menus.py:334-339` (`_switch_user_profile`) and `ui/menus.py:361-366` (`_delete_user_profile`) print `"This feature is not yet implemented."` and perform no state mutation.
2. Simulated Web Chat:
   `tactical_web_console.py:307-319` (`_handle_api_send`) returns a simulated loopback response (`status: "TRANSMITTED_SIMULATED"`). It does not transmit data over the live peer-to-peer transport socket.
3. Software Emulation Optical Diode:
   `tactical_web_console.py:570-582` (`_handle_api_diode_send`) returns a simulated Cauchy-Reed-Solomon telemetry response (`simulated: true`). Physical simplex optical diode hardware is not interfaced by this endpoint.
4. Unsigned Web Console CoT Beacons:
   `tactical_web_console.py:536-569` (`_handle_api_cot`) emits unsigned Cursor-on-Target demonstration beacons (`signature: "NOT_SIGNED_LOCAL_DEMO"`, `signature_verified: false`). Operational signed CoT flows reside in `cjadc2_tactical_cot.py`.

---

## 12. Discrepancies: Promotional / Unsubstantiated Terminology in User Presentation Interfaces

1. Discrepancy in Previous Audit Documentation:
   Previous documentation in `docs/audit/modules/ui_presentation.md:12, 28-34` described the safety number format as "8 blocks of 6 digits" derived from a 4-byte slice modulo $10^6$ algorithm. In the actual code (`ui/safety_numbers.py:25-30, 65-75`), the layout is 12 blocks of 4 digits derived from `int.from_bytes(digest, "big")`.
2. Discrepancy in Previous Pin Store Specification:
   Previous documentation cited HMAC-SHA256 over `pinned_keys.json` (`docs/audit/modules/ui_presentation.md:41`), and claim UIP-04 cited HMAC-SHA384 (`docs/audit/claims/ui_presentation_claims.md:10`). In reality, `ui/safety_numbers.py:24, 137-139, 194-198` uses `pins.json`, HMAC-SHA512 record authentication, and an scrypt + AES-256-GCM envelope.
3. Promotional Terminology in UI Strings:
   Multiple user presentation interfaces emit unverified operational or classification terminology:
   - `ui/display.py:405` outputs `"secure SECURITY STATUS REPORT"`.
   - `ui/display.py:451` outputs `"[DEFENSE] DOD CSRMC PHASE 5 OPERATIONS & TACTICAL DDIL RESILIENCE"`.
   - `ui/display.py:457` outputs `"[NETWORK] CJADC2 TACTICAL DATA FABRIC & CRYPTO-AGILITY"`.
   - `ui/display.py:679` outputs `"secure Compliance : NIST LEVEL 5"`.
   - `tactical_web/index.html:16` outputs `"TOP SECRET // CNSA SUITE 2.0 // NOFORN // SOVEREIGN MILITARY DATA PLANE"`.
   - `tactical_web/index.html:29` outputs `"DESTROYER TACTICAL P2P COMMAND CENTER"`.
   - `tactical_web_console.py:658` prints `"[DEFCON-1 TACTICAL P2P WEB COMMAND CENTER ONLINE]"`.
   These strings represent presentation-layer cosmetic fixtures and do not indicate formal government accreditation or physical data diode containment.

---

## 13. Open Questions for Author

1. Should `ui/display.py` implement an automatic terminal scrollback buffer flush (such as sending ANSI `\033[3J` or platform-specific console clearing APIs) upon session termination to prevent plaintext remnants in terminal buffers?
2. Are the stub methods `_switch_user_profile()` and `_delete_user_profile()` in `ui/menus.py:334-366` scheduled for implementation, or should the corresponding menu options (2 and 4) be omitted from `handle_user_management()`?
3. Should the diagnostic web console (`tactical_web_console.py`) incorporate an option to bind to an authenticated Unix domain socket rather than `127.0.0.1:8443` to restrict local inter-process access on multi-user hosts?


---

## 14. Known Limitations and Residual Risks

1. **Terminal ANSI Injection Risk:**
   While control sequences are sanitized before presentation (`ui/display.py:80-110`), malformed UTF-8 sequences or terminal emulator vulnerabilities (e.g. DEC private mode escape sequences) could theoretically trigger terminal emulator misbehavior if raw unvalidated peer nicknames are rendered.
2. **Local HTTP Surface in Development Mode:**
   When running the diagnostic web console (`tactical_web_console.py`), the HTTP daemon binds to `127.0.0.1:8443` with self-signed TLS certificates. Local unprivileged users on the same host can probe the web console API endpoints unless network namespaces or container boundaries are applied.
3. **Safety Number Visual Truncation:**
   Safety numbers are computed as 60-digit decimal representations of SHA-384 fingerprint digests (`ui/safety_numbers.py:45-70`). Operators performing out-of-band verification must check all 12 five-digit blocks; partial visual comparison introduces birthday attack vulnerabilities against modified key material.
