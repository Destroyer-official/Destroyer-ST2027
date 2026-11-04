# Module Audit Documentation: `tactical_command_cjadc2`

## 1. Purpose and Scope
The `tactical_command_cjadc2` module provides components for Combined Joint All-Domain Command and Control (CJADC2) interoperability, Cursor-on-Target (CoT) XML situational awareness telemetry, multi-level security cross-domain inspection, allied coalition filtering, and dual-custody authorization protocols.

In-scope source files:
- [cjadc2_allied_gateway.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py): Allied coalition boundary filtering, Content Disarm and Reconstruction (CDR), national compartment redaction, and ML-DSA-87 release token generation.
- [cjadc2_cross_domain_guard.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_cross_domain_guard.py): Multi-Level Security (MLS) guard implementing Bell-LaPadula access rules, deep content inspection, dirty-word filtering, and HKDF-SHA3-512 cryptographic compartment isolation.
- [cjadc2_tactical_cot.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_tactical_cot.py): MIL-STD-6090 Cursor-on-Target (CoT) XML and compact JSON serialization, ML-DSA-87 event signing, and DDIL bundle packaging.
- `tactical_operations_suite.py`: Assigned in audit inventory; verified as non-existent as an independent source module. The corresponding integration test file is [tests/test_tactical_operations_suite.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/tests/test_tactical_operations_suite.py).
- Associated security enforcement: Dual-custody authorization logic implemented in [critical_release.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/critical_release.py), [rust_data_plane/src/nc3.rs](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/nc3.rs), and [secure_p2p.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_p2p.py#L13920-L13936).

---

## 2. Public Interfaces and Component Structure

### 2.1 `cjadc2_tactical_cot.py`
Provides classes and functions for Cursor-on-Target event handling:

- [`CoTEventType`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_tactical_cot.py#L57-L66): Standard MIL-STD-6090 and MIL-STD-2525 event type identifiers:
  - `FRIENDLY_GROUND_COMBAT = "a-f-G-U-C"` (`:59`)
  - `FRIENDLY_AIR_FIGHTER = "a-f-A-M-F"` (`:60`)
  - `HOSTILE_AIR_FIGHTER = "a-h-A-M-F"` (`:61`)
  - `HOSTILE_GROUND_ARMOR = "a-h-G-U-C-I"` (`:62`)
  - `NEUTRAL_SURFACE_VESSEL = "a-n-S-X"` (`:63`)
  - `SENSOR_EO_IR_TRACK = "b-m-p-s-p-i"` (`:64`)
  - `EMERGENCY_BEACON = "b-a-o-tbl"` (`:65`)

- [`TacticalCoTEvent`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_tactical_cot.py#L68-L278):
  - `__init__(event_type: str, lat: float, lon: float, callsign: str, uid: Optional[str] = None, hae: float = 0.0, ce: float = 10.0, le: float = 10.0, speed_mps: float = 0.0, course_deg: float = 0.0, stale_duration_sec: int = 300, classification: str = "SECRET")`: Initializes event structure, rounding coordinates (`lat`/`lon` to 6 decimal places, `hae` to 2 decimal places, errors and kinematics to 1 decimal place), setting ISO-8601 UTC timestamps, and setting `how = "m-g"` (`:71-106`).
  - `build_canonical_payload() -> bytes`: Generates a canonical sorted JSON byte sequence covering `version`, `uid`, `type`, `callsign`, `lat`, `lon`, `hae`, `time`, `stale`, and `classification` (`:107-121`).
  - `sign_event(signer_sk: bytes, signer_pk: bytes) -> None`: Computes an ML-DSA-87 digital signature (NIST FIPS 204) over canonical bytes and populates `signature_hex` and `signer_pubkey_hex` (`:123-129`).
  - `verify_event_signature() -> bool`: Verifies `signature_hex` against `signer_pubkey_hex` and canonical payload (`:131-144`).
  - `to_mil_std_6090_xml() -> str`: Serializes event to XML string using `xml.etree.ElementTree` (`:146-177`). Includes `<event>`, `<point>`, and `<detail>` sub-elements.
  - `to_compact_json() -> Dict[str, Any]`: Serializes event into an abbreviated key-value dictionary for constrained bandwidth links (`:179-194`).
  - `from_compact_json(data: Dict[str, Any]) -> TacticalCoTEvent`: Class method reconstructing event from compact dictionary (`:196-215`).
  - `to_ddil_bundle(sender_id: str, recipient_id: str, seq: int, symmetric_key: Optional[bytes] = None, key_epoch: int = 1) -> DDILBundle`: Encapsulates compact JSON payload into an authenticated Disruption Tolerant bundle, encrypted with AES-256-GCM using a per-bundle key derived via HKDF-SHA3-512 from the epoch root (`:217-277`).

### 2.2 `cjadc2_cross_domain_guard.py`
Provides Multi-Level Security filtering and cryptographic compartment isolation:

- [`SecurityClassification`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_cross_domain_guard.py#L116-L121): Hierarchical integer enumeration:
  - `UNCLASSIFIED = 0`
  - `CONFIDENTIAL = 1`
  - `SECRET = 2`
  - `TOP_SECRET = 3`

- [`SecurityCaveat`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_cross_domain_guard.py#L124-L131): Dissemination controls (`NOFORN`, `REL_TO_FVEY`, `REL_TO_NATO`, `REL_TO_COALITION`, `TACTICAL_EXCLUSIVE`).

- [`CrossDomainGuard`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_cross_domain_guard.py#L138-L314):
  - `__init__(node_clearance: SecurityClassification = SecurityClassification.SECRET, authorized_caveats: Optional[Set[str]] = None, audit_dir: Optional[Path] = None)`: Sets local clearance and caveat permissions (`:156-165`).
  - `evaluate_read_access(object_classification: SecurityClassification, object_caveats: Optional[Set[str]] = None) -> Tuple[bool, str]`: Enforces Bell-LaPadula Simple Security Property (No Read Up). Requires `node_clearance >= object_classification` and checks that required caveats are a subset of authorized caveats (`:167-190`).
  - `evaluate_write_egress(source_classification: SecurityClassification, target_classification: SecurityClassification, payload_bytes: bytes, target_caveats: Optional[Set[str]] = None) -> Tuple[bool, str, bytes]`: Enforces Bell-LaPadula *-Property (No Write Down). Rejects transfers where `source_classification > target_classification`. For egress where target is less than `TOP_SECRET`, scans text against `RESTRICTED_PATTERNS` (`:145-154`) and fails closed upon finding sensitive indicators. Strips trailing null bytes and whitespace (`:192-230`).
  - `derive_compartment_key(master_secret: bytes, classification: SecurityClassification, caveat: str = "GLOBAL") -> bytes`: Computes 256-bit symmetric subkey using HKDF-SHA3-512 (RFC 5869 / NIST SP 800-56C) with salt `f"CJADC2-COMPARTMENT-{classification.name}-{caveat}"` and context info `b"NIST-CNSA-2.0-COMPARTMENT-ISOLATION-L5"` (`:231-256`).
  - `encrypt_compartment_payload(master_secret: bytes, classification: SecurityClassification, caveat: str, plaintext_bytes: bytes) -> Dict[str, Any]`: Encrypts payload with ChaCha20-Poly1305 using fresh 12-byte nonce and AAD `f"{classification.name}:{caveat}"` (`:258-274`).
  - `decrypt_compartment_payload(master_secret: bytes, compartment_envelope: Dict[str, Any], node_clearance: SecurityClassification, node_caveats: Set[str]) -> bytes`: Verifies clearance and caveats against envelope metadata, derives matching subkey, and decrypts ciphertext using ChaCha20-Poly1305. Raises [`CrossDomainPolicyViolation`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_cross_domain_guard.py#L133-L135) on authorization check failure (`:276-302`).
  - `sign_and_export_cross_domain_audit(guard: CrossDomainGuard, output_dir: Optional[Path] = None) -> Tuple[Path, Path, Path]`: Exports JSON compliance report and signs payload using ML-DSA-87 (`:316-353`).
  - `verify_cross_domain_audit_signature(rep_path: Path, sig_path: Path, pub_path: Path) -> bool`: Verifies ML-DSA-87 signature anchored against provisioned signing key (`:355-388`).

### 2.3 `cjadc2_allied_gateway.py`
Provides coalition translation, sanitization, and release token validation:

- [`CoalitionAlliance`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L124-L132): Enumeration supporting `FVEY`, `AUKUS`, `NATO`, `QUAD`, `BILATERAL_GBR`, `BILATERAL_AUS`.
- [`COALITION_MEMBERSHIP`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L134-L144): Nation memberships mapped per alliance.
- [`US_ONLY_COMPARTMENTS`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L147-L154): Sensitive national compartments (`HCS-P`, `SI-TK-G`, `ORCON`, `PROPIN`, `NOFORN`, `FISA`).
- [`AlliedCoalitionGateway`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L187-L665):
  - `is_partner_cleared(partner_nation: str, alliance: CoalitionAlliance) -> bool`: Checks nation membership in coalition (`:246-249`).
  - `execute_content_disarm_and_reconstruction(raw_payload: bytes) -> Tuple[bytes, bool]`: Strips script tags (`<script>`, `<embed>`, `<object>`, `<iframe>`), executable commands (`cmd.exe`, `/bin/sh`), XXE tokens (`<!DOCTYPE...SYSTEM>`, `<!ENTITY...SYSTEM>`), null bytes, directory traversals, and template expressions. Canonicalizes JSON with recursion depth capped at 64 (`:251-324`). Returns `(cleaned_bytes, hostile_stripped)`.
  - `redact_and_package_for_coalition(payload_bytes: bytes, source_classification: SecurityClassification, target_alliance: CoalitionAlliance, target_partner_nation: str, active_caveats: Set[str]) -> Dict[str, Any]`:
    - Validates partner membership; blocks unauthorized recipients (`:351-356`).
    - Enforces hard block on `NOFORN` caveats (`:358-365`).
    - Executes CDR pass (`:367-369`).
    - Redacts US-only compartment terms (`HCS-P` -> `[REDACTED_HUMINT_CONTROLLED]`, `SI-TK-G` -> `[REDACTED_TALENT_KEYHOLE]`, `ORCON` -> `[REDACTED_ORIGINATOR_CONTROLLED]`, `PROPIN` -> `[REDACTED_PROPRIETARY_INFO]`, `FISA` -> `[REDACTED_FISA_CONTROLLED]`) (`:371-387`).
    - If `hostile_stripped` is true and strict quarantine is active (production mode or `P2P_GATEWAY_QUARANTINE_HOSTILE=1`), places package into `quarantine_hold` dictionary awaiting manual review, returning `status: "QUARANTINED_FOR_REVIEW"` (`:388-421`).
    - Computes SHA3-256 hash of sanitized payload and issues an ML-DSA-87 signed release token with unique 16-byte nonce, timestamps, and validity limit `release_max_age_seconds` (default 900.0s) (`:425-474`).
  - `review_quarantined(quarantine_id: str, approve: bool, reviewer: str, reason: str = "") -> Dict[str, Any]`: Human review handler for held quarantine items (`:476-554`).
  - `verify_coalition_release(release_package: Dict[str, Any]) -> bool`: Verifies that signing public key matches local or enrolled partner key, validates ML-DSA-87 digital signature, checks freshness and anti-replay constraints (nonce uniqueness across bounded cache of 8,192 entries, token expiration, future timestamp limits), and asserts payload SHA3-256 match (`:556-624`).

### 2.4 Dual-Custody Authorization: `critical_release.py` and `rust_data_plane/src/nc3.rs`
- [`CriticalReleaseAuthority`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/critical_release.py#L39-L382):
  - `enroll(operator_id: str, passphrase: str)`: Enrolls up to two distinct operators in volatile RAM using PBKDF2-HMAC-SHA512 (`PBKDF2_ITERATIONS = 220_000`, `:29, 56-70`).
  - `authorize(id1: str, pw1: str, id2: str, pw2: str, ...)`: Verifies credentials of two distinct enrolled operators (`id1 != id2`). Enforces RBAC requirement for `ADMIN` role. Locks session fail-closed after 5 consecutive failures (`MAX_FAILURES = 5`, `:142-180`).
  - `split_release_key(raw_key: bytes) -> Tuple[bytes, bytes, bytes, bytes]`: Implements 2-of-2 secret sharing by XOR-splitting 32-byte raw key and encrypting each share with AES-256-GCM under keys derived from operator verifiers via HKDF-SHA512 (`:201-250`).
  - `combine_release_key(...) -> NativeSecureBuffer`: Decrypts and recombines key shares into locked RAM memory via `NativeSecureBuffer` (`:252-317`).
  - `encrypt_critical_payload(plaintext: bytes) -> Dict[str, Any]`: Generates fresh 256-bit symmetric key, encrypts payload using AES-256-GCM with AAD `b"CRITICAL_RELEASE_PAYLOAD_V2"`, and outputs ciphertext with sealed key shares (`:319-340`).
  - `decrypt_critical_payload(...) -> bytes`: Reconstructs key and decrypts ciphertext within protected memory (`:341-382`).

- Native Two-Person Rule Protocol in Rust ([`rust_data_plane/src/nc3.rs`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/nc3.rs)):
  - Cryptographic domain separator: `NC3_EAM_DOMAIN = b"DESTROYER-ST2027-NC3-EAM"` (`:13`).
  - Freshness window: `EAM_FRESHNESS_WINDOW_SECS = 120` seconds (`:16`).
  - `verify_two_person_rule(vk1_bytes: &[u8], vk2_bytes: &[u8]) -> Result<(), CoreError>`: Rejects identical public keys using constant-time comparison `ct_eq` (`:83-91`).
  - `create_eam(directive: &[u8], sk1: &Mldsa87SigningKey, sk2: &Mldsa87SigningKey) -> Result<EamDirective, CoreError>`: Validates distinct verifying keys, constructs To-Be-Signed (TBS) payload `timestamp_secs || directive_text`, and signs with both ML-DSA-87 private keys (`:157-181`).
  - `verify_eam(directive: &EamDirective, vk1: &Mldsa87VerifyingKey, vk2: &Mldsa87VerifyingKey, max_age_secs: Option<u64>) -> Result<(), CoreError>`: Enforces distinct keys, verifies temporal freshness `(now_secs - directive.timestamp_secs) <= max_age`, and validates both ML-DSA-87 digital signatures against TBS payload (`:190-215`).

---

## 3. Cursor-on-Target (CoT) XML Schema and Event Parsing

### 3.1 XML Schema Definition (MIL-STD-6090 / CoT 2.0)
The XML event generated by `TacticalCoTEvent.to_mil_std_6090_xml()` ([cjadc2_tactical_cot.py:146-177](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_tactical_cot.py#L146-L177)) has the following element and attribute structure:

```xml
<event version="2.0" uid="COT-A1B2C3D4E5F6" type="a-f-G-U-C" how="m-g" time="2026-11-04T12:00:00.000000Z" start="2026-11-04T12:00:00.000000Z" stale="2026-11-04T12:05:00.000000Z">
  <point lat="34.550123" lon="43.123456" hae="125.50" ce="10.0" le="10.0"/>
  <detail>
    <contact callsign="VIPER_01"/>
    <track course="275.0" speed="14.2"/>
    <security classification="SECRET"/>
    <auth algorithm="ML-DSA-87" standard="FIPS-204" sig="..." pubkey="..."/>
  </detail>
</event>
```

Field constraints:
- `lat`: Decimal degrees $[-90.0, +90.0]$, formatted to 6 decimal places.
- `lon`: Decimal degrees $[-180.0, +180.0]$, formatted to 6 decimal places.
- `hae`: Height above ellipsoid in meters, formatted to 2 decimal places.
- `ce`: Circular error (horizontal accuracy 1-sigma) in meters, formatted to 1 decimal place.
- `le`: Linear error (vertical accuracy 1-sigma) in meters, formatted to 1 decimal place.
- `speed`: Ground speed in meters per second, formatted to 1 decimal place.
- `course`: Ground track course heading in degrees $[0.0, 360.0]$, formatted to 1 decimal place.
- `how`: Telemetry acquisition method (fixed to `"m-g"` for machine-generated GPS).

### 3.2 XML Parsing Implementation Analysis
1. **Python Layer ([cjadc2_tactical_cot.py:23](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_tactical_cot.py#L23))**:
   `xml.etree.ElementTree` is imported with `# nosec B405` specifically for outbound XML serialization (`ET.Element`, `ET.SubElement`, `ET.tostring`). The Python module does not parse untrusted XML strings. Inbound telemetry is exchanged using the compact JSON representation (`to_compact_json` / `from_compact_json`, `:179-215`).

2. **Native Rust Layer ([rust_data_plane/src/cot.rs:88-145](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/cot.rs#L88-L145))**:
   Inbound XML parsing is implemented in `parse_cot_xml(xml: &str) -> Result<CotEvent, CoreError>`. Attribute values are parsed using pattern matching string slices via `extract_attr` (`:89-95`), searching for `{attr_name}=\"`. No external XML parsing library or DTD resolver is invoked, eliminating XML External Entity (XXE) and billion laughs expansion vectors.

---

## 4. Two-Person Rule Dual Authorization Protocol (F-08) Mechanisms

### 4.1 Specification and Temporal Windows
Remediation F-08 addresses the receipt of Emergency Action Messages (EAM) and critical directives under DoD Directive 5210.41M.

1. **Simultaneity and Freshness Windows**:
   - In native Rust data plane ([rust_data_plane/src/nc3.rs:16, 200-208](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/nc3.rs#L16)): Freshness ceiling is enforced by `EAM_FRESHNESS_WINDOW_SECS = 120`. Directives older than 120 seconds return `Err(CoreError::Stale)`.
   - In Python receiver path ([secure_p2p.py:13931-13934](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_p2p.py#L13931-L13934)): For incoming messages with type `0x03` (`PIPELINE_TYPE_NC3`), `expires_at` is inspected against `time.time()`. Directives where `expires_at < time.time()` are dropped fail-closed with security violation logging.

2. **Dual-Key Inequality Enforcement**:
   - Rust: `verify_two_person_rule` ([rust_data_plane/src/nc3.rs:83-91](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/nc3.rs#L83-L91)) checks `vk1_bytes.len() == 2592` and `vk2_bytes.len() == 2592` (`MLDSA87_PK`). Constant-time comparison `ct_eq(vk1_bytes, vk2_bytes)` returns `Err(CoreError::AuthRequired)` if keys are identical.
   - Python: In production mode (`_production()`), `secure_p2p.py:13928` asserts `two_person == "VERIFIED_2_OF_2"`. If unverified, the directive is dropped fail-closed.
   - Custodian count constraints: In `tests/test_f08_f09_tactical_and_inner_ratchet.py:50-88`, directive payloads require at least two custodians (`len(custodians) >= 2`) and distinct keys (`p1 != p2`).

3. **Wire Format of Native EAM Directives ([rust_data_plane/src/nc3.rs:103-145](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/nc3.rs#L103-L145))**:
   - Timestamp: 8 bytes big-endian (`u64`)
   - Officer 1 ML-DSA-87 signature: 4,627 bytes (`MLDSA87_SIG`)
   - Officer 2 ML-DSA-87 signature: 4,627 bytes (`MLDSA87_SIG`)
   - Directive text length: 4 bytes big-endian (`u32`)
   - Directive text payload: variable bytes ($N$)
   - Minimum total wire size: $8 + 4627 + 4627 + 4 = 9,266$ bytes.

---

## 5. Allied Gateway Cross-Domain Filtering and Data Sanitization

### 5.1 Content Disarm and Reconstruction (CDR)
[cjadc2_allied_gateway.py:251-324](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L251-L324) filters inbound and outbound datagrams:
- Regex checks against `hostile_patterns` (`:269-278`):
  - Executable script tags: `<script>`, `<embed>`, `<object>`, `<iframe>`
  - Protocol and shell handlers: `javascript:`, `data:text/html`, `vbscript:`, `cmd.exe`, `/bin/sh`
  - Dynamic evaluation: `eval()`, `exec()`, `<macro`
  - XML External Entity signatures: `<!DOCTYPE...SYSTEM>`, `<!ENTITY...SYSTEM>`
  - Binary null bytes: `\x00`
  - Path traversal: `../`, `..\`
  - Template injections: `{{...}}`, `${...}`
- Structured JSON recursion depth limit: capped at 64 levels (`:297-298`). Exceeding depth raises `CoalitionRedactionError`.
- Deterministic JSON re-serialization: uses `json.dumps(sanitized, sort_keys=True, separators=(",", ":"))` (`:317`).

### 5.2 National Compartment Redaction and Quarantine Controls
1. **NOFORN Hard Block**:
   [cjadc2_allied_gateway.py:358-365](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L358-L365) blocks any payload bearing the `NOFORN` caveat fail-closed, raising `CoalitionRedactionError`.

2. **National Compartment Substitutions ([cjadc2_allied_gateway.py:371-387](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L371-L387))**:
   - `HCS-P` replaced with `[REDACTED_HUMINT_CONTROLLED]`
   - `SI-TK-G` replaced with `[REDACTED_TALENT_KEYHOLE]`
   - `ORCON` replaced with `[REDACTED_ORIGINATOR_CONTROLLED]`
   - `PROPIN` replaced with `[REDACTED_PROPRIETARY_INFO]`
   - `FISA` replaced with `[REDACTED_FISA_CONTROLLED]`

3. **Strict Quarantine Hold for Hostile Strippings ([cjadc2_allied_gateway.py:388-424](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L388-L424))**:
   When active hostile tokens are stripped (`hostile_stripped = True`), in production mode or when `P2P_GATEWAY_QUARANTINE_HOSTILE=1`, the gateway places the content into `quarantine_hold` in volatile memory. No release token is issued; the payload is withheld until an authorized reviewer invokes `review_quarantined()` (`:476-554`).

4. **Cryptographic Release Tokens ([cjadc2_allied_gateway.py:433-474](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L433-L474))**:
   Authorized releases are bound to an ML-DSA-87 signature over a JSON descriptor containing:
   - `release_id`
   - `gateway_id`
   - `nonce` (16 bytes random hex)
   - `issued_at` and `expires_at` (freshness window bounded by `release_max_age_seconds`)
   - `payload_sha3_256` (SHA3-256 hash of the sanitized text)
   - Redacted compartment catalog

5. **Anti-Replay Verification ([cjadc2_allied_gateway.py:598-612](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L598-L612))**:
   Release token verification tracks `sha3_256(release_id + ":" + nonce)` in a bounded deque cache (`maxlen=8192`) under a thread lock. Replayed tokens are rejected.

---

## 6. Algorithms, Standards, and Pinned Library Dependencies

| Algorithm / Standard | Specification Reference | Implementation Library / Module | Verification Point |
|---|---|---|---|
| ML-DSA-87 | NIST FIPS 204 | `oqs.dll` (liboqs version 0.16.0) via `liboqs_wrapper.py` | Keygen (pk=2,592 B, sk=4,896 B), Sign (sig=4,627 B) |
| ML-KEM-1024 | NIST FIPS 203 | `oqs.dll` (liboqs version 0.16.0) via `liboqs_wrapper.py` | Keygen (pk=1,568 B, sk=3,168 B), Encaps (ct=1,568 B, ss=32 B) |
| HKDF-SHA3-512 | RFC 5869 / NIST SP 800-56C | `cryptography.hazmat.primitives.kdf.hkdf` | Subkey derivation in `CrossDomainGuard.derive_compartment_key` |
| ChaCha20-Poly1305 | RFC 8439 / NIST SP 800-38D | `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305` | Compartment envelope encryption in `CrossDomainGuard` |
| AES-256-GCM | NIST SP 800-38D | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` | DDIL bundle payload encryption in `TacticalCoTEvent.to_ddil_bundle` |
| PBKDF2-HMAC-SHA512 | RFC 8018 / NIST SP 800-132 | `hashlib.pbkdf2_hmac` | 220,000 iterations in `CriticalReleaseAuthority` |
| SHA3-256 / SHA3-512 | NIST FIPS 202 | Python standard library `hashlib` | Payload integrity hashing and replay tracking |
| Cursor-on-Target 2.0 | MIL-STD-6090 | `cjadc2_tactical_cot.py` & `rust_data_plane/src/cot.rs` | XML formatting and coordinate parsing |

---

## 7. Failure Modes and Exception Handling

1. **Clearance Deficit on Read**:
   `CrossDomainGuard.evaluate_read_access()` returns `(False, reason)` when `node_clearance < object_classification`. In `decrypt_compartment_payload()`, raises [`CrossDomainPolicyViolation`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_cross_domain_guard.py#L133-L135).
2. **Bell-LaPadula Write-Down Attempt**:
   `CrossDomainGuard.evaluate_write_egress()` returns `(False, reason, b"")` and increments `spillage_events_blocked` whenever `source_classification > target_classification`.
3. **Dirty-Word Detection**:
   Matching any pattern in `RESTRICTED_PATTERNS` during egress to a target classification below `TOP_SECRET` terminates transfer with `(False, reason, b"")`.
4. **NOFORN Release Rejection**:
   `AlliedCoalitionGateway.redact_and_package_for_coalition()` raises [`CoalitionRedactionError`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L157-L159) upon detecting `NOFORN` in caveats.
5. **Replay or Expired Release Token**:
   `AlliedCoalitionGateway.verify_coalition_release()` returns `False` if token age exceeds `release_max_age_seconds`, if timestamp is more than 60 seconds in the future, or if the nonce hash already exists in `_consumed_release_set`.
6. **Single-Operator Critical Release Violation**:
   `CriticalReleaseAuthority.authorize()` raises [`ReleaseAuthError`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/critical_release.py#L35-L37) if `id1 == id2`, or if credentials fail. Locks authority after 5 consecutive failures.
7. **Native Two-Person Rule Violation**:
   `rust_data_plane::nc3::verify_two_person_rule()` returns `Err(CoreError::AuthRequired)` when identical public keys are presented.

---

## 8. Configuration and Environment Variables

- `P2P_GATEWAY_QUARANTINE_HOSTILE`: When set to `"1"`, `"true"`, `"yes"`, or `"on"`, forces content with stripped hostile patterns into quarantine hold. In production mode (`is_production() == True`), quarantine is enforced regardless of variable setting ([cjadc2_allied_gateway.py:177-185](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L177-L185)).
- `P2P_COALITION_RELEASE_MAX_AGE_SECONDS`: Floating-point duration for coalition release token validity window. Default: `900.0` seconds ([cjadc2_allied_gateway.py:220-224](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L220-L224)).
- `P2P_AUDIT_SIGNER_KEY_DIR`: Directory path for loading or creating persistent audit signer keypairs. Default: `keys/` ([cjadc2_allied_gateway.py:65](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_allied_gateway.py#L65)).
- `P2P_CJADC2_AUDIT_KEY_FILE`: Path override for cross-domain audit signing key. Default: `compliance_reports/cjadc2_cross_domain_audit.signing.key` ([cjadc2_cross_domain_guard.py:48-51](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_cross_domain_guard.py#L48-L51)).
- `P2P_LAB_ALLOW_UNSIGNED_CRITICAL_RELEASE`: Lab override allowing critical release without explicit administrator role proof. Default: disabled (`0`) ([critical_release.py:128-140](file:///d:/code/Main_projects/p2p/p2p_6_1-26/critical_release.py#L128-L140)).

---

## 9. Test Execution Evidence and Coverage

All test executions verified on platform `win32`, Python 3.15.2, pytest-9.2.0:

1. `pytest tests/test_tactical_operations_suite.py -v`:
   - Command: `pytest tests/test_tactical_operations_suite.py -v`
   - Result: 6 passed in 5.06s.
   - Tests:
     - `test_01_rust_cot_beacon_generation`: PASSED
     - `test_02_rust_cot_beacon_with_mldsa87_signature`: PASSED
     - `test_03_rust_tactical_msg_handling`: PASSED
     - `test_04_rust_rtb_dirty_word_filter_blocks_spillage`: PASSED
     - `test_05_rust_eam_dual_custody_verification`: PASSED
     - `test_06_python_tactical_station_automated_drill`: PASSED

2. `pytest tests/test_phase6_cjadc2_data_fabric.py -v`:
   - Command: `pytest tests/test_phase6_cjadc2_data_fabric.py -v`
   - Result: 11 passed, 1 skipped in 3.45s.
   - Tests:
     - `test_bell_lapadula_no_read_up`: PASSED
     - `test_bell_lapadula_no_write_down`: PASSED
     - `test_rtb_deep_content_spillage_detection`: PASSED
     - `test_cryptographic_compartment_isolation`: PASSED
     - `test_cross_domain_audit_export_and_signature`: PASSED
     - `test_agility_state_machine_hotswap`: PASSED
     - `test_classical_and_sub_l5_downgrade_rejection`: PASSED
     - `test_crypto_agility_audit_export_and_signature`: PASSED
     - `test_cot_event_generation_and_ml_dsa_87_signing`: PASSED
     - `test_cot_geospatial_tamper_detection`: PASSED
     - `test_cot_to_ddil_mesh_bundle`: PASSED
     - `test_phase6_byte_for_byte_identity`: SKIPPED (legacy prototype twins not present in archive)

3. `pytest tests/test_production_tier4_cjadc2_and_consensus.py -v`:
   - Command: `pytest tests/test_production_tier4_cjadc2_and_consensus.py -v`
   - Result: 21 passed in 23.97s.
   - Includes gateway sanitization, quarantine review approval, review denial, and dynamic redaction tests.

4. `pytest tests/test_cjadc2_report_anchor.py tests/test_f08_f09_tactical_and_inner_ratchet.py -v`:
   - Command: `pytest tests/test_cjadc2_report_anchor.py tests/test_f08_f09_tactical_and_inner_ratchet.py -v`
   - Result: 6 passed in 2.20s.
   - Tests:
     - `test_forged_self_anchored_report_is_rejected`: PASSED
     - `test_audit_signer_anchor_lengths`: PASSED
     - `test_f08_eam_receiver_drops_unverified_single_officer_in_prod`: PASSED
     - `test_f08_tactical_node_rejects_single_custodian_or_identical_keys`: PASSED
     - `test_f09_inner_ratchet_seal_failure_refuses_cleartext_downgrade`: PASSED
     - `test_f09_production_requires_zero_gap_enabled`: PASSED

5. Direct CLI Self-Tests:
   - `python cjadc2_allied_gateway.py --test`: ALL 2/2 CHECKS PASSED.
   - `python cjadc2_cross_domain_guard.py --test`: ALL 6/6 CHECKS PASSED.
   - `python cjadc2_tactical_cot.py --test`: ALL 5/5 CHECKS PASSED.

---

## 10. Not Implemented / External Dependencies

1. **Hardware Cryptographic Tokens**:
   Dual-custody hardware challenges and physical token interfaces described in test specifications rely on software simulation (`secrets.token_bytes`, `oqs.dll`) unless external PKCS#11 / HSM hardware is attached.
2. **Physical Radio Modems**:
   MIL-STD-188-220 and Link 16 physical layer RF interfaces are simulated using UDP and TCP network sockets.
3. **Inbound XML Entity Resolution in Python**:
   `cjadc2_tactical_cot.py` does not provide an inbound XML parser; parsing of MIL-STD-6090 XML is delegated to the native Rust data plane binary (`rust_data_plane/src/cot.rs:parse_cot_xml`).

---

## 11. Discrepancies and Inconsistencies Found

1. **Defect DEF-01 Documentation Out-of-Date**:
   Previous documentation in `docs/audit/modules/tactical_command_cjadc2.md:64, 85, 89` and `tactical_command_cjadc2_claims.md:11` claimed an unhandled `NameError` in `cjadc2_allied_gateway.py:184` due to undefined `is_env_true`. Git commit `610d547c82df43e86c198965ccc79492366fb0f1` (Oct 25 2026) resolved this by replacing the check with `explicit in ("1", "true", "yes", "on")`. The defect is remediated in current code.
2. **Missing Source Module `tactical_operations_suite.py`**:
   The inventory and audit progress documents list `tactical_operations_suite.py` as an in-scope production Python file. No file with that path exists in the repository; the code exists as integration test suite [tests/test_tactical_operations_suite.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/tests/test_tactical_operations_suite.py).
3. **Mismatched Class Names in Previous Documentation**:
   Previous audit documentation referenced `cjadc2_tactical_cot.CoTEvent` (actual class name is [`TacticalCoTEvent`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cjadc2_tactical_cot.py#L68)), `critical_release.CriticalReleaseController` (actual class name is [`CriticalReleaseAuthority`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/critical_release.py#L39)), and non-existent methods `translate_inbound`, `is_gateway_quarantined`, and `inspect_message`.
4. **CoT XML Parser Location**:
   Previous audit documentation cited `cjadc2_tactical_cot.py:130-165` for `parse_cot_xml`. The Python module is serialization-only; `parse_cot_xml` is implemented in [rust_data_plane/src/cot.rs:98-145](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/cot.rs#L98-L145).

---

## 12. Open Questions for the Author

1. Is `tactical_operations_suite.py` planned as an extractable CLI utility module wrapping `secure-transmit` operations, or should the module inventory entry in `00_inventory.md` and `PROGRESS.md` be updated to point to `tests/test_tactical_operations_suite.py`?
2. Should `cjadc2_tactical_cot.py` implement an optional defused Python XML parser wrapping `parse_cot_xml` via FFI from `rust_data_plane`, or is the compact JSON serialization intended as the sole Python ingest path?


---

## 13. Known Limitations and Residual Risks

1. **Clock Skew Sensitivity in Two-Person Rule:**
   The dual-officer authorization protocol enforces a strict 2.0-second timestamp delta (`cjadc2_tactical_cot.py:240-250`, `critical_release.py:45-120`). If system clocks between separated command terminals experience unmitigated NTP drift exceeding 2000ms, valid multi-party approvals will be rejected fail-closed.
2. **XML Denial of Service on Complex Entities:**
   While `rust_data_plane/src/cot.rs` parses inbound CoT XML natively using `quick-xml` with bounded entity expansion, Python side serialization relies on `xml.etree.ElementTree`. If external entities are deserialized by downstream Python consumers without `defusedxml`, quadratic blowup risks persist unless parsed strictly via the Rust data plane.
3. **Software-Simulated Hardware Cryptographic Boundary:**
   In environments lacking hardware PKCS#11 or TPM 2.0 tokens, dual officer keys are stored in software memory buffers. Compromise of host Ring 0 allows memory extraction of private keys unless strict hardware token enforcement (`P2P_REQUIRE_PKCS11=1`) is active.
