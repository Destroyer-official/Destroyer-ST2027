# Module Audit: tactical_command_cjadc2

## 1. Overview and Scope
The `tactical_command_cjadc2` module implements joint all-domain command and control (CJADC2) protocols, cross-domain boundary inspection, Cursor-on-Target (CoT) XML event processing, allied coalition gateway translation, two-person rule authorization workflows, and operator console dashboards (both terminal and local web).

The module comprises 14 product files totaling 8,254 verified lines across Python backends, shell scripts, HTML, CSS, and JavaScript:

| File Name | Lines | Verified Purpose | Primary Classes / Interface |
| :--- | :--- | :--- | :--- |
| `cjadc2_allied_gateway.py` | 863 | Coalition gateway translating NATO FMN/STANAG data models to P2P frames | `AlliedCoalitionGateway`, `GatewaySecurityPolicy` |
| `cjadc2_cross_domain_guard.py` | 482 | Cross-domain solution inspecting messages across security domain boundaries | `CrossDomainGuard`, `DomainFilterRule` |
| `cjadc2_tactical_cot.py` | 347 | XML serializer and parser for Cursor-on-Target (CoT) positional events | `CoTEvent`, `CoTPoint`, `parse_cot_xml`, `serialize_cot_xml` |
| `critical_release.py` | 382 | Two-person rule engine verifying dual officer signatures for critical directives | `CriticalReleaseController`, `ReleaseAuthorization` |
| `launch_tactical_terminals.bat` | 14 | Windows batch script starting two local tactical terminal node processes | Batch execution script |
| `launch_tactical_web.bat` | 11 | Windows batch script launching local web console server and browser tab | Batch execution script |
| `nc3_[banned-name]_command.py` | 1,786 | Dual-custody authorization and two-terminal confirmation protocols (filename note: code embeds prohibited term) | `NC3CommandEngine`, `EmergencyActionMessage` |
| `start_tactical_alpha.bat` | 6 | Windows batch script initializing primary tactical node terminal | Batch execution script |
| `start_tactical_bravo.bat` | 6 | Windows batch script initializing secondary tactical node terminal | Batch execution script |
| `tactical_operator_console.py` | 992 | Terminal curses/CLI interface for monitoring tactical datalink status and peers | `TacticalConsoleApp`, `ConsoleView` |
| `tactical_web/app.js` | 592 | Frontend client application driving operator web console interactions | Client-side JavaScript |
| `tactical_web/index.css` | 1,462 | Stylesheet defining presentation rules for local tactical operator web interface | CSS Stylesheet |
| `tactical_web/index.html` | 681 | HTML structure for operator web dashboard and real-time telemetry panels | HTML Document |
| `tactical_web_console.py` | 630 | Local HTTP server providing REST and WebSocket telemetry endpoints for web console | `TacticalWebConsoleServer`, HTTP request handlers |

---

## 2. Architecture and Subsystem Mechanics

### 2.1 Two-Person Rule and Dual-Officer Authorization
In `critical_release.py` and the command authorization module (nc3):
- **Simultaneous Custody Verification:** Critical command release directives (such as Emergency Action Messages / EAMs) require two distinct officer authorization signatures generated using independent ML-DSA-87 key pairs (`critical_release.py:80-140`).
- **Temporal Simultaneity Window:** Both signatures must be submitted within an active validity window (default 120 seconds). Signatures with time deltas exceeding this threshold are rejected fail-closed.
- **Two-Terminal Confirmation:** Directives require bidirectional verification between distinct terminal nodes (AlphaStation and BravoStation), verifying dual-terminal acknowledgement before order release.
- **Uniform Wire Padding:** Command wire packets are padded to fixed 1024-byte blocks (`test_defensive_nc3_audit.py:P0.3`) to prevent passive network observers from inferring message semantics from packet lengths.

### 2.2 Cursor-on-Target (CoT) Tactical Event Processing
In `cjadc2_tactical_cot.py`:
- **CoT Schema Elements (`cjadc2_tactical_cot.py:45-120`):**
  - `<event>`: root element specifying `version="2.0"`, `type` (e.g. `a-f-G-U-C` for friendly ground unit), `uid`, `time`, `start`, `stale`, and `how`.
  - `<point>`: spatial coordinates specifying `lat` (latitude), `lon` (longitude), `hae` (height above ellipsoid), `ce` (circular error), and `le` (linear error).
  - `<detail>`: extensible metadata container for operational payloads.
- **XXE Injection Defenses:** Parsing disables external DTD resolution and entity substitution, preventing XML External Entity (XXE) and billion-laughs expansion attacks (`cjadc2_tactical_cot.py:130-165`).

### 2.3 Cross-Domain Solution (CDS) Boundary Inspection
In `cjadc2_cross_domain_guard.py`:
- **Security Domain Tag Filtering:** Validates security markings (e.g. Unrestricted, Restricted, Highly-Restricted domains). Messages containing unrecognized or conflicting domain labels are rejected.
- **Metadata Sanitization:** Strips internal routing headers, private IP addresses, and debugging fields prior to egress.
- **Directional Diode Enforcement:** Enforces unidirectional export policies, ensuring that low-security domains cannot inject unauthorized feedback into high-security domains.

### 2.4 Allied Coalition Gateway Mechanics and Verified Defect
In `cjadc2_allied_gateway.py`:
- **Model Translation (`cjadc2_allied_gateway.py:192-260`):** Translates incoming coalition datagrams into internal P2P message formats, re-encoding tactical points and stripping unverified extensions.
- **Verified Code Bug (`cjadc2_allied_gateway.py:184`):**
  - Function `is_gateway_quarantined()` executes:
    ```python
    prod = is_production()
    explicit = os.environ.get("P2P_GATEWAY_QUARANTINE_HOSTILE", "")
    if prod:
        if explicit == "0":
            log.critical("P2P_GATEWAY_QUARANTINE_HOSTILE=0 ignored in production (quarantine enforced)")
        return True
    return is_env_true("P2P_GATEWAY_QUARANTINE_HOSTILE")
    ```
  - In non-production testing environments (`prod == False`), calling this function raises `NameError: name 'is_env_true' is not defined`. The helper `is_env_true` was never imported or implemented in `cjadc2_allied_gateway.py`. This defect causes automated tests triggering hostile gateway quarantine to crash.

### 2.5 Local Operator Web and Terminal Consoles
- **Terminal Console (`tactical_operator_console.py`):** Curses-based terminal application rendering link status, peer lists, safety number fingerprints, and throughput graphs in an ANSI terminal.
- **Web Console (`tactical_web_console.py`, `tactical_web/`):**
  - Python HTTP server listening locally (default `127.0.0.1:8080`).
  - Serves static assets: `index.html` (dashboard layout), `app.js` (DOM updates and WebSocket polling), and `index.css` (custom dark theme styling).
  - Endpoints: `/api/status`, `/api/peers`, `/api/transfers`, `/api/cot`.

---

## 3. Interfaces and Public API Surface

### 3.1 `AlliedCoalitionGateway` (`cjadc2_allied_gateway.py`)
- `translate_inbound_message(raw_bytes: bytes, source_partner: str) -> dict`: Disarms and validates foreign coalition messages.
- `translate_outbound_message(internal_msg: dict, target_partner: str) -> bytes`: Formats internal message for coalition egress.

### 3.2 `CrossDomainGuard` (`cjadc2_cross_domain_guard.py`)
- `inspect_egress(payload: bytes, source_domain: str, dest_domain: str) -> bool`: Checks data flow rules between domains.
- `sanitize_payload(payload: bytes) -> bytes`: Removes unauthorized metadata fields.

### 3.3 `CoTEvent` (`cjadc2_tactical_cot.py`)
- `to_xml() -> str`: Serializes event into CoT XML string.
- `from_xml(xml_str: str) -> CoTEvent`: Safely parses CoT XML string.

### 3.4 `CriticalReleaseController` (`critical_release.py`)
- `submit_officer_signature(directive_id: str, officer_id: str, signature: bytes) -> bool`: Records officer approval.
- `is_authorized(directive_id: str) -> bool`: Checks if dual-officer requirement and simultaneity window are met.

---

## 4. Test Evidence and Verification Results

### 4.1 Passing Test Suites
Audit verification executed the following test suites directly verifying tactical command and CJADC2 components:

1. **CJADC2 Data Fabric, Report Anchoring, and CNSA Directives:**
   - Command: `pytest tests/test_cjadc2_report_anchor.py tests/test_phase6_cjadc2_data_fabric.py tests/test_nc3_cnsa_cipher.py tests/test_tactical_web_console.py tests/test_tactical_operations_suite.py -q`
   - Result: 31 passed, 2 skipped in 3.87s.
   - Verified behaviors:
     - CoT event generation and spatial coordinate extraction (`test_phase6_cjadc2_data_fabric.py`).
     - EAM creation, two-officer signing, and receipt verification (`test_nc3_cnsa_cipher.py`).
     - Local web console endpoints `/api/status` and `/api/peers` returning HTTP 200 (`test_tactical_web_console.py`).
     - Key generation and dual-officer approval signature generation in temporary mission environments (`test_tactical_operations_suite.py`).

### 4.2 Verified Defect Failure
- In test suite `tests/test_production_tier4_cjadc2_and_consensus.py`, 3 tests fail due to the `is_env_true` `NameError` in `cjadc2_allied_gateway.py:184`.

---

## 5. Discrepancies, Limitations, and Technical Debt

1. **Uncaught NameError in Allied Gateway (`cjadc2_allied_gateway.py:184`):**
   - Verified bug: calling `is_env_true("P2P_GATEWAY_QUARANTINE_HOSTILE")` crashes with `NameError` because `is_env_true` is not defined in module scope.
2. **Promotional and Sensitive Terminology in Code Filenames and Strings:**
   - The primary command authorization file embeds prohibited terminology in its filename: `nc3_[banned-word]_command.py`.
   - `cjadc2_allied_gateway.py` and `cjadc2_cross_domain_guard.py` embed promotional uppercase strings in logging statements.
   - Cataloged for `docs/audit/discrepancies.md`.
3. **Standalone UI Coupling:**
   - `tactical_web_console.py` and `tactical_operator_console.py` operate as standalone prototype frontends rather than integrated components of the primary orchestrator service.

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
