# Module Documentation: tactical_command_cjadc2

## 1. Purpose
The `tactical_command_cjadc2` module implements Joint All-Domain Command and Control (CJADC2) protocols, Cursor-on-Target (CoT) XML event processing, cross-domain boundary inspection, allied coalition gateway translation, and two-person rule directive releases (`cjadc2_tactical_cot.py:1-347`, `cjadc2_cross_domain_guard.py:1-482`, `critical_release.py:1-382`). It provides operational dashboards via terminal CLI and local web console interfaces (`tactical_operator_console.py:1-992`, `tactical_web_console.py:1-630`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `cjadc2_tactical_cot.CoTEvent` (`cjadc2_tactical_cot.py:45-120`)
- `__init__(uid: str, cot_type: str, point: CoTPoint, how: str = "m-g", stale_sec: int = 300)`: Constructs Cursor-on-Target event (`cjadc2_tactical_cot.py:50-80`). Parameter `point` specifies `CoTPoint(lat, lon, hae, ce, le)`.
- `to_xml() -> str`: Serializes CoT event to XML string conforming to CoT Schema 2.0 (`cjadc2_tactical_cot.py:85-115`).
- `parse_cot_xml(xml_str: str) -> CoTEvent`: Safe XML parser disabling external DTD resolution and entity substitution (`cjadc2_tactical_cot.py:130-165`). Raises `ValueError` on malformed XML or missing root `<event>` element (`:140`).

#### `critical_release.CriticalReleaseController` (`critical_release.py:65-240`)
- `submit_authorization(directive_id: str, officer_id: str, signature: bytes, public_key: bytes) -> ReleaseAuthorization`: Records officer approval for critical directive release (`critical_release.py:80-140`). Verifies ML-DSA-87 digital signature. When two distinct valid officer signatures arrive within `WINDOW_SECONDS = 120`, state transitions to `APPROVED` (`:125`). Raises `AuthorizationTimeoutError` if window expires.
- `execute_release(directive_id: str) -> bytes`: Releases payload to transport queue once dual custody is verified (`critical_release.py:150-185`). Raises `UnauthorizedReleaseError` if two valid officer signatures are not present (`:160`).

#### `cjadc2_cross_domain_guard.CrossDomainGuard` (`cjadc2_cross_domain_guard.py:55-210`)
- `inspect_message(message_bytes: bytes, source_domain: str, target_domain: str) -> bool`: Filters payload crossing security classification domain boundaries (`cjadc2_cross_domain_guard.py:75-130`). Strips internal network routing headers and private IP addresses. Returns `True` if message conforms to export policy; raises `CrossDomainViolationError` otherwise (`:110`).

#### `cjadc2_allied_gateway.AlliedCoalitionGateway` (`cjadc2_allied_gateway.py:70-260`)
- `translate_inbound(datagram: bytes) -> bytes`: Translates coalition NATO STANAG/FMN format into internal P2P message frame (`cjadc2_allied_gateway.py:90-140`).
- `is_gateway_quarantined() -> bool`: Evaluates whether coalition gateway is currently quarantined (`cjadc2_allied_gateway.py:175-190`).

#### `tactical_web_console.TacticalWebConsoleServer` (`tactical_web_console.py:80-260`)
- `start(host: str = "127.0.0.1", port: int = 8080) -> None`: Starts local HTTP and WebSocket server serving web console dashboard (`tactical_web_console.py:95-130`).
- `broadcast_telemetry(data: dict) -> None`: Streams link status, active peer counts, and throughput metrics to connected browser clients (`tactical_web_console.py:140-175`).

## 3. Data Formats and Byte Layouts

### 3.1 Cursor-on-Target XML Schema (`cjadc2_tactical_cot.py:45-120`)
- Standard CoT 2.0 XML representation:
  ```xml
  <event version="2.0" uid="TRACK-001" type="a-f-G-U-C" time="2026-11-04T00:00:00Z" start="2026-11-04T00:00:00Z" stale="2026-11-04T00:05:00Z" how="m-g">
    <point lat="38.8977" lon="-77.0365" hae="15.0" ce="5.0" le="2.0"/>
    <detail/>
  </event>
  ```
- Spatial fields: `lat` ($-90.0 \le \phi \le +90.0$), `lon` ($-180.0 \le \lambda \le +180.0$), `hae` (meters), `ce` (circular error meters $\ge 0.0$), `le` (linear error meters $\ge 0.0$).

### 3.2 Fixed Uniform Command Wire Cell (`tests/test_defensive_nc3_audit.py`)
- Wire packets are quantized to a uniform block size to eliminate side-channel packet length inferences:
  - Header: 8-byte big-endian sequence number at offset 0.
  - Directive Type: 2 bytes uint16 at offset 8.
  - Payload: $N$ bytes at offset 10.
  - Random Padding: $1024 - (10 + N + 16)$ bytes at offset $10 + N$.
  - Poly1305 / GCM Tag: 16 bytes at offset 1008.
  - Total Cell Size: Exactly $8 + 2 + N + (998 - N) + 16 = 1024$ bytes. Sum matches code arithmetic.

## 4. Algorithms and Pinned Libraries
- ML-DSA-87: NIST FIPS 204. Two-person authorization signature verification provided by `oqs.dll` version 0.16.0 (`critical_release.py:45`).
- XML Parser: Defused XML parser disabling DTD expansion via Python standard library `xml.etree.ElementTree` (`cjadc2_tactical_cot.py:130`).
- AES-256-GCM: NIST SP 800-38D. Session channel protection provided by `rust_data_plane` or `cryptography` library (`cjadc2_allied_gateway.py:65`).

## 5. Dependencies and Hardware Requirements
- Native Operating System APIs: Local socket networking (TCP/UDP, IPv4, IPv6) (`cjadc2_allied_gateway.py:40`).
- Web Assets: Requires local directory `tactical_web/` containing `index.html`, `index.css`, `app.js` (`tactical_web_console.py:90`).

## 6. Failure Behavior
- Second officer signature not received within 120 seconds raises `critical_release.AuthorizationTimeoutError` (`critical_release.py:135`).
- Malformed XML or XXE payload raises `ValueError("XML parsing failure")` (`cjadc2_tactical_cot.py:145`).
- Domain tag violation raises `cjadc2_cross_domain_guard.CrossDomainViolationError` and drops packet (`cjadc2_cross_domain_guard.py:115`).
- Unhandled `NameError` in `cjadc2_allied_gateway.py:184` on non-production runs due to undefined `is_env_true` (verified implementation defect `DEF-01`).

## 7. Configuration and Environment Variables
- `P2P_GATEWAY_QUARANTINE_HOSTILE`: Forces hostile quarantine of coalition gateway. Default: `0` (`cjadc2_allied_gateway.py:180`).
- `P2P_TPI_WINDOW_SEC`: Time window for two-person authorization. Default: `120` (`critical_release.py:75`).
- `P2P_WEB_PORT`: Local bind port for web console. Default: `8080` (`tactical_web_console.py:85`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - CoT XML parsing and XXE injection resistance: verified in `tests/test_cjadc2_data_fabric_drill.py` (8 tests).
  - Two-person rule dual officer authorization and timeout: verified in `tests/test_nc3_token_approval.py` (6 tests).
  - Uniform 1024-byte wire cell padding: verified in `tests/test_defensive_nc3_audit.py` (4 tests).
- NOT Covered:
  - Integration with live external tactical datalinks (Link 16, VMF, STANAG 4586).
  - Multi-operator concurrent token approvals on physical air-gapped terminals.

## 9. Not Implemented / External Dependencies
- Tactical Radio Interfaces: MIL-STD-188-220 and Link 16 physical modem interfaces require external tactical radio hardware; software simulates interfaces via UDP sockets.
- Production Command Surfaces: Commands `/eam`, `/ptt`, and `/nc3-verify` are disabled on production message paths (`secure_p2p.py:15738-15743`).

## 10. Known Limitations and Residual Risks
- Gateway Defect DEF-01: `cjadc2_allied_gateway.py:184` crashes with `NameError` when evaluated in non-production environments without `P2P_GATEWAY_QUARANTINE_HOSTILE` defined.
- Unauthenticated Web Console: `tactical_web_console.py` binds to localhost without HTTP basic authentication or TLS certificates; intended for local operator access only.

## 11. Discrepancies
- Undefined identifier `is_env_true` in `cjadc2_allied_gateway.py:184` cataloged in `docs/audit/discrepancies.md` as `DEF-01`.
- Promotional terms in filenames and console banners (`nc3_[banned-term]_command.py`) cataloged in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Should `tactical_web_console.py` require local token authentication before serving status endpoints to prevent unauthorized local browser scripts from reading telemetry?
