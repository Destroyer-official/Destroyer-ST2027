# Audit, threat, supply chain (verified maps)

## `audit_logging_system.py`

`AuditEventType/Severity`, `AuditEvent` (hash-chained entries),
`AuditLogger`: init/DB (`_initialize_database`, WAL on), flush thread,
`store_event`, SIEM streaming, `verify_chain_integrity`, sync/async
`log_event`, handlers, `query_events`. SQLite is deletable locally —
production needs WORM export + SIEM (operational track).

## `threat_detection_engine.py` + `threat_detection_response_system.py`

`ThreatLevel/Type/Event`, `SecurityStatus`, `ThreatDetectionEngine`
(platform capability probes, start/stop, detection loop/cycle). Statistical
heuristics (defense-in-depth signal, not a substitute for EDR), runtime pip
banned (fail-closed), psutil floor-checked.

## `supply_chain_security.py` + `dependency_security_verifier.py` +
`verify_deployment.py` + `generate_production_sbom.py`

Reproducible builds, artifact/dependency/SBOM records, dual SHA256+SHA512
hashing. Runtime truth (executed): `oqs.dll` CRITICAL sidecar-Ed25519
verified; pip dists tiered to hash+floor (sidecars impossible from PyPI —
documented control split, not a bypass); `verify_all_dependencies()` passes.
Requirements pinned `==` + hashes (8 lines). Next: Sigstore/transparency.
