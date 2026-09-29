# archive/experimental — quarantined non-core modules

These modules are NOT part of the audited production import closure
(`secure_transmit_2027.py` CLI and its session/transport/trust stack never
import them; proven by `test_production_surface_audit.py`). They remain
importable at the repository root ONLY because verified test suites
exercise them; moving them would break the green battery without reducing
real attack surface (attackers reach code through imports, not filenames).

- `nc3_nuclear_command.py` — NC3 command/dual-custody prototype (tested by
  `test_nc3_*`, `test_defensive_nc3_audit`, `test_pkcs11_token_provider`,
  `test_2028_national_security_remediations`, `test_security_audit_remediations`,
  `test_production_tier7_csprng_complete_audit`).
- `zk_authenticator.py` — zero-knowledge authenticator prototype (tested by
  `test_production_tier123_hardening`, `test_crypto_root_fixes`,
  `test_security_audit_remediations`; lazily imported by
  `threshold_cryptography.py`, itself outside the core closure).

Notes:

- `allied_gateway.py` named in older planning documents DOES NOT EXIST in
  this tree; the similarly named `cjadc2_allied_gateway.py` is a distinct,
  tier-tested module and is NOT quarantined here.
- Promotion of any module above into the production closure requires:
  CNSA 2.0 purity clearance, a security review entry, test coverage, and
  an update to `test_production_surface_audit.py`'s core list.
- Deletion or relocation of these files requires updating every test and
  document reference listed above; do not move them casually.
