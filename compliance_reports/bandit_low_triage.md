# Bandit SAST Low-Severity & Remediation Triage Report (`F-15`)

**Repository:** `p2p_6_1-26`  
**Audit Date:** 2026-11-26  
**Scanner Version:** Bandit `1.8.3`  
**Status:** **0 HIGH / 0 MEDIUM** across all active runtime Python modules and operational scripts; **1,278 LOW** triaged by category below.

---

## 1. Scan Scope & Exact Command

Executed across active repository Python sources excluding generated virtualenvs, build outputs, vendor/archive staging trees, logs, and unit-test directories under `tests/`:

```powershell
bandit -r . `
  --exclude "./.venv,./.audit-venv,./.audit-tools-venv,./.audit-download,./.git,./.ruff_cache,./rust_data_plane,./ts_rt,./sel4_mils_appliance,./scratch,./out,./test-results,./tests,./tests_bak,./archive,./notupload,./deploy_st2027,./vendor,./redesign,./downloads,./logs,./compliance_reports,./.hypothesis,./.pytest_cache,./cache" `
  -f json -o bandit_clean.json
```

**Measured Baseline Metrics:**
- **Lines of Code Scanned:** `187,652`
- **HIGH Severity:** `0`
- **MEDIUM Severity:** `0`
- **LOW Severity:** `1,278` (with `774` audited `# nosec` annotations)

---

## 2. Remediations Completed (Waves 4 & Pre-Wave Cleanups)

1. **`B311` (Non-cryptographic `random` PRNG) -> Eliminated (`0` remaining):**
   - Replaced `random.Random` packet-drop selection in `hardware/visual_airgap_diode.py::simulate_airgap_channel` with deterministic SHA-256 frame scoring (`domain = "airgap-channel-v1"`, `drop_count = int(len(frames) * loss_rate)`).
2. **`B101` (Runtime `assert` statements in security/production paths) -> Replaced with explicit fail-closed exceptions:**
   - Replaced 6 runtime assertions in `destroyer.py` with `RuntimeError`.
   - Replaced 12 remaining runtime assertions in `secure_p2p.py` (`L16376-16450`) with `RuntimeError`.
   - Replaced runtime assertions in `cng_crypto.py`, `scripts/sign_waiver.py`, and `sovereign_crypto_domain.py` with explicit exception checks.
3. **`B405` (`xml.etree.ElementTree`) -> Verified Safe Builder Usage:**
   - `sel4_microkit_manifest.py` constructs XML manifests solely via `xml.etree.ElementTree.Element` / `SubElement` (no untrusted XML parsing). Annotated explicitly as builder-only (`# nosec B405`).
4. **`B110` (`try/except/pass`) -> Fail-Closed Review:**
   - Audited exception handlers in `secure_p2p.py` and `scripts/hardware_tamper_monitor.py` to ensure security-relevant failures propagate or log explicitly rather than failing open.

---

## 3. Low-Severity Finding Triage Breakdown (`1,278` LOW)

| Bucket | LOW Count | Breakdown by Rule ID | Risk & Engineering Disposition |
|---|---:|---|---|
| **Runtime Python Modules** | `256` | `B110` (135), `B603` (69), `B404` (21), `B607` (10), `B112` (7), `B101` (6), `B105` (6), `B606` (1), `B107` (1) | **Acceptable / Triaged:** `B404`/`B603`/`B607` invoke fixed argument arrays with `shell=False` (`tpm2_*`, `cargo`, `git`, `proverif`). `B105`/`B107` are false-positive string/parameter matches (`'2'`, `'3'`, `'A'`, `'0.0'`, `'ZEROIZE-ALL'`, default empty `pin=''` overridden before HSM login in `secure_p2p_core/keys/hsm_integration.py:41`). `B606` in `hw_readiness.py:134` launches a bounded host-utility helper without shell expansion. Remaining `B101` (6) reside in root drill script `run_two_terminals_secure_p2_test.py`. Remaining `B110`/`B112` are non-security logging/cleanup loops. |
| **Operational / Drill Scripts (`scripts/`, `test_real_uses_dual_terminal*.py`)** | `107` | `B101` (46), `B603` (26), `B110` (19), `B607` (8), `B404` (7), `B105` (1) | **Test & Drill Harnesses Only:** Executed solely as operator/CI verification drills; assertions intentionally validate expected drill outcomes. |
| **Embedded Package Tests (`secure_p2p_core/tests/`)** | `915` | `B101` (915) | **Pytest Assertions Only:** Standard test assertions inside `secure_p2p_core/tests/`; non-runtime test code. |
| **Total Scanned** | **`1,278`** | — | **0 HIGH / 0 MEDIUM** |
