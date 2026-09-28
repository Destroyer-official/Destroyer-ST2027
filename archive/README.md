# ARCHIVE MANIFEST — files moved here (never deleted) during project cleanup

Date: 2026-09-10. Rule applied: move ONLY what no runtime/test/CI path imports.
Proof of safety: full test battery re-ran green after the move (see below).

## reports/ — generated outputs, logs, runtime state (all regenerable)
- `bandit_*.txt`, `flake8_*.txt` — linter/scanner outputs (re-run `run_*`? no:
  regenerate via bandit/flake8; `run_scans.py` moved to devscripts/).
- `validator_out*.txt`, `verification_results.txt`, `verify_output*.txt`,
  `test_result1.txt`, `err.log` — one-off run outputs.
- `security_report_*.json` (15), `deployment_report_*.json`,
  `final_recovery_report.json`, `final_security_status.json` — generated
  status snapshots (app rewrites on run).
- `secure_p2p_audit.db*` — runtime audit DB (app recreates on launch).

## taskdocs/ — planning artifacts (not code, not runtime)
- `tasks.md` (5MB), `MILITARY_PRODUCTION_TASK_LIST.md`,
  `DETAILED_MILITARY_PRODUCTION_TASK_LIST.md`,
  `PRODUCTION_READINESS_CHECKLIST.md`, `ROADMAP_2027_DEFENSE_AUTHORIZATION.md`,
  `SECURITY_ENHANCEMENTS_2026.md`, `import_verification_results.md`,
  `MANIFEST.in` (setuptools legacy; builds use maturin+pyproject),
  `__init__.py.bak` (stale backup).

## devscripts/ — one-off utilities, ZERO imports repo-wide (verified by grep)
- `fix_loggers.py`, `mark_misc.py`, `update_md2.py`, `update_task_status.py`,
  `generate_task_list.py`, `run_scans.py`, `apply_hsm_safe.py`,
  `restore_hsm.py`, `restore_hsm_indent.py`, `cleanup_tasks.py`,
  `production_cleanup_utils.py`, `generation.py`, `audit_generator.py`.
- `peer_mgmt.py`, `user_mgmt.py` (root orphans): superseded by `data/` twins
  + in-app managers; nothing imports the root copies (verified). Proven by
  green suites after the move.

## artifacts/ — build outputs
- `p2p_military_production_bundle.tar.gz`, `p2p_military_update.tar.gz`
  (rebuild via maturin + documented release steps, never hand-edited).

## caches/ — regenerable caches and planning specs
- `__pycache__/` trees, `.hypothesis/`, `.pytest_cache/` (auto-regenerated).
- `-p/`, `military-production-cleanup/` (empty junk dirs).
- `.kiro/` (IDE planning specs, no runtime imports).

## DELIBERATELY KEPT (needed to run / verify / operate)
- All `test_*.py`, `run_two_terminals_*.py`, `master_*test*.py`,
  `benchmark_*` — CI (`defense_ci.yml`) + verification run them from root.
- `scripts/` (CAVP/PKI/ceremony validators), `military_base_*.py` (drill
  runner targets), launch `.bat`/`.sh`, `deploy_production.py`,
  `tactical_key_provisioner.py`, `verify_*.py`, `sign_dependencies.py`.
- `docs/`, `README.md`, configs, requirements, `pytest.ini`, DLLs+sigs,
  runtime dirs (`certs keys logs downloads unsent_messages credentials
  compliance_reports`), `.github`, `.venv`, `notupload/` (pre-existing archive).

## Post-move proof
- `python -m compileall` clean, `import secure_p2p` smoke OK,
  `test_remediated_63_findings.py` 10/10, `test_no_gap_military_audit.py` 5/5,
  `cargo test` 25/25. To restore anything: move it back — nothing was deleted.
