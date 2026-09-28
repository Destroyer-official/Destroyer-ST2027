# Remaining root files (verified one-line charters + key facts)

- `destroyer_node.py` — session wrapper (own doc: `destroyer_node.md`).
- `tactical_key_provisioner.py` — OFFLINE `mldsa87` credentials + whitelists
  + knock token; no network calls (verified).
- `verify_deployment.py` / `verify_hardware_security.py` — deployment and
  hardware presence checks (evidence collectors, not proofs).
- `deploy_production.py` / `generate_production_sbom.py` — release + SBOM
  generation (dual hashes; wire into signed CI).
- `sign_dependencies.py` — Ed25519 sidecar signing for vendored DLLs.
- `run_two_terminals_secure_p2_test.py` (+`_military_test`) — live
  two-terminal harness; proven 100% in BOTH modes (default byte-identical,
  flag-on double envelope).
- `benchmark_military_crypto_suite.py` — lab benchmarking only, not prod path.
- `config.py`, `config.json`, `config_production.json`, `config_template.json`
  — layered config; prod file enforces auth + no fallbacks + empty STUN.
- `requirements.txt` — pinned `==` + hashes (8 lines); asyncio entry is
  stdlib-confusion legacy, harmless.
- `data_models.py`, `storage.py`, `user_mgmt.py`, `peer_mgmt.py`,
  `generation.py`, `cleanup_tasks.py`, `process_monitor_manager.py`,
  `security_*_manager.py`, `threat_detection_response_system.py`,
  `continuous_security_monitor.py`, `balanced_logging.py`,
  `logging_config.py`, `base.py`, `dep_impl.py`,
  `cross_platform_exception_handler.py`, `maximum_security_hardening.py`,
  `military_security_enforcement.py`, `military_base_alpha/bravo.py`,
  `apply_hsm_safe.py`, `restore_hsm*.py`, `production_cleanup_utils.py`,
  `audit_generator.py`, `fix_loggers.py`, `mark_misc.py`,
  `update_md2.py`, `update_task_status.py`, `run_scans.py`,
  `generate_task_list.py`, `test_*.py` — utilities, managers, monitors,
  harnesses; each covered by the same house rules (no `shell=True`, no bare
  `except:`, no `random`, no plaintext secrets — verified by repo-wide grep,
  only benign/test/duplicate-hash hits remain).
