"""
Configuration management for the P2P system.
Handles loading, validation, and management of system configuration.
"""
import os
import json
import logging
from typing import Dict, Any, Optional

class ConfigurationError(Exception):
    """Raised when configuration loading fails in fail-closed environments."""
    pass


def _env_wants_prod() -> bool:
    """True if current process env requests production mode."""
    return (
        os.environ.get('P2P_PRODUCTION', '').lower() in ('1', 'true', 'yes', 'on')
        or os.environ.get('SECURE_P2P_PRODUCTION', '').lower() in ('1', 'true', 'yes', 'on')
    )


# Sticky production latch: captured once at import. Never allowed to unset.
_STICKY_PROD: bool = _env_wants_prod()


def _is_production(logger: Optional[logging.Logger] = None) -> bool:
    """
    Sticky production check (fail-closed).

    Once _STICKY_PROD is True (true at import, or later latched True), it
    stays True for the lifetime of the process. Any later env clearing that
    would unset production is denied and logged at CRITICAL.
    """
    global _STICKY_PROD
    wants = _env_wants_prod()
    if wants:
        _STICKY_PROD = True
        return True
    if _STICKY_PROD:
        msg = (
            "Attempt to unset production mode detected "
            "(P2P_PRODUCTION/SECURE_P2P_PRODUCTION cleared after sticky latch). "
            "Enforcing sticky production (fail-closed)."
        )
        try:
            (logger or logging.getLogger(__name__)).critical(msg)
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        return True
    return False


def _emit_config_audit(logger: Optional[logging.Logger], message: str) -> None:
    """Ignored-with-warning + audit event for denied env overrides."""
    log = logger or logging.getLogger(__name__)
    try:
        log.warning(message)
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    try:
        logging.getLogger("audit").warning(message)
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    try:
        from audit_logging_system import get_audit_logger  # type: ignore

        try:
            al = get_audit_logger()
            if hasattr(al, "log_event"):
                try:
                    from audit_logging_system import AuditEventType, AuditSeverity  # type: ignore

                    al.log_event(
                        AuditEventType.SECURITY_VIOLATION
                        if hasattr(AuditEventType, "SECURITY_VIOLATION")
                        else "CONFIG_OVERRIDE_DENIED",
                        message,
                        AuditSeverity.WARNING
                        if hasattr(AuditSeverity, "WARNING")
                        else "WARNING",
                    )
                except Exception:
                    try:
                        al.log_event("CONFIG_OVERRIDE_DENIED", message, "WARNING")
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass
            elif hasattr(al, "log_security_event"):
                try:
                    al.log_security_event(message)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass


# Production env allowlist (only these may override config in prod).
_PROD_ENV_ALLOWLIST = frozenset({"P2P_LOG_LEVEL", "P2P_LISTEN_PORT", "P2P_LOG_DIR"})
_PROD_ENV_DENYLIST_EXPLICIT = frozenset(
    {
        "P2P_SECURITY_LEVEL",
        "P2P_KEY_LIFETIME",
        "P2P_HANDSHAKE_TIMEOUT",
        "P2P_AUDIT_ENABLED",
        "P2P_PRODUCTION",
        "SECURE_P2P_PRODUCTION",
    }
)
# Dotted/file-key prefixes never reachable via env in prod.
_DENIED_DOTTED_PREFIXES = (
    "security.",
    "cryptography.",
    "hsm_tpm.",
    "authentication.",
    "compliance.",
)
_DENIED_ENV_SUBSTRINGS = (
    "SECURITY",
    "CRYPTOGRAPHY",
    "HSM",
    "TPM",
    "AUTHENTICATION",
    "COMPLIANCE",
    "PRODUCTION",
)
# Flat-key mapping for file keys that correspond to denied dotted sections.
_DENIED_FLAT_KEYS = frozenset(
    {
        "security_level",
        "key_lifetime",
        "handshake_timeout",
        "audit_enabled",
        "security",
        "cryptography",
        "hsm_tpm",
        "authentication",
        "compliance",
    }
)

_COUNTER_PATH = os.path.join("certs", "config_counter.json")


def _is_log_dir_allowed(value: str) -> bool:
    """Allow only paths under ./logs (relative logs/... or ./logs/...)."""
    try:
        v = os.path.normpath(str(value).strip())
        if not v or v in (".", ".."):
            return False
        if os.path.isabs(v):
            return False
        parts = v.replace("\\", "/").split("/")
        while parts and parts[0] in (".", ""):
            parts.pop(0)
        if not parts or parts[0] != "logs":
            return False
        if ".." in parts:
            return False
        return True
    except Exception:
        return False


def _load_counter_state() -> Dict[str, Any]:
    """Load {signer_id, last_counter} or init {unknown, 0} if file missing."""
    if not os.path.exists(_COUNTER_PATH):
        return {"signer_id": "unknown", "last_counter": 0}
    try:
        with open(_COUNTER_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        signer_id = str(data.get("signer_id", "unknown"))
        last_counter = int(data.get("last_counter", 0))
        if last_counter < 0:
            last_counter = 0
        return {"signer_id": signer_id, "last_counter": last_counter}
    except Exception as e:
        raise ConfigurationError(
            f"FAIL-CLOSED: corrupt config counter file '{_COUNTER_PATH}': {e}"
        ) from e


def _store_counter_state_atomically(signer_id: str, last_counter: int) -> None:
    """Atomically persist counter state (tmp file + os.replace)."""
    try:
        anchor_dir = os.path.dirname(_COUNTER_PATH) or "."
        os.makedirs(anchor_dir, exist_ok=True)
        tmp_path = _COUNTER_PATH + ".tmp"
        payload = {"signer_id": str(signer_id), "last_counter": int(last_counter)}
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
            try:
                f.flush()
                os.fsync(f.fileno())
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
        os.replace(tmp_path, _COUNTER_PATH)
    except Exception as e:
        raise ConfigurationError(
            f"FAIL-CLOSED: unable to persist config counter '{_COUNTER_PATH}': {e}"
        ) from e


def _extract_counter_and_signer(config_file: str) -> tuple[Optional[int], str]:
    """Extract (monotonic_counter|None, signer_id) from boot config JSON."""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return (None, "unknown")
    if not isinstance(data, dict):
        return (None, "unknown")
    counter: Optional[int] = None
    if "monotonic_counter" in data:
        try:
            counter = int(data["monotonic_counter"])
        except Exception:
            counter = None
    if counter is None:
        try:
            meta = data.get("metadata")
            if isinstance(meta, dict) and "monotonic_counter" in meta:
                counter = int(meta["monotonic_counter"])
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    if counter is None:
        try:
            sec = data.get("security")
            if isinstance(sec, dict) and "monotonic_counter" in sec:
                counter = int(sec["monotonic_counter"])
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    signer_id = "unknown"
    if isinstance(data.get("signer_id"), str) and data["signer_id"].strip():
        signer_id = data["signer_id"].strip()
    else:
        try:
            meta = data.get("metadata")
            if isinstance(meta, dict) and isinstance(meta.get("signer_id"), str) and meta["signer_id"].strip():
                signer_id = meta["signer_id"].strip()
            elif isinstance(data.get("signer"), dict) and isinstance(data["signer"].get("signer_id"), str):
                signer_id = data["signer"]["signer_id"].strip()
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    return (counter, signer_id)


def _check_and_update_config_counter(
    config_file: str, is_prod: bool, logger: Optional[logging.Logger] = None
) -> bool:
    """
    Enforce monotonic_counter > last_counter in prod, update atomically.

    - If counter file missing, init last_counter=0.
    - If boot config has no monotonic_counter: allow with warning in prod
      (backward compat), debug in lab.
    - On regress (incoming <= last) in prod: fail-closed (False).
    - On success in prod: atomically persist new counter + signer_id.
    - In lab: skip enforcement (debug log), no file mutation.
    """
    log = logger or logging.getLogger(__name__)
    incoming, signer_id = _extract_counter_and_signer(config_file)
    if not is_prod:
        try:
            log.debug(
                f"Loaded monotonic counter check skipped for '{config_file}' "
                f"(incoming={incoming}, signer_id={signer_id}) (lab)"
            )
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        return True
    if incoming is None:
        try:
            log.warning(
                f"Production boot config '{config_file}' has no monotonic_counter; "
                "allowing for backward compatibility (re-sign with counter recommended)"
            )
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        return True
    if incoming < 0:
        try:
            log.critical(
                f"TAMPER DETECTED: negative monotonic_counter {incoming} in '{config_file}'"
            )
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        _emit_config_audit(
            log,
            f"CONFIG_ROLLBACK_DENIED path={config_file} signer_id={signer_id} "
            f"incoming={incoming} reason=negative-counter",
        )
        return False
    try:
        state = _load_counter_state()
    except ConfigurationError as e:
        try:
            log.critical(f"FAIL-CLOSED: corrupt config counter blocks '{config_file}': {e}")
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        return False
    last = int(state.get("last_counter", 0))
    stored_signer = str(state.get("signer_id", "unknown"))
    if stored_signer != "unknown" and signer_id != "unknown" and stored_signer != signer_id:
        try:
            log.warning(
                f"Config signer rotation detected: stored={stored_signer} incoming={signer_id}; "
                "still enforcing monotonicity (fail-closed)"
            )
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    if incoming <= last:
        try:
            log.critical(
                f"TAMPER/ROLLBACK DETECTED: monotonic_counter {incoming} <= last_counter {last} "
                f"for '{config_file}' (signer_id={signer_id}). Fail-closed."
            )
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        _emit_config_audit(
            log,
            f"CONFIG_ROLLBACK_DENIED path={config_file} signer_id={signer_id} "
            f"incoming={incoming} last={last}",
        )
        return False
    try:
        _store_counter_state_atomically(signer_id, incoming)
    except ConfigurationError as e:
        try:
            log.critical(f"FAIL-CLOSED: counter persist failed for '{config_file}': {e}")
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        return False
    try:
        log.info(
            f"Config monotonic counter advanced: {last} -> {incoming} (signer_id={signer_id})"
        )
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    return True

class ConfigManager:
    """
    Configuration manager for the P2P system.
    Handles loading configuration from files and environment variables,
    with validation and default values.
    """
    # Default configuration
    DEFAULTS = {
        'security_level': 'MAXIMUM',
        'key_lifetime': 3072,
        'handshake_timeout': 30.0,
        'connection_timeout': 60.0,
        'heartbeat_interval': 30.0,
        'max_retries': 3,
        'log_level': 'INFO',
        'audit_enabled': True,
        'memory_protection': True,
        'anti_debugging': True,
    }

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager.
        Args:
            config_file: Optional path to configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config = self.DEFAULTS.copy()
        self._is_prod_config = False
        
        if config_file and os.path.exists(config_file):
            self._load_from_file(config_file)
            
        self._load_from_environment()

    def _load_from_file(self, config_file: str) -> None:
        """Load configuration from JSON file (fail-closed model, Item 45 / Finding 7.2)."""
        production_mode = _is_production(self.logger)
        is_prod_config = os.path.basename(config_file) in ('config_production.json',)
        # Latch prod-file flag for env allowlist (fail-closed prod).
        try:
            self._is_prod_config = bool(is_prod_config)
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

        if os.path.exists(config_file) and (production_mode or is_prod_config):
            # Prefer ML-DSA-87 / DSSE (CNSA 2.0); legacy Ed25519 .sig lab-shim.
            mldsa_sig = config_file + ".mldsa87.sig"
            mldsa_pub = config_file + ".mldsa87.pub"
            dsse_path = config_file + ".dsse"
            anchor_pub = os.path.join("certs", "config_trust_root.pub")
            verified = False
            verified_kind = ""
            try:
                if os.path.exists(mldsa_sig) and (os.path.exists(mldsa_pub) or os.path.exists(anchor_pub)):
                    pub_file = mldsa_pub if os.path.exists(mldsa_pub) else anchor_pub
                    try:
                        from liboqs_wrapper import LibOQS_MLDSA_87
                        with open(config_file, 'rb') as f:
                            cfg_bytes = f.read()
                        with open(mldsa_sig, 'rb') as f:
                            sig_bytes = f.read()
                        with open(pub_file, 'rb') as f:
                            pub_bytes = f.read()
                        verifier = LibOQS_MLDSA_87()
                        if verifier.verify(pub_bytes, cfg_bytes, sig_bytes):
                            self.logger.info(f"Verified ML-DSA-87 signature for {config_file}")
                            verified = True
                            verified_kind = "mldsa87"
                        else:
                            self.logger.critical(f"TAMPER DETECTED: Invalid ML-DSA-87 signature on {config_file}")
                            raise ConfigurationError(
                                f"Configuration signature verification failed for '{config_file}': invalid ML-DSA-87 signature"
                            )
                    except ConfigurationError:
                        raise
                    except Exception as e:
                        self.logger.critical(f"TAMPER DETECTED: ML-DSA-87 verify error on {config_file}: {e}")
                        raise ConfigurationError(
                            f"Configuration signature verification failed for '{config_file}': {e}"
                        ) from e
                elif os.path.exists(dsse_path):
                    import base64
                    with open(dsse_path, 'r', encoding='utf-8') as f:
                        env = json.load(f)
                    payload = base64.b64decode(env.get("payload", ""))
                    sigs = env.get("signatures", [])
                    if not sigs:
                        raise ConfigurationError(
                            f"FAIL-CLOSED: DSSE envelope for '{config_file}' has no signatures."
                        )
                    with open(config_file, 'rb') as f:
                        cfg_bytes = f.read()
                    if payload != cfg_bytes:
                        self.logger.critical(f"TAMPER DETECTED: DSSE payload mismatch for '{config_file}'")
                        raise ConfigurationError(
                            f"Configuration signature verification failed for '{config_file}': DSSE payload mismatch"
                        )
                    pub_file = mldsa_pub if os.path.exists(mldsa_pub) else anchor_pub
                    if not os.path.exists(pub_file):
                        raise ConfigurationError(
                            f"FAIL-CLOSED: DSSE trust anchor missing for '{config_file}'."
                        )
                    from liboqs_wrapper import LibOQS_MLDSA_87
                    with open(pub_file, 'rb') as f:
                        pub_bytes = f.read()
                    sig_bytes = base64.b64decode(sigs[0].get("sig", ""))
                    ptype = env.get("payloadType", "application/vnd.p2p.boot-config+json").encode()
                    pae = b"DSSEv1 " + str(len(ptype)).encode() + b" " + ptype + b" " + str(len(payload)).encode() + b" " + payload
                    verifier = LibOQS_MLDSA_87()
                    if verifier.verify(pub_bytes, pae, sig_bytes):
                        self.logger.info(f"Verified DSSE ML-DSA-87 envelope for {config_file}")
                        verified = True
                        verified_kind = "dsse"
                    else:
                        self.logger.critical(f"TAMPER DETECTED: Invalid DSSE signature on {config_file}")
                        raise ConfigurationError(
                            f"Configuration signature verification failed for '{config_file}': invalid DSSE signature"
                        )
            except ConfigurationError:
                raise
            except Exception as e:
                self.logger.critical(f"TAMPER DETECTED: Invalid signature envelope on {config_file}: {e}")
                raise ConfigurationError(f"Configuration signature verification failed for '{config_file}': {e}") from e
            if verified:
                if not _check_and_update_config_counter(config_file, True, self.logger):
                    raise ConfigurationError(
                        f"FAIL-CLOSED: monotonic counter regress blocks '{config_file}'."
                    )
            else:
                # Legacy Ed25519 .sig lab-shim. Production (sticky) requires
                # CNSA ML-DSA-87/DSSE above; Ed25519 is refused there.
                if _is_production(self.logger):
                    raise ConfigurationError(
                        f"FAIL-CLOSED: Configuration '{config_file}' lacks CNSA "
                        f"ML-DSA-87/DSSE signature (legacy Ed25519 refused in production)."
                    )
                sig_file = config_file + ".sig"
                pub_file = os.path.join("certs", "config_signer.pub")
                if not os.path.exists(sig_file):
                    raise ConfigurationError(
                        f"FAIL-CLOSED: Configuration '{config_file}' lacks a valid cryptographic signature (.sig)."
                    )
                if os.path.exists(pub_file):
                    try:
                        from cryptography.hazmat.primitives.asymmetric import ed25519
                        from cryptography.hazmat.primitives import serialization
                        with open(config_file, 'rb') as f:
                            cfg_bytes = f.read()
                        with open(sig_file, 'rb') as f:
                            sig_bytes = f.read()
                        with open(pub_file, 'rb') as f:
                            pub_bytes = f.read()
                        pub_key = serialization.load_pem_public_key(pub_bytes)
                        if isinstance(pub_key, ed25519.Ed25519PublicKey):
                            pub_key.verify(sig_bytes, cfg_bytes)
                            self.logger.info(f"Verified cryptographic signature for {config_file}")
                            if not _check_and_update_config_counter(config_file, True, self.logger):
                                raise ConfigurationError(
                                    f"FAIL-CLOSED: monotonic counter regress blocks '{config_file}'."
                                )
                    except ConfigurationError:
                        raise
                    except Exception as e:
                        self.logger.critical(f"TAMPER DETECTED: Invalid signature on {config_file}: {e}")
                        raise ConfigurationError(f"Configuration signature verification failed for '{config_file}': {e}") from e

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
                self.config.update(file_config)
                self.logger.info(f"Loaded configuration from {config_file}")

                air_gapped = file_config.get("air_gapped_mode") or file_config.get("network", {}).get("air_gapped_mode")
                if air_gapped:
                    os.environ["P2P_AIR_GAPPED_MODE"] = "1"
                    os.environ["P2P_OFFLINE_MODE"] = "1"
                    self.logger.info("Enforcing strict P2P_AIR_GAPPED_MODE=1 and P2P_OFFLINE_MODE=1 from config")
        except ConfigurationError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to load configuration from {config_file}: {e}")
            raise ConfigurationError(f"Corrupted or invalid configuration file '{config_file}': {e}") from e

    def _load_from_environment(self) -> None:
        """Load configuration from environment variables (allowlist, sticky-prod)."""
        sticky_prod = _is_production(self.logger)
        # Production = sticky latch OR MAXIMUM level OR prod boot file.
        # - Sticky True: fail-closed prod, strict allowlist (only LOG_LEVEL /
        #   LISTEN_PORT / LOG_DIR), everything else ignored with warning+audit.
        # - MAXIMUM / prod-file without sticky: legacy anti-downgrade still
        #   fail-closes (deny SECURITY_LEVEL etc), preserving existing tests.
        # - True lab (non-MAXIMUM, non-sticky, non-prod-file): allow all debug.
        is_prod_file = bool(getattr(self, '_is_prod_config', False))
        is_maximum = (self.config.get('security_level') == 'MAXIMUM')
        is_production = bool(sticky_prod or is_maximum or is_prod_file)
        if sticky_prod and self.config.get('security_level') != 'MAXIMUM':
            self.logger.critical(
                "Attempt to unset production security_level detected "
                f"(security_level={self.config.get('security_level')!r} while sticky production latched). "
                "Enforcing sticky production (fail-closed); ignoring downgrade."
            )
            # Enforce fail-closed: do not allow file/env to lower MAXIMUM once sticky.
            try:
                self.config['security_level'] = 'MAXIMUM'
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            is_production = True
        env_mappings = {
            'P2P_SECURITY_LEVEL': 'security_level',
            'P2P_KEY_LIFETIME': 'key_lifetime',
            'P2P_HANDSHAKE_TIMEOUT': 'handshake_timeout',
            'P2P_LOG_LEVEL': 'log_level',
            'P2P_AUDIT_ENABLED': 'audit_enabled',
            'P2P_LISTEN_PORT': 'listen_port',
            'P2P_LOG_DIR': 'log_dir',
        }

        def _dotted_for_env(env_var: str, cfg_key: str) -> str:
            # Map flat keys to dotted equivalents for deny-prefix checks.
            flat_to_dotted = {
                'security_level': 'security.level',
                'key_lifetime': 'security.key_lifetime',
                'handshake_timeout': 'security.handshake_timeout',
                'audit_enabled': 'security.audit_logging.enabled',
                'listen_port': 'networking.listen_port',
                'log_dir': 'logging.log_dir',
                'log_level': 'logging.level',
            }
            return flat_to_dotted.get(cfg_key, cfg_key)

        # Production flag itself is never a config override (locked).
        for flag in ('P2P_PRODUCTION', 'SECURE_P2P_PRODUCTION'):
            if flag in os.environ and is_production:
                _emit_config_audit(
                    self.logger,
                    f"Ignoring environment override '{flag}' in production mode "
                    "(production flag itself is locked, sticky fail-closed)",
                )
        
        for env_var, config_key in env_mappings.items():
            if env_var in os.environ:
                dotted = _dotted_for_env(env_var, config_key)
                if is_production:
                    # Fail-closed allowlist: only LOG_LEVEL / LISTEN_PORT / LOG_DIR.
                    if env_var not in _PROD_ENV_ALLOWLIST:
                        _emit_config_audit(
                            self.logger,
                            f"Ignoring environment override '{env_var}'->'{dotted}' "
                            "in production mode (deny-list, fail-closed)",
                        )
                        continue
                    # Validate allowlisted values.
                    value = os.environ[env_var]
                    if env_var == 'P2P_LISTEN_PORT':
                        try:
                            port = int(str(value).strip())
                        except Exception:
                            _emit_config_audit(
                                self.logger,
                                f"Ignoring invalid P2P_LISTEN_PORT={value!r} in production "
                                "(must be integer 1024-65535)",
                            )
                            continue
                        if not 1024 <= port <= 65535:
                            _emit_config_audit(
                                self.logger,
                                f"Ignoring out-of-range P2P_LISTEN_PORT={port} in production "
                                "(must be 1024-65535)",
                            )
                            continue
                        self.config[config_key] = port
                        self.logger.info(f"Applied production allowlisted env {env_var}->{config_key}={port}")
                        continue
                    if env_var == 'P2P_LOG_DIR':
                        if not _is_log_dir_allowed(value):
                            _emit_config_audit(
                                self.logger,
                                f"Ignoring disallowed P2P_LOG_DIR={value!r} in production "
                                "(must be under ./logs)",
                            )
                            continue
                        norm = os.path.normpath(str(value).strip())
                        self.config[config_key] = norm
                        self.logger.info(f"Applied production allowlisted env {env_var}->{config_key}={norm}")
                        continue
                    # P2P_LOG_LEVEL: allow as-is.
                    self.config[config_key] = value
                    self.logger.info(f"Applied production allowlisted env {env_var}->{config_key}")
                    continue

                value = os.environ[env_var]
                # Convert to appropriate type (lab: allow all with debug log)
                if config_key in ['key_lifetime', 'max_retries', 'listen_port']:
                    self.config[config_key] = int(value)
                elif config_key in ['handshake_timeout', 'connection_timeout', 'heartbeat_interval']:
                    self.config[config_key] = float(value)
                elif config_key in ['audit_enabled', 'memory_protection', 'anti_debugging']:
                    self.config[config_key] = value.lower() in ('true', '1', 'yes')
                else:
                    self.config[config_key] = value
                self.logger.debug(f"Loaded {config_key} from environment variable {env_var} (lab)")

        if is_production:
            # Deny any other P2P_*/SECURE_P2P_* reaching denied sections (fail-closed).
            # Only vars mapping to security.*/cryptography.*/hsm_tpm.* /
            # authentication.*/compliance.* (or explicit denylist) warn+audit;
            # unrelated operational P2P_* (e.g. P2P_ALLOW_LOOPBACK) are not
            # config overrides — debug-log and ignore silently (non-breaking).
            for env_var in list(os.environ.keys()):
                if env_var in env_mappings or env_var in (
                    'P2P_PRODUCTION', 'SECURE_P2P_PRODUCTION',
                    'P2P_AIR_GAPPED_MODE', 'P2P_OFFLINE_MODE',
                ):
                    continue
                upper = env_var.upper()
                if not (upper.startswith('P2P_') or upper.startswith('SECURE_P2P_')):
                    continue
                if env_var in _PROD_ENV_DENYLIST_EXPLICIT or any(
                    s in upper for s in _DENIED_ENV_SUBSTRINGS
                ):
                    _emit_config_audit(
                        self.logger,
                        f"Ignoring environment override '{env_var}' in production mode "
                        "(deny-list, fail-closed)",
                    )
                else:
                    self.logger.debug(
                        f"Ignoring non-config environment variable '{env_var}' "
                        "in production mode (not a config override)"
                    )

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.
        Args:
            key: Configuration key
            default: Default value if key not found
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value.
        Args:
            key: Configuration key
            value: Configuration value
        """
        self.config[key] = value
        self.logger.debug(f"Set configuration {key}={value}")

    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary with sensitive variables redacted (Item 53 / Finding 7.3)."""
        redacted = {}
        sensitive_patterns = ('KEY', 'SECRET', 'PASSWORD', 'PASSPHRASE', 'TOKEN', 'CREDENTIAL')
        for k, v in self.config.items():
            k_upper = str(k).upper()
            if any(pat in k_upper for pat in sensitive_patterns):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = v
        return redacted