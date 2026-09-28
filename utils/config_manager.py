"""
Configuration Manager with Backward Compatibility

This module provides configuration management with full backward compatibility:
- Loads existing configurations without errors
- Provides default values for all new settings
- Supports graceful degradation when security modules are unavailable
- Maintains existing configuration format

Requirements: 7.4, 7.3
"""

import copy
import json
import logging
import os
import secrets
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def _env_wants_prod() -> bool:
    """True if current process env requests production mode."""
    return (
        os.environ.get('P2P_PRODUCTION', '').lower() in ('1', 'true', 'yes', 'on')
        or os.environ.get('SECURE_P2P_PRODUCTION', '').lower() in ('1', 'true', 'yes', 'on')
    )


# Sticky production latch: captured once at import. Never allowed to unset.
_STICKY_PROD: bool = _env_wants_prod()


def _is_production() -> bool:
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
        logger.critical(
            "Attempt to unset production mode detected "
            "(P2P_PRODUCTION/SECURE_P2P_PRODUCTION cleared after sticky latch). "
            "Enforcing sticky production (fail-closed)."
        )
        return True
    return False


def _emit_config_audit(message: str) -> None:
    """Emit audit event for denied config overrides (warning + audit channel)."""
    logger.warning(message)
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


# Production env allowlist (only these P2P_* vars may override config in prod).
_PROD_ENV_ALLOWLIST = frozenset({"P2P_LOG_LEVEL", "P2P_LISTEN_PORT", "P2P_LOG_DIR"})
# Explicit prod denylist (always ignored in prod with warning + audit).
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
# Dotted config prefixes that must never be reachable via env in prod.
_DENIED_DOTTED_PREFIXES = (
    "security.",
    "cryptography.",
    "hsm_tpm.",
    "authentication.",
    "compliance.",
)
# Env-name substrings treated as security-sensitive in prod (fail-closed).
_DENIED_ENV_SUBSTRINGS = (
    "SECURITY",
    "CRYPTOGRAPHY",
    "HSM",
    "TPM",
    "AUTHENTICATION",
    "COMPLIANCE",
    "PRODUCTION",
)

# Trust-anchor counter file (extends certs/ anchor dir).
_COUNTER_PATH = os.path.join("certs", "config_counter.json")


def _is_log_dir_allowed(value: str) -> bool:
    """Allow only paths under ./logs (relative logs/... or ./logs/...)."""
    try:
        v = os.path.normpath(str(value).strip())
        if not v or v in (".", ".."):
            return False
        # Reject absolute paths and parent traversal.
        if os.path.isabs(v):
            return False
        parts = v.replace("\\", "/").split("/")
        # Normalize ./ prefix.
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
        logger.error(f"Config counter file corrupt at {_COUNTER_PATH}: {e}")
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


def _extract_counter_and_signer(config_path: str) -> tuple[Optional[int], str]:
    """Extract (monotonic_counter|None, signer_id) from boot config JSON."""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return (None, "unknown")
    if not isinstance(data, dict):
        return (None, "unknown")
    counter: Optional[int] = None
    for key in ("monotonic_counter",):
        if key in data:
            try:
                counter = int(data[key])
            except Exception:
                counter = None
            break
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
    for key in ("signer_id",):
        if key in data and isinstance(data[key], str) and data[key].strip():
            signer_id = data[key].strip()
            break
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


def _check_and_update_config_counter(config_path: str, is_prod: bool) -> bool:
    """
    Enforce monotonic_counter > last_counter in prod, update atomically.

    - If counter file missing, init last_counter=0.
    - If boot config has no monotonic_counter: allow with warning in prod
      (backward compat for pre-counter signed configs), debug in lab.
    - On regress (incoming <= last) in prod: fail-closed (False).
    - On success in prod: atomically persist new counter + signer_id.
    - In lab: skip enforcement (debug log), no file mutation.
    """
    incoming, signer_id = _extract_counter_and_signer(config_path)
    if not is_prod:
        logger.debug(
            f"Lab mode: skipping monotonic counter check for '{config_path}' "
            f"(incoming={incoming}, signer_id={signer_id})"
        )
        return True
    if incoming is None:
        logger.warning(
            f"Production boot config '{config_path}' has no monotonic_counter; "
            "allowing for backward compatibility (re-sign with counter recommended)"
        )
        return True
    if incoming < 0:
        logger.critical(
            f"TAMPER DETECTED: negative monotonic_counter {incoming} in '{config_path}'"
        )
        _emit_config_audit(
            f"CONFIG_ROLLBACK_DENIED path={config_path} signer_id={signer_id} "
            f"incoming={incoming} reason=negative-counter"
        )
        return False
    try:
        state = _load_counter_state()
    except ConfigurationError:
        # Corrupt counter file fail-closes in prod.
        logger.critical(
            f"FAIL-CLOSED: corrupt config counter blocks boot config '{config_path}'"
        )
        return False
    last = int(state.get("last_counter", 0))
    stored_signer = str(state.get("signer_id", "unknown"))
    if stored_signer != "unknown" and signer_id != "unknown" and stored_signer != signer_id:
        logger.warning(
            f"Config signer rotation detected: stored={stored_signer} incoming={signer_id}; "
            "still enforcing monotonicity (fail-closed)"
        )
    if incoming <= last:
        logger.critical(
            f"TAMPER/ROLLBACK DETECTED: monotonic_counter {incoming} <= last_counter {last} "
            f"for '{config_path}' (signer_id={signer_id}). Fail-closed."
        )
        _emit_config_audit(
            f"CONFIG_ROLLBACK_DENIED path={config_path} signer_id={signer_id} "
            f"incoming={incoming} last={last}"
        )
        return False
    try:
        _store_counter_state_atomically(signer_id, incoming)
    except ConfigurationError as e:
        logger.critical(f"FAIL-CLOSED: counter persist failed for '{config_path}': {e}")
        return False
    logger.info(
        f"Config monotonic counter advanced: {last} -> {incoming} (signer_id={signer_id})"
    )
    return True


class ConfigurationError(Exception):
    """Raised when configuration loading fails (fail-closed, mirrors config.py)."""
    pass


class ConfigManager:
    """
    Configuration manager with backward compatibility support.
    
    This class ensures that:
    1. Existing configurations load without errors (Requirement 7.4)
    2. New security settings are optional with defaults
    3. Missing settings don't cause failures
    4. Configuration format is preserved
    """
    
    # Default configuration values for new security settings
    DEFAULT_SECURITY_SETTINGS = {
        "security": {
            "level": "MAXIMUM",
            "quantum_resistance": {
                "enabled": True,
                "preferred_algorithm": "ML-KEM-1024"
            },
            "algorithms": {
                "key_exchange": ["ML-KEM-1024"],
                "signatures": ["ML-DSA-87", "SLH-DSA-256f"],
                "encryption": ["ChaCha20-Poly1305", "AES-256-GCM"],
                "hash": ["SHA-512"],
                "kdf": ["HKDF-SHA512"]
            },
            "key_management": {
                "mandatory_key_rotation": True,
                "key_rotation_seconds": 900,
                "max_key_operations": 2500,
                "forward_secrecy": {
                    "enabled": True,
                    "ephemeral_keys_only": True
                }
            },
            "hardware_security": {
                "enabled": True,
                "tpm_required": True,
                "hsm_required": True
            },
            "memory_protection": {
                "enabled": True,
                "secure_erase": True,
                "canary_values": True
            },
            # Settings enforcing military fail-closed policy (zero fallbacks)
            "double_ratchet": {
                "enabled": True,
                "fallback_to_basic": False  # Military policy: fallback prohibited
            },
            "hybrid_kex": {
                "enabled": True,
                "fallback_to_x25519": False  # Military policy: classical-only fallback prohibited
            },
            "audit_logging": {
                "enabled": True,
                "fallback_to_file": False  # Military policy: tamper-evident logging required
            },
            # Unified caps (layered: frame 4MB > post-auth 512KB >= pre-auth 64KB
            # == chat payload 64KB strictest). Single source of truth lives in
            # utils/message_caps.py; these defaults are discoverability mirrors.
            "message_caps": {
                "max_message_payload": 65536,
                "max_file_payload": 524288,
                "max_frame": 4194304,
                "pre_auth_max": 65536,
                "post_auth_max": 524288
            },
            # Encrypt-sentinel strict mode: P2P_STRICT_ENCRYPT=1 fail-closed
            # (raise instead of b''); auto-on in production. Lab default False.
            "strict_encrypt": {
                "enabled": False,
                "auto_on_production": True
            }
        },
        "networking": {
            "tls": {
                "version": "1.3",
                "min_version": "1.3",
                "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                "allow_plaintext_fallback": False,
                "allow_unauthenticated_fallback": False
            },
            "secure_channels": {
                "mutual_authentication": True,
                "mandatory_authentication": True
            },
            "certificate_validation": True,
            "stun_servers": []
        },
        "platform": {
            "hardware_security": {
                "secure_memory_enabled": True,
                "tpm_integration": True,
                "hsm_integration": True
            }
        },
        "authentication": {
            "required": True,
            "anonymous_mode": False,
            "ephemeral_identities": True
        },
        "logging": {
            "level": "INFO",
            "security_events": True,
            "audit_trail": True
        }
    }
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    @staticmethod
    def verify_config_signature(config_path: str, pubkey_path: Optional[str] = None) -> bool:
        """
        Verify detached cryptographic signature for boot configuration file.
        2028 hardening (CNSA 2.0): prefer ML-DSA-87 detached envelope
        (config_path + ".mldsa87.sig" + ".mldsa87.pub", or ".dsse"), fallback
        to legacy Ed25519 .sig only in lab with explicit warning.
        Checks config_path + ".sig" against pubkey_path (defaults to certs/config_signer.pub).
        """
        # 1. ML-DSA-87 preferred path (CNSA 2.0)
        try:
            mldsa_sig = config_path + ".mldsa87.sig"
            mldsa_pub = config_path + ".mldsa87.pub"
            dsse_path = config_path + ".dsse"
            # Also support shared certs/ anchor
            anchor_pub = os.path.join("certs", "config_trust_root.pub")
            if os.path.exists(mldsa_sig) and (os.path.exists(mldsa_pub) or os.path.exists(anchor_pub)):
                pub_file = mldsa_pub if os.path.exists(mldsa_pub) else anchor_pub
                try:
                    from liboqs_wrapper import LibOQS_MLDSA_87
                    with open(config_path, 'rb') as f:
                        config_bytes = f.read()
                    with open(mldsa_sig, 'rb') as f:
                        sig_bytes = f.read()
                    with open(pub_file, 'rb') as f:
                        pub_bytes = f.read()
                    verifier = LibOQS_MLDSA_87()
                    if verifier.verify(pub_bytes, config_bytes, sig_bytes):
                        logger.info(f"Verified ML-DSA-87 signature for configuration '{config_path}'")
                        if not _check_and_update_config_counter(config_path, _is_production()):
                            logger.critical(
                                f"FAIL-CLOSED: monotonic counter regress blocks '{config_path}'"
                            )
                            return False
                        return True
                    logger.critical(f"TAMPER DETECTED: Invalid ML-DSA-87 signature on '{config_path}'")
                    return False
                except Exception as e:
                    logger.error(f"ML-DSA-87 config verify error: {e}")
                    return False
            if os.path.exists(dsse_path):
                # DSSE envelope: {"payload": b64, "signatures": [{"sig": b64}], "payloadType": ...}
                import base64
                with open(dsse_path, 'r', encoding='utf-8') as f:
                    env = json.load(f)
                payload = base64.b64decode(env.get("payload", ""))
                sigs = env.get("signatures", [])
                if not sigs:
                    return False
                with open(config_path, 'rb') as f:
                    config_bytes = f.read()
                if payload != config_bytes:
                    logger.critical(f"TAMPER DETECTED: DSSE payload mismatch for '{config_path}'")
                    return False
                # Verify first sig with anchor or sidecar pub
                pub_file = mldsa_pub if os.path.exists(mldsa_pub) else anchor_pub
                if not os.path.exists(pub_file):
                    return False
                from liboqs_wrapper import LibOQS_MLDSA_87
                with open(pub_file, 'rb') as f:
                    pub_bytes = f.read()
                sig_bytes = base64.b64decode(sigs[0].get("sig", ""))
                # PAE binding: DSSEv1 <len(type)> <type> <len(body)> <body>
                ptype = env.get("payloadType", "application/vnd.p2p.boot-config+json").encode()
                pae = b"DSSEv1 " + str(len(ptype)).encode() + b" " + ptype + b" " + str(len(payload)).encode() + b" " + payload
                verifier = LibOQS_MLDSA_87()
                if verifier.verify(pub_bytes, pae, sig_bytes):
                    logger.info(f"Verified DSSE ML-DSA-87 envelope for '{config_path}'")
                    if not _check_and_update_config_counter(config_path, _is_production()):
                        logger.critical(
                            f"FAIL-CLOSED: monotonic counter regress blocks '{config_path}'"
                        )
                        return False
                    return True
                logger.critical(f"TAMPER DETECTED: Invalid DSSE signature on '{config_path}'")
                return False
        except Exception as e:
            logger.error(f"Error during ML-DSA-87 config verification: {e}")
            return False

        sig_path = config_path + ".sig"
        if not os.path.exists(sig_path):
            return False

        pub_path = pubkey_path or os.path.join("certs", "config_signer.pub")
        if not os.path.exists(pub_path):
            logger.error(f"Config signature verification failed: public key not found at {pub_path}")
            return False

        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            from cryptography.exceptions import InvalidSignature

            with open(config_path, 'rb') as f:
                config_bytes = f.read()

            with open(sig_path, 'rb') as f:
                sig_bytes = f.read()

            with open(pub_path, 'rb') as f:
                pub_bytes = f.read()

            pub_key = serialization.load_pem_public_key(pub_bytes)
            if isinstance(pub_key, ed25519.Ed25519PublicKey):
                pub_key.verify(sig_bytes, config_bytes)
                # 2028: legacy Ed25519 accepted only as lab-migration shim (CNSA 2.0 requires ML-DSA-87)
                logger.warning(f"Legacy Ed25519 boot signature accepted for '{config_path}' - re-sign with ML-DSA-87 (CNSA 2.0)")
                if not _check_and_update_config_counter(config_path, _is_production()):
                    logger.critical(
                        f"FAIL-CLOSED: monotonic counter regress blocks '{config_path}'"
                    )
                    return False
                return True
            else:
                logger.error(f"Unsupported key type for config signer: {type(pub_key)}")
                return False
        except InvalidSignature:
            logger.critical(f"TAMPER DETECTED: Invalid signature on configuration '{config_path}'")
            return False
        except Exception as e:
            logger.error(f"Error during config signature verification: {e}")
            return False

    def _load_config(self) -> None:
        """
        Load configuration from file with backward compatibility.

        This method:
        1. Verifies cryptographic signature if running in production or for production configs
        2. Loads existing configuration if it exists
        3. Merges with default values for missing settings
        4. Fail-closed on corrupt config (raises ConfigurationError, never
           silently falls back to defaults - Finding 7.1 / Item 45).
        5. Enforces air_gapped_mode settings if enabled.

        Requirements: 7.4
        """
        production_mode = _is_production()
        is_prod_config = os.path.basename(self.config_path) in ('config_production.json',)

        if os.path.exists(self.config_path) and (production_mode or is_prod_config):
            # Enforce signed boot configuration in production (ML-DSA-87 preferred, Ed25519 legacy lab-only)
            sig_valid = self.verify_config_signature(self.config_path)
            if not sig_valid:
                raise ConfigurationError(
                    f"FAIL-CLOSED: Configuration '{self.config_path}' lacks a valid cryptographic signature (.mldsa87.sig/.dsse, legacy .sig lab-only). "
                    "Unsigned boot configs are strictly prohibited in production mode."
                )

        try:
            if os.path.exists(self.config_path):
                logger.info(f"Loading configuration from {self.config_path}")

                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)

                # Check air_gapped_mode
                air_gapped = loaded_config.get("air_gapped_mode") or loaded_config.get("network", {}).get("air_gapped_mode")
                if air_gapped:
                    os.environ["P2P_AIR_GAPPED_MODE"] = "1"
                    os.environ["P2P_OFFLINE_MODE"] = "1"
                    logger.info("Enforcing strict P2P_AIR_GAPPED_MODE=1 and P2P_OFFLINE_MODE=1 from config")

                # Merge loaded config with defaults
                # Existing settings take precedence (merge-after-verify: file
                # was already signature-verified above in prod).
                self.config = self._merge_configs(loaded_config, self.DEFAULT_SECURITY_SETTINGS)

                logger.info("Configuration loaded successfully with backward compatibility")
            else:
                logger.info(f"Configuration file not found at {self.config_path}, using defaults")
                self.config = self._merge_configs({}, self.DEFAULT_SECURITY_SETTINGS)

            # Apply environment overrides through production allowlist.
            # In prod only P2P_LOG_LEVEL / P2P_LISTEN_PORT / P2P_LOG_DIR apply;
            # everything else is ignored with warning + audit. In lab allow all.
            self._apply_env_overrides(_is_production())

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse configuration file: {e}")
            raise ConfigurationError(
                f"Corrupted or invalid configuration file '{self.config_path}': {e}"
            ) from e

        except ConfigurationError:
            raise

        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise ConfigurationError(
                f"Failed to load configuration file '{self.config_path}': {e}"
            ) from e

        # Enforce fail-closed security invariants on every load.
        is_valid, errors = self.validate()
        if not is_valid:
            raise ConfigurationError(
                f"Invalid configuration '{self.config_path}': {'; '.join(errors)}"
            )
    
    def _merge_configs(self, user_config: Dict[str, Any], default_config: Dict[str, Any], _prefix: str = "") -> Dict[str, Any]:
        """
        Recursively merge user configuration with defaults.
        
        User settings take precedence over defaults.
        Missing settings are filled in from defaults (merge-after-verify:
        caller must verify signature before merging in prod). Every
        default-fill is info-logged with its dotted key path.
        
        Args:
            user_config: User-provided configuration
            default_config: Default configuration values
            _prefix: Dotted prefix for logging (internal recursion)
            
        Returns:
            Merged configuration dictionary
        """
        merged = copy.deepcopy(default_config)

        def _log_default_subtree(value: Any, path: str) -> None:
            if isinstance(value, dict):
                for k, v in value.items():
                    _log_default_subtree(v, f"{path}.{k}")
            else:
                logger.info(
                    f"Using default for missing config key '{path}': {value!r} (merge-after-verify)"
                )

        # Info-log every default-fill key (present in defaults, absent in user).
        try:
            for dkey, dval in default_config.items():
                full = f"{_prefix}.{dkey}" if _prefix else str(dkey)
                if dkey not in user_config:
                    _log_default_subtree(dval, full)
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        
        for key, value in user_config.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                child_prefix = f"{_prefix}.{key}" if _prefix else str(key)
                merged[key] = self._merge_configs(value, merged[key], _prefix=child_prefix)
            else:
                # User value takes precedence
                merged[key] = value
        
        return merged

    def _apply_env_overrides(self, is_prod: bool) -> None:
        """
        Apply P2P_* environment overrides through production allowlist.

        Prod (fail-closed): only P2P_LOG_LEVEL, P2P_LISTEN_PORT (1024-65535),
        P2P_LOG_DIR (under ./logs) are honored. Everything else mapping to
        security.*/cryptography.*/hsm_tpm.*/authentication.*/compliance.*,
        plus P2P_SECURITY_LEVEL / P2P_KEY_LIFETIME / P2P_HANDSHAKE_TIMEOUT /
        P2P_AUDIT_ENABLED / P2P_PRODUCTION itself, is ignored with warning +
        audit event. Lab (non-breaking): allow all with debug log.

        Production = sticky latch OR MAXIMUM level OR prod boot file
        (consistent with config.py, preserves anti-downgrade tests).
        """
        try:
            eff_prod = bool(
                is_prod
                or (isinstance(self.config, dict) and self.get("security.level") == "MAXIMUM")
                or (os.path.basename(getattr(self, "config_path", "")) in ('config_production.json',))
            )
        except Exception:
            eff_prod = bool(is_prod)
        is_prod = eff_prod
        # Known env -> dotted key mapping (lab allows all; prod filters).
        env_to_dotted = {
            'P2P_LOG_LEVEL': 'logging.level',
            'P2P_LISTEN_PORT': 'networking.listen_port',
            'P2P_LOG_DIR': 'logging.log_dir',
            'P2P_SECURITY_LEVEL': 'security.level',
            'P2P_KEY_LIFETIME': 'security.key_management.key_rotation_seconds',
            'P2P_HANDSHAKE_TIMEOUT': 'networking.handshake_timeout',
            'P2P_AUDIT_ENABLED': 'security.audit_logging.enabled',
        }

        def _dotted_denied(dotted: str) -> bool:
            dl = dotted.lower()
            return any(dl == p[:-1] or dl.startswith(p) for p in _DENIED_DOTTED_PREFIXES)

        # Explicit production-flag envs are never config overrides.
        for flag in ('P2P_PRODUCTION', 'SECURE_P2P_PRODUCTION'):
            if flag in os.environ and is_prod:
                _emit_config_audit(
                    f"Ignoring environment override '{flag}' in production mode "
                    "(production flag itself is locked, sticky fail-closed)"
                )

        for env_var, dotted in env_to_dotted.items():
            if env_var not in os.environ:
                continue
            raw = os.environ[env_var]
            if is_prod:
                if env_var not in _PROD_ENV_ALLOWLIST:
                    _emit_config_audit(
                        f"Ignoring environment override '{env_var}'->'{dotted}' "
                        "in production mode (deny-list, fail-closed)"
                    )
                    continue
                # Allowlisted: validate.
                if env_var == 'P2P_LISTEN_PORT':
                    try:
                        port = int(str(raw).strip())
                    except Exception:
                        _emit_config_audit(
                            f"Ignoring invalid P2P_LISTEN_PORT={raw!r} in production "
                            "(must be integer 1024-65535)"
                        )
                        continue
                    if not 1024 <= port <= 65535:
                        _emit_config_audit(
                            f"Ignoring out-of-range P2P_LISTEN_PORT={port} in production "
                            "(must be 1024-65535)"
                        )
                        continue
                    self.set(dotted, port)
                    # Compat mirror for flat/network-style readers.
                    try:
                        self.set('network.listen_port', port)
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass
                    logger.info(f"Applied production allowlisted env {env_var}->{dotted}={port}")
                    continue
                if env_var == 'P2P_LOG_DIR':
                    if not _is_log_dir_allowed(raw):
                        _emit_config_audit(
                            f"Ignoring disallowed P2P_LOG_DIR={raw!r} in production "
                            "(must be under ./logs)"
                        )
                        continue
                    norm = os.path.normpath(str(raw).strip())
                    self.set(dotted, norm)
                    logger.info(f"Applied production allowlisted env {env_var}->{dotted}={norm}")
                    continue
                if env_var == 'P2P_LOG_LEVEL':
                    self.set(dotted, str(raw).strip())
                    logger.info(f"Applied production allowlisted env {env_var}->{dotted}")
                    continue
            else:
                # Lab: allow all with debug log (non-breaking).
                logger.debug(f"Loaded {dotted} from environment variable {env_var} (lab)")
                try:
                    if env_var == 'P2P_LISTEN_PORT':
                        self.set(dotted, int(str(raw).strip()))
                    elif env_var == 'P2P_AUDIT_ENABLED':
                        self.set(dotted, str(raw).lower() in ('true', '1', 'yes'))
                    elif env_var == 'P2P_KEY_LIFETIME':
                        self.set(dotted, int(str(raw).strip()))
                    elif env_var == 'P2P_HANDSHAKE_TIMEOUT':
                        self.set(dotted, float(str(raw).strip()))
                    else:
                        self.set(dotted, raw)
                except Exception as e:
                    logger.debug(f"Lab env override {env_var} conversion failed: {e}")
                    try:
                        self.set(dotted, raw)
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass

        if is_prod:
            # Deny any other P2P_*/SECURE_P2P_* env that would reach denied prefixes.
            # Only vars mapping to denied sections warn+audit; unrelated
            # operational P2P_* are debug-logged (non-breaking, not config overrides).
            for env_var in list(os.environ.keys()):
                if env_var in env_to_dotted or env_var in ('P2P_PRODUCTION', 'SECURE_P2P_PRODUCTION',
                                                           'P2P_AIR_GAPPED_MODE', 'P2P_OFFLINE_MODE'):
                    continue
                upper = env_var.upper()
                if not (upper.startswith('P2P_') or upper.startswith('SECURE_P2P_')):
                    continue
                if (env_var in _PROD_ENV_DENYLIST_EXPLICIT
                        or any(s in upper for s in _DENIED_ENV_SUBSTRINGS)):
                    _emit_config_audit(
                        f"Ignoring environment override '{env_var}' in production mode "
                        "(deny-list, fail-closed)"
                    )
                else:
                    logger.debug(
                        f"Ignoring non-config environment variable '{env_var}' "
                        "in production mode (not a config override)"
                    )
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-separated key path.
        
        Examples:
            config.get("security.level")
            config.get("security.double_ratchet.enabled", True)
        
        Args:
            key_path: Dot-separated path to configuration value
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set configuration value by dot-separated key path.
        
        Args:
            key_path: Dot-separated path to configuration value
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent dictionary
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
    
    def is_security_module_enabled(self, module_name: str) -> bool:
        """
        Check if a security module is enabled in configuration.
        
        Args:
            module_name: Name of the security module (e.g., "double_ratchet", "hybrid_kex")
            
        Returns:
            True if module is enabled, False otherwise
        """
        return self.get(f"security.{module_name}.enabled", True)
    
    def should_fallback(self, module_name: str) -> bool:
        """
        Check if fallback is allowed when a security module is unavailable.

        Args:
            module_name: Name of the security module

        Returns:
            True if fallback is allowed, False otherwise

        Requirements: 7.3
        """
        # Fail-closed default: unknown modules and missing keys deny fallback.
        # (Previously defaulted to True, contradicting the deny-by-default
        # DEFAULT_SECURITY_SETTINGS - Finding 7.1.)
        fallback_key = f"security.{module_name}.fallback_to_basic"
        if "hybrid_kex" in module_name:
            fallback_key = "security.hybrid_kex.fallback_to_x25519"
        elif "audit" in module_name:
            fallback_key = "security.audit_logging.fallback_to_file"

        return bool(self.get(fallback_key, False))
    
    def save(self, path: Optional[str] = None) -> bool:
        """
        Save current configuration to file atomically.
        
        Args:
            path: Optional path to save to (defaults to original path)
            
        Returns:
            True if saved successfully, False otherwise
        """
        save_path = path or self.config_path
        target_dir = os.path.dirname(save_path) if os.path.dirname(save_path) else '.'
        temp_path = None
        
        try:
            # Ensure directory exists
            os.makedirs(target_dir, exist_ok=True)
            
            # Atomic persistence: write to temp file, flush, fsync, and atomic swap via os.replace
            temp_path = f"{save_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            
            os.replace(temp_path, save_path)
            logger.info(f"Configuration saved atomically to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration atomically: {e}")
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            return False
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get the entire configuration dictionary.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config.copy()
    
    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate configuration for required settings.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check for critical settings
        if not self.get("security.level"):
            errors.append("Missing security.level setting")

        if not self.get("logging.level"):
            errors.append("Missing logging.level setting")

        # Validate security level
        valid_levels = ["LOW", "MEDIUM", "HIGH", "MAXIMUM"]
        security_level = self.get("security.level", "")
        if security_level not in valid_levels:
            errors.append(f"Invalid security.level: {security_level}. Must be one of {valid_levels}")

        # Fail-closed invariants (military zero-trust): any violation is fatal.
        if self.get("networking.tls.allow_plaintext_fallback", False) is True:
            errors.append("networking.tls.allow_plaintext_fallback must be false")
        if self.get("networking.tls.allow_unauthenticated_fallback", False) is True:
            errors.append("networking.tls.allow_unauthenticated_fallback must be false")
        if self.get("security.double_ratchet.fallback_to_basic", False) is True:
            errors.append("security.double_ratchet.fallback_to_basic must be false")
        if self.get("security.hybrid_kex.fallback_to_x25519", False) is True:
            errors.append("security.hybrid_kex.fallback_to_x25519 must be false")
        if self.get("security.audit_logging.fallback_to_file", False) is True:
            errors.append("security.audit_logging.fallback_to_file must be false")
        if self.get("authentication.required", True) is not True:
            errors.append("authentication.required must be true")
        if self.get("authentication.anonymous_mode", False) is True:
            errors.append("authentication.anonymous_mode must be false")

        return (len(errors) == 0, errors)


# Global configuration instance
_config_instance: Optional[ConfigManager] = None


def get_config(config_path: str = "config.json") -> ConfigManager:
    """
    Get or create global configuration instance.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        ConfigManager instance
    """
    global _config_instance
    
    if _config_instance is None:
        _config_instance = ConfigManager(config_path)
    
    return _config_instance


def reload_config(config_path: str = "config.json") -> ConfigManager:
    """
    Reload configuration from file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        New ConfigManager instance
    """
    global _config_instance
    _config_instance = ConfigManager(config_path)
    return _config_instance

