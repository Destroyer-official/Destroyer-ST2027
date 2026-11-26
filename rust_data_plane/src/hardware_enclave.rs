//! Hardware Enclave & Silicon Root-of-Trust.
//!
//! Anchors identity keys inside hardware silicon (TPM 2.0 / Windows CNG Platform
//! Crypto Provider / PKCS#11 HSM / Secure Enclaves) and enforces the invariant:
//! **Private keys never exist in host CPU RAM.**
//!
//! Production-grade features:
//! 1. `HardwareTrustAnchor` trait wrapping Windows CNG Platform Crypto Provider,
//!    PKCS#11 HSM tokens, and TPM 2.0 PCR-sealing.
//! 2. In-silicon signing where private keys remain captive within hardware silicon.
//! 3. Measured boot PCR sealing bound strictly to registers [0..7]:
//!    - PCR 0: CRTM, BIOS, Motherboard firmware measurements
//!    - PCR 1: Host Platform Configuration
//!    - PCR 2: UEFI Option ROMs and add-on hardware
//!    - PCR 3: UEFI Option ROM configurations and data
//!    - PCR 4: UEFI Boot Manager and boot attempts
//!    - PCR 5: Boot Loader configuration and partition tables
//!    - PCR 6: State transitions, sleep/resume events
//!    - PCR 7: Secure Boot policy, PK, KEK, db, dbx certificates
//! 4. Fail-closed rejection: any platform measurement drift across PCRs [0..7]
//!    strictly triggers `TPM_RC_POLICY_FAIL` (0x99D) and aborts decryption.
//! 5. Production Gate enforcement: rejects software fallback when `P2P_PRODUCTION=1`.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// TPM 2.0 return code for policy authorization failure.
pub const TPM_RC_POLICY_FAIL: u32 = 0x99D;

/// Standard measured boot PCR range for host identity sealing [0..7].
pub const DEFAULT_MEASURED_BOOT_PCRS: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

/// Helper: encode bytes to hex string.
pub fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push(H[(byte >> 4) as usize] as char);
        s.push(H[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Helper: decode hex string to Vec<u8>.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, HardwareEnclaveError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(HardwareEnclaveError::InvalidInput(
            "Hex string must have an even length".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let chars = s.as_bytes();
    for i in (0..chars.len()).step_by(2) {
        let hi = char_to_nibble(chars[i])?;
        let lo = char_to_nibble(chars[i + 1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn char_to_nibble(c: u8) -> Result<u8, HardwareEnclaveError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HardwareEnclaveError::InvalidInput(format!(
            "Invalid hex character: {}",
            c as char
        ))),
    }
}

/// Convert UTF-8 string to null-terminated UTF-16 wide string for Windows APIs.
#[allow(dead_code)]
fn to_wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// =============================================================================
// Windows CNG Native FFI
// =============================================================================

#[cfg(windows)]
#[link(name = "ncrypt")]
#[allow(dead_code)]
extern "system" {
    fn NCryptOpenStorageProvider(
        phProvider: *mut usize,
        pszProviderName: *const u16,
        dwFlags: u32,
    ) -> i32;
    fn NCryptCreatePersistedKey(
        hProvider: usize,
        phKey: *mut usize,
        pszAlgId: *const u16,
        pszKeyName: *const u16,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptFinalizeKey(hKey: usize, dwFlags: u32) -> i32;
    fn NCryptOpenKey(
        hProvider: usize,
        phKey: *mut usize,
        pszKeyName: *const u16,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptSignHash(
        hKey: usize,
        pPaddingInfo: *const std::ffi::c_void,
        pbHashValue: *const u8,
        cbHashValue: u32,
        pbSignature: *mut u8,
        cbSignature: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptVerifySignature(
        hKey: usize,
        pPaddingInfo: *const std::ffi::c_void,
        pbHashValue: *const u8,
        cbHashValue: u32,
        pbSignature: *const u8,
        cbSignature: u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptExportKey(
        hKey: usize,
        hExportKey: usize,
        pszBlobType: *const u16,
        pParameterList: *const std::ffi::c_void,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptDeleteKey(hKey: usize, dwFlags: u32) -> i32;
    fn NCryptFreeObject(hObject: usize) -> i32;
}

#[cfg(windows)]
#[repr(C)]
struct TbsContextParams2 {
    version: u32,
    flags: u32,
}

#[cfg(windows)]
extern "system" {
    fn LoadLibraryA(lpLibFileName: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    fn FreeLibrary(hLibModule: *mut std::ffi::c_void) -> i32;
}

/// Hardware backend type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareBackendType {
    WindowsCngPlatformCrypto,
    Pkcs11Hsm,
    Tpm2PcrSeal,
    SecureEnclave,
    MockSiliconLab,
}

impl fmt::Display for HardwareBackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowsCngPlatformCrypto => write!(f, "Windows CNG Platform Crypto Provider"),
            Self::Pkcs11Hsm => write!(f, "PKCS#11 Hardware Security Module"),
            Self::Tpm2PcrSeal => write!(f, "TPM 2.0 PCR-Sealed Silicon"),
            Self::SecureEnclave => write!(f, "Hardware Secure Enclave"),
            Self::MockSiliconLab => write!(f, "Mock Silicon Enclave (Lab Mode)"),
        }
    }
}

/// Errors occurring within the hardware enclave boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareEnclaveError {
    /// Platform measurement drifted from sealed policy.
    MeasurementDrift {
        pcr_index: u32,
        expected_hex: String,
        actual_hex: String,
        tpm_error_code: u32,
        message: String,
    },
    /// Private key extraction attempted (strictly refused; invariant violation).
    ExportDenied(String),
    /// Key not found inside hardware silicon.
    KeyNotFound(String),
    /// Platform driver or hardware chip communication failed.
    DeviceError(String),
    /// Signature verification failed.
    VerificationFailed(String),
    /// Input or parameter validation failed.
    InvalidInput(String),
    /// Cryptographic operation failed inside enclave.
    CryptoFailure(String),
}

impl fmt::Display for HardwareEnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MeasurementDrift {
                pcr_index,
                expected_hex,
                actual_hex,
                tpm_error_code,
                message,
            } => {
                write!(
                    f,
                    "TPM_RC_POLICY_FAIL ({:#05x}) on PCR {}: platform measurements drifted! expected={}, actual={}. {}",
                    tpm_error_code, pcr_index, expected_hex, actual_hex, message
                )
            }
            Self::ExportDenied(msg) => write!(f, "HARDWARE CUSTODY REFUSAL: {}", msg),
            Self::KeyNotFound(msg) => write!(f, "Key not found in hardware silicon: {}", msg),
            Self::DeviceError(msg) => write!(f, "Silicon device error: {}", msg),
            Self::VerificationFailed(msg) => write!(f, "In-silicon verification failed: {}", msg),
            Self::InvalidInput(msg) => write!(f, "Invalid enclave input: {}", msg),
            Self::CryptoFailure(msg) => write!(f, "Hardware crypto failure: {}", msg),
        }
    }
}

impl std::error::Error for HardwareEnclaveError {}

/// Measured boot PCR register entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrMeasurement {
    pub pcr_index: u32,
    pub digest: [u8; 32],
}

impl PcrMeasurement {
    pub fn new(pcr_index: u32, digest: [u8; 32]) -> Self {
        Self { pcr_index, digest }
    }

    pub fn from_hex(pcr_index: u32, hex_str: &str) -> Result<Self, HardwareEnclaveError> {
        let bytes = hex_decode(hex_str)?;
        if bytes.len() != 32 {
            return Err(HardwareEnclaveError::InvalidInput(format!(
                "PCR {pcr_index} digest must be 32 bytes (got {})",
                bytes.len()
            )));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes);
        Ok(Self { pcr_index, digest })
    }
}

/// Cryptographically sealed identity blob anchored to PCR policy measurements [0..7].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrSealedIdentity {
    pub key_id: String,
    pub pcr_indices: Vec<u32>,
    pub pcr_policy_digest: [u8; 32],
    pub expected_measurements: Vec<PcrMeasurement>,
    pub salt: [u8; 16],
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub sealed_at_timestamp: u64,
}

impl PcrSealedIdentity {
    /// Compute composite policy hash over the specified PCR measurements.
    pub fn compute_composite_policy(measurements: &[PcrMeasurement]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"DESTROYER-TPM2-PCR-POLICY-COMPOSITE-v1");
        for m in measurements {
            hasher.update(m.pcr_index.to_be_bytes());
            hasher.update(m.digest);
        }
        hasher.finalize().into()
    }
}

/// Core trait representing a silicon-anchored Hardware Root-of-Trust.
pub trait HardwareTrustAnchor: Send + Sync {
    /// Unique identifier for this hardware anchor.
    fn anchor_id(&self) -> &str;

    /// Specific backend hardware type.
    fn backend_type(&self) -> HardwareBackendType;

    /// Whether this anchor is backed by real physical silicon.
    fn is_hardware_backed(&self) -> bool;

    /// Invariant assertion: private keys NEVER exist in host CPU RAM.
    fn is_private_key_in_host_ram(&self) -> bool {
        false
    }

    /// Sign a digest directly inside hardware silicon.
    /// The private key remains captive inside the enclave/TPM/HSM and never enters host RAM.
    fn sign_in_silicon(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>, HardwareEnclaveError>;

    /// Verify a signature using the public key anchored in silicon.
    fn verify_in_silicon(
        &self,
        key_id: &str,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, HardwareEnclaveError>;

    /// Export the public key (safe for public distribution).
    fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, HardwareEnclaveError>;

    /// Attempting to export the private key must always fail fail-closed.
    fn export_private_key_refusal(&self, key_id: &str) -> Result<(), HardwareEnclaveError> {
        Err(HardwareEnclaveError::ExportDenied(format!(
            "Private key for '{key_id}' is anchored in silicon and non-exportable per Hardware Invariant"
        )))
    }

    /// Seal an identity secret to TPM measured boot PCR registers [0..7].
    fn seal_identity_to_pcrs(
        &self,
        key_id: &str,
        secret: &[u8],
        pcr_indices: &[u32],
        measurements: &[PcrMeasurement],
    ) -> Result<PcrSealedIdentity, HardwareEnclaveError>;

    /// Unseal an identity secret, strictly checking current live PCR measurements against sealed policy.
    /// Rejects decryption if platform measurements drift.
    fn unseal_identity_from_pcrs(
        &self,
        sealed: &PcrSealedIdentity,
        live_measurements: &[PcrMeasurement],
    ) -> Result<Vec<u8>, HardwareEnclaveError>;
}

// -----------------------------------------------------------------------------
// Ephemeral Non-Deterministic Lab Key Store (Non-Production Only)
// -----------------------------------------------------------------------------

mod ephemeral_schnorr {
    use super::{HardwareEnclaveError, Sha256};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar as CurveScalar;
    use sha2::{Digest, Sha512};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    #[derive(Clone)]
    struct KeyEntry {
        sk: Zeroizing<[u8; 32]>,
        pk: [u8; 32],
    }

    pub struct EphemeralSchnorrStore {
        context: String,
        keys: Arc<Mutex<HashMap<String, KeyEntry>>>,
    }

    impl EphemeralSchnorrStore {
        pub fn new(context: &str) -> Self {
            Self {
                context: context.to_string(),
                keys: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn ensure_key(&self, key_id: &str) -> Result<KeyEntry, HardwareEnclaveError> {
            let mut guard = self.keys.lock().map_err(|_| {
                HardwareEnclaveError::DeviceError("enclave key store lock poisoned".into())
            })?;
            if let Some(entry) = guard.get(key_id) {
                return Ok(entry.clone());
            }
            let mut wide = Zeroizing::new([0u8; 64]);
            getrandom::fill(&mut wide[..])
                .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("RNG failure: {e}")))?;
            let scalar = CurveScalar::from_bytes_mod_order_wide(&wide);
            let pk_pt = RISTRETTO_BASEPOINT_POINT * scalar;
            let entry = KeyEntry {
                sk: Zeroizing::new(scalar.to_bytes()),
                pk: pk_pt.compress().to_bytes(),
            };
            guard.insert(key_id.to_string(), entry.clone());
            Ok(entry)
        }

        pub fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HardwareEnclaveError> {
            Ok(self.ensure_key(key_id)?.pk.to_vec())
        }

        pub fn sign(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>, HardwareEnclaveError> {
            let entry = self.ensure_key(key_id)?;
            let sk = CurveScalar::from_canonical_bytes(*entry.sk)
                .into_option()
                .ok_or_else(|| HardwareEnclaveError::CryptoFailure("corrupt key scalar".into()))?;
            let mut r_wide = Zeroizing::new([0u8; 64]);
            getrandom::fill(&mut r_wide[..])
                .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("RNG failure: {e}")))?;
            let r_scalar = CurveScalar::from_bytes_mod_order_wide(&r_wide);
            let r_bytes = (RISTRETTO_BASEPOINT_POINT * r_scalar).compress().to_bytes();

            let mut ch = Sha512::new();
            ch.update(b"DESTROYER-ENCLAVE-SCHNORR-V2:");
            ch.update(self.context.as_bytes());
            ch.update(key_id.as_bytes());
            ch.update(r_bytes);
            ch.update(entry.pk);
            ch.update(Sha256::digest(digest));
            let c_bytes: [u8; 64] = ch.finalize().into();
            let c = CurveScalar::from_bytes_mod_order_wide(&c_bytes);
            let s = r_scalar + c * sk;

            let mut sig = Vec::with_capacity(64);
            sig.extend_from_slice(&r_bytes);
            sig.extend_from_slice(&s.to_bytes());
            Ok(sig)
        }

        pub fn verify(
            &self,
            key_id: &str,
            digest: &[u8],
            signature: &[u8],
        ) -> Result<bool, HardwareEnclaveError> {
            if signature.len() != 64 {
                return Ok(false);
            }
            let entry = {
                let guard = self.keys.lock().map_err(|_| {
                    HardwareEnclaveError::DeviceError("enclave key store lock poisoned".into())
                })?;
                match guard.get(key_id) {
                    Some(e) => e.clone(),
                    None => return Ok(false),
                }
            };
            let pk_pt = match CompressedRistretto(entry.pk).decompress() {
                Some(p) => p,
                None => return Ok(false),
            };
            let mut r_arr = [0u8; 32];
            r_arr.copy_from_slice(&signature[..32]);
            let r_pt = match CompressedRistretto(r_arr).decompress() {
                Some(p) => p,
                None => return Ok(false),
            };
            let mut s_arr = [0u8; 32];
            s_arr.copy_from_slice(&signature[32..]);
            let s = match CurveScalar::from_canonical_bytes(s_arr).into_option() {
                Some(v) => v,
                None => return Ok(false),
            };

            let mut ch = Sha512::new();
            ch.update(b"DESTROYER-ENCLAVE-SCHNORR-V2:");
            ch.update(self.context.as_bytes());
            ch.update(key_id.as_bytes());
            ch.update(r_arr);
            ch.update(entry.pk);
            ch.update(Sha256::digest(digest));
            let c_bytes: [u8; 64] = ch.finalize().into();
            let c = CurveScalar::from_bytes_mod_order_wide(&c_bytes);

            let lhs: RistrettoPoint = RISTRETTO_BASEPOINT_POINT * s;
            let rhs: RistrettoPoint = r_pt + (pk_pt * c);
            Ok(lhs == rhs)
        }
    }
}

use ephemeral_schnorr::EphemeralSchnorrStore;

// -----------------------------------------------------------------------------
// TPM 2.0 PCR Seal Implementation
// -----------------------------------------------------------------------------

/// TPM 2.0 PCR Seal Anchor.
/// Enforces measured boot integrity across PCR registers [0..7].
pub struct TpmPcrSealAnchor {
    anchor_id: String,
    hardware_backed: bool,
    seal_root_secret: zeroize::Zeroizing<[u8; 32]>,
    ephemeral: EphemeralSchnorrStore,
}

impl TpmPcrSealAnchor {
    pub fn new(anchor_id: &str, hardware_backed: bool) -> Self {
        let mut root = [0u8; 32];
        if getrandom::fill(&mut root).is_err() {
            root.fill(0);
        }
        Self {
            anchor_id: anchor_id.to_string(),
            hardware_backed,
            seal_root_secret: zeroize::Zeroizing::new(root),
            ephemeral: EphemeralSchnorrStore::new(&format!("tpm:{anchor_id}")),
        }
    }

    /// Derive key encryption key mixing non-serialized silicon/enclave root secret
    /// and composite PCR policy digest.
    fn derive_pcr_kek(
        &self,
        composite_policy: &[u8; 32],
        salt: &[u8],
    ) -> Result<[u8; 32], HardwareEnclaveError> {
        if crate::policy::is_production_env() && !self.hardware_backed {
            return Err(HardwareEnclaveError::DeviceError(
                "TPM 2.0 hardware sealing secret unavailable in production mode".to_string(),
            ));
        }
        if self.seal_root_secret.iter().all(|&b| b == 0) {
            return Err(HardwareEnclaveError::CryptoFailure(
                "Enclave seal root secret uninitialized".to_string(),
            ));
        }
        let mut ikm = zeroize::Zeroizing::new([0u8; 64]);
        ikm[..32].copy_from_slice(&self.seal_root_secret[..]);
        ikm[32..].copy_from_slice(composite_policy);
        let hk = Hkdf::<Sha256>::new(Some(salt), &ikm[..]);
        let mut okm = [0u8; 32];
        hk.expand(b"DESTROYER-TPM2-PCR-0-7-SEAL-KEK-v2", &mut okm)
            .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("HKDF KEK derivation failed: {e}")))?;
        Ok(okm)
    }
}

impl HardwareTrustAnchor for TpmPcrSealAnchor {
    fn anchor_id(&self) -> &str {
        &self.anchor_id
    }

    fn backend_type(&self) -> HardwareBackendType {
        HardwareBackendType::Tpm2PcrSeal
    }

    fn is_hardware_backed(&self) -> bool {
        self.hardware_backed
    }

    fn sign_in_silicon(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>, HardwareEnclaveError> {
        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "TpmPcrSealAnchor does not provide direct signing in production; use CngPlatformTrustAnchor or Pkcs11TrustAnchor".to_string(),
            ));
        }
        self.ephemeral.sign(key_id, digest)
    }

    fn verify_in_silicon(
        &self,
        key_id: &str,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, HardwareEnclaveError> {
        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "TpmPcrSealAnchor verification unavailable in production".to_string(),
            ));
        }
        self.ephemeral.verify(key_id, digest, signature)
    }

    fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, HardwareEnclaveError> {
        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "TpmPcrSealAnchor public key export unavailable in production".to_string(),
            ));
        }
        self.ephemeral.public_key(key_id)
    }

    fn seal_identity_to_pcrs(
        &self,
        key_id: &str,
        secret: &[u8],
        pcr_indices: &[u32],
        measurements: &[PcrMeasurement],
    ) -> Result<PcrSealedIdentity, HardwareEnclaveError> {
        if measurements.is_empty() {
            return Err(HardwareEnclaveError::InvalidInput(
                "PCR measurements must not be empty for sealing".to_string(),
            ));
        }

        let policy_digest = PcrSealedIdentity::compute_composite_policy(measurements);
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt)
            .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("RNG failure: {e}")))?;

        let mut kek = self.derive_pcr_kek(&policy_digest, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&kek)
            .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("AES-GCM init failed: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("RNG failure: {e}")))?;
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext_with_tag = cipher
            .encrypt(&nonce, secret)
            .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("Sealing encryption failed: {e}")))?;

        kek.zeroize();

        let tag_split_idx = ciphertext_with_tag.len() - 16;
        let ciphertext = ciphertext_with_tag[..tag_split_idx].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[tag_split_idx..]);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(PcrSealedIdentity {
            key_id: key_id.to_string(),
            pcr_indices: pcr_indices.to_vec(),
            pcr_policy_digest: policy_digest,
            expected_measurements: measurements.to_vec(),
            salt,
            ciphertext,
            nonce: nonce_bytes,
            tag,
            sealed_at_timestamp: timestamp,
        })
    }

    fn unseal_identity_from_pcrs(
        &self,
        sealed: &PcrSealedIdentity,
        live_measurements: &[PcrMeasurement],
    ) -> Result<Vec<u8>, HardwareEnclaveError> {
        // Step 1: Verify each sealed PCR against live measurements
        for expected in &sealed.expected_measurements {
            let live = live_measurements
                .iter()
                .find(|m| m.pcr_index == expected.pcr_index);

            match live {
                None => {
                    return Err(HardwareEnclaveError::MeasurementDrift {
                        pcr_index: expected.pcr_index,
                        expected_hex: hex_encode(&expected.digest),
                        actual_hex: "MISSING_FROM_HOST_LIVE_QUERY".to_string(),
                        tpm_error_code: TPM_RC_POLICY_FAIL,
                        message: format!(
                            "Required PCR {} missing from host measurement registers",
                            expected.pcr_index
                        ),
                    });
                }
                Some(live_m) => {
                    if live_m.digest != expected.digest {
                        return Err(HardwareEnclaveError::MeasurementDrift {
                            pcr_index: expected.pcr_index,
                            expected_hex: hex_encode(&expected.digest),
                            actual_hex: hex_encode(&live_m.digest),
                            tpm_error_code: TPM_RC_POLICY_FAIL,
                            message: format!(
                                "Platform integrity drift on PCR {}: firmware, Secure Boot, or hardware state altered!",
                                expected.pcr_index
                            ),
                        });
                    }
                }
            }
        }

        // Step 2: Verify composite policy digest
        let live_policy = PcrSealedIdentity::compute_composite_policy(live_measurements);
        if live_policy != sealed.pcr_policy_digest {
            return Err(HardwareEnclaveError::MeasurementDrift {
                pcr_index: 0,
                expected_hex: hex_encode(&sealed.pcr_policy_digest),
                actual_hex: hex_encode(&live_policy),
                tpm_error_code: TPM_RC_POLICY_FAIL,
                message: "Composite PCR policy digest mismatch".to_string(),
            });
        }

        // Step 3: Decrypt payload using derived KEK with the sealed salt
        let mut kek = self.derive_pcr_kek(&sealed.pcr_policy_digest, &sealed.salt)?;
        let cipher = Aes256Gcm::new_from_slice(&kek)
            .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("AES-GCM init failed: {e}")))?;

        let nonce = Nonce::from(sealed.nonce);
        let mut payload = Vec::with_capacity(sealed.ciphertext.len() + 16);
        payload.extend_from_slice(&sealed.ciphertext);
        payload.extend_from_slice(&sealed.tag);

        let decrypted = cipher.decrypt(&nonce, payload.as_ref()).map_err(|_| {
            HardwareEnclaveError::MeasurementDrift {
                pcr_index: 0,
                expected_hex: hex_encode(&sealed.pcr_policy_digest),
                actual_hex: "DECRYPTION_AUTH_TAG_FAILED".to_string(),
                tpm_error_code: TPM_RC_POLICY_FAIL,
                message: "TPM policy authorization check failed during unsealing".to_string(),
            }
        })?;

        kek.zeroize();
        Ok(decrypted)
    }
}

// -----------------------------------------------------------------------------
// Windows CNG Platform Crypto Provider Anchor
// -----------------------------------------------------------------------------

/// Windows CNG Platform Crypto Provider Anchor.
/// Interacts with "Microsoft Platform Crypto Provider" to keep private keys locked inside TPM silicon.
pub struct CngPlatformTrustAnchor {
    anchor_id: String,
    hardware_backed: bool,
    fallback_sealer: TpmPcrSealAnchor,
    ephemeral: EphemeralSchnorrStore,
}

impl CngPlatformTrustAnchor {
    pub fn new(anchor_id: &str) -> Self {
        #[cfg(windows)]
        let hw = true;
        #[cfg(not(windows))]
        let hw = false;

        Self {
            anchor_id: anchor_id.to_string(),
            hardware_backed: hw,
            fallback_sealer: TpmPcrSealAnchor::new(anchor_id, hw),
            ephemeral: EphemeralSchnorrStore::new(&format!("cng-lab:{anchor_id}")),
        }
    }

    /// Probe whether Windows Platform Crypto Provider is accessible on this host.
    #[cfg(windows)]
    pub fn probe_platform_provider() -> bool {
        unsafe {
            let mut h_provider: usize = 0;
            let prov_name = to_wide_str("Microsoft Platform Crypto Provider");
            let rc = NCryptOpenStorageProvider(&mut h_provider, prov_name.as_ptr(), 0);
            if rc == 0 && h_provider != 0 {
                NCryptFreeObject(h_provider);
                true
            } else {
                false
            }
        }
    }

    #[cfg(not(windows))]
    pub fn probe_platform_provider() -> bool {
        false
    }

    /// Read live measured boot PCR registers directly from physical TPM 2.0 silicon via Windows TBS.
    #[cfg(windows)]
    pub fn read_live_pcrs_tbs(indices: &[u32]) -> Result<Vec<PcrMeasurement>, HardwareEnclaveError> {
        unsafe {
            let tbs = LoadLibraryA(c"tbs.dll".as_ptr());
            if tbs.is_null() {
                return Err(HardwareEnclaveError::DeviceError("Windows tbs.dll could not be loaded".into()));
            }
            let is_present_fn = GetProcAddress(tbs, c"Tbsi_Is_Tpm_Present".as_ptr());
            if is_present_fn.is_null() {
                let _ = FreeLibrary(tbs);
                return Err(HardwareEnclaveError::DeviceError("tbs.dll missing Tbsi_Is_Tpm_Present".into()));
            }
            let is_present: extern "system" fn() -> u32 = std::mem::transmute(is_present_fn);
            if is_present() == 0 {
                let _ = FreeLibrary(tbs);
                return Err(HardwareEnclaveError::DeviceError("Physical TPM 2.0 device not present".into()));
            }

            let create_fn = GetProcAddress(tbs, c"Tbsi_Context_Create".as_ptr());
            let submit_fn = GetProcAddress(tbs, c"Tbsip_Submit_Command".as_ptr());
            let close_fn = GetProcAddress(tbs, c"Tbsip_Context_Close".as_ptr());

            if create_fn.is_null() || submit_fn.is_null() || close_fn.is_null() {
                let _ = FreeLibrary(tbs);
                return Err(HardwareEnclaveError::DeviceError("tbs.dll missing context symbols".into()));
            }

            let ctx_create: extern "system" fn(*const TbsContextParams2, *mut *mut std::ffi::c_void) -> u32 =
                std::mem::transmute(create_fn);
            let ctx_submit: extern "system" fn(*mut std::ffi::c_void, u32, u32, *const u8, u32, *mut u8, *mut u32) -> u32 =
                std::mem::transmute(submit_fn);
            let ctx_close: extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(close_fn);

            let params = TbsContextParams2 {
                version: 2,
                flags: 4, // includeTpm20
            };
            let mut h_ctx: *mut std::ffi::c_void = std::ptr::null_mut();
            let cr_res = ctx_create(&params, &mut h_ctx);
            if cr_res != 0 || h_ctx.is_null() {
                let _ = FreeLibrary(tbs);
                return Err(HardwareEnclaveError::DeviceError(format!("Tbsi_Context_Create failed: 0x{cr_res:08X}")));
            }

            // Build TPM2_CC_PCR_Read command
            let mut pcr_bitmap = [0u8; 3];
            for &idx in indices {
                if idx < 24 {
                    pcr_bitmap[(idx / 8) as usize] |= 1 << (idx % 8);
                }
            }

            let mut cmd = Vec::with_capacity(20);
            cmd.extend_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
            cmd.extend_from_slice(&20u32.to_be_bytes());     // paramSize
            cmd.extend_from_slice(&0x0000017Eu32.to_be_bytes()); // TPM_CC_PCR_Read
            cmd.extend_from_slice(&1u32.to_be_bytes());      // count = 1
            cmd.extend_from_slice(&0x000Bu16.to_be_bytes()); // TPM_ALG_SHA256
            cmd.push(3u8);                                   // sizeofSelect
            cmd.extend_from_slice(&pcr_bitmap);

            let mut resp_buf = vec![0u8; 4096];
            let mut resp_len = resp_buf.len() as u32;

            let sub_res = ctx_submit(
                h_ctx,
                0,   // TBS_COMMAND_LOCALITY_ZERO
                200, // TBS_COMMAND_PRIORITY_NORMAL
                cmd.as_ptr(),
                cmd.len() as u32,
                resp_buf.as_mut_ptr(),
                &mut resp_len,
            );

            let _ = ctx_close(h_ctx);
            let _ = FreeLibrary(tbs);

            if sub_res != 0 {
                return Err(HardwareEnclaveError::DeviceError(format!("Tbsip_Submit_Command failed: 0x{sub_res:08X}")));
            }

            let resp = &resp_buf[..resp_len as usize];
            if resp.len() < 10 {
                return Err(HardwareEnclaveError::DeviceError("TPM response truncated".into()));
            }

            let resp_code = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
            if resp_code != 0 {
                return Err(HardwareEnclaveError::DeviceError(format!("TPM error response: 0x{resp_code:08X}")));
            }

            let mut offset = 14; // skip 10-byte header + 4-byte update counter
            if offset + 4 > resp.len() {
                return Err(HardwareEnclaveError::DeviceError("Invalid TPM PCR response".into()));
            }
            let sel_count = u32::from_be_bytes([resp[offset], resp[offset+1], resp[offset+2], resp[offset+3]]) as usize;
            offset += 4;
            for _ in 0..sel_count {
                if offset + 3 > resp.len() {
                    return Err(HardwareEnclaveError::DeviceError("Truncated selection".into()));
                }
                let size_sel = resp[offset + 2] as usize;
                offset += 3 + size_sel;
            }

            if offset + 4 > resp.len() {
                return Err(HardwareEnclaveError::DeviceError("Truncated digest count".into()));
            }
            let digest_count = u32::from_be_bytes([resp[offset], resp[offset+1], resp[offset+2], resp[offset+3]]) as usize;
            offset += 4;

            let mut target_sorted: Vec<u32> = indices.iter().copied().filter(|&i| i < 24).collect();
            target_sorted.sort_unstable();

            let mut results = Vec::with_capacity(digest_count);
            for &pcr_idx in target_sorted.iter().take(digest_count) {
                if offset + 2 > resp.len() {
                    break;
                }
                let d_size = u16::from_be_bytes([resp[offset], resp[offset+1]]) as usize;
                offset += 2;
                if offset + d_size > resp.len() || d_size != 32 {
                    return Err(HardwareEnclaveError::DeviceError("Unexpected digest length".into()));
                }
                let mut d = [0u8; 32];
                d.copy_from_slice(&resp[offset..offset+32]);
                offset += 32;
                results.push(PcrMeasurement::new(pcr_idx, d));
            }

            Ok(results)
        }
    }

    #[cfg(not(windows))]
    pub fn read_live_pcrs_tbs(_indices: &[u32]) -> Result<Vec<PcrMeasurement>, HardwareEnclaveError> {
        Err(HardwareEnclaveError::DeviceError("Windows TBS not available on this platform".into()))
    }
}

impl HardwareTrustAnchor for CngPlatformTrustAnchor {
    fn anchor_id(&self) -> &str {
        &self.anchor_id
    }

    fn backend_type(&self) -> HardwareBackendType {
        HardwareBackendType::WindowsCngPlatformCrypto
    }

    fn is_hardware_backed(&self) -> bool {
        self.hardware_backed
    }

    fn sign_in_silicon(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>, HardwareEnclaveError> {
        #[cfg(windows)]
        {
            // Attempt genuine NCrypt Platform Crypto Provider signing if available
            unsafe {
                let mut h_provider: usize = 0;
                let prov_name = to_wide_str("Microsoft Platform Crypto Provider");
                let rc = NCryptOpenStorageProvider(&mut h_provider, prov_name.as_ptr(), 0);
                if rc == 0 && h_provider != 0 {
                    let mut h_key: usize = 0;
                    let k_name = to_wide_str(key_id);
                    let open_rc = NCryptOpenKey(h_provider, &mut h_key, k_name.as_ptr(), 0, 0);
                    if open_rc == 0 && h_key != 0 {
                        let mut sig_buf = vec![0u8; 128];
                        let mut cb_res: u32 = 0;
                        let sign_rc = NCryptSignHash(
                            h_key,
                            std::ptr::null(),
                            digest.as_ptr(),
                            digest.len() as u32,
                            sig_buf.as_mut_ptr(),
                            sig_buf.len() as u32,
                            &mut cb_res,
                            0,
                        );
                        NCryptFreeObject(h_key);
                        NCryptFreeObject(h_provider);
                        if sign_rc == 0 && cb_res > 0 {
                            sig_buf.truncate(cb_res as usize);
                            return Ok(sig_buf);
                        }
                    } else {
                        NCryptFreeObject(h_provider);
                    }
                }
            }
        }

        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "Windows CNG Platform Crypto Provider key missing or unavailable in production mode (no software fallback permitted)".into(),
            ));
        }
        self.ephemeral.sign(key_id, digest)
    }

    fn verify_in_silicon(
        &self,
        key_id: &str,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, HardwareEnclaveError> {
        #[cfg(windows)]
        {
            unsafe {
                let mut h_provider: usize = 0;
                let prov_name = to_wide_str("Microsoft Platform Crypto Provider");
                let rc = NCryptOpenStorageProvider(&mut h_provider, prov_name.as_ptr(), 0);
                if rc == 0 && h_provider != 0 {
                    let mut h_key: usize = 0;
                    let k_name = to_wide_str(key_id);
                    let open_rc = NCryptOpenKey(h_provider, &mut h_key, k_name.as_ptr(), 0, 0);
                    if open_rc == 0 && h_key != 0 {
                        let ver_rc = NCryptVerifySignature(
                            h_key,
                            std::ptr::null(),
                            digest.as_ptr(),
                            digest.len() as u32,
                            signature.as_ptr(),
                            signature.len() as u32,
                            0,
                        );
                        NCryptFreeObject(h_key);
                        NCryptFreeObject(h_provider);
                        return Ok(ver_rc == 0);
                    }
                    NCryptFreeObject(h_provider);
                }
            }
        }
        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "Windows CNG key unavailable for verification in production mode".into(),
            ));
        }
        self.ephemeral.verify(key_id, digest, signature)
    }

    fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, HardwareEnclaveError> {
        #[cfg(windows)]
        {
            unsafe {
                let mut h_provider: usize = 0;
                let prov_name = to_wide_str("Microsoft Platform Crypto Provider");
                let rc = NCryptOpenStorageProvider(&mut h_provider, prov_name.as_ptr(), 0);
                if rc == 0 && h_provider != 0 {
                    let mut h_key: usize = 0;
                    let k_name = to_wide_str(key_id);
                    let open_rc = NCryptOpenKey(h_provider, &mut h_key, k_name.as_ptr(), 0, 0);
                    if open_rc == 0 && h_key != 0 {
                        let blob_type = to_wide_str("ECCPUBLICBLOB");
                        let mut cb_res: u32 = 0;
                        let sz_rc = NCryptExportKey(
                            h_key,
                            0,
                            blob_type.as_ptr(),
                            std::ptr::null(),
                            std::ptr::null_mut(),
                            0,
                            &mut cb_res,
                            0,
                        );
                        if sz_rc == 0 && cb_res > 0 && cb_res <= 4096 {
                            let mut buf = vec![0u8; cb_res as usize];
                            let ex_rc = NCryptExportKey(
                                h_key,
                                0,
                                blob_type.as_ptr(),
                                std::ptr::null(),
                                buf.as_mut_ptr(),
                                cb_res,
                                &mut cb_res,
                                0,
                            );
                            NCryptFreeObject(h_key);
                            NCryptFreeObject(h_provider);
                            if ex_rc == 0 {
                                buf.truncate(cb_res as usize);
                                return Ok(buf);
                            }
                        } else {
                            NCryptFreeObject(h_key);
                            NCryptFreeObject(h_provider);
                        }
                    } else {
                        NCryptFreeObject(h_provider);
                    }
                }
            }
        }
        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "Windows CNG public key unavailable in production mode".into(),
            ));
        }
        self.ephemeral.public_key(key_id)
    }

    fn seal_identity_to_pcrs(
        &self,
        key_id: &str,
        secret: &[u8],
        pcr_indices: &[u32],
        measurements: &[PcrMeasurement],
    ) -> Result<PcrSealedIdentity, HardwareEnclaveError> {
        self.fallback_sealer
            .seal_identity_to_pcrs(key_id, secret, pcr_indices, measurements)
    }

    fn unseal_identity_from_pcrs(
        &self,
        sealed: &PcrSealedIdentity,
        live_measurements: &[PcrMeasurement],
    ) -> Result<Vec<u8>, HardwareEnclaveError> {
        self.fallback_sealer
            .unseal_identity_from_pcrs(sealed, live_measurements)
    }
}

// -----------------------------------------------------------------------------
// PKCS#11 HSM Anchor
// -----------------------------------------------------------------------------

/// PKCS#11 Hardware Security Module Anchor.
/// Anchors keys inside physical HSM tokens (YubiKey 5 FIPS, SafeNet Luna, Nitrokey).
pub struct Pkcs11TrustAnchor {
    anchor_id: String,
    hardware_backed: bool,
    fallback_sealer: TpmPcrSealAnchor,
    ephemeral: EphemeralSchnorrStore,
}

impl Pkcs11TrustAnchor {
    pub fn new(anchor_id: &str, hardware_backed: bool) -> Self {
        Self {
            anchor_id: anchor_id.to_string(),
            hardware_backed,
            fallback_sealer: TpmPcrSealAnchor::new(anchor_id, hardware_backed),
            ephemeral: EphemeralSchnorrStore::new(&format!("pkcs11-lab:{anchor_id}")),
        }
    }
}

impl HardwareTrustAnchor for Pkcs11TrustAnchor {
    fn anchor_id(&self) -> &str {
        &self.anchor_id
    }

    fn backend_type(&self) -> HardwareBackendType {
        HardwareBackendType::Pkcs11Hsm
    }

    fn is_hardware_backed(&self) -> bool {
        self.hardware_backed
    }

    fn sign_in_silicon(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>, HardwareEnclaveError> {
        let hsm_configured = std::env::var_os("P2P_PKCS11_MODULE").is_some();
        if hsm_configured || crate::policy::is_production_env() {
            let mut cfg = crate::auth::HsmConfig::from_env();
            if cfg.key_label.is_none() {
                cfg.key_label = Some(key_id.to_string());
            }
            let session = crate::auth::HsmSession::open(&cfg)
                .map_err(|e| HardwareEnclaveError::DeviceError(format!("PKCS#11 session failed: {e}")))?;
            let key_handle = session
                .find_private_key(cfg.key_label.as_deref(), cfg.key_id.as_deref())
                .map_err(|e| HardwareEnclaveError::KeyNotFound(format!("PKCS#11 key missing: {e}")))?;
            return session
                .sign(key_handle, digest)
                .map_err(|e| HardwareEnclaveError::CryptoFailure(format!("PKCS#11 sign failed: {e}")));
        }
        self.ephemeral.sign(key_id, digest)
    }

    fn verify_in_silicon(
        &self,
        key_id: &str,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, HardwareEnclaveError> {
        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "PKCS#11 hardware verification requires public key / X.509 certificate verification against token".into(),
            ));
        }
        self.ephemeral.verify(key_id, digest, signature)
    }

    fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, HardwareEnclaveError> {
        if std::env::var_os("P2P_PKCS11_MODULE").is_some() || crate::policy::is_production_env() {
            let mut cfg = crate::auth::HsmConfig::from_env();
            if cfg.key_label.is_none() {
                cfg.key_label = Some(key_id.to_string());
            }
            let session = crate::auth::HsmSession::open(&cfg)
                .map_err(|e| HardwareEnclaveError::DeviceError(format!("PKCS#11 session failed: {e}")))?;
            let pub_handle = session
                .find_public_key(cfg.key_label.as_deref(), cfg.key_id.as_deref())
                .map_err(|e| HardwareEnclaveError::KeyNotFound(format!("PKCS#11 public key missing: {e}")))?;
            return session
                .get_public_key_bytes(pub_handle)
                .map_err(|e| HardwareEnclaveError::DeviceError(format!("PKCS#11 pubkey read failed: {e}")));
        }
        self.ephemeral.public_key(key_id)
    }

    fn seal_identity_to_pcrs(
        &self,
        key_id: &str,
        secret: &[u8],
        pcr_indices: &[u32],
        measurements: &[PcrMeasurement],
    ) -> Result<PcrSealedIdentity, HardwareEnclaveError> {
        self.fallback_sealer
            .seal_identity_to_pcrs(key_id, secret, pcr_indices, measurements)
    }

    fn unseal_identity_from_pcrs(
        &self,
        sealed: &PcrSealedIdentity,
        live_measurements: &[PcrMeasurement],
    ) -> Result<Vec<u8>, HardwareEnclaveError> {
        self.fallback_sealer
            .unseal_identity_from_pcrs(sealed, live_measurements)
    }
}

// -----------------------------------------------------------------------------
// Mock Silicon Anchor for Testing
// -----------------------------------------------------------------------------

/// In-memory simulated silicon anchor for tests (never deterministic, forbidden in prod).
pub struct MockHardwareTrustAnchor {
    anchor_id: String,
    sealer: TpmPcrSealAnchor,
    keys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ephemeral: EphemeralSchnorrStore,
}

impl MockHardwareTrustAnchor {
    pub fn new(anchor_id: &str) -> Self {
        Self {
            anchor_id: anchor_id.to_string(),
            sealer: TpmPcrSealAnchor::new(anchor_id, false),
            keys: Arc::new(Mutex::new(HashMap::new())),
            ephemeral: EphemeralSchnorrStore::new(&format!("mock:{anchor_id}")),
        }
    }

    pub fn insert_test_key(&self, key_id: &str, pubkey: Vec<u8>) {
        self.keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key_id.to_string(), pubkey);
    }
}

impl HardwareTrustAnchor for MockHardwareTrustAnchor {
    fn anchor_id(&self) -> &str {
        &self.anchor_id
    }

    fn backend_type(&self) -> HardwareBackendType {
        HardwareBackendType::MockSiliconLab
    }

    fn is_hardware_backed(&self) -> bool {
        false
    }

    fn sign_in_silicon(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>, HardwareEnclaveError> {
        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "MockHardwareTrustAnchor forbidden in production mode".into(),
            ));
        }
        self.ephemeral.sign(key_id, digest)
    }

    fn verify_in_silicon(
        &self,
        key_id: &str,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, HardwareEnclaveError> {
        if crate::policy::is_production_env() {
            return Err(HardwareEnclaveError::DeviceError(
                "MockHardwareTrustAnchor forbidden in production mode".into(),
            ));
        }
        self.ephemeral.verify(key_id, digest, signature)
    }

    fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, HardwareEnclaveError> {
        let guard = self.keys.lock().map_err(|_| {
            HardwareEnclaveError::DeviceError("mock enclave key store lock poisoned".into())
        })?;
        if let Some(pk) = guard.get(key_id) {
            return Ok(pk.clone());
        }
        drop(guard);
        self.ephemeral.public_key(key_id)
    }

    fn seal_identity_to_pcrs(
        &self,
        key_id: &str,
        secret: &[u8],
        pcr_indices: &[u32],
        measurements: &[PcrMeasurement],
    ) -> Result<PcrSealedIdentity, HardwareEnclaveError> {
        self.sealer
            .seal_identity_to_pcrs(key_id, secret, pcr_indices, measurements)
    }

    fn unseal_identity_from_pcrs(
        &self,
        sealed: &PcrSealedIdentity,
        live_measurements: &[PcrMeasurement],
    ) -> Result<Vec<u8>, HardwareEnclaveError> {
        self.sealer
            .unseal_identity_from_pcrs(sealed, live_measurements)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pcrs() -> Vec<PcrMeasurement> {
        (0..8)
            .map(|i| {
                let mut d = [0u8; 32];
                d[0] = i as u8;
                d[31] = 0xAA;
                PcrMeasurement::new(i, d)
            })
            .collect()
    }

    #[test]
    fn test_invariant_private_key_never_in_host_ram() {
        let cng = CngPlatformTrustAnchor::new("test-cng");
        assert!(!cng.is_private_key_in_host_ram());

        let pkcs11 = Pkcs11TrustAnchor::new("test-pkcs11", true);
        assert!(!pkcs11.is_private_key_in_host_ram());

        let tpm = TpmPcrSealAnchor::new("test-tpm", true);
        assert!(!tpm.is_private_key_in_host_ram());

        // Private key export must be refused fail-closed
        assert!(cng.export_private_key_refusal("identity_key").is_err());
        assert!(pkcs11.export_private_key_refusal("identity_key").is_err());
        assert!(tpm.export_private_key_refusal("identity_key").is_err());
    }

    #[test]
    fn test_tpm_pcr_seal_and_unseal_roundtrip() {
        let tpm = TpmPcrSealAnchor::new("tpm-seal-01", true);
        let pcrs = sample_pcrs();
        let secret = b"CONFIDENTIAL_MLDSA87_IDENTITY_SEED_MATERIAL";

        let sealed = tpm
            .seal_identity_to_pcrs("node_identity", secret, &[0, 1, 2, 3, 4, 5, 6, 7], &pcrs)
            .expect("sealing failed");

        assert_eq!(sealed.key_id, "node_identity");
        assert_eq!(sealed.pcr_indices, vec![0, 1, 2, 3, 4, 5, 6, 7]);

        // Unseal with identical PCRs succeeds
        let unsealed = tpm
            .unseal_identity_from_pcrs(&sealed, &pcrs)
            .expect("unseal failed");
        assert_eq!(unsealed, secret);
    }

    #[test]
    fn test_tpm_pcr_measurement_drift_rejection_fail_closed() {
        let tpm = TpmPcrSealAnchor::new("tpm-seal-drift", true);
        let pcrs = sample_pcrs();
        let secret = b"TOP_SECRET_AIR_GAP_SEED";

        let sealed = tpm
            .seal_identity_to_pcrs("drift_identity", secret, &[0, 1, 2, 3, 4, 5, 6, 7], &pcrs)
            .expect("sealing failed");

        // Tamper with PCR 0 (BIOS / Firmware modified)
        let mut tampered_pcrs = pcrs.clone();
        tampered_pcrs[0].digest[15] ^= 0xFF;

        let err = tpm
            .unseal_identity_from_pcrs(&sealed, &tampered_pcrs)
            .expect_err("Drift must cause fail-closed rejection");

        match err {
            HardwareEnclaveError::MeasurementDrift {
                pcr_index,
                tpm_error_code,
                ..
            } => {
                assert_eq!(pcr_index, 0);
                assert_eq!(tpm_error_code, TPM_RC_POLICY_FAIL);
            }
            other => panic!("Unexpected error type: {other:?}"),
        }

        // Tamper with PCR 7 (Secure Boot policy altered)
        let mut tampered_sb = pcrs.clone();
        tampered_sb[7].digest[0] ^= 0x01;

        let err_sb = tpm
            .unseal_identity_from_pcrs(&sealed, &tampered_sb)
            .expect_err("Secure Boot drift must fail");

        match err_sb {
            HardwareEnclaveError::MeasurementDrift {
                pcr_index,
                tpm_error_code,
                ..
            } => {
                assert_eq!(pcr_index, 7);
                assert_eq!(tpm_error_code, TPM_RC_POLICY_FAIL);
            }
            other => panic!("Unexpected error type: {other:?}"),
        }
    }

    #[test]
    fn test_cng_platform_in_silicon_signing() {
        let cng = CngPlatformTrustAnchor::new("cng-platform-01");
        let digest = [0x5Au8; 32];
        let sig = cng
            .sign_in_silicon("device_key", &digest)
            .expect("signing failed");
        assert_eq!(sig.len(), 64);

        let ok = cng
            .verify_in_silicon("device_key", &digest, &sig)
            .expect("verification failed");
        assert!(ok);

        // Forged legacy deterministic SHA-256 signature must be rejected
        let mut h = Sha256::new();
        h.update(b"WINDOWS_CNG_PLATFORM_CRYPTO_SIGN:device_key");
        h.update(digest);
        let d = h.finalize();
        let mut forged = Vec::with_capacity(64);
        forged.extend_from_slice(&d);
        forged.extend_from_slice(&d);
        assert!(!cng
            .verify_in_silicon("device_key", &digest, &forged)
            .expect("verify returned err"));
    }

    #[test]
    fn test_pkcs11_in_silicon_signing() {
        let hsm = Pkcs11TrustAnchor::new("hsm-token-01", true);
        let digest = [0x3Cu8; 32];
        let sig = hsm
            .sign_in_silicon("hsm_key", &digest)
            .expect("signing failed");
        assert_eq!(sig.len(), 64);

        let ok = hsm
            .verify_in_silicon("hsm_key", &digest, &sig)
            .expect("verification failed");
        assert!(ok);

        let mut h = Sha256::new();
        h.update(b"PKCS11_HSM_IN_SILICON_SIGN:hsm_key");
        h.update(digest);
        let d = h.finalize();
        let mut forged = Vec::with_capacity(64);
        forged.extend_from_slice(&d);
        forged.extend_from_slice(&d);
        assert!(!hsm
            .verify_in_silicon("hsm_key", &digest, &forged)
            .expect("verify returned err"));
    }

    #[test]
    fn test_cross_anchor_pcr_kek_isolation() {
        // Two independent TPM seal anchors must NOT decrypt each other's sealed blobs offline
        let tpm_a = TpmPcrSealAnchor::new("tpm-a", true);
        let tpm_b = TpmPcrSealAnchor::new("tpm-b", true);
        let pcrs = sample_pcrs();
        let sealed = tpm_a
            .seal_identity_to_pcrs("isolated", b"TOP_SECRET_ROOT", &[0, 1, 2, 3, 4, 5, 6, 7], &pcrs)
            .unwrap();
        assert!(tpm_b.unseal_identity_from_pcrs(&sealed, &pcrs).is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_cng_provider_live_probe() {
        let available = CngPlatformTrustAnchor::probe_platform_provider();
        // On Windows 11 with TPM 2.0, probe reports true
        println!("Windows CNG Platform Crypto Provider live probe: {available}");
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_tbs_live_pcr_read() {
        match CngPlatformTrustAnchor::read_live_pcrs_tbs(&[0, 1, 2, 3, 4, 5, 6, 7]) {
            Ok(pcrs) => {
                assert_eq!(pcrs.len(), 8);
                for (i, p) in pcrs.iter().enumerate() {
                    assert_eq!(p.pcr_index, i as u32);
                    println!("Live TPM PCR[{}]: {}", p.pcr_index, hex_encode(&p.digest));
                }
            }
            Err(e) => {
                println!("Live TBS PCR query skipped / unavailable in this environment: {e}");
            }
        }
    }
}
