//! Native ML-DSA-87 authentication (FIPS 204, CNSA 2.0) and PKCS#11 Hardware Key Custody.
//!
//! Zero-Disk Key Containment:
//! Private keys never touch disk files in operational environments. Hardware
//! custody supports physical YubiKey 5 FIPS, Thales Luna PCIe HSM, and Nitrokey HSM
//! tokens natively via PKCS#11 (cryptoki) without Python wrappers or disk caches.
//! Upstream pure-Rust `ml-dsa` crate (FIPS 204 final) is used for in-memory
//! operations with verified zeroizing Drop.

use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, KeyExport, Keypair, MlDsa87, Signature,
    SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey,
};

use crate::ct::ct_eq;
use crate::policy::{
    CoreError, DOMAIN_SIG_INITIATOR, DOMAIN_SIG_RESPONDER, MLDSA87_PK, MLDSA87_SIG,
};

/// HSM hardware error variants surfaced during silicon key custody operations.
#[derive(Debug)]
pub enum HsmError {
    /// PKCS#11 driver/token error
    Pkcs11(cryptoki::error::Error),
    /// Target physical device not found or driver missing
    DeviceNotFound(String),
    /// Specified token slot not found
    SlotNotFound(String),
    /// Private key object not found on token
    KeyNotFound(String),
    /// Requested cryptographic mechanism not supported by token silicon
    MechanismUnsupported(String),
    /// PIN authentication failed
    InvalidPin,
    /// Physical silicon security boundary refusal
    HardwareRefusal(String),
    /// I/O error communicating with hardware driver
    Io(std::io::Error),
}

impl std::fmt::Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmError::Pkcs11(e) => write!(f, "PKCS#11 error: {e}"),
            HsmError::DeviceNotFound(d) => write!(f, "HSM hardware device not found: {d}"),
            HsmError::SlotNotFound(s) => write!(f, "HSM token slot not found: {s}"),
            HsmError::KeyNotFound(k) => write!(f, "Hardware key object not found: {k}"),
            HsmError::MechanismUnsupported(m) => {
                write!(f, "Cryptographic mechanism unsupported by token: {m}")
            }
            HsmError::InvalidPin => write!(f, "HSM hardware PIN authentication failed"),
            HsmError::HardwareRefusal(r) => write!(f, "HSM silicon security boundary refusal: {r}"),
            HsmError::Io(e) => write!(f, "I/O error during hardware communication: {e}"),
        }
    }
}

impl std::error::Error for HsmError {}

impl From<cryptoki::error::Error> for HsmError {
    fn from(e: cryptoki::error::Error) -> Self {
        HsmError::Pkcs11(e)
    }
}

impl From<std::io::Error> for HsmError {
    fn from(e: std::io::Error) -> Self {
        HsmError::Io(e)
    }
}

/// Supported physical hardware token / HSM device classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmDeviceType {
    /// YubiKey 5 Series (including 5 FIPS, 5 Nano, 5C NFC) via ykcs11 or OpenSC
    YubiKey5Fips,
    /// Thales SafeNet Luna PCIe / Network HSM via SafeNet Cryptoki driver
    ThalesLunaPcie,
    /// Nitrokey HSM / SmartCard-HSM via OpenSC driver
    NitrokeyHsm,
    /// Generic PKCS#11 compliant token
    GenericPkcs11,
}

impl HsmDeviceType {
    /// Detect device type from token information strings.
    pub fn from_token_info(manufacturer: &str, model: &str, label: &str) -> Self {
        let m = manufacturer.to_lowercase();
        let md = model.to_lowercase();
        let l = label.to_lowercase();

        if m.contains("yubico") || md.contains("yubikey") || l.contains("yubikey") {
            HsmDeviceType::YubiKey5Fips
        } else if m.contains("safenet")
            || m.contains("chrysalis")
            || md.contains("luna")
            || l.contains("luna")
        {
            HsmDeviceType::ThalesLunaPcie
        } else if m.contains("nitrokey")
            || m.contains("cardcontact")
            || md.contains("smartcard-hsm")
            || l.contains("smartcard-hsm")
        {
            HsmDeviceType::NitrokeyHsm
        } else {
            HsmDeviceType::GenericPkcs11
        }
    }

    /// Default PKCS#11 driver candidate library paths on the current operating system.
    pub fn default_driver_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        match self {
            HsmDeviceType::YubiKey5Fips => {
                #[cfg(target_os = "windows")]
                {
                    paths.push(PathBuf::from(
                        r"C:\Program Files\Yubico\Yubico PIV Tool\bin\ykcs11.dll",
                    ));
                    paths.push(PathBuf::from(
                        r"C:\Program Files (x86)\Yubico\Yubico PIV Tool\bin\ykcs11.dll",
                    ));
                    paths.push(PathBuf::from(
                        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
                    ));
                    paths.push(PathBuf::from("ykcs11.dll"));
                }
                #[cfg(target_os = "linux")]
                {
                    paths.push(PathBuf::from("/usr/lib/x86_64-linux-gnu/libykcs11.so"));
                    paths.push(PathBuf::from("/usr/lib64/libykcs11.so"));
                    paths.push(PathBuf::from("/usr/local/lib/libykcs11.so"));
                    paths.push(PathBuf::from("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("/usr/lib64/pkcs11/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("libykcs11.so"));
                }
                #[cfg(target_os = "macos")]
                {
                    paths.push(PathBuf::from("/usr/local/lib/libykcs11.dylib"));
                    paths.push(PathBuf::from("/opt/homebrew/lib/libykcs11.dylib"));
                    paths.push(PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so"));
                }
            }
            HsmDeviceType::ThalesLunaPcie => {
                #[cfg(target_os = "windows")]
                {
                    paths.push(PathBuf::from(
                        r"C:\Program Files\SafeNet\LunaClient\bin\cryptoki.dll",
                    ));
                    paths.push(PathBuf::from(
                        r"C:\Program Files\SafeNet\LunaClient\bin64\cryptoki.dll",
                    ));
                    paths.push(PathBuf::from("cryptoki.dll"));
                }
                #[cfg(target_os = "linux")]
                {
                    paths.push(PathBuf::from(
                        "/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
                    ));
                    paths.push(PathBuf::from(
                        "/opt/safenet/lunaclient/lib/libCryptoki2_64.so",
                    ));
                    paths.push(PathBuf::from("/usr/lib/libCryptoki2_64.so"));
                }
                #[cfg(target_os = "macos")]
                {
                    paths.push(PathBuf::from(
                        "/usr/safenet/lunaclient/lib/libCryptoki2_64.dylib",
                    ));
                }
            }
            HsmDeviceType::NitrokeyHsm => {
                #[cfg(target_os = "windows")]
                {
                    paths.push(PathBuf::from(
                        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
                    ));
                    paths.push(PathBuf::from("opensc-pkcs11.dll"));
                }
                #[cfg(target_os = "linux")]
                {
                    paths.push(PathBuf::from("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("/usr/lib64/pkcs11/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("/usr/lib/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("/usr/local/lib/opensc-pkcs11.so"));
                }
                #[cfg(target_os = "macos")]
                {
                    paths.push(PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("/usr/local/lib/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("/opt/homebrew/lib/opensc-pkcs11.so"));
                }
            }
            HsmDeviceType::GenericPkcs11 => {
                #[cfg(target_os = "windows")]
                {
                    paths.push(PathBuf::from(
                        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
                    ));
                    paths.push(PathBuf::from("opensc-pkcs11.dll"));
                }
                #[cfg(target_os = "linux")]
                {
                    paths.push(PathBuf::from("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("/usr/lib64/pkcs11/opensc-pkcs11.so"));
                    paths.push(PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"));
                }
                #[cfg(target_os = "macos")]
                {
                    paths.push(PathBuf::from("/usr/local/lib/softhsm/libsofthsm2.so"));
                    paths.push(PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so"));
                }
            }
        }
        paths
    }
}

/// Configuration for establishing a hardware silicon custody session.
#[derive(Debug, Clone)]
pub struct HsmConfig {
    pub device_type: HsmDeviceType,
    pub module_path: Option<PathBuf>,
    pub slot_index: Option<usize>,
    pub token_label: Option<String>,
    pub pin: Option<String>,
    pub key_label: Option<String>,
    pub key_id: Option<Vec<u8>>,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            device_type: HsmDeviceType::YubiKey5Fips,
            module_path: None,
            slot_index: None,
            token_label: None,
            pin: None,
            key_label: None,
            key_id: None,
        }
    }
}

impl HsmConfig {
    /// Load HSM configuration from environment variables.
    pub fn from_env() -> Self {
        let module_path = std::env::var("P2P_PKCS11_MODULE").ok().map(PathBuf::from);
        let device_type = match std::env::var("P2P_HSM_TYPE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "luna" | "thales" => HsmDeviceType::ThalesLunaPcie,
            "nitrokey" | "smartcard-hsm" => HsmDeviceType::NitrokeyHsm,
            "generic" | "softhsm" => HsmDeviceType::GenericPkcs11,
            _ => HsmDeviceType::YubiKey5Fips,
        };
        let slot_index = std::env::var("P2P_HSM_SLOT")
            .ok()
            .and_then(|s| s.parse().ok());
        let token_label = std::env::var("P2P_HSM_TOKEN_LABEL").ok();
        let pin = std::env::var("P2P_HSM_PIN").ok();
        let key_label = std::env::var("P2P_HSM_KEY_LABEL").ok();
        let key_id = std::env::var("P2P_HSM_KEY_ID").ok().and_then(|h| {
            let h = h.trim();
            if h.len() % 2 == 0 {
                (0..h.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok())
                    .collect()
            } else {
                None
            }
        });

        Self {
            device_type,
            module_path,
            slot_index,
            token_label,
            pin,
            key_label,
            key_id,
        }
    }

    /// Resolve effective driver library path.
    pub fn resolve_module_path(&self) -> Result<PathBuf, HsmError> {
        if let Some(ref p) = self.module_path {
            if p.exists() {
                return Ok(p.clone());
            }
            return Err(HsmError::DeviceNotFound(format!(
                "Configured PKCS#11 module not found at: {}",
                p.display()
            )));
        }

        // Search candidate paths
        let candidates = self.device_type.default_driver_paths();
        for p in candidates {
            if p.exists() {
                return Ok(p);
            }
        }

        Err(HsmError::DeviceNotFound(format!(
            "No PKCS#11 driver found for device type {:?}. Set P2P_PKCS11_MODULE.",
            self.device_type
        )))
    }
}

/// An authenticated session bound to a physical hardware security token.
pub struct HsmSession {
    _pkcs11: Pkcs11,
    session: Session,
    device_type: HsmDeviceType,
    slot_index: usize,
    token_serial: Option<String>,
}

impl HsmSession {
    /// Initialize PKCS#11 runtime, discover slot, and open authenticated session.
    pub fn open(config: &HsmConfig) -> Result<Self, HsmError> {
        let mod_path = config.resolve_module_path()?;
        let pkcs11 = Pkcs11::new(mod_path)?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        let slots = pkcs11.get_slots_with_token()?;
        if slots.is_empty() {
            return Err(HsmError::SlotNotFound(
                "No slots with connected hardware tokens found".into(),
            ));
        }

        let (target_slot, actual_slot_index) = if let Some(idx) = config.slot_index {
            let s = *slots
                .get(idx)
                .ok_or_else(|| HsmError::SlotNotFound(format!("Slot index {idx} out of range")))?;
            (s, idx)
        } else if let Some(ref label) = config.token_label {
            let mut found = None;
            for (idx, &s) in slots.iter().enumerate() {
                if let Ok(info) = pkcs11.get_token_info(s) {
                    if info.label().trim() == label.trim() {
                        found = Some((s, idx));
                        break;
                    }
                }
            }
            found.ok_or_else(|| {
                HsmError::SlotNotFound(format!("Token with label '{label}' not found"))
            })?
        } else {
            (slots[0], 0)
        };

        let session = pkcs11.open_ro_session(target_slot)?;
        if let Some(ref pin) = config.pin {
            session
                .login(UserType::User, Some(&AuthPin::from(pin.clone())))
                .map_err(|_| HsmError::InvalidPin)?;
        }

        let token_info = pkcs11.get_token_info(target_slot).ok();
        let detected_type = token_info
            .as_ref()
            .map(|ti| HsmDeviceType::from_token_info(ti.manufacturer_id(), ti.model(), ti.label()))
            .unwrap_or(config.device_type);
        let token_serial = token_info
            .as_ref()
            .map(|ti| ti.serial_number().trim().to_string());

        Ok(Self {
            _pkcs11: pkcs11,
            session,
            device_type: detected_type,
            slot_index: actual_slot_index,
            token_serial,
        })
    }

    /// Access the underlying cryptoki Session.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Identified hardware device type.
    pub fn device_type(&self) -> HsmDeviceType {
        self.device_type
    }

    /// Slot index of the token on the PKCS#11 subsystem.
    pub fn slot_index(&self) -> usize {
        self.slot_index
    }

    /// Serial number of the physical token hardware.
    pub fn token_serial(&self) -> Option<&str> {
        self.token_serial.as_deref()
    }

    /// Locate private key object handle by optional label or ID.
    pub fn find_private_key(
        &self,
        label: Option<&str>,
        id: Option<&[u8]>,
    ) -> Result<ObjectHandle, HsmError> {
        let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        if let Some(l) = label {
            template.push(Attribute::Label(l.as_bytes().to_vec()));
        }
        if let Some(i) = id {
            template.push(Attribute::Id(i.to_vec()));
        }

        let objects = self.session.find_objects(&template)?;
        objects.into_iter().next().ok_or_else(|| {
            HsmError::KeyNotFound(format!(
                "Private key object not found on token (label={label:?}, id={id:?})"
            ))
        })
    }

    /// Locate public key object handle by optional label or ID.
    pub fn find_public_key(
        &self,
        label: Option<&str>,
        id: Option<&[u8]>,
    ) -> Result<ObjectHandle, HsmError> {
        let mut template = vec![Attribute::Class(ObjectClass::PUBLIC_KEY)];
        if let Some(l) = label {
            template.push(Attribute::Label(l.as_bytes().to_vec()));
        }
        if let Some(i) = id {
            template.push(Attribute::Id(i.to_vec()));
        }

        let objects = self.session.find_objects(&template)?;
        objects.into_iter().next().ok_or_else(|| {
            HsmError::KeyNotFound(format!(
                "Public key object not found on token (label={label:?}, id={id:?})"
            ))
        })
    }

    /// Read public key raw bytes from hardware object handle.
    pub fn get_public_key_bytes(&self, key_handle: ObjectHandle) -> Result<Vec<u8>, HsmError> {
        // Try Value attribute first (common for ML-DSA / PQC and raw keys)
        let attrs = self
            .session
            .get_attributes(key_handle, &[AttributeType::Value]);
        if let Ok(attr_list) = attrs {
            for attr in attr_list {
                if let Attribute::Value(val) = attr {
                    if !val.is_empty() {
                        return Ok(val);
                    }
                }
            }
        }
        Err(HsmError::KeyNotFound(
            "Unable to read public key bytes from token object".into(),
        ))
    }

    /// Perform hardware signature inside token silicon.
    pub fn sign(&self, key_handle: ObjectHandle, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        sign_with_hsm(&self.session, key_handle, digest)
    }
}

/// Native PKCS#11 hardware signature generation inside HSM / secure element silicon.
///
/// Private key material never leaves hardware containment. Supports ML-DSA-87 (PQC),
/// ECDSA, EDDSA, and RSA with automatic mechanism selection and vendor fallback.
pub fn sign_with_hsm(
    session: &Session,
    key_handle: ObjectHandle,
    digest: &[u8],
) -> Result<Vec<u8>, HsmError> {
    // 1. Check KeyType attribute if obtainable from token
    let attrs = session.get_attributes(key_handle, &[AttributeType::KeyType]);
    let mut key_type = None;
    if let Ok(attr_list) = attrs {
        for attr in attr_list {
            if let Attribute::KeyType(kt) = attr {
                key_type = Some(kt);
                break;
            }
        }
    }

    // 2. Select mechanism based on token-reported KeyType
    if let Some(kt) = key_type {
        if kt == KeyType::ML_DSA {
            let mech = Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None));
            match session.sign(&mech, key_handle, digest) {
                Ok(sig) => return Ok(sig),
                Err(e) => {
                    let hmech = Mechanism::HashMlDsaSha384(SignAdditionalContext::new(
                        HedgeType::Preferred,
                        None,
                    ));
                    if let Ok(sig) = session.sign(&hmech, key_handle, digest) {
                        return Ok(sig);
                    }
                    return Err(HsmError::Pkcs11(e));
                }
            }
        } else if kt == KeyType::EC {
            let mech = Mechanism::Ecdsa;
            return session
                .sign(&mech, key_handle, digest)
                .map_err(HsmError::Pkcs11);
        } else if kt == KeyType::EC_EDWARDS {
            let mech = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
            return session
                .sign(&mech, key_handle, digest)
                .map_err(HsmError::Pkcs11);
        } else if kt == KeyType::RSA {
            let mech = Mechanism::RsaPkcs;
            return session
                .sign(&mech, key_handle, digest)
                .map_err(HsmError::Pkcs11);
        }
    }

    // 3. Fallback cascade: try ML-DSA, ECDSA, EDDSA, then RSA
    let mldsa_mech = Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None));
    if let Ok(sig) = session.sign(&mldsa_mech, key_handle, digest) {
        return Ok(sig);
    }
    let ecdsa_mech = Mechanism::Ecdsa;
    if let Ok(sig) = session.sign(&ecdsa_mech, key_handle, digest) {
        return Ok(sig);
    }
    let eddsa_mech = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
    if let Ok(sig) = session.sign(&eddsa_mech, key_handle, digest) {
        return Ok(sig);
    }
    let rsa_mech = Mechanism::RsaPkcs;
    if let Ok(sig) = session.sign(&rsa_mech, key_handle, digest) {
        return Ok(sig);
    }

    Err(HsmError::MechanismUnsupported(
        "Token refused all attempted signing mechanisms (ML-DSA, ECDSA, EDDSA, RSA)".to_string(),
    ))
}

/// ML-DSA-87 signing key. The inner `SigningKey` wipes itself on drop
/// (upstream `Drop` impl); this wrapper never exposes it.
pub struct Mldsa87SigningKey {
    inner: SigningKey<MlDsa87>,
}

impl Mldsa87SigningKey {
    /// Generate a fresh keypair from OS randomness.
    pub fn generate() -> Result<(Self, Mldsa87VerifyingKey), CoreError> {
        let sk = SigningKey::<MlDsa87>::generate();
        let vk = sk.verifying_key().clone();
        Ok((Self { inner: sk }, Mldsa87VerifyingKey { inner: vk }))
    }

    /// Generate deterministically from a 32-byte FIPS 204 seed (xi).
    pub fn from_seed(seed: &[u8; 32]) -> (Self, Mldsa87VerifyingKey) {
        let sk = SigningKey::<MlDsa87>::from_seed(seed.into());
        let vk = sk.verifying_key().clone();
        (Self { inner: sk }, Mldsa87VerifyingKey { inner: vk })
    }

    /// Sign `domain || message`. Domain MUST be a role-separated constant
    /// from `crate::policy` (prevents cross-role reflection).
    pub fn sign(&self, domain: &[u8], message: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(domain.len() + message.len());
        m.extend_from_slice(domain);
        m.extend_from_slice(message);
        let sig: Signature<MlDsa87> = self.inner.sign(&m);
        sig.to_bytes().to_vec()
    }

    /// Export the verifying key bytes (2592, FIPS 204).
    pub fn verifying_bytes(&self) -> Vec<u8> {
        self.inner.verifying_key().to_bytes().to_vec()
    }
}

/// ML-DSA-87 verifying key (public, enrolled out-of-band).
#[derive(Debug, Clone)]
pub struct Mldsa87VerifyingKey {
    inner: VerifyingKey<MlDsa87>,
}

impl Mldsa87VerifyingKey {
    /// Parse enrolled public bytes. Exact length required (fail-closed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        let arr: [u8; MLDSA87_PK] = bytes.try_into().map_err(|_| CoreError::Malformed)?;
        let enc: EncodedVerifyingKey<MlDsa87> = arr.into();
        let inner = VerifyingKey::<MlDsa87>::decode(&enc);
        Ok(Self { inner })
    }

    /// Canonical encoded bytes (for enrollment-pin comparison).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Verify `domain || message` against `sig_bytes`. Fixed-size sig only.
    pub fn verify(&self, domain: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<(), CoreError> {
        if sig_bytes.len() != MLDSA87_SIG {
            return Err(CoreError::Malformed);
        }
        let arr: [u8; MLDSA87_SIG] = sig_bytes.try_into().map_err(|_| CoreError::Malformed)?;
        let enc: EncodedSignature<MlDsa87> = arr.into();
        let sig = Signature::<MlDsa87>::decode(&enc).ok_or(CoreError::Malformed)?;
        let mut m = Vec::with_capacity(domain.len() + message.len());
        m.extend_from_slice(domain);
        m.extend_from_slice(message);
        self.inner
            .verify(&m, &sig)
            .map_err(|_| CoreError::BadSignature)
    }

    /// Constant-time enrollment-pin equality (for trust-anchor stores).
    pub fn ct_pin_eq(&self, enrolled_bytes: &[u8]) -> bool {
        ct_eq(&self.to_bytes(), enrolled_bytes)
    }
}

/// Convenience: responder-side sign over a handshake transcript hash.
pub fn sign_responder(sk: &Mldsa87SigningKey, transcript: &[u8; 48]) -> Vec<u8> {
    sk.sign(DOMAIN_SIG_RESPONDER, transcript)
}

/// Convenience: initiator-side sign over a handshake transcript hash.
pub fn sign_initiator(sk: &Mldsa87SigningKey, transcript: &[u8; 48]) -> Vec<u8> {
    sk.sign(DOMAIN_SIG_INITIATOR, transcript)
}

/// Convenience: verify-before-derive gate for the responder leg.
pub fn verify_responder(
    vk: &Mldsa87VerifyingKey,
    transcript: &[u8; 48],
    sig: &[u8],
) -> Result<(), CoreError> {
    vk.verify(DOMAIN_SIG_RESPONDER, transcript, sig)
}

/// Convenience: verify-before-derive gate for the initiator leg.
pub fn verify_initiator(
    vk: &Mldsa87VerifyingKey,
    transcript: &[u8; 48],
    sig: &[u8],
) -> Result<(), CoreError> {
    vk.verify(DOMAIN_SIG_INITIATOR, transcript, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_role_separation() {
        let (sk, vk) = Mldsa87SigningKey::generate().expect("keygen");
        let t = [0xA5u8; 48];
        let sr = sign_responder(&sk, &t);
        let si = sign_initiator(&sk, &t);
        assert_eq!(sr.len(), MLDSA87_SIG);
        // Correct roles verify.
        verify_responder(&vk, &t, &sr).expect("responder leg");
        verify_initiator(&vk, &t, &si).expect("initiator leg");
        // Cross-role reflection refused.
        assert!(verify_initiator(&vk, &t, &sr).is_err());
        assert!(verify_responder(&vk, &t, &si).is_err());
        // Tampered transcript refused.
        let mut t2 = t;
        t2[0] ^= 1;
        assert!(verify_responder(&vk, &t2, &sr).is_err());
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        let (_, vk) = Mldsa87SigningKey::generate().expect("keygen");
        let t = [0u8; 48];
        assert_eq!(
            vk.verify(DOMAIN_SIG_RESPONDER, &t, &[0u8; 10]).unwrap_err(),
            CoreError::Malformed
        );
        assert!(Mldsa87VerifyingKey::from_bytes(&[0u8; 100]).is_err());
        // Pin encode round-trips through enrollment parse.
        let raw = vk.to_bytes();
        assert_eq!(raw.len(), MLDSA87_PK);
        let vk2 = Mldsa87VerifyingKey::from_bytes(&raw).expect("reparse");
        assert!(vk2.ct_pin_eq(&raw));
        // Enrollment pin compare is constant-time equality, not pointer eq.
        let mut other = raw.clone();
        other[0] = other[0].wrapping_add(1);
        // NOTE: re-parsed key still compares against the ORIGINAL pin only.
        assert!(!vk2.ct_pin_eq(&other));
    }

    #[test]
    fn hsm_device_type_detection() {
        assert_eq!(
            HsmDeviceType::from_token_info("Yubico", "YubiKey OTP+FIDO+CCID", "YubiKey PIV"),
            HsmDeviceType::YubiKey5Fips
        );
        assert_eq!(
            HsmDeviceType::from_token_info("SafeNet, Inc.", "Luna PCIe HSM", "Partition_ALPHA"),
            HsmDeviceType::ThalesLunaPcie
        );
        assert_eq!(
            HsmDeviceType::from_token_info(
                "CardContact (www.cardcontact.de)",
                "SmartCard-HSM",
                "UserPIN (SmartCard-HSM)"
            ),
            HsmDeviceType::NitrokeyHsm
        );
        assert_eq!(
            HsmDeviceType::from_token_info("UnknownVendor", "GenericToken", "Token_1"),
            HsmDeviceType::GenericPkcs11
        );
    }

    #[test]
    fn hsm_default_paths_exist_for_all_devices() {
        let yk = HsmDeviceType::YubiKey5Fips.default_driver_paths();
        assert!(!yk.is_empty());
        let luna = HsmDeviceType::ThalesLunaPcie.default_driver_paths();
        assert!(!luna.is_empty());
        let nitro = HsmDeviceType::NitrokeyHsm.default_driver_paths();
        assert!(!nitro.is_empty());
    }

    #[test]
    fn hsm_error_display_formatting() {
        let err = HsmError::DeviceNotFound("YubiKey 5 FIPS".into());
        assert!(format!("{err}").contains("YubiKey 5 FIPS"));
        let err_pin = HsmError::InvalidPin;
        assert!(format!("{err_pin}").contains("PIN authentication failed"));
        let err_refusal = HsmError::HardwareRefusal("Physical tamper detection tripped".into());
        assert!(format!("{err_refusal}").contains("silicon security boundary"));
    }
}
