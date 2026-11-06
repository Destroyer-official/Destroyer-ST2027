//! TPM 2.0 NV monotonic counter — hardware high-water mark for send-seq state.
//!
//! F-01 residual (second audit): the authenticated `<state>` file and its
//! append-only `.seqlog` journal are BOTH software artifacts; an attacker
//! with write access can restore both to an old consistent pair and replay
//! nonce reservations. A TPM 2.0 NV *counter* index closes that hole:
//! `TPM2_NV_Increment` is the only write primitive for counter-type indices
//! (TCG TPM 2.0 Part 2, "NV Counter Index") — the value can never be moved
//! backwards, not even by the owner hierarchy.
//!
//! # Model
//! - NV counter value = **checkpoint generation** `G` (incremented once per
//!   checkpoint). On first use a counter index initializes to the largest
//!   value any NV counter on this TPM has ever held, then increments (TCG
//!   TPM 2.0 Part 1, 37.2.6.3) — the chain survives index deletion.
//! - Sidecar `<state>.nvck` (append-only, mirrors `.seqlog`): one line per
//!   checkpoint `<gen> <send_seq> <hex HMAC-SHA384[:32]>`. The tag is keyed from
//!   the session key (HKDF subkey `DESTROYER-ST2027-NVCK-AUTH-SUBKEY-v1`),
//!   so a file-only attacker cannot forge a plausible `(gen, send_seq)`
//!   even though the counter value may be readable via `ownerread`.
//! - `guard` (every state load / reservation): the last sidecar generation
//!   must equal the live counter and `send_seq` must not be behind it.
//!   Any mismatch, tool failure, or sidecar corruption fails the command
//!   (secure-transmit exits non-zero) — never a silent degradation.
//! - `checkpoint` (after each reservation): sidecar line first (`G+1`),
//!   then `nvincrement`. A crash between the two is self-healing: the next
//!   guard sees `sidecar_gen == counter + 1` and finishes the increment.
//!
//! # Enable / recovery
//! - `P2P_TPM_NV_INDEX=0x1500016` enables the guard (unset = no-op, i.e.
//!   the historical software-only `.seqlog` behavior). Optional
//!   `P2P_TPM_NV_OWNER` (default `o`).
//! - Requires `tpm2-tools` (`tpm2_nvdefine` / `tpm2_nvread` /
//!   `tpm2_nvincrement`) on PATH; tool paths overridable for tests via
//!   `P2P_TPM2_NVREAD` / `P2P_TPM2_NVINCREMENT` / `P2P_TPM2_NVDEFINE`.
//! - The owner hierarchy auth value must be EMPTY: this crate never puts
//!   secrets on argv (visible via `ps`).
//! - `P2P_TPM_NV_REPROVISION=1` is the ONLY sanctioned recovery from a
//!   broken chain (NV index loss, sidecar deletion/corruption, rekey): it
//!   re-anchors the sidecar at the live counter value and current
//!   `send_seq` after explicit operator acknowledgment. Both variables are
//!   in the operator trust domain — an attacker who can set them can
//!   disable the guard entirely.
//!
//! # Hardware NVRAM Anti-Rollback Architecture
//! - Receive-side anti-replay high-water mark protection (P1-10): dual-monotonic coverage
//!   checkpoints both send_seq and recv_hwm into TPM NVRAM sidecars, preventing rollback of
//!   either nonce reservation or incoming message acceptance state.
//! - Rollback of reservations since the last checkpoint is covered by the
//!   `.seqlog` journal; the NV layer covers restore of any
//!   sidecar-consistent snapshot the generation chain has passed.
//! - No real-TPM integration test runs in CI (no hardware); the policy
//!   layer is exercised against an in-memory fake transport and the tool
//!   layer against argv/classification unit tests.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha384;
use std::fs::OpenOptions;
use std::io::Write;

use crate::ct::ct_eq;
use crate::memlock::LockedKey32;
use zeroize::Zeroize;

type HmacSha384 = Hmac<Sha384>;

/// Failure modes surfaced by an [`NvTransport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvError {
    /// The NV index does not exist (TPM RC 0x18B / equivalent).
    NotDefined,
    /// Defined but never incremented (TPM RC 0x14A, "used before being
    /// initialized") — counter chain not started yet.
    Uninitialized,
    /// Policy failure / tamper detection: TPM silicon refused unseal because
    /// live PCRs do not match the sealed measurement policy (TPM RC 0x99D / 0x17D / POLICY_FAIL).
    PolicyFailure(String),
    /// Tool spawn/parse/TPM failure with no better classification.
    Tools(String),
}

impl NvError {
    pub fn describe(&self) -> String {
        match self {
            NvError::NotDefined => "NV index not defined".to_string(),
            NvError::Uninitialized => "NV index not yet initialized".to_string(),
            NvError::PolicyFailure(m) => format!("TPM PCR policy authorization failed: {m}"),
            NvError::Tools(m) => m.clone(),
        }
    }
}

/// Minimal TPM NV counter operations the policy layer depends on.
pub trait NvTransport {
    /// Current counter value; `NotDefined`/`Uninitialized` mean "chain not
    /// started" (the policy layer maps both to `None`).
    fn read(&self) -> Result<u64, NvError>;
    /// Increment by one and read back; returns the NEW value.
    fn increment(&self) -> Result<u64, NvError>;
    /// Ensure the index exists. Implementations must treat "already
    /// defined" as success (idempotent).
    fn define(&self) -> Result<(), NvError>;
}

/// Tool executable paths (overridable via `P2P_TPM2_*` for tests).
#[derive(Debug, Clone)]
pub struct ToolPaths {
    pub nvread: String,
    pub nvincrement: String,
    pub nvdefine: String,
    pub pcrread: String,
    pub createpolicy: String,
    pub createprimary: String,
    pub create: String,
    pub load: String,
    pub unseal: String,
    pub flushcontext: String,
}

impl Default for ToolPaths {
    fn default() -> Self {
        Self::from_env()
    }
}

impl ToolPaths {
    pub fn from_env() -> Self {
        Self {
            nvread: std::env::var("P2P_TPM2_NVREAD").unwrap_or_else(|_| "tpm2_nvread".to_string()),
            nvincrement: std::env::var("P2P_TPM2_NVINCREMENT")
                .unwrap_or_else(|_| "tpm2_nvincrement".to_string()),
            nvdefine: std::env::var("P2P_TPM2_NVDEFINE")
                .unwrap_or_else(|_| "tpm2_nvdefine".to_string()),
            pcrread: std::env::var("P2P_TPM2_PCRREAD")
                .unwrap_or_else(|_| "tpm2_pcrread".to_string()),
            createpolicy: std::env::var("P2P_TPM2_CREATEPOLICY")
                .unwrap_or_else(|_| "tpm2_createpolicy".to_string()),
            createprimary: std::env::var("P2P_TPM2_CREATEPRIMARY")
                .unwrap_or_else(|_| "tpm2_createprimary".to_string()),
            create: std::env::var("P2P_TPM2_CREATE").unwrap_or_else(|_| "tpm2_create".to_string()),
            load: std::env::var("P2P_TPM2_LOAD").unwrap_or_else(|_| "tpm2_load".to_string()),
            unseal: std::env::var("P2P_TPM2_UNSEAL").unwrap_or_else(|_| "tpm2_unseal".to_string()),
            flushcontext: std::env::var("P2P_TPM2_FLUSHCONTEXT")
                .unwrap_or_else(|_| "tpm2_flushcontext".to_string()),
        }
    }
}

/// Production transport: spawns tpm2-tools with list-form argv (no shell).
pub struct ToolsTransport {
    index: u64,
    owner: String,
    tools: ToolPaths,
}

impl ToolsTransport {
    pub fn new(index: u64, owner: &str, tools: ToolPaths) -> Self {
        Self {
            index,
            owner: owner.to_string(),
            tools,
        }
    }

    pub fn index_str(&self) -> String {
        format!("0x{:x}", self.index)
    }

    pub fn read_argv(&self) -> (String, Vec<String>) {
        (
            self.tools.nvread.clone(),
            vec![
                self.index_str(),
                "-C".to_string(),
                self.owner.clone(),
                "-s".to_string(),
                "8".to_string(),
            ],
        )
    }

    pub fn increment_argv(&self) -> (String, Vec<String>) {
        (
            self.tools.nvincrement.clone(),
            vec![self.index_str(), "-C".to_string(), self.owner.clone()],
        )
    }

    pub fn define_argv(&self) -> (String, Vec<String>) {
        (
            self.tools.nvdefine.clone(),
            vec![
                self.index_str(),
                "-C".to_string(),
                self.owner.clone(),
                "-s".to_string(),
                "8".to_string(),
                "-a".to_string(),
                "ownerread|ownerwrite|nt=counter".to_string(),
            ],
        )
    }
}

impl NvTransport for ToolsTransport {
    fn read(&self) -> Result<u64, NvError> {
        let (prog, argv) = self.read_argv();
        let out_bytes = run_tool_raw(&prog, &argv)?;
        if out_bytes.len() == 8 {
            return Ok(u64::from_be_bytes(
                out_bytes
                    .try_into()
                    .map_err(|_| NvError::Tools("8-byte slice conversion failed".into()))?,
            ));
        }
        let stdout = String::from_utf8_lossy(&out_bytes);
        parse_nvread_hex(&stdout)
    }

    fn increment(&self) -> Result<u64, NvError> {
        let (prog, argv) = self.increment_argv();
        run_tool(&prog, &argv)?;
        match self.read() {
            Ok(v) => Ok(v),
            Err(e) => Err(NvError::Tools(format!(
                "nvincrement succeeded but read-back failed: {}",
                e.describe()
            ))),
        }
    }

    fn define(&self) -> Result<(), NvError> {
        let (prog, argv) = self.define_argv();
        match run_tool(&prog, &argv) {
            Ok(_) => Ok(()),
            Err(NvError::Tools(m)) if already_defined(&m) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn run_tool_raw(prog: &str, argv: &[String]) -> Result<Vec<u8>, NvError> {
    let out = std::process::Command::new(prog)
        .args(argv)
        .output()
        .map_err(|e| NvError::Tools(format!("{prog}: {e}")))?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    Err(classify_failure(&format!("{stderr}{stdout}")))
}

fn run_tool(prog: &str, argv: &[String]) -> Result<String, NvError> {
    let out = std::process::Command::new(prog)
        .args(argv)
        .output()
        .map_err(|e| NvError::Tools(format!("{prog}: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(classify_failure(&format!("{stderr}{stdout}")))
}

/// Classify a failed tpm2-tools invocation (stderr+stdout blob).
pub fn classify_failure(blob: &str) -> NvError {
    let l = blob.to_lowercase();
    if l.contains("before being initialized")
        || l.contains("not been initialized")
        || l.contains("0x14a")
    {
        NvError::Uninitialized
    } else if l.contains("handle is not correct")
        || l.contains("does not exist")
        || l.contains("0x18b")
        || l.contains("not defined")
    {
        NvError::NotDefined
    } else if l.contains("policy")
        || l.contains("0x99d")
        || l.contains("0x17d")
        || l.contains("0x9a2")
        || l.contains("hash of the policy does not match")
    {
        NvError::PolicyFailure(blob.trim().to_string())
    } else {
        NvError::Tools(blob.trim().to_string())
    }
}

fn already_defined(msg: &str) -> bool {
    let l = msg.to_lowercase();
    (l.contains("already") && (l.contains("defined") || l.contains("exist"))) || l.contains("0x14c")
}

/// Parse `tpm2_nvread` hex stdout (plain, `0x`-prefixed, or space-separated
/// bytes) as a big-endian u64 — TCG NV counters are 8-octet big-endian.
pub fn parse_nvread_hex(stdout: &str) -> Result<u64, NvError> {
    if !stdout.is_ascii() {
        return Err(NvError::Tools(format!(
            "non-ascii tpm2_nvread output: {stdout:?}"
        )));
    }
    let s = stdout.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let digits: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.len() != 16 {
        return Err(NvError::Tools(format!(
            "unexpected tpm2_nvread output: {stdout:?}"
        )));
    }
    u64::from_str_radix(&digits, 16).map_err(|e| NvError::Tools(format!("nvread parse: {e}")))
}

/// Canonical TCG TPM 2.0 Monotonic Counter Index handle (0x01800001).
pub const CANONICAL_TPM_NV_COUNTER_INDEX: u64 = 0x01800001;

/// Parse `P2P_TPM_NV_INDEX` (hex `0x…`, decimal, or alias "default" / "canonical" / "1").
pub fn parse_index(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("default") || s.eq_ignore_ascii_case("canonical") || s == "1" {
        return Ok(CANONICAL_TPM_NV_COUNTER_INDEX);
    }
    let r = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else {
        s.parse::<u64>()
    };
    r.map_err(|_| format!("invalid P2P_TPM_NV_INDEX {s:?} (expected 0x<hex> or decimal u64)"))
}

/// `None` when the guard is disabled (env unset/empty), `Some` otherwise.
pub fn transport_from_index_str(index: Option<&str>) -> Result<Option<ToolsTransport>, String> {
    let Some(raw) = index else { return Ok(None) };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let idx = parse_index(raw)?;
    let owner = std::env::var("P2P_TPM_NV_OWNER").unwrap_or_else(|_| "o".to_string());
    Ok(Some(ToolsTransport::new(
        idx,
        &owner,
        ToolPaths::from_env(),
    )))
}

/// True when the state file does not exist yet or is empty (a fresh state
/// is created by `read_state_locked` on first open).
pub fn state_is_fresh(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => m.len() == 0,
        Err(_) => true,
    }
}

fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

/// Env-gated dual-monotonic guard entry point covering send_seq + recv_hwm.
pub fn guard_recv(
    state_path: &str,
    key: &[u8; 32],
    send_seq: u64,
    recv_hwm: u64,
    state_fresh: bool,
) -> Result<(), String> {
    let idx = std::env::var("P2P_TPM_NV_INDEX").ok();
    let is_prod = env_flag("P2P_PRODUCTION") || env_flag("SECURE_P2P_PRODUCTION");
    if is_prod && idx.as_deref().unwrap_or("").trim().is_empty() {
        return Err("production mode (P2P_PRODUCTION=1) strictly requires P2P_TPM_NV_INDEX hardware anti-rollback counter".to_string());
    }
    let Some(t) = transport_from_index_str(idx.as_deref())? else {
        return Ok(());
    };
    guard_with_recv(
        &t,
        key,
        state_path,
        send_seq,
        recv_hwm,
        state_fresh,
        env_flag("P2P_TPM_NV_REPROVISION"),
    )
}

/// Env-gated guard entry point (no-op while `P2P_TPM_NV_INDEX` is unset unless in production).
pub fn guard(
    state_path: &str,
    key: &[u8; 32],
    send_seq: u64,
    state_fresh: bool,
) -> Result<(), String> {
    guard_recv(state_path, key, send_seq, 0, state_fresh)
}

/// Env-gated checkpoint entry point (no-op while `P2P_TPM_NV_INDEX` is unset unless in production).
pub fn checkpoint(state_path: &str, key: &[u8; 32], send_seq: u64) -> Result<(), String> {
    checkpoint_recv(state_path, key, send_seq, 0)
}

/// Env-gated dual-monotonic checkpoint entry point covering send_seq + recv_hwm.
pub fn checkpoint_recv(
    state_path: &str,
    key: &[u8; 32],
    send_seq: u64,
    recv_hwm: u64,
) -> Result<(), String> {
    let idx = std::env::var("P2P_TPM_NV_INDEX").ok();
    let is_prod = env_flag("P2P_PRODUCTION") || env_flag("SECURE_P2P_PRODUCTION");
    if is_prod && idx.as_deref().unwrap_or("").trim().is_empty() {
        return Err("production mode (P2P_PRODUCTION=1) strictly requires P2P_TPM_NV_INDEX hardware anti-rollback counter".to_string());
    }
    let Some(t) = transport_from_index_str(idx.as_deref())? else {
        return Ok(());
    };
    checkpoint_with_recv(&t, key, state_path, send_seq, recv_hwm)
}

/// Policy guard against an explicit transport with dual-monotonic coverage (send_seq + recv_hwm).
/// Fail-closed: every inconsistency is an `Err` unless `reprovision` (operator-acknowledged
/// re-anchor) resolves it.
pub fn guard_with_recv(
    t: &dyn NvTransport,
    key: &[u8; 32],
    state_path: &str,
    send_seq: u64,
    recv_hwm: u64,
    state_fresh: bool,
    reprovision: bool,
) -> Result<(), String> {
    let nv = counter_value(t)?;
    let sc = sidecar_last_record(key, state_path);
    let verdict: Result<(), String> = match (&nv, &sc) {
        (None, Ok(None)) => Ok(()),
        (None, Ok(Some(_))) => Err(
            "TPM NV counter is gone/reset while a checkpoint sidecar exists — chain integrity unverifiable"
                .to_string(),
        ),
        (None, Err(e)) | (Some(_), Err(e)) => {
            Err(format!("checkpoint sidecar unusable: {e}"))
        }
        (Some(_), Ok(None)) => Err(
            "checkpoint sidecar (.nvck) missing while the TPM NV counter is live — restore it or re-provision"
                .to_string(),
        ),
        (Some(v), Ok(Some(rec))) => {
            let (v, g, seq, hwm) = (*v, rec.gen, rec.send_seq, rec.recv_hwm);
            if g == v {
                chain_ok_recv(state_fresh, send_seq, seq, recv_hwm, hwm)
            } else if v.checked_add(1) == Some(g) {
                // Crash between sidecar append and nvincrement: finish it.
                match t.increment() {
                    Ok(nv2) if nv2 == g => chain_ok_recv(state_fresh, send_seq, seq, recv_hwm, hwm),
                    Ok(nv2) => Err(format!(
                        "TPM NV counter {nv2} does not match pending checkpoint {g}"
                    )),
                    Err(e) => Err(format!(
                        "TPM NV increment failed while completing pending checkpoint: {}",
                        e.describe()
                    )),
                }
            } else if g > v {
                Err(format!(
                    "sidecar checkpoint {g} is ahead of TPM counter {v} — NV index lost/reset"
                ))
            } else {
                Err(format!(
                    "TPM counter {v} is ahead of sidecar checkpoint {g} — state+sidecar rolled back or foreign write"
                ))
            }
        }
    };
    match verdict {
        Ok(()) => Ok(()),
        Err(_) if reprovision => reanchor_recv(t, key, state_path, send_seq, recv_hwm, nv),
        Err(msg) => Err(format!(
            "{msg}; refusing (fail-closed). Set P2P_TPM_NV_REPROVISION=1 to explicitly \
             re-anchor this chain after operator verification."
        )),
    }
}

/// Policy guard against an explicit transport. Fail-closed: every
/// inconsistency is an `Err` unless `reprovision` (operator-acknowledged
/// re-anchor) resolves it.
pub fn guard_with(
    t: &dyn NvTransport,
    key: &[u8; 32],
    state_path: &str,
    send_seq: u64,
    state_fresh: bool,
    reprovision: bool,
) -> Result<(), String> {
    guard_with_recv(t, key, state_path, send_seq, 0, state_fresh, reprovision)
}

fn chain_ok_recv(
    state_fresh: bool,
    send_seq: u64,
    sidecar_seq: u64,
    recv_hwm: u64,
    sidecar_hwm: u64,
) -> Result<(), String> {
    if state_fresh {
        Err(
            "state file was recreated while an NV checkpoint chain is active — restore the state file or re-provision"
                .to_string(),
        )
    } else if send_seq < sidecar_seq {
        Err(format!(
            "state rollback: send_seq {send_seq} is behind NV checkpoint {sidecar_seq}"
        ))
    } else if recv_hwm < sidecar_hwm {
        Err(format!(
            "state rollback: recv_hwm {recv_hwm} is behind NV checkpoint {sidecar_hwm}"
        ))
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
fn chain_ok(state_fresh: bool, send_seq: u64, sidecar_seq: u64) -> Result<(), String> {
    chain_ok_recv(state_fresh, send_seq, sidecar_seq, 0, 0)
}

/// Append-then-increment checkpoint. See module docs for the crash window.
pub fn checkpoint_with(
    t: &dyn NvTransport,
    key: &[u8; 32],
    state_path: &str,
    send_seq: u64,
) -> Result<(), String> {
    checkpoint_with_recv(t, key, state_path, send_seq, 0)
}

/// Append-then-increment checkpoint with dual-monotonic coverage (send_seq + recv_hwm).
pub fn checkpoint_with_recv(
    t: &dyn NvTransport,
    key: &[u8; 32],
    state_path: &str,
    send_seq: u64,
    recv_hwm: u64,
) -> Result<(), String> {
    match counter_value(t)? {
        None => {
            t.define()
                .map_err(|e| format!("TPM NV define failed: {}", e.describe()))?;
            let v = t
                .increment()
                .map_err(|e| format!("TPM NV increment failed: {}", e.describe()))?;
            sidecar_append_recv(key, state_path, v, send_seq, recv_hwm)
        }
        Some(g) => {
            let g1 = g
                .checked_add(1)
                .ok_or_else(|| "TPM NV counter exhausted — re-provision required".to_string())?;
            sidecar_append_recv(key, state_path, g1, send_seq, recv_hwm)?;
            let v = t.increment().map_err(|e| {
                format!(
                    "TPM NV increment failed after sidecar append (next guard will \
                     complete the checkpoint): {}",
                    e.describe()
                )
            })?;
            if v != g1 {
                return Err(format!(
                    "TPM NV read-back mismatch: expected {g1} after increment, got {v} — \
                     concurrent writer or TPM fault; refusing"
                ));
            }
            Ok(())
        }
    }
}

/// Operator-acknowledged re-anchor (`P2P_TPM_NV_REPROVISION=1`): re-establish
/// the sidecar at the live counter value (or a freshly initialized one),
/// the current `send_seq`, and `recv_hwm`.
fn reanchor_recv(
    t: &dyn NvTransport,
    key: &[u8; 32],
    state_path: &str,
    send_seq: u64,
    recv_hwm: u64,
    nv: Option<u64>,
) -> Result<(), String> {
    let v = match nv {
        Some(v) => v,
        None => {
            t.define().map_err(|e| {
                format!("TPM NV define failed during re-provision: {}", e.describe())
            })?;
            t.increment().map_err(|e| {
                format!(
                    "TPM NV increment failed during re-provision: {}",
                    e.describe()
                )
            })?
        }
    };
    sidecar_append_recv(key, state_path, v, send_seq, recv_hwm)
}

#[allow(dead_code)]
fn reanchor(
    t: &dyn NvTransport,
    key: &[u8; 32],
    state_path: &str,
    send_seq: u64,
    nv: Option<u64>,
) -> Result<(), String> {
    reanchor_recv(t, key, state_path, send_seq, 0, nv)
}

/// `Some(v)` once the counter chain is live, `None` when not started.
fn counter_value(t: &dyn NvTransport) -> Result<Option<u64>, String> {
    match t.read() {
        Ok(v) => Ok(Some(v)),
        Err(NvError::NotDefined) | Err(NvError::Uninitialized) => Ok(None),
        Err(NvError::PolicyFailure(m)) => Err(format!("TPM NV policy check failed: {m}")),
        Err(NvError::Tools(m)) => Err(format!("TPM NV read failed: {m}")),
    }
}

fn sidecar_path(state_path: &str) -> String {
    format!("{state_path}.nvck")
}

fn nvck_subkey(master: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha384>::new(None, master);
    let mut okm = [0u8; 32];
    hk.expand(b"DESTROYER-ST2027-NVCK-AUTH-SUBKEY-v2", &mut okm)
        .expect("HKDF-SHA384 expand for NV checkpoint subkey cannot fail");
    okm
}

fn nvck_tag(master: &[u8; 32], gen: u64, send_seq: u64) -> [u8; 32] {
    let subkey = nvck_subkey(master);
    let mut mac = HmacSha384::new_from_slice(&subkey).expect("HMAC can take key of any size");
    mac.update(b"DESTROYER-ST2027-NVCK-v2");
    mac.update(&gen.to_le_bytes());
    mac.update(&send_seq.to_le_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

pub fn nvck_tag_v3(master: &[u8; 32], gen: u64, send_seq: u64, recv_hwm: u64) -> [u8; 32] {
    let subkey = nvck_subkey(master);
    let mut mac = HmacSha384::new_from_slice(&subkey).expect("HMAC can take key of any size");
    mac.update(b"DESTROYER-ST2027-NVCK-v3");
    mac.update(&gen.to_le_bytes());
    mac.update(&send_seq.to_le_bytes());
    mac.update(&recv_hwm.to_le_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarRecord {
    pub gen: u64,
    pub send_seq: u64,
    pub recv_hwm: u64,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode32(s: &str) -> Option<[u8; 32]> {
    if !s.is_ascii() || s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Append one authenticated checkpoint line and sync (O_APPEND is atomic
/// for small writes; mirrors `seq_journal_append`).
#[allow(dead_code)]
fn sidecar_append(key: &[u8; 32], state_path: &str, gen: u64, send_seq: u64) -> Result<(), String> {
    sidecar_append_recv(key, state_path, gen, send_seq, 0)
}

/// Append one authenticated dual-monotonic checkpoint line (send_seq + recv_hwm) and sync.
pub fn sidecar_append_recv(
    key: &[u8; 32],
    state_path: &str,
    gen: u64,
    send_seq: u64,
    recv_hwm: u64,
) -> Result<(), String> {
    let line = if recv_hwm == 0 {
        let tag = nvck_tag(key, gen, send_seq);
        format!("{gen} {send_seq} {}\n", hex_encode(&tag))
    } else {
        let tag = nvck_tag_v3(key, gen, send_seq, recv_hwm);
        format!("{gen} {send_seq} {recv_hwm} {}\n", hex_encode(&tag))
    };
    let path = sidecar_path(state_path);
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("NV checkpoint sidecar unopenable ({path}): {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = f.metadata() {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                let _ = f.set_permissions(std::fs::Permissions::from_mode(mode & !0o077));
            }
        }
    }
    f.write_all(line.as_bytes())
        .map_err(|e| format!("NV checkpoint sidecar write failed ({path}): {e}"))?;
    f.sync_all()
        .map_err(|e| format!("NV checkpoint sidecar sync failed ({path}): {e}"))?;
    Ok(())
}

/// Last authenticated sidecar record (supports both v2 3-token and v3 4-token formats).
pub fn sidecar_last_record(
    key: &[u8; 32],
    state_path: &str,
) -> Result<Option<SidecarRecord>, String> {
    let path = sidecar_path(state_path);
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("NV checkpoint sidecar unreadable ({path}): {e}")),
    };
    let Some(line) = contents.lines().rev().find(|l| !l.trim().is_empty()) else {
        return Ok(None);
    };
    let tokens: Vec<&str> = line.split_whitespace().collect();
    use subtle::ConstantTimeEq;
    match tokens.len() {
        3 => {
            let gen: u64 = tokens[0]
                .parse()
                .map_err(|_| format!("NV checkpoint sidecar corrupt (gen) in {path}"))?;
            let seq: u64 = tokens[1]
                .parse()
                .map_err(|_| format!("NV checkpoint sidecar corrupt (send_seq) in {path}"))?;
            let Some(tag_bytes) = hex_decode32(tokens[2]) else {
                return Err(format!("NV checkpoint sidecar corrupt (tag) in {path}"));
            };
            let expect = nvck_tag(key, gen, seq);
            if tag_bytes.ct_eq(&expect).unwrap_u8() != 1 {
                return Err(format!(
                    "NV checkpoint sidecar authentication failed in {path} \
                     (wrong session key or forged sidecar)"
                ));
            }
            Ok(Some(SidecarRecord {
                gen,
                send_seq: seq,
                recv_hwm: 0,
            }))
        }
        4 => {
            let gen: u64 = tokens[0]
                .parse()
                .map_err(|_| format!("NV checkpoint sidecar corrupt (gen) in {path}"))?;
            let seq: u64 = tokens[1]
                .parse()
                .map_err(|_| format!("NV checkpoint sidecar corrupt (send_seq) in {path}"))?;
            let recv_hwm: u64 = tokens[2]
                .parse()
                .map_err(|_| format!("NV checkpoint sidecar corrupt (recv_hwm) in {path}"))?;
            let Some(tag_bytes) = hex_decode32(tokens[3]) else {
                return Err(format!("NV checkpoint sidecar corrupt (tag) in {path}"));
            };
            let expect = nvck_tag_v3(key, gen, seq, recv_hwm);
            if tag_bytes.ct_eq(&expect).unwrap_u8() != 1 {
                return Err(format!(
                    "NV checkpoint sidecar authentication failed in {path} \
                     (wrong session key or forged sidecar)"
                ));
            }
            Ok(Some(SidecarRecord {
                gen,
                send_seq: seq,
                recv_hwm,
            }))
        }
        _ => Err(format!(
            "NV checkpoint sidecar corrupt (malformed last line) in {path}"
        )),
    }
}

/// Last authenticated sidecar line. `Ok(None)` = no sidecar; corruption or
/// a bad tag is `Err` (fail-closed; only the last line is load-bearing).
#[allow(dead_code)]
fn sidecar_last(key: &[u8; 32], state_path: &str) -> Result<Option<(u64, u64)>, String> {
    sidecar_last_record(key, state_path).map(|opt| opt.map(|r| (r.gen, r.send_seq)))
}

/// Measured Boot PCR bank and registers policy for TPM 2.0 object sealing.
/// Default configuration covers PCRs 0, 1, 2, and 7:
/// - PCR 0: CRTM, BIOS / UEFI firmware code & embedded measurements
/// - PCR 1: Host Platform Configuration & motherboard hardware
/// - PCR 2: UEFI Option ROMs (PCIe devices, RAID, NIC firmware)
/// - PCR 7: Secure Boot State, PK, KEK, db, dbx, and policy enforcement
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPcrPolicy {
    pub bank: String,
    pub pcrs: Vec<u32>,
}

impl Default for TpmPcrPolicy {
    fn default() -> Self {
        Self {
            bank: "sha256".to_string(),
            pcrs: vec![0, 1, 2, 7],
        }
    }
}

impl TpmPcrPolicy {
    pub fn new(bank: &str, pcrs: &[u32]) -> Self {
        Self {
            bank: bank.to_string(),
            pcrs: pcrs.to_vec(),
        }
    }

    pub fn pcr_spec(&self) -> String {
        let list: Vec<String> = self.pcrs.iter().map(|p| p.to_string()).collect();
        format!("{}:{}", self.bank, list.join(","))
    }
}

/// Seal a 32-byte signing seed into TPM 2.0 silicon bound to measured boot PCRs (0, 1, 2, 7).
pub fn seal_seed_to_pcrs(
    seed: &[u8; 32],
    policy: &TpmPcrPolicy,
    out_priv: &str,
    out_pub: &str,
    owner: &str,
    tools: &ToolPaths,
) -> Result<(), NvError> {
    let temp_dir = std::env::temp_dir().join(format!("tpm_seal_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| NvError::Tools(format!("temp dir creation: {e}")))?;

    let primary_ctx = temp_dir.join("primary.ctx");
    let pcr_bin = temp_dir.join("pcr.bin");
    let policy_file = temp_dir.join("pcr.policy");
    let seed_file = temp_dir.join("seed.dat");

    std::fs::write(&seed_file, seed)
        .map_err(|e| NvError::Tools(format!("seed file write: {e}")))?;

    let pcr_spec = policy.pcr_spec();
    let primary_args = vec![
        "-C".to_string(),
        owner.to_string(),
        "-g".to_string(),
        "sha256".to_string(),
        "-G".to_string(),
        "rsa".to_string(),
        "-c".to_string(),
        primary_ctx.to_string_lossy().to_string(),
    ];
    if let Err(e) = run_tool(&tools.createprimary, &primary_args) {
        let _ = purge_temp_dir(&temp_dir, &seed_file);
        return Err(e);
    }

    let pcrread_args = vec![
        "-l".to_string(),
        pcr_spec.clone(),
        "-o".to_string(),
        pcr_bin.to_string_lossy().to_string(),
    ];
    if let Err(e) = run_tool(&tools.pcrread, &pcrread_args) {
        let _ = purge_temp_dir(&temp_dir, &seed_file);
        return Err(e);
    }

    let policy_args = vec![
        "--policy-pcr".to_string(),
        "-l".to_string(),
        pcr_spec,
        "-f".to_string(),
        pcr_bin.to_string_lossy().to_string(),
        "-L".to_string(),
        policy_file.to_string_lossy().to_string(),
    ];
    if let Err(e) = run_tool(&tools.createpolicy, &policy_args) {
        let _ = purge_temp_dir(&temp_dir, &seed_file);
        return Err(e);
    }

    let create_args = vec![
        "-C".to_string(),
        primary_ctx.to_string_lossy().to_string(),
        "-L".to_string(),
        policy_file.to_string_lossy().to_string(),
        "-u".to_string(),
        out_pub.to_string(),
        "-r".to_string(),
        out_priv.to_string(),
        "-i".to_string(),
        seed_file.to_string_lossy().to_string(),
    ];
    let res = run_tool(&tools.create, &create_args);

    let _ = run_tool(
        &tools.flushcontext,
        &[primary_ctx.to_string_lossy().to_string()],
    );
    let _ = purge_temp_dir(&temp_dir, &seed_file);

    res.map(|_| ())
}

/// Unseal a 32-byte signing seed from TPM 2.0 silicon.
///
/// Fails fail-closed if:
/// - Firmware or BIOS is tampered with (PCR 0/1 changed)
/// - Option ROMs / hardware cards altered (PCR 2 changed)
/// - Secure Boot state or platform keys tampered/disabled (PCR 7 changed)
pub fn unseal_seed_from_pcrs(
    priv_path: &str,
    pub_path: &str,
    policy: &TpmPcrPolicy,
    owner: &str,
    tools: &ToolPaths,
) -> Result<LockedKey32, NvError> {
    let temp_dir = std::env::temp_dir().join(format!("tpm_unseal_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| NvError::Tools(format!("temp dir creation: {e}")))?;

    let primary_ctx = temp_dir.join("primary.ctx");
    let seal_ctx = temp_dir.join("seal.ctx");
    let pcr_spec = policy.pcr_spec();

    let primary_args = vec![
        "-C".to_string(),
        owner.to_string(),
        "-g".to_string(),
        "sha256".to_string(),
        "-G".to_string(),
        "rsa".to_string(),
        "-c".to_string(),
        primary_ctx.to_string_lossy().to_string(),
    ];
    let p_res = run_tool(&tools.createprimary, &primary_args);
    if let Err(e) = p_res {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(e);
    }

    let load_args = vec![
        "-C".to_string(),
        primary_ctx.to_string_lossy().to_string(),
        "-u".to_string(),
        pub_path.to_string(),
        "-r".to_string(),
        priv_path.to_string(),
        "-c".to_string(),
        seal_ctx.to_string_lossy().to_string(),
    ];
    let load_res = run_tool(&tools.load, &load_args);
    if let Err(e) = load_res {
        let _ = run_tool(
            &tools.flushcontext,
            &[primary_ctx.to_string_lossy().to_string()],
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(e);
    }

    let unseal_args = vec![
        "-c".to_string(),
        seal_ctx.to_string_lossy().to_string(),
        "-p".to_string(),
        format!("pcr:{}", pcr_spec),
    ];
    let unseal_res = run_tool_bytes(&tools.unseal, &unseal_args);

    let _ = run_tool(
        &tools.flushcontext,
        &[seal_ctx.to_string_lossy().to_string()],
    );
    let _ = run_tool(
        &tools.flushcontext,
        &[primary_ctx.to_string_lossy().to_string()],
    );
    let _ = std::fs::remove_dir_all(&temp_dir);

    let raw_bytes = unseal_res?;
    if raw_bytes.len() < 32 {
        return Err(NvError::PolicyFailure(format!(
            "Unsealed payload size mismatch (expected 32 bytes, got {})",
            raw_bytes.len()
        )));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw_bytes[..32]);
    let locked = LockedKey32::new(seed);
    seed.zeroize();

    Ok(locked)
}

pub fn run_tool_bytes(prog: &str, argv: &[String]) -> Result<Vec<u8>, NvError> {
    let out = std::process::Command::new(prog)
        .args(argv)
        .output()
        .map_err(|e| NvError::Tools(format!("{prog}: {e}")))?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    Err(classify_failure(&format!("{stderr}{stdout}")))
}

fn purge_temp_dir(dir: &std::path::Path, seed_file: &std::path::Path) -> Result<(), NvError> {
    if seed_file.exists() {
        if let Ok(meta) = std::fs::metadata(seed_file) {
            let zeros = vec![0u8; meta.len() as usize];
            let _ = std::fs::write(seed_file, zeros);
        }
        let _ = std::fs::remove_file(seed_file);
    }
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// In-memory mock PCR policy simulator for unit tests and CI verification without hardware.
#[derive(Debug, Clone)]
pub struct MockTpmPcrSimulator {
    pub pcr_0: [u8; 32], // CRTM / BIOS
    pub pcr_1: [u8; 32], // Platform config
    pub pcr_2: [u8; 32], // Option ROMs
    pub pcr_7: [u8; 32], // Secure Boot state
    sealed_policy_digest: Option<[u8; 32]>,
    sealed_ciphertext: Option<Vec<u8>>,
}

impl MockTpmPcrSimulator {
    pub fn new_clean_measured_boot() -> Self {
        Self {
            pcr_0: [0x11u8; 32], // Measured BIOS
            pcr_1: [0x22u8; 32], // Measured Motherboard
            pcr_2: [0x33u8; 32], // Measured Option ROM
            pcr_7: [0x77u8; 32], // Secure Boot ENABLED + Valid PK/KEK
            sealed_policy_digest: None,
            sealed_ciphertext: None,
        }
    }

    pub fn compute_composite_pcr_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.pcr_0);
        hasher.update(self.pcr_1);
        hasher.update(self.pcr_2);
        hasher.update(self.pcr_7);
        hasher.finalize().into()
    }

    pub fn seal(&mut self, seed: &[u8; 32]) {
        let policy_digest = self.compute_composite_pcr_digest();
        let mut ct = vec![0u8; 32];
        for i in 0..32 {
            ct[i] = seed[i] ^ policy_digest[i];
        }
        self.sealed_policy_digest = Some(policy_digest);
        self.sealed_ciphertext = Some(ct);
    }

    pub fn unseal(&self) -> Result<LockedKey32, NvError> {
        let current_policy_digest = self.compute_composite_pcr_digest();
        let expected = self.sealed_policy_digest.ok_or(NvError::NotDefined)?;

        if !ct_eq(&current_policy_digest, &expected) {
            return Err(NvError::PolicyFailure(
                "TPM_RC_POLICY_FAIL (0x99D): Platform Configuration Registers mismatch. Firmware tampered or Secure Boot disabled."
                    .to_string(),
            ));
        }

        let ct = self
            .sealed_ciphertext
            .as_ref()
            .ok_or(NvError::Uninitialized)?;
        let mut pt = [0u8; 32];
        for i in 0..32 {
            pt[i] = ct[i] ^ current_policy_digest[i];
        }
        let locked = LockedKey32::new(pt);
        pt.zeroize();
        Ok(locked)
    }

    pub fn tamper_firmware(&mut self) {
        self.pcr_0[0] ^= 0xFF; // Modify BIOS measurement
    }

    pub fn disable_secure_boot(&mut self) {
        self.pcr_7[0] ^= 0xAA; // Modify Secure Boot measurement
    }

    pub fn tamper_option_rom(&mut self) {
        self.pcr_2[0] ^= 0x55; // Modify Option ROM measurement
    }
}

/// Default TPM 2.0 NV index for CRL sequence anti-rollback guard.
pub const DEFAULT_TPM_CRL_INDEX: u64 = 0x1500017;

/// TPM 2.0 CRL hardware anti-rollback guard.
/// Enforces monotonic sequence numbers for in-band Certificate Revocation Lists.
/// Replay or rollback of older/equal CRL sequence numbers is rejected fail-closed
/// by hardware anti-rollback counters.
pub fn guard_crl_sequence_with(t: &dyn NvTransport, crl_seq: u64) -> Result<(), String> {
    let live = counter_value(t)?;
    match live {
        Some(v) => {
            if crl_seq <= v {
                return Err(format!(
                    "CRL sequence rollback refused by hardware TPM 2.0 counter: crl_seq={crl_seq} <= live_tpm={v}"
                ));
            }
            let steps = crl_seq.saturating_sub(v);
            for _ in 0..steps {
                t.increment().map_err(|e| {
                    format!(
                        "TPM NV increment failed advancing CRL counter: {}",
                        e.describe()
                    )
                })?;
            }
            Ok(())
        }
        None => {
            let _ = t.define();
            for _ in 0..crl_seq.max(1) {
                t.increment().map_err(|e| {
                    format!(
                        "TPM NV increment failed initializing CRL counter: {}",
                        e.describe()
                    )
                })?;
            }
            Ok(())
        }
    }
}

/// Check and record a new CRL sequence number against the active TPM 2.0 NV counter.
/// If `P2P_TPM_CRL_INDEX` is configured (or if `P2P_TPM_NV_INDEX` is set), binds to physical TPM silicon.
/// In software/test environments without hardware TPM, anchors to sidecar `<state>.crl_seq`.
pub fn guard_crl_sequence(state_path: Option<&str>, crl_seq: u64) -> Result<(), String> {
    let index_str = std::env::var("P2P_TPM_CRL_INDEX")
        .or_else(|_| std::env::var("P2P_TPM_NV_INDEX"))
        .ok();

    if let Some(s) = index_str {
        if let Ok(idx) = parse_index(&s) {
            let crl_idx = if std::env::var("P2P_TPM_CRL_INDEX").is_ok() {
                idx
            } else {
                idx.saturating_add(1)
            };
            let owner = std::env::var("P2P_TPM_NV_OWNER").unwrap_or_else(|_| "o".to_string());
            let transport = ToolsTransport::new(crl_idx, &owner, ToolPaths::from_env());
            return guard_crl_sequence_with(&transport, crl_seq);
        }
    }

    let sidecar_opt = state_path
        .map(|sp| format!("{sp}.crl_seq"))
        .or_else(|| std::env::var("ST2027_CRL_SIDECAR").ok());

    if let Some(sidecar) = sidecar_opt {
        if let Ok(content) = std::fs::read_to_string(&sidecar) {
            if let Ok(last_seq) = content.trim().parse::<u64>() {
                if crl_seq <= last_seq {
                    return Err(format!(
                        "CRL sequence rollback refused by anti-rollback counter: crl_seq={crl_seq} <= last_seq={last_seq}"
                    ));
                }
            }
        }
        let _ = std::fs::write(&sidecar, crl_seq.to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn crl_sequence_hardware_anti_rollback() {
        let t = FakeNv::new();
        // First CRL seq = 5 initializes counter to 5
        guard_crl_sequence_with(&t, 5).unwrap();
        assert_eq!(t.value.get(), Some(5));

        // Replay of seq = 5 rejected
        assert!(guard_crl_sequence_with(&t, 5).is_err());

        // Stale older CRL seq = 4 rejected
        assert!(guard_crl_sequence_with(&t, 4).is_err());

        // Monotonic higher CRL seq = 8 accepted and advances counter
        guard_crl_sequence_with(&t, 8).unwrap();
        assert_eq!(t.value.get(), Some(8));

        // Replay of seq = 8 rejected
        assert!(guard_crl_sequence_with(&t, 8).is_err());
    }

    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "st2027_tpmnv_{tag}_{}_{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        p.to_string_lossy().into_owned()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(sidecar_path(path));
    }

    /// In-memory transport: defined flag + optional counter value.
    struct FakeNv {
        defined: Cell<bool>,
        value: Cell<Option<u64>>,
        /// Read-back returns one more than stored (TPM fault simulation).
        wrong_readback: Cell<bool>,
    }

    impl FakeNv {
        fn new() -> Self {
            Self {
                defined: Cell::new(false),
                value: Cell::new(None),
                wrong_readback: Cell::new(false),
            }
        }

        fn started(v: u64) -> Self {
            let t = Self::new();
            t.defined.set(true);
            t.value.set(Some(v));
            t
        }
    }

    impl NvTransport for FakeNv {
        fn read(&self) -> Result<u64, NvError> {
            if !self.defined.get() {
                return Err(NvError::NotDefined);
            }
            self.value.get().ok_or(NvError::Uninitialized)
        }

        fn increment(&self) -> Result<u64, NvError> {
            if !self.defined.get() {
                return Err(NvError::NotDefined);
            }
            let nv = match self.value.get() {
                None => 1,
                Some(v) => v
                    .checked_add(1)
                    .ok_or_else(|| NvError::Tools("counter exhausted".to_string()))?,
            };
            if self.wrong_readback.get() {
                let wrong = nv + 1;
                self.value.set(Some(wrong));
                return Ok(wrong);
            }
            self.value.set(Some(nv));
            Ok(nv)
        }

        fn define(&self) -> Result<(), NvError> {
            self.defined.set(true);
            Ok(())
        }
    }

    const KEY: [u8; 32] = [9u8; 32];

    #[test]
    fn parse_index_forms() {
        assert_eq!(parse_index("0x1500016").unwrap(), 0x1500016);
        assert_eq!(parse_index("1500016").unwrap(), 1_500_016);
        assert!(parse_index("0xzz").is_err());
        assert!(parse_index("").is_err());
        assert!(transport_from_index_str(None).unwrap().is_none());
        assert!(transport_from_index_str(Some("  ")).unwrap().is_none());
        assert!(transport_from_index_str(Some("0xnope")).is_err());
    }

    #[test]
    fn parse_nvread_output_forms() {
        assert_eq!(parse_nvread_hex("0000000000000000\n").unwrap(), 0);
        assert_eq!(parse_nvread_hex("0x000000000000000f").unwrap(), 15);
        assert_eq!(parse_nvread_hex("00 00 00 00 00 00 00 0a").unwrap(), 10);
        assert!(parse_nvread_hex("zz").is_err());
        assert!(parse_nvread_hex("").is_err());
        assert!(parse_nvread_hex("000000000000000000000000").is_err());
    }

    #[test]
    fn classify_failure_variants() {
        assert_eq!(
            classify_failure("tpm: an NV Index is used before being initialized (0x0000014a)"),
            NvError::Uninitialized
        );
        assert_eq!(
            classify_failure("tpm:handle(1):the handle is not correct for the use"),
            NvError::NotDefined
        );
        assert_eq!(
            classify_failure("ERROR: Unable to run tpm2_nvread"),
            NvError::Tools("ERROR: Unable to run tpm2_nvread".to_string())
        );
        assert!(already_defined("ERROR: NV index already defined"));
        assert!(!already_defined("ERROR: no space left"));
    }

    #[test]
    fn pcr_policy_specification_format() {
        let policy = TpmPcrPolicy::default();
        assert_eq!(policy.pcr_spec(), "sha256:0,1,2,7");
        let custom = TpmPcrPolicy::new("sha384", &[0, 7]);
        assert_eq!(custom.pcr_spec(), "sha384:0,7");
    }

    #[test]
    fn mock_tpm_pcr_sealing_unseal_roundtrip() {
        let mut sim = MockTpmPcrSimulator::new_clean_measured_boot();
        let seed = [0x42u8; 32];
        sim.seal(&seed);
        let unsealed = sim.unseal().expect("unseal on clean boot");
        assert_eq!(unsealed.as_bytes(), &seed);
    }

    #[test]
    fn mock_tpm_pcr_tamper_firmware_fails_closed() {
        let mut sim = MockTpmPcrSimulator::new_clean_measured_boot();
        let seed = [0x42u8; 32];
        sim.seal(&seed);
        sim.tamper_firmware();
        let err = sim.unseal().unwrap_err();
        match err {
            NvError::PolicyFailure(msg) => {
                assert!(msg.contains("TPM_RC_POLICY_FAIL") || msg.contains("mismatch"));
            }
            _ => panic!("Expected PolicyFailure, got {err:?}"),
        }
    }

    #[test]
    fn mock_tpm_pcr_disable_secure_boot_fails_closed() {
        let mut sim = MockTpmPcrSimulator::new_clean_measured_boot();
        let seed = [0x42u8; 32];
        sim.seal(&seed);
        sim.disable_secure_boot();
        let err = sim.unseal().unwrap_err();
        match err {
            NvError::PolicyFailure(msg) => {
                assert!(msg.contains("TPM_RC_POLICY_FAIL") || msg.contains("mismatch"));
            }
            _ => panic!("Expected PolicyFailure, got {err:?}"),
        }
    }

    #[test]
    fn mock_tpm_pcr_tamper_option_rom_fails_closed() {
        let mut sim = MockTpmPcrSimulator::new_clean_measured_boot();
        let seed = [0x42u8; 32];
        sim.seal(&seed);
        sim.tamper_option_rom();
        let err = sim.unseal().unwrap_err();
        match err {
            NvError::PolicyFailure(msg) => {
                assert!(msg.contains("TPM_RC_POLICY_FAIL") || msg.contains("mismatch"));
            }
            _ => panic!("Expected PolicyFailure, got {err:?}"),
        }
    }

    #[test]
    fn tool_argv_construction() {
        let t = ToolsTransport::new(
            0x1500016,
            "o",
            ToolPaths {
                nvread: "tpm2_nvread".to_string(),
                nvincrement: "tpm2_nvincrement".to_string(),
                nvdefine: "tpm2_nvdefine".to_string(),
                ..ToolPaths::default()
            },
        );
        let (p, a) = t.read_argv();
        assert_eq!(p, "tpm2_nvread");
        assert_eq!(a, vec!["0x1500016", "-C", "o", "-s", "8"]);
        let (p, a) = t.increment_argv();
        assert_eq!(p, "tpm2_nvincrement");
        assert_eq!(a, vec!["0x1500016", "-C", "o"]);
        let (p, a) = t.define_argv();
        assert_eq!(p, "tpm2_nvdefine");
        assert_eq!(
            a,
            vec![
                "0x1500016",
                "-C",
                "o",
                "-s",
                "8",
                "-a",
                "ownerread|ownerwrite|nt=counter"
            ]
        );
    }

    #[test]
    fn state_fresh_detection() {
        let path = tmp_path("fresh");
        let _ = std::fs::remove_file(&path);
        assert!(state_is_fresh(&path));
        std::fs::write(&path, b"").unwrap();
        assert!(state_is_fresh(&path));
        std::fs::write(&path, b"STSTATE3...").unwrap();
        assert!(!state_is_fresh(&path));
        cleanup(&path);
    }

    #[test]
    fn first_run_noop_then_anchor() {
        let path = tmp_path("anchor");
        let t = FakeNv::new();
        // Fresh state, chain not started: nothing to compare.
        guard_with(&t, &KEY, &path, 100, true, false).unwrap();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        assert_eq!(t.value.get(), Some(1));
        assert_eq!(sidecar_last(&KEY, &path).unwrap(), Some((1, 100)));
        // Later loads: equal or advanced send_seq both pass.
        guard_with(&t, &KEY, &path, 100, false, false).unwrap();
        guard_with(&t, &KEY, &path, 150, false, false).unwrap();
        checkpoint_with(&t, &KEY, &path, 150).unwrap();
        assert_eq!(sidecar_last(&KEY, &path).unwrap(), Some((2, 150)));
        cleanup(&path);
    }

    #[test]
    fn send_seq_rollback_refused() {
        let path = tmp_path("rollback");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        let e = guard_with(&t, &KEY, &path, 50, false, false).unwrap_err();
        assert!(e.contains("behind NV checkpoint"), "{e}");
        assert!(e.contains("REPROVISION"), "{e}");
        cleanup(&path);
    }

    #[test]
    fn recv_hwm_rollback_refused() {
        let path = tmp_path("rollback_recv");
        let t = FakeNv::new();
        checkpoint_with_recv(&t, &KEY, &path, 100, 200).unwrap();
        let e = guard_with_recv(&t, &KEY, &path, 100, 150, false, false).unwrap_err();
        assert!(e.contains("recv_hwm 150 is behind NV checkpoint 200"), "{e}");
        assert!(e.contains("REPROVISION"), "{e}");
        guard_with_recv(&t, &KEY, &path, 100, 250, false, false).unwrap();
        cleanup(&path);
    }

    #[test]
    fn counter_ahead_of_sidecar_refused_unless_reprovisioned() {
        let path = tmp_path("ahead");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        // Foreign increment: counter advances without a sidecar line.
        t.value.set(Some(3));
        let e = guard_with(&t, &KEY, &path, 100, false, false).unwrap_err();
        assert!(e.contains("ahead of sidecar checkpoint"), "{e}");
        // Operator-acknowledged re-anchor recovers.
        guard_with(&t, &KEY, &path, 100, false, true).unwrap();
        assert_eq!(sidecar_last(&KEY, &path).unwrap(), Some((3, 100)));
        guard_with(&t, &KEY, &path, 100, false, false).unwrap();
        cleanup(&path);
    }

    #[test]
    fn sidecar_missing_refused_unless_reprovisioned() {
        let path = tmp_path("sidegone");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        std::fs::remove_file(sidecar_path(&path)).unwrap();
        let e = guard_with(&t, &KEY, &path, 100, false, false).unwrap_err();
        assert!(e.contains("sidecar (.nvck) missing"), "{e}");
        guard_with(&t, &KEY, &path, 100, false, true).unwrap();
        assert_eq!(sidecar_last(&KEY, &path).unwrap(), Some((1, 100)));
        cleanup(&path);
    }

    #[test]
    fn counter_gone_refused_unless_reprovisioned() {
        let path = tmp_path("countergone");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        t.defined.set(false);
        let e = guard_with(&t, &KEY, &path, 100, false, false).unwrap_err();
        assert!(e.contains("gone/reset"), "{e}");
        guard_with(&t, &KEY, &path, 100, false, true).unwrap();
        // Re-anchored: the sidecar generation now matches the live counter.
        let (g, _) = sidecar_last(&KEY, &path).unwrap().unwrap();
        assert_eq!(g, t.value.get().unwrap());
        guard_with(&t, &KEY, &path, 100, false, false).unwrap();
        cleanup(&path);
    }

    #[test]
    fn fresh_state_mid_chain_refused() {
        let path = tmp_path("freshmid");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        let e = guard_with(&t, &KEY, &path, 999, true, false).unwrap_err();
        assert!(e.contains("recreated"), "{e}");
        cleanup(&path);
    }

    #[test]
    fn crash_window_self_heals() {
        let path = tmp_path("crashwin");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap(); // gen 1
                                                        // Simulate crash after sidecar append, before nvincrement.
        sidecar_append(&KEY, &path, 2, 150).unwrap();
        assert_eq!(t.value.get(), Some(1));
        guard_with(&t, &KEY, &path, 150, false, false).unwrap();
        assert_eq!(t.value.get(), Some(2));
        assert_eq!(sidecar_last(&KEY, &path).unwrap(), Some((2, 150)));
        cleanup(&path);
    }

    #[test]
    fn sidecar_far_ahead_refused() {
        let path = tmp_path("farahead");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap(); // gen 1, nv 1
        sidecar_append(&KEY, &path, 4, 100).unwrap();
        let e = guard_with(&t, &KEY, &path, 100, false, false).unwrap_err();
        assert!(e.contains("ahead of TPM counter"), "{e}");
        cleanup(&path);
    }

    #[test]
    fn forged_sidecar_tag_rejected() {
        let path = tmp_path("forged");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        // Forge a line with a bad tag (attacker without the session key).
        let p = sidecar_path(&path);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "1 50 {}", "00".repeat(32)).unwrap();
        drop(f);
        let e = guard_with(&t, &KEY, &path, 100, false, false).unwrap_err();
        assert!(
            e.contains("unusable") && e.contains("authentication"),
            "{e}"
        );
        cleanup(&path);
    }

    #[test]
    fn rekeyed_key_rejected() {
        let path = tmp_path("rekey");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        let other = [1u8; 32];
        let e = guard_with(&t, &other, &path, 100, false, false).unwrap_err();
        assert!(e.contains("authentication"), "{e}");
        cleanup(&path);
    }

    #[test]
    fn corrupt_sidecar_line_refused() {
        let path = tmp_path("corrupt");
        let t = FakeNv::new();
        checkpoint_with(&t, &KEY, &path, 100).unwrap();
        std::fs::write(sidecar_path(&path), "garbage line\n").unwrap();
        let e = guard_with(&t, &KEY, &path, 100, false, false).unwrap_err();
        assert!(e.contains("corrupt"), "{e}");
        // Reprovision recovers by appending a fresh valid anchor.
        guard_with(&t, &KEY, &path, 100, false, true).unwrap();
        assert_eq!(sidecar_last(&KEY, &path).unwrap(), Some((1, 100)));
        cleanup(&path);
    }

    #[test]
    fn readback_mismatch_fails_checkpoint() {
        let path = tmp_path("readback");
        let t = FakeNv::started(5);
        t.wrong_readback.set(true);
        let e = checkpoint_with(&t, &KEY, &path, 100).unwrap_err();
        assert!(e.contains("read-back mismatch"), "{e}");
        cleanup(&path);
    }

    #[test]
    fn counter_exhaustion_fails_checkpoint() {
        let path = tmp_path("exhaust");
        let t = FakeNv::started(u64::MAX);
        let e = checkpoint_with(&t, &KEY, &path, 100).unwrap_err();
        assert!(e.contains("exhausted"), "{e}");
        cleanup(&path);
    }

    #[test]
    fn tools_read_failure_is_fail_closed() {
        let path = tmp_path("toolerr");
        struct Broken;
        impl NvTransport for Broken {
            fn read(&self) -> Result<u64, NvError> {
                Err(NvError::Tools("device gone".to_string()))
            }
            fn increment(&self) -> Result<u64, NvError> {
                Err(NvError::Tools("device gone".to_string()))
            }
            fn define(&self) -> Result<(), NvError> {
                Err(NvError::Tools("device gone".to_string()))
            }
        }
        let e = guard_with(&Broken, &KEY, &path, 1, false, false).unwrap_err();
        assert!(e.contains("TPM NV read failed"), "{e}");
        let e = checkpoint_with(&Broken, &KEY, &path, 1).unwrap_err();
        assert!(e.contains("TPM NV read failed"), "{e}");
        cleanup(&path);
    }
}
