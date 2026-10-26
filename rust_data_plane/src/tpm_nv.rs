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
//!   checkpoint `<gen> <send_seq> <hex HMAC-SHA256>`. The tag is keyed from
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
//! # Honest limitations
//! - The receive-side replay bitmap is not NV-covered: recv updates keep
//!   `send_seq` unchanged, so a bitmap-only state regression between
//!   checkpoints is out of scope here (F-01 covers the send/nonce side).
//! - Rollback of reservations since the last checkpoint is covered by the
//!   `.seqlog` journal; the NV layer covers restore of any
//!   sidecar-consistent snapshot the generation chain has passed.
//! - No real-TPM integration test runs in CI (no hardware); the policy
//!   layer is exercised against an in-memory fake transport and the tool
//!   layer against argv/classification unit tests.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;

type HmacSha256 = Hmac<Sha256>;

/// Failure modes surfaced by an [`NvTransport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvError {
    /// The NV index does not exist (TPM RC 0x18B / equivalent).
    NotDefined,
    /// Defined but never incremented (TPM RC 0x14A, "used before being
    /// initialized") — counter chain not started yet.
    Uninitialized,
    /// Tool spawn/parse/TPM failure with no better classification.
    Tools(String),
}

impl NvError {
    pub fn describe(&self) -> String {
        match self {
            NvError::NotDefined => "NV index not defined".to_string(),
            NvError::Uninitialized => "NV index not yet initialized".to_string(),
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
}

impl ToolPaths {
    pub fn from_env() -> Self {
        Self {
            nvread: std::env::var("P2P_TPM2_NVREAD").unwrap_or_else(|_| "tpm2_nvread".to_string()),
            nvincrement: std::env::var("P2P_TPM2_NVINCREMENT")
                .unwrap_or_else(|_| "tpm2_nvincrement".to_string()),
            nvdefine: std::env::var("P2P_TPM2_NVDEFINE")
                .unwrap_or_else(|_| "tpm2_nvdefine".to_string()),
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
        let out = run_tool(&prog, &argv)?;
        parse_nvread_hex(&out)
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

/// Parse `P2P_TPM_NV_INDEX` (hex `0x…` or decimal).
pub fn parse_index(s: &str) -> Result<u64, String> {
    let s = s.trim();
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

/// Env-gated guard entry point (no-op while `P2P_TPM_NV_INDEX` is unset).
pub fn guard(
    state_path: &str,
    key: &[u8; 32],
    send_seq: u64,
    state_fresh: bool,
) -> Result<(), String> {
    let idx = std::env::var("P2P_TPM_NV_INDEX").ok();
    let Some(t) = transport_from_index_str(idx.as_deref())? else {
        return Ok(());
    };
    guard_with(
        &t,
        key,
        state_path,
        send_seq,
        state_fresh,
        env_flag("P2P_TPM_NV_REPROVISION"),
    )
}

/// Env-gated checkpoint entry point (no-op while `P2P_TPM_NV_INDEX` is unset).
pub fn checkpoint(state_path: &str, key: &[u8; 32], send_seq: u64) -> Result<(), String> {
    let idx = std::env::var("P2P_TPM_NV_INDEX").ok();
    let Some(t) = transport_from_index_str(idx.as_deref())? else {
        return Ok(());
    };
    checkpoint_with(&t, key, state_path, send_seq)
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
    let nv = counter_value(t)?;
    let sc = sidecar_last(key, state_path);
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
        (Some(v), Ok(Some((g, seq)))) => {
            let (v, g, seq) = (*v, *g, *seq);
            if g == v {
                chain_ok(state_fresh, send_seq, seq)
            } else if v.checked_add(1) == Some(g) {
                // Crash between sidecar append and nvincrement: finish it.
                match t.increment() {
                    Ok(nv2) if nv2 == g => chain_ok(state_fresh, send_seq, seq),
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
        Err(_) if reprovision => reanchor(t, key, state_path, send_seq, nv),
        Err(msg) => Err(format!(
            "{msg}; refusing (fail-closed). Set P2P_TPM_NV_REPROVISION=1 to explicitly \
             re-anchor this chain after operator verification."
        )),
    }
}

fn chain_ok(state_fresh: bool, send_seq: u64, sidecar_seq: u64) -> Result<(), String> {
    if state_fresh {
        Err(
            "state file was recreated while an NV checkpoint chain is active — restore the state file or re-provision"
                .to_string(),
        )
    } else if send_seq < sidecar_seq {
        Err(format!(
            "state rollback: send_seq {send_seq} is behind NV checkpoint {sidecar_seq}"
        ))
    } else {
        Ok(())
    }
}

/// Append-then-increment checkpoint. See module docs for the crash window.
pub fn checkpoint_with(
    t: &dyn NvTransport,
    key: &[u8; 32],
    state_path: &str,
    send_seq: u64,
) -> Result<(), String> {
    match counter_value(t)? {
        None => {
            // Chain not started: define (idempotent), increment once
            // (initializes to the TPM lifetime max, then +1 per TCG), then
            // anchor the observed value. Crash between increment and append
            // leaves (counter live, no sidecar) — recovered explicitly via
            // P2P_TPM_NV_REPROVISION (cannot be told apart from deletion).
            t.define()
                .map_err(|e| format!("TPM NV define failed: {}", e.describe()))?;
            let v = t
                .increment()
                .map_err(|e| format!("TPM NV increment failed: {}", e.describe()))?;
            sidecar_append(key, state_path, v, send_seq)
        }
        Some(g) => {
            let g1 = g
                .checked_add(1)
                .ok_or_else(|| "TPM NV counter exhausted — re-provision required".to_string())?;
            // Sidecar first: a crash before the increment is detected next
            // run as gen == counter+1 and completed by the guard.
            sidecar_append(key, state_path, g1, send_seq)?;
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
/// the sidecar at the live counter value (or a freshly initialized one) and
/// the current `send_seq`.
fn reanchor(
    t: &dyn NvTransport,
    key: &[u8; 32],
    state_path: &str,
    send_seq: u64,
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
    sidecar_append(key, state_path, v, send_seq)
}

/// `Some(v)` once the counter chain is live, `None` when not started.
fn counter_value(t: &dyn NvTransport) -> Result<Option<u64>, String> {
    match t.read() {
        Ok(v) => Ok(Some(v)),
        Err(NvError::NotDefined) | Err(NvError::Uninitialized) => Ok(None),
        Err(NvError::Tools(m)) => Err(format!("TPM NV read failed: {m}")),
    }
}

fn sidecar_path(state_path: &str) -> String {
    format!("{state_path}.nvck")
}

fn nvck_subkey(master: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut okm = [0u8; 32];
    hk.expand(b"DESTROYER-ST2027-NVCK-AUTH-SUBKEY-v1", &mut okm)
        .expect("HKDF-SHA256 expand for NV checkpoint subkey cannot fail");
    okm
}

fn nvck_tag(master: &[u8; 32], gen: u64, send_seq: u64) -> [u8; 32] {
    let subkey = nvck_subkey(master);
    let mut mac = HmacSha256::new_from_slice(&subkey).expect("HMAC can take key of any size");
    mac.update(b"DESTROYER-ST2027-NVCK-v1");
    mac.update(&gen.to_le_bytes());
    mac.update(&send_seq.to_le_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
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
fn sidecar_append(key: &[u8; 32], state_path: &str, gen: u64, send_seq: u64) -> Result<(), String> {
    let tag = nvck_tag(key, gen, send_seq);
    let line = format!("{gen} {send_seq} {}\n", hex_encode(&tag));
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

/// Last authenticated sidecar line. `Ok(None)` = no sidecar; corruption or
/// a bad tag is `Err` (fail-closed; only the last line is load-bearing).
fn sidecar_last(key: &[u8; 32], state_path: &str) -> Result<Option<(u64, u64)>, String> {
    let path = sidecar_path(state_path);
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("NV checkpoint sidecar unreadable ({path}): {e}")),
    };
    let Some(line) = contents.lines().rev().find(|l| !l.trim().is_empty()) else {
        return Ok(None);
    };
    let mut it = line.split_whitespace();
    let (Some(g), Some(s), Some(tag), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(format!(
            "NV checkpoint sidecar corrupt (malformed last line) in {path}"
        ));
    };
    let gen: u64 = g
        .parse()
        .map_err(|_| format!("NV checkpoint sidecar corrupt (gen) in {path}"))?;
    let seq: u64 = s
        .parse()
        .map_err(|_| format!("NV checkpoint sidecar corrupt (send_seq) in {path}"))?;
    let Some(tag_bytes) = hex_decode32(tag) else {
        return Err(format!("NV checkpoint sidecar corrupt (tag) in {path}"));
    };
    let expect = nvck_tag(key, gen, seq);
    use subtle::ConstantTimeEq;
    if tag_bytes.ct_eq(&expect).unwrap_u8() != 1 {
        return Err(format!(
            "NV checkpoint sidecar authentication failed in {path} \
             (wrong session key or forged sidecar)"
        ));
    }
    Ok(Some((gen, seq)))
}

#[cfg(test)]
mod tests {
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
    fn tool_argv_construction() {
        let t = ToolsTransport::new(
            0x1500016,
            "o",
            ToolPaths {
                nvread: "tpm2_nvread".to_string(),
                nvincrement: "tpm2_nvincrement".to_string(),
                nvdefine: "tpm2_nvdefine".to_string(),
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
