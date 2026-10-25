//! secure-transmit — standalone post-quantum secure core & data-plane executor.
//!
//! ARCHITECTURE & ZERO-PYTHON PRODUCTION PATH:
//! - Native Post-Quantum Cryptographic Secure Core:
//!   * Noise_XXhfs P-384 + ML-KEM-1024 + ML-DSA-87 handshake (`destroyer_core::handshake`).
//!   * Pure-Rust FIPS 204 ML-DSA-87 signatures with domain separation (`destroyer_core::auth`).
//!   * Sparse Post-Quantum Ratchet (SPQR / Triple Ratchet per Dodis et al. EUROCRYPT 2025)
//!     with fresh-KEM braiding per step (`destroyer_core::ratchet`).
//!   * 3-of-5 threshold PKI quorum verification & CRL revocation (`destroyer_core::pki`).
//!   * Authenticated hybrid KEX (ML-KEM-1024 + X25519) (`destroyer_core::kem`, `destroyer_core::kex_auth`).
//!   * Sealed key-file custody (0600 / exclusive lock / memory zeroization) (`destroyer_core::keystore`).
//!   * NIST SP 800-88 Rev 1 media sanitization (`destroyer_core::purge`).
//! - Military-Grade Data-Plane:
//!   * AEAD AES-256-GCM framing with header whitening (`destroyer_core::aead`).
//!   * Strict 64-bit anti-replay sliding window (`destroyer_core::replay`).
//!   * Cauchy-Reed-Solomon Forward Error Correction (`destroyer_core::fec`).
//!   * Constant-rate (CBR) traffic pacing with continuous CSPRNG chaff (`destroyer_core::pacing`).
//!   * Silent-drop stealth UDP networking (`destroyer_core::net`).
//! - Reference & Interop:
//!   * The Python control plane (`noise_pq.py`, `double_ratchet.py`, `trust_anchor.py`)
//!     is kept intact as the audited reference implementation and backup path.
//!   * Secrets NEVER appear in command line arguments (`ps` / argv).
//!   * All cryptographic secrets zeroize on drop and are memory-protected.

use destroyer_core::acd::{ActiveCyberDefenseEngine, DefensivePlaybook, ThreatTrigger};
use destroyer_core::aead::{self, FrameKey, DIR_RECV, DIR_SEND};
use destroyer_core::auth::{Mldsa87SigningKey, Mldsa87VerifyingKey};
use destroyer_core::cookie::StatelessCookieGate;
use destroyer_core::fec::CauchyReedSolomon;
use destroyer_core::frame::{self, FTYPE_CHAFF, FTYPE_MSG};
use destroyer_core::handshake::Handshake;
use destroyer_core::kem::{self, EphemeralKeys, MLKEM_CT, MLKEM_PK};
use destroyer_core::keystore;
use destroyer_core::memory_guard::GuardedBuffer;
use destroyer_core::memlock::LockedKey32;
use destroyer_core::net::{Endpoint, MAX_DATAGRAM};
use destroyer_core::pacing::{self, PacedScheduler};
use destroyer_core::pki::{self, CertSig, Custodian};
use destroyer_core::policy::{DOMAIN_SIG_INITIATOR, DOMAIN_SIG_RESPONDER, MLDSA87_PK, MLDSA87_SIG};
use destroyer_core::purge;
use destroyer_core::ratchet::PcsRatchet;
use destroyer_core::replay::AntiReplayWindow;
use destroyer_core::tpm_nv;
use destroyer_core::zero_trust::{
    inspect_content_rtb, ClearanceLevel, SecurityRole, ZeroTrustEngine, PERM_CRITICAL_RELEASE,
    PERM_MESSAGE_SEND,
};
use fs2::FileExt;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

const VERSION: &str = "0.2.0";
/// Largest user payload accepted by `send` (largest fixed quantum, frame.rs).
const MAX_PAYLOAD: usize = 1205;
/// Stream cap mirrored from the Python plane (destroyer_node 16 MiB):
/// a single file transfer never exceeds this; larger inputs are refused.
const MAX_STREAM_BYTES: usize = 16 << 20;
/// Persistent state file layout: MAGIC(8) || key_id(16) || send_seq(8LE)
/// || recv_last(8LE) || recv_bitmap(256LE: 32 words) || hmac_tag(32) = 328 bytes.
/// Authenticated via HMAC-SHA256 with key derived from session key via HKDF (S-08)
/// to defeat sequence rollback / state tampering attacks. Full 32-word bitmap
/// prevents replay history loss across restarts (S-02).
const STATE_MAGIC: &[u8; 8] = b"STSTATE3";
const STATE_RAW_LEN: usize = 296;
const STATE_HMAC_LEN: usize = 32;
const STATE_LEN: usize = 328;

fn usage() -> ! {
    eprintln!(
        "secure-transmit {VERSION} — standalone post-quantum secure core & data plane\n\
         \n\
         keygen [--out PATH]              print fresh 32B frame key (hex)\n\
         auth-keygen --out-sk PATH --out-pk PATH       generate ML-DSA-87 (FIPS 204) keypair\n\
         auth-sign   --sk-file PATH [--domain TEXT] --in PATH --out PATH  sign file with ML-DSA-87\n\
         auth-verify --pk-file PATH [--domain TEXT] --in PATH --sig-file PATH verify ML-DSA-87 signature\n\
         kex-listen  --bind ADDR --out-key PATH --psk-file PATH [--timeout-ms MS]  negotiate ML-KEM-1024 hybrid key (listen)\n\
         kex-connect --to ADDR --out-key PATH --psk-file PATH [--timeout-ms MS]    negotiate ML-KEM-1024 hybrid key (connect)\n\
         send   --key-file PATH|--key-stdin --state PATH --to ADDR --msg TEXT\n\
         recv   --key-file PATH|--key-stdin --state PATH --bind ADDR [--count N] [--timeout-ms MS]\n\
         send-file --key-file PATH|--key-stdin --state PATH --to ADDR --file PATH\n\
         recv-file --key-file PATH|--key-stdin --state PATH --bind ADDR --out PATH --count K [--timeout-ms MS]\n\
         diode-send --key-file PATH|--key-stdin --state PATH --to ADDR --file PATH [--parity-ratio FLOAT]\n\
         diode-recv --key-file PATH|--key-stdin --state PATH --bind ADDR --out PATH [--timeout-ms MS]\n\
         stream-chaff --key-file PATH|--key-stdin --state PATH --to ADDR [--interval-ms MS] [--count N] [--quantum 256|512|1232]\n\
         channel --key-file PATH|--key-stdin --state PATH --bind ADDR --to ADDR [--role initiator|responder] [--interval-ms MS] [--quantum 256|512|1232] [--msg TEXT] [--count N] [--recv-count N] [--timeout-ms MS]\n\
         cookie-challenge [--ip IP] [--port PORT] [--payload TEXT] [--difficulty N]  generate anti-amplification micro-PoW challenge\n\
         cookie-solve --challenge HEX [--max-iters N]                                solve anti-amplification PoW challenge\n\
         cookie-verify --solution HEX [--ip IP] [--port PORT] [--payload TEXT]        verify solved PoW cookie challenge\n\
         threat-eval --peer ID [--trigger TYPE] [--count N] [--threshold N]           simulate and evaluate DoD cATO ACD playbook\n\
         zero-trust-eval --peer ID [--role ROLE] [--penalty N] [--reward N]           evaluate NIST SP 800-207 continuous trust score\n\
         cot-beacon [--callsign CALL] [--lat LAT] [--lon LON] [--type TYPE] [--sk-file PATH] [--out PATH]  emit MIL-STD-6090 Cursor-on-Target event (demo formatter)\n\
         tactical-msg [--precedence (Y|Z|O|P|R)] [--clearance LEVEL] [--caveats CAVEAT] --msg TEXT  format classified military telegram (RTB scan always ON; --scan-rtb accepted as no-op)\n\
         eam-auth --directive TEXT --officer1-pk PATH --officer1-sig PATH --officer2-pk PATH --officer2-sig PATH [--officers-manifest PATH]  verify NC3 dual-officer EAM (optional roster manifest)\n\
         zeroize --target PATH...|--state PATH|--key-file PATH  NIST SP 800-88 3-pass cryptographic media purge\n\
         selftest                        deterministic module self-checks\n\
         \n\
         send-file splits at the 1205B quantum with incrementing seq; recv-file\n\
         accepts only K consecutive seqs, reassembles, prints SHA-256, and\n\
         writes the file. Any gap/tamper/timeout: exit 4, nothing written.\n\
         \n\
         diode-send/recv: Simplex Optical Data Diode transfer with Cauchy-Reed-Solomon\n\
         Forward Error Correction (FEC). ZERO return channel / zero ACKs.\n\
         Reconstructs original file from ANY K chunks even with packet loss.\n\
         \n\
          channel: Full-duplex hardware-paced enclave link with continuous CSPRNG chaff\n\
          and directional nonce separation. Flat wire timing and fixed-size cells\n\
          defeat Signals Intelligence (SIGINT) flow correlation and timing analysis;\n\
          chaff uniformity (Shannon H) is a sanity check, not the security argument.\n\
         \n\
         Security: --seq, --key HEX and --psk HEX are REFUSED. Seq comes only from the\n\
         locked --state file (monotonic, persisted before encrypt). Keys/PSK NEVER\n\
         appear in argv (visible via ps): provision via --key-file (0600), --key-stdin,\n\
         --psk-file, or native quantum-resistant kex-listen/kex-connect with ML-KEM-1024 + X25519.\n\
         \n\
         Env: P2P_TPM_NV_INDEX=0x<hex> binds seq reservations to a TPM 2.0 NV monotonic\n\
         counter (fail-closed hardware rollback guard; P2P_TPM_NV_REPROVISION=1 is the\n\
         explicit operator re-anchor recovery)."
    );
    std::process::exit(2);
}

fn fail(msg: &str) -> ! {
    eprintln!("secure-transmit: FAIL: {msg}");
    std::process::exit(1);
}

fn get_flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn reject_forbidden_cli(args: &[String]) {
    if get_flag(args, "--key").is_some() {
        fail("refusing --key on command line (secret in ps argv); use --key-file or --key-stdin");
    }
    if get_flag(args, "--seq").is_some() {
        fail("refusing --seq (nonce must come from locked --state, never user input)");
    }
    if get_flag(args, "--psk").is_some() {
        fail("refusing --psk on command line (secret in ps argv); use --psk-file");
    }
}

/// Load a 32-byte PSK from `--psk-file` into a stack array for HKDF-salt
/// use. The file itself is read through the hardened `keystore` path
/// (0600 / no-symlink enforced — previously unchecked), then copied out
/// once; callers MUST `zeroize` the array when the KEX completes (done at
/// the end of `cmd_kex_listen` / `cmd_kex_connect`).
fn load_psk_file(path: &str) -> [u8; 32] {
    let guard = keystore::read_key_file(path)
        .unwrap_or_else(|_| fail("psk file unreadable or permission-hardening failed"));
    let mut out = [0u8; 32];
    out.copy_from_slice(guard.as_bytes());
    out
}

/// Load frame key bytes from --key-file or --key-stdin (exactly one).
/// Returns (locked key guard, key_id). File branch delegates to the
/// single-sourced `keystore::read_key_file`: symlink/reparse refused via
/// `symlink_metadata` (the old `metadata().is_symlink()` check was dead
/// code — followed metadata never reports symlink — and is now replaced
/// by a real refusal), 0600 enforced, 128-byte cap fail-closed.
/// Exit behavior is unchanged (non-zero + one-line stderr, nothing
/// signaled to the peer); permission failures now name the cause.
/// The guard page-locks (best-effort) a heap-stable copy, wipes + unlocks
/// on drop; callers copy out once via as_bytes() then drop at the same
/// points where the raw array was previously zeroized (identical lifetime).
/// The guard page-locks (best-effort) a heap-stable copy, wipes + unlocks
/// on drop; callers copy out once via as_bytes() then drop at the same
/// points where the raw array was previously zeroized (identical lifetime).
fn load_key_material(args: &[String]) -> (LockedKey32, [u8; 16]) {
    reject_forbidden_cli(args);
    let from_file = get_flag(args, "--key-file");
    let from_stdin = has_flag(args, "--key-stdin");
    if from_file.is_some() == from_stdin {
        fail("exactly one of --key-file PATH or --key-stdin is required");
    }
    let mut hex_z: Zeroizing<String> = if let Some(path) = from_file {
        // Single-sourced hardened read: symlink/reparse refused (via
        // `symlink_metadata`, NOT the dead `metadata().is_symlink()` check
        // this replaces), 0600 enforced, content parsed straight into the
        // page-locked guard — no intermediate hex `String` of the secret.
        let out = keystore::read_key_file(&path).unwrap_or_else(|e| match e {
            destroyer_core::policy::CoreError::FilePermissions => {
                fail("key file permission hardening failed (must be 0600, no symlinks)")
            }
            _ => fail("key file unreadable"),
        });
        let digest = Sha384::digest(out.as_bytes());
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&digest[..16]);
        return (out, key_id);
    } else {
        let mut s = String::with_capacity(128);
        std::io::stdin()
            .read_to_string(&mut s)
            .unwrap_or_else(|_| fail("key stdin unreadable"));
        Zeroizing::new(s)
    };
    // Direct in-place parse into page-locked buffer: zero stack copies of raw secret
    let out = LockedKey32::from_hex(&hex_z).unwrap_or_else(|e| fail(e));
    hex_z.zeroize();
    let digest = Sha384::digest(out.as_bytes());
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&digest[..16]);
    (out, key_id)
}

fn state_path(args: &[String]) -> String {
    get_flag(args, "--state")
        .unwrap_or_else(|| fail("missing --state PATH (monotonic nonce state required)"))
}

/// Sidecar path for the append-only send-seq high-water journal.
fn seq_journal_path(state_path: &str) -> String {
    format!("{state_path}.seqlog")
}

/// Read the max reserved end-seq from the journal (empty/missing → 0).
fn seq_journal_high_water(jpath: &str) -> u64 {
    let Ok(contents) = std::fs::read_to_string(jpath) else {
        return 0;
    };
    let mut max_hw: u64 = 0;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = line.parse::<u64>() {
            if v > max_hw {
                max_hw = v;
            }
        }
    }
    max_hw
}

/// Append one reservation high-water mark. O_APPEND is atomic for small
/// writes; sync_all after. Journal is never rewritten (only appended).
fn seq_journal_append(jpath: &str, end: u64) {
    use std::io::Write;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(jpath)
        .unwrap_or_else(|_| fail("seq journal unopenable"));
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
    writeln!(f, "{end}").unwrap_or_else(|_| fail("seq journal write failed"));
    f.sync_all().unwrap_or_else(|_| fail("seq journal sync failed"));
}

/// In-memory session state mirror (persisted as 328-byte authenticated record).
struct SessionState {
    key_id: [u8; 16],
    send_seq: u64,
    recv_last: u64,
    recv_bitmap: [u64; destroyer_core::replay::WINDOW_WORDS],
}

/// Derive dedicated HMAC subkey from master key via HKDF-SHA256 (S-08).
/// Eliminates key reuse across AES-GCM and HMAC-SHA256 primitives.
fn derive_state_hmac_key(master_key: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut subkey = [0u8; 32];
    hk.expand(b"DESTROYER-ST2027-STATE-FILE-AUTH-SUBKEY-v1", &mut subkey)
        .expect("HKDF-SHA256 expand for state HMAC subkey cannot fail");
    subkey
}

fn compute_state_hmac(key: &[u8; 32], raw: &[u8]) -> [u8; STATE_HMAC_LEN] {
    let hmac_key = derive_state_hmac_key(key);
    let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("HMAC can take key of any size");
    mac.update(b"DESTROYER-ST2027-STATE-FILE-AUTH-v1");
    mac.update(raw);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; STATE_HMAC_LEN];
    out.copy_from_slice(&result);
    out
}

fn verify_state_hmac(key: &[u8; 32], raw: &[u8], expected_tag: &[u8; STATE_HMAC_LEN]) -> bool {
    let hmac_key = derive_state_hmac_key(key);
    let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("HMAC init");
    mac.update(b"DESTROYER-ST2027-STATE-FILE-AUTH-v1");
    mac.update(raw);
    mac.verify_slice(expected_tag).is_ok()
}

fn encode_state(st: &SessionState, key: &[u8; 32]) -> [u8; STATE_LEN] {
    let mut b = [0u8; STATE_LEN];
    b[..8].copy_from_slice(STATE_MAGIC);
    b[8..24].copy_from_slice(&st.key_id);
    b[24..32].copy_from_slice(&st.send_seq.to_le_bytes());
    b[32..40].copy_from_slice(&st.recv_last.to_le_bytes());
    for i in 0..destroyer_core::replay::WINDOW_WORDS {
        let start = 40 + i * 8;
        b[start..start + 8].copy_from_slice(&st.recv_bitmap[i].to_le_bytes());
    }
    let mac = compute_state_hmac(key, &b[..STATE_RAW_LEN]);
    b[STATE_RAW_LEN..STATE_LEN].copy_from_slice(&mac);
    b
}

fn decode_state(buf: &[u8; STATE_LEN], key: &[u8; 32], expect_key_id: &[u8; 16]) -> SessionState {
    if &buf[..8] != STATE_MAGIC {
        fail("state file corrupt (bad magic) — rekey with fresh key+state");
    }
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&buf[8..24]);
    if &key_id != expect_key_id {
        fail(
            "state file bound to a different key (key_id mismatch) — use matching --state or rekey",
        );
    }
    let mut expected_mac = [0u8; STATE_HMAC_LEN];
    expected_mac.copy_from_slice(&buf[STATE_RAW_LEN..STATE_LEN]);
    if !verify_state_hmac(key, &buf[..STATE_RAW_LEN], &expected_mac) {
        fail("state file authentication failed (HMAC mismatch / state corrupt or forged) — refusing to reuse nonces under this key");
    }
    let mut u = [0u8; 8];
    u.copy_from_slice(&buf[24..32]);
    let send_seq = u64::from_le_bytes(u);
    u.copy_from_slice(&buf[32..40]);
    let recv_last = u64::from_le_bytes(u);
    let mut recv_bitmap = [0u64; destroyer_core::replay::WINDOW_WORDS];
    for (i, word) in recv_bitmap.iter_mut().enumerate() {
        let start = 40 + i * 8;
        u.copy_from_slice(&buf[start..start + 8]);
        *word = u64::from_le_bytes(u);
    }
    SessionState {
        key_id,
        send_seq,
        recv_last,
        recv_bitmap,
    }
}

fn open_locked_state(path: &str) -> File {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap_or_else(|_| fail("state file unopenable"));
    // F-04: enforce 0600 on newly created state files (unix). The file
    // holds the authenticated monotonic nonce counter; world-readable
    // state is an integrity/oracle hazard even though the HMAC protects
    // the contents.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = f.metadata() {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                // Only chmod if we created it fresh (mode still has group/other).
                // Existing files with correct 0600 are left alone; wider files
                // from prior versions are tightened once under the exclusive lock.
                let _ = f.set_permissions(std::fs::Permissions::from_mode(mode & !0o077));
            }
        }
    }
    f.lock_exclusive()
        .unwrap_or_else(|_| fail("state file lock failed"));
    f
}

fn read_state_locked(f: &mut File, key: &[u8; 32], key_id: &[u8; 16]) -> SessionState {
    let mut buf = Vec::new();
    f.seek(SeekFrom::Start(0))
        .unwrap_or_else(|_| fail("state seek failed"));
    f.read_to_end(&mut buf)
        .unwrap_or_else(|_| fail("state read failed"));
    if buf.is_empty() {
        // Fresh state: random send start (2^-64 collision on re-create),
        // empty recv window. Persisted below by caller.
        let mut r = [0u8; 8];
        if getrandom::fill(&mut r).is_err() {
            fail("OS RNG unavailable");
        }
        let mut send_seq = u64::from_le_bytes(r);
        if send_seq == u64::MAX {
            send_seq = 0;
        }
        let st = SessionState {
            key_id: *key_id,
            send_seq,
            recv_last: 0,
            recv_bitmap: [0u64; destroyer_core::replay::WINDOW_WORDS],
        };
        write_state_locked(f, &st, key);
        return st;
    }
    if buf.len() != STATE_LEN {
        fail("state file corrupt (bad length / missing authentication) — rekey with fresh key+state");
    }
    let mut arr = [0u8; STATE_LEN];
    arr.copy_from_slice(&buf);
    decode_state(&arr, key, key_id)
}

fn write_state_locked(f: &mut File, st: &SessionState, key: &[u8; 32]) {
    let enc = encode_state(st, key);
    f.seek(SeekFrom::Start(0))
        .unwrap_or_else(|_| fail("state seek failed"));
    f.write_all(&enc)
        .unwrap_or_else(|_| fail("state write failed"));
    f.set_len(STATE_LEN as u64)
        .unwrap_or_else(|_| fail("state truncate failed"));
    f.sync_all().unwrap_or_else(|_| fail("state sync failed"));
}

/// Reserve one send seq: persist N+1 BEFORE encrypting (crash may skip,
/// never reuse). Returns the seq to seal with.
///
/// F-01 (nonce rollback): every reservation is also appended to a sidecar
/// high-water journal (`<state>.seqlog`). If the state file is restored to
/// an older snapshot while the journal still records a higher end-seq, the
/// reservation is refused — a rollback must not successfully encrypt under
/// a reused counter. Restoring BOTH files to an old consistent pair is
/// additionally refused when the hardware guard is enabled
/// (`P2P_TPM_NV_INDEX` — see `tpm_nv`): a TPM 2.0 NV counter generation
/// cannot be rolled back in software or by the owner hierarchy.
fn reserve_send_seq(path: &str, key: &[u8; 32], key_id: &[u8; 16], count: u64) -> u64 {
    if count == 0 {
        fail("reservation count must be >= 1");
    }
    let state_fresh = tpm_nv::state_is_fresh(path);
    let jpath = seq_journal_path(path);
    let mut f = open_locked_state(path);
    let mut st = read_state_locked(&mut f, key, key_id);
    tpm_nv::guard(path, key, st.send_seq, state_fresh).unwrap_or_else(|e| fail(&e));
    let journal_hw = seq_journal_high_water(&jpath);
    if st.send_seq < journal_hw {
        fail(
            "state rollback detected (send_seq behind append-only seq journal) — refusing to reuse nonces under this key; rekey with fresh key+state",
        );
    }
    let start = st.send_seq;
    let end = start
        .checked_add(count)
        .unwrap_or_else(|| fail("sequence exhausted — rekey required"));
    if start == u64::MAX || (end == 0 && count > 0) {
        fail("sequence exhausted — rekey required");
    }
    // Reserve [start, start+count): fail if range would wrap past MAX.
    if start.checked_add(count - 1).is_none() {
        fail("sequence exhausted — rekey required");
    }
    st.send_seq = end;
    write_state_locked(&mut f, &st, key);
    // Journal AFTER successful state persist: crash here leaves journal
    // behind state (safe — next run catches up); never journaled-ahead.
    seq_journal_append(&jpath, end);
    // Hardware generation checkpoint last (no-op without P2P_TPM_NV_INDEX);
    // a crash before it leaves the NV chain one checkpoint behind, which the
    // next guard tolerates (state >= sidecar seq) and the next checkpoint
    // catches up.
    tpm_nv::checkpoint(path, key, end).unwrap_or_else(|e| fail(&e));
    // Unlock via drop.
    start
}

fn load_recv_window(path: &str, key: &[u8; 32], key_id: &[u8; 16]) -> (File, AntiReplayWindow) {
    let state_fresh = tpm_nv::state_is_fresh(path);
    let mut f = open_locked_state(path);
    let st = read_state_locked(&mut f, key, key_id);
    tpm_nv::guard(path, key, st.send_seq, state_fresh).unwrap_or_else(|e| fail(&e));
    let w = AntiReplayWindow::from_parts(st.recv_last, st.recv_bitmap);
    (f, w)
}

fn persist_recv_window(
    f: &mut File,
    key: &[u8; 32],
    key_id: &[u8; 16],
    send_seq_preserve: u64,
    w: &AntiReplayWindow,
) {
    // Re-read send_seq under the same lock to avoid clobbering a
    // concurrent reservation (recv holds the lock for the session, so
    // this is normally unchanged; defense in depth).
    f.seek(SeekFrom::Start(0))
        .unwrap_or_else(|_| fail("state seek failed"));
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .unwrap_or_else(|_| fail("state read failed"));
    let cur_send = if buf.len() == STATE_LEN {
        let mut arr = [0u8; STATE_LEN];
        arr.copy_from_slice(&buf);
        let cur = decode_state(&arr, key, key_id);
        cur.send_seq
    } else {
        send_seq_preserve
    };
    let (last, bitmap) = w.parts();
    let st = SessionState {
        key_id: *key_id,
        send_seq: cur_send,
        recv_last: last,
        recv_bitmap: bitmap,
    };
    write_state_locked(f, &st, key);
}

fn cmd_keygen(args: &[String]) {
    if get_flag(args, "--key").is_some() || get_flag(args, "--seq").is_some() {
        fail("keygen takes no --key/--seq");
    }
    let mut k = [0u8; 32];
    if getrandom::fill(&mut k).is_err() {
        fail("OS RNG unavailable");
    }
    let hex = hex_of(&k);
    k.zeroize();
    if let Some(out) = get_flag(args, "--out") {
        write_key_file(&out, &hex);
    } else {
        print!("{hex}");
    }
}

fn hex_of(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s.push('\n');
    s
}

fn decode_hex(s: &str) -> Result<Vec<u8>, &'static str> {
    let clean = s.trim();
    if !clean.len().is_multiple_of(2) {
        return Err("hex length must be even");
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for chunk in clean.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(chunk).map_err(|_| "bad utf8 in hex")?;
        let byte = u8::from_str_radix(text, 16).map_err(|_| "bad hex digit")?;
        out.push(byte);
    }
    Ok(out)
}

fn cmd_auth_keygen(args: &[String]) {
    reject_forbidden_cli(args);
    let out_sk = get_flag(args, "--out-sk").unwrap_or_else(|| fail("missing --out-sk PATH"));
    let out_pk = get_flag(args, "--out-pk").unwrap_or_else(|| fail("missing --out-pk PATH"));

    let mut seed = [0u8; 32];
    if getrandom::fill(&mut seed).is_err() {
        fail("OS RNG unavailable");
    }
    let (_sk, vk) = Mldsa87SigningKey::from_seed(&seed);
    let seed_hex = hex_of(&seed);
    seed.zeroize();
    write_key_file(&out_sk, &seed_hex);

    let vk_bytes = vk.to_bytes();
    let vk_hex = hex_of(&vk_bytes);
    std::fs::write(&out_pk, vk_hex.as_bytes()).unwrap_or_else(|_| fail("pk out unwritable"));

    println!("auth-keygen SUCCESS: ML-DSA-87 keypair generated -> sk:{out_sk} pk:{out_pk}");
}

fn cmd_auth_sign(args: &[String]) {
    reject_forbidden_cli(args);
    let sk_file = get_flag(args, "--sk-file").unwrap_or_else(|| fail("missing --sk-file PATH"));
    let in_file = get_flag(args, "--in").unwrap_or_else(|| fail("missing --in PATH"));
    let out_file = get_flag(args, "--out").unwrap_or_else(|| fail("missing --out PATH"));
    let domain_str =
        get_flag(args, "--domain").unwrap_or_else(|| "DESTROYER-ST2027-SIG-GENERIC".to_string());

    let (locked_seed, _) = load_key_material(&["--key-file".to_string(), sk_file]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(locked_seed.as_bytes());
    let (sk, _) = Mldsa87SigningKey::from_seed(&seed);
    seed.zeroize();

    let payload = std::fs::read(&in_file).unwrap_or_else(|_| fail("input file unreadable"));
    let sig = sk.sign(domain_str.as_bytes(), &payload);
    let sig_hex = hex_of(&sig);
    std::fs::write(&out_file, sig_hex.as_bytes())
        .unwrap_or_else(|_| fail("out signature unwritable"));

    println!(
        "auth-sign SUCCESS: ML-DSA-87 signature written to {out_file} (bytes: {})",
        sig.len()
    );
}

fn cmd_auth_verify(args: &[String]) {
    reject_forbidden_cli(args);
    let pk_file = get_flag(args, "--pk-file").unwrap_or_else(|| fail("missing --pk-file PATH"));
    let in_file = get_flag(args, "--in").unwrap_or_else(|| fail("missing --in PATH"));
    let sig_file = get_flag(args, "--sig-file").unwrap_or_else(|| fail("missing --sig-file PATH"));
    let domain_str =
        get_flag(args, "--domain").unwrap_or_else(|| "DESTROYER-ST2027-SIG-GENERIC".to_string());

    let pk_hex_str =
        std::fs::read_to_string(&pk_file).unwrap_or_else(|_| fail("pk file unreadable"));
    let pk_bytes = decode_hex(&pk_hex_str).unwrap_or_else(|_| fail("pk file not valid hex"));
    let vk = Mldsa87VerifyingKey::from_bytes(&pk_bytes)
        .unwrap_or_else(|_| fail("invalid ML-DSA-87 public key bytes"));

    let payload = std::fs::read(&in_file).unwrap_or_else(|_| fail("input file unreadable"));
    let sig_hex_str =
        std::fs::read_to_string(&sig_file).unwrap_or_else(|_| fail("sig file unreadable"));
    let sig_bytes = decode_hex(&sig_hex_str).unwrap_or_else(|_| fail("sig file not valid hex"));

    match vk.verify(domain_str.as_bytes(), &payload, &sig_bytes) {
        Ok(()) => {
            println!("auth-verify SUCCESS: ML-DSA-87 signature VALID");
        }
        Err(_) => {
            fail("ML-DSA-87 signature INVALID");
        }
    }
}

/// Write a session-key hex file. Delegates to the single-sourced
/// `keystore::write_key_file_truncate` (0600 / share-NONE / owner-only
/// `icacls`, ACL failure deletes + errors). Operator-facing fail strings
/// preserved: write/sync problems report as before, ACL failure keeps its
/// explicit message.
fn write_key_file(out: &str, hex: &str) {
    keystore::write_key_file_truncate(out, hex).unwrap_or_else(|e| {
        match e {
            destroyer_core::policy::CoreError::Malformed => fail("key out unwritable"),
            #[cfg(not(unix))]
            destroyer_core::policy::CoreError::FilePermissions => {
                // Distinguish ACL-hardening failure (file already removed)
                // from plain write failure for operator diagnosis.
                fail("key out ACL hardening failed (icacls owner-only); nothing written")
            }
            // All other failures are permission-hardening failures by
            // construction (the only CoreError this path can return).
            _ => fail("key out unwritable"),
        }
    });
}

fn cmd_send(args: &[String]) {
    let (kb, key_id) = load_key_material(args);
    let state = state_path(args);
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let msg = get_flag(args, "--msg").unwrap_or_else(|| usage());
    if msg.len() > MAX_PAYLOAD {
        drop(kb);
        fail("payload exceeds largest quantum (1205B)");
    }
    // Reserve BEFORE encrypt: crash skips, never reuses (NIST SP 800-38D).
    let key_bytes: [u8; 32] = *kb.as_bytes();
    let seq = reserve_send_seq(&state, &key_bytes, &key_id, 1);
    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);
    // TRAFFIC-SHAPING (audit Finding 3): pad every send frame to its
    // quantum (256/512/1232) so wire length reveals only the quantum, not
    // the true payload length. Header len field carries the TRUE length;
    // padding is zero bytes stripped on open_indexed after tag verify.
    // Residual: seq/ftype stay clear as AAD (needed to parse); message
    // COUNT is hidden only under constant-rate channel/chaff cover —
    // use `channel` mode for TOP SECRET.
    let (quantum, pad) = frame::pad_to_quantum(msg.len())
        .unwrap_or_else(|| fail("payload exceeds largest quantum (1205B)"));
    let mut padded = Vec::with_capacity(msg.len() + pad);
    padded.extend_from_slice(msg.as_bytes());
    if pad > 0 {
        let mut pad_bytes = vec![0u8; pad];
        if getrandom::fill(&mut pad_bytes).is_err() {
            fail("CSPRNG unavailable for padding");
        }
        padded.extend_from_slice(&pad_bytes);
    }
    let msg_len = u16::try_from(msg.len()).unwrap_or_else(|_| fail("message length exceeds u16"));
    let frame = aead::seal_with_len(&key, seq, DIR_SEND, FTYPE_MSG, msg_len, &padded)
        .unwrap_or_else(|_| fail("seal failed"));
    if frame.len() != quantum {
        fail("sealed frame length mismatch with expected quantum");
    }
    if frame.len() > MAX_DATAGRAM {
        fail("sealed frame exceeds IPv6 MTU budget (1280B)");
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));
    rt.block_on(async {
        // Bind the wildcard of the peer's family: an IPv6 socket cannot
        // send_to an AF_INET addr (and vice versa on strict stacks).
        let any = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let ep = Endpoint::bind(any)
            .await
            .unwrap_or_else(|_| fail("bind failed"));
        ep.send_raw(&frame, to)
            .await
            .unwrap_or_else(|_| fail("send failed"));
    });
    eprintln!("sent seq={seq} wire={}B", frame.len());
}

fn cmd_recv(args: &[String]) {
    let (kb, key_id) = load_key_material(args);
    let key_bytes: [u8; 32] = *kb.as_bytes();
    let state = state_path(args);
    let bind = get_flag(args, "--bind").unwrap_or_else(|| usage());
    let want: u64 = get_flag(args, "--count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --count")))
        .unwrap_or(1);
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(5000);
    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);
    // Hold the state lock for the whole recv session so concurrent
    // receivers cannot accept the same seq twice.
    let (mut sf, mut window) = load_recv_window(&state, &key_bytes, &key_id);
    // Snapshot send_seq to preserve across write-throughs.
    let send_preserve: u64 = {
        sf.seek(SeekFrom::Start(0))
            .unwrap_or_else(|_| fail("state seek failed"));
        let mut buf = Vec::new();
        sf.read_to_end(&mut buf)
            .unwrap_or_else(|_| fail("state read failed"));
        if buf.len() == STATE_LEN {
            let mut arr = [0u8; STATE_LEN];
            arr.copy_from_slice(&buf);
            decode_state(&arr, &key_bytes, &key_id).send_seq
        } else {
            0
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));
    let opened = rt.block_on(async {
        let mut ep = Endpoint::bind(&bind)
            .await
            .unwrap_or_else(|_| fail("bind failed"));
        let mut opened = 0u64;
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while opened < want {
            let wait = deadline.saturating_duration_since(std::time::Instant::now());
            if wait.is_zero() {
                break;
            }
            match ep.recv_raw(wait).await {
                None => break,
                Some(Err(_)) => {} // rate/oversize/io: counted, silent
                Some(Ok((bytes, _from))) => {
                    // Split discipline: read-only check, then AEAD auth,
                    // then mark + write-through while holding the lock.
                    let seq = match aead::peek_seq(&key, &bytes) {
                        Some(s) => s,
                        None => {
                            ep.note_auth_drop();
                            continue;
                        }
                    };
                    if !window.check(seq) {
                        ep.note_auth_drop();
                        continue;
                    }
                    let Ok((seq2, ftype, pt)) = aead::open_indexed(&key, DIR_SEND, &bytes) else {
                        ep.note_auth_drop();
                        continue;
                    };
                    if seq2 != seq {
                        ep.note_auth_drop();
                        continue;
                    }
                    window.mark(seq2);
                    persist_recv_window(&mut sf, &key_bytes, &key_id, send_preserve, &window);
                    if ftype == FTYPE_MSG {
                        println!("seq={seq2} {}", String::from_utf8_lossy(&pt));
                        opened += 1;
                    }
                    // CHAFF absorbed silently (stealth: no wire signal, no stdout).
                }
            }
        }
        eprintln!("drops={} admitted={}", ep.drops, ep.admitted);
        opened
    });
    if opened < want {
        eprintln!("timeout: opened {opened}/{want} authenticated messages");
        std::process::exit(3);
    }
}

fn cmd_selftest() {
    // Deterministic checks over the exact modules this binary executes.
    let key = FrameKey::from_bytes([0x5Au8; 32]);
    let f = aead::seal(&key, 7, DIR_SEND, FTYPE_MSG, b"selftest-vector").expect("seal");
    let (t, pt) = aead::open(&key, DIR_SEND, &f).expect("open");
    assert_eq!(t, FTYPE_MSG);
    assert_eq!(&pt[..], b"selftest-vector");
    let mut bad = f.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01;
    assert!(aead::open(&key, DIR_SEND, &bad).is_err(), "tamper accepted");
    let mut w = AntiReplayWindow::new();
    assert!(w.check(7));
    w.mark(7);
    assert!(!w.check(7), "replay accepted");
    assert!(f.len() <= MAX_DATAGRAM, "quantum exceeds MTU");
    // State codec roundtrip (no I/O): magic + key binding enforced.
    let test_key = [0x5Au8; 32];
    let mut test_bitmap = [0u64; destroyer_core::replay::WINDOW_WORDS];
    test_bitmap[0] = 0b11;
    let st = SessionState {
        key_id: [0xABu8; 16],
        send_seq: 41,
        recv_last: 7,
        recv_bitmap: test_bitmap,
    };
    let enc = encode_state(&st, &test_key);
    assert_eq!(enc.len(), STATE_LEN);
    let dec = decode_state(&enc, &test_key, &[0xABu8; 16]);
    assert_eq!(dec.send_seq, 41);
    assert_eq!(dec.recv_bitmap[0], 0b11);
    // Verify HMAC-SHA256 tamper / rollback detection (Finding 04):
    let mut tampered_enc = enc;
    tampered_enc[24] ^= 0x01; // flip sequence counter bit
    assert!(
        !verify_state_hmac(
            &test_key,
            &tampered_enc[..STATE_RAW_LEN],
            tampered_enc[STATE_RAW_LEN..].try_into().unwrap()
        ),
        "tampered state HMAC must fail verification"
    );
    eprintln!("selftest: aead-roundtrip ok, tamper-reject ok, replay ok, mtu ok, state-hmac ok");
    // Page-lock probe (best-effort, reported never failed: containers without
    // lock privilege run wipe-only hygiene by design).
    let probe = [0u8; 32];
    let probe_locked = destroyer_core::memlock::lock_slice(&probe);
    destroyer_core::memlock::unlock_slice(&probe);
    eprintln!(
        "selftest: memlock-probe {}",
        if probe_locked {
            "locked"
        } else {
            "unlocked-best-effort"
        }
    );

    // Cauchy-Reed-Solomon FEC self-check
    let crs = CauchyReedSolomon::new(3, 2).expect("crs new");
    let d0 = vec![1u8, 2, 3, 4];
    let d1 = vec![5u8, 6, 7, 8];
    let d2 = vec![9u8, 10, 11, 12];
    let parities = crs.encode(&[&d0, &d1, &d2]).expect("crs encode");
    let recovered = crs
        .decode(&[(0, &d0), (3, &parities[0]), (4, &parities[1])])
        .expect("crs decode");
    assert_eq!(&recovered[0], &d0);
    assert_eq!(&recovered[1], &d1);
    assert_eq!(&recovered[2], &d2);

    // Pacing chaff sanity check (F-16): a chaff frame that decrypts to the
    // right shape must also look uniform; low Shannon entropy here means the
    // chaff builder is broken (detectable pattern), NOT a cryptographic
    // security property. Security rests on AES-256-GCM, not on this metric.
    let chaff = pacing::build_chaff_frame(&key, 99, 1232).expect("chaff build");
    assert_eq!(chaff.len(), 1232);
    let entropy = pacing::calculate_shannon_entropy(&chaff);
    assert!(entropy > 7.70, "chaff sanity: frame entropy below uniform-look floor ({entropy:.4} <= 7.70)");
    let (c_seq, c_type, _) = aead::open_indexed(&key, DIR_SEND, &chaff).expect("chaff open");
    assert_eq!(c_seq, 99);
    assert_eq!(c_type, frame::FTYPE_CHAFF);

    // Hybrid KEM (ML-KEM-1024 + X25519) self-check
    let resp = EphemeralKeys::generate().expect("kem keygen");
    let (ml_ct, ss_init, eph_pub) =
        EphemeralKeys::encapsulate(&resp.x_public, &resp.ml_ek).expect("encaps");
    let ss_resp = resp.decapsulate(&eph_pub, &ml_ct).expect("decaps");
    assert_eq!(&ss_init[..], &ss_resp[..]);
    let k_init = kem::derive_session_key(&ss_init, b"selftest-kex");
    let k_resp = kem::derive_session_key(&ss_resp, b"selftest-kex");
    assert_eq!(k_init, k_resp);
    let t_hash = [0x5Au8; 48];
    let kt_init = kem::derive_session_key_transcript(&ss_init, None, &t_hash);
    let kt_resp = kem::derive_session_key_transcript(&ss_resp, None, &t_hash);
    assert_eq!(kt_init, kt_resp);
    let tag_init = kem::compute_confirmation_tag(&kt_init, b"TEST", &t_hash);
    let tag_resp = kem::compute_confirmation_tag(&kt_resp, b"TEST", &t_hash);
    assert!(kem::constant_time_eq_32(&tag_init, &tag_resp));

    // NIST SP 800-88 Purge self-check
    let tmp_purge = std::env::temp_dir().join(format!("selftest_purge_{}.dat", std::process::id()));
    std::fs::write(&tmp_purge, b"selftest-purge-material").expect("write purge temp");
    purge::purge_file(&tmp_purge).expect("purge selftest");
    assert!(!tmp_purge.exists(), "purge selftest failed to unlink");

    // ML-DSA-87 (FIPS 204) native authentication self-check
    let (mldsa_sk, mldsa_vk) = Mldsa87SigningKey::generate().expect("mldsa keygen");
    let test_msg = b"selftest-mldsa-87-message";
    let sig = mldsa_sk.sign(DOMAIN_SIG_INITIATOR, test_msg);
    assert_eq!(sig.len(), MLDSA87_SIG);
    mldsa_vk
        .verify(DOMAIN_SIG_INITIATOR, test_msg, &sig)
        .expect("mldsa verify");
    assert!(
        mldsa_vk
            .verify(DOMAIN_SIG_RESPONDER, test_msg, &sig)
            .is_err(),
        "cross-domain signature must fail"
    );

    // Noise_XXhfs handshake self-check
    let (init_sk, init_vk) = Mldsa87SigningKey::generate().expect("init mldsa");
    let (resp_sk, resp_vk) = Mldsa87SigningKey::generate().expect("resp mldsa");
    let mut init_hs = Handshake::initiator(init_sk, init_vk.to_bytes(), None).expect("init hs");
    let mut resp_hs = Handshake::responder(resp_sk, resp_vk.to_bytes(), None).expect("resp hs");

    let m1 = init_hs.initiator_hello().expect("m1");
    let m2 = resp_hs.responder_reply(&m1).expect("m2");
    init_hs
        .initiator_finish(&m2, &resp_vk.to_bytes())
        .expect("m2 finish");
    let m3 = init_hs.initiator_complete().expect("m3");
    resp_hs
        .responder_complete(&m3, &init_vk.to_bytes())
        .expect("resp complete");

    let (i_send, i_recv, i_th) = init_hs.split().expect("init split");
    let (r_send, r_recv, r_th) = resp_hs.split().expect("resp split");
    assert_eq!(i_send, r_recv);
    assert_eq!(i_recv, r_send);
    assert_eq!(i_th, r_th);

    // Sparse Post-Quantum Ratchet (SPQR) self-check
    let ratchet_root = [0x55u8; 32];
    let mut r_alice = PcsRatchet::new(&ratchet_root).expect("alice ratchet");
    let mut r_bob = PcsRatchet::new(&ratchet_root).expect("bob ratchet");
    let (bob_x, bob_ek) = r_bob.advertise();
    let (r_step, a_msg_key) = r_alice.send_step(&bob_x, &bob_ek).expect("alice step");
    let b_msg_key = r_bob
        .receive_step(&r_step.eph_x_pub, &r_step.ml_ct)
        .expect("bob step");
    assert_eq!(a_msg_key, b_msg_key);

    // 3-of-5 threshold PKI self-check
    let mut cust_seeds = [[0u8; 32]; 5];
    for (i, s) in cust_seeds.iter_mut().enumerate() {
        s[0] = (i + 1) as u8;
    }
    let cust_keys: Vec<(Mldsa87SigningKey, Mldsa87VerifyingKey)> = cust_seeds
        .iter()
        .map(Mldsa87SigningKey::from_seed)
        .collect();
    let custodians: Vec<Custodian> = cust_keys
        .iter()
        .enumerate()
        .map(|(i, (_, vk))| {
            Custodian::new(&format!("custodian-{i}"), vk.to_bytes()).expect("cust new")
        })
        .collect();

    let serial = [0x11u8; 16];
    let subject_pk = vec![0x22u8; MLDSA87_PK];
    let now = 1700000000.0;
    let not_before = 1700000000;
    let not_after = 1700003600;
    let tbs =
        pki::tbs_bytes(&serial, "node-pki-test", &subject_pk, not_before, not_after).expect("tbs");

    let sig0 = cust_keys[0].0.sign(&[], &tbs);
    let sig1 = cust_keys[1].0.sign(&[], &tbs);
    let sig2 = cust_keys[2].0.sign(&[], &tbs);

    let cert_sigs = [
        CertSig {
            custodian: "custodian-0",
            sig: &sig0,
        },
        CertSig {
            custodian: "custodian-1",
            sig: &sig1,
        },
        CertSig {
            custodian: "custodian-2",
            sig: &sig2,
        },
    ];
    pki::verify_certificate(
        &serial,
        "node-pki-test",
        &subject_pk,
        not_before,
        not_after,
        &cert_sigs,
        &custodians,
        now,
    )
    .expect("verify cert");

    // Stateless Anti-Amplification Cookie Gate & micro-PoW self-check
    let mut cookie_gate = StatelessCookieGate::new(120, 1024);
    let cookie = cookie_gate.create_cookie("127.0.0.1", 51820, b"selftest-m1");
    assert!(cookie_gate.verify_cookie(&cookie, "127.0.0.1", 51820, b"selftest-m1"));
    assert!(!cookie_gate.verify_cookie(&cookie, "127.0.0.2", 51820, b"selftest-m1"));
    let chal = cookie_gate.create_challenge("127.0.0.1", 51820, b"selftest-m1", 2);
    let sol = StatelessCookieGate::solve_challenge(&chal, 100_000).expect("solve challenge");
    assert!(cookie_gate.verify_response(&sol, "127.0.0.1", 51820, b"selftest-m1", 2));
    assert!(!cookie_gate.verify_response(&sol, "127.0.0.1", 51820, b"selftest-m1", 2), "replay solution rejected");

    // Active Cyber Defense (ACD) self-check
    let acd = ActiveCyberDefenseEngine::new(2, 5.0, 3, 10.0, 30.0, None);
    assert!(!acd.is_quarantined("bad-peer"));
    acd.record_event(ThreatTrigger::ReplayBurst, "bad-peer");
    let pb = acd.record_event(ThreatTrigger::ReplayBurst, "bad-peer");
    assert_eq!(pb, Some(DefensivePlaybook::QuarantinePeer));
    assert!(acd.is_quarantined("bad-peer"));

    // Zero-Trust continuous risk engine self-check
    let zt = ZeroTrustEngine::new(50);
    zt.register_peer("operator-node", SecurityRole::Operator);
    assert!(zt.authorize("operator-node", PERM_MESSAGE_SEND).is_ok());
    assert!(zt.authorize("operator-node", PERM_CRITICAL_RELEASE).is_err());
    assert!(zt.is_trusted("operator-node"));
    let penalty_res = zt.record_penalty("operator-node", 30);
    assert!(penalty_res.is_err(), "trust drop below 50 must revoke");
    assert!(!zt.is_trusted("operator-node"));

    // GuardedBuffer memory protection & sanitization self-check
    let mut gbuf = GuardedBuffer::from_slice(b"secret-selftest-buffer").expect("guarded buf alloc");
    assert!(gbuf.check_canaries());
    gbuf.secure_wipe();
    assert!(gbuf.check_canaries());
    assert_eq!(gbuf.as_slice()[0], 0x00);

    eprintln!("selftest: fec-cauchy ok, pacing-chaff ok, mlkem-1024-kex ok, zeroize-sp800-88 ok");
    eprintln!("selftest: mldsa-87 ok, noise-xxhfs ok, spqr-ratchet ok, threshold-pki ok");
    eprintln!("selftest: cookie-gate ok, acd-defense ok, zero-trust ok, memory-guard ok");
}

fn cmd_send_file(args: &[String]) {
    let (kb, key_id) = load_key_material(args);
    let state = state_path(args);
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let path = get_flag(args, "--file").unwrap_or_else(|| usage());
    let bytes = std::fs::read(&path).unwrap_or_else(|_| fail("file unreadable"));
    if bytes.len() > MAX_STREAM_BYTES {
        drop(kb);
        fail("file exceeds 16 MiB stream cap");
    }
    let chunks = frame::split_payload(&bytes);
    let digest = hex_of(&Sha256::digest(&bytes));
    let n = chunks.len() as u64;
    if n == 0 {
        drop(kb);
        fail("file empty refused");
    }
    // Reserve the full range BEFORE sealing any chunk.
    let key_bytes: [u8; 32] = *kb.as_bytes();
    let seq0 = reserve_send_seq(&state, &key_bytes, &key_id, n);
    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));
    let wire_total = rt.block_on(async {
        let any = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let ep = Endpoint::bind(any)
            .await
            .unwrap_or_else(|_| fail("bind failed"));
        let mut total = 0usize;
        for (i, chunk) in chunks.iter().enumerate() {
            // Quantum padding per chunk with CSPRNG filler.
            let (quantum, pad) = frame::pad_to_quantum(chunk.len())
                .unwrap_or_else(|| fail("chunk exceeds largest quantum"));
            let mut padded = Vec::with_capacity(chunk.len() + pad);
            padded.extend_from_slice(chunk);
            if pad > 0 {
                let mut pad_bytes = vec![0u8; pad];
                if getrandom::fill(&mut pad_bytes).is_err() {
                    fail("CSPRNG unavailable for padding");
                }
                padded.extend_from_slice(&pad_bytes);
            }
            let chunk_len = u16::try_from(chunk.len()).unwrap_or_else(|_| fail("chunk length exceeds u16"));
            let frame = aead::seal_with_len(
                &key,
                seq0.wrapping_add(i as u64),
                DIR_SEND,
                FTYPE_MSG,
                chunk_len,
                &padded,
            )
            .unwrap_or_else(|_| fail("seal failed"));
            if frame.len() != quantum {
                fail("sealed frame length mismatch with expected quantum");
            }
            if frame.len() > MAX_DATAGRAM {
                fail("sealed frame exceeds IPv6 MTU budget (1280B)");
            }
            total += frame.len();
            ep.send_raw(&frame, to)
                .await
                .unwrap_or_else(|_| fail("send failed"));
        }
        total
    });
    println!(
        "sent chunks={} bytes={} wire={}B digest={digest}",
        chunks.len(),
        bytes.len(),
        wire_total
    );
}

fn cmd_recv_file(args: &[String]) {
    let (kb, key_id) = load_key_material(args);
    let key_bytes: [u8; 32] = *kb.as_bytes();
    let state = state_path(args);
    let bind = get_flag(args, "--bind").unwrap_or_else(|| usage());
    let out = get_flag(args, "--out").unwrap_or_else(|| usage());
    let want: usize = get_flag(args, "--count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --count")))
        .unwrap_or_else(|| fail("--count K (chunk count) is required"));
    if want == 0 || want * MAX_PAYLOAD > MAX_STREAM_BYTES {
        drop(kb);
        fail("count outside 16 MiB stream cap");
    }
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(15000);
    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);
    let (mut sf, mut window) = load_recv_window(&state, &key_bytes, &key_id);
    let send_preserve: u64 = {
        sf.seek(SeekFrom::Start(0))
            .unwrap_or_else(|_| fail("state seek failed"));
        let mut buf = Vec::new();
        sf.read_to_end(&mut buf)
            .unwrap_or_else(|_| fail("state read failed"));
        if buf.len() == STATE_LEN {
            let mut arr = [0u8; STATE_LEN];
            arr.copy_from_slice(&buf);
            decode_state(&arr, &key_bytes, &key_id).send_seq
        } else {
            0
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));
    let data: Option<Vec<u8>> = rt.block_on(async {
        let mut ep = Endpoint::bind(&bind)
            .await
            .unwrap_or_else(|_| fail("bind failed"));
        let mut got: Vec<(u64, Vec<u8>)> = Vec::with_capacity(want);
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while got.len() < want {
            let wait = deadline.saturating_duration_since(std::time::Instant::now());
            if wait.is_zero() {
                break;
            }
            match ep.recv_raw(wait).await {
                None => break,
                Some(Err(_)) => {} // rate/oversize/io: counted, silent
                Some(Ok((bytes, _from))) => {
                    let seq = match aead::peek_seq(&key, &bytes) {
                        Some(s) => s,
                        None => {
                            ep.note_auth_drop();
                            continue;
                        }
                    };
                    if !window.check(seq) {
                        ep.note_auth_drop();
                        continue;
                    }
                    let Ok((seq2, ftype, pt)) = aead::open_indexed(&key, DIR_SEND, &bytes) else {
                        ep.note_auth_drop();
                        continue;
                    };
                    if seq2 != seq {
                        ep.note_auth_drop();
                        continue;
                    }
                    if ftype != FTYPE_MSG {
                        ep.note_auth_drop();
                        continue;
                    }
                    window.mark(seq2);
                    persist_recv_window(&mut sf, &key_bytes, &key_id, send_preserve, &window);
                    // open_indexed returns true-plaintext (padding stripped).
                    let plain: Vec<u8> = pt;
                    got.push((seq2, plain));
                }
            }
        }
        eprintln!("drops={} admitted={}", ep.drops, ep.admitted);
        if got.len() != want {
            return None;
        }
        got.sort_by_key(|(s, _)| *s);
        // Consecutiveness from the first seq: any gap/reorder-loss refuses.
        let base = got[0].0;
        for (i, (s, _)) in got.iter().enumerate() {
            if *s != base.wrapping_add(i as u64) {
                return None;
            }
        }
        let mut out_bytes = Vec::new();
        for (_, p) in &got {
            out_bytes.extend_from_slice(p);
        }
        Some(out_bytes)
    });
    let Some(data) = data else {
        eprintln!(
            "file refused: missing/tampered/out-of-order chunks \
                   (nothing written)"
        );
        std::process::exit(4);
    };
    let digest = hex_of(&Sha256::digest(&data));
    std::fs::write(&out, &data).unwrap_or_else(|_| fail("output unwritable"));
    println!(
        "received chunks={want} bytes={} digest={digest}",
        data.len()
    );
}

const DIODE_MAGIC: &[u8; 4] = b"STDD";
const DIODE_HEADER_LEN: usize = 4 + 16 + 8 + 2 + 2 + 2 + 2 + 48; // 84 bytes
const DIODE_CHUNK_SIZE: usize = 1024;

#[derive(Clone, Debug)]
struct DiodeHeader {
    transfer_id: [u8; 16],
    total_len: u64,
    k_data: u16,
    m_parity: u16,
    chunk_idx: u16,
    chunk_len: u16,
    sha384: [u8; 48],
}

impl DiodeHeader {
    fn encode(&self) -> [u8; DIODE_HEADER_LEN] {
        let mut b = [0u8; DIODE_HEADER_LEN];
        b[0..4].copy_from_slice(DIODE_MAGIC);
        b[4..20].copy_from_slice(&self.transfer_id);
        b[20..28].copy_from_slice(&self.total_len.to_be_bytes());
        b[28..30].copy_from_slice(&self.k_data.to_be_bytes());
        b[30..32].copy_from_slice(&self.m_parity.to_be_bytes());
        b[32..34].copy_from_slice(&self.chunk_idx.to_be_bytes());
        b[34..36].copy_from_slice(&self.chunk_len.to_be_bytes());
        b[36..84].copy_from_slice(&self.sha384);
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < DIODE_HEADER_LEN || &b[0..4] != DIODE_MAGIC {
            return None;
        }
        let mut transfer_id = [0u8; 16];
        transfer_id.copy_from_slice(&b[4..20]);
        let total_len = u64::from_be_bytes(b[20..28].try_into().ok()?);
        let k_data = u16::from_be_bytes(b[28..30].try_into().ok()?);
        let m_parity = u16::from_be_bytes(b[30..32].try_into().ok()?);
        let chunk_idx = u16::from_be_bytes(b[32..34].try_into().ok()?);
        let chunk_len = u16::from_be_bytes(b[34..36].try_into().ok()?);
        let mut sha384 = [0u8; 48];
        sha384.copy_from_slice(&b[36..84]);

        Some(Self {
            transfer_id,
            total_len,
            k_data,
            m_parity,
            chunk_idx,
            chunk_len,
            sha384,
        })
    }
}

fn cmd_diode_send(args: &[String]) {
    let (kb, key_id) = load_key_material(args);
    let state = state_path(args);
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let path = get_flag(args, "--file").unwrap_or_else(|| usage());
    let bytes = std::fs::read(&path).unwrap_or_else(|_| fail("file unreadable"));
    if bytes.is_empty() {
        drop(kb);
        fail("empty file refused");
    }
    if bytes.len() > MAX_STREAM_BYTES {
        drop(kb);
        fail("file exceeds 16 MiB stream cap");
    }

    // SHA-384 root hash
    let mut hasher = Sha384::new();
    hasher.update(&bytes);
    let digest: [u8; 48] = hasher.finalize().into();

    let total_len = bytes.len() as u64;
    let k = bytes.len().div_ceil(DIODE_CHUNK_SIZE);
    if k > 200 {
        drop(kb);
        fail("file exceeds single-bundle diode capacity (max 200 chunks / 200 KiB per transfer)");
    }

    let parity_ratio: f64 = get_flag(args, "--parity-ratio")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.25);
    let mut m = ((k as f64) * parity_ratio).ceil() as usize;
    if m < 2 {
        m = 2;
    }
    if k + m > 255 {
        m = 255 - k;
    }

    // Pad chunks to uniform DIODE_CHUNK_SIZE
    let mut data_chunks = vec![vec![0u8; DIODE_CHUNK_SIZE]; k];
    for (i, slice) in bytes.chunks(DIODE_CHUNK_SIZE).enumerate() {
        data_chunks[i][..slice.len()].copy_from_slice(slice);
    }

    // Cauchy-RS encoding
    let crs = CauchyReedSolomon::new(k, m).unwrap_or_else(|e| fail(&e.to_string()));
    let data_refs: Vec<&[u8]> = data_chunks.iter().map(|c| c.as_slice()).collect();
    let parity_chunks = crs
        .encode(&data_refs)
        .unwrap_or_else(|e| fail(&e.to_string()));

    // Random transfer ID
    let mut transfer_id = [0u8; 16];
    if getrandom::fill(&mut transfer_id).is_err() {
        fail("getrandom failed");
    }

    let n = (k + m) as u64;
    let key_bytes: [u8; 32] = *kb.as_bytes();
    let seq0 = reserve_send_seq(&state, &key_bytes, &key_id, n);
    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));

    let wire_total = rt.block_on(async {
        let any = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let ep = Endpoint::bind(any)
            .await
            .unwrap_or_else(|_| fail("bind failed"));
        let mut total = 0usize;

        for chunk_idx in 0..(k + m) {
            let (is_data, payload_chunk) = if chunk_idx < k {
                (true, &data_chunks[chunk_idx])
            } else {
                (false, &parity_chunks[chunk_idx - k])
            };
            let chunk_len = if is_data && chunk_idx == k - 1 {
                let rem = (total_len as usize) % DIODE_CHUNK_SIZE;
                if rem == 0 {
                    DIODE_CHUNK_SIZE
                } else {
                    rem
                }
            } else {
                DIODE_CHUNK_SIZE
            };

            let hdr = DiodeHeader {
                transfer_id,
                total_len,
                k_data: k as u16,
                m_parity: m as u16,
                chunk_idx: chunk_idx as u16,
                chunk_len: chunk_len as u16,
                sha384: digest,
            };

            let mut chunk_packet = Vec::with_capacity(DIODE_HEADER_LEN + DIODE_CHUNK_SIZE);
            chunk_packet.extend_from_slice(&hdr.encode());
            chunk_packet.extend_from_slice(payload_chunk);

            let frame = aead::seal(
                &key,
                seq0.wrapping_add(chunk_idx as u64),
                DIR_SEND,
                FTYPE_MSG,
                &chunk_packet,
            )
            .unwrap_or_else(|_| fail("seal failed"));
            total += frame.len();
            ep.send_raw(&frame, to)
                .await
                .unwrap_or_else(|_| fail("send failed"));

            // Inter-chunk pacing delay (500us) for simplex transmission line stability
            tokio::time::sleep(Duration::from_micros(500)).await;
        }
        total
    });

    println!(
        "diode-sent transfer_id={} file={} bytes={} data_chunks={} parity_chunks={} total_chunks={} wire={}B sha384={}",
        hex_of(&transfer_id), path, total_len, k, m, k + m, wire_total, hex_of(&digest)
    );
}

fn cmd_diode_recv(args: &[String]) {
    let (kb, key_id) = load_key_material(args);
    let key_bytes: [u8; 32] = *kb.as_bytes();
    let state = state_path(args);
    let bind = get_flag(args, "--bind").unwrap_or_else(|| usage());
    let out = get_flag(args, "--out").unwrap_or_else(|| usage());
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20000);
    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);

    let (mut sf, mut window) = load_recv_window(&state, &key_bytes, &key_id);
    let send_preserve: u64 = {
        sf.seek(SeekFrom::Start(0))
            .unwrap_or_else(|_| fail("state seek failed"));
        let mut buf = Vec::new();
        sf.read_to_end(&mut buf)
            .unwrap_or_else(|_| fail("state read failed"));
        if buf.len() == STATE_LEN {
            let mut arr = [0u8; STATE_LEN];
            arr.copy_from_slice(&buf);
            decode_state(&arr, &key_bytes, &key_id).send_seq
        } else {
            0
        }
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));

    struct DiodeTransferState {
        total_len: u64,
        k: usize,
        m: usize,
        sha384: [u8; 48],
        chunks: HashMap<usize, Vec<u8>>,
    }

    let result = rt.block_on(async {
        let mut ep = Endpoint::bind(&bind)
            .await
            .unwrap_or_else(|_| fail("bind failed"));
        let mut transfers: HashMap<[u8; 16], DiodeTransferState> = HashMap::new();
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);

        loop {
            let wait = deadline.saturating_duration_since(std::time::Instant::now());
            if wait.is_zero() {
                break;
            }
            match ep.recv_raw(wait).await {
                None => break,
                Some(Err(_)) => {}
                Some(Ok((bytes, _from))) => {
                    let seq = match aead::peek_seq(&key, &bytes) {
                        Some(s) => s,
                        None => {
                            ep.note_auth_drop();
                            continue;
                        }
                    };
                    if !window.check(seq) {
                        ep.note_auth_drop();
                        continue;
                    }
                    let Ok((seq2, ftype, pt)) = aead::open_indexed(&key, DIR_SEND, &bytes) else {
                        ep.note_auth_drop();
                        continue;
                    };
                    if seq2 != seq || ftype != FTYPE_MSG {
                        ep.note_auth_drop();
                        continue;
                    }
                    window.mark(seq2);
                    persist_recv_window(&mut sf, &key_bytes, &key_id, send_preserve, &window);

                    let Some(hdr) = DiodeHeader::decode(&pt) else {
                        continue;
                    };
                    if pt.len() < DIODE_HEADER_LEN + DIODE_CHUNK_SIZE {
                        continue;
                    }
                    let chunk_payload =
                        pt[DIODE_HEADER_LEN..DIODE_HEADER_LEN + DIODE_CHUNK_SIZE].to_vec();

                    let entry =
                        transfers
                            .entry(hdr.transfer_id)
                            .or_insert_with(|| DiodeTransferState {
                                total_len: hdr.total_len,
                                k: hdr.k_data as usize,
                                m: hdr.m_parity as usize,
                                sha384: hdr.sha384,
                                chunks: HashMap::new(),
                            });

                    entry.chunks.insert(hdr.chunk_idx as usize, chunk_payload);

                    // Check if we have gathered K chunks
                    if entry.chunks.len() >= entry.k {
                        let k = entry.k;
                        let m = entry.m;
                        let total_len = entry.total_len as usize;
                        let expected_sha384 = entry.sha384;
                        let transfer_id = hdr.transfer_id;

                        // Sort chunks by index
                        let mut sorted_indices: Vec<usize> = entry.chunks.keys().copied().collect();
                        sorted_indices.sort_unstable();

                        let mut k_chunks: Vec<(usize, &[u8])> = Vec::with_capacity(k);
                        for &idx in sorted_indices.iter().take(k) {
                            k_chunks.push((idx, entry.chunks[&idx].as_slice()));
                        }

                        let crs = match CauchyReedSolomon::new(k, m) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };

                        let recovered = match crs.decode(&k_chunks) {
                            Ok(rec) => rec,
                            Err(_) => continue,
                        };

                        let mut full_file = Vec::with_capacity(k * DIODE_CHUNK_SIZE);
                        for chunk in recovered {
                            full_file.extend_from_slice(&chunk);
                        }
                        if full_file.len() < total_len {
                            continue;
                        }
                        full_file.truncate(total_len);

                        // Verify SHA-384 root hash
                        let mut hasher = Sha384::new();
                        hasher.update(&full_file);
                        let computed_digest: [u8; 48] = hasher.finalize().into();

                        if computed_digest != expected_sha384 {
                            eprintln!("diode-recv hash verification failed!");
                            continue;
                        }

                        return Some((
                            transfer_id,
                            full_file,
                            computed_digest,
                            entry.chunks.len(),
                            k + m,
                        ));
                    }
                }
            }
        }
        None
    });

    let Some((transfer_id, data, digest, chunks_got, total_chunks)) = result else {
        fail("diode-recv timed out: insufficient chunks received or hash mismatch");
    };

    std::fs::write(&out, &data).unwrap_or_else(|_| fail("output unwritable"));
    println!(
        "diode-recv SUCCESS transfer_id={} out={} bytes={} received_chunks={}/{} sha384={}",
        hex_of(&transfer_id),
        out,
        data.len(),
        chunks_got,
        total_chunks,
        hex_of(&digest)
    );
}

fn cmd_stream_chaff(args: &[String]) {
    reject_forbidden_cli(args);
    let (kb, key_id) = load_key_material(args);
    let key_bytes: [u8; 32] = *kb.as_bytes();
    let state = state_path(args);
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let interval_ms: u64 = get_flag(args, "--interval-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --interval-ms")))
        .unwrap_or(50);
    let count: u64 = get_flag(args, "--count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --count")))
        .unwrap_or(10);
    let quantum: usize = get_flag(args, "--quantum")
        .map(|s| {
            s.parse()
                .unwrap_or_else(|_| fail("bad --quantum (must be 256, 512, or 1232)"))
        })
        .unwrap_or(1232);

    if quantum != 256 && quantum != 512 && quantum != 1232 {
        drop(kb);
        fail("bad --quantum: must be 256, 512, or 1232");
    }

    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));

    let bind_addr = if to.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let mut scheduler = PacedScheduler::new(Duration::from_millis(interval_ms));

    rt.block_on(async {
        let ep = Endpoint::bind(bind_addr)
            .await
            .unwrap_or_else(|_| fail("bind failed"));

        let mut emitted = 0u64;
        while count == 0 || emitted < count {
            scheduler.wait_next_tick();
            let seq = reserve_send_seq(&state, &key_bytes, &key_id, 1);
            let frame = pacing::build_chaff_frame(&key, seq, quantum)
                .unwrap_or_else(|_| fail("build chaff failed"));
            if ep.send_raw(&frame, to).await.is_err() {
                fail("chaff send failed");
            }
            emitted += 1;
        }
        println!("stream-chaff: emitted {emitted} frames wire={quantum}B interval={interval_ms}ms");
    });
}

fn cmd_channel(args: &[String]) {
    reject_forbidden_cli(args);
    let (kb, key_id) = load_key_material(args);
    let key_bytes: [u8; 32] = *kb.as_bytes();
    let state = state_path(args);
    let bind: SocketAddr = get_flag(args, "--bind")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --bind ADDR (host:port)"));
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let role = get_flag(args, "--role").unwrap_or_else(|| "initiator".to_string());
    if role != "initiator" && role != "responder" {
        fail("bad --role: must be 'initiator' or 'responder'");
    }
    let interval_ms: u64 = get_flag(args, "--interval-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --interval-ms")))
        .unwrap_or(50);
    let quantum: usize = get_flag(args, "--quantum")
        .map(|s| {
            s.parse()
                .unwrap_or_else(|_| fail("bad --quantum (must be 256, 512, or 1232)"))
        })
        .unwrap_or(1232);
    if quantum != 256 && quantum != 512 && quantum != 1232 {
        drop(kb);
        fail("bad --quantum: must be 256, 512, or 1232");
    }
    let count: u64 = get_flag(args, "--count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --count")))
        .unwrap_or(0);
    let recv_count: u64 = get_flag(args, "--recv-count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --recv-count")))
        .unwrap_or(0);
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(0);
    let reply_msg = get_flag(args, "--reply");
    let drain_ticks: u64 = get_flag(args, "--drain-ticks")
        .map(|s| s.parse().unwrap_or(0))
        .unwrap_or(3);
    let use_stdin = has_flag(args, "--stdin");

    let mut msgs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--msg" && i + 1 < args.len() {
            msgs.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }

    let (tx_dir, rx_dir) = if role == "responder" {
        (DIR_RECV, DIR_SEND)
    } else {
        (DIR_SEND, DIR_RECV)
    };

    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);

    let state_fresh = tpm_nv::state_is_fresh(&state);
    let mut state_file = open_locked_state(&state);
    let initial_st = read_state_locked(&mut state_file, &key_bytes, &key_id);
    tpm_nv::guard(&state, &key_bytes, initial_st.send_seq, state_fresh)
        .unwrap_or_else(|e| fail(&e));
    let mut next_send_seq = initial_st.send_seq;
    let mut window = AntiReplayWindow::from_parts(initial_st.recv_last, initial_st.recv_bitmap);

    let mut reserved_limit = next_send_seq
        .checked_add(512)
        .unwrap_or_else(|| fail("sequence exhausted"));
    let mut st = read_state_locked(&mut state_file, &key_bytes, &key_id);
    st.send_seq = reserved_limit;
    write_state_locked(&mut state_file, &st, &key_bytes);
    tpm_nv::checkpoint(&state, &key_bytes, reserved_limit).unwrap_or_else(|e| fail(&e));

    let mut outbound_msgs: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    for m in &msgs {
        outbound_msgs.push_back(m.as_bytes().to_vec());
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));

    rt.block_on(async {
        let mut ep = Endpoint::bind(&bind.to_string())
            .await
            .unwrap_or_else(|_| fail("channel bind failed"));
        let mut ticks_emitted = 0u64;
        let mut msgs_sent = 0u64;
        let mut msgs_received = 0u64;
        let mut chaff_received = 0u64;
        let mut draining: Option<u64> = None;

        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<String>(32);
        if use_stdin {
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let mut reader = tokio::io::BufReader::new(tokio::io::stdin()).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    if stdin_tx.send(line).await.is_err() {
                        break;
                    }
                }
            });
        }

        let start_time = Instant::now();
        let mut tick_timer = tokio::time::interval(Duration::from_millis(interval_ms));
        tick_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        println!(
            "channel: ACTIVE role={role} bind={bind} to={to} interval={interval_ms}ms quantum={quantum}B"
        );

        loop {
            if count > 0 && ticks_emitted >= count {
                break;
            }
            if recv_count > 0 && msgs_received >= recv_count && draining.is_none() {
                draining = Some(drain_ticks);
            }
            if let Some(rem) = draining {
                if rem == 0 {
                    break;
                }
            }
            if timeout_ms > 0 && start_time.elapsed() >= Duration::from_millis(timeout_ms) {
                break;
            }

            tokio::select! {
                line_opt = stdin_rx.recv(), if use_stdin => {
                    if let Some(line) = line_opt {
                        let trimmed = line.trim();
                        if trimmed == "/zeroize" || trimmed == "ZEROIZE" {
                            println!("channel: OPERATOR_REQUEST_ZEROIZE");
                            break;
                        } else if !trimmed.is_empty() {
                            outbound_msgs.push_back(trimmed.as_bytes().to_vec());
                        }
                    }
                }
                _ = tick_timer.tick() => {
                    if next_send_seq >= reserved_limit {
                        // Persisted send_seq is still the previous limit here
                        // (fresh=false): guard the chain before moving it up.
                        tpm_nv::guard(&state, &key_bytes, reserved_limit, false)
                            .unwrap_or_else(|e| fail(&e));
                        reserved_limit = next_send_seq
                            .checked_add(512)
                            .unwrap_or_else(|| fail("sequence exhausted"));
                        let (last, bitmap) = window.parts();
                        let st = SessionState {
                            key_id,
                            send_seq: reserved_limit,
                            recv_last: last,
                            recv_bitmap: bitmap,
                        };
                        write_state_locked(&mut state_file, &st, &key_bytes);
                        tpm_nv::checkpoint(&state, &key_bytes, reserved_limit)
                            .unwrap_or_else(|e| fail(&e));
                    }

                    let seq = next_send_seq;
                    next_send_seq += 1;

                    let frame = if let Some(payload) = outbound_msgs.pop_front() {
                        let f = pacing::build_data_frame_directed(&key, seq, tx_dir, quantum, &payload)
                            .unwrap_or_else(|_| fail("build data frame failed"));
                        msgs_sent += 1;
                        println!("channel: EMIT_MSG seq={seq} bytes={}", payload.len());
                        f
                    } else {
                        pacing::build_chaff_frame_directed(&key, seq, tx_dir, quantum)
                            .unwrap_or_else(|_| fail("build chaff failed"))
                    };

                    if ep.send_raw(&frame, to).await.is_err() {
                        ep.drops += 1;
                    }
                    ticks_emitted += 1;
                    if let Some(ref mut rem) = draining {
                        if *rem > 0 {
                            *rem -= 1;
                        }
                    }
                }
                recv_opt = ep.recv_unthrottled(Duration::from_millis(50)) => {
                    if let Some(Ok((bytes, _from))) = recv_opt {
                        if bytes.len() != quantum {
                            ep.note_auth_drop();
                            continue;
                        }
                        let seq = match aead::peek_seq(&key, &bytes) {
                            Some(s) => s,
                            None => {
                                ep.note_auth_drop();
                                continue;
                            }
                        };
                        if !window.check(seq) {
                            ep.note_auth_drop();
                            continue;
                        }
                        let Ok((seq2, ftype, pt)) = aead::open_indexed(&key, rx_dir, &bytes) else {
                            ep.note_auth_drop();
                            continue;
                        };
                        if seq2 != seq {
                            ep.note_auth_drop();
                            continue;
                        }
                        window.mark(seq2);
                        if ftype == FTYPE_MSG {
                            msgs_received += 1;
                            let text = String::from_utf8_lossy(&pt);
                            println!("channel: RECV_MSG seq={seq2} bytes={} payload={text}", pt.len());
                            if let Some(ref r) = reply_msg {
                                outbound_msgs.push_back(r.as_bytes().to_vec());
                            }
                            let (last, bitmap) = window.parts();
                            let st = SessionState {
                                key_id,
                                send_seq: reserved_limit,
                                recv_last: last,
                                recv_bitmap: bitmap,
                            };
                            write_state_locked(&mut state_file, &st, &key_bytes);
                        } else if ftype == FTYPE_CHAFF {
                            chaff_received += 1;
                        }
                    }
                }
            }
        }

        let (last, bitmap) = window.parts();
        let st = SessionState {
            key_id,
            send_seq: next_send_seq,
            recv_last: last,
            recv_bitmap: bitmap,
        };
        write_state_locked(&mut state_file, &st, &key_bytes);
        // Final write gives unused reservations back (send_seq may drop to
        // the consumed value): re-anchor the NV chain so the next guard
        // sees sidecar == state instead of a false rollback.
        tpm_nv::checkpoint(&state, &key_bytes, next_send_seq)
            .unwrap_or_else(|e| fail(&e));

        println!(
            "channel: TERMINATED ticks={ticks_emitted} sent_msgs={msgs_sent} recv_msgs={msgs_received} recv_chaff={chaff_received} drops={}",
            ep.drops
        );
    });
}

fn is_lab_mode() -> bool {
    for k in ["P2P_LAB_MODE", "ST2027_LAB_MODE"] {
        if let Ok(v) = std::env::var(k) {
            let v = v.trim().to_lowercase();
            if v == "1" || v == "true" || v == "yes" || v == "on" {
                return true;
            }
        }
    }
    false
}

fn kex_auth_required() -> bool {
    // Military-grade fail-closed: authentication is REQUIRED by default.
    // Unauthenticated KEX is strictly refused unless explicit lab mode is enabled.
    !is_lab_mode()
}

fn require_kex_auth(psk_present: bool) {
    if kex_auth_required() && !psk_present {
        fail("kex PSK required by default (set --psk-file); unauthenticated KEX refused (MITM protection; set P2P_LAB_MODE=1 for lab testing)");
    }
    if !psk_present {
        eprintln!("WARNING: kex running WITHOUT PSK — key is NOT authenticated. You MUST compare SAS out-of-band before use (lab only).");
    }
}

fn cmd_kex_listen(args: &[String]) {
    reject_forbidden_cli(args);
    let bind: SocketAddr = get_flag(args, "--bind")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --bind ADDR (host:port)"));
    let out = get_flag(args, "--out-key").unwrap_or_else(|| usage());
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(30000);
    let mut psk_bytes = get_flag(args, "--psk-file").map(|path| load_psk_file(&path));
    require_kex_auth(psk_bytes.is_some());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));

    let (key_hex, sas) = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .unwrap_or_else(|_| fail("kex-listen bind failed"));

        let accept_fut = async {
            let (mut socket, _peer) = listener.accept().await.map_err(|_| "accept failed")?;

            // 1. Generate ephemeral hybrid keypair (X25519 + ML-KEM-1024)
            let resp_keys = EphemeralKeys::generate().map_err(|_| "KEM key generation failed")?;

            // 2. Transmit responder bundle: x_public (32) || ml_ek (MLKEM_PK)
            let mut bundle = Vec::with_capacity(32 + MLKEM_PK);
            bundle.extend_from_slice(&resp_keys.x_public);
            bundle.extend_from_slice(&resp_keys.ml_ek);
            socket
                .write_all(&bundle)
                .await
                .map_err(|_| "bundle write failed")?;

            // 3. Receive initiator bundle: eph_pub (32) || ml_ct (MLKEM_CT)
            let mut init_bundle = vec![0u8; 32 + MLKEM_CT];
            socket
                .read_exact(&mut init_bundle)
                .await
                .map_err(|_| "initiator bundle read failed")?;

            let mut eph_pub = [0u8; 32];
            eph_pub.copy_from_slice(&init_bundle[..32]);
            let ml_ct = &init_bundle[32..];

            // 4. Decapsulate hybrid shared secret
            let hybrid_ss = resp_keys
                .decapsulate(&eph_pub, ml_ct)
                .map_err(|_| "decapsulate failed")?;

            // 5. Compute transcript hash over both bundles: SHA-384(resp_bundle || init_bundle)
            let mut transcript_hasher = Sha384::new();
            transcript_hasher.update(&bundle);
            transcript_hasher.update(&init_bundle);
            let transcript_hash: [u8; 48] = transcript_hasher.finalize().into();

            // 6. Derive symmetric frame key bound to transcript (and optional PSK)
            let frame_key = kem::derive_session_key_transcript(
                &hybrid_ss,
                psk_bytes.as_ref().map(|b| &b[..]),
                &transcript_hash,
            );

            // 7. Mutual Key Confirmation tag exchange
            let resp_tag = kem::compute_confirmation_tag(
                &frame_key,
                b"ST2027-RESPONDER-CONFIRM",
                &transcript_hash,
            );
            let init_tag = kem::compute_confirmation_tag(
                &frame_key,
                b"ST2027-INITIATOR-CONFIRM",
                &transcript_hash,
            );

            socket
                .write_all(&resp_tag)
                .await
                .map_err(|_| "responder confirmation tag write failed")?;
            let mut recv_init_tag = [0u8; 32];
            socket
                .read_exact(&mut recv_init_tag)
                .await
                .map_err(|_| "initiator confirmation tag read failed")?;
            if !kem::constant_time_eq_32(&recv_init_tag, &init_tag) {
                return Err("initiator confirmation tag mismatch (MITM detected)");
            }

            let sas = kem::compute_sas(&frame_key, &transcript_hash);
            let hex = hex_of(&frame_key);
            Ok::<(String, String), &'static str>((hex, sas))
        };

        match tokio::time::timeout(Duration::from_millis(timeout_ms), accept_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => fail(e),
            Err(_) => fail("kex-listen timed out waiting for peer"),
        }
    });

    write_key_file(&out, &key_hex);
    if psk_bytes.is_some() {
        println!("kex-listen SUCCESS: ML-KEM-1024 + X25519 hybrid key [SAS: {sas}] -> {out} (PSK-authenticated; SAS OOB-verify still recommended)");
    } else {
        println!("kex-listen SUCCESS: ML-KEM-1024 + X25519 hybrid key [SAS: {sas}] -> {out} (UNAUTHENTICATED — VERIFY SAS OOB BEFORE USE, lab only)");
    }
    // Wipe the PSK stack copy now that derivation is complete.
    if let Some(ref mut b) = psk_bytes {
        b.zeroize();
    }
}

fn cmd_kex_connect(args: &[String]) {
    reject_forbidden_cli(args);
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let out = get_flag(args, "--out-key").unwrap_or_else(|| usage());
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(30000);
    let mut psk_bytes = get_flag(args, "--psk-file").map(|path| load_psk_file(&path));
    require_kex_auth(psk_bytes.is_some());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| fail("tokio runtime unavailable"));

    let (key_hex, sas) = rt.block_on(async {
        let connect_fut = async {
            let mut socket = tokio::net::TcpStream::connect(to)
                .await
                .map_err(|_| "connect failed")?;

            // 1. Receive responder bundle: resp_x_pub (32) || resp_ml_ek (MLKEM_PK)
            let mut resp_bundle = vec![0u8; 32 + MLKEM_PK];
            socket
                .read_exact(&mut resp_bundle)
                .await
                .map_err(|_| "bundle read failed")?;

            let mut resp_x_pub = [0u8; 32];
            resp_x_pub.copy_from_slice(&resp_bundle[..32]);
            let resp_ml_ek = &resp_bundle[32..];

            // 2. Encapsulate hybrid shared secret
            let (ml_ct, hybrid_ss, eph_pub) = EphemeralKeys::encapsulate(&resp_x_pub, resp_ml_ek)
                .map_err(|_| "encapsulate failed")?;

            // 3. Transmit initiator bundle: eph_pub (32) || ml_ct (MLKEM_CT)
            let mut init_bundle = Vec::with_capacity(32 + MLKEM_CT);
            init_bundle.extend_from_slice(&eph_pub);
            init_bundle.extend_from_slice(&ml_ct);
            socket
                .write_all(&init_bundle)
                .await
                .map_err(|_| "initiator bundle write failed")?;

            // 4. Compute transcript hash over both bundles: SHA-384(resp_bundle || init_bundle)
            let mut transcript_hasher = Sha384::new();
            transcript_hasher.update(&resp_bundle);
            transcript_hasher.update(&init_bundle);
            let transcript_hash: [u8; 48] = transcript_hasher.finalize().into();

            // 5. Derive symmetric frame key bound to transcript (and optional PSK)
            let frame_key = kem::derive_session_key_transcript(
                &hybrid_ss,
                psk_bytes.as_ref().map(|b| &b[..]),
                &transcript_hash,
            );

            // 6. Mutual Key Confirmation tag exchange
            let resp_tag = kem::compute_confirmation_tag(
                &frame_key,
                b"ST2027-RESPONDER-CONFIRM",
                &transcript_hash,
            );
            let init_tag = kem::compute_confirmation_tag(
                &frame_key,
                b"ST2027-INITIATOR-CONFIRM",
                &transcript_hash,
            );

            let mut recv_resp_tag = [0u8; 32];
            socket
                .read_exact(&mut recv_resp_tag)
                .await
                .map_err(|_| "responder confirmation tag read failed")?;
            if !kem::constant_time_eq_32(&recv_resp_tag, &resp_tag) {
                return Err("responder confirmation tag mismatch (MITM detected)");
            }

            socket
                .write_all(&init_tag)
                .await
                .map_err(|_| "initiator confirmation tag write failed")?;

            let sas = kem::compute_sas(&frame_key, &transcript_hash);
            let hex = hex_of(&frame_key);
            Ok::<(String, String), &'static str>((hex, sas))
        };

        match tokio::time::timeout(Duration::from_millis(timeout_ms), connect_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => fail(e),
            Err(_) => fail("kex-connect timed out"),
        }
    });

    write_key_file(&out, &key_hex);
    if psk_bytes.is_some() {
        println!("kex-connect SUCCESS: ML-KEM-1024 + X25519 hybrid key [SAS: {sas}] -> {out} (PSK-authenticated; SAS OOB-verify still recommended)");
    } else {
        println!("kex-connect SUCCESS: ML-KEM-1024 + X25519 hybrid key [SAS: {sas}] -> {out} (UNAUTHENTICATED — VERIFY SAS OOB BEFORE USE, lab only)");
    }
    // Wipe the PSK stack copy now that derivation is complete.
    if let Some(ref mut b) = psk_bytes {
        b.zeroize();
    }
}

fn cmd_zeroize(args: &[String]) {
    reject_forbidden_cli(args);
    let mut targets = Vec::new();
    if let Some(s) = get_flag(args, "--state") {
        targets.push(s);
    }
    if let Some(k) = get_flag(args, "--key-file") {
        targets.push(k);
    }
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--target" && i + 1 < args.len() {
            targets.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    if targets.is_empty() {
        fail("zeroize requires at least one --target PATH, --state PATH, or --key-file PATH");
    }
    let mut purged = 0;
    for target in &targets {
        match purge::purge_file(target) {
            Ok(()) => {
                println!("zeroize: purged {target}");
                purged += 1;
            }
            Err(e) => {
                fail(&format!("zeroize failed on {target}: {e}"));
            }
        }
        // Sidecars pin this state lineage (append-only seq journal, NV
        // checkpoint chain): purge them too so a fresh state at the same
        // path starts a clean chain instead of tripping a stale
        // high-water refusal.
        for suffix in [".seqlog", ".nvck"] {
            let side = format!("{target}{suffix}");
            if std::path::Path::new(&side).exists() {
                purge::purge_file(&side)
                    .unwrap_or_else(|e| fail(&format!("zeroize failed on {side}: {e}")));
                println!("zeroize: purged {side}");
                purged += 1;
            }
        }
    }
    println!("ZEROIZE COMPLETE: {purged} file(s) cryptographically sanitized & unlinked (NIST SP 800-88)");
}

fn cmd_cookie_challenge(args: &[String]) {
    reject_forbidden_cli(args);
    let ip = get_flag(args, "--ip").unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = get_flag(args, "--port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(51820);
    let payload = get_flag(args, "--payload")
        .map(|s| s.into_bytes())
        .unwrap_or_else(|| b"ST2027-COOKIE-CHALLENGE".to_vec());
    let difficulty: u8 = get_flag(args, "--difficulty")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let epoch_secs: u64 = get_flag(args, "--epoch-secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);

    let mut gate = if let Some(kf) = get_flag(args, "--key-file") {
        let psk = load_psk_file(&kf);
        StatelessCookieGate::with_secret(psk, epoch_secs, 1024)
    } else {
        StatelessCookieGate::new(epoch_secs, 1024)
    };
    let challenge = gate.create_challenge(&ip, port, &payload, difficulty);
    let challenge_hex = hex_of(&challenge);
    println!(
        "cookie-challenge SUCCESS: ip={ip} port={port} difficulty={difficulty} challenge={}",
        challenge_hex.trim()
    );
}

fn cmd_cookie_solve(args: &[String]) {
    reject_forbidden_cli(args);
    let chal_hex = get_flag(args, "--challenge")
        .unwrap_or_else(|| fail("--challenge HEX is required"));
    let chal_bytes = decode_hex(&chal_hex).unwrap_or_else(|e| fail(e));
    let max_iters: u64 = get_flag(args, "--max-iters")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);

    let t0 = Instant::now();
    let solution = match StatelessCookieGate::solve_challenge(&chal_bytes, max_iters) {
        Some(sol) => sol,
        None => fail("cookie-solve failed: maximum iterations exceeded"),
    };
    let elapsed = t0.elapsed();
    let sol_hex = hex_of(&solution);
    println!(
        "cookie-solve SUCCESS: iterations_cap={max_iters} time={:?} solution={}",
        elapsed,
        sol_hex.trim()
    );
}

fn cmd_cookie_verify(args: &[String]) {
    reject_forbidden_cli(args);
    let sol_hex = get_flag(args, "--solution")
        .unwrap_or_else(|| fail("--solution HEX is required"));
    let sol_bytes = decode_hex(&sol_hex).unwrap_or_else(|e| fail(e));
    let ip = get_flag(args, "--ip").unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = get_flag(args, "--port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(51820);
    let payload = get_flag(args, "--payload")
        .map(|s| s.into_bytes())
        .unwrap_or_else(|| b"ST2027-COOKIE-CHALLENGE".to_vec());
    let difficulty: u8 = get_flag(args, "--difficulty")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let epoch_secs: u64 = get_flag(args, "--epoch-secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);

    let mut gate = if let Some(kf) = get_flag(args, "--key-file") {
        let psk = load_psk_file(&kf);
        StatelessCookieGate::with_secret(psk, epoch_secs, 1024)
    } else {
        StatelessCookieGate::new(epoch_secs, 1024)
    };
    let ok = gate.verify_response(&sol_bytes, &ip, port, &payload, difficulty);
    if ok {
        println!("cookie-verify SUCCESS: solution valid for {ip}:{port} (difficulty={difficulty})");
    } else {
        fail("cookie-verify FAILED: invalid solution, expired epoch, or replay detected");
    }
}

fn cmd_threat_eval(args: &[String]) {
    reject_forbidden_cli(args);
    let peer = get_flag(args, "--peer").unwrap_or_else(|| fail("--peer ID is required"));
    let trigger_name = get_flag(args, "--trigger").unwrap_or_else(|| "replay".to_string());
    let count: usize = get_flag(args, "--count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let threshold: usize = get_flag(args, "--threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let quarantine_sec: f64 = get_flag(args, "--quarantine-sec")
        .and_then(|s| s.parse().ok())
        .unwrap_or(300.0);

    let trigger = match trigger_name.to_lowercase().as_str() {
        "replay" | "replay-burst" => ThreatTrigger::ReplayBurst,
        "tamper" | "payload-tamper" => ThreatTrigger::TamperDetected,
        "auth_fail" | "auth-fail" | "flood" => ThreatTrigger::AuthFailureFlood,
        "traffic" | "traffic-anomaly" => ThreatTrigger::TrafficAnomaly,
        "fault" | "key-exposure" => ThreatTrigger::FaultDetected,
        _ => fail("unknown --trigger (use: replay, tamper, auth_fail, traffic, fault)"),
    };

    let acd = ActiveCyberDefenseEngine::new(
        threshold,
        10.0,
        threshold,
        30.0,
        quarantine_sec,
        None,
    );

    let mut last_pb = None;
    for _ in 0..count {
        last_pb = acd.record_event(trigger, &peer);
    }

    let quarantined = acd.is_quarantined(&peer);
    println!(
        "threat-eval SUCCESS: peer={peer} trigger={trigger_name} events={count} playbook={:?} quarantined={quarantined}",
        last_pb
    );
}

fn cmd_zero_trust_eval(args: &[String]) {
    reject_forbidden_cli(args);
    let peer = get_flag(args, "--peer").unwrap_or_else(|| fail("--peer ID is required"));
    let role_name = get_flag(args, "--role").unwrap_or_else(|| "operator".to_string());
    let role = match role_name.to_lowercase().as_str() {
        "admin" => SecurityRole::Admin,
        "operator" => SecurityRole::Operator,
        "viewer" => SecurityRole::Viewer,
        _ => fail("unknown --role (use: admin, operator, viewer)"),
    };
    let min_score: u32 = get_flag(args, "--min-score")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let penalty: u32 = get_flag(args, "--penalty")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let reward: u32 = get_flag(args, "--reward")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let perm_check = get_flag(args, "--check-perm");

    let zt = ZeroTrustEngine::new(min_score);
    zt.register_peer(&peer, role);

    if penalty > 0 {
        let _ = zt.record_penalty(&peer, penalty);
    }
    for _ in 0..reward {
        let _ = zt.record_success(&peer);
    }

    let score = zt.trust_score(&peer).unwrap_or(0);
    let trusted = zt.is_trusted(&peer);

    let perm_res = perm_check.map(|p| {
        let mask = match p.to_lowercase().as_str() {
            "send" | "message-send" => PERM_MESSAGE_SEND,
            "critical" | "critical-release" => PERM_CRITICAL_RELEASE,
            _ => PERM_MESSAGE_SEND,
        };
        zt.authorize(&peer, mask).is_ok()
    });

    println!(
        "zero-trust-eval SUCCESS: peer={peer} role={role_name} score={score}/100 trusted={trusted} perm_allowed={:?}",
        perm_res
    );
}

fn cmd_cot_beacon(args: &[String]) {
    reject_forbidden_cli(args);
    // F-15 fence: cot-beacon is a FORMATTER that emits demo/lab CoT XML.
    // It is not an operational C4ISR publisher. Banner on stderr so stdout
    // stays machine-parseable for tests and tooling.
    eprintln!(
        "FORMATTER NOTICE (stderr): cot-beacon emits a MIL-STD-6090 CoT XML document from \
local inputs; this is a demo/lab formatter, not an operational tactical data link publish."
    );
    let callsign = get_flag(args, "--callsign").unwrap_or_else(|| "TACTICAL-ST2027".to_string());
    let event_type = get_flag(args, "--type").unwrap_or_else(|| "a-f-G-U-C".to_string());
    let lat: f64 = get_flag(args, "--lat")
        .and_then(|s| s.parse().ok())
        .unwrap_or(38.8719);
    let lon: f64 = get_flag(args, "--lon")
        .and_then(|s| s.parse().ok())
        .unwrap_or(-77.0563);
    let hae: f64 = get_flag(args, "--hae")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100.0);
    let status = get_flag(args, "--status").unwrap_or_else(|| "DEFCON-1-ARMED".to_string());
    let out_path = get_flag(args, "--out");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let stale_secs = now_secs + 300;

    let uid = format!("COT-ST2027-{:08X}", now_secs ^ (lat.to_bits()));

    let cot_xml = format!(
        "<?xml version=\"1.0\" standalone=\"yes\"?>\
<event version=\"2.0\" uid=\"{uid}\" type=\"{event_type}\" time=\"{now_secs}\" start=\"{now_secs}\" stale=\"{stale_secs}\" how=\"m-g\">\
<point lat=\"{lat:.6}\" lon=\"{lon:.6}\" hae=\"{hae:.1}\" ce=\"5.0\" le=\"10.0\"/>\
<detail><contact callsign=\"{callsign}\"/><status readiness=\"{status}\"/></detail>\
</event>"
    );

    let signed_xml = if let Some(sk_path) = get_flag(args, "--sk-file") {
        let (locked_seed, _) = load_key_material(&["--key-file".to_string(), sk_path]);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(locked_seed.as_bytes());
        let (sk, _) = Mldsa87SigningKey::from_seed(&seed);
        seed.zeroize();
        let sig = sk.sign(b"DESTROYER-ST2027-COT-EVENT", cot_xml.as_bytes());
        let sig_hex = hex_of(&sig);
        format!(
            "{cot_xml}<!-- MIL-STD-6090 FIPS 204 SIGNATURE: alg=\"ML-DSA-87\" signer=\"{callsign}\" sig=\"{sig_hex}\" -->"
        )
    } else {
        cot_xml
    };

    if let Some(ref path) = out_path {
        std::fs::write(path, signed_xml.as_bytes())
            .unwrap_or_else(|_| fail("failed to write output CoT XML file"));
        println!("cot-beacon SUCCESS: MIL-STD-6090 CoT event written to {path}");
    } else {
        println!("{signed_xml}");
    }
}

fn cmd_tactical_msg(args: &[String]) {
    reject_forbidden_cli(args);
    // F-15 fence: tactical-msg is a FORMATTER that renders an MMHS-style
    // telegram string from local inputs. Banner on stderr (stdout contract
    // is pinned by tests: returncode 0 + FLASH_OVERRIDE/TOP_SECRET/...).
    eprintln!(
        "FORMATTER NOTICE (stderr): tactical-msg formats an MMHS precedence telegram; \
this is a demo/lab formatter, not an operational message-center transmit."
    );
    let precedence = get_flag(args, "--precedence").unwrap_or_else(|| "Z".to_string()).to_uppercase();
    let clearance_str = get_flag(args, "--clearance").unwrap_or_else(|| "TOP_SECRET".to_string()).to_uppercase();
    let caveats = get_flag(args, "--caveats").unwrap_or_else(|| "NOFORN".to_string()).to_uppercase();
    let msg = get_flag(args, "--msg").unwrap_or_else(|| fail("missing --msg TEXT"));
    // F-15: RTB classified-spillage scan is ON BY DEFAULT. --scan-rtb is
    // retained as an accepted no-op for CLI compatibility (older scripts
    // that pass the flag keep working; the scan no longer depends on it).
    let _scan_rtb_compat = has_flag(args, "--scan-rtb");

    let prec_label = match precedence.as_str() {
        "Y" | "FLASH_OVERRIDE" => "FLASH_OVERRIDE",
        "Z" | "FLASH" => "FLASH",
        "O" | "IMMEDIATE" => "IMMEDIATE",
        "P" | "PRIORITY" => "PRIORITY",
        "R" | "ROUTINE" => "ROUTINE",
        _ => fail("bad --precedence: must be Y, Z, O, P, or R"),
    };

    let clearance = match clearance_str.as_str() {
        "UNCLASSIFIED" => ClearanceLevel::Unclassified,
        "CONFIDENTIAL" => ClearanceLevel::Confidential,
        "SECRET" => ClearanceLevel::Secret,
        "TOP_SECRET" => ClearanceLevel::TopSecret,
        _ => fail("bad --clearance: must be UNCLASSIFIED, CONFIDENTIAL, SECRET, or TOP_SECRET"),
    };

    // F-15: always scan (not gated on the compat flag).
    if let Err(indicator) = inspect_content_rtb(msg.as_bytes()) {
        if clearance < ClearanceLevel::TopSecret {
            fail(&format!("RTB SPILLAGE PREVENTED: detected classified indicator '{indicator}' in {clearance_str} message"));
        }
    }

    let wire_telegram = format!("[MMHS PRECEDENCE={prec_label} // {clearance_str} // {caveats}] {msg}");
    println!("tactical-msg SUCCESS: clearance={clearance_str} precedence={prec_label} caveats={caveats}");
    println!("telegram: {wire_telegram}");
}

fn cmd_eam_auth(args: &[String]) {
    reject_forbidden_cli(args);
    // F-15 fence: eam-auth verifies dual-officer signatures over a directive
    // string. Banner on stderr (stdout contract pinned by tests).
    eprintln!(
        "FORMATTER NOTICE (stderr): eam-auth verifies two ML-DSA-87 officer signatures \
over a directive; it does not query a personnel system or hardware token store."
    );
    // F-15: optional --officers-manifest PATH (JSON/TOML roster of authorized
    // officer public keys). When absent, verification still proceeds on the
    // four provided key/sig files, but a stderr warning records that no
    // roster cross-check was performed (tests invoke without a manifest).
    if get_flag(args, "--officers-manifest").is_none() {
        eprintln!(
            "WARNING (stderr): no --officers-manifest provided; dual-officer signature \
verification runs without a roster cross-check of officer identity."
        );
    }
    let directive = get_flag(args, "--directive").unwrap_or_else(|| fail("missing --directive TEXT"));
    let of1_pk = get_flag(args, "--officer1-pk").unwrap_or_else(|| fail("missing --officer1-pk PATH"));
    let of1_sig = get_flag(args, "--officer1-sig").unwrap_or_else(|| fail("missing --officer1-sig PATH"));
    let of2_pk = get_flag(args, "--officer2-pk").unwrap_or_else(|| fail("missing --officer2-pk PATH"));
    let of2_sig = get_flag(args, "--officer2-sig").unwrap_or_else(|| fail("missing --officer2-sig PATH"));

    let pk1_hex = std::fs::read_to_string(&of1_pk).unwrap_or_else(|_| fail("officer1-pk unreadable"));
    let pk2_hex = std::fs::read_to_string(&of2_pk).unwrap_or_else(|_| fail("officer2-pk unreadable"));
    let pk1_bytes = decode_hex(pk1_hex.trim()).unwrap_or_else(|e| fail(e));
    let pk2_bytes = decode_hex(pk2_hex.trim()).unwrap_or_else(|e| fail(e));

    if pk1_bytes == pk2_bytes {
        fail("NC3 TWO-PERSON RULE VIOLATION: Officer 1 and Officer 2 keys are identical (single-custody attempt)");
    }

    let vk1 = Mldsa87VerifyingKey::from_bytes(&pk1_bytes).unwrap_or_else(|_| fail("invalid officer 1 ML-DSA-87 public key"));
    let vk2 = Mldsa87VerifyingKey::from_bytes(&pk2_bytes).unwrap_or_else(|_| fail("invalid officer 2 ML-DSA-87 public key"));

    let sig1_hex = std::fs::read_to_string(&of1_sig).unwrap_or_else(|_| fail("officer1-sig unreadable"));
    let sig2_hex = std::fs::read_to_string(&of2_sig).unwrap_or_else(|_| fail("officer2-sig unreadable"));
    let sig1_bytes = decode_hex(sig1_hex.trim()).unwrap_or_else(|e| fail(e));
    let sig2_bytes = decode_hex(sig2_hex.trim()).unwrap_or_else(|e| fail(e));

    let domain = b"DESTROYER-ST2027-NC3-EAM";
    if vk1.verify(domain, directive.as_bytes(), &sig1_bytes).is_err() {
        fail("Officer 1 signature verification FAILED");
    }
    if vk2.verify(domain, directive.as_bytes(), &sig2_bytes).is_err() {
        fail("Officer 2 signature verification FAILED");
    }

    println!("eam-auth SUCCESS: NC3 TWO-PERSON RULE DUAL CUSTODY VERIFIED (DoD S-5210.41M)");
    println!("authorized_directive: {directive}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "keygen" => cmd_keygen(&args[2..]),
        "auth-keygen" => cmd_auth_keygen(&args[2..]),
        "auth-sign" => cmd_auth_sign(&args[2..]),
        "auth-verify" => cmd_auth_verify(&args[2..]),
        "kex-listen" => cmd_kex_listen(&args[2..]),
        "kex-connect" => cmd_kex_connect(&args[2..]),
        "send" => cmd_send(&args[2..]),
        "recv" => cmd_recv(&args[2..]),
        "send-file" => cmd_send_file(&args[2..]),
        "recv-file" => cmd_recv_file(&args[2..]),
        "diode-send" => cmd_diode_send(&args[2..]),
        "diode-recv" => cmd_diode_recv(&args[2..]),
        "stream-chaff" => cmd_stream_chaff(&args[2..]),
        "channel" => cmd_channel(&args[2..]),
        "cookie-challenge" => cmd_cookie_challenge(&args[2..]),
        "cookie-solve" => cmd_cookie_solve(&args[2..]),
        "cookie-verify" => cmd_cookie_verify(&args[2..]),
        "threat-eval" => cmd_threat_eval(&args[2..]),
        "zero-trust-eval" => cmd_zero_trust_eval(&args[2..]),
        "cot-beacon" => cmd_cot_beacon(&args[2..]),
        "tactical-msg" => cmd_tactical_msg(&args[2..]),
        "eam-auth" => cmd_eam_auth(&args[2..]),
        "zeroize" | "purge" => cmd_zeroize(&args[2..]),
        "selftest" => cmd_selftest(),
        "-h" | "--help" | "help" => usage(),
        _ => usage(),
    }
}
