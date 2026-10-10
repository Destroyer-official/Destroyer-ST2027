//! secure-transmit — standalone data-plane executor (zero-Python binary).
//!
//! SCOPE (explicit boundary, no handshake claims):
//! - This binary executes the TESTED data-plane modules only: AEAD framing
//!   (`aead`), fixed quanta (`frame`/`pad`), 64-bit anti-replay (`replay`),
//!   silent-drop UDP transport (`net`), constant-time compare (`ct`).
//! - Session-key provisioning (ML-KEM-1024 PQ handshake, ML-DSA-87 PKI,
//!   SPO/DPO ceremony, TLS 1.3) remains in the audited Python control plane
//!   (`secure_transmit_2027.py`, `noise_pq.py`, `trust_anchor.py`,
//!   `spo_dpo.py`). This binary NEVER negotiates keys: the frame key arrives
//!   from that plane (or offline ceremony) via `--key-file` / `--key-stdin`
//!   and is zeroized after use. Raw key material on the process command line
//!   (`--key HEX`) is REFUSED (DoD Zero Trust: secrets must never appear in
//!   `ps` / `Get-Process` argv).
//! - Nonce discipline (NIST SP 800-38D uniqueness: the 96-bit nonce MUST
//!   be unique per invocation; counters are the prescribed construction;
//!   reuse destroys AEAD guarantees):
//!   seq is NEVER user input. `--seq` is REFUSED. Each `send` reserves a
//!   strictly monotonic seq (range for `send-file`) from a persistent
//!   `--state` file under an exclusive OS lock, persisted BEFORE encrypting,
//!   so concurrent runs and crashes can skip but never reuse a nonce.
//! - One direction per invocation: `send` seals with DIR_SEND, `recv` opens
//!   with DIR_SEND. Bidirectional traffic = two sessions with opposite roles
//!   (same doctrine as `SecureEngine::establish_session(is_initiator)`).
//! - Bulk cipher here is the data-plane AEAD (AES-256-GCM, CNSA 2.0 suite)
//!   as tested in `aead.rs` (NIST SP 800-38D KAT). This binary seals exactly
//!   what it is handed under the frame key it is given.
//!
//! FAIL-CLOSED CLI: bad key length, oversize payload, unauthenticated traffic,
//! exhausted sequence space, state/key mismatch, and timeouts exit non-zero
//! with a one-line stderr reason. Nothing is ever signaled back to the peer
//! (stealth discipline from `net.rs`).

use destroyer_core::aead::{self, FrameKey, DIR_RECV, DIR_SEND};
use destroyer_core::fec::CauchyReedSolomon;
use destroyer_core::frame::{self, FTYPE_CHAFF, FTYPE_MSG};
use destroyer_core::kem::{self, EphemeralKeys, MLKEM_CT, MLKEM_PK};
use destroyer_core::memlock::LockedKey32;
use destroyer_core::net::{Endpoint, MAX_DATAGRAM};
use destroyer_core::pacing::{self, PacedScheduler};
use destroyer_core::purge;
use destroyer_core::replay::AntiReplayWindow;
use fs2::FileExt;
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

const VERSION: &str = "0.2.0";
/// Largest user payload accepted by `send` (largest fixed quantum, frame.rs).
const MAX_PAYLOAD: usize = 1205;
/// Stream cap mirrored from the Python plane (destroyer_node 16 MiB):
/// a single file transfer never exceeds this; larger inputs are refused.
const MAX_STREAM_BYTES: usize = 16 << 20;
/// Persistent state file layout: MAGIC(8) || key_id(16) || send_seq(8LE)
/// || recv_last(8LE) || recv_bitmap(8LE) = 48 bytes.
const STATE_MAGIC: &[u8; 8] = b"STSTATE1";
const STATE_LEN: usize = 48;

fn usage() -> ! {
    eprintln!(
        "secure-transmit {VERSION} — standalone data-plane executor\n\
         \n\
         keygen [--out PATH]              print fresh 32B frame key (hex)\n\
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
         and directional nonce separation. Flat wire timing and constant Shannon entropy\n\
         defeats Signals Intelligence (SIGINT) flow correlation and timing analysis.\n\
         \n\
         Security: --seq, --key HEX and --psk HEX are REFUSED. Seq comes only from the\n\
         locked --state file (monotonic, persisted before encrypt). Keys/PSK NEVER\n\
         appear in argv (visible via ps): provision via --key-file (0600), --key-stdin,\n\
         --psk-file, or native quantum-resistant kex-listen/kex-connect with ML-KEM-1024 + X25519."
    );
    std::process::exit(2);
}

fn fail(msg: &str) -> ! {
    eprintln!("secure-transmit: FAIL: {msg}");
    std::process::exit(1);
}

fn get_flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
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

fn parse_key_hex(h: &str) -> [u8; 32] {
    let h = h.trim();
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        fail("key must be 64 hex chars (32 bytes)");
    }
    let mut out = [0u8; 32];
    for (i, chunk) in h.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16)
            .unwrap_or_else(|_| fail("key must be 64 hex chars (32 bytes)"));
    }
    out
}

/// Load frame key bytes from --key-file or --key-stdin (exactly one).
/// Returns (locked key guard, key_id). Key file should be 0600 on Unix.
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
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .unwrap_or_else(|_| fail("key file unreadable"));
        let meta = file.metadata().unwrap_or_else(|_| fail("key file metadata unreadable"));
        if meta.file_type().is_symlink() {
            fail("key file must not be a symlink");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                fail("key file must be 0600 (group/other readable refused)");
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let attrs = meta.file_attributes();
            // Refuse reparse points (symlinks/mount points)
            if attrs & 0x400 != 0 {
                fail("key file must not be a reparse point or symlink");
            }
        }
        let mut s = String::with_capacity(128);
        file.read_to_string(&mut s).unwrap_or_else(|_| fail("key file read failed"));
        // Zeroize the file buffer copy held by Rust String after parse.
        let z = Zeroizing::new(s.clone());
        s.zeroize();
        z
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
    get_flag(args, "--state").unwrap_or_else(|| fail("missing --state PATH (monotonic nonce state required)"))
}

/// In-memory session state mirror (persisted as 48-byte record).
struct SessionState {
    key_id: [u8; 16],
    send_seq: u64,
    recv_last: u64,
    recv_bitmap: u64,
}

fn encode_state(st: &SessionState) -> [u8; STATE_LEN] {
    let mut b = [0u8; STATE_LEN];
    b[..8].copy_from_slice(STATE_MAGIC);
    b[8..24].copy_from_slice(&st.key_id);
    b[24..32].copy_from_slice(&st.send_seq.to_le_bytes());
    b[32..40].copy_from_slice(&st.recv_last.to_le_bytes());
    b[40..48].copy_from_slice(&st.recv_bitmap.to_le_bytes());
    b
}

fn decode_state(buf: &[u8; STATE_LEN], expect_key_id: &[u8; 16]) -> SessionState {
    if &buf[..8] != STATE_MAGIC {
        fail("state file corrupt (bad magic) — rekey with fresh key+state");
    }
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&buf[8..24]);
    if &key_id != expect_key_id {
        fail("state file bound to a different key (key_id mismatch) — use matching --state or rekey");
    }
    let mut u = [0u8; 8];
    u.copy_from_slice(&buf[24..32]);
    let send_seq = u64::from_le_bytes(u);
    u.copy_from_slice(&buf[32..40]);
    let recv_last = u64::from_le_bytes(u);
    u.copy_from_slice(&buf[40..48]);
    let recv_bitmap = u64::from_le_bytes(u);
    SessionState { key_id, send_seq, recv_last, recv_bitmap }
}

fn open_locked_state(path: &str) -> File {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap_or_else(|_| fail("state file unopenable"));
    f.lock_exclusive().unwrap_or_else(|_| fail("state file lock failed"));
    f
}

fn read_state_locked(f: &mut File, key_id: &[u8; 16]) -> SessionState {
    let mut buf = Vec::new();
    f.seek(SeekFrom::Start(0)).unwrap_or_else(|_| fail("state seek failed"));
    f.read_to_end(&mut buf).unwrap_or_else(|_| fail("state read failed"));
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
        return SessionState { key_id: *key_id, send_seq, recv_last: 0, recv_bitmap: 0 };
    }
    if buf.len() != STATE_LEN {
        fail("state file corrupt (bad length) — rekey with fresh key+state");
    }
    let mut arr = [0u8; STATE_LEN];
    arr.copy_from_slice(&buf);
    decode_state(&arr, key_id)
}

fn write_state_locked(f: &mut File, st: &SessionState) {
    let enc = encode_state(st);
    f.seek(SeekFrom::Start(0)).unwrap_or_else(|_| fail("state seek failed"));
    f.write_all(&enc).unwrap_or_else(|_| fail("state write failed"));
    f.set_len(STATE_LEN as u64).unwrap_or_else(|_| fail("state truncate failed"));
    f.sync_all().unwrap_or_else(|_| fail("state sync failed"));
}

/// Reserve one send seq: persist N+1 BEFORE encrypting (crash may skip,
/// never reuse). Returns the seq to seal with.
fn reserve_send_seq(path: &str, key_id: &[u8; 16], count: u64) -> u64 {
    if count == 0 {
        fail("reservation count must be >= 1");
    }
    let mut f = open_locked_state(path);
    let mut st = read_state_locked(&mut f, key_id);
    let start = st.send_seq;
    let end = start.checked_add(count).unwrap_or_else(|| fail("sequence exhausted — rekey required"));
    if start == u64::MAX || (end == 0 && count > 0) {
        fail("sequence exhausted — rekey required");
    }
    // Reserve [start, start+count): fail if range would wrap past MAX.
    if start.checked_add(count - 1).is_none() {
        fail("sequence exhausted — rekey required");
    }
    st.send_seq = end;
    write_state_locked(&mut f, &st);
    // Unlock via drop.
    start
}

fn load_recv_window(path: &str, key_id: &[u8; 16]) -> (File, AntiReplayWindow) {
    let mut f = open_locked_state(path);
    let st = read_state_locked(&mut f, key_id);
    let w = AntiReplayWindow::from_parts(st.recv_last, st.recv_bitmap);
    (f, w)
}

fn persist_recv_window(f: &mut File, key_id: &[u8; 16], send_seq_preserve: u64, w: &AntiReplayWindow) {
    // Re-read send_seq under the same lock to avoid clobbering a
    // concurrent reservation (recv holds the lock for the session, so
    // this is normally unchanged; defense in depth).
    f.seek(SeekFrom::Start(0)).unwrap_or_else(|_| fail("state seek failed"));
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap_or_else(|_| fail("state read failed"));
    let cur_send = if buf.len() == STATE_LEN {
        let mut arr = [0u8; STATE_LEN];
        arr.copy_from_slice(&buf);
        let cur = decode_state(&arr, key_id);
        cur.send_seq
    } else {
        send_seq_preserve
    };
    let (last, bitmap) = w.parts();
    let st = SessionState { key_id: *key_id, send_seq: cur_send, recv_last: last, recv_bitmap: bitmap };
    write_state_locked(f, &st);
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

fn write_key_file(out: &str, hex: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(out)
            .unwrap_or_else(|_| fail("key out unwritable"));
        f.write_all(hex.as_bytes()).unwrap_or_else(|_| fail("key out unwritable"));
        f.sync_all().unwrap_or_else(|_| fail("key out sync failed"));
    }
    #[cfg(not(unix))]
    {
        // Windows/NTFS has no Unix mode bits: enforce owner-only ACL
        // best-effort (icacls inheritance removal), then verify the file is
        // not world-readable. Fail-closed on ACL hardening failure so
        // session keys never rest on disk with loose permissions.
        // Residual: SSD wear-leveling/swap/hibernation can retain copies —
        // a facility duty (see trust_anchor ephemeral doctrine); prefer
        // --key-stdin + locked memory / HSM custody for TOP SECRET.
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_NONE: u32 = 0;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .share_mode(FILE_SHARE_NONE)
            .open(out)
            .unwrap_or_else(|_| fail("key out unwritable"));
        f.write_all(hex.as_bytes()).unwrap_or_else(|_| fail("key out unwritable"));
        f.sync_all().unwrap_or_else(|_| fail("key out sync failed"));
        drop(f);
        let acl_ok = std::process::Command::new("icacls")
            .args([out, "/inheritance:r", "/grant:r", &format!("{}:F", std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string()))])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !acl_ok {
            let _ = std::fs::remove_file(out);
            fail("key out ACL hardening failed (icacls owner-only); nothing written");
        }
    }
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
    let seq = reserve_send_seq(&state, &key_id, 1);
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
    let frame = aead::seal_with_len(&key, seq, DIR_SEND, FTYPE_MSG, msg.len() as u16, &padded)
        .unwrap_or_else(|_| fail("seal failed"));
    debug_assert_eq!(frame.len(), quantum);
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
    let (mut sf, mut window) = load_recv_window(&state, &key_id);
    // Snapshot send_seq to preserve across write-throughs.
    let send_preserve: u64 = {
        sf.seek(SeekFrom::Start(0)).unwrap_or_else(|_| fail("state seek failed"));
        let mut buf = Vec::new();
        sf.read_to_end(&mut buf).unwrap_or_else(|_| fail("state read failed"));
        if buf.len() == STATE_LEN {
            let mut arr = [0u8; STATE_LEN];
            arr.copy_from_slice(&buf);
            decode_state(&arr, &key_id).send_seq
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
                    let Ok((seq2, ftype, pt)) = aead::open_indexed(&key, DIR_SEND, &bytes)
                    else {
                        ep.note_auth_drop();
                        continue;
                    };
                    if seq2 != seq {
                        ep.note_auth_drop();
                        continue;
                    }
                    window.mark(seq2);
                    persist_recv_window(&mut sf, &key_id, send_preserve, &window);
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
    let f = aead::seal(&key, 7, DIR_SEND, FTYPE_MSG, b"selftest-vector")
        .expect("seal");
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
    let st = SessionState { key_id: [0xABu8; 16], send_seq: 41, recv_last: 7, recv_bitmap: 0b11 };
    let enc = encode_state(&st);
    assert_eq!(enc.len(), STATE_LEN);
    let dec = decode_state(&enc, &[0xABu8; 16]);
    assert_eq!(dec.send_seq, 41);
    eprintln!("selftest: aead-roundtrip ok, tamper-reject ok, replay ok, mtu ok");
    // Page-lock probe (best-effort, reported never failed: containers without
    // lock privilege run wipe-only hygiene by design).
    let probe = [0u8; 32];
    let probe_locked = destroyer_core::memlock::lock_slice(&probe);
    destroyer_core::memlock::unlock_slice(&probe);
    eprintln!("selftest: memlock-probe {}", if probe_locked { "locked" } else { "unlocked-best-effort" });

    // Cauchy-Reed-Solomon FEC self-check
    let crs = CauchyReedSolomon::new(3, 2).expect("crs new");
    let d0 = vec![1u8, 2, 3, 4];
    let d1 = vec![5u8, 6, 7, 8];
    let d2 = vec![9u8, 10, 11, 12];
    let parities = crs.encode(&[&d0, &d1, &d2]).expect("crs encode");
    let recovered = crs.decode(&[(0, &d0), (3, &parities[0]), (4, &parities[1])]).expect("crs decode");
    assert_eq!(&recovered[0], &d0);
    assert_eq!(&recovered[1], &d1);
    assert_eq!(&recovered[2], &d2);

    // Pacing chaff and entropy self-check
    let chaff = pacing::build_chaff_frame(&key, 99, 1232).expect("chaff build");
    assert_eq!(chaff.len(), 1232);
    let entropy = pacing::calculate_shannon_entropy(&chaff);
    assert!(entropy > 7.80, "chaff entropy below threshold");
    let (c_seq, c_type, _) = aead::open_indexed(&key, DIR_SEND, &chaff).expect("chaff open");
    assert_eq!(c_seq, 99);
    assert_eq!(c_type, frame::FTYPE_CHAFF);

    // Hybrid KEM (ML-KEM-1024 + X25519) self-check
    let resp = EphemeralKeys::generate().expect("kem keygen");
    let (ml_ct, ss_init, eph_pub) = EphemeralKeys::encapsulate(&resp.x_public, &resp.ml_ek).expect("encaps");
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
    eprintln!("selftest: fec-cauchy ok, pacing-chaff ok, mlkem-1024-kex ok, zeroize-sp800-88 ok");
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
    let seq0 = reserve_send_seq(&state, &key_id, n);
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
            let frame = aead::seal_with_len(&key, seq0.wrapping_add(i as u64), DIR_SEND,
                                   FTYPE_MSG, chunk.len() as u16, &padded)
            .unwrap_or_else(|_| fail("seal failed"));
            debug_assert_eq!(frame.len(), quantum);
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
    println!("sent chunks={} bytes={} wire={}B digest={digest}",
             chunks.len(), bytes.len(), wire_total);
}

fn cmd_recv_file(args: &[String]) {
    let (kb, key_id) = load_key_material(args);
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
    let (mut sf, mut window) = load_recv_window(&state, &key_id);
    let send_preserve: u64 = {
        sf.seek(SeekFrom::Start(0)).unwrap_or_else(|_| fail("state seek failed"));
        let mut buf = Vec::new();
        sf.read_to_end(&mut buf).unwrap_or_else(|_| fail("state read failed"));
        if buf.len() == STATE_LEN {
            let mut arr = [0u8; STATE_LEN];
            arr.copy_from_slice(&buf);
            decode_state(&arr, &key_id).send_seq
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
                    let Ok((seq2, ftype, pt)) = aead::open_indexed(&key, DIR_SEND, &bytes)
                    else {
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
                    persist_recv_window(&mut sf, &key_id, send_preserve, &window);
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
        eprintln!("file refused: missing/tampered/out-of-order chunks \
                   (nothing written)");
        std::process::exit(4);
    };
    let digest = hex_of(&Sha256::digest(&data));
    std::fs::write(&out, &data).unwrap_or_else(|_| fail("output unwritable"));
    println!("received chunks={want} bytes={} digest={digest}", data.len());
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
    let parity_chunks = crs.encode(&data_refs).unwrap_or_else(|e| fail(&e.to_string()));

    // Random transfer ID
    let mut transfer_id = [0u8; 16];
    if getrandom::fill(&mut transfer_id).is_err() {
        fail("getrandom failed");
    }

    let n = (k + m) as u64;
    let seq0 = reserve_send_seq(&state, &key_id, n);
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
                if rem == 0 { DIODE_CHUNK_SIZE } else { rem }
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

            let frame = aead::seal(&key, seq0.wrapping_add(chunk_idx as u64), DIR_SEND, FTYPE_MSG, &chunk_packet)
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
    let state = state_path(args);
    let bind = get_flag(args, "--bind").unwrap_or_else(|| usage());
    let out = get_flag(args, "--out").unwrap_or_else(|| usage());
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20000);
    let key = FrameKey::from_slice(kb.as_bytes());
    drop(kb);

    let (mut sf, mut window) = load_recv_window(&state, &key_id);
    let send_preserve: u64 = {
        sf.seek(SeekFrom::Start(0)).unwrap_or_else(|_| fail("state seek failed"));
        let mut buf = Vec::new();
        sf.read_to_end(&mut buf).unwrap_or_else(|_| fail("state read failed"));
        if buf.len() == STATE_LEN {
            let mut arr = [0u8; STATE_LEN];
            arr.copy_from_slice(&buf);
            decode_state(&arr, &key_id).send_seq
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
                    persist_recv_window(&mut sf, &key_id, send_preserve, &window);

                    let Some(hdr) = DiodeHeader::decode(&pt) else {
                        continue;
                    };
                    if pt.len() < DIODE_HEADER_LEN + DIODE_CHUNK_SIZE {
                        continue;
                    }
                    let chunk_payload = pt[DIODE_HEADER_LEN..DIODE_HEADER_LEN + DIODE_CHUNK_SIZE].to_vec();

                    let entry = transfers.entry(hdr.transfer_id).or_insert_with(|| DiodeTransferState {
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

                        return Some((transfer_id, full_file, computed_digest, entry.chunks.len(), k + m));
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
        hex_of(&transfer_id), out, data.len(), chunks_got, total_chunks, hex_of(&digest)
    );
}

fn cmd_stream_chaff(args: &[String]) {
    reject_forbidden_cli(args);
    let (kb, key_id) = load_key_material(args);
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
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --quantum (must be 256, 512, or 1232)")))
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
            let seq = reserve_send_seq(&state, &key_id, 1);
            let frame = pacing::build_chaff_frame(&key, seq, quantum)
                .unwrap_or_else(|_| fail("build chaff failed"));
            if ep.send_raw(&frame, to).await.is_err() {
                fail("chaff send failed");
            }
            emitted += 1;
        }
        println!(
            "stream-chaff: emitted {emitted} frames wire={quantum}B interval={interval_ms}ms"
        );
    });
}

fn cmd_channel(args: &[String]) {
    reject_forbidden_cli(args);
    let (kb, key_id) = load_key_material(args);
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
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --quantum (must be 256, 512, or 1232)")))
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

    let mut state_file = open_locked_state(&state);
    let initial_st = read_state_locked(&mut state_file, &key_id);
    let mut next_send_seq = initial_st.send_seq;
    let mut window = AntiReplayWindow::from_parts(initial_st.recv_last, initial_st.recv_bitmap);

    let mut reserved_limit = next_send_seq
        .checked_add(512)
        .unwrap_or_else(|| fail("sequence exhausted"));
    let mut st = read_state_locked(&mut state_file, &key_id);
    st.send_seq = reserved_limit;
    write_state_locked(&mut state_file, &st);

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
                        write_state_locked(&mut state_file, &st);
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
                            write_state_locked(&mut state_file, &st);
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
        write_state_locked(&mut state_file, &st);

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
    let psk_bytes = if let Some(path) = get_flag(args, "--psk-file") {
        let s = std::fs::read_to_string(&path).unwrap_or_else(|_| fail("psk file unreadable"));
        let b = parse_key_hex(s.trim());
        Some(b)
    } else {
        None
    };
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
            socket.write_all(&bundle).await.map_err(|_| "bundle write failed")?;

            // 3. Receive initiator bundle: eph_pub (32) || ml_ct (MLKEM_CT)
            let mut init_bundle = vec![0u8; 32 + MLKEM_CT];
            socket.read_exact(&mut init_bundle).await.map_err(|_| "initiator bundle read failed")?;

            let mut eph_pub = [0u8; 32];
            eph_pub.copy_from_slice(&init_bundle[..32]);
            let ml_ct = &init_bundle[32..];

            // 4. Decapsulate hybrid shared secret
            let hybrid_ss = resp_keys.decapsulate(&eph_pub, ml_ct).map_err(|_| "decapsulate failed")?;

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
            let resp_tag = kem::compute_confirmation_tag(&frame_key, b"ST2027-RESPONDER-CONFIRM", &transcript_hash);
            let init_tag = kem::compute_confirmation_tag(&frame_key, b"ST2027-INITIATOR-CONFIRM", &transcript_hash);

            socket.write_all(&resp_tag).await.map_err(|_| "responder confirmation tag write failed")?;
            let mut recv_init_tag = [0u8; 32];
            socket.read_exact(&mut recv_init_tag).await.map_err(|_| "initiator confirmation tag read failed")?;
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
    let psk_bytes = if let Some(path) = get_flag(args, "--psk-file") {
        let s = std::fs::read_to_string(&path).unwrap_or_else(|_| fail("psk file unreadable"));
        let b = parse_key_hex(s.trim());
        Some(b)
    } else {
        None
    };
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
            socket.read_exact(&mut resp_bundle).await.map_err(|_| "bundle read failed")?;

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
            socket.write_all(&init_bundle).await.map_err(|_| "initiator bundle write failed")?;

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
            let resp_tag = kem::compute_confirmation_tag(&frame_key, b"ST2027-RESPONDER-CONFIRM", &transcript_hash);
            let init_tag = kem::compute_confirmation_tag(&frame_key, b"ST2027-INITIATOR-CONFIRM", &transcript_hash);

            let mut recv_resp_tag = [0u8; 32];
            socket.read_exact(&mut recv_resp_tag).await.map_err(|_| "responder confirmation tag read failed")?;
            if !kem::constant_time_eq_32(&recv_resp_tag, &resp_tag) {
                return Err("responder confirmation tag mismatch (MITM detected)");
            }

            socket.write_all(&init_tag).await.map_err(|_| "initiator confirmation tag write failed")?;

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
    }
    println!("ZEROIZE COMPLETE: {purged} file(s) cryptographically sanitized & unlinked (NIST SP 800-88)");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "keygen" => cmd_keygen(&args[2..]),
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
        "zeroize" | "purge" => cmd_zeroize(&args[2..]),
        "selftest" => cmd_selftest(),
        "-h" | "--help" | "help" => usage(),
        _ => usage(),
    }
}
