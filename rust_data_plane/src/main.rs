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

use destroyer_core::aead::{self, FrameKey, DIR_SEND};
use destroyer_core::frame::{self, FTYPE_MSG};
use destroyer_core::net::{Endpoint, MAX_DATAGRAM};
use destroyer_core::replay::AntiReplayWindow;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::time::Duration;
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
         send   --key-file PATH|--key-stdin --state PATH --to ADDR --msg TEXT\n\
         recv   --key-file PATH|--key-stdin --state PATH --bind ADDR [--count N] [--timeout-ms MS]\n\
         send-file --key-file PATH|--key-stdin --state PATH --to ADDR --file PATH\n\
         recv-file --key-file PATH|--key-stdin --state PATH --bind ADDR --out PATH --count K [--timeout-ms MS]\n\
         selftest                        deterministic module self-checks\n\
         \n\
         send-file splits at the 1205B quantum with incrementing seq; recv-file\n\
         accepts only K consecutive seqs, reassembles, prints SHA-256, and\n\
         writes the file. Any gap/tamper/timeout: exit 4, nothing written.\n\
         \n\
         Security: --seq and --key HEX are REFUSED. Seq comes only from the\n\
         locked --state file (monotonic, persisted before encrypt). Key NEVER\n\
         appears in argv: provision via --key-file (0600) or --key-stdin.\n\
         Key NEVER negotiates here: provision it from the audited PQ\n\
         handshake (secure_transmit_2027.py) or offline ceremony."
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
/// Returns (key_bytes, key_id). Key file should be 0600 on Unix.
fn load_key_material(args: &[String]) -> ([u8; 32], [u8; 16]) {
    reject_forbidden_cli(args);
    let from_file = get_flag(args, "--key-file");
    let from_stdin = has_flag(args, "--key-stdin");
    if from_file.is_some() == from_stdin {
        fail("exactly one of --key-file PATH or --key-stdin is required");
    }
    let mut hex_z: Zeroizing<String> = if let Some(path) = from_file {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).unwrap_or_else(|_| fail("key file unreadable"));
            if meta.permissions().mode() & 0o077 != 0 {
                fail("key file must be 0600 (group/other readable refused)");
            }
        }
        let mut s = std::fs::read_to_string(&path).unwrap_or_else(|_| fail("key file unreadable"));
        // Zeroize the file buffer copy held by Rust String after parse.
        let z = Zeroizing::new(s.clone());
        s.zeroize();
        z
    } else {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .unwrap_or_else(|_| fail("key stdin unreadable"));
        Zeroizing::new(s)
    };
    let mut bytes = parse_key_hex(&hex_z);
    hex_z.zeroize();
    let digest = Sha256::digest(bytes);
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&digest[..16]);
    // Caller builds FrameKey then zeroizes `bytes`.
    let out = bytes;
    bytes.zeroize();
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&out)
                .unwrap_or_else(|_| fail("key out unwritable (must not exist)"));
            f.write_all(hex.as_bytes()).unwrap_or_else(|_| fail("key out unwritable"));
            f.sync_all().unwrap_or_else(|_| fail("key out sync failed"));
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&out, hex.as_bytes()).unwrap_or_else(|_| fail("key out unwritable"));
        }
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

fn cmd_send(args: &[String]) {
    let (mut kb, key_id) = load_key_material(args);
    let state = state_path(args);
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let msg = get_flag(args, "--msg").unwrap_or_else(|| usage());
    if msg.len() > MAX_PAYLOAD {
        kb.zeroize();
        fail("payload exceeds largest quantum (1205B)");
    }
    // Reserve BEFORE encrypt: crash skips, never reuses (NIST SP 800-38D).
    let seq = reserve_send_seq(&state, &key_id, 1);
    let key = FrameKey::from_bytes(kb);
    kb.zeroize();
    let frame = aead::seal(&key, seq, DIR_SEND, FTYPE_MSG, msg.as_bytes())
        .unwrap_or_else(|_| fail("seal failed"));
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
    let (mut kb, key_id) = load_key_material(args);
    let state = state_path(args);
    let bind = get_flag(args, "--bind").unwrap_or_else(|| usage());
    let want: u64 = get_flag(args, "--count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --count")))
        .unwrap_or(1);
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(5000);
    let key = FrameKey::from_bytes(kb);
    kb.zeroize();
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
                    let seq = match aead::peek_seq(&bytes) {
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
}

fn cmd_send_file(args: &[String]) {
    let (mut kb, key_id) = load_key_material(args);
    let state = state_path(args);
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let path = get_flag(args, "--file").unwrap_or_else(|| usage());
    let bytes = std::fs::read(&path).unwrap_or_else(|_| fail("file unreadable"));
    if bytes.len() > MAX_STREAM_BYTES {
        kb.zeroize();
        fail("file exceeds 16 MiB stream cap");
    }
    let chunks = frame::split_payload(&bytes);
    let digest = hex_of(&Sha256::digest(&bytes));
    let n = chunks.len() as u64;
    if n == 0 {
        kb.zeroize();
        fail("file empty refused");
    }
    // Reserve the full range BEFORE sealing any chunk.
    let seq0 = reserve_send_seq(&state, &key_id, n);
    let key = FrameKey::from_bytes(kb);
    kb.zeroize();
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
            let frame = aead::seal(&key, seq0.wrapping_add(i as u64), DIR_SEND,
                                   FTYPE_MSG, chunk)
            .unwrap_or_else(|_| fail("seal failed"));
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
    let (mut kb, key_id) = load_key_material(args);
    let state = state_path(args);
    let bind = get_flag(args, "--bind").unwrap_or_else(|| usage());
    let out = get_flag(args, "--out").unwrap_or_else(|| usage());
    let want: usize = get_flag(args, "--count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --count")))
        .unwrap_or_else(|| fail("--count K (chunk count) is required"));
    if want == 0 || want * MAX_PAYLOAD > MAX_STREAM_BYTES {
        kb.zeroize();
        fail("count outside 16 MiB stream cap");
    }
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(15000);
    let key = FrameKey::from_bytes(kb);
    kb.zeroize();
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
                    let seq = match aead::peek_seq(&bytes) {
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "keygen" => cmd_keygen(&args[2..]),
        "send" => cmd_send(&args[2..]),
        "recv" => cmd_recv(&args[2..]),
        "send-file" => cmd_send_file(&args[2..]),
        "recv-file" => cmd_recv_file(&args[2..]),
        "selftest" => cmd_selftest(),
        "-h" | "--help" | "help" => usage(),
        _ => usage(),
    }
}
