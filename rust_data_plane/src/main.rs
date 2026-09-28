//! secure-transmit — standalone data-plane executor (zero-Python binary).
//!
//! SCOPE (explicit boundary, no handshake claims):
//! - This binary executes the TESTED data-plane modules only: AEAD framing
//!   (`aead`), fixed quanta (`frame`/`pad`), 64-bit anti-replay (`replay`),
//!   silent-drop UDP transport (`net`), constant-time compare (`ct`).
//! - Session-key provisioning (ML-KEM-1024 PQ handshake, ML-DSA-87 PKI,
//!   SPO/DPO ceremony, TLS 1.3) remains in the audited Python control plane
//!   (`secure_transmit_2027.py`, `noise_pq.py`, `trust_anchor.py`,
//!   `spo_dpo.py`). This binary NEVER negotiates keys: `--key` arrives from
//!   that plane (or offline ceremony) and is zeroized after use.
//! - One direction per invocation: `send` seals with DIR_SEND, `recv` opens
//!   with DIR_SEND. Bidirectional traffic = two sessions with opposite roles
//!   (same doctrine as `SecureEngine::establish_session(is_initiator)`).
//! - Bulk cipher here is the data-plane AEAD (ChaCha20-Poly1305) as tested in
//!   `aead.rs`/64 Rust tests. CNSA-strict session suites (AES-256-GCM) are
//!   enforced by the Python session layer; this binary seals exactly what it
//!   is handed under the frame key it is given.
//!
//! FAIL-CLOSED CLI: bad key length, oversize payload, unauthenticated traffic,
//! and timeouts exit non-zero with a one-line stderr reason. Nothing is ever
//! signaled back to the peer (stealth discipline from `net.rs`).

use destroyer_core::aead::{self, FrameKey, DIR_SEND};
use destroyer_core::frame::{self, FTYPE_MSG};
use destroyer_core::net::{Endpoint, MAX_DATAGRAM};
use destroyer_core::replay::AntiReplayWindow;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::Duration;
use zeroize::Zeroize;

const VERSION: &str = "0.2.0";
/// Largest user payload accepted by `send` (largest fixed quantum, frame.rs).
const MAX_PAYLOAD: usize = 1205;
/// Stream cap mirrored from the Python plane (destroyer_node 16 MiB):
/// a single file transfer never exceeds this; larger inputs are refused.
const MAX_STREAM_BYTES: usize = 16 << 20;

fn usage() -> ! {
    eprintln!(
        "secure-transmit {VERSION} — standalone data-plane executor\n\
         \n\
         keygen                          print fresh 32B frame key (hex)\n\
         send   --key HEX --to ADDR --msg TEXT [--seq N]\n\
         recv   --key HEX --bind ADDR [--count N] [--timeout-ms MS]\n\
         send-file --key HEX --to ADDR --file PATH [--seq N]\n\
         recv-file --key HEX --bind ADDR --out PATH --count K [--timeout-ms MS]\n\
         selftest                        deterministic module self-checks\n\
         \n\
         send-file splits at the 1205B quantum with incrementing seq; recv-file\n\
         accepts only K consecutive seqs, reassembles, prints SHA-256, and\n\
         writes the file. Any gap/tamper/timeout: exit 4, nothing written.\n\
         \n\
         Key NEVER negotiates here: provision --key from the audited PQ\n\
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

fn parse_key(hex: &str) -> [u8; 32] {
    let h = hex.trim();
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

fn cmd_keygen() {
    let mut k = [0u8; 32];
    if getrandom::fill(&mut k).is_err() {
        fail("OS RNG unavailable");
    }
    print!("{}", hex_of(&k));
    k.zeroize();
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
    let key_hex = get_flag(args, "--key").unwrap_or_else(|| usage());
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let msg = get_flag(args, "--msg").unwrap_or_else(|| usage());
    let seq: u64 = get_flag(args, "--seq")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --seq")))
        .unwrap_or(1);
    if msg.len() > MAX_PAYLOAD {
        fail("payload exceeds largest quantum (1205B)");
    }
    let mut key_bytes = parse_key(&key_hex);
    let key = FrameKey::from_bytes(key_bytes);
    key_bytes.zeroize();
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
    let key_hex = get_flag(args, "--key").unwrap_or_else(|| usage());
    let bind = get_flag(args, "--bind").unwrap_or_else(|| usage());
    let want: u64 = get_flag(args, "--count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --count")))
        .unwrap_or(1);
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(5000);
    let mut key_bytes = parse_key(&key_hex);
    let key = FrameKey::from_bytes(key_bytes);
    key_bytes.zeroize();
    let mut window = AntiReplayWindow::new();
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
                    let Ok((seq, ftype, pt)) = aead::open_indexed(&key, DIR_SEND, &bytes)
                    else {
                        ep.note_auth_drop();
                        continue;
                    };
                    if !window.check_and_update(seq) {
                        ep.note_auth_drop();
                        continue;
                    }
                    if ftype == FTYPE_MSG {
                        println!("seq={seq} {}", String::from_utf8_lossy(&pt));
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
    assert!(w.check_and_update(7));
    assert!(!w.check_and_update(7), "replay accepted");
    assert!(f.len() <= MAX_DATAGRAM, "quantum exceeds MTU");
    eprintln!("selftest: aead-roundtrip ok, tamper-reject ok, replay ok, mtu ok");
}

fn cmd_send_file(args: &[String]) {
    let key_hex = get_flag(args, "--key").unwrap_or_else(|| usage());
    let to: SocketAddr = get_flag(args, "--to")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| fail("bad --to ADDR (host:port)"));
    let path = get_flag(args, "--file").unwrap_or_else(|| usage());
    let seq0: u64 = get_flag(args, "--seq")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --seq")))
        .unwrap_or(1);
    let bytes = std::fs::read(&path).unwrap_or_else(|_| fail("file unreadable"));
    if bytes.len() > MAX_STREAM_BYTES {
        fail("file exceeds 16 MiB stream cap");
    }
    let mut key_bytes = parse_key(&key_hex);
    let key = FrameKey::from_bytes(key_bytes);
    key_bytes.zeroize();
    let chunks = frame::split_payload(&bytes);
    let digest = hex_of(&Sha256::digest(&bytes));
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
    let key_hex = get_flag(args, "--key").unwrap_or_else(|| usage());
    let bind = get_flag(args, "--bind").unwrap_or_else(|| usage());
    let out = get_flag(args, "--out").unwrap_or_else(|| usage());
    let want: usize = get_flag(args, "--count")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --count")))
        .unwrap_or_else(|| fail("--count K (chunk count) is required"));
    if want == 0 || want * MAX_PAYLOAD > MAX_STREAM_BYTES {
        fail("count outside 16 MiB stream cap");
    }
    let timeout_ms: u64 = get_flag(args, "--timeout-ms")
        .map(|s| s.parse().unwrap_or_else(|_| fail("bad --timeout-ms")))
        .unwrap_or(15000);
    let mut key_bytes = parse_key(&key_hex);
    let key = FrameKey::from_bytes(key_bytes);
    key_bytes.zeroize();
    let mut window = AntiReplayWindow::new();
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
                    let Ok((seq, ftype, pt)) = aead::open_indexed(&key, DIR_SEND, &bytes)
                    else {
                        ep.note_auth_drop();
                        continue;
                    };
                    if ftype != FTYPE_MSG || !window.check_and_update(seq) {
                        ep.note_auth_drop();
                        continue;
                    }
                    // open_indexed returns true-plaintext (padding stripped).
                    let plain: Vec<u8> = pt.into();
                    got.push((seq, plain));
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
        "keygen" => cmd_keygen(),
        "send" => cmd_send(&args[2..]),
        "recv" => cmd_recv(&args[2..]),
        "send-file" => cmd_send_file(&args[2..]),
        "recv-file" => cmd_recv_file(&args[2..]),
        "selftest" => cmd_selftest(),
        "-h" | "--help" | "help" => usage(),
        _ => usage(),
    }
}
