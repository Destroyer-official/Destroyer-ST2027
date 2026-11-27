//! secure-transmit-tor — privilege-separated embedded Arti Tor v3 transport bridge.
//!
//! Cryptographic Isolation Boundary (MILS):
//! This process holds ONLY ephemeral Tor v3 onion identity keys (`ArtiEphemeralKeystore`),
//! Restricted Discovery (`ClientAuthV3`) x25519 credentials, and Tor circuit handles.
//! It NEVER receives `--psk-file`, `ML-DSA-87` signing keys, `ML-KEM-1024` / `P-384`
//! session secrets, TPM/HSM handles, or unencrypted ST2027 payloads.
//! All communication with `secure-transmit` flows strictly over anonymous OS pipes
//! (`stdin` / `stdout` length-prefixed frames) — zero localhost SOCKS5 ports opened.

use std::fs::{self, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{KeystoreSelector, TorClient};
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tor_cell::relaycell::msg::{Connected, End};
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_hscrypto::pk::{HsClientDescEncKey, HsClientDescEncSecretKey, HsId};
use tor_hsservice::config::restricted_discovery::HsClientNickname;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::curve25519;
use tor_persist::hsnickname::HsNickname;
use tor_proto::stream::IncomingStreamRequest;
use zeroize::{Zeroize, Zeroizing};

/// Max frame size relayed between `secure-transmit` pipe and Arti `DataStream`
/// (covers Noise M2 = 8916B during handshake and quantized cells up to 1232B).
const MAX_IPC_FRAME_LEN: usize = 16 * 1024;
const DEFAULT_ONION_PORT: u16 = 443;

fn usage() -> ! {
    eprintln!(
        "secure-transmit-tor — privilege-separated embedded Arti v3 onion bridge\n\
         \n\
         Modes:\n\
           --mode client-auth-keygen [--out-pk PATH] [--out-sk PATH]\n\
           --mode responder [--port 443] [--client-auth-pk KEY|PATH] [--require-restricted-discovery]\n\
                            [--pt-binary PATH --pt-type webtunnel|obfs4 --pt-bridge LINE]\n\
           --mode initiator --to <56-char>.onion:<port> [--auth-sk-file PATH | --auth-sk-stdin]\n\
                            [--pt-binary PATH --pt-type webtunnel|obfs4 --pt-bridge LINE]\n"
    );
    std::process::exit(2);
}

fn get_flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn fail(msg: &str) -> ! {
    eprintln!("[TOR-BRIDGE-ERROR] {msg}");
    std::process::exit(1);
}

/// Restrictive volatile work directory wiped with 3-pass cryptographic purge on drop.
struct VolatileWorkDir {
    path: PathBuf,
}

impl VolatileWorkDir {
    fn create() -> io::Result<Self> {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).map_err(|_| io::Error::other("CSPRNG failure"))?;
        let tag = format!("st2027_arti_{}_{:016x}", std::process::id(), u64::from_ne_bytes(r));

        #[cfg(target_os = "linux")]
        let base = {
            let shm = Path::new("/dev/shm");
            if shm.is_dir() {
                shm.to_path_buf()
            } else {
                std::env::temp_dir()
            }
        };
        #[cfg(not(target_os = "linux"))]
        let base = std::env::temp_dir();

        let dir = base.join(tag);
        fs::create_dir_all(&dir)?;
        fs::create_dir_all(dir.join("state"))?;
        fs::create_dir_all(dir.join("cache"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(dir.join("state"), fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(dir.join("cache"), fs::Permissions::from_mode(0o700));
        }

        Ok(Self { path: dir })
    }

    fn state_dir(&self) -> PathBuf {
        self.path.join("state")
    }

    fn cache_dir(&self) -> PathBuf {
        self.path.join("cache")
    }
}

fn purge_file_3pass(p: &Path) {
    if !p.is_file() {
        return;
    }
    if let Ok(meta) = fs::metadata(p) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = fs::set_permissions(p, perms);
    }
    if let Ok(mut f) = OpenOptions::new().read(true).write(true).open(p) {
        let len = f.metadata().map(|m| m.len() as usize).unwrap_or(0).max(512);
        let chunk = len.min(64 * 1024);
        let mut buf = vec![0u8; chunk];
        if getrandom::fill(&mut buf).is_ok() {
            let _ = f.seek(SeekFrom::Start(0));
            let _ = f.write_all(&buf);
            let _ = f.sync_all();
        }
        buf.fill(0xFF);
        let _ = f.seek(SeekFrom::Start(0));
        let _ = f.write_all(&buf);
        let _ = f.sync_all();
        buf.fill(0x00);
        let _ = f.seek(SeekFrom::Start(0));
        let _ = f.write_all(&buf);
        let _ = f.sync_all();
        buf.zeroize();
        let _ = f.set_len(0);
    }
    let _ = fs::remove_file(p);
}

fn purge_dir_recursive(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                purge_dir_recursive(&p);
            } else {
                purge_file_3pass(&p);
            }
        }
    }
    let _ = fs::remove_dir(dir);
}

impl Drop for VolatileWorkDir {
    fn drop(&mut self) {
        purge_dir_recursive(&self.path);
    }
}

/// Strictly validate a Tor v3 `<56-char-base32>.onion:<port>` endpoint (no clearnet/IP/DNS).
pub fn parse_onion_v3_target(target: &str) -> Result<(String, u16, HsId), String> {
    let trimmed = target.trim();
    let (host, port) = if let Some((h, p_str)) = trimmed.rsplit_once(':') {
        let port: u16 = p_str
            .parse()
            .map_err(|_| "invalid Tor .onion target port".to_string())?;
        if port == 0 {
            return Err("invalid port 0 for Tor target".to_string());
        }
        (h.to_ascii_lowercase(), port)
    } else {
        (trimmed.to_ascii_lowercase(), DEFAULT_ONION_PORT)
    };

    if !host.ends_with(".onion") || host.len() != 62 {
        return Err("target must be a valid 56-char Tor v3 <addr>.onion[:port]".to_string());
    }
    let hsid = HsId::from_str(&host).map_err(|e| format!("invalid Tor v3 .onion address: {e}"))?;
    Ok((host, port, hsid))
}

fn parse_client_auth_pk(arg: &str) -> Result<HsClientDescEncKey, String> {
    let raw = if Path::new(arg).is_file() {
        fs::read_to_string(arg).map_err(|e| format!("failed to read client auth pk: {e}"))?
    } else {
        arg.to_string()
    };
    let s = raw.trim();
    HsClientDescEncKey::from_str(s)
        .map_err(|e| format!("invalid ClientAuthV3 public key (expected descriptor:x25519:<base32>): {e}"))
}

fn parse_client_auth_sk_hex(hex_str: &str) -> Result<HsClientDescEncSecretKey, String> {
    let clean = Zeroizing::new(hex_str.trim().to_string());
    if clean.len() != 64 {
        return Err("ClientAuthV3 secret key must be 64 hex characters (32 bytes)".to_string());
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    let (chunks, _) = clean.as_bytes().as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in secret key")?;
        raw[i] = u8::from_str_radix(s, 16).map_err(|_| "invalid hex in secret key")?;
    }
    let secret = curve25519::StaticSecret::from(*raw);
    Ok(HsClientDescEncSecretKey::from(secret))
}

fn cmd_client_auth_keygen(args: &[String]) {
    let mut seed = Zeroizing::new([0u8; 32]);
    if getrandom::fill(&mut *seed).is_err() {
        fail("CSPRNG failure generating ClientAuthV3 x25519 key");
    }
    let sk = curve25519::StaticSecret::from(*seed);
    let pk = curve25519::PublicKey::from(&sk);
    let desc_pk = HsClientDescEncKey::from(pk).to_string();
    let mut sk_hex = Zeroizing::new(String::with_capacity(64));
    for b in seed.iter() {
        sk_hex.push_str(&format!("{b:02x}"));
    }

    if let Some(out_pk) = get_flag(args, "--out-pk") {
        if let Err(e) = fs::write(&out_pk, format!("{desc_pk}\n")) {
            fail(&format!("failed to write --out-pk: {e}"));
        }
    } else {
        println!("CLIENT_AUTH_PK={desc_pk}");
    }

    if let Some(out_sk) = get_flag(args, "--out-sk") {
        if let Err(e) = fs::write(&out_sk, format!("{}\n", *sk_hex)) {
            fail(&format!("failed to write --out-sk: {e}"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&out_sk, fs::Permissions::from_mode(0o600));
        }
    } else {
        println!("CLIENT_AUTH_SK_HEX={}", *sk_hex);
    }
}

fn build_tor_config(
    work: &VolatileWorkDir,
    args: &[String],
) -> Result<arti_client::TorClientConfig, String> {
    let mut cfg = TorClientConfigBuilder::from_directories(work.state_dir(), work.cache_dir());
    cfg.storage()
        .keystore()
        .primary()
        .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));
    cfg.vanguards()
        .mode(ExplicitOrAuto::Explicit(VanguardMode::Full));

    if let Some(pt_bin) = get_flag(args, "--pt-binary") {
        let pt_type = get_flag(args, "--pt-type")
            .ok_or_else(|| "--pt-type <webtunnel|obfs4> is required with --pt-binary".to_string())?;
        let bridge_line = get_flag(args, "--pt-bridge")
            .ok_or_else(|| "--pt-bridge <bridge-line> is required with --pt-binary".to_string())?;

        let bridge: BridgeConfigBuilder = bridge_line
            .parse()
            .map_err(|e| format!("invalid --pt-bridge line: {e}"))?;
        cfg.bridges().bridges().push(bridge);

        let proto = pt_type
            .parse()
            .map_err(|e| format!("invalid --pt-type '{pt_type}': {e}"))?;
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec![proto])
            .path(CfgPath::new_literal(PathBuf::from(pt_bin)))
            .run_on_startup(true);
        cfg.bridges().transports().push(transport);
    }

    cfg.build().map_err(|e| format!("failed to build TorClientConfig: {e}"))
}

async fn write_ipc_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    if data.is_empty() || data.len() > MAX_IPC_FRAME_LEN || data.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPC frame size out of bounds",
        ));
    }
    w.write_all(&(data.len() as u16).to_be_bytes()).await?;
    w.write_all(data).await?;
    w.flush().await
}

async fn read_ipc_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; 2];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u16::from_be_bytes(hdr) as usize;
    if len == 0 || len > MAX_IPC_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed IPC frame length",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Symmetrically bridge anonymous OS pipe (`stdin`/`stdout`) and an Arti `DataStream`.
async fn pump_pipe_to_tor_stream<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> io::Result<()> {
    let (mut tor_r, mut tor_w) = tokio::io::split(stream);
    let mut pipe_in = tokio::io::stdin();
    let mut pipe_out = tokio::io::stdout();

    let up = async {
        while let Some(frame) = read_ipc_frame(&mut pipe_in).await? {
            write_ipc_frame(&mut tor_w, &frame).await?;
        }
        let _ = tor_w.shutdown().await;
        io::Result::<()>::Ok(())
    };

    let down = async {
        while let Some(frame) = read_ipc_frame(&mut tor_r).await? {
            write_ipc_frame(&mut pipe_out, &frame).await?;
        }
        let _ = pipe_out.flush().await;
        io::Result::<()>::Ok(())
    };

    tokio::select! {
        res = up => res,
        res = down => res,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

async fn run_responder(args: &[String], work: &VolatileWorkDir) -> Result<(), String> {
    let port: u16 = get_flag(args, "--port")
        .map(|s| s.parse().map_err(|_| "invalid --port".to_string()))
        .transpose()?
        .unwrap_or(DEFAULT_ONION_PORT);
    if port == 0 {
        return Err("--port must be 1..=65535".to_string());
    }

    let require_restricted = has_flag(args, "--require-restricted-discovery");
    let client_auth_pk = get_flag(args, "--client-auth-pk")
        .map(|s| parse_client_auth_pk(&s))
        .transpose()?;
    if require_restricted && client_auth_pk.is_none() {
        return Err("--require-restricted-discovery requires --client-auth-pk".to_string());
    }

    let tor_cfg = build_tor_config(work, args)?;
    eprintln!("[TOR-BRIDGE] Bootstrapping ephemeral Arti Tor client (Vanguards + RAM keystore)...");
    let client = TorClient::create_bootstrapped(tor_cfg)
        .await
        .map_err(|e| format!("Arti bootstrap failed: {e}"))?;

    let mut svc_cfg = OnionServiceConfigBuilder::default();
    let nickname = HsNickname::new("st2027_ephem".to_string())
        .map_err(|e| format!("invalid HS nickname: {e}"))?;
    svc_cfg.nickname(nickname);

    if let Some(auth_pk) = client_auth_pk {
        let client_nick = HsClientNickname::from_str("peer0")
            .map_err(|e| format!("invalid client nickname: {e}"))?;
        let rd = svc_cfg.restricted_discovery();
        rd.enabled(true);
        rd.static_keys().access().push((client_nick, auth_pk));
        eprintln!("[TOR-BRIDGE] Restricted Discovery (ClientAuthV3) ENFORCED on descriptor");
    }

    let built_svc = svc_cfg
        .build()
        .map_err(|e| format!("OnionServiceConfig build failed: {e}"))?;

    let (svc, rend_requests) = client
        .launch_onion_service(built_svc)
        .map_err(|e| format!("launch_onion_service failed: {e}"))?
        .ok_or_else(|| "onion service returned None".to_string())?;

    let hsid = svc
        .onion_address()
        .ok_or_else(|| "ephemeral onion address unavailable".to_string())?;
    let onion_str = hsid.display_unredacted().to_string();
    eprintln!("[ONION] {onion_str}:{port}");

    let mut stream_reqs = Box::pin(tor_hsservice::handle_rend_requests(rend_requests));
    let mut accepted = None;
    while let Some(req) = stream_reqs.next().await {
        match req.request() {
            IncomingStreamRequest::Begin(begin) if begin.port() == port => {
                let ds = req
                    .accept(Connected::new_empty())
                    .await
                    .map_err(|e| format!("failed to accept rendezvous stream: {e}"))?;
                accepted = Some(ds);
                break;
            }
            _ => {
                let _ = req.reject(End::new_misc()).await;
            }
        }
    }

    let Some(data_stream) = accepted else {
        return Err("onion service closed before receiving an authorized stream".to_string());
    };
    eprintln!("[CONNECTED]");

    // Reject any concurrent secondary rendezvous attempts while session is active.
    let reject_extra = async {
        while let Some(extra) = stream_reqs.next().await {
            let _ = extra.shutdown_circuit();
        }
    };

    tokio::select! {
        res = pump_pipe_to_tor_stream(data_stream) => res.map_err(|e| format!("stream bridge IO error: {e}")),
        _ = reject_extra => Ok(()),
    }
}

async fn run_initiator(args: &[String], work: &VolatileWorkDir) -> Result<(), String> {
    let target = get_flag(args, "--to")
        .ok_or_else(|| "--to <56-char>.onion:<port> is required in initiator mode".to_string())?;
    let (host, port, hsid) = parse_onion_v3_target(&target)?;

    let auth_sk_hex = if has_flag(args, "--auth-sk-stdin") {
        let mut s = Zeroizing::new(String::new());
        io::stdin()
            .read_line(&mut s)
            .map_err(|e| format!("failed reading --auth-sk-stdin: {e}"))?;
        Some(s)
    } else if let Some(path) = get_flag(args, "--auth-sk-file") {
        let s = fs::read_to_string(&path)
            .map_err(|e| format!("failed reading --auth-sk-file: {e}"))?;
        Some(Zeroizing::new(s))
    } else {
        None
    };

    let tor_cfg = build_tor_config(work, args)?;
    eprintln!("[TOR-BRIDGE] Bootstrapping ephemeral Arti Tor client...");
    let client = TorClient::create_bootstrapped(tor_cfg)
        .await
        .map_err(|e| format!("Arti bootstrap failed: {e}"))?;

    if let Some(ref sk_hex) = auth_sk_hex {
        let sk = parse_client_auth_sk_hex(sk_hex)?;
        client
            .insert_service_discovery_key(KeystoreSelector::Primary, hsid, sk)
            .map_err(|e| format!("failed inserting ClientAuthV3 key into RAM keystore: {e}"))?;
        eprintln!("[TOR-BRIDGE] ClientAuthV3 discovery key loaded into RAM keystore");
    }

    eprintln!("[TOR-BRIDGE] Dialing {host}:{port} via Tor v3 rendezvous circuit...");
    let data_stream = client
        .connect((host.as_str(), port))
        .await
        .map_err(|e| format!("Tor .onion connect failed: {e}"))?;
    eprintln!("[CONNECTED]");

    pump_pipe_to_tor_stream(data_stream)
        .await
        .map_err(|e| format!("stream bridge IO error: {e}"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = get_flag(&args, "--mode").unwrap_or_else(|| usage());

    if mode == "client-auth-keygen" {
        cmd_client_auth_keygen(&args);
        return;
    }

    let work = VolatileWorkDir::create()
        .unwrap_or_else(|e| fail(&format!("failed creating volatile Arti dir: {e}")));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| fail(&format!("tokio runtime error: {e}")));

    let res = rt.block_on(async {
        match mode.as_str() {
            "responder" => run_responder(&args, &work).await,
            "initiator" => run_initiator(&args, &work).await,
            _ => Err(format!("unknown --mode '{mode}'")),
        }
    });

    drop(work);
    if let Err(e) = res {
        fail(&e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_v3_validation_rejects_clearnet_and_malformed() {
        // Reject clearnet / IPs / v2 / bad checksum (no local DNS leaks possible).
        assert!(parse_onion_v3_target("example.com:443").is_err());
        assert!(parse_onion_v3_target("127.0.0.1:9050").is_err());
        assert!(parse_onion_v3_target("facebookcorewwwi.onion:80").is_err());
        assert!(parse_onion_v3_target("a".repeat(56).as_str()).is_err());

        // Real valid v3 checksum onion (Tor Project v3 example address):
        let valid = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:443";
        let (host, port, _id) = parse_onion_v3_target(valid).expect("valid v3 onion");
        assert_eq!(port, 443);
        assert_eq!(host.len(), 62);
    }

    #[test]
    fn client_auth_hex_and_descriptor_parse() {
        let seed = [0x11u8; 32];
        let sk_hex = "11".repeat(32);
        let sk = parse_client_auth_sk_hex(&sk_hex).expect("valid hex");
        let pk_str = HsClientDescEncKey::from(&sk).to_string();
        let parsed = parse_client_auth_pk(&pk_str).expect("valid descriptor:x25519");
        let expected = HsClientDescEncKey::from(curve25519::PublicKey::from(
            &curve25519::StaticSecret::from(seed),
        ));
        assert_eq!(parsed, expected);
        assert!(parse_client_auth_sk_hex("abcd").is_err());
    }

    #[test]
    fn volatile_workdir_wipes_and_unlinks_cleanly() {
        let dir_path;
        let secret_file;
        {
            let w = VolatileWorkDir::create().unwrap();
            dir_path = w.path.clone();
            secret_file = w.state_dir().join("ephem_test.bin");
            fs::write(&secret_file, b"TOP-SECRET-TOR-CACHE-DATA").unwrap();
            assert!(secret_file.exists());
        }
        assert!(!secret_file.exists());
        assert!(!dir_path.exists());
    }

    #[tokio::test]
    async fn ipc_frame_pump_enforces_bounds() {
        let (mut w, mut r) = tokio::io::duplex(4096);
        assert!(write_ipc_frame(&mut w, &[]).await.is_err());
        write_ipc_frame(&mut w, b"hello-tor-cell").await.unwrap();
        let got = read_ipc_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(got, b"hello-tor-cell");

        w.write_all(&((MAX_IPC_FRAME_LEN + 1) as u16).to_be_bytes())
            .await
            .unwrap();
        w.flush().await.unwrap();
        assert!(read_ipc_frame(&mut r).await.is_err());
    }
}
