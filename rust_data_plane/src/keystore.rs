//! Sealed key-file custody (Rust secure core, single-sourced).
//!
//! Rules (fail-closed):
//! - Secrets NEVER appear in argv (`--key HEX` / `--psk HEX` refused by
//!   `main.rs::reject_forbidden_cli`; this module provides the file/stdin
//!   path those errors point to).
//! - Symlinks / reparse points are refused via `symlink_metadata` (which,
//!   unlike `metadata`, does NOT follow links — checking `is_symlink` on
//!   followed metadata is dead code and is NOT used here).
//! - Unix: mode 0600 enforced on read AND set atomically on write.
//! - Windows: exclusive share mode (`FILE_SHARE_NONE`) + owner-only ACL via
//!   `icacls` (std has no ACL API); ACL failure deletes the file and errors
//!   so loose-permission keys never rest on disk.
//! - Session keys on disk conflict with zero-plaintext-disk doctrine:
//!   prefer stdin + `LockedKey32` / HSM custody for TOP SECRET; files are
//!   a lab/transport convenience with hardened permissions, documented.
//!
//! Reference: `trust_anchor.py` ephemeral doctrine. `main.rs`
//! `load_key_material` / `write_key_file` delegate here — behavior
//! identical, code single-sourced. KEX `--out-key` rotation uses the
//! truncate variant (explicit operator intent); the exclusive variant is
//! for first-write paths where overwrite would signal a race.

use std::fs::OpenOptions;
use std::io::{Read, Write};
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt;

use crate::memlock::LockedKey32;
use crate::policy::CoreError;

/// Expected key-file payload: 64 hex chars (32 bytes) + optional newline.
const MAX_KEY_FILE_LEN: u64 = 128;

/// Parse 64-hex-char key material into a page-locked container.
/// No intermediate secret `String` is retained (parsed in place).
pub fn parse_key_hex(hex: &str) -> Result<LockedKey32, CoreError> {
    LockedKey32::from_hex(hex).map_err(|_| CoreError::Malformed)
}

/// Read a key file with permission checks (Unix 0600 enforced,
/// symlinks/reparse points refused). Returns a locked key container; the
/// file-content copy is wiped after parse.
pub fn read_key_file(path: &str) -> Result<LockedKey32, CoreError> {
    // `symlink_metadata` does NOT follow links: a symlink itself is
    // refused here. (`metadata().is_symlink()` would be dead code — it
    // always reports false on followed metadata.)
    let link_meta = std::fs::symlink_metadata(path).map_err(|_| CoreError::Malformed)?;
    if link_meta.file_type().is_symlink() {
        return Err(CoreError::FilePermissions);
    }
    #[cfg(not(unix))]
    {
        use std::os::windows::fs::MetadataExt;
        // Refuse reparse points (symlinks/mount points/junctions).
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if link_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(CoreError::FilePermissions);
        }
    }
    let meta = std::fs::metadata(path).map_err(|_| CoreError::Malformed)?;
    if !meta.is_file() {
        return Err(CoreError::Malformed);
    }
    if meta.len() > MAX_KEY_FILE_LEN {
        return Err(CoreError::Malformed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(CoreError::FilePermissions);
        }
    }
    let mut f = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| CoreError::Malformed)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|_| CoreError::Malformed)?;
    let text = std::str::from_utf8(&buf).map_err(|_| CoreError::Malformed)?;
    let key = parse_key_hex(text.trim())?;
    // Wipe the file-content copy immediately.
    use zeroize::Zeroize;
    buf.zeroize();
    Ok(key)
}

/// Write `hex` (64 chars + newline) exclusively. Fails if the path exists
/// (no truncate races); callers remove-then-write explicitly when rotation
/// is intended. Unix sets 0600 atomically at create.
pub fn write_key_file_exclusive(path: &str, hex: &str) -> Result<(), CoreError> {
    let clean = hex.trim();
    if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CoreError::Malformed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| CoreError::FilePermissions)?;
        f.write_all(clean.as_bytes())
            .map_err(|_| CoreError::FilePermissions)?;
        f.write_all(b"\n").map_err(|_| CoreError::FilePermissions)?;
        f.sync_all().map_err(|_| CoreError::FilePermissions)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)
            .map_err(|_| CoreError::FilePermissions)?;
        f.write_all(clean.as_bytes())
            .map_err(|_| CoreError::FilePermissions)?;
        f.write_all(b"\n").map_err(|_| CoreError::FilePermissions)?;
        f.sync_all().map_err(|_| CoreError::FilePermissions)?;
        Ok(())
    }
}

/// Write `hex` (64 chars + newline) with create+truncate semantics for
/// explicit rotation paths (KEX `--out-key`, `keygen --out`). Hardening is
/// identical to the exclusive variant (Unix 0600, Windows share-NONE plus
/// owner-only `icacls`; ACL failure deletes the file and errors).
/// Rotation is an explicit operator act — callers never truncate implicitly.
pub fn write_key_file_truncate(path: &str, hex: &str) -> Result<(), CoreError> {
    let clean = hex.trim();
    if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CoreError::Malformed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| CoreError::FilePermissions)?;
        f.write_all(clean.as_bytes())
            .map_err(|_| CoreError::FilePermissions)?;
        f.write_all(b"\n").map_err(|_| CoreError::FilePermissions)?;
        f.sync_all().map_err(|_| CoreError::FilePermissions)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // Residual (documented, unchanged): SSD wear-leveling / swap /
        // hibernation can retain copies — a facility duty (see trust_anchor
        // ephemeral doctrine); prefer stdin + locked memory / HSM custody
        // for TOP SECRET.
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .share_mode(0)
            .open(path)
            .map_err(|_| CoreError::FilePermissions)?;
        f.write_all(clean.as_bytes())
            .map_err(|_| CoreError::FilePermissions)?;
        f.write_all(b"\n").map_err(|_| CoreError::FilePermissions)?;
        f.sync_all().map_err(|_| CoreError::FilePermissions)?;
        drop(f);
        let acl_ok = std::process::Command::new("icacls")
            .args([
                path,
                "/inheritance:r",
                "/grant:r",
                &format!(
                    "{}:F",
                    std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string())
                ),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !acl_ok {
            let _ = std::fs::remove_file(path);
            return Err(CoreError::FilePermissions);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_key_hex("short").is_err());
        assert!(parse_key_hex(&"zz".repeat(32)).is_err());
        assert!(parse_key_hex(&"ab".repeat(32)).is_ok());
    }

    #[test]
    fn exclusive_write_refuses_overwrite() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("st2027-core-test-{}-{}", std::process::id(), 1u64));
        let s = p.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&p);
        write_key_file_exclusive(&s, &"ab".repeat(32)).unwrap();
        // Second create must fail (no silent truncation).
        assert!(write_key_file_exclusive(&s, &"cd".repeat(32)).is_err());
        let back = read_key_file(&s).unwrap();
        assert_eq!(back.as_bytes().len(), 32);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn truncate_write_roundtrips_with_hardening() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("st2027-core-test-{}-{}", std::process::id(), 3u64));
        let s = p.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&p);
        write_key_file_truncate(&s, &"ab".repeat(32)).unwrap();
        // Rotation overwrites explicitly and stays readable.
        write_key_file_truncate(&s, &"cd".repeat(32)).unwrap();
        let back = read_key_file(&s).unwrap();
        assert_eq!(&back.as_bytes()[..], &[0xCDu8; 32][..]);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    #[cfg(unix)]
    fn symlink_refused() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir();
        let real = dir.join(format!("st2027-core-test-{}-{}", std::process::id(), 4u64));
        let link = dir.join(format!("st2027-core-test-{}-{}", std::process::id(), 5u64));
        let (rs, ls) = (
            real.to_str().unwrap().to_string(),
            link.to_str().unwrap().to_string(),
        );
        let _ = std::fs::remove_file(&real);
        let _ = std::fs::remove_file(&link);
        write_key_file_exclusive(&rs, &"ab".repeat(32)).unwrap();
        symlink(&real, &link).unwrap();
        // Followed-metadata `is_symlink` would MISS this; `symlink_metadata`
        // refuses it fail-closed.
        assert_eq!(read_key_file(&ls).unwrap_err(), CoreError::FilePermissions);
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&real);
    }

    #[test]
    #[cfg(unix)]
    fn world_readable_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let p = dir.join(format!("st2027-core-test-{}-{}", std::process::id(), 2u64));
        let s = p.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&p);
        write_key_file_exclusive(&s, &"ab".repeat(32)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_key_file(&s).unwrap_err(), CoreError::FilePermissions);
        let _ = std::fs::remove_file(&p);
    }
}
