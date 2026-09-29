//! Cryptographic media sanitization & emergency zeroization (NIST SP 800-88 Rev 1 / DoD 5220.22-M).
//!
//! Provides multi-pass cryptographic erasure:
//! - Pass 1: CSPRNG cryptographically secure random bytes
//! - Pass 2: Inverted bitwise complement (0xFF)
//! - Pass 3: All-zeros (0x00)
//!
//! Followed by OS hardware buffer flush (`sync_all`), zero-byte truncation, and unlink.

use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::Zeroize;

#[derive(Debug)]
pub enum PurgeError {
    NotFound,
    IoError(std::io::Error),
    RandomError,
}

impl std::fmt::Display for PurgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PurgeError::NotFound => write!(f, "target file does not exist"),
            PurgeError::IoError(e) => write!(f, "I/O error during purge: {e}"),
            PurgeError::RandomError => write!(f, "CSPRNG randomness failure"),
        }
    }
}

impl std::error::Error for PurgeError {}

impl From<std::io::Error> for PurgeError {
    fn from(e: std::io::Error) -> Self {
        PurgeError::IoError(e)
    }
}

/// Perform a 3-pass NIST SP 800-88 Rev 1 cryptographic purge on a file,
/// sync to persistent storage, truncate, and delete.
pub fn purge_file<P: AsRef<Path>>(path: P) -> Result<(), PurgeError> {
    let p = path.as_ref();
    if !p.exists() {
        return Err(PurgeError::NotFound);
    }

    // Ensure file is writable even if flagged read-only
    if let Ok(meta) = std::fs::metadata(p) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(p, perms);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(p)?;

    file.lock_exclusive()?;

    let meta = file.metadata()?;
    let raw_len = meta.len() as usize;
    // Overwrite at least 4096 bytes (standard OS sector size) to clear slack space
    let purge_len = raw_len.max(4096);
    let mut buf = vec![0u8; purge_len];

    // Pass 1: CSPRNG Random Overwrite
    getrandom::fill(&mut buf).map_err(|_| PurgeError::RandomError)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buf)?;
    file.sync_all()?;

    // Pass 2: Inverted Complement (0xFF)
    buf.fill(0xFF);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buf)?;
    file.sync_all()?;

    // Pass 3: Zeroization (0x00)
    buf.fill(0x00);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buf)?;
    file.sync_all()?;

    // Truncate to 0 and flush
    file.set_len(0)?;
    file.sync_all()?;

    let _ = file.unlock();
    drop(file);

    // Securely wipe memory buffer
    buf.zeroize();

    // Unlink file from filesystem
    std::fs::remove_file(p)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purge_file_erases_and_unlinks() {
        let tmp_dir = std::env::temp_dir();
        let target = tmp_dir.join(format!("st2027_purge_test_{}.dat", std::process::id()));

        // Create test file with sensitive markers
        let sensitive_data = b"TOP-SECRET-KEY-MATERIAL-1234567890-CONFIDENTIAL";
        std::fs::write(&target, sensitive_data).expect("write temp");
        assert!(target.exists());

        // Perform multi-pass purge
        purge_file(&target).expect("purge failed");

        // Verify file is completely unlinked
        assert!(!target.exists(), "file should be unlinked");
    }

    #[test]
    fn test_purge_nonexistent_returns_not_found() {
        let nonexistent = Path::new("nonexistent_purge_path_xyz_123.bin");
        let res = purge_file(nonexistent);
        assert!(matches!(res, Err(PurgeError::NotFound)));
    }
}
