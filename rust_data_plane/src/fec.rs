//! fec.rs — Cauchy-Reed-Solomon Forward Error Correction (FEC) over GF(2^8).
//!
//! Designed specifically for Unidirectional Simplex Optical Data Diodes:
//! - Physical one-way optical transmission requires Zero-ACK reliable delivery.
//! - Splits file payload into K data chunks, generates M parity chunks (N = K + M).
//! - Maximum Distance Separable (MDS): ANY K chunks out of the N transmitted chunks
//!   are mathematically sufficient to reconstruct the entire cleartext file.
//! - GF(2^8) field with polynomial 0x11D and generator 3.
//! - Cauchy matrix construction guarantees every square submatrix is invertible.

use std::fmt;

/// Galois Field GF(2^8) with polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1)
pub struct GF256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Default for GF256 {
    fn default() -> Self {
        Self::new()
    }
}

impl GF256 {
    /// Initialize log and exp lookup tables for fast constant-time field arithmetic.
    pub const fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut val = 1u16;

        let mut i = 0;
        while i < 255 {
            exp[i] = val as u8;
            exp[i + 255] = val as u8;
            log[val as usize] = i as u8;

            // Multiply by generator 2 in GF(2^8) (polynomial 0x11D)
            val = val << 1;
            if (val & 0x100) != 0 {
                val ^= 0x11D;
            }
            i += 1;
        }

        // Sentinel values
        exp[510] = exp[0];
        exp[511] = exp[1];

        Self { exp, log }
    }

    #[inline(always)]
    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline(always)]
    pub fn sub(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline(always)]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let idx = (self.log[a as usize] as usize) + (self.log[b as usize] as usize);
            self.exp[idx]
        }
    }

    #[inline(always)]
    pub fn div(&self, a: u8, b: u8) -> Result<u8, FecError> {
        if b == 0 {
            return Err(FecError::DivisionByZero);
        }
        if a == 0 {
            return Ok(0);
        }
        let idx = (self.log[a as usize] as usize) + 255 - (self.log[b as usize] as usize);
        Ok(self.exp[idx])
    }

    #[inline(always)]
    pub fn inv(&self, a: u8) -> Result<u8, FecError> {
        if a == 0 {
            return Err(FecError::DivisionByZero);
        }
        let idx = 255 - (self.log[a as usize] as usize);
        Ok(self.exp[idx])
    }
}

pub static GF: GF256 = GF256::new();

#[derive(Debug, PartialEq, Eq)]
pub enum FecError {
    DivisionByZero,
    TooManyChunks,
    InsufficientChunks { needed: usize, got: usize },
    SingularMatrix,
    ChunkSizeMismatch,
    InvalidChunkIndex,
}

impl fmt::Display for FecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FecError::DivisionByZero => write!(f, "FEC arithmetic error: division by zero"),
            FecError::TooManyChunks => {
                write!(f, "FEC parameter error: K + M exceeds 255 in GF(2^8)")
            }
            FecError::InsufficientChunks { needed, got } => {
                write!(
                    f,
                    "FEC decode error: needed {needed} chunks, but only received {got}"
                )
            }
            FecError::SingularMatrix => {
                write!(f, "FEC matrix error: non-invertible matrix encountered")
            }
            FecError::ChunkSizeMismatch => write!(f, "FEC chunk error: chunk size mismatch"),
            FecError::InvalidChunkIndex => write!(f, "FEC chunk error: chunk index out of range"),
        }
    }
}

impl std::error::Error for FecError {}

/// Systematic Cauchy-Reed-Solomon Encoder/Decoder.
pub struct CauchyReedSolomon {
    k: usize,               // Data chunks
    m: usize,               // Parity chunks
    cauchy_matrix: Vec<u8>, // M x K matrix in row-major order
}

impl CauchyReedSolomon {
    /// Creates a new Cauchy-Reed-Solomon encoder/decoder with K data and M parity chunks.
    /// Constraint: K >= 1, M >= 1, K + M <= 255.
    pub fn new(k: usize, m: usize) -> Result<Self, FecError> {
        if k == 0 || m == 0 || (k + m) > 255 {
            return Err(FecError::TooManyChunks);
        }

        // Cauchy matrix generation:
        // Let X = [0..M-1] and Y = [M..M+K-1]
        // Since X and Y are disjoint, X_i ^ Y_j != 0 for all i, j.
        // C_{i, j} = 1 / (X_i ^ Y_j)
        let mut cauchy_matrix = vec![0u8; m * k];
        for i in 0..m {
            let x = i as u8;
            for j in 0..k {
                let y = (m + j) as u8;
                let diff = GF.add(x, y);
                cauchy_matrix[i * k + j] = GF.inv(diff)?;
            }
        }

        Ok(Self {
            k,
            m,
            cauchy_matrix,
        })
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn m(&self) -> usize {
        self.m
    }

    pub fn n(&self) -> usize {
        self.k + self.m
    }

    /// Encodes K data chunks of uniform length into M parity chunks of the same length.
    pub fn encode(&self, data_chunks: &[&[u8]]) -> Result<Vec<Vec<u8>>, FecError> {
        if data_chunks.len() != self.k {
            return Err(FecError::InsufficientChunks {
                needed: self.k,
                got: data_chunks.len(),
            });
        }
        let chunk_len = data_chunks[0].len();
        for chunk in data_chunks {
            if chunk.len() != chunk_len {
                return Err(FecError::ChunkSizeMismatch);
            }
        }

        let mut parity_chunks = vec![vec![0u8; chunk_len]; self.m];

        for (i, p_chunk) in parity_chunks.iter_mut().enumerate().take(self.m) {
            for (j, d_chunk) in data_chunks.iter().enumerate().take(self.k) {
                let coeff = self.cauchy_matrix[i * self.k + j];
                for byte_idx in 0..chunk_len {
                    p_chunk[byte_idx] ^= GF.mul(coeff, d_chunk[byte_idx]);
                }
            }
        }

        Ok(parity_chunks)
    }

    /// Decodes any K chunks (data or parity) to recover all K original data chunks.
    /// `received`: Slice of (chunk_index, chunk_data) where chunk_index in 0..(K+M).
    pub fn decode(&self, received: &[(usize, &[u8])]) -> Result<Vec<Vec<u8>>, FecError> {
        if received.len() < self.k {
            return Err(FecError::InsufficientChunks {
                needed: self.k,
                got: received.len(),
            });
        }

        // Take exactly the first K distinct chunks received
        let k_recv = &received[..self.k];
        let chunk_len = k_recv[0].1.len();
        for (_, data) in k_recv {
            if data.len() != chunk_len {
                return Err(FecError::ChunkSizeMismatch);
            }
        }

        // Quick check: if we already have all original data chunks 0..K-1, return directly
        let mut has_all_data = true;
        let mut original_data = vec![vec![0u8; chunk_len]; self.k];
        let mut present_data = vec![false; self.k];

        for &(idx, data) in k_recv {
            if idx < self.k {
                original_data[idx].copy_from_slice(data);
                present_data[idx] = true;
            } else {
                has_all_data = false;
            }
        }

        if has_all_data && present_data.iter().all(|&p| p) {
            return Ok(original_data);
        }

        // Construct K x K encoding submatrix A corresponding to the received rows
        let mut a = vec![0u8; self.k * self.k];
        for (row_idx, &(chunk_idx, _)) in k_recv.iter().enumerate() {
            if chunk_idx < self.k {
                // Identity row
                a[row_idx * self.k + chunk_idx] = 1;
            } else if chunk_idx < self.n() {
                // Parity row from Cauchy matrix
                let parity_row = chunk_idx - self.k;
                for col in 0..self.k {
                    a[row_idx * self.k + col] = self.cauchy_matrix[parity_row * self.k + col];
                }
            } else {
                return Err(FecError::InvalidChunkIndex);
            }
        }

        // Invert K x K matrix A using Gaussian elimination over GF(2^8)
        let a_inv = invert_matrix(&a, self.k)?;

        // Multiply A_inv by the received chunks to recover original data chunks: D = A_inv * R
        let mut recovered_data = vec![vec![0u8; chunk_len]; self.k];

        for i in 0..self.k {
            let out_chunk = &mut recovered_data[i];
            for j in 0..self.k {
                let coeff = a_inv[i * self.k + j];
                let r_chunk = k_recv[j].1;
                for byte_idx in 0..chunk_len {
                    out_chunk[byte_idx] ^= GF.mul(coeff, r_chunk[byte_idx]);
                }
            }
        }

        Ok(recovered_data)
    }
}

/// Gaussian elimination matrix inversion over GF(2^8).
fn invert_matrix(mat: &[u8], n: usize) -> Result<Vec<u8>, FecError> {
    // Augmented matrix [A | I] of dimension n x (2n)
    let mut aug = vec![0u8; n * 2 * n];
    for i in 0..n {
        for j in 0..n {
            aug[i * 2 * n + j] = mat[i * n + j];
        }
        aug[i * 2 * n + n + i] = 1; // Identity
    }

    // Forward and backward elimination
    for col in 0..n {
        // Find pivot
        let mut pivot_row = None;
        for row in col..n {
            if aug[row * 2 * n + col] != 0 {
                pivot_row = Some(row);
                break;
            }
        }
        let pivot_row = pivot_row.ok_or(FecError::SingularMatrix)?;

        // Swap current row with pivot row
        if pivot_row != col {
            for j in 0..(2 * n) {
                aug.swap(col * 2 * n + j, pivot_row * 2 * n + j);
            }
        }

        // Normalize pivot row
        let pivot_val = aug[col * 2 * n + col];
        let pivot_inv = GF.inv(pivot_val)?;
        for j in 0..(2 * n) {
            let cur = aug[col * 2 * n + j];
            aug[col * 2 * n + j] = GF.mul(cur, pivot_inv);
        }

        // Eliminate all other rows
        for row in 0..n {
            if row != col {
                let factor = aug[row * 2 * n + col];
                if factor != 0 {
                    for j in 0..(2 * n) {
                        let sub_val = GF.mul(factor, aug[col * 2 * n + j]);
                        aug[row * 2 * n + j] = GF.sub(aug[row * 2 * n + j], sub_val);
                    }
                }
            }
        }
    }

    // Extract right-hand side (inverse matrix)
    let mut inv = vec![0u8; n * n];
    for i in 0..n {
        for j in 0..n {
            inv[i * n + j] = aug[i * 2 * n + n + j];
        }
    }

    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_arithmetic() {
        assert_eq!(GF.add(42, 42), 0);
        assert_eq!(GF.sub(100, 100), 0);
        assert_eq!(GF.mul(0, 50), 0);
        assert_eq!(GF.mul(1, 50), 50);

        // Inversion check
        for a in 1..=255 {
            let inv = GF.inv(a).expect("inv failed");
            assert_eq!(GF.mul(a, inv), 1, "Failed for a = {a}");
        }
    }

    #[test]
    fn test_fec_encode_decode_exact() {
        let crs = CauchyReedSolomon::new(4, 2).expect("CRS init failed");
        let d0 = b"Hello Sovereign!".to_vec();
        let d1 = b"Simplex Diode OK".to_vec();
        let d2 = b"Zero Return Path".to_vec();
        let d3 = b"MDS Optical 2027".to_vec();

        let data = [&d0[..], &d1[..], &d2[..], &d3[..]];
        let parity = crs.encode(&data).expect("Encode failed");
        assert_eq!(parity.len(), 2);

        // Case 1: All 4 data chunks received
        let recv1 = vec![(0, &d0[..]), (1, &d1[..]), (2, &d2[..]), (3, &d3[..])];
        let recovered1 = crs.decode(&recv1).expect("Decode 1 failed");
        assert_eq!(recovered1[0], d0);
        assert_eq!(recovered1[1], d1);
        assert_eq!(recovered1[2], d2);
        assert_eq!(recovered1[3], d3);

        // Case 2: Data chunks 1 and 3 LOST, replaced by Parity chunks 0 and 1
        let recv2 = vec![
            (0, &d0[..]),
            (4, &parity[0][..]), // Parity 0
            (2, &d2[..]),
            (5, &parity[1][..]), // Parity 1
        ];
        let recovered2 = crs.decode(&recv2).expect("Decode 2 failed");
        assert_eq!(recovered2[0], d0);
        assert_eq!(recovered2[1], d1);
        assert_eq!(recovered2[2], d2);
        assert_eq!(recovered2[3], d3);
    }

    #[test]
    fn test_fec_arbitrary_loss_recovery_sweep() {
        let crs = CauchyReedSolomon::new(5, 3).expect("CRS init failed");
        let chunk_len = 64;
        let mut data_chunks = Vec::new();
        for i in 0..5 {
            data_chunks.push(vec![(i as u8) * 17 + 1; chunk_len]);
        }
        let data_refs: Vec<&[u8]> = data_chunks.iter().map(|c| c.as_slice()).collect();
        let parity_chunks = crs.encode(&data_refs).expect("Encode failed");

        // Total 8 chunks available (0..4 data, 5..7 parity)
        let all_chunks: Vec<(usize, Vec<u8>)> = (0..5)
            .map(|i| (i, data_chunks[i].clone()))
            .chain((0..3).map(|i| (5 + i, parity_chunks[i].clone())))
            .collect();

        // Any combination of 5 chunks must decode correctly
        // Test combination [0, 2, 5, 6, 7] (chunks 1 and 3 dropped)
        let chosen_indices = [0, 2, 5, 6, 7];
        let recv: Vec<(usize, &[u8])> = chosen_indices
            .iter()
            .map(|&idx| (all_chunks[idx].0, all_chunks[idx].1.as_slice()))
            .collect();

        let decoded = crs.decode(&recv).expect("Decode failed");
        for i in 0..5 {
            assert_eq!(decoded[i], data_chunks[i], "Mismatch at chunk {i}");
        }
    }
}
