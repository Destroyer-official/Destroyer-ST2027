//! Tactical SDR DSSS LPI/LPD Physical Waveform Engine
//!
//! Provides direct baseband I/Q synthesis for Software Defined Radios (USRP, HackRF)
//! emitting Direct Sequence Spread Spectrum (DSSS) below the ambient thermal noise
//! floor (SNR < -15 dB) to defeat physical RF direction-finding and SIGINT interception.
//!
//! Mathematical Grounding:
//! - Spreading factor N_chips in {127, 255, 511, 1023}.
//! - Processing gain: PG = 10 * log10(N_chips) dB. For N=511, PG ~= 27.1 dB.
//! - Enables reliable signal recovery at input SNR = -18 dB with Eb/N0 > +9 dB post-despreading.
//! - Root-Raised-Cosine (RRC) pulse shaping filter with roll-off alpha = 0.35.

use std::f32::consts::PI;

pub const DEFAULT_CHIP_RATE_HZ: f32 = 2_048_000.0;
pub const DEFAULT_CARRIER_OFFSET_HZ: f32 = 0.0;
pub const RRC_ROLLOFF: f32 = 0.35;
pub const RRC_SPAN_SYMBOLS: usize = 6;
pub const SAMPLES_PER_CHIP: usize = 4;

/// Generates a maximal-length pseudo-noise (PN) sequence (m-sequence) of length 2^k - 1.
pub fn generate_gold_sequence(polynomial: u16, initial_state: u16, length: usize) -> Vec<f32> {
    let mut state = if initial_state == 0 { 0x01 } else { initial_state };
    let mut chips = Vec::with_capacity(length);

    for _ in 0..length {
        let bit = (state & 1) as f32;
        // BPSK mapping: 0 -> +1.0, 1 -> -1.0
        chips.push(if bit == 0.0 { 1.0 } else { -1.0 });

        let feedback = ((state & polynomial).count_ones() & 1) as u16;
        state = (state >> 1) | (feedback << 8);
    }

    chips
}

/// Evaluates Root-Raised-Cosine (RRC) filter impulse response.
pub fn rrc_filter(span_samples: usize, samples_per_symbol: usize, alpha: f32) -> Vec<f32> {
    let mut coeffs = Vec::with_capacity(span_samples * 2 + 1);
    let sps = samples_per_symbol as f32;

    for i in -(span_samples as isize)..=(span_samples as isize) {
        let t = i as f32 / sps;
        if t == 0.0 {
            coeffs.push(1.0 - alpha + (4.0 * alpha / PI));
        } else if (4.0 * alpha * t).abs() == 1.0 {
            let val = (alpha / (2.0f32.sqrt()))
                * ((1.0 + 2.0 / PI) * (PI / (4.0 * alpha)).sin()
                    + (1.0 - 2.0 / PI) * (PI / (4.0 * alpha)).cos());
            coeffs.push(val);
        } else {
            let num = (PI * t * (1.0 - alpha)).sin() + 4.0 * alpha * t * (PI * t * (1.0 + alpha)).cos();
            let den = PI * t * (1.0 - (4.0 * alpha * t).powi(2));
            coeffs.push(num / den);
        }
    }

    // Normalize filter energy
    let energy: f32 = coeffs.iter().map(|&x| x * x).sum();
    let norm = energy.sqrt();
    for c in &mut coeffs {
        *c /= norm;
    }

    coeffs
}

/// DSSS Baseband Modulator & Spreader.
#[derive(Debug, Clone)]
pub struct DsssModulator {
    pub spreading_code: Vec<f32>,
    pub spreading_factor: usize,
    pub rrc_coeffs: Vec<f32>,
    pub samples_per_chip: usize,
}

impl DsssModulator {
    /// Constructs a DSSS modulator with specified spreading factor.
    pub fn new(spreading_factor: usize) -> Self {
        let poly = 0x011D; // x^8 + x^4 + x^3 + x^2 + 1
        let pn = generate_gold_sequence(poly, 0x5A, spreading_factor);
        let rrc = rrc_filter(RRC_SPAN_SYMBOLS * SAMPLES_PER_CHIP, SAMPLES_PER_CHIP, RRC_ROLLOFF);

        Self {
            spreading_code: pn,
            spreading_factor,
            rrc_coeffs: rrc,
            samples_per_chip: SAMPLES_PER_CHIP,
        }
    }

    /// Spreads raw data bits into complex baseband I/Q samples (BPSK modulated).
    /// Bits: slice of 0s and 1s.
    /// Returns: Vec<(I: f32, Q: f32)>.
    pub fn modulate_bits(&self, bits: &[u8]) -> Vec<(f32, f32)> {
        let total_chips = bits.len() * self.spreading_factor;
        let mut chip_stream = Vec::with_capacity(total_chips);

        // 1. DSSS Spreading: data_symbol * chip_sequence
        for &bit in bits {
            let data_sign = if bit == 0 { 1.0f32 } else { -1.0f32 };
            for &chip in &self.spreading_code {
                chip_stream.push(data_sign * chip);
            }
        }

        // 2. Pulse shaping interpolation (upsample + RRC convolution)
        let upsampled_len = chip_stream.len() * self.samples_per_chip;
        let mut upsampled = vec![0.0f32; upsampled_len];
        for (i, &chip) in chip_stream.iter().enumerate() {
            upsampled[i * self.samples_per_chip] = chip;
        }

        // Convolve with RRC filter
        let filter_len = self.rrc_coeffs.len();
        let half_span = filter_len / 2;
        let mut i_samples = Vec::with_capacity(upsampled_len);

        for n in 0..upsampled_len {
            let mut acc = 0.0f32;
            for (k, &coeff) in self.rrc_coeffs.iter().enumerate() {
                let sample_idx = n as isize + half_span as isize - k as isize;
                if sample_idx >= 0 && (sample_idx as usize) < upsampled_len {
                    acc += upsampled[sample_idx as usize] * coeff;
                }
            }
            i_samples.push(acc);
        }

        // Return complex I/Q (Q = 0.0 for pure BPSK)
        i_samples.into_iter().map(|i| (i, 0.0f32)).collect()
    }

    /// Packs I/Q samples into signed 16-bit interleaved PCM (`cs16`) format for USRP / HackRF.
    pub fn to_cs16(&self, iq: &[(f32, f32)], amplitude: f32) -> Vec<i16> {
        let mut out = Vec::with_capacity(iq.len() * 2);
        for &(i, q) in iq {
            let i_int = (i * amplitude * 32767.0).clamp(-32768.0, 32767.0) as i16;
            let q_int = (q * amplitude * 32767.0).clamp(-32768.0, 32767.0) as i16;
            out.push(i_int);
            out.push(q_int);
        }
        out
    }
}

/// DSSS Baseband Demodulator & Despreader.
#[derive(Debug, Clone)]
pub struct DsssDemodulator {
    pub spreading_code: Vec<f32>,
    pub spreading_factor: usize,
    pub samples_per_chip: usize,
}

impl DsssDemodulator {
    pub fn new(spreading_factor: usize) -> Self {
        let poly = 0x011D;
        let pn = generate_gold_sequence(poly, 0x5A, spreading_factor);

        Self {
            spreading_code: pn,
            spreading_factor,
            samples_per_chip: SAMPLES_PER_CHIP,
        }
    }

    /// Correlates received noisy I/Q stream against reference spreading code.
    /// Returns: Vec<correlation_value_per_symbol_window>.
    pub fn correlate(&self, i_samples: &[f32]) -> Vec<f32> {
        let samples_per_symbol = self.spreading_factor * self.samples_per_chip;
        if i_samples.len() < samples_per_symbol {
            return Vec::new();
        }

        let num_symbols = i_samples.len() / samples_per_symbol;
        let mut correlations = Vec::with_capacity(num_symbols);

        for sym_idx in 0..num_symbols {
            let start = sym_idx * samples_per_symbol;
            let mut acc = 0.0f32;

            for (chip_idx, &chip) in self.spreading_code.iter().enumerate() {
                // Center-sample each chip
                let sample_pos = start + chip_idx * self.samples_per_chip;
                if sample_pos < i_samples.len() {
                    acc += i_samples[sample_pos] * chip;
                }
            }
            correlations.push(acc / self.spreading_factor as f32);
        }

        correlations
    }

    /// Despreads noisy I/Q baseband and recovers data bits.
    /// Robust against negative SNR (down to -18 dB).
    pub fn demodulate_bits(&self, i_samples: &[f32]) -> Vec<u8> {
        let correlations = self.correlate(i_samples);
        correlations
            .into_iter()
            .map(|val| if val >= 0.0 { 0u8 } else { 1u8 })
            .collect()
    }
}

/// Adds Additive White Gaussian Noise (AWGN) to simulate contested physical RF channel.
pub fn add_awgn_noise(samples: &[f32], snr_db: f32) -> Vec<f32> {
    // Linear SNR: SNR_linear = 10^(snr_db / 10)
    // Signal power: S = (1/N) * sum(x_i^2)
    // Noise variance: sigma^2 = S / SNR_linear
    let signal_power: f32 = samples.iter().map(|&x| x * x).sum::<f32>() / samples.len().max(1) as f32;
    let snr_linear = 10.0f32.powf(snr_db / 10.0);
    let noise_std = (signal_power / snr_linear).sqrt();

    // Box-Muller transform for Gaussian noise
    let mut noisy = Vec::with_capacity(samples.len());
    let mut seed = 0x12345678u64;

    let mut lcg_rand = || -> f32 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        ((seed >> 32) as u32 as f32) / (u32::MAX as f32)
    };

    for i in 0..samples.len() {
        let u1 = lcg_rand().max(1e-7);
        let u2 = lcg_rand();
        let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
        noisy.push(samples[i] + z0 * noise_std);
    }

    noisy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsss_modulation_and_despreading_clean() {
        let modulator = DsssModulator::new(127);
        let demodulator = DsssDemodulator::new(127);

        let data_bits = vec![1, 0, 1, 1, 0, 0, 1, 0];
        let iq = modulator.modulate_bits(&data_bits);
        let i_channel: Vec<f32> = iq.iter().map(|&(i, _)| i).collect();

        let recovered_bits = demodulator.demodulate_bits(&i_channel);
        assert_eq!(recovered_bits, data_bits);
    }

    #[test]
    fn test_dsss_despreading_under_thermal_noise_floor_negative_snr() {
        // High processing gain (N=511, PG ~= 27 dB)
        let modulator = DsssModulator::new(511);
        let demodulator = DsssDemodulator::new(511);

        let secret_directive = vec![1, 1, 0, 1, 0, 0, 1, 1, 0, 1];
        let iq = modulator.modulate_bits(&secret_directive);
        let i_channel: Vec<f32> = iq.iter().map(|&(i, _)| i).collect();

        // Inject intense noise: SNR = -15 dB (ambient noise power is ~31.6 times higher than signal!)
        let noisy_channel = add_awgn_noise(&i_channel, -15.0);

        let recovered = demodulator.demodulate_bits(&noisy_channel);
        assert_eq!(recovered, secret_directive);
    }

    #[test]
    fn test_cs16_wire_packing() {
        let modulator = DsssModulator::new(127);
        let bits = vec![0, 1];
        let iq = modulator.modulate_bits(&bits);
        let pcm = modulator.to_cs16(&iq, 0.8);
        assert_eq!(pcm.len(), iq.len() * 2);
    }
}
