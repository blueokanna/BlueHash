//! BlueHash: A cryptographic hash function with quantum-resistant features.
//!
//! This library implements the BlueHash algorithm, designed to resist quantum attacks
//! while maintaining high security. It includes state manipulation, constant generation,
//! and noise-based perturbations inspired by lattice-based cryptography.
//!
//! Full details and source code: https://github.com/blueokanna/BlueHash.
//!
//! # BlueHash Usage Example (BlueHash128)
//!
//! ```rust
//! use BlueHash::BlueHashCore;
//! use BlueHash::DigestSize;
//! use BlueHash::Digest;
//! fn main() {
//!     let test_data = b"Hello, world! This is a test message for BlueHash";
//!     let mut hasher128 = BlueHashCore::new(DigestSize::Bit128);
//!     hasher128.update(test_data);
//!     let result128 = hasher128.finalize();
//!     println!("BlueHash128 Result: {}", to_hex_string(&result128));
//! }
//!
//! // Helper function to convert bytes to a hexadecimal string
//! fn to_hex_string(bytes: &[u8]) -> String {
//!     let mut hex = String::new();
//!     for byte in bytes {
//!         write!(&mut hex, "{:02x}", byte).unwrap();
//!     }
//!     hex
//! }
//! ```
//!
//! You may also refer to the [BlueHash][1] readme for more information.
//!

pub mod constants;
pub mod noise;
pub mod utils;

pub use constants::generate_constants;
pub use noise::generate_lwe_noise;
pub use utils::to_u64;

use std::fmt;
use crate::constants::STATE_SIZE;

/// Represents the available digest sizes for BlueHash.
#[derive(Debug, Copy, Clone)]
pub enum DigestSize {
    Bit128,
    Bit256,
    Bit512,
}

impl DigestSize {
    /// Returns the number of rounds based on the digest size.
    pub fn round_count(&self) -> usize {
        match self {
            DigestSize::Bit128 => 56,
            DigestSize::Bit256 => 64,
            DigestSize::Bit512 => 80,
        }
    }

    /// Returns the output length of the digest in bytes.
    pub fn digest_length(&self) -> usize {
        match self {
            DigestSize::Bit128 => 16,
            DigestSize::Bit256 => 32,
            DigestSize::Bit512 => 64,
        }
    }
}

/// Implements the `Digest` trait for cryptographic hash functions with fixed output size.
pub trait Digest {
    fn update(&mut self, data: &[u8]);
    fn finalize(&self) -> Vec<u8>;
    fn reset(&mut self);
}

/// Implements the `VariableDigest` trait for hash functions with variable output size.
pub trait VariableDigest: Digest {
    fn new_variable(output_size: usize) -> Self;
}

/// BlueHash core structure implementing the cryptographic hash algorithm.
#[derive(Debug, Clone)]
pub struct BlueHashCore {
    pub state: [u64; STATE_SIZE],
    pub round_count: usize,
    pub digest_size: DigestSize,
}

impl BlueHashCore {
    pub fn new(digest_size: DigestSize) -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            round_count: digest_size.round_count(),
            digest_size,
        }
    }

    pub fn permute(&mut self, input_data: &[u8]) {
        let mut tmp_state = [0u64; STATE_SIZE];
        for round in 0..self.round_count {
            let constant = generate_constants(round, input_data, self.round_count);
            for i in 0..STATE_SIZE {
                let local_vars = [
                    self.state[(i + 1) % STATE_SIZE],
                    self.state[(i + 2) % STATE_SIZE],
                    self.state[(i + 3) % STATE_SIZE],
                    self.state[(i + 4) % STATE_SIZE],
                    self.state[(i + 5) % STATE_SIZE],
                ];
                tmp_state[i] = self.state[i]
                    .wrapping_add(constant)
                    .wrapping_add(local_vars[2])
                    .rotate_left(29)
                    .wrapping_add(local_vars[0] & local_vars[1])
                    .wrapping_add(local_vars[3].rotate_right(17))
                    .rotate_left(23);
            }
            self.state.copy_from_slice(&tmp_state);
        }
    }
}

impl Digest for BlueHashCore {
    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(8) {
            let block = to_u64(chunk);
            self.state[0] ^= block;
            self.permute(data);
        }
    }

    fn finalize(&self) -> Vec<u8> {
        let digest_size = self.digest_size.digest_length();
        let mut result = vec![0u8; digest_size];
        let mut output_idx = 0;

        while output_idx < digest_size {
            let idx = (output_idx / 8) % STATE_SIZE;
            let val = self.state[idx];
            let bytes = val.to_be_bytes();

            let copy_len = usize::min(8, digest_size - output_idx);
            result[output_idx..output_idx + copy_len].copy_from_slice(&bytes[..copy_len]);
            output_idx += copy_len;
        }

        result
    }

    fn reset(&mut self) {
        self.state = [0u64; STATE_SIZE];
    }
}

/// Aliases for fixed-size BlueHash instances.
pub type BlueHash128 = BlueHashCore;
pub type BlueHash256 = BlueHashCore;
pub type BlueHash512 = BlueHashCore;

/// Implements the `fmt::Display` trait for BlueHash.
impl fmt::Display for BlueHashCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueHash(digest_size: {:?})", self.digest_size)
    }
}

/// Test module for the BlueHash implementation.
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_bluehash128() {
        let mut hasher = BlueHash128::new(DigestSize::Bit128);
        hasher.update(b"Test message for BlueHash");
        let result = hasher.finalize();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_bluehash256() {
        let mut hasher = BlueHash256::new(DigestSize::Bit256);
        hasher.update(b"Another test for BlueHash");
        let result = hasher.finalize();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_bluehash512() {
        let mut hasher = BlueHash512::new(DigestSize::Bit512);
        hasher.update(b"Final test for BlueHash");
        let result = hasher.finalize();
        assert_eq!(result.len(), 64);
    }
}
