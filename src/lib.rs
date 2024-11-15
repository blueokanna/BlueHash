//! BlueHash: A cryptographic hash function with quantum-resistant features.
//!
//! This library provides the implementation of the BlueHash algorithm, designed to
//! resist quantum attacks while maintaining high security. It includes state manipulation,
//! constant generation, and noise-based perturbations inspired by lattice-based cryptography.
//!
//! You can check github: https://github.com/blueokanna/BlueHash for details.

mod constants;
mod noise;
mod utils;

use crate::constants::generate_constants;

/// The size of the state array (fixed size).
const STATE_SIZE: usize = 25;

#[derive(Debug, Copy, Clone)]
#[warn(non_snake_case)]
pub enum DigestSize {
    Bit128,
    Bit256,
    Bit512,
}

impl DigestSize {
    fn round_count(&self) -> usize {
        match self {
            DigestSize::Bit128 => 56,
            DigestSize::Bit256 => 64,
            DigestSize::Bit512 => 80,
        }
    }

    fn digest_length(&self) -> usize {
        match self {
            DigestSize::Bit128 => 16,
            DigestSize::Bit256 => 32,
            DigestSize::Bit512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BlueHash {
    state: [u64; STATE_SIZE],
    round_count: usize,
    digest_size: DigestSize,
    key: u64,
}

impl BlueHash {
    /// Constructs a new BlueHash instance with the given digest size and key.
    ///
    /// # Arguments
    ///
    /// * `digest_size` - Defines the desired size of the resulting hash (e.g., 128-bit, 256-bit).
    /// * `key` - A secret key used for noise generation and state manipulation.
    ///
    /// # Returns
    ///
    /// A new `BlueHash` instance with the specified configuration.
    pub fn new(digest_size: &DigestSize, key: u64) -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            round_count: digest_size.round_count(),
            digest_size: digest_size.clone(),
            key,
        }
    }

    /// Updates the hash state with new data in chunks of 8 bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Input data to update the hash state.
    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(8) {
            let block = utils::to_u64(chunk);
            self.state[0] ^= block;
            self.permute(data);
        }
    }

    /// Applies a permutation to the internal state based on the input data.
    ///
    /// # Arguments
    ///
    /// * `input_data` - The data used to perturb the state.
    fn permute(&mut self, input_data: &[u8]) {
        let mut local_vars = [0u64; 5];
        for round in 0..self.round_count {
            let constant = generate_constants(round, input_data, self.round_count, self.key);
            for i in 0..STATE_SIZE {
                local_vars = [
                    self.state[(i + 1) % STATE_SIZE],
                    self.state[(i + 2) % STATE_SIZE],
                    self.state[(i + 3) % STATE_SIZE],
                    self.state[(i + 4) % STATE_SIZE],
                    self.state[(i + 5) % STATE_SIZE],
                ];

                self.state[i] = self.state[i]
                    .rotate_left(29)
                    .wrapping_add(constant)
                    .wrapping_add(local_vars[2])
                    ^ (local_vars[0] & local_vars[1])
                    ^ local_vars[3].rotate_right(17)
                    ^ constant.rotate_left(23);
            }
        }
    }

    /// Finalizes the hash calculation and returns the hash output as a byte vector.
    ///
    /// # Returns
    ///
    /// The final hash output as a vector of bytes.
    pub fn finalize(&self) -> Vec<u8> {
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
}
