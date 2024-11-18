//! BlueHash: A cryptographic hash function with quantum-resistant features.
//!
//! This library provides the implementation of the BlueHash algorithm, designed to
//! resist quantum attacks while maintaining high security. It includes state manipulation,
//! constant generation, and noise-based perturbations inspired by lattice-based cryptography.
//!
//! Full details and source code: https://github.com/blueokanna/BlueHash.

pub mod constants;
pub mod noise;
pub mod utils;

pub use constants::generate_constants;
pub use noise::generate_lwe_noise;
pub use utils::to_u64;

/// State size used for the internal state array of BlueHash.
pub const STATE_SIZE: usize = 25;

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

/// The `Digest` trait for cryptographic hash functions.
pub trait Digest {
    /// Updates the internal state with the given input data.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the computation and returns the resulting hash as a byte vector.
    fn finalize(&self) -> Vec<u8>;

    /// Resets the internal state, making the hasher ready for reuse.
    fn reset(&mut self);
}

/// BlueHash structure implementing the cryptographic hash algorithm.
#[derive(Debug, Clone)]
pub struct BlueHash {
    /// The internal state array of the hasher.
    state: [u64; STATE_SIZE],

    /// The number of rounds for this instance of BlueHash.
    round_count: usize,

    /// The digest size configuration (e.g., 128-bit, 256-bit).
    digest_size: DigestSize,
}

impl BlueHash {
    /// Constructs a new BlueHash instance with the given digest size.
    ///
    /// # Arguments
    ///
    /// * `digest_size` - Defines the desired size of the resulting hash (e.g., 128-bit, 256-bit).
    ///
    /// # Returns
    ///
    /// A new `BlueHash` instance with the specified configuration.
    pub fn new(digest_size: DigestSize) -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            round_count: digest_size.round_count(),
            digest_size,
        }
    }

    /// Applies a permutation to the internal state based on the input data.
    ///
    /// # Arguments
    ///
    /// * `input_data` - The data used to perturb the state.
    fn permute(&mut self, input_data: &[u8]) {
        // Optimize by replacing VecDeque with a fixed-size array
        let mut tmp_state = [0u64; STATE_SIZE];

        for round in 0..self.round_count {
            // Generate a constant value for this round using input data
            let constant = generate_constants(round, input_data, self.round_count);
            let state = &mut self.state;

            for i in 0..STATE_SIZE {
                let local_vars = [
                    state[(i + 1) % STATE_SIZE],
                    state[(i + 2) % STATE_SIZE],
                    state[(i + 3) % STATE_SIZE],
                    state[(i + 4) % STATE_SIZE],
                    state[(i + 5) % STATE_SIZE],
                ];

                // Update temporary state with computed value
                tmp_state[i] = state[i]
                    .wrapping_add(constant)
                    .wrapping_add(local_vars[2])
                    .rotate_left(29)
                    .wrapping_add(local_vars[0] & local_vars[1])
                    .wrapping_add(local_vars[3].rotate_right(17))
                    .rotate_left(23);
            }

            // Update the main state array from the temporary state
            self.state.copy_from_slice(&tmp_state);
        }
    }
}

/// Implements the `Digest` trait for BlueHash.
impl Digest for BlueHash {
    /// Updates the internal state with the given input data.
    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(8) {
            let block = to_u64(chunk);
            self.state[0] ^= block;
            self.permute(data);
        }
    }

    /// Finalizes the computation and returns the resulting hash as a byte vector.
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

    /// Resets the internal state to its initial value.
    fn reset(&mut self) {
        self.state = [0u64; STATE_SIZE];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bluehash() {
        let mut hasher = BlueHash::new(DigestSize::Bit256);
        hasher.update(b"Hello, world! This is a test message for BlueHash");
        let result = hasher.finalize();

        // Adjust expected values to match algorithm logic
        assert_eq!(result.len(), 32);
        assert_eq!(
            hex::encode(result.clone()),
            "c472cbe52b0f1b44f3aa1cec8d56dc578eb75048be19ca5edc6d349c2b5c7ceb"
        );
    }
}
