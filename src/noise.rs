/// Generates LWE noise based on the input data, round number, and secret key.
/// The noise is designed to enhance resistance against quantum attacks by using
/// a combination of multiplicative and additive operations, with bit rotations
/// to introduce sufficient mixing.
// <Author: BlueOkanna>
// <Email: blueokanna@gmail.com>
/// This function is inspired by lattice-based cryptography and is designed
/// to be more resilient against quantum attacks while maintaining efficiency.
///
/// # Arguments
///
/// * `input_data` - The input data used to generate the noise.
/// * `round` - The current round number in the hash algorithm.
/// * `prime` - A secret key that adds an extra layer of security to the noise generation.
///
/// # Returns
///
/// A 64-bit unsigned integer representing the generated noise value.
/// Generates LWE noise based on input data, round, and a prime number.
/// This function introduces non-linear operations to improve security.
use rayon::prelude::*;
use std::ops::{BitAnd, BitXor, Shl};

/// Macros for generating secure obfuscation functions, supporting different rotations and non-linear operations
macro_rules! secure_transform {
    ($value:expr, $factor:expr, $prime:expr) => {{
        // Precompute rotations for constants that don't change frequently
        let rotated1 = $value.rotate_left(($factor & 31) as u32);
        let rotated2 = ($value ^ 0x9E3779B9).rotate_right((($factor + 13) & 31) as u32);
        let mixed = rotated1
            .wrapping_mul(0x53FA0915)
            .wrapping_add(rotated2 ^ $prime);
        mixed ^ ((mixed & 0x40490FDB) << 3) ^ ((mixed & 0x7F4A7C15) >> 5)
    }};
}

/// Generic safe LWE noise generator
pub fn generate_lwe_noise<T>(input_data: &[T], round: usize, prime: u64) -> u64
where
    T: Copy
        + Into<u64>
        + BitXor<Output = T>
        + BitAnd<Output = T>
        + Shl<u32, Output = T>
        + Send
        + Sync, // Ensure T is thread-safe for parallel execution
{
    let mut noise: u64 = prime;

    // Validate input data to ensure security
    if input_data.is_empty() {
        noise ^= round as u64; // Use round as degradation noise
        return noise.rotate_left((round % 64) as u32);
    }

    // Parallelize the iteration to leverage multiple cores
    noise = input_data
        .par_iter()
        .enumerate()
        .fold(
            || noise,
            |acc, (i, &item)| {
                let value = item.into();
                let multiplied = value.wrapping_mul((i + 1) as u64); // Avoid zero products
                secure_transform!(acc.wrapping_add(multiplied), i as u64, prime)
            },
        )
        .reduce(|| noise, |a, b| a ^ b); // Reduce all computed noises into one value

    // Add round specific noise and apply final transform
    secure_transform!(noise ^ round as u64, round as u64, prime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lwe_noise() {
        let data: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78];
        let result = generate_lwe_noise(&data, 5, 0x9E3779B97F4A7C15);
        println!("Generated Noise: {:#x}", result);

        assert_ne!(result, 0);
    }
}
