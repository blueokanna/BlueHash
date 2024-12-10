/// Generates a constant value for the round using input data, round number, hash length,
/// and a secret key. This constant is used for permutations in the hash algorithm.
/// The generation process is designed to introduce enough randomness and complexity,
/// making it resistant to both classical and quantum attacks.
// <Author: BlueOkanna>
// <Email: blueokanna@gmail.com>
/// # Arguments
/// * `round` - The current round number in the hash algorithm.
/// * `input_data` - The input data used to generate the noise.
/// * `hash_length` - The length of the hash output, used to adjust the constant.
///
/// # Returns
/// A 64-bit unsigned integer representing the generated constant.
use std::ops::{BitAnd, BitXor, Shl};
use crate::noise::generate_lwe_noise;

/// Secure combination with optimizations (nonlinear perturbations)
macro_rules! secure_combine {
    ($val1:expr, $val2:expr, $prime:expr, $round:expr) => {{
        let mix1 = $val1.rotate_left(($round % 64) as u32);
        let mix2 = $val2.rotate_right(($round % 32) as u32);
        let nonlinear = (mix1.wrapping_mul(0x53FA0915)).wrapping_add(mix2 ^ $prime);
        nonlinear ^ ((nonlinear & 0x40490FDB) << 5) ^ ((nonlinear & 0x7F4A7C15) >> 7)
    }};
}

/// Precompute rotation values once for reuse
macro_rules! precompute_rotation {
    ($value:expr, $shift_left:expr, $shift_right:expr) => {{
        let rotated_left = $value.rotate_left($shift_left);
        let rotated_right = $value.rotate_right($shift_right);
        (rotated_left, rotated_right)
    }};
}

/// Generate constant functions, support generics and high safety
pub fn generate_constants<T>(round: usize, input_data: &[T], hash_length: usize) -> u64
where
    T: Copy
    + Into<u64>
    + BitXor<Output = T>
    + Shl<u32, Output = T>
    + BitAnd<Output = T>
    + Send
    + Sync,
{
    let prime = 0x9E3779B97F4A7C15u64;
    let round_factor = (round as u64).wrapping_add(0xABCDEF1234567890);
    let extra_prime = 0x7FFFFFFFFFFFFFFFu64;

    // Precompute rotation values once for the round
    let (round_factor_rot_left, round_factor_rot_right) = precompute_rotation!(round_factor, 32, 16);
    let (rotated_prime, _) = precompute_rotation!(prime, (round % 64) as u32, 0);
    let (extra_prime_rot_left, _) = precompute_rotation!(extra_prime, (round % 32) as u32, 0);

    // Use optimized LWE noise generation
    let noise_rot_left = generate_lwe_noise(input_data, round, prime).rotate_left(8);

    // Combine the values with optimized transformations
    secure_combine!(
        rotated_prime
            .wrapping_mul(round_factor_rot_left)
            .wrapping_add(round_factor_rot_right)
            .wrapping_add(extra_prime_rot_left),
        noise_rot_left.wrapping_add(hash_length as u64),
        prime,
        round
    )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_constants() {
        let data: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78];
        let result = generate_constants(5, &data, 32);
        println!("Generated Constant: {:#x}", result);

        assert_ne!(result, 0); // Check if the result is non-zero
    }
}