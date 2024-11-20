/// Generates a constant value for the round using input data, round number, hash length,
/// and a secret key. This constant is used for permutations in the hash algorithm.
/// The generation process is designed to introduce enough randomness and complexity,
/// making it resistant to both classical and quantum attacks.
///
/// # Arguments
/// * `round` - The current round number in the hash algorithm.
/// * `input_data` - The input data used to generate the noise.
/// * `hash_length` - The length of the hash output, used to adjust the constant.
///
/// # Returns
/// A 64-bit unsigned integer representing the generated constant.

use crate::noise::generate_lwe_noise;

pub const STATE_SIZE: usize = 25;

pub fn generate_constants(round: usize, input_data: &[u8], hash_length: usize) -> u64 {
    let prime = 0x9e3779b97f4a7c15u64;
    let round_factor = (round as u64).wrapping_add(0xabcdef1234567890);
    let extra_prime = 0x7fffffffffffffffu64;
    let noise = generate_lwe_noise(input_data, round, prime);

    // Calculate the rotation value in advance
    let round_factor_rot_left = round_factor.rotate_left(32);
    let round_factor_rot_right = round_factor.rotate_right(16);
    let rotated_prime = prime.rotate_left((round % 64) as u32);
    let extra_prime_rot_left = extra_prime.rotate_left((round % 32) as u32);
    let noise_rot_left = noise.rotate_left(8);

    // Reduce double counting by using already calculated rotation values
    rotated_prime
        .wrapping_mul(round_factor_rot_left)
        .wrapping_add(round_factor_rot_right)
        .wrapping_add(extra_prime_rot_left)
        .wrapping_add(noise_rot_left)
        .wrapping_add(hash_length as u64)
}

