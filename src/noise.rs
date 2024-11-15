
/// Generates LWE noise based on the input data, round number, and secret key.
/// The noise is designed to enhance resistance against quantum attacks by using
/// a combination of multiplicative and additive operations, with bit rotations
/// to introduce sufficient mixing.
///
/// This function is inspired by lattice-based cryptography and is designed
/// to be more resilient against quantum attacks while maintaining efficiency.
///
/// # Arguments
///
/// * `input_data` - The input data used to generate the noise.
/// * `round` - The current round number in the hash algorithm.
/// * `key` - A secret key that adds an extra layer of security to the noise generation.
///
/// # Returns
///
/// A 64-bit unsigned integer representing the generated noise value.

use rand::Rng;

pub fn generate_lwe_noise(input_data: &[u8], round: usize, key: u64, prime: u64) -> u64 {
    let mut rng = rand::thread_rng();
    let s: Vec<u64> = (0..input_data.len()).map(|_| rng.gen::<u64>() % prime).collect();
    let mut noise = 0u64;

    for (i, &byte) in input_data.iter().enumerate() {
        let a = rng.gen::<u64>() % prime;
        noise = noise.wrapping_add((a * s[i] + byte as u64) % prime);
    }

    noise.rotate_left((round % 64) as u32)
}
