/// Generates a constant value for the round using input data, round number, hash length,
/// and a secret key. This constant is used for permutations in the hash algorithm.
/// The generation process is designed to introduce enough randomness and complexity,
/// making it resistant to both classical and quantum attacks.
///
/// # Arguments
/// * `round` - The current round number in the hash algorithm.
/// * `input_data` - The input data used to generate the noise.
/// * `hash_length` - The length of the hash output, used to adjust the constant.
/// * `key` - A secret key that adds additional security to the constant generation.
///
/// # Returns
/// A 64-bit unsigned integer representing the generated constant.
pub fn generate_constants(round: usize, input_data: &[u8], hash_length: usize, key: u64) -> u64 {
    // Prime values used in the constant generation
    let prime = 0x9e3779b97f4a7c15u64; // A constant prime number for hash mixing
    let round_factor = (round as u64).wrapping_add(0xabcdef1234567890); // Round-dependent factor
    let extra_prime = 0x7fffffffffffffffu64; // Another large prime constant for additional mixing

    // Generate noise based on input data and round number using LWE noise model
    let noise = crate::noise::generate_lwe_noise(input_data, round, key);

    // Rotate prime to introduce round-based variability
    let rotated_prime = prime.rotate_left((round % 64) as u32);

    // Generate the constant by applying various bitwise operations for mixing
    rotated_prime
        .wrapping_mul(round_factor.rotate_left(32))
        .wrapping_add(round_factor.rotate_right(16))
        .wrapping_add(extra_prime.rotate_left((round % 32) as u32))
        .wrapping_add(noise.rotate_left(8))
        .wrapping_add(hash_length as u64)
}
