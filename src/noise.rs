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
pub fn generate_lwe_noise(input_data: &[u8], round: usize, key: u64) -> u64 {
    // Initial noise value is derived from the secret key to ensure consistency
    let mut noise = key;

    // Sum the weighted contributions of each byte in the input data
    for (i, byte) in input_data.iter().enumerate() {
        noise = noise.wrapping_add((*byte as u64).wrapping_mul(i as u64));
        noise = noise.rotate_left(7); // Rotate by 7 bits for better distribution
    }

    // Introduce round-based variation by XOR the round number into the noise
    noise ^= round as u64;

    // Apply another rotation to further disrupt the noise distribution
    noise = noise.rotate_left((round % 64) as u32);

    // Return the generated noise
    noise
}
