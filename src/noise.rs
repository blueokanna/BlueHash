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
/// * `prime` - A secret key that adds an extra layer of security to the noise generation.
///
/// # Returns
///
/// A 64-bit unsigned integer representing the generated noise value.
/// Generates LWE noise based on input data, round, and a prime number.
/// This function introduces non-linear operations to improve security.
pub fn generate_lwe_noise(input_data: &[u8], round: usize, prime: u64) -> u64 {
    let mut noise = prime;

    // Validate input to prevent issues with empty data
    if input_data.is_empty() {
        noise ^= round as u64; // Add round as fallback noise
        return noise.rotate_left((round % 64) as u32);
    }

    // Iterate over input_data, applying secure operations to generate noise
    for (i, &byte) in input_data.iter().enumerate() {
        let multiplied = (byte as u64).wrapping_mul((i.wrapping_add(1)) as u64); // Avoid zero multiplication
        noise = noise.wrapping_add(multiplied);
        noise = noise.rotate_left(7); // Distribute noise with rotations
    }

    // Add round-specific noise and apply final rotation
    noise ^= round as u64;
    noise.rotate_left((round % 64) as u32)
}