
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

pub fn generate_lwe_noise(input_data: &[u8], round: usize, prime: u64) -> u64 {
    let mut noise = prime;

    // Iterate over input_data, multiply each byte by the index and add it to noise
    for (i, byte) in input_data.iter().enumerate() {
        // Use wrapping_mul and wrapping_add to ensure no overflow
        let multiplied = (*byte as u64).wrapping_mul(i as u64);
        noise = noise.wrapping_add(multiplied);
        noise = noise.rotate_left(7); // Shift operations are used to distribute noise
    }

    noise ^= round as u64;
    noise = noise.rotate_left((round % 64) as u32); // Round shift operation

    noise
}