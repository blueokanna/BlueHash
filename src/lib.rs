const STATE_SIZE: usize = 25;

#[derive(Debug)]
enum DigestSize {
    Bit128,
    Bit256,
    Bit512,
}

impl DigestSize {
    // Method to return the number of rounds based on the digest size.
    fn round_count(&self) -> usize {
        match self {
            DigestSize::Bit128 => 56,
            DigestSize::Bit256 => 64,
            DigestSize::Bit512 => 80,
        }
    }

    // Method to return the length of the hash output in bytes.
    fn digest_length(&self) -> usize {
        match self {
            DigestSize::Bit128 => 16,
            DigestSize::Bit256 => 32,
            DigestSize::Bit512 => 64,
        }
    }
}

// Generate a noise value based on input data and the current round number.
fn generate_lwe_noise(input_data: &[u8], round: usize) -> u64 {
    let mut hash = 0u64;
    for (i, byte) in input_data.iter().enumerate() {
        // Update the hash by combining each byte with its index, using multiplication and addition.
        hash = hash.wrapping_add((*byte as u64).wrapping_mul(i as u64));
    }
    // XOR the hash with the round number, and rotate the result to the left.
    hash ^= round as u64;
    hash.rotate_left((round % 64) as u32)
}

// Generate a constant value based on the round number and input data for use in the permutation.
fn generate_constants(round: usize, input_data: &[u8], hash_length: usize) -> u64 {
    let prime = 0x9e3779b97f4a7c15u64; // Prime constant for hash calculations
    let round_factor = (round as u64).wrapping_add(0xabcdef1234567890); // Round factor constant
    let extra_prime = 0x7fffffffffffffffu64; // Extra large prime constant
    let noise = generate_lwe_noise(input_data, round);

    // Combine constants, round factor, and noise using bit rotations and arithmetic operations.
    let rotated_prime = prime.rotate_left((round % 64) as u32);
    rotated_prime
        .wrapping_mul(round_factor.rotate_left(32))
        .wrapping_add(round_factor.rotate_right(16))
        .wrapping_add(extra_prime.rotate_left((round % 32) as u32))
        .wrapping_add(noise.rotate_left(8))
        .wrapping_add(hash_length as u64)
}


#[derive(Debug)]
pub struct BlueHash {
    state: [u64; STATE_SIZE],
    round_count: usize,
    digest_size: DigestSize,
}

impl BlueHash {
    // Create a new BlueHash instance with the given digest size.
    pub fn new(digest_size: DigestSize) -> Self {
        Self {
            state: [0u64; STATE_SIZE], // Initialize state to zero
            round_count: digest_size.round_count(),
            digest_size,
        }
    }

    // Update the hash state with new data in chunks of 8 bytes.
    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(8) {
            // Convert chunk of data to a u64 value.
            let block = Self::to_u64(chunk);
            self.state[0] ^= block; // XOR with the first state element
            self.permute(data); // Apply permutation function to the state
        }
    }

    // Permutation function that applies transformations to the internal state.
    pub fn permute(&mut self, input_data: &[u8]) {
        let mut local_vars: [u64; 5];
        for round in 0..self.round_count {
            // Generate a constant for the current round.
            let constant = generate_constants(round, input_data, self.round_count);

            for i in 0..STATE_SIZE {
                // Access state elements cyclically for local variables.
                local_vars = [
                    self.state[(i + 1) % STATE_SIZE],
                    self.state[(i + 2) % STATE_SIZE],
                    self.state[(i + 3) % STATE_SIZE],
                    self.state[(i + 4) % STATE_SIZE],
                    self.state[(i + 5) % STATE_SIZE],
                ];

                // Apply bit rotations, arithmetic operations, and bitwise operations to update the state.
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

    // Finalize the hash calculation and return the hash output as a byte vector.
    pub fn finalize(&self) -> Vec<u8> {
        let digest_size = self.digest_size.digest_length();
        let mut result = vec![0u8; digest_size]; // Initialize result buffer
        let mut output_idx = 0;

        // Copy state values into the result buffer until the digest length is filled.
        while output_idx < digest_size {
            let idx = (output_idx / 8) % STATE_SIZE;
            let val = self.state[idx];
            let bytes = val.to_be_bytes();

            // Copy the required number of bytes from the state value.
            let copy_len = usize::min(8, digest_size - output_idx);
            result[output_idx..output_idx + copy_len].copy_from_slice(&bytes[..copy_len]);
            output_idx += copy_len;
        }

        result
    }

    // Convert a byte slice (chunk) into a u64 integer.
    pub fn to_u64(chunk: &[u8]) -> u64 {
        chunk.iter().fold(0, |acc, &b| (acc << 8) | b as u64)
    }
}
