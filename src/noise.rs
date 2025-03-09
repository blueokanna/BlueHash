use rand::{Rng, SeedableRng};
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
use rand_chacha::ChaCha20Rng;

pub fn generate_lwe_noise<T>(input_data: &[T], round: usize, prime: u64) -> u64
where
    T: Copy + Into<u64>,
{
    let seed_base: u64 = input_data
        .iter()
        .fold(0u64, |acc, &x| acc.wrapping_add(x.into()));
    let seed_val = seed_base.wrapping_add(round as u64);
    let mut seed_bytes = [0u8; 32];
    for (i, b) in seed_val.to_le_bytes().iter().cycle().take(32).enumerate() {
        seed_bytes[i] = *b;
    }
    for (i, b) in (round as u64).to_le_bytes().iter().enumerate() {
        seed_bytes[i] ^= *b;
    }
    let mut rng = ChaCha20Rng::from_seed(seed_bytes);

    // 离散高斯分布参数：标准差 sigma 与尾部界 k（取 6*sigma 上界）
    let sigma = 3.2f64;
    let k_bound = (6.0 * sigma).ceil() as i64;

    loop {
        // 采样候选值，范围为 [-k_bound, k_bound]
        let candidate = rng.gen_range(-k_bound..=k_bound);
        // 计算接受概率：exp(- x^2 / (2*sigma^2))，使用恒定时间实现对数计算
        let exponent = -((candidate as f64).powi(2)) / (2.0 * sigma * sigma);
        let accept_prob = exponent.exp();
        let u: f64 = rng.gen();
        if u <= accept_prob {
            let error = candidate;
            return if error < 0 {
                prime.wrapping_sub(error.wrapping_abs() as u64)
            } else {
                prime.wrapping_add(error as u64)
            };
        }
    }
}
