//! BlueHash: A cryptographic hash function with quantum-resistant features.
// <Author: BlueOkanna>
// <Email: blueokanna@gmail.com>
//! This library implements the BlueHash algorithm, designed to resist quantum attacks
//! while maintaining high security. It includes state manipulation, constant generation,
//! and noise-based perturbations inspired by lattice-based cryptography.
//!
//! Full details and source code: https://github.com/blueokanna/BlueHash.
//!
//! # BlueHash Usage Example (BlueHash128)
//!
//! ```rust
//! use BlueHash::DigestSize;
//! use std::fmt::Write;
//! use BlueHash::Digest;
//! use BlueHash::BlueHashCore;
//!
//! fn main() {
//! let test_data = b"Hello, world! This is a test message for BlueHash";
//!     let mut hasher128 = BlueHashCore::new(DigestSize::Bit128);
//!     hasher128.update(test_data);
//!     let result128 = hasher128.finalize();
//!     println!("BlueHash128 Result: {}", to_hex_string(&result128));
//! }
//!
//! // Helper function to convert bytes to a hexadecimal string
//! fn to_hex_string(bytes: &[u8]) -> String {
//!     let mut hex = String::new();
//!     for byte in bytes {
//!         write!(&mut hex, "{:02x}", byte).unwrap();
//!     }
//!     hex
//! }
//! ```
//!
//! You may also refer to the BlueHash readme for more information.
//!
//! BlueHash: A cryptographic hash function with quantum-resistant features.
//!
//! This library implements the BlueHash algorithm, designed to resist quantum attacks
//! while maintaining high security. It includes state manipulation, constant generation,
//! and noise-based perturbations inspired by lattice-based cryptography.

mod constants;
mod noise;
mod utils;

pub use constants::generate_constants;
pub use noise::generate_lwe_noise;
pub use utils::to_u64;

use num_cpus;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use std::fmt;
use std::sync::{Arc, RwLock}; // 确保引用了 RwLock

/// Represents the available digest sizes for BlueHash.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DigestSize {
    Bit128,
    Bit256,
    Bit512,
}

impl DigestSize {
    fn round_count(&self) -> usize {
        match self {
            DigestSize::Bit128 => 56,
            DigestSize::Bit256 => 64,
            DigestSize::Bit512 => 80,
        }
    }

    fn digest_length(&self) -> usize {
        match self {
            DigestSize::Bit128 => 16,
            DigestSize::Bit256 => 32,
            DigestSize::Bit512 => 64,
        }
    }

    fn state_size(&self) -> usize {
        match self {
            DigestSize::Bit128 => 25,
            DigestSize::Bit256 => 32,
            DigestSize::Bit512 => 40,
        }
    }
}

/// Helper function to perform the common permutation logic
/// Optimized permutation using SIMD when available
pub fn permute_core(
    state: Arc<RwLock<Vec<u64>>>, // 使用 Arc<RwLock<Vec<u64>>> 来共享和保护状态
    input_data: &[u8],
    round_count: usize,
    state_size: usize,
    digest_size: DigestSize,
) -> Arc<RwLock<Vec<u64>>> {
    // 返回一个 Arc<RwLock<Vec<u64>>> 作为新状态
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(num_cpus::get() / 2)
        .build()
        .unwrap();

    let new_state = Arc::new(RwLock::new(vec![0u64; state_size]));

    thread_pool.install(|| {
        (0..round_count).for_each(|round| {
            let constant = generate_constants(round, input_data, digest_size.digest_length());
            let new_state = Arc::clone(&new_state);

            (0..state_size).into_par_iter().for_each(|i| {
                // 使用 RwLock 的 read 方法来获取共享数据
                let local_vars = {
                    let state = state.read().unwrap(); // 获取对状态的读取锁
                    [
                        state[(i + 1) % state_size],
                        state[(i + 2) % state_size],
                        state[(i + 3) % state_size],
                    ]
                };

                let new_value = {
                    let state = state.read().unwrap(); // 获取对状态的读取锁
                    state[i]
                        .wrapping_add(constant)
                        .wrapping_add(local_vars[0])
                        .rotate_left(29)
                        .wrapping_add(local_vars[1] & local_vars[2].rotate_right(17))
                        .rotate_left(23)
                };

                // 使用 RwLock 的 write 方法来更新数据
                let mut new_state_guard = new_state.write().unwrap();
                new_state_guard[i] = new_value;
            });
        });
    });

    Arc::clone(&new_state) // 返回 Arc<RwLock<Vec<u64>>> 新状态
}

/// Macro to define the architecture-specific permute function
macro_rules! define_permute {
    ($arch:literal, $target_feature:expr, $feature:ident) => {
        #[cfg(target_arch = $arch)]
        #[target_feature(enable = $target_feature)] // Enable target feature for specific architecture
        pub unsafe fn permute(
            state: Arc<RwLock<Vec<u64>>>, // 参数类型改为 Arc<RwLock<Vec<u64>>>
            input_data: &[u8],
            round_count: usize,
            state_size: usize,
            digest_size: DigestSize,
        ) {
            permute_core(state, input_data, round_count, state_size, digest_size);
        }
    };
}

/// Core structure for the BlueHash algorithm.
#[derive(Debug, Clone)]
pub struct BlueHashCore {
    state: Arc<RwLock<Vec<u64>>>, // 使用 Arc<RwLock<Vec<u64>>> 来保护状态
    round_count: usize,
    digest_size: DigestSize,
}

impl BlueHashCore {
    /// Creates a new instance of BlueHashCore.
    pub fn new(digest_size: DigestSize) -> Self {
        let state_size = digest_size.state_size();
        Self {
            state: Arc::new(RwLock::new(vec![0u64; state_size])), // 初始化 RwLock
            round_count: digest_size.round_count(),
            digest_size,
        }
    }

    // For x86_64 architecture using AVX2
    define_permute!("x86_64", "avx2", avx2);

    // For ARM 64-bit architecture using NEON
    define_permute!("aarch64", "neon", neon);
}

/// Trait defining a cryptographic hash function.
pub trait Digest {
    fn update(&mut self, data: &[u8]);
    fn finalize(&self) -> Vec<u8>;
    fn reset(&mut self);
}

impl Digest for BlueHashCore {
    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(8) {
            let block = chunk
                .iter()
                .fold(0u64, |acc, &byte| (acc << 8) | (byte as u64));
            // 使用 write() 锁定 state 进行修改
            let mut state_guard = self.state.write().unwrap();
            state_guard[0] ^= block;
        }

        // 克隆 state 的数据并传递到 permute_core
        let state_clone = Arc::clone(&self.state); // 传递 Arc<RwLock<Vec<u64>>> 给 permute_core
        let state_size = self.digest_size.state_size();
        let new_state = permute_core(
            state_clone, // 使用 Arc<RwLock<Vec<u64>>> 传递
            data,
            self.round_count,
            state_size,
            self.digest_size,
        );

        // 更新状态
        let mut state_guard = self.state.write().unwrap();
        let new_state_guard = new_state.read().unwrap();
        state_guard.copy_from_slice(&new_state_guard);
    }

    fn finalize(&self) -> Vec<u8> {
        let digest_length = self.digest_size.digest_length();
        let mut result = vec![0u8; digest_length];
        let state_size = self.digest_size.state_size();

        for (i, chunk) in result.chunks_mut(8).enumerate() {
            let idx = i % state_size;
            let bytes = self.state.read().unwrap()[idx].to_be_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }

        result
    }

    fn reset(&mut self) {
        let mut state_guard = self.state.write().unwrap();
        state_guard.fill(0);
    }
}

impl fmt::Display for BlueHashCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueHash(DigestSize: {:?})", self.digest_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bluehash128() {
        let mut hasher = BlueHashCore::new(DigestSize::Bit128);
        hasher.update(b"Hello, world! This is a test message for BlueHash");
        let result = hasher.finalize();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_bluehash256() {
        let mut hasher = BlueHashCore::new(DigestSize::Bit256);
        hasher.update(b"Hello, world! This is a test message for BlueHash");
        let result = hasher.finalize();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_bluehash512() {
        let mut hasher = BlueHashCore::new(DigestSize::Bit512);
        hasher.update(b"Hello, world! This is a test message for BlueHash");
        let result = hasher.finalize();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_reset() {
        let mut hasher = BlueHashCore::new(DigestSize::Bit256);
        hasher.update(b"Hello, world! This is a test message for BlueHash");
        hasher.reset();
        let result = hasher.finalize();
        assert_eq!(result, vec![0u8; 32]);
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(DigestSize::Bit128, DigestSize::Bit128);
        assert_ne!(DigestSize::Bit128, DigestSize::Bit256);
    }
}
