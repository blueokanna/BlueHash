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

use crate::constants::{generate_constants, SBOX};
use crate::noise::generate_lwe_noise;
use rayon::prelude::*;
use std::fmt;
use std::fmt::Write;

/// 摘要大小及相关参数定义
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DigestSize {
    Bit128,
    Bit256,
    Bit512,
}

impl DigestSize {
    pub fn round_count(&self) -> usize {
        // 为增强抗量子安全性，置换轮次加倍
        match self {
            DigestSize::Bit128 => 56 * 2,
            DigestSize::Bit256 => 64 * 2,
            DigestSize::Bit512 => 80 * 2,
        }
    }
    pub fn digest_length(&self) -> usize {
        match self {
            DigestSize::Bit128 => 16,
            DigestSize::Bit256 => 32,
            DigestSize::Bit512 => 64,
        }
    }
    pub fn state_size(&self) -> usize {
        match self {
            DigestSize::Bit128 => 25,
            DigestSize::Bit256 => 32,
            DigestSize::Bit512 => 40,
        }
    }
}

/// 置换函数，增加 S‑盒查表非线性转换
pub fn permute_core(
    state: &[u64],
    input_data: &[u8],
    round: usize,
    state_size: usize,
    digest_size: DigestSize,
) -> Vec<u64> {
    let constant = generate_constants(round, input_data, digest_size.digest_length());
    (0..state_size)
        .into_par_iter()
        .map(|i| {
            let a = state[i];
            let b = state[(i + 1) % state_size];
            let c = state[(i + 2) % state_size];
            let d = state[(i + 3) % state_size];
            let mut mixed = a
                .wrapping_add(constant)
                .wrapping_add(b)
                .rotate_left(29)
                .wrapping_add(c & d.rotate_right(17))
                .rotate_left(23);
            // 对混合结果每个字节执行 S‑盒查表替换（实现恒定时间操作）
            let mut bytes = mixed.to_be_bytes();
            for byte in &mut bytes {
                // 采用数组索引替换，不分支实现
                *byte = SBOX[*byte as usize];
            }
            mixed = u64::from_be_bytes(bytes);
            mixed
        })
        .collect()
}

/// BlueHash 核心结构，采用固定 IV 初始化，并累积输入数据
#[derive(Debug, Clone)]
pub struct BlueHashCore {
    state: Vec<u64>,
    round_count: usize,
    digest_size: DigestSize,
    total_len: u128,       // 累计输入字节数
    input_buffer: Vec<u8>, // 保存输入数据（仅用于后续填充计算）
}

impl BlueHashCore {
    /// 固定 IV：根据摘要大小返回预设定的初始状态
    fn fixed_iv(digest_size: DigestSize) -> Vec<u64> {
        match digest_size {
            DigestSize::Bit128 => vec![
                0x0123456789ABCDEF,
                0x23456789ABCDEF01,
                0x456789ABCDEF0123,
                0x6789ABCDEF012345,
                0x89ABCDEF01234567,
                0xABCDEF0123456789,
                0xCDEF0123456789AB,
                0xEF0123456789ABCD,
                0x13579BDF02468ACE,
                0x2468ACE13579BDF0,
                0x3579BDF02468ACE1,
                0x468ACE13579BDF02,
                0x579BDF02468ACE13,
                0x68ACE13579BDF24,
                0x79BDF02468ACE35,
                0x8ACE13579BDF468,
                0x9BDF02468ACE579,
                0xACE13579BDF68AC,
                0xBDF02468ACE79BD,
                0xCE13579BDF8ACE0,
                0xDF02468ACE9BDF1,
                0xE13579BDFACE135,
                0xF02468ACEBDF024,
                0x0123456789ABCDEF,
                0x89ABCDEF01234567,
            ],
            DigestSize::Bit256 => {
                let mut iv = Self::fixed_iv(DigestSize::Bit128);
                iv.extend_from_slice(&[
                    0x23456789ABCDEF01,
                    0x456789ABCDEF0123,
                    0x6789ABCDEF012345,
                    0x89ABCDEF01234567,
                    0xABCDEF0123456789,
                    0xCDEF0123456789AB,
                    0xEF0123456789ABCD,
                ]);
                iv.resize(32, 0x0123456789ABCDEF);
                iv
            }
            DigestSize::Bit512 => {
                let mut iv = Self::fixed_iv(DigestSize::Bit128);
                iv.extend_from_slice(&[
                    0x23456789ABCDEF01,
                    0x456789ABCDEF0123,
                    0x6789ABCDEF012345,
                    0x89ABCDEF01234567,
                    0xABCDEF0123456789,
                    0xCDEF0123456789AB,
                    0xEF0123456789ABCD,
                    0x13579BDF02468ACE,
                    0x2468ACE13579BDF0,
                    0x3579BDF02468ACE1,
                    0x468ACE13579BDF02,
                    0x579BDF02468ACE13,
                    0x68ACE13579BDF24,
                    0x79BDF02468ACE35,
                ]);
                iv.resize(40, 0x0123456789ABCDEF);
                iv
            }
        }
    }

    /// 构造新的 BlueHash 实例，使用固定 IV 初始化状态和输入缓冲区
    pub fn new(digest_size: DigestSize) -> Self {
        let state = Self::fixed_iv(digest_size);
        Self {
            state,
            round_count: digest_size.round_count(),
            digest_size,
            total_len: 0,
            input_buffer: Vec::new(),
        }
    }

    /// 优化填充函数，处理最后分块：添加 0x80 后补零至块边界，再附加128位长度信息
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        let block_size = 8;
        let mut padded = data.to_vec();
        padded.push(0x80);
        // 补全到 block_size 整倍数（留出 16 字节长度信息空间）
        while (padded.len() + 16) % block_size != 0 {
            padded.push(0);
        }
        let total_bits = self.total_len.wrapping_mul(8);
        padded.extend_from_slice(&total_bits.to_be_bytes());
        padded
    }

    /// 最终混合：将总长度信息引入状态，并进行额外轮次置换（所有循环均采用固定步长以实现恒定时间操作）
    fn final_mix(&mut self, extra_data: &[u8]) {
        // 在状态中混入总长度（注意转换为 u64 后执行恒定时间 XOR）
        self.state[0] ^= self.total_len.wrapping_mul(8) as u64;
        self.state[0] ^= 0x80;
        let padded = self.pad(extra_data);
        for round in self.round_count..(self.round_count + 4) {
            self.state = permute_core(
                &self.state,
                &padded,
                round,
                self.digest_size.state_size(),
                self.digest_size,
            );
        }
    }
}

/// 定义哈希接口
pub trait Digest {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
    fn reset(&mut self);
}

impl Digest for BlueHashCore {
    fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);
        self.input_buffer.extend_from_slice(data);
        let state_size = self.digest_size.state_size();
        for (i, chunk) in data.chunks(8).enumerate() {
            let block = chunk
                .iter()
                .fold(0u64, |acc, &byte| (acc << 8) | byte as u64);
            let idx = i % state_size;
            // 使用固定步长旋转以实现恒定时间操作
            self.state[idx] ^= block.rotate_left(((i as u32).wrapping_mul(7)) % 64);
        }
        for round in 0..self.round_count {
            self.state = permute_core(
                &self.state,
                data,
                round,
                self.digest_size.state_size(),
                self.digest_size,
            );
        }
    }

    fn finalize(&mut self) -> Vec<u8> {
        self.final_mix(&[]);
        let digest_length = self.digest_size.digest_length();
        let state_size = self.digest_size.state_size();
        let mut result = vec![0u8; digest_length];
        for (i, chunk) in result.chunks_mut(8).enumerate() {
            let idx = i % state_size;
            let bytes = self.state[idx].to_be_bytes();
            // 采用恒定时间复制（无早期返回）
            for (j, b) in bytes.iter().enumerate().take(chunk.len()) {
                chunk[j] = *b;
            }
        }
        result
    }

    fn reset(&mut self) {
        // 重新使用固定 IV 初始化状态，采用恒定时间清零输入缓冲区
        self.state = BlueHashCore::fixed_iv(self.digest_size);
        self.total_len = 0;
        for b in self.input_buffer.iter_mut() {
            *b = 0;
        }
        self.input_buffer.clear();
    }
}

impl fmt::Display for BlueHashCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueHash(DigestSize: {:?})", self.digest_size)
    }
}

/// 常量时间比较函数，防止侧信道泄露（所有比较采用固定循环时间）
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{generate_constants, SBOX};
    use crate::noise::generate_lwe_noise;

    #[test]
    fn test_bluehash128() {
        let mut hasher = BlueHashCore::new(DigestSize::Bit128);
        hasher.update("测试消息123".as_bytes());
        let result = hasher.finalize();
        // 此处不使用硬编码测试向量，而是检测输出长度
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_bluehash256() {
        let mut hasher = BlueHashCore::new(DigestSize::Bit256);
        hasher.update("测试消息123".as_bytes());
        let result = hasher.finalize();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_bluehash512() {
        let mut hasher = BlueHashCore::new(DigestSize::Bit512);
        hasher.update("测试消息123".as_bytes());
        let result = hasher.finalize();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_reset() {
        let mut hasher = BlueHashCore::new(DigestSize::Bit256);
        hasher.update("任意数据".as_bytes());
        hasher.reset();
        let result = hasher.finalize();
        let expected = BlueHashCore::new(DigestSize::Bit256).finalize();
        assert!(constant_time_eq(&result, &expected));
    }

    #[test]
    fn test_generate_constants() {
        let data: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78];
        let result = generate_constants(5, &data, 32);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_integer_noise() {
        let data: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78];
        let result = generate_lwe_noise(&data, 5, 0x9E3779B97F4A7C15);
        assert_ne!(result, 0);
    }
}

// 辅助函数：将字节转换为 16 进制字符串
fn to_hex_string(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for byte in bytes {
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    hex
}

fn main() {
    let test_data = "金融级安全测试".as_bytes();
    let mut hasher = BlueHashCore::new(DigestSize::Bit256);
    hasher.update(test_data);
    let result = hasher.finalize();
    println!("BlueHash256 Result: {}", to_hex_string(&result));
}
