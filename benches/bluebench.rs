use std::collections::HashSet;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use rand::Rng;

const STATE_SIZE: usize = 25;  // Sponge state size

#[derive(Debug, Clone, Copy)]  // 为 DigestSize 添加 Copy 和 Clone trait
enum DigestSize {
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
}

fn generate_lwe_noise(input_data: &[u8], round: usize) -> u64 {
    let mut hash = 0u64;
    for (i, byte) in input_data.iter().enumerate() {
        hash = hash.wrapping_add((*byte as u64).wrapping_mul(i as u64));
    }
    hash ^= round as u64;
    hash.rotate_left((round % 64) as u32)
}

fn generate_constants(round: usize, input_data: &[u8], hash_length: usize) -> u64 {
    let prime = 0x9e3779b97f4a7c15u64;
    let round_factor = (round as u64).wrapping_add(0xabcdef1234567890);
    let extra_prime = 0x7fffffffffffffffu64;
    let noise = generate_lwe_noise(input_data, round);

    let rotated_prime = prime.rotate_left((round % 64) as u32);
    rotated_prime
        .wrapping_mul(round_factor.rotate_left(32))
        .wrapping_add(round_factor.rotate_right(16))
        .wrapping_add(extra_prime.rotate_left((round % 32) as u32))
        .wrapping_add(noise.rotate_left(8))
        .wrapping_add(hash_length as u64)
}

#[derive(Debug)]
struct BlueHash {
    state: [u64; STATE_SIZE],
    round_count: usize,
    digest_size: DigestSize,
}

impl BlueHash {
    fn new(digest_size: DigestSize) -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            round_count: digest_size.round_count(),
            digest_size,
        }
    }

    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(8) {
            let block = Self::to_u64(chunk);
            self.state[0] ^= block;
            self.permute(data);
        }
    }

    fn permute(&mut self, input_data: &[u8]) {
        let mut local_vars: [u64; 5];
        for round in 0..self.round_count {
            let constant = generate_constants(round, input_data, self.round_count);

            for i in 0..STATE_SIZE {
                local_vars = [
                    self.state[(i + 1) % STATE_SIZE],
                    self.state[(i + 2) % STATE_SIZE],
                    self.state[(i + 3) % STATE_SIZE],
                    self.state[(i + 4) % STATE_SIZE],
                    self.state[(i + 5) % STATE_SIZE],
                ];

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

    fn finalize(&self) -> Vec<u8> {
        let digest_size = self.digest_size.digest_length();
        let mut result = vec![0u8; digest_size];
        let mut output_idx = 0;

        while output_idx < digest_size {
            let idx = (output_idx / 8) % STATE_SIZE;
            let val = self.state[idx];
            let bytes = val.to_be_bytes();

            let copy_len = usize::min(8, digest_size - output_idx);
            result[output_idx..output_idx + copy_len].copy_from_slice(&bytes[..copy_len]);
            output_idx += copy_len;
        }

        result
    }

    fn to_u64(chunk: &[u8]) -> u64 {
        chunk.iter().fold(0, |acc, &b| (acc << 8) | b as u64)
    }
}

fn collision_test(digest_size: DigestSize, trials: usize) -> f64 {
    let mut rng = rand::thread_rng();
    let mut hashes = HashSet::new();
    let mut collisions = 0;

    for _ in 0..trials {
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::new(digest_size);
        hash.update(&data);
        let result = hash.finalize();

        if !hashes.insert(result) {
            collisions += 1;
        }
    }

    collisions as f64 / trials as f64
}

fn differential_attack_test(digest_size: DigestSize, trials: usize) -> f64 {
    let mut rng = rand::thread_rng();
    let mut avalanche_effect = 0.0;

    for _ in 0..trials {
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::new(digest_size);
        hash.update(&data);
        let original_hash = hash.finalize();

        let mut modified_data = data.clone();
        modified_data[0] ^= 0x01; // Flip one bit

        let mut modified_hash = BlueHash::new(digest_size);
        modified_hash.update(&modified_data);
        let modified_result = modified_hash.finalize();

        let bit_diff = original_hash.iter()
            .zip(modified_result.iter())
            .map(|(a, b)| (a ^ b).count_ones() as f64)
            .sum::<f64>();

        avalanche_effect += bit_diff / (original_hash.len() * 8) as f64;
    }

    avalanche_effect / trials as f64
}

fn bench_bluehash(c: &mut Criterion) {
    let data = b"Benchmarking BlueHash performance";

    // Performance Benchmark
    c.bench_function("BlueHash 128-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::new(DigestSize::Bit128);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    c.bench_function("BlueHash 256-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::new(DigestSize::Bit256);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    c.bench_function("BlueHash 512-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::new(DigestSize::Bit512);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    // Security Testing
    let collision_rate_128 = collision_test(DigestSize::Bit128, 100000);   //1000w
    println!("128-bit collision rate: {}", collision_rate_128);

    let avalanche_effect_128 = differential_attack_test(DigestSize::Bit128, 100000);
    println!("128-bit differential attack avalanche effect: {}", avalanche_effect_128);

    let collision_rate_256 = collision_test(DigestSize::Bit256, 100000);
    println!("256-bit collision rate: {}", collision_rate_256);

    let avalanche_effect_256 = differential_attack_test(DigestSize::Bit256, 100000);
    println!("256-bit differential attack avalanche effect: {}", avalanche_effect_256);

    let collision_rate_512 = collision_test(DigestSize::Bit512, 100000);
    println!("512-bit collision rate: {}", collision_rate_512);

    let avalanche_effect_512 = differential_attack_test(DigestSize::Bit512, 100000);
    println!("512-bit differential attack avalanche effect: {}", avalanche_effect_512);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(60))
        .sample_size(1500);
    targets = bench_bluehash
}
criterion_main!(benches);
