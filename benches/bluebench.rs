use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use rayon::prelude::*;
use rand::Rng;
const STATE_SIZE: usize = 25;

#[derive(Debug, Clone, Copy)]
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
}

#[warn(unused_variables)]
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

pub fn generate_constants(round: usize, input_data: &[u8], hash_length: usize) -> u64 {
    let prime = 0x9e3779b97f4a7c15u64;
    let round_factor = (round as u64).wrapping_add(0xabcdef1234567890);
    let extra_prime = 0x7fffffffffffffffu64;
    let noise = generate_lwe_noise(input_data, round, prime);

    // Calculate the rotation value in advance
    let round_factor_rot_left = round_factor.rotate_left(32);
    let round_factor_rot_right = round_factor.rotate_right(16);
    let rotated_prime = prime.rotate_left((round % 64) as u32);
    let extra_prime_rot_left = extra_prime.rotate_left((round % 32) as u32);
    let noise_rot_left = noise.rotate_left(8);

    // Reduce double counting by using already calculated rotation values
    rotated_prime
        .wrapping_mul(round_factor_rot_left)
        .wrapping_add(round_factor_rot_right)
        .wrapping_add(extra_prime_rot_left)
        .wrapping_add(noise_rot_left)
        .wrapping_add(hash_length as u64)
}


#[derive(Debug, Clone, Copy)]
struct BlueHash {
    state: [u64; STATE_SIZE],
    round_count: usize,
    digest_size: DigestSize,
}

impl BlueHash {
    pub fn new(digest_size: &DigestSize) -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            round_count: digest_size.round_count(),
            digest_size: digest_size.clone(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(8) {
            let block = Self::to_u64(chunk);
            self.state[0] ^= block;
            self.permute(data);
        }
    }

    fn permute(&mut self, input_data: &[u8]) {
        let mut queue: VecDeque<u64> = VecDeque::new();

        // Using the idea of Merkle tree to reduce repeated calculations
        for round in 0..self.round_count {
            let constant = generate_constants(round, input_data, self.round_count);
            let state = &mut self.state;

            // Change the state update to a divide-and-conquer calculation on a tree structure
            for i in 0..STATE_SIZE {
                let local_vars = [
                    state[(i + 1) % STATE_SIZE],
                    state[(i + 2) % STATE_SIZE],
                    state[(i + 3) % STATE_SIZE],
                    state[(i + 4) % STATE_SIZE],
                    state[(i + 5) % STATE_SIZE],
                ];

                let tmp = state[i]
                    .wrapping_add(constant)
                    .wrapping_add(local_vars[2])
                    .rotate_left(29)
                    .wrapping_add(local_vars[0] & local_vars[1])
                    .wrapping_add(local_vars[3].rotate_right(17))
                    .rotate_left(23);

                queue.push_back(tmp);
            }

            // After each round of calculation, the update of the state value is optimized through the queue
            for i in 0..STATE_SIZE {
                self.state[i] = queue.pop_front().unwrap_or(0);
            }
        }
    }


    pub fn finalize(&self) -> Vec<u8> {
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

    pub fn to_u64(chunk: &[u8]) -> u64 {
        chunk.iter().fold(0, |acc, &b| (acc << 8) | b as u64)
    }
}

// 并行碰撞测试
pub fn parallel_collision_test(digest_size: DigestSize, trials: usize, num_threads: usize) -> f64 {
    let hashes = Arc::new(Mutex::new(HashSet::new())); // Shared HashSet, multiple threads can access
    let collisions = Arc::new(Mutex::new(0)); // Shared collision counter

    let trials_per_thread = trials / num_threads;

    let mut handles = vec![];

    for _ in 0..num_threads {
        let hashes = Arc::clone(&hashes);
        let collisions = Arc::clone(&collisions);

        let handle = thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let mut local_hashes = HashSet::new();
            let mut local_collisions = 0;

            for _ in 0..trials_per_thread {
                let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
                let mut hash = BlueHash::new(&digest_size);
                hash.update(&data);
                let result = hash.finalize();

                // Detecting Collisions
                if !local_hashes.insert(result.to_vec()) {
                    local_collisions += 1;
                }
            }

            // Merge local collisions and HashSets into global
            let mut global_hashes = hashes.lock().unwrap();
            global_hashes.extend(local_hashes); // Merge local HashSet
            let mut global_collisions = collisions.lock().unwrap();
            *global_collisions += local_collisions; // Update global collision count
        });

        handles.push(handle);
    }

    // Wait for all threads to finish executing
    for handle in handles {
        handle.join().unwrap();
    }

    // Calculate the total collision rate
    let collisions_count = *collisions.lock().unwrap();
    collisions_count as f64 / trials as f64
}

// 差分攻击测试
pub fn differential_attack_test(digest_size: DigestSize, trials: usize) -> f64 {
    let avalanche_effects: Vec<f64> = (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::new(&digest_size);
        hash.update(&data);
        let original_hash = hash.finalize();

        let mut modified_data = data.clone();
        let mod_type = rng.gen_range(0..3);
        match mod_type {
            0 => modified_data[0] ^= 0x01,
            1 => modified_data[0..8].reverse(),
            2 => modified_data[16..24].fill(0xFF),
            _ => {}
        }

        let mut modified_hash = BlueHash::new(&digest_size);
        modified_hash.update(&modified_data);
        let modified_result = modified_hash.finalize();

        let bit_diff = original_hash.iter()
            .zip(modified_result.iter())
            .map(|(a, b)| (a ^ b).count_ones() as f64)
            .sum::<f64>();

        bit_diff / (original_hash.len() * 8) as f64
    }).collect();

    avalanche_effects.iter().sum::<f64>() / trials as f64
}

// 第二原像攻击
pub fn second_preimage_attack(digest_size: DigestSize, trials: usize) -> f64 {
    let successful_attacks: Vec<f64> = (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::new(&digest_size);
        hash.update(&data);
        let original_hash = hash.finalize();

        let mut second_data = data.clone();
        second_data[0] ^= 0x01;

        let mut second_hash = BlueHash::new(&digest_size);
        second_hash.update(&second_data);
        let second_hash_result = second_hash.finalize();

        if original_hash == second_hash_result {
            1.0
        } else {
            0.0
        }
    }).collect();

    successful_attacks.iter().sum::<f64>() / trials as f64
}

// 向前安全性测试
pub fn forward_security_test(digest_size: DigestSize, trials: usize) -> f64 {
    let success_count: Vec<f64> = (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::new(&digest_size);
        hash.update(&data);
        let hash_result = hash.finalize();

        let guess: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut guess_hash = BlueHash::new(&digest_size);
        guess_hash.update(&guess);
        let guess_result = guess_hash.finalize();

        if guess_result == hash_result {
            1.0
        } else {
            0.0
        }
    }).collect();

    success_count.iter().sum::<f64>() / trials as f64
}

// 生日攻击
pub fn birthday_attack(digest_size: DigestSize, trials: usize) -> f64 {
    let collisions: Vec<f64> = (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::new(&digest_size);
        hash.update(&data);
        let result = hash.finalize();

        let mut hashes = HashSet::new();
        if !hashes.insert(result) {
            1.0
        } else {
            0.0
        }
    }).collect();

    collisions.iter().sum::<f64>() / trials as f64
}

// 长度扩展攻击
pub fn length_extension_attack(digest_size: DigestSize, trials: usize) -> f64 {
    let successful_attacks: Vec<f64> = (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::new(&digest_size);
        hash.update(&data);
        let original_hash = hash.finalize();

        let extra_data: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        let mut attack_data = data.clone();
        attack_data.extend(extra_data.clone());

        let mut attack_hash = BlueHash::new(&digest_size);
        attack_hash.update(&attack_data);
        let attack_result = attack_hash.finalize();

        if attack_result == original_hash {
            1.0
        } else {
            0.0
        }
    }).collect();

    successful_attacks.iter().sum::<f64>() / trials as f64
}


pub fn bench_bluehash(c: &mut Criterion) {
    let data = b"A benchmark for BlueHash performance";

    c.bench_function("BlueHash 128-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::new(&DigestSize::Bit128);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    c.bench_function("BlueHash 256-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::new(&DigestSize::Bit256);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    c.bench_function("BlueHash 512-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::new(&DigestSize::Bit512);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    println!("Collision attack test (128-bit): {}", parallel_collision_test(DigestSize::Bit128, 1000000, 12));
    println!("Differential attack test (128-bit): {}", differential_attack_test(DigestSize::Bit128, 1000000));
    println!("Second preimage attack (128-bit): {}", second_preimage_attack(DigestSize::Bit128, 1000000));
    println!("Forward security test (128-bit): {}", forward_security_test(DigestSize::Bit128, 1000000));
    println!("Birthday attack (128-bit): {}", birthday_attack(DigestSize::Bit128, 1000000));
    println!("Length extension attack (128-bit): {}", length_extension_attack(DigestSize::Bit128, 100000));

    println!("\n");
    println!("Collision attack test (256-bit): {}", parallel_collision_test(DigestSize::Bit256, 1000000, 13));
    println!("Differential attack test (256-bit): {}", differential_attack_test(DigestSize::Bit256, 1000000));
    println!("Second preimage attack (256-bit): {}", second_preimage_attack(DigestSize::Bit256, 1000000));
    println!("Forward security test (256-bit): {}", forward_security_test(DigestSize::Bit256, 1000000));
    println!("Birthday attack (256-bit): {}", birthday_attack(DigestSize::Bit256, 1000000));
    println!("Length extension attack (256-bit): {}", length_extension_attack(DigestSize::Bit256, 100000));

    println!("\n");
    println!("Collision attack test (512-bit): {}", parallel_collision_test(DigestSize::Bit512, 1000000, 14));
    println!("Differential attack test (512-bit): {}", differential_attack_test(DigestSize::Bit512, 1000000));
    println!("Second preimage attack (512-bit): {}", second_preimage_attack(DigestSize::Bit512, 1000000));
    println!("Forward security test (512-bit): {}", forward_security_test(DigestSize::Bit512, 1000000));
    println!("Birthday attack (512-bit): {}", birthday_attack(DigestSize::Bit512, 1000000));
    println!("Length extension attack (512-bit): {}", length_extension_attack(DigestSize::Bit512, 100000));
}

criterion_group! {
    name = benches;
    config = Criterion::default()
    .measurement_time(Duration::from_secs(15))
    .sample_size(1000);

    targets = bench_bluehash
}
criterion_main!(benches);
