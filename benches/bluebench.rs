use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use rayon::prelude::*;
use BlueHash::{Digest, DigestSize};

// 并行碰撞测试
pub fn parallel_collision_test(digest_size: DigestSize, trials: usize, num_threads: usize) -> f64 {
    let hashes = Arc::new(Mutex::new(HashSet::new()));
    let collisions = Arc::new(Mutex::new(0));
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
                let mut hash = BlueHash::BlueHashCore::new(digest_size);
                hash.update(&data);
                let result = hash.finalize();

                if !local_hashes.insert(result) {
                    local_collisions += 1;
                }
            }

            let mut global_hashes = hashes.lock().unwrap();
            global_hashes.extend(local_hashes);
            let mut global_collisions = collisions.lock().unwrap();
            *global_collisions += local_collisions;
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let collisions_count = *collisions.lock().unwrap();
    collisions_count as f64 / trials as f64
}

// 差分攻击测试
pub fn differential_attack_test(digest_size: DigestSize, trials: usize) -> f64 {
    let avalanche_effects: Vec<f64> = (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::BlueHashCore::new(digest_size);
        hash.update(&data);
        let original_hash = hash.finalize();

        let mut modified_data = data.clone();
        match rng.gen_range(0..3) {
            0 => modified_data[0] ^= 0x01,
            1 => modified_data[0..8].reverse(),
            2 => modified_data[16..24].fill(0xFF),
            _ => {}
        }

        let mut modified_hash = BlueHash::BlueHashCore::new(digest_size);
        modified_hash.update(&modified_data);
        let modified_result = modified_hash.finalize();

        original_hash.iter()
            .zip(modified_result.iter())
            .map(|(a, b)| (a ^ b).count_ones() as f64)
            .sum::<f64>() / (original_hash.len() * 8) as f64
    }).collect();

    avalanche_effects.iter().sum::<f64>() / trials as f64
}

// 第二原像攻击
pub fn second_preimage_attack(digest_size: DigestSize, trials: usize) -> f64 {
    (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::BlueHashCore::new(digest_size);
        hash.update(&data);
        let original_hash = hash.finalize();

        let mut second_data = data.clone();
        second_data[0] ^= 0x01;

        let mut second_hash = BlueHash::BlueHashCore::new(digest_size);
        second_hash.update(&second_data);
        let second_hash_result = second_hash.finalize();

        if original_hash == second_hash_result { 1.0 } else { 0.0 }
    }).sum::<f64>() / trials as f64
}

// 向前安全性测试
pub fn forward_security_test(digest_size: DigestSize, trials: usize) -> f64 {
    (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::BlueHashCore::new(digest_size);
        hash.update(&data);
        let hash_result = hash.finalize();

        let guess: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut guess_hash = BlueHash::BlueHashCore::new(digest_size);
        guess_hash.update(&guess);
        let guess_result = guess_hash.finalize();

        if guess_result == hash_result { 1.0 } else { 0.0 }
    }).sum::<f64>() / trials as f64
}

// 生日攻击
pub fn birthday_attack(digest_size: DigestSize, trials: usize) -> f64 {
    (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::BlueHashCore::new(digest_size);
        hash.update(&data);
        let result = hash.finalize();

        let mut hashes = HashSet::new();
        if !hashes.insert(result) { 1.0 } else { 0.0 }
    }).sum::<f64>() / trials as f64
}

// 长度扩展攻击
pub fn length_extension_attack(digest_size: DigestSize, trials: usize) -> f64 {
    (0..trials).into_par_iter().map(|_| {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut hash = BlueHash::BlueHashCore::new(digest_size);
        hash.update(&data);
        let original_hash = hash.finalize();

        let extra_data: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        let mut attack_data = data.clone();
        attack_data.extend(extra_data.clone());

        let mut attack_hash = BlueHash::BlueHashCore::new(digest_size);
        attack_hash.update(&attack_data);
        let attack_result = attack_hash.finalize();

        if attack_result == original_hash { 1.0 } else { 0.0 }
    }).sum::<f64>() / trials as f64
}

pub fn bench_bluehash(c: &mut Criterion) {
    let data = b"A benchmark for BlueHash performance";

    // 测试 BlueHash 不同摘要大小的性能
    c.bench_function("BlueHash 128-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::BlueHashCore::new(DigestSize::Bit128);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    c.bench_function("BlueHash 256-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::BlueHashCore::new(DigestSize::Bit256);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    c.bench_function("BlueHash 512-bit", |b| {
        b.iter(|| {
            let mut hash = BlueHash::BlueHashCore::new(DigestSize::Bit512);
            hash.update(black_box(data));
            black_box(hash.finalize());
        });
    });

    // 打印攻击测试结果
    println!("Collision attack test (128-bit): {}", parallel_collision_test(DigestSize::Bit128, 1_000_000, 12));
    println!("Differential attack test (128-bit): {}", differential_attack_test(DigestSize::Bit128, 1_000_000));
    println!("Second preimage attack (128-bit): {}", second_preimage_attack(DigestSize::Bit128, 1_000_000));
    println!("Forward security test (128-bit): {}", forward_security_test(DigestSize::Bit128, 1_000_000));
    println!("Birthday attack (128-bit): {}", birthday_attack(DigestSize::Bit128, 1_000_000));
    println!("Length extension attack (128-bit): {}", length_extension_attack(DigestSize::Bit128, 1_000_000));

    println!("\n");
    println!("Collision attack test (256-bit): {}", parallel_collision_test(DigestSize::Bit256, 1_000_000, 12));
    println!("Differential attack test (256-bit): {}", differential_attack_test(DigestSize::Bit256, 1_000_000));
    println!("Second preimage attack (256-bit): {}", second_preimage_attack(DigestSize::Bit256, 1_000_000));
    println!("Forward security test (256-bit): {}", forward_security_test(DigestSize::Bit256, 1_000_000));
    println!("Birthday attack (256-bit): {}", birthday_attack(DigestSize::Bit256, 1_000_000));
    println!("Length extension attack (256-bit): {}", length_extension_attack(DigestSize::Bit256, 1_000_000));

    println!("\n");
    println!("Collision attack test (512-bit): {}", parallel_collision_test(DigestSize::Bit512, 1_000_000, 12));
    println!("Differential attack test (512-bit): {}", differential_attack_test(DigestSize::Bit512, 1_000_000));
    println!("Second preimage attack (512-bit): {}", second_preimage_attack(DigestSize::Bit512, 1_000_000));
    println!("Forward security test (512-bit): {}", forward_security_test(DigestSize::Bit512, 1_000_000));
    println!("Birthday attack (512-bit): {}", birthday_attack(DigestSize::Bit512, 1_000_000));
    println!("Length extension attack (512-bit): {}", length_extension_attack(DigestSize::Bit512, 1_000_000));
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10)) // 设定测试时长为 15 秒
        .sample_size(800); // 每个基准测试的样本大小
    targets = bench_bluehash
}

criterion_main!(benches);
