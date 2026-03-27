use quicfuscate::rng;
use rand::RngCore;
use std::env;
use std::time::Instant;

fn main() {
    let mut args = env::args().skip(1);
    let mut total_mb: u64 = 128;
    let mut block_size: usize = 64 * 1024;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--total-mb" => {
                if let Some(val) = args.next() {
                    total_mb = val.parse().expect("invalid --total-mb value");
                }
            }
            "--block" => {
                if let Some(val) = args.next() {
                    block_size = val.parse().expect("invalid --block value");
                }
            }
            _ => {
                eprintln!("usage: rng_bench [--total-mb <u64>] [--block <usize>]");
                return;
            }
        }
    }

    if block_size == 0 {
        eprintln!("block size must be > 0");
        return;
    }

    let total_bytes = total_mb * 1024 * 1024;
    let iterations = std::cmp::max(1, total_bytes / block_size as u64);
    let effective_bytes = iterations * block_size as u64;

    println!(
        "# RNG benchmark\n# total ≈ {} MB ({} bytes), block {} bytes, iterations {}",
        effective_bytes as f64 / (1024.0 * 1024.0),
        effective_bytes,
        block_size,
        iterations
    );

    let mut buffer = vec![0u8; block_size];

    // Warm-up
    rng::fill_secure_or_abort(&mut buffer, "examples::rng_bench::warmup");
    let mut rand_rng = rand::rng();
    rand_rng.fill_bytes(&mut buffer);

    // Measure canonical secure entropy API
    let start_simd = Instant::now();
    for _ in 0..iterations {
        rng::fill_secure_or_abort(&mut buffer, "examples::rng_bench::loop");
    }
    let dur_simd = start_simd.elapsed();
    let throughput_simd = bytes_per_second(effective_bytes, dur_simd);

    // Measure rand::rng fallback
    let start_scalar = Instant::now();
    for _ in 0..iterations {
        rand_rng.fill_bytes(&mut buffer);
    }
    let dur_scalar = start_scalar.elapsed();
    let throughput_scalar = bytes_per_second(effective_bytes, dur_scalar);

    println!(
        "rng::fill_secure_or_abort: {:.2} MB/s (elapsed {:.3}s)",
        throughput_simd / (1024.0 * 1024.0),
        dur_simd.as_secs_f64()
    );
    println!(
        "rand::rng::fill_bytes: {:.2} MB/s (elapsed {:.3}s)",
        throughput_scalar / (1024.0 * 1024.0),
        dur_scalar.as_secs_f64()
    );
}

fn bytes_per_second(total: u64, duration: std::time::Duration) -> f64 {
    if duration.as_secs_f64() == 0.0 {
        return total as f64;
    }
    total as f64 / duration.as_secs_f64()
}
