#![cfg(target_arch = "aarch64")]
#![cfg(feature = "rust-tests")]

use quicfuscate::accelerate::random;

#[test]
fn optimize_random_helpers_provide_nonsecurity_words_and_scalars() {
    let mut words = [0u32; 16];
    random::random_array_u32(&mut words);
    assert!(
        words.iter().any(|&word| word != 0),
        "random_array_u32 must produce non-zero-looking output"
    );

    let a = random::random_u64();
    let b = random::random_u64();
    assert_ne!(a, b, "non-security helper should advance its per-thread PRNG state");
}
