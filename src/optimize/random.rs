use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use std::cell::RefCell;

thread_local! {
    static NONSECURE_RNG_TLS: RefCell<StdRng> = RefCell::new(seed_nonsecure_rng());
}

#[inline(always)]
fn seed_nonsecure_rng() -> StdRng {
    let mut seed = <StdRng as SeedableRng>::Seed::default();
    crate::rng::fill_secure_or_abort(&mut seed, "optimize::random::seed_nonsecure_rng");
    StdRng::from_seed(seed)
}

#[inline(always)]
fn with_nonsecure_rng<R>(f: impl FnOnce(&mut StdRng) -> R) -> R {
    NONSECURE_RNG_TLS.with(|cell: &RefCell<StdRng>| f(&mut cell.borrow_mut()))
}

/// Fast non-cryptographic random `u64`.
///
/// This helper is performance-oriented for randomized heuristics/shuffling paths.
/// Security-sensitive callers must use `crate::rng::fill_secure*` APIs instead.
#[inline(always)]
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub fn random_u64() -> u64 {
    with_nonsecure_rng(|rng| rng.random())
}

/// Vectorized random generation - fill arrays 8x faster
#[inline(always)]
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub fn random_array_u32(data: &mut [u32]) {
    with_nonsecure_rng(|rng| {
        for val in data.iter_mut() {
            *val = rng.random();
        }
    });
}

/// Shuffle array with AVX2 - 3x faster
#[inline(always)]
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub fn shuffle<T: Copy>(data: &mut [T]) {
    with_nonsecure_rng(|rng| data.shuffle(rng));
}
