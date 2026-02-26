#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::transport::count_ecn_marks;
use rand::Rng;

fn scalar_count(bitmap: &[u64]) -> u32 {
    bitmap.iter().map(|&w| w.count_ones()).sum()
}

#[test]
fn ecn_popcount_basic_cases() {
    let cases: Vec<Vec<u64>> = vec![
        vec![],
        vec![0],
        vec![u64::MAX],
        vec![0xFFFF_FFFF_0000_0000],
        vec![0x0123_4567_89AB_CDEF],
        vec![0x0000_0000_FFFF_FFFF, 0xFFFF_0000_FFFF_0000],
    ];

    for bm in cases {
        let acc = count_ecn_marks(&bm);
        let refc = scalar_count(&bm);
        assert_eq!(acc, refc, "mismatch for bitmap {:?}", bm);
    }
}

#[test]
fn ecn_popcount_randomized() {
    let mut rng = rand::thread_rng();
    for &len_words in &[0usize, 1, 2, 3, 4, 7, 8, 16, 31, 32, 64, 127, 128, 256] {
        for _ in 0..32 {
            let mut v = vec![0u64; len_words];
            for w in &mut v {
                *w = rng.gen::<u64>();
            }
            let acc = count_ecn_marks(&v);
            let refc = scalar_count(&v);
            assert_eq!(acc, refc, "len_words={len_words}");
        }
    }
}
