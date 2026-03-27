use rand::Rng;

fn gf16_mul_ref(a: u16, b: u16) -> u16 {
    let mut aa = a;
    let mut bb = b;
    let mut res: u16 = 0;
    while bb != 0 {
        if (bb & 1) != 0 {
            res ^= aa;
        }
        bb >>= 1;
        let carry = (aa & 0x8000) != 0;
        aa <<= 1;
        if carry {
            aa ^= 0x100B;
        }
    }
    res
}

#[test]
fn gf16_mul_consistency_random() {
    use crate::fec::gf_tables::gf16_mul as gf16_mul_impl;
    let mut rng = rand::rng();
    let iters = std::env::var("QUICFUSCATE_GF16_TEST_ITERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(500);
    for _ in 0..iters {
        let a: u16 = rng.random();
        let b: u16 = rng.random();
        let r1 = gf16_mul_impl(a, b);
        let r2 = gf16_mul_ref(a, b);
        assert_eq!(r1, r2, "gf16 mul mismatch for a={:#06x}, b={:#06x}", a, b);
    }
}
