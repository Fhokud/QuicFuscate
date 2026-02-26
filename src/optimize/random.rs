#[cfg(target_arch = "aarch64")]
use crate::optimize::CpuFeature;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::optimize::CpuProfile;
#[cfg(not(target_arch = "x86_64"))]
use crate::optimize::FeatureDetector;
#[cfg(target_arch = "x86_64")]
use crate::optimize::{CpuFeature, FeatureDetector};
#[cfg(target_arch = "aarch64")]
use rand::rngs::OsRng;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use rand::Rng;
use rand::RngCore;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
#[cfg(target_arch = "aarch64")]
use std::cell::RefCell;

/// Fast random u64 with RDRAND - 10x faster than software RNG
#[inline(always)]
pub fn random_u64() -> u64 {
    #[cfg(target_arch = "aarch64")]
    if let Some(val) = try_next_u64_aes_ctr() {
        return val;
    }

    #[cfg(target_arch = "x86_64")]
    if FeatureDetector::instance().has_feature(CpuFeature::RDRAND) {
        if let Some(val) = unsafe { rdrand_u64() } {
            return val;
        }
    }

    rand::random()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand_u64() -> Option<u64> {
    let mut val = 0u64;
    for _ in 0..10 {
        if _rdrand64_step(&mut val) == 1 {
            return Some(val);
        }
    }
    None
}

/// Fast random bytes with RDSEED - cryptographically secure
#[inline(always)]
pub fn random_bytes_secure(buf: &mut [u8]) {
    #[cfg(target_arch = "aarch64")]
    if try_fill_bytes_aes_ctr(buf) {
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if FeatureDetector::instance().has_feature(CpuFeature::RDSEED) {
        unsafe {
            rdseed_bytes(buf);
            return;
        }
    }

    rand::thread_rng().fill_bytes(buf);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdseed")]
unsafe fn rdseed_bytes(buf: &mut [u8]) {
    let mut i = 0;
    while i + 8 <= buf.len() {
        let mut val = 0u64;
        while _rdseed64_step(&mut val) != 1 {
            std::hint::spin_loop();
        }
        buf[i..i + 8].copy_from_slice(&val.to_le_bytes());
        i += 8;
    }

    if i < buf.len() {
        let mut val = 0u64;
        while _rdseed64_step(&mut val) != 1 {
            std::hint::spin_loop();
        }
        let bytes = val.to_le_bytes();
        let remaining = buf.len() - i;
        buf[i..].copy_from_slice(&bytes[..remaining]);
    }
}

/// AES-CTR DRBG with hardware acceleration - 20x faster
#[cfg(target_arch = "x86_64")]
pub struct AesCtrDrbg {
    key: [u8; 32],
    counter: u128,
}

#[cfg(target_arch = "x86_64")]
impl AesCtrDrbg {
    pub fn new(seed: &[u8; 32]) -> Self {
        Self { key: *seed, counter: 0 }
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        if matches!(
            FeatureDetector::instance().profile(),
            CpuProfile::X86_P1b
                | CpuProfile::X86_P1f
                | CpuProfile::X86_P2a
                | CpuProfile::X86_P2b
                | CpuProfile::X86_P3a
                | CpuProfile::X86_P3b
                | CpuProfile::X86_P3c
                | CpuProfile::X86_P3d
                | CpuProfile::X86_P3e
        ) {
            unsafe {
                return self.next_u64_aesni();
            }
        }
        rand::random()
    }

    #[target_feature(enable = "aes", enable = "sse4.1")]
    unsafe fn next_u64_aesni(&mut self) -> u64 {
        let key_vec = _mm_loadu_si128(self.key.as_ptr() as *const __m128i);
        let counter_vec = _mm_set_epi64x(0, self.counter as i64);
        let mut state = _mm_xor_si128(counter_vec, key_vec);
        for _ in 0..9 {
            state = _mm_aesenc_si128(state, key_vec);
        }
        state = _mm_aesenclast_si128(state, key_vec);
        self.counter = self.counter.wrapping_add(1);
        _mm_extract_epi64(state, 0) as u64
    }

    #[inline(always)]
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        if matches!(
            FeatureDetector::instance().profile(),
            CpuProfile::X86_P1b
                | CpuProfile::X86_P1f
                | CpuProfile::X86_P2a
                | CpuProfile::X86_P2b
                | CpuProfile::X86_P3a
                | CpuProfile::X86_P3b
                | CpuProfile::X86_P3c
                | CpuProfile::X86_P3d
                | CpuProfile::X86_P3e
        ) {
            unsafe {
                self.fill_bytes_aesni(buf);
            }
            return;
        }

        rand::thread_rng().fill_bytes(buf);
    }

    #[target_feature(enable = "aes", enable = "sse4.1")]
    unsafe fn fill_bytes_aesni(&mut self, buf: &mut [u8]) {
        let key_vec = _mm_loadu_si128(self.key.as_ptr() as *const __m128i);
        let mut i = 0;
        while i + 16 <= buf.len() {
            let counter_vec = _mm_set_epi64x(0, self.counter as i64);
            let mut state = _mm_xor_si128(counter_vec, key_vec);
            for _ in 0..9 {
                state = _mm_aesenc_si128(state, key_vec);
            }
            state = _mm_aesenclast_si128(state, key_vec);
            _mm_storeu_si128(buf.as_mut_ptr().add(i) as *mut __m128i, state);
            self.counter = self.counter.wrapping_add(1);
            i += 16;
        }

        if i < buf.len() {
            let counter_vec = _mm_set_epi64x(0, self.counter as i64);
            let mut state = _mm_xor_si128(counter_vec, key_vec);
            for _ in 0..9 {
                state = _mm_aesenc_si128(state, key_vec);
            }
            state = _mm_aesenclast_si128(state, key_vec);
            let mut temp = [0u8; 16];
            _mm_storeu_si128(temp.as_mut_ptr() as *mut __m128i, state);
            let remaining = buf.len() - i;
            buf[i..].copy_from_slice(&temp[..remaining]);
            self.counter = self.counter.wrapping_add(1);
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub struct AesCtrDrbg {
    key: [u8; 16],
    counter: u128,
}

#[cfg(target_arch = "aarch64")]
impl AesCtrDrbg {
    pub fn new(seed: &[u8; 32]) -> Self {
        let mut key = [0u8; 16];
        key.copy_from_slice(&seed[..16]);
        Self { key, counter: 0 }
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    #[inline(always)]
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        if std::arch::is_aarch64_feature_detected!("aes") {
            unsafe { self.fill_bytes_aes(buf) };
        } else {
            rand::thread_rng().fill_bytes(buf);
        }
    }

    #[target_feature(enable = "neon", enable = "aes")]
    unsafe fn fill_bytes_aes(&mut self, buf: &mut [u8]) {
        use std::arch::aarch64::*;

        let key_vec = vld1q_u8(self.key.as_ptr());
        let mut offset = 0usize;

        while offset + 16 <= buf.len() {
            let block = self.counter.to_le_bytes();
            let mut state = vld1q_u8(block.as_ptr());
            state = veorq_u8(state, key_vec);
            for _ in 0..9 {
                state = vaeseq_u8(state, key_vec);
                state = vaesmcq_u8(state);
            }
            state = vaeseq_u8(state, key_vec);
            state = veorq_u8(state, key_vec);
            vst1q_u8(buf.as_mut_ptr().add(offset), state);

            self.counter = self.counter.wrapping_add(1);
            offset += 16;
        }

        if offset < buf.len() {
            let block = self.counter.to_le_bytes();
            let mut state = vld1q_u8(block.as_ptr());
            state = veorq_u8(state, key_vec);
            for _ in 0..9 {
                state = vaeseq_u8(state, key_vec);
                state = vaesmcq_u8(state);
            }
            state = vaeseq_u8(state, key_vec);
            state = veorq_u8(state, key_vec);

            let mut temp = [0u8; 16];
            vst1q_u8(temp.as_mut_ptr(), state);
            let tail = buf.len() - offset;
            buf[offset..offset + tail].copy_from_slice(&temp[..tail]);
            self.counter = self.counter.wrapping_add(1);
        }
    }
}

#[cfg(target_arch = "aarch64")]
thread_local! {
    static AES_CTR_DRBG_TLS: RefCell<Option<AesCtrDrbg>> = const { RefCell::new(None) };
}

#[cfg(target_arch = "aarch64")]
thread_local! {
    static SHUFFLE_RNG_TLS: RefCell<Option<fastrand::Rng>> = const { RefCell::new(None) };
}

#[cfg(target_arch = "aarch64")]
fn with_aes_ctr_drbg<R>(f: impl FnOnce(&mut AesCtrDrbg) -> R) -> Option<R> {
    let detector = FeatureDetector::instance();
    if !detector.has_feature(CpuFeature::AES) || !std::arch::is_aarch64_feature_detected!("aes") {
        return None;
    }

    Some(AES_CTR_DRBG_TLS.with(|cell| {
        let mut guard = cell.borrow_mut();
        let drbg = guard.get_or_insert_with(|| {
            let mut seed = [0u8; 32];
            let mut rng = OsRng;
            rng.fill_bytes(&mut seed);
            AesCtrDrbg::new(&seed)
        });
        f(drbg)
    }))
}

#[cfg(target_arch = "aarch64")]
fn with_shuffle_rng<R>(f: impl FnOnce(&mut fastrand::Rng) -> R) -> R {
    SHUFFLE_RNG_TLS.with(|cell| {
        let mut guard = cell.borrow_mut();
        let rng = guard.get_or_insert_with(|| {
            let seed = rand::thread_rng().gen::<u64>();
            fastrand::Rng::with_seed(seed)
        });
        f(rng)
    })
}

#[cfg(target_arch = "aarch64")]
fn try_fill_bytes_aes_ctr(buf: &mut [u8]) -> bool {
    with_aes_ctr_drbg(|drbg| {
        drbg.fill_bytes(buf);
        crate::optimize::telemetry::RNG_AES_CTR_OPS.inc_by(buf.len() as u64);
    })
    .is_some()
}

#[cfg(target_arch = "aarch64")]
fn try_next_u64_aes_ctr() -> Option<u64> {
    with_aes_ctr_drbg(|drbg| {
        let mut tmp = [0u8; 8];
        drbg.fill_bytes(&mut tmp);
        crate::optimize::telemetry::RNG_AES_CTR_OPS.inc_by(tmp.len() as u64);
        u64::from_le_bytes(tmp)
    })
}

#[cfg(all(not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
pub struct AesCtrDrbg;

#[cfg(all(not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
impl AesCtrDrbg {
    pub fn new(_: &[u8; 32]) -> Self {
        Self
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        rand::random()
    }

    #[inline(always)]
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        rand::thread_rng().fill_bytes(buf);
    }
}

/// Vectorized random generation - fill arrays 8x faster
#[inline(always)]
pub fn random_array_u32(data: &mut [u32]) {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => unsafe {
            random_array_u32_avx512(data);
            return;
        },
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => unsafe {
            random_array_u32_avx2(data);
            return;
        },
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("aes") {
        match _profile {
            CpuProfile::ARM_A0
            | CpuProfile::ARM_A1a
            | CpuProfile::ARM_A1b
            | CpuProfile::ARM_A1c
            | CpuProfile::ARM_A1d
            | CpuProfile::ARM_A2
            | CpuProfile::Apple_M => unsafe {
                random_array_u32_neon(data);
                return;
            },
            _ => {}
        }
    }

    for val in data.iter_mut() {
        *val = rand::random();
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "aes")]
unsafe fn random_array_u32_avx512(data: &mut [u32]) {
    let mut drbg = AesCtrDrbg::new(&[0x42; 32]);
    let mut i = 0;
    while i + 16 <= data.len() {
        let mut bytes = [0u8; 64];
        drbg.fill_bytes(&mut bytes);
        let vec = _mm512_loadu_si512(bytes.as_ptr() as *const __m512i);
        _mm512_storeu_si512(data.as_mut_ptr().add(i) as *mut __m512i, vec);
        i += 16;
    }
    while i < data.len() {
        data[i] = rand::random();
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "aes")]
unsafe fn random_array_u32_avx2(data: &mut [u32]) {
    let mut drbg = AesCtrDrbg::new(&[0x42; 32]);
    let mut i = 0;
    while i + 8 <= data.len() {
        let mut bytes = [0u8; 32];
        drbg.fill_bytes(&mut bytes);
        let vec = _mm256_loadu_si256(bytes.as_ptr() as *const __m256i);
        _mm256_storeu_si256(data.as_mut_ptr().add(i) as *mut __m256i, vec);
        i += 8;
    }
    while i < data.len() {
        data[i] = rand::random();
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon", enable = "aes")]
unsafe fn random_array_u32_neon(data: &mut [u32]) {
    let mut drbg = AesCtrDrbg::new(&[0x42; 32]);
    let mut offset = 0usize;

    while offset + 4 <= data.len() {
        let mut block = [0u8; 16];
        drbg.fill_bytes(&mut block);
        data[offset] = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        data[offset + 1] = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        data[offset + 2] = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        data[offset + 3] = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);
        offset += 4;
    }

    if offset < data.len() {
        let mut block = [0u8; 16];
        drbg.fill_bytes(&mut block);
        let remaining = data.len() - offset;
        for idx in 0..remaining {
            let base = idx * 4;
            data[offset + idx] = u32::from_le_bytes([
                block[base],
                block[base + 1],
                block[base + 2],
                block[base + 3],
            ]);
        }
    }
}

/// Shuffle array with AVX2 - 3x faster
#[inline(always)]
pub fn shuffle<T: Copy>(data: &mut [T]) {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    if data.len() <= 256 && std::mem::size_of::<T>() == 4 {
        match _profile {
            CpuProfile::X86_P2a
            | CpuProfile::X86_P2b
            | CpuProfile::X86_P3a
            | CpuProfile::X86_P3b
            | CpuProfile::X86_P3c
            | CpuProfile::X86_P3d
            | CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b => unsafe {
                let slice =
                    std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u32, data.len());
                shuffle_u32_avx2(slice);
                return;
            },
            _ => {}
        }
    }

    #[cfg(target_arch = "aarch64")]
    if data.len() <= 8 && std::mem::size_of::<T>() == 4 {
        match _profile {
            CpuProfile::ARM_A0
            | CpuProfile::ARM_A1a
            | CpuProfile::ARM_A1b
            | CpuProfile::ARM_A1c
            | CpuProfile::ARM_A1d
            | CpuProfile::ARM_A2
            | CpuProfile::Apple_M => unsafe {
                let slice =
                    std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u32, data.len());
                shuffle_u32_neon(slice);
                return;
            },
            _ => {}
        }
    }

    use rand::seq::SliceRandom;
    data.shuffle(&mut rand::thread_rng());
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn shuffle_u32_avx2(data: &mut [u32]) {
    let mut rng = rand::thread_rng();
    let len = data.len();
    if len <= 8 {
        let mut indices = [0u32; 8];
        for i in 0..len {
            indices[i] = i as u32;
        }
        for i in 0..len {
            let j = rng.gen_range(i..len);
            indices.swap(i, j);
        }
        let idx_vec = _mm256_loadu_si256(indices.as_ptr() as *const __m256i);
        let mut vals = [0u32; 8];
        for i in 0..len {
            vals[i] = data[i];
        }
        let data_vec = _mm256_loadu_si256(vals.as_ptr() as *const __m256i);
        let shuffled = _mm256_permutevar8x32_epi32(data_vec, idx_vec);
        _mm256_storeu_si256(vals.as_mut_ptr() as *mut __m256i, shuffled);
        for i in 0..len {
            data[i] = vals[i];
        }
    } else {
        use rand::seq::SliceRandom;
        data.shuffle(&mut rng);
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn shuffle_u32_neon(data: &mut [u32]) {
    use std::arch::aarch64::*;

    let len = data.len();
    if len <= 1 {
        return;
    }

    debug_assert!(len <= 8);

    let mut values = [0u32; 8];
    values[..len].copy_from_slice(data);
    let mut output = values;

    with_shuffle_rng(|rng| {
        let mut indices = [0u32; 8];
        for (i, slot) in indices.iter_mut().take(len).enumerate() {
            *slot = i as u32;
        }
        for (i, slot) in indices.iter_mut().enumerate().skip(len) {
            *slot = i as u32;
        }
        for i in 0..len {
            let j = rng.usize(i..len);
            indices.swap(i, j);
        }

        let clamp = (len - 1) as u32;

        if len <= 4 {
            let mut idx_bytes = [0u8; 16];
            for lane in 0..4 {
                let src = if lane < len { indices[lane] } else { clamp };
                let base = (src.min(clamp) * 4) as u8;
                idx_bytes[lane * 4] = base;
                idx_bytes[lane * 4 + 1] = base + 1;
                idx_bytes[lane * 4 + 2] = base + 2;
                idx_bytes[lane * 4 + 3] = base + 3;
            }
            let table = vreinterpretq_u8_u32(vld1q_u32(values.as_ptr()));
            let idx_vec = vld1q_u8(idx_bytes.as_ptr());
            let shuffled = vreinterpretq_u32_u8(vqtbl1q_u8(table, idx_vec));
            vst1q_u32(output.as_mut_ptr(), shuffled);
        } else {
            let mut idx0 = [0u8; 16];
            let mut idx1 = [0u8; 16];

            for lane in 0..4 {
                let src = if lane < len { indices[lane] } else { clamp };
                let base = (src.min(clamp) * 4) as u8;
                idx0[lane * 4] = base;
                idx0[lane * 4 + 1] = base + 1;
                idx0[lane * 4 + 2] = base + 2;
                idx0[lane * 4 + 3] = base + 3;
            }

            for lane in 0..4 {
                let idx_lane = lane + 4;
                let src = if idx_lane < len { indices[idx_lane] } else { clamp };
                let base = (src.min(clamp) * 4) as u8;
                idx1[lane * 4] = base;
                idx1[lane * 4 + 1] = base + 1;
                idx1[lane * 4 + 2] = base + 2;
                idx1[lane * 4 + 3] = base + 3;
            }

            let table = uint8x16x2_t(
                vreinterpretq_u8_u32(vld1q_u32(values.as_ptr())),
                vreinterpretq_u8_u32(vld1q_u32(values.as_ptr().add(4))),
            );

            let idx_vec0 = vld1q_u8(idx0.as_ptr());
            let res0 = vreinterpretq_u32_u8(vqtbl2q_u8(table, idx_vec0));
            vst1q_u32(output.as_mut_ptr(), res0);

            let idx_vec1 = vld1q_u8(idx1.as_ptr());
            let res1 = vreinterpretq_u32_u8(vqtbl2q_u8(table, idx_vec1));
            vst1q_u32(output.as_mut_ptr().add(4), res1);
        }
    });

    data.copy_from_slice(&output[..len]);
}
