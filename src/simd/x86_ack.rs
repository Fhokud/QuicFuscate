#![cfg(target_arch = "x86_64")]
//! x86 SIMD helpers for ACK range canonicalization/merge
//! AVX2/AVX-512 implementations used by transport layer

use std::arch::x86_64::*;

#[inline]
pub unsafe fn canonical_ack_blocks_avx2(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return Vec::new();
    }

    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|r| r.0);

    let len = sorted.len();
    let mut starts: Vec<u64> = Vec::with_capacity(len);
    let mut ends: Vec<u64> = Vec::with_capacity(len);
    for (s, e) in &sorted {
        starts.push(*s);
        ends.push(*e);
    }

    let mut out: Vec<(u64, u64)> = Vec::with_capacity(len);
    let mut idx = 0usize;
    while idx < len {
        let current_start = starts[idx];
        let mut current_end = ends[idx];
        idx += 1;

        loop {
            if idx >= len {
                break;
            }

            let mut local = idx;
            let mut advanced = 0usize;
            let mut max_candidate = current_end;

            while local + 4 <= len {
                let s_ptr = starts.as_ptr().add(local) as *const __m256i;
                let s_vec = _mm256_loadu_si256(s_ptr);
                let end_bcast = _mm256_set1_epi64x(current_end as i64);
                let gt = _mm256_cmpgt_epi64(s_vec, end_bcast);
                let gt_pd = core::mem::transmute::<__m256i, __m256d>(gt);
                let mask = _mm256_movemask_pd(gt_pd) as u32; // 1 if start > end
                let le_mask = (!mask) & 0xF;
                if le_mask == 0 {
                    break;
                }
                let count = le_mask.trailing_ones().min(4);

                let e_ptr = ends.as_ptr().add(local) as *const __m256i;
                let e_vec = _mm256_loadu_si256(e_ptr);
                let mut tmp: [u64; 4] = core::mem::transmute(e_vec);
                let mut local_max = max_candidate;
                for lane in 0..(count as usize) {
                    if tmp[lane] > local_max {
                        local_max = tmp[lane];
                    }
                }

                max_candidate = local_max;
                advanced += count as usize;
                local += count as usize;
            }

            while local < len && starts[local] <= current_end {
                if ends[local] > max_candidate {
                    max_candidate = ends[local];
                }
                local += 1;
                advanced += 1;
            }

            if advanced == 0 {
                break;
            }
            idx += advanced;
            if max_candidate > current_end {
                current_end = max_candidate;
                continue;
            }
        }

        out.push((current_start, current_end));
    }

    out
}

#[target_feature(enable = "avx512f", enable = "avx512vl")]
pub unsafe fn canonical_ack_blocks_avx512(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return Vec::new();
    }

    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|r| r.0);

    let len = sorted.len();
    let mut starts: Vec<u64> = Vec::with_capacity(len);
    let mut ends: Vec<u64> = Vec::with_capacity(len);
    for (s, e) in &sorted {
        starts.push(*s);
        ends.push(*e);
    }

    let mut out: Vec<(u64, u64)> = Vec::with_capacity(len);
    let mut idx = 0usize;
    while idx < len {
        let current_start = starts[idx];
        let mut current_end = ends[idx];
        idx += 1;

        loop {
            if idx >= len {
                break;
            }
            let mut local = idx;
            let mut advanced = 0usize;
            let mut max_candidate = current_end;

            while local + 8 <= len {
                let s_ptr = starts.as_ptr().add(local) as *const __m512i;
                let s_vec = _mm512_loadu_si512(s_ptr);
                let end_bcast = _mm512_set1_epi64(current_end as i64);
                // 6 == _MM_CMPINT_NLE, which is equivalent to "greater than".
                let gt_mask = _mm512_cmp_epi64_mask(s_vec, end_bcast, 6);
                let le_mask = (!gt_mask) & 0xFF; // lanes where start <= end
                if le_mask == 0 {
                    break;
                }
                let count = le_mask.trailing_zeros().min(8);

                let e_ptr = ends.as_ptr().add(local) as *const __m512i;
                let e_vec = _mm512_loadu_si512(e_ptr);
                let mut tmp: [u64; 8] = core::mem::transmute(e_vec);
                let mut local_max = max_candidate;
                for lane in 0..(count as usize) {
                    if tmp[lane] > local_max {
                        local_max = tmp[lane];
                    }
                }
                max_candidate = local_max;
                advanced += count as usize;
                local += count as usize;
            }

            while local < len && starts[local] <= current_end {
                if ends[local] > max_candidate {
                    max_candidate = ends[local];
                }
                local += 1;
                advanced += 1;
            }

            if advanced == 0 {
                break;
            }
            idx += advanced;
            if max_candidate > current_end {
                current_end = max_candidate;
                continue;
            }
        }

        out.push((current_start, current_end));
    }

    out
}
