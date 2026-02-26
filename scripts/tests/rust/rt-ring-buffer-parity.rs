#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::memory::LockFreeRingBuffer;

struct ReferenceRing {
    buffer: Vec<u8>,
    capacity: usize,
    mask: usize,
    head: usize,
    tail: usize,
}

impl ReferenceRing {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        Self { buffer: vec![0; capacity], capacity, mask: capacity - 1, head: 0, tail: 0 }
    }

    fn push(&mut self, data: &[u8]) -> bool {
        let head = self.head;
        let tail = self.tail;

        let used = head.wrapping_sub(tail);
        let available = if used >= self.capacity { 0 } else { self.capacity - used - 1 };
        if data.len() > available {
            return false;
        }

        let mut pos = head;
        for &byte in data {
            let dst = pos & self.mask;
            self.buffer[dst] = byte;
            pos = pos.wrapping_add(1);
        }

        self.head = pos;
        true
    }

    fn pop(&mut self, out: &mut [u8]) -> usize {
        let head = self.head;
        let tail = self.tail;

        let available = head.wrapping_sub(tail);
        let to_read = out.len().min(available);

        let mut pos = tail;
        for slot in out.iter_mut().take(to_read) {
            let idx = pos & self.mask;
            *slot = self.buffer[idx];
            pos = pos.wrapping_add(1);
        }

        self.tail = pos;
        to_read
    }
}

#[test]
fn ring_buffer_matches_reference_under_random_load() {
    let mut rng = fastrand::Rng::with_seed(0xDEADBEEFCAFEBABE);
    let capacity = 256usize;
    let ring = LockFreeRingBuffer::new(capacity);
    let mut reference = ReferenceRing::new(capacity);

    let mut scratch = vec![0u8; 512];
    let mut out_simd = vec![0u8; 512];
    let mut out_ref = vec![0u8; 512];

    for _ in 0..10_000 {
        if rng.bool() {
            let len = rng.usize(0..=128);
            scratch.resize(len, 0);
            rng.fill(&mut scratch);

            let simd_ok = ring.push(&scratch);
            let ref_ok = reference.push(&scratch);
            assert_eq!(simd_ok, ref_ok, "push boolean mismatch");
        } else {
            let len = rng.usize(0..=128);
            out_simd.resize(len, 0);
            out_ref.resize(len, 0);

            let simd_len = ring.pop(&mut out_simd);
            let ref_len = reference.pop(&mut out_ref);
            assert_eq!(simd_len, ref_len, "pop length mismatch");
            assert_eq!(
                &out_simd[..simd_len],
                &out_ref[..ref_len],
                "pop data mismatch (len={})",
                simd_len
            );
        }
    }
}

#[test]
fn ring_buffer_basic_wraparound() {
    let ring = LockFreeRingBuffer::new(8);
    let mut reference = ReferenceRing::new(8);

    assert!(ring.push(&[1, 2, 3, 4, 5]));
    assert!(reference.push(&[1, 2, 3, 4, 5]));

    let mut out_simd = [0u8; 3];
    let mut out_ref = [0u8; 3];
    assert_eq!(ring.pop(&mut out_simd), 3);
    assert_eq!(reference.pop(&mut out_ref), 3);
    assert_eq!(out_simd, out_ref);

    assert!(ring.push(&[6, 7, 8, 9]));
    assert!(reference.push(&[6, 7, 8, 9]));

    let mut out_simd2 = [0u8; 6];
    let mut out_ref2 = [0u8; 6];
    let simd_len = ring.pop(&mut out_simd2);
    let ref_len = reference.pop(&mut out_ref2);
    assert_eq!(simd_len, ref_len);
    assert_eq!(&out_simd2[..simd_len], &out_ref2[..ref_len]);
}
