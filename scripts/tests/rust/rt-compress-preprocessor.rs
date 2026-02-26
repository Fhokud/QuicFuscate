#![cfg(feature = "rust-tests")]
use quicfuscate::compress::CompressionAnalysis;

fn make_text_payload() -> Vec<u8> {
    let paragraph = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
    let mut buf = Vec::new();
    for _ in 0..64 {
        buf.extend_from_slice(paragraph);
    }
    buf
}

fn make_binary_payload() -> Vec<u8> {
    let mut buf = Vec::new();
    for i in 0..512u32 {
        buf.extend_from_slice(&(i as u64).to_le_bytes());
    }
    buf
}

#[test]
fn compression_analysis_flags_textual_payload() {
    let payload = make_text_payload();
    let analysis = CompressionAnalysis::from_full(&payload);
    assert!(analysis.is_textual(), "expected textual payload to be classified as textual");
    assert!(analysis.ascii_ratio() > 0.8, "ascii ratio too low: {}", analysis.ascii_ratio());
    assert!(analysis.newline_ratio() > 0.01, "newline ratio too low: {}", analysis.newline_ratio());
    assert!(
        analysis.high_ratio() < 0.05,
        "high-byte ratio unexpectedly high: {}",
        analysis.high_ratio()
    );
}

#[test]
fn compression_analysis_flags_binary_payload() {
    let payload = make_binary_payload();
    let analysis = CompressionAnalysis::from_full(&payload);
    assert!(!analysis.is_textual(), "binary payload should not be classified as textual");
    assert!(
        analysis.ascii_ratio() < 0.3,
        "expected low ASCII ratio, got {}",
        analysis.ascii_ratio()
    );
    assert!(
        analysis.null_ratio() > 0.1,
        "expected null byte ratio > 0.1, got {}",
        analysis.null_ratio()
    );
}

#[test]
fn compression_analysis_detects_repeated_chunks() {
    let mut chunk = vec![0u8; 64];
    for (i, b) in chunk.iter_mut().enumerate() {
        *b = (i * 7 % 251) as u8;
    }
    let mut payload = Vec::new();
    for _ in 0..16 {
        payload.extend_from_slice(&chunk);
    }

    let analysis = CompressionAnalysis::from_full(&payload);
    assert!(analysis.chunk_total >= 16, "expected chunk_total >= 16, got {}", analysis.chunk_total);
    assert!(
        analysis.chunk_repeated > 0,
        "expected repeated chunk detections, got {}",
        analysis.chunk_repeated
    );
    assert!(analysis.chunk_skew() > 0.4, "expected noticeable skew, got {}", analysis.chunk_skew());
}
