#![no_main]

use libfuzzer_sys::fuzz_target;

use quicfuscate::transport::varint::{read_varint, varint_len, write_varint};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    if let Ok((value, _used)) = read_varint(data) {
        let mut buf = vec![0u8; varint_len(value)];
        let _ = write_varint(value, &mut buf);
    }
});
