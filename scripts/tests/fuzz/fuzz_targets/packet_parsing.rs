#![no_main]

use libfuzzer_sys::fuzz_target;

use quicfuscate::transport::packet;

fuzz_target!(|data: &[u8]| {
    let _ = packet::parse_header(data, 0);
});
