#![no_main]

use flowersec::e2ee::decode_handshake_frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limit = data
        .first()
        .map_or(8 * 1024, |value| usize::from(*value) * 64);
    let _ = decode_handshake_frame(data, limit);
});
