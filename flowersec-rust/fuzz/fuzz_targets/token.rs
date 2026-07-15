#![no_main]

use flowersec::controlplane::token;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let _ = token::parse(value);
    }
});
