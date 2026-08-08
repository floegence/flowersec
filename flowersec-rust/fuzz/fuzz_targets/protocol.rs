#![no_main]

use flowersec::fuzzing::parse_protocol;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    parse_protocol(data);
});
