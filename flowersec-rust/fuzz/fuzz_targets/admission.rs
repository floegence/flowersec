#![no_main]

use flowersec::fuzzing::parse_admission;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    parse_admission(data);
});
