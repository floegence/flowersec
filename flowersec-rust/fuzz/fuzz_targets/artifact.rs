#![no_main]

use flowersec::fuzzing::parse_artifact;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    parse_artifact(data);
});
