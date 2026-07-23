#![no_main]

use flowersec::artifact_v2::Artifact;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Artifact::parse(data);
});
