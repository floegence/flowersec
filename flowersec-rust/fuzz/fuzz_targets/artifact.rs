#![no_main]

use flowersec::ConnectArtifact;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ConnectArtifact::from_json(data);
});
