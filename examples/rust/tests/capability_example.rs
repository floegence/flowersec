use flowersec::transport_v2::{
    encode_runtime_capability_descriptor_v2, native_rust_capability_descriptor_v2,
    runtime_capability_digest_hex_v2,
};
use std::process::Command;

#[test]
fn capability_subcommand_prints_the_canonical_native_descriptor() {
    let descriptor = native_rust_capability_descriptor_v2();
    assert_eq!(descriptor.tuples.len(), 0);
    let canonical = encode_runtime_capability_descriptor_v2(&descriptor).unwrap();
    let digest = runtime_capability_digest_hex_v2(&descriptor).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_flowersec-rust-client-example"))
        .arg("capability-v2")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "descriptor={}\ntuple_count=0\ndigest={}\n",
            String::from_utf8(canonical).unwrap(),
            digest
        )
    );
}
