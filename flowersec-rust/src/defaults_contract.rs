use std::{fs, path::PathBuf, time::Duration};

use serde_json::Value;

use crate::session_v2::{MAX_HANDSHAKE_PAYLOAD_BYTES, SessionDeadlinesV2};

#[test]
fn v2_defaults_match_shared_stability_contract() {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("stability")
        .join("sdk_defaults.json");
    let manifest: Value = serde_json::from_slice(
        &fs::read(manifest_path).expect("read shared SDK defaults stability contract"),
    )
    .expect("parse shared SDK defaults stability contract");

    assert_eq!(
        MAX_HANDSHAKE_PAYLOAD_BYTES as u64,
        manifest["e2ee"]["max_handshake_payload_bytes"]
            .as_u64()
            .expect("e2ee.max_handshake_payload_bytes")
    );

    let deadlines = SessionDeadlinesV2::default();
    assert_eq!(deadlines.establish, Duration::from_secs(30));
    assert_eq!(deadlines.rekey_prepare, Duration::from_secs(10));
    assert_eq!(deadlines.rekey_completion, Duration::from_secs(30));
    assert_eq!(deadlines.close_flush, Duration::from_secs(2));
}
