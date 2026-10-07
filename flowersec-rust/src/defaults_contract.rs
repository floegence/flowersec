use std::{fs, path::PathBuf};

use serde_json::Value;

use crate::ConnectionRequest;
use crate::proxy_server::{
    DEFAULT_MAX_BODY, DEFAULT_MAX_CHUNK, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_METADATA,
    DEFAULT_MAX_WEBSOCKET_FRAME, DEFAULT_TIMEOUT, MAX_TIMEOUT,
};
#[test]
fn defaults_match_shared_stability_contract() {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("stability")
        .join("sdk_defaults.json");
    let manifest: Value = serde_json::from_slice(
        &fs::read(manifest_path).expect("read shared SDK defaults stability contract"),
    )
    .expect("parse shared SDK defaults stability contract");

    let proxy = &manifest["proxy"];
    assert_eq!(
        DEFAULT_MAX_METADATA as u64,
        proxy["max_metadata_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        DEFAULT_MAX_CONCURRENT as u64,
        proxy["max_concurrent_streams"].as_u64().unwrap()
    );
    assert_eq!(
        DEFAULT_MAX_CHUNK as u64,
        proxy["max_chunk_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        DEFAULT_MAX_BODY as u64,
        proxy["max_body_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        DEFAULT_MAX_WEBSOCKET_FRAME as u64,
        proxy["max_ws_frame_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        DEFAULT_TIMEOUT.as_millis() as u64,
        proxy["default_timeout_ms"].as_u64().unwrap()
    );
    assert_eq!(
        MAX_TIMEOUT.as_millis() as u64,
        proxy["max_timeout_ms"].as_u64().unwrap()
    );
}

#[test]
fn public_connection_request_keeps_requirements_explicit() {
    let request = ConnectionRequest::default();
    assert!(request.handlers.is_none());
    assert!(request.requirements.application_profile.is_none());
    assert!(!request.requirements.independent_reliable_read_progress);
    assert!(!request.requirements.bound_stream_input_isolation);
    assert!(!request.requirements.datagram);
}
