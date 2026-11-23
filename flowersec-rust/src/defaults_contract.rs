use std::{fs, path::PathBuf, time::Duration};

use serde_json::Value;

use crate::ConnectorOptions;
use crate::proxy_server::{
    DEFAULT_MAX_BODY, DEFAULT_MAX_CHUNK, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_JSON,
    DEFAULT_MAX_WEBSOCKET_FRAME, DEFAULT_TIMEOUT, MAX_TIMEOUT,
};
use crate::session_v3::{
    MAX_BUFFERED_STREAM_BYTES_V3, MAX_HANDSHAKE_PAYLOAD_BYTES, SessionDeadlinesV3,
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

    assert_eq!(
        MAX_HANDSHAKE_PAYLOAD_BYTES as u64,
        manifest["e2ee"]["max_handshake_payload_bytes"]
            .as_u64()
            .expect("e2ee.max_handshake_payload_bytes")
    );
    assert_eq!(
        MAX_BUFFERED_STREAM_BYTES_V3 as u64,
        manifest["e2ee"]["max_inbound_buffered_bytes"]
            .as_u64()
            .expect("e2ee.max_inbound_buffered_bytes")
    );

    let deadlines = SessionDeadlinesV3::default();
    assert_eq!(deadlines.establish, Duration::from_secs(30));
    assert_eq!(deadlines.rekey_prepare, Duration::from_secs(10));
    assert_eq!(deadlines.rekey_completion, Duration::from_secs(30));
    assert_eq!(deadlines.close_flush, Duration::from_secs(7));

    let proxy = &manifest["proxy"];
    let rpc = &manifest["rpc"];
    assert_eq!(
        crate::session_v3::MAX_CONCURRENT_RPC_REQUESTS as u64,
        rpc["max_concurrent_requests"].as_u64().unwrap()
    );
    assert_eq!(
        crate::session_v3::MAX_QUEUED_RPC_REQUESTS as u64,
        rpc["max_queued_requests"].as_u64().unwrap()
    );
    assert_eq!(
        crate::session_v3::MAX_QUEUED_RPC_NOTIFICATIONS as u64,
        rpc["max_queued_notifications"].as_u64().unwrap()
    );
    assert_eq!(
        DEFAULT_MAX_JSON as u64,
        proxy["max_json_frame_bytes"].as_u64().unwrap()
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
fn public_connector_uses_shared_connect_timeout_default() {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("stability")
        .join("sdk_defaults.json");
    let manifest: Value = serde_json::from_slice(&fs::read(manifest_path).unwrap()).unwrap();
    let options = ConnectorOptions::new();
    assert_eq!(
        options.connect_timeout().as_millis(),
        manifest["transport"]["connect_timeout_ms"]
            .as_u64()
            .unwrap() as u128
    );
    assert!(options.trust_roots_der().is_empty());
}
