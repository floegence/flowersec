use flowersec::defaults;
use serde_json::Value;
use std::{fs, path::PathBuf};

#[test]
fn rust_defaults_match_stability_contract() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("stability")
        .join("sdk_defaults.json");
    let document: Value =
        serde_json::from_slice(&fs::read(path).expect("read defaults")).expect("parse defaults");

    assert_eq!(
        ms(&document, "transport", "connect_timeout_ms"),
        defaults::CONNECT_TIMEOUT.as_millis()
    );
    assert_eq!(
        ms(&document, "transport", "handshake_timeout_ms"),
        defaults::HANDSHAKE_TIMEOUT.as_millis()
    );
    assert_eq!(
        ms(&document, "transport", "handshake_clock_skew_ms"),
        defaults::HANDSHAKE_CLOCK_SKEW.as_millis()
    );
    assert_eq!(
        number(&document, "e2ee", "max_handshake_payload_bytes"),
        defaults::MAX_HANDSHAKE_PAYLOAD_BYTES as u64
    );
    assert_eq!(
        number(&document, "e2ee", "max_record_bytes"),
        defaults::MAX_RECORD_BYTES as u64
    );
    assert_eq!(
        number(&document, "e2ee", "outbound_record_chunk_bytes"),
        defaults::OUTBOUND_RECORD_CHUNK_BYTES as u64
    );
    assert_eq!(
        number(&document, "e2ee", "max_outbound_buffered_bytes"),
        defaults::MAX_OUTBOUND_BUFFERED_BYTES as u64
    );
    assert_eq!(
        number(&document, "yamux", "max_active_streams"),
        defaults::YAMUX_MAX_ACTIVE_STREAMS as u64
    );
    assert_eq!(
        number(&document, "yamux", "max_inbound_streams"),
        defaults::YAMUX_MAX_INBOUND_STREAMS as u64
    );
    assert_eq!(
        number(&document, "yamux", "max_frame_bytes"),
        defaults::YAMUX_MAX_FRAME_BYTES as u64
    );
    assert_eq!(
        number(&document, "yamux", "preferred_outbound_frame_bytes"),
        defaults::YAMUX_PREFERRED_OUTBOUND_FRAME_BYTES as u64
    );
    assert_eq!(
        number(&document, "yamux", "max_session_receive_bytes"),
        defaults::YAMUX_MAX_SESSION_RECEIVE_BYTES as u64
    );
    assert_eq!(
        number(&document, "yamux", "max_stream_write_queue_bytes"),
        defaults::YAMUX_MAX_STREAM_WRITE_QUEUE_BYTES as u64
    );
    assert_eq!(
        number(&document, "yamux", "max_stream_receive_bytes"),
        defaults::YAMUX_MAX_STREAM_RECEIVE_BYTES as u64
    );
    assert_eq!(
        number(&document, "rpc", "max_json_frame_bytes"),
        defaults::MAX_JSON_FRAME_BYTES as u64
    );
    assert_eq!(
        number(&document, "rpc", "max_concurrent_requests"),
        defaults::RPC_MAX_CONCURRENT_REQUESTS as u64
    );
    assert_eq!(
        number(&document, "rpc", "max_queued_requests"),
        defaults::RPC_MAX_QUEUED_REQUESTS as u64
    );
    assert_eq!(
        number(&document, "rpc", "max_queued_notifications"),
        defaults::RPC_MAX_QUEUED_NOTIFICATIONS as u64
    );
    assert_eq!(
        number(&document, "controlplane", "max_request_body_bytes"),
        defaults::CONTROLPLANE_MAX_REQUEST_BODY_BYTES as u64
    );
    assert_eq!(
        number(&document, "controlplane", "max_response_body_bytes"),
        defaults::CONTROLPLANE_MAX_RESPONSE_BODY_BYTES as u64
    );
    assert_eq!(
        number(&document, "proxy", "max_json_frame_bytes"),
        defaults::MAX_JSON_FRAME_BYTES as u64
    );
    assert_eq!(
        number(&document, "proxy", "max_chunk_bytes"),
        defaults::PROXY_MAX_CHUNK_BYTES as u64
    );
    assert_eq!(
        number(&document, "proxy", "max_body_bytes"),
        defaults::PROXY_MAX_BODY_BYTES as u64
    );
    assert_eq!(
        number(&document, "proxy", "max_ws_frame_bytes"),
        defaults::PROXY_MAX_WS_FRAME_BYTES as u64
    );
    assert_eq!(
        ms(&document, "proxy", "default_timeout_ms"),
        defaults::PROXY_DEFAULT_TIMEOUT.as_millis()
    );
    assert_eq!(
        ms(&document, "proxy", "max_timeout_ms"),
        defaults::PROXY_MAX_TIMEOUT.as_millis()
    );
    assert_eq!(
        number(&document, "reconnect", "max_attempts"),
        defaults::RECONNECT_MAX_ATTEMPTS as u64
    );
    assert_eq!(
        ms(&document, "reconnect", "initial_delay_ms"),
        defaults::RECONNECT_INITIAL_DELAY.as_millis()
    );
    assert_eq!(
        ms(&document, "reconnect", "max_delay_ms"),
        defaults::RECONNECT_MAX_DELAY.as_millis()
    );
    assert_eq!(
        document["reconnect"]["factor"]
            .as_f64()
            .expect("reconnect factor"),
        defaults::RECONNECT_FACTOR
    );
    assert_eq!(
        document["reconnect"]["jitter_ratio"]
            .as_f64()
            .expect("reconnect jitter ratio"),
        defaults::RECONNECT_JITTER_RATIO
    );
}

fn ms(document: &Value, section: &str, key: &str) -> u128 {
    number(document, section, key) as u128
}

fn number(document: &Value, section: &str, key: &str) -> u64 {
    document[section][key].as_u64().expect("numeric default")
}
