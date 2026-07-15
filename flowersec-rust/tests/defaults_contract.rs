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
        number(&document, "e2ee", "max_record_bytes"),
        defaults::MAX_RECORD_BYTES as u64
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
        number(&document, "yamux", "max_session_receive_bytes"),
        defaults::YAMUX_MAX_SESSION_RECEIVE_BYTES as u64
    );
    assert_eq!(
        number(&document, "rpc", "max_concurrent_requests"),
        defaults::RPC_MAX_CONCURRENT_REQUESTS as u64
    );
    assert_eq!(
        number(&document, "proxy", "max_body_bytes"),
        defaults::PROXY_MAX_BODY_BYTES as u64
    );
    assert_eq!(
        number(&document, "reconnect", "max_attempts"),
        defaults::RECONNECT_MAX_ATTEMPTS as u64
    );
}

fn ms(document: &Value, section: &str, key: &str) -> u128 {
    number(document, section, key) as u128
}

fn number(document: &Value, section: &str, key: &str) -> u64 {
    document[section][key].as_u64().expect("numeric default")
}
