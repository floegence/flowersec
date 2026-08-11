use std::fs;

#[test]
fn addon_is_a_thin_bridge_without_protocol_or_product_logic() {
    let source = fs::read_to_string("src/raw_quic.rs").expect("raw QUIC bridge source");
    for forbidden in [
        "SETTINGS_",
        "QPACK",
        "SessionHandlers",
        "Artifact",
        "TunnelRuntime",
        "@matrixai/quic",
    ] {
        assert!(
            !source.contains(forbidden),
            "addon contains forbidden boundary {forbidden}"
        );
    }
}
