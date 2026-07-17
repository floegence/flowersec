use flowersec::{
    Path as ConnectionPath, Stage,
    controlplane::http::ErrorEnvelope,
    generated::flowersec::rpc::v1::RpcEnvelope,
    observability::DiagnosticEvent,
    proxy::{HttpRequestMeta, WebSocketOpenMeta},
    transport_security::{
        NetworkPlaintextPolicyOptions, PlaintextRiskAcceptance, TransportSecurityPolicy,
    },
};
use serde::Deserialize;
use std::{fs, path::PathBuf};
use url::Url;

#[derive(Debug, Deserialize)]
struct PortableVectors {
    version: u32,
    transport_policy: Vec<TransportCase>,
    yamux_header: YamuxHeader,
    rpc_envelope: RpcEnvelope,
    controlplane_error_envelope: ErrorEnvelope,
    proxy_http_request_meta: HttpRequestMeta,
    proxy_ws_open_meta: WebSocketOpenMeta,
    diagnostic_event: DiagnosticEvent,
}

#[derive(Debug, Deserialize)]
struct TransportCase {
    url: String,
    policy: String,
    #[serde(default)]
    allowed_hosts: Vec<String>,
    risk_acceptance: Option<String>,
    allowed: bool,
}

#[derive(Debug, Deserialize)]
struct YamuxHeader {
    bytes_hex: String,
    version: u8,
    #[serde(rename = "type")]
    frame_type: u8,
    flags: u16,
    stream_id: u32,
    length: u32,
}

#[derive(Debug, Deserialize)]
struct CodeRegistry {
    codes: Vec<RegistryCode>,
}

#[derive(Debug, Deserialize)]
struct RegistryCode {
    code: String,
    #[serde(default)]
    stages: Vec<String>,
}

#[tokio::test]
async fn shared_portable_protocol_vectors_match_rust_contracts() {
    let vectors: PortableVectors = read_json("testdata/portable_protocol_vectors.json");
    assert_eq!(vectors.version, 1);

    for test in vectors.transport_policy {
        #[allow(deprecated)]
        let policy = match test.policy.as_str() {
            "require_tls" => TransportSecurityPolicy::require_tls(),
            "allow_plaintext_for_loopback" => {
                TransportSecurityPolicy::allow_plaintext_for_loopback()
            }
            "allow_plaintext" => TransportSecurityPolicy::allow_plaintext(),
            "network_plaintext" => {
                assert_eq!(
                    test.risk_acceptance.as_deref(),
                    Some("accept_pre_e2ee_credential_exposure")
                );
                TransportSecurityPolicy::network_plaintext(NetworkPlaintextPolicyOptions {
                    allowed_hosts: test.allowed_hosts.clone(),
                    risk_acceptance: PlaintextRiskAcceptance::AcceptPreE2ECredentialExposure,
                })
                .expect("network plaintext policy")
            }
            value => panic!("unknown transport policy {value}"),
        };
        let result = policy
            .evaluate(
                &Url::parse(&test.url).expect("transport URL"),
                ConnectionPath::Direct,
            )
            .await;
        assert_eq!(result.is_ok(), test.allowed, "transport case {}", test.url);
    }

    let header = decode_hex(&vectors.yamux_header.bytes_hex);
    assert_eq!(header.len(), 12);
    assert_eq!(header[0], vectors.yamux_header.version);
    assert_eq!(header[1], vectors.yamux_header.frame_type);
    assert_eq!(
        u16::from_be_bytes([header[2], header[3]]),
        vectors.yamux_header.flags
    );
    assert_eq!(
        u32::from_be_bytes(header[4..8].try_into().expect("stream ID bytes")),
        vectors.yamux_header.stream_id
    );
    assert_eq!(
        u32::from_be_bytes(header[8..12].try_into().expect("length bytes")),
        vectors.yamux_header.length
    );

    assert_eq!(vectors.rpc_envelope.type_id, 7);
    assert_eq!(vectors.rpc_envelope.request_id, 42);
    assert_eq!(vectors.rpc_envelope.payload["message"], "flowersec");
    assert_eq!(
        vectors.controlplane_error_envelope.error.code,
        "artifact_not_found"
    );
    assert_eq!(vectors.proxy_http_request_meta.v, 1);
    assert_eq!(vectors.proxy_http_request_meta.method, "POST");
    assert_eq!(vectors.proxy_http_request_meta.timeout_ms, Some(1500));
    assert_eq!(vectors.proxy_ws_open_meta.v, 1);
    assert_eq!(vectors.proxy_ws_open_meta.conn_id, "connection-vector-1");
    assert_eq!(vectors.diagnostic_event.path, ConnectionPath::Tunnel);
    assert_eq!(vectors.diagnostic_event.stage, Stage::Yamux);
    assert_eq!(vectors.diagnostic_event.code, "liveness_timeout");

    assert_registry_contains(
        "stability/connect_error_code_registry.json",
        "resource_exhausted",
    );
    assert_registry_pair(
        "stability/connect_error_code_registry.json",
        "rpc",
        "resource_exhausted",
    );
    assert_registry_pair(
        "stability/connect_error_code_registry.json",
        "rpc",
        "missing_stream_kind",
    );
    assert_registry_contains(
        "stability/connect_diagnostics_code_registry.json",
        &vectors.diagnostic_event.code,
    );
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input length");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex byte"))
        .collect()
}

fn assert_registry_contains(path: &str, code: &str) {
    let registry: CodeRegistry = read_json(path);
    assert!(registry.codes.iter().any(|entry| entry.code == code));
}

fn assert_registry_pair(path: &str, stage: &str, code: &str) {
    let registry: CodeRegistry = read_json(path);
    assert!(
        registry
            .codes
            .iter()
            .any(|entry| entry.code == code && entry.stages.iter().any(|item| item == stage)),
        "missing registry pair {stage}/{code}"
    );
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root")
        .to_owned();
    serde_json::from_slice(&fs::read(root.join(path)).expect("read shared fixture"))
        .expect("decode shared fixture")
}
