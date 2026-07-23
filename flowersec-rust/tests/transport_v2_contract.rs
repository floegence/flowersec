use std::{io, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use flowersec::transport_v2::{
    ByteStreamV2, CapabilityTupleV2, CarrierKind, IncomingStreamV2, JsonObjectV2,
    NATIVE_RUST_CAPABILITIES_V2, NetworkMode, PathKind, RpcPeerV2, SessionRole, SessionV2,
    carrier_inbound_stream_limit_v2, decode_runtime_capability_descriptor_v2,
    encode_runtime_capability_descriptor_v2, native_rust_capability_descriptor_v2,
    runtime_capability_digest_hex_v2, validate_capabilities_v2,
};

#[test]
fn logical_stream_limit_reserves_control_and_rpc_carrier_streams() {
    assert_eq!(carrier_inbound_stream_limit_v2(1).unwrap(), 3);
    assert_eq!(carrier_inbound_stream_limit_v2(128).unwrap(), 130);
    assert!(carrier_inbound_stream_limit_v2(0).is_err());
    assert!(carrier_inbound_stream_limit_v2(129).is_err());
}

const EXPECTED_NATIVE_RUST_CAPABILITIES: [CapabilityTupleV2; 2] = [
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Dial,
        SessionRole::Client,
        PathKind::Direct,
    ),
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Dial,
        SessionRole::Client,
        PathKind::Tunnel,
    ),
];

#[test]
fn native_rust_capabilities_are_the_signed_exact_tuples() {
    assert_eq!(
        NATIVE_RUST_CAPABILITIES_V2,
        &EXPECTED_NATIVE_RUST_CAPABILITIES
    );
    validate_capabilities_v2(NATIVE_RUST_CAPABILITIES_V2)
        .expect("the signed native Rust capability table is valid");
}

#[test]
fn native_rust_descriptor_matches_the_shared_strict_codec_vector() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v2/capability_vectors.json"
    ))
    .unwrap();
    let vector = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["name"] == "rust-native")
        .unwrap();
    let descriptor = native_rust_capability_descriptor_v2();
    let canonical = encode_runtime_capability_descriptor_v2(&descriptor).unwrap();
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        vector["canonical_json"].as_str().unwrap()
    );
    assert_eq!(
        runtime_capability_digest_hex_v2(&descriptor).unwrap(),
        vector["digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        decode_runtime_capability_descriptor_v2(&canonical).unwrap(),
        descriptor
    );
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&canonical);
    assert!(decode_runtime_capability_descriptor_v2(&noncanonical).is_err());
}

#[test]
fn capability_validation_rejects_duplicates_and_invalid_role_path_pairs() {
    let valid = CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Dial,
        SessionRole::Client,
        PathKind::Direct,
    );
    let duplicate = [valid, valid];
    let error = validate_capabilities_v2(&duplicate).expect_err("duplicate tuple must fail");
    assert!(error.to_string().contains("duplicate"));

    let invalid = [CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Listen,
        SessionRole::Client,
        PathKind::Tunnel,
    )];
    let error = validate_capabilities_v2(&invalid).expect_err("listen/tunnel must fail");
    assert!(error.to_string().contains("invalid"));
}

#[derive(Debug)]
struct ProbeStream;

#[async_trait]
impl ByteStreamV2 for ProbeStream {
    fn id(&self) -> u64 {
        7
    }

    fn kind(&self) -> &str {
        "rpc"
    }

    fn terminal_error(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        None
    }

    async fn read(&self) -> io::Result<Option<Bytes>> {
        Ok(None)
    }

    async fn write(&self, payload: Bytes) -> io::Result<usize> {
        Ok(payload.len())
    }

    async fn close_write(&self) -> io::Result<()> {
        Ok(())
    }

    async fn reset(&self) -> io::Result<()> {
        Ok(())
    }

    async fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct ProbeRpc;

#[async_trait]
impl RpcPeerV2 for ProbeRpc {
    async fn call(
        &self,
        _type_id: u32,
        request: serde_json::Value,
    ) -> io::Result<serde_json::Value> {
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct ProbeSession {
    rpc: ProbeRpc,
}

#[async_trait]
impl SessionV2 for ProbeSession {
    fn path(&self) -> PathKind {
        PathKind::Direct
    }

    fn endpoint_instance_id(&self) -> Option<&str> {
        None
    }

    fn rpc(&self) -> &dyn RpcPeerV2 {
        &self.rpc
    }

    async fn open_stream(
        &self,
        _kind: &str,
        _metadata: JsonObjectV2,
    ) -> io::Result<Box<dyn ByteStreamV2>> {
        Ok(Box::new(ProbeStream))
    }

    async fn accept_stream(&self) -> io::Result<IncomingStreamV2> {
        Ok(IncomingStreamV2::new(
            "rpc",
            JsonObjectV2::new(),
            Box::new(ProbeStream),
        ))
    }

    async fn rekey(&self) -> io::Result<()> {
        Ok(())
    }

    async fn probe_liveness(&self) -> io::Result<Duration> {
        Ok(Duration::ZERO)
    }

    async fn wait_closed(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "probe session closed",
        ))
    }

    async fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

fn assert_session_object_safe(_session: Option<&dyn SessionV2>) {}
fn assert_stream_object_safe(_stream: Option<&dyn ByteStreamV2>) {}

#[test]
fn v2_contract_is_object_safe_and_carrier_neutral() {
    let session = ProbeSession { rpc: ProbeRpc };
    assert_session_object_safe(Some(&session));
    assert_stream_object_safe(None);

    assert_eq!(session.path(), PathKind::Direct);
    assert_eq!(session.endpoint_instance_id(), None);
    let _rpc: &dyn RpcPeerV2 = session.rpc();

    let incoming = IncomingStreamV2::new("rpc", JsonObjectV2::new(), Box::new(ProbeStream));
    assert_eq!(incoming.id(), 7);
    assert_eq!(incoming.kind(), "rpc");
    assert!(incoming.metadata().is_empty());
    assert_eq!(incoming.stream().kind(), "rpc");
    assert!(format!("{incoming:?}").contains("IncomingStreamV2"));
    let _stream: Box<dyn ByteStreamV2> = incoming.into_stream();

    let public_contract = include_str!("../src/transport_v2.rs");
    assert!(!public_contract.contains("quinn::"));
    assert!(!public_contract.contains("Yamux"));
}

#[test]
fn future_quic_handshake_tests_use_checked_in_der_not_runtime_generation() {
    // Future handshake slices must place stable certificate and PKCS#8 fixtures under
    // tests/fixtures/quic/*.der. Runtime certificate generation would make tests
    // nondeterministic and currently pulls an advisory-affected MSRV-compatible time crate.
    let manifest = include_str!("../Cargo.toml");
    let lockfile = include_str!("../Cargo.lock");
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim_start().starts_with("rcgen"))
    );
    assert!(!lockfile.lines().any(|line| line == "name = \"rcgen\""));
    assert!("tests/fixtures/quic/server-cert.der".ends_with(".der"));
    assert!("tests/fixtures/quic/server-key.der".ends_with(".der"));
}
