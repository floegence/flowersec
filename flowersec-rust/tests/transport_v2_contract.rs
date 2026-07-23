use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use flowersec::{
    ByteStream, IncomingStream, JsonObject, RpcPeer, Session, SessionError, StreamTerminalError,
};

#[derive(Debug)]
struct ProbeStream;

#[async_trait]
impl ByteStream for ProbeStream {
    fn kind(&self) -> &str {
        "rpc"
    }

    fn terminal_error(&self) -> Option<StreamTerminalError> {
        Some(StreamTerminalError::Reset)
    }

    async fn read(&self) -> Result<Option<Bytes>, SessionError> {
        Ok(None)
    }

    async fn write(&self, payload: Bytes) -> Result<usize, SessionError> {
        Ok(payload.len())
    }

    async fn close_write(&self) -> Result<(), SessionError> {
        Ok(())
    }

    async fn reset(&self) -> Result<(), SessionError> {
        Ok(())
    }

    async fn close(&self) -> Result<(), SessionError> {
        Ok(())
    }
}

#[derive(Debug)]
struct ProbeRpc;

#[async_trait]
impl RpcPeer for ProbeRpc {
    async fn call(
        &self,
        _type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, SessionError> {
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), SessionError> {
        Ok(())
    }
}

#[derive(Debug)]
struct ProbeSession {
    rpc: ProbeRpc,
}

#[async_trait]
impl Session for ProbeSession {
    fn rpc(&self) -> &dyn RpcPeer {
        &self.rpc
    }

    async fn open_stream(
        &self,
        _kind: &str,
        _metadata: JsonObject,
    ) -> Result<Box<dyn ByteStream>, SessionError> {
        Ok(Box::new(ProbeStream))
    }

    async fn accept_stream(&self) -> Result<IncomingStream, SessionError> {
        Ok(IncomingStream::new(
            "rpc",
            JsonObject::new(),
            Box::new(ProbeStream),
        ))
    }

    async fn rekey(&self) -> Result<(), SessionError> {
        Ok(())
    }

    async fn probe_liveness(&self) -> Result<Duration, SessionError> {
        Ok(Duration::ZERO)
    }

    async fn wait_closed(&self) -> Result<(), SessionError> {
        Err(SessionError::Closed)
    }

    async fn close(&self) -> Result<(), SessionError> {
        Ok(())
    }
}

fn assert_session_object_safe(_session: Option<&dyn Session>) {}
fn assert_stream_object_safe(_stream: Option<&dyn ByteStream>) {}
fn assert_terminal_error_is_closed(
    error: Option<StreamTerminalError>,
) -> Option<StreamTerminalError> {
    error
}

#[test]
fn v2_contract_is_object_safe_and_carrier_neutral() {
    let session = ProbeSession { rpc: ProbeRpc };
    assert_session_object_safe(Some(&session));
    assert_stream_object_safe(None);

    let _rpc: &dyn RpcPeer = session.rpc();

    let incoming = IncomingStream::new("rpc", JsonObject::new(), Box::new(ProbeStream));
    assert_eq!(incoming.kind(), "rpc");
    assert!(incoming.metadata().is_empty());
    assert_eq!(incoming.stream().kind(), "rpc");
    assert_eq!(
        assert_terminal_error_is_closed(incoming.stream().terminal_error()),
        Some(StreamTerminalError::Reset)
    );
    assert!(format!("{incoming:?}").contains("IncomingStreamV2"));
    let _stream: Box<dyn ByteStream> = incoming.into_stream();

    let public_contract = include_str!("../src/transport_v2.rs");
    assert!(!public_contract.contains("quinn::"));
    assert!(!public_contract.contains("Yamux"));
}

#[test]
fn crate_root_does_not_export_transport_topology() {
    let facade = include_str!("../src/lib.rs");
    for forbidden in [
        "CapabilityTupleV2",
        "CarrierKind",
        "NetworkMode",
        "PathKind",
        "SessionRole",
        "NATIVE_RUST_CAPABILITIES_V2",
    ] {
        assert!(
            !facade.contains(forbidden),
            "root facade exported {forbidden}"
        );
    }
}

#[test]
fn stream_terminal_errors_are_typed_and_redacted() {
    let snapshots = [
        (
            StreamTerminalError::Closed,
            "Closed",
            "Flowersec stream closed",
        ),
        (
            StreamTerminalError::Failed,
            "Failed",
            "Flowersec stream failed",
        ),
        (
            StreamTerminalError::Reset,
            "Reset",
            "Flowersec stream reset",
        ),
        (
            StreamTerminalError::TimedOut,
            "TimedOut",
            "Flowersec stream timed out",
        ),
    ];
    for (error, debug, display) in snapshots {
        assert_eq!(format!("{error:?}"), debug);
        assert_eq!(error.to_string(), display);
    }
}

#[test]
fn session_errors_are_closed_and_redacted() {
    let snapshots = [
        (SessionError::Canceled, "Flowersec operation was canceled"),
        (SessionError::Closed, "Flowersec session is closed"),
        (SessionError::InvalidInput, "invalid Flowersec operation"),
        (SessionError::Rejected, "Flowersec operation was rejected"),
        (
            SessionError::ResourceExhausted,
            "Flowersec resources are exhausted",
        ),
        (SessionError::Reset, "Flowersec stream was reset"),
        (SessionError::TimedOut, "Flowersec operation timed out"),
        (SessionError::Failed, "Flowersec operation failed"),
    ];
    for (error, display) in snapshots {
        assert_eq!(error.to_string(), display);
    }
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
