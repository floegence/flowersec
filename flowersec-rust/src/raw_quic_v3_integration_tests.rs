use std::{
    io::{BufRead, BufReader, Read},
    net::{Ipv4Addr, SocketAddr},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use cert_test_builder::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use flowersec_native_transport::{
    Cancellation as NativeCancellation, PathProfile as NativePathProfile,
    RawQuicClientConfig as NativeClientConfig, RawQuicLimits as NativeLimits,
    RawQuicListener as NativeListener, RawQuicServerConfig as NativeServerConfig,
    RawQuicSession as NativeSession,
};
use serde_json::{Value, json};
use sha2::Digest as _;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio_util::sync::CancellationToken;

use crate::{
    Acceptor, AcceptorOptions, ArtifactLease, ConnectorOptions, RpcHandler, RpcHandlers,
    RuntimeAuthorizationRequest, TunnelAuthorizationError, TunnelAuthorizationResponse,
    TunnelAuthorizer, TunnelRuntime, TunnelRuntimeOptions,
    artifact_v3::{AdmissionStatusV3, Artifact, decode_fsa3, hash_lp, jcs_value},
    connector_v3::connect_v3,
    protocol_v3::CipherSuiteV3,
    raw_quic_v3::carrier_from_native_session,
    session_v3::{RpcHandlerV3, SessionConfigV3, SessionDeadlinesV3, establish_session_v3},
    transport::{RpcError, Session, StreamMetadata, UnreliableSendOutcome},
    transport_v3::{
        CarrierSessionV3, CarrierStreamV3, PathKind, SessionRole, carrier_inbound_stream_limit_v3,
    },
};

const TEST_CERT_DER_B64: &str = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";
const TEST_KEY_DER_B64: &str = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6";
const CHANNEL_ID: &str = "rust-go-v3-interop";
const MAX_STREAMS: u16 = 4;
const FSA3_SUCCESS: &[u8] = b"FSA3\x03\x00\x00\x00";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_and_rust_exchange_fsb3_in_both_directions_for_direct_and_tunnel() {
    for profile in [NativePathProfile::Direct, NativePathProfile::Tunnel] {
        rust_client_to_go_admission(profile).await;
        go_client_to_rust_admission(profile).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_and_rust_run_full_v3_sessions_in_both_directions_for_direct_and_tunnel() {
    for profile in [NativePathProfile::Direct, NativePathProfile::Tunnel] {
        rust_client_to_go_session(profile).await;
        go_client_to_rust_session(profile).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_raw_quic_tunnel_runtime_relays_a_complete_v3_session() {
    let identity = short_lived_identity();
    let certificate = identity.certificate;
    let pin =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&certificate));
    let authorizer = Arc::new(TestTunnelAuthorizer::default());
    let runtime = Arc::new(
        TunnelRuntime::bind_raw_quic(
            TunnelRuntimeOptions {
                bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                certificate_chain_der: vec![certificate],
                private_key_der: identity.private_key,
                allowed_origins: Vec::new(),
                admission_reasons: Vec::new(),
                max_inbound_streams: MAX_STREAMS,
                pair_timeout: Duration::from_secs(5),
                max_pending_legs: 8,
                max_active_pairs: 4,
            },
            authorizer.clone(),
        )
        .unwrap(),
    );
    let address = runtime.local_address().unwrap();
    let client_artifact = tunnel_relay_artifact(
        address,
        1,
        "endpoint-client",
        "endpoint-server",
        "client-token",
        &pin,
    );
    let server_artifact = tunnel_relay_artifact(
        address,
        2,
        "endpoint-server",
        "endpoint-client",
        "server-token",
        &pin,
    );
    authorizer
        .artifacts
        .lock()
        .unwrap()
        .extend([client_artifact.clone(), server_artifact.clone()]);
    let runtime_cancellation = tokio_util::sync::CancellationToken::new();
    let runtime_task = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = runtime_cancellation.clone();
        async move { runtime.serve(cancellation).await }
    });
    let options = ConnectorOptions::new;
    let (client, server) = tokio::join!(
        connect_v3(
            ArtifactLease::new(client_artifact, || async { Ok(()) }),
            options(),
        ),
        connect_v3(
            ArtifactLease::new(server_artifact, || async { Ok(()) }),
            options(),
        ),
    );
    let client = client.unwrap();
    let server = server.unwrap();

    let receiver = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept_stream().await.unwrap();
            assert_eq!(incoming.kind(), "raw-quic.tunnel.v3");
            assert_eq!(
                incoming.stream().read().await.unwrap(),
                Some(Bytes::from_static(b"client payload"))
            );
            assert_eq!(incoming.stream().read().await.unwrap(), None);
            incoming
                .stream()
                .write(Bytes::from_static(b"server reply"))
                .await
                .unwrap();
            incoming.stream().close_write().await.unwrap();
        }
    });
    let stream = client
        .open_stream("raw-quic.tunnel.v3", StreamMetadata::empty())
        .await
        .unwrap();
    stream
        .write(Bytes::from_static(b"client payload"))
        .await
        .unwrap();
    stream.close_write().await.unwrap();
    assert_eq!(
        stream.read().await.unwrap(),
        Some(Bytes::from_static(b"server reply"))
    );
    assert_eq!(stream.read().await.unwrap(), None);
    receiver.await.unwrap();

    let client_unreliable = client.unreliable_messages().unwrap();
    let server_unreliable = server.unreliable_messages().unwrap();
    assert_eq!(
        client_unreliable
            .send(
                Bytes::from_static(b"client datagram"),
                SystemTime::now() + Duration::from_secs(30),
            )
            .await
            .unwrap(),
        UnreliableSendOutcome::Accepted
    );
    assert_eq!(
        server_unreliable.receive().await.unwrap(),
        Bytes::from_static(b"client datagram")
    );
    assert_eq!(
        server_unreliable
            .send(
                Bytes::from_static(b"server datagram"),
                SystemTime::now() + Duration::from_secs(30),
            )
            .await
            .unwrap(),
        UnreliableSendOutcome::Accepted
    );
    assert_eq!(
        client_unreliable.receive().await.unwrap(),
        Bytes::from_static(b"server datagram")
    );

    let _ = tokio::join!(client.close(), server.close());
    runtime.close().await;
    runtime_cancellation.cancel();
    runtime_task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_raw_quic_acceptor_establishes_a_complete_v3_session() {
    let acceptor = Arc::new(
        Acceptor::bind(AcceptorOptions {
            bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            certificate_chain_der: vec![test_certificate()],
            private_key_der: test_private_key(),
            max_inbound_streams: MAX_STREAMS,
            accept_timeout: Duration::from_secs(5),
        })
        .unwrap(),
    );
    let artifact = interop_artifact(acceptor.local_address().unwrap(), NativePathProfile::Direct);
    let server_artifact = artifact.clone();
    let server_task = tokio::spawn(async move {
        acceptor
            .accept(&server_artifact, tokio_util::sync::CancellationToken::new())
            .await
            .unwrap()
    });
    let client = connect_v3(
        ArtifactLease::new(artifact, || async { Ok(()) }),
        ConnectorOptions::new()
            .with_trust_roots_der(vec![test_certificate()])
            .unwrap(),
    )
    .await
    .unwrap();
    let server = server_task.await.unwrap();
    let receiver = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept_stream().await.unwrap();
            assert_eq!(incoming.kind(), "raw-quic.direct.v3");
            assert_eq!(read_logical(incoming.stream()).await, b"request");
            incoming
                .stream()
                .write(Bytes::from_static(b"response"))
                .await
                .unwrap();
            incoming.stream().close_write().await.unwrap();
        }
    });
    let stream = client
        .open_stream("raw-quic.direct.v3", StreamMetadata::empty())
        .await
        .unwrap();
    stream.write(Bytes::from_static(b"request")).await.unwrap();
    stream.close_write().await.unwrap();
    assert_eq!(read_logical(stream.as_ref()).await, b"response");
    receiver.await.unwrap();
    let _ = tokio::join!(client.close(), server.close());
}

#[derive(Default)]
struct TestTunnelAuthorizer {
    artifacts: StdMutex<Vec<Artifact>>,
}

#[async_trait]
impl TunnelAuthorizer for TestTunnelAuthorizer {
    async fn authorize(
        &self,
        request: RuntimeAuthorizationRequest,
        _cancellation: CancellationToken,
    ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
        self.artifacts
            .lock()
            .unwrap()
            .iter()
            .find_map(|artifact| {
                TunnelAuthorizationResponse::allow(&request, artifact, request.lookup_key(), false)
                    .ok()
            })
            .ok_or(TunnelAuthorizationError)
    }
}

async fn rust_client_to_go_admission(profile: NativePathProfile) {
    let (child, reader, _stderr, address) = start_go_server("server", profile).await;
    let native = dial_native(address, profile).await;
    let carrier = carrier_from_native_session(native);
    let artifact = interop_artifact(address, profile);
    let fsb3 = artifact.encode_fsb3("q-ca").unwrap();
    commit_admission(carrier.as_ref(), &fsb3.raw).await;
    let barrier = carrier.open_stream().await.unwrap();
    write_all(barrier.as_ref(), b"ACK").await;
    barrier.close_write_delivered().await.unwrap();
    wait_go_server(child, reader, _stderr).await;
    carrier.abort();
}

async fn go_client_to_rust_admission(profile: NativePathProfile) {
    let listener = native_listener(profile);
    let address = listener.local_address().unwrap();
    let go = tokio::task::spawn_blocking(move || go_peer("client", Some(address), profile));
    let native = listener.accept(&NativeCancellation::new()).await.unwrap();
    let carrier = carrier_from_native_session(native);
    let artifact = interop_artifact_with_host(address, profile, "localhost");
    let fsb3 = artifact.encode_fsb3("q-ca").unwrap();
    serve_admission(carrier.as_ref(), &fsb3.raw).await;
    let output = go.await.unwrap();
    assert_go_output(output);
    carrier.abort();
    listener.abort();
}

async fn rust_client_to_go_session(profile: NativePathProfile) {
    let (child, reader, _stderr, address) = start_go_server("session-server", profile).await;
    let artifact = interop_artifact(address, profile);
    let spends = Arc::new(AtomicUsize::new(0));
    let spend_capture = spends.clone();
    let lease = ArtifactLease::new(artifact, move || async move {
        spend_capture.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let mut handlers = RpcHandlers::new();
    handlers.handle_rpc(110, InteropRpc).unwrap();
    let options = ConnectorOptions::new()
        .with_trust_roots_der(vec![test_certificate()])
        .unwrap()
        .with_rpc_handlers(handlers);
    let session = connect_v3(lease, options).await.unwrap();
    exercise_rust_side(session.as_ref()).await;
    tokio::time::timeout(Duration::from_secs(10), session.wait_termination())
        .await
        .expect("Go peer must close the established v3 session");
    wait_go_server(child, reader, _stderr).await;
    assert_eq!(spends.load(Ordering::SeqCst), 1);
}

async fn go_client_to_rust_session(profile: NativePathProfile) {
    let listener = native_listener(profile);
    let address = listener.local_address().unwrap();
    let go = tokio::task::spawn_blocking(move || go_peer("session-client", Some(address), profile));
    let native = listener.accept(&NativeCancellation::new()).await.unwrap();
    let carrier = carrier_from_native_session(native);
    let artifact = interop_artifact_with_host(address, profile, "localhost");
    let fsb3 = artifact.encode_fsb3("q-ca").unwrap();
    serve_admission(carrier.as_ref(), &fsb3.raw).await;
    let session = establish_session_v3(
        carrier,
        session_config(profile, SessionRole::Server, fsb3.binding),
    )
    .await
    .unwrap();
    exercise_rust_side(session.as_ref()).await;
    tokio::time::timeout(Duration::from_secs(10), session.wait_termination())
        .await
        .expect("Go peer must close the established v3 session");
    let output = go.await.unwrap();
    assert_go_output(output);
    listener.abort();
}

async fn exercise_rust_side(session: &dyn Session) {
    let incoming = session.accept_stream().await.unwrap();
    assert_eq!(incoming.kind(), "go-to-rust");
    assert_eq!(
        incoming.metadata().values().get("language"),
        Some(&json!("go"))
    );
    assert_eq!(read_logical(incoming.stream()).await, b"go-app");
    incoming
        .stream()
        .write(Bytes::from_static(b"rust-reply"))
        .await
        .unwrap();
    incoming.stream().close_write().await.unwrap();

    let metadata = StreamMetadata::try_from(json!({"language": "rust"})).unwrap();
    let outbound = session.open_stream("rust-to-go", metadata).await.unwrap();
    outbound
        .write(Bytes::from_static(b"rust-app"))
        .await
        .unwrap();
    outbound.close_write().await.unwrap();
    assert_eq!(read_logical(outbound.as_ref()).await, b"go-reply");
}

async fn read_logical(stream: &dyn crate::ByteStream) -> Vec<u8> {
    let mut output = Vec::new();
    while let Some(chunk) = stream.read().await.unwrap() {
        output.extend_from_slice(&chunk);
    }
    output
}

async fn commit_admission(carrier: &dyn CarrierSessionV3, fsb3: &[u8]) {
    let stream = carrier.open_stream().await.unwrap();
    write_all(stream.as_ref(), fsb3).await;
    stream.close_write_delivered().await.unwrap();
    let response = read_to_end(stream.as_ref()).await;
    assert_eq!(
        decode_fsa3(&response).unwrap().status,
        AdmissionStatusV3::Success
    );
}

async fn serve_admission(carrier: &dyn CarrierSessionV3, expected_fsb3: &[u8]) {
    let stream = carrier.accept_stream().await.unwrap();
    assert_eq!(read_to_end(stream.as_ref()).await, expected_fsb3);
    write_all(stream.as_ref(), FSA3_SUCCESS).await;
    stream.close_write_delivered().await.unwrap();
}

async fn write_all(stream: &dyn CarrierStreamV3, payload: &[u8]) {
    let mut offset = 0;
    while offset < payload.len() {
        let written = stream.write(&payload[offset..]).await.unwrap();
        assert_ne!(written, 0);
        offset += written;
    }
}

async fn read_to_end(stream: &dyn CarrierStreamV3) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4_096];
    loop {
        let count = stream.read(&mut buffer).await.unwrap();
        if count == 0 {
            return output;
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

async fn dial_native(address: SocketAddr, profile: NativePathProfile) -> NativeSession {
    let config =
        NativeClientConfig::new_ca(profile, vec![test_certificate()], native_limits()).unwrap();
    NativeSession::dial(
        vec![address],
        "localhost".into(),
        config,
        &NativeCancellation::new(),
    )
    .await
    .unwrap()
}

fn native_listener(profile: NativePathProfile) -> NativeListener {
    let config = NativeServerConfig::new(
        profile,
        vec![test_certificate()],
        test_private_key(),
        native_limits(),
    )
    .unwrap();
    NativeListener::bind((Ipv4Addr::LOCALHOST, 0).into(), config).unwrap()
}

fn native_limits() -> NativeLimits {
    NativeLimits::for_session(
        carrier_inbound_stream_limit_v3(MAX_STREAMS).unwrap(),
        Duration::from_secs(30),
    )
    .unwrap()
}

fn interop_artifact(address: SocketAddr, profile: NativePathProfile) -> Artifact {
    interop_artifact_with_host(address, profile, "127.0.0.1")
}

fn interop_artifact_with_host(
    address: SocketAddr,
    profile: NativePathProfile,
    host: &str,
) -> Artifact {
    let projection = json!({
        "allowed_suites": [1],
        "channel_id": CHANNEL_ID,
        "default_suite": 1,
        "establish_timeout_seconds": 30,
        "idle_timeout_seconds": 60,
        "max_inbound_streams": MAX_STREAMS,
        "profile": "flowersec/3",
        "rekey_completion_timeout_seconds": 30,
        "rekey_prepare_timeout_seconds": 10,
        "selected_features": 0
    });
    let contract_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash_lp(
        b"flowersec-v3-session-contract\0",
        &jcs_value(&projection).unwrap(),
    ));
    let candidate = json!({
        "carrier": "raw_quic",
        "id": "q-ca",
        "tls": {"mode": "ca"},
        "url": format!("quic://{host}:{}/", address.port()),
        "wire_profile": match profile {
            NativePathProfile::Direct => "flowersec-direct/3",
            NativePathProfile::Tunnel => "flowersec-tunnel/3",
        }
    });
    let path = match profile {
        NativePathProfile::Direct => json!({
            "candidates": [candidate],
            "kind": "direct",
            "listener_audience": "rust-go-v3-listener",
            "rendezvous_group_id": "rust-go-v3",
            "routing_token": "rust-go-v3-routing"
        }),
        NativePathProfile::Tunnel => json!({
            "candidates": [candidate],
            "expected_peer_endpoint_instance_id": "endpoint-server",
            "kind": "tunnel",
            "listener_audience": "rust-go-v3-listener",
            "local_endpoint_instance_id": "endpoint-client",
            "rendezvous_group_id": "rust-go-v3",
            "role": 1,
            "token": "rust-go-v3-attach"
        }),
    };
    let value = json!({
        "correlation": {"tags": [], "v": 3},
        "path": path,
        "profile": "flowersec/3",
        "scoped": [],
        "session": {
            "allowed_suites": [1],
            "channel_id": CHANNEL_ID,
            "contract_hash_b64u": contract_hash,
            "default_suite": 1,
            "e2ee_psk_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(interop_psk()),
            "establish_timeout_seconds": 30,
            "idle_timeout_seconds": 60,
            "init_expire_at_unix_s": 2_000_000_000_u64,
            "max_inbound_streams": MAX_STREAMS,
            "rekey_completion_timeout_seconds": 30,
            "rekey_prepare_timeout_seconds": 10,
            "selected_features": 0
        },
        "v": 3
    });
    Artifact::parse(jcs_value(&value).unwrap()).unwrap()
}

fn tunnel_relay_artifact(
    address: SocketAddr,
    role: u8,
    local_endpoint: &str,
    peer_endpoint: &str,
    token: &str,
    pin: &str,
) -> Artifact {
    let projection = json!({
        "allowed_suites": [1],
        "channel_id": CHANNEL_ID,
        "default_suite": 1,
        "establish_timeout_seconds": 30,
        "idle_timeout_seconds": 60,
        "max_inbound_streams": MAX_STREAMS,
        "profile": "flowersec/3",
        "rekey_completion_timeout_seconds": 30,
        "rekey_prepare_timeout_seconds": 10,
        "selected_features": 0
    });
    let contract_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash_lp(
        b"flowersec-v3-session-contract\0",
        &jcs_value(&projection).unwrap(),
    ));
    let value = json!({
        "correlation": {"tags": [], "v": 3},
        "path": {
            "candidates": [{
                "carrier": "raw_quic",
                "id": "q-ca",
                "tls": {"mode": "pin", "pins": [{
                    "algorithm": "sha-256",
                    "not_after_unix_s": 2_000_000_000_u64,
                    "value_b64u": pin
                }]},
                "url": format!("quic://127.0.0.1:{}/", address.port()),
                "wire_profile": "flowersec-tunnel/3"
            }],
            "expected_peer_endpoint_instance_id": peer_endpoint,
            "kind": "tunnel",
            "listener_audience": "rust-relay-v3-listener",
            "local_endpoint_instance_id": local_endpoint,
            "rendezvous_group_id": "rust-relay-v3",
            "role": role,
            "token": token
        },
        "profile": "flowersec/3",
        "scoped": [],
        "session": {
            "allowed_suites": [1],
            "channel_id": CHANNEL_ID,
            "contract_hash_b64u": contract_hash,
            "default_suite": 1,
            "e2ee_psk_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(interop_psk()),
            "establish_timeout_seconds": 30,
            "idle_timeout_seconds": 60,
            "init_expire_at_unix_s": 2_000_000_000_u64,
            "max_inbound_streams": MAX_STREAMS,
            "rekey_completion_timeout_seconds": 30,
            "rekey_prepare_timeout_seconds": 10,
            "selected_features": 0
        },
        "v": 3
    });
    Artifact::parse(jcs_value(&value).unwrap()).unwrap()
}

fn session_config(
    profile: NativePathProfile,
    role: SessionRole,
    local_binding: [u8; 32],
) -> SessionConfigV3 {
    let (path, peer_binding, local_endpoint, peer_endpoint) = match profile {
        NativePathProfile::Direct => (PathKind::Direct, Some(local_binding), None, None),
        NativePathProfile::Tunnel if role == SessionRole::Client => (
            PathKind::Tunnel,
            None,
            Some("endpoint-client".into()),
            Some("endpoint-server".into()),
        ),
        NativePathProfile::Tunnel => (
            PathKind::Tunnel,
            None,
            Some("endpoint-server".into()),
            Some("endpoint-client".into()),
        ),
    };
    let artifact = interop_artifact("127.0.0.1:443".parse().unwrap(), profile);
    let plan = artifact.connection_plan().unwrap();
    SessionConfigV3 {
        role,
        path,
        channel_id: CHANNEL_ID.into(),
        session_contract_hash: plan.session.session_contract_hash,
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: interop_psk(),
        max_inbound_streams: MAX_STREAMS,
        idle_timeout: Duration::from_secs(60),
        local_admission_binding: local_binding,
        peer_admission_binding: peer_binding,
        local_endpoint_instance_id: local_endpoint,
        expected_peer_endpoint_instance_id: peer_endpoint,
        rpc_handler: Some(Arc::new(InteropRpc)),
        deadlines: SessionDeadlinesV3::default(),
    }
}

fn interop_psk() -> [u8; 32] {
    std::array::from_fn(|index| u8::try_from(index + 1).expect("interop PSK index fits in u8"))
}

#[derive(Debug)]
struct InteropRpc;

#[async_trait]
impl RpcHandler for InteropRpc {
    async fn call(&self, _type_id: u32, request: Value) -> Result<Value, RpcError> {
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: Value) -> Result<(), RpcError> {
        Ok(())
    }
}

#[async_trait]
impl RpcHandlerV3 for InteropRpc {
    async fn call(&self, _type_id: u32, request: Value) -> Result<Value, RpcError> {
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: Value) -> Result<(), RpcError> {
        Ok(())
    }
}

async fn start_go_server(
    mode: &str,
    profile: NativePathProfile,
) -> (
    Child,
    BufReader<std::process::ChildStdout>,
    BufReader<std::process::ChildStderr>,
    SocketAddr,
) {
    let mut command = go_peer_command(mode, None, profile);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().expect("start Go v3 raw QUIC peer");
    let stdout = child.stdout.take().expect("Go peer stdout");
    let stderr = child.stderr.take().expect("Go peer stderr");
    let (reader, ready) = tokio::task::spawn_blocking(move || {
        let mut reader = BufReader::new(stdout);
        let mut ready = String::new();
        reader.read_line(&mut ready).expect("read Go READY");
        (reader, ready)
    })
    .await
    .unwrap();
    let address = ready
        .trim()
        .strip_prefix("READY ")
        .expect("Go READY prefix")
        .parse()
        .expect("Go peer address");
    (child, reader, BufReader::new(stderr), address)
}

async fn wait_go_server(
    mut child: Child,
    mut reader: BufReader<std::process::ChildStdout>,
    mut stderr: BufReader<std::process::ChildStderr>,
) {
    let (status, remainder, error_output) = tokio::task::spawn_blocking(move || {
        let status = child.wait().expect("wait Go peer");
        let mut remainder = String::new();
        reader.read_to_string(&mut remainder).unwrap();
        let mut error_output = String::new();
        stderr.read_to_string(&mut error_output).unwrap();
        (status, remainder, error_output)
    })
    .await
    .unwrap();
    assert!(
        status.success(),
        "Go peer failed: stdout={remainder} stderr={error_output}"
    );
    assert!(remainder.contains("OK"), "Go peer output: {remainder}");
}

fn go_peer(
    mode: &str,
    address: Option<SocketAddr>,
    profile: NativePathProfile,
) -> std::process::Output {
    go_peer_command(mode, address, profile)
        .output()
        .expect("run Go v3 raw QUIC peer")
}

fn go_peer_command(mode: &str, address: Option<SocketAddr>, profile: NativePathProfile) -> Command {
    let mut command = Command::new("go");
    command
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../flowersec-go"))
        .env("GOWORK", "off")
        .arg("run")
        .arg("./internal/cmd/rust-raw-quic-peer-v3")
        .arg(mode);
    if let Some(address) = address {
        command.arg(address.to_string());
    }
    command.arg(profile_name(profile));
    command
}

fn assert_go_output(output: std::process::Output) {
    assert!(
        output.status.success(),
        "Go peer failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("OK"));
}

fn profile_name(profile: NativePathProfile) -> &'static str {
    match profile {
        NativePathProfile::Direct => "direct",
        NativePathProfile::Tunnel => "tunnel",
    }
}

fn test_certificate() -> Vec<u8> {
    STANDARD.decode(TEST_CERT_DER_B64).unwrap()
}

fn test_private_key() -> Vec<u8> {
    STANDARD.decode(TEST_KEY_DER_B64).unwrap()
}

struct TestIdentity {
    certificate: Vec<u8>,
    private_key: Vec<u8>,
}

fn short_lived_identity() -> TestIdentity {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::hours(1);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let certificate = params.self_signed(&key).unwrap();
    TestIdentity {
        certificate: certificate.der().to_vec(),
        private_key: key.serialize_der(),
    }
}
