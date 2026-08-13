use std::{
    env,
    io::{self, Read},
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use flowersec::controlplane::{ControlPlaneError, RuntimeAuthorizationRequest};
use flowersec::{
    allow_tunnel_runtime, connect, Acceptor, AcceptorOptions, Artifact, ArtifactLease,
    ConnectorOptions, DirectIssueOptions, EndpointSet, IncomingStream, Issuer, NotificationHandler,
    RpcError, RpcHandler, Session, SessionError, SessionHandlerOptions, SessionHandlers,
    StreamHandler, StreamMetadata, TunnelAuthorizationResponse, TunnelAuthorizer,
    TunnelIssueOptions, TunnelRuntime, TunnelRuntimeOptions, UnreliableSendOutcome,
    WebSocketAcceptorOptions,
};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const ECHO_RPC: u32 = 7001;
const NOTIFY_RPC: u32 = 7002;
const COMPLETE_RPC: u32 = 7003;
const DATAGRAM_READY_RPC: u32 = 7005;

const TEST_CERT_DER_B64: &str = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";
const TEST_KEY_DER_B64: &str = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6";

#[derive(Deserialize)]
struct Ready {
    artifact_json: String,
    #[serde(default)]
    trust_roots_der: Vec<String>,
    #[serde(default)]
    trust_pem: Option<String>,
    origin: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RelayReady {
    #[serde(rename = "type")]
    message_type: String,
    runtime: String,
    carrier: String,
    path: String,
    endpoint_url: String,
    trust_pem: String,
    #[serde(default)]
    trust_roots_der: Vec<String>,
    server_certificate_der: String,
    origin: String,
}

#[derive(Clone, Debug, Deserialize)]
struct TunnelTopology {
    id: String,
    endpoint_a: String,
    endpoint_b: String,
    tunnel_runtime: String,
    ingress_carrier_a: String,
    ingress_carrier_b: String,
}

#[derive(Clone, Debug, Deserialize)]
struct TunnelEndpointBInput {
    topology: TunnelTopology,
    relay: RelayReady,
}

#[derive(Clone, Debug, Deserialize)]
struct TunnelEndpointAInput {
    topology: TunnelTopology,
    endpoint_b: TunnelEndpointBReady,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TunnelAuthorizationWire {
    decision: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
    #[serde(rename = "leaseId")]
    lease_id: String,
    #[serde(rename = "expiresAtUnixSeconds")]
    expires_at_unix_seconds: u64,
    #[serde(rename = "expectedPeerEndpointInstanceId")]
    expected_peer_endpoint_instance_id: String,
    #[serde(rename = "allowReplacement", default)]
    allow_replacement: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TunnelEndpointBReady {
    #[serde(rename = "type")]
    message_type: String,
    runtime: String,
    carrier: String,
    path: String,
    endpoint_a_artifact_json: String,
    endpoint_b_artifact_json: String,
    relay: RelayReady,
    authorizations: Vec<TunnelAuthorizationWire>,
}

#[derive(Clone, Debug)]
struct RelayDecision {
    lease_id: String,
    expires_at: SystemTime,
    expected_peer_endpoint_instance_id: String,
    allow_replacement: bool,
}

struct ParityTunnelAuthorizer {
    decisions: std::sync::Mutex<std::collections::HashMap<String, RelayDecision>>,
    released: Arc<AtomicUsize>,
    released_notify: Arc<Notify>,
}

#[async_trait]
impl TunnelAuthorizer for ParityTunnelAuthorizer {
    async fn authorize(
        &self,
        request: RuntimeAuthorizationRequest,
    ) -> Result<TunnelAuthorizationResponse, ControlPlaneError> {
        let decision = self
            .decisions
            .lock()
            .expect("relay decision lock poisoned")
            .get(request.lookup_key())
            .cloned()
            .ok_or(ControlPlaneError::InvalidInput)?;
        allow_tunnel_runtime(
            &request,
            &decision.lease_id,
            decision.expires_at,
            &decision.expected_peer_endpoint_instance_id,
            decision.allow_replacement,
        )
    }

    async fn release(&self, _lease_id: &str) {
        self.released.fetch_add(1, Ordering::SeqCst);
        self.released_notify.notify_waiters();
    }
}

#[derive(Clone, Default)]
struct ExecutionLedger {
    cases: Arc<Mutex<Vec<&'static str>>>,
}

impl ExecutionLedger {
    fn record(&self, case_ids: &[&'static str]) {
        let mut cases = self.cases.lock().expect("execution ledger lock poisoned");
        for case_id in case_ids {
            if !cases.contains(case_id) {
                cases.push(case_id);
            }
        }
    }

    fn snapshot(&self) -> Vec<&'static str> {
        self.cases
            .lock()
            .expect("execution ledger lock poisoned")
            .clone()
    }
}

#[derive(Serialize)]
struct ResultMessage<'a> {
    #[serde(rename = "type")]
    message_type: &'a str,
    runtime: &'a str,
    carrier: &'a str,
    path: &'a str,
    cases: Vec<&'a str>,
}

struct EchoRpc {
    executed: ExecutionLedger,
}

#[async_trait]
impl RpcHandler for EchoRpc {
    async fn call(
        &self,
        _type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        self.executed.record(&["rpc"]);
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        Ok(())
    }
}

struct BarrierRpc {
    value: &'static str,
    count: Arc<AtomicUsize>,
    executed: ExecutionLedger,
}

#[async_trait]
impl RpcHandler for BarrierRpc {
    async fn call(
        &self,
        _type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        if request != serde_json::json!({"value": self.value}) {
            return Err(RpcError::new(400, Some("invalid barrier payload".into())).unwrap());
        }
        self.count.fetch_add(1, Ordering::SeqCst);
        if self.value == "complete" {
            self.executed.record(&["rekey", "liveness"]);
        }
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        Ok(())
    }
}

struct NotifyHandler {
    count: Arc<AtomicUsize>,
    received: Arc<Notify>,
    executed: ExecutionLedger,
}

#[async_trait]
impl NotificationHandler for NotifyHandler {
    async fn handle_notification(
        &self,
        _type_id: u32,
        _request: serde_json::Value,
    ) -> Result<(), RpcError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.executed.record(&["notification"]);
        self.received.notify_one();
        Ok(())
    }
}

struct EchoStreamHandler {
    path: &'static str,
    executed: ExecutionLedger,
}

#[async_trait]
impl StreamHandler for EchoStreamHandler {
    async fn handle(
        &self,
        stream: &IncomingStream,
        _cancellation: CancellationToken,
    ) -> Result<(), SessionError> {
        assert_eq!(stream.metadata().values()["cell"], self.path);
        self.executed.record(&["stream-metadata"]);
        assert_eq!(
            stream.stream().read().await.unwrap(),
            Some(Bytes::from_static(b"hello"))
        );
        assert_eq!(stream.stream().read().await.unwrap(), None);
        stream
            .stream()
            .write(Bytes::from_static(b"world"))
            .await
            .unwrap();
        self.executed.record(&["stream-fin"]);
        Ok(())
    }
}

struct FailingResetStreamHandler {
    executed: ExecutionLedger,
}

#[async_trait]
impl StreamHandler for FailingResetStreamHandler {
    async fn handle(
        &self,
        stream: &IncomingStream,
        _cancellation: CancellationToken,
    ) -> Result<(), SessionError> {
        assert_eq!(
            stream.stream().read().await.unwrap(),
            Some(Bytes::from_static(b"reset"))
        );
        assert_eq!(stream.stream().read().await.unwrap(), None);
        self.executed.record(&["stream-reset"]);
        Err(SessionError::OperationFailed)
    }
}

fn handlers(
    notifications: Arc<AtomicUsize>,
    notification_received: Arc<Notify>,
    path: &'static str,
    executed: ExecutionLedger,
) -> SessionHandlers {
    let mut handlers = SessionHandlers::new(SessionHandlerOptions::default()).unwrap();
    handlers
        .handle_rpc(
            ECHO_RPC,
            EchoRpc {
                executed: executed.clone(),
            },
        )
        .unwrap();
    handlers
        .handle_rpc(
            COMPLETE_RPC,
            BarrierRpc {
                value: "complete",
                count: notifications.clone(),
                executed: executed.clone(),
            },
        )
        .unwrap();
    handlers
        .handle_rpc(
            DATAGRAM_READY_RPC,
            BarrierRpc {
                value: "datagram-ready",
                count: notifications.clone(),
                executed: executed.clone(),
            },
        )
        .unwrap();
    handlers
        .handle_notification(
            NOTIFY_RPC,
            NotifyHandler {
                count: notifications,
                received: notification_received,
                executed: executed.clone(),
            },
        )
        .unwrap();
    handlers
        .handle_stream(
            "parity.echo",
            EchoStreamHandler {
                path,
                executed: executed.clone(),
            },
        )
        .unwrap();
    handlers
        .handle_stream("parity.reset", FailingResetStreamHandler { executed })
        .unwrap();
    handlers
}

fn root_cert() -> Vec<u8> {
    STANDARD.decode(TEST_CERT_DER_B64).unwrap()
}

fn leaf_cert() -> Vec<u8> {
    STANDARD.decode(TEST_CERT_DER_B64).unwrap()
}

fn key() -> Vec<u8> {
    STANDARD.decode(TEST_KEY_DER_B64).unwrap()
}

fn cert_pem(value: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(value)
    )
}

fn issue(carrier: &str, address: SocketAddr) -> flowersec::IssuedArtifact {
    let endpoint = match carrier {
        "websocket" => format!("wss://127.0.0.1:{}", address.port()),
        "raw-quic" => format!("quic://127.0.0.1:{}", address.port()),
        _ => panic!("unsupported carrier"),
    };
    let mut session = flowersec::SessionOptions::new("rust-direct-parity");
    session.max_inbound_streams = 16;
    Issuer::new()
        .issue_direct(DirectIssueOptions {
            session,
            endpoints: EndpointSet::new([endpoint]).unwrap(),
            rendezvous_group_id: "rust-direct-parity-group".into(),
            listener_audience: "rust-direct-parity-listener".into(),
            upstream_address: "127.0.0.1:1".into(),
        })
        .unwrap()
}

fn print_result(message_type: &str, carrier: &str, executed: &ExecutionLedger) {
    println!(
        "{}",
        serde_json::to_string(&ResultMessage {
            message_type,
            runtime: "rust",
            carrier,
            path: "direct",
            cases: executed.snapshot(),
        })
        .unwrap()
    );
}

async fn rpc_and_notifications(
    session: &dyn Session,
    notifications: &Arc<AtomicUsize>,
    notification_received: &Arc<Notify>,
    executed: &ExecutionLedger,
) {
    let response = session
        .rpc()
        .call(ECHO_RPC, serde_json::json!({"value":"ping"}))
        .await
        .unwrap();
    assert_eq!(response, serde_json::json!({"value":"ping"}));
    executed.record(&["rpc"]);
    session
        .rpc()
        .notify(NOTIFY_RPC, serde_json::json!({"value":"notify"}))
        .await
        .unwrap();
    notification_received.notified().await;
    assert!(notifications.load(Ordering::SeqCst) > 0);
    executed.record(&["notification"]);
}

async fn server_streams(session: &dyn Session, path: &str, executed: &ExecutionLedger) {
    let incoming = session.accept_stream().await.unwrap();
    assert_eq!(incoming.kind(), "parity.echo");
    assert_eq!(incoming.metadata().values()["cell"], path);
    executed.record(&["stream-metadata"]);
    assert_eq!(
        incoming.stream().read().await.unwrap(),
        Some(Bytes::from_static(b"hello"))
    );
    assert_eq!(incoming.stream().read().await.unwrap(), None);
    incoming
        .stream()
        .write(Bytes::from_static(b"world"))
        .await
        .unwrap();
    incoming.stream().close_write().await.unwrap();
    executed.record(&["stream-fin"]);
    let reset = session.accept_stream().await.unwrap();
    assert_eq!(reset.kind(), "parity.reset");
    assert_eq!(
        reset.stream().read().await.unwrap(),
        Some(Bytes::from_static(b"reset"))
    );
    assert_eq!(reset.stream().read().await.unwrap(), None);
    reset.stream().reset().await.unwrap();
    let _ = reset.stream().close().await;
    executed.record(&["stream-reset"]);
}

async fn client_streams(session: &dyn Session, path: &str, executed: &ExecutionLedger) {
    let metadata = StreamMetadata::try_from(serde_json::json!({"cell":path})).unwrap();
    let stream = session.open_stream("parity.echo", metadata).await.unwrap();
    stream.write(Bytes::from_static(b"hello")).await.unwrap();
    stream.close_write().await.unwrap();
    assert_eq!(
        stream.read().await.unwrap(),
        Some(Bytes::from_static(b"world"))
    );
    assert_eq!(stream.read().await.unwrap(), None);
    executed.record(&["stream-metadata", "stream-fin"]);
    let reset = session
        .open_stream("parity.reset", StreamMetadata::empty())
        .await
        .unwrap();
    reset.write(Bytes::from_static(b"reset")).await.unwrap();
    reset.close_write().await.unwrap();
    assert!(reset.read().await.is_err());
    let _ = reset.close().await;
    executed.record(&["stream-reset"]);
}

async fn assert_cancellable_wait(session: &dyn Session) {
    let cancellation = CancellationToken::new();
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        trigger.cancel();
    });
    tokio::select! {
        _ = session.wait_termination() => panic!("termination completed before local cancellation"),
        _ = cancellation.cancelled() => {}
    }
}

async fn call_barrier(session: &dyn Session, type_id: u32, value: &'static str) {
    let response = session
        .rpc()
        .call(type_id, serde_json::json!({"value":value}))
        .await
        .unwrap();
    assert_eq!(response, serde_json::json!({"value":value}));
}

async fn server_datagram(session: &dyn Session, executed: &ExecutionLedger) {
    let channel = session.unreliable_messages().unwrap();
    assert_eq!(
        channel.receive().await.unwrap(),
        Bytes::from_static(&[1, 2, 3])
    );
    assert_eq!(
        channel
            .send(
                Bytes::from_static(&[3, 2, 1]),
                SystemTime::now() + Duration::from_secs(2),
            )
            .await
            .unwrap(),
        UnreliableSendOutcome::Accepted
    );
    executed.record(&["datagram"]);
}

async fn run_server(carrier: &str) {
    let origin = parity_origin();
    let notifications = Arc::new(AtomicUsize::new(0));
    let notification_received = Arc::new(Notify::new());
    let executed = ExecutionLedger::default();
    let root = root_cert();
    let leaf = leaf_cert();
    let acceptor = match carrier {
        "websocket" => Acceptor::bind_websocket(WebSocketAcceptorOptions {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            certificate_chain_der: vec![leaf.clone(), root.clone()],
            private_key_der: key(),
            allowed_origins: vec![origin.clone()],
            max_inbound_streams: 16,
            accept_timeout: Duration::from_secs(10),
        }),
        "raw-quic" => Acceptor::bind(AcceptorOptions {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            certificate_chain_der: vec![leaf.clone(), root.clone()],
            private_key_der: key(),
            max_inbound_streams: 16,
            accept_timeout: Duration::from_secs(10),
        }),
        _ => panic!("unsupported carrier"),
    }
    .unwrap();
    let address = acceptor.local_address().unwrap();
    let issued = issue(carrier, address);
    println!(
        "{}",
        serde_json::json!({
            "type":"ready", "runtime":"rust", "carrier":carrier, "path":"direct",
            "artifact_json":String::from_utf8(issued.artifact_json()).unwrap(),
            "trust_roots_der":[STANDARD.encode(&root)], "trust_pem":cert_pem(&root),
            "server_certificate_der":STANDARD.encode(&leaf), "origin":origin
        })
    );
    let artifact = Artifact::parse(issued.artifact_json()).unwrap();
    let accepted = acceptor
        .accept_with_handlers(
            &artifact,
            handlers(
                notifications.clone(),
                notification_received.clone(),
                "direct",
                executed.clone(),
            ),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let session = accepted.session();
    executed.record(&["admission"]);
    let (serve_result, ()) = tokio::join!(accepted.serve(CancellationToken::new()), async {
        assert_cancellable_wait(session).await;
        executed.record(&["cancel"]);
        if env::var("FLOWERSEC_PARITY_CLIENT_PROFILE").is_ok() {
            external_server(session, &executed).await;
        } else if carrier == "websocket" {
            rpc_and_notifications(session, &notifications, &notification_received, &executed).await;
        } else {
            tokio::join!(
                rpc_and_notifications(session, &notifications, &notification_received, &executed),
                server_datagram(session, &executed),
            );
        }
        session.wait_termination().await;
    });
    assert_eq!(serve_result.unwrap_err(), SessionError::Closed);
    executed.record(&["close", "cleanup"]);
    print_result("server-result", carrier, &executed);
}

async fn run_client(carrier: &str, ready: Ready) {
    let notifications = Arc::new(AtomicUsize::new(0));
    let notification_received = Arc::new(Notify::new());
    let executed = ExecutionLedger::default();
    let artifact = Artifact::parse(ready.artifact_json.as_bytes()).unwrap();
    let trust_roots = if ready.trust_roots_der.is_empty() {
        ready
            .trust_pem
            .as_deref()
            .into_iter()
            .flat_map(|pem| CertificateDer::pem_slice_iter(pem.as_bytes()))
            .filter_map(Result::ok)
            .map(|certificate| certificate.to_vec())
            .collect()
    } else {
        ready
            .trust_roots_der
            .iter()
            .map(|value| STANDARD.decode(value).unwrap())
            .collect()
    };
    let lease = ArtifactLease::new(artifact, || async { Ok(()) });
    let mut options = ConnectorOptions::new(trust_roots)
        .unwrap()
        .with_handlers(handlers(
            notifications.clone(),
            notification_received.clone(),
            "direct",
            executed.clone(),
        ));
    if carrier == "websocket" {
        options = options.with_websocket_origin(ready.origin).unwrap();
    }
    let session = connect(lease, options).await.unwrap();
    executed.record(&["admission"]);
    assert_cancellable_wait(session.as_ref()).await;
    executed.record(&["cancel"]);
    if env::var("FLOWERSEC_PARITY_CLIENT_PROFILE").is_ok() {
        external_server(session.as_ref(), &executed).await;
    } else {
        tokio::join!(
            rpc_and_notifications(
                session.as_ref(),
                &notifications,
                &notification_received,
                &executed
            ),
            client_streams(session.as_ref(), "direct", &executed)
        );
    }
    call_barrier(session.as_ref(), DATAGRAM_READY_RPC, "datagram-ready").await;
    if carrier != "websocket" {
        let channel = session.unreliable_messages().unwrap();
        assert_eq!(
            channel
                .send(
                    Bytes::from_static(&[1, 2, 3]),
                    SystemTime::now() + Duration::from_secs(2)
                )
                .await
                .unwrap(),
            UnreliableSendOutcome::Accepted
        );
        assert_eq!(
            channel.receive().await.unwrap(),
            Bytes::from_static(&[3, 2, 1])
        );
        executed.record(&["datagram"]);
    }
    session.rekey().await.unwrap();
    executed.record(&["rekey"]);
    session.probe_liveness().await.unwrap();
    executed.record(&["liveness"]);
    call_barrier(session.as_ref(), COMPLETE_RPC, "complete").await;
    session
        .rpc()
        .notify(NOTIFY_RPC, serde_json::json!({"value":"notify"}))
        .await
        .unwrap();
    if let Err(error) = session.close().await {
        assert_eq!(error, SessionError::Closed);
    }
    executed.record(&["close", "cleanup"]);
    print_result("client-result", carrier, &executed);
}

async fn external_server(session: &dyn Session, executed: &ExecutionLedger) {
    let _ = session.wait_termination().await;
    executed.record(&["close"]);
}

fn relay_endpoint(carrier: &str, address: SocketAddr) -> String {
    match carrier {
        "websocket" => format!("wss://localhost:{}/flowersec/v2/tunnel", address.port()),
        "raw-quic" => format!("quic://127.0.0.1:{}", address.port()),
        _ => panic!("unsupported carrier"),
    }
}

fn tunnel_runtime_options(_carrier: &str, origin: &str) -> TunnelRuntimeOptions {
    TunnelRuntimeOptions {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        certificate_chain_der: vec![leaf_cert(), root_cert()],
        private_key_der: key(),
        allowed_origins: vec![origin.to_owned()],
        max_inbound_streams: 16,
        pair_timeout: Duration::from_secs(10),
        max_pending_legs: 16,
        max_active_pairs: 8,
    }
}

fn bind_tunnel_runtime(
    carrier: &str,
    authorizer: Arc<dyn TunnelAuthorizer>,
    origin: &str,
) -> TunnelRuntime {
    let options = tunnel_runtime_options(carrier, origin);
    match carrier {
        "websocket" => TunnelRuntime::bind_websocket(options, authorizer),
        "raw-quic" => TunnelRuntime::bind_raw_quic(options, authorizer),
        _ => panic!("unsupported carrier"),
    }
    .unwrap()
}

fn tunnel_relay_ready(carrier: &str, address: SocketAddr, origin: &str) -> RelayReady {
    RelayReady {
        message_type: "relay-ready".into(),
        runtime: "rust".into(),
        carrier: carrier.into(),
        path: "tunnel".into(),
        endpoint_url: relay_endpoint(carrier, address),
        trust_pem: cert_pem(&root_cert()),
        trust_roots_der: vec![STANDARD.encode(root_cert())],
        server_certificate_der: STANDARD.encode(leaf_cert()),
        origin: origin.into(),
    }
}

async fn run_tunnel_relay(carrier: &str) {
    let origin = parity_origin();
    let released = Arc::new(AtomicUsize::new(0));
    let executed = ExecutionLedger::default();
    let authorizer = Arc::new(ParityTunnelAuthorizer {
        decisions: std::sync::Mutex::new(std::collections::HashMap::new()),
        released: released.clone(),
        released_notify: Arc::new(Notify::new()),
    });
    let runtime = Arc::new(bind_tunnel_runtime(carrier, authorizer.clone(), &origin));
    let address = runtime.local_address().unwrap();
    println!(
        "{}",
        serde_json::to_string(&tunnel_relay_ready(carrier, address, &origin)).unwrap()
    );

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let configure: Value = serde_json::from_str(input.trim()).unwrap();
    if configure.get("type").and_then(Value::as_str) != Some("configure") {
        panic!("relay did not receive configure command");
    }
    let authorizations = configure
        .get("authorizations")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("relay did not receive authorizations"));
    {
        let mut decisions = authorizer.decisions.lock().unwrap();
        for value in authorizations {
            let wire: TunnelAuthorizationWire = serde_json::from_value(value.clone()).unwrap();
            if wire.decision != "allow"
                || wire.credential_id.is_empty()
                || wire.lease_id.is_empty()
                || wire.expected_peer_endpoint_instance_id.is_empty()
            {
                panic!("invalid secret-free tunnel authorization");
            }
            decisions.insert(
                wire.credential_id,
                RelayDecision {
                    lease_id: wire.lease_id,
                    expires_at: UNIX_EPOCH + Duration::from_secs(wire.expires_at_unix_seconds),
                    expected_peer_endpoint_instance_id: wire.expected_peer_endpoint_instance_id,
                    allow_replacement: wire.allow_replacement,
                },
            );
        }
    }

    let cancellation = CancellationToken::new();
    let serving = {
        let runtime = runtime.clone();
        let cancellation = cancellation.clone();
        tokio::spawn(async move { runtime.serve(cancellation).await })
    };
    input.clear();
    io::stdin().read_line(&mut input).unwrap();
    if serde_json::from_str::<Value>(input.trim())
        .ok()
        .and_then(|value| value.get("type").and_then(Value::as_str).map(str::to_owned))
        .as_deref()
        != Some("close")
    {
        panic!("relay did not receive close command");
    }
    executed.record(&["close", "cancel"]);
    cancellation.cancel();
    runtime.close().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), serving).await;
    let expected = authorizer.decisions.lock().unwrap().len();
    let release_wait = async {
        while released.load(Ordering::SeqCst) < expected {
            authorizer.released_notify.notified().await;
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), release_wait).await;
    if released.load(Ordering::SeqCst) != expected {
        panic!(
            "relay cleanup released {} of {} leases",
            released.load(Ordering::SeqCst),
            expected
        );
    }
    executed.record(&["admission", "pairing", "opaque-forwarding"]);
    if carrier != "websocket" {
        executed.record(&["datagram-forwarding"]);
    }
    executed.record(&["cleanup"]);
    println!(
        "{}",
        serde_json::json!({
            "type": "relay-result", "runtime": "rust", "carrier": carrier, "path": "tunnel",
            "cases": executed.snapshot(), "observed_plaintext": false,
            "released_leases": released.load(Ordering::SeqCst),
        })
    );
}

fn artifact_tunnel_claims(artifact_json: &[u8]) -> (u64, String) {
    let value: Value = serde_json::from_slice(artifact_json).unwrap();
    let expiry = value["session"]["init_expire_at_unix_s"].as_u64().unwrap();
    let expected = value["path"]["expected_peer_endpoint_instance_id"]
        .as_str()
        .unwrap()
        .to_owned();
    (expiry, expected)
}

fn tunnel_authorization(
    issued: &flowersec::IssuedArtifact,
    carrier: &str,
    lease_id: &str,
) -> TunnelAuthorizationWire {
    let artifact_json = issued.artifact_json();
    let (expiry, expected_peer) = artifact_tunnel_claims(&artifact_json);
    let wire_carrier = match carrier {
        "raw-quic" => "raw_quic",
        value => value,
    };
    let request = issued
        .runtime_authorization_request(wire_carrier, "127.0.0.1:1")
        .unwrap();
    let response = allow_tunnel_runtime(
        &request,
        lease_id,
        UNIX_EPOCH + Duration::from_secs(expiry),
        &expected_peer,
        false,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&response.json()).unwrap();
    TunnelAuthorizationWire {
        decision: value["decision"].as_str().unwrap().to_owned(),
        credential_id: value["credential_id"].as_str().unwrap().to_owned(),
        lease_id: value["lease_id"].as_str().unwrap().to_owned(),
        expires_at_unix_seconds: expiry,
        expected_peer_endpoint_instance_id: value["expected_peer_endpoint_instance_id"]
            .as_str()
            .unwrap()
            .to_owned(),
        allow_replacement: value["allow_replacement"].as_bool().unwrap_or(false),
    }
}

fn tunnel_connector_options(
    carrier: &str,
    relay: &RelayReady,
    handlers: SessionHandlers,
) -> ConnectorOptions {
    let roots = relay
        .trust_roots_der
        .iter()
        .map(|root| STANDARD.decode(root).unwrap())
        .collect();
    let mut options = ConnectorOptions::new(roots)
        .unwrap()
        .with_handlers(handlers);
    if carrier == "websocket" {
        options = options.with_websocket_origin(relay.origin.clone()).unwrap();
    }
    options
}

async fn connect_tunnel_artifact(
    carrier: &str,
    relay: &RelayReady,
    artifact_json: String,
    handlers: SessionHandlers,
) -> Arc<dyn Session> {
    let artifact = Artifact::parse(artifact_json.as_bytes()).unwrap();
    let lease = ArtifactLease::new(artifact, || async { Ok(()) });
    connect(lease, tunnel_connector_options(carrier, relay, handlers))
        .await
        .unwrap()
}

async fn run_tunnel_endpoint_b(carrier: &str) {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let envelope: TunnelEndpointBInput = serde_json::from_str(input.trim()).unwrap();
    if envelope.topology.endpoint_b != "rust"
        || envelope.topology.tunnel_runtime != envelope.relay.runtime
        || envelope.topology.ingress_carrier_a != carrier
        || envelope.topology.ingress_carrier_b != carrier
        || envelope.relay.carrier != carrier
        || envelope.relay.path != "tunnel"
    {
        panic!("invalid tunnel endpoint B input");
    }
    let mut session_options =
        flowersec::SessionOptions::new(format!("parity-{}", envelope.topology.id));
    session_options.max_inbound_streams = 16;
    session_options.expires_at = Some(SystemTime::now() + Duration::from_secs(60));
    let pair = Issuer::new()
        .issue_tunnel_pair(TunnelIssueOptions {
            session: session_options,
            endpoints: EndpointSet::new([envelope.relay.endpoint_url.clone()]).unwrap(),
            rendezvous_group_id: envelope.topology.id.clone(),
            listener_audience: "server-parity".into(),
            first_endpoint_id: format!("{}-a", envelope.topology.id),
            second_endpoint_id: format!("{}-b", envelope.topology.id),
            allow_replacement: false,
        })
        .unwrap();
    let first_json = String::from_utf8(pair.first().artifact_json()).unwrap();
    let second_json = String::from_utf8(pair.second().artifact_json()).unwrap();
    let authorizations = vec![
        tunnel_authorization(pair.first(), carrier, "lease-endpoint-a"),
        tunnel_authorization(pair.second(), carrier, "lease-endpoint-b"),
    ];
    let ready = TunnelEndpointBReady {
        message_type: "endpoint-b-ready".into(),
        runtime: "rust".into(),
        carrier: carrier.into(),
        path: "tunnel".into(),
        endpoint_a_artifact_json: first_json,
        endpoint_b_artifact_json: second_json.clone(),
        relay: envelope.relay.clone(),
        authorizations,
    };
    println!("{}", serde_json::to_string(&ready).unwrap());
    input.clear();
    io::stdin().read_line(&mut input).unwrap();
    if serde_json::from_str::<Value>(input.trim())
        .ok()
        .and_then(|value| value.get("type").and_then(Value::as_str).map(str::to_owned))
        .as_deref()
        != Some("connect")
    {
        panic!("endpoint B did not receive connect command");
    }
    let notifications = Arc::new(AtomicUsize::new(0));
    let notification_received = Arc::new(Notify::new());
    let executed = ExecutionLedger::default();
    let session = connect_tunnel_artifact(
        carrier,
        &envelope.relay,
        second_json,
        handlers(
            notifications.clone(),
            notification_received.clone(),
            "tunnel",
            executed.clone(),
        ),
    )
    .await;
    executed.record(&["admission"]);
    assert_cancellable_wait(session.as_ref()).await;
    executed.record(&["cancel"]);
    if env::var("FLOWERSEC_PARITY_CLIENT_PROFILE").is_ok() {
        external_server(session.as_ref(), &executed).await;
    } else if carrier == "websocket" {
        tokio::join!(
            rpc_and_notifications(
                session.as_ref(),
                &notifications,
                &notification_received,
                &executed
            ),
            server_streams(session.as_ref(), "tunnel", &executed),
        );
    } else {
        tokio::join!(
            rpc_and_notifications(
                session.as_ref(),
                &notifications,
                &notification_received,
                &executed
            ),
            server_streams(session.as_ref(), "tunnel", &executed),
            server_datagram(session.as_ref(), &executed),
        );
    }
    session.wait_termination().await;
    executed.record(&["close", "cleanup"]);
    println!(
        "{}",
        serde_json::json!({"type":"endpoint-b-result","runtime":"rust","carrier":carrier,"path":"tunnel","cases":executed.snapshot()})
    );
}

fn parity_origin() -> String {
    env::var("FLOWERSEC_PARITY_ORIGIN").unwrap_or_else(|_| "https://native-client.test".into())
}

async fn run_tunnel_endpoint_a(carrier: &str) {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let envelope: TunnelEndpointAInput =
        serde_json::from_str(input.lines().next().unwrap()).unwrap();
    let ready = &envelope.endpoint_b;
    if envelope.topology.endpoint_a != "rust"
        || envelope.topology.tunnel_runtime != ready.relay.runtime
        || envelope.topology.ingress_carrier_a != carrier
        || envelope.topology.ingress_carrier_b != carrier
        || ready.carrier != carrier
        || ready.path != "tunnel"
    {
        panic!("invalid tunnel endpoint A input");
    }
    let notifications = Arc::new(AtomicUsize::new(0));
    let notification_received = Arc::new(Notify::new());
    let executed = ExecutionLedger::default();
    let session = connect_tunnel_artifact(
        carrier,
        &ready.relay,
        ready.endpoint_a_artifact_json.clone(),
        handlers(
            notifications.clone(),
            notification_received.clone(),
            "tunnel",
            executed.clone(),
        ),
    )
    .await;
    executed.record(&["admission"]);
    assert_cancellable_wait(session.as_ref()).await;
    executed.record(&["cancel"]);
    tokio::join!(
        rpc_and_notifications(
            session.as_ref(),
            &notifications,
            &notification_received,
            &executed
        ),
        client_streams(session.as_ref(), "tunnel", &executed),
    );
    call_barrier(session.as_ref(), DATAGRAM_READY_RPC, "datagram-ready").await;
    if carrier != "websocket" {
        let channel = session.unreliable_messages().unwrap();
        assert_eq!(
            channel
                .send(
                    Bytes::from_static(&[1, 2, 3]),
                    SystemTime::now() + Duration::from_secs(2)
                )
                .await
                .unwrap(),
            UnreliableSendOutcome::Accepted
        );
        assert_eq!(
            channel.receive().await.unwrap(),
            Bytes::from_static(&[3, 2, 1])
        );
        executed.record(&["datagram"]);
    }
    session.rekey().await.unwrap();
    executed.record(&["rekey"]);
    session.probe_liveness().await.unwrap();
    executed.record(&["liveness"]);
    call_barrier(session.as_ref(), COMPLETE_RPC, "complete").await;
    session
        .rpc()
        .notify(NOTIFY_RPC, serde_json::json!({"value":"notify"}))
        .await
        .unwrap();
    let _ = session.close().await;
    executed.record(&["close", "cleanup"]);
    println!(
        "{}",
        serde_json::json!({"type":"endpoint-a-result","runtime":"rust","carrier":carrier,"path":"tunnel","cases":executed.snapshot()})
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut args = env::args().skip(1);
    let role = args.next().expect("server or client");
    assert_eq!(args.next().as_deref(), Some("--carrier"));
    let carrier = args.next().expect("carrier");
    match role.as_str() {
        "server" => run_server(&carrier).await,
        "client" => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input).unwrap();
            let ready: Ready = serde_json::from_str(input.lines().next().unwrap()).unwrap();
            run_client(&carrier, ready).await;
        }
        "relay" => run_tunnel_relay(&carrier).await,
        "tunnel-endpoint-a" => run_tunnel_endpoint_a(&carrier).await,
        "tunnel-endpoint-b" => run_tunnel_endpoint_b(&carrier).await,
        _ => panic!("invalid role"),
    }
}
