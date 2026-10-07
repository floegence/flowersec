#![allow(clippy::all)]
#![recursion_limit = "256"]

use flowersec::{
    AcceptedMaterialSource, ApplicationBinding, ApplicationLimits, ConnectError,
    ConnectionController, ConnectionControllerError, ConnectionControllerOptions,
    ConnectionMaterial, ConnectionMaterialSource, ConnectionRequest, ExecutionNotificationHandler,
    HandlerPlan, HandlerPlanOptions, IdentityKeys, MaterialSourceError, MessageCodec, Metadata,
    MethodDefinition, Namespace, NotificationContext, RawStreamHandler, RawStreamRegistration,
    RelayHost, RelayHostOptions, SQLiteAdmissionAuthority, SQLiteRelayLedger, ServeError,
    ServeFailure, ServeHandle, ServiceClient, ServiceError, ServicePlan, Session, SessionError,
    SessionTermination, Stream, StreamAuthorization, StreamDispatch, TransportEnvironment,
    TypedUnaryValue, UnaryPrepareOptions, UnaryRequestContext, UnaryResponse, UnaryServiceHandler,
    UnaryServiceRegistration, WssServeOptions, WssServerIdentity, connect,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

static CARGO_PROBE_LOCK: Mutex<()> = Mutex::new(());

fn cargo_probe_target() -> PathBuf {
    // Keep probe inputs disposable while reusing dependency compilation. The
    // running test's profile separates ordinary and instrumented build caches,
    // and this nested target never contends with the parent Cargo target lock.
    std::env::current_exe()
        .expect("locate public API test executable")
        .parent()
        .and_then(Path::parent)
        .expect("locate public API test profile")
        .join("public-api-probes")
}

struct RpcWithoutDebug;
struct NotificationWithoutDebug;
struct StreamWithoutDebug;

struct OpaqueApplication<T>(T);
impl<T> fmt::Debug for OpaqueApplication<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationHandler { <opaque> }")
    }
}
#[async_trait::async_trait]
impl UnaryServiceHandler for OpaqueApplication<RpcWithoutDebug> {
    async fn authorize(&self, _context: UnaryRequestContext) -> Result<(), ServiceError> {
        Ok(())
    }
    async fn handle(
        &self,
        _context: UnaryRequestContext,
        request: &[u8],
    ) -> Result<UnaryResponse, ServiceError> {
        Ok(UnaryResponse {
            payload: request.to_vec(),
            application_error_code: None,
        })
    }
}
#[async_trait::async_trait]
impl ExecutionNotificationHandler for OpaqueApplication<NotificationWithoutDebug> {
    fn application_bytes(&self) -> u64 {
        4096
    }
    async fn authorize(&self, _context: NotificationContext) -> Result<(), ServiceError> {
        Ok(())
    }
    async fn handle(
        &self,
        _payload: &[u8],
        _context: NotificationContext,
    ) -> Result<(), ServiceError> {
        Ok(())
    }
}
#[async_trait::async_trait]
impl RawStreamHandler for OpaqueApplication<StreamWithoutDebug> {
    async fn authorize(
        &self,
        _binding: ApplicationBinding,
        _metadata: Metadata,
        _cancellation: CancellationToken,
    ) -> Result<StreamAuthorization, ServeError> {
        Ok(StreamAuthorization::Accept {
            receive_window: 65536,
        })
    }
    async fn handle(
        &self,
        _stream: Stream,
        _metadata: Metadata,
        _cancellation: CancellationToken,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

#[derive(Serialize)]
struct TypedRequest {
    value: String,
}
#[derive(Deserialize)]
struct TypedResponse {
    accepted: bool,
}

async fn compile_current_public_api(
    environment: &TransportEnvironment,
    source: &ConnectionMaterialSource,
) {
    let session: Result<Session, ConnectError> = connect(
        environment,
        source,
        ConnectionRequest::default(),
        CancellationToken::new(),
    )
    .await;
    if let Ok(session) = session {
        session.close();
        let _ = session.wait_cleanup().await;
    }
}
async fn compile_advanced_handoff(
    environment: &TransportEnvironment,
    material: ConnectionMaterial,
    handlers: HandlerPlan,
    limits: ApplicationLimits,
) {
    let _ = environment
        .connect_material_with_handlers(
            material,
            Some((handlers, limits)),
            CancellationToken::new(),
        )
        .await;
}
async fn compile_typed_rpc(
    client: &ServiceClient,
    method: &MethodDefinition,
    request_codec: Arc<dyn MessageCodec<TypedRequest>>,
    response_codec: Arc<dyn MessageCodec<TypedResponse>>,
    options: UnaryPrepareOptions,
) {
    if let Ok(operation) = client.prepare_unary(
        method,
        &TypedRequest {
            value: "request".into(),
        },
        request_codec,
        response_codec,
        options,
    ) {
        if operation.start().is_ok() {
            if let Ok(result) = operation.wait_typed(CancellationToken::new()).await {
                if let TypedUnaryValue::Response(response) = result.value {
                    let _ = response.accepted;
                }
            }
        }
        operation.close();
        let _ = operation.wait_cleanup().await;
    }
}

#[test]
fn exposes_captured_connection_options_and_typed_rpc() {
    let _ = compile_current_public_api;
    let _ = compile_advanced_handoff;
    let _ = compile_typed_rpc;
}

#[test]
fn exposes_production_direct_listeners_for_each_carrier() {
    async fn compile_listener(
        environment: &TransportEnvironment,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        source: Arc<dyn AcceptedMaterialSource>,
        admission: Arc<SQLiteAdmissionAuthority>,
        identity: WssServerIdentity,
        options: WssServeOptions,
    ) -> Result<ServeHandle, ServeError> {
        environment
            .serve_wss(namespaces, keys, source, admission, identity, options)
            .await
    }
    async fn compile_raw_quic_listener(
        environment: &TransportEnvironment,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        source: Arc<dyn AcceptedMaterialSource>,
        admission: Arc<SQLiteAdmissionAuthority>,
        identity: WssServerIdentity,
        options: WssServeOptions,
    ) -> Result<ServeHandle, ServeError> {
        environment
            .serve_raw_quic(namespaces, keys, source, admission, identity, options)
            .await
    }
    async fn compile_webtransport_listener(
        environment: &TransportEnvironment,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        source: Arc<dyn AcceptedMaterialSource>,
        admission: Arc<SQLiteAdmissionAuthority>,
        identity: WssServerIdentity,
        options: WssServeOptions,
    ) -> Result<ServeHandle, ServeError> {
        environment
            .serve_webtransport(namespaces, keys, source, admission, identity, options)
            .await
    }
    let _ = compile_listener;
    let _ = compile_raw_quic_listener;
    let _ = compile_webtransport_listener;
}

#[test]
fn exposes_an_independent_opaque_tunnel_relay() {
    fn compile_relay(
        environment: &TransportEnvironment,
        keys: IdentityKeys,
        ledger: Arc<SQLiteRelayLedger>,
        options: RelayHostOptions,
    ) -> Result<RelayHost, flowersec::TransportConnectError> {
        environment.wss_relay_host(keys, ledger, options)
    }
    fn compile_prebound_relay(
        environment: &TransportEnvironment,
        keys: IdentityKeys,
        ledger: Arc<SQLiteRelayLedger>,
        options: RelayHostOptions,
        socket: std::net::UdpSocket,
    ) -> Result<RelayHost, flowersec::TransportConnectError> {
        environment.wss_relay_host_on_udp_socket(socket, keys, ledger, options)
    }
    let _ = compile_relay;
    let _ = compile_prebound_relay;
}

#[test]
fn application_handlers_can_keep_user_state_opaque() {
    let stream: Arc<dyn RawStreamHandler> = Arc::new(OpaqueApplication(StreamWithoutDebug));
    let rpc: Arc<dyn UnaryServiceHandler> = Arc::new(OpaqueApplication(RpcWithoutDebug));
    let notification: Arc<dyn ExecutionNotificationHandler> =
        Arc::new(OpaqueApplication(NotificationWithoutDebug));
    assert_eq!(format!("{stream:?}"), "ApplicationHandler { <opaque> }");
    assert_eq!(format!("{rpc:?}"), "ApplicationHandler { <opaque> }");
    assert_eq!(
        format!("{notification:?}"),
        "ApplicationHandler { <opaque> }"
    );
    fn compile_frozen_dispatch(
        environment: &TransportEnvironment,
        mut services: ServicePlan,
        mut unary: UnaryServiceRegistration,
    ) -> Result<HandlerPlan, ServeError> {
        unary.handler = Arc::new(OpaqueApplication(RpcWithoutDebug));
        services.unary.push(unary);
        environment
            .handler_plan(HandlerPlanOptions {
                streams: StreamDispatch::Registered(vec![RawStreamRegistration {
                    kind: "application.stream".into(),
                    metadata: None,
                    handler: Arc::new(OpaqueApplication(StreamWithoutDebug)),
                }]),
                application_bytes: 65536,
            })?
            .with_services(services)
    }
    let _ = compile_frozen_dispatch;
}

#[test]
fn current_controller_accepts_captured_material_sources() {
    fn compile_controller(
        environment: Arc<TransportEnvironment>,
        options: ConnectionControllerOptions,
    ) -> Result<ConnectionController, ConnectionControllerError> {
        ConnectionController::new(environment, options)
    }
    let _ = compile_controller;
}

#[test]
fn public_errors_keep_source_and_session_failures_distinct() {
    let error = ConnectError::Source(MaterialSourceError::RequiredGuaranteeUnavailable);
    assert!(matches!(
        error,
        ConnectError::Source(MaterialSourceError::RequiredGuaranteeUnavailable)
    ));
    assert_eq!(SessionError::Timeout.as_str(), "timeout");
    assert_eq!(SessionError::GoingAway.as_str(), "going_away");
    assert_eq!(SessionError::StreamRejected.as_str(), "stream_rejected");
    assert_eq!(
        ServeError::new(ServeFailure::Configuration).code,
        ServeFailure::Configuration
    );
}

#[test]
fn stream_metadata_is_validated_before_opening_a_stream() {
    let values = BTreeMap::from([("purpose".to_owned(), bytes::Bytes::from_static(b"health"))]);
    let metadata = Metadata::new("application/metadata", 1, &values).expect("valid metadata");
    assert_eq!(metadata.namespace(), Some("application/metadata"));
    assert_eq!(metadata.version(), Some(1));
    assert_eq!(metadata.byte_values()["purpose"], values["purpose"]);
    assert!(Metadata::new("invalid namespace", 1, &values).is_err());
    assert_eq!(Metadata::empty().namespace(), None);
}

#[test]
fn connection_material_does_not_expose_its_artifact() {
    let _probe_guard = CARGO_PROBE_LOCK.lock().expect("cargo probe lock");
    let fixture = tempfile::tempdir().expect("create lease API probe directory");
    let crate_path = env!("CARGO_MANIFEST_DIR").replace('\\', "\\\\");
    fs::write(
        fixture.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"flowersec-lease-opacity-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nflowersec = {{ path = \"{crate_path}\" }}\n"
        ),
    )
    .expect("write lease API probe manifest");
    fs::create_dir(fixture.path().join("src")).expect("create lease API probe source directory");
    fs::write(
        fixture.path().join("src/main.rs"),
        "use flowersec::ConnectionMaterial;\n\nfn inspect(material: &ConnectionMaterial) { let _ = material.artifact(); }\nfn main() {}\n",
    )
    .expect("write lease API probe source");

    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline", "--quiet"])
        .current_dir(fixture.path())
        .env("CARGO_TARGET_DIR", cargo_probe_target())
        .output()
        .expect("run lease API probe");
    assert!(
        !output.status.success(),
        "ConnectionMaterial unexpectedly exposes its artifact"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("artifact"),
        "material opacity probe failed for an unrelated reason:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn rustdoc_uses_real_unversioned_portable_types() {
    let _probe_guard = CARGO_PROBE_LOCK.lock().expect("cargo probe lock");
    let target = cargo_probe_target();
    let documentation = target.join("doc/flowersec");
    if documentation.exists() {
        fs::remove_dir_all(&documentation).expect("remove previous public rustdoc pages");
    }
    let output = Command::new(env!("CARGO"))
        .args(["doc", "--no-deps", "--quiet", "--target-dir"])
        .arg(&target)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("generate public rustdoc");
    assert!(
        output.status.success(),
        "cargo doc failed:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let mut pages = Vec::new();
    collect_html(&documentation, &mut pages);
    assert!(!pages.is_empty(), "cargo doc produced no Flowersec pages");
    for page in pages {
        if matches!(
            page.file_name().and_then(|name| name.to_str()),
            Some("index.html" | "all.html" | "sidebar-items.js")
        ) {
            continue;
        }
        let source = fs::read_to_string(&page).expect("read rustdoc page");
        for name in [
            "struct.Artifact.html",
            "struct.ArtifactLease.html",
            "struct.Acceptor.html",
            "struct.ConnectorOptions.html",
            "V3ConnectionController",
            "connect_v3",
            "SessionV2",
            "ByteStreamV2",
            "IncomingStreamV2",
            "RpcPeerV2",
            "UnreliableMessageChannelV2",
            "JsonObjectV2",
        ] {
            assert!(
                !source.contains(name),
                "public rustdoc {} leaked {name}",
                page.display(),
            );
        }
    }
}

fn collect_html(directory: &Path, pages: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(directory).expect("read rustdoc directory") {
        let path = entry.expect("read rustdoc entry").path();
        if path.is_dir() {
            collect_html(&path, pages);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "html")
        {
            pages.push(path);
        }
    }
}

#[test]
fn session_termination_is_a_stable_value() {
    let termination = SessionTermination {
        error: SessionError::Closed,
    };
    assert_eq!(termination.error, SessionError::Closed);
}

#[test]
fn session_error_names_cover_portable_session_states() {
    assert_eq!(SessionError::GoingAway.as_str(), "going_away");
    assert_eq!(SessionError::StreamRejected.as_str(), "stream_rejected");
    assert_eq!(SessionError::StreamReset.as_str(), "stream_reset");
    assert_eq!(SessionError::RekeyFailed.as_str(), "rekey_failed");
    assert_eq!(SessionError::LivenessFailed.as_str(), "liveness_failed");
}

#[test]
fn default_public_api_does_not_expose_fuzzing() {
    let _probe_guard = CARGO_PROBE_LOCK.lock().expect("cargo probe lock");
    let fixture = tempfile::tempdir().expect("create default API probe directory");
    let crate_path = env!("CARGO_MANIFEST_DIR").replace('\\', "\\\\");
    fs::write(
        fixture.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"flowersec-default-api-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nflowersec = {{ path = \"{crate_path}\" }}\n"
        ),
    )
    .expect("write default API probe manifest");
    fs::create_dir(fixture.path().join("src")).expect("create default API probe source directory");
    fs::write(
        fixture.path().join("src/main.rs"),
        "use flowersec::fuzzing;\n\nfn main() { let _ = fuzzing::parse_protocol; }\n",
    )
    .expect("write default API probe source");

    let output = Command::new("cargo")
        .args(["check", "--offline", "--quiet"])
        .current_dir(fixture.path())
        .env("CARGO_TARGET_DIR", cargo_probe_target())
        .output()
        .expect("run default API probe");

    assert!(
        !output.status.success(),
        "default crate unexpectedly exposes fuzzing:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fuzzing"),
        "default API probe failed for an unrelated reason:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}
