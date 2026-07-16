use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time::Duration};
use url::Url;

use crate::{
    ConnectArtifact, ErrorCode, FlowersecError, Path, ScopeMetadataEntry, Stage,
    e2ee::{ClientHandshakeOptions, Secret32, Suite, client_handshake},
    generated::flowersec::{
        controlplane::v1::{ChannelInitGrant, Role as ControlRole, Suite as ControlSuite},
        direct::v1::{DirectConnectInfo, Suite as DirectSuite},
        tunnel::v1::{Attach, Role as TunnelRole},
    },
    observability::{DiagnosticCodeDomain, DiagnosticEvent, DiagnosticResult, SharedObserver},
    rpc::RpcClient,
    streamhello,
    transport::{WebSocketMessage, WebSocketMessageKind, WebSocketTransport, connect_native},
    transport_security::TransportSecurityPolicy,
    yamux::{Mode, YamuxLimits, YamuxSession, YamuxStream},
};

type ScopeFuture = Pin<Box<dyn Future<Output = Result<(), FlowersecError>> + Send>>;
pub type ScopeResolver = Arc<dyn Fn(ScopeMetadataEntry) -> ScopeFuture + Send + Sync>;

#[derive(Clone)]
pub struct ConnectOptions {
    pub origin: Option<String>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub transport_security_policy: TransportSecurityPolicy,
    pub outbound_record_chunk_bytes: usize,
    pub max_outbound_buffered_bytes: usize,
    pub yamux_limits: YamuxLimits,
    pub scope_resolvers: HashMap<String, ScopeResolver>,
    pub relaxed_optional_scope_validation: bool,
    pub observer: Option<SharedObserver>,
    pub attempt_seq: u64,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
}

impl std::fmt::Debug for ConnectOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectOptions")
            .field("origin", &self.origin)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("transport_security_policy", &self.transport_security_policy)
            .field(
                "outbound_record_chunk_bytes",
                &self.outbound_record_chunk_bytes,
            )
            .field(
                "max_outbound_buffered_bytes",
                &self.max_outbound_buffered_bytes,
            )
            .field("yamux_limits", &self.yamux_limits)
            .field("scope_resolvers", &self.scope_resolvers.keys())
            .field(
                "relaxed_optional_scope_validation",
                &self.relaxed_optional_scope_validation,
            )
            .field("observer", &self.observer.as_ref().map(|_| "configured"))
            .field("attempt_seq", &self.attempt_seq)
            .field("trace_id", &self.trace_id)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            origin: None,
            connect_timeout: crate::defaults::CONNECT_TIMEOUT,
            handshake_timeout: crate::defaults::HANDSHAKE_TIMEOUT,
            transport_security_policy: TransportSecurityPolicy::default(),
            outbound_record_chunk_bytes: crate::defaults::OUTBOUND_RECORD_CHUNK_BYTES,
            max_outbound_buffered_bytes: crate::defaults::MAX_OUTBOUND_BUFFERED_BYTES,
            yamux_limits: YamuxLimits::default(),
            scope_resolvers: HashMap::new(),
            relaxed_optional_scope_validation: false,
            observer: None,
            attempt_seq: 1,
            trace_id: None,
            session_id: None,
        }
    }
}

#[derive(Debug)]
pub struct Client {
    path: Path,
    secure: Arc<dyn crate::e2ee::SecureChannelControl>,
    session: YamuxSession,
    rpc: RpcClient,
}

impl Client {
    pub fn path(&self) -> Path {
        self.path
    }

    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    pub async fn open_stream(&self, kind: &str) -> Result<YamuxStream, FlowersecError> {
        let stream = self.session.open_stream().await.map_err(|error| {
            let code = yamux_session_code(&error, ErrorCode::OPEN_STREAM_FAILED);
            FlowersecError::new(self.path, Stage::Yamux, code, "failed to open stream")
                .with_source(error)
        })?;
        if let Err(error) = streamhello::write(&stream, kind).await {
            let code = match self.session.terminal_error().await {
                Some(terminal) => yamux_session_code(&terminal, ErrorCode::STREAM_HELLO_FAILED),
                None => match &error {
                    crate::streamio::StreamIoError::Yamux(yamux) => {
                        yamux_session_code(yamux, ErrorCode::STREAM_HELLO_FAILED)
                    }
                    _ => ErrorCode::STREAM_HELLO_FAILED,
                },
            };
            return Err(FlowersecError::new(
                self.path,
                Stage::Rpc,
                code,
                "failed to write stream hello",
            )
            .with_source(error));
        }
        Ok(stream)
    }

    pub async fn accept_stream(&self) -> Result<(String, YamuxStream), FlowersecError> {
        let stream = self.session.accept_stream().await.map_err(|error| {
            let code = yamux_session_code(&error, ErrorCode::ACCEPT_STREAM_FAILED);
            FlowersecError::new(self.path, Stage::Yamux, code, "failed to accept stream")
                .with_source(error)
        })?;
        let kind = match streamhello::read(&stream, crate::defaults::MAX_STREAM_HELLO_BYTES).await {
            Ok(kind) => kind,
            Err(error) => {
                let code = match self.session.terminal_error().await {
                    Some(terminal) => yamux_session_code(&terminal, ErrorCode::STREAM_HELLO_FAILED),
                    None => match &error {
                        crate::streamio::StreamIoError::Yamux(yamux) => {
                            yamux_session_code(yamux, ErrorCode::STREAM_HELLO_FAILED)
                        }
                        _ => ErrorCode::STREAM_HELLO_FAILED,
                    },
                };
                return Err(FlowersecError::new(
                    self.path,
                    Stage::Rpc,
                    code,
                    "failed to read stream hello",
                )
                .with_source(error));
            }
        };
        Ok((kind, stream))
    }

    pub async fn probe_liveness(&self, timeout: Duration) -> Result<Duration, FlowersecError> {
        self.session.probe_liveness(timeout).await.map_err(|error| {
            FlowersecError::new(
                self.path,
                Stage::Yamux,
                ErrorCode::PING_FAILED,
                "liveness probe failed",
            )
            .with_source(error)
        })
    }

    pub async fn rekey(&self) -> Result<(), FlowersecError> {
        self.secure.rekey_channel().await.map_err(|error| {
            FlowersecError::new(
                self.path,
                Stage::Secure,
                ErrorCode::REKEY_FAILED,
                "failed to rekey secure channel",
            )
            .with_source(error)
        })
    }

    pub async fn close(&self) -> Result<(), FlowersecError> {
        self.session.close().await.map_err(|error| {
            FlowersecError::new(
                self.path,
                Stage::Close,
                ErrorCode::NOT_CONNECTED,
                "failed to close session",
            )
            .with_source(error)
        })
    }

    pub async fn terminated(&self) {
        self.session.wait_closed().await;
    }
}

fn yamux_session_code(error: &crate::yamux::YamuxError, fallback: &'static str) -> &'static str {
    match error {
        crate::yamux::YamuxError::ResourceExhausted { .. } => ErrorCode::RESOURCE_EXHAUSTED,
        crate::yamux::YamuxError::Closed
        | crate::yamux::YamuxError::StreamClosed
        | crate::yamux::YamuxError::Reset
        | crate::yamux::YamuxError::Transport(_) => ErrorCode::NOT_CONNECTED,
        _ => fallback,
    }
}

pub async fn connect(
    artifact: ConnectArtifact,
    mut options: ConnectOptions,
) -> Result<Client, FlowersecError> {
    if let Some(correlation) = artifact.correlation() {
        if options.trace_id.is_none() {
            options.trace_id.clone_from(&correlation.trace_id);
        }
        if options.session_id.is_none() {
            options.session_id.clone_from(&correlation.session_id);
        }
    }
    validate_scopes(artifact.scoped(), &options).await?;
    match artifact {
        ConnectArtifact::Tunnel { grant, .. } => connect_tunnel(grant, options).await,
        ConnectArtifact::Direct { info, .. } => connect_direct(info, options).await,
    }
}

pub async fn connect_tunnel(
    grant: ChannelInitGrant,
    options: ConnectOptions,
) -> Result<Client, FlowersecError> {
    if grant.role != ControlRole::Client {
        return Err(validation_error(
            Path::Tunnel,
            ErrorCode::ROLE_MISMATCH,
            "client grant required",
        ));
    }
    let url = parse_url(&grant.tunnel_url, Path::Tunnel)?;
    let psk = decode_psk(&grant.e2ee_psk_b64u, Path::Tunnel)?;
    options
        .transport_security_policy
        .evaluate(&url, Path::Tunnel)
        .await?;
    let transport = dial(&url, Path::Tunnel, &options).await?;
    let mut endpoint_instance_id = [0_u8; 24];
    OsRng.fill_bytes(&mut endpoint_instance_id);
    let attach = Attach {
        v: 1,
        channel_id: grant.channel_id.clone(),
        role: TunnelRole::Client,
        token: grant.token.clone(),
        endpoint_instance_id: URL_SAFE_NO_PAD.encode(endpoint_instance_id),
        caps: None,
    };
    let attach_payload = serde_json::to_vec(&attach).map_err(|error| {
        FlowersecError::new(
            Path::Tunnel,
            Stage::Attach,
            ErrorCode::ATTACH_FAILED,
            "failed to encode tunnel attach",
        )
        .with_source(error)
    })?;
    transport
        .send(WebSocketMessage {
            kind: WebSocketMessageKind::Text,
            payload: attach_payload.into(),
        })
        .await
        .map_err(|error| connect_error(Path::Tunnel, Stage::Attach, error))?;
    establish_client(
        transport,
        Path::Tunnel,
        grant.channel_id,
        psk,
        suite_from_control(grant.default_suite),
        options,
    )
    .await
}

pub async fn connect_direct(
    info: DirectConnectInfo,
    options: ConnectOptions,
) -> Result<Client, FlowersecError> {
    let url = parse_url(&info.ws_url, Path::Direct)?;
    let psk = decode_psk(&info.e2ee_psk_b64u, Path::Direct)?;
    options
        .transport_security_policy
        .evaluate(&url, Path::Direct)
        .await?;
    let transport = dial(&url, Path::Direct, &options).await?;
    establish_client(
        transport,
        Path::Direct,
        info.channel_id,
        psk,
        suite_from_direct(info.default_suite),
        options,
    )
    .await
}

async fn establish_client<T: crate::transport::WebSocketTransport>(
    transport: Arc<T>,
    path: Path,
    channel_id: String,
    psk: Secret32,
    suite: Suite,
    options: ConnectOptions,
) -> Result<Client, FlowersecError> {
    let mut handshake = ClientHandshakeOptions::new(psk, suite, channel_id);
    handshake.outbound_record_chunk_bytes = options.outbound_record_chunk_bytes;
    handshake.max_outbound_buffered_bytes = options.max_outbound_buffered_bytes;
    let secure = tokio::time::timeout(
        options.handshake_timeout,
        client_handshake(transport, handshake),
    )
    .await
    .map_err(|_| {
        FlowersecError::new(
            path,
            Stage::Handshake,
            ErrorCode::TIMEOUT,
            "E2EE handshake timed out",
        )
    })?
    .map_err(|error| {
        FlowersecError::new(
            path,
            Stage::Handshake,
            ErrorCode::HANDSHAKE_FAILED,
            "E2EE handshake failed",
        )
        .with_source(error)
    })?;
    let secure = Arc::new(secure);
    let session =
        YamuxSession::new(secure.clone(), Mode::Client, options.yamux_limits).map_err(|error| {
            FlowersecError::new(
                path,
                Stage::Yamux,
                ErrorCode::OPEN_STREAM_FAILED,
                "Yamux setup failed",
            )
            .with_source(error)
        })?;
    let rpc_stream = session.open_stream().await.map_err(|error| {
        FlowersecError::new(
            path,
            Stage::Rpc,
            ErrorCode::RPC_FAILED,
            "failed to open RPC stream",
        )
        .with_source(error)
    })?;
    streamhello::write(&rpc_stream, streamhello::RPC_KIND)
        .await
        .map_err(|error| {
            FlowersecError::new(
                path,
                Stage::Rpc,
                ErrorCode::STREAM_HELLO_FAILED,
                "failed to initialize RPC stream",
            )
            .with_source(error)
        })?;
    emit(
        &options,
        path,
        Stage::Connect,
        "connect_ok",
        DiagnosticResult::Ok,
    );
    Ok(Client {
        path,
        secure,
        session,
        rpc: RpcClient::from_stream(rpc_stream),
    })
}

async fn dial(
    url: &Url,
    path: Path,
    options: &ConnectOptions,
) -> Result<Arc<crate::transport::NativeWebSocketTransport>, FlowersecError> {
    connect_native(url, options.origin.as_deref(), options.connect_timeout)
        .await
        .map_err(|error| connect_error(path, Stage::Connect, error))
}

async fn validate_scopes(
    scopes: &[ScopeMetadataEntry],
    options: &ConnectOptions,
) -> Result<(), FlowersecError> {
    for scope in scopes {
        let resolver = options.scope_resolvers.get(&scope.scope);
        match resolver {
            None if scope.critical => {
                return Err(FlowersecError::new(
                    Path::Auto,
                    Stage::Scope,
                    ErrorCode::RESOLVE_FAILED,
                    format!(
                        "missing resolver for {}@{}",
                        scope.scope, scope.scope_version
                    ),
                ));
            }
            None => emit(
                options,
                Path::Auto,
                Stage::Scope,
                "scope_ignored_missing_resolver",
                DiagnosticResult::Skip,
            ),
            Some(resolver) => {
                if let Err(error) = resolver(scope.clone()).await {
                    if scope.critical || !options.relaxed_optional_scope_validation {
                        return Err(FlowersecError::new(
                            Path::Auto,
                            Stage::Scope,
                            ErrorCode::RESOLVE_FAILED,
                            format!(
                                "scope validation failed for {}@{}",
                                scope.scope, scope.scope_version
                            ),
                        )
                        .with_source(error));
                    }
                    emit(
                        options,
                        Path::Auto,
                        Stage::Scope,
                        "scope_ignored_relaxed_validation",
                        DiagnosticResult::Skip,
                    );
                }
            }
        }
    }
    Ok(())
}

fn emit(options: &ConnectOptions, path: Path, stage: Stage, code: &str, result: DiagnosticResult) {
    if let Some(observer) = &options.observer {
        observer.on_diagnostic(&DiagnosticEvent {
            v: 1,
            namespace: "connect".to_owned(),
            path,
            stage,
            code_domain: DiagnosticCodeDomain::Event,
            code: code.to_owned(),
            result,
            elapsed_ms: 0.0,
            attempt_seq: options.attempt_seq.max(1),
            trace_id: options.trace_id.clone(),
            session_id: options.session_id.clone(),
            resource: None,
            current: None,
            limit: None,
        });
    }
}

fn parse_url(value: &str, path: Path) -> Result<Url, FlowersecError> {
    Url::parse(value).map_err(|error| {
        validation_error(path, ErrorCode::MISSING_WS_URL, "invalid WebSocket URL")
            .with_source(error)
    })
}

fn decode_psk(value: &str, path: Path) -> Result<Secret32, FlowersecError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        validation_error(path, ErrorCode::INVALID_PSK, "invalid E2EE PSK").with_source(error)
    })?;
    let psk = bytes
        .try_into()
        .map_err(|_| validation_error(path, ErrorCode::INVALID_PSK, "E2EE PSK must be 32 bytes"))?;
    Ok(Secret32::new(psk))
}

fn suite_from_control(suite: ControlSuite) -> Suite {
    match suite {
        ControlSuite::X25519HkdfSha256Aes256Gcm => Suite::X25519HkdfSha256Aes256Gcm,
        ControlSuite::P256HkdfSha256Aes256Gcm => Suite::P256HkdfSha256Aes256Gcm,
    }
}

fn suite_from_direct(suite: DirectSuite) -> Suite {
    match suite {
        DirectSuite::X25519HkdfSha256Aes256Gcm => Suite::X25519HkdfSha256Aes256Gcm,
        DirectSuite::P256HkdfSha256Aes256Gcm => Suite::P256HkdfSha256Aes256Gcm,
    }
}

fn validation_error(path: Path, code: &'static str, message: &str) -> FlowersecError {
    FlowersecError::new(path, Stage::Validate, code, message)
}

fn connect_error(path: Path, stage: Stage, error: std::io::Error) -> FlowersecError {
    let code = if error.kind() == std::io::ErrorKind::TimedOut {
        ErrorCode::TIMEOUT
    } else {
        ErrorCode::DIAL_FAILED
    };
    FlowersecError::new(path, stage, code, "WebSocket operation failed").with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    fn scope(name: &str, critical: bool) -> ScopeMetadataEntry {
        ScopeMetadataEntry {
            scope: name.to_owned(),
            scope_version: 1,
            critical,
            payload: Map::new(),
        }
    }

    fn resolver<F, Fut>(resolve: F) -> ScopeResolver
    where
        F: Fn(ScopeMetadataEntry) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), FlowersecError>> + Send + 'static,
    {
        Arc::new(move |scope| Box::pin(resolve(scope)))
    }

    #[tokio::test]
    async fn scope_validation_covers_required_optional_and_relaxed_paths() {
        let required = scope("required", true);
        let missing = validate_scopes(&[required.clone()], &ConnectOptions::default())
            .await
            .expect_err("critical scope requires a resolver");
        assert_eq!(missing.stage, Stage::Scope);
        assert_eq!(missing.code.as_str(), ErrorCode::RESOLVE_FAILED);

        let events = Arc::new(Mutex::new(Vec::new()));
        let mut options = ConnectOptions {
            observer: Some(Arc::new({
                let events = events.clone();
                move |event: &DiagnosticEvent| events.lock().unwrap().push(event.clone())
            })),
            attempt_seq: 0,
            trace_id: Some("trace-scope".to_owned()),
            session_id: Some("session-scope".to_owned()),
            ..ConnectOptions::default()
        };
        validate_scopes(&[scope("optional", false)], &options)
            .await
            .expect("optional missing resolver is ignored");
        assert_eq!(
            events.lock().unwrap()[0].code,
            "scope_ignored_missing_resolver"
        );
        assert_eq!(events.lock().unwrap()[0].attempt_seq, 1);

        let calls = Arc::new(AtomicUsize::new(0));
        options.scope_resolvers.insert(
            "required".to_owned(),
            resolver({
                let calls = calls.clone();
                move |resolved| {
                    assert_eq!(resolved.scope, "required");
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }
            }),
        );
        validate_scopes(&[required.clone()], &options)
            .await
            .expect("registered resolver succeeds");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let rejecting = resolver(|_| async {
            Err(FlowersecError::new(
                Path::Auto,
                Stage::Scope,
                ErrorCode::RESOLVE_FAILED,
                "rejected",
            ))
        });
        options
            .scope_resolvers
            .insert("required".to_owned(), rejecting.clone());
        let rejected = validate_scopes(&[required], &options)
            .await
            .expect_err("critical resolver failures are terminal");
        assert!(rejected.source.is_some());

        options
            .scope_resolvers
            .insert("optional".to_owned(), rejecting);
        let strict = validate_scopes(&[scope("optional", false)], &options)
            .await
            .expect_err("optional resolver failures are strict by default");
        assert_eq!(strict.code.as_str(), ErrorCode::RESOLVE_FAILED);
        options.relaxed_optional_scope_validation = true;
        validate_scopes(&[scope("optional", false)], &options)
            .await
            .expect("relaxed optional resolver failure is ignored");
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.code == "scope_ignored_relaxed_validation")
        );
    }

    #[tokio::test]
    async fn client_validation_rejects_role_url_policy_and_psk_errors() {
        let wrong_role = ChannelInitGrant {
            tunnel_url: "wss://example.test/tunnel".to_owned(),
            channel_id: "channel-test".to_owned(),
            channel_init_expire_at_unix_s: 1,
            idle_timeout_seconds: 60,
            role: ControlRole::Server,
            token: "token".to_owned(),
            e2ee_psk_b64u: URL_SAFE_NO_PAD.encode([0_u8; 32]),
            allowed_suites: vec![ControlSuite::X25519HkdfSha256Aes256Gcm],
            default_suite: ControlSuite::X25519HkdfSha256Aes256Gcm,
        };
        let role = connect_tunnel(wrong_role, ConnectOptions::default())
            .await
            .expect_err("client rejects a server grant");
        assert_eq!(role.code.as_str(), ErrorCode::ROLE_MISMATCH);

        let invalid_url = parse_url("not a URL", Path::Direct).expect_err("invalid URL");
        assert_eq!(invalid_url.code.as_str(), ErrorCode::MISSING_WS_URL);
        let denied = TransportSecurityPolicy::require_tls()
            .evaluate(&Url::parse("ws://example.test/ws").unwrap(), Path::Direct)
            .await
            .expect_err("remote plaintext denied");
        assert_eq!(denied.code.as_str(), ErrorCode::TRANSPORT_POLICY_DENIED);

        assert_eq!(
            decode_psk("%%%", Path::Direct)
                .expect_err("invalid base64")
                .code
                .as_str(),
            ErrorCode::INVALID_PSK
        );
        assert_eq!(
            decode_psk(&URL_SAFE_NO_PAD.encode([0_u8; 31]), Path::Tunnel)
                .expect_err("wrong PSK length")
                .code
                .as_str(),
            ErrorCode::INVALID_PSK
        );
        assert_eq!(
            format!(
                "{:?}",
                decode_psk(&URL_SAFE_NO_PAD.encode([0_u8; 32]), Path::Direct).unwrap()
            ),
            "Secret32([REDACTED])"
        );

        let direct = connect_direct(
            DirectConnectInfo {
                ws_url: "ws://127.0.0.1:9/direct".to_owned(),
                channel_id: "channel-test".to_owned(),
                e2ee_psk_b64u: "invalid".to_owned(),
                channel_init_expire_at_unix_s: 1,
                default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
            },
            ConnectOptions {
                transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..ConnectOptions::default()
            },
        )
        .await
        .expect_err("invalid direct PSK is rejected before dialing");
        assert_eq!(direct.code.as_str(), ErrorCode::INVALID_PSK);
    }

    #[test]
    fn client_helpers_preserve_suite_and_transport_error_contracts() {
        assert_eq!(
            suite_from_control(ControlSuite::X25519HkdfSha256Aes256Gcm),
            Suite::X25519HkdfSha256Aes256Gcm
        );
        assert_eq!(
            suite_from_control(ControlSuite::P256HkdfSha256Aes256Gcm),
            Suite::P256HkdfSha256Aes256Gcm
        );
        assert_eq!(
            suite_from_direct(DirectSuite::X25519HkdfSha256Aes256Gcm),
            Suite::X25519HkdfSha256Aes256Gcm
        );
        assert_eq!(
            suite_from_direct(DirectSuite::P256HkdfSha256Aes256Gcm),
            Suite::P256HkdfSha256Aes256Gcm
        );

        let timeout = connect_error(
            Path::Direct,
            Stage::Connect,
            std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"),
        );
        assert_eq!(timeout.code.as_str(), ErrorCode::TIMEOUT);
        let failed = connect_error(
            Path::Tunnel,
            Stage::Attach,
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        );
        assert_eq!(failed.code.as_str(), ErrorCode::DIAL_FAILED);
        assert!(failed.source.is_some());

        let options = ConnectOptions::default();
        let debug = format!("{options:?}");
        assert!(debug.contains("transport_security_policy"));
        assert!(debug.contains("scope_resolvers"));
    }
}
