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
    transport_security::{TransportSecurityPolicy, validate_websocket_url},
    yamux::{
        AutomaticLiveness, LivenessOptions, Mode, YamuxLimits, YamuxSession, YamuxStream,
        resolve_liveness,
    },
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
    pub liveness: LivenessOptions,
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
            .field("liveness", &self.liveness)
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
            liveness: LivenessOptions::default(),
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
        let kind = kind.trim();
        if kind.is_empty() {
            return Err(FlowersecError::new(
                self.path,
                Stage::Rpc,
                ErrorCode::MISSING_STREAM_KIND,
                "stream kind is empty",
            ));
        }
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
            let code = yamux_probe_code(&error);
            FlowersecError::new(self.path, Stage::Yamux, code, "liveness probe failed")
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

impl Drop for Client {
    fn drop(&mut self) {
        self.session.close_in_background();
    }
}

fn yamux_probe_code(error: &crate::yamux::YamuxError) -> &'static str {
    match error {
        crate::yamux::YamuxError::PingTimeout => ErrorCode::TIMEOUT,
        crate::yamux::YamuxError::ResourceExhausted { .. } => ErrorCode::RESOURCE_EXHAUSTED,
        _ => ErrorCode::PING_FAILED,
    }
}

fn yamux_session_code(error: &crate::yamux::YamuxError, fallback: &'static str) -> &'static str {
    match error {
        crate::yamux::YamuxError::ResourceExhausted { .. } => ErrorCode::RESOURCE_EXHAUSTED,
        crate::yamux::YamuxError::PingTimeout => ErrorCode::TIMEOUT,
        crate::yamux::YamuxError::Closed
        | crate::yamux::YamuxError::StreamClosed
        | crate::yamux::YamuxError::Reset
        | crate::yamux::YamuxError::Transport(_) => ErrorCode::NOT_CONNECTED,
        _ => fallback,
    }
}

pub async fn connect(
    mut artifact: ConnectArtifact,
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
    validate_artifact_transport(&mut artifact, &options)?;
    validate_scopes(artifact.scoped(), &options).await?;
    match artifact {
        ConnectArtifact::Tunnel { grant, .. } => connect_tunnel(grant, options).await,
        ConnectArtifact::Direct { info, .. } => connect_direct(info, options).await,
    }
}

fn validate_artifact_transport(
    artifact: &mut ConnectArtifact,
    options: &ConnectOptions,
) -> Result<(), FlowersecError> {
    match artifact {
        ConnectArtifact::Tunnel { grant, .. } => {
            validate_tunnel_grant(grant, ControlRole::Client)?;
            validate_client_runtime_options(
                Path::Tunnel,
                options,
                tunnel_idle_timeout(grant.idle_timeout_seconds),
            )?;
            validate_websocket_url(&grant.tunnel_url, Path::Tunnel)?;
            decode_psk(&grant.e2ee_psk_b64u, Path::Tunnel)?;
        }
        ConnectArtifact::Direct { info, .. } => {
            validate_direct_info(info)?;
            validate_client_runtime_options(Path::Direct, options, None)?;
            validate_websocket_url(&info.ws_url, Path::Direct)?;
            decode_psk(&info.e2ee_psk_b64u, Path::Direct)?;
        }
    }
    Ok(())
}

pub async fn connect_tunnel(
    mut grant: ChannelInitGrant,
    options: ConnectOptions,
) -> Result<Client, FlowersecError> {
    validate_tunnel_grant(&mut grant, ControlRole::Client)?;
    let liveness = validate_client_runtime_options(
        Path::Tunnel,
        &options,
        tunnel_idle_timeout(grant.idle_timeout_seconds),
    )?;
    let url = validate_websocket_url(&grant.tunnel_url, Path::Tunnel)?;
    let psk = decode_psk(&grant.e2ee_psk_b64u, Path::Tunnel)?;
    options
        .transport_security_policy
        .evaluate(&url, Path::Tunnel)
        .await?;
    if url.scheme() == "ws" {
        emit(
            &options,
            Path::Tunnel,
            Stage::Transport,
            "plaintext_transport",
            DiagnosticResult::Skip,
        );
    }
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
        liveness,
    )
    .await
}

pub async fn connect_direct(
    mut info: DirectConnectInfo,
    options: ConnectOptions,
) -> Result<Client, FlowersecError> {
    validate_direct_info(&mut info)?;
    let liveness = validate_client_runtime_options(Path::Direct, &options, None)?;
    let url = validate_websocket_url(&info.ws_url, Path::Direct)?;
    let psk = decode_psk(&info.e2ee_psk_b64u, Path::Direct)?;
    options
        .transport_security_policy
        .evaluate(&url, Path::Direct)
        .await?;
    if url.scheme() == "ws" {
        emit(
            &options,
            Path::Direct,
            Stage::Transport,
            "plaintext_transport",
            DiagnosticResult::Skip,
        );
    }
    let transport = dial(&url, Path::Direct, &options).await?;
    establish_client(
        transport,
        Path::Direct,
        info.channel_id,
        psk,
        suite_from_direct(info.default_suite),
        options,
        liveness,
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
    liveness: Option<AutomaticLiveness>,
) -> Result<Client, FlowersecError> {
    let deadline = tokio::time::Instant::now() + options.handshake_timeout;
    let mut handshake = ClientHandshakeOptions::new(psk, suite, channel_id);
    handshake.outbound_record_chunk_bytes = options.outbound_record_chunk_bytes;
    handshake.max_outbound_buffered_bytes = options.max_outbound_buffered_bytes;
    let secure = tokio::time::timeout_at(deadline, client_handshake(transport, handshake))
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
    let rpc_stream = initialize_client_rpc_stream(&session, path, deadline).await?;
    if let Some(liveness) = liveness {
        session.start_automatic_liveness(liveness, liveness_timeout_observer(&options, path));
    }
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

async fn initialize_client_rpc_stream(
    session: &YamuxSession,
    path: Path,
    deadline: tokio::time::Instant,
) -> Result<YamuxStream, FlowersecError> {
    let mut cleanup = YamuxSessionCleanupGuard::new(session.clone());
    let result = initialize_rpc_stream(session, path, deadline).await;
    cleanup.disarm();
    result
}

struct YamuxSessionCleanupGuard {
    session: Option<YamuxSession>,
}

impl YamuxSessionCleanupGuard {
    fn new(session: YamuxSession) -> Self {
        Self {
            session: Some(session),
        }
    }

    fn disarm(&mut self) {
        self.session = None;
    }
}

impl Drop for YamuxSessionCleanupGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            session.close_in_background();
        }
    }
}

async fn initialize_rpc_stream(
    session: &YamuxSession,
    path: Path,
    deadline: tokio::time::Instant,
) -> Result<YamuxStream, FlowersecError> {
    let result = match tokio::time::timeout_at(deadline, async {
        let rpc_stream = session.open_stream().await.map_err(|error| {
            let code = yamux_session_code(&error, ErrorCode::RPC_FAILED);
            FlowersecError::new(path, Stage::Rpc, code, "failed to open RPC stream")
                .with_source(error)
        })?;
        streamhello::write(&rpc_stream, streamhello::RPC_KIND)
            .await
            .map_err(|error| {
                let code = match &error {
                    crate::streamio::StreamIoError::Yamux(yamux) => {
                        yamux_session_code(yamux, ErrorCode::STREAM_HELLO_FAILED)
                    }
                    _ => ErrorCode::STREAM_HELLO_FAILED,
                };
                FlowersecError::new(path, Stage::Rpc, code, "failed to initialize RPC stream")
                    .with_source(error)
            })?;
        Ok(rpc_stream)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(FlowersecError::new(
            path,
            Stage::Rpc,
            ErrorCode::TIMEOUT,
            "client initialization timed out",
        )),
    };
    if result.is_err() {
        if tokio::time::Instant::now() >= deadline {
            session.close_in_background();
        } else {
            session.close_bounded().await;
        }
    }
    result
}

fn validate_client_runtime_options(
    path: Path,
    options: &ConnectOptions,
    path_default_idle_timeout: Option<Duration>,
) -> Result<Option<AutomaticLiveness>, FlowersecError> {
    validate_yamux_limits(path, options.yamux_limits)?;
    client_liveness(path, options.liveness, path_default_idle_timeout)
}

pub(crate) fn validate_yamux_limits(path: Path, limits: YamuxLimits) -> Result<(), FlowersecError> {
    limits.validate().map(|_| ()).map_err(|error| {
        FlowersecError::new(
            path,
            Stage::Validate,
            ErrorCode::INVALID_OPTION,
            "Yamux limits are invalid",
        )
        .with_source(error)
    })
}

fn liveness_timeout_observer(
    options: &ConnectOptions,
    path: Path,
) -> Option<Arc<dyn Fn() + Send + Sync>> {
    let observer = options.observer.clone()?;
    let attempt_seq = options.attempt_seq.max(1);
    let trace_id = options.trace_id.clone();
    let session_id = options.session_id.clone();
    Some(Arc::new(move || {
        observer.on_diagnostic(&DiagnosticEvent {
            v: 1,
            namespace: "connect".to_owned(),
            path,
            stage: Stage::Yamux,
            code_domain: DiagnosticCodeDomain::Event,
            code: "liveness_timeout".to_owned(),
            result: DiagnosticResult::Fail,
            elapsed_ms: 0.0,
            attempt_seq,
            trace_id: trace_id.clone(),
            session_id: session_id.clone(),
            resource: None,
            current: None,
            limit: None,
        });
    }))
}

fn client_liveness(
    path: Path,
    options: LivenessOptions,
    path_default_idle_timeout: Option<Duration>,
) -> Result<Option<AutomaticLiveness>, FlowersecError> {
    resolve_liveness(options, path_default_idle_timeout).map_err(|error| {
        FlowersecError::new(
            path,
            Stage::Validate,
            ErrorCode::INVALID_OPTION,
            "client liveness options are invalid",
        )
        .with_source(error)
    })
}

fn tunnel_idle_timeout(seconds: i32) -> Option<Duration> {
    u64::try_from(seconds)
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

fn validate_direct_info(info: &mut DirectConnectInfo) -> Result<(), FlowersecError> {
    info.channel_id = info.channel_id.trim().to_owned();
    if info.channel_id.is_empty() {
        return Err(validation_error(
            Path::Direct,
            ErrorCode::MISSING_CHANNEL_ID,
            "missing channel_id",
        ));
    }
    if info.channel_id.len() > 256 {
        return Err(validation_error(
            Path::Direct,
            ErrorCode::INVALID_INPUT,
            "channel_id is too long",
        ));
    }
    if info.channel_init_expire_at_unix_s <= 0 {
        return Err(validation_error(
            Path::Direct,
            ErrorCode::MISSING_INIT_EXP,
            "missing channel init expiry",
        ));
    }
    Ok(())
}

pub(crate) fn validate_tunnel_grant(
    grant: &mut ChannelInitGrant,
    expected_role: ControlRole,
) -> Result<(), FlowersecError> {
    if grant.role != expected_role {
        return Err(validation_error(
            Path::Tunnel,
            ErrorCode::ROLE_MISMATCH,
            match expected_role {
                ControlRole::Client => "client grant required",
                ControlRole::Server => "server grant required",
            },
        ));
    }
    grant.channel_id = grant.channel_id.trim().to_owned();
    if grant.channel_id.is_empty() {
        return Err(validation_error(
            Path::Tunnel,
            ErrorCode::MISSING_CHANNEL_ID,
            "missing channel_id",
        ));
    }
    if grant.channel_id.len() > 256 {
        return Err(validation_error(
            Path::Tunnel,
            ErrorCode::INVALID_INPUT,
            "channel_id is too long",
        ));
    }
    grant.token = grant.token.trim().to_owned();
    if grant.token.is_empty() {
        return Err(validation_error(
            Path::Tunnel,
            ErrorCode::MISSING_TOKEN,
            "missing token",
        ));
    }
    if grant.channel_init_expire_at_unix_s <= 0 {
        return Err(validation_error(
            Path::Tunnel,
            ErrorCode::MISSING_INIT_EXP,
            "missing channel init expiry",
        ));
    }
    if grant.allowed_suites.is_empty() || !grant.allowed_suites.contains(&grant.default_suite) {
        return Err(validation_error(
            Path::Tunnel,
            ErrorCode::INVALID_SUITE,
            "invalid tunnel cipher suites",
        ));
    }
    Ok(())
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
        atomic::{AtomicBool, AtomicUsize, Ordering},
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

    fn tunnel_grant(role: ControlRole) -> ChannelInitGrant {
        ChannelInitGrant {
            tunnel_url: "ws://127.0.0.1:9/tunnel".to_owned(),
            channel_id: "channel-test".to_owned(),
            channel_init_expire_at_unix_s: 1,
            idle_timeout_seconds: 60,
            role,
            token: "token".to_owned(),
            e2ee_psk_b64u: URL_SAFE_NO_PAD.encode([0_u8; 32]),
            allowed_suites: vec![ControlSuite::X25519HkdfSha256Aes256Gcm],
            default_suite: ControlSuite::X25519HkdfSha256Aes256Gcm,
        }
    }

    fn direct_info(ws_url: &str) -> DirectConnectInfo {
        DirectConnectInfo {
            ws_url: ws_url.to_owned(),
            channel_id: "channel-test".to_owned(),
            e2ee_psk_b64u: URL_SAFE_NO_PAD.encode([0_u8; 32]),
            channel_init_expire_at_unix_s: 1,
            default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
        }
    }

    #[derive(Debug)]
    struct PendingDuplex;

    #[async_trait::async_trait]
    impl crate::yamux::ByteDuplex for PendingDuplex {
        async fn read(&self) -> Result<Vec<u8>, crate::yamux::YamuxError> {
            std::future::pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), crate::yamux::YamuxError> {
            Ok(())
        }

        async fn close(&self) -> Result<(), crate::yamux::YamuxError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct TrackingDuplex {
        closed: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct BlockingRpcInitDuplex {
        closed: Arc<AtomicBool>,
        write_started: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl crate::yamux::ByteDuplex for BlockingRpcInitDuplex {
        async fn read(&self) -> Result<Vec<u8>, crate::yamux::YamuxError> {
            std::future::pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), crate::yamux::YamuxError> {
            self.write_started.notify_waiters();
            std::future::pending().await
        }

        async fn close(&self) -> Result<(), crate::yamux::YamuxError> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl crate::yamux::ByteDuplex for TrackingDuplex {
        async fn read(&self) -> Result<Vec<u8>, crate::yamux::YamuxError> {
            std::future::pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), crate::yamux::YamuxError> {
            Ok(())
        }

        async fn close(&self) -> Result<(), crate::yamux::YamuxError> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailingWriteDuplex;

    #[async_trait::async_trait]
    impl crate::yamux::ByteDuplex for FailingWriteDuplex {
        async fn read(&self) -> Result<Vec<u8>, crate::yamux::YamuxError> {
            std::future::pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), crate::yamux::YamuxError> {
            Err(crate::yamux::YamuxError::Transport(
                "test transport failure".to_owned(),
            ))
        }

        async fn close(&self) -> Result<(), crate::yamux::YamuxError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct NoopSecureControl;

    #[async_trait::async_trait]
    impl crate::e2ee::SecureChannelControl for NoopSecureControl {
        async fn rekey_channel(&self) -> Result<(), crate::e2ee::E2eeError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn client_liveness_timeout_uses_typed_timeout_code() {
        let session = YamuxSession::new(
            Arc::new(PendingDuplex),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create Yamux session");
        let rpc =
            RpcClient::from_stream(session.open_stream().await.expect("open test RPC stream"));
        let client = Client {
            path: Path::Direct,
            secure: Arc::new(NoopSecureControl),
            session,
            rpc,
        };

        let error = client
            .probe_liveness(Duration::ZERO)
            .await
            .expect_err("zero liveness timeout must fail");
        assert_eq!(error.path, Path::Direct);
        assert_eq!(error.stage, Stage::Yamux);
        assert_eq!(error.code.as_str(), ErrorCode::TIMEOUT);
        assert!(error.source.is_some());
    }

    #[tokio::test]
    async fn client_liveness_transport_failure_uses_ping_failed_code() {
        let session = YamuxSession::new(
            Arc::new(FailingWriteDuplex),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create failing Yamux session");
        let rpc_session = YamuxSession::new(
            Arc::new(PendingDuplex),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create RPC Yamux session");
        let rpc = RpcClient::from_stream(
            rpc_session
                .open_stream()
                .await
                .expect("open test RPC stream"),
        );
        let client = Client {
            path: Path::Tunnel,
            secure: Arc::new(NoopSecureControl),
            session,
            rpc,
        };

        let error = client
            .probe_liveness(Duration::from_secs(1))
            .await
            .expect_err("transport failure must fail the liveness probe");
        assert_eq!(error.path, Path::Tunnel);
        assert_eq!(error.stage, Stage::Yamux);
        assert_eq!(error.code.as_str(), ErrorCode::PING_FAILED);
        assert!(error.source.is_some());
    }

    #[tokio::test]
    async fn dropping_client_closes_and_releases_the_transport() {
        let transport = Arc::new(TrackingDuplex::default());
        let closed = transport.closed.clone();
        let weak = Arc::downgrade(&transport);
        let session = YamuxSession::new(transport.clone(), Mode::Client, YamuxLimits::default())
            .expect("create Yamux session");
        let rpc = RpcClient::from_stream(session.open_stream().await.expect("open RPC stream"));
        let client = Client {
            path: Path::Direct,
            secure: Arc::new(NoopSecureControl),
            session,
            rpc,
        };

        drop(transport);
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !closed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped client did not close its transport");
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped client retained its transport");
    }

    #[tokio::test]
    async fn automatic_liveness_timeout_emits_the_shared_diagnostic() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let options = ConnectOptions {
            observer: Some(Arc::new({
                let events = events.clone();
                move |event: &DiagnosticEvent| events.lock().unwrap().push(event.clone())
            })),
            attempt_seq: 7,
            trace_id: Some("trace-liveness".to_owned()),
            session_id: Some("session-liveness".to_owned()),
            ..ConnectOptions::default()
        };
        let session = YamuxSession::new(
            Arc::new(PendingDuplex),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create Yamux session");
        session.start_automatic_liveness(
            AutomaticLiveness {
                interval: Duration::from_millis(1),
                timeout: Duration::from_millis(1),
            },
            liveness_timeout_observer(&options, Path::Tunnel),
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while events.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("missing liveness timeout diagnostic");
        let event = events.lock().unwrap()[0].clone();
        assert_eq!(event.path, Path::Tunnel);
        assert_eq!(event.stage, Stage::Yamux);
        assert_eq!(event.code, "liveness_timeout");
        assert_eq!(event.result, DiagnosticResult::Fail);
        assert_eq!(event.attempt_seq, 7);
        assert_eq!(event.trace_id.as_deref(), Some("trace-liveness"));
        assert_eq!(event.session_id.as_deref(), Some("session-liveness"));
    }

    #[tokio::test]
    async fn rpc_initialization_closes_session_when_stream_open_fails() {
        let transport = Arc::new(TrackingDuplex::default());
        let session = YamuxSession::new(
            transport.clone(),
            Mode::Client,
            YamuxLimits {
                max_active_streams: 1,
                max_inbound_streams: 1,
                ..YamuxLimits::default()
            },
        )
        .expect("create Yamux session");
        let _occupied = session.open_stream().await.expect("occupy the only stream");

        let error = initialize_rpc_stream(
            &session,
            Path::Tunnel,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("RPC stream limit must fail initialization");
        assert_eq!(error.stage, Stage::Rpc);
        assert_eq!(error.code.as_str(), ErrorCode::RESOURCE_EXHAUSTED);
        assert!(transport.closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn rpc_initialization_closes_session_when_stream_hello_fails() {
        let transport = Arc::new(TrackingDuplex::default());
        let session = YamuxSession::new(
            transport.clone(),
            Mode::Client,
            YamuxLimits {
                max_stream_write_queue_bytes: 1,
                ..YamuxLimits::default()
            },
        )
        .expect("create Yamux session");

        let error = initialize_rpc_stream(
            &session,
            Path::Direct,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("RPC stream hello must exceed the local write queue");
        assert_eq!(error.stage, Stage::Rpc);
        assert_eq!(error.code.as_str(), ErrorCode::RESOURCE_EXHAUSTED);
        assert!(transport.closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn rpc_initialization_uses_the_existing_connection_deadline() {
        let closed = Arc::new(AtomicBool::new(false));
        let write_started = Arc::new(tokio::sync::Notify::new());
        let session = YamuxSession::new(
            Arc::new(BlockingRpcInitDuplex {
                closed: closed.clone(),
                write_started,
            }),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create Yamux session");
        let started = std::time::Instant::now();
        let error = initialize_rpc_stream(
            &session,
            Path::Direct,
            tokio::time::Instant::now() + Duration::from_millis(10),
        )
        .await
        .expect_err("RPC initialization must respect the connection deadline");

        assert_eq!(error.stage, Stage::Rpc);
        assert_eq!(error.code.as_str(), ErrorCode::TIMEOUT);
        assert!(started.elapsed() < Duration::from_millis(100));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !closed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed out RPC initialization did not close the session");
    }

    #[tokio::test]
    async fn aborting_rpc_initialization_closes_the_session() {
        let closed = Arc::new(AtomicBool::new(false));
        let write_started = Arc::new(tokio::sync::Notify::new());
        let session = YamuxSession::new(
            Arc::new(BlockingRpcInitDuplex {
                closed: closed.clone(),
                write_started: write_started.clone(),
            }),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create Yamux session");
        let task = tokio::spawn(async move {
            initialize_client_rpc_stream(
                &session,
                Path::Direct,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), write_started.notified())
            .await
            .expect("RPC initialization write did not start");
        task.abort();
        assert!(
            task.await
                .expect_err("RPC initialization task must be canceled")
                .is_cancelled()
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while !closed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted RPC initialization did not close the session");
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
        let wrong_role = tunnel_grant(ControlRole::Server);
        let role = connect_tunnel(wrong_role, ConnectOptions::default())
            .await
            .expect_err("client rejects a server grant");
        assert_eq!(role.code.as_str(), ErrorCode::ROLE_MISMATCH);

        let invalid_url =
            validate_websocket_url("not a URL", Path::Direct).expect_err("invalid URL");
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

    #[tokio::test]
    async fn public_connect_rejects_invalid_inputs_before_policy_or_dial() {
        let scope_calls = Arc::new(AtomicUsize::new(0));
        let mut artifact_options = ConnectOptions::default();
        artifact_options.scope_resolvers.insert(
            "required".to_owned(),
            resolver({
                let scope_calls = scope_calls.clone();
                move |_| {
                    scope_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }
            }),
        );
        let artifact_error = connect(
            ConnectArtifact::Direct {
                info: direct_info("https://example.test/direct"),
                scoped: vec![scope("required", true)],
                correlation: None,
            },
            artifact_options,
        )
        .await
        .expect_err("artifact transport validation must precede scope resolution");
        assert_eq!(artifact_error.code.as_str(), ErrorCode::MISSING_WS_URL);
        assert_eq!(scope_calls.load(Ordering::SeqCst), 0);

        let scope_calls = Arc::new(AtomicUsize::new(0));
        let mut invalid_limit_options = ConnectOptions {
            yamux_limits: YamuxLimits {
                max_active_streams: 0,
                ..YamuxLimits::default()
            },
            ..ConnectOptions::default()
        };
        invalid_limit_options.scope_resolvers.insert(
            "required".to_owned(),
            resolver({
                let scope_calls = scope_calls.clone();
                move |_| {
                    scope_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }
            }),
        );
        let limit_error = connect(
            ConnectArtifact::Direct {
                info: direct_info("wss://example.test/direct"),
                scoped: vec![scope("required", true)],
                correlation: None,
            },
            invalid_limit_options,
        )
        .await
        .expect_err("invalid Yamux limits must precede scope resolution");
        assert_eq!(limit_error.stage, Stage::Validate);
        assert_eq!(limit_error.code.as_str(), ErrorCode::INVALID_OPTION);
        assert_eq!(scope_calls.load(Ordering::SeqCst), 0);

        for invalid_url in [
            "https://example.test/direct",
            "ws://user@example.test/direct",
            "ws://",
            "wss://example.test/direct#fragment",
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let policy_calls = calls.clone();
            let error = connect_direct(
                direct_info(invalid_url),
                ConnectOptions {
                    transport_security_policy: TransportSecurityPolicy::new(move |_| {
                        policy_calls.fetch_add(1, Ordering::SeqCst);
                        async { Ok(()) }
                    }),
                    ..ConnectOptions::default()
                },
            )
            .await
            .expect_err("invalid direct URL must fail before policy evaluation");
            assert_eq!(error.path, Path::Direct);
            assert_eq!(error.stage, Stage::Validate);
            assert_eq!(error.code.as_str(), ErrorCode::MISSING_WS_URL);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        for invalid_url in [
            "http://example.test/tunnel",
            "wss://user@example.test/tunnel",
            "wss://",
            "wss://example.test/tunnel#fragment",
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let policy_calls = calls.clone();
            let mut grant = tunnel_grant(ControlRole::Client);
            grant.tunnel_url = invalid_url.to_owned();
            let error = connect_tunnel(
                grant,
                ConnectOptions {
                    transport_security_policy: TransportSecurityPolicy::new(move |_| {
                        policy_calls.fetch_add(1, Ordering::SeqCst);
                        async { Ok(()) }
                    }),
                    ..ConnectOptions::default()
                },
            )
            .await
            .expect_err("invalid tunnel URL must fail before policy evaluation");
            assert_eq!(error.path, Path::Tunnel);
            assert_eq!(error.stage, Stage::Validate);
            assert_eq!(error.code.as_str(), ErrorCode::MISSING_TUNNEL_URL);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let policy_calls = calls.clone();
        let error = connect_direct(
            direct_info("wss://example.test/direct"),
            ConnectOptions {
                liveness: LivenessOptions::Enabled {
                    interval: Duration::ZERO,
                    timeout: Duration::from_secs(1),
                },
                transport_security_policy: TransportSecurityPolicy::new(move |_| {
                    policy_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }),
                ..ConnectOptions::default()
            },
        )
        .await
        .expect_err("invalid client liveness must fail before policy evaluation");
        assert_eq!(error.code.as_str(), ErrorCode::INVALID_OPTION);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let policy_calls = calls.clone();
        let error = connect_tunnel(
            tunnel_grant(ControlRole::Client),
            ConnectOptions {
                liveness: LivenessOptions::Enabled {
                    interval: Duration::from_secs(1),
                    timeout: Duration::ZERO,
                },
                transport_security_policy: TransportSecurityPolicy::new(move |_| {
                    policy_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }),
                ..ConnectOptions::default()
            },
        )
        .await
        .expect_err("invalid tunnel liveness must fail before policy evaluation");
        assert_eq!(error.code.as_str(), ErrorCode::INVALID_OPTION);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let policy_calls = calls.clone();
        let mut grant = tunnel_grant(ControlRole::Client);
        grant.token = " \t ".to_owned();
        let error = connect_tunnel(
            grant,
            ConnectOptions {
                transport_security_policy: TransportSecurityPolicy::new(move |_| {
                    policy_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }),
                ..ConnectOptions::default()
            },
        )
        .await
        .expect_err("invalid client grant must fail before policy evaluation");
        assert_eq!(error.code.as_str(), ErrorCode::MISSING_TOKEN);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn tunnel_grant_validation_normalizes_and_rejects_invalid_contracts() {
        let mut normalized = tunnel_grant(ControlRole::Client);
        normalized.channel_id = "  channel-test  ".to_owned();
        normalized.token = "  token  ".to_owned();
        validate_tunnel_grant(&mut normalized, ControlRole::Client)
            .expect("valid grant is normalized");
        assert_eq!(normalized.channel_id, "channel-test");
        assert_eq!(normalized.token, "token");

        let cases = [
            (
                {
                    let mut grant = tunnel_grant(ControlRole::Client);
                    grant.channel_id = "  ".to_owned();
                    grant
                },
                ErrorCode::MISSING_CHANNEL_ID,
            ),
            (
                {
                    let mut grant = tunnel_grant(ControlRole::Client);
                    grant.channel_id = "x".repeat(257);
                    grant
                },
                ErrorCode::INVALID_INPUT,
            ),
            (
                {
                    let mut grant = tunnel_grant(ControlRole::Client);
                    grant.token = "  ".to_owned();
                    grant
                },
                ErrorCode::MISSING_TOKEN,
            ),
            (
                {
                    let mut grant = tunnel_grant(ControlRole::Client);
                    grant.channel_init_expire_at_unix_s = 0;
                    grant
                },
                ErrorCode::MISSING_INIT_EXP,
            ),
            (
                {
                    let mut grant = tunnel_grant(ControlRole::Client);
                    grant.allowed_suites.clear();
                    grant
                },
                ErrorCode::INVALID_SUITE,
            ),
            (
                {
                    let mut grant = tunnel_grant(ControlRole::Client);
                    grant.default_suite = ControlSuite::P256HkdfSha256Aes256Gcm;
                    grant
                },
                ErrorCode::INVALID_SUITE,
            ),
        ];
        for (mut grant, expected_code) in cases {
            let error = validate_tunnel_grant(&mut grant, ControlRole::Client)
                .expect_err("invalid tunnel grant must be rejected");
            assert_eq!(error.path, Path::Tunnel);
            assert_eq!(error.stage, Stage::Validate);
            assert_eq!(error.code.as_str(), expected_code);
        }
    }

    #[test]
    fn direct_info_validation_normalizes_and_rejects_invalid_contracts() {
        let mut normalized = direct_info("wss://example.test/direct");
        normalized.channel_id = "  channel-test  ".to_owned();
        validate_direct_info(&mut normalized).expect("valid direct info is normalized");
        assert_eq!(normalized.channel_id, "channel-test");

        let cases = [
            (
                {
                    let mut info = direct_info("wss://example.test/direct");
                    info.channel_id = "  ".to_owned();
                    info
                },
                ErrorCode::MISSING_CHANNEL_ID,
            ),
            (
                {
                    let mut info = direct_info("wss://example.test/direct");
                    info.channel_id = "x".repeat(257);
                    info
                },
                ErrorCode::INVALID_INPUT,
            ),
            (
                {
                    let mut info = direct_info("wss://example.test/direct");
                    info.channel_init_expire_at_unix_s = 0;
                    info
                },
                ErrorCode::MISSING_INIT_EXP,
            ),
        ];
        for (mut info, expected) in cases {
            let error = validate_direct_info(&mut info).expect_err("invalid direct info");
            assert_eq!(error.code.as_str(), expected);
        }
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
        assert_eq!(
            yamux_probe_code(&crate::yamux::YamuxError::InvalidFrame),
            ErrorCode::PING_FAILED
        );
        assert_eq!(
            client_liveness(Path::Direct, LivenessOptions::PathDefault, None).unwrap(),
            None
        );
        assert_eq!(
            client_liveness(
                Path::Tunnel,
                LivenessOptions::PathDefault,
                tunnel_idle_timeout(30)
            )
            .unwrap(),
            Some(AutomaticLiveness {
                interval: Duration::from_secs(15),
                timeout: Duration::from_secs(10),
            })
        );
        let invalid_liveness = client_liveness(
            Path::Tunnel,
            LivenessOptions::Enabled {
                interval: Duration::ZERO,
                timeout: Duration::from_secs(1),
            },
            tunnel_idle_timeout(30),
        )
        .expect_err("zero liveness interval must fail before dialing");
        assert_eq!(invalid_liveness.stage, Stage::Validate);
        assert_eq!(invalid_liveness.code.as_str(), ErrorCode::INVALID_OPTION);

        let options = ConnectOptions::default();
        let debug = format!("{options:?}");
        assert!(debug.contains("transport_security_policy"));
        assert!(debug.contains("liveness"));
        assert!(debug.contains("scope_resolvers"));
    }
}
