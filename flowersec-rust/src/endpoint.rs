use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Mutex;

use crate::{
    ErrorCode, FlowersecError, Path, Stage,
    client::{validate_tunnel_grant, validate_yamux_limits},
    e2ee::{
        Secret32, ServerHandshakeCache, ServerHandshakeOptions, Suite, decode_handshake_frame,
        server_handshake, validate_client_handshake_init,
    },
    generated::flowersec::{
        controlplane::v1::{ChannelInitGrant, Role as ControlRole, Suite as ControlSuite},
        e2ee::v1 as e2ee_wire,
        tunnel::v1::{Attach, Role as TunnelRole},
    },
    rpc::{Router, Server as RpcServer},
    streamhello,
    transport::{WebSocketMessage, WebSocketMessageKind, WebSocketTransport, connect_native},
    transport_security::{TransportSecurityPolicy, validate_websocket_url},
    yamux::{
        AutomaticLiveness, LivenessOptions, Mode, YamuxLimits, YamuxSession, YamuxStream,
        resolve_liveness,
    },
};

#[derive(Clone, Debug)]
pub struct EndpointOptions {
    pub origin: Option<String>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub transport_security_policy: TransportSecurityPolicy,
    pub yamux_limits: YamuxLimits,
    pub liveness: LivenessOptions,
    pub handshake_cache: Arc<ServerHandshakeCache>,
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self {
            origin: None,
            connect_timeout: crate::defaults::CONNECT_TIMEOUT,
            handshake_timeout: crate::defaults::HANDSHAKE_TIMEOUT,
            transport_security_policy: TransportSecurityPolicy::default(),
            yamux_limits: YamuxLimits::default(),
            liveness: LivenessOptions::default(),
            handshake_cache: Arc::new(ServerHandshakeCache::default()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DirectAcceptOptions {
    pub handshake: ServerHandshakeOptions,
    pub handshake_timeout: Duration,
    pub yamux_limits: YamuxLimits,
    pub liveness: LivenessOptions,
    pub handshake_cache: Arc<ServerHandshakeCache>,
}

impl DirectAcceptOptions {
    pub fn new(handshake: ServerHandshakeOptions) -> Self {
        Self {
            handshake,
            handshake_timeout: crate::defaults::HANDSHAKE_TIMEOUT,
            yamux_limits: YamuxLimits::default(),
            liveness: LivenessOptions::default(),
            handshake_cache: Arc::new(ServerHandshakeCache::default()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DirectHandshakeInit {
    pub channel_id: String,
    pub version: u8,
    pub suite: Suite,
    pub client_features: u32,
}

type CommitFuture = Pin<Box<dyn Future<Output = Result<(), FlowersecError>> + Send>>;
pub type CredentialCommit = Arc<dyn Fn() -> CommitFuture + Send + Sync>;

#[derive(Clone)]
pub struct DirectHandshakeCredential {
    pub psk: Secret32,
    pub init_expires_at_unix_s: i64,
    pub commit_authenticated: Option<CredentialCommit>,
}

impl std::fmt::Debug for DirectHandshakeCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DirectHandshakeCredential")
            .field("psk", &self.psk)
            .field("init_expires_at_unix_s", &self.init_expires_at_unix_s)
            .field(
                "commit_authenticated",
                &self.commit_authenticated.as_ref().map(|_| "configured"),
            )
            .finish()
    }
}

#[async_trait]
pub trait DirectCredentialResolver: Send + Sync + 'static {
    async fn resolve(
        &self,
        init: DirectHandshakeInit,
    ) -> Result<DirectHandshakeCredential, FlowersecError>;
}

#[derive(Debug)]
pub struct Session {
    path: Path,
    secure: Arc<dyn crate::e2ee::SecureChannelControl>,
    yamux: YamuxSession,
}

impl Session {
    pub fn path(&self) -> Path {
        self.path
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
        let stream = self.yamux.open_stream().await.map_err(|error| {
            let code = endpoint_yamux_session_code(&error, ErrorCode::OPEN_STREAM_FAILED);
            FlowersecError::new(
                self.path,
                Stage::Yamux,
                code,
                "failed to open endpoint stream",
            )
            .with_source(error)
        })?;
        if let Err(error) = streamhello::write(&stream, kind).await {
            let code = match self.yamux.terminal_error().await {
                Some(terminal) => {
                    endpoint_yamux_session_code(&terminal, ErrorCode::STREAM_HELLO_FAILED)
                }
                None => match &error {
                    crate::streamio::StreamIoError::Yamux(yamux) => {
                        endpoint_yamux_session_code(yamux, ErrorCode::STREAM_HELLO_FAILED)
                    }
                    _ => ErrorCode::STREAM_HELLO_FAILED,
                },
            };
            return Err(FlowersecError::new(
                self.path,
                Stage::Rpc,
                code,
                "failed to write endpoint stream hello",
            )
            .with_source(error));
        }
        Ok(stream)
    }

    pub async fn accept_stream(&self) -> Result<(String, YamuxStream), FlowersecError> {
        let stream = self.yamux.accept_stream().await.map_err(|error| {
            let code = endpoint_yamux_session_code(&error, ErrorCode::ACCEPT_STREAM_FAILED);
            FlowersecError::new(
                self.path,
                Stage::Yamux,
                code,
                "failed to accept endpoint stream",
            )
            .with_source(error)
        })?;
        let kind = match streamhello::read(&stream, crate::defaults::MAX_STREAM_HELLO_BYTES).await {
            Ok(kind) => kind,
            Err(error) => {
                let code = match self.yamux.terminal_error().await {
                    Some(terminal) => {
                        endpoint_yamux_session_code(&terminal, ErrorCode::STREAM_HELLO_FAILED)
                    }
                    None => match &error {
                        crate::streamio::StreamIoError::Yamux(yamux) => {
                            endpoint_yamux_session_code(yamux, ErrorCode::STREAM_HELLO_FAILED)
                        }
                        _ => ErrorCode::STREAM_HELLO_FAILED,
                    },
                };
                return Err(FlowersecError::new(
                    self.path,
                    Stage::Rpc,
                    code,
                    "failed to read endpoint stream hello",
                )
                .with_source(error));
            }
        };
        Ok((kind, stream))
    }

    pub async fn serve_rpc(&self, router: Router) -> Result<(), FlowersecError> {
        loop {
            let (kind, stream) = self.accept_stream().await?;
            if kind != streamhello::RPC_KIND {
                stream.reset().await.map_err(|error| {
                    FlowersecError::new(
                        self.path,
                        Stage::Rpc,
                        ErrorCode::RPC_FAILED,
                        "unexpected endpoint stream kind",
                    )
                    .with_source(error)
                })?;
                continue;
            }
            return Arc::new(RpcServer::new(router))
                .serve(stream)
                .await
                .map_err(|error| {
                    FlowersecError::new(
                        self.path,
                        Stage::Rpc,
                        ErrorCode::RPC_FAILED,
                        "RPC server failed",
                    )
                    .with_source(error)
                });
        }
    }

    pub async fn probe_liveness(&self, timeout: Duration) -> Result<Duration, FlowersecError> {
        self.yamux.probe_liveness(timeout).await.map_err(|error| {
            let code = endpoint_yamux_probe_code(&error);
            FlowersecError::new(
                self.path,
                Stage::Yamux,
                code,
                "endpoint liveness probe failed",
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
                "failed to rekey endpoint secure channel",
            )
            .with_source(error)
        })
    }

    pub async fn close(&self) -> Result<(), FlowersecError> {
        self.yamux.close().await.map_err(|error| {
            FlowersecError::new(
                self.path,
                Stage::Close,
                ErrorCode::NOT_CONNECTED,
                "failed to close endpoint session",
            )
            .with_source(error)
        })
    }

    pub async fn terminated(&self) {
        self.yamux.wait_closed().await;
    }

    pub async fn termination_error(&self) -> Option<FlowersecError> {
        self.yamux.terminal_error().await.map(|error| {
            let code = endpoint_yamux_session_code(&error, ErrorCode::NOT_CONNECTED);
            FlowersecError::new(self.path, Stage::Yamux, code, "endpoint session terminated")
                .with_source(error)
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.yamux.close_in_background();
    }
}

fn endpoint_yamux_probe_code(error: &crate::yamux::YamuxError) -> &'static str {
    match error {
        crate::yamux::YamuxError::PingTimeout => ErrorCode::TIMEOUT,
        crate::yamux::YamuxError::ResourceExhausted { .. } => ErrorCode::RESOURCE_EXHAUSTED,
        _ => ErrorCode::PING_FAILED,
    }
}

fn endpoint_yamux_session_code(
    error: &crate::yamux::YamuxError,
    fallback: &'static str,
) -> &'static str {
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

pub async fn accept_direct<T: WebSocketTransport>(
    transport: Arc<T>,
    options: DirectAcceptOptions,
) -> Result<Session, FlowersecError> {
    if let Err(error) = validate_yamux_limits(Path::Direct, options.yamux_limits) {
        close_transport_bounded(transport.clone()).await;
        return Err(error);
    }
    let liveness = match endpoint_liveness(Path::Direct, options.liveness, None) {
        Ok(liveness) => liveness,
        Err(error) => {
            close_transport_bounded(transport.clone()).await;
            return Err(error);
        }
    };
    establish_server(
        transport,
        Path::Direct,
        &options.handshake_cache,
        options.handshake,
        options.handshake_timeout,
        options.yamux_limits,
        liveness,
    )
    .await
}

pub async fn accept_direct_resolved<T: WebSocketTransport, R: DirectCredentialResolver>(
    transport: Arc<T>,
    resolver: &R,
    options: EndpointOptions,
) -> Result<Session, FlowersecError> {
    let deadline = tokio::time::Instant::now() + options.handshake_timeout;
    let mut close_guard = TransportCloseGuard::new(transport.clone());
    if let Err(error) = validate_yamux_limits(Path::Direct, options.yamux_limits) {
        close_transport_bounded(transport.clone()).await;
        close_guard.disarm();
        return Err(error);
    }
    let liveness = match endpoint_liveness(Path::Direct, options.liveness, None) {
        Ok(liveness) => liveness,
        Err(error) => {
            close_transport_before_deadline(transport.clone(), deadline).await;
            close_guard.disarm();
            return Err(error);
        }
    };
    let result = match tokio::time::timeout_at(
        deadline,
        accept_direct_resolved_inner(
            transport.clone(),
            resolver,
            &options.handshake_cache,
            options.yamux_limits,
            liveness,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(FlowersecError::new(
            Path::Direct,
            Stage::Handshake,
            ErrorCode::TIMEOUT,
            "endpoint handshake timed out",
        )),
    };
    if result.is_ok() {
        close_guard.disarm();
        return result;
    }
    close_transport_before_deadline(transport.clone(), deadline).await;
    close_guard.disarm();
    result
}

async fn accept_direct_resolved_inner<T: WebSocketTransport, R: DirectCredentialResolver>(
    transport: Arc<T>,
    resolver: &R,
    cache: &ServerHandshakeCache,
    limits: YamuxLimits,
    liveness: Option<AutomaticLiveness>,
) -> Result<Session, FlowersecError> {
    let first = transport
        .receive()
        .await
        .map_err(|error| endpoint_error(Path::Direct, Stage::Handshake, error))?
        .ok_or_else(|| {
            FlowersecError::new(
                Path::Direct,
                Stage::Handshake,
                ErrorCode::HANDSHAKE_FAILED,
                "transport closed before handshake",
            )
        })?;
    if first.kind != WebSocketMessageKind::Binary {
        return Err(FlowersecError::new(
            Path::Direct,
            Stage::Handshake,
            ErrorCode::HANDSHAKE_FAILED,
            "expected binary handshake frame",
        ));
    }
    let (message_type, payload) =
        decode_handshake_frame(&first.payload, crate::defaults::MAX_HANDSHAKE_PAYLOAD_BYTES)
            .map_err(|error| {
                FlowersecError::new(
                    Path::Direct,
                    Stage::Handshake,
                    ErrorCode::HANDSHAKE_FAILED,
                    "invalid direct handshake init",
                )
                .with_source(error)
            })?;
    if message_type != crate::e2ee::HANDSHAKE_TYPE_INIT {
        return Err(FlowersecError::new(
            Path::Direct,
            Stage::Handshake,
            ErrorCode::HANDSHAKE_FAILED,
            "unexpected direct handshake message",
        ));
    }
    let init: e2ee_wire::E2EE_Init = serde_json::from_slice(payload).map_err(|error| {
        FlowersecError::new(
            Path::Direct,
            Stage::Handshake,
            ErrorCode::HANDSHAKE_FAILED,
            "invalid direct handshake JSON",
        )
        .with_source(error)
    })?;
    let suite = validate_client_handshake_init(&init).map_err(|error| {
        FlowersecError::new(
            Path::Direct,
            Stage::Handshake,
            ErrorCode::HANDSHAKE_FAILED,
            "invalid direct handshake init",
        )
        .with_source(error)
    })?;
    let channel_id = init.channel_id.trim();
    if channel_id.is_empty() {
        return Err(FlowersecError::new(
            Path::Direct,
            Stage::Validate,
            ErrorCode::MISSING_CHANNEL_ID,
            "direct handshake init is missing channel_id",
        ));
    }
    if channel_id != init.channel_id || init.channel_id.len() > 256 {
        return Err(FlowersecError::new(
            Path::Direct,
            Stage::Validate,
            ErrorCode::INVALID_INPUT,
            "direct handshake channel_id is not canonical",
        ));
    }
    let credential = resolver
        .resolve(DirectHandshakeInit {
            channel_id: init.channel_id.clone(),
            version: init.version,
            suite,
            client_features: init.client_features,
        })
        .await
        .map_err(|error| {
            endpoint_callback_error(
                Path::Direct,
                error,
                Stage::Validate,
                ErrorCode::RESOLVE_FAILED,
                "direct credential resolution failed",
            )
        })?;
    let replay = Arc::new(ReplayTransport::new(transport, first));
    let mut handshake =
        ServerHandshakeOptions::new(credential.psk, suite, credential.init_expires_at_unix_s);
    handshake.channel_id = Some(init.channel_id);
    establish_server_core(
        replay,
        Path::Direct,
        cache,
        handshake,
        limits,
        liveness,
        credential.commit_authenticated,
    )
    .await
}

pub async fn connect_tunnel(
    mut grant: ChannelInitGrant,
    options: EndpointOptions,
) -> Result<Session, FlowersecError> {
    validate_tunnel_grant(&mut grant, ControlRole::Server)?;
    validate_yamux_limits(Path::Tunnel, options.yamux_limits)?;
    let liveness = endpoint_liveness(
        Path::Tunnel,
        options.liveness,
        tunnel_idle_timeout(grant.idle_timeout_seconds),
    )?;
    let url = validate_websocket_url(&grant.tunnel_url, Path::Tunnel)?;
    let psk = decode_psk(&grant.e2ee_psk_b64u)?;
    let mut endpoint_instance_id = [0_u8; 24];
    OsRng.fill_bytes(&mut endpoint_instance_id);
    let attach = Attach {
        v: 1,
        channel_id: grant.channel_id.clone(),
        role: TunnelRole::Server,
        token: grant.token,
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
    options
        .transport_security_policy
        .evaluate(&url, Path::Tunnel)
        .await?;
    let transport = connect_native(&url, options.origin.as_deref(), options.connect_timeout)
        .await
        .map_err(|error| endpoint_error(Path::Tunnel, Stage::Connect, error))?;
    if let Err(error) = transport
        .send(WebSocketMessage {
            kind: WebSocketMessageKind::Text,
            payload: attach_payload.into(),
        })
        .await
    {
        close_transport_bounded(transport.clone()).await;
        return Err(endpoint_error(Path::Tunnel, Stage::Attach, error));
    }
    let mut handshake = ServerHandshakeOptions::new(
        psk,
        suite_from_control(grant.default_suite),
        grant.channel_init_expire_at_unix_s,
    );
    handshake.channel_id = Some(grant.channel_id);
    establish_server(
        transport,
        Path::Tunnel,
        &options.handshake_cache,
        handshake,
        options.handshake_timeout,
        options.yamux_limits,
        liveness,
    )
    .await
}

async fn establish_server<T: WebSocketTransport>(
    transport: Arc<T>,
    path: Path,
    cache: &ServerHandshakeCache,
    handshake: ServerHandshakeOptions,
    handshake_timeout: Duration,
    limits: YamuxLimits,
    liveness: Option<AutomaticLiveness>,
) -> Result<Session, FlowersecError> {
    let deadline = tokio::time::Instant::now() + handshake_timeout;
    let result = match tokio::time::timeout_at(
        deadline,
        establish_server_core(
            transport.clone(),
            path,
            cache,
            handshake,
            limits,
            liveness,
            None,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(FlowersecError::new(
            path,
            Stage::Handshake,
            ErrorCode::TIMEOUT,
            "endpoint E2EE handshake timed out",
        )),
    };
    if result.is_err() {
        close_transport_before_deadline(transport, deadline).await;
    }
    result
}

async fn establish_server_core<T: WebSocketTransport>(
    transport: Arc<T>,
    path: Path,
    cache: &ServerHandshakeCache,
    handshake: ServerHandshakeOptions,
    limits: YamuxLimits,
    liveness: Option<AutomaticLiveness>,
    commit_authenticated: Option<CredentialCommit>,
) -> Result<Session, FlowersecError> {
    let secure = server_handshake(transport, cache, handshake)
        .await
        .map_err(|error| {
            FlowersecError::new(
                path,
                Stage::Handshake,
                ErrorCode::HANDSHAKE_FAILED,
                "endpoint E2EE handshake failed",
            )
            .with_source(error)
        })?;
    if let Some(commit) = commit_authenticated {
        commit().await.map_err(|error| {
            endpoint_callback_error(
                path,
                error,
                Stage::Handshake,
                ErrorCode::CREDENTIAL_COMMIT_FAILED,
                "authenticated credential commit failed",
            )
        })?;
    }
    let secure = Arc::new(secure);
    let yamux = YamuxSession::new(secure.clone(), Mode::Server, limits).map_err(|error| {
        FlowersecError::new(
            path,
            Stage::Yamux,
            ErrorCode::OPEN_STREAM_FAILED,
            "endpoint Yamux setup failed",
        )
        .with_source(error)
    })?;
    if let Some(liveness) = liveness {
        yamux.start_automatic_liveness(liveness, None);
    }
    Ok(Session {
        path,
        secure,
        yamux,
    })
}

async fn close_transport_before_deadline<T: WebSocketTransport>(
    transport: Arc<T>,
    deadline: tokio::time::Instant,
) {
    let now = tokio::time::Instant::now();
    if now >= deadline {
        spawn_bounded_transport_close(transport);
        return;
    }
    let budget = (deadline - now).min(crate::defaults::TRANSPORT_CLOSE_GRACE_PERIOD);
    close_transport_with_timeout(transport, budget).await;
}

async fn close_transport_bounded<T: WebSocketTransport>(transport: Arc<T>) {
    close_transport_with_timeout(transport, crate::defaults::TRANSPORT_CLOSE_GRACE_PERIOD).await;
}

async fn close_transport_with_timeout<T: WebSocketTransport>(transport: Arc<T>, timeout: Duration) {
    match tokio::time::timeout(timeout, transport.close()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "endpoint transport close failed"),
        Err(_) => tracing::warn!("endpoint transport close timed out"),
    }
}

fn spawn_bounded_transport_close<T: WebSocketTransport>(transport: Arc<T>) {
    tokio::spawn(close_transport_bounded(transport));
}

#[derive(Debug)]
struct TransportCloseGuard<T: WebSocketTransport> {
    transport: Option<Arc<T>>,
}

impl<T: WebSocketTransport> TransportCloseGuard<T> {
    fn new(transport: Arc<T>) -> Self {
        Self {
            transport: Some(transport),
        }
    }

    fn disarm(&mut self) {
        self.transport = None;
    }
}

impl<T: WebSocketTransport> Drop for TransportCloseGuard<T> {
    fn drop(&mut self) {
        let Some(transport) = self.transport.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(close_transport_bounded(transport));
        }
    }
}

fn endpoint_callback_error(
    path: Path,
    error: FlowersecError,
    fallback_stage: Stage,
    fallback_code: &'static str,
    fallback_message: &'static str,
) -> FlowersecError {
    match error.code.as_str() {
        ErrorCode::TIMEOUT => FlowersecError::new(
            path,
            Stage::Handshake,
            ErrorCode::TIMEOUT,
            "endpoint handshake timed out",
        )
        .with_source(error),
        ErrorCode::CANCELED => FlowersecError::new(
            path,
            Stage::Handshake,
            ErrorCode::CANCELED,
            "endpoint handshake was canceled",
        )
        .with_source(error),
        _ => FlowersecError::new(path, fallback_stage, fallback_code, fallback_message)
            .with_source(error),
    }
}

fn endpoint_liveness(
    path: Path,
    options: LivenessOptions,
    path_default_idle_timeout: Option<Duration>,
) -> Result<Option<AutomaticLiveness>, FlowersecError> {
    resolve_liveness(options, path_default_idle_timeout).map_err(|error| {
        FlowersecError::new(
            path,
            Stage::Validate,
            ErrorCode::INVALID_OPTION,
            "endpoint liveness options are invalid",
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

#[derive(Debug)]
struct ReplayTransport<T: WebSocketTransport> {
    inner: Arc<T>,
    first: Mutex<Option<WebSocketMessage>>,
}

impl<T: WebSocketTransport> ReplayTransport<T> {
    fn new(inner: Arc<T>, first: WebSocketMessage) -> Self {
        Self {
            inner,
            first: Mutex::new(Some(first)),
        }
    }
}

#[async_trait]
impl<T: WebSocketTransport> WebSocketTransport for ReplayTransport<T> {
    async fn receive(&self) -> std::io::Result<Option<WebSocketMessage>> {
        if let Some(first) = self.first.lock().await.take() {
            return Ok(Some(first));
        }
        self.inner.receive().await
    }

    async fn send(&self, message: WebSocketMessage) -> std::io::Result<()> {
        self.inner.send(message).await
    }

    async fn close(&self) -> std::io::Result<()> {
        self.inner.close().await
    }
}

fn decode_psk(value: &str) -> Result<Secret32, FlowersecError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        FlowersecError::new(
            Path::Tunnel,
            Stage::Validate,
            ErrorCode::INVALID_PSK,
            "invalid endpoint PSK",
        )
        .with_source(error)
    })?;
    Ok(Secret32::new(bytes.try_into().map_err(|_| {
        FlowersecError::new(
            Path::Tunnel,
            Stage::Validate,
            ErrorCode::INVALID_PSK,
            "endpoint PSK must be 32 bytes",
        )
    })?))
}

fn suite_from_control(suite: ControlSuite) -> Suite {
    match suite {
        ControlSuite::X25519HkdfSha256Aes256Gcm => Suite::X25519HkdfSha256Aes256Gcm,
        ControlSuite::P256HkdfSha256Aes256Gcm => Suite::P256HkdfSha256Aes256Gcm,
    }
}

fn endpoint_error(path: Path, stage: Stage, error: std::io::Error) -> FlowersecError {
    FlowersecError::new(
        path,
        stage,
        if error.kind() == std::io::ErrorKind::TimedOut {
            ErrorCode::TIMEOUT
        } else {
            ErrorCode::DIAL_FAILED
        },
        "endpoint WebSocket operation failed",
    )
    .with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2ee::{HANDSHAKE_TYPE_RESP, encode_handshake_frame};
    use bytes::Bytes;
    use std::{
        collections::VecDeque,
        io,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct PendingDuplex;

    #[async_trait]
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

    #[derive(Debug)]
    struct FailingWriteDuplex;

    #[async_trait]
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
    struct DropTrackingDuplex {
        closed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl crate::yamux::ByteDuplex for DropTrackingDuplex {
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
    struct NoopSecureControl;

    #[async_trait]
    impl crate::e2ee::SecureChannelControl for NoopSecureControl {
        async fn rekey_channel(&self) -> Result<(), crate::e2ee::E2eeError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn endpoint_liveness_timeout_uses_typed_timeout_code() {
        let session = Session {
            path: Path::Tunnel,
            secure: Arc::new(NoopSecureControl),
            yamux: YamuxSession::new(
                Arc::new(PendingDuplex),
                Mode::Server,
                YamuxLimits::default(),
            )
            .expect("create Yamux session"),
        };

        let error = session
            .probe_liveness(Duration::ZERO)
            .await
            .expect_err("zero liveness timeout must fail");
        assert_eq!(error.path, Path::Tunnel);
        assert_eq!(error.stage, Stage::Yamux);
        assert_eq!(error.code.as_str(), ErrorCode::TIMEOUT);
        assert!(error.source.is_some());
    }

    #[tokio::test]
    async fn endpoint_liveness_transport_failure_uses_ping_failed_code() {
        let session = Session {
            path: Path::Direct,
            secure: Arc::new(NoopSecureControl),
            yamux: YamuxSession::new(
                Arc::new(FailingWriteDuplex),
                Mode::Server,
                YamuxLimits::default(),
            )
            .expect("create failing Yamux session"),
        };

        let error = session
            .probe_liveness(Duration::from_secs(1))
            .await
            .expect_err("transport failure must fail the liveness probe");
        assert_eq!(error.path, Path::Direct);
        assert_eq!(error.stage, Stage::Yamux);
        assert_eq!(error.code.as_str(), ErrorCode::PING_FAILED);
        assert!(error.source.is_some());
    }

    #[tokio::test]
    async fn dropping_endpoint_session_closes_and_releases_the_transport() {
        let closed = Arc::new(AtomicBool::new(false));
        let transport = Arc::new(DropTrackingDuplex {
            closed: closed.clone(),
        });
        let weak = Arc::downgrade(&transport);
        let session = Session {
            path: Path::Direct,
            secure: Arc::new(NoopSecureControl),
            yamux: YamuxSession::new(transport.clone(), Mode::Server, YamuxLimits::default())
                .expect("create Yamux session"),
        };

        drop(transport);
        drop(session);
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped endpoint session retained its transport");
        assert!(closed.load(Ordering::SeqCst));
    }

    #[derive(Debug, Default)]
    struct FakeTransport {
        incoming: Mutex<VecDeque<WebSocketMessage>>,
        sent: Mutex<Vec<WebSocketMessage>>,
        closed: AtomicBool,
    }

    impl FakeTransport {
        fn with_message(message: WebSocketMessage) -> Self {
            Self {
                incoming: Mutex::new(VecDeque::from([message])),
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl WebSocketTransport for FakeTransport {
        async fn receive(&self) -> io::Result<Option<WebSocketMessage>> {
            Ok(self.incoming.lock().await.pop_front())
        }

        async fn send(&self, message: WebSocketMessage) -> io::Result<()> {
            self.sent.lock().await.push(message);
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct RejectingResolver;

    #[async_trait]
    impl DirectCredentialResolver for RejectingResolver {
        async fn resolve(
            &self,
            _: DirectHandshakeInit,
        ) -> Result<DirectHandshakeCredential, FlowersecError> {
            Err(FlowersecError::new(
                Path::Direct,
                Stage::Validate,
                ErrorCode::RESOLVE_FAILED,
                "credential unavailable",
            ))
        }
    }

    #[derive(Debug, Default)]
    struct PendingTransport {
        closed: AtomicBool,
    }

    #[async_trait]
    impl WebSocketTransport for PendingTransport {
        async fn receive(&self) -> io::Result<Option<WebSocketMessage>> {
            std::future::pending().await
        }

        async fn send(&self, _message: WebSocketMessage) -> io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct PendingResolver;

    #[async_trait]
    impl DirectCredentialResolver for PendingResolver {
        async fn resolve(
            &self,
            _: DirectHandshakeInit,
        ) -> Result<DirectHandshakeCredential, FlowersecError> {
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct InterruptingResolver(&'static str);

    #[async_trait]
    impl DirectCredentialResolver for InterruptingResolver {
        async fn resolve(
            &self,
            _: DirectHandshakeInit,
        ) -> Result<DirectHandshakeCredential, FlowersecError> {
            Err(FlowersecError::new(
                Path::Auto,
                Stage::Validate,
                self.0,
                "resolver interrupted",
            ))
        }
    }

    #[derive(Debug)]
    struct HangingCloseTransport {
        incoming: Mutex<VecDeque<WebSocketMessage>>,
        close_calls: AtomicUsize,
    }

    impl HangingCloseTransport {
        fn with_message(message: WebSocketMessage) -> Self {
            Self {
                incoming: Mutex::new(VecDeque::from([message])),
                close_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl WebSocketTransport for HangingCloseTransport {
        async fn receive(&self) -> io::Result<Option<WebSocketMessage>> {
            Ok(self.incoming.lock().await.pop_front())
        }

        async fn send(&self, _message: WebSocketMessage) -> io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct CountingResolver(AtomicUsize);

    #[async_trait]
    impl DirectCredentialResolver for CountingResolver {
        async fn resolve(
            &self,
            _: DirectHandshakeInit,
        ) -> Result<DirectHandshakeCredential, FlowersecError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(FlowersecError::new(
                Path::Direct,
                Stage::Validate,
                ErrorCode::RESOLVE_FAILED,
                "credential unavailable",
            ))
        }
    }

    fn message(kind: WebSocketMessageKind, payload: impl Into<Bytes>) -> Arc<FakeTransport> {
        Arc::new(FakeTransport::with_message(WebSocketMessage {
            kind,
            payload: payload.into(),
        }))
    }

    fn init_message(init: &e2ee_wire::E2EE_Init) -> Arc<FakeTransport> {
        message(
            WebSocketMessageKind::Binary,
            encode_handshake_frame(
                crate::e2ee::HANDSHAKE_TYPE_INIT,
                &serde_json::to_vec(init).unwrap(),
            ),
        )
    }

    fn valid_init() -> e2ee_wire::E2EE_Init {
        e2ee_wire::E2EE_Init {
            channel_id: "channel-resolver".to_owned(),
            role: e2ee_wire::Role::Client,
            version: crate::e2ee::PROTOCOL_VERSION,
            suite: e2ee_wire::Suite::X25519HkdfSha256Aes256Gcm,
            client_eph_pub_b64u: URL_SAFE_NO_PAD.encode([0x31_u8; 32]),
            nonce_c_b64u: URL_SAFE_NO_PAD.encode([0x32_u8; 32]),
            client_features: 7,
        }
    }

    #[tokio::test]
    async fn resolved_accept_times_out_waiting_for_the_first_frame_and_closes_transport() {
        let transport = Arc::new(PendingTransport::default());
        let error = accept_direct_resolved(
            transport.clone(),
            &RejectingResolver,
            EndpointOptions {
                handshake_timeout: Duration::from_millis(10),
                ..EndpointOptions::default()
            },
        )
        .await
        .expect_err("first frame must share the handshake deadline");

        assert_eq!(error.code.as_str(), ErrorCode::TIMEOUT);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !transport.closed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed out first-frame receive did not close transport");
    }

    #[tokio::test]
    async fn resolved_accept_times_out_waiting_for_the_resolver_and_closes_transport() {
        let transport = init_message(&valid_init());
        let error = accept_direct_resolved(
            transport.clone(),
            &PendingResolver,
            EndpointOptions {
                handshake_timeout: Duration::from_millis(10),
                ..EndpointOptions::default()
            },
        )
        .await
        .expect_err("resolver must share the handshake deadline");

        assert_eq!(error.code.as_str(), ErrorCode::TIMEOUT);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !transport.closed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed out resolver did not close transport");
    }

    #[tokio::test]
    async fn resolved_accept_deadline_does_not_wait_for_hanging_close() {
        let transport = Arc::new(HangingCloseTransport::with_message(
            init_message(&valid_init())
                .incoming
                .lock()
                .await
                .pop_front()
                .expect("init message"),
        ));
        let weak = Arc::downgrade(&transport);
        let started = std::time::Instant::now();
        let error = accept_direct_resolved(
            transport.clone(),
            &PendingResolver,
            EndpointOptions {
                handshake_timeout: Duration::from_millis(10),
                ..EndpointOptions::default()
            },
        )
        .await
        .expect_err("resolver must time out");

        assert_eq!(error.code.as_str(), ErrorCode::TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(1));
        tokio::time::timeout(Duration::from_secs(1), async {
            while transport.close_calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background close was not started");
        drop(transport);
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded close retained the transport");
    }

    #[tokio::test]
    async fn resolved_accept_task_abort_closes_transport() {
        let transport = Arc::new(PendingTransport::default());
        let task = tokio::spawn({
            let transport = transport.clone();
            async move {
                accept_direct_resolved(transport, &PendingResolver, EndpointOptions::default())
                    .await
            }
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.expect_err("task must be aborted").is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !transport.closed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted accept did not close transport");
    }

    #[tokio::test]
    async fn resolved_accept_preserves_resolver_interruptions() {
        for code in [ErrorCode::TIMEOUT, ErrorCode::CANCELED] {
            let transport = init_message(&valid_init());
            let error = accept_direct_resolved(
                transport.clone(),
                &InterruptingResolver(code),
                EndpointOptions::default(),
            )
            .await
            .expect_err("resolver interruption must fail");
            assert_eq!(error.path, Path::Direct);
            assert_eq!(error.stage, Stage::Handshake);
            assert_eq!(error.code.as_str(), code);
            assert!(transport.closed.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn credential_commit_interruptions_use_handshake_codes() {
        for code in [ErrorCode::TIMEOUT, ErrorCode::CANCELED] {
            let error = endpoint_callback_error(
                Path::Tunnel,
                FlowersecError::new(Path::Auto, Stage::Validate, code, "interrupted"),
                Stage::Handshake,
                ErrorCode::CREDENTIAL_COMMIT_FAILED,
                "commit failed",
            );
            assert_eq!(error.path, Path::Tunnel);
            assert_eq!(error.stage, Stage::Handshake);
            assert_eq!(error.code.as_str(), code);
            assert!(error.source.is_some());
        }
    }

    #[tokio::test]
    async fn resolved_accept_validates_init_before_calling_the_resolver() {
        let resolver = CountingResolver(AtomicUsize::new(0));
        let mut cases = Vec::new();
        let mut invalid_version = valid_init();
        invalid_version.version = crate::e2ee::PROTOCOL_VERSION + 1;
        cases.push((init_message(&invalid_version), ErrorCode::HANDSHAKE_FAILED));
        let mut invalid_role = valid_init();
        invalid_role.role = e2ee_wire::Role::Server;
        cases.push((init_message(&invalid_role), ErrorCode::HANDSHAKE_FAILED));
        let mut missing_channel = valid_init();
        missing_channel.channel_id = " \t ".to_owned();
        cases.push((
            init_message(&missing_channel),
            ErrorCode::MISSING_CHANNEL_ID,
        ));
        let mut padded_channel = valid_init();
        padded_channel.channel_id = " channel-resolver ".to_owned();
        cases.push((init_message(&padded_channel), ErrorCode::INVALID_INPUT));
        let mut long_channel = valid_init();
        long_channel.channel_id = "x".repeat(257);
        cases.push((init_message(&long_channel), ErrorCode::INVALID_INPUT));
        let mut invalid_key = valid_init();
        invalid_key.client_eph_pub_b64u = "invalid".to_owned();
        cases.push((init_message(&invalid_key), ErrorCode::HANDSHAKE_FAILED));
        let mut invalid_nonce = valid_init();
        invalid_nonce.nonce_c_b64u = URL_SAFE_NO_PAD.encode([0_u8; 31]);
        cases.push((init_message(&invalid_nonce), ErrorCode::HANDSHAKE_FAILED));
        let invalid_suite = serde_json::json!({
            "channel_id": "channel-resolver",
            "role": 1,
            "version": crate::e2ee::PROTOCOL_VERSION,
            "suite": 99,
            "client_eph_pub_b64u": "unused",
            "nonce_c_b64u": "unused",
            "client_features": 7
        });
        cases.push((
            message(
                WebSocketMessageKind::Binary,
                encode_handshake_frame(
                    crate::e2ee::HANDSHAKE_TYPE_INIT,
                    &serde_json::to_vec(&invalid_suite).unwrap(),
                ),
            ),
            ErrorCode::HANDSHAKE_FAILED,
        ));

        for (transport, expected_code) in cases {
            let error =
                accept_direct_resolved(transport.clone(), &resolver, EndpointOptions::default())
                    .await
                    .expect_err("invalid init must fail before resolution");
            assert_eq!(error.code.as_str(), expected_code);
            assert!(transport.closed.load(Ordering::SeqCst));
        }
        assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resolved_accept_rejects_closed_text_and_malformed_handshakes() {
        let closed = accept_direct_resolved(
            Arc::new(FakeTransport::default()),
            &RejectingResolver,
            EndpointOptions::default(),
        )
        .await
        .expect_err("closed transport");
        assert_eq!(closed.code.as_str(), ErrorCode::HANDSHAKE_FAILED);

        let text = accept_direct_resolved(
            message(WebSocketMessageKind::Text, Bytes::from_static(b"init")),
            &RejectingResolver,
            EndpointOptions::default(),
        )
        .await
        .expect_err("text handshake");
        assert_eq!(text.code.as_str(), ErrorCode::HANDSHAKE_FAILED);

        let malformed = accept_direct_resolved(
            message(WebSocketMessageKind::Binary, Bytes::from_static(b"short")),
            &RejectingResolver,
            EndpointOptions::default(),
        )
        .await
        .expect_err("malformed frame");
        assert!(malformed.source.is_some());

        let wrong_type = accept_direct_resolved(
            message(
                WebSocketMessageKind::Binary,
                encode_handshake_frame(HANDSHAKE_TYPE_RESP, b"{}"),
            ),
            &RejectingResolver,
            EndpointOptions::default(),
        )
        .await
        .expect_err("unexpected handshake type");
        assert_eq!(wrong_type.code.as_str(), ErrorCode::HANDSHAKE_FAILED);

        let invalid_json = accept_direct_resolved(
            message(
                WebSocketMessageKind::Binary,
                encode_handshake_frame(crate::e2ee::HANDSHAKE_TYPE_INIT, b"{"),
            ),
            &RejectingResolver,
            EndpointOptions::default(),
        )
        .await
        .expect_err("invalid handshake JSON");
        assert!(invalid_json.source.is_some());
    }

    #[tokio::test]
    async fn resolved_accept_wraps_credential_resolution_errors() {
        let init = valid_init();
        let transport = message(
            WebSocketMessageKind::Binary,
            encode_handshake_frame(
                crate::e2ee::HANDSHAKE_TYPE_INIT,
                &serde_json::to_vec(&init).unwrap(),
            ),
        );
        let error = accept_direct_resolved(
            transport.clone(),
            &RejectingResolver,
            EndpointOptions::default(),
        )
        .await
        .expect_err("resolver failure");
        assert_eq!(error.stage, Stage::Validate);
        assert_eq!(error.code.as_str(), ErrorCode::RESOLVE_FAILED);
        assert!(error.source.is_some());
        assert!(transport.closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn replay_transport_replays_once_then_delegates() {
        let inner = Arc::new(FakeTransport::with_message(WebSocketMessage {
            kind: WebSocketMessageKind::Binary,
            payload: Bytes::from_static(b"second"),
        }));
        let replay = ReplayTransport::new(
            inner.clone(),
            WebSocketMessage {
                kind: WebSocketMessageKind::Text,
                payload: Bytes::from_static(b"first"),
            },
        );
        assert_eq!(
            replay.receive().await.unwrap().unwrap().payload,
            Bytes::from_static(b"first")
        );
        assert_eq!(
            replay.receive().await.unwrap().unwrap().payload,
            Bytes::from_static(b"second")
        );
        replay
            .send(WebSocketMessage {
                kind: WebSocketMessageKind::Binary,
                payload: Bytes::from_static(b"sent"),
            })
            .await
            .unwrap();
        assert_eq!(inner.sent.lock().await.len(), 1);
        replay.close().await.unwrap();
        assert!(inner.closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tunnel_endpoint_validation_and_helpers_are_stable() {
        let grant = ChannelInitGrant {
            tunnel_url: "wss://example.test/tunnel".to_owned(),
            channel_id: "channel-test".to_owned(),
            channel_init_expire_at_unix_s: 1,
            idle_timeout_seconds: 60,
            role: ControlRole::Client,
            token: "token".to_owned(),
            e2ee_psk_b64u: URL_SAFE_NO_PAD.encode([0_u8; 32]),
            allowed_suites: vec![ControlSuite::X25519HkdfSha256Aes256Gcm],
            default_suite: ControlSuite::X25519HkdfSha256Aes256Gcm,
        };
        let role = connect_tunnel(grant, EndpointOptions::default())
            .await
            .expect_err("endpoint requires server role");
        assert_eq!(role.code.as_str(), ErrorCode::ROLE_MISMATCH);

        let missing_token = connect_tunnel(
            ChannelInitGrant {
                tunnel_url: "ws://127.0.0.1:9/tunnel".to_owned(),
                channel_id: "channel-test".to_owned(),
                channel_init_expire_at_unix_s: 1,
                idle_timeout_seconds: 60,
                role: ControlRole::Server,
                token: "  ".to_owned(),
                e2ee_psk_b64u: URL_SAFE_NO_PAD.encode([0_u8; 32]),
                allowed_suites: vec![ControlSuite::X25519HkdfSha256Aes256Gcm],
                default_suite: ControlSuite::X25519HkdfSha256Aes256Gcm,
            },
            EndpointOptions {
                transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..EndpointOptions::default()
            },
        )
        .await
        .expect_err("missing endpoint token is rejected before dialing");
        assert_eq!(missing_token.code.as_str(), ErrorCode::MISSING_TOKEN);

        let invalid_psk = connect_tunnel(
            ChannelInitGrant {
                tunnel_url: "ws://127.0.0.1:9/tunnel".to_owned(),
                channel_id: "channel-test".to_owned(),
                channel_init_expire_at_unix_s: 1,
                idle_timeout_seconds: 60,
                role: ControlRole::Server,
                token: "token".to_owned(),
                e2ee_psk_b64u: "invalid".to_owned(),
                allowed_suites: vec![ControlSuite::X25519HkdfSha256Aes256Gcm],
                default_suite: ControlSuite::X25519HkdfSha256Aes256Gcm,
            },
            EndpointOptions {
                transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..EndpointOptions::default()
            },
        )
        .await
        .expect_err("invalid endpoint PSK is rejected before dialing");
        assert_eq!(invalid_psk.code.as_str(), ErrorCode::INVALID_PSK);

        assert!(decode_psk("invalid").is_err());
        assert!(decode_psk(&URL_SAFE_NO_PAD.encode([0_u8; 31])).is_err());
        assert_eq!(
            format!(
                "{:?}",
                decode_psk(&URL_SAFE_NO_PAD.encode([0_u8; 32])).unwrap()
            ),
            "Secret32([REDACTED])"
        );
        assert_eq!(
            suite_from_control(ControlSuite::X25519HkdfSha256Aes256Gcm),
            Suite::X25519HkdfSha256Aes256Gcm
        );
        assert_eq!(
            suite_from_control(ControlSuite::P256HkdfSha256Aes256Gcm),
            Suite::P256HkdfSha256Aes256Gcm
        );
        let timeout = endpoint_error(
            Path::Tunnel,
            Stage::Connect,
            io::Error::new(io::ErrorKind::TimedOut, "timeout"),
        );
        assert_eq!(timeout.code.as_str(), ErrorCode::TIMEOUT);
        let failed = endpoint_error(
            Path::Direct,
            Stage::Handshake,
            io::Error::new(io::ErrorKind::ConnectionReset, "reset"),
        );
        assert_eq!(failed.code.as_str(), ErrorCode::DIAL_FAILED);
        assert!(failed.source.is_some());
        assert_eq!(
            endpoint_yamux_probe_code(&crate::yamux::YamuxError::InvalidFrame),
            ErrorCode::PING_FAILED
        );
        assert_eq!(
            endpoint_liveness(Path::Direct, LivenessOptions::PathDefault, None).unwrap(),
            None
        );
        assert_eq!(
            endpoint_liveness(
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
        let invalid_liveness = endpoint_liveness(
            Path::Tunnel,
            LivenessOptions::Enabled {
                interval: Duration::from_secs(1),
                timeout: Duration::ZERO,
            },
            tunnel_idle_timeout(30),
        )
        .expect_err("zero liveness timeout must fail before dialing");
        assert_eq!(invalid_liveness.stage, Stage::Validate);
        assert_eq!(invalid_liveness.code.as_str(), ErrorCode::INVALID_OPTION);
        assert_eq!(
            EndpointOptions::default().liveness,
            LivenessOptions::PathDefault
        );
        let direct_options = DirectAcceptOptions::new(ServerHandshakeOptions::new(
            Secret32::new([0_u8; 32]),
            Suite::X25519HkdfSha256Aes256Gcm,
            1,
        ));
        assert_eq!(direct_options.liveness, LivenessOptions::PathDefault);
        let debug = format!("{:?}", EndpointOptions::default());
        assert!(debug.contains("handshake_cache"));
        assert!(debug.contains("liveness"));
    }

    #[tokio::test]
    async fn public_tunnel_endpoint_rejects_invalid_inputs_before_policy_or_dial() {
        fn server_grant() -> ChannelInitGrant {
            ChannelInitGrant {
                tunnel_url: "wss://example.test/tunnel".to_owned(),
                channel_id: "channel-test".to_owned(),
                channel_init_expire_at_unix_s: 1,
                idle_timeout_seconds: 60,
                role: ControlRole::Server,
                token: "token".to_owned(),
                e2ee_psk_b64u: URL_SAFE_NO_PAD.encode([0_u8; 32]),
                allowed_suites: vec![ControlSuite::X25519HkdfSha256Aes256Gcm],
                default_suite: ControlSuite::X25519HkdfSha256Aes256Gcm,
            }
        }

        for invalid_url in [
            "https://example.test/tunnel",
            "ws://user@example.test/tunnel",
            "ws://",
            "wss://example.test/tunnel#fragment",
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let policy_calls = calls.clone();
            let mut grant = server_grant();
            grant.tunnel_url = invalid_url.to_owned();
            let error = connect_tunnel(
                grant,
                EndpointOptions {
                    transport_security_policy: TransportSecurityPolicy::new(move |_| {
                        policy_calls.fetch_add(1, Ordering::SeqCst);
                        async { Ok(()) }
                    }),
                    ..EndpointOptions::default()
                },
            )
            .await
            .expect_err("invalid endpoint tunnel URL must fail before policy evaluation");
            assert_eq!(error.path, Path::Tunnel);
            assert_eq!(error.stage, Stage::Validate);
            assert_eq!(error.code.as_str(), ErrorCode::MISSING_TUNNEL_URL);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        let transport = Arc::new(FakeTransport::default());
        let mut direct_options = DirectAcceptOptions::new(ServerHandshakeOptions::new(
            Secret32::new([0_u8; 32]),
            Suite::X25519HkdfSha256Aes256Gcm,
            1,
        ));
        direct_options.liveness = LivenessOptions::Enabled {
            interval: Duration::ZERO,
            timeout: Duration::from_secs(1),
        };
        let error = accept_direct(transport.clone(), direct_options)
            .await
            .expect_err("invalid direct endpoint liveness must fail before handshake");
        assert_eq!(error.code.as_str(), ErrorCode::INVALID_OPTION);
        assert!(transport.closed.load(Ordering::SeqCst));

        let transport = Arc::new(FakeTransport::default());
        let mut direct_options = DirectAcceptOptions::new(ServerHandshakeOptions::new(
            Secret32::new([0_u8; 32]),
            Suite::X25519HkdfSha256Aes256Gcm,
            1,
        ));
        direct_options.yamux_limits = YamuxLimits {
            max_active_streams: 0,
            ..YamuxLimits::default()
        };
        let error = accept_direct(transport.clone(), direct_options)
            .await
            .expect_err("invalid Yamux limits must fail before handshake");
        assert_eq!(error.stage, Stage::Validate);
        assert_eq!(error.code.as_str(), ErrorCode::INVALID_OPTION);
        assert!(transport.closed.load(Ordering::SeqCst));

        let calls = Arc::new(AtomicUsize::new(0));
        let policy_calls = calls.clone();
        let error = connect_tunnel(
            server_grant(),
            EndpointOptions {
                liveness: LivenessOptions::Enabled {
                    interval: Duration::from_secs(1),
                    timeout: Duration::ZERO,
                },
                transport_security_policy: TransportSecurityPolicy::new(move |_| {
                    policy_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }),
                ..EndpointOptions::default()
            },
        )
        .await
        .expect_err("invalid endpoint liveness must fail before policy evaluation");
        assert_eq!(error.code.as_str(), ErrorCode::INVALID_OPTION);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let policy_calls = calls.clone();
        let error = connect_tunnel(
            server_grant(),
            EndpointOptions {
                yamux_limits: YamuxLimits {
                    max_active_streams: 0,
                    ..YamuxLimits::default()
                },
                transport_security_policy: TransportSecurityPolicy::new(move |_| {
                    policy_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }),
                ..EndpointOptions::default()
            },
        )
        .await
        .expect_err("invalid endpoint Yamux limits must fail before policy evaluation");
        assert_eq!(error.stage, Stage::Validate);
        assert_eq!(error.code.as_str(), ErrorCode::INVALID_OPTION);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let policy_calls = calls.clone();
        let mut grant = server_grant();
        grant.token = " \t ".to_owned();
        let error = connect_tunnel(
            grant,
            EndpointOptions {
                transport_security_policy: TransportSecurityPolicy::new(move |_| {
                    policy_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }),
                ..EndpointOptions::default()
            },
        )
        .await
        .expect_err("invalid endpoint grant must fail before policy evaluation");
        assert_eq!(error.code.as_str(), ErrorCode::MISSING_TOKEN);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
