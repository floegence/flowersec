use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use url::Url;

use crate::{
    ErrorCode, FlowersecError, Path, Stage,
    e2ee::{
        Secret32, ServerHandshakeCache, ServerHandshakeOptions, Suite, decode_handshake_frame,
        server_handshake,
    },
    generated::flowersec::{
        controlplane::v1::{ChannelInitGrant, Role as ControlRole, Suite as ControlSuite},
        e2ee::v1 as e2ee_wire,
        tunnel::v1::{Attach, Role as TunnelRole},
    },
    rpc::{Router, Server as RpcServer},
    streamhello,
    transport::{WebSocketMessage, WebSocketMessageKind, WebSocketTransport, connect_native},
    transport_security::TransportSecurityPolicy,
    yamux::{Mode, YamuxLimits, YamuxSession, YamuxStream},
};

#[derive(Clone, Debug)]
pub struct EndpointOptions {
    pub origin: Option<String>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub transport_security_policy: TransportSecurityPolicy,
    pub yamux_limits: YamuxLimits,
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
            handshake_cache: Arc::new(ServerHandshakeCache::default()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DirectAcceptOptions {
    pub handshake: ServerHandshakeOptions,
    pub handshake_timeout: Duration,
    pub yamux_limits: YamuxLimits,
    pub handshake_cache: Arc<ServerHandshakeCache>,
}

impl DirectAcceptOptions {
    pub fn new(handshake: ServerHandshakeOptions) -> Self {
        Self {
            handshake,
            handshake_timeout: crate::defaults::HANDSHAKE_TIMEOUT,
            yamux_limits: YamuxLimits::default(),
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
    yamux: YamuxSession,
}

impl Session {
    pub fn path(&self) -> Path {
        self.path
    }

    pub async fn open_stream(&self, kind: &str) -> Result<YamuxStream, FlowersecError> {
        let stream = self.yamux.open_stream().await.map_err(|error| {
            FlowersecError::new(
                self.path,
                Stage::Yamux,
                ErrorCode::OPEN_STREAM_FAILED,
                "failed to open endpoint stream",
            )
            .with_source(error)
        })?;
        streamhello::write(&stream, kind).await.map_err(|error| {
            FlowersecError::new(
                self.path,
                Stage::Rpc,
                ErrorCode::STREAM_HELLO_FAILED,
                "failed to write endpoint stream hello",
            )
            .with_source(error)
        })?;
        Ok(stream)
    }

    pub async fn accept_stream(&self) -> Result<(String, YamuxStream), FlowersecError> {
        let stream = self.yamux.accept_stream().await.map_err(|error| {
            FlowersecError::new(
                self.path,
                Stage::Yamux,
                ErrorCode::ACCEPT_STREAM_FAILED,
                "failed to accept endpoint stream",
            )
            .with_source(error)
        })?;
        let kind = streamhello::read(&stream, crate::defaults::MAX_STREAM_HELLO_BYTES)
            .await
            .map_err(|error| {
                FlowersecError::new(
                    self.path,
                    Stage::Rpc,
                    ErrorCode::STREAM_HELLO_FAILED,
                    "failed to read endpoint stream hello",
                )
                .with_source(error)
            })?;
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
            FlowersecError::new(
                self.path,
                Stage::Yamux,
                ErrorCode::PING_FAILED,
                "endpoint liveness probe failed",
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
}

pub async fn accept_direct<T: WebSocketTransport>(
    transport: Arc<T>,
    options: DirectAcceptOptions,
) -> Result<Session, FlowersecError> {
    establish_server(
        transport,
        Path::Direct,
        &options.handshake_cache,
        options.handshake,
        options.handshake_timeout,
        options.yamux_limits,
    )
    .await
}

pub async fn accept_direct_resolved<T: WebSocketTransport, R: DirectCredentialResolver>(
    transport: Arc<T>,
    resolver: &R,
    options: EndpointOptions,
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
    let suite = suite_from_e2ee(init.suite);
    let credential = resolver
        .resolve(DirectHandshakeInit {
            channel_id: init.channel_id.clone(),
            version: init.version,
            suite,
            client_features: init.client_features,
        })
        .await
        .map_err(|error| {
            FlowersecError::new(
                Path::Direct,
                Stage::Validate,
                ErrorCode::RESOLVE_FAILED,
                "direct credential resolution failed",
            )
            .with_source(error)
        })?;
    let replay = Arc::new(ReplayTransport::new(transport, first));
    let mut handshake =
        ServerHandshakeOptions::new(credential.psk, suite, credential.init_expires_at_unix_s);
    handshake.channel_id = Some(init.channel_id);
    let session = establish_server(
        replay,
        Path::Direct,
        &options.handshake_cache,
        handshake,
        options.handshake_timeout,
        options.yamux_limits,
    )
    .await?;
    if let Some(commit) = credential.commit_authenticated {
        if let Err(error) = commit().await {
            let _ = session.close().await;
            return Err(FlowersecError::new(
                Path::Direct,
                Stage::Handshake,
                ErrorCode::CREDENTIAL_COMMIT_FAILED,
                "authenticated credential commit failed",
            )
            .with_source(error));
        }
    }
    Ok(session)
}

pub async fn connect_tunnel(
    grant: ChannelInitGrant,
    options: EndpointOptions,
) -> Result<Session, FlowersecError> {
    if grant.role != ControlRole::Server {
        return Err(FlowersecError::new(
            Path::Tunnel,
            Stage::Validate,
            ErrorCode::ROLE_MISMATCH,
            "server grant required",
        ));
    }
    let url = Url::parse(&grant.tunnel_url).map_err(|error| {
        FlowersecError::new(
            Path::Tunnel,
            Stage::Validate,
            ErrorCode::MISSING_TUNNEL_URL,
            "invalid tunnel URL",
        )
        .with_source(error)
    })?;
    let psk = decode_psk(&grant.e2ee_psk_b64u)?;
    options
        .transport_security_policy
        .evaluate(&url, Path::Tunnel)
        .await?;
    let transport = connect_native(&url, options.origin.as_deref(), options.connect_timeout)
        .await
        .map_err(|error| endpoint_error(Path::Tunnel, Stage::Connect, error))?;
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
    transport
        .send(WebSocketMessage {
            kind: WebSocketMessageKind::Text,
            payload: serde_json::to_vec(&attach)
                .map_err(|error| {
                    FlowersecError::new(
                        Path::Tunnel,
                        Stage::Attach,
                        ErrorCode::ATTACH_FAILED,
                        "failed to encode tunnel attach",
                    )
                    .with_source(error)
                })?
                .into(),
        })
        .await
        .map_err(|error| endpoint_error(Path::Tunnel, Stage::Attach, error))?;
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
) -> Result<Session, FlowersecError> {
    let secure = tokio::time::timeout(
        handshake_timeout,
        server_handshake(transport, cache, handshake),
    )
    .await
    .map_err(|_| {
        FlowersecError::new(
            path,
            Stage::Handshake,
            ErrorCode::TIMEOUT,
            "endpoint E2EE handshake timed out",
        )
    })?
    .map_err(|error| {
        FlowersecError::new(
            path,
            Stage::Handshake,
            ErrorCode::HANDSHAKE_FAILED,
            "endpoint E2EE handshake failed",
        )
        .with_source(error)
    })?;
    let yamux = YamuxSession::new(Arc::new(secure), Mode::Server, limits).map_err(|error| {
        FlowersecError::new(
            path,
            Stage::Yamux,
            ErrorCode::OPEN_STREAM_FAILED,
            "endpoint Yamux setup failed",
        )
        .with_source(error)
    })?;
    Ok(Session { path, yamux })
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

fn suite_from_e2ee(suite: e2ee_wire::Suite) -> Suite {
    match suite {
        e2ee_wire::Suite::X25519HkdfSha256Aes256Gcm => Suite::X25519HkdfSha256Aes256Gcm,
        e2ee_wire::Suite::P256HkdfSha256Aes256Gcm => Suite::P256HkdfSha256Aes256Gcm,
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
        sync::atomic::{AtomicBool, Ordering},
    };

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

    fn message(kind: WebSocketMessageKind, payload: impl Into<Bytes>) -> Arc<FakeTransport> {
        Arc::new(FakeTransport::with_message(WebSocketMessage {
            kind,
            payload: payload.into(),
        }))
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
        let init = e2ee_wire::E2EE_Init {
            channel_id: "channel-resolver".to_owned(),
            role: e2ee_wire::Role::Client,
            version: 1,
            suite: e2ee_wire::Suite::P256HkdfSha256Aes256Gcm,
            client_eph_pub_b64u: "unused".to_owned(),
            nonce_c_b64u: "unused".to_owned(),
            client_features: 7,
        };
        let transport = message(
            WebSocketMessageKind::Binary,
            encode_handshake_frame(
                crate::e2ee::HANDSHAKE_TYPE_INIT,
                &serde_json::to_vec(&init).unwrap(),
            ),
        );
        let error =
            accept_direct_resolved(transport, &RejectingResolver, EndpointOptions::default())
                .await
                .expect_err("resolver failure");
        assert_eq!(error.stage, Stage::Validate);
        assert_eq!(error.code.as_str(), ErrorCode::RESOLVE_FAILED);
        assert!(error.source.is_some());
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
        assert_eq!(
            suite_from_e2ee(e2ee_wire::Suite::X25519HkdfSha256Aes256Gcm),
            Suite::X25519HkdfSha256Aes256Gcm
        );
        assert_eq!(
            suite_from_e2ee(e2ee_wire::Suite::P256HkdfSha256Aes256Gcm),
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
        assert!(format!("{:?}", EndpointOptions::default()).contains("handshake_cache"));
    }
}
