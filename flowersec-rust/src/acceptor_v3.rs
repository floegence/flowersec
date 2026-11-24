//! Production direct-listener runtime for strict Flowersec v5 artifacts.

use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flowersec_native_transport::{PathProfile as NativePathProfile, RawQuicError};
use futures_util::FutureExt;
use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use crate::{
    artifact_v3::{
        Artifact, ArtifactLease, CarrierWireV3, ConnectionPlanV3, ConsumedArtifactLeaseV3,
        EncodedFsb3, acceptor_admissions_hash, decode_direct_fsb3,
    },
    raw_quic_v3::RawQuicListenerV3,
    session_handlers::{AcceptedSession, SessionHandlerSnapshot, SessionHandlers, rpc_router_v3},
    session_v3::{
        DEFAULT_RPC_CONCURRENCY, RpcFrameLimit, SessionConfigV3, SessionDeadlinesV3,
        establish_session_with_limit,
    },
    transport::Session,
    transport_v3::{
        CarrierKind, CarrierSessionV3, CarrierStreamV3, PathKind, SessionRole,
        carrier_inbound_stream_limit_v3,
    },
    websocket_v3::WebSocketListener,
};

const FSB5_HEADER_BYTES: usize = 12;
const MAX_FSB5_PAYLOAD_BYTES: usize = 32 * 1024;
const FSA5_SUCCESS: &[u8; 8] = b"FSA5\x05\x00\x00\x00";
const FSA5_EXPIRED: &[u8; 24] = b"FSA5\x05\x02\x00\x10expired_artifact";

/// Immutable handlers for one authorization policy. Clone to share registrations.
#[derive(Clone)]
pub struct DirectHandlers(Arc<SessionHandlerSnapshot>);

impl DirectHandlers {
    pub fn new(handlers: SessionHandlers) -> Self {
        Self(handlers.into_snapshot())
    }
}

impl fmt::Debug for DirectHandlers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectHandlers { <opaque> }")
    }
}

/// Lookup uses an untrusted routing hint. The SDK verifies the complete admission
/// before spending the returned lease. Its callback must atomically check and
/// consume current authorization in the host store, including expiry/revocation.
#[async_trait::async_trait]
pub trait DirectAuthorizer: Send + Sync + 'static {
    async fn lookup(&self, _channel_id: &str) -> Option<(ArtifactLease, DirectHandlers)> {
        None
    }

    async fn lookup_credential(
        &self,
        channel_id: &str,
        _lookup_key: &str,
    ) -> Option<(ArtifactLease, DirectHandlers)> {
        self.lookup(channel_id).await
    }

    /// Optional outbound work; incoming RPC dispatch is already active.
    async fn connected(&self, _channel_id: &str, _session: Arc<dyn Session>) {}
}

/// Runtime-owned raw QUIC bind, TLS identity, and resource policy.
pub struct AcceptorOptions {
    pub bind_address: SocketAddr,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
    pub max_inbound_streams: u16,
    pub accept_timeout: Duration,
}

/// Runtime-owned WSS bind, TLS identity, origin, and resource policy.
pub struct WebSocketAcceptorOptions {
    pub bind_address: SocketAddr,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
    pub allowed_origins: Vec<String>,
    pub max_inbound_streams: u16,
    pub accept_timeout: Duration,
}

impl fmt::Debug for AcceptorOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptorOptions")
            .field("bind_address", &self.bind_address)
            .field("certificate_chain_der", &"[REDACTED]")
            .field("private_key_der", &"[REDACTED]")
            .field("max_inbound_streams", &self.max_inbound_streams)
            .field("accept_timeout", &self.accept_timeout)
            .finish()
    }
}

impl fmt::Debug for WebSocketAcceptorOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketAcceptorOptions")
            .field("bind_address", &self.bind_address)
            .field("certificate_chain_der", &"[REDACTED]")
            .field("private_key_der", &"[REDACTED]")
            .field("allowed_origins", &"[REDACTED]")
            .field("max_inbound_streams", &self.max_inbound_streams)
            .field("accept_timeout", &self.accept_timeout)
            .finish()
    }
}

/// Stable, redacted direct-acceptance failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptErrorCode {
    InvalidInput,
    RuntimeUnsupported,
    Expired,
    AlreadyRegistered,
    Busy,
    BindFailed,
    Closed,
    Timeout,
    Canceled,
    HandshakeFailed,
    ArtifactSpendFailed,
}

impl AcceptErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::RuntimeUnsupported => "runtime_unsupported",
            Self::Expired => "expired_artifact",
            Self::AlreadyRegistered => "already_registered",
            Self::Busy => "busy",
            Self::BindFailed => "bind_failed",
            Self::Closed => "closed",
            Self::Timeout => "timeout",
            Self::Canceled => "canceled",
            Self::HandshakeFailed => "handshake_failed",
            Self::ArtifactSpendFailed => "artifact_spend_failed",
        }
    }
}

impl fmt::Display for AcceptErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted direct-acceptance failure without artifact or peer diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec session acceptance failed (code={code})")]
pub struct AcceptError {
    code: AcceptErrorCode,
}

impl AcceptError {
    pub const fn code(&self) -> AcceptErrorCode {
        self.code
    }
}

/// Accepts strict v3 direct sessions without exposing carrier or wire state.
pub struct Acceptor {
    leaf: Vec<u8>,
    public_endpoint: Option<String>,
    rpc_frame_limit: RpcFrameLimit,
    rpc_concurrency: NonZeroU16,
    listener: AcceptorListener,
    carrier: CarrierKind,
    max_inbound_streams: u16,
    accept_timeout: Duration,
    accept_gate: AsyncMutex<()>,
    registrations: Mutex<RegistrationRegistry>,
}

enum AcceptorListener {
    WebTransport(crate::webtransport_v5::Listener),
    RawQuic(RawQuicListenerV3),
    WebSocket(WebSocketListener),
}

impl AcceptorListener {
    fn local_address(&self) -> io::Result<SocketAddr> {
        match self {
            Self::WebTransport(listener) => listener.local_address(),
            Self::RawQuic(listener) => listener.local_address().map_err(io::Error::other),
            Self::WebSocket(listener) => listener.local_addr(),
        }
    }

    async fn accept(&self) -> io::Result<Arc<dyn CarrierSessionV3>> {
        match self {
            Self::WebTransport(listener) => listener.accept().await.map(|(session, _)| session),
            Self::RawQuic(listener) => listener
                .accept()
                .await
                .map(|(carrier, _)| carrier)
                .map_err(io::Error::other),
            Self::WebSocket(listener) => listener.accept().await.map_err(io::Error::other),
        }
    }
}

impl Acceptor {
    /// Accepts the policy's HTTP/3 WebTransport profile on a dedicated UDP endpoint.
    pub fn bind_webtransport(
        mut options: AcceptorOptions,
        policy: crate::WebTransportListenerPolicy,
    ) -> Result<Self, AcceptError> {
        let socket = std::net::UdpSocket::bind(options.bind_address)
            .map_err(|_| error(AcceptErrorCode::BindFailed))?;
        options.bind_address = socket
            .local_addr()
            .map_err(|_| error(AcceptErrorCode::BindFailed))?;
        Self::bind_webtransport_on_socket(socket, options, policy)
    }

    /// Takes ownership of a UDP socket whose address matches the configured bind address.
    pub fn bind_webtransport_on_socket(
        socket: std::net::UdpSocket,
        options: AcceptorOptions,
        policy: crate::WebTransportListenerPolicy,
    ) -> Result<Self, AcceptError> {
        validate_common(options.max_inbound_streams, options.accept_timeout)?;
        let leaf = options
            .certificate_chain_der
            .first()
            .cloned()
            .ok_or_else(|| error(AcceptErrorCode::InvalidInput))?;
        let listener = crate::webtransport_v5::Listener::new(
            socket,
            options.bind_address,
            options.certificate_chain_der,
            options.private_key_der,
            policy,
            crate::webtransport_v5::DIRECT,
            options.max_inbound_streams,
            options.accept_timeout,
        )
        .map_err(|_| error(AcceptErrorCode::InvalidInput))?;
        Ok(Self::new(
            AcceptorListener::WebTransport(listener),
            leaf,
            CarrierKind::WebTransport,
            options.max_inbound_streams,
            options.accept_timeout,
        ))
    }

    /// Binds a production strict-v3 raw QUIC direct listener.
    pub fn bind(options: AcceptorOptions) -> Result<Self, AcceptError> {
        validate_common(options.max_inbound_streams, options.accept_timeout)?;
        let leaf = options
            .certificate_chain_der
            .first()
            .cloned()
            .ok_or_else(|| error(AcceptErrorCode::InvalidInput))?;
        let listener = RawQuicListenerV3::bind(
            options.bind_address,
            NativePathProfile::Direct,
            options.certificate_chain_der,
            options.private_key_der,
            options.max_inbound_streams,
            options.accept_timeout,
        )
        .map_err(|_| error(AcceptErrorCode::BindFailed))?;
        Ok(Self::new(
            AcceptorListener::RawQuic(listener),
            leaf,
            CarrierKind::RawQuic,
            options.max_inbound_streams,
            options.accept_timeout,
        ))
    }

    /// Binds a production strict-v3 WSS direct listener.
    pub fn bind_websocket(options: WebSocketAcceptorOptions) -> Result<Self, AcceptError> {
        validate_common(options.max_inbound_streams, options.accept_timeout)?;
        let capacity = carrier_inbound_stream_limit_v3(options.max_inbound_streams)
            .map_err(|_| error(AcceptErrorCode::InvalidInput))?;
        let leaf = options
            .certificate_chain_der
            .first()
            .cloned()
            .ok_or_else(|| error(AcceptErrorCode::InvalidInput))?;
        let listener = WebSocketListener::bind_direct(
            options.bind_address,
            options.certificate_chain_der,
            options.private_key_der,
            options.allowed_origins,
            capacity,
        )
        .map_err(|_| error(AcceptErrorCode::BindFailed))?;
        Ok(Self::new(
            AcceptorListener::WebSocket(listener),
            leaf,
            CarrierKind::Wss,
            options.max_inbound_streams,
            options.accept_timeout,
        ))
    }

    fn new(
        listener: AcceptorListener,
        leaf: Vec<u8>,
        carrier: CarrierKind,
        max_inbound_streams: u16,
        accept_timeout: Duration,
    ) -> Self {
        Self {
            listener,
            leaf,
            public_endpoint: None,
            rpc_frame_limit: RpcFrameLimit::default(),
            rpc_concurrency: DEFAULT_RPC_CONCURRENCY,
            carrier,
            max_inbound_streams,
            accept_timeout,
            accept_gate: AsyncMutex::new(()),
            registrations: Mutex::new(RegistrationRegistry::default()),
        }
    }

    pub fn local_address(&self) -> Result<SocketAddr, AcceptError> {
        self.listener
            .local_address()
            .map_err(|_| error(AcceptErrorCode::BindFailed))
    }

    pub fn with_rpc_frame_limit(mut self, limit: RpcFrameLimit) -> Self {
        self.rpc_frame_limit = limit;
        self
    }

    /// Sets the trusted public direct URL for a forwarded or multi-name listener.
    pub fn with_public_endpoint(mut self, endpoint: &str) -> Result<Self, AcceptError> {
        let carrier = match self.carrier {
            CarrierKind::RawQuic => CarrierWireV3::RawQuic,
            CarrierKind::Wss => CarrierWireV3::Websocket,
            CarrierKind::WebTransport => CarrierWireV3::Webtransport,
        };
        self.public_endpoint = Some(
            crate::artifact_v3::normalize_url_v3("direct", carrier, endpoint)
                .map_err(|_| error(AcceptErrorCode::InvalidInput))?,
        );
        Ok(self)
    }

    fn matched_binding(&self, plan: &AcceptPlanV3, raw: &[u8]) -> Option<[u8; 32]> {
        let frame = plan.expected_fsb3.iter().find(|frame| {
            frame.raw.len() == raw.len() && bool::from(frame.raw.as_slice().ct_eq(raw))
        })?;
        let candidate = plan
            .connection
            .candidates
            .iter()
            .find(|candidate| candidate.id == frame.chosen_candidate_id)?;
        crate::tls_v3::matches_listener(
            candidate,
            self.local_address().ok()?,
            self.public_endpoint.as_deref(),
            &self.leaf,
            unix_seconds(),
        )
        .then_some(frame.binding)
    }

    /// Limits simultaneous outgoing calls and running inbound RPC handlers per session.
    pub fn with_rpc_concurrency(mut self, limit: NonZeroU16) -> Self {
        self.rpc_concurrency = limit;
        self
    }

    /// Serves a shared listener from zero invitations. Only incoming carriers
    /// occupy worker slots; issuing an invitation does not start any SDK task.
    pub async fn serve(
        self,
        authorizer: Arc<dyn DirectAuthorizer>,
        max_sessions: NonZeroUsize,
        cancellation: CancellationToken,
    ) -> Result<(), AcceptError> {
        let shutdown = cancellation.child_token();
        let _cancel_on_drop = shutdown.clone().drop_guard();
        tokio::spawn(self.run_listener(authorizer, max_sessions, shutdown))
            .await
            .map_err(|_| error(AcceptErrorCode::Closed))?
    }

    async fn run_listener(
        self,
        authorizer: Arc<dyn DirectAuthorizer>,
        max_sessions: NonZeroUsize,
        shutdown: CancellationToken,
    ) -> Result<(), AcceptError> {
        let this = Arc::new(self);
        let mut workers = tokio::task::JoinSet::new();
        let result = 'listen: loop {
            let next = this.listener.accept();
            tokio::pin!(next);
            let carrier = loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break 'listen Ok(()),
                    _ = workers.join_next(), if !workers.is_empty() => {},
                    result = &mut next => match result {
                        Ok(carrier) => break carrier,
                        Err(ref cause) if cause.get_ref().and_then(|e| e.downcast_ref::<RawQuicError>()).is_some_and(|e| matches!(e, RawQuicError::Handshake | RawQuicError::Timeout)) => continue 'listen,
                        Err(_) => break 'listen Err(error(AcceptErrorCode::Closed)),
                    },
                }
            };
            if workers.len() >= max_sessions.get() {
                carrier.abort();
                continue;
            }
            let this = this.clone();
            let authorizer = authorizer.clone();
            let shutdown = shutdown.clone();
            workers.spawn(async move {
                let deadline = tokio::time::Instant::now() + this.accept_timeout;
                let (worker, cleanup) = tokio::sync::oneshot::channel();
                let result = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => None,
                    result = tokio::time::timeout_at(deadline, this.accept_authorized(
                        carrier.clone(), authorizer.as_ref(), deadline, &shutdown, worker,
                    )) => result.ok().and_then(Result::ok),
                };
                let Some((accepted, channel_id)) = result else {
                    carrier.abort();
                    let _ = cleanup.await;
                    return;
                };
                let application = async {
                    tokio::select! {
                        _ = shutdown.cancelled() => {},
                        _ = accepted.session().wait_termination() => {},
                        callback = std::panic::AssertUnwindSafe(authorizer.connected(&channel_id, accepted.shared_session())).catch_unwind() => {
                            if callback.is_err() { let _ = accepted.session().close().await; }
                        },
                    }
                };
                let _ = tokio::join!(accepted.serve(shutdown.clone()), application);
                let _ = cleanup.await;
            });
        };
        shutdown.cancel();
        while workers.join_next().await.is_some() {}
        if let AcceptorListener::RawQuic(listener) = &this.listener {
            listener.close().await;
        }
        if let AcceptorListener::WebTransport(listener) = &this.listener {
            listener.close().await;
        }
        result
    }

    async fn accept_authorized(
        &self,
        carrier: Arc<dyn CarrierSessionV3>,
        authorizer: &dyn DirectAuthorizer,
        deadline: tokio::time::Instant,
        cancellation: &CancellationToken,
        worker: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(AcceptedSession, String), AcceptErrorCode> {
        let stream = carrier
            .listener_admission()
            .await
            .map_err(|_| AcceptErrorCode::HandshakeFailed)?;
        let raw = read_fsb3(stream.as_ref(), deadline, cancellation).await?;
        let (channel_id, lookup_key) =
            decode_direct_fsb3(&raw).map_err(|_| AcceptErrorCode::HandshakeFailed)?;
        let (lease, handlers) = authorizer
            .lookup_credential(&channel_id, &lookup_key)
            .await
            .ok_or(AcceptErrorCode::HandshakeFailed)?;
        let plan =
            accept_plan(lease.artifact_for_connector(), self.carrier).map_err(|e| e.code())?;
        let capacity = carrier_inbound_stream_limit_v3(self.max_inbound_streams)
            .map_err(|_| AcceptErrorCode::InvalidInput)?;
        if self.max_inbound_streams != plan.connection.session.max_inbound_streams
            || carrier.inbound_bidirectional_stream_capacity() != capacity
        {
            return Err(AcceptErrorCode::HandshakeFailed);
        }
        let binding = self
            .matched_binding(&plan, &raw)
            .ok_or(AcceptErrorCode::HandshakeFailed)?;
        if unix_seconds() >= plan.connection.expires_at_unix_seconds {
            return Err(AcceptErrorCode::Expired);
        }
        let consumed = spend_direct(
            &lease,
            carrier.clone(),
            plan.connection.expires_at_unix_seconds,
            deadline,
            cancellation,
            Some(worker),
        )
        .await?;
        write_all(stream.as_ref(), FSA5_SUCCESS, deadline, cancellation).await?;
        stream
            .close_write_delivered()
            .await
            .map_err(|_| AcceptErrorCode::HandshakeFailed)?;
        if self.carrier == CarrierKind::Wss {
            carrier
                .set_multiplexer_client(false)
                .map_err(|_| AcceptErrorCode::HandshakeFailed)?;
        }
        let config = session_config(
            &plan.connection,
            binding,
            Some(rpc_router_v3(handlers.0.rpc.clone())),
        );
        let session = establish_session_with_limit(
            carrier,
            config,
            self.rpc_frame_limit,
            self.rpc_concurrency,
            Some(consumed),
        )
        .await
        .map_err(|_| AcceptErrorCode::HandshakeFailed)?;
        Ok((AcceptedSession::new(session, handlers.0), channel_id))
    }

    pub async fn accept(
        &self,
        lease: &ArtifactLease,
        cancellation: CancellationToken,
    ) -> Result<Arc<dyn Session>, AcceptError> {
        self.accept_session(lease, cancellation, None).await
    }

    pub async fn accept_with_handlers(
        &self,
        lease: &ArtifactLease,
        handlers: SessionHandlers,
        cancellation: CancellationToken,
    ) -> Result<AcceptedSession, AcceptError> {
        let handlers = handlers.into_snapshot();
        let rpc_handler = rpc_router_v3(handlers.rpc.clone());
        let session = self
            .accept_session(lease, cancellation, Some(rpc_handler))
            .await?;
        Ok(AcceptedSession::new(session, handlers))
    }

    async fn accept_session(
        &self,
        lease: &ArtifactLease,
        cancellation: CancellationToken,
        rpc_handler: Option<Arc<dyn crate::session_v3::RpcHandlerV3>>,
    ) -> Result<Arc<dyn Session>, AcceptError> {
        let plan = accept_plan(lease.artifact_for_connector(), self.carrier)?;
        if plan.connection.session.max_inbound_streams != self.max_inbound_streams {
            return Err(error(AcceptErrorCode::InvalidInput));
        }
        let now = unix_seconds();
        let expiry = plan
            .connection
            .expires_at_unix_seconds
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| error(AcceptErrorCode::Expired))?;
        let operation_timeout = self.accept_timeout.min(Duration::from_secs(expiry));
        {
            let mut registrations = self
                .registrations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registrations
                .begin(plan.registration_id, now + expiry, now)
                .map_err(error)?;
        }

        let _registration = RegistrationGuard {
            registry: &self.registrations,
            id: plan.registration_id,
            lease,
        };
        let deadline = tokio::time::Instant::now() + operation_timeout;
        let gate = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(error(AcceptErrorCode::Canceled)),
            result = tokio::time::timeout_at(deadline, self.accept_gate.lock()) => {
                result.map_err(|_| error(AcceptErrorCode::Timeout))
            }
        };
        match gate {
            Ok(_guard) => {
                self.accept_registered(plan, lease, cancellation, deadline, rpc_handler)
                    .await
            }
            Err(failure) => Err(failure),
        }
    }

    async fn accept_registered(
        &self,
        plan: AcceptPlanV3,
        lease: &ArtifactLease,
        cancellation: CancellationToken,
        deadline: tokio::time::Instant,
        rpc_handler: Option<Arc<dyn crate::session_v3::RpcHandlerV3>>,
    ) -> Result<Arc<dyn Session>, AcceptError> {
        loop {
            let carrier = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(error(AcceptErrorCode::Canceled)),
                accepted = tokio::time::timeout_at(deadline, self.listener.accept()) => match accepted {
                    Err(_) => return Err(error(AcceptErrorCode::Timeout)),
                    Ok(Err(_)) => return Err(error(AcceptErrorCode::Closed)),
                    Ok(Ok(carrier)) => carrier,
                },
            };
            let (admission, consumed) = match admit_direct(
                carrier.clone(),
                lease,
                |raw| self.matched_binding(&plan, raw),
                plan.connection.session.max_inbound_streams,
                plan.connection.expires_at_unix_seconds,
                deadline,
                &cancellation,
            )
            .await
            {
                Ok(Some(binding)) => binding,
                Ok(None) => continue,
                Err(code) => {
                    carrier.abort();
                    return Err(error(code));
                }
            };
            if self.carrier == CarrierKind::Wss && carrier.set_multiplexer_client(false).is_err() {
                carrier.abort();
                return Err(error(AcceptErrorCode::HandshakeFailed));
            }
            let config = session_config(&plan.connection, admission, rpc_handler.clone());
            let established = tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(error(AcceptErrorCode::Canceled)),
                result = tokio::time::timeout_at(deadline, establish_session_with_limit(carrier.clone(), config, self.rpc_frame_limit, self.rpc_concurrency, Some(consumed))) => match result {
                    Err(_) => Err(error(AcceptErrorCode::Timeout)),
                    Ok(Err(_)) => Err(error(AcceptErrorCode::HandshakeFailed)),
                    Ok(Ok(session)) => Ok(session),
                }
            };
            if established.is_err() {
                carrier.abort();
            }
            return established;
        }
    }
}

impl fmt::Debug for Acceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Acceptor { <opaque> }")
    }
}

struct AcceptPlanV3 {
    connection: ConnectionPlanV3,
    expected_fsb3: Vec<EncodedFsb3>,
    registration_id: [u8; 32],
}

fn accept_plan(artifact: &Artifact, carrier: CarrierKind) -> Result<AcceptPlanV3, AcceptError> {
    let mut connection = artifact
        .connection_plan()
        .map_err(|_| error(AcceptErrorCode::InvalidInput))?;
    if connection.path != PathKind::Direct {
        return Err(error(AcceptErrorCode::InvalidInput));
    }
    let all_fsb3 = connection
        .candidates
        .iter()
        .map(|candidate| {
            artifact
                .encode_fsb3(&candidate.id)
                .map(|frame| (candidate_carrier(candidate.carrier), frame))
                .map_err(|_| error(AcceptErrorCode::InvalidInput))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if all_fsb3.is_empty() {
        return Err(error(AcceptErrorCode::RuntimeUnsupported));
    }
    let expected_fsb3 = all_fsb3
        .iter()
        .filter(|(candidate_carrier, _)| *candidate_carrier == carrier)
        .map(|(_, frame)| frame.clone())
        .collect::<Vec<_>>();
    if expected_fsb3.is_empty() {
        return Err(error(AcceptErrorCode::RuntimeUnsupported));
    }
    let registration_id = acceptor_admissions_hash(
        &all_fsb3
            .iter()
            .map(|(_, frame)| frame.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| error(AcceptErrorCode::InvalidInput))?;
    connection.role = SessionRole::Server;
    Ok(AcceptPlanV3 {
        connection,
        expected_fsb3,
        registration_id,
    })
}

fn candidate_carrier(carrier: CarrierWireV3) -> CarrierKind {
    match carrier {
        CarrierWireV3::Websocket => CarrierKind::Wss,
        CarrierWireV3::RawQuic => CarrierKind::RawQuic,
        CarrierWireV3::Webtransport => CarrierKind::WebTransport,
    }
}

fn session_config(
    plan: &ConnectionPlanV3,
    admission_binding: [u8; 32],
    rpc_handler: Option<Arc<dyn crate::session_v3::RpcHandlerV3>>,
) -> SessionConfigV3 {
    SessionConfigV3 {
        role: SessionRole::Server,
        path: PathKind::Direct,
        channel_id: plan.session.channel_id.clone(),
        session_contract_hash: plan.session.session_contract_hash,
        suite: plan.session.suite,
        psk: plan.session.psk,
        max_inbound_streams: plan.session.max_inbound_streams,
        idle_timeout: plan.session.idle_timeout,
        local_admission_binding: admission_binding,
        peer_admission_binding: Some(admission_binding),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler,
        deadlines: SessionDeadlinesV3 {
            establish: plan.session.establish_timeout,
            rekey_prepare: plan.session.rekey_prepare_timeout,
            rekey_completion: plan.session.rekey_completion_timeout,
            ..Default::default()
        },
    }
}

async fn admit_direct(
    carrier: Arc<dyn CarrierSessionV3>,
    lease: &ArtifactLease,
    match_binding: impl FnOnce(&[u8]) -> Option<[u8; 32]>,
    max_inbound_streams: u16,
    expires_at_unix_seconds: u64,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Option<([u8; 32], ConsumedArtifactLeaseV3)>, AcceptErrorCode> {
    let capacity = carrier_inbound_stream_limit_v3(max_inbound_streams)
        .map_err(|_| AcceptErrorCode::InvalidInput)?;
    if carrier.inbound_bidirectional_stream_capacity() != capacity {
        carrier.abort();
        return Err(AcceptErrorCode::HandshakeFailed);
    }
    let admission = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(AcceptErrorCode::Canceled),
        result = tokio::time::timeout_at(deadline, carrier.listener_admission()) => match result {
            Err(_) => return Err(AcceptErrorCode::Timeout),
            Ok(Err(_)) => return Err(AcceptErrorCode::HandshakeFailed),
            Ok(Ok(stream)) => stream,
        }
    };
    let raw = match read_fsb3(admission.as_ref(), deadline, cancellation).await {
        Ok(raw) => raw,
        Err(code) => {
            let _ = admission.reset().await;
            carrier.abort();
            return Err(code);
        }
    };
    if decode_direct_fsb3(&raw).is_err() {
        let _ = admission.reset().await;
        carrier.abort();
        return Err(AcceptErrorCode::HandshakeFailed);
    }
    let Some(binding) = match_binding(&raw) else {
        let _ = admission.reset().await;
        carrier.abort();
        return Ok(None);
    };
    if unix_seconds() >= expires_at_unix_seconds {
        let response_result = if let Err(code) =
            write_all(admission.as_ref(), FSA5_EXPIRED, deadline, cancellation).await
        {
            Err(code)
        } else {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(AcceptErrorCode::Canceled),
                result = tokio::time::timeout_at(deadline, admission.close_write_delivered()) => match result {
                    Err(_) => Err(AcceptErrorCode::Timeout),
                    Ok(Err(_)) => Err(AcceptErrorCode::HandshakeFailed),
                    Ok(Ok(())) => Ok(()),
                }
            }
        };
        if let Err(code) = response_result {
            let _ = admission.reset().await;
            carrier.abort();
            return Err(code);
        }
        carrier.abort();
        return Err(AcceptErrorCode::Expired);
    }
    let consumed = spend_direct(
        lease,
        carrier.clone(),
        expires_at_unix_seconds,
        deadline,
        cancellation,
        None,
    )
    .await?;
    write_all(admission.as_ref(), FSA5_SUCCESS, deadline, cancellation).await?;
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(AcceptErrorCode::Canceled),
        result = tokio::time::timeout_at(deadline, admission.close_write_delivered()) => match result {
            Err(_) => return Err(AcceptErrorCode::Timeout),
            Ok(Err(_)) => return Err(AcceptErrorCode::HandshakeFailed),
            Ok(Ok(())) => {}
        }
    }
    Ok(Some((binding, consumed)))
}

async fn spend_direct(
    lease: &ArtifactLease,
    carrier: Arc<dyn CarrierSessionV3>,
    expiry: u64,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    worker: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<ConsumedArtifactLeaseV3, AcceptErrorCode> {
    let spend = async {
        lease
            .claim()
            .and_then(|claim| claim.begin_spend())
            .map_err(|_| AcceptErrorCode::ArtifactSpendFailed)?
            .commit_on_carrier(carrier, worker)
            .await
            .map_err(|_| AcceptErrorCode::ArtifactSpendFailed)
    };
    let consumed = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(AcceptErrorCode::Canceled),
        _ = tokio::time::sleep_until(deadline) => return Err(AcceptErrorCode::Timeout),
        result = std::panic::AssertUnwindSafe(spend).catch_unwind() => result.map_err(|_| AcceptErrorCode::ArtifactSpendFailed)??,
    };
    if unix_seconds() >= expiry {
        return Err(AcceptErrorCode::Expired);
    }
    Ok(consumed)
}

async fn read_fsb3(
    stream: &dyn CarrierStreamV3,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, AcceptErrorCode> {
    let mut header = [0_u8; FSB5_HEADER_BYTES];
    read_exact(stream, &mut header, deadline, cancellation).await?;
    if &header[..4] != b"FSB5" || header[4] != 5 || header[5] != 1 || header[6..8] != [0, 0] {
        return Err(AcceptErrorCode::HandshakeFailed);
    }
    let length = u32::from_be_bytes(header[8..12].try_into().expect("fixed header")) as usize;
    if length == 0 || length > MAX_FSB5_PAYLOAD_BYTES {
        return Err(AcceptErrorCode::HandshakeFailed);
    }
    let mut raw = Vec::with_capacity(FSB5_HEADER_BYTES + length);
    raw.extend_from_slice(&header);
    raw.resize(FSB5_HEADER_BYTES + length, 0);
    read_exact(
        stream,
        &mut raw[FSB5_HEADER_BYTES..],
        deadline,
        cancellation,
    )
    .await?;
    let mut trailing = [0_u8; 1];
    let count = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(AcceptErrorCode::Canceled),
        result = tokio::time::timeout_at(deadline, stream.read(&mut trailing)) => match result {
            Err(_) => return Err(AcceptErrorCode::Timeout),
            Ok(Err(_)) => return Err(AcceptErrorCode::HandshakeFailed),
            Ok(Ok(count)) => count,
        }
    };
    if count != 0 {
        return Err(AcceptErrorCode::HandshakeFailed);
    }
    Ok(raw)
}

async fn read_exact(
    stream: &dyn CarrierStreamV3,
    mut output: &mut [u8],
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<(), AcceptErrorCode> {
    while !output.is_empty() {
        let count = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(AcceptErrorCode::Canceled),
            result = tokio::time::timeout_at(deadline, stream.read(output)) => match result {
                Err(_) => return Err(AcceptErrorCode::Timeout),
                Ok(Err(_)) => return Err(AcceptErrorCode::HandshakeFailed),
                Ok(Ok(count)) => count,
            }
        };
        if count == 0 {
            return Err(AcceptErrorCode::HandshakeFailed);
        }
        output = &mut output[count..];
    }
    Ok(())
}

async fn write_all(
    stream: &dyn CarrierStreamV3,
    mut input: &[u8],
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<(), AcceptErrorCode> {
    while !input.is_empty() {
        let count = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(AcceptErrorCode::Canceled),
            result = tokio::time::timeout_at(deadline, stream.write(input)) => match result {
                Err(_) => return Err(AcceptErrorCode::Timeout),
                Ok(Err(_)) => return Err(AcceptErrorCode::HandshakeFailed),
                Ok(Ok(count)) => count,
            }
        };
        if count == 0 {
            return Err(AcceptErrorCode::HandshakeFailed);
        }
        input = &input[count..];
    }
    Ok(())
}

fn validate_common(max_inbound_streams: u16, timeout: Duration) -> Result<(), AcceptError> {
    if timeout.is_zero() || carrier_inbound_stream_limit_v3(max_inbound_streams).is_err() {
        return Err(error(AcceptErrorCode::InvalidInput));
    }
    Ok(())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const fn error(code: AcceptErrorCode) -> AcceptError {
    AcceptError { code }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationState {
    InFlight,
    Consumed,
}

#[derive(Clone, Copy, Debug)]
struct Registration {
    expires_at_unix_seconds: u64,
    state: RegistrationState,
}

#[derive(Default)]
struct RegistrationRegistry {
    entries: HashMap<[u8; 32], Registration>,
}

struct RegistrationGuard<'a> {
    registry: &'a Mutex<RegistrationRegistry>,
    id: [u8; 32],
    lease: &'a ArtifactLease,
}

impl Drop for RegistrationGuard<'_> {
    fn drop(&mut self) {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .finish(&self.id, self.lease.spend_attempted());
    }
}

impl RegistrationRegistry {
    fn begin(&mut self, id: [u8; 32], expiry: u64, now: u64) -> Result<(), AcceptErrorCode> {
        self.entries.retain(|_, value| {
            value.state == RegistrationState::InFlight || value.expires_at_unix_seconds > now
        });
        if self.entries.contains_key(&id) {
            return Err(AcceptErrorCode::AlreadyRegistered);
        }
        if self
            .entries
            .values()
            .any(|value| value.state == RegistrationState::InFlight)
        {
            return Err(AcceptErrorCode::Busy);
        }
        self.entries.insert(
            id,
            Registration {
                expires_at_unix_seconds: expiry,
                state: RegistrationState::InFlight,
            },
        );
        Ok(())
    }

    fn finish(&mut self, id: &[u8; 32], succeeded: bool) {
        if succeeded {
            if let Some(value) = self.entries.get_mut(id) {
                value.state = RegistrationState::Consumed;
            }
        } else {
            self.entries.remove(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_v3::{AdmissionStatusV3, decode_fsa3};

    #[test]
    fn expired_admission_response_is_retryable_and_audited() {
        let response = decode_fsa3(FSA5_EXPIRED).expect("canonical expired FSA5");
        assert_eq!(response.status, AdmissionStatusV3::Retryable);
        assert_eq!(response.reason, "expired_artifact");
    }

    #[test]
    fn websocket_options_debug_redacts_tls_material_and_origins() {
        let options = WebSocketAcceptorOptions {
            bind_address: "127.0.0.1:43210".parse().unwrap(),
            certificate_chain_der: vec![b"certificate-sentinel".to_vec()],
            private_key_der: b"private-key-sentinel".to_vec(),
            allowed_origins: vec!["https://origin-sentinel.example".into()],
            max_inbound_streams: 7,
            accept_timeout: Duration::from_secs(11),
        };
        let debug = format!("{options:?}");
        for secret in [
            "certificate-sentinel",
            "private-key-sentinel",
            "origin-sentinel",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("127.0.0.1:43210"));
        assert!(debug.contains("max_inbound_streams: 7"));
        assert!(debug.contains("accept_timeout: 11s"));
    }
}
