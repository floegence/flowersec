//! Production direct-listener runtime for strict Flowersec v3 artifacts.

use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flowersec_native_transport::PathProfile as NativePathProfile;
use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use crate::{
    artifact_v3::{
        Artifact, CarrierWireV3, ConnectionPlanV3, EncodedFsb3, acceptor_admissions_hash,
        decode_direct_fsb3,
    },
    raw_quic_v3::RawQuicListenerV3,
    session_handlers::{AcceptedSession, SessionHandlers, rpc_router_v3},
    session_v3::{SessionConfigV3, SessionDeadlinesV3, establish_session_v3},
    transport::Session,
    transport_v3::{
        CarrierKind, CarrierSessionV3, CarrierStreamV3, PathKind, SessionRole,
        carrier_inbound_stream_limit_v3,
    },
    websocket_v3::WebSocketListener,
};

const FSB3_HEADER_BYTES: usize = 12;
const MAX_FSB3_PAYLOAD_BYTES: usize = 32 * 1024;
const FSA3_SUCCESS: &[u8; 8] = b"FSA3\x03\x00\x00\x00";
const FSA3_EXPIRED: &[u8; 24] = b"FSA3\x03\x02\x00\x10expired_artifact";

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
    listener: AcceptorListener,
    carrier: CarrierKind,
    max_inbound_streams: u16,
    accept_timeout: Duration,
    accept_gate: AsyncMutex<()>,
    registrations: Mutex<RegistrationRegistry>,
}

enum AcceptorListener {
    RawQuic(RawQuicListenerV3),
    WebSocket(WebSocketListener),
}

impl AcceptorListener {
    fn local_address(&self) -> io::Result<SocketAddr> {
        match self {
            Self::RawQuic(listener) => listener.local_address().map_err(io::Error::other),
            Self::WebSocket(listener) => listener.local_addr(),
        }
    }

    async fn accept(&self) -> io::Result<Arc<dyn CarrierSessionV3>> {
        match self {
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
    /// Binds a production strict-v3 raw QUIC direct listener.
    pub fn bind(options: AcceptorOptions) -> Result<Self, AcceptError> {
        validate_common(options.max_inbound_streams, options.accept_timeout)?;
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
            CarrierKind::Wss,
            options.max_inbound_streams,
            options.accept_timeout,
        ))
    }

    fn new(
        listener: AcceptorListener,
        carrier: CarrierKind,
        max_inbound_streams: u16,
        accept_timeout: Duration,
    ) -> Self {
        Self {
            listener,
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

    pub async fn accept(
        &self,
        artifact: &Artifact,
        cancellation: CancellationToken,
    ) -> Result<Arc<dyn Session>, AcceptError> {
        self.accept_session(artifact, cancellation, None).await
    }

    pub async fn accept_with_handlers(
        &self,
        artifact: &Artifact,
        handlers: SessionHandlers,
        cancellation: CancellationToken,
    ) -> Result<AcceptedSession, AcceptError> {
        let handlers = handlers.into_snapshot();
        let rpc_handler = rpc_router_v3(handlers.rpc.clone());
        let session = self
            .accept_session(artifact, cancellation, Some(rpc_handler))
            .await?;
        Ok(AcceptedSession::new(session, handlers))
    }

    async fn accept_session(
        &self,
        artifact: &Artifact,
        cancellation: CancellationToken,
        rpc_handler: Option<Arc<dyn crate::session_v3::RpcHandlerV3>>,
    ) -> Result<Arc<dyn Session>, AcceptError> {
        let plan = accept_plan(artifact, self.carrier)?;
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

        let registration_id = plan.registration_id;
        let deadline = tokio::time::Instant::now() + operation_timeout;
        let gate = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(error(AcceptErrorCode::Canceled)),
            result = tokio::time::timeout_at(deadline, self.accept_gate.lock()) => {
                result.map_err(|_| error(AcceptErrorCode::Timeout))
            }
        };
        let result = match gate {
            Ok(_guard) => {
                self.accept_registered(plan, cancellation, deadline, rpc_handler)
                    .await
            }
            Err(failure) => Err(failure),
        };
        self.registrations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .finish(&registration_id, result.is_ok());
        result
    }

    async fn accept_registered(
        &self,
        plan: AcceptPlanV3,
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
            let admission = match admit_direct(
                carrier.clone(),
                &plan.expected_fsb3,
                plan.connection.session.max_inbound_streams,
                plan.connection.expires_at_unix_seconds,
                deadline,
                &cancellation,
            )
            .await
            {
                Ok(Some(binding)) => binding,
                Ok(None) => continue,
                Err(code) => return Err(error(code)),
            };
            if self.carrier == CarrierKind::Wss && carrier.set_multiplexer_client(false).is_err() {
                carrier.abort();
                return Err(error(AcceptErrorCode::HandshakeFailed));
            }
            let config = session_config(&plan.connection, admission, rpc_handler.clone());
            let established = tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(error(AcceptErrorCode::Canceled)),
                result = tokio::time::timeout_at(deadline, establish_session_v3(carrier.clone(), config)) => match result {
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
    expected: &[EncodedFsb3],
    max_inbound_streams: u16,
    expires_at_unix_seconds: u64,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Option<[u8; 32]>, AcceptErrorCode> {
    let capacity = carrier_inbound_stream_limit_v3(max_inbound_streams)
        .map_err(|_| AcceptErrorCode::InvalidInput)?;
    if carrier.inbound_bidirectional_stream_capacity() != capacity {
        carrier.abort();
        return Err(AcceptErrorCode::HandshakeFailed);
    }
    let admission = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(AcceptErrorCode::Canceled),
        result = tokio::time::timeout_at(deadline, carrier.accept_stream()) => match result {
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
    let Some(matched) = expected.iter().find(|candidate| {
        candidate.raw.len() == raw.len()
            && bool::from(candidate.raw.as_slice().ct_eq(raw.as_slice()))
    }) else {
        let _ = admission.reset().await;
        carrier.abort();
        return Ok(None);
    };
    if unix_seconds() >= expires_at_unix_seconds {
        let response_result = if let Err(code) =
            write_all(admission.as_ref(), FSA3_EXPIRED, deadline, cancellation).await
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
    write_all(admission.as_ref(), FSA3_SUCCESS, deadline, cancellation).await?;
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(AcceptErrorCode::Canceled),
        result = tokio::time::timeout_at(deadline, admission.close_write_delivered()) => match result {
            Err(_) => return Err(AcceptErrorCode::Timeout),
            Ok(Err(_)) => return Err(AcceptErrorCode::HandshakeFailed),
            Ok(Ok(())) => {}
        }
    }
    Ok(Some(matched.binding))
}

async fn read_fsb3(
    stream: &dyn CarrierStreamV3,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, AcceptErrorCode> {
    let mut header = [0_u8; FSB3_HEADER_BYTES];
    read_exact(stream, &mut header, deadline, cancellation).await?;
    if &header[..4] != b"FSB3" || header[4] != 3 || header[5] != 1 || header[6..8] != [0, 0] {
        return Err(AcceptErrorCode::HandshakeFailed);
    }
    let length = u32::from_be_bytes(header[8..12].try_into().expect("fixed header")) as usize;
    if length == 0 || length > MAX_FSB3_PAYLOAD_BYTES {
        return Err(AcceptErrorCode::HandshakeFailed);
    }
    let mut raw = Vec::with_capacity(FSB3_HEADER_BYTES + length);
    raw.extend_from_slice(&header);
    raw.resize(FSB3_HEADER_BYTES + length, 0);
    read_exact(
        stream,
        &mut raw[FSB3_HEADER_BYTES..],
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
        let response = decode_fsa3(FSA3_EXPIRED).expect("canonical expired FSA3");
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
