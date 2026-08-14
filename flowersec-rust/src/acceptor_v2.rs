//! Carrier-neutral runtime acceptance for opaque Flowersec v2 artifacts.

use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use crate::{
    admission_v2::{CandidateAttemptV2, ServerAdmissionV2},
    artifact_v2::{Artifact, ConnectionPlanError, ConnectionPlanV2, EncodedFsb2},
    connector_v2::session_config,
    raw_quic_v2::{RawQuicLimits, RawQuicListener, RawQuicPathProfile, RawQuicServerConfig},
    session_handlers::{AcceptedSession, SessionHandlers},
    session_v2::{RpcHandlerV2, establish_session_v2},
    transport_v2::{CarrierKind, CarrierSessionV2, PathKind, Session, SessionRole},
    websocket_v2::WebSocketListener,
};

/// Runtime-owned bind, TLS, and resource policy for direct session acceptance.
pub struct AcceptorOptions {
    pub bind_address: SocketAddr,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
    pub max_inbound_streams: u16,
    pub accept_timeout: Duration,
}

/// Runtime-owned bind, TLS, origin, and resource policy for a direct WebSocket listener.
pub struct WebSocketAcceptorOptions {
    pub bind_address: SocketAddr,
    /// Empty certificate and key values select plaintext loopback-only WebSocket.
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
    pub allowed_origins: Vec<String>,
    pub max_inbound_streams: u16,
    pub accept_timeout: Duration,
}

impl fmt::Debug for WebSocketAcceptorOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketAcceptorOptions")
            .field("bind_address", &self.bind_address)
            .field("certificate_chain_der", &"[REDACTED]")
            .field("private_key_der", &"[REDACTED]")
            .field("allowed_origins", &self.allowed_origins)
            .field("max_inbound_streams", &self.max_inbound_streams)
            .field("accept_timeout", &self.accept_timeout)
            .finish()
    }
}

impl std::fmt::Debug for AcceptorOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// Stable, redacted runtime acceptance failure category.
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
    /// Returns the stable public code string used in redacted error text.
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

/// A redacted runtime acceptance failure without credentials or peer diagnostics.
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

/// Accepts direct sessions from opaque artifacts without exposing carrier state.
pub struct Acceptor {
    listener: AcceptorListener,
    carrier: CarrierKind,
    max_inbound_streams: u16,
    accept_timeout: Duration,
    accept_gate: AsyncMutex<()>,
    registrations: Mutex<HashMap<[u8; 32], bool>>,
}

enum AcceptorListener {
    RawQuic(RawQuicListener),
    WebSocket(WebSocketListener),
}

impl AcceptorListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::RawQuic(listener) => listener.local_addr(),
            Self::WebSocket(listener) => listener.local_addr(),
        }
    }

    async fn accept(&self) -> io::Result<std::sync::Arc<dyn CarrierSessionV2>> {
        match self {
            Self::RawQuic(listener) => listener
                .accept()
                .await
                .map(|session| std::sync::Arc::new(session) as std::sync::Arc<dyn CarrierSessionV2>)
                .map_err(io::Error::other),
            Self::WebSocket(listener) => listener.accept().await.map_err(io::Error::other),
        }
    }
}

impl Acceptor {
    pub fn bind(options: AcceptorOptions) -> Result<Self, AcceptError> {
        if options.accept_timeout.is_zero() {
            return Err(error(AcceptErrorCode::InvalidInput));
        }
        let limits =
            RawQuicLimits::for_session_v2(options.max_inbound_streams, options.accept_timeout)
                .map_err(|_| error(AcceptErrorCode::InvalidInput))?;
        let config = RawQuicServerConfig::new(
            RawQuicPathProfile::Direct,
            options.certificate_chain_der,
            options.private_key_der,
            limits,
        )
        .map_err(|_| error(AcceptErrorCode::InvalidInput))?;
        let listener = RawQuicListener::bind(options.bind_address, config)
            .map_err(|_| error(AcceptErrorCode::BindFailed))?;
        Ok(Self {
            listener: AcceptorListener::RawQuic(listener),
            carrier: CarrierKind::RawQuic,
            max_inbound_streams: options.max_inbound_streams,
            accept_timeout: options.accept_timeout,
            accept_gate: AsyncMutex::new(()),
            registrations: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the effective local address after binding, including an OS-assigned port.
    pub fn local_address(&self) -> Result<SocketAddr, AcceptError> {
        self.listener
            .local_addr()
            .map_err(|_| error(AcceptErrorCode::BindFailed))
    }

    /// Binds a production direct WebSocket listener.
    pub fn bind_websocket(options: WebSocketAcceptorOptions) -> Result<Self, AcceptError> {
        if options.accept_timeout.is_zero() {
            return Err(error(AcceptErrorCode::InvalidInput));
        }
        let capacity =
            crate::transport_v2::carrier_inbound_stream_limit_v2(options.max_inbound_streams)
                .map_err(|_| error(AcceptErrorCode::InvalidInput))?;
        let listener = WebSocketListener::bind_direct(
            options.bind_address,
            options.certificate_chain_der,
            options.private_key_der,
            options.allowed_origins,
            capacity,
        )
        .map_err(|_| error(AcceptErrorCode::BindFailed))?;
        Ok(Self {
            listener: AcceptorListener::WebSocket(listener),
            carrier: CarrierKind::Wss,
            max_inbound_streams: options.max_inbound_streams,
            accept_timeout: options.accept_timeout,
            accept_gate: AsyncMutex::new(()),
            registrations: Mutex::new(HashMap::new()),
        })
    }

    pub async fn accept(
        &self,
        artifact: &Artifact,
        cancellation: CancellationToken,
    ) -> Result<std::sync::Arc<dyn Session>, AcceptError> {
        self.accept_session(artifact, cancellation, None).await
    }

    /// Accepts one session after freezing its application RPC and stream
    /// handlers before encrypted session establishment.
    pub async fn accept_with_handlers(
        &self,
        artifact: &Artifact,
        handlers: SessionHandlers,
        cancellation: CancellationToken,
    ) -> Result<AcceptedSession, AcceptError> {
        let handlers = handlers.into_snapshot();
        let rpc_handler = crate::session_handlers::rpc_router(handlers.rpc.clone());
        let session = self
            .accept_session(artifact, cancellation, Some(rpc_handler))
            .await?;
        Ok(AcceptedSession::new(session, handlers))
    }

    async fn accept_session(
        &self,
        artifact: &Artifact,
        cancellation: CancellationToken,
        rpc_handler: Option<std::sync::Arc<dyn RpcHandlerV2>>,
    ) -> Result<std::sync::Arc<dyn Session>, AcceptError> {
        let plan = accept_plan(artifact, self.carrier)?;
        if plan.connection.session.max_inbound_streams != self.max_inbound_streams {
            return Err(error(AcceptErrorCode::InvalidInput));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expiry = u64::try_from(plan.expires_at_unix_seconds)
            .ok()
            .filter(|expiry| *expiry > now)
            .ok_or_else(|| error(AcceptErrorCode::Expired))?;
        let operation_timeout = self
            .accept_timeout
            .min(Duration::from_secs(expiry.saturating_sub(now)));
        if operation_timeout.is_zero() {
            return Err(error(AcceptErrorCode::Expired));
        }
        {
            let mut registrations = self
                .registrations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if registrations.contains_key(&plan.registration_id) {
                return Err(error(AcceptErrorCode::AlreadyRegistered));
            }
            if registrations.values().any(|consumed| !consumed) {
                return Err(error(AcceptErrorCode::Busy));
            }
            registrations.insert(plan.registration_id, false);
        }

        let registration_id = plan.registration_id;
        let deadline = tokio::time::Instant::now() + operation_timeout;
        let gate = tokio::select! {
            _ = cancellation.cancelled() => Err(error(AcceptErrorCode::Canceled)),
            locked = tokio::time::timeout_at(deadline, self.accept_gate.lock()) => {
                locked.map_err(|_| error(AcceptErrorCode::Timeout))
            }
        };
        let result = match gate {
            Ok(_gate) => {
                self.accept_registered(plan, cancellation, deadline, rpc_handler)
                    .await
            }
            Err(failure) => Err(failure),
        };
        let mut registrations = self
            .registrations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if result.is_ok() {
            registrations.insert(registration_id, true);
        } else {
            registrations.remove(&registration_id);
        }
        result
    }

    async fn accept_registered(
        &self,
        plan: AcceptPlanV2,
        cancellation: CancellationToken,
        deadline: tokio::time::Instant,
        rpc_handler: Option<std::sync::Arc<dyn RpcHandlerV2>>,
    ) -> Result<std::sync::Arc<dyn Session>, AcceptError> {
        loop {
            let raw = tokio::select! {
                _ = cancellation.cancelled() => return Err(error(AcceptErrorCode::Canceled)),
                accepted = tokio::time::timeout_at(deadline, self.listener.accept()) => match accepted {
                    Err(_) => return Err(error(AcceptErrorCode::Timeout)),
                    Ok(Err(_)) => return Err(error(AcceptErrorCode::Closed)),
                    Ok(Ok(raw)) => raw,
                },
            };
            let cancel_raw = raw.clone();
            let admitted = tokio::select! {
                _ = cancellation.cancelled() => {
                    cancel_raw.abort();
                    return Err(error(AcceptErrorCode::Canceled));
                }
                result = tokio::time::timeout_at(
                    deadline,
                    ServerAdmissionV2::new(
                        CandidateAttemptV2::attempt()
                            .ready(raw)
                            .select_winner(),
                        &plan.expected_fsb2,
                        plan.connection.session.max_inbound_streams,
                    ).commit(),
                ) => match result {
                    Err(_) => return Err(error(AcceptErrorCode::Timeout)),
                    Ok(Err(_)) => return Err(error(AcceptErrorCode::HandshakeFailed)),
                    Ok(Ok(value)) => value,
                },
            };
            if let Some(admitted) = admitted {
                let mut config = session_config(&plan.connection, admitted.binding(), None);
                config.peer_admission_binding = Some(admitted.binding());
                config.rpc_handler = rpc_handler.clone();
                let session = tokio::select! {
                    _ = cancellation.cancelled() => return Err(error(AcceptErrorCode::Canceled)),
                    result = tokio::time::timeout_at(
                        deadline,
                        establish_session_v2(admitted.carrier(), config),
                    ) => match result {
                        Err(_) => return Err(error(AcceptErrorCode::Timeout)),
                        Ok(Err(_)) => return Err(error(AcceptErrorCode::HandshakeFailed)),
                        Ok(Ok(session)) => session,
                    },
                };
                admitted.mark_established();
                return Ok(session);
            }
        }
    }
}

impl std::fmt::Debug for Acceptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Acceptor { <opaque> }")
    }
}

const fn error(code: AcceptErrorCode) -> AcceptError {
    AcceptError { code }
}

struct AcceptPlanV2 {
    connection: ConnectionPlanV2,
    expected_fsb2: Vec<EncodedFsb2>,
    registration_id: [u8; 32],
    expires_at_unix_seconds: i64,
}

fn accept_plan(artifact: &Artifact, carrier: CarrierKind) -> Result<AcceptPlanV2, AcceptError> {
    let mut connection = artifact
        .connection_plan()
        .map_err(|ConnectionPlanError::Invalid| error(AcceptErrorCode::InvalidInput))?;
    if connection.path != PathKind::Direct {
        return Err(error(AcceptErrorCode::InvalidInput));
    }
    let expected_fsb2 = connection
        .candidates
        .iter()
        .filter(|candidate| candidate.carrier == carrier)
        .map(|candidate| {
            artifact
                .encode_fsb2(&candidate.id)
                .map_err(|_| error(AcceptErrorCode::InvalidInput))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if expected_fsb2.is_empty() {
        return Err(error(AcceptErrorCode::RuntimeUnsupported));
    }
    connection.role = SessionRole::Server;
    let registration_id = hash_acceptor_admissions(&expected_fsb2);
    Ok(AcceptPlanV2 {
        expires_at_unix_seconds: connection.expires_at_unix_seconds,
        connection,
        expected_fsb2,
        registration_id,
    })
}

fn hash_acceptor_admissions(admissions: &[EncodedFsb2]) -> [u8; 32] {
    let mut preimage = b"flowersec-v2-acceptor-admissions\0".to_vec();
    for admission in admissions {
        preimage.extend_from_slice(&(admission.raw.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&admission.raw);
    }
    Sha256::digest(preimage).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_accept_error_uses_canonical_code_strings() {
        assert_eq!(AcceptErrorCode::InvalidInput.as_str(), "invalid_input");
        assert_eq!(
            AcceptErrorCode::RuntimeUnsupported.as_str(),
            "runtime_unsupported"
        );
        assert_eq!(AcceptErrorCode::Expired.as_str(), "expired_artifact");
        assert_eq!(
            AcceptErrorCode::AlreadyRegistered.as_str(),
            "already_registered"
        );
        assert_eq!(AcceptErrorCode::Busy.as_str(), "busy");
        assert_eq!(AcceptErrorCode::BindFailed.as_str(), "bind_failed");
        assert_eq!(AcceptErrorCode::Closed.as_str(), "closed");
        assert_eq!(AcceptErrorCode::Timeout.as_str(), "timeout");
        assert_eq!(AcceptErrorCode::Canceled.as_str(), "canceled");
        assert_eq!(
            AcceptErrorCode::HandshakeFailed.as_str(),
            "handshake_failed"
        );
        assert_eq!(
            error(AcceptErrorCode::BindFailed).to_string(),
            "Flowersec session acceptance failed (code=bind_failed)"
        );
    }
}
