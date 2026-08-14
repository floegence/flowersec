//! Native Rust runtime composition for the carrier-neutral connector.

use std::{
    collections::HashSet,
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::{
    artifact_v2::{ArtifactLease, CandidatePlanV2},
    connector_v2::{
        CandidateAttemptFactoryV2, ConnectError, RuntimeFailureV2, SessionConnectorOptionsV2,
        SessionConnectorV2,
    },
    raw_quic_v2::{RawQuicClientConfig, RawQuicLimits, RawQuicPathProfile, RawQuicSession},
    session_handlers::{RpcHandlerSnapshot, RpcHandlers, rpc_router},
    transport_v2::{CarrierKind, CarrierSessionV2, PathKind, Session, SessionRole},
    websocket_v2,
};

const RESOLVED_ADDRESS_PROBE_DELAY: Duration = Duration::from_millis(250);

/// Native runtime trust and lifecycle configuration.
#[derive(Clone)]
pub struct ConnectorOptions {
    trust_roots_der: Vec<Vec<u8>>,
    connect_timeout: Duration,
    close_flush_timeout: Option<Duration>,
    websocket_origin: Option<String>,
    rpc_handlers: Option<Arc<RpcHandlerSnapshot>>,
}

impl fmt::Debug for ConnectorOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorOptions")
            .field(
                "trust_roots_der",
                &format_args!("[{} roots]", self.trust_roots_der.len()),
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("close_flush_timeout", &self.close_flush_timeout)
            .field("websocket_origin", &self.websocket_origin)
            .field("has_rpc_handlers", &self.rpc_handlers.is_some())
            .finish()
    }
}

impl ConnectorOptions {
    /// Creates native raw-QUIC options with explicit DER trust roots and the
    /// shared ten-second connection timeout.
    pub fn new(trust_roots_der: Vec<Vec<u8>>) -> Result<Self, ConnectError> {
        if trust_roots_der.is_empty() || trust_roots_der.iter().any(Vec::is_empty) {
            return Err(ConnectError::from_runtime_code(
                crate::connector_v2::ConnectErrorCode::InvalidInput,
            ));
        }
        Ok(Self {
            trust_roots_der,
            connect_timeout: Duration::from_secs(10),
            close_flush_timeout: None,
            websocket_origin: None,
            rpc_handlers: None,
        })
    }

    /// Overrides the complete connection-attempt deadline.
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Result<Self, ConnectError> {
        if connect_timeout.is_zero() {
            return Err(ConnectError::from_runtime_code(
                crate::connector_v2::ConnectErrorCode::InvalidInput,
            ));
        }
        self.connect_timeout = connect_timeout;
        Ok(self)
    }

    /// Overrides the bounded session close-control delivery deadline.
    pub fn with_close_flush_timeout(
        mut self,
        close_flush_timeout: Duration,
    ) -> Result<Self, ConnectError> {
        if close_flush_timeout.is_zero() {
            return Err(ConnectError::from_runtime_code(
                crate::connector_v2::ConnectErrorCode::InvalidInput,
            ));
        }
        self.close_flush_timeout = Some(close_flush_timeout);
        Ok(self)
    }

    pub fn trust_roots_der(&self) -> &[Vec<u8>] {
        &self.trust_roots_der
    }

    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Sets the exact HTTP Origin sent by native WebSocket candidates.
    pub fn with_websocket_origin(
        mut self,
        origin: impl Into<String>,
    ) -> Result<Self, ConnectError> {
        let origin = origin.into();
        let valid = url::Url::parse(&origin).is_ok_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
        });
        if !valid {
            return Err(ConnectError::from_runtime_code(
                crate::connector_v2::ConnectErrorCode::InvalidInput,
            ));
        }
        self.websocket_origin = Some(origin);
        Ok(self)
    }

    /// Freezes inbound RPC and notification handlers before session establishment.
    pub fn with_rpc_handlers(mut self, handlers: RpcHandlers) -> Self {
        self.rpc_handlers = Some(handlers.into_snapshot());
        self
    }
}

/// Establishes one carrier-neutral session from a single-use artifact lease.
pub async fn connect(
    lease: ArtifactLease,
    options: ConnectorOptions,
) -> Result<Arc<dyn Session>, ConnectError> {
    connect_with_cancellation(lease, options, CancellationToken::new()).await
}

/// Establishes one carrier-neutral session with explicit external cancellation.
pub async fn connect_with_cancellation(
    lease: ArtifactLease,
    options: ConnectorOptions,
    cancellation: CancellationToken,
) -> Result<Arc<dyn Session>, ConnectError> {
    let rpc_handler = options
        .rpc_handlers
        .as_ref()
        .map(|snapshot| rpc_router(snapshot.clone()));
    let connector_options = SessionConnectorOptionsV2 {
        connect_timeout: options.connect_timeout,
        close_flush_timeout: options.close_flush_timeout,
    };
    let runtime = Arc::new(RawQuicRuntimeAdapterV2 {
        trust_roots_der: options.trust_roots_der,
        connect_timeout: options.connect_timeout,
        websocket_origin: options.websocket_origin,
    });
    SessionConnectorV2::new(connector_options, runtime, rpc_handler)?
        .connect(lease, cancellation)
        .await
}

#[derive(Clone)]
struct RawQuicRuntimeAdapterV2 {
    trust_roots_der: Vec<Vec<u8>>,
    connect_timeout: Duration,
    websocket_origin: Option<String>,
}

impl fmt::Debug for RawQuicRuntimeAdapterV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawQuicRuntimeAdapterV2")
    }
}

#[async_trait]
impl CandidateAttemptFactoryV2 for RawQuicRuntimeAdapterV2 {
    fn supports(&self, candidate: &CandidatePlanV2, path: PathKind, _role: SessionRole) -> bool {
        matches!(candidate.carrier, CarrierKind::RawQuic | CarrierKind::Wss)
            && candidate.wire_profile
                == match path {
                    PathKind::Direct => "flowersec-direct/2",
                    PathKind::Tunnel => "flowersec-tunnel/2",
                }
            && (candidate.carrier != CarrierKind::Wss || self.websocket_origin.is_some())
    }

    async fn prepare(
        &self,
        candidate: CandidatePlanV2,
        role: SessionRole,
        max_inbound_streams: u16,
        deadline: tokio::time::Instant,
        cancellation: CancellationToken,
    ) -> Result<Arc<dyn CarrierSessionV2>, RuntimeFailureV2> {
        if candidate.carrier == CarrierKind::Wss {
            let origin = self
                .websocket_origin
                .as_deref()
                .ok_or(RuntimeFailureV2::Start)?;
            let subprotocol = match candidate.wire_profile.as_str() {
                "flowersec-direct/2" => websocket_v2::SUBPROTOCOL_DIRECT,
                "flowersec-tunnel/2" => websocket_v2::SUBPROTOCOL_TUNNEL,
                _ => return Err(RuntimeFailureV2::Start),
            };
            let capacity =
                crate::transport_v2::carrier_inbound_stream_limit_v2(max_inbound_streams)
                    .map_err(|_| RuntimeFailureV2::Start)?;
            return tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(RuntimeFailureV2::Canceled),
                result = tokio::time::timeout_at(deadline, websocket_v2::dial(
                    &candidate.normalized_url,
                    subprotocol,
                    origin,
                    self.trust_roots_der.clone(),
                    capacity,
                )) => match result {
                    Err(_) => Err(RuntimeFailureV2::Timeout),
                    Ok(Err(_)) => Err(RuntimeFailureV2::Start),
                    Ok(Ok(carrier)) => {
                        carrier
                            .set_multiplexer_client(role == SessionRole::Client)
                            .map_err(|_| RuntimeFailureV2::Start)?;
                        Ok(carrier)
                    },
                }
            };
        }
        let url =
            url::Url::parse(&candidate.normalized_url).map_err(|_| RuntimeFailureV2::Resolve)?;
        let host = url
            .host_str()
            .ok_or(RuntimeFailureV2::Resolve)?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url.port().unwrap_or(443);
        let resolved = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(RuntimeFailureV2::Canceled),
            result = tokio::time::timeout_at(deadline, tokio::net::lookup_host((host.as_str(), port))) => {
                match result {
                    Err(_) => return Err(RuntimeFailureV2::Timeout),
                    Ok(Err(_)) => return Err(RuntimeFailureV2::Resolve),
                    Ok(Ok(addresses)) => addresses,
                }
            }
        };
        let mut seen = HashSet::new();
        let addresses = resolved
            .filter(|address| seen.insert(*address))
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(RuntimeFailureV2::Resolve);
        }
        let profile = match candidate.wire_profile.as_str() {
            "flowersec-direct/2" => RawQuicPathProfile::Direct,
            "flowersec-tunnel/2" => RawQuicPathProfile::Tunnel,
            _ => return Err(RuntimeFailureV2::Start),
        };
        let limits = RawQuicLimits::for_session_v2(max_inbound_streams, self.connect_timeout)
            .map_err(|_| RuntimeFailureV2::Start)?;
        let config = RawQuicClientConfig::new(profile, self.trust_roots_der.clone(), limits)
            .map_err(|_| RuntimeFailureV2::Start)?;
        dial_resolved_raw_quic(&host, addresses, config, deadline, cancellation)
            .await
            .map(|session| Arc::new(session) as Arc<dyn CarrierSessionV2>)
    }
}

pub(crate) async fn dial_resolved_raw_quic(
    host: &str,
    addresses: Vec<SocketAddr>,
    config: RawQuicClientConfig,
    deadline: tokio::time::Instant,
    cancellation: CancellationToken,
) -> Result<RawQuicSession, RuntimeFailureV2> {
    let total_addresses = addresses.len();
    for (index, address) in addresses.into_iter().enumerate() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(RuntimeFailureV2::Timeout);
        }
        let attempts_left = u32::try_from(total_addresses - index).unwrap_or(u32::MAX);
        let attempt_deadline = if attempts_left == 1 {
            deadline
        } else {
            now + (deadline.saturating_duration_since(now) / attempts_left)
                .min(RESOLVED_ADDRESS_PROBE_DELAY)
        };
        let local = if address.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(RuntimeFailureV2::Canceled),
            result = tokio::time::timeout_at(
                attempt_deadline,
                RawQuicSession::dial(local, address, host, config.clone()),
            ) => result,
        };
        if let Ok(Ok(session)) = result {
            return Ok(session);
        }
    }
    if tokio::time::Instant::now() >= deadline {
        Err(RuntimeFailureV2::Timeout)
    } else {
        Err(RuntimeFailureV2::Start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(carrier: CarrierKind, url: &str) -> CandidatePlanV2 {
        CandidatePlanV2 {
            id: "candidate".into(),
            carrier,
            normalized_url: url.into(),
            wire_profile: "flowersec-direct/2".into(),
        }
    }

    #[test]
    fn runtime_does_not_claim_webtransport_without_a_production_driver() {
        let runtime = RawQuicRuntimeAdapterV2 {
            trust_roots_der: vec![vec![1]],
            connect_timeout: Duration::from_secs(1),
            websocket_origin: Some("https://app.example".into()),
        };
        assert!(runtime.supports(
            &candidate(CarrierKind::RawQuic, "quic://127.0.0.1:443"),
            PathKind::Direct,
            SessionRole::Client,
        ));
        assert!(runtime.supports(
            &candidate(CarrierKind::Wss, "wss://localhost:443/flowersec/v2/direct"),
            PathKind::Direct,
            SessionRole::Client,
        ));
        assert!(!runtime.supports(
            &candidate(
                CarrierKind::WebTransport,
                "https://localhost:443/flowersec/webtransport/v2/direct",
            ),
            PathKind::Direct,
            SessionRole::Client,
        ));
    }
}
