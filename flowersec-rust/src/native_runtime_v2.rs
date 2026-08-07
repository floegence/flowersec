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
    transport_v2::{CarrierKind, CarrierSessionV2, PathKind, SessionRole, SessionV2},
};

const RESOLVED_ADDRESS_PROBE_DELAY: Duration = Duration::from_millis(250);

/// Native runtime trust and lifecycle configuration.
#[derive(Clone)]
pub struct ConnectorOptions {
    trust_roots_der: Vec<Vec<u8>>,
    connect_timeout: Duration,
    close_flush_timeout: Option<Duration>,
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
}

/// Establishes one carrier-neutral session from a single-use artifact lease.
pub async fn connect(
    lease: &mut ArtifactLease,
    options: ConnectorOptions,
) -> Result<Arc<dyn SessionV2>, ConnectError> {
    connect_with_cancellation(lease, options, CancellationToken::new()).await
}

/// Establishes one carrier-neutral session with explicit external cancellation.
pub async fn connect_with_cancellation(
    lease: &mut ArtifactLease,
    options: ConnectorOptions,
    cancellation: CancellationToken,
) -> Result<Arc<dyn SessionV2>, ConnectError> {
    let connector_options = SessionConnectorOptionsV2 {
        connect_timeout: options.connect_timeout,
        close_flush_timeout: options.close_flush_timeout,
    };
    let runtime = Arc::new(RawQuicRuntimeAdapterV2 {
        trust_roots_der: options.trust_roots_der,
        connect_timeout: options.connect_timeout,
    });
    SessionConnectorV2::new(connector_options, runtime)?
        .connect(lease, cancellation)
        .await
}

#[derive(Clone)]
struct RawQuicRuntimeAdapterV2 {
    trust_roots_der: Vec<Vec<u8>>,
    connect_timeout: Duration,
}

impl fmt::Debug for RawQuicRuntimeAdapterV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawQuicRuntimeAdapterV2")
    }
}

#[async_trait]
impl CandidateAttemptFactoryV2 for RawQuicRuntimeAdapterV2 {
    fn supports(&self, candidate: &CandidatePlanV2, path: PathKind, _role: SessionRole) -> bool {
        candidate.carrier == CarrierKind::RawQuic
            && candidate.wire_profile
                == match path {
                    PathKind::Direct => "flowersec-direct/2",
                    PathKind::Tunnel => "flowersec-tunnel/2",
                }
    }

    async fn prepare(
        &self,
        candidate: CandidatePlanV2,
        max_inbound_streams: u16,
        deadline: tokio::time::Instant,
        cancellation: CancellationToken,
    ) -> Result<Arc<dyn CarrierSessionV2>, RuntimeFailureV2> {
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
