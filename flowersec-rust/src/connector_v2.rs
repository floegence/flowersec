//! Carrier-neutral production connector for opaque Flowersec v2 artifacts.

use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio_util::sync::CancellationToken;

use crate::{
    artifact_v2::{ArtifactLease, ArtifactSpendError, RawQuicCandidatePlan},
    raw_quic_v2::{RawQuicClientConfig, RawQuicLimits, RawQuicPathProfile, RawQuicSession},
    transport_v2::{PathKind, SessionV2},
};

/// Carrier-neutral trust and lifecycle policy.
#[derive(Clone, Debug)]
pub struct ConnectorOptions {
    trust_roots_der: Vec<Vec<u8>>,
    connect_timeout: Duration,
}

impl ConnectorOptions {
    /// Creates valid client options with explicit DER trust roots and the shared
    /// ten-second connection timeout.
    pub fn new(trust_roots_der: Vec<Vec<u8>>) -> Result<Self, ConnectError> {
        if trust_roots_der.is_empty() || trust_roots_der.iter().any(Vec::is_empty) {
            return Err(error(PathKind::Direct, ConnectErrorCode::InvalidInput));
        }
        Ok(Self {
            trust_roots_der,
            connect_timeout: Duration::from_secs(10),
        })
    }

    /// Overrides the complete connection-attempt deadline.
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Result<Self, ConnectError> {
        if connect_timeout.is_zero() {
            return Err(error(PathKind::Direct, ConnectErrorCode::InvalidInput));
        }
        self.connect_timeout = connect_timeout;
        Ok(self)
    }

    pub fn trust_roots_der(&self) -> &[Vec<u8>] {
        &self.trust_roots_der
    }

    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
}

/// Stable, redacted connection failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectErrorCode {
    InvalidInput,
    Expired,
    ResolveFailed,
    SpendFailed,
    DialFailed,
    Timeout,
    Canceled,
    HandshakeFailed,
}

impl ConnectErrorCode {
    /// Returns the stable public code string used in redacted error text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::Expired => "expired_artifact",
            Self::ResolveFailed => "resolve_failed",
            Self::SpendFailed => "credential_spend_failed",
            Self::DialFailed => "connection_failed",
            Self::Timeout => "timeout",
            Self::Canceled => "canceled",
            Self::HandshakeFailed => "handshake_failed",
        }
    }
}

impl fmt::Display for ConnectErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted connection failure that never retains carrier credentials or diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec connection failed (code={code})")]
pub struct ConnectError {
    code: ConnectErrorCode,
}

impl ConnectError {
    #[cfg(test)]
    pub(crate) const fn from_code(code: ConnectErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(&self) -> ConnectErrorCode {
        self.code
    }

    /// Returns the stable public code string for this redacted connection failure.
    pub const fn as_str(&self) -> &'static str {
        self.code.as_str()
    }
}

/// Establishes a v2 session without exposing candidates or carrier configuration.
#[derive(Debug)]
pub(crate) struct Connector {
    options: ConnectorOptions,
    backend: Arc<dyn DialBackend>,
}

impl std::fmt::Debug for dyn DialBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DialBackend")
    }
}

#[async_trait]
trait DialBackend: Send + Sync {
    async fn dial(
        &self,
        candidate: RawQuicCandidatePlan,
        config: RawQuicClientConfig,
    ) -> Result<Box<dyn ReadyCarrier>, ()>;
}

#[async_trait]
trait ReadyCarrier: Send + Sync {
    async fn establish(
        &self,
        raw_fsb2: &[u8],
        config: crate::session_v2::SessionConfigV2,
        contract: crate::raw_quic_v2::SessionContractV2,
    ) -> io::Result<Arc<dyn SessionV2>>;
    fn close(&self);
}

type DialResult = (RawQuicCandidatePlan, Result<Box<dyn ReadyCarrier>, ()>);

struct ProductionDialBackend;
struct ProductionReadyCarrier(RawQuicSession);

#[async_trait]
impl DialBackend for ProductionDialBackend {
    async fn dial(
        &self,
        candidate: RawQuicCandidatePlan,
        config: RawQuicClientConfig,
    ) -> Result<Box<dyn ReadyCarrier>, ()> {
        let addresses = tokio::net::lookup_host((candidate.host.as_str(), candidate.port))
            .await
            .map_err(|_| ())?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(());
        }
        let mut attempts = FuturesUnordered::new();
        for address in addresses {
            let local = if address.is_ipv4() {
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            };
            attempts.push(RawQuicSession::dial(
                local,
                address,
                &candidate.host,
                config.clone(),
            ));
        }
        while let Some(result) = attempts.next().await {
            if let Ok(session) = result {
                return Ok(Box::new(ProductionReadyCarrier(session)));
            }
        }
        Err(())
    }
}

#[async_trait]
impl ReadyCarrier for ProductionReadyCarrier {
    async fn establish(
        &self,
        raw_fsb2: &[u8],
        config: crate::session_v2::SessionConfigV2,
        contract: crate::raw_quic_v2::SessionContractV2,
    ) -> io::Result<Arc<dyn SessionV2>> {
        self.0
            .clone()
            .commit_admission_and_establish_v2(raw_fsb2, config, contract)
            .await
    }
    fn close(&self) {
        self.0.close();
    }
}

impl Connector {
    pub(crate) fn new(options: ConnectorOptions) -> Result<Self, ConnectError> {
        if options.trust_roots_der.is_empty() || options.connect_timeout.is_zero() {
            return Err(error(PathKind::Direct, ConnectErrorCode::InvalidInput));
        }
        Ok(Self {
            options,
            backend: Arc::new(ProductionDialBackend),
        })
    }

    pub(crate) async fn connect(
        &self,
        lease: &mut ArtifactLease,
        cancellation: CancellationToken,
    ) -> Result<Arc<dyn SessionV2>, ConnectError> {
        let deadline = tokio::time::Instant::now() + self.options.connect_timeout;
        let plan = lease
            .artifact()
            .raw_quic_dial_plan()
            .map_err(|_| error(PathKind::Direct, ConnectErrorCode::InvalidInput))?;
        let path = plan.path;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if u64::try_from(plan.expires_at_unix_seconds).map_or(true, |expiry| expiry <= now) {
            return Err(error(path, ConnectErrorCode::Expired));
        }
        let mut config = plan.session_config;
        config.local_endpoint_instance_id = plan.local_endpoint_instance_id;
        config.expected_peer_endpoint_instance_id = plan.expected_peer_endpoint_instance_id;
        let limits =
            RawQuicLimits::for_session_v2(config.max_inbound_streams, self.options.connect_timeout)
                .map_err(|_| error(path, ConnectErrorCode::InvalidInput))?;
        let profile = if path == PathKind::Direct {
            RawQuicPathProfile::Direct
        } else {
            RawQuicPathProfile::Tunnel
        };
        let client =
            RawQuicClientConfig::new(profile, self.options.trust_roots_der.clone(), limits)
                .map_err(|_| error(path, ConnectErrorCode::InvalidInput))?;
        let dials: FuturesUnordered<BoxFuture<'static, DialResult>> = FuturesUnordered::new();
        for candidate in plan.candidates.iter().cloned() {
            let backend = self.backend.clone();
            let config = client.clone();
            dials.push(
                async move { (candidate.clone(), backend.dial(candidate, config).await) }.boxed(),
            );
        }
        let (winner, carrier) = select_winner(dials, deadline, &cancellation, path).await?;

        // Once durable commit begins it is authoritative and must not be canceled midway.
        lease
            .commit_spend()
            .await
            .map_err(|failure| match failure {
                ArtifactSpendError::AlreadyCommitted | ArtifactSpendError::CommitFailed => {
                    carrier.close();
                    error(path, ConnectErrorCode::SpendFailed)
                }
            })?;
        if cancellation.is_cancelled() {
            carrier.close();
            return Err(error(path, ConnectErrorCode::Canceled));
        }
        if tokio::time::Instant::now() >= deadline {
            carrier.close();
            return Err(error(path, ConnectErrorCode::Timeout));
        }
        let encoded = lease.artifact().encode_fsb2(&winner.id).map_err(|_| {
            carrier.close();
            error(path, ConnectErrorCode::InvalidInput)
        })?;
        if path == PathKind::Direct {
            config.peer_admission_binding = Some(encoded.binding);
        }
        finish_establish(
            carrier,
            &encoded.raw,
            config,
            plan.session_contract,
            deadline,
            &cancellation,
            path,
        )
        .await
    }
}

/// Establishes one carrier-neutral session from a single-use artifact lease.
pub async fn connect(
    lease: &mut ArtifactLease,
    options: ConnectorOptions,
    cancellation: CancellationToken,
) -> Result<Arc<dyn SessionV2>, ConnectError> {
    Connector::new(options)?.connect(lease, cancellation).await
}

async fn select_winner(
    mut dials: FuturesUnordered<BoxFuture<'static, DialResult>>,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    path: PathKind,
) -> Result<(RawQuicCandidatePlan, Box<dyn ReadyCarrier>), ConnectError> {
    let winner = tokio::select! {
        _ = cancellation.cancelled() => return Err(error(path, ConnectErrorCode::Canceled)),
        result = tokio::time::timeout_at(deadline, async {
            while let Some((candidate, result)) = dials.next().await {
                if let Ok(carrier) = result { return Some((candidate, carrier)); }
            }
            None
        }) => match result {
            Err(_) => return Err(error(path, ConnectErrorCode::Timeout)),
            Ok(None) => return Err(error(path, ConnectErrorCode::DialFailed)),
            Ok(Some(value)) => value,
        }
    };
    while let Some(Some((_candidate, result))) = dials.next().now_or_never() {
        if let Ok(loser) = result {
            loser.close();
        }
    }
    Ok(winner)
}

async fn finish_establish(
    carrier: Box<dyn ReadyCarrier>,
    raw: &[u8],
    config: crate::session_v2::SessionConfigV2,
    contract: crate::raw_quic_v2::SessionContractV2,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    path: PathKind,
) -> Result<Arc<dyn SessionV2>, ConnectError> {
    let establish = carrier.establish(raw, config, contract);
    tokio::select! {
            _ = cancellation.cancelled() => { carrier.close(); Err(error(path, ConnectErrorCode::Canceled)) },
            result = tokio::time::timeout_at(deadline, establish) => match result {
                Err(_) => { carrier.close(); Err(error(path, ConnectErrorCode::Timeout)) },
                Ok(Err(failure)) if failure.kind() == io::ErrorKind::TimedOut => { carrier.close(); Err(error(path, ConnectErrorCode::Timeout)) },
                Ok(Err(_)) => { carrier.close(); Err(error(path, ConnectErrorCode::HandshakeFailed)) },
                Ok(Ok(session)) => Ok(session),
            },
    }
}

const fn error(path: PathKind, code: ConnectErrorCode) -> ConnectError {
    let _ = path;
    ConnectError { code }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FailingReadyCarrier(Arc<AtomicBool>);
    struct HangingReadyCarrier(Arc<AtomicBool>);

    #[async_trait]
    impl ReadyCarrier for FailingReadyCarrier {
        async fn establish(
            &self,
            _: &[u8],
            _: crate::session_v2::SessionConfigV2,
            _: crate::raw_quic_v2::SessionContractV2,
        ) -> io::Result<Arc<dyn SessionV2>> {
            Err(io::Error::other("sensitive candidate failure"))
        }
        fn close(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ReadyCarrier for HangingReadyCarrier {
        async fn establish(
            &self,
            _: &[u8],
            _: crate::session_v2::SessionConfigV2,
            _: crate::raw_quic_v2::SessionContractV2,
        ) -> io::Result<Arc<dyn SessionV2>> {
            std::future::pending().await
        }
        fn close(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn public_error_is_redacted() {
        let failure = error(PathKind::Tunnel, ConnectErrorCode::DialFailed);
        let text = failure.to_string().to_ascii_lowercase();
        assert_eq!(failure.code(), ConnectErrorCode::DialFailed);
        assert_eq!(ConnectErrorCode::InvalidInput.as_str(), "invalid_input");
        assert_eq!(ConnectErrorCode::Expired.as_str(), "expired_artifact");
        assert_eq!(ConnectErrorCode::ResolveFailed.as_str(), "resolve_failed");
        assert_eq!(
            ConnectErrorCode::SpendFailed.as_str(),
            "credential_spend_failed"
        );
        assert_eq!(ConnectErrorCode::DialFailed.as_str(), "connection_failed");
        assert_eq!(ConnectErrorCode::Timeout.as_str(), "timeout");
        assert_eq!(ConnectErrorCode::Canceled.as_str(), "canceled");
        assert_eq!(
            ConnectErrorCode::HandshakeFailed.as_str(),
            "handshake_failed"
        );
        assert_eq!(text, "flowersec connection failed (code=connection_failed)");
        for forbidden in ["candidate", "carrier", "quic://", "token", "certificate"] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn connector_rejects_empty_trust_or_lifecycle_deadline() {
        assert_eq!(
            ConnectorOptions::new(vec![]).unwrap_err().code(),
            ConnectErrorCode::InvalidInput
        );
        assert_eq!(
            ConnectorOptions::new(vec![vec![1]])
                .unwrap()
                .with_connect_timeout(Duration::ZERO)
                .unwrap_err()
                .code(),
            ConnectErrorCode::InvalidInput
        );
    }

    #[tokio::test]
    async fn establish_error_explicitly_closes_winner() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/artifact_vectors.json"
        ))
        .unwrap();
        let artifact = crate::artifact_v2::Artifact::parse(
            fixture["positive"][0]["artifact_json"].as_str().unwrap(),
        )
        .unwrap();
        let plan = artifact.raw_quic_dial_plan().unwrap();
        let closed = Arc::new(AtomicBool::new(false));
        let failure = finish_establish(
            Box::new(FailingReadyCarrier(closed.clone())),
            b"FSB2",
            plan.session_config,
            plan.session_contract,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
            PathKind::Direct,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.code(), ConnectErrorCode::HandshakeFailed);
        assert!(closed.load(Ordering::SeqCst));
        assert!(!failure.to_string().contains("sensitive"));
    }

    #[tokio::test]
    async fn establish_cancel_and_timeout_explicitly_close_winner() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/artifact_vectors.json"
        ))
        .unwrap();
        let artifact = crate::artifact_v2::Artifact::parse(
            fixture["positive"][0]["artifact_json"].as_str().unwrap(),
        )
        .unwrap();
        for canceled in [true, false] {
            let plan = artifact.raw_quic_dial_plan().unwrap();
            let closed = Arc::new(AtomicBool::new(false));
            let cancellation = CancellationToken::new();
            if canceled {
                cancellation.cancel();
            }
            let failure = finish_establish(
                Box::new(HangingReadyCarrier(closed.clone())),
                b"FSB2",
                plan.session_config,
                plan.session_contract,
                tokio::time::Instant::now() + Duration::from_millis(1),
                &cancellation,
                PathKind::Direct,
            )
            .await
            .unwrap_err();
            assert_eq!(
                failure.code(),
                if canceled {
                    ConnectErrorCode::Canceled
                } else {
                    ConnectErrorCode::Timeout
                }
            );
            assert!(closed.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn concurrent_ready_candidates_close_every_non_winner() {
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let dials: FuturesUnordered<BoxFuture<'static, DialResult>> = FuturesUnordered::new();
        for (id, closed) in [("q1", first.clone()), ("q2", second.clone())] {
            let candidate = RawQuicCandidatePlan {
                id: id.into(),
                host: "localhost".into(),
                port: 443,
            };
            dials.push(
                async move {
                    (
                        candidate,
                        Ok(Box::new(FailingReadyCarrier(closed)) as Box<dyn ReadyCarrier>),
                    )
                }
                .boxed(),
            );
        }
        let (_winner, carrier) = select_winner(
            dials,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
            PathKind::Direct,
        )
        .await
        .unwrap();
        assert_eq!(
            u8::from(first.load(Ordering::SeqCst)) + u8::from(second.load(Ordering::SeqCst)),
            1
        );
        carrier.close();
        assert!(first.load(Ordering::SeqCst) && second.load(Ordering::SeqCst));
    }
}
