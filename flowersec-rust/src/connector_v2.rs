//! Carrier-neutral candidate selection, admission, and session establishment.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio_util::sync::CancellationToken;

use crate::{
    admission_v2::{AdmissionCommitErrorV2, AdmissionCommitV2, CandidateAttemptV2},
    artifact_v2::{ArtifactLease, CandidatePlanV2, ConnectionPlanError, ConnectionPlanV2},
    session_v2::{SessionConfigV2, SessionDeadlinesV2, establish_session_v2},
    transport_v2::{CarrierSessionV2, PathKind, Session, SessionRole},
};

/// Stable, redacted connection failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectErrorCode {
    InvalidInput,
    RuntimeUnsupported,
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
            Self::RuntimeUnsupported => "runtime_unsupported",
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
    controller_retryable: bool,
}

impl ConnectError {
    pub const fn code(&self) -> ConnectErrorCode {
        self.code
    }

    pub(crate) const fn from_runtime_code(code: ConnectErrorCode) -> Self {
        error(code)
    }

    pub(crate) const fn controller_retryable(&self) -> bool {
        self.controller_retryable
    }

    /// Returns the stable public code string for this redacted connection failure.
    pub const fn as_str(&self) -> &'static str {
        self.code.as_str()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionConnectorOptionsV2 {
    pub(crate) connect_timeout: Duration,
    pub(crate) close_flush_timeout: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeFailureV2 {
    Resolve,
    Start,
    Canceled,
    Timeout,
}

/// Runtime composition point used by the carrier-neutral connector.
#[async_trait]
pub(crate) trait CandidateAttemptFactoryV2: fmt::Debug + Send + Sync {
    fn supports(&self, candidate: &CandidatePlanV2, path: PathKind, role: SessionRole) -> bool;

    async fn prepare(
        &self,
        candidate: CandidatePlanV2,
        max_inbound_streams: u16,
        deadline: tokio::time::Instant,
        cancellation: CancellationToken,
    ) -> Result<Arc<dyn CarrierSessionV2>, RuntimeFailureV2>;
}

pub(crate) struct SessionConnectorV2 {
    options: SessionConnectorOptionsV2,
    runtime: Arc<dyn CandidateAttemptFactoryV2>,
}

impl fmt::Debug for SessionConnectorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConnectorV2")
            .field("options", &self.options)
            .field("runtime", &self.runtime)
            .finish()
    }
}

impl SessionConnectorV2 {
    pub(crate) fn new(
        options: SessionConnectorOptionsV2,
        runtime: Arc<dyn CandidateAttemptFactoryV2>,
    ) -> Result<Self, ConnectError> {
        if options.connect_timeout.is_zero() {
            return Err(error(ConnectErrorCode::InvalidInput));
        }
        Ok(Self { options, runtime })
    }

    pub(crate) async fn connect(
        &self,
        mut lease: ArtifactLease,
        cancellation: CancellationToken,
    ) -> Result<Arc<dyn Session>, ConnectError> {
        let deadline = tokio::time::Instant::now() + self.options.connect_timeout;
        let plan = lease
            .artifact_for_connector()
            .connection_plan()
            .map_err(|ConnectionPlanError::Invalid| error(ConnectErrorCode::InvalidInput))?;
        require_unexpired(&plan)?;

        let candidates = plan
            .candidates
            .iter()
            .filter(|candidate| self.runtime.supports(candidate, plan.path, plan.role))
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(error(ConnectErrorCode::RuntimeUnsupported));
        }

        let dials: FuturesUnordered<BoxFuture<'static, DialResult>> = FuturesUnordered::new();
        for candidate in candidates {
            let runtime = self.runtime.clone();
            let max_inbound_streams = plan.session.max_inbound_streams;
            let cancellation = cancellation.clone();
            dials.push(
                async move {
                    let id = candidate.id.clone();
                    let attempt = CandidateAttemptV2::attempt();
                    let prepared = runtime
                        .prepare(candidate, max_inbound_streams, deadline, cancellation)
                        .await
                        .map(|carrier| attempt.ready(carrier));
                    (id, prepared)
                }
                .boxed(),
            );
        }
        let (winner_id, attempt) = select_winner(dials, deadline, &cancellation).await?;
        let encoded = lease
            .artifact_for_connector()
            .encode_fsb2(&winner_id)
            .map_err(|_| error(ConnectErrorCode::InvalidInput))?;

        require_active(deadline, &cancellation)?;
        let admitted = AdmissionCommitV2::new(
            attempt,
            &mut lease,
            encoded,
            plan.session.max_inbound_streams,
        )
        .commit(deadline, &cancellation)
        .await
        .map_err(|failure| match failure {
            AdmissionCommitErrorV2::Spend => error(ConnectErrorCode::SpendFailed),
            AdmissionCommitErrorV2::Canceled => error(ConnectErrorCode::Canceled),
            AdmissionCommitErrorV2::Timeout => error(ConnectErrorCode::Timeout),
            AdmissionCommitErrorV2::Rejected => terminal_error(ConnectErrorCode::DialFailed),
            AdmissionCommitErrorV2::Retryable => error(ConnectErrorCode::DialFailed),
            AdmissionCommitErrorV2::Carrier => error(ConnectErrorCode::DialFailed),
        })?;

        let mut config =
            session_config(&plan, admitted.binding(), self.options.close_flush_timeout);
        if plan.path == PathKind::Direct {
            config.peer_admission_binding = Some(admitted.binding());
        }
        let session = tokio::select! {
            _ = cancellation.cancelled() => return Err(error(ConnectErrorCode::Canceled)),
            result = tokio::time::timeout_at(
                deadline,
                establish_session_v2(admitted.carrier(), config),
            ) => match result {
                Err(_) => return Err(error(ConnectErrorCode::Timeout)),
                Ok(Err(failure)) if failure.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(error(ConnectErrorCode::Timeout));
                }
                Ok(Err(_)) => return Err(error(ConnectErrorCode::HandshakeFailed)),
                Ok(Ok(session)) => session,
            },
        };
        admitted.mark_established();
        Ok(session)
    }
}

type DialResult = (String, Result<CandidateAttemptV2, RuntimeFailureV2>);

async fn select_winner(
    mut dials: FuturesUnordered<BoxFuture<'static, DialResult>>,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<(String, CandidateAttemptV2), ConnectError> {
    let mut saw_runtime_failure = false;
    tokio::select! {
        _ = cancellation.cancelled() => Err(error(ConnectErrorCode::Canceled)),
        result = tokio::time::timeout_at(deadline, async {
            while let Some((candidate_id, result)) = dials.next().await {
                match result {
                    Ok(attempt) => return Ok(Some((candidate_id, attempt.select_winner()))),
                    Err(RuntimeFailureV2::Start) => saw_runtime_failure = true,
                    Err(RuntimeFailureV2::Resolve) => {}
                    Err(RuntimeFailureV2::Canceled) => {
                        return Err(error(ConnectErrorCode::Canceled));
                    }
                    Err(RuntimeFailureV2::Timeout) => {
                        return Err(error(ConnectErrorCode::Timeout));
                    }
                }
            }
            Ok(None)
        }) => match result {
            Err(_) => Err(error(ConnectErrorCode::Timeout)),
            Ok(Err(error)) => Err(error),
            Ok(Ok(None)) if saw_runtime_failure => Err(error(ConnectErrorCode::DialFailed)),
            Ok(Ok(None)) => Err(error(ConnectErrorCode::ResolveFailed)),
            Ok(Ok(Some(winner))) => Ok(winner),
        },
    }
}

pub(crate) fn session_config(
    plan: &ConnectionPlanV2,
    admission_binding: [u8; 32],
    close_flush_timeout: Option<Duration>,
) -> SessionConfigV2 {
    let mut deadlines = SessionDeadlinesV2 {
        establish: plan.session.establish_timeout,
        rekey_prepare: plan.session.rekey_prepare_timeout,
        rekey_completion: plan.session.rekey_completion_timeout,
        ..Default::default()
    };
    if let Some(close_flush) = close_flush_timeout {
        deadlines.close_flush = close_flush;
    }
    SessionConfigV2 {
        role: plan.role,
        path: plan.path,
        channel_id: plan.session.channel_id.clone(),
        session_contract_hash: plan.session.session_contract_hash,
        suite: plan.session.suite,
        psk: plan.session.psk,
        max_inbound_streams: plan.session.max_inbound_streams,
        idle_timeout: plan.session.idle_timeout,
        local_admission_binding: admission_binding,
        peer_admission_binding: None,
        local_endpoint_instance_id: plan.local_endpoint_instance_id.clone(),
        expected_peer_endpoint_instance_id: plan.expected_peer_endpoint_instance_id.clone(),
        rpc_handler: None,
        deadlines,
    }
}

fn require_unexpired(plan: &ConnectionPlanV2) -> Result<(), ConnectError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if u64::try_from(plan.expires_at_unix_seconds).map_or(true, |expiry| expiry <= now) {
        return Err(error(ConnectErrorCode::Expired));
    }
    Ok(())
}

fn require_active(
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<(), ConnectError> {
    if cancellation.is_cancelled() {
        return Err(error(ConnectErrorCode::Canceled));
    }
    if tokio::time::Instant::now() >= deadline {
        return Err(error(ConnectErrorCode::Timeout));
    }
    Ok(())
}

const fn error(code: ConnectErrorCode) -> ConnectError {
    ConnectError {
        code,
        controller_retryable: !matches!(
            code,
            ConnectErrorCode::InvalidInput
                | ConnectErrorCode::RuntimeUnsupported
                | ConnectErrorCode::Canceled
        ),
    }
}

const fn terminal_error(code: ConnectErrorCode) -> ConnectError {
    ConnectError {
        code,
        controller_retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::atomic::{AtomicBool, Ordering},
    };

    use super::*;
    use crate::{
        session_v2::memory_carrier_pair_v2_with_capacity,
        transport_v2::{CarrierKind, CarrierStreamV2},
    };

    #[derive(Debug)]
    struct AbortProbeCarrier {
        inner: Arc<dyn CarrierSessionV2>,
        aborted: Arc<AtomicBool>,
    }

    #[async_trait]
    impl CarrierSessionV2 for AbortProbeCarrier {
        fn kind(&self) -> CarrierKind {
            self.inner.kind()
        }

        fn inbound_bidirectional_stream_capacity(&self) -> u32 {
            self.inner.inbound_bidirectional_stream_capacity()
        }

        async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
            self.inner.open_stream().await
        }

        async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
            self.inner.accept_stream().await
        }

        async fn close(&self) -> io::Result<()> {
            self.inner.close().await
        }

        fn abort(&self) {
            self.aborted.store(true, Ordering::SeqCst);
            self.inner.abort();
        }
    }

    #[test]
    fn public_errors_are_redacted_and_controller_disposition_is_structured() {
        let retryable = error(ConnectErrorCode::DialFailed);
        assert_eq!(retryable.code(), ConnectErrorCode::DialFailed);
        assert!(retryable.controller_retryable());
        assert_eq!(
            retryable.to_string(),
            "Flowersec connection failed (code=connection_failed)"
        );
        for forbidden in ["candidate", "carrier", "quic://", "token", "certificate"] {
            assert!(!retryable.to_string().contains(forbidden));
        }

        assert!(!error(ConnectErrorCode::RuntimeUnsupported).controller_retryable());
        assert!(!error(ConnectErrorCode::Canceled).controller_retryable());
        assert!(!terminal_error(ConnectErrorCode::DialFailed).controller_retryable());
    }

    #[tokio::test]
    async fn candidate_selection_aborts_every_non_established_carrier() {
        let mut aborted = Vec::new();
        let dials: FuturesUnordered<BoxFuture<'static, DialResult>> = FuturesUnordered::new();
        for id in ["q1", "q2"] {
            let (inner, _peer) = memory_carrier_pair_v2_with_capacity(3);
            let flag = Arc::new(AtomicBool::new(false));
            aborted.push(flag.clone());
            let carrier: Arc<dyn CarrierSessionV2> = Arc::new(AbortProbeCarrier {
                inner,
                aborted: flag,
            });
            let attempt = CandidateAttemptV2::attempt().ready(carrier);
            dials.push(async move { (id.to_owned(), Ok(attempt)) }.boxed());
        }

        let (_winner, attempt) = select_winner(
            dials,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await
        .expect("one candidate wins");
        assert_eq!(
            aborted
                .iter()
                .filter(|flag| flag.load(Ordering::SeqCst))
                .count(),
            1,
            "selection must abort exactly the ready loser"
        );

        drop(attempt);
        assert!(
            aborted.iter().all(|flag| flag.load(Ordering::SeqCst)),
            "a winner that never reaches admission must also abort"
        );
    }

    #[tokio::test]
    async fn candidate_failures_map_without_carrier_or_text_fallbacks() {
        for (failure, expected) in [
            (RuntimeFailureV2::Resolve, ConnectErrorCode::ResolveFailed),
            (RuntimeFailureV2::Start, ConnectErrorCode::DialFailed),
            (RuntimeFailureV2::Canceled, ConnectErrorCode::Canceled),
            (RuntimeFailureV2::Timeout, ConnectErrorCode::Timeout),
        ] {
            let dials: FuturesUnordered<BoxFuture<'static, DialResult>> = FuturesUnordered::new();
            dials.push(async move { ("q1".to_owned(), Err(failure)) }.boxed());
            let error = select_winner(
                dials,
                tokio::time::Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await
            .expect_err("candidate preparation fails");
            assert_eq!(error.code(), expected);
        }
    }
}
