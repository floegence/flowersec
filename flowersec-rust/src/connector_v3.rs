//! Strict Flowersec v3 native connector.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use rustls::pki_types::CertificateDer;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    artifact_v3::{
        AdmissionStatusV3, ArtifactLeaseV3, ArtifactSpendErrorV3, CanonicalCandidateV3,
        CarrierWireV3, ClaimedArtifactLeaseV3, ConnectionPlanV3, SpendOperationV3, TlsPolicyWireV3,
        decode_fsa3, decode32,
    },
    connection_controller::RetryDisposition,
    native_runtime_v2::ConnectorOptions as ConnectorOptionsV2,
    raw_quic_v3::{self, RawQuicDialFailureV3},
    session_handlers::{RpcHandlerSnapshot, RpcHandlers, rpc_router_v3},
    session_v3::{SessionConfigV3, SessionDeadlinesV3, establish_session_v3},
    tls_v3::NativeTlsPolicyV3,
    transport_v2::Session,
    transport_v3::{
        ALPN_DIRECT_V3, ALPN_TUNNEL_V3, CarrierSessionV3, CarrierStreamV3, PathKind, SessionRole,
        carrier_inbound_stream_limit_v3,
    },
    websocket_v3::{self, SUBPROTOCOL_DIRECT_V3, SUBPROTOCOL_TUNNEL_V3, WebSocketError},
};

/// Stable, redacted Flowersec v3 connection failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectErrorCode {
    ArtifactInvalid,
    Expired,
    TransportSecurityUnsupported,
    TransportSecurityFailed,
    ConnectionFailed,
}

impl ConnectErrorCode {
    /// Returns the canonical public v3 code string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactInvalid => "artifact_invalid",
            Self::Expired => "expired_artifact",
            Self::TransportSecurityUnsupported => "transport_security_unsupported",
            Self::TransportSecurityFailed => "transport_security_failed",
            Self::ConnectionFailed => "connection_failed",
        }
    }
}

impl fmt::Display for ConnectErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted v3 connection failure with a closed five-code public surface.
#[derive(Clone, Copy, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec connection failed (code={code})")]
pub struct ConnectError {
    code: ConnectErrorCode,
    controller_retryable: bool,
    policy_trigger_mask: u8,
    failed_candidate_mask: u8,
}

impl fmt::Debug for ConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectError")
            .field("code", &self.code)
            .field("retry_disposition", &self.retry_disposition())
            .finish()
    }
}

impl ConnectError {
    pub const fn code(&self) -> ConnectErrorCode {
        self.code
    }

    /// Returns the canonical public v3 code string.
    pub const fn as_str(&self) -> &'static str {
        self.code.as_str()
    }

    /// Returns whether a one-shot failure is terminal or may be retried with a fresh artifact.
    pub const fn retry_disposition(&self) -> RetryDisposition {
        if self.controller_retryable {
            RetryDisposition::Retryable
        } else {
            RetryDisposition::Terminal
        }
    }

    #[cfg(test)]
    pub(crate) const fn controller_retryable(&self) -> bool {
        self.controller_retryable
    }

    #[cfg(test)]
    pub(crate) const fn from_runtime_code(code: ConnectErrorCode) -> Self {
        public_error(code)
    }

    pub(crate) const fn from_terminal_runtime_code(code: ConnectErrorCode) -> Self {
        terminal_error(code)
    }

    pub(crate) const fn with_v3_candidate_masks(
        mut self,
        policy_trigger_mask: u8,
        failed_candidate_mask: u8,
    ) -> Self {
        self.policy_trigger_mask = policy_trigger_mask;
        self.failed_candidate_mask = failed_candidate_mask;
        self
    }

    pub(crate) const fn v3_policy_trigger_mask(&self) -> u8 {
        self.policy_trigger_mask
    }

    pub(crate) const fn v3_failed_candidate_mask(&self) -> u8 {
        self.failed_candidate_mask
    }
}

/// Native v3 connector trust, handler, and lifecycle configuration.
#[derive(Clone)]
pub struct ConnectorOptions {
    inner: ConnectorOptionsV2,
}

impl fmt::Debug for ConnectorOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectorOptions { <redacted> }")
    }
}

impl ConnectorOptions {
    /// Creates v3 connector options with the shared ten-second deadline.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: ConnectorOptionsV2::new(),
        }
    }

    pub fn with_trust_roots_der(mut self, roots: Vec<Vec<u8>>) -> Result<Self, ConnectError> {
        self.inner = self
            .inner
            .with_trust_roots_der(roots)
            .map_err(|_| terminal_error(ConnectErrorCode::ArtifactInvalid))?;
        Ok(self)
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Result<Self, ConnectError> {
        self.inner = self
            .inner
            .with_connect_timeout(timeout)
            .map_err(|_| terminal_error(ConnectErrorCode::ArtifactInvalid))?;
        Ok(self)
    }

    pub fn with_close_flush_timeout(mut self, timeout: Duration) -> Result<Self, ConnectError> {
        self.inner = self
            .inner
            .with_close_flush_timeout(timeout)
            .map_err(|_| terminal_error(ConnectErrorCode::ArtifactInvalid))?;
        Ok(self)
    }

    pub fn with_websocket_origin(
        mut self,
        origin: impl Into<String>,
    ) -> Result<Self, ConnectError> {
        self.inner = self
            .inner
            .with_websocket_origin(origin)
            .map_err(|_| terminal_error(ConnectErrorCode::ArtifactInvalid))?;
        Ok(self)
    }

    pub fn with_rpc_handlers(mut self, handlers: RpcHandlers) -> Self {
        self.inner = self.inner.with_rpc_handlers(handlers);
        self
    }

    pub fn trust_roots_der(&self) -> &[Vec<u8>] {
        self.inner.trust_roots_der()
    }

    pub const fn connect_timeout(&self) -> Duration {
        self.inner.connect_timeout()
    }

    pub(crate) const fn close_flush_timeout(&self) -> Option<Duration> {
        self.inner.close_flush_timeout()
    }

    pub(crate) fn websocket_origin(&self) -> Option<&str> {
        self.inner.websocket_origin()
    }

    pub(crate) fn rpc_handler_snapshot(&self) -> Option<Arc<RpcHandlerSnapshot>> {
        self.inner.rpc_handler_snapshot()
    }
}

const MAX_FSA3_BYTES: usize = 72;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateFailureV3 {
    InvalidArtifact,
    Unsupported,
    PolicyExpired,
    Security,
    Connection,
    Canceled,
    Timeout,
}

pub(crate) type CandidatePrepareFutureV3<'a> = Pin<
    Box<dyn Future<Output = Result<Arc<dyn CarrierSessionV3>, CandidateFailureV3>> + Send + 'a>,
>;

pub(crate) trait CandidatePreparerV3: Send + Sync {
    fn prepare<'a>(
        &'a self,
        candidate: &'a CanonicalCandidateV3,
        plan: &'a ConnectionPlanV3,
        options: &'a ConnectorOptions,
        deadline: tokio::time::Instant,
        cancellation: &'a CancellationToken,
    ) -> CandidatePrepareFutureV3<'a>;
}

struct ProductionCandidatePreparerV3;

impl CandidatePreparerV3 for ProductionCandidatePreparerV3 {
    fn prepare<'a>(
        &'a self,
        candidate: &'a CanonicalCandidateV3,
        plan: &'a ConnectionPlanV3,
        options: &'a ConnectorOptions,
        deadline: tokio::time::Instant,
        cancellation: &'a CancellationToken,
    ) -> CandidatePrepareFutureV3<'a> {
        Box::pin(prepare_candidate(
            candidate,
            plan,
            options,
            deadline,
            cancellation,
        ))
    }
}

/// Establishes one strict v3 session from a single-use artifact lease.
pub async fn connect_v3(
    lease: ArtifactLeaseV3,
    options: ConnectorOptions,
) -> Result<Arc<dyn Session>, ConnectError> {
    connect_v3_with_cancellation(lease, options, CancellationToken::new()).await
}

/// Establishes one strict v3 session with caller-owned cancellation.
pub async fn connect_v3_with_cancellation(
    lease: ArtifactLeaseV3,
    options: ConnectorOptions,
    cancellation: CancellationToken,
) -> Result<Arc<dyn Session>, ConnectError> {
    connect_v3_with_cancellation_and_preparer(
        lease,
        options,
        cancellation,
        &ProductionCandidatePreparerV3,
    )
    .await
}

pub(crate) async fn connect_v3_with_cancellation_and_preparer(
    lease: ArtifactLeaseV3,
    options: ConnectorOptions,
    cancellation: CancellationToken,
    preparer: &dyn CandidatePreparerV3,
) -> Result<Arc<dyn Session>, ConnectError> {
    let claimed = PreSpendLeaseGuardV3::new(
        lease
            .claim()
            .map_err(|_| terminal_error(ConnectErrorCode::ArtifactInvalid))?,
    );
    // A pre-canceled one-shot still owns the lease after claiming it. Retire
    // that claim before returning so the source cannot hand the idle lease to
    // a later attempt.
    if cancellation.is_cancelled() {
        let _ = claimed.retire().await;
        return Err(terminal_error(ConnectErrorCode::ConnectionFailed));
    }
    let plan = match claimed.artifact().connection_plan() {
        Ok(plan) => plan,
        Err(_) => {
            let _ = claimed.retire().await;
            return Err(public_error(ConnectErrorCode::ArtifactInvalid));
        }
    };
    if let Err(error) = require_unexpired(&plan) {
        let _ = claimed.retire().await;
        return Err(error);
    }
    let attempt_now = unix_seconds();
    let deadline = tokio::time::Instant::now() + options.connect_timeout();
    let mut aggregate = CandidateFailureV3::Unsupported;
    let mut policy_trigger_mask = 0_u8;
    // Only candidates that pass the local capability filter can contribute to
    // failure provenance.  A skipped carrier is not an attempted endpoint and
    // must not influence policy refresh or replacement selection.
    let mut failed_candidate_mask = 0_u8;
    let mut attempted = false;
    let race_cancellation = cancellation.child_token();
    let plan_ref = &plan;
    let options_ref = &options;
    let mut attempts = FuturesUnordered::new();

    for (candidate_index, candidate) in plan.candidates.iter().enumerate() {
        if !candidate_is_supported(candidate, &options) {
            continue;
        }
        let snapshot = match snapshot_candidate_policy(candidate, attempt_now) {
            Ok(snapshot) => snapshot,
            Err(failure) => {
                failed_candidate_mask |= 1_u8 << candidate_index;
                if matches!(failure, CandidateFailureV3::PolicyExpired) {
                    policy_trigger_mask |= 1_u8 << candidate_index;
                }
                aggregate = aggregate_failure(aggregate, failure);
                continue;
            }
        };
        attempted = true;
        let attempt_cancellation = race_cancellation.child_token();
        attempts.push(async move {
            let result = preparer
                .prepare(
                    &snapshot,
                    plan_ref,
                    options_ref,
                    deadline,
                    &attempt_cancellation,
                )
                .await;
            (candidate_index, candidate, result)
        });
    }

    if !attempted {
        return Err(finalize_candidate_race(
            claimed,
            &plan,
            aggregate,
            policy_trigger_mask,
            failed_candidate_mask,
        )
        .await);
    }
    while let Some((candidate_index, candidate, result)) = attempts.next().await {
        match result {
            Ok(carrier) => {
                race_cancellation.cancel();
                let admission = admit_candidate_and_establish(
                    claimed,
                    candidate,
                    &plan,
                    carrier,
                    &options,
                    deadline,
                    &cancellation,
                );
                tokio::pin!(admission);
                loop {
                    tokio::select! {
                        biased;
                        result = &mut admission => return result,
                        loser = attempts.next(), if !attempts.is_empty() => {
                            if let Some((_, _, Ok(carrier))) = loser {
                                carrier.abort();
                            }
                        }
                    }
                }
            }
            Err(failure) => {
                failed_candidate_mask |= 1_u8 << candidate_index;
                if matches!(
                    candidate.tls,
                    crate::artifact_v3::TlsPolicyWireV3::Pin { .. }
                ) && matches!(
                    failure,
                    CandidateFailureV3::PolicyExpired | CandidateFailureV3::Security
                ) {
                    policy_trigger_mask |= 1_u8 << candidate_index;
                }
                aggregate = aggregate_failure(aggregate, failure);
            }
        }
    }

    Err(finalize_candidate_race(
        claimed,
        &plan,
        aggregate,
        policy_trigger_mask,
        failed_candidate_mask,
    )
    .await)
}

async fn finalize_candidate_race(
    claimed: PreSpendLeaseGuardV3,
    plan: &ConnectionPlanV3,
    aggregate: CandidateFailureV3,
    policy_trigger_mask: u8,
    failed_candidate_mask: u8,
) -> ConnectError {
    // Expiry at the race boundary is authoritative over candidate failures.
    let expiry = require_unexpired(plan).err();
    let _ = claimed.retire().await;
    if let Some(error) = expiry {
        return error;
    }
    let error = match aggregate {
        CandidateFailureV3::InvalidArtifact => public_error(ConnectErrorCode::ArtifactInvalid),
        CandidateFailureV3::Unsupported => {
            public_error(ConnectErrorCode::TransportSecurityUnsupported)
        }
        CandidateFailureV3::PolicyExpired | CandidateFailureV3::Security => {
            public_error(ConnectErrorCode::TransportSecurityFailed)
        }
        CandidateFailureV3::Canceled => terminal_error(ConnectErrorCode::ConnectionFailed),
        CandidateFailureV3::Timeout | CandidateFailureV3::Connection => {
            public_error(ConnectErrorCode::ConnectionFailed)
        }
    };
    error.with_v3_candidate_masks(policy_trigger_mask, failed_candidate_mask)
}

async fn prepare_candidate(
    candidate: &CanonicalCandidateV3,
    plan: &ConnectionPlanV3,
    options: &ConnectorOptions,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Arc<dyn CarrierSessionV3>, CandidateFailureV3> {
    match candidate.carrier {
        CarrierWireV3::Websocket => {
            prepare_websocket(
                candidate,
                plan,
                options
                    .websocket_origin()
                    .ok_or(CandidateFailureV3::Unsupported)?,
                options,
                deadline,
                cancellation,
            )
            .await
        }
        CarrierWireV3::RawQuic => {
            prepare_raw_quic(candidate, plan, options, deadline, cancellation).await
        }
        CarrierWireV3::Webtransport => Err(CandidateFailureV3::Unsupported),
    }
}

async fn prepare_websocket(
    candidate: &CanonicalCandidateV3,
    plan: &ConnectionPlanV3,
    origin: &str,
    options: &ConnectorOptions,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Arc<dyn CarrierSessionV3>, CandidateFailureV3> {
    let tls = client_tls_policy(candidate, options)?
        .client_config(b"http/1.1")
        .map_err(|_| CandidateFailureV3::Unsupported)?;
    let subprotocol = match plan.path {
        PathKind::Direct => SUBPROTOCOL_DIRECT_V3,
        PathKind::Tunnel => SUBPROTOCOL_TUNNEL_V3,
    };
    let capacity = carrier_inbound_stream_limit_v3(plan.session.max_inbound_streams)
        .map_err(|_| CandidateFailureV3::InvalidArtifact)?;
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(CandidateFailureV3::Canceled),
        result = tokio::time::timeout_at(
            deadline,
            websocket_v3::dial(
                &candidate.normalized_url,
                subprotocol,
                origin,
                tls,
                capacity,
            ),
        ) => match result {
            Err(_) => Err(CandidateFailureV3::Timeout),
            Ok(Err(WebSocketError::Tls(_))) => Err(CandidateFailureV3::Security),
            Ok(Err(WebSocketError::InvalidConfiguration)) => {
                Err(CandidateFailureV3::InvalidArtifact)
            }
            Ok(Err(_)) => Err(CandidateFailureV3::Connection),
            Ok(Ok(carrier)) => Ok(carrier),
        },
    }
}

async fn prepare_raw_quic(
    candidate: &CanonicalCandidateV3,
    plan: &ConnectionPlanV3,
    options: &ConnectorOptions,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Arc<dyn CarrierSessionV3>, CandidateFailureV3> {
    let alpn = match plan.path {
        PathKind::Direct => ALPN_DIRECT_V3,
        PathKind::Tunnel => ALPN_TUNNEL_V3,
    };
    let tls = client_tls_policy(candidate, options)?;
    let capacity = carrier_inbound_stream_limit_v3(plan.session.max_inbound_streams)
        .map_err(|_| CandidateFailureV3::InvalidArtifact)?;
    raw_quic_v3::dial(
        &candidate.normalized_url,
        &tls,
        alpn,
        capacity,
        deadline,
        cancellation.clone(),
    )
    .await
    .map_err(|failure| match failure {
        RawQuicDialFailureV3::Invalid => CandidateFailureV3::InvalidArtifact,
        RawQuicDialFailureV3::Security => CandidateFailureV3::Security,
        RawQuicDialFailureV3::Canceled => CandidateFailureV3::Canceled,
        RawQuicDialFailureV3::Timeout => CandidateFailureV3::Timeout,
        RawQuicDialFailureV3::Resolve | RawQuicDialFailureV3::Connection => {
            CandidateFailureV3::Connection
        }
    })
}

fn client_tls_policy(
    candidate: &CanonicalCandidateV3,
    options: &ConnectorOptions,
) -> Result<NativeTlsPolicyV3, CandidateFailureV3> {
    let tls_policy = match &candidate.tls {
        TlsPolicyWireV3::Pin { pins } => NativeTlsPolicyV3::pin(
            pins.iter()
                .map(|pin| decode32(&pin.value_b64u).ok_or(CandidateFailureV3::InvalidArtifact))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        TlsPolicyWireV3::Ca {} if options.trust_roots_der().is_empty() => {
            NativeTlsPolicyV3::ca_with_platform_roots()
        }
        TlsPolicyWireV3::Ca {} => NativeTlsPolicyV3::ca_with_configured_roots(
            options
                .trust_roots_der()
                .iter()
                .cloned()
                .map(CertificateDer::from),
        ),
    }
    .map_err(|_| CandidateFailureV3::Unsupported)?;
    Ok(tls_policy)
}

fn snapshot_candidate_policy(
    candidate: &CanonicalCandidateV3,
    attempt_now: u64,
) -> Result<CanonicalCandidateV3, CandidateFailureV3> {
    let mut snapshot = candidate.clone();
    if let TlsPolicyWireV3::Pin { pins } = &mut snapshot.tls {
        pins.retain(|pin| attempt_now < pin.not_after_unix_s);
        if pins.is_empty() {
            return Err(CandidateFailureV3::PolicyExpired);
        }
    }
    Ok(snapshot)
}

fn candidate_is_supported(candidate: &CanonicalCandidateV3, options: &ConnectorOptions) -> bool {
    match candidate.carrier {
        CarrierWireV3::Websocket => options.websocket_origin().is_some(),
        CarrierWireV3::RawQuic => true,
        CarrierWireV3::Webtransport => false,
    }
}

async fn admit_and_establish(
    claimed: PreSpendLeaseGuardV3,
    candidate: &CanonicalCandidateV3,
    plan: &ConnectionPlanV3,
    carrier: Arc<dyn CarrierSessionV3>,
    options: &ConnectorOptions,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Arc<dyn Session>, ConnectError> {
    if let Err(error) = require_active(deadline, cancellation) {
        let _ = claimed.retire().await;
        return Err(error);
    }
    if let Err(error) = require_unexpired(plan) {
        let _ = claimed.retire().await;
        return Err(error);
    }
    let fsb3 = match claimed.artifact().encode_fsb3(&candidate.id) {
        Ok(frame) => frame,
        Err(_) => {
            let _ = claimed.retire().await;
            return Err(public_error(ConnectErrorCode::ArtifactInvalid));
        }
    };
    if let Err(error) = require_unexpired(plan) {
        let _ = claimed.retire().await;
        return Err(error);
    }
    // The owned task makes caller-future drops explicit. Cancellation aborts
    // the callback; the lease guard still commits the irreversible consumed
    // state because the durable result is then unknown.
    let spend_operation = claimed
        .begin_spend()
        .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?;
    let mut spend = AbortOnDropJoinHandle::new(tokio::spawn(spend_operation.commit()));
    let spent = tokio::select! {
        biased;
        result = spend.wait() => result,
        _ = cancellation.cancelled() => {
            spend.abort();
            let _ = spend.wait().await;
            return Err(terminal_error(ConnectErrorCode::ConnectionFailed));
        }
        _ = tokio::time::sleep_until(deadline) => {
            spend.abort();
            let _ = spend.wait().await;
            return Err(public_error(ConnectErrorCode::ConnectionFailed));
        }
    };
    spent
        .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?
        .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?;
    require_active(deadline, cancellation)?;
    // A spend may complete across the initiation expiry boundary. The lease is
    // already consumed, but the credential must never be sent after expiry.
    require_unexpired(plan)?;

    let admission = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(terminal_error(ConnectErrorCode::ConnectionFailed)),
        result = tokio::time::timeout_at(deadline, carrier.open_stream()) => {
            result
                .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?
                .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?
        }
    };
    write_all(admission.as_ref(), &fsb3.raw, deadline, cancellation).await?;
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(terminal_error(ConnectErrorCode::ConnectionFailed)),
        result = tokio::time::timeout_at(deadline, admission.close_write_delivered()) => {
            result
                .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?
                .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?;
        }
    }
    let response = read_to_end(admission.as_ref(), deadline, cancellation).await?;
    let response =
        decode_fsa3(&response).map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?;
    if response.status != AdmissionStatusV3::Success {
        return Err(admission_failure(response.status));
    }
    if candidate.carrier == CarrierWireV3::Websocket {
        carrier
            .set_multiplexer_client(plan.role == SessionRole::Client)
            .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?;
    }
    let rpc_handler = options.rpc_handler_snapshot().map(rpc_router_v3);
    let mut deadlines = SessionDeadlinesV3 {
        establish: plan.session.establish_timeout,
        rekey_prepare: plan.session.rekey_prepare_timeout,
        rekey_completion: plan.session.rekey_completion_timeout,
        ..Default::default()
    };
    if let Some(close_flush) = options.close_flush_timeout() {
        deadlines.close_flush = close_flush;
    }
    let config = SessionConfigV3 {
        role: plan.role,
        path: plan.path,
        channel_id: plan.session.channel_id.clone(),
        session_contract_hash: plan.session.session_contract_hash,
        suite: plan.session.suite,
        psk: plan.session.psk,
        max_inbound_streams: plan.session.max_inbound_streams,
        idle_timeout: plan.session.idle_timeout,
        local_admission_binding: fsb3.binding,
        peer_admission_binding: (plan.path == PathKind::Direct).then_some(fsb3.binding),
        local_endpoint_instance_id: plan.local_endpoint_instance_id.clone(),
        expected_peer_endpoint_instance_id: plan.expected_peer_endpoint_instance_id.clone(),
        rpc_handler,
        deadlines,
    };
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(terminal_error(ConnectErrorCode::ConnectionFailed)),
        result = tokio::time::timeout_at(deadline, establish_session_v3(carrier, config)) => {
            match result {
                Err(_) | Ok(Err(_)) => Err(public_error(ConnectErrorCode::ConnectionFailed)),
                Ok(Ok(session)) => Ok(session),
            }
        }
    }
}

async fn admit_candidate_and_establish(
    claimed: PreSpendLeaseGuardV3,
    candidate: &CanonicalCandidateV3,
    plan: &ConnectionPlanV3,
    carrier: Arc<dyn CarrierSessionV3>,
    options: &ConnectorOptions,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Arc<dyn Session>, ConnectError> {
    let mut cleanup = CarrierAbortGuard::new(carrier.clone());
    let result = admit_and_establish(
        claimed,
        candidate,
        plan,
        carrier.clone(),
        options,
        deadline,
        cancellation,
    )
    .await;
    if result.is_ok() {
        cleanup.disarm();
    }
    result
}

struct PreSpendLeaseGuardV3 {
    claimed: Option<ClaimedArtifactLeaseV3>,
    runtime: tokio::runtime::Handle,
}

impl PreSpendLeaseGuardV3 {
    fn new(claimed: ClaimedArtifactLeaseV3) -> Self {
        Self {
            claimed: Some(claimed),
            runtime: tokio::runtime::Handle::current(),
        }
    }

    fn artifact(&self) -> &crate::artifact_v3::ArtifactV3 {
        self.claimed
            .as_ref()
            .expect("pre-spend lease ownership is present")
            .artifact()
    }

    async fn retire(mut self) -> Result<(), ArtifactSpendErrorV3> {
        self.claimed
            .take()
            .expect("pre-spend lease ownership is present")
            .retire()
            .await
    }

    fn begin_spend(mut self) -> Result<SpendOperationV3, ArtifactSpendErrorV3> {
        self.claimed
            .take()
            .expect("pre-spend lease ownership is present")
            .begin_spend()
    }
}

impl Drop for PreSpendLeaseGuardV3 {
    fn drop(&mut self) {
        let Some(claimed) = self.claimed.take() else {
            return;
        };
        let Ok(retirement) = claimed.begin_retire() else {
            return;
        };
        self.runtime.spawn(async move {
            let _ = retirement.finish().await;
        });
    }
}

struct CarrierAbortGuard {
    carrier: Arc<dyn CarrierSessionV3>,
    armed: bool,
}

impl CarrierAbortGuard {
    fn new(carrier: Arc<dyn CarrierSessionV3>) -> Self {
        Self {
            carrier,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CarrierAbortGuard {
    fn drop(&mut self) {
        if self.armed {
            self.carrier.abort();
        }
    }
}

/// Keeps a spawned spend task owned by the admission future.
///
/// Dropping a `JoinHandle` detaches its task, which would leave a callback
/// that ignores cancellation running after the connector future is gone. The
/// guard aborts that task on drop so `SpendCompletionV3` can burn the lease.
struct AbortOnDropJoinHandle<T> {
    handle: JoinHandle<T>,
}

impl<T> AbortOnDropJoinHandle<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self { handle }
    }

    fn abort(&self) {
        self.handle.abort();
    }

    async fn wait(&mut self) -> Result<T, tokio::task::JoinError> {
        (&mut self.handle).await
    }
}

impl<T> Drop for AbortOnDropJoinHandle<T> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn write_all(
    stream: &dyn CarrierStreamV3,
    mut payload: &[u8],
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<(), ConnectError> {
    while !payload.is_empty() {
        let written = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(terminal_error(ConnectErrorCode::ConnectionFailed)),
            result = tokio::time::timeout_at(deadline, stream.write(payload)) => {
                result
                    .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?
                    .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?
            }
        };
        if written == 0 {
            return Err(public_error(ConnectErrorCode::ConnectionFailed));
        }
        payload = &payload[written..];
    }
    Ok(())
}

async fn read_to_end(
    stream: &dyn CarrierStreamV3,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, ConnectError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; MAX_FSA3_BYTES + 1];
    loop {
        let count = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(terminal_error(ConnectErrorCode::ConnectionFailed)),
            result = tokio::time::timeout_at(deadline, stream.read(&mut buffer)) => {
                result
                    .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?
                    .map_err(|_| public_error(ConnectErrorCode::ConnectionFailed))?
            }
        };
        if count == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(count) > MAX_FSA3_BYTES {
            return Err(public_error(ConnectErrorCode::ConnectionFailed));
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

fn admission_failure(status: AdmissionStatusV3) -> ConnectError {
    match status {
        AdmissionStatusV3::Reject => {
            ConnectError::from_terminal_runtime_code(ConnectErrorCode::ConnectionFailed)
        }
        AdmissionStatusV3::Retryable => public_error(ConnectErrorCode::ConnectionFailed),
        AdmissionStatusV3::Success => unreachable!("success admission has no failure"),
    }
}

fn aggregate_failure(current: CandidateFailureV3, next: CandidateFailureV3) -> CandidateFailureV3 {
    fn priority(failure: CandidateFailureV3) -> u8 {
        match failure {
            CandidateFailureV3::InvalidArtifact => 7,
            CandidateFailureV3::Canceled => 6,
            // A security or policy decision is stronger evidence than a
            // carrier timeout. Completion order must not hide that failure.
            CandidateFailureV3::PolicyExpired | CandidateFailureV3::Security => 5,
            CandidateFailureV3::Timeout => 4,
            CandidateFailureV3::Connection => 3,
            CandidateFailureV3::Unsupported => 2,
        }
    }
    if priority(next) > priority(current) {
        next
    } else {
        current
    }
}

fn require_unexpired(plan: &ConnectionPlanV3) -> Result<(), ConnectError> {
    if plan.expires_at_unix_seconds <= unix_seconds() {
        Err(public_error(ConnectErrorCode::Expired))
    } else {
        Ok(())
    }
}

fn require_active(
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<(), ConnectError> {
    if cancellation.is_cancelled() {
        Err(terminal_error(ConnectErrorCode::ConnectionFailed))
    } else if tokio::time::Instant::now() >= deadline {
        Err(public_error(ConnectErrorCode::ConnectionFailed))
    } else {
        Ok(())
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const fn public_error(code: ConnectErrorCode) -> ConnectError {
    ConnectError {
        code,
        controller_retryable: matches!(
            code,
            ConnectErrorCode::Expired | ConnectErrorCode::ConnectionFailed
        ),
        policy_trigger_mask: 0,
        failed_candidate_mask: 0,
    }
}

const fn terminal_error(code: ConnectErrorCode) -> ConnectError {
    ConnectError {
        code,
        controller_retryable: false,
        policy_trigger_mask: 0,
        failed_candidate_mask: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead as _, BufReader},
        net::{Ipv4Addr, SocketAddr},
        path::Path,
        process::{Child, Command, Stdio},
        sync::{
            Arc, Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use bytes::Bytes;
    use cert_test_builder::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use time::{Duration as TimeDuration, OffsetDateTime};

    use super::*;
    use crate::{
        Acceptor, IncomingStream, SessionError, SessionHandlerOptions, SessionHandlers,
        StreamHandler, TunnelAuthorizationError, TunnelAuthorizationResponse, TunnelAuthorizer,
        TunnelRuntime, TunnelRuntimeOptions, WebSocketAcceptorOptions,
        artifact_v3::{ArtifactV3, hash_lp, jcs_value},
    };

    struct TestIdentityV3 {
        chain: Vec<Vec<u8>>,
        key: Vec<u8>,
    }

    struct ProductStreamHandler(tokio::sync::mpsc::UnboundedSender<Bytes>);

    #[derive(Clone, Copy, Debug)]
    enum HangingAdmissionPhase {
        Open,
        FinishDelivery,
    }

    #[derive(Debug)]
    struct HangingAdmissionCarrier {
        phase: HangingAdmissionPhase,
        entered: Arc<tokio::sync::Semaphore>,
        aborts: AtomicUsize,
        opens: AtomicUsize,
        credential_writes: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct HangingAdmissionStream {
        entered: Arc<tokio::sync::Semaphore>,
        credential_writes: Arc<AtomicUsize>,
    }

    struct HangingCandidatePreparer {
        entered: Arc<tokio::sync::Notify>,
    }

    struct WinnerWithUncooperativeLoserPreparer {
        barrier: Arc<tokio::sync::Barrier>,
        winner: Arc<dyn CarrierSessionV3>,
    }

    struct WinnerWithLatePreparedLoserPreparer {
        barrier: Arc<tokio::sync::Barrier>,
        release_loser: Arc<tokio::sync::Notify>,
        winner: Arc<dyn CarrierSessionV3>,
        loser: Arc<dyn CarrierSessionV3>,
    }

    struct FailingCandidatePreparer {
        failures: Vec<(&'static str, CandidateFailureV3)>,
    }

    impl CandidatePreparerV3 for FailingCandidatePreparer {
        fn prepare<'a>(
            &'a self,
            candidate: &'a CanonicalCandidateV3,
            _plan: &'a ConnectionPlanV3,
            _options: &'a ConnectorOptions,
            _deadline: tokio::time::Instant,
            _cancellation: &'a CancellationToken,
        ) -> CandidatePrepareFutureV3<'a> {
            let failure = self
                .failures
                .iter()
                .find_map(|(id, failure)| (candidate.id == *id).then_some(*failure))
                .expect("test candidate has a configured failure");
            Box::pin(async move { Err(failure) })
        }
    }

    impl CandidatePreparerV3 for HangingCandidatePreparer {
        fn prepare<'a>(
            &'a self,
            _candidate: &'a CanonicalCandidateV3,
            _plan: &'a ConnectionPlanV3,
            _options: &'a ConnectorOptions,
            _deadline: tokio::time::Instant,
            _cancellation: &'a CancellationToken,
        ) -> CandidatePrepareFutureV3<'a> {
            let entered = self.entered.clone();
            Box::pin(async move {
                entered.notify_one();
                std::future::pending().await
            })
        }
    }

    impl CandidatePreparerV3 for WinnerWithUncooperativeLoserPreparer {
        fn prepare<'a>(
            &'a self,
            candidate: &'a CanonicalCandidateV3,
            _plan: &'a ConnectionPlanV3,
            _options: &'a ConnectorOptions,
            _deadline: tokio::time::Instant,
            _cancellation: &'a CancellationToken,
        ) -> CandidatePrepareFutureV3<'a> {
            let barrier = self.barrier.clone();
            let winner = self.winner.clone();
            Box::pin(async move {
                barrier.wait().await;
                if candidate.id == "winner" {
                    Ok(winner)
                } else {
                    std::future::pending().await
                }
            })
        }
    }

    impl CandidatePreparerV3 for WinnerWithLatePreparedLoserPreparer {
        fn prepare<'a>(
            &'a self,
            candidate: &'a CanonicalCandidateV3,
            _plan: &'a ConnectionPlanV3,
            _options: &'a ConnectorOptions,
            _deadline: tokio::time::Instant,
            _cancellation: &'a CancellationToken,
        ) -> CandidatePrepareFutureV3<'a> {
            let barrier = self.barrier.clone();
            let release_loser = self.release_loser.clone();
            let winner = self.winner.clone();
            let loser = self.loser.clone();
            Box::pin(async move {
                barrier.wait().await;
                if candidate.id == "winner" {
                    Ok(winner)
                } else {
                    release_loser.notified().await;
                    Ok(loser)
                }
            })
        }
    }

    #[async_trait]
    impl CarrierSessionV3 for HangingAdmissionCarrier {
        fn kind(&self) -> crate::transport_v3::CarrierKind {
            crate::transport_v3::CarrierKind::Wss
        }

        fn set_multiplexer_client(&self, _client: bool) -> std::io::Result<()> {
            Ok(())
        }

        fn inbound_bidirectional_stream_capacity(&self) -> u32 {
            3
        }

        async fn open_stream(&self) -> std::io::Result<Arc<dyn CarrierStreamV3>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if matches!(self.phase, HangingAdmissionPhase::Open) {
                self.entered.add_permits(1);
                return std::future::pending().await;
            }
            Ok(Arc::new(HangingAdmissionStream {
                entered: self.entered.clone(),
                credential_writes: self.credential_writes.clone(),
            }))
        }

        async fn accept_stream(&self) -> std::io::Result<Arc<dyn CarrierStreamV3>> {
            std::future::pending().await
        }

        async fn close(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn abort(&self) {
            self.aborts.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CarrierStreamV3 for HangingAdmissionStream {
        async fn read(&self, _payload: &mut [u8]) -> std::io::Result<usize> {
            std::future::pending().await
        }

        async fn write(&self, payload: &[u8]) -> std::io::Result<usize> {
            self.credential_writes.fetch_add(1, Ordering::SeqCst);
            Ok(payload.len())
        }

        async fn close_write(&self) -> std::io::Result<()> {
            Ok(())
        }

        async fn close_write_delivered(&self) -> std::io::Result<()> {
            self.entered.add_permits(1);
            std::future::pending().await
        }

        async fn stop_sending(&self) -> std::io::Result<()> {
            Ok(())
        }

        async fn reset(&self) -> std::io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl StreamHandler for ProductStreamHandler {
        async fn handle(
            &self,
            incoming: &IncomingStream,
            _cancellation: CancellationToken,
        ) -> Result<(), SessionError> {
            let payload = incoming
                .stream()
                .read()
                .await?
                .ok_or(SessionError::OperationFailed)?;
            let _ = self.0.send(payload);
            Ok(())
        }
    }

    #[tokio::test]
    async fn admission_open_obeys_the_overall_timeout_and_aborts_the_carrier() {
        let (result, carrier) = run_hanging_admission(
            HangingAdmissionPhase::Open,
            Duration::from_millis(25),
            false,
        )
        .await;

        let error = result.unwrap_err();
        assert_eq!(error.code(), ConnectErrorCode::ConnectionFailed);
        assert!(error.controller_retryable());
        assert_eq!(carrier.aborts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn admission_open_prefers_cancellation_and_aborts_the_carrier() {
        let (result, carrier) =
            run_hanging_admission(HangingAdmissionPhase::Open, Duration::from_secs(1), true).await;

        let error = result.unwrap_err();
        assert_eq!(error.code(), ConnectErrorCode::ConnectionFailed);
        assert!(!error.controller_retryable());
        assert_eq!(carrier.aborts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn admission_finish_delivery_obeys_the_overall_timeout_and_aborts_the_carrier() {
        let (result, carrier) = run_hanging_admission(
            HangingAdmissionPhase::FinishDelivery,
            Duration::from_millis(25),
            false,
        )
        .await;

        let error = result.unwrap_err();
        assert_eq!(error.code(), ConnectErrorCode::ConnectionFailed);
        assert!(error.controller_retryable());
        assert_eq!(carrier.aborts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn admission_finish_delivery_prefers_cancellation_and_aborts_the_carrier() {
        let (result, carrier) = run_hanging_admission(
            HangingAdmissionPhase::FinishDelivery,
            Duration::from_secs(1),
            true,
        )
        .await;

        let error = result.unwrap_err();
        assert_eq!(error.code(), ConnectErrorCode::ConnectionFailed);
        assert!(!error.controller_retryable());
        assert_eq!(carrier.aborts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_bounds_an_in_flight_spend_and_consumes_the_lease() {
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "websocket",
            "id": "ca",
            "tls": {"mode": "ca"},
            "url": "wss://127.0.0.1:443/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3"
        })]);
        let plan = artifact.connection_plan().expect("valid connection plan");
        let candidate = plan.candidates[0].clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let settled = Arc::new(AtomicUsize::new(0));
        let spend_entered = entered.clone();
        let spend_release = release.clone();
        let spend_settled = settled.clone();
        let lease = ArtifactLeaseV3::new(artifact, move || async move {
            spend_entered.notify_one();
            spend_release.notified().await;
            spend_settled.store(1, Ordering::Release);
            Ok(())
        });
        let observed_lease = lease.clone();
        let claimed = lease.claim().expect("claim lease");
        let carrier = Arc::new(HangingAdmissionCarrier {
            phase: HangingAdmissionPhase::Open,
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            aborts: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            credential_writes: Arc::new(AtomicUsize::new(0)),
        });
        let cancellation = CancellationToken::new();
        let options = ConnectorOptions::new();
        let mut operation = Box::pin(admit_candidate_and_establish(
            PreSpendLeaseGuardV3::new(claimed),
            &candidate,
            &plan,
            carrier,
            &options,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &cancellation,
        ));
        tokio::select! {
            _ = entered.notified() => {}
            result = &mut operation => panic!("admission completed before spend cancellation: {result:?}"),
        }
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_millis(100), &mut operation)
            .await
            .expect("cancellation must bound the spend callback");
        assert_eq!(
            result.unwrap_err().code(),
            ConnectErrorCode::ConnectionFailed
        );
        assert_eq!(settled.load(Ordering::Acquire), 0);
        assert!(observed_lease.is_consumed_for_test());
        release.notify_one();
    }

    #[tokio::test]
    async fn dropping_admission_future_aborts_spend_and_carrier() {
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "websocket",
            "id": "ca",
            "tls": {"mode": "ca"},
            "url": "wss://127.0.0.1:443/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3"
        })]);
        let plan = artifact.connection_plan().expect("valid connection plan");
        let candidate = plan.candidates[0].clone();
        let spend_entered = Arc::new(tokio::sync::Notify::new());
        let spend_release = Arc::new(tokio::sync::Notify::new());
        let spend_entered_capture = spend_entered.clone();
        let spend_release_capture = spend_release.clone();
        let lease = ArtifactLeaseV3::new(artifact, move || async move {
            spend_entered_capture.notify_one();
            spend_release_capture.notified().await;
            Ok(())
        });
        let observed_lease = lease.clone();
        let claimed = lease.claim().expect("claim lease");
        let carrier = Arc::new(HangingAdmissionCarrier {
            phase: HangingAdmissionPhase::Open,
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            aborts: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            credential_writes: Arc::new(AtomicUsize::new(0)),
        });
        let cancellation = CancellationToken::new();
        let options = ConnectorOptions::new();
        let mut operation = Box::pin(admit_candidate_and_establish(
            PreSpendLeaseGuardV3::new(claimed),
            &candidate,
            &plan,
            carrier.clone(),
            &options,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &cancellation,
        ));
        tokio::time::timeout(Duration::from_millis(100), async {
            tokio::select! {
                _ = spend_entered.notified() => {}
                result = &mut operation => panic!("admission unexpectedly completed: {result:?}"),
            }
        })
        .await
        .expect("spend callback did not start");
        drop(operation);

        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if observed_lease.is_consumed_for_test()
                    && carrier.aborts.load(Ordering::Acquire) == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped admission did not settle spend and carrier cleanup");
        spend_release.notify_one();
    }

    async fn run_hanging_admission(
        phase: HangingAdmissionPhase,
        timeout: Duration,
        cancel_when_entered: bool,
    ) -> (
        Result<Arc<dyn Session>, ConnectError>,
        Arc<HangingAdmissionCarrier>,
    ) {
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "websocket",
            "id": "ca",
            "tls": {"mode": "ca"},
            "url": "wss://127.0.0.1:443/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3"
        })]);
        let plan = artifact.connection_plan().unwrap();
        let candidate = plan.candidates[0].clone();
        let claimed = ArtifactLeaseV3::new(artifact, || async { Ok(()) })
            .claim()
            .unwrap();
        let carrier = Arc::new(HangingAdmissionCarrier {
            phase,
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            aborts: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            credential_writes: Arc::new(AtomicUsize::new(0)),
        });
        let cancellation = CancellationToken::new();
        let options = ConnectorOptions::new();
        let operation = admit_candidate_and_establish(
            PreSpendLeaseGuardV3::new(claimed),
            &candidate,
            &plan,
            carrier.clone(),
            &options,
            tokio::time::Instant::now() + timeout,
            &cancellation,
        );
        let result = if cancel_when_entered {
            let canceler = async {
                carrier.entered.acquire().await.unwrap().forget();
                cancellation.cancel();
            };
            let (result, ()) = tokio::join!(operation, canceler);
            result
        } else {
            operation.await
        };
        (result, carrier)
    }

    #[tokio::test]
    async fn production_websocket_connector_completes_ca_admission_and_session() {
        let (root, identity) = private_ca_identity();
        let acceptor = Arc::new(
            Acceptor::bind_websocket(WebSocketAcceptorOptions {
                bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                certificate_chain_der: identity.chain,
                private_key_der: identity.key,
                allowed_origins: vec!["https://app.example".into()],
                max_inbound_streams: 1,
                accept_timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        let address = acceptor.local_address().unwrap();
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "websocket",
            "id": "ca",
            "tls": {"mode": "ca"},
            "url": format!("wss://127.0.0.1:{}/flowersec/v3/direct", address.port()),
            "wire_profile": "flowersec-direct/3"
        })]);
        let server_artifact = artifact.clone();
        let server = tokio::spawn(async move {
            acceptor
                .accept(&server_artifact, CancellationToken::new())
                .await
                .unwrap()
        });
        let spends = Arc::new(AtomicUsize::new(0));
        let spend_capture = spends.clone();
        let lease = ArtifactLeaseV3::new(artifact, move || async move {
            spend_capture.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let options = ConnectorOptions::new()
            .with_trust_roots_der(vec![root])
            .unwrap()
            .with_websocket_origin("https://app.example")
            .unwrap();
        let session = connect_v3(lease, options).await.unwrap();
        assert_eq!(spends.load(Ordering::SeqCst), 1);
        let server = server.await.unwrap();
        let _ = tokio::join!(session.close(), server.close());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_pin_provider_matrix_rejects_hash_matched_leaf_with_invalid_tls_proof() {
        for carrier in ["websocket", "raw_quic"] {
            let peer = InvalidProofPeer::start(carrier);
            let pin = URL_SAFE_NO_PAD.encode(Sha256::digest(&peer.leaf_der));
            let port = peer
                .address
                .rsplit_once(':')
                .unwrap()
                .1
                .parse::<u16>()
                .unwrap();
            let (url, origin) = match carrier {
                "websocket" => (
                    format!("wss://localhost:{port}/flowersec/v3/direct"),
                    Some("https://app.example"),
                ),
                "raw_quic" => (format!("quic://localhost:{port}"), None),
                _ => unreachable!(),
            };
            let artifact = artifact_with_candidates(vec![json!({
                "carrier": carrier,
                "id": format!("{carrier}-invalid-proof"),
                "tls": {"mode": "pin", "pins": [{
                    "algorithm": "sha-256",
                    "not_after_unix_s": unix_seconds() + 600,
                    "value_b64u": pin
                }]},
                "url": url,
                "wire_profile": "flowersec-direct/3"
            })]);
            let spends = Arc::new(AtomicUsize::new(0));
            let spend_counter = spends.clone();
            let lease = ArtifactLeaseV3::new(artifact, move || {
                let spend_counter = spend_counter.clone();
                async move {
                    spend_counter.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            });
            let mut options = ConnectorOptions::new()
                .with_connect_timeout(Duration::from_secs(3))
                .unwrap();
            if let Some(origin) = origin {
                options = options.with_websocket_origin(origin).unwrap();
            }
            let error = connect_v3(lease, options).await.unwrap_err();
            assert_eq!(
                error.code(),
                ConnectErrorCode::TransportSecurityFailed,
                "{carrier}"
            );
            assert!(!error.controller_retryable(), "{carrier}");
            assert_eq!(spends.load(Ordering::SeqCst), 0, "{carrier}");
        }
    }

    #[test]
    fn fsa3_reject_is_terminal_but_retryable_is_controller_retryable() {
        assert_eq!(
            admission_failure(AdmissionStatusV3::Reject).retry_disposition(),
            RetryDisposition::Terminal
        );
        assert_eq!(
            admission_failure(AdmissionStatusV3::Retryable).retry_disposition(),
            RetryDisposition::Retryable
        );
        assert_eq!(
            admission_failure(AdmissionStatusV3::Reject).code(),
            ConnectErrorCode::ConnectionFailed
        );
        assert_eq!(
            admission_failure(AdmissionStatusV3::Retryable).code(),
            ConnectErrorCode::ConnectionFailed
        );
    }

    #[test]
    fn candidate_policy_snapshot_keeps_only_pins_active_at_race_start() {
        let first = URL_SAFE_NO_PAD.encode([0x11_u8; 32]);
        let second = URL_SAFE_NO_PAD.encode([0x22_u8; 32]);
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "websocket",
            "id": "pin",
            "tls": {"mode": "pin", "pins": [
                {"algorithm": "sha-256", "not_after_unix_s": 100, "value_b64u": first},
                {"algorithm": "sha-256", "not_after_unix_s": 200, "value_b64u": second}
            ]},
            "url": "wss://127.0.0.1:443/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3"
        })]);
        let plan = artifact.connection_plan().unwrap();
        let declared = &plan.candidates[0];
        let snapshot = snapshot_candidate_policy(declared, 100).unwrap();
        assert!(matches!(&declared.tls, TlsPolicyWireV3::Pin { pins } if pins.len() == 2));
        assert!(matches!(&snapshot.tls, TlsPolicyWireV3::Pin { pins } if pins.len() == 1));
        assert_eq!(
            snapshot_candidate_policy(declared, 200),
            Err(CandidateFailureV3::PolicyExpired)
        );
    }

    #[tokio::test]
    async fn unsupported_candidates_do_not_snapshot_expired_pins_or_trigger_refresh() {
        for candidate in [
            json!({
                "carrier": "webtransport",
                "id": "unsupported-webtransport",
                "tls": {"mode": "pin", "pins": [{
                    "algorithm": "sha-256",
                    "not_after_unix_s": unix_seconds().saturating_sub(1),
                    "value_b64u": URL_SAFE_NO_PAD.encode([0x11_u8; 32])
                }]},
                "url": "https://127.0.0.1:443/flowersec/webtransport/v3/direct",
                "wire_profile": "flowersec-direct/3"
            }),
            json!({
                "carrier": "websocket",
                "id": "websocket-without-origin",
                "tls": {"mode": "pin", "pins": [{
                    "algorithm": "sha-256",
                    "not_after_unix_s": unix_seconds().saturating_sub(1),
                    "value_b64u": URL_SAFE_NO_PAD.encode([0x22_u8; 32])
                }]},
                "url": "wss://127.0.0.1:443/flowersec/v3/direct",
                "wire_profile": "flowersec-direct/3"
            }),
        ] {
            let spends = Arc::new(AtomicUsize::new(0));
            let spend_capture = spends.clone();
            let error = connect_v3_with_cancellation_and_preparer(
                ArtifactLeaseV3::new(artifact_with_candidates(vec![candidate]), move || {
                    spend_capture.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }),
                ConnectorOptions::new(),
                CancellationToken::new(),
                &FailingCandidatePreparer { failures: vec![] },
            )
            .await
            .expect_err("unsupported candidate unexpectedly connected");

            assert_eq!(error.code(), ConnectErrorCode::TransportSecurityUnsupported);
            assert_eq!(error.v3_policy_trigger_mask(), 0);
            assert_eq!(error.v3_failed_candidate_mask(), 0);
            assert_eq!(spends.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn established_session_remains_usable_after_pin_policy_expiry() {
        let (_root, identity) = private_ca_identity();
        let pin = URL_SAFE_NO_PAD.encode(Sha256::digest(&identity.chain[0]));
        let pin_expiry = unix_seconds() + 2;
        let acceptor = Arc::new(
            Acceptor::bind_websocket(WebSocketAcceptorOptions {
                bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                certificate_chain_der: identity.chain,
                private_key_der: identity.key,
                allowed_origins: vec!["https://app.example".into()],
                max_inbound_streams: 1,
                accept_timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        let address = acceptor.local_address().unwrap();
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "websocket",
            "id": "pin",
            "tls": {"mode": "pin", "pins": [{
                "algorithm": "sha-256",
                "not_after_unix_s": pin_expiry,
                "value_b64u": pin
            }]},
            "url": format!("wss://127.0.0.1:{}/flowersec/v3/direct", address.port()),
            "wire_profile": "flowersec-direct/3"
        })]);
        let server_artifact = artifact.clone();
        let server = tokio::spawn(async move {
            acceptor
                .accept(&server_artifact, CancellationToken::new())
                .await
                .unwrap()
        });
        let options = ConnectorOptions::new()
            .with_websocket_origin("https://app.example")
            .unwrap();
        let session = connect_v3(ArtifactLeaseV3::new(artifact, || async { Ok(()) }), options)
            .await
            .unwrap();
        let server = server.await.unwrap();

        tokio::time::sleep(Duration::from_secs(
            pin_expiry.saturating_sub(unix_seconds()) + 1,
        ))
        .await;
        assert!(unix_seconds() > pin_expiry);
        tokio::time::timeout(Duration::from_secs(2), session.probe_liveness())
            .await
            .expect("established v3 session liveness timed out after pin expiry")
            .unwrap();

        let _ = tokio::join!(session.close(), server.close());
    }

    #[tokio::test]
    async fn unsupported_candidate_creates_no_transport_and_does_not_spend_lease() {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = socket.local_addr().unwrap();
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "webtransport",
            "id": "unsupported",
            "tls": {"mode": "ca"},
            "url": format!(
                "https://127.0.0.1:{}/flowersec/webtransport/v3/direct",
                address.port()
            ),
            "wire_profile": "flowersec-direct/3"
        })]);
        let spends = Arc::new(AtomicUsize::new(0));
        let spend_capture = spends.clone();
        let lease = ArtifactLeaseV3::new(artifact, move || async move {
            spend_capture.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        let error = connect_v3(lease, ConnectorOptions::new())
            .await
            .expect_err("unsupported WebTransport unexpectedly connected");
        assert_eq!(error.code(), ConnectErrorCode::TransportSecurityUnsupported);
        assert_eq!(spends.load(Ordering::SeqCst), 0);
        let mut datagram = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), socket.recv(&mut datagram))
                .await
                .is_err(),
            "unsupported candidate created a network transport"
        );
    }

    #[tokio::test]
    async fn pre_canceled_one_shot_claims_and_retires_the_lease() {
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "webtransport",
            "id": "unsupported",
            "tls": {"mode": "ca"},
            "url": "https://example.org/flowersec/webtransport/v3/direct",
            "wire_profile": "flowersec-direct/3"
        })]);
        let retires = Arc::new(AtomicUsize::new(0));
        let retires_capture = retires.clone();
        let lease = ArtifactLeaseV3::new_with_retire(
            artifact,
            || async { Ok(()) },
            move || async move {
                retires_capture.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        let reusable = lease.clone();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = connect_v3_with_cancellation(lease, ConnectorOptions::new(), cancellation)
            .await
            .expect_err("pre-canceled one-shot unexpectedly connected");
        assert_eq!(error.code(), ConnectErrorCode::ConnectionFailed);
        assert_eq!(retires.load(Ordering::SeqCst), 1);
        assert!(reusable.claim().is_err(), "retired lease was left reusable");
    }

    #[tokio::test]
    async fn dropping_one_shot_before_spend_retires_the_claimed_lease() {
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "raw_quic",
            "id": "ca",
            "tls": {"mode": "ca"},
            "url": "quic://127.0.0.1:443",
            "wire_profile": "flowersec-direct/3"
        })]);
        let retires = Arc::new(AtomicUsize::new(0));
        let retires_capture = retires.clone();
        let lease = ArtifactLeaseV3::new_with_retire(
            artifact,
            || async { Ok(()) },
            move || async move {
                retires_capture.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        let reusable = lease.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let preparer = HangingCandidatePreparer {
            entered: entered.clone(),
        };
        let mut operation = Box::pin(connect_v3_with_cancellation_and_preparer(
            lease,
            ConnectorOptions::new(),
            CancellationToken::new(),
            &preparer,
        ));
        tokio::time::timeout(Duration::from_millis(100), async {
            tokio::select! {
                _ = entered.notified() => {}
                result = &mut operation => panic!("one-shot unexpectedly completed: {result:?}"),
            }
        })
        .await
        .expect("candidate preparation did not start");
        drop(operation);

        tokio::time::timeout(Duration::from_millis(100), async {
            while retires.load(Ordering::Acquire) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped one-shot did not run retire cleanup");
        assert!(reusable.claim().is_err(), "dropped claim became reusable");
    }

    #[tokio::test]
    async fn prepared_winner_enters_admission_without_waiting_for_an_uncooperative_loser() {
        let artifact = artifact_with_candidates(vec![
            json!({
                "carrier": "raw_quic",
                "id": "loser",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:443",
                "wire_profile": "flowersec-direct/3"
            }),
            json!({
                "carrier": "raw_quic",
                "id": "winner",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:444",
                "wire_profile": "flowersec-direct/3"
            }),
        ]);
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let preparer = WinnerWithUncooperativeLoserPreparer {
            barrier: Arc::new(tokio::sync::Barrier::new(2)),
            winner: Arc::new(HangingAdmissionCarrier {
                phase: HangingAdmissionPhase::Open,
                entered: entered.clone(),
                aborts: AtomicUsize::new(0),
                opens: AtomicUsize::new(0),
                credential_writes: Arc::new(AtomicUsize::new(0)),
            }),
        };
        let mut operation = Box::pin(connect_v3_with_cancellation_and_preparer(
            ArtifactLeaseV3::new(artifact, || async { Ok(()) }),
            ConnectorOptions::new(),
            CancellationToken::new(),
            &preparer,
        ));
        tokio::time::timeout(Duration::from_millis(100), async {
            tokio::select! {
                permit = entered.acquire() => { permit.unwrap().forget(); }
                result = &mut operation => panic!("winner admission unexpectedly completed: {result:?}"),
            }
        })
        .await
        .expect("prepared winner waited for an uncooperative loser");
        drop(operation);
    }

    #[tokio::test]
    async fn late_prepared_loser_is_aborted_while_winner_enters_admission() {
        let artifact = artifact_with_candidates(vec![
            json!({
                "carrier": "raw_quic",
                "id": "loser",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:443",
                "wire_profile": "flowersec-direct/3"
            }),
            json!({
                "carrier": "raw_quic",
                "id": "winner",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:444",
                "wire_profile": "flowersec-direct/3"
            }),
        ]);
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let winner = Arc::new(HangingAdmissionCarrier {
            phase: HangingAdmissionPhase::Open,
            entered: entered.clone(),
            aborts: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            credential_writes: Arc::new(AtomicUsize::new(0)),
        });
        let loser = Arc::new(HangingAdmissionCarrier {
            phase: HangingAdmissionPhase::Open,
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            aborts: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            credential_writes: Arc::new(AtomicUsize::new(0)),
        });
        let release_loser = Arc::new(tokio::sync::Notify::new());
        let preparer = WinnerWithLatePreparedLoserPreparer {
            barrier: Arc::new(tokio::sync::Barrier::new(2)),
            release_loser: release_loser.clone(),
            winner: winner.clone(),
            loser: loser.clone(),
        };
        let mut operation = Box::pin(connect_v3_with_cancellation_and_preparer(
            ArtifactLeaseV3::new(artifact, || async { Ok(()) }),
            ConnectorOptions::new(),
            CancellationToken::new(),
            &preparer,
        ));
        tokio::time::timeout(Duration::from_millis(100), async {
            tokio::select! {
                permit = entered.acquire() => { permit.unwrap().forget(); }
                result = &mut operation => panic!("winner admission unexpectedly completed: {result:?}"),
            }
        })
        .await
        .expect("winner did not enter admission");
        release_loser.notify_one();
        tokio::time::timeout(Duration::from_millis(100), async {
            while loser.aborts.load(Ordering::Acquire) != 1 {
                tokio::select! {
                    result = &mut operation => panic!("winner admission unexpectedly completed: {result:?}"),
                    _ = tokio::task::yield_now() => {}
                }
            }
        })
        .await
        .expect("late prepared loser was not aborted");
        assert_eq!(loser.opens.load(Ordering::Acquire), 0);
        assert_eq!(loser.credential_writes.load(Ordering::Acquire), 0);
        assert_eq!(loser.aborts.load(Ordering::Acquire), 1);
        drop(operation);
    }

    #[test]
    fn public_debug_output_redacts_candidate_masks_and_websocket_origin() {
        let error = public_error(ConnectErrorCode::TransportSecurityFailed)
            .with_v3_candidate_masks(0b1010, 0b1111);
        let debug = format!("{error:?}");
        assert!(!debug.contains("policy_trigger_mask"));
        assert!(!debug.contains("failed_candidate_mask"));
        assert!(!debug.contains("1010"));
        assert!(!debug.contains("1111"));

        let options = ConnectorOptions::new()
            .with_websocket_origin("https://secret-origin.example")
            .unwrap();
        assert!(!format!("{options:?}").contains("secret-origin"));
    }

    #[tokio::test]
    async fn canceled_candidate_failure_is_terminal_for_the_controller() {
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "raw_quic",
            "id": "canceled",
            "tls": {"mode": "ca"},
            "url": "quic://127.0.0.1:443",
            "wire_profile": "flowersec-direct/3"
        })]);
        let error = connect_v3_with_cancellation_and_preparer(
            ArtifactLeaseV3::new(artifact, || async { Ok(()) }),
            ConnectorOptions::new(),
            CancellationToken::new(),
            &FailingCandidatePreparer {
                failures: vec![("canceled", CandidateFailureV3::Canceled)],
            },
        )
        .await
        .expect_err("canceled candidate preparation unexpectedly connected");

        assert_eq!(error.code(), ConnectErrorCode::ConnectionFailed);
        assert!(!error.controller_retryable());
    }

    #[tokio::test]
    async fn cancellation_dominates_mixed_candidate_failures_and_is_terminal() {
        let artifact = artifact_with_candidates(vec![
            json!({
                "carrier": "raw_quic",
                "id": "security",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:443",
                "wire_profile": "flowersec-direct/3"
            }),
            json!({
                "carrier": "raw_quic",
                "id": "timeout",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:444",
                "wire_profile": "flowersec-direct/3"
            }),
            json!({
                "carrier": "raw_quic",
                "id": "connection",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:445",
                "wire_profile": "flowersec-direct/3"
            }),
            json!({
                "carrier": "raw_quic",
                "id": "canceled",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:446",
                "wire_profile": "flowersec-direct/3"
            }),
        ]);
        let error = connect_v3_with_cancellation_and_preparer(
            ArtifactLeaseV3::new(artifact, || async { Ok(()) }),
            ConnectorOptions::new(),
            CancellationToken::new(),
            &FailingCandidatePreparer {
                failures: vec![
                    ("security", CandidateFailureV3::Security),
                    ("timeout", CandidateFailureV3::Timeout),
                    ("connection", CandidateFailureV3::Connection),
                    ("canceled", CandidateFailureV3::Canceled),
                ],
            },
        )
        .await
        .expect_err("mixed candidate failures unexpectedly connected");

        assert_eq!(error.code(), ConnectErrorCode::ConnectionFailed);
        assert!(!error.controller_retryable());
    }

    #[tokio::test]
    async fn timeout_and_connection_candidate_failures_remain_controller_retryable() {
        for failure in [CandidateFailureV3::Timeout, CandidateFailureV3::Connection] {
            let artifact = artifact_with_candidates(vec![json!({
                "carrier": "raw_quic",
                "id": "failed",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:443",
                "wire_profile": "flowersec-direct/3"
            })]);
            let error = connect_v3_with_cancellation_and_preparer(
                ArtifactLeaseV3::new(artifact, || async { Ok(()) }),
                ConnectorOptions::new(),
                CancellationToken::new(),
                &FailingCandidatePreparer {
                    failures: vec![("failed", failure)],
                },
            )
            .await
            .expect_err("failed candidate preparation unexpectedly connected");

            assert_eq!(error.code(), ConnectErrorCode::ConnectionFailed);
            assert!(error.controller_retryable(), "{failure:?}");
        }
    }

    #[tokio::test]
    async fn race_end_expiry_overrides_security_aggregate_and_retires_once() {
        let artifact = artifact_with_candidates_and_expiry(
            vec![json!({
                "carrier": "raw_quic",
                "id": "failed",
                "tls": {"mode": "ca"},
                "url": "quic://127.0.0.1:443",
                "wire_profile": "flowersec-direct/3"
            })],
            unix_seconds(),
        );
        let plan = artifact.connection_plan().expect("valid connection plan");
        let retires = Arc::new(AtomicUsize::new(0));
        let retire_capture = retires.clone();
        let claimed = ArtifactLeaseV3::new_with_retire(
            artifact,
            || async { Ok(()) },
            move || async move {
                retire_capture.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .claim()
        .expect("claim lease");

        let error = finalize_candidate_race(
            PreSpendLeaseGuardV3::new(claimed),
            &plan,
            CandidateFailureV3::Security,
            1,
            1,
        )
        .await;

        assert_eq!(error.code(), ConnectErrorCode::Expired);
        assert!(error.controller_retryable());
        assert_eq!(error.v3_policy_trigger_mask(), 0);
        assert_eq!(error.v3_failed_candidate_mask(), 0);
        assert_eq!(retires.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancellation_dominates_security_while_security_dominates_timeout() {
        assert_eq!(
            aggregate_failure(CandidateFailureV3::Security, CandidateFailureV3::Canceled),
            CandidateFailureV3::Canceled
        );
        assert_eq!(
            aggregate_failure(CandidateFailureV3::Timeout, CandidateFailureV3::Security),
            CandidateFailureV3::Security
        );
        assert_eq!(
            aggregate_failure(
                CandidateFailureV3::Timeout,
                CandidateFailureV3::PolicyExpired
            ),
            CandidateFailureV3::PolicyExpired
        );
    }

    #[test]
    fn version_isolation_alpn_vectors_match_the_native_v3_dialer() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/version_isolation_vectors.json"
        ))
        .unwrap();
        for mutation in fixture["alpn_mutations"].as_array().unwrap() {
            let id = mutation["id"].as_str().unwrap();
            let v3 = mutation["v3"].as_str().unwrap().as_bytes();
            let v2 = mutation["v2"].as_str().unwrap().as_bytes();
            let expected = if id == "direct" {
                ALPN_DIRECT_V3
            } else {
                ALPN_TUNNEL_V3
            };
            assert_eq!(v3, expected);
            assert_ne!(v2, expected);
        }
    }

    #[tokio::test]
    async fn production_websocket_acceptor_binds_handlers_before_session_establishment() {
        for _ in 0..32 {
            production_websocket_acceptor_binds_handlers_before_session_establishment_once().await;
        }
    }

    async fn production_websocket_acceptor_binds_handlers_before_session_establishment_once() {
        let (root, identity) = private_ca_identity();
        let acceptor = Acceptor::bind_websocket(WebSocketAcceptorOptions {
            bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            certificate_chain_der: identity.chain,
            private_key_der: identity.key,
            allowed_origins: vec!["https://app.example".into()],
            max_inbound_streams: 1,
            accept_timeout: Duration::from_secs(5),
        })
        .unwrap();
        let address = acceptor.local_address().unwrap();
        let artifact = artifact_with_candidates(vec![json!({
            "carrier": "websocket",
            "id": "ca",
            "tls": {"mode": "ca"},
            "url": format!("wss://127.0.0.1:{}/flowersec/v3/direct", address.port()),
            "wire_profile": "flowersec-direct/3"
        })]);
        let (handled_send, mut handled_receive) = tokio::sync::mpsc::unbounded_channel();
        let mut handlers = SessionHandlers::new(SessionHandlerOptions {
            max_concurrent_streams: 1,
        })
        .unwrap();
        handlers
            .handle_stream("accepted.v3", ProductStreamHandler(handled_send))
            .unwrap();

        let server_artifact = artifact.clone();
        let server_cancellation = CancellationToken::new();
        let serving_cancellation = server_cancellation.clone();
        let server = tokio::spawn(async move {
            let accepted = acceptor
                .accept_with_handlers(&server_artifact, handlers, CancellationToken::new())
                .await
                .unwrap();
            accepted.serve(serving_cancellation).await
        });
        let options = ConnectorOptions::new()
            .with_trust_roots_der(vec![root])
            .unwrap()
            .with_websocket_origin("https://app.example")
            .unwrap();
        let session = connect_v3(ArtifactLeaseV3::new(artifact, || async { Ok(()) }), options)
            .await
            .unwrap();
        let stream = session
            .open_stream("accepted.v3", crate::StreamMetadata::empty())
            .await
            .unwrap();
        stream
            .write(Bytes::from_static(b"handled before establishment"))
            .await
            .unwrap();
        stream.close_write().await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), handled_receive.recv())
                .await
                .expect("v3 handler timed out"),
            Some(Bytes::from_static(b"handled before establishment"))
        );
        server_cancellation.cancel();
        let (client_close, server) = tokio::join!(session.close(), server);
        client_close.unwrap();
        assert_eq!(
            server
                .expect("join v3 handler server")
                .expect_err("peer close must stop v3 handler serving"),
            SessionError::Canceled
        );
    }

    #[tokio::test]
    async fn same_endpoint_pin_and_ca_is_rejected_before_dial_or_spend() {
        let url = "wss://127.0.0.1:24443/flowersec/v3/direct";
        let artifact = parse_artifact_with_candidates(vec![
            json!({
                "carrier": "websocket",
                "id": "a-pin",
                "tls": {"mode": "pin", "pins": [{
                    "algorithm": "sha-256",
                    "not_after_unix_s": unix_seconds() + 600,
                    "value_b64u": URL_SAFE_NO_PAD.encode([0xA5; 32])
                }]},
                "url": url,
                "wire_profile": "flowersec-direct/3"
            }),
            json!({
                "carrier": "websocket",
                "id": "z-ca",
                "tls": {"mode": "ca"},
                "url": url,
                "wire_profile": "flowersec-direct/3"
            }),
        ]);
        assert!(artifact.is_err());
    }

    #[tokio::test]
    async fn candidate_race_does_not_let_a_lower_id_blackhole_block_a_ready_endpoint() {
        let (root, identity) = private_ca_identity();
        let acceptor = Arc::new(
            Acceptor::bind_websocket(WebSocketAcceptorOptions {
                bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                certificate_chain_der: identity.chain,
                private_key_der: identity.key,
                allowed_origins: vec!["https://app.example".into()],
                max_inbound_streams: 1,
                accept_timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        let address = acceptor.local_address().unwrap();
        let blackhole = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let blackhole_address = blackhole.local_addr().unwrap();
        let blackhole_task = tokio::spawn(async move {
            let (_stream, _) = blackhole.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let artifact = artifact_with_candidates(vec![
            json!({
                "carrier": "websocket",
                "id": "a-blackhole",
                "tls": {"mode": "ca"},
                "url": format!("wss://127.0.0.1:{}/flowersec/v3/direct", blackhole_address.port()),
                "wire_profile": "flowersec-direct/3"
            }),
            json!({
                "carrier": "websocket",
                "id": "z-ready",
                "tls": {"mode": "ca"},
                "url": format!("wss://127.0.0.1:{}/flowersec/v3/direct", address.port()),
                "wire_profile": "flowersec-direct/3"
            }),
        ]);
        let server_artifact = artifact.clone();
        let server = tokio::spawn(async move {
            acceptor
                .accept(&server_artifact, CancellationToken::new())
                .await
                .unwrap()
        });
        let spends = Arc::new(AtomicUsize::new(0));
        let spend_capture = spends.clone();
        let lease = ArtifactLeaseV3::new(artifact, move || async move {
            spend_capture.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let options = ConnectorOptions::new()
            .with_trust_roots_der(vec![root])
            .unwrap()
            .with_websocket_origin("https://app.example")
            .unwrap();
        let session = tokio::time::timeout(Duration::from_secs(2), connect_v3(lease, options))
            .await
            .expect("ready endpoint must win without waiting for the TLS blackhole")
            .unwrap();
        assert_eq!(spends.load(Ordering::SeqCst), 1);
        blackhole_task.abort();
        let server = server.await.unwrap();
        let _ = tokio::join!(session.close(), server.close());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn production_wss_tunnel_runtime_relays_a_complete_v3_session() {
        let (_root, identity) = private_ca_identity();
        let pin = URL_SAFE_NO_PAD.encode(Sha256::digest(&identity.chain[0]));
        let authorizer = Arc::new(TestTunnelAuthorizer::default());
        let runtime = Arc::new(
            TunnelRuntime::bind_websocket(
                TunnelRuntimeOptions {
                    bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                    certificate_chain_der: identity.chain,
                    private_key_der: identity.key,
                    allowed_origins: vec!["https://app.example".into()],
                    admission_reasons: Vec::new(),
                    max_inbound_streams: 1,
                    pair_timeout: Duration::from_secs(5),
                    max_pending_legs: 8,
                    max_active_pairs: 4,
                },
                authorizer.clone(),
            )
            .unwrap(),
        );
        let address = runtime.local_address().unwrap();
        let client_artifact = tunnel_artifact(
            address.port(),
            1,
            "endpoint-client",
            "endpoint-server",
            "client-token",
            &pin,
        );
        let server_artifact = tunnel_artifact(
            address.port(),
            2,
            "endpoint-server",
            "endpoint-client",
            "server-token",
            &pin,
        );
        authorizer
            .artifacts
            .lock()
            .unwrap()
            .extend([client_artifact.clone(), server_artifact.clone()]);
        let runtime_cancellation = CancellationToken::new();
        let runtime_task = tokio::spawn({
            let runtime = runtime.clone();
            let cancellation = runtime_cancellation.clone();
            async move { runtime.serve(cancellation).await }
        });

        let options = || {
            ConnectorOptions::new()
                .with_websocket_origin("https://app.example")
                .unwrap()
        };
        let (client, server) = tokio::join!(
            connect_v3(
                ArtifactLeaseV3::new(client_artifact, || async { Ok(()) }),
                options(),
            ),
            connect_v3(
                ArtifactLeaseV3::new(server_artifact, || async { Ok(()) }),
                options(),
            ),
        );
        let client = client.unwrap();
        let server = server.unwrap();

        let receiver = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.accept_stream().await.unwrap();
                assert_eq!(incoming.kind(), "wss.tunnel.v3");
                assert_eq!(
                    incoming.stream().read().await.unwrap(),
                    Some(Bytes::from_static(b"client payload"))
                );
                assert_eq!(incoming.stream().read().await.unwrap(), None);
                incoming
                    .stream()
                    .write(Bytes::from_static(b"server reply"))
                    .await
                    .unwrap();
                incoming.stream().close_write().await.unwrap();
            }
        });
        let stream = client
            .open_stream("wss.tunnel.v3", crate::StreamMetadata::empty())
            .await
            .unwrap();
        stream
            .write(Bytes::from_static(b"client payload"))
            .await
            .unwrap();
        stream.close_write().await.unwrap();
        assert_eq!(
            stream.read().await.unwrap(),
            Some(Bytes::from_static(b"server reply"))
        );
        assert_eq!(stream.read().await.unwrap(), None);
        receiver.await.unwrap();

        let _ = tokio::join!(client.close(), server.close());
        runtime.close().await;
        runtime_cancellation.cancel();
        runtime_task.await.unwrap().unwrap();
    }

    #[derive(Default)]
    struct TestTunnelAuthorizer {
        artifacts: StdMutex<Vec<ArtifactV3>>,
    }

    struct InvalidProofPeer {
        child: Child,
        address: String,
        leaf_der: Vec<u8>,
    }

    impl InvalidProofPeer {
        fn start(carrier: &str) -> Self {
            let go_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../flowersec-go");
            let mut child = Command::new("go")
                .args([
                    "run",
                    "./internal/cmd/invalid-proof-peer",
                    "--carrier",
                    carrier,
                ])
                .current_dir(go_root)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            let ready: Value = serde_json::from_str(&line).unwrap();
            Self {
                child,
                address: ready["address"].as_str().unwrap().to_owned(),
                leaf_der: STANDARD
                    .decode(ready["leaf_der_base64"].as_str().unwrap())
                    .unwrap(),
            }
        }
    }

    impl Drop for InvalidProofPeer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[async_trait]
    impl TunnelAuthorizer for TestTunnelAuthorizer {
        async fn authorize(
            &self,
            request: crate::RuntimeAuthorizationRequest,
            _cancellation: CancellationToken,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            self.artifacts
                .lock()
                .unwrap()
                .iter()
                .find_map(|artifact| {
                    TunnelAuthorizationResponse::allow(
                        &request,
                        artifact,
                        request.lookup_key(),
                        false,
                    )
                    .ok()
                })
                .ok_or(TunnelAuthorizationError)
        }
    }

    fn artifact_with_candidates(candidates: Vec<Value>) -> ArtifactV3 {
        parse_artifact_with_candidates(candidates).unwrap()
    }

    fn artifact_with_candidates_and_expiry(
        candidates: Vec<Value>,
        expires_at_unix_seconds: u64,
    ) -> ArtifactV3 {
        parse_artifact_with_candidates_and_expiry(candidates, expires_at_unix_seconds).unwrap()
    }

    fn parse_artifact_with_candidates(
        candidates: Vec<Value>,
    ) -> Result<ArtifactV3, crate::artifact_v3::ArtifactErrorV3> {
        parse_artifact_with_candidates_and_expiry(candidates, unix_seconds() + 600)
    }

    fn parse_artifact_with_candidates_and_expiry(
        candidates: Vec<Value>,
        expires_at_unix_seconds: u64,
    ) -> Result<ArtifactV3, crate::artifact_v3::ArtifactErrorV3> {
        let projection = json!({
            "allowed_suites": [1],
            "channel_id": "channel",
            "default_suite": 1,
            "establish_timeout_seconds": 30,
            "idle_timeout_seconds": 0,
            "max_inbound_streams": 1,
            "profile": "flowersec/3",
            "rekey_completion_timeout_seconds": 30,
            "rekey_prepare_timeout_seconds": 10,
            "selected_features": 0
        });
        let contract = URL_SAFE_NO_PAD.encode(hash_lp(
            b"flowersec-v3-session-contract\0",
            &jcs_value(&projection).unwrap(),
        ));
        let value = json!({
            "correlation": {"tags": [], "v": 3},
            "path": {
                "candidates": candidates,
                "kind": "direct",
                "listener_audience": "listener",
                "rendezvous_group_id": "group",
                "routing_token": "token"
            },
            "profile": "flowersec/3",
            "scoped": [],
            "session": {
                "allowed_suites": [1],
                "channel_id": "channel",
                "contract_hash_b64u": contract,
                "default_suite": 1,
                "e2ee_psk_b64u": URL_SAFE_NO_PAD.encode([7_u8; 32]),
                "establish_timeout_seconds": 30,
                "idle_timeout_seconds": 0,
                "init_expire_at_unix_s": expires_at_unix_seconds,
                "max_inbound_streams": 1,
                "rekey_completion_timeout_seconds": 30,
                "rekey_prepare_timeout_seconds": 10,
                "selected_features": 0
            },
            "v": 3
        });
        ArtifactV3::parse(jcs_value(&value).unwrap())
    }

    fn tunnel_artifact(
        port: u16,
        role: u8,
        local_endpoint: &str,
        peer_endpoint: &str,
        token: &str,
        pin: &str,
    ) -> ArtifactV3 {
        let projection = json!({
            "allowed_suites": [1],
            "channel_id": "channel",
            "default_suite": 1,
            "establish_timeout_seconds": 30,
            "idle_timeout_seconds": 0,
            "max_inbound_streams": 1,
            "profile": "flowersec/3",
            "rekey_completion_timeout_seconds": 30,
            "rekey_prepare_timeout_seconds": 10,
            "selected_features": 0
        });
        let contract = URL_SAFE_NO_PAD.encode(hash_lp(
            b"flowersec-v3-session-contract\0",
            &jcs_value(&projection).unwrap(),
        ));
        let value = json!({
            "correlation": {"tags": [], "v": 3},
            "path": {
                "candidates": [{
                    "carrier": "websocket",
                    "id": "ca",
                    "tls": {"mode": "pin", "pins": [{
                        "algorithm": "sha-256",
                        "not_after_unix_s": unix_seconds() + 600,
                        "value_b64u": pin
                    }]},
                    "url": format!("wss://127.0.0.1:{port}/flowersec/v3/tunnel"),
                    "wire_profile": "flowersec-tunnel/3"
                }],
                "expected_peer_endpoint_instance_id": peer_endpoint,
                "kind": "tunnel",
                "listener_audience": "listener",
                "local_endpoint_instance_id": local_endpoint,
                "rendezvous_group_id": "group",
                "role": role,
                "token": token
            },
            "profile": "flowersec/3",
            "scoped": [],
            "session": {
                "allowed_suites": [1],
                "channel_id": "channel",
                "contract_hash_b64u": contract,
                "default_suite": 1,
                "e2ee_psk_b64u": URL_SAFE_NO_PAD.encode([7_u8; 32]),
                "establish_timeout_seconds": 30,
                "idle_timeout_seconds": 0,
                "init_expire_at_unix_s": unix_seconds() + 600,
                "max_inbound_streams": 1,
                "rekey_completion_timeout_seconds": 30,
                "rekey_prepare_timeout_seconds": 10,
                "selected_features": 0
            },
            "v": 3
        });
        ArtifactV3::parse(jcs_value(&value).unwrap()).unwrap()
    }

    fn validity() -> (OffsetDateTime, OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        (now - TimeDuration::minutes(1), now + TimeDuration::hours(1))
    }

    fn private_ca_identity() -> (Vec<u8>, TestIdentityV3) {
        let (not_before, not_after) = validity();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        leaf_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        leaf_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let leaf_certificate: Certificate = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let root = ca.der().to_vec();
        let leaf = leaf_certificate.der().to_vec();
        (
            root.clone(),
            TestIdentityV3 {
                chain: vec![leaf.clone(), root],
                key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der())
                    .secret_pkcs8_der()
                    .to_vec(),
            },
        )
    }
}
