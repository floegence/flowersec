use std::{
    collections::{HashSet, VecDeque},
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    ArtifactSpendErrorV3,
    artifact_v3::{CanonicalCandidateV3, ConnectionPlanV3},
    connector_v3::{
        CandidateFailureV3, CandidatePrepareFutureV3, CandidatePreparerV3,
        connect_v3_with_cancellation_and_preparer,
    },
    transport_v2::{ByteStream, IncomingStream, RpcPeer, SessionTermination, StreamMetadata},
};

#[derive(Clone, Debug, Deserialize)]
struct ScenarioV3 {
    id: String,
    driver: String,
    input: Value,
    expected: ExpectedV3,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ExpectedV3 {
    final_state: String,
    public_error: Option<String>,
    disposition: Option<String>,
    acquisitions: u64,
    connect_attempts: u64,
    transports_created: u64,
    replacement_acquisitions: u64,
    replacement_quota_used: u64,
    spend_callbacks: u64,
    retire_callbacks: u64,
    lease_terminal_states: Vec<String>,
    retry_delays_ms: Vec<u64>,
    #[serde(default)]
    no_mode_downgrade: Option<bool>,
    #[serde(default)]
    tls_error_claimed: Option<bool>,
    #[serde(default)]
    blocked_policy_remains_blocked: Option<bool>,
    #[serde(default)]
    retry_now_allowed_before_deadline: Option<bool>,
    #[serde(default)]
    wall_end_ms: Option<u64>,
    #[serde(default)]
    monotonic_end_ms: Option<u64>,
    #[serde(default)]
    order_independent: Option<bool>,
    #[serde(default)]
    attempt: Option<u64>,
    #[serde(default)]
    counter_saturated: Option<bool>,
    #[serde(default)]
    capability_rechecked: Option<bool>,
    #[serde(default)]
    cleanup_error_ignored: Option<bool>,
    #[serde(default)]
    credential_bytes_written: Option<u64>,
    #[serde(default)]
    failure_ordinal: Option<u64>,
    #[serde(default)]
    maximum_wall_reread_ms: Option<u64>,
    #[serde(default)]
    timer_saturated: Option<bool>,
    #[serde(default)]
    concurrent_acquisition_peak: Option<u64>,
    #[serde(default)]
    controller_connector_attempts: Option<u64>,
    #[serde(default)]
    capability_snapshots: Option<Vec<String>>,
    #[serde(default)]
    pin_constructor_calls: Option<u64>,
    #[serde(default)]
    ca_constructor_calls: Option<u64>,
    #[serde(default)]
    old_snapshot_live_gate_failures: Option<u64>,
    #[serde(default)]
    post_invalidation_pin_constructor_calls: Option<u64>,
    #[serde(default)]
    replacement_dial_candidate_ids: Option<Vec<String>>,
    #[serde(default)]
    peer_final_state: Option<String>,
    #[serde(default)]
    peer_public_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ControllerVectorsV3 {
    internal_transport_results: Vec<(String, Option<String>, String)>,
    retry_after: RetryAfterVectorsV3,
    lease_state_machine: LeaseStateMachineVectorsV3,
    scenarios: Vec<ScenarioV3>,
    browser_capability_scenarios: Vec<ScenarioV3>,
}

#[derive(Debug, Deserialize)]
struct RetryAfterVectorsV3 {
    valid: Vec<u64>,
    invalid: Vec<Value>,
    aggregate: String,
}

#[derive(Debug, Deserialize)]
struct LeaseStateMachineVectorsV3 {
    states: Vec<String>,
    transitions: Vec<(String, String, String)>,
    terminal_states: Vec<String>,
}

#[derive(Debug)]
struct TrackedLease {
    lease: ArtifactLeaseV3,
    terminal: Arc<Mutex<Option<&'static str>>>,
    spends: Arc<AtomicU64>,
    retires: Arc<AtomicU64>,
}

impl TrackedLease {
    fn new(artifact: ArtifactV3) -> Self {
        Self::new_with_retire_result(artifact, Ok(()))
    }

    fn new_with_retire_result(
        artifact: ArtifactV3,
        retire_result: Result<(), ArtifactSpendErrorV3>,
    ) -> Self {
        let terminal = Arc::new(Mutex::new(None));
        let spends = Arc::new(AtomicU64::new(0));
        let retires = Arc::new(AtomicU64::new(0));
        let spend_terminal = terminal.clone();
        let spend_count = spends.clone();
        let retire_terminal = terminal.clone();
        let retire_count = retires.clone();
        let lease = ArtifactLeaseV3::new_with_retire(
            artifact,
            move || async move {
                spend_count.fetch_add(1, Ordering::SeqCst);
                *lock(&spend_terminal) = Some("consumed");
                Ok(())
            },
            move || async move {
                retire_count.fetch_add(1, Ordering::SeqCst);
                *lock(&retire_terminal) = Some("retired");
                retire_result
            },
        );
        Self {
            lease,
            terminal,
            spends,
            retires,
        }
    }

    fn new_with_retire_gate(artifact: ArtifactV3, gate: Arc<AsyncGate>) -> Self {
        let terminal = Arc::new(Mutex::new(None));
        let spends = Arc::new(AtomicU64::new(0));
        let retires = Arc::new(AtomicU64::new(0));
        let spend_terminal = terminal.clone();
        let spend_count = spends.clone();
        let retire_terminal = terminal.clone();
        let retire_count = retires.clone();
        let lease = ArtifactLeaseV3::new_with_retire(
            artifact,
            move || async move {
                spend_count.fetch_add(1, Ordering::SeqCst);
                *lock(&spend_terminal) = Some("consumed");
                Ok(())
            },
            move || async move {
                retire_count.fetch_add(1, Ordering::SeqCst);
                gate.enter();
                gate.wait_for_release().await;
                *lock(&retire_terminal) = Some("retired");
                Ok(())
            },
        );
        Self {
            lease,
            terminal,
            spends,
            retires,
        }
    }

    fn state(&self) -> String {
        lock(&self.terminal).unwrap_or("idle").to_owned()
    }
}

#[derive(Debug)]
struct AsyncGate {
    entered: AtomicBool,
    released: AtomicBool,
    changed: Notify,
}

impl AsyncGate {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            changed: Notify::new(),
        }
    }

    fn enter(&self) {
        self.entered.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait_for_entry(&self) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.entered.load(Ordering::Acquire) {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("retirement gate was not entered");
    }

    async fn wait_for_release(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.released.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

struct GateReleaseGuard(Arc<AsyncGate>);

impl Drop for GateReleaseGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Debug)]
struct SourceEntry {
    replacement: bool,
    result: Result<ArtifactLeaseV3, ArtifactSourceError>,
}

#[derive(Debug)]
struct VectorSource {
    entries: Mutex<VecDeque<SourceEntry>>,
    acquisitions: AtomicU64,
    replacement_acquisitions: AtomicU64,
    acquisition_times: Mutex<Vec<SystemTime>>,
}

#[derive(Debug)]
struct ClockBoundarySource {
    retry_after_unix_milliseconds: u64,
    retry_after_acquisition: u64,
    acquisitions: AtomicU64,
    changed: Notify,
}

impl ClockBoundarySource {
    fn new(retry_after_unix_milliseconds: u64, retry_after_acquisition: u64) -> Self {
        Self {
            retry_after_unix_milliseconds,
            retry_after_acquisition,
            acquisitions: AtomicU64::new(0),
            changed: Notify::new(),
        }
    }

    async fn wait_for_acquisitions(&self, expected: u64) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let changed = self.changed.notified();
                if self.acquisitions.load(Ordering::SeqCst) >= expected {
                    return;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("controller did not reach acquisition {expected}"));
    }
}

#[async_trait]
impl ArtifactSource for ClockBoundarySource {
    async fn acquire(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ArtifactLeaseV3, ArtifactSourceError> {
        let acquisition = self.acquisitions.fetch_add(1, Ordering::SeqCst) + 1;
        self.changed.notify_waiters();
        if acquisition < self.retry_after_acquisition {
            return Err(ArtifactSourceError::retryable());
        }
        if acquisition == self.retry_after_acquisition {
            return Err(ArtifactSourceError::retry_after(
                self.retry_after_unix_milliseconds,
            ));
        }
        cancellation.cancelled().await;
        Err(ArtifactSourceError::terminal())
    }
}

#[derive(Debug)]
struct ManualClockState {
    wall_milliseconds: i64,
    monotonic_milliseconds: u64,
    requested_sleeps: Vec<u64>,
}

#[derive(Debug)]
struct ManualControllerClock {
    state: Mutex<ManualClockState>,
    advanced: Notify,
    sleep_started: Notify,
}

impl ManualControllerClock {
    fn new(wall_milliseconds: i64, monotonic_milliseconds: u64) -> Self {
        Self {
            state: Mutex::new(ManualClockState {
                wall_milliseconds,
                monotonic_milliseconds,
                requested_sleeps: Vec::new(),
            }),
            advanced: Notify::new(),
            sleep_started: Notify::new(),
        }
    }

    fn advance(&self, wall_milliseconds: i64, monotonic_milliseconds: i64) {
        let mut state = lock(&self.state);
        state.wall_milliseconds = state.wall_milliseconds.saturating_add(wall_milliseconds);
        state.monotonic_milliseconds = if monotonic_milliseconds >= 0 {
            add_safe_counter(state.monotonic_milliseconds, monotonic_milliseconds as u64)
        } else {
            state
                .monotonic_milliseconds
                .saturating_sub(monotonic_milliseconds.unsigned_abs())
        };
        drop(state);
        self.advanced.notify_waiters();
    }

    async fn wait_for_sleep_count(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let started = self.sleep_started.notified();
                if lock(&self.state).requested_sleeps.len() >= expected {
                    return;
                }
                started.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("controller did not schedule sleep {expected}"));
    }

    fn requested_sleeps(&self) -> Vec<u64> {
        lock(&self.state).requested_sleeps.clone()
    }

    fn values(&self) -> (i64, u64) {
        let state = lock(&self.state);
        (state.wall_milliseconds, state.monotonic_milliseconds)
    }
}

impl ControllerClock for ManualControllerClock {
    fn wall_now(&self) -> SystemTime {
        let milliseconds = lock(&self.state).wall_milliseconds;
        if milliseconds >= 0 {
            SystemTime::UNIX_EPOCH + Duration::from_millis(milliseconds as u64)
        } else {
            SystemTime::UNIX_EPOCH - Duration::from_millis(milliseconds.unsigned_abs())
        }
    }

    fn monotonic_now_milliseconds(&self) -> u64 {
        lock(&self.state).monotonic_milliseconds
    }

    fn sleep(self: Arc<Self>, delay: Duration) -> ClockSleep {
        let deadline = {
            let mut state = lock(&self.state);
            let delay = duration_milliseconds(delay);
            state.requested_sleeps.push(delay);
            add_safe_counter(state.monotonic_milliseconds, delay)
        };
        self.sleep_started.notify_waiters();
        Box::pin(async move {
            loop {
                let advanced = self.advanced.notified();
                if self.monotonic_now_milliseconds() >= deadline {
                    return;
                }
                advanced.await;
            }
        })
    }
}

impl VectorSource {
    fn new(entries: impl IntoIterator<Item = SourceEntry>) -> Self {
        Self {
            entries: Mutex::new(entries.into_iter().collect()),
            acquisitions: AtomicU64::new(0),
            replacement_acquisitions: AtomicU64::new(0),
            acquisition_times: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl ArtifactSource for VectorSource {
    async fn acquire(
        &self,
        _cancellation: CancellationToken,
    ) -> Result<ArtifactLeaseV3, ArtifactSourceError> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        lock(&self.acquisition_times).push(SystemTime::now());
        let entry = lock(&self.entries)
            .pop_front()
            .unwrap_or_else(|| SourceEntry {
                replacement: false,
                result: Err(ArtifactSourceError::terminal()),
            });
        if entry.replacement {
            self.replacement_acquisitions.fetch_add(1, Ordering::SeqCst);
        }
        entry.result
    }
}

fn primary(lease: &TrackedLease) -> SourceEntry {
    SourceEntry {
        replacement: false,
        result: Ok(lease.lease.clone()),
    }
}

fn replacement(lease: &TrackedLease) -> SourceEntry {
    SourceEntry {
        replacement: true,
        result: Ok(lease.lease.clone()),
    }
}

fn source_error(error: ArtifactSourceError) -> SourceEntry {
    SourceEntry {
        replacement: false,
        result: Err(error),
    }
}

enum ConnectorOutcome {
    Error(ConnectError),
    SpendThenError(ConnectError),
    Success(Arc<dyn Session>),
    WaitForCancellation,
}

struct ConnectorAction {
    attempts: u64,
    transports: u64,
    allowed_candidate_ids: Option<HashSet<String>>,
    outcome: ConnectorOutcome,
}

#[derive(Default)]
struct ConnectorMetrics {
    attempts: AtomicU64,
    transports: AtomicU64,
}

fn vector_connector(
    actions: impl IntoIterator<Item = ConnectorAction>,
    metrics: Arc<ConnectorMetrics>,
) -> ConnectOneShot {
    let actions = Arc::new(Mutex::new(actions.into_iter().collect::<VecDeque<_>>()));
    Arc::new(move |lease, _options, cancellation| {
        let action = lock(&actions)
            .pop_front()
            .expect("controller vector connector action");
        metrics
            .attempts
            .fetch_add(action.attempts, Ordering::SeqCst);
        metrics
            .transports
            .fetch_add(action.transports, Ordering::SeqCst);
        if let Some(expected) = action.allowed_candidate_ids {
            let actual = lease
                .artifact_for_connector()
                .connection_plan()
                .expect("filtered controller connection plan")
                .candidates
                .iter()
                .map(|candidate| candidate.id.clone())
                .collect::<HashSet<_>>();
            assert_eq!(actual, expected, "controller candidate filter");
        }
        Box::pin(async move {
            match action.outcome {
                ConnectorOutcome::Error(error) => Err(error),
                ConnectorOutcome::SpendThenError(error) => {
                    spend(lease).await?;
                    Err(error)
                }
                ConnectorOutcome::Success(session) => {
                    spend(lease).await?;
                    Ok(session)
                }
                ConnectorOutcome::WaitForCancellation => {
                    cancellation.cancelled().await;
                    Err(ConnectError::from_runtime_code(
                        ConnectErrorCode::ConnectionFailed,
                    ))
                }
            }
        })
    })
}

async fn spend(lease: ArtifactLeaseV3) -> Result<(), ConnectError> {
    lease
        .claim()
        .map_err(|_| ConnectError::from_runtime_code(ConnectErrorCode::ArtifactInvalid))?
        .commit_spend()
        .await
        .map_err(|_| ConnectError::from_runtime_code(ConnectErrorCode::ConnectionFailed))?;
    Ok(())
}

#[derive(Debug)]
struct ControlledSession {
    terminated: AtomicBool,
    changed: Notify,
    termination_error: SessionError,
}

impl ControlledSession {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            terminated: AtomicBool::new(false),
            changed: Notify::new(),
            termination_error: SessionError::Closed,
        })
    }

    fn terminal() -> Arc<Self> {
        Arc::new(Self {
            terminated: AtomicBool::new(false),
            changed: Notify::new(),
            termination_error: SessionError::OperationFailed,
        })
    }

    fn terminate(&self) {
        self.terminated.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

#[async_trait]
impl Session for ControlledSession {
    fn rpc(&self) -> &dyn RpcPeer {
        panic!("RPC is not used by controller vector tests")
    }

    async fn open_stream(
        &self,
        _kind: &str,
        _metadata: StreamMetadata,
    ) -> Result<Box<dyn ByteStream>, SessionError> {
        Err(SessionError::OperationFailed)
    }

    async fn accept_stream(&self) -> Result<IncomingStream, SessionError> {
        Err(SessionError::OperationFailed)
    }

    async fn rekey(&self) -> Result<(), SessionError> {
        Err(SessionError::OperationFailed)
    }

    async fn probe_liveness(&self) -> Result<Duration, SessionError> {
        Err(SessionError::OperationFailed)
    }

    async fn wait_termination(&self) -> SessionTermination {
        while !self.terminated.load(Ordering::Acquire) {
            self.changed.notified().await;
        }
        SessionTermination {
            error: self.termination_error,
        }
    }

    async fn close(&self) -> Result<(), SessionError> {
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ObservedV3 {
    final_state: String,
    public_error: Option<String>,
    disposition: Option<String>,
    acquisitions: u64,
    connect_attempts: u64,
    transports_created: u64,
    replacement_acquisitions: u64,
    replacement_quota_used: u64,
    spend_callbacks: u64,
    retire_callbacks: u64,
    lease_terminal_states: Vec<String>,
    retry_delays_ms: Vec<u64>,
}

fn observe(
    status: ControllerStatus,
    source: &VectorSource,
    metrics: &ConnectorMetrics,
    leases: &[&TrackedLease],
    retry_delays_ms: Vec<u64>,
) -> ObservedV3 {
    observe_counts(
        status,
        source.acquisitions.load(Ordering::SeqCst),
        source.replacement_acquisitions.load(Ordering::SeqCst),
        metrics,
        leases,
        retry_delays_ms,
    )
}

fn observe_counts(
    status: ControllerStatus,
    acquisitions: u64,
    replacement_acquisitions: u64,
    metrics: &ConnectorMetrics,
    leases: &[&TrackedLease],
    retry_delays_ms: Vec<u64>,
) -> ObservedV3 {
    let (public_error, disposition) = status.last_failure.map_or((None, None), |failure| {
        let (code, disposition) = match failure {
            ConnectionFailure::ArtifactSource(error) => ("connection_failed", error.disposition()),
            ConnectionFailure::Connect { code, disposition } => (code.as_str(), disposition),
            ConnectionFailure::Session { disposition, .. } => ("connection_failed", disposition),
        };
        (
            Some(code.to_owned()),
            Some(disposition_name(disposition).to_owned()),
        )
    });
    ObservedV3 {
        final_state: state_name(status.state).to_owned(),
        public_error,
        disposition,
        acquisitions,
        connect_attempts: metrics.attempts.load(Ordering::SeqCst),
        transports_created: metrics.transports.load(Ordering::SeqCst),
        replacement_acquisitions,
        replacement_quota_used: replacement_acquisitions.min(1),
        spend_callbacks: leases
            .iter()
            .map(|lease| lease.spends.load(Ordering::SeqCst))
            .sum(),
        retire_callbacks: leases
            .iter()
            .map(|lease| lease.retires.load(Ordering::SeqCst))
            .sum(),
        lease_terminal_states: leases.iter().map(|lease| lease.state()).collect(),
        retry_delays_ms,
    }
}

fn assert_observed(scenario: &ScenarioV3, observed: ObservedV3) {
    let expected = &scenario.expected;
    let wanted = ObservedV3 {
        final_state: expected.final_state.clone(),
        public_error: expected.public_error.clone(),
        disposition: expected.disposition.clone(),
        acquisitions: expected.acquisitions,
        connect_attempts: expected.connect_attempts,
        transports_created: expected.transports_created,
        replacement_acquisitions: expected.replacement_acquisitions,
        replacement_quota_used: expected.replacement_quota_used,
        spend_callbacks: expected.spend_callbacks,
        retire_callbacks: expected.retire_callbacks,
        lease_terminal_states: expected.lease_terminal_states.clone(),
        retry_delays_ms: expected.retry_delays_ms.clone(),
    };
    assert_eq!(observed, wanted, "controller vector {}", scenario.id);
}

const fn state_name(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Idle => "idle",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Waiting => "waiting",
        ConnectionState::Failed => "failed",
        ConnectionState::Closed => "closed",
    }
}

const fn disposition_name(disposition: RetryDisposition) -> &'static str {
    match disposition {
        RetryDisposition::Terminal => "terminal",
        RetryDisposition::Retryable | RetryDisposition::RetryAfter(_) => "retryable",
    }
}

fn test_options(maximum_attempts: Option<u64>) -> ConnectionControllerOptions {
    let options = ConnectionControllerOptions::new(ConnectorOptions::new());
    match maximum_attempts {
        Some(maximum) => options
            .with_maximum_attempts(NonZeroU64::new(maximum).expect("nonzero"))
            .expect("safe maximum attempts"),
        None => options,
    }
}

async fn wait_for_state(
    controller: &ConnectionController,
    expected: ConnectionState,
) -> ControllerStatus {
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let status = controller.status();
            if status.state == expected {
                return status;
            }
            let snapshot = controller.snapshot();
            let _ = controller.wait_for_snapshot_change(&snapshot).await;
        }
    })
    .await;
    result.unwrap_or_else(|_| {
        panic!(
            "controller reaches {expected:?}; last status: {:?}",
            controller.status()
        )
    })
}

fn retry_delays(indices: impl IntoIterator<Item = u64>) -> Vec<u64> {
    indices
        .into_iter()
        .map(|index| retry_delay(index).as_millis() as u64)
        .collect()
}

fn scenarios() -> Vec<ScenarioV3> {
    controller_vectors().scenarios
}

fn browser_scenarios() -> Vec<ScenarioV3> {
    controller_vectors().browser_capability_scenarios
}

fn controller_vectors() -> ControllerVectorsV3 {
    serde_json::from_str::<ControllerVectorsV3>(include_str!(
        "../../testdata/transport_v3/controller_vectors.json"
    ))
    .expect("parse controller vectors")
}

#[tokio::test]
async fn top_level_controller_vectors_bind_production_results_retry_and_lease_state() {
    let vectors = controller_vectors();
    let mut seen = HashSet::new();
    for (code, detail, action) in &vectors.internal_transport_results {
        let key = format!("{code}/{}", detail.as_deref().unwrap_or(""));
        let (expected_action, public_code, disposition) = match (code.as_str(), detail.as_deref()) {
            ("invalid_artifact", None) => (
                "terminal",
                ConnectErrorCode::ArtifactInvalid,
                RetryDisposition::Terminal,
            ),
            ("expired_artifact", None) => (
                "acquire_primary",
                ConnectErrorCode::Expired,
                RetryDisposition::Retryable,
            ),
            ("tls_unsupported", None) => (
                "skip_candidate",
                ConnectErrorCode::TransportSecurityUnsupported,
                RetryDisposition::Terminal,
            ),
            ("tls_policy_expired", None) => (
                "policy_refresh",
                ConnectErrorCode::TransportSecurityFailed,
                RetryDisposition::Terminal,
            ),
            ("tls_failed", Some("ca_untrusted")) => (
                "candidate_terminal",
                ConnectErrorCode::TransportSecurityFailed,
                RetryDisposition::Terminal,
            ),
            ("tls_failed", Some("pin_mismatch")) => (
                "policy_refresh",
                ConnectErrorCode::TransportSecurityFailed,
                RetryDisposition::Terminal,
            ),
            ("tls_failed", Some("unknown")) => (
                "policy_refresh_for_pin",
                ConnectErrorCode::TransportSecurityFailed,
                RetryDisposition::Terminal,
            ),
            ("connection_failed", Some("browser_pin_opaque")) => (
                "policy_sensitive_replacement",
                ConnectErrorCode::ConnectionFailed,
                RetryDisposition::Retryable,
            ),
            other => panic!("unknown internal transport result {other:?}"),
        };
        assert_eq!(action, expected_action, "{key}");
        assert!(seen.insert(key), "duplicate internal transport result");
        let projected = ConnectError::from_runtime_code(public_code);
        assert_eq!(projected.code(), public_code);
        assert_eq!(connect_disposition(projected), disposition);
    }
    assert_eq!(seen.len(), 8);

    assert_eq!(vectors.retry_after.aggregate, "maximum_absolute_unix_ms");
    for value in &vectors.retry_after.valid {
        assert!(valid_retry_after(*value), "valid retry_after {value}");
        assert_eq!(
            ArtifactSourceError::retry_after(*value).disposition(),
            RetryDisposition::RetryAfter(*value)
        );
    }
    assert_eq!(
        vectors.retry_after.valid.iter().copied().max(),
        Some(MAX_RETRY_AFTER_UNIX_MILLISECONDS as u64)
    );
    for value in &vectors.retry_after.invalid {
        assert!(
            !value.as_u64().is_some_and(valid_retry_after),
            "invalid retry_after accepted: {value}"
        );
    }

    assert_eq!(
        vectors.lease_state_machine.states,
        ["idle", "claimed", "spending", "consumed", "retired"]
    );
    assert_eq!(
        vectors.lease_state_machine.transitions,
        [
            ("idle".into(), "claimed".into(), "claim".into()),
            ("claimed".into(), "spending".into(), "commitSpend".into()),
            (
                "spending".into(),
                "consumed".into(),
                "durable_result".into()
            ),
            ("claimed".into(), "retired".into(), "retire".into()),
        ]
    );
    assert_eq!(
        vectors.lease_state_machine.terminal_states,
        ["consumed", "retired"]
    );

    let artifact = ArtifactV3::parse(
        crate::artifact_v3::jcs_value(&base_artifact_value()).expect("artifact JCS"),
    )
    .expect("controller lease artifact");
    let spent = TrackedLease::new(artifact.clone());
    let duplicate = spent.lease.clone();
    let claimed = spent.lease.claim_for_controller().expect("idle -> claimed");
    assert!(
        duplicate.claim_for_controller().is_err(),
        "claimed lease was reusable"
    );
    let spending = claimed.begin_spend().expect("claimed -> spending");
    assert!(
        duplicate.claim_for_controller().is_err(),
        "spending lease was reusable"
    );
    spending.commit().await.expect("spending -> consumed");
    assert_eq!(spent.state(), "consumed");

    let retired = TrackedLease::new(artifact);
    let duplicate = retired.lease.clone();
    retired
        .lease
        .claim_for_controller()
        .expect("idle -> claimed")
        .retire()
        .await
        .expect("claimed -> retired");
    assert_eq!(retired.state(), "retired");
    assert!(
        duplicate.claim_for_controller().is_err(),
        "retired lease was reusable"
    );
}

#[tokio::test]
async fn every_registered_controller_scenario_executes_production_state() {
    let scenarios = scenarios();
    let mut executed = HashSet::new();
    for scenario in &scenarios {
        assert!(executed.insert(scenario.id.clone()), "duplicate vector ID");
        run_scenario(scenario).await;
    }
    assert_eq!(executed.len(), scenarios.len());
}

#[tokio::test]
async fn every_registered_browser_controller_scenario_executes_production_barrier_path() {
    let scenarios = browser_scenarios();
    let mut executed = HashSet::new();
    for scenario in &scenarios {
        assert!(
            executed.insert(scenario.id.clone()),
            "duplicate browser vector ID"
        );
        run_browser_capability_scenario(scenario).await;
    }
    assert_eq!(executed.len(), scenarios.len());
}

async fn run_browser_capability_scenario(scenario: &ScenarioV3) {
    assert_eq!(
        scenario.id,
        "concurrent-capability-invalidation-replacement-barrier"
    );
    assert_eq!(scenario.driver, "capability-linearization-barrier");
    assert_eq!(scenario.input["concurrent_controllers"], 2);
    assert_eq!(scenario.input["initial_capability"], "enabled");
    assert_eq!(scenario.input["invalidated_capability"], "ca_only");
    assert_eq!(scenario.input["primary_trigger"], "browser_pin_opaque");
    assert_eq!(
        scenario.input["invalidation_trigger"],
        "synchronous_not_supported"
    );

    let primary_retirement = Arc::new(AsyncGate::new());
    let _retirement_release = GateReleaseGuard(primary_retirement.clone());
    let refresh_primary = TrackedLease::new_with_retire_gate(
        browser_pin_artifact("refresh-pin", "refresh-primary.example", [0x11; 32]),
        primary_retirement.clone(),
    );
    let stale_primary = TrackedLease::new(browser_pin_artifact_with_candidates([
        ("stale-blocked", "stale-blocked.example", [0x21; 32]),
        ("stale-invalidator", "stale-invalidator.example", [0x22; 32]),
    ]));
    let refresh_replacement = TrackedLease::new(browser_replacement_artifact());
    let acquisitions = Arc::new(BrowserAcquisitionCoordinator::new());
    let refresh_source = Arc::new(BrowserBarrierSource::new(
        acquisitions.clone(),
        [
            SourceEntry {
                replacement: false,
                result: Ok(refresh_primary.lease.clone()),
            },
            SourceEntry {
                replacement: true,
                result: Ok(refresh_replacement.lease.clone()),
            },
        ],
    ));
    let stale_source = Arc::new(BrowserBarrierSource::new(
        acquisitions.clone(),
        [SourceEntry {
            replacement: false,
            result: Ok(stale_primary.lease.clone()),
        }],
    ));
    let state = Arc::new(BrowserBarrierState::new(primary_retirement.clone()));
    let preparer = Arc::new(BrowserBarrierPreparer::new(state.clone()));
    let connector = browser_barrier_connector(state.clone(), preparer);
    let refresh_controller = ConnectionController::new_with_connector(
        refresh_source,
        browser_test_options(2),
        connector.clone(),
    );
    let stale_controller =
        ConnectionController::new_with_connector(stale_source, browser_test_options(1), connector);

    refresh_controller.start();
    stale_controller.start();
    let release_initial = GateReleaseGuard(acquisitions.initial_release.clone());
    acquisitions.wait_for_initial_acquisitions().await;
    acquisitions.release_initial();
    acquisitions.wait_for_initial_release_observed().await;
    primary_retirement.wait_for_entry().await;
    assert_eq!(
        acquisitions.acquisitions.load(Ordering::SeqCst),
        2,
        "replacement acquisition crossed the primary retirement barrier"
    );
    tokio::time::timeout(
        Duration::from_secs(3),
        wait_for_state(&stale_controller, ConnectionState::Failed),
    )
    .await
    .expect("stale controller reaches failed state before replacement retirement release");
    assert_eq!(
        acquisitions.acquisitions.load(Ordering::SeqCst),
        2,
        "replacement acquisition occurred before retirement completed"
    );
    primary_retirement.release();
    drop(release_initial);
    let refresh_status = wait_for_state(&refresh_controller, ConnectionState::Failed).await;
    let stale_status = stale_controller.status();

    assert_eq!(
        acquisitions.peak.load(Ordering::SeqCst),
        scenario.expected.concurrent_acquisition_peak.unwrap()
    );
    assert_eq!(
        state.capability_snapshots(),
        scenario.expected.capability_snapshots.clone().unwrap()
    );
    assert_eq!(
        state.old_snapshot_live_gate_failures.load(Ordering::SeqCst),
        scenario.expected.old_snapshot_live_gate_failures.unwrap()
    );
    assert_eq!(
        state.pin_constructor_calls.load(Ordering::SeqCst),
        scenario.expected.pin_constructor_calls.unwrap()
    );
    assert_eq!(
        state.ca_constructor_calls.load(Ordering::SeqCst),
        scenario.expected.ca_constructor_calls.unwrap()
    );
    assert_eq!(
        state
            .post_invalidation_pin_constructor_calls
            .load(Ordering::SeqCst),
        scenario
            .expected
            .post_invalidation_pin_constructor_calls
            .unwrap()
    );
    assert_eq!(
        state.replacement_dial_candidate_ids(),
        scenario
            .expected
            .replacement_dial_candidate_ids
            .clone()
            .unwrap()
    );
    assert_eq!(
        state.connector_attempts.load(Ordering::SeqCst),
        scenario.expected.controller_connector_attempts.unwrap()
    );
    assert_eq!(stale_status.state, ConnectionState::Failed);
    assert!(matches!(
        stale_status.last_failure,
        Some(ConnectionFailure::Connect {
            code: ConnectErrorCode::TransportSecurityUnsupported,
            disposition: RetryDisposition::Terminal,
        })
    ));
    assert_eq!(
        scenario.expected.peer_final_state.as_deref(),
        Some(state_name(stale_status.state))
    );
    assert_eq!(
        scenario.expected.peer_public_error.as_deref(),
        stale_status.last_failure.and_then(|failure| match failure {
            ConnectionFailure::Connect { code, .. } => Some(code.as_str()),
            _ => None,
        })
    );
    let (public_error, disposition) = match refresh_status.last_failure {
        Some(ConnectionFailure::Connect { code, disposition }) => (
            Some(code.as_str().to_owned()),
            Some(disposition_name(disposition).to_owned()),
        ),
        failure => panic!("unexpected refresh controller failure: {failure:?}"),
    };
    assert_observed(
        scenario,
        ObservedV3 {
            final_state: state_name(refresh_status.state).to_owned(),
            public_error,
            disposition,
            acquisitions: acquisitions.acquisitions.load(Ordering::SeqCst),
            connect_attempts: state.dial_attempts.load(Ordering::SeqCst),
            transports_created: state.transports_created.load(Ordering::SeqCst),
            replacement_acquisitions: acquisitions.replacement_acquisitions.load(Ordering::SeqCst),
            replacement_quota_used: acquisitions.replacement_acquisitions.load(Ordering::SeqCst),
            spend_callbacks: refresh_primary.spends.load(Ordering::SeqCst)
                + stale_primary.spends.load(Ordering::SeqCst)
                + refresh_replacement.spends.load(Ordering::SeqCst),
            retire_callbacks: refresh_primary.retires.load(Ordering::SeqCst)
                + stale_primary.retires.load(Ordering::SeqCst)
                + refresh_replacement.retires.load(Ordering::SeqCst),
            lease_terminal_states: vec![
                refresh_primary.state(),
                stale_primary.state(),
                refresh_replacement.state(),
            ],
            retry_delays_ms: Vec::new(),
        },
    );
    refresh_controller.close().await;
    stale_controller.close().await;
}

#[derive(Debug)]
struct BrowserAcquisitionCoordinator {
    initial_release: Arc<AsyncGate>,
    active: AtomicU64,
    peak: AtomicU64,
    acquisitions: AtomicU64,
    replacement_acquisitions: AtomicU64,
    changed: Notify,
}

impl BrowserAcquisitionCoordinator {
    fn new() -> Self {
        Self {
            initial_release: Arc::new(AsyncGate::new()),
            active: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            acquisitions: AtomicU64::new(0),
            replacement_acquisitions: AtomicU64::new(0),
            changed: Notify::new(),
        }
    }

    fn enter_initial(&self) {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    fn leave_initial(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    fn release_initial(&self) {
        self.initial_release.release();
    }

    async fn wait_for_initial_acquisitions(&self) {
        self.wait_for_acquisition_condition(
            || self.peak.load(Ordering::SeqCst) == 2,
            "two initial controller acquisitions did not reach the barrier",
        )
        .await;
    }

    async fn wait_for_initial_release_observed(&self) {
        self.wait_for_acquisition_condition(
            || self.active.load(Ordering::SeqCst) == 0,
            "initial controller acquisitions did not leave the barrier",
        )
        .await;
    }

    async fn wait_for_acquisition_condition(
        &self,
        condition: impl Fn() -> bool,
        message: &'static str,
    ) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if condition() {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect(message);
    }
}

#[derive(Debug)]
struct BrowserBarrierSource {
    coordinator: Arc<BrowserAcquisitionCoordinator>,
    entries: Mutex<VecDeque<SourceEntry>>,
    initial_pending: AtomicBool,
}

impl BrowserBarrierSource {
    fn new(
        coordinator: Arc<BrowserAcquisitionCoordinator>,
        entries: impl IntoIterator<Item = SourceEntry>,
    ) -> Self {
        Self {
            coordinator,
            entries: Mutex::new(entries.into_iter().collect()),
            initial_pending: AtomicBool::new(true),
        }
    }
}

#[async_trait]
impl ArtifactSource for BrowserBarrierSource {
    async fn acquire(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ArtifactLeaseV3, ArtifactSourceError> {
        let entry = lock(&self.entries)
            .pop_front()
            .unwrap_or_else(|| SourceEntry {
                replacement: false,
                result: Err(ArtifactSourceError::terminal()),
            });
        self.coordinator.acquisitions.fetch_add(1, Ordering::SeqCst);
        if entry.replacement {
            self.coordinator
                .replacement_acquisitions
                .fetch_add(1, Ordering::SeqCst);
        }
        if self.initial_pending.swap(false, Ordering::AcqRel) {
            self.coordinator.enter_initial();
            let released = tokio::select! {
                _ = self.coordinator.initial_release.wait_for_release() => true,
                _ = cancellation.cancelled() => false,
            };
            self.coordinator.leave_initial();
            if !released {
                return Err(ArtifactSourceError::terminal());
            }
        }
        entry.result
    }
}

#[derive(Debug)]
struct BrowserBarrierState {
    pin_enabled: AtomicBool,
    capability_changed: Notify,
    primary_retirement: Arc<AsyncGate>,
    capability_snapshots: Mutex<Vec<String>>,
    connector_attempts: AtomicU64,
    dial_attempts: AtomicU64,
    transports_created: AtomicU64,
    pin_constructor_calls: AtomicU64,
    ca_constructor_calls: AtomicU64,
    old_snapshot_live_gate_failures: AtomicU64,
    post_invalidation_pin_constructor_calls: AtomicU64,
    replacement_dial_candidate_ids: Mutex<Vec<String>>,
}

impl BrowserBarrierState {
    fn new(primary_retirement: Arc<AsyncGate>) -> Self {
        Self {
            pin_enabled: AtomicBool::new(true),
            capability_changed: Notify::new(),
            primary_retirement,
            capability_snapshots: Mutex::new(Vec::new()),
            connector_attempts: AtomicU64::new(0),
            dial_attempts: AtomicU64::new(0),
            transports_created: AtomicU64::new(0),
            pin_constructor_calls: AtomicU64::new(0),
            ca_constructor_calls: AtomicU64::new(0),
            old_snapshot_live_gate_failures: AtomicU64::new(0),
            post_invalidation_pin_constructor_calls: AtomicU64::new(0),
            replacement_dial_candidate_ids: Mutex::new(Vec::new()),
        }
    }

    fn capability_name(&self) -> &'static str {
        if self.pin_enabled.load(Ordering::Acquire) {
            "enabled"
        } else {
            "ca_only"
        }
    }

    fn record_capability_snapshot(&self) {
        lock(&self.capability_snapshots).push(self.capability_name().to_owned());
    }

    fn capability_snapshots(&self) -> Vec<String> {
        lock(&self.capability_snapshots).clone()
    }

    fn invalidate_pin_support(&self) {
        assert!(
            self.pin_enabled.swap(false, Ordering::AcqRel),
            "pin capability invalidated more than once"
        );
        self.capability_changed.notify_waiters();
    }

    async fn wait_for_ca_only(&self) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let changed = self.capability_changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if !self.pin_enabled.load(Ordering::Acquire) {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("runtime capability did not become ca_only");
    }

    fn replacement_dial_candidate_ids(&self) -> Vec<String> {
        lock(&self.replacement_dial_candidate_ids).clone()
    }
}

struct BrowserBarrierPreparer {
    state: Arc<BrowserBarrierState>,
}

impl BrowserBarrierPreparer {
    fn new(state: Arc<BrowserBarrierState>) -> Self {
        Self { state }
    }
}

impl CandidatePreparerV3 for BrowserBarrierPreparer {
    fn prepare<'a>(
        &'a self,
        candidate: &'a CanonicalCandidateV3,
        _plan: &'a ConnectionPlanV3,
        _options: &'a ConnectorOptions,
        _deadline: tokio::time::Instant,
        _cancellation: &'a CancellationToken,
    ) -> CandidatePrepareFutureV3<'a> {
        Box::pin(async move {
            match candidate.id.as_str() {
                "stale-blocked" => {
                    self.state.dial_attempts.fetch_add(1, Ordering::SeqCst);
                    self.state.wait_for_ca_only().await;
                    self.state
                        .old_snapshot_live_gate_failures
                        .fetch_add(1, Ordering::SeqCst);
                    Err(CandidateFailureV3::Unsupported)
                }
                "stale-invalidator" => {
                    self.state.dial_attempts.fetch_add(1, Ordering::SeqCst);
                    self.state.primary_retirement.wait_for_entry().await;
                    assert!(self.state.pin_enabled.load(Ordering::Acquire));
                    self.state
                        .pin_constructor_calls
                        .fetch_add(1, Ordering::SeqCst);
                    self.state.invalidate_pin_support();
                    Err(CandidateFailureV3::Unsupported)
                }
                "refresh-pin" if !self.state.pin_enabled.load(Ordering::Acquire) => {
                    Err(CandidateFailureV3::Unsupported)
                }
                "refresh-pin" => {
                    self.state.dial_attempts.fetch_add(1, Ordering::SeqCst);
                    self.state
                        .pin_constructor_calls
                        .fetch_add(1, Ordering::SeqCst);
                    if !self.state.pin_enabled.load(Ordering::Acquire) {
                        self.state
                            .post_invalidation_pin_constructor_calls
                            .fetch_add(1, Ordering::SeqCst);
                    }
                    self.state.transports_created.fetch_add(1, Ordering::SeqCst);
                    Err(CandidateFailureV3::Security)
                }
                "replacement-ca" => {
                    self.state.dial_attempts.fetch_add(1, Ordering::SeqCst);
                    self.state
                        .ca_constructor_calls
                        .fetch_add(1, Ordering::SeqCst);
                    self.state.transports_created.fetch_add(1, Ordering::SeqCst);
                    lock(&self.state.replacement_dial_candidate_ids).push(candidate.id.clone());
                    Err(CandidateFailureV3::Connection)
                }
                _ => Err(CandidateFailureV3::InvalidArtifact),
            }
        })
    }
}

fn browser_barrier_connector(
    state: Arc<BrowserBarrierState>,
    preparer: Arc<BrowserBarrierPreparer>,
) -> ConnectOneShot {
    Arc::new(move |lease, options, cancellation| {
        state.connector_attempts.fetch_add(1, Ordering::SeqCst);
        state.record_capability_snapshot();
        let primary_opaque = {
            let candidates = lease.artifact_for_connector().controller_candidates();
            candidates.len() == 1 && candidates[0].id == "refresh-pin"
        };
        let preparer = preparer.clone();
        Box::pin(async move {
            match connect_v3_with_cancellation_and_preparer(
                lease,
                options,
                cancellation,
                preparer.as_ref(),
            )
            .await
            {
                Err(error)
                    if primary_opaque
                        && error.code() == ConnectErrorCode::TransportSecurityFailed =>
                {
                    Err(
                        ConnectError::from_runtime_code(ConnectErrorCode::ConnectionFailed)
                            .with_v3_candidate_masks(
                                error.v3_policy_trigger_mask(),
                                error.v3_failed_candidate_mask(),
                            ),
                    )
                }
                result => result,
            }
        })
    })
}

fn browser_test_options(maximum_attempts: u64) -> ConnectionControllerOptions {
    let connector = ConnectorOptions::new()
        .with_websocket_origin("https://example.org")
        .expect("browser barrier websocket origin");
    ConnectionControllerOptions::new(connector)
        .with_maximum_attempts(NonZeroU64::new(maximum_attempts).expect("nonzero"))
        .expect("safe maximum attempts")
}

async fn run_scenario(scenario: &ScenarioV3) {
    match scenario.id.as_str() {
        "pin-mismatch-changed-pin-success"
        | "pin-mismatch-same-policy-terminal"
        | "pin-to-ca-filtered"
        | "browser-opaque-exhausted"
        | "mixed-security-opaque-policy-refresh" => run_policy_replacement(scenario).await,
        "all-unsupported" | "capability-snapshot-invalidation-barrier" => {
            run_capability_filter(scenario).await
        }
        "replacement-expired-returns-primary"
        | "replacement-expired-before-race-returns-primary" => {
            run_replacement_expiry(scenario).await
        }
        "replacement-acquisition-retryable-continues-search" => {
            run_replacement_acquisition(scenario).await
        }
        "post-spend-retry-preserves-quota" => run_post_spend_retry(scenario).await,
        "lease-cancellation-first" | "lease-delivery-first" => {
            run_lease_cancel_race(scenario).await
        }
        "attempt-exhaustion" => run_attempt_exhaustion(scenario).await,
        "retry-after-and-monotonic-backoff" => run_retry_after(scenario).await,
        "race-order-independent-security-priority"
        | "single-ca-untrusted-terminal"
        | "ca-untrusted-dominates-ordinary-failure" => run_candidate_aggregation(scenario).await,
        "failure-ordinal-counts-attempt-once" => run_failure_ordinal(scenario).await,
        "artifact-expiry-before-race"
        | "artifact-expiry-at-race-end"
        | "artifact-expiry-immediately-before-spend"
        | "artifact-expiry-after-spend" => run_expiry_boundary(scenario).await,
        "established-session-termination-resets-cycle" => run_cycle_reset(scenario).await,
        "established-session-terminal-termination-resets-cycle" => {
            run_terminal_cycle_reset(scenario).await
        }
        "retry-after-wall-clock-forward-jump"
        | "retry-after-wall-clock-backward-jump"
        | "retry-after-wall-reread-bounded"
        | "monotonic-timer-safe-integer-saturation" => run_clock_boundary(scenario).await,
        "multiple-pin-trigger-endpoints-filtered" => run_multi_trigger(scenario).await,
        "retire-cleanup-failure-does-not-retry-lease" => run_retire_cleanup(scenario).await,
        "ordinary-retry-refresh-preserves-replacement-quota" => {
            run_quota_preservation(scenario).await
        }
        "attempt-counter-safe-integer-saturation" => run_attempt_saturation(scenario),
        "primary-fsa3-reject-consumes-spent"
        | "primary-fsa3-retryable-consumes-spent"
        | "replacement-fsa3-reject-consumes-spent"
        | "replacement-fsa3-retryable-consumes-spent"
        | "primary-fsh3-failure-consumes-spent"
        | "replacement-fsh3-failure-consumes-spent" => run_admission_boundary(scenario).await,
        "artifact-source-repeats-consumed-lease" | "artifact-source-repeats-retired-lease" => {
            run_duplicate_lease(scenario).await
        }
        id => panic!("unimplemented controller vector scenario {id}"),
    }
}

async fn run_policy_replacement(scenario: &ScenarioV3) {
    let mixed = scenario.input["trigger"].as_str() == Some("mixed_security_opaque");
    let primary_lease = TrackedLease::new(if mixed {
        pin_and_unrelated_ca_artifact([0x11; 32])
    } else {
        pin_artifact([0x11; 32])
    });
    let replacement_kind = scenario.input["replacement_policy"]
        .as_str()
        .expect("replacement policy");
    let replacement_artifact = match replacement_kind {
        "changed_pin" => {
            if mixed {
                pin_and_unrelated_ca_artifact([0x22; 32])
            } else {
                pin_artifact([0x22; 32])
            }
        }
        "same_pin" => pin_artifact([0x11; 32]),
        "ca" => ca_artifact(),
        value => panic!("unknown replacement policy {value}"),
    };
    let replacement_lease = TrackedLease::new(replacement_artifact);
    let source = Arc::new(VectorSource::new([
        primary(&primary_lease),
        replacement(&replacement_lease),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let opaque = scenario.input["trigger"].as_str() == Some("browser_pin_opaque");
    let code = if opaque {
        ConnectErrorCode::ConnectionFailed
    } else {
        ConnectErrorCode::TransportSecurityFailed
    };
    let mut actions = vec![ConnectorAction {
        attempts: 1,
        transports: 1,
        allowed_candidate_ids: None,
        outcome: ConnectorOutcome::Error(
            ConnectError::from_runtime_code(code)
                .with_v3_candidate_masks(1, if mixed { 0b11 } else { 1 }),
        ),
    }];
    if replacement_kind == "changed_pin" {
        actions.push(ConnectorAction {
            attempts: 1,
            transports: 1,
            allowed_candidate_ids: Some(HashSet::from(["w-pin".to_owned()])),
            outcome: ConnectorOutcome::Success(ControlledSession::new()),
        });
    }
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(actions, metrics.clone()),
    );
    controller.start();
    let wanted_state = if replacement_kind == "changed_pin" {
        ConnectionState::Connected
    } else {
        ConnectionState::Failed
    };
    let status = wait_for_state(&controller, wanted_state).await;
    assert_eq!(
        scenario.expected.no_mode_downgrade,
        (replacement_kind == "ca").then_some(true)
    );
    assert_eq!(scenario.expected.tls_error_claimed, opaque.then_some(false));
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&primary_lease, &replacement_lease],
            vec![],
        ),
    );
    controller.close().await;
}

async fn run_capability_filter(scenario: &ScenarioV3) {
    if scenario.driver != "capability-barrier" {
        let lease = TrackedLease::new(ca_artifact());
        let source = Arc::new(VectorSource::new([primary(&lease)]));
        let metrics = Arc::new(ConnectorMetrics::default());
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            vector_connector(
                [ConnectorAction {
                    attempts: 1,
                    transports: 0,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Error(ConnectError::from_runtime_code(
                        ConnectErrorCode::TransportSecurityUnsupported,
                    )),
                }],
                metrics.clone(),
            ),
        );
        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_observed(
            scenario,
            observe(status, &source, &metrics, &[&lease], vec![]),
        );
        controller.close().await;
        return;
    }

    let lease = TrackedLease::new(pin_artifact([0x11; 32]));
    let source = Arc::new(VectorSource::new([primary(&lease)]));
    let arrived = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let invalidated = Arc::new(AtomicBool::new(false));
    let preparer = Arc::new(BarrierCandidatePreparer {
        arrived: Arc::clone(&arrived),
        release: Arc::clone(&release),
        invalidated: Arc::clone(&invalidated),
    });
    let mut options = ConnectorOptions::new();
    options = options
        .with_websocket_origin("https://example.org")
        .expect("origin");
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        ConnectionControllerOptions::new(options)
            .with_maximum_attempts(NonZeroU64::new(1).expect("nonzero"))
            .expect("safe maximum attempts"),
        Arc::new({
            let preparer = Arc::clone(&preparer);
            move |lease, options, cancellation| {
                let preparer = Arc::clone(&preparer);
                Box::pin(async move {
                    connect_v3_with_cancellation_and_preparer(
                        lease,
                        options,
                        cancellation,
                        preparer.as_ref(),
                    )
                    .await
                })
            }
        }),
    );
    controller.start();
    arrived.notified().await;
    assert!(!invalidated.swap(true, Ordering::AcqRel));
    release.notify_one();
    let status = wait_for_state(&controller, ConnectionState::Failed).await;
    assert_eq!(scenario.expected.capability_rechecked, Some(true));
    assert!(matches!(
        status.last_failure,
        Some(ConnectionFailure::Connect {
            code: ConnectErrorCode::TransportSecurityUnsupported,
            disposition: RetryDisposition::Terminal,
        })
    ));
    assert_eq!(lease.spends.load(Ordering::SeqCst), 0);
    assert_eq!(lease.retires.load(Ordering::SeqCst), 1);
    controller.close().await;
}

struct BarrierCandidatePreparer {
    arrived: Arc<Notify>,
    release: Arc<Notify>,
    invalidated: Arc<AtomicBool>,
}

impl CandidatePreparerV3 for BarrierCandidatePreparer {
    fn prepare<'a>(
        &'a self,
        _candidate: &'a CanonicalCandidateV3,
        _plan: &'a ConnectionPlanV3,
        _options: &'a ConnectorOptions,
        _deadline: tokio::time::Instant,
        _cancellation: &'a CancellationToken,
    ) -> CandidatePrepareFutureV3<'a> {
        Box::pin(async move {
            self.arrived.notify_one();
            self.release.notified().await;
            if self.invalidated.load(Ordering::Acquire) {
                Err(CandidateFailureV3::Unsupported)
            } else {
                Err(CandidateFailureV3::Connection)
            }
        })
    }
}

async fn run_replacement_expiry(scenario: &ScenarioV3) {
    let first = TrackedLease::new(pin_artifact([0x11; 32]));
    let before_race = scenario.input["expiry_boundary"].as_str() == Some("before_race");
    let replacement_lease = TrackedLease::new(if before_race {
        pin_artifact_with_expiry([0x22; 32], 1)
    } else {
        pin_artifact([0x22; 32])
    });
    let third = TrackedLease::new(pin_and_unrelated_ca_artifact([0x11; 32]));
    let source = Arc::new(VectorSource::new([
        primary(&first),
        replacement(&replacement_lease),
        primary(&third),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            if before_race {
                vec![
                    ConnectorAction {
                        attempts: 1,
                        transports: 1,
                        allowed_candidate_ids: None,
                        outcome: ConnectorOutcome::Error(
                            ConnectError::from_runtime_code(
                                ConnectErrorCode::TransportSecurityFailed,
                            )
                            .with_v3_candidate_masks(1, 1),
                        ),
                    },
                    ConnectorAction {
                        attempts: 1,
                        transports: 1,
                        allowed_candidate_ids: Some(HashSet::from(["z-ca".to_owned()])),
                        outcome: ConnectorOutcome::Success(ControlledSession::new()),
                    },
                ]
            } else {
                vec![
                    ConnectorAction {
                        attempts: 1,
                        transports: 1,
                        allowed_candidate_ids: None,
                        outcome: ConnectorOutcome::Error(
                            ConnectError::from_runtime_code(
                                ConnectErrorCode::TransportSecurityFailed,
                            )
                            .with_v3_candidate_masks(1, 1),
                        ),
                    },
                    ConnectorAction {
                        attempts: 1,
                        transports: 1,
                        allowed_candidate_ids: Some(HashSet::from(["w-pin".to_owned()])),
                        outcome: ConnectorOutcome::Error(ConnectError::from_runtime_code(
                            ConnectErrorCode::Expired,
                        )),
                    },
                    ConnectorAction {
                        attempts: 1,
                        transports: 1,
                        allowed_candidate_ids: Some(HashSet::from(["z-ca".to_owned()])),
                        outcome: ConnectorOutcome::Success(ControlledSession::new()),
                    },
                ]
            },
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert!(controller.retry_now());
    let status = wait_for_state(&controller, ConnectionState::Connected).await;
    assert_eq!(scenario.expected.blocked_policy_remains_blocked, Some(true));
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&first, &replacement_lease, &third],
            retry_delays([1]),
        ),
    );
    controller.close().await;
}

async fn run_replacement_acquisition(scenario: &ScenarioV3) {
    let first = TrackedLease::new(pin_artifact([0x11; 32]));
    let replacement_lease = TrackedLease::new(pin_artifact([0x22; 32]));
    let source = Arc::new(VectorSource::new([
        primary(&first),
        source_error(ArtifactSourceError::retryable()),
        replacement(&replacement_lease),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Error(
                        ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
                            .with_v3_candidate_masks(1, 1),
                    ),
                },
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: Some(HashSet::from(["w-pin".to_owned()])),
                    outcome: ConnectorOutcome::Success(ControlledSession::new()),
                },
            ],
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert!(controller.retry_now());
    let status = wait_for_state(&controller, ConnectionState::Connected).await;
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&first, &replacement_lease],
            retry_delays([1]),
        ),
    );
    controller.close().await;
}

async fn run_post_spend_retry(scenario: &ScenarioV3) {
    let first = TrackedLease::new(pin_artifact([0x11; 32]));
    let replacement_lease = TrackedLease::new(pin_artifact([0x22; 32]));
    let third = TrackedLease::new(pin_artifact([0x22; 32]));
    let source = Arc::new(VectorSource::new([
        primary(&first),
        replacement(&replacement_lease),
        primary(&third),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let security = || {
        ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
            .with_v3_candidate_masks(1, 1)
    };
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Error(security()),
                },
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::SpendThenError(ConnectError::from_runtime_code(
                        ConnectErrorCode::ConnectionFailed,
                    )),
                },
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Error(security()),
                },
            ],
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert!(controller.retry_now());
    let status = wait_for_state(&controller, ConnectionState::Failed).await;
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&first, &replacement_lease, &third],
            retry_delays([1]),
        ),
    );
    controller.close().await;
}

#[derive(Debug)]
struct LateVectorSource {
    lease: Mutex<Option<ArtifactLeaseV3>>,
    acquisitions: AtomicU64,
}

#[async_trait]
impl ArtifactSource for LateVectorSource {
    async fn acquire(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ArtifactLeaseV3, ArtifactSourceError> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        cancellation.cancelled().await;
        lock(&self.lease)
            .take()
            .ok_or_else(ArtifactSourceError::terminal)
    }
}

async fn run_lease_cancel_race(scenario: &ScenarioV3) {
    let lease = TrackedLease::new(pin_artifact([0x11; 32]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let winner = scenario.input["linearization_winner"]
        .as_str()
        .expect("linearization winner");
    let status;
    let acquisitions;
    match winner {
        "cancellation" => {
            let source = Arc::new(LateVectorSource {
                lease: Mutex::new(Some(lease.lease.clone())),
                acquisitions: AtomicU64::new(0),
            });
            let controller = ConnectionController::new_with_connector(
                source.clone(),
                test_options(None),
                vector_connector([], metrics.clone()),
            );
            controller.start();
            while source.acquisitions.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            controller.close().await;
            status = controller.status();
            acquisitions = source.acquisitions.load(Ordering::SeqCst);
        }
        "delivery" => {
            let source = Arc::new(VectorSource::new([primary(&lease)]));
            let controller = ConnectionController::new_with_connector(
                source.clone(),
                test_options(None),
                vector_connector(
                    [ConnectorAction {
                        attempts: 1,
                        transports: 1,
                        allowed_candidate_ids: None,
                        outcome: ConnectorOutcome::WaitForCancellation,
                    }],
                    metrics.clone(),
                ),
            );
            controller.start();
            tokio::time::timeout(Duration::from_secs(3), async {
                while metrics.attempts.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("delivery wins before cancellation");
            controller.close().await;
            status = controller.status();
            acquisitions = source.acquisitions.load(Ordering::SeqCst);
        }
        value => panic!("unknown cancellation winner {value}"),
    }
    assert_observed(
        scenario,
        observe_counts(status, acquisitions, 0, &metrics, &[&lease], vec![]),
    );
}

async fn run_attempt_exhaustion(scenario: &ScenarioV3) {
    let maximum = scenario.input["maximum_attempts"]
        .as_u64()
        .expect("maximum attempts");
    let source = Arc::new(VectorSource::new([
        source_error(ArtifactSourceError::retryable()),
        source_error(ArtifactSourceError::retryable()),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(Some(maximum)),
        vector_connector([], metrics.clone()),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert!(controller.retry_now());
    let status = wait_for_state(&controller, ConnectionState::Failed).await;
    assert_observed(
        scenario,
        observe(status, &source, &metrics, &[], retry_delays([0])),
    );
    controller.close().await;
}

async fn run_retry_after(scenario: &ScenarioV3) {
    let (_, clock_delays) = assert_clock_vector(scenario);
    let lease = TrackedLease::new(pin_artifact([0x11; 32]));
    let now_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("wall clock after epoch")
        .as_millis() as u64;
    let deadline = now_ms + 280;
    let source = Arc::new(VectorSource::new([
        source_error(ArtifactSourceError::retry_after(deadline)),
        primary(&lease),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [ConnectorAction {
                attempts: 1,
                transports: 1,
                allowed_candidate_ids: None,
                outcome: ConnectorOutcome::Success(ControlledSession::new()),
            }],
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert_eq!(
        controller.retry_now(),
        scenario
            .expected
            .retry_now_allowed_before_deadline
            .unwrap_or(false)
    );
    let status = wait_for_state(&controller, ConnectionState::Connected).await;
    {
        let acquisition_times = lock(&source.acquisition_times);
        assert_eq!(acquisition_times.len(), 2);
        assert!(
            acquisition_times[1]
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("acquisition after epoch")
                .as_millis() as u64
                >= deadline
        );
    }
    assert_observed(
        scenario,
        observe(status, &source, &metrics, &[&lease], clock_delays),
    );
    controller.close().await;
}

async fn run_candidate_aggregation(scenario: &ScenarioV3) {
    let attempts = scenario.input["candidate_results"]
        .as_array()
        .map(|values| values.len() as u64)
        .or_else(|| {
            scenario.input["permutations"]
                .as_array()
                .and_then(|values| values.first())
                .and_then(Value::as_array)
                .map(|values| values.len() as u64)
        })
        .expect("candidate results");
    if let Some(permutations) = scenario.input["permutations"].as_array() {
        assert_eq!(scenario.expected.order_independent, Some(true));
        for permutation in permutations {
            let results = permutation.as_array().expect("failure permutation");
            assert!(
                results
                    .iter()
                    .any(|result| result.as_str() == Some("tls_failed")),
                "each completion order retains the security failure"
            );
        }
    }
    let lease = TrackedLease::new(ca_artifact());
    let source = Arc::new(VectorSource::new([primary(&lease)]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [ConnectorAction {
                attempts,
                transports: attempts,
                allowed_candidate_ids: None,
                outcome: ConnectorOutcome::Error(ConnectError::from_runtime_code(
                    ConnectErrorCode::TransportSecurityFailed,
                )),
            }],
            metrics.clone(),
        ),
    );
    controller.start();
    let status = wait_for_state(&controller, ConnectionState::Failed).await;
    if scenario.driver == "candidate-security-aggregation" {
        assert_eq!(scenario.expected.tls_error_claimed, Some(true));
    }
    assert_observed(
        scenario,
        observe(status, &source, &metrics, &[&lease], vec![]),
    );
    controller.close().await;
}

async fn run_failure_ordinal(scenario: &ScenarioV3) {
    let attempts = scenario.input["candidate_results"]
        .as_array()
        .expect("candidate results")
        .len() as u64;
    let lease = TrackedLease::new(ca_artifact());
    let source = Arc::new(VectorSource::new([primary(&lease)]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [ConnectorAction {
                attempts,
                transports: attempts,
                allowed_candidate_ids: None,
                outcome: ConnectorOutcome::Error(ConnectError::from_runtime_code(
                    ConnectErrorCode::ConnectionFailed,
                )),
            }],
            metrics.clone(),
        ),
    );
    controller.start();
    let status = wait_for_state(&controller, ConnectionState::Waiting).await;
    let ordinal = scenario.expected.failure_ordinal.expect("failure ordinal");
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&lease],
            retry_delays([ordinal - 1]),
        ),
    );
    controller.close().await;
}

async fn run_expiry_boundary(scenario: &ScenarioV3) {
    let boundary = scenario.input["expiry_boundary"]
        .as_str()
        .expect("expiry boundary");
    let lease = TrackedLease::new(ca_artifact());
    let source = Arc::new(VectorSource::new([primary(&lease)]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let outcome = if boundary == "after_spend" {
        ConnectorOutcome::SpendThenError(ConnectError::from_runtime_code(ConnectErrorCode::Expired))
    } else {
        ConnectorOutcome::Error(ConnectError::from_runtime_code(ConnectErrorCode::Expired))
    };
    let attempts = u64::from(boundary != "before_race");
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [ConnectorAction {
                attempts,
                transports: attempts,
                allowed_candidate_ids: None,
                outcome,
            }],
            metrics.clone(),
        ),
    );
    controller.start();
    let status = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert_eq!(scenario.expected.credential_bytes_written, Some(0));
    assert_observed(
        scenario,
        observe(status, &source, &metrics, &[&lease], retry_delays([0])),
    );
    controller.close().await;
}

async fn run_cycle_reset(scenario: &ScenarioV3) {
    let first = TrackedLease::new(ca_artifact());
    let second = TrackedLease::new(ca_artifact());
    let third = TrackedLease::new(ca_artifact());
    let source = Arc::new(VectorSource::new([
        primary(&first),
        primary(&second),
        primary(&third),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let first_session = ControlledSession::new();
    let final_session = ControlledSession::new();
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Error(ConnectError::from_runtime_code(
                        ConnectErrorCode::ConnectionFailed,
                    )),
                },
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Success(first_session.clone()),
                },
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Success(final_session),
                },
            ],
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert!(controller.retry_now());
    let _ = wait_for_state(&controller, ConnectionState::Connected).await;
    first_session.terminate();
    let waiting = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert_eq!(
        waiting.attempt, 0,
        "post-session cycle must publish attempt zero"
    );
    assert!(controller.retry_now());
    let status = wait_for_state(&controller, ConnectionState::Connected).await;
    assert_eq!(scenario.expected.failure_ordinal, Some(1));
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&first, &second, &third],
            retry_delays([0, 0]),
        ),
    );
    controller.close().await;
}

async fn run_terminal_cycle_reset(scenario: &ScenarioV3) {
    let lease = TrackedLease::new(ca_artifact());
    let source = Arc::new(VectorSource::new([primary(&lease)]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let session = ControlledSession::terminal();
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [ConnectorAction {
                attempts: 1,
                transports: 1,
                allowed_candidate_ids: None,
                outcome: ConnectorOutcome::Success(session.clone()),
            }],
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Connected).await;
    session.terminate();
    let status = wait_for_state(&controller, ConnectionState::Failed).await;
    assert_eq!(Some(status.attempt), scenario.expected.attempt);
    assert_eq!(scenario.expected.failure_ordinal, Some(1));
    assert_observed(
        scenario,
        observe(status, &source, &metrics, &[&lease], Vec::new()),
    );
    controller.close().await;
}

async fn run_clock_boundary(scenario: &ScenarioV3) {
    let wall_start = input_i64(scenario, "wall_start_ms");
    let monotonic_start = input_i64(scenario, "monotonic_start_ms");
    let retry_after = input_i64(scenario, "retry_after_unix_ms");
    let backoff = input_i64(scenario, "backoff_ms");
    let failure_ordinal = input_u64(scenario, "failure_ordinal");
    assert_eq!(
        retry_delay(failure_ordinal - 1).as_millis() as i64,
        backoff,
        "{} production backoff",
        scenario.id
    );
    assert!(wall_start >= 0 && monotonic_start >= 0 && retry_after >= 0);

    let source = Arc::new(ClockBoundarySource::new(
        retry_after as u64,
        failure_ordinal,
    ));
    let clock = Arc::new(ManualControllerClock::new(
        wall_start,
        monotonic_start as u64,
    ));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector_and_clock(
        source.clone(),
        test_options(None),
        vector_connector([], metrics.clone()),
        clock.clone(),
    );
    controller.start();
    for acquisition in 1..failure_ordinal {
        source.wait_for_acquisitions(acquisition).await;
        clock.wait_for_sleep_count(acquisition as usize).await;
        assert!(
            controller.retry_now(),
            "{} advances failure ordinal {acquisition}",
            scenario.id
        );
    }
    source.wait_for_acquisitions(failure_ordinal).await;
    let sleep_offset = failure_ordinal.saturating_sub(1) as usize;

    let wall_advances = input_i64_array(scenario, "wall_advances_ms");
    let monotonic_advances = input_i64_array(scenario, "monotonic_advances_ms");
    assert_eq!(wall_advances.len(), monotonic_advances.len());
    for (index, (wall_advance, monotonic_advance)) in wall_advances
        .into_iter()
        .zip(monotonic_advances)
        .enumerate()
    {
        clock.wait_for_sleep_count(sleep_offset + index + 1).await;
        assert_eq!(
            clock.requested_sleeps()[sleep_offset + index],
            scenario.expected.retry_delays_ms[index],
            "{} production scheduler sleep {index}",
            scenario.id
        );
        clock.advance(wall_advance, monotonic_advance);
    }

    let expected_state = match scenario.expected.final_state.as_str() {
        "connecting" => {
            source.wait_for_acquisitions(failure_ordinal + 1).await;
            assert_eq!(
                source.acquisitions.load(Ordering::SeqCst),
                failure_ordinal + 1
            );
            ConnectionState::Connecting
        }
        "waiting" => {
            clock
                .wait_for_sleep_count(sleep_offset + scenario.expected.retry_delays_ms.len() + 1)
                .await;
            assert_eq!(source.acquisitions.load(Ordering::SeqCst), failure_ordinal);
            ConnectionState::Waiting
        }
        state => panic!("unsupported clock-boundary state {state}"),
    };
    let status = controller.status();
    assert_eq!(
        status.state, expected_state,
        "{} controller state",
        scenario.id
    );

    let (wall_end, monotonic_end) = clock.values();
    assert_eq!(Some(wall_end as u64), scenario.expected.wall_end_ms);
    assert_eq!(Some(monotonic_end), scenario.expected.monotonic_end_ms);
    if let Some(maximum) = scenario.expected.maximum_wall_reread_ms {
        assert!(
            clock
                .requested_sleeps()
                .iter()
                .skip(sleep_offset)
                .all(|sleep| *sleep <= maximum),
            "{} wall reread interval",
            scenario.id
        );
    }
    if scenario.expected.timer_saturated == Some(true) {
        assert_eq!(monotonic_end, MAX_SAFE_INTEGER);
    }

    // These vectors scope acquisition and connector counters to work after the
    // scheduler boundary. The assertions above separately prove the real
    // controller source calls that enter and leave the production wait.
    assert_observed(
        scenario,
        ObservedV3 {
            final_state: state_name(status.state).to_owned(),
            public_error: None,
            disposition: None,
            acquisitions: 0,
            connect_attempts: 0,
            transports_created: 0,
            replacement_acquisitions: 0,
            replacement_quota_used: 0,
            spend_callbacks: 0,
            retire_callbacks: 0,
            lease_terminal_states: vec![],
            retry_delays_ms: scenario.expected.retry_delays_ms.clone(),
        },
    );
    controller.close().await;
}

fn assert_clock_vector(scenario: &ScenarioV3) -> (&'static str, Vec<u64>) {
    let wall_start = input_i64(scenario, "wall_start_ms");
    let monotonic_start = input_i64(scenario, "monotonic_start_ms");
    let retry_after = input_i64(scenario, "retry_after_unix_ms");
    let backoff = input_i64(scenario, "backoff_ms");
    let failure_ordinal = input_u64(scenario, "failure_ordinal");
    assert_eq!(
        retry_delay(failure_ordinal - 1).as_millis() as i64,
        backoff,
        "{} production backoff",
        scenario.id
    );
    let wall_advances = input_i64_array(scenario, "wall_advances_ms");
    let monotonic_advances = input_i64_array(scenario, "monotonic_advances_ms");
    assert_eq!(wall_advances.len(), monotonic_advances.len());

    if scenario.expected.timer_saturated == Some(true) {
        assert_eq!(monotonic_start as u64, MAX_SAFE_INTEGER - 1);
        assert_eq!(
            add_safe_counter(monotonic_start as u64, backoff as u64),
            MAX_SAFE_INTEGER
        );
        let sleeps = vec![MAX_SAFE_INTEGER - monotonic_start as u64];
        assert_eq!(scenario.expected.retry_delays_ms, sleeps);
        assert_eq!(scenario.expected.wall_end_ms, Some(0));
        assert_eq!(scenario.expected.monotonic_end_ms, Some(MAX_SAFE_INTEGER));
        return ("connecting", sleeps);
    }

    let mut wall = wall_start;
    let mut monotonic = monotonic_start;
    let monotonic_deadline = monotonic.saturating_add(backoff);
    let mut sleeps = Vec::with_capacity(wall_advances.len());
    for (wall_advance, monotonic_advance) in wall_advances
        .into_iter()
        .zip(monotonic_advances.into_iter())
    {
        let mut remaining = retry_after.saturating_sub(wall).clamp(0, 1_000);
        let monotonic_remaining = monotonic_deadline.saturating_sub(monotonic);
        if monotonic_remaining > 0 && monotonic_remaining < remaining {
            remaining = monotonic_remaining;
        }
        sleeps.push(remaining as u64);
        wall = wall.saturating_add(wall_advance);
        monotonic = monotonic.saturating_add(monotonic_advance);
    }
    assert_eq!(
        sleeps, scenario.expected.retry_delays_ms,
        "{} sleeps",
        scenario.id
    );
    assert_eq!(Some(wall as u64), scenario.expected.wall_end_ms);
    assert_eq!(Some(monotonic as u64), scenario.expected.monotonic_end_ms);
    if let Some(maximum) = scenario.expected.maximum_wall_reread_ms {
        assert!(sleeps.iter().all(|sleep| *sleep <= maximum));
    }
    let final_state = if wall >= retry_after && monotonic >= monotonic_deadline {
        "connecting"
    } else {
        "waiting"
    };
    (final_state, sleeps)
}

async fn run_multi_trigger(scenario: &ScenarioV3) {
    let first = TrackedLease::new(two_pin_artifact([0x11; 32], [0x33; 32]));
    let replacement_lease = TrackedLease::new(two_pin_artifact([0x11; 32], [0x33; 32]));
    let source = Arc::new(VectorSource::new([
        primary(&first),
        replacement(&replacement_lease),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let attempts = scenario.input["candidate_results"]
        .as_array()
        .expect("candidate results")
        .len() as u64;
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [ConnectorAction {
                attempts,
                transports: attempts,
                allowed_candidate_ids: None,
                outcome: ConnectorOutcome::Error(
                    ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
                        .with_v3_candidate_masks(0b11, 0b11),
                ),
            }],
            metrics.clone(),
        ),
    );
    controller.start();
    let status = wait_for_state(&controller, ConnectionState::Failed).await;
    assert_eq!(scenario.expected.no_mode_downgrade, Some(true));
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&first, &replacement_lease],
            vec![],
        ),
    );
    controller.close().await;
}

async fn run_retire_cleanup(scenario: &ScenarioV3) {
    let first = TrackedLease::new_with_retire_result(
        ca_artifact(),
        Err(ArtifactSpendErrorV3::CommitFailed),
    );
    let second = TrackedLease::new(ca_artifact());
    let source = Arc::new(VectorSource::new([primary(&first), primary(&second)]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Error(ConnectError::from_runtime_code(
                        ConnectErrorCode::ConnectionFailed,
                    )),
                },
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Success(ControlledSession::new()),
                },
            ],
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert_eq!(scenario.expected.cleanup_error_ignored, Some(true));
    assert!(controller.retry_now());
    let status = wait_for_state(&controller, ConnectionState::Connected).await;
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&first, &second],
            retry_delays([0]),
        ),
    );
    controller.close().await;
}

async fn run_quota_preservation(scenario: &ScenarioV3) {
    let first = TrackedLease::new(ca_artifact());
    let second = TrackedLease::new(pin_artifact([0x11; 32]));
    let third = TrackedLease::new(pin_artifact([0x22; 32]));
    let source = Arc::new(VectorSource::new([
        primary(&first),
        primary(&second),
        replacement(&third),
    ]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Error(ConnectError::from_runtime_code(
                        ConnectErrorCode::ConnectionFailed,
                    )),
                },
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: None,
                    outcome: ConnectorOutcome::Error(
                        ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
                            .with_v3_candidate_masks(1, 1),
                    ),
                },
                ConnectorAction {
                    attempts: 1,
                    transports: 1,
                    allowed_candidate_ids: Some(HashSet::from(["w-pin".to_owned()])),
                    outcome: ConnectorOutcome::Success(ControlledSession::new()),
                },
            ],
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert!(controller.retry_now());
    let status = wait_for_state(&controller, ConnectionState::Connected).await;
    assert_observed(
        scenario,
        observe(
            status,
            &source,
            &metrics,
            &[&first, &second, &third],
            retry_delays([0]),
        ),
    );
    controller.close().await;
}

fn run_attempt_saturation(scenario: &ScenarioV3) {
    let initial = input_u64(scenario, "initial_attempt");
    let maximum = input_u64(scenario, "maximum_attempts");
    assert_eq!(initial, MAX_SAFE_INTEGER);
    assert_eq!(maximum, MAX_SAFE_INTEGER);
    let observed_attempt = increment_safe_counter(initial);
    assert_eq!(Some(observed_attempt), scenario.expected.attempt);
    assert_eq!(scenario.expected.counter_saturated, Some(true));
    assert_observed(
        scenario,
        ObservedV3 {
            final_state: "connecting".to_owned(),
            public_error: None,
            disposition: None,
            acquisitions: 0,
            connect_attempts: 0,
            transports_created: 0,
            replacement_acquisitions: 0,
            replacement_quota_used: 0,
            spend_callbacks: 0,
            retire_callbacks: 0,
            lease_terminal_states: vec![],
            retry_delays_ms: vec![],
        },
    );
}

async fn run_admission_boundary(scenario: &ScenarioV3) {
    let phase = scenario.input["phase"].as_str().expect("admission phase");
    let admission_result = scenario.input["admission_result"]
        .as_str()
        .expect("admission result");
    let primary_lease = TrackedLease::new(pin_artifact([0x11; 32]));
    let replacement_lease =
        (phase == "replacement").then(|| TrackedLease::new(pin_artifact([0x22; 32])));
    let mut entries = vec![primary(&primary_lease)];
    if let Some(lease) = &replacement_lease {
        entries.push(replacement(lease));
    }
    let source = Arc::new(VectorSource::new(entries));
    let metrics = Arc::new(ConnectorMetrics::default());
    let terminal = admission_result == "fsa_reject";
    let admission_error = if terminal {
        ConnectError::from_terminal_runtime_code(ConnectErrorCode::ConnectionFailed)
    } else {
        ConnectError::from_runtime_code(ConnectErrorCode::ConnectionFailed)
    };
    let mut actions = Vec::new();
    if phase == "replacement" {
        actions.push(ConnectorAction {
            attempts: 1,
            transports: 1,
            allowed_candidate_ids: None,
            outcome: ConnectorOutcome::Error(
                ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
                    .with_v3_candidate_masks(1, 1),
            ),
        });
    }
    actions.push(ConnectorAction {
        attempts: 1,
        transports: 1,
        allowed_candidate_ids: None,
        outcome: ConnectorOutcome::SpendThenError(admission_error),
    });
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(actions, metrics.clone()),
    );
    controller.start();
    let status = if terminal {
        wait_for_state(&controller, ConnectionState::Failed).await
    } else {
        wait_for_state(&controller, ConnectionState::Waiting).await
    };
    let mut leases = vec![&primary_lease];
    if let Some(lease) = &replacement_lease {
        leases.push(lease);
    }
    let delays = if terminal {
        vec![]
    } else if phase == "replacement" {
        retry_delays([1])
    } else {
        retry_delays([0])
    };
    assert_observed(
        scenario,
        observe(status, &source, &metrics, &leases, delays),
    );
    controller.close().await;
}

async fn run_duplicate_lease(scenario: &ScenarioV3) {
    let terminal = scenario.input["repeated_terminal_state"]
        .as_str()
        .expect("repeated terminal state");
    let lease = TrackedLease::new(ca_artifact());
    let source = Arc::new(VectorSource::new([primary(&lease), primary(&lease)]));
    let metrics = Arc::new(ConnectorMetrics::default());
    let outcome = match terminal {
        "consumed" => ConnectorOutcome::SpendThenError(ConnectError::from_runtime_code(
            ConnectErrorCode::ConnectionFailed,
        )),
        "retired" => ConnectorOutcome::Error(ConnectError::from_runtime_code(
            ConnectErrorCode::ConnectionFailed,
        )),
        value => panic!("unknown repeated terminal state {value}"),
    };
    let controller = ConnectionController::new_with_connector(
        source.clone(),
        test_options(None),
        vector_connector(
            [ConnectorAction {
                attempts: 1,
                transports: 1,
                allowed_candidate_ids: None,
                outcome,
            }],
            metrics.clone(),
        ),
    );
    controller.start();
    let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
    assert!(controller.retry_now());
    let status = wait_for_state(&controller, ConnectionState::Failed).await;
    assert_observed(
        scenario,
        observe(status, &source, &metrics, &[&lease], retry_delays([0])),
    );
    controller.close().await;
}

fn pin_artifact(pin: [u8; 32]) -> ArtifactV3 {
    artifact_with_candidates(serde_json::json!([pin_candidate(
        "w-pin",
        "wss://pin.example.org/flowersec/v3/direct",
        pin
    )]))
}

fn browser_pin_artifact(id: &str, host: &str, pin: [u8; 32]) -> ArtifactV3 {
    browser_pin_artifact_with_candidates([(id, host, pin)])
}

fn browser_pin_artifact_with_candidates<const N: usize>(
    candidates: [(&str, &str, [u8; 32]); N],
) -> ArtifactV3 {
    artifact_with_candidates(Value::Array(
        candidates
            .into_iter()
            .map(|(id, host, pin)| {
                pin_candidate(id, &format!("wss://{host}/flowersec/v3/direct"), pin)
            })
            .collect(),
    ))
}

fn browser_replacement_artifact() -> ArtifactV3 {
    artifact_with_candidates(serde_json::json!([
        pin_candidate(
            "refresh-pin",
            "wss://refresh-primary.example/flowersec/v3/direct",
            [0x12; 32]
        ),
        {
            "carrier": "websocket",
            "id": "replacement-ca",
            "tls": {"mode": "ca"},
            "url": "wss://replacement-ca.example/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3"
        }
    ]))
}

fn pin_artifact_with_expiry(pin: [u8; 32], expires_at_unix_seconds: u64) -> ArtifactV3 {
    let mut value = base_artifact_value();
    value["session"]["init_expire_at_unix_s"] = expires_at_unix_seconds.into();
    value["path"]["candidates"] = serde_json::json!([pin_candidate(
        "w-pin",
        "wss://pin.example.org/flowersec/v3/direct",
        pin
    )]);
    ArtifactV3::parse(crate::artifact_v3::jcs_value(&value).expect("artifact JCS"))
        .expect("valid expiring controller vector artifact")
}

fn ca_artifact() -> ArtifactV3 {
    artifact_with_candidates(serde_json::json!([{
        "carrier": "websocket",
        "id": "w-ca",
        "tls": {"mode": "ca"},
        "url": "wss://ca.example.org/flowersec/v3/direct",
        "wire_profile": "flowersec-direct/3"
    }]))
}

fn pin_and_unrelated_ca_artifact(pin: [u8; 32]) -> ArtifactV3 {
    artifact_with_candidates(serde_json::json!([
        pin_candidate(
            "w-pin",
            "wss://pin.example.org/flowersec/v3/direct",
            pin
        ),
        {
            "carrier": "websocket",
            "id": "z-ca",
            "tls": {"mode": "ca"},
            "url": "wss://ca.example.org/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3"
        }
    ]))
}

fn two_pin_artifact(first: [u8; 32], second: [u8; 32]) -> ArtifactV3 {
    artifact_with_candidates(serde_json::json!([
        pin_candidate(
            "a-pin",
            "wss://a-pin.example.org/flowersec/v3/direct",
            first
        ),
        pin_candidate(
            "z-pin",
            "wss://z-pin.example.org/flowersec/v3/direct",
            second
        )
    ]))
}

fn pin_candidate(id: &str, url: &str, pin: [u8; 32]) -> Value {
    serde_json::json!({
        "carrier": "websocket",
        "id": id,
        "tls": {"mode": "pin", "pins": [{
            "algorithm": "sha-256",
            "not_after_unix_s": 2_000_000_300_u64,
            "value_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pin)
        }]},
        "url": url,
        "wire_profile": "flowersec-direct/3"
    })
}

fn artifact_with_candidates(candidates: Value) -> ArtifactV3 {
    let mut value = base_artifact_value();
    value["path"]["candidates"] = candidates;
    ArtifactV3::parse(crate::artifact_v3::jcs_value(&value).expect("artifact JCS"))
        .expect("valid controller vector artifact")
}

fn base_artifact_value() -> Value {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v3/artifact_vectors.json"
    ))
    .expect("artifact vectors");
    serde_json::from_str(
        vectors["positive"][0]["artifact_json"]
            .as_str()
            .expect("positive artifact JSON"),
    )
    .expect("positive artifact value")
}

fn input_u64(scenario: &ScenarioV3, key: &str) -> u64 {
    scenario.input[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{} missing u64 {key}", scenario.id))
}

fn input_i64(scenario: &ScenarioV3, key: &str) -> i64 {
    scenario.input[key]
        .as_i64()
        .unwrap_or_else(|| panic!("{} missing i64 {key}", scenario.id))
}

fn input_i64_array(scenario: &ScenarioV3, key: &str) -> Vec<i64> {
    scenario.input[key]
        .as_array()
        .unwrap_or_else(|| panic!("{} missing array {key}", scenario.id))
        .iter()
        .map(|value| value.as_i64().expect("i64 array value"))
        .collect()
}
