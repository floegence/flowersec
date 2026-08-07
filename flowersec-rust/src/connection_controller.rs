//! Long-lived connection ownership above the one-shot native connector.

use std::{
    fmt,
    num::NonZeroU64,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    ArtifactLease, ConnectError, ConnectErrorCode, ConnectorOptions, SessionError,
    connect_with_cancellation, transport_v2::SessionV2,
};

const DEFAULT_INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_RETRY_FACTOR: u32 = 2;
const DEFAULT_MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// A structured retry decision. No decision is inferred from error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDisposition {
    Terminal,
    Retryable,
    RetryAfter(SystemTime),
}

/// A redacted artifact acquisition failure with an explicit retry decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec artifact acquisition failed")]
pub struct ArtifactSourceError {
    disposition: RetryDisposition,
}

impl ArtifactSourceError {
    /// Creates a terminal failure. Sources should use this for unknown errors.
    pub const fn terminal() -> Self {
        Self {
            disposition: RetryDisposition::Terminal,
        }
    }

    /// Creates a retryable failure governed by the controller's backoff policy.
    pub const fn retryable() -> Self {
        Self {
            disposition: RetryDisposition::Retryable,
        }
    }

    /// Creates a retryable failure that cannot run before `not_before`.
    pub const fn retry_after(not_before: SystemTime) -> Self {
        Self {
            disposition: RetryDisposition::RetryAfter(not_before),
        }
    }

    pub const fn disposition(self) -> RetryDisposition {
        self.disposition
    }
}

/// Supplies one fresh, independently spendable artifact lease per attempt.
///
/// The controller races acquisition against cancellation, so dropping the
/// acquisition future must release all source-owned resources.
#[async_trait]
pub trait ArtifactSource: fmt::Debug + Send + Sync + 'static {
    async fn acquire(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ArtifactLease, ArtifactSourceError>;
}

/// Deterministic exponential retry policy for one connection cycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    initial_delay: Duration,
    factor: u32,
    max_delay: Duration,
    max_attempts: Option<NonZeroU64>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay: DEFAULT_INITIAL_RETRY_DELAY,
            factor: DEFAULT_RETRY_FACTOR,
            max_delay: DEFAULT_MAX_RETRY_DELAY,
            max_attempts: None,
        }
    }
}

impl RetryPolicy {
    pub fn new(
        initial_delay: Duration,
        factor: u32,
        max_delay: Duration,
    ) -> Result<Self, RetryPolicyError> {
        if initial_delay.is_zero()
            || factor == 0
            || max_delay < initial_delay
            || SystemTime::now().checked_add(max_delay).is_none()
        {
            return Err(RetryPolicyError::Invalid);
        }
        Ok(Self {
            initial_delay,
            factor,
            max_delay,
            max_attempts: None,
        })
    }

    pub const fn with_max_attempts(mut self, max_attempts: NonZeroU64) -> Self {
        self.max_attempts = Some(max_attempts);
        self
    }

    pub const fn initial_delay(self) -> Duration {
        self.initial_delay
    }

    pub const fn factor(self) -> u32 {
        self.factor
    }

    pub const fn max_delay(self) -> Duration {
        self.max_delay
    }

    pub const fn max_attempts(self) -> Option<NonZeroU64> {
        self.max_attempts
    }

    fn delay(self, retry_index: u64) -> Duration {
        let mut delay = self.initial_delay;
        for _ in 0..retry_index {
            delay = delay.saturating_mul(self.factor).min(self.max_delay);
            if delay == self.max_delay {
                break;
            }
        }
        delay
    }
}

/// Complete native connector and retry configuration.
#[derive(Clone, Debug)]
pub struct ConnectionControllerOptions {
    connector: ConnectorOptions,
    retry: RetryPolicy,
}

impl ConnectionControllerOptions {
    pub fn new(connector: ConnectorOptions) -> Self {
        Self {
            connector,
            retry: RetryPolicy::default(),
        }
    }

    pub const fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    pub const fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RetryPolicyError {
    #[error("invalid Flowersec connection retry policy")]
    Invalid,
}

/// Observable long-lived connection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Idle,
    Connecting,
    Connected,
    Waiting,
    Failed,
    Closed,
}

/// The bounded owning boundary for the most recent connection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionFailure {
    ArtifactSource(ArtifactSourceError),
    Connect {
        code: ConnectErrorCode,
        disposition: RetryDisposition,
    },
    Session {
        error: SessionError,
        disposition: RetryDisposition,
    },
}

impl ConnectionFailure {
    pub const fn disposition(self) -> RetryDisposition {
        match self {
            Self::ArtifactSource(error) => error.disposition(),
            Self::Connect { disposition, .. } | Self::Session { disposition, .. } => disposition,
        }
    }
}

/// An immutable controller snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionStatus {
    pub state: ConnectionState,
    /// The 1-based attempt ordinal for the current connection cycle. Idle is
    /// zero; waiting after termination retains the completed cycle's ordinal,
    /// and the replacement cycle starts at one when it enters connecting.
    pub attempt: u64,
    pub next_retry_at: Option<SystemTime>,
    pub last_failure: Option<ConnectionFailure>,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectionControllerStartError {
    #[error("Flowersec connection controller is already started")]
    AlreadyStarted,
    #[error("Flowersec connection controller is closed")]
    Closed,
    #[error("Flowersec connection controller requires a Tokio runtime")]
    RuntimeUnavailable,
}

struct ControllerState {
    status: ConnectionStatus,
    current: Option<Arc<dyn SessionV2>>,
}

struct ControllerInner {
    source: Arc<dyn ArtifactSource>,
    options: ConnectionControllerOptions,
    cancellation: CancellationToken,
    retry_wake: Notify,
    retry_revision: AtomicU64,
    changed: Notify,
    state: Mutex<ControllerState>,
}

impl fmt::Debug for ControllerInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerInner")
            .field("source", &self.source)
            .field("options", &self.options)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

/// The sole owner of refresh, retry, and current-session replacement.
pub struct ConnectionController {
    inner: Arc<ControllerInner>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for ConnectionController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionController")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl ConnectionController {
    pub fn new(source: Arc<dyn ArtifactSource>, options: ConnectionControllerOptions) -> Self {
        Self {
            inner: Arc::new(ControllerInner {
                source,
                options,
                cancellation: CancellationToken::new(),
                retry_wake: Notify::new(),
                retry_revision: AtomicU64::new(0),
                changed: Notify::new(),
                state: Mutex::new(ControllerState {
                    status: ConnectionStatus {
                        state: ConnectionState::Idle,
                        attempt: 0,
                        next_retry_at: None,
                        last_failure: None,
                        revision: 0,
                    },
                    current: None,
                }),
            }),
            task: Mutex::new(None),
        }
    }

    /// Starts the controller's only scheduler.
    pub fn start(&self) -> Result<(), ConnectionControllerStartError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| ConnectionControllerStartError::RuntimeUnavailable)?;
        let mut task = lock(&self.task);
        if task.is_some() {
            return Err(ConnectionControllerStartError::AlreadyStarted);
        }
        if self.status().state == ConnectionState::Closed {
            return Err(ConnectionControllerStartError::Closed);
        }
        *task = Some(runtime.spawn(run_controller(self.inner.clone())));
        Ok(())
    }

    pub fn status(&self) -> ConnectionStatus {
        self.inner.status()
    }

    /// Returns the current established session. A terminated session is
    /// removed before retry begins, and a replacement is published only after
    /// it has fully established.
    pub fn current_session(&self) -> Option<Arc<dyn SessionV2>> {
        lock(&self.inner.state).current.clone()
    }

    /// Waits until the controller advances beyond `revision`.
    pub async fn wait_for_status_change(&self, revision: u64) -> ConnectionStatus {
        loop {
            let changed = self.inner.changed.notified();
            let status = self.status();
            if status.revision != revision {
                return status;
            }
            changed.await;
        }
    }

    /// Wakes the sole scheduler only while it is waiting. A server-supplied
    /// retry-after deadline remains authoritative.
    pub fn retry_now(&self) -> bool {
        let revision = {
            let state = lock(&self.inner.state);
            if state.status.state != ConnectionState::Waiting {
                return false;
            }
            state.status.revision
        };
        self.inner.retry_revision.store(revision, Ordering::Release);
        self.inner.retry_wake.notify_waiters();
        true
    }

    /// Atomically closes the controller, cancels all in-flight work, and closes
    /// the current session without scheduling another attempt.
    pub async fn close(&self) {
        self.inner.cancellation.cancel();
        self.inner.retry_wake.notify_waiters();
        if let Some(session) = self.inner.finish_closed() {
            let _ = session.close().await;
        }
        let task = lock(&self.task).take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for ConnectionController {
    fn drop(&mut self) {
        self.inner.cancellation.cancel();
        self.inner.retry_wake.notify_waiters();
    }
}

impl ControllerInner {
    fn status(&self) -> ConnectionStatus {
        lock(&self.state).status
    }

    fn set_connecting(&self, attempt: u64) -> bool {
        self.update(|state| {
            state.status.state = ConnectionState::Connecting;
            state.status.attempt = attempt;
            state.status.next_retry_at = None;
            state.status.last_failure = None;
        })
    }

    fn set_connected(&self, attempt: u64, session: Arc<dyn SessionV2>) -> bool {
        self.update(|state| {
            state.current = Some(session);
            state.status.state = ConnectionState::Connected;
            state.status.attempt = attempt;
            state.status.next_retry_at = None;
            state.status.last_failure = None;
        })
    }

    fn set_waiting(
        &self,
        attempt: u64,
        next_retry_at: SystemTime,
        failure: ConnectionFailure,
        clear_current: bool,
    ) -> Option<u64> {
        if !self.update(|state| {
            if clear_current {
                state.current = None;
            }
            state.status.state = ConnectionState::Waiting;
            state.status.attempt = attempt;
            state.status.next_retry_at = Some(next_retry_at);
            state.status.last_failure = Some(failure);
        }) {
            return None;
        }
        Some(self.status().revision)
    }

    fn set_failed(&self, attempt: u64, failure: ConnectionFailure, clear_current: bool) -> bool {
        self.update(|state| {
            if clear_current {
                state.current = None;
            }
            state.status.state = ConnectionState::Failed;
            state.status.attempt = attempt;
            state.status.next_retry_at = None;
            state.status.last_failure = Some(failure);
        })
    }

    fn update(&self, update: impl FnOnce(&mut ControllerState)) -> bool {
        {
            let mut state = lock(&self.state);
            if state.status.state == ConnectionState::Closed {
                return false;
            }
            update(&mut state);
            state.status.revision = state.status.revision.saturating_add(1);
        }
        self.changed.notify_waiters();
        true
    }

    fn finish_closed(&self) -> Option<Arc<dyn SessionV2>> {
        let current = {
            let mut state = lock(&self.state);
            if state.status.state == ConnectionState::Closed {
                return None;
            }
            state.status.state = ConnectionState::Closed;
            state.status.next_retry_at = None;
            state.status.revision = state.status.revision.saturating_add(1);
            state.current.take()
        };
        self.changed.notify_waiters();
        current
    }
}

async fn run_controller(inner: Arc<ControllerInner>) {
    let mut attempt = 0_u64;
    let mut retry_index = 0_u64;
    loop {
        if inner.cancellation.is_cancelled() {
            close_inner(&inner).await;
            return;
        }
        attempt = attempt.saturating_add(1);
        if !inner.set_connecting(attempt) {
            return;
        }

        let acquisition = inner.source.acquire(inner.cancellation.child_token());
        let lease = tokio::select! {
            _ = inner.cancellation.cancelled() => {
                close_inner(&inner).await;
                return;
            }
            result = acquisition => match result {
                Ok(lease) => lease,
                Err(error) => {
                    let failure = ConnectionFailure::ArtifactSource(error);
                    if !schedule_retry(
                        &inner,
                        attempt,
                        attempt,
                        retry_index,
                        failure,
                    ).await {
                        return;
                    }
                    retry_index = retry_index.saturating_add(1);
                    continue;
                }
            }
        };

        let mut lease = lease;
        let result = connect_with_cancellation(
            &mut lease,
            inner.options.connector.clone(),
            inner.cancellation.child_token(),
        )
        .await;
        if inner.cancellation.is_cancelled() {
            if let Ok(session) = result {
                let _ = session.close().await;
            }
            close_inner(&inner).await;
            return;
        }
        let session = match result {
            Ok(session) => session,
            Err(error) => {
                let disposition = connect_disposition(error);
                let failure = ConnectionFailure::Connect {
                    code: error.code(),
                    disposition,
                };
                if !schedule_retry(&inner, attempt, attempt, retry_index, failure).await {
                    return;
                }
                retry_index = retry_index.saturating_add(1);
                continue;
            }
        };

        if !inner.set_connected(attempt, session.clone()) {
            let _ = session.close().await;
            return;
        }
        let termination = tokio::select! {
            _ = inner.cancellation.cancelled() => {
                close_inner(&inner).await;
                return;
            }
            termination = session.wait_termination() => termination,
        };
        retry_index = 0;
        let failure = ConnectionFailure::Session {
            error: termination.error,
            disposition: session_disposition(termination.error),
        };
        // A terminated session is never reused or migrated into its replacement.
        // Close it before entering retry scheduling so every controller-owned
        // carrier is retired before a fresh artifact can establish a session.
        let _ = session.close().await;
        if !schedule_retry(&inner, attempt, 0, retry_index, failure).await {
            return;
        }
        attempt = 0;
        retry_index = 1;
    }
}

async fn schedule_retry(
    inner: &ControllerInner,
    status_attempt: u64,
    attempts_in_cycle: u64,
    retry_index: u64,
    failure: ConnectionFailure,
) -> bool {
    let disposition = failure.disposition();
    let clear_current = matches!(failure, ConnectionFailure::Session { .. });
    if disposition == RetryDisposition::Terminal
        || inner
            .options
            .retry
            .max_attempts
            .is_some_and(|maximum| attempts_in_cycle >= maximum.get())
    {
        inner.set_failed(status_attempt, failure, clear_current);
        return false;
    }
    let now = SystemTime::now();
    let backoff_at = now + inner.options.retry.delay(retry_index);
    let not_before = match disposition {
        RetryDisposition::RetryAfter(deadline) => Some(deadline),
        RetryDisposition::Terminal | RetryDisposition::Retryable => None,
    };
    let next_retry_at = not_before.map_or(backoff_at, |deadline| deadline.max(backoff_at));
    let Some(waiting_revision) =
        inner.set_waiting(status_attempt, next_retry_at, failure, clear_current)
    else {
        return false;
    };
    wait_for_retry(inner, next_retry_at, not_before, waiting_revision).await
}

async fn wait_for_retry(
    inner: &ControllerInner,
    scheduled: SystemTime,
    not_before: Option<SystemTime>,
    waiting_revision: u64,
) -> bool {
    tokio::select! {
        _ = inner.cancellation.cancelled() => false,
        ready = wait_until(inner, scheduled) => ready,
        _ = wait_for_retry_now(inner, waiting_revision) => {
            if let Some(deadline) = not_before {
                wait_until(inner, deadline).await
            } else {
                true
            }
        }
    }
}

async fn wait_for_retry_now(inner: &ControllerInner, waiting_revision: u64) {
    loop {
        let notified = inner.retry_wake.notified();
        if inner.retry_revision.load(Ordering::Acquire) == waiting_revision {
            return;
        }
        notified.await;
    }
}

async fn wait_until(inner: &ControllerInner, deadline: SystemTime) -> bool {
    loop {
        let Ok(delay) = deadline.duration_since(SystemTime::now()) else {
            return true;
        };
        if delay.is_zero() {
            return true;
        }
        let bounded_delay = delay.min(DEFAULT_MAX_RETRY_DELAY);
        tokio::select! {
            _ = inner.cancellation.cancelled() => return false,
            _ = tokio::time::sleep(bounded_delay) => {}
        }
    }
}

async fn close_inner(inner: &ControllerInner) {
    if let Some(session) = inner.finish_closed() {
        let _ = session.close().await;
    }
}

fn connect_disposition(error: ConnectError) -> RetryDisposition {
    if error.controller_retryable() {
        RetryDisposition::Retryable
    } else {
        RetryDisposition::Terminal
    }
}

fn session_disposition(error: SessionError) -> RetryDisposition {
    match error {
        SessionError::Canceled | SessionError::StreamRejected | SessionError::OperationFailed => {
            RetryDisposition::Terminal
        }
        SessionError::Timeout
        | SessionError::Closed
        | SessionError::GoingAway
        | SessionError::ResourceExhausted
        | SessionError::StreamReset
        | SessionError::RekeyFailed
        | SessionError::LivenessFailed => RetryDisposition::Retryable,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct ControllerVectors {
        version: u64,
        states: Vec<String>,
        retry_dispositions: Vec<String>,
        defaults: ControllerDefaults,
        backoff_vectors: Vec<ControllerBackoffVector>,
        scenarios: Vec<ControllerScenario>,
        invariants: ControllerInvariants,
    }

    #[derive(Debug, Deserialize)]
    struct ControllerDefaults {
        initial_delay_ms: u64,
        max_delay_ms: u64,
        factor: u32,
        jitter_ratio: u64,
        attempt_limit: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    struct ControllerBackoffVector {
        consecutive_failure: u64,
        delay_ms: u64,
    }

    #[derive(Debug, Deserialize)]
    struct ControllerInvariants {
        one_shot_artifact_controller: String,
        fresh_artifact_per_attempt: bool,
        single_scheduler: bool,
        single_in_flight_attempt: bool,
        retry_now_outside_waiting: bool,
        old_stream_migration: bool,
        rpc_replay: bool,
        write_replay: bool,
        cross_session_exactly_once: bool,
    }

    #[derive(Debug, Deserialize)]
    struct ControllerScenarioPolicy {
        max_attempts: u64,
    }

    #[derive(Debug, Deserialize)]
    struct ControllerScenario {
        name: String,
        events: Vec<String>,
        states: Vec<String>,
        #[serde(default)]
        sessions: Vec<String>,
        #[serde(default)]
        replay: Vec<String>,
        #[serde(default)]
        clock_start_unix_ms: Option<u64>,
        #[serde(default)]
        artifact_acquisitions: Option<u64>,
        #[serde(default)]
        scheduler_count: Option<u64>,
        #[serde(default)]
        max_in_flight_attempts: Option<u64>,
        #[serde(default)]
        retry_at_unix_ms: Option<u64>,
        #[serde(default)]
        policy: Option<ControllerScenarioPolicy>,
    }

    fn scenario(name: &str) -> ControllerScenario {
        serde_json::from_str::<ControllerVectors>(include_str!(
            "../../testdata/transport_v2/connection_controller_vectors.json"
        ))
        .expect("parse shared connection-controller vectors")
        .scenarios
        .into_iter()
        .find(|scenario| scenario.name == name)
        .unwrap_or_else(|| panic!("missing controller scenario {name}"))
    }

    #[derive(Debug)]
    struct PendingSource {
        future_dropped: Arc<AtomicBool>,
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ArtifactSource for PendingSource {
        async fn acquire(
            &self,
            _cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceError> {
            let _drop_signal = DropSignal(self.future_dropped.clone());
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct FailingSource {
        attempts: AtomicU64,
        error: ArtifactSourceError,
    }

    #[derive(Debug)]
    struct RetryThenPendingSource {
        attempts: AtomicU64,
        pending_future_dropped: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ArtifactSource for RetryThenPendingSource {
        async fn acquire(
            &self,
            _cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceError> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(ArtifactSourceError::retryable());
            }
            let _drop_signal = DropSignal(self.pending_future_dropped.clone());
            std::future::pending().await
        }
    }

    #[async_trait]
    impl ArtifactSource for FailingSource {
        async fn acquire(
            &self,
            _cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(self.error)
        }
    }

    fn options(retry: RetryPolicy) -> ConnectionControllerOptions {
        let connector = ConnectorOptions::new(vec![vec![1]]).expect("valid test trust root");
        ConnectionControllerOptions::new(connector).with_retry_policy(retry)
    }

    async fn wait_for_state(
        controller: &ConnectionController,
        expected: ConnectionState,
    ) -> ConnectionStatus {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let status = controller.status();
                if status.state == expected {
                    return status;
                }
                let _ = controller.wait_for_status_change(status.revision).await;
            }
        })
        .await
        .expect("controller reaches expected state")
    }

    #[test]
    fn retry_policy_is_bounded_without_compatibility_defaults() {
        let retry = RetryPolicy::new(Duration::from_millis(2), 3, Duration::from_millis(10))
            .expect("valid retry policy");
        assert_eq!(retry.delay(0), Duration::from_millis(2));
        assert_eq!(retry.delay(1), Duration::from_millis(6));
        assert_eq!(retry.delay(2), Duration::from_millis(10));
        assert_eq!(retry.delay(u64::MAX), Duration::from_millis(10));
        assert!(RetryPolicy::new(Duration::ZERO, 2, Duration::from_secs(1)).is_err());
        assert!(RetryPolicy::new(Duration::from_secs(1), 0, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn shared_controller_defaults_backoff_and_invariants_match_the_implementation() {
        let vectors = serde_json::from_str::<ControllerVectors>(include_str!(
            "../../testdata/transport_v2/connection_controller_vectors.json"
        ))
        .expect("parse shared connection-controller vectors");
        assert_eq!(vectors.version, 1);
        assert_eq!(
            vectors.states,
            [
                "idle",
                "connecting",
                "connected",
                "waiting",
                "failed",
                "closed"
            ]
        );
        assert_eq!(
            vectors.retry_dispositions,
            ["terminal", "retryable", "retry_after"]
        );
        let retry = RetryPolicy::default();
        assert_eq!(
            retry.initial_delay(),
            Duration::from_millis(vectors.defaults.initial_delay_ms)
        );
        assert_eq!(
            retry.max_delay(),
            Duration::from_millis(vectors.defaults.max_delay_ms)
        );
        assert_eq!(retry.factor(), vectors.defaults.factor);
        assert_eq!(vectors.defaults.jitter_ratio, 0);
        assert_eq!(
            retry.max_attempts().map(NonZeroU64::get),
            vectors.defaults.attempt_limit
        );
        for vector in vectors.backoff_vectors {
            assert_eq!(
                retry.delay(vector.consecutive_failure - 1),
                Duration::from_millis(vector.delay_ms)
            );
        }
        let invariants = vectors.invariants;
        assert_eq!(invariants.one_shot_artifact_controller, "forbidden");
        assert!(invariants.fresh_artifact_per_attempt);
        assert!(invariants.single_scheduler);
        assert!(invariants.single_in_flight_attempt);
        assert!(!invariants.retry_now_outside_waiting);
        assert!(!invariants.old_stream_migration);
        assert!(!invariants.rpc_replay);
        assert!(!invariants.write_replay);
        assert!(!invariants.cross_session_exactly_once);
    }

    #[tokio::test]
    async fn close_cancels_the_owned_artifact_acquisition() {
        let scenario = scenario("close_cancels_single_attempt");
        assert_eq!(scenario.max_in_flight_attempts, Some(1));
        assert_eq!(scenario.states, ["idle", "connecting", "closed"]);
        let future_dropped = Arc::new(AtomicBool::new(false));
        let controller = ConnectionController::new(
            Arc::new(PendingSource {
                future_dropped: future_dropped.clone(),
            }),
            options(RetryPolicy::default()),
        );
        controller.start().expect("controller starts");
        wait_for_state(&controller, ConnectionState::Connecting).await;

        controller.close().await;

        assert_eq!(controller.status().state, ConnectionState::Closed);
        assert!(future_dropped.load(Ordering::SeqCst));
        assert!(controller.current_session().is_none());
        assert!(!controller.retry_now());
    }

    #[tokio::test]
    async fn structured_retryable_source_failure_obeys_attempt_limit() {
        let scenario = scenario("explicit_attempt_exhaustion");
        assert_eq!(scenario.artifact_acquisitions, Some(2));
        let source = Arc::new(FailingSource {
            attempts: AtomicU64::new(0),
            error: ArtifactSourceError::retryable(),
        });
        let retry = RetryPolicy::new(Duration::from_millis(1), 1, Duration::from_millis(1))
            .expect("valid retry policy")
            .with_max_attempts(NonZeroU64::new(2).expect("nonzero"));
        let controller = ConnectionController::new(source.clone(), options(retry));
        controller.start().expect("controller starts");

        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(status.attempt, 2);
        assert_eq!(source.attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            status.last_failure,
            Some(ConnectionFailure::ArtifactSource(
                ArtifactSourceError::retryable()
            ))
        );
        assert_eq!(
            status.last_failure.map(ConnectionFailure::disposition),
            Some(RetryDisposition::Retryable)
        );

        controller.close().await;
    }

    #[tokio::test]
    async fn terminal_source_failure_stops_after_one_attempt() {
        let scenario = scenario("terminal_failure");
        assert_eq!(scenario.artifact_acquisitions, Some(1));
        let source = Arc::new(FailingSource {
            attempts: AtomicU64::new(0),
            error: ArtifactSourceError::terminal(),
        });
        let controller = ConnectionController::new(source.clone(), options(RetryPolicy::default()));
        controller.start().expect("controller starts");

        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(status.attempt, 1);
        assert_eq!(source.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            status.last_failure,
            Some(ConnectionFailure::ArtifactSource(
                ArtifactSourceError::terminal()
            ))
        );
        controller.close().await;
    }

    #[tokio::test]
    async fn retry_now_wakes_only_the_existing_scheduler_and_attempt() {
        let scenario = scenario("retry_now_wakes_existing_wait");
        assert_eq!(scenario.scheduler_count, Some(1));
        assert_eq!(scenario.max_in_flight_attempts, Some(1));
        let pending_future_dropped = Arc::new(AtomicBool::new(false));
        let source = Arc::new(RetryThenPendingSource {
            attempts: AtomicU64::new(0),
            pending_future_dropped: pending_future_dropped.clone(),
        });
        let retry = RetryPolicy::new(Duration::from_secs(30), 1, Duration::from_secs(30))
            .expect("valid retry policy");
        let controller = ConnectionController::new(source.clone(), options(retry));
        controller.start().expect("controller starts");
        wait_for_state(&controller, ConnectionState::Waiting).await;

        assert!(controller.retry_now());
        tokio::time::timeout(Duration::from_secs(1), async {
            while source.attempts.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("existing scheduler starts the second attempt");
        assert_eq!(controller.status().state, ConnectionState::Connecting);
        assert_eq!(source.attempts.load(Ordering::SeqCst), 2);
        assert!(!controller.retry_now());

        controller.close().await;
        assert!(pending_future_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn retry_now_cannot_bypass_retry_after() {
        let scenario = scenario("retry_after_is_authoritative");
        assert_eq!(scenario.retry_at_unix_ms, Some(1_004_000));
        let source = Arc::new(FailingSource {
            attempts: AtomicU64::new(0),
            error: ArtifactSourceError::retry_after(SystemTime::now() + Duration::from_millis(200)),
        });
        let retry = RetryPolicy::new(Duration::from_millis(1), 1, Duration::from_millis(1))
            .expect("valid retry policy");
        let controller = ConnectionController::new(source.clone(), options(retry));
        controller.start().expect("controller starts");
        wait_for_state(&controller, ConnectionState::Waiting).await;

        assert!(controller.retry_now());
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(source.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(controller.status().state, ConnectionState::Waiting);
        controller.close().await;
    }

    #[test]
    fn shared_controller_vector_inventory_has_one_owning_test_per_scenario() {
        let vectors = serde_json::from_str::<ControllerVectors>(include_str!(
            "../../testdata/transport_v2/connection_controller_vectors.json"
        ))
        .expect("parse shared connection-controller vectors");
        for scenario in &vectors.scenarios {
            assert!(
                !scenario.events.is_empty(),
                "{} has no executable events",
                scenario.name
            );
            match scenario.name.as_str() {
                "connect_and_replace_after_termination" => {
                    assert_eq!(scenario.sessions, ["session-1", "session-2"]);
                    assert!(scenario.replay.is_empty());
                }
                "retry_after_is_authoritative" => {
                    assert_eq!(scenario.clock_start_unix_ms, Some(1_000_000));
                    assert_eq!(scenario.retry_at_unix_ms, Some(1_004_000));
                }
                "explicit_attempt_exhaustion" => {
                    assert_eq!(
                        scenario.policy.as_ref().map(|policy| policy.max_attempts),
                        Some(2)
                    );
                }
                _ => {}
            }
        }
        let mut names = vectors
            .scenarios
            .into_iter()
            .map(|scenario| scenario.name)
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [
                "close_cancels_single_attempt",
                "connect_and_replace_after_termination",
                "explicit_attempt_exhaustion",
                "retry_after_is_authoritative",
                "retry_now_wakes_existing_wait",
                "terminal_failure",
            ]
        );
    }
}
