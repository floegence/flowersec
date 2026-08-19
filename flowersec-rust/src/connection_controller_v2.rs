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
    ConnectError, ConnectErrorCode, ConnectorOptions, SessionError, artifact_v2::ArtifactLease,
    native_runtime_v2::connect_with_cancellation, transport_v2::Session,
};

const DEFAULT_INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_RETRY_FACTOR: u32 = 2;
const DEFAULT_MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// A structured retry decision. No decision is inferred from error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDispositionV2 {
    Terminal,
    Retryable,
    RetryAfter(SystemTime),
}

/// A redacted artifact acquisition failure with an explicit retry decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec artifact acquisition failed")]
pub struct ArtifactSourceErrorV2 {
    disposition: RetryDispositionV2,
}

impl ArtifactSourceErrorV2 {
    /// Creates a terminal failure. Sources should use this for unknown errors.
    pub const fn terminal() -> Self {
        Self {
            disposition: RetryDispositionV2::Terminal,
        }
    }

    /// Creates a retryable failure governed by the controller's backoff policy.
    pub const fn retryable() -> Self {
        Self {
            disposition: RetryDispositionV2::Retryable,
        }
    }

    /// Creates a retryable failure that cannot run before `not_before`.
    pub const fn retry_after(not_before: SystemTime) -> Self {
        Self {
            disposition: RetryDispositionV2::RetryAfter(not_before),
        }
    }

    pub const fn disposition(self) -> RetryDispositionV2 {
        self.disposition
    }
}

/// Supplies one fresh, independently spendable artifact lease per attempt.
///
/// The controller races acquisition against cancellation, so dropping the
/// acquisition future must release all source-owned resources.
#[async_trait]
pub trait ArtifactSourceV2: fmt::Debug + Send + Sync + 'static {
    async fn acquire(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ArtifactLease, ArtifactSourceErrorV2>;
}

/// Complete native connector configuration and the only portable retry limit.
#[derive(Clone, Debug)]
pub struct ConnectionControllerOptionsV2 {
    connector: ConnectorOptions,
    maximum_attempts: Option<NonZeroU64>,
}

impl ConnectionControllerOptionsV2 {
    pub fn new(connector: ConnectorOptions) -> Self {
        Self {
            connector,
            maximum_attempts: None,
        }
    }

    pub const fn with_maximum_attempts(mut self, maximum_attempts: NonZeroU64) -> Self {
        self.maximum_attempts = Some(maximum_attempts);
        self
    }

    pub const fn maximum_attempts(&self) -> Option<NonZeroU64> {
        self.maximum_attempts
    }
}

/// Observable long-lived connection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionStateV2 {
    Idle,
    Connecting,
    Connected,
    Waiting,
    Failed,
    Closed,
}

/// The bounded owning boundary for the most recent connection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionFailureV2 {
    ArtifactSourceV2(ArtifactSourceErrorV2),
    Connect {
        code: ConnectErrorCode,
        disposition: RetryDispositionV2,
    },
    Session {
        error: SessionError,
        disposition: RetryDispositionV2,
    },
}

impl ConnectionFailureV2 {
    pub const fn disposition(self) -> RetryDispositionV2 {
        match self {
            Self::ArtifactSourceV2(error) => error.disposition(),
            Self::Connect { disposition, .. } | Self::Session { disposition, .. } => disposition,
        }
    }
}

/// An immutable controller snapshot over the portable lifecycle fields.
#[derive(Clone, Debug)]
pub struct ConnectionSnapshotV2 {
    pub state: ConnectionStateV2,
    pub attempt: u64,
    pub current_session: Option<Arc<dyn Session>>,
    pub failure: Option<ConnectionFailureV2>,
    revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerStatus {
    pub(crate) state: ConnectionStateV2,
    pub(crate) attempt: u64,
    pub(crate) next_retry_at: Option<SystemTime>,
    pub(crate) retry_not_before: Option<SystemTime>,
    pub(crate) last_failure: Option<ConnectionFailureV2>,
    pub(crate) revision: u64,
}

struct ControllerState {
    status: ControllerStatus,
    current: Option<Arc<dyn Session>>,
}

struct ControllerInner {
    source: Arc<dyn ArtifactSourceV2>,
    options: ConnectionControllerOptionsV2,
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
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

/// The sole owner of refresh, retry, and current-session replacement.
pub struct ConnectionControllerV2 {
    inner: Arc<ControllerInner>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for ConnectionControllerV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionControllerV2")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl ConnectionControllerV2 {
    pub fn new(source: Arc<dyn ArtifactSourceV2>, options: ConnectionControllerOptionsV2) -> Self {
        Self {
            inner: Arc::new(ControllerInner {
                source,
                options,
                cancellation: CancellationToken::new(),
                retry_wake: Notify::new(),
                retry_revision: AtomicU64::new(0),
                changed: Notify::new(),
                state: Mutex::new(ControllerState {
                    status: ControllerStatus {
                        state: ConnectionStateV2::Idle,
                        attempt: 0,
                        next_retry_at: None,
                        retry_not_before: None,
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
    pub fn start(&self) {
        let runtime = tokio::runtime::Handle::current();
        let mut task = lock(&self.task);
        if task.is_some() || self.inner.status().state == ConnectionStateV2::Closed {
            return;
        }
        *task = Some(runtime.spawn(run_controller(self.inner.clone())));
    }

    pub fn snapshot(&self) -> ConnectionSnapshotV2 {
        self.inner.snapshot()
    }

    /// Waits until the controller publishes a newer snapshot.
    ///
    /// Dropping the returned future cancels only this wait. Closing the
    /// controller publishes a closed snapshot and wakes every waiter.
    pub async fn wait_for_snapshot_change(
        &self,
        after: &ConnectionSnapshotV2,
    ) -> ConnectionSnapshotV2 {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.inner.status();
            if status.revision != after.revision {
                return self.inner.snapshot();
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn status(&self) -> ControllerStatus {
        self.inner.status()
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_status_change(&self, revision: u64) -> ControllerStatus {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.inner.status();
            if status.revision != revision {
                return status;
            }
            changed.await;
        }
    }

    /// Returns the current established session. A terminated session is
    /// removed before retry begins, and a replacement is published only after
    /// it has fully established.
    pub fn current_session(&self) -> Option<Arc<dyn Session>> {
        lock(&self.inner.state).current.clone()
    }

    /// Wakes the sole scheduler only while it is waiting. A server-supplied
    /// retry-after deadline remains authoritative.
    pub fn retry_now(&self) -> bool {
        let revision = {
            let state = lock(&self.inner.state);
            if state.status.state != ConnectionStateV2::Waiting
                || state
                    .status
                    .retry_not_before
                    .is_some_and(|deadline| SystemTime::now() < deadline)
            {
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
            ignore_subordinate_close_result(session.close().await);
        }
        let task = lock(&self.task).take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for ConnectionControllerV2 {
    fn drop(&mut self) {
        self.inner.cancellation.cancel();
        self.inner.retry_wake.notify_waiters();
    }
}

impl ControllerInner {
    fn status(&self) -> ControllerStatus {
        lock(&self.state).status
    }

    fn snapshot(&self) -> ConnectionSnapshotV2 {
        let state = lock(&self.state);
        ConnectionSnapshotV2 {
            state: state.status.state,
            attempt: state.status.attempt,
            current_session: state.current.clone(),
            failure: state.status.last_failure,
            revision: state.status.revision,
        }
    }

    fn set_connecting(&self, attempt: u64) -> bool {
        self.update(|state| {
            state.status.state = ConnectionStateV2::Connecting;
            state.status.attempt = attempt;
            state.status.next_retry_at = None;
            state.status.retry_not_before = None;
            state.status.last_failure = None;
        })
    }

    fn set_connected(&self, attempt: u64, session: Arc<dyn Session>) -> bool {
        self.update(|state| {
            state.current = Some(session);
            state.status.state = ConnectionStateV2::Connected;
            state.status.attempt = attempt;
            state.status.next_retry_at = None;
            state.status.retry_not_before = None;
            state.status.last_failure = None;
        })
    }

    fn set_waiting(
        &self,
        attempt: u64,
        next_retry_at: SystemTime,
        retry_not_before: Option<SystemTime>,
        failure: ConnectionFailureV2,
        clear_current: bool,
    ) -> Option<u64> {
        if !self.update(|state| {
            if clear_current {
                state.current = None;
            }
            state.status.state = ConnectionStateV2::Waiting;
            state.status.attempt = attempt;
            state.status.next_retry_at = Some(next_retry_at);
            state.status.retry_not_before = retry_not_before;
            state.status.last_failure = Some(failure);
        }) {
            return None;
        }
        Some(self.status().revision)
    }

    fn set_failed(&self, attempt: u64, failure: ConnectionFailureV2, clear_current: bool) -> bool {
        self.update(|state| {
            if clear_current {
                state.current = None;
            }
            state.status.state = ConnectionStateV2::Failed;
            state.status.attempt = attempt;
            state.status.next_retry_at = None;
            state.status.retry_not_before = None;
            state.status.last_failure = Some(failure);
        })
    }

    fn update(&self, update: impl FnOnce(&mut ControllerState)) -> bool {
        {
            let mut state = lock(&self.state);
            if state.status.state == ConnectionStateV2::Closed {
                return false;
            }
            update(&mut state);
            state.status.revision = state.status.revision.saturating_add(1);
        }
        self.changed.notify_waiters();
        true
    }

    fn finish_closed(&self) -> Option<Arc<dyn Session>> {
        let current = {
            let mut state = lock(&self.state);
            if state.status.state == ConnectionStateV2::Closed {
                return None;
            }
            state.status.state = ConnectionStateV2::Closed;
            state.status.next_retry_at = None;
            state.status.retry_not_before = None;
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
                    let failure = ConnectionFailureV2::ArtifactSourceV2(error);
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

        let result = connect_with_cancellation(
            lease,
            inner.options.connector.clone(),
            inner.cancellation.child_token(),
        )
        .await;
        if inner.cancellation.is_cancelled() {
            if let Ok(session) = result {
                ignore_subordinate_close_result(session.close().await);
            }
            close_inner(&inner).await;
            return;
        }
        let session = match result {
            Ok(session) => session,
            Err(error) => {
                let disposition = connect_disposition(error);
                let failure = ConnectionFailureV2::Connect {
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
            ignore_subordinate_close_result(session.close().await);
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
        let failure = ConnectionFailureV2::Session {
            error: termination.error,
            disposition: session_disposition(termination.error),
        };
        // A terminated session is never reused or migrated into its replacement.
        // Close it before entering retry scheduling so every controller-owned
        // carrier is retired before a fresh artifact can establish a session.
        ignore_subordinate_close_result(session.close().await);
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
    failure: ConnectionFailureV2,
) -> bool {
    let disposition = failure.disposition();
    let clear_current = matches!(failure, ConnectionFailureV2::Session { .. });
    if disposition == RetryDispositionV2::Terminal
        || inner
            .options
            .maximum_attempts
            .is_some_and(|maximum| attempts_in_cycle >= maximum.get())
    {
        inner.set_failed(status_attempt, failure, clear_current);
        return false;
    }
    let now = SystemTime::now();
    let backoff_at = now + retry_delay(retry_index);
    let not_before = match disposition {
        RetryDispositionV2::RetryAfter(deadline) => Some(deadline),
        RetryDispositionV2::Terminal | RetryDispositionV2::Retryable => None,
    };
    let next_retry_at = not_before.map_or(backoff_at, |deadline| deadline.max(backoff_at));
    let Some(waiting_revision) = inner.set_waiting(
        status_attempt,
        next_retry_at,
        not_before,
        failure,
        clear_current,
    ) else {
        return false;
    };
    wait_for_retry(inner, next_retry_at, not_before, waiting_revision).await
}

fn retry_delay(retry_index: u64) -> Duration {
    let mut delay = DEFAULT_INITIAL_RETRY_DELAY;
    for _ in 0..retry_index {
        delay = delay
            .saturating_mul(DEFAULT_RETRY_FACTOR)
            .min(DEFAULT_MAX_RETRY_DELAY);
        if delay == DEFAULT_MAX_RETRY_DELAY {
            break;
        }
    }
    delay
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
        tokio::pin!(notified);
        notified.as_mut().enable();
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
        ignore_subordinate_close_result(session.close().await);
    }
}

fn ignore_subordinate_close_result(_result: Result<(), SessionError>) {}

fn connect_disposition(error: ConnectError) -> RetryDispositionV2 {
    if error.controller_retryable() {
        RetryDispositionV2::Retryable
    } else {
        RetryDispositionV2::Terminal
    }
}

fn session_disposition(error: SessionError) -> RetryDispositionV2 {
    match error {
        SessionError::Canceled | SessionError::StreamRejected | SessionError::OperationFailed => {
            RetryDispositionV2::Terminal
        }
        SessionError::Timeout
        | SessionError::Closed
        | SessionError::GoingAway
        | SessionError::ResourceExhausted
        | SessionError::StreamReset
        | SessionError::RekeyFailed
        | SessionError::LivenessFailed => RetryDispositionV2::Retryable,
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
        start_idempotent: bool,
        close_idempotent: bool,
        retry_now_outside_waiting: bool,
        retry_after_bypass: bool,
        subordinate_close_failure_propagates: bool,
        public_retry_configuration: Vec<String>,
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
        retry_now_results: Vec<bool>,
        #[serde(default)]
        close_calls: Option<u64>,
        #[serde(default)]
        cleanup_calls: Option<u64>,
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
        attempts: Arc<AtomicU64>,
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ArtifactSourceV2 for PendingSource {
        async fn acquire(
            &self,
            _cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceErrorV2> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let _drop_signal = DropSignal(self.future_dropped.clone());
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct FailingSource {
        attempts: AtomicU64,
        error: ArtifactSourceErrorV2,
    }

    #[derive(Debug)]
    struct RetryThenPendingSource {
        attempts: AtomicU64,
        pending_future_dropped: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ArtifactSourceV2 for RetryThenPendingSource {
        async fn acquire(
            &self,
            _cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceErrorV2> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(ArtifactSourceErrorV2::retryable());
            }
            let _drop_signal = DropSignal(self.pending_future_dropped.clone());
            std::future::pending().await
        }
    }

    #[async_trait]
    impl ArtifactSourceV2 for FailingSource {
        async fn acquire(
            &self,
            _cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceErrorV2> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(self.error)
        }
    }

    fn options() -> ConnectionControllerOptionsV2 {
        let connector = ConnectorOptions::new();
        ConnectionControllerOptionsV2::new(connector)
    }

    async fn wait_for_state(
        controller: &ConnectionControllerV2,
        expected: ConnectionStateV2,
    ) -> ControllerStatus {
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

    #[tokio::test]
    async fn public_snapshot_wait_returns_on_change_and_for_stale_snapshot() {
        let controller = ConnectionControllerV2::new(
            Arc::new(PendingSource {
                future_dropped: Arc::new(AtomicBool::new(false)),
                attempts: Arc::new(AtomicU64::new(0)),
            }),
            options(),
        );
        let idle = controller.snapshot();
        controller.start();

        let connecting = tokio::time::timeout(
            Duration::from_secs(1),
            controller.wait_for_snapshot_change(&idle),
        )
        .await
        .expect("snapshot waiter observes connecting");
        assert_eq!(connecting.state, ConnectionStateV2::Connecting);

        let stale = tokio::time::timeout(
            Duration::from_millis(50),
            controller.wait_for_snapshot_change(&idle),
        )
        .await
        .expect("stale snapshot returns immediately");
        assert_eq!(stale.state, ConnectionStateV2::Connecting);
        controller.close().await;
    }

    #[tokio::test]
    async fn close_wakes_all_public_snapshot_waiters() {
        let controller = Arc::new(ConnectionControllerV2::new(
            Arc::new(PendingSource {
                future_dropped: Arc::new(AtomicBool::new(false)),
                attempts: Arc::new(AtomicU64::new(0)),
            }),
            options(),
        ));
        let idle = controller.snapshot();
        let first = {
            let controller = controller.clone();
            let idle = idle.clone();
            tokio::spawn(async move { controller.wait_for_snapshot_change(&idle).await })
        };
        let second = {
            let controller = controller.clone();
            let idle = idle.clone();
            tokio::spawn(async move { controller.wait_for_snapshot_change(&idle).await })
        };
        tokio::task::yield_now().await;
        controller.close().await;

        for waiter in [first, second] {
            let snapshot = tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("close wakes waiter")
                .expect("waiter task succeeds");
            assert_eq!(snapshot.state, ConnectionStateV2::Closed);
        }
    }

    #[tokio::test]
    async fn dropping_snapshot_wait_does_not_change_controller_ownership() {
        let attempts = Arc::new(AtomicU64::new(0));
        let controller = ConnectionControllerV2::new(
            Arc::new(PendingSource {
                future_dropped: Arc::new(AtomicBool::new(false)),
                attempts: attempts.clone(),
            }),
            options(),
        );
        let snapshot = controller.snapshot();
        let wait = controller.wait_for_snapshot_change(&snapshot);
        drop(wait);
        controller.start();
        wait_for_state(&controller, ConnectionStateV2::Connecting).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        controller.close().await;
    }

    #[test]
    fn retry_backoff_is_fixed_by_the_portable_contract() {
        assert_eq!(retry_delay(0), Duration::from_millis(250));
        assert_eq!(retry_delay(1), Duration::from_millis(500));
        assert_eq!(retry_delay(2), Duration::from_secs(1));
        assert_eq!(retry_delay(u64::MAX), Duration::from_secs(30));
    }

    #[test]
    fn shared_controller_defaults_backoff_and_invariants_match_the_implementation() {
        let vectors = serde_json::from_str::<ControllerVectors>(include_str!(
            "../../testdata/transport_v2/connection_controller_vectors.json"
        ))
        .expect("parse shared connection-controller vectors");
        assert_eq!(vectors.version, 2);
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
        assert_eq!(
            DEFAULT_INITIAL_RETRY_DELAY,
            Duration::from_millis(vectors.defaults.initial_delay_ms)
        );
        assert_eq!(
            DEFAULT_MAX_RETRY_DELAY,
            Duration::from_millis(vectors.defaults.max_delay_ms)
        );
        assert_eq!(DEFAULT_RETRY_FACTOR, vectors.defaults.factor);
        assert_eq!(vectors.defaults.jitter_ratio, 0);
        assert_eq!(vectors.defaults.attempt_limit, None);
        for vector in vectors.backoff_vectors {
            assert_eq!(
                retry_delay(vector.consecutive_failure - 1),
                Duration::from_millis(vector.delay_ms)
            );
        }
        let invariants = vectors.invariants;
        assert_eq!(invariants.one_shot_artifact_controller, "forbidden");
        assert!(invariants.fresh_artifact_per_attempt);
        assert!(invariants.single_scheduler);
        assert!(invariants.single_in_flight_attempt);
        assert!(invariants.start_idempotent);
        assert!(invariants.close_idempotent);
        assert!(!invariants.retry_now_outside_waiting);
        assert!(!invariants.retry_after_bypass);
        assert!(!invariants.subordinate_close_failure_propagates);
        assert_eq!(invariants.public_retry_configuration, ["maximum_attempts"]);
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
        let attempts = Arc::new(AtomicU64::new(0));
        let controller = ConnectionControllerV2::new(
            Arc::new(PendingSource {
                future_dropped: future_dropped.clone(),
                attempts,
            }),
            options(),
        );
        controller.start();
        wait_for_state(&controller, ConnectionStateV2::Connecting).await;

        controller.close().await;

        assert_eq!(controller.status().state, ConnectionStateV2::Closed);
        assert!(future_dropped.load(Ordering::SeqCst));
        assert!(controller.current_session().is_none());
        assert!(!controller.retry_now());
    }

    #[tokio::test]
    async fn repeated_start_and_close_are_idempotent() {
        let start_scenario = scenario("repeated_start_is_idempotent");
        let close_scenario = scenario("repeated_close_is_idempotent");
        let future_dropped = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicU64::new(0));
        let controller = ConnectionControllerV2::new(
            Arc::new(PendingSource {
                future_dropped: future_dropped.clone(),
                attempts: attempts.clone(),
            }),
            options(),
        );
        controller.start();
        controller.start();
        wait_for_state(&controller, ConnectionStateV2::Connecting).await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            start_scenario.max_in_flight_attempts.unwrap()
        );
        controller.close().await;
        controller.close().await;
        assert_eq!(close_scenario.close_calls, Some(2));
        assert!(future_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn start_after_close_stays_closed_and_retry_now_is_state_bounded() {
        let close_scenario = scenario("start_after_close_stays_closed");
        let retry_scenario = scenario("retry_now_outside_waiting_returns_false");
        let attempts = Arc::new(AtomicU64::new(0));
        let controller = ConnectionControllerV2::new(
            Arc::new(PendingSource {
                future_dropped: Arc::new(AtomicBool::new(false)),
                attempts: attempts.clone(),
            }),
            options(),
        );
        assert!(!controller.retry_now());
        controller.close().await;
        controller.start();
        assert_eq!(controller.snapshot().state, ConnectionStateV2::Closed);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            close_scenario.artifact_acquisitions.unwrap()
        );
        assert_eq!(retry_scenario.retry_now_results, [false, false, false]);
        assert!(!controller.retry_now());
    }

    #[test]
    fn subordinate_close_failure_does_not_escape_controller_cleanup() {
        let scenario = scenario("subordinate_close_failure_is_ignored");
        ignore_subordinate_close_result(Err(SessionError::OperationFailed));
        assert_eq!(scenario.cleanup_calls, Some(1));
    }

    #[tokio::test]
    async fn structured_retryable_source_failure_obeys_attempt_limit() {
        let scenario = scenario("explicit_attempt_exhaustion");
        assert_eq!(scenario.artifact_acquisitions, Some(2));
        let source = Arc::new(FailingSource {
            attempts: AtomicU64::new(0),
            error: ArtifactSourceErrorV2::retryable(),
        });
        let options = options().with_maximum_attempts(NonZeroU64::new(2).expect("nonzero"));
        let controller = ConnectionControllerV2::new(source.clone(), options);
        controller.start();

        let status = wait_for_state(&controller, ConnectionStateV2::Failed).await;
        assert_eq!(status.attempt, 2);
        assert_eq!(source.attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            status.last_failure,
            Some(ConnectionFailureV2::ArtifactSourceV2(
                ArtifactSourceErrorV2::retryable()
            ))
        );
        assert_eq!(
            status.last_failure.map(ConnectionFailureV2::disposition),
            Some(RetryDispositionV2::Retryable)
        );

        controller.close().await;
    }

    #[tokio::test]
    async fn terminal_source_failure_stops_after_one_attempt() {
        let scenario = scenario("terminal_failure");
        assert_eq!(scenario.artifact_acquisitions, Some(1));
        let source = Arc::new(FailingSource {
            attempts: AtomicU64::new(0),
            error: ArtifactSourceErrorV2::terminal(),
        });
        let controller = ConnectionControllerV2::new(source.clone(), options());
        controller.start();

        let status = wait_for_state(&controller, ConnectionStateV2::Failed).await;
        assert_eq!(status.attempt, 1);
        assert_eq!(source.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            status.last_failure,
            Some(ConnectionFailureV2::ArtifactSourceV2(
                ArtifactSourceErrorV2::terminal()
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
        let controller = ConnectionControllerV2::new(source.clone(), options());
        controller.start();
        wait_for_state(&controller, ConnectionStateV2::Waiting).await;

        assert!(controller.retry_now());
        tokio::time::timeout(Duration::from_secs(1), async {
            while source.attempts.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("existing scheduler starts the second attempt");
        assert_eq!(controller.status().state, ConnectionStateV2::Connecting);
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
            error: ArtifactSourceErrorV2::retry_after(
                SystemTime::now() + Duration::from_millis(200),
            ),
        });
        let controller = ConnectionControllerV2::new(source.clone(), options());
        controller.start();
        wait_for_state(&controller, ConnectionStateV2::Waiting).await;

        assert!(!controller.retry_now());
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(source.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(controller.status().state, ConnectionStateV2::Waiting);
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
                "close_waits_for_owned_cleanup",
                "connect_and_replace_after_termination",
                "explicit_attempt_exhaustion",
                "repeated_close_is_idempotent",
                "repeated_start_is_idempotent",
                "retry_after_is_authoritative",
                "retry_now_outside_waiting_returns_false",
                "retry_now_wakes_existing_wait",
                "start_after_close_stays_closed",
                "subordinate_close_failure_is_ignored",
                "terminal_failure",
            ]
        );
    }
}
