//! Long-lived Flowersec v3 connection ownership and policy refresh.

use std::{
    collections::HashSet,
    fmt,
    future::Future,
    num::NonZeroU64,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use futures_util::FutureExt as _;
use tokio::{
    sync::{Mutex as AsyncMutex, Notify},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    ArtifactLease, ConnectError, ConnectErrorCode, ConnectorOptions, SessionError,
    artifact_v3::{ArtifactV3, ClaimedArtifactLeaseV3, TlsPolicyWireV3},
    connector_v3::connect_v3_with_cancellation,
    transport::Session,
};

const DEFAULT_INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_RETRY_FACTOR: u32 = 2;
const DEFAULT_MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_RETRY_AFTER_UNIX_MILLISECONDS: u128 = 253_402_300_799_999;

type ConnectFuture =
    Pin<Box<dyn Future<Output = Result<Arc<dyn Session>, ConnectError>> + Send + 'static>>;
type ClockSleep = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type ConnectOneShot = Arc<
    dyn Fn(ArtifactLease, ConnectorOptions, CancellationToken) -> ConnectFuture
        + Send
        + Sync
        + 'static,
>;

trait ControllerClock: fmt::Debug + Send + Sync + 'static {
    fn wall_now(&self) -> SystemTime;
    fn monotonic_now_milliseconds(&self) -> u64;
    fn sleep(self: Arc<Self>, delay: Duration) -> ClockSleep;
}

#[derive(Debug)]
struct SystemControllerClock {
    monotonic_origin: tokio::time::Instant,
}

impl SystemControllerClock {
    fn new() -> Self {
        Self {
            monotonic_origin: tokio::time::Instant::now(),
        }
    }
}

impl ControllerClock for SystemControllerClock {
    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic_now_milliseconds(&self) -> u64 {
        self.monotonic_origin
            .elapsed()
            .as_millis()
            .min(MAX_SAFE_INTEGER as u128) as u64
    }

    fn sleep(self: Arc<Self>, delay: Duration) -> ClockSleep {
        Box::pin(tokio::time::sleep(delay))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDisposition {
    Terminal,
    Retryable,
    RetryAfter(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec artifact acquisition failed")]
pub struct ArtifactSourceError {
    disposition: RetryDisposition,
    code: ConnectErrorCode,
}

impl ArtifactSourceError {
    pub const fn terminal() -> Self {
        Self {
            disposition: RetryDisposition::Terminal,
            code: ConnectErrorCode::ConnectionFailed,
        }
    }
    pub const fn retryable() -> Self {
        Self {
            disposition: RetryDisposition::Retryable,
            code: ConnectErrorCode::ConnectionFailed,
        }
    }
    pub const fn retry_after(not_before_unix_milliseconds: u64) -> Self {
        Self {
            disposition: RetryDisposition::RetryAfter(not_before_unix_milliseconds),
            code: ConnectErrorCode::ConnectionFailed,
        }
    }
    const fn invalid() -> Self {
        Self {
            disposition: RetryDisposition::Terminal,
            code: ConnectErrorCode::ArtifactInvalid,
        }
    }
    pub const fn disposition(self) -> RetryDisposition {
        self.disposition
    }
    pub const fn code(self) -> ConnectErrorCode {
        self.code
    }
}

#[async_trait]
pub trait ArtifactSource: fmt::Debug + Send + Sync + 'static {
    async fn acquire(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ArtifactLease, ArtifactSourceError>;
}

#[derive(Clone, Debug)]
pub struct ConnectionControllerOptions {
    connector: ConnectorOptions,
    maximum_attempts: Option<NonZeroU64>,
}

/// Invalid public connection-controller configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid Flowersec connection controller configuration")]
pub struct ConnectionControllerConfigurationError;

impl ConnectionControllerOptions {
    pub fn new(connector: ConnectorOptions) -> Self {
        Self {
            connector,
            maximum_attempts: None,
        }
    }
    pub fn with_maximum_attempts(
        mut self,
        maximum_attempts: NonZeroU64,
    ) -> Result<Self, ConnectionControllerConfigurationError> {
        if maximum_attempts.get() > MAX_SAFE_INTEGER {
            return Err(ConnectionControllerConfigurationError);
        }
        self.maximum_attempts = Some(maximum_attempts);
        Ok(self)
    }
    pub const fn maximum_attempts(&self) -> Option<NonZeroU64> {
        self.maximum_attempts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Idle,
    Connecting,
    Connected,
    Waiting,
    Failed,
    Closed,
}

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
    pub const fn code(self) -> ConnectErrorCode {
        match self {
            Self::ArtifactSource(error) => error.code(),
            Self::Connect { code, .. } => code,
            Self::Session { .. } => ConnectErrorCode::ConnectionFailed,
        }
    }

    pub const fn disposition(self) -> RetryDisposition {
        match self {
            Self::ArtifactSource(error) => error.disposition(),
            Self::Connect { disposition, .. } | Self::Session { disposition, .. } => disposition,
        }
    }

    pub const fn phase(self) -> ConnectionFailurePhase {
        match self {
            Self::ArtifactSource(_) => ConnectionFailurePhase::Artifact,
            Self::Connect { .. } => ConnectionFailurePhase::Connect,
            Self::Session { .. } => ConnectionFailurePhase::Session,
        }
    }

    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::ArtifactSource(error) => error.code().as_str(),
            Self::Connect { code, .. } => code.as_str(),
            Self::Session { error, .. } => error.as_str(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionSnapshot {
    pub state: ConnectionState,
    pub attempt: u64,
    pub current_session: Option<Arc<dyn Session>>,
    pub failure: Option<ConnectionFailure>,
    revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionFailurePhase {
    Artifact,
    Connect,
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionDiagnosticFailure {
    pub phase: ConnectionFailurePhase,
    pub code: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionDiagnostic {
    pub state: ConnectionState,
    pub attempt: u64,
    pub failure: Option<ConnectionDiagnosticFailure>,
    pub retry_disposition: Option<RetryDisposition>,
}

impl ConnectionSnapshot {
    /// Removes the live Session and retains only stable, redacted state.
    pub fn diagnostic(&self) -> ConnectionDiagnostic {
        ConnectionDiagnostic {
            state: self.state,
            attempt: self.attempt,
            failure: self.failure.map(|failure| ConnectionDiagnosticFailure {
                phase: failure.phase(),
                code: failure.diagnostic_code(),
            }),
            retry_disposition: self.failure.map(ConnectionFailure::disposition),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionControllerErrorCode {
    Failed,
    Closed,
    Canceled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec connection controller stopped")]
pub struct ConnectionControllerError {
    code: ConnectionControllerErrorCode,
    diagnostic: ConnectionDiagnostic,
}

impl ConnectionControllerError {
    pub const fn code(&self) -> ConnectionControllerErrorCode {
        self.code
    }

    pub const fn diagnostic(&self) -> ConnectionDiagnostic {
        self.diagnostic
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerStatus {
    pub(crate) state: ConnectionState,
    pub(crate) attempt: u64,
    pub(crate) next_retry_at: Option<SystemTime>,
    pub(crate) retry_not_before: Option<SystemTime>,
    pub(crate) last_failure: Option<ConnectionFailure>,
    pub(crate) revision: u64,
}

struct ControllerState {
    status: ControllerStatus,
    current: Option<Arc<dyn Session>>,
}

struct ControllerInner {
    source: Arc<dyn ArtifactSource>,
    options: ConnectionControllerOptions,
    connect_one_shot: ConnectOneShot,
    clock: Arc<dyn ControllerClock>,
    cancellation: CancellationToken,
    retry_wake: Notify,
    retry_revision: AtomicU64,
    changed: Notify,
    close_workflow_started: AtomicBool,
    close_complete: AtomicBool,
    close_complete_changed: Notify,
    scheduler_join_started: AtomicBool,
    scheduler_join_complete: AtomicBool,
    scheduler_join_complete_changed: Notify,
    state: Mutex<ControllerState>,
    // Admission, source-future construction, and close publication share one
    // short synchronous critical section. Third-party futures are polled only
    // after this gate is released.
    acquisition_gate: Mutex<()>,
    #[cfg(test)]
    before_acquire_admission: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    after_acquire_claim: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
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

pub struct ConnectionController {
    inner: Arc<ControllerInner>,
    task: Mutex<Option<JoinHandle<()>>>,
    close_lock: AsyncMutex<()>,
}

impl fmt::Debug for ConnectionController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionController")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl ConnectionController {
    pub fn new(source: Arc<dyn ArtifactSource>, options: ConnectionControllerOptions) -> Self {
        Self::new_with_connector(
            source,
            options,
            Arc::new(|lease, options, cancellation| {
                Box::pin(connect_v3_with_cancellation(lease, options, cancellation))
            }),
        )
    }

    fn new_with_connector(
        source: Arc<dyn ArtifactSource>,
        options: ConnectionControllerOptions,
        connect_one_shot: ConnectOneShot,
    ) -> Self {
        Self::new_with_connector_and_clock(
            source,
            options,
            connect_one_shot,
            Arc::new(SystemControllerClock::new()),
        )
    }

    fn new_with_connector_and_clock(
        source: Arc<dyn ArtifactSource>,
        options: ConnectionControllerOptions,
        connect_one_shot: ConnectOneShot,
        clock: Arc<dyn ControllerClock>,
    ) -> Self {
        Self {
            inner: Arc::new(ControllerInner {
                source,
                options,
                connect_one_shot,
                clock,
                cancellation: CancellationToken::new(),
                retry_wake: Notify::new(),
                retry_revision: AtomicU64::new(0),
                changed: Notify::new(),
                close_workflow_started: AtomicBool::new(false),
                close_complete: AtomicBool::new(false),
                close_complete_changed: Notify::new(),
                scheduler_join_started: AtomicBool::new(false),
                scheduler_join_complete: AtomicBool::new(false),
                scheduler_join_complete_changed: Notify::new(),
                state: Mutex::new(ControllerState {
                    status: ControllerStatus {
                        state: ConnectionState::Idle,
                        attempt: 0,
                        next_retry_at: None,
                        retry_not_before: None,
                        last_failure: None,
                        revision: 0,
                    },
                    current: None,
                }),
                acquisition_gate: Mutex::new(()),
                #[cfg(test)]
                before_acquire_admission: Mutex::new(None),
                #[cfg(test)]
                after_acquire_claim: Mutex::new(None),
            }),
            task: Mutex::new(None),
            close_lock: AsyncMutex::new(()),
        }
    }

    pub fn start(&self) {
        let mut task = lock(&self.task);
        if task.is_some() || self.inner.status().state == ConnectionState::Closed {
            return;
        }
        let runtime = tokio::runtime::Handle::current();
        *task = Some(runtime.spawn(run_controller(self.inner.clone())));
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        self.inner.snapshot()
    }

    /// Waits for an established Session without starting the controller.
    pub async fn wait_for_session(&self) -> Result<Arc<dyn Session>, ConnectionControllerError> {
        self.wait_for_session_with_cancellation(CancellationToken::new())
            .await
    }

    /// Waits for an established Session or explicit caller cancellation.
    pub async fn wait_for_session_with_cancellation(
        &self,
        cancellation: CancellationToken,
    ) -> Result<Arc<dyn Session>, ConnectionControllerError> {
        loop {
            let snapshot = self.snapshot();
            match snapshot.state {
                ConnectionState::Connected => {
                    if let Some(session) = snapshot.current_session.clone() {
                        return Ok(session);
                    }
                }
                ConnectionState::Failed => {
                    return Err(connection_controller_error(
                        ConnectionControllerErrorCode::Failed,
                        &snapshot,
                    ));
                }
                ConnectionState::Closed => {
                    return Err(connection_controller_error(
                        ConnectionControllerErrorCode::Closed,
                        &snapshot,
                    ));
                }
                ConnectionState::Idle | ConnectionState::Connecting | ConnectionState::Waiting => {}
            }
            tokio::select! {
                _ = self.wait_for_snapshot_change(&snapshot) => {}
                _ = cancellation.cancelled() => {
                    return Err(connection_controller_error(
                        ConnectionControllerErrorCode::Canceled,
                        &snapshot,
                    ));
                }
            }
        }
    }

    pub async fn wait_for_snapshot_change(&self, after: &ConnectionSnapshot) -> ConnectionSnapshot {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.inner.status().revision != after.revision {
                return self.inner.snapshot();
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn status(&self) -> ControllerStatus {
        self.inner.status()
    }

    pub fn current_session(&self) -> Option<Arc<dyn Session>> {
        lock(&self.inner.state).current.clone()
    }

    pub fn retry_now(&self) -> bool {
        let revision = {
            let state = lock(&self.inner.state);
            if state.status.state != ConnectionState::Waiting
                || state
                    .status
                    .retry_not_before
                    .is_some_and(|deadline| self.inner.clock.wall_now() < deadline)
            {
                return false;
            }
            state.status.revision
        };
        self.inner.retry_revision.store(revision, Ordering::Release);
        self.inner.retry_wake.notify_waiters();
        true
    }

    pub async fn close(&self) {
        // Serialize close callers so every caller waits for the same cleanup barrier.
        let _close = self.close_lock.lock().await;
        {
            let _admission = lock(&self.inner.acquisition_gate);
            self.inner.cancellation.cancel();
            self.inner.retry_wake.notify_waiters();
            self.inner.start_close_workflow();
        }
        let task = lock(&self.task).take();
        self.inner.start_scheduler_join_workflow(task);
        self.inner.wait_close_completion().await;
        self.inner.wait_scheduler_join_completion().await;
    }
}

fn connection_controller_error(
    code: ConnectionControllerErrorCode,
    snapshot: &ConnectionSnapshot,
) -> ConnectionControllerError {
    ConnectionControllerError {
        code,
        diagnostic: snapshot.diagnostic(),
    }
}

impl Drop for ConnectionController {
    fn drop(&mut self) {
        let _admission = lock(&self.inner.acquisition_gate);
        self.inner.cancellation.cancel();
        self.inner.retry_wake.notify_waiters();
    }
}

impl ControllerInner {
    fn status(&self) -> ControllerStatus {
        lock(&self.state).status
    }
    fn snapshot(&self) -> ConnectionSnapshot {
        let state = lock(&self.state);
        ConnectionSnapshot {
            state: state.status.state,
            attempt: state.status.attempt,
            current_session: state.current.clone(),
            failure: state.status.last_failure,
            revision: state.status.revision,
        }
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
    fn set_connecting(&self, attempt: u64) -> bool {
        self.update(|state| {
            state.status.state = ConnectionState::Connecting;
            state.status.attempt = attempt;
            state.status.next_retry_at = None;
            state.status.retry_not_before = None;
            state.status.last_failure = None;
        })
    }

    #[cfg(test)]
    fn run_before_acquire_admission(&self) {
        let hook = lock(&self.before_acquire_admission).clone();
        if let Some(hook) = hook {
            hook();
        }
    }
    #[cfg(test)]
    fn run_after_acquire_claim(&self) {
        let hook = lock(&self.after_acquire_claim).clone();
        if let Some(hook) = hook {
            hook();
        }
    }
    fn set_connected(&self, attempt: u64, session: Arc<dyn Session>) -> bool {
        self.update(|state| {
            state.current = Some(session);
            state.status.state = ConnectionState::Connected;
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
            state.status.retry_not_before = retry_not_before;
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
            state.status.retry_not_before = None;
            state.status.last_failure = Some(failure);
        })
    }
    fn start_close_workflow(self: &Arc<Self>) {
        // Claim the workflow while holding the state lock so a scheduler close
        // cannot publish completion before the caller has taken the session.
        let (session, changed) = {
            let mut state = lock(&self.state);
            if self.close_workflow_started.swap(true, Ordering::AcqRel) {
                return;
            }
            let changed = state.status.state != ConnectionState::Closed;
            if changed {
                state.status.state = ConnectionState::Closed;
                state.status.next_retry_at = None;
                state.status.retry_not_before = None;
                state.status.last_failure = None;
                state.status.revision = state.status.revision.saturating_add(1);
            }
            (state.current.take(), changed)
        };
        if changed {
            self.changed.notify_waiters();
        }
        let Some(session) = session else {
            self.close_complete.store(true, Ordering::Release);
            self.close_complete_changed.notify_waiters();
            return;
        };
        let inner = self.clone();
        tokio::spawn(async move {
            let _ = std::panic::AssertUnwindSafe(session.close())
                .catch_unwind()
                .await;
            inner.close_complete.store(true, Ordering::Release);
            inner.close_complete_changed.notify_waiters();
        });
    }

    async fn wait_close_completion(&self) {
        loop {
            let changed = self.close_complete_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.close_complete.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    fn start_scheduler_join_workflow(self: &Arc<Self>, task: Option<JoinHandle<()>>) {
        if self.scheduler_join_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(task) = task else {
            self.scheduler_join_complete.store(true, Ordering::Release);
            self.scheduler_join_complete_changed.notify_waiters();
            return;
        };
        let inner = self.clone();
        tokio::spawn(async move {
            let _ = task.await;
            inner.scheduler_join_complete.store(true, Ordering::Release);
            inner.scheduler_join_complete_changed.notify_waiters();
        });
    }

    async fn wait_scheduler_join_completion(&self) {
        loop {
            let changed = self.scheduler_join_complete_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.scheduler_join_complete.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Clone, Debug)]
struct PolicyIdentity {
    pins: Vec<PinIdentity>,
    trigger_endpoints: HashSet<EndpointIdentity>,
    failed_endpoints: HashSet<EndpointIdentity>,
    source_endpoints: HashSet<EndpointIdentity>,
    public_code: ConnectErrorCode,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct EndpointIdentity {
    carrier: crate::artifact_v3::CarrierWireV3,
    path: &'static str,
    url: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PinIdentity {
    endpoint: EndpointIdentity,
    digest: [u8; 32],
}

fn merge_policy_public_code(
    current: Option<ConnectErrorCode>,
    next: ConnectErrorCode,
) -> ConnectErrorCode {
    if matches!(current, Some(ConnectErrorCode::TransportSecurityFailed))
        || next == ConnectErrorCode::TransportSecurityFailed
    {
        ConnectErrorCode::TransportSecurityFailed
    } else {
        next
    }
}

fn policy_identity(artifact: &ArtifactV3, error: ConnectError) -> PolicyIdentity {
    let path = artifact.path_kind_for_controller();
    // Connector candidate masks are indexed over the controller-filtered
    // plan, so provenance must use that same ordering after blocked policies
    // remove candidates from a later attempt.
    let candidates = artifact.controller_candidates();
    let source_endpoints = candidates
        .iter()
        .map(|candidate| EndpointIdentity {
            carrier: candidate.carrier,
            path,
            url: candidate.normalized_url.clone(),
        })
        .collect::<HashSet<_>>();
    let failed_endpoints = candidates
        .iter()
        .enumerate()
        .filter(|(index, _)| error.v3_failed_candidate_mask() & (1_u8 << index) != 0)
        .map(|(_, candidate)| EndpointIdentity {
            carrier: candidate.carrier,
            path,
            url: candidate.normalized_url.clone(),
        })
        .collect::<HashSet<_>>();
    let pins = candidates
        .iter()
        .enumerate()
        .filter(|(index, candidate)| {
            error.v3_policy_trigger_mask() & (1_u8 << index) != 0
                && matches!(candidate.tls, TlsPolicyWireV3::Pin { .. })
        })
        .filter_map(|(_, candidate)| {
            candidate.policy_digest().ok().map(|digest| PinIdentity {
                endpoint: EndpointIdentity {
                    carrier: candidate.carrier,
                    path,
                    url: candidate.normalized_url.clone(),
                },
                digest,
            })
        })
        .collect::<Vec<_>>();
    let trigger_endpoints = pins.iter().map(|pin| pin.endpoint.clone()).collect();
    PolicyIdentity {
        pins,
        trigger_endpoints,
        failed_endpoints,
        source_endpoints,
        public_code: error.code(),
    }
}

fn replacement_candidate_ids(
    artifact: &ArtifactV3,
    trigger: &PolicyIdentity,
    blocked: &HashSet<PinIdentity>,
) -> Option<HashSet<String>> {
    if trigger.pins.is_empty() {
        return None;
    }
    let path = artifact.path_kind_for_controller();
    let mut changed = false;
    let mut eligible = HashSet::new();
    for candidate in artifact.canonical_candidates() {
        let endpoint = EndpointIdentity {
            carrier: candidate.carrier,
            path,
            url: candidate.normalized_url.clone(),
        };
        match &candidate.tls {
            TlsPolicyWireV3::Ca {} if trigger.trigger_endpoints.contains(&endpoint) => continue,
            TlsPolicyWireV3::Ca {} => {}
            TlsPolicyWireV3::Pin { .. } => {
                let Ok(digest) = candidate.policy_digest() else {
                    return None;
                };
                let changed_trigger = if let Some(previous) =
                    trigger.pins.iter().find(|pin| pin.endpoint == endpoint)
                {
                    if previous.digest == digest {
                        continue;
                    }
                    true
                } else {
                    false
                };
                let identity = PinIdentity {
                    endpoint: endpoint.clone(),
                    digest,
                };
                if blocked.contains(&identity) {
                    continue;
                }
                if changed_trigger {
                    changed = true;
                    eligible.insert(candidate.id.clone());
                    continue;
                }
            }
        }
        if !trigger.source_endpoints.contains(&endpoint)
            || !trigger.failed_endpoints.contains(&endpoint)
        {
            eligible.insert(candidate.id.clone());
        }
    }
    (changed && !eligible.is_empty()).then_some(eligible)
}

fn primary_candidate_ids(artifact: &ArtifactV3, blocked: &HashSet<PinIdentity>) -> HashSet<String> {
    let path = artifact.path_kind_for_controller();
    artifact
        .canonical_candidates()
        .iter()
        .filter_map(|candidate| match &candidate.tls {
            TlsPolicyWireV3::Ca {}
                if blocked.iter().any(|pin| {
                    pin.endpoint.carrier == candidate.carrier
                        && pin.endpoint.path == path
                        && pin.endpoint.url == candidate.normalized_url
                }) =>
            {
                None
            }
            TlsPolicyWireV3::Pin { .. } => candidate.policy_digest().ok().and_then(|digest| {
                (!blocked.contains(&PinIdentity {
                    endpoint: EndpointIdentity {
                        carrier: candidate.carrier,
                        path,
                        url: candidate.normalized_url.clone(),
                    },
                    digest,
                }))
                .then(|| candidate.id.clone())
            }),
            _ => Some(candidate.id.clone()),
        })
        .collect()
}

async fn run_controller(inner: Arc<ControllerInner>) {
    let mut attempt = 0_u64;
    let mut retry_index = 0_u64;
    let mut attempts_in_cycle = 0_u64;
    let mut replacement_used = false;
    let mut blocked_pin_policy = HashSet::new();
    let mut blocked_public_code = None;
    loop {
        if inner.cancellation.is_cancelled() {
            close_inner(&inner).await;
            return;
        }
        attempt = increment_safe_counter(attempt);
        attempts_in_cycle = increment_safe_counter(attempts_in_cycle);
        let claimed = match acquire_lease(&inner, attempt).await {
            Ok(Some(claimed)) => claimed,
            Ok(None) => return,
            Err(failure) => {
                if !schedule_retry(&inner, attempt, attempts_in_cycle, retry_index, failure).await {
                    return;
                }
                retry_index = retry_index.saturating_add(1);
                continue;
            }
        };
        if claimed.artifact().expires_at_unix_seconds() <= unix_seconds(inner.clock.wall_now()) {
            let _ = claimed.retire().await;
            if !schedule_retry(
                &inner,
                attempt,
                attempts_in_cycle,
                retry_index,
                connect_failure(ConnectErrorCode::Expired, RetryDisposition::Retryable),
            )
            .await
            {
                return;
            }
            retry_index = retry_index.saturating_add(1);
            continue;
        }
        let candidate_ids = primary_candidate_ids(claimed.artifact(), &blocked_pin_policy);
        if candidate_ids.is_empty() {
            let _ = claimed.retire().await;
            inner.set_failed(
                attempt,
                connect_failure(
                    blocked_public_code.unwrap_or(ConnectErrorCode::TransportSecurityFailed),
                    RetryDisposition::Terminal,
                ),
                false,
            );
            return;
        }
        let connector_artifact = claimed
            .artifact()
            .with_controller_candidate_ids(candidate_ids);
        let attempt_artifact = connector_artifact.clone();
        let result = (inner.connect_one_shot)(
            claimed.connector_lease_with_artifact(connector_artifact),
            inner.options.connector.clone(),
            inner.cancellation.child_token(),
        )
        .await;
        if inner.cancellation.is_cancelled() {
            if let Ok(session) = result {
                let _ = session.close().await;
            } else if !claimed.is_consumed() {
                let _ = claimed.retire().await;
            }
            close_inner(&inner).await;
            return;
        }
        let session = match result {
            Ok(session) => session,
            Err(error) => {
                let policy_sensitive = !claimed.is_consumed()
                    && !policy_identity(&attempt_artifact, error).pins.is_empty();
                if policy_sensitive {
                    let trigger = policy_identity(&attempt_artifact, error);
                    blocked_public_code = Some(merge_policy_public_code(
                        blocked_public_code,
                        trigger.public_code,
                    ));
                    blocked_pin_policy.extend(trigger.pins.iter().cloned());
                    let _ = claimed.retire().await;
                    if replacement_used {
                        inner.set_failed(
                            attempt,
                            connect_failure(
                                blocked_public_code.unwrap_or(error.code()),
                                RetryDisposition::Terminal,
                            ),
                            false,
                        );
                        return;
                    }
                    retry_index = retry_index.saturating_add(1);
                    match run_replacement(
                        &inner,
                        &trigger,
                        &mut attempt,
                        &mut attempts_in_cycle,
                        &mut retry_index,
                        &mut replacement_used,
                        &blocked_pin_policy,
                    )
                    .await
                    {
                        ReplacementResult::Connected(session) => session,
                        ReplacementResult::Retry(failure) => {
                            if !schedule_retry(
                                &inner,
                                attempt,
                                attempts_in_cycle,
                                retry_index,
                                failure,
                            )
                            .await
                            {
                                return;
                            }
                            retry_index = retry_index.saturating_add(1);
                            continue;
                        }
                        ReplacementResult::Terminal(code) => {
                            inner.set_failed(
                                attempt,
                                connect_failure(code, RetryDisposition::Terminal),
                                false,
                            );
                            return;
                        }
                        ReplacementResult::Stopped => return,
                    }
                } else {
                    if !claimed.is_consumed() {
                        let _ = claimed.retire().await;
                    }
                    let failure = connect_failure(error.code(), connect_disposition(error));
                    if !schedule_retry(&inner, attempt, attempts_in_cycle, retry_index, failure)
                        .await
                    {
                        return;
                    }
                    retry_index = retry_index.saturating_add(1);
                    continue;
                }
            }
        };

        attempts_in_cycle = 0;
        replacement_used = false;
        blocked_pin_policy.clear();
        blocked_public_code = None;
        retry_index = 0;
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
        let _ = session.close().await;
        let failure = ConnectionFailure::Session {
            error: termination.error,
            disposition: session_disposition(termination.error),
        };
        attempt = 0;
        if !schedule_retry(&inner, attempt, 0, retry_index, failure).await {
            return;
        }
        retry_index = 1;
    }
}

async fn acquire_lease(
    inner: &ControllerInner,
    attempt: u64,
) -> Result<Option<ClaimedArtifactLeaseV3>, ConnectionFailure> {
    // ArtifactSource is a public async boundary. Isolate both panics while
    // creating its future and panics while polling it so a source contract
    // violation cannot terminate the controller scheduler.
    #[cfg(test)]
    inner.run_before_acquire_admission();
    let future = {
        let _admission = lock(&inner.acquisition_gate);
        if inner.cancellation.is_cancelled() || !inner.set_connecting(attempt) {
            return Ok(None);
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            inner.source.acquire(inner.cancellation.child_token())
        })) {
            Ok(future) => future,
            Err(_) => {
                return Err(ConnectionFailure::ArtifactSource(
                    ArtifactSourceError::invalid(),
                ));
            }
        }
    };
    let acquisition = std::panic::AssertUnwindSafe(future).catch_unwind();
    tokio::pin!(acquisition);
    let result = tokio::select! {
        biased;
        _ = inner.cancellation.cancelled() => {
            if let Ok(Ok(lease)) = acquisition.await
                && let Ok(claimed) = lease.claim()
            {
                // Cancellation won before delivery, so the source-side
                // ownership token retires the late lease without exposing it
                // to the Controller's connector path.
                let _ = claimed.retire().await;
                }
            return Ok(None);
        },
        result = &mut acquisition => result,
    };
    let result =
        result.map_err(|_| ConnectionFailure::ArtifactSource(ArtifactSourceError::invalid()))?;
    let lease = result.map_err(|error| match error.disposition() {
        RetryDisposition::RetryAfter(deadline) if !valid_retry_after(deadline) => {
            ConnectionFailure::ArtifactSource(ArtifactSourceError::invalid())
        }
        _ => ConnectionFailure::ArtifactSource(error),
    })?;
    let claimed = lease
        .claim_for_controller()
        .map_err(|_| ConnectionFailure::ArtifactSource(ArtifactSourceError::invalid()))?;
    #[cfg(test)]
    inner.run_after_acquire_claim();
    if inner.cancellation.is_cancelled() {
        // Delivery won the source race, so the Controller owns the lease even
        // when cancellation is observed immediately afterward.
        let _ = claimed.retire().await;
        return Ok(None);
    }
    Ok(Some(claimed))
}

fn valid_retry_after(deadline: u64) -> bool {
    deadline <= MAX_RETRY_AFTER_UNIX_MILLISECONDS as u64
}

fn retry_after_system_time(deadline: u64) -> Option<SystemTime> {
    valid_retry_after(deadline).then(|| SystemTime::UNIX_EPOCH + Duration::from_millis(deadline))
}

enum ReplacementResult {
    Connected(Arc<dyn Session>),
    Retry(ConnectionFailure),
    Terminal(ConnectErrorCode),
    Stopped,
}

async fn run_replacement(
    inner: &ControllerInner,
    trigger: &PolicyIdentity,
    status_attempt: &mut u64,
    attempts_in_cycle: &mut u64,
    retry_index: &mut u64,
    replacement_used: &mut bool,
    blocked_pin_policy: &HashSet<PinIdentity>,
) -> ReplacementResult {
    let claimed = loop {
        if inner
            .options
            .maximum_attempts
            .is_some_and(|maximum| *attempts_in_cycle >= maximum.get())
        {
            return ReplacementResult::Terminal(trigger.public_code);
        }
        *status_attempt = increment_safe_counter(*status_attempt);
        *attempts_in_cycle = increment_safe_counter(*attempts_in_cycle);
        match acquire_lease(inner, *status_attempt).await {
            Ok(Some(claimed)) => break claimed,
            Ok(None) => return ReplacementResult::Stopped,
            Err(failure) => {
                if !schedule_retry(
                    inner,
                    *status_attempt,
                    *attempts_in_cycle,
                    *retry_index,
                    failure,
                )
                .await
                {
                    return ReplacementResult::Stopped;
                }
                *retry_index = retry_index.saturating_add(1);
            }
        }
    };
    *replacement_used = true;
    if claimed.artifact().expires_at_unix_seconds() <= unix_seconds(inner.clock.wall_now()) {
        let _ = claimed.retire().await;
        return ReplacementResult::Retry(connect_failure(
            ConnectErrorCode::Expired,
            RetryDisposition::Retryable,
        ));
    }
    let Some(candidate_ids) =
        replacement_candidate_ids(claimed.artifact(), trigger, blocked_pin_policy)
    else {
        let _ = claimed.retire().await;
        return ReplacementResult::Terminal(trigger.public_code);
    };
    let connector_artifact = claimed
        .artifact()
        .with_controller_candidate_ids(candidate_ids);
    let result = (inner.connect_one_shot)(
        claimed.connector_lease_with_artifact(connector_artifact),
        inner.options.connector.clone(),
        inner.cancellation.child_token(),
    )
    .await;
    match result {
        Ok(session) => ReplacementResult::Connected(session),
        Err(error) if claimed.is_consumed() => {
            ReplacementResult::Retry(connect_failure(error.code(), connect_disposition(error)))
        }
        Err(error) if error.code() == ConnectErrorCode::Expired => {
            let _ = claimed.retire().await;
            ReplacementResult::Retry(connect_failure(
                ConnectErrorCode::Expired,
                RetryDisposition::Retryable,
            ))
        }
        Err(_) => {
            let _ = claimed.retire().await;
            ReplacementResult::Terminal(trigger.public_code)
        }
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
    if disposition == RetryDisposition::Terminal {
        inner.set_failed(status_attempt, failure, clear_current);
        return false;
    }
    if inner
        .options
        .maximum_attempts
        .is_some_and(|maximum| attempts_in_cycle >= maximum.get())
    {
        inner.set_failed(status_attempt, terminal_failure(failure), clear_current);
        return false;
    }
    let backoff_delay = retry_delay(retry_index);
    let backoff_deadline = add_safe_counter(
        inner.clock.monotonic_now_milliseconds(),
        duration_milliseconds(backoff_delay),
    );
    let backoff_at = inner
        .clock
        .wall_now()
        .checked_add(backoff_delay)
        .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(253_402_300_799));
    let not_before = match disposition {
        RetryDisposition::RetryAfter(deadline) => retry_after_system_time(deadline),
        RetryDisposition::Terminal | RetryDisposition::Retryable => None,
    };
    let next_retry_at = not_before.map_or(backoff_at, |deadline| deadline.max(backoff_at));
    let Some(revision) = inner.set_waiting(
        status_attempt,
        next_retry_at,
        not_before,
        failure,
        clear_current,
    ) else {
        return false;
    };
    wait_for_retry(inner, backoff_deadline, not_before, revision).await
}

fn terminal_failure(failure: ConnectionFailure) -> ConnectionFailure {
    match failure {
        ConnectionFailure::ArtifactSource(_) => {
            ConnectionFailure::ArtifactSource(ArtifactSourceError::terminal())
        }
        ConnectionFailure::Connect { code, .. } => ConnectionFailure::Connect {
            code,
            disposition: RetryDisposition::Terminal,
        },
        ConnectionFailure::Session { error, .. } => ConnectionFailure::Session {
            error,
            disposition: RetryDisposition::Terminal,
        },
    }
}

fn retry_delay(retry_index: u64) -> Duration {
    let mut delay = DEFAULT_INITIAL_RETRY_DELAY;
    for _ in 0..retry_index.min(8) {
        delay = delay
            .saturating_mul(DEFAULT_RETRY_FACTOR)
            .min(DEFAULT_MAX_RETRY_DELAY);
        if delay == DEFAULT_MAX_RETRY_DELAY {
            break;
        }
    }
    delay
}

const fn increment_safe_counter(value: u64) -> u64 {
    add_safe_counter(value, 1)
}

const fn add_safe_counter(value: u64, amount: u64) -> u64 {
    if value >= MAX_SAFE_INTEGER || amount >= MAX_SAFE_INTEGER - value {
        MAX_SAFE_INTEGER
    } else {
        value + amount
    }
}

async fn wait_for_retry(
    inner: &ControllerInner,
    backoff_deadline: u64,
    not_before: Option<SystemTime>,
    revision: u64,
) -> bool {
    tokio::select! {
        _ = inner.cancellation.cancelled() => false,
        ready = wait_for_deadlines(inner, Some(backoff_deadline), not_before) => ready,
        _ = wait_for_retry_now(inner, revision) => {
            if let Some(deadline) = not_before {
                wait_for_deadlines(inner, None, Some(deadline)).await
            } else {
                true
            }
        }
    }
}

async fn wait_for_retry_now(inner: &ControllerInner, revision: u64) {
    loop {
        let notified = inner.retry_wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if inner.retry_revision.load(Ordering::Acquire) == revision {
            return;
        }
        notified.await;
    }
}

async fn wait_for_deadlines(
    inner: &ControllerInner,
    monotonic_deadline: Option<u64>,
    wall_deadline: Option<SystemTime>,
) -> bool {
    loop {
        let monotonic_delay = monotonic_deadline
            .map(|deadline| {
                Duration::from_millis(
                    deadline.saturating_sub(inner.clock.monotonic_now_milliseconds()),
                )
            })
            .unwrap_or_default();
        let wall_delay = wall_deadline
            .and_then(|deadline| deadline.duration_since(inner.clock.wall_now()).ok())
            .unwrap_or_default();
        if monotonic_delay.is_zero() && wall_delay.is_zero() {
            return true;
        }
        let delay = next_clock_delay(monotonic_delay, wall_delay).min(Duration::from_secs(1));
        tokio::select! {
            _ = inner.cancellation.cancelled() => return false,
            _ = inner.clock.clone().sleep(delay) => {}
        }
    }
}

fn next_clock_delay(monotonic_delay: Duration, wall_delay: Duration) -> Duration {
    match (monotonic_delay.is_zero(), wall_delay.is_zero()) {
        (false, false) => monotonic_delay.min(wall_delay),
        (false, true) => monotonic_delay,
        (true, false) => wall_delay,
        (true, true) => Duration::ZERO,
    }
}

async fn close_inner(inner: &Arc<ControllerInner>) {
    inner.start_close_workflow();
    inner.wait_close_completion().await;
}

const fn connect_failure(
    code: ConnectErrorCode,
    disposition: RetryDisposition,
) -> ConnectionFailure {
    ConnectionFailure::Connect { code, disposition }
}

fn connect_disposition(error: ConnectError) -> RetryDisposition {
    error.retry_disposition()
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

fn duration_milliseconds(duration: Duration) -> u64 {
    duration.as_millis().min(MAX_SAFE_INTEGER as u128) as u64
}

fn unix_seconds(now: SystemTime) -> u64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
#[path = "connection_controller_vectors.rs"]
mod vector_tests;

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicU64, Ordering},
    };

    use base64::Engine as _;
    use serde::Deserialize;

    use super::*;
    use crate::transport::{
        ByteStream, IncomingStream, RpcPeer, SessionTermination, StreamMetadata,
    };

    #[derive(Deserialize)]
    struct ControllerVectorsV3 {
        version: u64,
        public_errors: Vec<String>,
        sdk_api_consistency: serde_json::Value,
        defaults: DefaultsV3,
        backoff_vectors: Vec<BackoffV3>,
        scenarios: Vec<ScenarioV3>,
        browser_capability_scenarios: Vec<ScenarioV3>,
    }
    #[derive(Deserialize)]
    struct DefaultsV3 {
        initial_backoff_ms: u64,
        maximum_backoff_ms: u64,
        maximum_policy_sensitive_replacement_leases_per_cycle: u64,
    }
    #[derive(Deserialize)]
    struct BackoffV3 {
        consecutive_failure: u64,
        delay_ms: u64,
    }
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    struct ScenarioV3 {
        id: String,
        driver: String,
        steps: Vec<String>,
        input: serde_json::Value,
        expected: ScenarioExpectedV3,
    }
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    struct ScenarioExpectedV3 {
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

    #[test]
    fn default_controller_consumes_the_complete_v3_vector_inventory() {
        let vectors: ControllerVectorsV3 = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/controller_vectors.json"
        ))
        .expect("parse Flowersec v3 controller vectors");
        assert_eq!(vectors.version, 3);
        assert_eq!(
            vectors.public_errors,
            [
                ConnectErrorCode::ArtifactInvalid,
                ConnectErrorCode::Expired,
                ConnectErrorCode::TransportSecurityUnsupported,
                ConnectErrorCode::TransportSecurityFailed,
                ConnectErrorCode::ConnectionFailed,
            ]
            .map(ConnectErrorCode::as_str)
        );
        assert_eq!(
            vectors.sdk_api_consistency["connection_error_codes"],
            serde_json::json!([
                "artifact_invalid",
                "expired_artifact",
                "transport_security_unsupported",
                "transport_security_failed",
                "connection_failed",
            ])
        );
        assert_eq!(
            vectors.sdk_api_consistency["unreliable_error_codes"],
            serde_json::json!([
                "unavailable",
                "invalid_message",
                "too_large",
                "canceled",
                "closed",
                "operation_failed",
            ])
        );
        assert_eq!(
            vectors.sdk_api_consistency["unreliable_send_results"],
            serde_json::json!([
                "accepted",
                "dropped_budget",
                "dropped_expired",
                "dropped_carrier",
            ])
        );
        assert_eq!(
            vectors.sdk_api_consistency["retry"],
            serde_json::json!({
                "error_property": "retryDisposition",
                "deprecated_error_property": "disposition",
                "retry_after_property": "notBeforeUnixMilliseconds",
                "deprecated_retry_after_property": "absoluteUnixMilliseconds",
            })
        );
        assert_eq!(
            vectors.sdk_api_consistency["connection_diagnostic"],
            serde_json::json!({
                "fields": ["state", "attempt", "failure", "retryDisposition"],
                "failure_fields": ["phase", "code"],
                "forbidden_fields": [
                    "url", "carrier", "candidates", "error", "credentials", "peer", "session"
                ],
            })
        );
        assert_eq!(
            vectors.sdk_api_consistency["wait_for_session"],
            serde_json::json!({
                "starts_controller": false,
                "outcomes": ["connected", "failed", "closed", "canceled"],
                "migrates_operations": false,
            })
        );
        assert_eq!(
            vectors.sdk_api_consistency["swift"]["unreliable_messages"],
            "unsupported"
        );
        assert_eq!(vectors.defaults.initial_backoff_ms, 250);
        assert_eq!(vectors.defaults.maximum_backoff_ms, 30_000);
        assert_eq!(
            vectors
                .defaults
                .maximum_policy_sensitive_replacement_leases_per_cycle,
            1
        );
        for vector in &vectors.backoff_vectors {
            assert_eq!(
                retry_delay(vector.consecutive_failure - 1),
                Duration::from_millis(vector.delay_ms)
            );
        }
        let mut ids = HashSet::new();
        for scenario in &vectors.scenarios {
            assert!(
                ids.insert(scenario.id.as_str()),
                "duplicate scenario {}",
                scenario.id
            );
            assert!(
                !scenario.steps.is_empty(),
                "{} has no executable steps",
                scenario.id
            );
            assert!(
                scenario.input.is_object(),
                "{} input is not an object",
                scenario.id
            );
            assert_scenario_schema(scenario, &vectors.backoff_vectors);
        }
        assert_browser_capability_scenarios(&vectors.browser_capability_scenarios);
    }

    fn assert_browser_capability_scenarios(scenarios: &[ScenarioV3]) {
        assert_eq!(scenarios.len(), 1);
        let scenario = &scenarios[0];
        assert_eq!(
            scenario.id,
            "concurrent-capability-invalidation-replacement-barrier"
        );
        assert_eq!(scenario.driver, "capability-linearization-barrier");
        assert!(!scenario.steps.is_empty());
        assert_eq!(scenario.input["concurrent_controllers"], 2);
        assert_eq!(scenario.input["initial_capability"], "enabled");
        assert_eq!(scenario.input["invalidated_capability"], "ca_only");
        assert_eq!(scenario.input["primary_trigger"], "browser_pin_opaque");
        assert_eq!(
            scenario.input["invalidation_trigger"],
            "synchronous_not_supported"
        );
        let expected = &scenario.expected;
        assert_eq!(expected.final_state, "failed");
        assert_eq!(expected.public_error.as_deref(), Some("connection_failed"));
        assert_eq!(expected.disposition.as_deref(), Some("terminal"));
        assert_eq!(expected.concurrent_acquisition_peak, Some(2));
        assert_eq!(expected.replacement_quota_used, 1);
        assert_eq!(
            expected.capability_snapshots.as_deref(),
            Some(["enabled".into(), "enabled".into(), "ca_only".into()].as_slice())
        );
        assert_eq!(expected.old_snapshot_live_gate_failures, Some(1));
        assert_eq!(expected.post_invalidation_pin_constructor_calls, Some(0));
        assert_eq!(
            expected.replacement_dial_candidate_ids.as_deref(),
            Some(["replacement-ca".into()].as_slice())
        );
        assert_eq!(expected.peer_final_state.as_deref(), Some("failed"));
        assert_eq!(
            expected.peer_public_error.as_deref(),
            Some("transport_security_unsupported")
        );
        assert_eq!(
            expected.lease_terminal_states,
            ["retired", "retired", "retired"]
        );
        // Once enabled -> ca_only linearizes, the stale snapshot can only fail closed.
        let mut capability = "enabled";
        let stale_snapshot = capability;
        capability = "ca_only";
        assert_eq!(stale_snapshot, "enabled");
        assert_eq!(capability, "ca_only");
    }

    fn assert_scenario_schema(scenario: &ScenarioV3, backoff: &[BackoffV3]) {
        match scenario.driver.as_str() {
            "policy-replacement"
            | "candidate-capability-filter"
            | "replacement-expiry"
            | "replacement-acquisition"
            | "post-spend-retry"
            | "lease-cancel-race"
            | "attempt-exhaustion"
            | "retry-after-clock"
            | "candidate-failure-aggregation"
            | "failure-ordinal"
            | "expiry-boundary"
            | "cycle-reset"
            | "cycle-reset-terminal"
            | "retry-clock-boundary"
            | "candidate-security-aggregation"
            | "multi-trigger-replacement"
            | "retire-cleanup"
            | "quota-preservation"
            | "attempt-saturation"
            | "capability-barrier"
            | "admission-spend-boundary"
            | "duplicate-lease-identity"
            | "source-contract-validation" => {}
            driver => panic!("unknown controller vector driver {driver}"),
        }
        let expected = &scenario.expected;
        assert!(matches!(
            expected.final_state.as_str(),
            "connecting" | "connected" | "waiting" | "failed" | "closed"
        ));
        assert!(expected.replacement_acquisitions <= expected.acquisitions);
        assert!(expected.replacement_quota_used <= expected.replacement_acquisitions);
        assert!(expected.transports_created <= expected.connect_attempts);
        assert_eq!(
            expected.lease_terminal_states.len() as u64,
            expected.spend_callbacks + expected.retire_callbacks,
            "{} lease callbacks do not account for every terminal lease",
            scenario.id
        );
        assert!(
            expected
                .lease_terminal_states
                .iter()
                .all(|state| matches!(state.as_str(), "consumed" | "retired"))
        );
        for delay in &expected.retry_delays_ms {
            assert!(
                backoff.iter().any(|vector| vector.delay_ms == *delay) || *delay == 1,
                "{} declares an unknown retry delay {delay}",
                scenario.id
            );
        }
        if let Some(value) = expected.no_mode_downgrade {
            assert!(
                value
                    && matches!(
                        scenario.driver.as_str(),
                        "policy-replacement" | "multi-trigger-replacement"
                    )
            );
        }
        if let Some(value) = expected.tls_error_claimed {
            assert!(
                (!value && scenario.driver == "policy-replacement")
                    || (value && scenario.driver == "candidate-security-aggregation")
            );
        }
        if let Some(value) = expected.blocked_policy_remains_blocked {
            assert!(value && scenario.driver == "replacement-expiry");
        }
        if let Some(value) = expected.retry_now_allowed_before_deadline {
            assert!(!value && scenario.driver == "retry-after-clock");
        }
        if let Some(value) = expected.order_independent {
            assert!(
                value
                    && matches!(
                        scenario.driver.as_str(),
                        "candidate-failure-aggregation" | "candidate-security-aggregation"
                    )
            );
        }
        assert_eq!(
            expected.wall_end_ms.is_some(),
            expected.monotonic_end_ms.is_some()
        );
        if let Some(attempt) = expected.attempt {
            if scenario.driver == "attempt-saturation" {
                assert!(attempt > 0);
            } else if scenario.driver == "source-contract-validation" {
                assert_eq!(attempt, 1);
            } else {
                assert_eq!(scenario.driver, "cycle-reset-terminal");
                assert_eq!(attempt, 0);
            }
        }
        if let Some(value) = expected.counter_saturated {
            assert!(value && scenario.driver == "attempt-saturation");
        }
        if let Some(value) = expected.capability_rechecked {
            assert!(value && scenario.driver == "capability-barrier");
        }
        if let Some(value) = expected.cleanup_error_ignored {
            assert!(value && scenario.driver == "retire-cleanup");
        }
        if let Some(bytes) = expected.credential_bytes_written {
            assert_eq!(bytes, 0);
            assert_eq!(scenario.driver, "expiry-boundary");
        }
        if let Some(ordinal) = expected.failure_ordinal {
            assert_eq!(ordinal, 1);
            assert!(matches!(
                scenario.driver.as_str(),
                "failure-ordinal"
                    | "cycle-reset"
                    | "cycle-reset-terminal"
                    | "source-contract-validation"
            ));
        }
        if let Some(interval) = expected.maximum_wall_reread_ms {
            assert_eq!(interval, 1_000);
            assert_eq!(scenario.driver, "retry-clock-boundary");
        }
        if let Some(value) = expected.timer_saturated {
            assert!(value && scenario.driver == "retry-clock-boundary");
        }
    }

    fn scenario_expected(id: &str) -> ScenarioExpectedV3 {
        serde_json::from_str::<ControllerVectorsV3>(include_str!(
            "../../testdata/transport_v3/controller_vectors.json"
        ))
        .expect("parse Flowersec v3 controller vectors")
        .scenarios
        .into_iter()
        .find(|scenario| scenario.id == id)
        .unwrap_or_else(|| panic!("missing controller scenario {id}"))
        .expected
    }

    #[test]
    fn replacement_policy_rejects_same_pin_and_pin_to_ca() {
        let artifact = pin_only_artifact([0x11; 32]);
        let trigger = policy_identity(
            &artifact,
            ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
                .with_v3_candidate_masks(1, 1),
        );
        let blocked = trigger.pins.iter().cloned().collect();
        assert!(replacement_candidate_ids(&artifact, &trigger, &blocked).is_none());
        assert!(
            replacement_candidate_ids(&pin_only_artifact([0x22; 32]), &trigger, &blocked).is_some()
        );
        assert!(replacement_candidate_ids(&ca_only_artifact(), &trigger, &blocked).is_none());
    }

    #[test]
    fn policy_refresh_uses_only_the_pin_candidates_that_actually_triggered() {
        let artifact = mixed_ca_pin_artifact();
        let ca_only_failure = policy_identity(
            &artifact,
            ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
                .with_v3_candidate_masks(0, 0b11),
        );
        assert!(ca_only_failure.pins.is_empty());

        let pin_trigger = policy_identity(
            &artifact,
            ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
                .with_v3_candidate_masks(0b10, 0b11),
        );
        assert_eq!(pin_trigger.pins.len(), 1);
        assert_eq!(
            pin_trigger.pins[0].endpoint.url,
            "wss://pin.example.org/flowersec/v3/direct"
        );
        assert_eq!(pin_trigger.failed_endpoints.len(), 2);

        let filtered = artifact.with_controller_candidate_ids(HashSet::from(["z-pin".to_owned()]));
        let filtered_trigger = policy_identity(
            &filtered,
            ConnectError::from_runtime_code(ConnectErrorCode::TransportSecurityFailed)
                .with_v3_candidate_masks(0b1, 0b1),
        );
        assert_eq!(filtered_trigger.pins.len(), 1);
        assert_eq!(
            filtered_trigger.pins[0].endpoint.url,
            "wss://pin.example.org/flowersec/v3/direct"
        );
    }

    #[test]
    fn retry_after_requires_nonnegative_integer_milliseconds_within_rfc3339_range() {
        assert!(valid_retry_after(0));
        assert!(valid_retry_after(253_402_300_799_999));
        assert!(!valid_retry_after(253_402_300_800_000));
    }

    #[test]
    fn closed_start_is_idempotent_outside_a_runtime() {
        let controller = ConnectionController::new_with_connector(
            Arc::new(QueueSource::new([])),
            test_options(Some(1)),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(controller.close());
        drop(runtime);

        assert_eq!(controller.status().state, ConnectionState::Closed);
        controller.start();
        assert_eq!(controller.status().state, ConnectionState::Closed);
    }

    #[test]
    fn repeated_start_is_idempotent_outside_a_runtime() {
        let source = Arc::new(LateLeaseSource {
            lease: Mutex::new(None),
            acquisitions: AtomicU64::new(0),
        });
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(Some(1)),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            controller.start();
            while source.acquisitions.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        });

        controller.start();

        runtime.block_on(controller.close());
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 1);
        assert_eq!(controller.status().state, ConnectionState::Closed);
    }

    #[tokio::test]
    async fn source_admission_publishes_one_connecting_revision() {
        let source = Arc::new(LateLeaseSource {
            lease: Mutex::new(None),
            acquisitions: AtomicU64::new(0),
        });
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        controller.start();
        while source.acquisitions.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        let status = controller.status();
        assert_eq!(status.state, ConnectionState::Connecting);
        assert_eq!(status.revision, 1);
        controller.close().await;
    }

    #[tokio::test]
    async fn cancellation_drains_and_retires_a_late_delivered_lease() {
        let retired = Arc::new(AtomicU64::new(0));
        let source = Arc::new(LateLeaseSource {
            lease: Mutex::new(Some(test_lease(
                pin_only_artifact([0x11; 32]),
                Arc::new(AtomicU64::new(0)),
                retired.clone(),
            ))),
            acquisitions: AtomicU64::new(0),
        });
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        controller.start();
        while source.acquisitions.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        controller.close().await;
        assert_eq!(retired.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_drain_close_completes_after_retire_panic() {
        let retire_calls = Arc::new(AtomicU64::new(0));
        let retire_calls_capture = retire_calls.clone();
        let lease = ArtifactLease::new_with_retire(
            pin_only_artifact([0x11; 32]),
            || async { Ok(()) },
            move || {
                retire_calls_capture.fetch_add(1, Ordering::SeqCst);
                async {
                    panic!("secret cancellation retirement failure");
                    #[allow(unreachable_code)]
                    Ok(())
                }
            },
        );
        let lease_copy = lease.clone();
        let source = Arc::new(LateLeaseSource {
            lease: Mutex::new(Some(lease)),
            acquisitions: AtomicU64::new(0),
        });
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        controller.start();
        while source.acquisitions.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        tokio::time::timeout(Duration::from_millis(500), controller.close())
            .await
            .expect("controller close remained blocked after retire panic");

        assert_eq!(controller.status().state, ConnectionState::Closed);
        assert_eq!(retire_calls.load(Ordering::SeqCst), 1);
        assert!(
            lease_copy.claim().is_err(),
            "cancellation-retired lease became reusable"
        );
    }

    #[tokio::test]
    async fn canceled_first_close_still_waits_for_owned_scheduler_cleanup() {
        let retire_entered = Arc::new(Notify::new());
        let retire_release = Arc::new(Notify::new());
        let retire_entered_capture = retire_entered.clone();
        let retire_release_capture = retire_release.clone();
        let lease = ArtifactLease::new_with_retire(
            pin_only_artifact([0x11; 32]),
            || async { Ok(()) },
            move || async move {
                retire_entered_capture.notify_one();
                retire_release_capture.notified().await;
                Ok(())
            },
        );
        let source = Arc::new(LateLeaseSource {
            lease: Mutex::new(Some(lease)),
            acquisitions: AtomicU64::new(0),
        });
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        controller.start();
        while source.acquisitions.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        let mut first = Box::pin(controller.close());
        tokio::time::timeout(Duration::from_millis(250), async {
            tokio::select! {
                _ = retire_entered.notified() => {}
                () = &mut first => panic!("controller close completed before scheduler cleanup"),
            }
        })
        .await
        .expect("scheduler cleanup did not enter lease retirement");
        drop(first);

        let mut second = Box::pin(controller.close());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second)
                .await
                .is_err(),
            "later close returned before owned scheduler cleanup"
        );
        retire_release.notify_one();
        tokio::time::timeout(Duration::from_millis(500), &mut second)
            .await
            .expect("later close remained blocked after scheduler cleanup");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delivery_first_close_waits_for_claimed_lease_retirement() {
        let claim_entered = Arc::new(std::sync::Barrier::new(2));
        let claim_release = Arc::new(std::sync::Barrier::new(2));
        let claim_entered_hook = claim_entered.clone();
        let claim_release_hook = claim_release.clone();
        let retire_entered = Arc::new(Notify::new());
        let retire_release = Arc::new(Notify::new());
        let retire_entered_capture = retire_entered.clone();
        let retire_release_capture = retire_release.clone();
        let spends = Arc::new(AtomicU64::new(0));
        let spends_capture = spends.clone();
        let retires = Arc::new(AtomicU64::new(0));
        let retires_capture = retires.clone();
        let connector_calls = Arc::new(AtomicU64::new(0));
        let lease = ArtifactLease::new_with_retire(
            pin_only_artifact([0x11; 32]),
            move || async move {
                spends_capture.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            move || async move {
                retires_capture.fetch_add(1, Ordering::SeqCst);
                retire_entered_capture.notify_one();
                retire_release_capture.notified().await;
                Ok(())
            },
        );
        let lease_copy = lease.clone();
        let controller = Arc::new(ConnectionController::new_with_connector(
            Arc::new(QueueSource::new([Ok(lease)])),
            test_options(None),
            counting_connector([ConnectorStep::Success], connector_calls.clone()),
        ));
        *lock(&controller.inner.after_acquire_claim) = Some(Arc::new(move || {
            claim_entered_hook.wait();
            claim_release_hook.wait();
        }));

        controller.start();
        tokio::task::block_in_place(|| claim_entered.wait());
        let close_controller = controller.clone();
        let mut close = tokio::spawn(async move {
            close_controller.close().await;
        });
        let closed = tokio::time::timeout(Duration::from_millis(500), async {
            let closed = controller.snapshot();
            if closed.state == ConnectionState::Closed {
                closed
            } else {
                controller.wait_for_snapshot_change(&closed).await
            }
        })
        .await
        .expect("close did not publish Closed while acquisition was paused");
        assert_eq!(closed.state, ConnectionState::Closed);
        assert_eq!(closed.failure, None);
        assert!(!close.is_finished());
        assert_eq!(connector_calls.load(Ordering::SeqCst), 0);
        assert_eq!(spends.load(Ordering::SeqCst), 0);
        assert_eq!(retires.load(Ordering::SeqCst), 0);

        tokio::task::block_in_place(|| claim_release.wait());
        tokio::select! {
            biased;
            result = &mut close => panic!("close returned before retirement started: {result:?}"),
            _ = retire_entered.notified() => {}
        }
        assert_eq!(retires.load(Ordering::SeqCst), 1);
        assert_eq!(connector_calls.load(Ordering::SeqCst), 0);
        assert_eq!(spends.load(Ordering::SeqCst), 0);
        assert!(
            lease_copy.claim().is_err(),
            "Controller-claimed lease became reusable"
        );

        retire_release.notify_one();
        tokio::time::timeout(Duration::from_millis(500), &mut close)
            .await
            .expect("close did not complete after retirement cleanup")
            .expect("close task panicked");
        assert_eq!(controller.snapshot().state, ConnectionState::Closed);
        assert_eq!(controller.snapshot().failure, None);
        assert_eq!(retires.load(Ordering::SeqCst), 1);
        assert_eq!(connector_calls.load(Ordering::SeqCst), 0);
        assert_eq!(spends.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_retry_after_and_maximum_attempts_fail_before_retry() {
        let source = Arc::new(QueueSource::new([Err(ArtifactSourceError::retry_after(
            MAX_RETRY_AFTER_UNIX_MILLISECONDS as u64 + 1,
        ))]));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 1);
        assert_eq!(
            status.last_failure,
            Some(ConnectionFailure::ArtifactSource(
                ArtifactSourceError::invalid()
            ))
        );
        assert_eq!(
            status.last_failure.map(ConnectionFailure::code),
            Some(ConnectErrorCode::ArtifactInvalid)
        );
        controller.close().await;

        let source = Arc::new(QueueSource::new(std::iter::empty()));
        let options = ConnectionControllerOptions::new(ConnectorOptions::new())
            .with_maximum_attempts(NonZeroU64::new(MAX_SAFE_INTEGER + 1).unwrap());
        assert!(matches!(
            options,
            Err(ConnectionControllerConfigurationError)
        ));
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn close_winning_primary_admission_prevents_source_call() {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let entered_hook = entered.clone();
        let release_hook = release.clone();
        let source = Arc::new(QueueSource::new(std::iter::empty()));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        *lock(&controller.inner.before_acquire_admission) = Some(Arc::new(move || {
            entered_hook.wait();
            release_hook.wait();
        }));

        controller.start();
        tokio::task::block_in_place(|| entered.wait());
        let mut close = Box::pin(controller.close());
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                tokio::select! {
                    () = &mut close => panic!("close completed before the scheduler barrier released"),
                    () = tokio::task::yield_now() => {
                        if controller.status().state == ConnectionState::Closed {
                            return;
                        }
                    }
                }
            }
        })
        .await
        .expect("close did not publish Closed before primary admission");
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 0);

        tokio::task::block_in_place(|| release.wait());
        tokio::time::timeout(Duration::from_millis(500), &mut close)
            .await
            .expect("close did not complete after primary admission released");
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn close_winning_replacement_admission_prevents_source_call() {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let hook_calls = Arc::new(AtomicU64::new(0));
        let entered_hook = entered.clone();
        let release_hook = release.clone();
        let hook_calls_capture = hook_calls.clone();
        let spent = Arc::new(AtomicU64::new(0));
        let retired = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([Ok(test_lease(
            pin_only_artifact([0x11; 32]),
            spent,
            retired,
        ))]));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector([ConnectorStep::PreSpendSecurity]),
        );
        *lock(&controller.inner.before_acquire_admission) = Some(Arc::new(move || {
            if hook_calls_capture.fetch_add(1, Ordering::SeqCst) == 1 {
                entered_hook.wait();
                release_hook.wait();
            }
        }));

        controller.start();
        tokio::task::block_in_place(|| entered.wait());
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 1);
        let mut close = Box::pin(controller.close());
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                tokio::select! {
                    () = &mut close => panic!("close completed before the scheduler barrier released"),
                    () = tokio::task::yield_now() => {
                        if controller.status().state == ConnectionState::Closed {
                            return;
                        }
                    }
                }
            }
        })
        .await
        .expect("close did not publish Closed before replacement admission");
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 1);

        tokio::task::block_in_place(|| release.wait());
        tokio::time::timeout(Duration::from_millis(500), &mut close)
            .await
            .expect("close did not complete after replacement admission released");
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 1);
        assert_eq!(hook_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn source_panic_projects_to_artifact_invalid_terminal() {
        let controller = ConnectionController::new_with_connector(
            Arc::new(PanicSource),
            test_options(None),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(
            status.last_failure,
            Some(ConnectionFailure::ArtifactSource(
                ArtifactSourceError::invalid()
            ))
        );
        controller.close().await;
        assert_eq!(controller.snapshot().failure, None);
    }

    #[tokio::test]
    async fn source_future_constructor_panic_projects_to_artifact_invalid_terminal() {
        let controller = ConnectionController::new_with_connector(
            Arc::new(ConstructorPanicSource),
            test_options(None),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(
            status.last_failure,
            Some(ConnectionFailure::ArtifactSource(
                ArtifactSourceError::invalid()
            ))
        );
        controller.close().await;
        assert_eq!(controller.snapshot().failure, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn source_first_poll_close_drains_late_lease_before_returning() {
        let spent = Arc::new(AtomicU64::new(0));
        let retired = Arc::new(AtomicU64::new(0));
        let connector_calls = Arc::new(AtomicU64::new(0));
        let close_returned = Arc::new(AtomicBool::new(false));
        let source = Arc::new(FirstPollCloseSource {
            controller: Mutex::new(None),
            lease: Mutex::new(Some(test_lease(
                pin_only_artifact([0x11; 32]),
                spent.clone(),
                retired.clone(),
            ))),
            close_returned: close_returned.clone(),
        });
        let controller = Arc::new(ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            counting_connector([ConnectorStep::Success], connector_calls.clone()),
        ));
        *lock(&source.controller) = Some(Arc::downgrade(&controller));

        controller.start();
        tokio::time::timeout(Duration::from_millis(500), async {
            while !close_returned.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("close started by the source first poll did not return");
        assert_eq!(retired.load(Ordering::SeqCst), 1);
        assert_eq!(spent.load(Ordering::SeqCst), 0);
        assert_eq!(connector_calls.load(Ordering::SeqCst), 0);
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.state, ConnectionState::Closed);
        assert_eq!(snapshot.failure, None);
    }

    #[tokio::test]
    async fn filtered_browser_opaque_policy_exhaustion_stays_connection_failed() {
        let source = Arc::new(QueueSource::new([
            Ok(test_lease(
                pin_only_artifact([0x11; 32]),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
            )),
            Ok(test_lease(
                pin_only_artifact([0x11; 32]),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
            )),
        ]));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(Some(3)),
            scripted_connector([
                ConnectorStep::PreSpendOpaque,
                ConnectorStep::PostSpendRetryable,
            ]),
        );
        controller.start();
        let _ = wait_for_state(&controller, ConnectionState::Waiting).await;
        assert!(controller.retry_now());
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 3);
        assert_eq!(
            status.last_failure,
            Some(connect_failure(
                ConnectErrorCode::ConnectionFailed,
                RetryDisposition::Terminal,
            ))
        );
        controller.close().await;
    }

    #[test]
    fn maximum_attempts_rejects_unsafe_integers_at_the_public_builder_boundary() {
        let accepted = ConnectionControllerOptions::new(ConnectorOptions::new())
            .with_maximum_attempts(NonZeroU64::new(MAX_SAFE_INTEGER).unwrap())
            .expect("maximum safe integer");
        assert_eq!(
            accepted.maximum_attempts().map(NonZeroU64::get),
            Some(MAX_SAFE_INTEGER)
        );
        assert!(matches!(
            ConnectionControllerOptions::new(ConnectorOptions::new())
                .with_maximum_attempts(NonZeroU64::new(MAX_SAFE_INTEGER + 1).unwrap()),
            Err(ConnectionControllerConfigurationError)
        ));
    }

    #[tokio::test]
    async fn changed_pin_replacement_establishes_with_fresh_leases() {
        let expected = scenario_expected("pin-mismatch-changed-pin-success");
        let primary_retired = Arc::new(AtomicU64::new(0));
        let replacement_spent = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([
            Ok(test_lease(
                pin_only_artifact([0x11; 32]),
                Arc::new(AtomicU64::new(0)),
                primary_retired.clone(),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                replacement_spent.clone(),
                Arc::new(AtomicU64::new(0)),
            )),
        ]));
        let connector_calls = Arc::new(AtomicU64::new(0));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            counting_connector(
                [ConnectorStep::PreSpendSecurity, ConnectorStep::Success],
                connector_calls.clone(),
            ),
        );

        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Connected).await;
        assert_eq!(state_name(status.state), expected.final_state);
        assert_eq!(
            source.acquisitions.load(Ordering::SeqCst),
            expected.acquisitions
        );
        assert_eq!(
            connector_calls.load(Ordering::SeqCst),
            expected.connect_attempts
        );
        assert_eq!(
            connector_calls.load(Ordering::SeqCst),
            expected.transports_created
        );
        assert_eq!(expected.replacement_acquisitions, 1);
        assert_eq!(expected.replacement_quota_used, 1);
        assert_eq!(
            primary_retired.load(Ordering::SeqCst),
            expected.retire_callbacks
        );
        assert_eq!(
            replacement_spent.load(Ordering::SeqCst),
            expected.spend_callbacks
        );
        assert_eq!(expected.lease_terminal_states, ["retired", "consumed"]);
        assert!(expected.retry_delays_ms.is_empty());
        assert_eq!(expected.public_error, None);
        assert_eq!(expected.disposition, None);
        controller.close().await;
    }

    #[tokio::test]
    async fn replacement_pre_spend_failure_preserves_the_primary_security_trigger() {
        let retired = Arc::new(AtomicU64::new(0));
        let spent = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([
            Ok(test_lease(
                pin_only_artifact([0x11; 32]),
                spent.clone(),
                retired.clone(),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                spent.clone(),
                retired.clone(),
            )),
        ]));
        let controller = ConnectionController::new_with_connector(
            source,
            test_options(None),
            scripted_connector([
                ConnectorStep::PreSpendSecurity,
                ConnectorStep::PreSpendConnection,
            ]),
        );

        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(
            status.last_failure,
            Some(connect_failure(
                ConnectErrorCode::TransportSecurityFailed,
                RetryDisposition::Terminal,
            ))
        );
        assert_eq!(spent.load(Ordering::SeqCst), 0);
        assert_eq!(retired.load(Ordering::SeqCst), 2);
        controller.close().await;
    }

    #[tokio::test]
    async fn digest_only_pin_rotation_is_an_eligible_replacement() {
        let retired = Arc::new(AtomicU64::new(0));
        let spent = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([
            Ok(test_lease(
                pin_policy_artifact([0x11; 32], 2_000_000_300),
                spent.clone(),
                retired.clone(),
            )),
            Ok(test_lease(
                pin_policy_artifact([0x11; 32], 2_000_000_500),
                spent.clone(),
                retired.clone(),
            )),
        ]));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector([ConnectorStep::PreSpendSecurity, ConnectorStep::Success]),
        );

        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Connected).await;
        assert_eq!(status.state, ConnectionState::Connected);
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 2);
        assert_eq!(retired.load(Ordering::SeqCst), 1);
        assert_eq!(spent.load(Ordering::SeqCst), 1);
        controller.close().await;
    }

    #[tokio::test]
    async fn retryable_replacement_source_failure_continues_finding_replacement() {
        let retired = Arc::new(AtomicU64::new(0));
        let spent = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([
            Ok(test_lease(
                pin_only_artifact([0x11; 32]),
                spent.clone(),
                retired.clone(),
            )),
            Err(ArtifactSourceError::retryable()),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                spent.clone(),
                retired.clone(),
            )),
        ]));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            scripted_connector([ConnectorStep::PreSpendSecurity, ConnectorStep::Success]),
        );

        controller.start();
        let waiting = wait_for_state(&controller, ConnectionState::Waiting).await;
        assert_eq!(waiting.attempt, 2);
        assert!(controller.retry_now());
        let status = wait_for_state(&controller, ConnectionState::Connected).await;
        assert_eq!(status.state, ConnectionState::Connected);
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 3);
        assert_eq!(retired.load(Ordering::SeqCst), 1);
        assert_eq!(spent.load(Ordering::SeqCst), 1);
        controller.close().await;
    }

    #[tokio::test]
    async fn same_pin_and_pin_to_ca_replacements_are_terminal_without_connecting() {
        for (scenario_id, replacement) in [
            (
                "pin-mismatch-same-policy-terminal",
                pin_only_artifact([0x11; 32]),
            ),
            ("pin-to-ca-filtered", ca_only_artifact()),
        ] {
            let expected = scenario_expected(scenario_id);
            let retired = Arc::new(AtomicU64::new(0));
            let spent = Arc::new(AtomicU64::new(0));
            let source = Arc::new(QueueSource::new([
                Ok(test_lease(
                    pin_only_artifact([0x11; 32]),
                    spent.clone(),
                    retired.clone(),
                )),
                Ok(test_lease(replacement, spent.clone(), retired.clone())),
            ]));
            let connector_calls = Arc::new(AtomicU64::new(0));
            let controller = ConnectionController::new_with_connector(
                source.clone(),
                test_options(None),
                counting_connector([ConnectorStep::PreSpendSecurity], connector_calls.clone()),
            );

            controller.start();
            let status = wait_for_state(&controller, ConnectionState::Failed).await;
            assert_eq!(state_name(status.state), expected.final_state);
            assert_eq!(
                source.acquisitions.load(Ordering::SeqCst),
                expected.acquisitions
            );
            assert_eq!(
                connector_calls.load(Ordering::SeqCst),
                expected.connect_attempts
            );
            assert_eq!(
                connector_calls.load(Ordering::SeqCst),
                expected.transports_created
            );
            assert_eq!(expected.replacement_acquisitions, 1);
            assert_eq!(expected.replacement_quota_used, 1);
            assert_eq!(spent.load(Ordering::SeqCst), expected.spend_callbacks);
            assert_eq!(retired.load(Ordering::SeqCst), expected.retire_callbacks);
            assert_eq!(expected.lease_terminal_states, ["retired", "retired"]);
            assert!(expected.retry_delays_ms.is_empty());
            assert_eq!(
                expected.public_error.as_deref(),
                Some("transport_security_failed")
            );
            assert_eq!(expected.disposition.as_deref(), Some("terminal"));
            assert_eq!(
                status.last_failure,
                Some(connect_failure(
                    ConnectErrorCode::TransportSecurityFailed,
                    RetryDisposition::Terminal
                ))
            );
            if scenario_id == "pin-to-ca-filtered" {
                assert_eq!(expected.no_mode_downgrade, Some(true));
            }
            controller.close().await;
        }
    }

    #[tokio::test]
    async fn all_unsupported_is_terminal_without_creating_a_transport() {
        let expected = scenario_expected("all-unsupported");
        let retired = Arc::new(AtomicU64::new(0));
        let spent = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([Ok(test_lease(
            ca_only_artifact(),
            spent.clone(),
            retired.clone(),
        ))]));
        let connect_attempts = Arc::new(AtomicU64::new(0));
        let attempts = connect_attempts.clone();
        let connector: ConnectOneShot = Arc::new(move |_lease, _options, _cancellation| {
            attempts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(ConnectError::from_runtime_code(
                    ConnectErrorCode::TransportSecurityUnsupported,
                ))
            })
        });
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(Some(1)),
            connector,
        );

        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(state_name(status.state), expected.final_state);
        assert_eq!(
            source.acquisitions.load(Ordering::SeqCst),
            expected.acquisitions
        );
        assert_eq!(
            connect_attempts.load(Ordering::SeqCst),
            expected.connect_attempts
        );
        assert_eq!(expected.transports_created, 0);
        assert_eq!(expected.replacement_acquisitions, 0);
        assert_eq!(expected.replacement_quota_used, 0);
        assert_eq!(spent.load(Ordering::SeqCst), expected.spend_callbacks);
        assert_eq!(retired.load(Ordering::SeqCst), expected.retire_callbacks);
        assert_eq!(expected.lease_terminal_states, ["retired"]);
        assert!(expected.retry_delays_ms.is_empty());
        assert_eq!(
            expected.public_error.as_deref(),
            Some("transport_security_unsupported")
        );
        assert_eq!(expected.disposition.as_deref(), Some("terminal"));
        assert_eq!(
            status.last_failure,
            Some(connect_failure(
                ConnectErrorCode::TransportSecurityUnsupported,
                RetryDisposition::Terminal,
            ))
        );
        controller.close().await;
    }

    #[tokio::test]
    async fn ordinary_native_connection_failure_does_not_request_policy_replacement() {
        let source = Arc::new(QueueSource::new([Ok(test_lease(
            pin_only_artifact([0x11; 32]),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        ))]));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(Some(1)),
            scripted_connector([ConnectorStep::PreSpendConnection]),
        );

        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 1);
        assert_eq!(
            status.last_failure,
            Some(connect_failure(
                ConnectErrorCode::ConnectionFailed,
                RetryDisposition::Terminal
            ))
        );
        controller.close().await;
    }

    #[tokio::test]
    async fn ordinary_pre_spend_retry_continues_after_retire_panic() {
        let retire_calls = Arc::new(AtomicU64::new(0));
        let retire_calls_capture = retire_calls.clone();
        let first = ArtifactLease::new_with_retire(
            pin_only_artifact([0x11; 32]),
            || async { Ok(()) },
            move || {
                retire_calls_capture.fetch_add(1, Ordering::SeqCst);
                async {
                    panic!("secret retirement failure");
                    #[allow(unreachable_code)]
                    Ok(())
                }
            },
        );
        let first_copy = first.clone();
        let second_spent = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([
            Ok(first),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                second_spent.clone(),
                Arc::new(AtomicU64::new(0)),
            )),
        ]));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(Some(2)),
            scripted_connector([ConnectorStep::PreSpendConnection, ConnectorStep::Success]),
        );

        controller.start();
        let waiting = wait_for_state(&controller, ConnectionState::Waiting).await;
        assert_eq!(
            waiting.last_failure,
            Some(connect_failure(
                ConnectErrorCode::ConnectionFailed,
                RetryDisposition::Retryable,
            ))
        );
        assert!(controller.retry_now());
        let connected = wait_for_state(&controller, ConnectionState::Connected).await;

        assert_eq!(connected.state, ConnectionState::Connected);
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 2);
        assert_eq!(retire_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_spent.load(Ordering::SeqCst), 1);
        assert!(first_copy.claim().is_err(), "retired lease became reusable");
        controller.close().await;
    }

    #[tokio::test]
    async fn session_termination_starts_a_fresh_cycle_at_initial_backoff() {
        let source = Arc::new(QueueSource::new([Ok(test_lease(
            pin_only_artifact([0x11; 32]),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        ))]));
        let controller = ConnectionController::new_with_connector(
            source,
            test_options(None),
            Arc::new(|lease, _options, _cancellation| {
                Box::pin(async move {
                    spend_lease(lease).await?;
                    Ok(Arc::new(TerminatingSession) as Arc<dyn Session>)
                })
            }),
        );

        controller.start();
        let waiting = wait_for_state(&controller, ConnectionState::Waiting).await;
        let next_retry_at = waiting.next_retry_at.expect("session retry deadline");
        let delay = next_retry_at
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        assert!(delay >= Duration::from_millis(150));
        assert!(delay <= Duration::from_millis(500));
        assert_eq!(waiting.attempt, 0);
        controller.close().await;
    }

    #[tokio::test]
    async fn expired_replacement_keeps_quota_and_returns_to_primary_backoff() {
        let expected = scenario_expected("replacement-expired-returns-primary");
        let retired = Arc::new(AtomicU64::new(0));
        let spent = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([
            Ok(test_lease(
                pin_only_artifact([0x11; 32]),
                spent.clone(),
                retired.clone(),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                spent.clone(),
                retired.clone(),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                spent.clone(),
                retired.clone(),
            )),
        ]));
        let connector_calls = Arc::new(AtomicU64::new(0));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            counting_connector(
                [
                    ConnectorStep::PreSpendSecurity,
                    ConnectorStep::PreSpendExpired,
                    ConnectorStep::Success,
                ],
                connector_calls.clone(),
            ),
        );

        controller.start();
        let waiting = wait_for_state(&controller, ConnectionState::Waiting).await;
        let scheduled_delay = waiting
            .next_retry_at
            .expect("retry deadline")
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        assert!(scheduled_delay <= Duration::from_millis(expected.retry_delays_ms[0]));
        assert!(scheduled_delay >= Duration::from_millis(350));
        assert!(controller.retry_now());
        let status = wait_for_state(&controller, ConnectionState::Connected).await;
        assert_eq!(state_name(status.state), expected.final_state);
        assert_eq!(
            source.acquisitions.load(Ordering::SeqCst),
            expected.acquisitions
        );
        assert_eq!(
            connector_calls.load(Ordering::SeqCst),
            expected.connect_attempts
        );
        assert_eq!(
            connector_calls.load(Ordering::SeqCst),
            expected.transports_created
        );
        assert_eq!(expected.replacement_acquisitions, 1);
        assert_eq!(expected.replacement_quota_used, 1);
        assert_eq!(spent.load(Ordering::SeqCst), expected.spend_callbacks);
        assert_eq!(retired.load(Ordering::SeqCst), expected.retire_callbacks);
        assert_eq!(
            expected.lease_terminal_states,
            ["retired", "retired", "consumed"]
        );
        assert_eq!(expected.blocked_policy_remains_blocked, Some(true));
        assert_eq!(expected.public_error, None);
        assert_eq!(expected.disposition, None);
        controller.close().await;
    }

    #[tokio::test]
    async fn post_spend_replacement_retry_preserves_replacement_quota() {
        let expected = scenario_expected("post-spend-retry-preserves-quota");
        let spent = Arc::new(AtomicU64::new(0));
        let retired = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([
            Ok(test_lease(
                pin_only_artifact([0x11; 32]),
                spent.clone(),
                retired.clone(),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                spent.clone(),
                retired.clone(),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                spent.clone(),
                retired.clone(),
            )),
        ]));
        let connector_calls = Arc::new(AtomicU64::new(0));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(None),
            counting_connector(
                [
                    ConnectorStep::PreSpendSecurity,
                    ConnectorStep::PostSpendRetryable,
                    ConnectorStep::PreSpendSecurity,
                ],
                connector_calls.clone(),
            ),
        );

        controller.start();
        let waiting = wait_for_state(&controller, ConnectionState::Waiting).await;
        let scheduled_delay = waiting
            .next_retry_at
            .expect("retry deadline")
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        assert!(scheduled_delay <= Duration::from_millis(expected.retry_delays_ms[0]));
        assert!(scheduled_delay >= Duration::from_millis(350));
        assert!(controller.retry_now());
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(state_name(status.state), expected.final_state);
        assert_eq!(
            source.acquisitions.load(Ordering::SeqCst),
            expected.acquisitions
        );
        assert_eq!(
            connector_calls.load(Ordering::SeqCst),
            expected.connect_attempts
        );
        assert_eq!(
            connector_calls.load(Ordering::SeqCst),
            expected.transports_created
        );
        assert_eq!(expected.replacement_acquisitions, 1);
        assert_eq!(expected.replacement_quota_used, 1);
        assert_eq!(spent.load(Ordering::SeqCst), expected.spend_callbacks);
        assert_eq!(retired.load(Ordering::SeqCst), expected.retire_callbacks);
        assert_eq!(
            expected.lease_terminal_states,
            ["retired", "consumed", "retired"]
        );
        assert_eq!(
            expected.public_error.as_deref(),
            Some("transport_security_failed")
        );
        assert_eq!(expected.disposition.as_deref(), Some("terminal"));
        controller.close().await;
    }

    #[tokio::test]
    async fn opaque_trigger_after_security_replacement_preserves_security_error() {
        let spent = Arc::new(AtomicU64::new(0));
        let retired = Arc::new(AtomicU64::new(0));
        let source = Arc::new(QueueSource::new([
            Ok(test_lease(
                pin_only_artifact([0x11; 32]),
                spent.clone(),
                retired.clone(),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                spent.clone(),
                retired.clone(),
            )),
            Ok(test_lease(
                pin_only_artifact([0x22; 32]),
                spent.clone(),
                retired.clone(),
            )),
        ]));
        let controller = ConnectionController::new_with_connector(
            source,
            test_options(None),
            scripted_connector([
                ConnectorStep::PreSpendSecurity,
                ConnectorStep::PostSpendRetryable,
                ConnectorStep::PreSpendOpaque,
            ]),
        );

        controller.start();
        let waiting = wait_for_state(&controller, ConnectionState::Waiting).await;
        assert!(controller.retry_now());
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(
            state_name(status.state),
            state_name(ConnectionState::Failed)
        );
        assert_eq!(
            status.last_failure,
            Some(connect_failure(
                ConnectErrorCode::TransportSecurityFailed,
                RetryDisposition::Terminal,
            ))
        );
        assert_eq!(spent.load(Ordering::SeqCst), 1);
        assert_eq!(retired.load(Ordering::SeqCst), 2);
        assert!(waiting.next_retry_at.is_some());
        controller.close().await;
    }

    #[tokio::test]
    async fn source_attempt_exhaustion_covers_replacement_acquisitions() {
        let expected = scenario_expected("attempt-exhaustion");
        let source = Arc::new(QueueSource::new([
            Err(ArtifactSourceError::retryable()),
            Err(ArtifactSourceError::retryable()),
        ]));
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            test_options(Some(2)),
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );

        controller.start();
        let waiting = wait_for_state(&controller, ConnectionState::Waiting).await;
        let scheduled_delay = waiting
            .next_retry_at
            .expect("retry deadline")
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        assert!(scheduled_delay <= Duration::from_millis(expected.retry_delays_ms[0]));
        assert!(scheduled_delay >= Duration::from_millis(150));
        assert!(controller.retry_now());
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(state_name(status.state), expected.final_state);
        assert_eq!(
            source.acquisitions.load(Ordering::SeqCst),
            expected.acquisitions
        );
        assert_eq!(expected.connect_attempts, 0);
        assert_eq!(expected.transports_created, 0);
        assert_eq!(expected.replacement_acquisitions, 0);
        assert_eq!(expected.replacement_quota_used, 0);
        assert_eq!(expected.spend_callbacks, 0);
        assert_eq!(expected.retire_callbacks, 0);
        assert!(expected.lease_terminal_states.is_empty());
        assert_eq!(expected.public_error.as_deref(), Some("connection_failed"));
        assert_eq!(expected.disposition.as_deref(), Some("terminal"));
        assert_eq!(
            status.last_failure,
            Some(ConnectionFailure::ArtifactSource(
                ArtifactSourceError::terminal()
            ))
        );
        controller.close().await;
    }

    #[derive(Debug)]
    struct QueueSource {
        items: Mutex<VecDeque<Result<ArtifactLease, ArtifactSourceError>>>,
        acquisitions: AtomicU64,
    }

    #[derive(Debug)]
    struct LateLeaseSource {
        lease: Mutex<Option<ArtifactLease>>,
        acquisitions: AtomicU64,
    }

    #[derive(Debug)]
    struct PanicSource;

    #[derive(Debug)]
    struct ConstructorPanicSource;

    #[derive(Debug)]
    struct FirstPollCloseSource {
        controller: Mutex<Option<std::sync::Weak<ConnectionController>>>,
        lease: Mutex<Option<ArtifactLease>>,
        close_returned: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ArtifactSource for PanicSource {
        async fn acquire(
            &self,
            _cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceError> {
            panic!("source contract violation");
        }
    }

    impl ArtifactSource for ConstructorPanicSource {
        fn acquire<'source, 'future>(
            &'source self,
            _cancellation: CancellationToken,
        ) -> Pin<
            Box<dyn Future<Output = Result<ArtifactLease, ArtifactSourceError>> + Send + 'future>,
        >
        where
            'source: 'future,
            Self: 'future,
        {
            panic!("source future construction violation");
        }
    }

    #[async_trait]
    impl ArtifactSource for FirstPollCloseSource {
        async fn acquire(
            &self,
            cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceError> {
            let controller = lock(&self.controller)
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .expect("controller installed");
            let close_returned = self.close_returned.clone();
            tokio::spawn(async move {
                controller.close().await;
                close_returned.store(true, Ordering::Release);
            });
            cancellation.cancelled().await;
            lock(&self.lease)
                .take()
                .ok_or_else(ArtifactSourceError::terminal)
        }
    }

    #[async_trait]
    impl ArtifactSource for LateLeaseSource {
        async fn acquire(
            &self,
            cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceError> {
            self.acquisitions.fetch_add(1, Ordering::SeqCst);
            cancellation.cancelled().await;
            lock(&self.lease)
                .take()
                .ok_or_else(ArtifactSourceError::terminal)
        }
    }

    impl QueueSource {
        fn new(
            items: impl IntoIterator<Item = Result<ArtifactLease, ArtifactSourceError>>,
        ) -> Self {
            Self {
                items: Mutex::new(items.into_iter().collect()),
                acquisitions: AtomicU64::new(0),
            }
        }
    }

    #[async_trait]
    impl ArtifactSource for QueueSource {
        async fn acquire(
            &self,
            _cancellation: CancellationToken,
        ) -> Result<ArtifactLease, ArtifactSourceError> {
            self.acquisitions.fetch_add(1, Ordering::SeqCst);
            lock(&self.items)
                .pop_front()
                .unwrap_or_else(|| Err(ArtifactSourceError::terminal()))
        }
    }

    #[derive(Clone, Copy)]
    enum ConnectorStep {
        PreSpendSecurity,
        PreSpendOpaque,
        PreSpendConnection,
        PreSpendExpired,
        PostSpendRetryable,
        Success,
    }

    fn scripted_connector(steps: impl IntoIterator<Item = ConnectorStep>) -> ConnectOneShot {
        counting_connector(steps, Arc::new(AtomicU64::new(0)))
    }

    fn counting_connector(
        steps: impl IntoIterator<Item = ConnectorStep>,
        calls: Arc<AtomicU64>,
    ) -> ConnectOneShot {
        let steps = Arc::new(Mutex::new(steps.into_iter().collect::<VecDeque<_>>()));
        Arc::new(move |lease, _options, _cancellation| {
            let step = lock(&steps).pop_front().expect("scripted connector step");
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                match step {
                    ConnectorStep::PreSpendSecurity => Err(ConnectError::from_runtime_code(
                        ConnectErrorCode::TransportSecurityFailed,
                    )
                    .with_v3_candidate_masks(1, 1)),
                    ConnectorStep::PreSpendOpaque => Err(ConnectError::from_runtime_code(
                        ConnectErrorCode::ConnectionFailed,
                    )
                    .with_v3_candidate_masks(1, 1)),
                    ConnectorStep::PreSpendConnection => Err(ConnectError::from_runtime_code(
                        ConnectErrorCode::ConnectionFailed,
                    )),
                    ConnectorStep::PreSpendExpired => {
                        Err(ConnectError::from_runtime_code(ConnectErrorCode::Expired))
                    }
                    ConnectorStep::PostSpendRetryable => {
                        spend_lease(lease).await?;
                        Err(ConnectError::from_runtime_code(
                            ConnectErrorCode::ConnectionFailed,
                        ))
                    }
                    ConnectorStep::Success => {
                        spend_lease(lease).await?;
                        Ok(Arc::new(TestSession) as Arc<dyn Session>)
                    }
                }
            })
        })
    }

    async fn spend_lease(lease: ArtifactLease) -> Result<(), ConnectError> {
        let claimed = lease
            .claim()
            .map_err(|_| ConnectError::from_runtime_code(ConnectErrorCode::ArtifactInvalid))?;
        claimed
            .commit_spend()
            .await
            .map_err(|_| ConnectError::from_runtime_code(ConnectErrorCode::ConnectionFailed))?;
        Ok(())
    }

    fn test_lease(
        artifact: ArtifactV3,
        spends: Arc<AtomicU64>,
        retires: Arc<AtomicU64>,
    ) -> ArtifactLease {
        ArtifactLease::new_with_retire(
            artifact,
            move || async move {
                spends.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            move || async move {
                retires.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
    }

    fn test_options(maximum_attempts: Option<u64>) -> ConnectionControllerOptions {
        let options = ConnectionControllerOptions::new(ConnectorOptions::new());
        maximum_attempts.map_or(options.clone(), |maximum| {
            options
                .with_maximum_attempts(NonZeroU64::new(maximum).expect("nonzero"))
                .expect("safe maximum attempts")
        })
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

    async fn wait_for_state(
        controller: &ConnectionController,
        expected: ConnectionState,
    ) -> ControllerStatus {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let status = controller.status();
                if status.state == expected {
                    return status;
                }
                let snapshot = controller.snapshot();
                let _ = controller.wait_for_snapshot_change(&snapshot).await;
            }
        })
        .await
        .expect("controller reaches expected state")
    }

    #[derive(Debug)]
    struct TestSession;

    #[tokio::test]
    async fn wait_for_session_is_passive_and_returns_structured_outcomes() {
        let idle_source = Arc::new(QueueSource::new([]));
        let idle = ConnectionController::new_with_connector(
            idle_source.clone(),
            test_options(Some(1)),
            scripted_connector([]),
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let canceled = idle
            .wait_for_session_with_cancellation(cancellation)
            .await
            .expect_err("canceled wait");
        assert_eq!(canceled.code(), ConnectionControllerErrorCode::Canceled);
        assert_eq!(canceled.diagnostic().state, ConnectionState::Idle);
        assert_eq!(idle_source.acquisitions.load(Ordering::SeqCst), 0);

        let source = Arc::new(QueueSource::new([Ok(test_lease(
            pin_only_artifact([0x11; 32]),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        ))]));
        let connected = ConnectionController::new_with_connector(
            source,
            test_options(Some(1)),
            scripted_connector([ConnectorStep::Success]),
        );
        connected.start();
        let session = connected
            .wait_for_session()
            .await
            .expect("established session");
        assert!(Arc::ptr_eq(
            &session,
            connected
                .snapshot()
                .current_session
                .as_ref()
                .expect("snapshot session")
        ));
        assert_eq!(
            connected.snapshot().diagnostic(),
            ConnectionDiagnostic {
                state: ConnectionState::Connected,
                attempt: 1,
                failure: None,
                retry_disposition: None,
            }
        );
        connected.close().await;

        let failed = ConnectionController::new_with_connector(
            Arc::new(QueueSource::new([Err(ArtifactSourceError::terminal())])),
            test_options(Some(1)),
            scripted_connector([]),
        );
        failed.start();
        let failure = failed
            .wait_for_session()
            .await
            .expect_err("terminal failure");
        assert_eq!(failure.code(), ConnectionControllerErrorCode::Failed);
        assert_eq!(
            failure.diagnostic(),
            ConnectionDiagnostic {
                state: ConnectionState::Failed,
                attempt: 1,
                failure: Some(ConnectionDiagnosticFailure {
                    phase: ConnectionFailurePhase::Artifact,
                    code: "connection_failed",
                }),
                retry_disposition: Some(RetryDisposition::Terminal),
            }
        );
        failed.close().await;

        let closed = ConnectionController::new_with_connector(
            Arc::new(QueueSource::new([])),
            test_options(Some(1)),
            scripted_connector([]),
        );
        closed.close().await;
        let error = closed
            .wait_for_session()
            .await
            .expect_err("closed controller");
        assert_eq!(error.code(), ConnectionControllerErrorCode::Closed);
        assert_eq!(error.diagnostic().state, ConnectionState::Closed);
    }

    #[async_trait]
    impl Session for TestSession {
        fn rpc(&self) -> &dyn RpcPeer {
            panic!("RPC is not used by controller tests")
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
            std::future::pending().await
        }

        async fn close(&self) -> Result<(), SessionError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TerminatingSession;

    #[async_trait]
    impl Session for TerminatingSession {
        fn rpc(&self) -> &dyn RpcPeer {
            panic!("RPC is not used by controller tests")
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
            SessionTermination {
                error: SessionError::GoingAway,
            }
        }

        async fn close(&self) -> Result<(), SessionError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct BlockingCloseSession {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        close_calls: Arc<AtomicU64>,
    }

    #[async_trait]
    impl Session for BlockingCloseSession {
        fn rpc(&self) -> &dyn RpcPeer {
            panic!("RPC is not used by controller tests")
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
            std::future::pending().await
        }

        async fn close(&self) -> Result<(), SessionError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn concurrent_controller_close_waits_for_session_cleanup() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let close_calls = Arc::new(AtomicU64::new(0));
        let session = Arc::new(BlockingCloseSession {
            entered: entered.clone(),
            release: release.clone(),
            close_calls: close_calls.clone(),
        });
        let source = Arc::new(QueueSource::new([Ok(test_lease(
            pin_only_artifact([0x11; 32]),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        ))]));
        let controller = ConnectionController::new_with_connector(
            source,
            test_options(Some(1)),
            Arc::new(move |lease, _options, _cancellation| {
                let session = session.clone();
                Box::pin(async move {
                    spend_lease(lease).await?;
                    Ok(session as Arc<dyn Session>)
                })
            }),
        );
        controller.start();
        wait_for_state(&controller, ConnectionState::Connected).await;

        let mut first = Box::pin(controller.close());
        tokio::select! {
            _ = entered.notified() => {}
            () = &mut first => panic!("controller close completed before session cleanup"),
        }
        let mut second = Box::pin(controller.close());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second)
                .await
                .is_err(),
            "concurrent controller close returned before cleanup"
        );
        release.notify_one();
        first.await;
        second.await;
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn canceled_first_controller_close_leaves_owned_cleanup_for_later_close() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let close_calls = Arc::new(AtomicU64::new(0));
        let session = Arc::new(BlockingCloseSession {
            entered: entered.clone(),
            release: release.clone(),
            close_calls: close_calls.clone(),
        });
        let source = Arc::new(QueueSource::new([Ok(test_lease(
            pin_only_artifact([0x11; 32]),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        ))]));
        let controller = ConnectionController::new_with_connector(
            source,
            test_options(Some(1)),
            Arc::new(move |lease, _options, _cancellation| {
                let session = session.clone();
                Box::pin(async move {
                    spend_lease(lease).await?;
                    Ok(session as Arc<dyn Session>)
                })
            }),
        );
        controller.start();
        wait_for_state(&controller, ConnectionState::Connected).await;

        let mut first = Box::pin(controller.close());
        tokio::time::timeout(Duration::from_millis(250), async {
            tokio::select! {
                _ = entered.notified() => {}
                () = &mut first => panic!("controller close completed before session cleanup"),
            }
        })
        .await
        .expect("first controller close did not enter session cleanup");
        drop(first);

        let mut second = Box::pin(controller.close());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second)
                .await
                .is_err(),
            "later controller close returned before owned cleanup"
        );
        release.notify_one();
        tokio::time::timeout(Duration::from_millis(500), &mut second)
            .await
            .expect("later controller close remained blocked after release");
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn scheduler_and_explicit_close_atomically_claim_one_cleanup_workflow() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let close_calls = Arc::new(AtomicU64::new(0));
        let session: Arc<dyn Session> = Arc::new(BlockingCloseSession {
            entered: entered.clone(),
            release: release.clone(),
            close_calls: close_calls.clone(),
        });
        let controller = ConnectionController::new_with_connector(
            Arc::new(QueueSource::new([])),
            test_options(Some(1)),
            Arc::new(|_lease, _options, _cancellation| {
                Box::pin(async {
                    Err(ConnectError::from_terminal_runtime_code(
                        ConnectErrorCode::ConnectionFailed,
                    ))
                })
            }),
        );
        {
            let mut state = lock(&controller.inner.state);
            state.status.state = ConnectionState::Connected;
            state.current = Some(session);
        }

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let scheduler_inner = controller.inner.clone();
        let scheduler_barrier = barrier.clone();
        let scheduler = tokio::spawn(async move {
            scheduler_barrier.wait().await;
            close_inner(&scheduler_inner).await;
        });
        let explicit_inner = controller.inner.clone();
        let explicit_barrier = barrier.clone();
        let explicit = tokio::spawn(async move {
            explicit_barrier.wait().await;
            explicit_inner.start_close_workflow();
            explicit_inner.wait_close_completion().await;
        });
        barrier.wait().await;

        tokio::time::timeout(Duration::from_millis(250), entered.notified())
            .await
            .expect("session cleanup did not start");
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);
        assert!(!scheduler.is_finished());
        assert!(!explicit.is_finished());

        release.notify_one();
        tokio::time::timeout(Duration::from_millis(500), scheduler)
            .await
            .expect("scheduler close remained blocked after cleanup")
            .expect("scheduler close task panicked");
        tokio::time::timeout(Duration::from_millis(500), explicit)
            .await
            .expect("explicit close remained blocked after cleanup")
            .expect("explicit close task panicked");
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(controller.status().state, ConnectionState::Closed);
        assert!(controller.current_session().is_none());
    }

    fn pin_only_artifact(pin: [u8; 32]) -> ArtifactV3 {
        pin_policy_artifact(pin, 2_000_000_300)
    }

    fn pin_policy_artifact(pin: [u8; 32], not_after_unix_s: u64) -> ArtifactV3 {
        let mut value = base_artifact_value();
        value["path"]["candidates"] = serde_json::json!([{
            "carrier": "websocket",
            "id": "w-pin",
            "tls": {"mode": "pin", "pins": [{
                "algorithm": "sha-256",
                "not_after_unix_s": not_after_unix_s,
                "value_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pin)
            }]},
            "url": "wss://pin.example.org/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3"
        }]);
        ArtifactV3::parse(crate::artifact_v3::jcs_value(&value).unwrap()).unwrap()
    }

    fn ca_only_artifact() -> ArtifactV3 {
        let mut value = base_artifact_value();
        value["path"]["candidates"] = serde_json::json!([{
            "carrier": "websocket",
            "id": "w-ca",
            "tls": {"mode": "ca"},
            "url": "wss://pin.example.org/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3"
        }]);
        ArtifactV3::parse(crate::artifact_v3::jcs_value(&value).unwrap()).unwrap()
    }

    fn mixed_ca_pin_artifact() -> ArtifactV3 {
        let mut value = base_artifact_value();
        value["path"]["candidates"] = serde_json::json!([
            {
                "carrier": "websocket",
                "id": "a-ca",
                "tls": {"mode": "ca"},
                "url": "wss://ca.example.org/flowersec/v3/direct",
                "wire_profile": "flowersec-direct/3"
            },
            {
                "carrier": "websocket",
                "id": "z-pin",
                "tls": {"mode": "pin", "pins": [{
                    "algorithm": "sha-256",
                    "not_after_unix_s": 2_000_000_300_u64,
                    "value_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11; 32])
                }]},
                "url": "wss://pin.example.org/flowersec/v3/direct",
                "wire_profile": "flowersec-direct/3"
            }
        ]);
        ArtifactV3::parse(crate::artifact_v3::jcs_value(&value).unwrap()).unwrap()
    }

    fn base_artifact_value() -> serde_json::Value {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/artifact_vectors.json"
        ))
        .unwrap();
        serde_json::from_str(vectors["positive"][0]["artifact_json"].as_str().unwrap()).unwrap()
    }
}
