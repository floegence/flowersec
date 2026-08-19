//! Long-lived Flowersec v3 connection ownership and policy refresh.

use std::{
    collections::HashSet,
    fmt,
    future::Future,
    num::NonZeroU64,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use tokio::{
    sync::{Mutex as AsyncMutex, Notify},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    ArtifactLeaseV3, ConnectError, ConnectErrorCode, ConnectorOptions, SessionError,
    artifact_v3::{ArtifactV3, ClaimedArtifactLeaseV3, TlsPolicyWireV3},
    connector_v3::connect_v3_with_cancellation,
    transport_v2::Session,
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
    dyn Fn(ArtifactLeaseV3, ConnectorOptions, CancellationToken) -> ConnectFuture
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
}

impl ArtifactSourceError {
    pub const fn terminal() -> Self {
        Self {
            disposition: RetryDisposition::Terminal,
        }
    }
    pub const fn retryable() -> Self {
        Self {
            disposition: RetryDisposition::Retryable,
        }
    }
    pub const fn retry_after(not_before_unix_milliseconds: u64) -> Self {
        Self {
            disposition: RetryDisposition::RetryAfter(not_before_unix_milliseconds),
        }
    }
    pub const fn disposition(self) -> RetryDisposition {
        self.disposition
    }
}

#[async_trait]
pub trait ArtifactSource: fmt::Debug + Send + Sync + 'static {
    async fn acquire(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ArtifactLeaseV3, ArtifactSourceError>;
}

#[derive(Clone, Debug)]
pub struct ConnectionControllerOptions {
    connector: ConnectorOptions,
    maximum_attempts: Option<NonZeroU64>,
}

impl ConnectionControllerOptions {
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
    pub const fn disposition(self) -> RetryDisposition {
        match self {
            Self::ArtifactSource(error) => error.disposition(),
            Self::Connect { disposition, .. } | Self::Session { disposition, .. } => disposition,
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
            }),
            task: Mutex::new(None),
            close_lock: AsyncMutex::new(()),
        }
    }

    pub fn start(&self) {
        let runtime = tokio::runtime::Handle::current();
        let mut task = lock(&self.task);
        if task.is_some() || self.inner.status().state == ConnectionState::Closed {
            return;
        }
        *task = Some(runtime.spawn(run_controller(self.inner.clone())));
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        self.inner.snapshot()
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
    fn finish_closed(&self) -> Option<Arc<dyn Session>> {
        let current = {
            let mut state = lock(&self.state);
            if state.status.state == ConnectionState::Closed {
                return None;
            }
            state.status.state = ConnectionState::Closed;
            state.status.next_retry_at = None;
            state.status.retry_not_before = None;
            state.status.revision = state.status.revision.saturating_add(1);
            state.current.take()
        };
        self.changed.notify_waiters();
        current
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

fn policy_identity(artifact: &ArtifactV3, error: ConnectError) -> PolicyIdentity {
    let path = artifact.path_kind_for_controller();
    let candidates = artifact.canonical_candidates();
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
    if inner
        .options
        .maximum_attempts
        .is_some_and(|maximum| maximum.get() > MAX_SAFE_INTEGER)
    {
        inner.set_failed(
            0,
            connect_failure(
                ConnectErrorCode::ArtifactInvalid,
                RetryDisposition::Terminal,
            ),
            false,
        );
        return;
    }
    let mut attempt = 0_u64;
    let mut retry_index = 0_u64;
    let mut attempts_in_cycle = 0_u64;
    let mut replacement_used = false;
    let mut blocked_pin_policy = HashSet::new();
    loop {
        if inner.cancellation.is_cancelled() {
            close_inner(&inner).await;
            return;
        }
        attempt = increment_safe_counter(attempt);
        attempts_in_cycle = increment_safe_counter(attempts_in_cycle);
        if !inner.set_connecting(attempt) {
            return;
        }
        let claimed = match acquire_lease(&inner).await {
            Ok(claimed) => claimed,
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
                    ConnectErrorCode::TransportSecurityFailed,
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
                    blocked_pin_policy.extend(trigger.pins.iter().cloned());
                    let _ = claimed.retire().await;
                    if replacement_used {
                        inner.set_failed(
                            attempt,
                            connect_failure(error.code(), RetryDisposition::Terminal),
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
        if !schedule_retry(&inner, attempt, 0, 0, failure).await {
            return;
        }
        attempt = 0;
        retry_index = 1;
    }
}

async fn acquire_lease(
    inner: &ControllerInner,
) -> Result<ClaimedArtifactLeaseV3, ConnectionFailure> {
    let mut acquisition = Box::pin(inner.source.acquire(inner.cancellation.child_token()));
    let result = tokio::select! {
        biased;
        _ = inner.cancellation.cancelled() => {
            if let Ok(lease) = acquisition.await
                && let Ok(claimed) = lease.claim_for_controller()
            {
                let _ = claimed.retire().await;
            }
            return Err(connect_failure(
                ConnectErrorCode::ConnectionFailed,
                RetryDisposition::Terminal,
            ));
        },
        result = &mut acquisition => result,
    };
    let lease = result.map_err(|error| match error.disposition() {
        RetryDisposition::RetryAfter(deadline) if !valid_retry_after(deadline) => connect_failure(
            ConnectErrorCode::ArtifactInvalid,
            RetryDisposition::Terminal,
        ),
        _ => ConnectionFailure::ArtifactSource(error),
    })?;
    lease.claim_for_controller().map_err(|_| {
        connect_failure(
            ConnectErrorCode::ArtifactInvalid,
            RetryDisposition::Terminal,
        )
    })
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
        if !inner.set_connecting(*status_attempt) {
            return ReplacementResult::Stopped;
        }
        match acquire_lease(inner).await {
            Ok(claimed) => break claimed,
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
        Err(error) => {
            let _ = claimed.retire().await;
            ReplacementResult::Terminal(error.code())
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

async fn close_inner(inner: &ControllerInner) {
    if let Some(session) = inner.finish_closed() {
        let _ = session.close().await;
    }
}

const fn connect_failure(
    code: ConnectErrorCode,
    disposition: RetryDisposition,
) -> ConnectionFailure {
    ConnectionFailure::Connect { code, disposition }
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
    use crate::transport_v2::{
        ByteStream, IncomingStream, RpcPeer, SessionTermination, StreamMetadata,
    };

    #[derive(Deserialize)]
    struct ControllerVectorsV3 {
        version: u64,
        public_errors: Vec<String>,
        defaults: DefaultsV3,
        backoff_vectors: Vec<BackoffV3>,
        scenarios: Vec<ScenarioV3>,
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
            | "retry-clock-boundary"
            | "candidate-security-aggregation"
            | "multi-trigger-replacement"
            | "retire-cleanup"
            | "quota-preservation"
            | "attempt-saturation"
            | "capability-barrier"
            | "admission-spend-boundary"
            | "duplicate-lease-identity" => {}
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
            assert_eq!(scenario.driver, "attempt-saturation");
            assert!(attempt > 0);
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
                "failure-ordinal" | "cycle-reset"
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
    }

    #[test]
    fn retry_after_requires_nonnegative_integer_milliseconds_within_rfc3339_range() {
        assert!(valid_retry_after(0));
        assert!(valid_retry_after(253_402_300_799_999));
        assert!(!valid_retry_after(253_402_300_800_000));
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
            Some(connect_failure(
                ConnectErrorCode::ArtifactInvalid,
                RetryDisposition::Terminal
            ))
        );
        controller.close().await;

        let source = Arc::new(QueueSource::new(std::iter::empty()));
        let options = ConnectionControllerOptions::new(ConnectorOptions::new())
            .with_maximum_attempts(NonZeroU64::new(MAX_SAFE_INTEGER + 1).unwrap());
        let controller = ConnectionController::new_with_connector(
            source.clone(),
            options,
            scripted_connector(std::iter::empty::<ConnectorStep>()),
        );
        controller.start();
        let status = wait_for_state(&controller, ConnectionState::Failed).await;
        assert_eq!(source.acquisitions.load(Ordering::SeqCst), 0);
        assert_eq!(status.attempt, 0);
        controller.close().await;
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
        items: Mutex<VecDeque<Result<ArtifactLeaseV3, ArtifactSourceError>>>,
        acquisitions: AtomicU64,
    }

    #[derive(Debug)]
    struct LateLeaseSource {
        lease: Mutex<Option<ArtifactLeaseV3>>,
        acquisitions: AtomicU64,
    }

    #[async_trait]
    impl ArtifactSource for LateLeaseSource {
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

    impl QueueSource {
        fn new(
            items: impl IntoIterator<Item = Result<ArtifactLeaseV3, ArtifactSourceError>>,
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
        ) -> Result<ArtifactLeaseV3, ArtifactSourceError> {
            self.acquisitions.fetch_add(1, Ordering::SeqCst);
            lock(&self.items)
                .pop_front()
                .unwrap_or_else(|| Err(ArtifactSourceError::terminal()))
        }
    }

    #[derive(Clone, Copy)]
    enum ConnectorStep {
        PreSpendSecurity,
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

    async fn spend_lease(lease: ArtifactLeaseV3) -> Result<(), ConnectError> {
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
    ) -> ArtifactLeaseV3 {
        ArtifactLeaseV3::new_with_retire(
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
            options.with_maximum_attempts(NonZeroU64::new(maximum).expect("nonzero"))
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
    struct BlockingCloseSession {
        entered: Arc<Notify>,
        release: Arc<Notify>,
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
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn concurrent_controller_close_waits_for_session_cleanup() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let session = Arc::new(BlockingCloseSession {
            entered: entered.clone(),
            release: release.clone(),
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
