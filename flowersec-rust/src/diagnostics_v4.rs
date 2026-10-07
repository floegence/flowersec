//! Bounded, opt-in diagnostic observations with an independent callback lane.
use crate::environment_v4::EnvironmentCharge;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::VecDeque,
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant as MonotonicInstant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const BUCKET_SECONDS: u64 = 15 * 60;
const MAX_IDS: usize = 1024;
const MAX_EVENTS: usize = 4096;
const MAX_EVENT_BYTES: usize = 512;
const MAX_QUEUE_BYTES: usize = 2 * 1024 * 1024;
const CLEANUP_BOUND: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticState {
    Started,
    Succeeded,
    Failed,
    Canceled,
    Closed,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticAttemptBucket {
    One,
    TwoToThree,
    FourToSeven,
    EightOrMore,
    Other,
}
impl DiagnosticAttemptBucket {
    fn ordinal(value: u32) -> Self {
        match value {
            1 => Self::One,
            2..=3 => Self::TwoToThree,
            4..=7 => Self::FourToSeven,
            8.. => Self::EightOrMore,
            _ => Self::Other,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticPhase {
    Connect,
    Authenticate,
    Store,
    Rekey,
    RekeyPrepare,
    RekeyCommit,
    RekeyConfirm,
    Publish,
    Application,
    Session,
    Serve,
    Accept,
    Close,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticCode {
    None,
    Timeout,
    ResourceRejected,
    StoreUnavailable,
    IdentityRejected,
    TlsRejected,
    ReservationConflict,
    Canceled,
    Closed,
    SpendUnknown,
    SlowConsumer,
    Protocol,
    DatagramCurrent,
    DatagramOld,
    DatagramFuture,
    RekeyTimeout,
    CleanupTimeout,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticRetryDisposition {
    None,
    Retry,
    DoNotRetry,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticDurationBucket {
    Under10Ms,
    Ms10To99,
    Ms100To999,
    S1To9,
    AtLeast10S,
    Other,
}
impl DiagnosticDurationBucket {
    fn elapsed(value: Duration) -> Self {
        match value.as_millis() {
            0..=9 => Self::Under10Ms,
            10..=99 => Self::Ms10To99,
            100..=999 => Self::Ms100To999,
            1000..=9999 => Self::S1To9,
            _ => Self::AtLeast10S,
        }
    }
}
/// The complete detailed event projection; identifiers and error text are never included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticEvent {
    pub state: DiagnosticState,
    pub attempt_bucket: DiagnosticAttemptBucket,
    pub phase: DiagnosticPhase,
    pub code: DiagnosticCode,
    pub retry_disposition: DiagnosticRetryDisposition,
    pub duration_bucket: DiagnosticDurationBucket,
    pub correlation_id: [u8; 16],
}
impl DiagnosticEvent {
    fn encoded_bytes(self) -> usize {
        // Conservative bound for all seven finite fields encoded as JSON,
        // including a 32-character hexadecimal bytes16 correlation value.
        384
    }
}
pub type DiagnosticCallback = Arc<dyn Fn(DiagnosticEvent) + Send + Sync + 'static>;
pub type CancellableDiagnosticCallback =
    Arc<dyn Fn(DiagnosticEvent, CancellationToken) + Send + Sync + 'static>;

/// Configuration for production events from this Environment. Detailed events
/// remain disabled unless this configuration is supplied explicitly.
#[derive(Clone)]
pub struct DiagnosticSinkConfiguration {
    pub options: DiagnosticSinkOptions,
    pub callback: CancellableDiagnosticCallback,
}
impl fmt::Debug for DiagnosticSinkConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticSinkConfiguration")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}
impl DiagnosticSinkConfiguration {
    pub fn new(callback: DiagnosticCallback) -> Self {
        Self {
            options: DiagnosticSinkOptions::default(),
            callback: Arc::new(move |event, _| callback(event)),
        }
    }
    pub fn cancellable(callback: CancellableDiagnosticCallback) -> Self {
        Self {
            options: DiagnosticSinkOptions::default(),
            callback,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticSinkOptions {
    /// Sampling probability in basis points, in the inclusive range 0..=100.
    pub sampling_basis_points: u16,
}
impl Default for DiagnosticSinkOptions {
    fn default() -> Self {
        Self {
            sampling_basis_points: 100,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiagnosticSinkError {
    #[error("diagnostic sampling must be between 0 and 100 basis points")]
    InvalidSampling,
    #[error("diagnostic sink is closed")]
    Closed,
    #[error("diagnostic sink capacity is exhausted")]
    Capacity,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticCleanupStatus {
    pub complete: bool,
    pub cleanup_incomplete: bool,
    pub pending_callbacks: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticCounts {
    pub dropped_events: u64,
    pub cleanup_timeouts: u64,
}

/// Finite unsampled counters. No peer, tenant, Session or operation labels exist.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportDiagnosticCounts {
    pub connect_attempts: u64,
    pub connect_failures: u64,
    pub tls_failures: u64,
    pub identity_failures: u64,
    pub spend_unknown: u64,
    pub store_failures: u64,
    pub reservation_conflicts: u64,
    pub resource_rejections: u64,
    pub slow_consumers: u64,
    pub rekey_starts: u64,
    pub rekey_successes: u64,
    pub rekey_timeouts: u64,
    pub current_datagram_drops: u64,
    pub old_datagram_drops: u64,
    pub future_datagram_drops: u64,
    pub diagnostic_drops: u64,
    pub cleanup_timeouts: u64,
}
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum DiagnosticMetric {
    ConnectAttempts,
    ConnectFailures,
    TlsFailures,
    IdentityFailures,
    SpendUnknown,
    StoreFailures,
    ReservationConflicts,
    ResourceRejections,
    SlowConsumers,
    RekeyStarts,
    RekeySuccesses,
    RekeyTimeouts,
    CurrentDatagramDrops,
    OldDatagramDrops,
    FutureDatagramDrops,
    DiagnosticDrops,
    CleanupTimeouts,
    ApplicationOperations,
    ApplicationFailures,
    ApplicationCompleted,
    ConnectSuccesses,
    RekeyPhaseCompleted,
    Other,
}
pub(crate) type DiagnosticCounter = DiagnosticMetric;
const METRIC_COUNT: usize = DiagnosticMetric::Other as usize + 1;
const STATE_COUNT: usize = DiagnosticState::Other as usize + 1;
const PHASE_COUNT: usize = DiagnosticPhase::Other as usize + 1;
const CODE_COUNT: usize = DiagnosticCode::Other as usize + 1;
const DURATION_COUNT: usize = DiagnosticDurationBucket::Other as usize + 1;
const ATTEMPT_COUNT: usize = DiagnosticAttemptBucket::Other as usize + 1;
/// Fixed marginal counts for a single finite metric. This is not a cross-product
/// map, and no correlation ID or caller-provided label can enter the registry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiagnosticMetricCounts {
    pub total: u64,
    states: [u64; STATE_COUNT],
    phases: [u64; PHASE_COUNT],
    codes: [u64; CODE_COUNT],
    durations: [u64; DURATION_COUNT],
    attempts: [u64; ATTEMPT_COUNT],
}
impl DiagnosticMetricCounts {
    pub fn state(&self, value: DiagnosticState) -> u64 {
        self.states[value as usize]
    }
    pub fn phase(&self, value: DiagnosticPhase) -> u64 {
        self.phases[value as usize]
    }
    pub fn code(&self, value: DiagnosticCode) -> u64 {
        self.codes[value as usize]
    }
    pub fn duration(&self, value: DiagnosticDurationBucket) -> u64 {
        self.durations[value as usize]
    }
    pub fn attempt(&self, value: DiagnosticAttemptBucket) -> u64 {
        self.attempts[value as usize]
    }
}
#[derive(Debug, Default)]
struct CounterRow {
    total: AtomicU64,
    states: [AtomicU64; STATE_COUNT],
    phases: [AtomicU64; PHASE_COUNT],
    codes: [AtomicU64; CODE_COUNT],
    durations: [AtomicU64; DURATION_COUNT],
    attempts: [AtomicU64; ATTEMPT_COUNT],
}
#[derive(Debug, Default)]
pub(crate) struct DiagnosticCounters([CounterRow; METRIC_COUNT]);
fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(value))
    });
}
impl DiagnosticCounters {
    pub(crate) fn increment(&self, counter: DiagnosticCounter) {
        self.increment_by(counter, 1);
    }
    fn increment_by(&self, counter: DiagnosticCounter, count: u64) {
        let (phase, code) = match counter {
            DiagnosticMetric::TlsFailures => {
                (DiagnosticPhase::Connect, DiagnosticCode::TlsRejected)
            }
            DiagnosticMetric::IdentityFailures => (
                DiagnosticPhase::Authenticate,
                DiagnosticCode::IdentityRejected,
            ),
            DiagnosticMetric::StoreFailures => {
                (DiagnosticPhase::Store, DiagnosticCode::StoreUnavailable)
            }
            DiagnosticMetric::SpendUnknown => {
                (DiagnosticPhase::Store, DiagnosticCode::SpendUnknown)
            }
            DiagnosticMetric::ReservationConflicts => {
                (DiagnosticPhase::Store, DiagnosticCode::ReservationConflict)
            }
            DiagnosticMetric::ResourceRejections => {
                (DiagnosticPhase::Other, DiagnosticCode::ResourceRejected)
            }
            DiagnosticMetric::SlowConsumers => {
                (DiagnosticPhase::Application, DiagnosticCode::SlowConsumer)
            }
            DiagnosticMetric::RekeyTimeouts => {
                (DiagnosticPhase::Rekey, DiagnosticCode::RekeyTimeout)
            }
            DiagnosticMetric::CleanupTimeouts => {
                (DiagnosticPhase::Close, DiagnosticCode::CleanupTimeout)
            }
            DiagnosticMetric::CurrentDatagramDrops => (
                DiagnosticPhase::Application,
                DiagnosticCode::DatagramCurrent,
            ),
            DiagnosticMetric::OldDatagramDrops => {
                (DiagnosticPhase::Application, DiagnosticCode::DatagramOld)
            }
            DiagnosticMetric::FutureDatagramDrops => {
                (DiagnosticPhase::Application, DiagnosticCode::DatagramFuture)
            }
            _ => (DiagnosticPhase::Other, DiagnosticCode::Other),
        };
        self.observe(
            counter,
            count,
            DiagnosticState::Other,
            phase,
            code,
            DiagnosticDurationBucket::Other,
            DiagnosticAttemptBucket::Other,
        );
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Each argument is an independent bounded diagnostic dimension; no dynamic event fields are accepted."
    )]
    pub(crate) fn observe(
        &self,
        metric: DiagnosticMetric,
        count: u64,
        state: DiagnosticState,
        phase: DiagnosticPhase,
        code: DiagnosticCode,
        duration: DiagnosticDurationBucket,
        attempt: DiagnosticAttemptBucket,
    ) {
        let row = &self.0[metric as usize];
        add(&row.total, count);
        add(&row.states[state as usize], count);
        add(&row.phases[phase as usize], count);
        add(&row.codes[code as usize], count);
        add(&row.durations[duration as usize], count);
        add(&row.attempts[attempt as usize], count);
    }
    pub(crate) fn metric(&self, metric: DiagnosticMetric) -> DiagnosticMetricCounts {
        let row = &self.0[metric as usize];
        DiagnosticMetricCounts {
            total: row.total.load(Ordering::Relaxed),
            states: row.states.each_ref().map(|v| v.load(Ordering::Relaxed)),
            phases: row.phases.each_ref().map(|v| v.load(Ordering::Relaxed)),
            codes: row.codes.each_ref().map(|v| v.load(Ordering::Relaxed)),
            durations: row.durations.each_ref().map(|v| v.load(Ordering::Relaxed)),
            attempts: row.attempts.each_ref().map(|v| v.load(Ordering::Relaxed)),
        }
    }
    pub(crate) fn snapshot(&self) -> TransportDiagnosticCounts {
        let values = self
            .0
            .each_ref()
            .map(|row| row.total.load(Ordering::Relaxed));
        TransportDiagnosticCounts {
            connect_attempts: values[0],
            connect_failures: values[1],
            tls_failures: values[2],
            identity_failures: values[3],
            spend_unknown: values[4],
            store_failures: values[5],
            reservation_conflicts: values[6],
            resource_rejections: values[7],
            slow_consumers: values[8],
            rekey_starts: values[9],
            rekey_successes: values[10],
            rekey_timeouts: values[11],
            current_datagram_drops: values[12],
            old_datagram_drops: values[13],
            future_datagram_drops: values[14],
            diagnostic_drops: values[15],
            cleanup_timeouts: values[16],
        }
    }
}

struct ObservationState {
    id: Mutex<Option<[u8; 16]>>,
}
struct QueueState {
    bucket: u64,
    ids: usize,
    events: usize,
    queue_bytes: usize,
    closed: bool,
    closed_at: Option<MonotonicInstant>,
    worker_done: bool,
    maintenance_done: bool,
    releasing: bool,
    physically_released: bool,
    running: usize,
    active_cancel: Option<CancellationToken>,
    queue: VecDeque<DiagnosticEvent>,
    live: Vec<Weak<ObservationState>>,
}
#[cfg(test)]
type RandomSource = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

pub(crate) struct Inner {
    state: Mutex<QueueState>,
    wake: Condvar,
    changed: Notify,
    callback: Mutex<Option<CancellableDiagnosticCallback>>,
    sampling_basis_points: u16,
    dropped_events: AtomicU64,
    cleanup_timeouts: AtomicU64,
    timeout_reported: AtomicBool,
    counters: Arc<DiagnosticCounters>,
    charge: Mutex<Option<EnvironmentCharge>>,
    #[cfg(test)]
    random: Mutex<Option<RandomSource>>,
}
struct Handle(Arc<Inner>);
impl Drop for Handle {
    fn drop(&mut self) {
        self.0.close();
    }
}
/// Clones share one lifetime. Dropping a clone does not close other handles.
#[derive(Clone)]
pub struct DiagnosticSink {
    pub(crate) inner: Arc<Inner>,
    _handle: Arc<Handle>,
}
impl fmt::Debug for DiagnosticSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DiagnosticSink { <opaque> }")
    }
}
impl DiagnosticSink {
    pub(crate) fn new(
        options: DiagnosticSinkOptions,
        callback: CancellableDiagnosticCallback,
        charge: EnvironmentCharge,
        counters: Arc<DiagnosticCounters>,
    ) -> Result<Self, DiagnosticSinkError> {
        if options.sampling_basis_points > 100 {
            return Err(DiagnosticSinkError::InvalidSampling);
        }
        let inner = Arc::new(Inner {
            state: Mutex::new(QueueState {
                bucket: current_bucket(),
                ids: 0,
                events: 0,
                queue_bytes: 0,
                closed: false,
                closed_at: None,
                worker_done: false,
                maintenance_done: false,
                releasing: false,
                physically_released: false,
                running: 0,
                active_cancel: None,
                queue: VecDeque::with_capacity(MAX_EVENTS),
                live: Vec::with_capacity(MAX_IDS),
            }),
            wake: Condvar::new(),
            changed: Notify::new(),
            callback: Mutex::new(Some(callback)),
            sampling_basis_points: options.sampling_basis_points,
            dropped_events: AtomicU64::new(0),
            cleanup_timeouts: AtomicU64::new(0),
            timeout_reported: AtomicBool::new(false),
            counters,
            charge: Mutex::new(Some(charge)),
            #[cfg(test)]
            random: Mutex::new(None),
        });
        let worker = inner.clone();
        thread::Builder::new()
            .name("flowersec-diagnostic".to_owned())
            .spawn(move || diagnostic_worker(worker))
            .map_err(|_| DiagnosticSinkError::Capacity)?;
        let maintenance = inner.clone();
        if thread::Builder::new()
            .name("flowersec-diagnostic-expiry".to_owned())
            .spawn(move || diagnostic_maintenance(maintenance))
            .is_err()
        {
            inner
                .state
                .lock()
                .expect("diagnostic state")
                .maintenance_done = true;
            inner.close();
            return Err(DiagnosticSinkError::Capacity);
        }
        Ok(Self {
            _handle: Arc::new(Handle(inner.clone())),
            inner,
        })
    }
    pub fn begin(&self) -> Result<DiagnosticObservation, DiagnosticSinkError> {
        self.inner.begin()
    }
    pub fn counts(&self) -> DiagnosticCounts {
        DiagnosticCounts {
            dropped_events: self.inner.dropped_events.load(Ordering::Relaxed),
            cleanup_timeouts: self.inner.cleanup_timeouts.load(Ordering::Relaxed),
        }
    }
    pub fn close(&self) -> DiagnosticCleanupStatus {
        self.inner.close();
        self.cleanup_status()
    }
    pub fn cleanup_status(&self) -> DiagnosticCleanupStatus {
        self.inner.cleanup_status()
    }
    /// Observe physical release within a fixed bound; this never closes the sink.
    pub async fn wait_cleanup(&self) -> DiagnosticCleanupStatus {
        let deadline = tokio::time::Instant::now() + CLEANUP_BOUND;
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete || status.cleanup_incomplete {
                return status;
            }
            let remaining = self
                .inner
                .state
                .lock()
                .expect("diagnostic state")
                .closed_at
                .map(|closed| CLEANUP_BOUND.saturating_sub(closed.elapsed()));
            let current_deadline = remaining.map_or(deadline, |remaining| {
                deadline.min(tokio::time::Instant::now() + remaining)
            });
            if tokio::time::Instant::now() >= current_deadline {
                return DiagnosticCleanupStatus {
                    cleanup_incomplete: true,
                    ..status
                };
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(current_deadline) => {} }
        }
    }
    pub async fn wait_cleanup_with_cancellation(
        &self,
        cancellation: &CancellationToken,
    ) -> DiagnosticCleanupStatus {
        tokio::select! { status = self.wait_cleanup() => status, _ = cancellation.cancelled() => self.cleanup_status() }
    }
}

pub struct DiagnosticObservation {
    sink: Weak<Inner>,
    state: Arc<ObservationState>,
}
impl fmt::Debug for DiagnosticObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DiagnosticObservation { <opaque> }")
    }
}
impl DiagnosticObservation {
    pub fn emit(
        &self,
        state: DiagnosticState,
        attempt_bucket: DiagnosticAttemptBucket,
        phase: DiagnosticPhase,
        code: DiagnosticCode,
        retry_disposition: DiagnosticRetryDisposition,
        duration_bucket: DiagnosticDurationBucket,
    ) -> bool {
        let Some(sink) = self.sink.upgrade() else {
            return false;
        };
        // Refresh and read the ID under the same queue lock. A boundary event
        // can never enqueue an ID from the preceding UTC bucket.
        let mut queue = sink.state.lock().expect("diagnostic state");
        refresh_bucket(&sink, &mut queue, current_bucket());
        if queue.closed {
            return false;
        }
        let Some(id) = *self.state.id.lock().expect("diagnostic id") else {
            sink.dropped(1);
            return false;
        };
        if sink.sampling_basis_points == 0 {
            return false;
        }
        let mut random = [0; 8];
        if !sink.random_bytes(&mut random) {
            sink.dropped(1);
            return false;
        }
        if u128::from(u64::from_be_bytes(random)) * 10_000
            >= u128::from(sink.sampling_basis_points) * (1_u128 << 64)
        {
            return false;
        }
        let event = DiagnosticEvent {
            state,
            attempt_bucket,
            phase,
            code,
            retry_disposition,
            duration_bucket,
            correlation_id: id,
        };
        let bytes = event.encoded_bytes();
        if queue.events >= MAX_EVENTS
            || bytes > MAX_EVENT_BYTES
            || queue.queue_bytes.saturating_add(bytes) > MAX_QUEUE_BYTES
        {
            sink.dropped(1);
            return false;
        }
        queue.events += 1;
        queue.queue_bytes += bytes;
        queue.queue.push_back(event);
        sink.wake.notify_all();
        true
    }
}
impl Inner {
    fn random_bytes(&self, bytes: &mut [u8]) -> bool {
        #[cfg(test)]
        if let Some(random) = self.random.lock().expect("diagnostic test random").as_ref() {
            random(bytes);
            return true;
        }
        SystemRandom::new().fill(bytes).is_ok()
    }
    fn begin(self: &Arc<Self>) -> Result<DiagnosticObservation, DiagnosticSinkError> {
        let mut state = self.state.lock().expect("diagnostic state");
        refresh_bucket(self, &mut state, current_bucket());
        if state.closed {
            return Err(DiagnosticSinkError::Closed);
        }
        if state.ids >= MAX_IDS {
            self.dropped(1);
            return Err(DiagnosticSinkError::Capacity);
        }
        let mut id = [0; 16];
        if !self.random_bytes(&mut id) {
            self.dropped(1);
            return Err(DiagnosticSinkError::Capacity);
        }
        state.ids += 1;
        let observation = Arc::new(ObservationState {
            id: Mutex::new(Some(id)),
        });
        state.live.push(Arc::downgrade(&observation));
        Ok(DiagnosticObservation {
            sink: Arc::downgrade(self),
            state: observation,
        })
    }
    fn dropped(&self, count: u64) {
        add(&self.dropped_events, count);
        self.counters
            .increment_by(DiagnosticCounter::DiagnosticDrops, count);
    }
    pub(crate) fn close(&self) {
        let cancel = {
            let mut state = self.state.lock().expect("diagnostic state");
            if state.closed {
                return;
            }
            state.closed = true;
            state.closed_at = Some(MonotonicInstant::now());
            self.dropped(state.queue.len() as u64);
            state.queue.clear();
            state.queue_bytes = 0;
            for observation in state.live.drain(..).filter_map(|weak| weak.upgrade()) {
                *observation.id.lock().expect("diagnostic id") = None;
            }
            state.active_cancel.take()
        };
        if let Some(cancel) = cancel {
            cancel.cancel();
        }
        self.wake.notify_all();
        self.changed.notify_waiters();
    }
    pub(crate) fn cleanup_status(&self) -> DiagnosticCleanupStatus {
        let state = self.state.lock().expect("diagnostic state");
        let complete = state.physically_released;
        let cleanup_incomplete = !complete
            && state
                .closed_at
                .is_some_and(|start| start.elapsed() >= CLEANUP_BOUND);
        if cleanup_incomplete && !self.timeout_reported.swap(true, Ordering::AcqRel) {
            add(&self.cleanup_timeouts, 1);
            self.counters.increment(DiagnosticCounter::CleanupTimeouts);
        }
        DiagnosticCleanupStatus {
            complete,
            cleanup_incomplete,
            pending_callbacks: state.running,
        }
    }
    fn finish_lane(&self, maintenance: bool) {
        {
            let mut state = self.state.lock().expect("diagnostic state");
            if maintenance {
                state.maintenance_done = true;
            } else {
                state.worker_done = true;
            }
            if !state.maintenance_done || !state.worker_done || state.releasing {
                return;
            }
            state.releasing = true;
        }
        // User callback destructors and the root charge release never execute
        // under the queue lock. Completion follows their physical release.
        drop(self.callback.lock().expect("diagnostic callback").take());
        drop(self.charge.lock().expect("diagnostic charge").take());
        self.state
            .lock()
            .expect("diagnostic state")
            .physically_released = true;
        self.changed.notify_waiters();
        self.wake.notify_all();
    }
}
fn diagnostic_worker(inner: Arc<Inner>) {
    loop {
        let next = {
            let mut state = inner.state.lock().expect("diagnostic state");
            loop {
                refresh_bucket(&inner, &mut state, current_bucket());
                if state.closed {
                    break None;
                }
                if let Some(event) = state.queue.pop_front() {
                    state.queue_bytes -= event.encoded_bytes();
                    state.running = 1;
                    let cancel = CancellationToken::new();
                    state.active_cancel = Some(cancel.clone());
                    break Some((event, cancel));
                }
                state = inner.wake.wait(state).expect("diagnostic wait");
            }
        };
        let Some((event, cancel)) = next else {
            inner.finish_lane(false);
            return;
        };
        let callback = inner.callback.lock().expect("diagnostic callback").clone();
        if let Some(callback) = callback
            && !cancel.is_cancelled()
        {
            let _ = catch_unwind(AssertUnwindSafe(|| callback(event, cancel)));
        }
        let mut state = inner.state.lock().expect("diagnostic state");
        state.running = 0;
        state.active_cancel = None;
        inner.changed.notify_waiters();
    }
}
fn diagnostic_maintenance(inner: Arc<Inner>) {
    loop {
        let mut state = inner.state.lock().expect("diagnostic state");
        if state.closed {
            drop(state);
            inner.finish_lane(true);
            return;
        }
        refresh_bucket(&inner, &mut state, current_bucket());
        let (state, _) = inner
            .wake
            .wait_timeout(state, Duration::from_millis(100))
            .expect("diagnostic expiry wait");
        drop(state);
    }
}
fn current_bucket() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / BUCKET_SECONDS
}
fn refresh_bucket(inner: &Inner, state: &mut QueueState, bucket: u64) {
    if state.closed {
        return;
    }
    state.live.retain(|item| item.strong_count() != 0);
    if state.bucket == bucket {
        return;
    }
    state.bucket = bucket;
    state.ids = 0;
    state.events = 0;
    inner.dropped(state.queue.len() as u64);
    state.queue.clear();
    state.queue_bytes = 0;
    if let Some(cancel) = state.active_cancel.take() {
        cancel.cancel();
    }
    for weak in &state.live {
        if let Some(observation) = weak.upgrade() {
            let mut id = [0; 16];
            let replacement = if state.ids < MAX_IDS {
                state.ids += 1;
                if inner.random_bytes(&mut id) {
                    Some(id)
                } else {
                    inner.dropped(1);
                    None
                }
            } else {
                inner.dropped(1);
                None
            };
            *observation.id.lock().expect("diagnostic id") = replacement;
        }
    }
}

/// Belongs to the original admitted operation; public waits borrow this owner.
#[derive(Debug)]
pub(crate) struct DiagnosticActivity {
    observation: Mutex<Option<DiagnosticObservation>>,
    counters: Arc<DiagnosticCounters>,
    phase: DiagnosticPhase,
    started: MonotonicInstant,
    attempt: AtomicU32,
    terminal: AtomicBool,
    closed: AtomicBool,
    lifecycle: Mutex<()>,
    close_requested: AtomicBool,
    physical_pending: AtomicUsize,
}
impl DiagnosticActivity {
    pub(crate) fn new(
        sink: Option<&DiagnosticSink>,
        counters: Arc<DiagnosticCounters>,
        phase: DiagnosticPhase,
        ordinal: u32,
    ) -> Arc<Self> {
        let activity = Arc::new(Self {
            observation: Mutex::new(sink.and_then(|sink| sink.begin().ok())),
            counters,
            phase,
            started: MonotonicInstant::now(),
            attempt: AtomicU32::new(ordinal),
            terminal: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            lifecycle: Mutex::new(()),
            close_requested: AtomicBool::new(false),
            physical_pending: AtomicUsize::new(0),
        });
        if matches!(phase, DiagnosticPhase::Connect | DiagnosticPhase::Accept) {
            activity.observe(
                DiagnosticCounter::ConnectAttempts,
                DiagnosticState::Started,
                phase,
                DiagnosticCode::None,
            );
        } else if phase == DiagnosticPhase::Application {
            activity.observe(
                DiagnosticCounter::ApplicationOperations,
                DiagnosticState::Started,
                phase,
                DiagnosticCode::None,
            );
        }
        activity.event(
            DiagnosticState::Started,
            phase,
            DiagnosticCode::None,
            DiagnosticRetryDisposition::None,
        );
        activity
    }
    pub(crate) fn set_attempt(&self, ordinal: u32) {
        let previous = self.attempt.swap(ordinal, Ordering::AcqRel);
        if matches!(
            self.phase,
            DiagnosticPhase::Connect | DiagnosticPhase::Accept
        ) && ordinal > previous
        {
            for attempt in previous.saturating_add(1)..=ordinal {
                self.counters.observe(
                    DiagnosticCounter::ConnectAttempts,
                    1,
                    DiagnosticState::Started,
                    self.phase,
                    DiagnosticCode::None,
                    DiagnosticDurationBucket::elapsed(self.started.elapsed()),
                    DiagnosticAttemptBucket::ordinal(attempt),
                );
            }
        }
    }
    pub(crate) fn observe(
        &self,
        metric: DiagnosticMetric,
        state: DiagnosticState,
        phase: DiagnosticPhase,
        code: DiagnosticCode,
    ) {
        self.counters.observe(
            metric,
            1,
            state,
            phase,
            code,
            DiagnosticDurationBucket::elapsed(self.started.elapsed()),
            DiagnosticAttemptBucket::ordinal(self.attempt.load(Ordering::Acquire)),
        );
    }
    pub(crate) fn event(
        &self,
        state: DiagnosticState,
        phase: DiagnosticPhase,
        code: DiagnosticCode,
        retry: DiagnosticRetryDisposition,
    ) {
        if let Some(observation) = self
            .observation
            .lock()
            .expect("diagnostic observation")
            .as_ref()
        {
            observation.emit(
                state,
                DiagnosticAttemptBucket::ordinal(self.attempt.load(Ordering::Acquire)),
                phase,
                code,
                retry,
                DiagnosticDurationBucket::elapsed(self.started.elapsed()),
            );
        }
    }
    pub(crate) fn succeed(&self) {
        let _lifecycle = self.lifecycle.lock().expect("diagnostic lifecycle");
        if !self.terminal.swap(true, Ordering::AcqRel) {
            let metric = match self.phase {
                DiagnosticPhase::Connect | DiagnosticPhase::Accept => {
                    Some(DiagnosticMetric::ConnectSuccesses)
                }
                DiagnosticPhase::Application => Some(DiagnosticMetric::ApplicationCompleted),
                _ => None,
            };
            if let Some(metric) = metric {
                self.observe(
                    metric,
                    DiagnosticState::Succeeded,
                    self.phase,
                    DiagnosticCode::None,
                );
            }
            self.event(
                DiagnosticState::Succeeded,
                self.phase,
                DiagnosticCode::None,
                DiagnosticRetryDisposition::None,
            );
        }
    }
    pub(crate) fn fail(&self, code: DiagnosticCode, retry: DiagnosticRetryDisposition) {
        let _lifecycle = self.lifecycle.lock().expect("diagnostic lifecycle");
        if !self.terminal.swap(true, Ordering::AcqRel) {
            let metric = match self.phase {
                DiagnosticPhase::Connect | DiagnosticPhase::Accept => {
                    Some(DiagnosticMetric::ConnectFailures)
                }
                DiagnosticPhase::Application => Some(DiagnosticMetric::ApplicationFailures),
                _ => None,
            };
            let state = if code == DiagnosticCode::Canceled {
                DiagnosticState::Canceled
            } else {
                DiagnosticState::Failed
            };
            if let Some(metric) = metric {
                self.observe(metric, state, self.phase, code);
            }
            self.event(state, self.phase, code, retry);
        }
    }
    pub(crate) fn retain_physical(self: &Arc<Self>) -> DiagnosticPhysicalTail {
        let _lifecycle = self.lifecycle.lock().expect("diagnostic lifecycle");
        self.physical_pending.fetch_add(1, Ordering::AcqRel);
        DiagnosticPhysicalTail(self.clone())
    }
    pub(crate) fn closed(&self) {
        let _lifecycle = self.lifecycle.lock().expect("diagnostic lifecycle");
        self.close_requested.store(true, Ordering::Release);
        if self.physical_pending.load(Ordering::Acquire) == 0 {
            self.closed_locked();
        }
    }
    fn closed_locked(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let mut observation = self.observation.lock().expect("diagnostic observation");
            if let Some(observation) = observation.as_ref() {
                observation.emit(
                    DiagnosticState::Closed,
                    DiagnosticAttemptBucket::ordinal(self.attempt.load(Ordering::Acquire)),
                    DiagnosticPhase::Close,
                    DiagnosticCode::None,
                    DiagnosticRetryDisposition::None,
                    DiagnosticDurationBucket::elapsed(self.started.elapsed()),
                );
            }
            observation.take();
        }
    }
    pub(crate) fn serve_outcome<T>(&self, outcome: &Result<T, crate::ServeError>) {
        match outcome {
            Ok(_) => self.succeed(),
            Err(error) => self.fail(
                match error.code {
                    crate::ServeFailure::Canceled => DiagnosticCode::Canceled,
                    crate::ServeFailure::Closed => DiagnosticCode::Closed,
                    crate::ServeFailure::Capacity => DiagnosticCode::ResourceRejected,
                    _ => DiagnosticCode::Other,
                },
                DiagnosticRetryDisposition::DoNotRetry,
            ),
        }
    }
    pub(crate) fn session_failure(&self, error: crate::SessionError) {
        self.fail(
            match error {
                crate::SessionError::Canceled => DiagnosticCode::Canceled,
                crate::SessionError::Timeout => DiagnosticCode::Timeout,
                crate::SessionError::Closed | crate::SessionError::StreamReset => {
                    DiagnosticCode::Closed
                }
                crate::SessionError::ResourceExhausted => DiagnosticCode::ResourceRejected,
                _ => DiagnosticCode::Other,
            },
            DiagnosticRetryDisposition::DoNotRetry,
        );
    }
    pub(crate) fn service_outcome<T>(&self, outcome: &Result<T, crate::ServiceError>) {
        match outcome {
            Ok(_) => self.succeed(),
            Err(error) => self.service_failure(*error),
        }
    }
    pub(crate) fn service_failure(&self, error: crate::ServiceError) {
        self.fail(
            match error.0 {
                crate::ServiceFailure::Canceled => DiagnosticCode::Canceled,
                crate::ServiceFailure::Closed => DiagnosticCode::Closed,
                crate::ServiceFailure::DeadlineExceeded => DiagnosticCode::Timeout,
                _ => DiagnosticCode::Other,
            },
            DiagnosticRetryDisposition::DoNotRetry,
        );
    }
}

/// Shares an existing provider preparation tail; it owns no new task or timer.
pub(crate) struct DiagnosticPhysicalTail(Arc<DiagnosticActivity>);
impl Drop for DiagnosticPhysicalTail {
    fn drop(&mut self) {
        let activity = &self.0;
        let _lifecycle = activity.lifecycle.lock().expect("diagnostic lifecycle");
        if activity.physical_pending.fetch_sub(1, Ordering::AcqRel) == 1
            && activity.close_requested.load(Ordering::Acquire)
        {
            activity.closed_locked();
        }
    }
}

impl Drop for DiagnosticActivity {
    fn drop(&mut self) {
        self.fail(
            DiagnosticCode::Closed,
            DiagnosticRetryDisposition::DoNotRetry,
        );
        if !matches!(
            self.phase,
            DiagnosticPhase::Connect
                | DiagnosticPhase::Session
                | DiagnosticPhase::Serve
                | DiagnosticPhase::Accept
        ) {
            self.closed();
        }
    }
}

#[cfg(test)]
pub(crate) fn capture_for_test(
    root: &Arc<crate::environment_v4::EnvironmentRoot>,
) -> (DiagnosticSink, Arc<Mutex<Vec<DiagnosticEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let output = events.clone();
    let sink = root
        .diagnostic_sink(
            DiagnosticSinkOptions::default(),
            Arc::new(move |event| output.lock().unwrap().push(event)),
        )
        .unwrap();
    let next = Arc::new(AtomicU64::new(1));
    *sink.inner.random.lock().unwrap() = Some(Arc::new(move |bytes| {
        bytes.fill(0);
        if bytes.len() == 16 {
            bytes[..8].copy_from_slice(&next.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        }
    }));
    root.install_test_diagnostics(sink.clone());
    (sink, events)
}

#[cfg(test)]
#[path = "diagnostics_v4_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResourceLimits, TransportEnvironment, TransportEnvironmentOptions};

    async fn until(mut ready: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !ready() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn normal_configuration_is_opt_in_and_resource_counters_are_unsampled() {
        let environment = TransportEnvironment::new();
        assert!(environment.configured_diagnostic_sink().is_none());
        assert!(
            environment
                .root()
                .reserve_environment(ResourceLimits {
                    sdk_bytes: u64::MAX,
                    ..ResourceLimits::default()
                })
                .is_err()
        );
        assert_eq!(environment.diagnostic_counts().resource_rejections, 1);
        let metric = environment.diagnostic_metric(DiagnosticMetric::ResourceRejections);
        assert_eq!(metric.total, 1);
        assert_eq!(metric.code(DiagnosticCode::ResourceRejected), 1);
        assert_eq!(metric.duration(DiagnosticDurationBucket::Other), 1);
        assert_eq!(metric.attempt(DiagnosticAttemptBucket::Other), 1);
        let mut options = TransportEnvironmentOptions::default();
        options.application_executor.diagnostics = false;
        options.diagnostics = Some(DiagnosticSinkConfiguration {
            options: DiagnosticSinkOptions {
                sampling_basis_points: 0,
            },
            callback: Arc::new(|_, _| panic!("sampling zero must never invoke user code")),
        });
        let configured = TransportEnvironment::with_options(options).unwrap();
        let sink = configured.configured_diagnostic_sink().unwrap();
        let activity = configured
            .root()
            .diagnostic_activity(DiagnosticPhase::Application, 7);
        activity.service_failure(crate::ServiceError(crate::ServiceFailure::DeadlineExceeded));
        activity.service_failure(crate::ServiceError(crate::ServiceFailure::DeadlineExceeded));
        activity.succeed();
        let metric = configured.diagnostic_metric(DiagnosticMetric::ApplicationFailures);
        assert_eq!(metric.total, 1);
        assert_eq!(metric.state(DiagnosticState::Failed), 1);
        assert_eq!(metric.phase(DiagnosticPhase::Application), 1);
        assert_eq!(metric.code(DiagnosticCode::Timeout), 1);
        assert_eq!(metric.attempt(DiagnosticAttemptBucket::FourToSeven), 1);
        let canceled_wait = CancellationToken::new();
        canceled_wait.cancel();
        assert!(
            !sink
                .wait_cleanup_with_cancellation(&canceled_wait)
                .await
                .complete
        );
        assert!(sink.begin().is_ok());
        sink.close();
        assert!(sink.wait_cleanup().await.complete);
        assert!(configured.close().await.unwrap().complete);
    }

    #[tokio::test]
    async fn clones_expiry_and_physical_callback_tail_share_the_original_charge() {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let release = state.clone();
        let (entered, observed) = std::sync::mpsc::channel();
        let options = TransportEnvironmentOptions {
            diagnostics: Some(DiagnosticSinkConfiguration::cancellable(Arc::new(
                move |event, cancellation| {
                    entered.send((event, cancellation)).unwrap();
                    let (gate, wake) = &*release;
                    let mut released = gate.lock().unwrap();
                    while !*released {
                        released = wake.wait(released).unwrap();
                    }
                },
            ))),
            ..TransportEnvironmentOptions::default()
        };
        let environment = TransportEnvironment::with_options(options).unwrap();
        let sink = environment.configured_diagnostic_sink().unwrap();
        let discarded_clone = sink.clone();
        drop(discarded_clone);
        let sequence = Arc::new(AtomicU64::new(1));
        *sink.inner.random.lock().unwrap() = Some(Arc::new(move |bytes| {
            bytes.fill(0);
            if bytes.len() == 16 {
                bytes[..8].copy_from_slice(&sequence.fetch_add(1, Ordering::Relaxed).to_be_bytes());
            }
        }));
        let observation = sink.begin().unwrap();
        let emit = || {
            observation.emit(
                DiagnosticState::Started,
                DiagnosticAttemptBucket::One,
                DiagnosticPhase::Application,
                DiagnosticCode::None,
                DiagnosticRetryDisposition::None,
                DiagnosticDurationBucket::Under10Ms,
            )
        };
        assert!(emit());
        let (first, callback_cancel) = observed.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(emit());
        {
            let mut state = sink.inner.state.lock().unwrap();
            state.bucket = current_bucket().saturating_sub(1);
        }
        assert!(emit());
        let replacement = sink
            .inner
            .state
            .lock()
            .unwrap()
            .queue
            .back()
            .unwrap()
            .correlation_id;
        assert_ne!(first.correlation_id, replacement);
        assert!(callback_cancel.is_cancelled());
        assert!(sink.counts().dropped_events >= 1);
        let retained = environment.resource_usage();
        assert!(retained.tasks >= 2);
        let status = sink.close();
        assert!(!status.complete);
        assert_eq!(status.pending_callbacks, 1);
        assert_eq!(environment.resource_usage().tasks, retained.tasks);
        {
            sink.inner.state.lock().unwrap().closed_at =
                MonotonicInstant::now().checked_sub(Duration::from_secs(6));
        }
        assert!(sink.cleanup_status().cleanup_incomplete);
        assert!(sink.cleanup_status().cleanup_incomplete);
        assert_eq!(sink.counts().cleanup_timeouts, 1);
        *state.0.lock().unwrap() = true;
        state.1.notify_all();
        until(|| sink.cleanup_status().complete).await;
        assert_eq!(environment.resource_usage().tasks, retained.tasks - 2);
        assert_eq!(
            environment
                .diagnostic_metric(DiagnosticMetric::CleanupTimeouts)
                .total,
            1
        );
        assert!(environment.close().await.unwrap().complete);
    }

    #[tokio::test]
    async fn original_id_and_event_limits_remain_bounded_and_counters_saturate() {
        let environment = TransportEnvironment::new();
        let (sink, _) = capture_for_test(environment.root());
        let observations: Vec<_> = (0..MAX_IDS).map(|_| sink.begin().unwrap()).collect();
        assert_eq!(sink.begin().unwrap_err(), DiagnosticSinkError::Capacity);
        assert_eq!(environment.diagnostic_counts().diagnostic_drops, 1);
        sink.inner.state.lock().unwrap().events = MAX_EVENTS;
        assert!(!observations[0].emit(
            DiagnosticState::Started,
            DiagnosticAttemptBucket::One,
            DiagnosticPhase::Application,
            DiagnosticCode::None,
            DiagnosticRetryDisposition::None,
            DiagnosticDurationBucket::Under10Ms
        ));
        assert_eq!(environment.diagnostic_counts().diagnostic_drops, 2);
        let counters = DiagnosticCounters::default();
        counters.0[DiagnosticMetric::ResourceRejections as usize]
            .total
            .store(u64::MAX, Ordering::Relaxed);
        counters.increment(DiagnosticMetric::ResourceRejections);
        assert_eq!(
            counters.metric(DiagnosticMetric::ResourceRejections).total,
            u64::MAX
        );
        drop(observations);
        sink.close();
        assert!(sink.wait_cleanup().await.complete);
        assert!(environment.close().await.unwrap().complete);
    }
}
