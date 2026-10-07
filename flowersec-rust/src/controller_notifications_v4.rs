//! Managed notification roots attach only to published, configured peers. They
//! retain two original subscription positions through real callback cleanup.
#[cfg(test)]
#[path = "controller_notification_entry_v4_tests.rs"]
mod entry_tests;
use super::*;
use crate::{
    MessageCodec, NotificationDropPolicy, ServiceContract, ServiceError, ServiceFailure,
    ServiceNotificationObserver, ServiceNotificationSubscription, ServiceSemantics, ServiceShape,
    application_executor_v4::ApplicationGroup,
    environment_v4::EnvironmentCharge,
    notification_peer_v4::{EncodedControl, EncodedNotification, NotificationScheduler},
};
use futures_util::FutureExt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize};
#[cfg(test)]
use std::sync::{Condvar, LazyLock};
use std::{
    panic::AssertUnwindSafe,
    sync::{OnceLock, Weak},
};

tokio::task_local! { static CONTROLLER_NOTIFICATION_ROOT: usize; }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerNotificationObservation {
    CurrentOnly,
    DrainAware,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerNotificationSourcePhase {
    Current,
    Retained,
    Draining,
}
// Candidate is internal and never appears in a delivered source projection.
const SOURCE_CANDIDATE: u8 = 3;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NotificationLockOrderStage {
    LateAttachment,
    OldInputRejection,
    Publication,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct NotificationLockOrderProbeState {
    root: usize,
    entered: Vec<NotificationLockOrderStage>,
    released: Vec<NotificationLockOrderStage>,
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct NotificationLockOrderProbe {
    state: Mutex<NotificationLockOrderProbeState>,
    changed: Condvar,
}

#[cfg(test)]
impl NotificationLockOrderProbe {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn wait_entered(&self, stage: NotificationLockOrderStage) {
        let mut state = self.state.lock().expect("notification lock-order probe");
        while !state.entered.contains(&stage) {
            let (next, timeout) = self
                .changed
                .wait_timeout(state, Duration::from_secs(5))
                .expect("notification lock-order probe wait");
            state = next;
            if timeout.timed_out() && !state.entered.contains(&stage) {
                drop(state);
                panic!("notification lock-order stage not entered: {stage:?}");
            }
        }
    }

    pub(crate) fn release(&self, stage: NotificationLockOrderStage) {
        let mut state = self.state.lock().expect("notification lock-order probe");
        if !state.released.contains(&stage) {
            state.released.push(stage);
        }
        self.changed.notify_all();
    }

    fn block(&self, root: usize, stage: NotificationLockOrderStage) {
        let mut state = self.state.lock().expect("notification lock-order probe");
        if state.root != root {
            return;
        }
        if !state.entered.contains(&stage) {
            state.entered.push(stage);
        }
        self.changed.notify_all();
        while !state.released.contains(&stage) {
            state = self
                .changed
                .wait(state)
                .expect("notification lock-order probe wait");
        }
    }
}

#[cfg(test)]
static NOTIFICATION_LOCK_ORDER_PROBE: LazyLock<Mutex<Option<Arc<NotificationLockOrderProbe>>>> =
    LazyLock::new(|| Mutex::new(None));

#[cfg(test)]
pub(crate) struct NotificationLockOrderProbeGuard;

#[cfg(test)]
pub(crate) fn install_notification_lock_order_probe(
    probe: Arc<NotificationLockOrderProbe>,
) -> NotificationLockOrderProbeGuard {
    *NOTIFICATION_LOCK_ORDER_PROBE
        .lock()
        .expect("notification lock-order probe") = Some(probe);
    NotificationLockOrderProbeGuard
}

#[cfg(test)]
impl Drop for NotificationLockOrderProbeGuard {
    fn drop(&mut self) {
        if let Some(probe) = NOTIFICATION_LOCK_ORDER_PROBE
            .lock()
            .expect("notification lock-order probe")
            .take()
        {
            for stage in [
                NotificationLockOrderStage::Publication,
                NotificationLockOrderStage::LateAttachment,
                NotificationLockOrderStage::OldInputRejection,
            ] {
                probe.release(stage);
            }
        }
    }
}

#[cfg(test)]
fn block_test_stage(root: usize, stage: NotificationLockOrderStage) {
    let probe = NOTIFICATION_LOCK_ORDER_PROBE
        .lock()
        .expect("notification lock-order probe")
        .clone();
    if let Some(probe) = probe {
        probe.block(root, stage);
    }
}
fn phase_code(phase: ControllerNotificationSourcePhase) -> u8 {
    match phase {
        ControllerNotificationSourcePhase::Current => 0,
        ControllerNotificationSourcePhase::Retained => 1,
        ControllerNotificationSourcePhase::Draining => 2,
    }
}
fn phase_from_code(code: u8) -> ControllerNotificationSourcePhase {
    match code {
        1 => ControllerNotificationSourcePhase::Retained,
        2 => ControllerNotificationSourcePhase::Draining,
        _ => ControllerNotificationSourcePhase::Current,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerNotificationGapReason {
    Handoff,
    Unattached,
    LateAttachment,
    SourceClosed,
    SourceUnauthorized,
    DroppedBudget,
    Coalesced,
    Expired,
    DecodeError,
    HandlerError,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerNotificationGap {
    pub from_generation: u64,
    pub to_generation: u64,
    pub reasons: Vec<ControllerNotificationGapReason>,
    pub known_dropped: u64,
    pub possible_gap: bool,
}
#[derive(Debug)]
pub enum ControllerNotificationEvent<T> {
    Notification {
        value: T,
        context: crate::NotificationContext,
        source_generation: u64,
        source_phase: ControllerNotificationSourcePhase,
    },
    ObservationGap {
        gap: ControllerNotificationGap,
    },
}
#[async_trait]
pub trait ControllerNotificationObserver<T>: fmt::Debug + Send + Sync + 'static {
    fn application_bytes(&self) -> u64;
    async fn observe(&self, event: ControllerNotificationEvent<T>) -> Result<(), ServiceError>;
}
pub struct ControllerNotificationOptions {
    pub observation: ControllerNotificationObservation,
    pub max_observed_sessions: usize,
}
impl Default for ControllerNotificationOptions {
    fn default() -> Self {
        Self {
            observation: ControllerNotificationObservation::CurrentOnly,
            max_observed_sessions: 2,
        }
    }
}
impl fmt::Debug for ControllerNotificationOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllerNotificationOptions")
            .field("observation", &self.observation)
            .field("max_observed_sessions", &self.max_observed_sessions)
            .finish()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerNotificationSnapshot {
    pub generation: u64,
    pub source_phase: ControllerNotificationSourcePhase,
    pub observed_sources: usize,
    pub attached: bool,
    pub closing: bool,
    pub gap: Option<ControllerNotificationGap>,
    pub service_failure: Option<ServiceError>,
    pub controller_failure: Option<MaterialControllerError>,
}
struct NotificationState<T> {
    current: Option<ServiceNotificationSubscription<T>>,
    retired: Option<ServiceNotificationSubscription<T>>,
    pending: Option<ServiceNotificationSubscription<T>>,
    pending_session: Option<Session>,
    pending_generation: Option<u64>,
    pending_phase: Option<Arc<AtomicU8>>,
    current_phase: Option<Arc<AtomicU8>>,
    retired_phase: Option<Arc<AtomicU8>>,
    generation: u64,
    source_phase: ControllerNotificationSourcePhase,
    gap: Option<ControllerNotificationGap>,
    gap_emitted: Option<ControllerNotificationGap>,
    reader_gap_generation: u64,
    reader_gap_sequence: u64,
    service_failure: Option<ServiceError>,
    controller_failure: Option<MaterialControllerError>,
}
#[derive(Clone)]
struct ActiveDelivery {
    control: EncodedControl,
    generation: u64,
}
struct DeliveryTicket(Arc<AtomicUsize>);
impl Drop for DeliveryTicket {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
enum RootDelivery {
    Encoded {
        task: EncodedNotification,
        completion: oneshot::Sender<Result<(), ServiceError>>,
        ticket: DeliveryTicket,
    },
    Gap {
        gap: ControllerNotificationGap,
        ticket: DeliveryTicket,
    },
}

struct RootResources<T> {
    codec: Arc<dyn MessageCodec<T>>,
    observer: Option<Arc<dyn ServiceNotificationObserver<T>>>,
    event_observer: Option<Arc<dyn ControllerNotificationObserver<T>>>,
    callback: ApplicationGroup,
    _charge: EnvironmentCharge,
}
struct Root<T> {
    controller: Weak<Owner>,
    contract: ServiceContract,
    resources: Mutex<Option<RootResources<T>>>,
    _status_charge: EnvironmentCharge,
    resources_released: AtomicBool,
    application_bytes: u64,
    delivery: Mutex<std::collections::VecDeque<RootDelivery>>,
    delivery_changed: Notify,
    active_delivery: Mutex<Option<ActiveDelivery>>,
    callback_entry: Mutex<()>,
    prefer_gap: AtomicBool,
    delivery_pending: Arc<AtomicUsize>,
    self_weak: OnceLock<Weak<Root<T>>>,
    published_generation: AtomicU64,
    delivery_generation: AtomicU64,
    policy: NotificationDropPolicy,
    options: ControllerNotificationOptions,
    state: Mutex<NotificationState<T>>,
    cancellation: CancellationToken,
    close_deadline: Mutex<Option<Instant>>,
    changed: Notify,
    handles: AtomicUsize,
    done: AtomicBool,
    delivery_done: AtomicBool,
}
impl<T> fmt::Debug for Root<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControllerNotificationRoot { <opaque> }")
    }
}
/// A stable subscription root. Replacement changes only its future delivery
/// source; already admitted observer work retains its original context.
pub struct ControllerNotificationSubscription<T>(Arc<Root<T>>);
impl<T> fmt::Debug for ControllerNotificationSubscription<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControllerNotificationSubscription { <opaque> }")
    }
}
impl<T> Clone for ControllerNotificationSubscription<T> {
    fn clone(&self) -> Self {
        self.0.handles.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}
impl<T> Drop for ControllerNotificationSubscription<T> {
    fn drop(&mut self) {
        if self.0.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.close();
        }
    }
}
impl<T> Root<T> {
    fn application_bytes(&self) -> u64 {
        self.application_bytes
    }

    fn codec(&self) -> Option<Arc<dyn MessageCodec<T>>> {
        self.resources
            .lock()
            .expect("managed notification resources")
            .as_ref()
            .map(|resources| resources.codec.clone())
    }

    fn legacy_observer(&self) -> Option<Arc<dyn ServiceNotificationObserver<T>>> {
        self.resources
            .lock()
            .expect("managed notification resources")
            .as_ref()
            .and_then(|resources| resources.observer.clone())
    }

    fn event_observer(&self) -> Option<Arc<dyn ControllerNotificationObserver<T>>> {
        self.resources
            .lock()
            .expect("managed notification resources")
            .as_ref()
            .and_then(|resources| resources.event_observer.clone())
    }

    fn callback_runtime(&self) -> Option<ApplicationGroup> {
        self.resources
            .lock()
            .expect("managed notification resources")
            .as_ref()
            .map(|resources| resources.callback.clone())
    }

    fn record_queue_drops<'a>(
        &self,
        dropped: impl IntoIterator<Item = &'a RootDelivery>,
        reason: ControllerNotificationGapReason,
    ) {
        let mut count = 0u64;
        let mut from = u64::MAX;
        let mut to = 0;
        for delivery in dropped {
            if let RootDelivery::Encoded { task, .. } = delivery {
                count += 1;
                from = from.min(task.generation());
                to = to.max(task.generation());
            }
        }
        if count != 0 {
            let mut state = self
                .state
                .lock()
                .expect("managed notification queue drop gap");
            Self::record_gap_locked(&mut state, reason, from, to, true, count);
        }
    }

    fn enqueue_delivery(&self, delivery: RootDelivery) -> Result<(), RootDelivery> {
        let mut dropped = Vec::new();
        let mut queue = self
            .delivery
            .lock()
            .expect("managed notification delivery queue");
        if self.cancellation.is_cancelled() {
            drop(queue);
            return Err(delivery);
        }
        let mut active_coalesced_generation = None;
        if self.policy == NotificationDropPolicy::KeepLatest {
            let published = self.delivery_generation.load(Ordering::Acquire);
            let eligible = |delivery: &RootDelivery| match delivery {
                RootDelivery::Encoded { task, .. } => task.eligible(published),
                RootDelivery::Gap { .. } => false,
            };
            let incoming_ready = eligible(&delivery);
            let active = self
                .active_delivery
                .lock()
                .expect("managed active notification delivery")
                .as_ref()
                .cloned();
            // An input waiting for its actual decode entry still owns the one
            // logical pending position. An unpublished candidate cannot take
            // it or occupy a second position beside it.
            if !incoming_ready
                && active.as_ref().is_some_and(|active| {
                    !EncodedNotification::control_is_admitted(&active.control)
                })
            {
                drop(queue);
                return Err(delivery);
            }
            if !queue.is_empty() {
                if !eligible(&delivery) && queue.iter().any(eligible) {
                    drop(queue);
                    return Err(delivery);
                }
                dropped.extend(queue.drain(..));
            }
            active_coalesced_generation = active.and_then(|active| {
                if !incoming_ready || EncodedNotification::control_is_admitted(&active.control) {
                    return None;
                }
                EncodedNotification::supersede_control(&active.control).then_some(active.generation)
            });
        } else if queue.len() >= 16 {
            match self.policy {
                NotificationDropPolicy::DropNewest => {
                    drop(queue);
                    return Err(delivery);
                }
                NotificationDropPolicy::DropOldest => {
                    if let Some(old) = queue.pop_front() {
                        dropped.push(old);
                    }
                }
                NotificationDropPolicy::KeepLatest => unreachable!("single latest pending slot"),
            }
        }
        queue.push_back(delivery);
        drop(queue);
        self.record_queue_drops(
            &dropped,
            if self.policy == NotificationDropPolicy::KeepLatest {
                ControllerNotificationGapReason::Coalesced
            } else {
                ControllerNotificationGapReason::DroppedBudget
            },
        );
        if let Some(generation) = active_coalesced_generation {
            let mut state = self
                .state
                .lock()
                .expect("managed active notification coalesce gap");
            Self::record_gap_locked(
                &mut state,
                ControllerNotificationGapReason::Coalesced,
                generation,
                generation,
                true,
                1,
            );
            drop(state);
            self.emit_pending_gap();
        }
        drop(dropped);
        self.delivery_changed.notify_one();
        Ok(())
    }

    fn pop_delivery(&self) -> Option<RootDelivery> {
        let mut state = self.state.lock().expect("managed notification gap slot");
        let mut queue = self
            .delivery
            .lock()
            .expect("managed notification delivery queue");
        if self.cancellation.is_cancelled() {
            return None;
        }
        let published = self.delivery_generation.load(Ordering::Acquire);
        let index = queue.iter().position(|delivery| match delivery {
            RootDelivery::Encoded { task, .. } => task.ready(published),
            RootDelivery::Gap { .. } => false,
        });
        let gap = state
            .gap
            .as_ref()
            .filter(|gap| state.gap_emitted.as_ref() != Some(*gap));
        if let Some(gap) = gap
            && (index.is_none() || self.prefer_gap.load(Ordering::Acquire))
        {
            let gap = gap.clone();
            state.gap_emitted = Some(gap.clone());
            self.prefer_gap.store(false, Ordering::Release);
            self.delivery_pending.fetch_add(1, Ordering::AcqRel);
            return Some(RootDelivery::Gap {
                gap,
                ticket: DeliveryTicket(self.delivery_pending.clone()),
            });
        }
        if let Some(index) = index {
            self.prefer_gap.store(true, Ordering::Release);
            let delivery = queue
                .remove(index)
                .expect("managed notification delivery index");
            if let RootDelivery::Encoded { task, .. } = &delivery {
                *self
                    .active_delivery
                    .lock()
                    .expect("managed active notification delivery") = Some(ActiveDelivery {
                    control: task.control(),
                    generation: task.generation(),
                });
            }
            return Some(delivery);
        }
        None
    }

    fn try_release_resources(&self) {
        if !self.cancellation.is_cancelled()
            || !self.done.load(Ordering::Acquire)
            || !self.delivery_done.load(Ordering::Acquire)
            || self.delivery_pending.load(Ordering::Acquire) != 0
        {
            return;
        }
        let subscriptions = {
            let mut state = self
                .state
                .lock()
                .expect("managed notification release state");
            if [
                state.current.as_ref(),
                state.retired.as_ref(),
                state.pending.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|subscription| !subscription.cleanup_status().complete)
            {
                return;
            }
            let subscriptions = [
                state.current.take(),
                state.retired.take(),
                state.pending.take(),
            ];
            state.pending_session.take();
            state.pending_generation.take();
            state.pending_phase.take();
            state.current_phase.take();
            state.retired_phase.take();
            subscriptions
        };
        drop(subscriptions);
        let queued = {
            let mut queue = self
                .delivery
                .lock()
                .expect("managed notification release queue");
            std::mem::take(&mut *queue)
        };
        if !queued.is_empty() {
            drop(queued);
            return;
        }
        let resources = self
            .resources
            .lock()
            .expect("managed notification release resources")
            .take();
        if let Some(resources) = resources {
            // User-owned captures are destroyed outside every SDK gate. Their
            // original charge and root slot remain held through actual return.
            drop(resources);
            if let Some(controller) = self.controller.upgrade() {
                controller.notification_roots.fetch_sub(1, Ordering::AcqRel);
            }
            self.resources_released.store(true, Ordering::Release);
            self.changed.notify_waiters();
        }
    }

    fn drain_delivery_queue(&self, reason: ControllerNotificationGapReason) {
        let queued = {
            let mut queue = self
                .delivery
                .lock()
                .expect("managed notification delivery drain");
            std::mem::take(&mut *queue)
        };
        self.record_queue_drops(&queued, reason);
        drop(queued);
    }

    fn close(&self) {
        let entry = self
            .callback_entry
            .lock()
            .expect("managed notification callback entry");
        {
            let mut deadline = self
                .close_deadline
                .lock()
                .expect("managed notification close deadline");
            deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
            self.cancellation.cancel();
        }
        drop(entry);
        let mut state = self.state.lock().expect("managed notification close");
        if state.current.is_some() || state.retired.is_some() || state.pending.is_some() {
            let generation = state.generation;
            Root::<T>::record_gap_locked(
                &mut state,
                ControllerNotificationGapReason::SourceClosed,
                generation,
                generation,
                true,
                0,
            );
        }
        for phase in [
            state.current_phase.as_ref(),
            state.retired_phase.as_ref(),
            state.pending_phase.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            phase.store(
                phase_code(ControllerNotificationSourcePhase::Draining),
                Ordering::Release,
            );
        }
        for subscription in [
            state.current.as_ref(),
            state.retired.as_ref(),
            state.pending.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            subscription.close();
        }
        drop(state);
        self.drain_delivery_queue(ControllerNotificationGapReason::SourceClosed);
        self.delivery_changed.notify_waiters();
        self.changed.notify_waiters();
    }
}
#[cfg(test)]
pub(crate) struct TestNotificationRoot<T>(Arc<Root<T>>);

#[cfg(test)]
impl<T> Clone for TestNotificationRoot<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(test)]
pub(crate) fn new_test_notification_root<T: Send + 'static>(
    controller: &MaterialConnectionController,
    contract: ServiceContract,
    codec: Arc<dyn MessageCodec<T>>,
) -> TestNotificationRoot<T> {
    let owner = &controller.0;
    let charge = owner
        .environment
        .root()
        .reserve_environment(ResourceLimits {
            sdk_bytes: 16384 + codec.application_bytes(),
            items: 4,
            tasks: 2,
            work_slots: 1,
            timers: 1,
            ..ResourceLimits::default()
        })
        .expect("test notification root charge");
    let status_charge = owner
        .environment
        .root()
        .reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            ..ResourceLimits::default()
        })
        .expect("test notification root status charge");
    let callback = ApplicationGroup::new_local(
        owner
            .environment
            .root()
            .application_services()
            .expect("test notification root application services"),
        CancellationToken::new(),
    )
    .expect("test notification root callback group");
    let root = Arc::new(Root {
        controller: Arc::downgrade(owner),
        contract,
        resources: Mutex::new(Some(RootResources {
            codec,
            observer: None,
            event_observer: None,
            callback,
            _charge: charge,
        })),
        _status_charge: status_charge,
        resources_released: AtomicBool::new(false),
        application_bytes: 1024,
        delivery: Mutex::new(std::collections::VecDeque::with_capacity(16)),
        delivery_changed: Notify::new(),
        active_delivery: Mutex::new(None),
        callback_entry: Mutex::new(()),
        prefer_gap: AtomicBool::new(true),
        delivery_pending: Arc::new(AtomicUsize::new(0)),
        self_weak: OnceLock::new(),
        published_generation: AtomicU64::new(owner.publication_generation.load(Ordering::Acquire)),
        delivery_generation: AtomicU64::new(owner.publication_generation.load(Ordering::Acquire)),
        policy: NotificationDropPolicy::KeepLatest,
        options: ControllerNotificationOptions::default(),
        state: Mutex::new(NotificationState {
            current: None,
            retired: None,
            pending: None,
            pending_session: None,
            pending_generation: None,
            pending_phase: None,
            current_phase: None,
            retired_phase: None,
            generation: 0,
            source_phase: ControllerNotificationSourcePhase::Current,
            gap: None,
            gap_emitted: None,
            reader_gap_generation: 0,
            reader_gap_sequence: 0,
            service_failure: None,
            controller_failure: None,
        }),
        cancellation: CancellationToken::new(),
        close_deadline: Mutex::new(None),
        changed: Notify::new(),
        handles: AtomicUsize::new(1),
        done: AtomicBool::new(false),
        delivery_done: AtomicBool::new(true),
    });
    root.self_weak
        .set(Arc::downgrade(&root))
        .expect("test notification root self reference");
    if let Some(probe) = NOTIFICATION_LOCK_ORDER_PROBE
        .lock()
        .expect("notification lock-order probe")
        .as_ref()
    {
        probe
            .state
            .lock()
            .expect("notification lock-order root")
            .root = Arc::as_ptr(&root) as usize;
    }
    let hook: Arc<dyn NotificationCandidateHook> = root.clone();
    owner.register_notification_candidate_hook(Arc::downgrade(&hook));
    owner.notification_roots.fetch_add(1, Ordering::AcqRel);
    TestNotificationRoot(root)
}

#[cfg(test)]
pub(crate) fn start_test_notification_root<T: Send + 'static>(
    root: TestNotificationRoot<T>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { root.0.run().await })
}

#[cfg(test)]
pub(crate) fn close_test_notification_root<T>(root: &TestNotificationRoot<T>) {
    root.0.close();
}

#[cfg(test)]
pub(crate) fn test_notification_root_attached<T>(root: &TestNotificationRoot<T>) -> bool {
    root.0
        .state
        .lock()
        .expect("test notification root snapshot")
        .current
        .is_some()
}

#[cfg(test)]
pub(crate) fn exercise_test_old_input_rejection<T: Send + 'static>(
    root: &TestNotificationRoot<T>,
    admit: bool,
) {
    let phase = Arc::new(AtomicU8::new(phase_code(
        ControllerNotificationSourcePhase::Current,
    )));
    let entry = Mutex::new(());
    let cancellation = CancellationToken::new();
    let task = EncodedNotification::new(0, CancellationToken::new(), |_| async { Ok(()) });
    let control = task.control();
    let eligible = if admit {
        root.0
            .source_admit(0, &phase, &control, &entry, &cancellation)
    } else {
        root.0.source_eligible(
            0,
            phase_code(ControllerNotificationSourcePhase::Current),
            &control,
        )
    };
    assert!(!eligible);
    assert!(!EncodedNotification::try_admit_control(&control));
}

#[cfg(test)]
pub(crate) fn exercise_test_notification_publication<T: Send + 'static>(
    root: &TestNotificationRoot<T>,
) {
    let controller = root.0.controller.upgrade().unwrap();
    let state = controller.state.lock().unwrap();
    let generation = state.current.as_ref().unwrap().generation;
    // Replay the idempotent publication fence under its original Controller
    // lock. This neither invents a Session nor advances its generation.
    controller.notify_notification_publication_stage(generation);
}

impl<T> ControllerNotificationSubscription<T> {
    pub fn close(&self) {
        self.0.close();
    }
    pub fn snapshot(&self) -> ControllerNotificationSnapshot {
        let state = self.0.state.lock().expect("managed notification snapshot");
        ControllerNotificationSnapshot {
            generation: state.generation,
            source_phase: state.source_phase,
            observed_sources: usize::from(state.current.is_some())
                + usize::from(state.retired.is_some())
                + usize::from(state.pending.is_some()),
            attached: state.current.is_some(),
            closing: self.0.cancellation.is_cancelled(),
            gap: state.gap.clone(),
            service_failure: state.service_failure,
            controller_failure: state.controller_failure,
        }
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let state = self.0.state.lock().expect("managed notification cleanup");
        let mut pending = u64::from(!self.0.done.load(Ordering::Acquire))
            + u64::from(!self.0.delivery_done.load(Ordering::Acquire))
            + u64::from(!self.0.resources_released.load(Ordering::Acquire));
        pending += self.0.delivery_pending.load(Ordering::Acquire) as u64;
        for subscription in [
            state.current.as_ref(),
            state.retired.as_ref(),
            state.pending.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            pending += subscription.cleanup_status().pending_callbacks;
        }
        let deadline_elapsed = self
            .0
            .close_deadline
            .lock()
            .expect("managed notification cleanup deadline")
            .is_some_and(|deadline| Instant::now() >= deadline);
        let complete = self.0.cancellation.is_cancelled() && pending == 0;
        let status = CleanupStatus {
            complete,
            cleanup_incomplete: !complete || (deadline_elapsed && pending != 0),
            pending_callbacks: pending,
        };
        drop(state);
        if status.complete {
            self.0.try_release_resources();
        }
        status
    }
    pub async fn wait_closed(&self, timeout: Duration) -> CleanupStatus {
        self.wait_cleanup(timeout).await
    }
    pub async fn wait_cleanup(&self, timeout: Duration) -> CleanupStatus {
        if self.0.controller.upgrade().is_none_or(|controller| {
            controller.cancellation.is_cancelled() || controller.environment.root().is_closed()
        }) {
            self.0.close();
        }
        let self_wait = CONTROLLER_NOTIFICATION_ROOT
            .try_with(|root| *root == Arc::as_ptr(&self.0) as usize)
            .unwrap_or(false);
        if self_wait {
            let status = self.cleanup_status();
            return CleanupStatus {
                complete: false,
                cleanup_incomplete: true,
                pending_callbacks: status.pending_callbacks.max(1),
            };
        }
        let requested = Instant::now() + timeout.min(Duration::from_secs(60));
        let until = self
            .0
            .close_deadline
            .lock()
            .expect("managed notification wait deadline")
            .map_or(requested, |deadline| requested.min(deadline));
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! {_=changed=>{},_=tokio::time::sleep_until(until)=>return self.cleanup_status()}
        }
    }
}
impl ControllerServiceClient {
    pub fn subscribe_notification<T: Send + 'static>(
        &self,
        contract: ServiceContract,
        codec: Arc<dyn MessageCodec<T>>,
        policy: NotificationDropPolicy,
        observer: Arc<dyn ServiceNotificationObserver<T>>,
    ) -> Result<ControllerNotificationSubscription<T>, ControllerServiceError> {
        self.subscribe_notification_with_options(
            contract,
            codec,
            policy,
            observer,
            ControllerNotificationOptions::default(),
        )
    }

    pub fn subscribe_notification_with_options<T: Send + 'static>(
        &self,
        contract: ServiceContract,
        codec: Arc<dyn MessageCodec<T>>,
        policy: NotificationDropPolicy,
        observer: Arc<dyn ServiceNotificationObserver<T>>,
        options: ControllerNotificationOptions,
    ) -> Result<ControllerNotificationSubscription<T>, ControllerServiceError> {
        self.subscribe_notification_inner(contract, codec, policy, Some(observer), None, options)
    }

    pub fn subscribe_notification_events_with_options<T: Send + 'static>(
        &self,
        contract: ServiceContract,
        codec: Arc<dyn MessageCodec<T>>,
        policy: NotificationDropPolicy,
        observer: Arc<dyn ControllerNotificationObserver<T>>,
        options: ControllerNotificationOptions,
    ) -> Result<ControllerNotificationSubscription<T>, ControllerServiceError> {
        self.subscribe_notification_inner(contract, codec, policy, None, Some(observer), options)
    }

    fn subscribe_notification_inner<T: Send + 'static>(
        &self,
        contract: ServiceContract,
        codec: Arc<dyn MessageCodec<T>>,
        policy: NotificationDropPolicy,
        observer: Option<Arc<dyn ServiceNotificationObserver<T>>>,
        event_observer: Option<Arc<dyn ControllerNotificationObserver<T>>>,
        options: ControllerNotificationOptions,
    ) -> Result<ControllerNotificationSubscription<T>, ControllerServiceError> {
        if !matches!(options.max_observed_sessions, 1 | 2) {
            return Err(MaterialControllerError::Configuration.into());
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| MaterialControllerError::Configuration)?;
        let owner = &self.controller.0;
        let definition = owner
            .options
            .managed_services
            .iter()
            .find(|service| service.definition.namespace() == self.namespace)
            .ok_or(MaterialControllerError::ServiceUnavailable)?;
        let codec_bytes = codec.application_bytes();
        let observer_bytes = observer.as_ref().map_or_else(
            || {
                event_observer
                    .as_ref()
                    .map_or(0, |value| value.application_bytes())
            },
            |value| value.application_bytes(),
        );
        if contract.namespace() != self.namespace
            || contract.shape() != ServiceShape::Notify
            || contract.semantics() != ServiceSemantics::Observation
            || !definition
                .definition
                .methods()
                .iter()
                .any(|method| method.method.type_id() == contract.type_id())
            || codec_bytes == 0
            || observer_bytes == 0
            || codec_bytes > 1 << 30
            || observer_bytes > 1 << 30
        {
            return Err(ServiceError(ServiceFailure::ContractMismatch).into());
        }
        if owner.cancellation.is_cancelled() || owner.environment.root().is_closed() {
            return Err(MaterialControllerError::Closed.into());
        }
        let application_bytes = observer_bytes;
        // Root capture and its sole publication observer are bounded locally.
        // Each actual Session subscriber retains its own accounted mailbox and
        // callback lifetime; no publication can release an older callback.
        let charge = owner
            .environment
            .root()
            .reserve_environment(ResourceLimits {
                sdk_bytes: 16384 + codec_bytes + application_bytes + self.namespace.len() as u64,
                items: 4,
                tasks: 2,
                work_slots: 1,
                timers: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialControllerError::Capacity)?;
        let status_charge = owner
            .environment
            .root()
            .reserve_environment(ResourceLimits {
                sdk_bytes: 8192 + self.namespace.len() as u64,
                items: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialControllerError::Capacity)?;
        let cancellation = owner.cancellation.child_token();
        let callback = ApplicationGroup::new_local(
            owner
                .environment
                .root()
                .application_services()
                .map_err(|_| MaterialControllerError::Capacity)?,
            cancellation.clone(),
        )
        .map_err(|_| MaterialControllerError::Capacity)?;
        owner
            .notification_roots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 32).then_some(count + 1)
            })
            .map_err(|_| MaterialControllerError::Capacity)?;
        let delivery_pending = Arc::new(AtomicUsize::new(0));
        let root = Arc::new(Root {
            controller: Arc::downgrade(owner),
            contract,
            resources: Mutex::new(Some(RootResources {
                codec,
                observer,
                event_observer,
                callback,
                _charge: charge,
            })),
            _status_charge: status_charge,
            resources_released: AtomicBool::new(false),
            application_bytes,
            delivery: Mutex::new(std::collections::VecDeque::with_capacity(16)),
            delivery_changed: Notify::new(),
            active_delivery: Mutex::new(None),
            callback_entry: Mutex::new(()),
            prefer_gap: AtomicBool::new(true),
            delivery_pending,
            self_weak: OnceLock::new(),
            published_generation: AtomicU64::new(0),
            delivery_generation: AtomicU64::new(0),
            policy,
            options,
            state: Mutex::new(NotificationState {
                current: None,
                retired: None,
                pending: None,
                pending_session: None,
                pending_generation: None,
                pending_phase: None,
                current_phase: None,
                retired_phase: None,
                generation: 0,
                source_phase: ControllerNotificationSourcePhase::Current,
                gap: None,
                gap_emitted: None,
                reader_gap_generation: 0,
                reader_gap_sequence: 0,
                service_failure: None,
                controller_failure: None,
            }),
            cancellation,
            close_deadline: Mutex::new(None),
            changed: Notify::new(),
            handles: AtomicUsize::new(1),
            done: AtomicBool::new(false),
            delivery_done: AtomicBool::new(false),
        });
        root.self_weak
            .set(Arc::downgrade(&root))
            .expect("managed notification root self reference");
        let hook: Arc<dyn NotificationCandidateHook> = root.clone();
        owner.register_notification_candidate_hook(Arc::downgrade(&hook));
        // Keep one worker reservation for the root state machine and one for
        // the serial delivery worker; the controller worker owns its original
        // reservation independently.
        owner.workers.fetch_add(2, Ordering::AcqRel);
        let worker = root.clone();
        let original = Worker(owner.clone());
        runtime.spawn(async move {
            let _original = original;
            worker.run().await;
            worker.done.store(true, Ordering::Release);
            worker.try_release_resources();
            worker.changed.notify_waiters();
            _original.0.changed.notify_waiters();
            drop(_original);
        });
        let delivery_worker = root.clone();
        let original_delivery = Worker(owner.clone());
        runtime.spawn(async move {
            let _delivery = original_delivery;
            delivery_worker.run_delivery().await;
            delivery_worker.delivery_done.store(true, Ordering::Release);
            delivery_worker.try_release_resources();
            delivery_worker.changed.notify_waiters();
            _delivery.0.changed.notify_waiters();
            drop(_delivery);
        });
        Ok(ControllerNotificationSubscription(root))
    }
}
struct ControllerEventBridge<T> {
    root: Arc<Root<T>>,
    session: crate::crypto_v4::SessionLink,
    generation: u64,
    phase: Arc<AtomicU8>,
}
impl<T> fmt::Debug for ControllerEventBridge<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControllerEventBridge { <opaque> }")
    }
}
#[async_trait]
impl<T: Send + 'static> ServiceNotificationObserver<T> for ControllerEventBridge<T> {
    fn application_bytes(&self) -> u64 {
        self.root.application_bytes()
    }

    async fn observe(
        &self,
        value: T,
        context: crate::NotificationContext,
    ) -> Result<(), ServiceError> {
        self.root
            .deliver_notification(
                value,
                context,
                self.generation,
                self.phase.clone(),
                &self.session,
            )
            .await
    }
}

#[async_trait]
impl<T: Send + 'static> NotificationScheduler for Root<T> {
    fn application_bytes(&self) -> u64 {
        Root::<T>::application_bytes(self)
    }

    fn source_changed(&self) {
        self.delivery_changed.notify_one();
        if let Some(controller) = self.controller.upgrade() {
            controller.changed.notify_waiters();
        }
        self.changed.notify_waiters();
    }

    fn source_gap(&self, generation: u64, sequence: u64) {
        let mut state = self.state.lock().expect("managed notification source gap");
        if state.reader_gap_generation == generation && sequence <= state.reader_gap_sequence {
            return;
        }
        state.reader_gap_generation = generation;
        state.reader_gap_sequence = sequence;
        Self::record_gap_locked(
            &mut state,
            ControllerNotificationGapReason::DroppedBudget,
            generation,
            generation,
            true,
            1,
        );
        drop(state);
        self.source_changed();
    }

    fn source_failed(
        &self,
        generation: u64,
        failure: ServiceFailure,
        application_entered: bool,
        control: &EncodedControl,
    ) {
        if !EncodedNotification::claim_drop_control(control) {
            return;
        }
        let reason = match failure {
            ServiceFailure::PermissionDenied => ControllerNotificationGapReason::SourceUnauthorized,
            ServiceFailure::DeadlineExceeded => ControllerNotificationGapReason::Expired,
            ServiceFailure::DecodeFailed => ControllerNotificationGapReason::DecodeError,
            ServiceFailure::ResourceExhausted => ControllerNotificationGapReason::DroppedBudget,
            ServiceFailure::Canceled | ServiceFailure::Closed => {
                ControllerNotificationGapReason::SourceClosed
            }
            _ if application_entered => ControllerNotificationGapReason::HandlerError,
            _ => ControllerNotificationGapReason::SourceClosed,
        };
        let mut state = self
            .state
            .lock()
            .expect("managed notification source failure");
        Self::record_gap_locked(
            &mut state,
            reason,
            generation,
            generation,
            true,
            u64::from(!application_entered),
        );
        drop(state);
        self.emit_pending_gap();
    }

    fn source_eligible(
        &self,
        generation: u64,
        phase_code_value: u8,
        control: &EncodedControl,
    ) -> bool {
        let (eligible, dropped, phase, published_generation) = {
            let _entry = self
                .callback_entry
                .lock()
                .expect("managed notification source fence");
            #[cfg(test)]
            block_test_stage(
                self as *const Self as usize,
                NotificationLockOrderStage::OldInputRejection,
            );
            let candidate = phase_code_value == SOURCE_CANDIDATE;
            let phase = phase_from_code(phase_code_value);
            let published_generation = self.published_generation.load(Ordering::Acquire);
            let eligible = !candidate
                && !self.cancellation.is_cancelled()
                && generation <= self.delivery_generation.load(Ordering::Acquire)
                && !(matches!(phase, ControllerNotificationSourcePhase::Draining)
                    && (self.options.observation
                        == ControllerNotificationObservation::CurrentOnly
                        || self.options.max_observed_sessions == 1))
                && !(matches!(phase, ControllerNotificationSourcePhase::Retained)
                    && (self.options.observation != ControllerNotificationObservation::DrainAware
                        || self.options.max_observed_sessions == 1))
                && !(matches!(phase, ControllerNotificationSourcePhase::Draining)
                    && generation > published_generation)
                && !((self.options.observation == ControllerNotificationObservation::CurrentOnly
                    || self.options.max_observed_sessions == 1)
                    && generation < published_generation);
            let dropped = !eligible && EncodedNotification::claim_drop_control(control);
            (eligible, dropped, phase, published_generation)
        };
        if dropped {
            let mut state = self
                .state
                .lock()
                .expect("managed notification source fence gap");
            Self::record_gap_locked(
                &mut state,
                if matches!(phase, ControllerNotificationSourcePhase::Draining) {
                    ControllerNotificationGapReason::SourceClosed
                } else {
                    ControllerNotificationGapReason::Handoff
                },
                generation,
                published_generation.max(generation),
                true,
                1,
            );
            drop(state);
            self.emit_pending_gap();
        }
        eligible
    }

    fn source_admit(
        &self,
        generation: u64,
        source_phase: &Arc<AtomicU8>,
        control: &EncodedControl,
        subscriber_entry: &Mutex<()>,
        subscriber_cancellation: &CancellationToken,
    ) -> bool {
        let (eligible, admitted, dropped, phase, published_generation) = {
            let _root_entry = self
                .callback_entry
                .lock()
                .expect("managed notification source admission");
            let _subscriber_entry = subscriber_entry
                .lock()
                .expect("managed subscriber source admission");
            #[cfg(test)]
            block_test_stage(
                self as *const Self as usize,
                NotificationLockOrderStage::OldInputRejection,
            );
            let phase_code_value = source_phase.load(Ordering::Acquire);
            let phase = phase_from_code(phase_code_value);
            let published_generation = self.published_generation.load(Ordering::Acquire);
            let eligible = !self.cancellation.is_cancelled()
                && !subscriber_cancellation.is_cancelled()
                && phase_code_value != SOURCE_CANDIDATE
                && generation <= self.delivery_generation.load(Ordering::Acquire)
                && !(matches!(phase, ControllerNotificationSourcePhase::Draining)
                    && (self.options.observation
                        == ControllerNotificationObservation::CurrentOnly
                        || self.options.max_observed_sessions == 1))
                && !(matches!(phase, ControllerNotificationSourcePhase::Retained)
                    && (self.options.observation != ControllerNotificationObservation::DrainAware
                        || self.options.max_observed_sessions == 1))
                && !(matches!(phase, ControllerNotificationSourcePhase::Draining)
                    && generation > published_generation)
                && !((self.options.observation == ControllerNotificationObservation::CurrentOnly
                    || self.options.max_observed_sessions == 1)
                    && generation < published_generation);
            let admitted = eligible && EncodedNotification::try_admit_control(control);
            let dropped = !eligible && EncodedNotification::claim_drop_control(control);
            (eligible, admitted, dropped, phase, published_generation)
        };
        if dropped {
            let mut state = self
                .state
                .lock()
                .expect("managed notification source admission gap");
            Self::record_gap_locked(
                &mut state,
                if matches!(phase, ControllerNotificationSourcePhase::Draining) {
                    ControllerNotificationGapReason::SourceClosed
                } else {
                    ControllerNotificationGapReason::Handoff
                },
                generation,
                published_generation.max(generation),
                true,
                1,
            );
            drop(state);
            self.emit_pending_gap();
        }
        eligible && admitted
    }

    fn try_schedule(
        &self,
        task: EncodedNotification,
    ) -> std::result::Result<(), EncodedNotification> {
        if self.cancellation.is_cancelled() {
            return Err(task);
        }
        self.delivery_pending.fetch_add(1, Ordering::AcqRel);
        let delivery = RootDelivery::Encoded {
            task,
            completion: oneshot::channel().0,
            ticket: DeliveryTicket(self.delivery_pending.clone()),
        };
        match self.enqueue_delivery(delivery) {
            Ok(()) => Ok(()),
            Err(delivery) => {
                let task = match delivery {
                    RootDelivery::Encoded { task, .. } => task,
                    RootDelivery::Gap { .. } => unreachable!("encoded scheduler delivery"),
                };
                let mut state = self.state.lock().expect("managed notification queue drop");
                let generation = task.generation();
                Self::record_gap_locked(
                    &mut state,
                    ControllerNotificationGapReason::DroppedBudget,
                    generation,
                    generation,
                    true,
                    1,
                );
                drop(state);
                self.emit_pending_gap();
                Err(task)
            }
        }
    }

    async fn schedule(&self, task: EncodedNotification) -> Result<(), ServiceError> {
        if self.cancellation.is_cancelled() {
            return Err(ServiceError(ServiceFailure::Closed));
        }
        self.delivery_pending.fetch_add(1, Ordering::AcqRel);
        let (completion, completed) = oneshot::channel();
        let delivery = RootDelivery::Encoded {
            task,
            completion,
            ticket: DeliveryTicket(self.delivery_pending.clone()),
        };
        self.enqueue_delivery(delivery)
            .map_err(|_| ServiceError(ServiceFailure::ResourceExhausted))?;
        completed
            .await
            .map_err(|_| ServiceError(ServiceFailure::Closed))?
    }
}

impl<T: Send + 'static> NotificationCandidateHook for Root<T> {
    fn candidate(&self, session: Session) {
        let Some(controller) = self.controller.upgrade() else {
            return;
        };
        if self.cancellation.is_cancelled() {
            return;
        }
        let mut state = self
            .state
            .lock()
            .expect("managed notification candidate hook");
        if self.cancellation.is_cancelled()
            || state
                .pending_session
                .as_ref()
                .is_some_and(|pending| pending.same_original(&session))
        {
            return;
        }
        let generation = controller
            .publication_generation
            .load(Ordering::Acquire)
            .saturating_add(1);
        let observed = usize::from(state.current.is_some())
            + usize::from(state.retired.is_some())
            + usize::from(state.pending.is_some());
        if state.pending.is_some() || observed >= self.options.max_observed_sessions {
            Root::<T>::record_gap_locked(
                &mut state,
                ControllerNotificationGapReason::Unattached,
                generation,
                generation,
                true,
                0,
            );
        } else {
            let Some(root) = self.self_weak.get().and_then(Weak::upgrade) else {
                return;
            };
            let phase = Arc::new(AtomicU8::new(SOURCE_CANDIDATE));
            match root.subscribe_session(&session, generation, phase.clone()) {
                Ok(subscription) => {
                    state.pending = Some(subscription);
                    state.pending_session = Some(session);
                    state.pending_generation = Some(generation);
                    state.pending_phase = Some(phase);
                    state.service_failure = None;
                    state.controller_failure = None;
                }
                Err(error) => {
                    state.service_failure = Some(error);
                    Root::<T>::record_gap_locked(
                        &mut state,
                        ControllerNotificationGapReason::Unattached,
                        generation,
                        generation,
                        true,
                        0,
                    );
                }
            }
        }
        drop(state);
        self.emit_pending_gap();
        self.changed.notify_waiters();
    }

    fn publication_stage(&self, generation: u64) {
        #[cfg(test)]
        block_test_stage(
            self as *const Self as usize,
            NotificationLockOrderStage::Publication,
        );
        let _entry = self
            .callback_entry
            .lock()
            .expect("managed notification publication entry");
        self.published_generation
            .fetch_max(generation, Ordering::AcqRel);
    }

    fn publication_flush(&self, generation: u64, session: &Session) {
        if self.cancellation.is_cancelled() {
            return;
        }
        let mut state = self
            .state
            .lock()
            .expect("managed notification publication hook");
        if self.cancellation.is_cancelled()
            || generation < self.published_generation.load(Ordering::Acquire)
        {
            return;
        }
        let previous_generation = state.generation;
        if state
            .pending_session
            .as_ref()
            .is_some_and(|pending| pending.same_original(session))
            && let Some(phase) = state.pending_phase.as_ref()
        {
            phase.store(
                phase_code(ControllerNotificationSourcePhase::Current),
                Ordering::Release,
            );
        }
        if generation > previous_generation {
            if let Some(phase) = state.current_phase.as_ref() {
                let phase_value = if self.options.observation
                    == ControllerNotificationObservation::CurrentOnly
                    || self.options.max_observed_sessions == 1
                {
                    ControllerNotificationSourcePhase::Draining
                } else {
                    ControllerNotificationSourcePhase::Retained
                };
                phase.store(phase_code(phase_value), Ordering::Release);
            }
            if let Some(current) = state.current.as_ref()
                && (self.options.observation == ControllerNotificationObservation::CurrentOnly
                    || self.options.max_observed_sessions == 1)
            {
                current.close();
            }
            Root::<T>::record_gap_locked(
                &mut state,
                ControllerNotificationGapReason::Handoff,
                previous_generation,
                generation,
                true,
                0,
            );
            state.source_phase = if self.options.observation
                == ControllerNotificationObservation::CurrentOnly
                || self.options.max_observed_sessions == 1
            {
                ControllerNotificationSourcePhase::Draining
            } else {
                ControllerNotificationSourcePhase::Retained
            };
        }
        self.delivery_generation
            .fetch_max(generation, Ordering::AcqRel);
        drop(state);
        self.emit_pending_gap();
        self.changed.notify_waiters();
    }
}
impl<T> Root<T> {
    fn record_gap_locked(
        state: &mut NotificationState<T>,
        reason: ControllerNotificationGapReason,
        from_generation: u64,
        to_generation: u64,
        possible_gap: bool,
        known_dropped: u64,
    ) {
        let gap = state.gap.get_or_insert_with(|| ControllerNotificationGap {
            from_generation,
            to_generation,
            reasons: Vec::new(),
            known_dropped: 0,
            possible_gap: false,
        });
        if !gap.reasons.contains(&reason) {
            gap.reasons.push(reason);
        }
        if gap.from_generation == 0 || from_generation != 0 {
            gap.from_generation = if gap.from_generation == 0 {
                from_generation
            } else {
                gap.from_generation.min(from_generation)
            };
        }
        gap.to_generation = gap.to_generation.max(to_generation);
        gap.known_dropped = gap.known_dropped.saturating_add(known_dropped);
        gap.possible_gap |= possible_gap;
    }

    fn emit_pending_gap(&self) {
        self.delivery_changed.notify_one();
    }
}
impl<T: Send + 'static> Root<T> {
    fn delivery_allowed(&self, source_generation: u64, source_phase: &Arc<AtomicU8>) -> bool {
        if self.cancellation.is_cancelled()
            || source_generation > self.delivery_generation.load(Ordering::Acquire)
            || source_phase.load(Ordering::Acquire) == SOURCE_CANDIDATE
        {
            return false;
        }
        let phase = phase_from_code(source_phase.load(Ordering::Acquire));
        if matches!(phase, ControllerNotificationSourcePhase::Draining)
            && (self.options.observation == ControllerNotificationObservation::CurrentOnly
                || self.options.max_observed_sessions == 1)
        {
            return false;
        }
        if matches!(phase, ControllerNotificationSourcePhase::Retained)
            && (self.options.observation != ControllerNotificationObservation::DrainAware
                || self.options.max_observed_sessions == 1)
        {
            return false;
        }
        if matches!(phase, ControllerNotificationSourcePhase::Draining)
            && source_generation > self.published_generation.load(Ordering::Acquire)
        {
            return false;
        }
        if (self.options.observation == ControllerNotificationObservation::CurrentOnly
            || self.options.max_observed_sessions == 1)
            && source_generation < self.published_generation.load(Ordering::Acquire)
        {
            return false;
        }
        true
    }

    async fn deliver_notification(
        &self,
        value: T,
        context: crate::NotificationContext,
        source_generation: u64,
        source_phase: Arc<AtomicU8>,
        source_session: &crate::crypto_v4::SessionLink,
    ) -> Result<(), ServiceError> {
        let allowed = {
            let _entry = self
                .callback_entry
                .lock()
                .expect("managed notification callback entry");
            self.delivery_allowed(source_generation, &source_phase)
                && !context.cancellation.is_cancelled()
                && context.invocation.check_cancellation().is_ok()
        };
        if !allowed {
            let reason = if matches!(
                phase_from_code(source_phase.load(Ordering::Acquire)),
                ControllerNotificationSourcePhase::Draining
            ) {
                ControllerNotificationGapReason::SourceClosed
            } else {
                ControllerNotificationGapReason::Handoff
            };
            let mut state = self
                .state
                .lock()
                .expect("managed notification dropped delivery");
            Self::record_gap_locked(
                &mut state,
                reason,
                source_generation,
                self.published_generation
                    .load(Ordering::Acquire)
                    .max(source_generation),
                true,
                1,
            );
            drop(state);
            self.emit_pending_gap();
            return Ok(());
        }
        if let Some(observer) = self.event_observer() {
            // Project the original source's current drain state after decoding.
            // The weak link neither retains a replacement nor reacquires a Session.
            // Sample outside root/callback locks to preserve Session lock order.
            let phase = if source_session
                .session()
                .is_ok_and(|session| session.application_draining())
            {
                ControllerNotificationSourcePhase::Draining
            } else {
                phase_from_code(source_phase.load(Ordering::Acquire))
            };
            observer
                .observe(ControllerNotificationEvent::Notification {
                    value,
                    context,
                    source_generation,
                    source_phase: phase,
                })
                .await
        } else if let Some(observer) = self.legacy_observer() {
            observer.observe(value, context).await
        } else {
            Ok(())
        }
    }

    async fn dispatch_gap(&self, gap: ControllerNotificationGap) {
        let Some(observer) = self.event_observer() else {
            return;
        };
        let Some(group) = self.callback_runtime() else {
            return;
        };
        let position = match group.local_ordinary().await {
            Ok(position) => position,
            Err(_) => return,
        };
        let Some(controller) = self.controller.upgrade() else {
            return;
        };
        let environment = controller.environment.root();
        let invocation = loop {
            let available = environment.changed.notified();
            tokio::pin!(available);
            available.as_mut().enable();
            match position.enter() {
                Ok(invocation) => break invocation,
                Err(
                    crate::application_executor_v4::ApplicationInvocationError::ResourceExhausted,
                ) => {}
                Err(_) => return,
            }
            tokio::select! {
                _ = available => {},
                _ = self.cancellation.cancelled() => return,
            }
        };
        let cancellation = invocation.cancellation();
        let deadline = Instant::now() + Duration::from_secs(5);
        // Admission into the application domain is the root Close linearization
        // point. The callback itself and its destructor always run outside it.
        let callback = async {
            {
                let _entry = self
                    .callback_entry
                    .lock()
                    .expect("managed notification callback entry");
                if self.cancellation.is_cancelled()
                    || cancellation.is_cancelled()
                    || environment.is_closed()
                    || Instant::now() >= deadline
                {
                    return Err(ServiceError(ServiceFailure::Closed));
                }
            }
            observer
                .observe(ControllerNotificationEvent::ObservationGap { gap })
                .await
        };
        let callback = AssertUnwindSafe(callback).catch_unwind();
        tokio::pin!(callback);
        tokio::select! {
            _ = &mut callback => {},
            _ = self.cancellation.cancelled() => {
                cancellation.cancel();
                let _ = callback.await;
            },
            _ = cancellation.cancelled() => { let _ = callback.await; },
            _ = tokio::time::sleep_until(deadline) => {
                cancellation.cancel();
                let _ = callback.await;
            },
        }
        drop(invocation);
        drop(position);
    }

    async fn dispatch_delivery(&self, delivery: RootDelivery) {
        let root_id = self as *const Root<T> as usize;
        CONTROLLER_NOTIFICATION_ROOT
            .scope(root_id, async {
                match delivery {
                    RootDelivery::Encoded {
                        task,
                        completion,
                        ticket,
                    } => {
                        let result = task.run().await;
                        self.active_delivery
                            .lock()
                            .expect("managed active notification delivery")
                            .take();
                        let _ = completion.send(result);
                        drop(ticket);
                    }
                    RootDelivery::Gap { gap, ticket } => {
                        if !self.cancellation.is_cancelled() {
                            self.dispatch_gap(gap).await;
                        }
                        drop(ticket);
                    }
                }
            })
            .await;
        self.changed.notify_waiters();
        self.delivery_changed.notify_one();
    }

    async fn run_delivery(self: &Arc<Self>) {
        loop {
            if let Some(delivery) = self.pop_delivery() {
                self.dispatch_delivery(delivery).await;
                continue;
            }
            if self.cancellation.is_cancelled() {
                self.drain_delivery_queue(ControllerNotificationGapReason::SourceClosed);
                return;
            }
            tokio::select! {
                _ = self.delivery_changed.notified() => {},
                _ = self.cancellation.cancelled() => {},
            }
        }
    }

    fn subscribe_session(
        self: &Arc<Self>,
        session: &Session,
        generation: u64,
        phase: Arc<AtomicU8>,
    ) -> Result<ServiceNotificationSubscription<T>, ServiceError> {
        let observer: Arc<dyn ServiceNotificationObserver<T>> = Arc::new(ControllerEventBridge {
            root: self.clone(),
            session: session.link(),
            generation,
            phase: phase.clone(),
        });
        let scheduler: Arc<dyn NotificationScheduler> = self.clone();
        let peer = session
            .configured_services()
            .and_then(|services| services.notifications())
            .ok_or(ServiceError(ServiceFailure::ServiceUnavailable))?;
        let subscription = peer.subscribe_with_scheduler(
            self.contract.clone(),
            self.codec().ok_or(ServiceError(ServiceFailure::Closed))?,
            self.policy,
            observer,
            scheduler,
            generation,
            phase,
        )?;
        Ok(subscription)
    }

    async fn run(self: &Arc<Self>) {
        let Some(controller) = self.controller.upgrade() else {
            self.close();
            return;
        };
        let environment = controller.environment.root();
        loop {
            let changed = controller.changed.notified();
            let availability = environment.changed.notified();
            tokio::pin!(changed);
            tokio::pin!(availability);
            changed.as_mut().enable();
            availability.as_mut().enable();

            if self.cancellation.is_cancelled() {
                self.close();
                break;
            }

            let (publication, candidate, observed_generation) = {
                let controller_state = controller
                    .state
                    .lock()
                    .expect("managed notification publication observation");
                if controller_state.closed
                    || controller.cancellation.is_cancelled()
                    || environment.is_closed()
                {
                    (None, None, controller_state.generation)
                } else if controller_state.state == MaterialControllerState::Failed {
                    self.state
                        .lock()
                        .expect("managed notification controller failure")
                        .controller_failure = controller_state.failure;
                    (None, None, controller_state.generation)
                } else {
                    (
                        controller_state
                            .current
                            .as_ref()
                            .filter(|current| current.session.termination_cause().is_none())
                            .cloned(),
                        controller_state
                            .candidate
                            .as_ref()
                            .filter(|candidate| candidate.termination_cause().is_none())
                            .cloned(),
                        controller_state.generation,
                    )
                }
            };

            let mut notify = false;
            {
                let mut state = self
                    .state
                    .lock()
                    .expect("managed notification original positions");

                if state
                    .retired
                    .as_ref()
                    .is_some_and(|old| old.cleanup_status().complete)
                {
                    if let Some(phase) = state.retired_phase.as_ref() {
                        phase.store(
                            phase_code(ControllerNotificationSourcePhase::Draining),
                            Ordering::Release,
                        );
                    }
                    state.retired = None;
                    state.retired_phase = None;
                    let generation = state.generation;
                    Self::record_gap_locked(
                        &mut state,
                        ControllerNotificationGapReason::SourceClosed,
                        generation,
                        generation,
                        true,
                        0,
                    );
                    notify = true;
                }
                if state
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.cleanup_status().complete)
                    && let Some(pending) = state.pending.take()
                {
                    if let Some(phase) = state.pending_phase.as_ref() {
                        phase.store(
                            phase_code(ControllerNotificationSourcePhase::Draining),
                            Ordering::Release,
                        );
                    }
                    pending.close();
                    state.pending_session = None;
                    state.pending_generation = None;
                    state.pending_phase = None;
                    let generation = state.generation;
                    Self::record_gap_locked(
                        &mut state,
                        ControllerNotificationGapReason::SourceClosed,
                        generation,
                        generation,
                        true,
                        0,
                    );
                    notify = true;
                }
                if state
                    .current
                    .as_ref()
                    .is_some_and(|current| current.cleanup_status().complete)
                    && let Some(current) = state.current.take()
                {
                    if let Some(phase) = state.current_phase.as_ref() {
                        phase.store(
                            phase_code(ControllerNotificationSourcePhase::Draining),
                            Ordering::Release,
                        );
                    }
                    state.service_failure = current.failure();
                    state.current_phase = None;
                    let generation = state.generation;
                    Self::record_gap_locked(
                        &mut state,
                        ControllerNotificationGapReason::SourceClosed,
                        generation,
                        generation,
                        true,
                        0,
                    );
                    notify = true;
                }

                let candidate_matches = candidate
                    .as_ref()
                    .zip(state.pending_session.as_ref())
                    .is_some_and(|(candidate, pending)| candidate.same_original(pending));
                let pending_published = publication
                    .as_ref()
                    .zip(state.pending_session.as_ref())
                    .is_some_and(|(publication, pending)| {
                        publication.session.same_original(pending)
                    });
                let pending_replaced = candidate.is_some() && !candidate_matches
                    || state.pending_generation.is_some_and(|generation| {
                        observed_generation >= generation && !pending_published
                    });
                if state.pending.is_some() && pending_replaced {
                    if let Some(pending) = state.pending.as_ref() {
                        pending.close();
                    }
                    if let Some(phase) = state.pending_phase.as_ref() {
                        phase.store(
                            phase_code(ControllerNotificationSourcePhase::Draining),
                            Ordering::Release,
                        );
                    }
                    // Keep the pending slot occupied until the real subscriber
                    // worker exits. This prevents a replacement from exceeding
                    // the source cap while the abandoned candidate drains.
                    state.pending_session = None;
                    let generation = state.generation;
                    Self::record_gap_locked(
                        &mut state,
                        ControllerNotificationGapReason::SourceClosed,
                        generation,
                        generation,
                        true,
                        0,
                    );
                    notify = true;
                }

                // A disconnected or failed publication has no future source. Close the
                // active subscription in place and keep it until its callbacks drain;
                // this preserves the source position while a replacement is unavailable.
                if publication.is_none() {
                    if let Some(phase) = state.current_phase.as_ref() {
                        phase.store(
                            phase_code(ControllerNotificationSourcePhase::Draining),
                            Ordering::Release,
                        );
                    }
                    if let Some(current) = state.current.as_ref() {
                        current.close();
                    }
                    if self.cancellation.is_cancelled()
                        && state.current.is_none()
                        && state.retired.is_none()
                        && state.pending.is_none()
                    {
                        break;
                    }
                }

                let generation = publication.as_ref().map_or(0, |current| current.generation);

                // A source observed after its inbound plan was fixed is a late
                // attachment. It keeps the same candidate gate until publication.
                if !self.cancellation.is_cancelled()
                    && let Some(candidate_session) = candidate.as_ref()
                    && state.pending.is_none()
                    && (usize::from(state.current.is_some())
                        + usize::from(state.retired.is_some())
                        + usize::from(state.pending.is_some()))
                        < self.options.max_observed_sessions
                {
                    let candidate_generation = observed_generation.saturating_add(1);
                    let phase = Arc::new(AtomicU8::new(SOURCE_CANDIDATE));
                    match self.subscribe_session(
                        candidate_session,
                        candidate_generation,
                        phase.clone(),
                    ) {
                        Ok(subscription) => {
                            state.pending = Some(subscription);
                            state.pending_session = Some(candidate_session.clone());
                            state.pending_generation = Some(candidate_generation);
                            Self::record_gap_locked(
                                &mut state,
                                ControllerNotificationGapReason::LateAttachment,
                                candidate_generation,
                                candidate_generation,
                                true,
                                0,
                            );
                            state.pending_phase = Some(phase);
                            state.service_failure = None;
                            state.controller_failure = None;
                        }
                        Err(error) => {
                            state.service_failure = Some(error);
                            let generation = state.generation.saturating_add(1);
                            Self::record_gap_locked(
                                &mut state,
                                ControllerNotificationGapReason::Unattached,
                                generation,
                                generation,
                                true,
                                0,
                            );
                        }
                    }
                    notify = true;
                }

                let pending_publication = publication
                    .as_ref()
                    .zip(state.pending_session.as_ref())
                    .is_some_and(|(publication, pending)| {
                        publication.session.same_original(pending)
                    });
                if pending_publication && state.pending.is_some() {
                    let pending = state.pending.take().expect("checked pending source");
                    state.pending_session = None;
                    state.pending_generation = None;
                    let pending_phase = state.pending_phase.take().expect("checked pending phase");
                    pending_phase.store(
                        phase_code(ControllerNotificationSourcePhase::Current),
                        Ordering::Release,
                    );
                    if let Some(previous) = state.current.take() {
                        let previous_generation = state.generation;
                        Self::record_gap_locked(
                            &mut state,
                            ControllerNotificationGapReason::Handoff,
                            previous_generation,
                            generation,
                            true,
                            0,
                        );
                        let retired_phase =
                            state.current_phase.take().expect("checked current phase");
                        retired_phase.store(
                            phase_code(
                                if self.options.observation
                                    == ControllerNotificationObservation::CurrentOnly
                                    || self.options.max_observed_sessions == 1
                                {
                                    ControllerNotificationSourcePhase::Draining
                                } else {
                                    ControllerNotificationSourcePhase::Retained
                                },
                            ),
                            Ordering::Release,
                        );
                        if self.options.observation
                            == ControllerNotificationObservation::CurrentOnly
                            || self.options.max_observed_sessions == 1
                        {
                            previous.close();
                        }
                        state.retired_phase = Some(retired_phase);
                        state.retired = Some(previous);
                    }
                    state.current_phase = Some(pending_phase);
                    state.current = Some(pending);
                    state.generation = generation;
                    state.source_phase = ControllerNotificationSourcePhase::Current;
                    state.service_failure = None;
                    state.controller_failure = None;
                    notify = true;
                }

                // Publication fences current_only immediately. The previous source
                // cannot admit new callbacks after C2 is published, even if C2 is
                // waiting for a source slot. Drain-aware roots retain it until the
                // replacement is attached, subject to the configured source cap.
                if publication.is_some()
                    && generation != 0
                    && generation != state.generation
                    && state.retired.is_none()
                    && (self.options.observation == ControllerNotificationObservation::CurrentOnly
                        || self.options.max_observed_sessions == 1)
                    && let Some(previous) = state.current.take()
                {
                    let previous_generation = state.generation;
                    Self::record_gap_locked(
                        &mut state,
                        ControllerNotificationGapReason::Handoff,
                        previous_generation,
                        generation,
                        true,
                        0,
                    );
                    let current_phase = state.current_phase.take().expect("checked current phase");
                    current_phase.store(
                        phase_code(
                            if self.options.observation
                                == ControllerNotificationObservation::CurrentOnly
                                || self.options.max_observed_sessions == 1
                            {
                                ControllerNotificationSourcePhase::Draining
                            } else {
                                ControllerNotificationSourcePhase::Retained
                            },
                        ),
                        Ordering::Release,
                    );
                    if self.options.observation == ControllerNotificationObservation::CurrentOnly
                        || self.options.max_observed_sessions == 1
                    {
                        previous.close();
                    }
                    state.retired_phase = Some(current_phase);
                    state.source_phase = if self.options.observation
                        == ControllerNotificationObservation::CurrentOnly
                        || self.options.max_observed_sessions == 1
                    {
                        ControllerNotificationSourcePhase::Draining
                    } else {
                        ControllerNotificationSourcePhase::Retained
                    };
                    state.retired = Some(previous);
                    notify = true;
                }

                // A replacement is installed into a spare source position first. The
                // old current remains live until this attempt actually succeeds, then
                // becomes the one retired source. This keeps the source cap at two.
                let can_attempt = !self.cancellation.is_cancelled()
                    && publication.is_some()
                    && candidate.is_none()
                    && state.pending.is_none()
                    && (usize::from(state.current.is_some())
                        + usize::from(state.retired.is_some())
                        + usize::from(state.pending.is_some()))
                        < self.options.max_observed_sessions
                    && state.current.as_ref().is_none_or(|current| {
                        current.cleanup_status().complete || state.generation != generation
                    });
                if can_attempt {
                    let publication_phase = Arc::new(AtomicU8::new(phase_code(
                        ControllerNotificationSourcePhase::Current,
                    )));
                    let result = self.subscribe_session(
                        &publication
                            .as_ref()
                            .expect("checked notification publication")
                            .session,
                        generation,
                        publication_phase.clone(),
                    );
                    match result {
                        Ok(subscription) => {
                            let still_current = {
                                #[cfg(test)]
                                block_test_stage(
                                    Arc::as_ptr(self) as usize,
                                    NotificationLockOrderStage::LateAttachment,
                                );
                                let controller_state = controller
                                    .state
                                    .lock()
                                    .expect("managed notification replacement validation");
                                controller_state.current.as_ref().is_some_and(|current| {
                                    current.generation == generation
                                        && current.session.same_original(
                                            &publication
                                                .as_ref()
                                                .expect("checked notification publication")
                                                .session,
                                        )
                                })
                            };
                            if still_current && !self.cancellation.is_cancelled() {
                                Self::record_gap_locked(
                                    &mut state,
                                    ControllerNotificationGapReason::LateAttachment,
                                    generation,
                                    generation,
                                    true,
                                    0,
                                );
                                self.published_generation
                                    .fetch_max(generation, Ordering::AcqRel);
                                self.delivery_generation
                                    .fetch_max(generation, Ordering::AcqRel);
                                if let Some(previous) = state.current.take() {
                                    let previous_generation = state.generation;
                                    Self::record_gap_locked(
                                        &mut state,
                                        ControllerNotificationGapReason::Handoff,
                                        previous_generation,
                                        generation,
                                        true,
                                        0,
                                    );
                                    let retired_phase =
                                        state.current_phase.take().expect("checked current phase");
                                    retired_phase.store(
                                        phase_code(
                                            if self.options.observation
                                                == ControllerNotificationObservation::CurrentOnly
                                                || self.options.max_observed_sessions == 1
                                            {
                                                ControllerNotificationSourcePhase::Draining
                                            } else {
                                                ControllerNotificationSourcePhase::Retained
                                            },
                                        ),
                                        Ordering::Release,
                                    );
                                    if self.options.observation
                                        == ControllerNotificationObservation::CurrentOnly
                                        || self.options.max_observed_sessions == 1
                                    {
                                        previous.close();
                                    }
                                    state.retired_phase = Some(retired_phase);
                                    state.retired = Some(previous);
                                }
                                state.current_phase = Some(publication_phase);
                                state.current = Some(subscription);
                                state.source_phase = ControllerNotificationSourcePhase::Current;
                                state.generation = generation;
                                state.service_failure = None;
                                state.controller_failure = None;
                            } else {
                                subscription.close();
                                state.pending = Some(subscription);
                                state.pending_session = None;
                                state.pending_generation = Some(generation);
                                state.pending_phase = Some(publication_phase);
                            }
                            notify = true;
                        }
                        Err(error) => {
                            // Capacity and service failures are availability-sensitive.
                            // Preserve the published generation and retry only after a
                            // controller or environment availability notification.
                            state.service_failure = Some(error);
                            state.controller_failure = None;
                            Self::record_gap_locked(
                                &mut state,
                                ControllerNotificationGapReason::Unattached,
                                generation,
                                generation,
                                true,
                                0,
                            );
                            notify = true;
                        }
                    }
                }
            }
            self.emit_pending_gap();
            if notify {
                self.changed.notify_waiters();
            }

            if self.cancellation.is_cancelled() {
                self.close();
                break;
            }
            tokio::select! {
                _ = changed => {},
                _ = availability => {},
                _ = self.cancellation.cancelled() => {
                    self.close();
                    break;
                },
            }
        }
        self.close();
        loop {
            let changed = controller.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let complete = {
                let state = self
                    .state
                    .lock()
                    .expect("managed notification source cleanup");
                [
                    state.current.as_ref(),
                    state.retired.as_ref(),
                    state.pending.as_ref(),
                ]
                .into_iter()
                .flatten()
                .all(|subscription| subscription.cleanup_status().complete)
            };
            if complete {
                break;
            }
            changed.await;
        }
    }
}
