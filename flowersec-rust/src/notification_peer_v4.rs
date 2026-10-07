//! The current ordered notification lane, with independent finite subscribers.
//! Subscriber failure closes only that subscriber; the original reader keeps
//! draining authenticated messages and returning their actual stream credit.
use crate::{
    AdmissionOffer, ApplicationInvocationContext, ExecutionIdentity, ExecutionService,
    api_v4::{CleanupStatus, ReadStreamStatus, StreamReadPermit, WriteOperation},
    application_executor_v4::ApplicationGroup,
    crypto_v4::{Session, Stream},
    environment_v4::{BusinessActivity, ResourceAccount, ResourceCharge, ResourceLimits},
    rpc_wire_v4::{ApplicationHeader, HeaderScalar},
    service_contract::{
        MessageCodec, ServiceContract, ServiceError, ServiceFailure, ServiceSemantics, ServiceShape,
    },
    transport::ByteStream,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::FutureExt;
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
const KIND: &str = "flowersec.notify.v4";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationDropPolicy {
    DropNewest,
    DropOldest,
    KeepLatest,
}
#[derive(Clone, Debug)]
pub struct NotificationContext {
    pub invocation: ApplicationInvocationContext,
    pub cancellation: CancellationToken,
    pub sequence: u64,
    pub dropped_before: u64,
    pub application_input_provided: bool,
}
#[async_trait]
pub trait ServiceNotificationObserver<T>: fmt::Debug + Send + Sync + 'static {
    fn application_bytes(&self) -> u64;
    async fn observe(&self, value: T, context: NotificationContext) -> Result<()>;
}
#[async_trait]
pub trait ExecutionNotificationHandler: fmt::Debug + Send + Sync + 'static {
    fn application_bytes(&self) -> u64;
    async fn authorize(&self, context: NotificationContext) -> Result<()>;
    async fn handle(&self, payload: &[u8], context: NotificationContext) -> Result<()>;
}
#[derive(Clone, Debug)]
pub struct NotificationServiceRegistration {
    pub contract: ServiceContract,
    pub request: crate::MessageDefinition,
    pub query_allowed: bool,
    pub offer: Option<AdmissionOffer>,
    pub execution: Option<ExecutionService>,
    pub caller: Option<ExecutionIdentity>,
    pub handler: Option<Arc<dyn ExecutionNotificationHandler>>,
}
pub(crate) struct NotificationPreparation {
    group: ApplicationGroup,
    charge: ResourceCharge,
    tail: ResourceCharge,
}
struct Payload {
    bytes: Zeroizing<Vec<u8>>,
    _charge: ResourceCharge,
    _business: BusinessActivity,
}
impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone)]
struct Input {
    header: ApplicationHeader,
    payload: Bytes,
    sequence: u64,
    diagnostics: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
}
#[derive(Clone)]
pub(crate) struct EncodedControl {
    admission: Arc<AtomicU8>,
    superseded: CancellationToken,
}
type EncodedTask =
    Box<dyn FnOnce(EncodedControl) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send>;
pub(crate) struct EncodedNotification {
    generation: u64,
    cancellation: CancellationToken,
    control: EncodedControl,
    task: Option<EncodedTask>,
}
impl EncodedNotification {
    pub(crate) fn new<F, Fut>(generation: u64, cancellation: CancellationToken, task: F) -> Self
    where
        F: FnOnce(EncodedControl) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let control = EncodedControl {
            admission: Arc::new(AtomicU8::new(0)),
            superseded: CancellationToken::new(),
        };
        Self {
            generation,
            cancellation,
            control,
            task: Some(Box::new(move |control| Box::pin(task(control)))),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn ready(&self, published_generation: u64) -> bool {
        self.generation <= published_generation || self.cancellation.is_cancelled()
    }

    pub(crate) fn eligible(&self, published_generation: u64) -> bool {
        self.generation <= published_generation && !self.cancellation.is_cancelled()
    }

    pub(crate) fn control(&self) -> EncodedControl {
        self.control.clone()
    }

    pub(crate) fn same_control(left: &EncodedControl, right: &EncodedControl) -> bool {
        Arc::ptr_eq(&left.admission, &right.admission)
    }

    pub(crate) fn control_is_admitted(control: &EncodedControl) -> bool {
        control.admission.load(Ordering::Acquire) != 0
    }

    pub(crate) fn try_admit_control(control: &EncodedControl) -> bool {
        control
            .admission
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            && !control.superseded.is_cancelled()
    }

    pub(crate) fn claim_drop_control(control: &EncodedControl) -> bool {
        for expected in [0, 1] {
            if control
                .admission
                .compare_exchange(expected, 3, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
        false
    }

    pub(crate) fn supersede_control(control: &EncodedControl) -> bool {
        if control
            .admission
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            control.superseded.cancel();
            true
        } else {
            false
        }
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        let control = self.control.clone();
        (self.task.take().expect("encoded notification task"))(control).await
    }
}
#[async_trait]
pub(crate) trait NotificationScheduler: fmt::Debug + Send + Sync + 'static {
    fn application_bytes(&self) -> u64;
    fn source_eligible(&self, generation: u64, phase: u8, control: &EncodedControl) -> bool;
    fn source_admit(
        &self,
        generation: u64,
        phase: &Arc<AtomicU8>,
        control: &EncodedControl,
        subscriber_entry: &Mutex<()>,
        subscriber_cancellation: &CancellationToken,
    ) -> bool;
    fn source_changed(&self);
    fn source_gap(&self, generation: u64, sequence: u64);
    fn source_failed(
        &self,
        generation: u64,
        failure: ServiceFailure,
        application_entered: bool,
        control: &EncodedControl,
    );
    fn try_schedule(
        &self,
        notification: EncodedNotification,
    ) -> std::result::Result<(), EncodedNotification>;
    async fn schedule(&self, notification: EncodedNotification) -> Result<()>;
}
struct Mailbox {
    queue: VecDeque<Input>,
    dropped: u64,
    dropped_until: u64,
    closed: bool,
    failure: Option<ServiceError>,
}
#[async_trait]
trait Sink: Send + Sync {
    fn type_id(&self) -> u32;
    fn contract_digest(&self) -> [u8; 32];
    fn offer(self: Arc<Self>, message: Input);
    fn gap(&self, sequence: u64);
    fn close(&self);
}
struct ActiveSubscriberDelivery {
    control: EncodedControl,
    sequence: u64,
}
struct Subscriber<T> {
    parent: Weak<Core>,
    id: u64,
    account: ResourceAccount,
    group: ApplicationGroup,
    contract: ServiceContract,
    codec: Arc<dyn MessageCodec<T>>,
    observer: Arc<dyn ServiceNotificationObserver<T>>,
    scheduler: Option<Arc<dyn NotificationScheduler>>,
    source_generation: u64,
    source_phase: Arc<AtomicU8>,
    policy: NotificationDropPolicy,
    mailbox: Mutex<Mailbox>,
    changed: Notify,
    cancellation: CancellationToken,
    entry_gate: Mutex<()>,
    active_delivery: Mutex<Option<ActiveSubscriberDelivery>>,
    active: AtomicBool,
    encoded_pending: AtomicUsize,
    handles: AtomicUsize,
    charge: Mutex<Option<Arc<ResourceCharge>>>,
    _capture_charge: Arc<ResourceCharge>,
}
struct EncodedTail<T> {
    subscriber: Arc<Subscriber<T>>,
    control: Arc<Mutex<Option<EncodedControl>>>,
}
impl<T> Drop for EncodedTail<T> {
    fn drop(&mut self) {
        if self.subscriber.scheduler.is_none()
            && let Some(control) = self
                .control
                .lock()
                .expect("notification active control")
                .as_ref()
        {
            self.subscriber.clear_active_control(control);
        }
        self.subscriber
            .encoded_pending
            .fetch_sub(1, Ordering::AcqRel);
        self.subscriber.changed.notify_waiters();
        if let Some(scheduler) = &self.subscriber.scheduler {
            scheduler.source_changed();
        }
    }
}
impl<T> Subscriber<T> {
    fn close_owner(&self) {
        let _entry = self
            .entry_gate
            .lock()
            .expect("notification subscriber entry");
        let queue = {
            let mut mailbox = self.mailbox.lock().expect("notification mailbox");
            if mailbox.closed {
                return;
            }
            mailbox.closed = true;
            std::mem::take(&mut mailbox.queue)
        };
        drop(queue);
        self.cancellation.cancel();
        self.group.close();
        self.changed.notify_waiters();
        if let Some(scheduler) = &self.scheduler {
            scheduler.source_changed();
        }
        // The original worker keeps this finite subscriber position until its
        // decoder/observer actually exits. Unsubscribe only closes delivery.
    }
    fn clear_active_control(&self, control: &EncodedControl) {
        let mut active = self
            .active_delivery
            .lock()
            .expect("notification active control");
        if active
            .as_ref()
            .is_some_and(|current| EncodedNotification::same_control(&current.control, control))
        {
            active.take();
        }
    }
    fn admit_local(&self, control: &EncodedControl) -> bool {
        let _entry = self
            .entry_gate
            .lock()
            .expect("notification subscriber entry");
        let mailbox_open = !self.mailbox.lock().expect("notification mailbox").closed;
        mailbox_open
            && !self.cancellation.is_cancelled()
            && !self.group.is_cancelled()
            && EncodedNotification::try_admit_control(control)
    }
    fn take_dropped_before(&self, sequence: u64) -> u64 {
        let mut mailbox = self.mailbox.lock().expect("notification mailbox");
        if sequence > mailbox.dropped_until {
            std::mem::take(&mut mailbox.dropped)
        } else {
            0
        }
    }
}
impl<T: Send + 'static> Subscriber<T> {
    fn encoded_task(self: Arc<Self>, input: Input) -> Option<EncodedNotification> {
        {
            let mailbox = self.mailbox.lock().expect("notification encoded admission");
            if mailbox.closed {
                return None;
            }
            self.encoded_pending.fetch_add(1, Ordering::AcqRel);
        }
        let control_slot = Arc::new(Mutex::new(None));
        let tail = EncodedTail {
            subscriber: self.clone(),
            control: control_slot.clone(),
        };
        let sequence = input.sequence;
        let diagnostics = input.diagnostics.clone();
        let local_subscriber = self.scheduler.is_none().then(|| self.clone());
        let notification = EncodedNotification::new(
            self.source_generation,
            self.cancellation.clone(),
            move |control| async move {
                let _tail = tail;
                if let Some(scheduler) = &self.scheduler
                    && !scheduler.source_eligible(
                        self.source_generation,
                        self.source_phase.load(Ordering::Acquire),
                        &control,
                    )
                {
                    return Ok(());
                }
                let mut skipped = false;
                let application_entered = Arc::new(AtomicBool::new(false));
                let delivery: Result<()> = async {
                let position = tokio::select! {
                    position = self.group.ordinary(false, None) => position?,
                    _ = self.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                    _ = control.superseded.cancelled() => return Ok(()),
                };
                let invocation = position.enter()?;
                if let Some(scheduler) = &self.scheduler
                    && !scheduler.source_eligible(
                        self.source_generation,
                        self.source_phase.load(Ordering::Acquire),
                        &control,
                    )
                {
                    skipped = true;
                    drop(invocation);
                    drop(position);
                    return Ok(());
                }
                let cap = input.header.uint(5)?;
                self.account.check()?;
                if self.account.security_time()?.upper_ms >= cap {
                    skipped = true;
                    return Err(failure(ServiceFailure::DeadlineExceeded));
                }
                let mut context = NotificationContext {
                    invocation: invocation.context(),
                    cancellation: invocation.cancellation(),
                    sequence: input.sequence,
                    dropped_before: 0,
                    application_input_provided: true,
                };
                let codec = self.codec.clone();
                let bytes = input.payload.clone();
                let decode_context = context.invocation.clone();
                let scheduler = self.scheduler.clone();
                let source_generation = self.source_generation;
                let source_phase = self.source_phase.clone();
                let decoded = if crate::message_codec_v4::controlled(codec.as_ref()) {
                    if let Some(scheduler) = &scheduler {
                        if !scheduler.source_admit(
                            source_generation,
                            &source_phase,
                            &control,
                            &self.entry_gate,
                            &self.cancellation,
                        ) {
                            skipped = true;
                            return Ok(());
                        }
                    } else if !self.admit_local(&control) {
                        skipped = true;
                        return Ok(());
                    }
                    context.dropped_before = self.take_dropped_before(input.sequence);
                    codec.decode_with_context(&bytes, &decode_context)?
                } else {
                    let decode_scheduler = scheduler.clone();
                    let decode_phase = source_phase.clone();
                    let decode_account = self.account.clone();
                    let decode_closed = self.cancellation.clone();
                    let decode_control = control.clone();
                    let decode_subscriber = self.clone();
                    let decoded = tokio::task::spawn_blocking(move || {
                        decode_account.check()?;
                        if decode_closed.is_cancelled() {
                            return Err(failure(ServiceFailure::Canceled));
                        }
                        if decode_account.security_time()?.upper_ms >= cap {
                            return Err(failure(ServiceFailure::DeadlineExceeded));
                        }
                        if let Some(scheduler) = &decode_scheduler {
                            if !scheduler.source_admit(
                                source_generation,
                                &decode_phase,
                                &decode_control,
                                &decode_subscriber.entry_gate,
                                &decode_subscriber.cancellation,
                            ) {
                                return Ok(None);
                            }
                        } else if !decode_subscriber.admit_local(&decode_control) {
                            return Ok(None);
                        }
                        let dropped = decode_subscriber.take_dropped_before(sequence);
                        std::panic::catch_unwind(AssertUnwindSafe(|| {
                            codec.decode_with_context(&bytes, &decode_context)
                        }))
                        .map(|decoded| decoded.map(|value| Some((value, dropped))))
                        .unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed)))
                    })
                    .await
                    .unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed)))?;
                    match decoded {
                        Some((decoded, dropped)) => {
                            context.dropped_before = dropped;
                            decoded
                        },
                        None => {
                            skipped = true;
                            return Ok(());
                        }
                    }
                };
                self.account.check()?;
                if self.cancellation.is_cancelled()
                    || self.account.security_time()?.upper_ms >= cap
                {
                    skipped = true;
                    return Err(failure(ServiceFailure::Canceled));
                }
                if scheduler.as_ref().is_some_and(|scheduler| {
                    !scheduler.source_eligible(
                        source_generation,
                        source_phase.load(Ordering::Acquire),
                        &control,
                    )
                }) {
                    skipped = true;
                    return Ok(());
                }
                let source_rejected = Arc::new(AtomicBool::new(false));
                let callback_scheduler = scheduler.clone();
                let callback_phase = source_phase.clone();
                let callback_observer = self.observer.clone();
                let callback_context = context.clone();
                let callback_rejected = source_rejected.clone();
                let callback_account = self.account.clone();
                let callback_closed = self.cancellation.clone();
                let callback_entered = application_entered.clone();
                let callback_control = control.clone();
                let callback = async move {
                    callback_account.check()?;
                    if callback_closed.is_cancelled() || callback_context.cancellation.is_cancelled() {
                        return Err(failure(ServiceFailure::Canceled));
                    }
                    if callback_account.security_time()?.upper_ms >= cap {
                        return Err(failure(ServiceFailure::DeadlineExceeded));
                    }
                    if callback_scheduler.as_ref().is_some_and(|scheduler| {
                        !scheduler.source_eligible(
                            source_generation,
                            callback_phase.load(Ordering::Acquire),
                            &callback_control,
                        )
                    }) {
                        callback_rejected.store(true, Ordering::Release);
                        return Err(failure(ServiceFailure::Canceled));
                    }
                    callback_entered.store(true, Ordering::Release);
                    callback_observer.observe(decoded, callback_context).await
                };
                let callback_result = await_callback(
                    &self.account,
                    &self.cancellation,
                    &context.cancellation,
                    cap,
                    AssertUnwindSafe(callback).catch_unwind(),
                )
                .await;
                if source_rejected.load(Ordering::Acquire) {
                    skipped = true;
                    return Ok(());
                }
                callback_result??;
                drop(invocation);
                drop(position);
                Ok(())
            }
            .await;
                if let Err(error) = delivery
                    && let Some(scheduler) = &self.scheduler
                {
                    scheduler.source_failed(
                        self.source_generation,
                        error.0,
                        application_entered.load(Ordering::Acquire),
                        &control,
                    );
                }
                let result = if skipped { Ok(()) } else { delivery };
                if let Some(diagnostics) = diagnostics {
                    diagnostics.service_outcome(&result);
                }
                if let Err(error) = result {
                    self.mailbox
                        .lock()
                        .expect("notification callback failure")
                        .failure = Some(error);
                }
                result
            },
        );
        *control_slot.lock().expect("notification active control") = Some(notification.control());
        if let Some(subscriber) = local_subscriber {
            *subscriber
                .active_delivery
                .lock()
                .expect("notification active control") = Some(ActiveSubscriberDelivery {
                control: notification.control(),
                sequence,
            });
        }
        Some(notification)
    }
}

#[async_trait]
impl<T: Send + 'static> Sink for Subscriber<T> {
    fn type_id(&self) -> u32 {
        self.contract.type_id()
    }
    fn contract_digest(&self) -> [u8; 32] {
        self.contract.digest()
    }
    fn close(&self) {
        self.close_owner();
    }
    fn gap(&self, sequence: u64) {
        let accepted = {
            let mut mailbox = self.mailbox.lock().expect("notification mailbox");
            if mailbox.closed {
                false
            } else {
                mailbox.dropped = mailbox.dropped.saturating_add(1);
                mailbox.dropped_until = mailbox.dropped_until.max(sequence);
                true
            }
        };
        if accepted {
            if let Some(scheduler) = &self.scheduler {
                scheduler.source_gap(self.source_generation, sequence);
            }
            self.changed.notify_one();
        }
    }
    fn offer(self: Arc<Self>, mut message: Input) {
        message.diagnostics = Some(
            self.account
                .diagnostic_activity(crate::DiagnosticPhase::Application, 1),
        );
        if self.scheduler.is_some() {
            let diagnostics = message.diagnostics.clone();
            let Some(notification) = self.clone().encoded_task(message) else {
                return;
            };
            if let Some(scheduler) = &self.scheduler {
                if scheduler.try_schedule(notification).is_ok() {
                    return;
                }
                self.account
                    .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::SlowConsumers);
                if let Some(diagnostics) = diagnostics {
                    diagnostics.fail(
                        crate::DiagnosticCode::SlowConsumer,
                        crate::DiagnosticRetryDisposition::DoNotRetry,
                    );
                }
            }
            return;
        }
        let _entry = (self.scheduler.is_none()
            && self.policy == NotificationDropPolicy::KeepLatest)
            .then(|| {
                self.entry_gate
                    .lock()
                    .expect("notification subscriber entry")
            });
        let mut removed = Vec::new();
        let mut active_dropped = None;
        let mut message = Some(message);
        let _ = self.account.with_security(|| {
            if self.policy == NotificationDropPolicy::KeepLatest {
                let active = self
                    .active_delivery
                    .lock()
                    .expect("notification active control")
                    .as_ref()
                    .map(|active| (active.control.clone(), active.sequence));
                if let Some((control, sequence)) = active
                    && !EncodedNotification::control_is_admitted(&control)
                    && EncodedNotification::supersede_control(&control)
                {
                    active_dropped = Some(sequence);
                }
            }
            let mut mailbox = self.mailbox.lock().expect("notification mailbox");
            if mailbox.closed {
                return;
            }
            if self.policy == NotificationDropPolicy::KeepLatest && !mailbox.queue.is_empty() {
                removed.extend(mailbox.queue.drain(..));
            } else if mailbox.queue.len() == 16 {
                match self.policy {
                    NotificationDropPolicy::DropNewest => {
                        self.account.diagnostic_count(
                            crate::diagnostics_v4::DiagnosticCounter::SlowConsumers,
                        );
                        if let Some(diagnostics) = message
                            .as_ref()
                            .and_then(|message| message.diagnostics.as_ref())
                        {
                            diagnostics.fail(
                                crate::DiagnosticCode::SlowConsumer,
                                crate::DiagnosticRetryDisposition::DoNotRetry,
                            );
                        }
                        mailbox.dropped = mailbox.dropped.saturating_add(1);
                        mailbox.dropped_until = mailbox.dropped_until.max(
                            message
                                .as_ref()
                                .expect("original notification entry")
                                .sequence,
                        );
                        return;
                    }
                    NotificationDropPolicy::DropOldest => {
                        if let Some(old) = mailbox.queue.pop_front() {
                            removed.push(old);
                        }
                    }
                    NotificationDropPolicy::KeepLatest => {
                        removed.extend(mailbox.queue.drain(..));
                    }
                }
            }
            mailbox.dropped = mailbox.dropped.saturating_add(removed.len() as u64);
            if let Some(sequence) = removed.iter().map(|input| input.sequence).max() {
                mailbox.dropped_until = mailbox.dropped_until.max(sequence);
            }
            mailbox
                .queue
                .push_back(message.take().expect("original notification entry"));
        });
        if let Some(sequence) = active_dropped {
            let mut mailbox = self.mailbox.lock().expect("notification mailbox");
            if !mailbox.closed {
                mailbox.dropped = mailbox.dropped.saturating_add(1);
                mailbox.dropped_until = mailbox.dropped_until.max(sequence);
            }
        }
        // Destructors may return original root capacity. They never execute
        // under either the security gate or the subscriber mailbox gate.
        for removed in &removed {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::SlowConsumers);
            if let Some(diagnostics) = &removed.diagnostics {
                diagnostics.fail(
                    crate::DiagnosticCode::SlowConsumer,
                    crate::DiagnosticRetryDisposition::DoNotRetry,
                );
            }
        }
        drop(removed);
        drop(message);
        self.changed.notify_one();
    }
}
/// A public handle owns subscription lifetime, independently of its callback.
pub struct ServiceNotificationSubscription<T>(Arc<Subscriber<T>>);
impl<T> fmt::Debug for ServiceNotificationSubscription<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceNotificationSubscription { <opaque> }")
    }
}
impl<T> Clone for ServiceNotificationSubscription<T> {
    fn clone(&self) -> Self {
        self.0.handles.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}
impl<T> Drop for ServiceNotificationSubscription<T> {
    fn drop(&mut self) {
        if self.0.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.close_owner();
        }
    }
}
impl<T> ServiceNotificationSubscription<T> {
    pub fn close(&self) {
        self.0.close_owner();
    }
    pub fn pending_gap(&self) -> (u64, u64) {
        let mailbox = self.0.mailbox.lock().expect("notification mailbox");
        (mailbox.dropped, mailbox.dropped_until)
    }
    pub fn failure(&self) -> Option<ServiceError> {
        self.0.mailbox.lock().expect("notification mailbox").failure
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let active = self.0.active.load(Ordering::Acquire);
        CleanupStatus {
            complete: !active,
            cleanup_incomplete: active,
            pending_callbacks: u64::from(active),
        }
    }
    pub async fn wait_closed(&self, timeout: Duration) -> CleanupStatus {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(60));
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(deadline) => return self.cleanup_status() }
        }
    }
}
struct Output {
    header: ApplicationHeader,
    payload: Zeroizing<Vec<u8>>,
    cancellation: CancellationToken,
    result: oneshot::Sender<Result<NotificationPublication>>,
    _charge: Arc<ResourceCharge>,
    diagnostics: Arc<crate::diagnostics_v4::DiagnosticActivity>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotificationPublication {
    pub submitted: bool,
    pub accepted_bytes: u64,
    pub requested_bytes: u64,
    pub publication: crate::ServicePublication,
    pub error: Option<ServiceFailure>,
}
struct Core {
    account: ResourceAccount,
    group: ApplicationGroup,
    registrations: Arc<[NotificationServiceRegistration]>,
    session: Mutex<Option<Session>>,
    incoming: Mutex<Option<Arc<Stream>>>,
    outgoing: Mutex<Option<Arc<Stream>>>,
    subscribers: Mutex<BTreeMap<u64, Weak<dyn Sink>>>,
    next_subscriber: Mutex<u64>,
    execution: BTreeMap<u32, mpsc::Sender<Input>>,
    output: mpsc::Sender<Output>,
    cancellation: CancellationToken,
    closed: Arc<AtomicBool>,
    workers: AtomicUsize,
    handles: AtomicUsize,
    tail: crate::application_tails_v4::ApplicationTail,
    changed: Notify,
    charge: Mutex<Option<Arc<ResourceCharge>>>,
    _capture_charge: Arc<ResourceCharge>,
}
impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NotificationPeer { <opaque> }")
    }
}
pub struct NotificationPeer(Arc<Core>);
impl fmt::Debug for NotificationPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NotificationPeer { <opaque> }")
    }
}
impl Clone for NotificationPeer {
    fn clone(&self) -> Self {
        self.0.handles.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}
impl Drop for NotificationPeer {
    fn drop(&mut self) {
        if self.0.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.close();
        }
    }
}
impl NotificationPeer {
    pub(crate) fn create(
        session: &Session,
        registrations: Vec<NotificationServiceRegistration>,
    ) -> Result<Self> {
        let (_, profile, identity) = session
            .service_identity()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        let prepared = Self::prepare_installation(
            &session.application_account(),
            profile,
            identity,
            &registrations,
        )?;
        Self::create_prepared(session, registrations, prepared)
    }
    pub(crate) fn validate_installation(
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        registrations: &[NotificationServiceRegistration],
    ) -> Result<ResourceLimits> {
        if profile == 0 || registrations.len() > 256 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        for (index, registration) in registrations.iter().enumerate() {
            registration
                .contract
                .check_environment(account.environment_root())?;
            let execution = registration.contract.semantics() == ServiceSemantics::Execution;
            if execution && profile != 2 {
                return Err(failure(ServiceFailure::PermissionDenied));
            }
            if registration.contract.shape() != ServiceShape::Notify
                || registration.request.revision() != registration.contract.request_revision()?
                || (registration.request.max_message_bytes() as u64)
                    < registration.contract.uint(23)?
                || registrations[..index]
                    .iter()
                    .any(|old| old.contract.type_id() == registration.contract.type_id())
                || execution
                    != (registration.execution.is_some()
                        && registration.caller.is_some()
                        && registration.offer.is_some()
                        && registration.handler.is_some())
                || !execution
                    && (registration.execution.is_some()
                        || registration.caller.is_some()
                        || registration.handler.is_some()
                        || registration.offer.is_some())
                || registration
                    .caller
                    .as_ref()
                    .is_some_and(|caller| caller.identity_digest != identity)
                || registration.handler.as_ref().is_some_and(|handler| {
                    handler.application_bytes() == 0 || handler.application_bytes() > 1 << 30
                })
            {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
        }
        Self::graph_limits(registrations)
    }
    fn graph_limits(registrations: &[NotificationServiceRegistration]) -> Result<ResourceLimits> {
        let graph = registrations
            .iter()
            .try_fold(131072u64, |total, entry| {
                total.checked_add(4096)?.checked_add(
                    entry
                        .handler
                        .as_ref()
                        .map_or(0, |handler| handler.application_bytes()),
                )
            })
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        Ok(ResourceLimits {
            sdk_bytes: graph,
            items: registrations.len() as u64 * 17 + 132,
            tasks: registrations
                .iter()
                .filter(|registration| registration.execution.is_some())
                .count() as u64
                + 4,
            work_slots: 2,
            ..ResourceLimits::default()
        })
    }
    pub(crate) fn prepare_installation(
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        registrations: &[NotificationServiceRegistration],
    ) -> Result<NotificationPreparation> {
        let charge = account.reserve(Self::preparation_limits(registrations)?)?;
        Self::prepare_installation_prepaid(account, profile, identity, registrations, charge)
    }
    pub(crate) fn preparation_limits(
        registrations: &[NotificationServiceRegistration],
    ) -> Result<ResourceLimits> {
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            Self::graph_limits(registrations)?,
            crate::application_tails_v4::ApplicationTails::resources(),
        )?;
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            limits,
            ApplicationGroup::preparation_limits(),
        )?)
    }
    pub(crate) fn prepare_installation_prepaid(
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        registrations: &[NotificationServiceRegistration],
        mut backing: ResourceCharge,
    ) -> Result<NotificationPreparation> {
        let resources = Self::validate_installation(account, profile, identity, registrations)?;
        if !backing.matches(account, Self::preparation_limits(registrations)?) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let group_charge = backing.split(ApplicationGroup::preparation_limits())?;
        Ok(NotificationPreparation {
            group: account.application_group_prepaid(group_charge)?,
            charge: backing.split(resources)?,
            tail: backing,
        })
    }
    pub(crate) fn create_prepared(
        session: &Session,
        registrations: Vec<NotificationServiceRegistration>,
        prepared: NotificationPreparation,
    ) -> Result<Self> {
        let (_, profile, identity) = session
            .service_identity()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        let account = session.application_account();
        Self::validate_installation(&account, profile, identity, &registrations)?;
        let NotificationPreparation {
            group,
            charge,
            tail: tail_charge,
        } = prepared;
        let tail = session
            .application_tail_reserved(tail_charge)
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let charge = Arc::new(charge);
        session
            .claim_notifications()
            .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
        let (output, receiver) = mpsc::channel(4);
        let mut execution = BTreeMap::new();
        let mut receivers = Vec::new();
        for registration in &registrations {
            if registration.execution.is_some() {
                let (sender, receiver) = mpsc::channel(16);
                execution.insert(registration.contract.type_id(), sender);
                receivers.push((registration.clone(), receiver));
            }
        }
        let core = Arc::new(Core {
            account,
            group,
            registrations: registrations.into(),
            session: Mutex::new(Some(session.clone())),
            incoming: Mutex::new(None),
            outgoing: Mutex::new(None),
            subscribers: Mutex::new(BTreeMap::new()),
            next_subscriber: Mutex::new(1),
            execution,
            output,
            cancellation: tail.cancellation(),
            tail,
            closed: Arc::new(AtomicBool::new(false)),
            workers: AtomicUsize::new(2 + receivers.len()),
            handles: AtomicUsize::new(1),
            changed: Notify::new(),
            charge: Mutex::new(Some(charge.clone())),
            _capture_charge: charge,
        });
        let reader = core.clone();
        tokio::spawn(async move {
            let _tail = CoreWorker(reader.clone());
            let result = reader.read().await;
            if result.is_err() || reader.cancellation.is_cancelled() {
                reader.close();
            }
        });
        let writer = core.clone();
        tokio::spawn(async move {
            let _tail = CoreWorker(writer.clone());
            let result = writer.write(receiver).await;
            if result.is_err() || writer.cancellation.is_cancelled() {
                writer.close();
            }
        });
        for (registration, receiver) in receivers {
            let owner = core.clone();
            tokio::spawn(async move {
                let _tail = CoreWorker(owner.clone());
                owner.execute(registration, receiver).await;
            });
        }
        Ok(Self(core))
    }
    pub fn subscribe<T: Send + 'static>(
        &self,
        contract: ServiceContract,
        codec: Arc<dyn MessageCodec<T>>,
        policy: NotificationDropPolicy,
        observer: Arc<dyn ServiceNotificationObserver<T>>,
    ) -> Result<ServiceNotificationSubscription<T>> {
        self.subscribe_inner(
            contract,
            codec,
            policy,
            observer,
            None,
            0,
            Arc::new(AtomicU8::new(0)),
        )
    }

    #[allow(clippy::too_many_arguments)] // Original subscription plus its Controller source identity.
    pub(crate) fn subscribe_with_scheduler<T: Send + 'static>(
        &self,
        contract: ServiceContract,
        codec: Arc<dyn MessageCodec<T>>,
        policy: NotificationDropPolicy,
        observer: Arc<dyn ServiceNotificationObserver<T>>,
        scheduler: Arc<dyn NotificationScheduler>,
        source_generation: u64,
        source_phase: Arc<AtomicU8>,
    ) -> Result<ServiceNotificationSubscription<T>> {
        self.subscribe_inner(
            contract,
            codec,
            policy,
            observer,
            Some(scheduler),
            source_generation,
            source_phase,
        )
    }

    #[allow(clippy::too_many_arguments)] // Shared ordinary and Controller subscription admission.
    fn subscribe_inner<T: Send + 'static>(
        &self,
        contract: ServiceContract,
        codec: Arc<dyn MessageCodec<T>>,
        policy: NotificationDropPolicy,
        observer: Arc<dyn ServiceNotificationObserver<T>>,
        scheduler: Option<Arc<dyn NotificationScheduler>>,
        source_generation: u64,
        source_phase: Arc<AtomicU8>,
    ) -> Result<ServiceNotificationSubscription<T>> {
        self.0.check()?;
        if !self.0.registrations.iter().any(|registration| {
            registration.contract.digest() == contract.digest()
                && &registration.request == codec.definition()
        }) || contract.semantics() != ServiceSemantics::Observation
            || codec.definition().revision() != contract.request_revision()?
            || (codec.definition().max_message_bytes() as u64) < contract.uint(23)?
            || codec.application_bytes() == 0
            || codec.application_bytes() > 1 << 30
            || observer.application_bytes() == 0
            || observer.application_bytes() > 1 << 30
            || scheduler.as_ref().is_some_and(|scheduler| {
                scheduler.application_bytes() == 0 || scheduler.application_bytes() > 1 << 30
            })
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let charge = self.0.account.reserve(ResourceLimits {
            sdk_bytes: 8192
                + codec.application_bytes()
                + observer.application_bytes()
                + scheduler
                    .as_ref()
                    .map_or(0, |scheduler| scheduler.application_bytes())
                + contract.uint(23)?,
            items: 18,
            tasks: 1,
            ..ResourceLimits::default()
        })?;
        let group = self.0.account.application_group()?;
        let mut subscribers = self.0.subscribers.lock().expect("notification subscribers");
        subscribers.retain(|_, subscriber| subscriber.strong_count() != 0);
        if subscribers.len() >= 128
            || subscribers
                .values()
                .filter_map(Weak::upgrade)
                .filter(|subscriber| subscriber.type_id() == contract.type_id())
                .count()
                >= 32
        {
            return Err(failure(ServiceFailure::ResourceExhausted));
        }
        let mut next = self
            .0
            .next_subscriber
            .lock()
            .expect("notification subscription identity");
        let id = *next;
        *next = next
            .checked_add(1)
            .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
        let charge = Arc::new(charge);
        let subscriber = Arc::new(Subscriber {
            parent: Arc::downgrade(&self.0),
            id,
            account: self.0.account.clone(),
            group,
            contract,
            codec,
            observer,
            scheduler,
            source_generation,
            source_phase,
            policy,
            mailbox: Mutex::new(Mailbox {
                queue: VecDeque::with_capacity(16),
                dropped: 0,
                dropped_until: 0,
                closed: false,
                failure: None,
            }),
            changed: Notify::new(),
            // Normal lane FIN may retire both IO workers before Session Close.
            // The original subscriber must still observe its parent's tail close.
            cancellation: self.0.cancellation.child_token(),
            entry_gate: Mutex::new(()),
            active_delivery: Mutex::new(None),
            active: AtomicBool::new(true),
            encoded_pending: AtomicUsize::new(0),
            handles: AtomicUsize::new(1),
            charge: Mutex::new(Some(charge.clone())),
            _capture_charge: charge,
        });
        let sink: Arc<dyn Sink> = subscriber.clone();
        subscribers.insert(id, Arc::downgrade(&sink));
        drop(subscribers);
        self.0.workers.fetch_add(1, Ordering::AcqRel);
        let owner = self.0.clone();
        let current = subscriber.clone();
        tokio::spawn(async move {
            let _tail = CoreWorker(owner);
            current.run().await;
        });
        Ok(ServiceNotificationSubscription(subscriber))
    }
    pub fn prepare_encoded(
        &self,
        contract: &ServiceContract,
        payload: &[u8],
        timeout: Duration,
        execution: Option<([u8; 32], &AdmissionOffer)>,
    ) -> Result<NotificationOperation> {
        self.prepare_encoded_owned(contract, payload, timeout, execution, None)
    }
    pub(crate) fn prepare_encoded_owned(
        &self,
        contract: &ServiceContract,
        payload: &[u8],
        timeout: Duration,
        execution: Option<([u8; 32], &AdmissionOffer)>,
        prepaid: Option<(ResourceAccount, Arc<ResourceCharge>)>,
    ) -> Result<NotificationOperation> {
        self.0.check()?;
        contract.check_environment(self.0.account.environment_root())?;
        if contract.shape() != ServiceShape::Notify
            || payload.len() as u64 > contract.uint(23)?
            || timeout.is_zero()
            || timeout.as_millis() > u128::from(contract.uint(11)?)
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let now = self.0.account.security_time()?;
        let cap = now
            .lower_ms
            .checked_add(timeout.as_millis() as u64)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        if cap <= now.upper_ms {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let (account, charge) = match prepaid {
            Some((account, charge)) => {
                if !account.belongs_to(self.0.account.environment_root()) {
                    return Err(failure(ServiceFailure::PermissionDenied));
                }
                account.check()?;
                (account, charge)
            }
            None => {
                let account = self.0.account.reserve_result()?;
                let charge = Arc::new(account.reserve(ResourceLimits {
                    sdk_bytes: payload.len() as u64 * 2 + 8192,
                    items: 3,
                    tasks: 2,
                    timers: 1,
                    ..ResourceLimits::default()
                })?);
                (account, charge)
            }
        };
        let mut fields = [None; 11];
        fields[2] = Some(HeaderScalar::Uint(contract.type_id() as u64));
        fields[3] = Some(HeaderScalar::Uint(payload.len() as u64));
        fields[5] = Some(HeaderScalar::Uint(cap));
        fields[6] = Some(HeaderScalar::Bytes(contract.digest()));
        let kind = match (contract.semantics(), execution) {
            (ServiceSemantics::Observation, None) => "observation_notify",
            (ServiceSemantics::Execution, Some((operation, offer))) => {
                let cutoff = u64::from_be_bytes(
                    operation[..8]
                        .try_into()
                        .map_err(|_| failure(ServiceFailure::Protocol))?,
                );
                offer.check_interval(contract, cutoff, now.lower_ms, now.upper_ms)?;
                fields[1] = Some(HeaderScalar::Bytes(operation));
                fields[4] = Some(HeaderScalar::Bytes([0; 32]));
                fields[7] = Some(HeaderScalar::Uint(0));
                fields[8] = Some(HeaderScalar::Uint(0));
                "execution_notify"
            }
            _ => return Err(failure(ServiceFailure::ContractMismatch)),
        };
        let mut header = ApplicationHeader::create(kind, fields)?;
        if kind == "execution_notify" {
            fields[4] = Some(HeaderScalar::Bytes(crate::rpc_wire_v4::execution_digest(
                contract.encoded(),
                &header,
                payload,
            )?));
            header = ApplicationHeader::create(kind, fields)?;
        }
        Ok(NotificationOperation(Arc::new(
            NotificationOperationInner {
                diagnostics: account.diagnostic_activity(crate::DiagnosticPhase::Application, 1),
                peer: Arc::downgrade(&self.0),
                account,
                deadline: Instant::now() + Duration::from_millis(cap - now.upper_ms),
                cancellation: CancellationToken::new(),
                handles: AtomicUsize::new(1),
                changed: Notify::new(),
                state: Mutex::new(NotificationOperationState {
                    prepared: Some((header, Zeroizing::new(payload.to_vec()), charge)),
                    started: false,
                    closed: false,
                    settled: None,
                    active: false,
                    reference: None,
                    waiter: false,
                }),
            },
        )))
    }
    pub async fn publish_encoded(
        &self,
        contract: &ServiceContract,
        payload: &[u8],
        timeout: Duration,
        execution: Option<([u8; 32], &AdmissionOffer)>,
        cancellation: &CancellationToken,
    ) -> Result<NotificationPublication> {
        let operation = self.prepare_encoded(contract, payload, timeout, execution)?;
        operation.start()?;
        let outcome = operation.wait_submission(cancellation).await;
        if outcome.is_err() {
            operation.cancel();
        }
        outcome
    }
    pub(crate) fn publication_gate(&self) -> Arc<AtomicBool> {
        self.0.closed.clone()
    }
    pub(crate) fn catalog(
        &self,
        account: &ResourceAccount,
    ) -> Result<Arc<[NotificationServiceRegistration]>> {
        self.0.check()?;
        if !account.same_owner(&self.0.account) {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok(self.0.registrations.clone())
    }
    pub fn close(&self) {
        self.0.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.0.cleanup()
    }
    pub async fn wait_cleanup(&self, timeout: Duration) -> CleanupStatus {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(60));
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.0.cleanup();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(deadline) => return self.0.cleanup() }
        }
    }
}
struct NotificationOperationState {
    prepared: Option<(ApplicationHeader, Zeroizing<Vec<u8>>, Arc<ResourceCharge>)>,
    started: bool,
    closed: bool,
    settled: Option<Result<NotificationPublication>>,
    active: bool,
    reference: Option<crate::OperationReference>,
    waiter: bool,
}
struct NotificationOperationInner {
    diagnostics: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    peer: Weak<Core>,
    account: ResourceAccount,
    deadline: Instant,
    cancellation: CancellationToken,
    state: Mutex<NotificationOperationState>,
    changed: Notify,
    handles: AtomicUsize,
}
/// A once-only prepared notification. Its original publication receipt remains
/// observable after a canceled waiter or a closed Session; it grants no replay.
pub struct NotificationOperation(Arc<NotificationOperationInner>);
impl fmt::Debug for NotificationOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NotificationOperation { <opaque> }")
    }
}
impl Clone for NotificationOperation {
    fn clone(&self) -> Self {
        self.0.handles.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}
impl Drop for NotificationOperation {
    fn drop(&mut self) {
        if self.0.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.close();
        }
    }
}
impl NotificationOperation {
    pub(crate) fn capture_reference(
        &self,
        codec: &crate::OperationReferenceCodec,
        identity: &crate::ExecutionReferenceIdentity,
        contract: &ServiceContract,
    ) -> Result<()> {
        let mut state = self.0.state.lock().expect("notification operation");
        if state.started || state.closed || state.reference.is_some() {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        let header = &state
            .prepared
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::Closed))?
            .0;
        let reference = codec.capture(
            crate::ExecutionTarget {
                tenant: identity.tenant.clone(),
                audience: identity.audience.clone(),
                namespace: contract.namespace().to_owned(),
                caller_subject: identity.caller_subject.clone(),
                caller_authority: identity.caller_authority,
                operation_id: header.bytes(1)?,
                request_digest: header.bytes(4)?,
                contract_digest: contract.digest(),
            },
            header,
            contract,
        )?;
        state.reference = Some(reference);
        Ok(())
    }
    pub fn reference(&self) -> Option<crate::OperationReference> {
        self.0
            .state
            .lock()
            .expect("notification operation")
            .reference
            .clone()
    }
    pub fn start(&self) -> Result<()> {
        self.0.account.check()?;
        let peer = self
            .0
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        peer.check()?;
        if self.0.cancellation.is_cancelled() || Instant::now() >= self.0.deadline {
            return Err(failure(ServiceFailure::Canceled));
        }
        let (header, payload, charge) = {
            let mut state = self.0.state.lock().expect("notification operation");
            if state.closed || state.started {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            state.started = true;
            state.active = true;
            state
                .prepared
                .take()
                .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?
        };
        let (sender, receiver) = oneshot::channel();
        let output = Output {
            header,
            payload,
            cancellation: self.0.cancellation.clone(),
            result: sender,
            _charge: charge,
            diagnostics: self.0.diagnostics.clone(),
        };
        // A refused Output must leave the publication gate before its original
        // charge and diagnostics are dropped; preserve the inline error owner.
        #[allow(clippy::result_large_err)]
        let admitted = peer.session().and_then(|session| {
            session
                .controller_publication_gate(|| peer.output.try_send(output))
                .map_err(|_| failure(ServiceFailure::Closed))?
                .map_err(|error| {
                    failure(match error {
                        mpsc::error::TrySendError::Full(_) => ServiceFailure::ResourceExhausted,
                        mpsc::error::TrySendError::Closed(_) => ServiceFailure::Closed,
                    })
                })
        });
        if let Err(error) = admitted {
            let mut state = self.0.state.lock().expect("notification operation");
            state.active = false;
            state.settled = Some(Err(error));
            self.0.diagnostics.service_failure(error);
            drop(state);
            self.0.account.detach_result();
            self.0.changed.notify_waiters();
            return Err(error);
        }
        let owner = self.0.clone();
        tokio::spawn(async move {
            let result = receiver
                .await
                .unwrap_or_else(|_| Err(failure(ServiceFailure::Closed)));
            match &result {
                Ok(publication)
                    if publication.publication == crate::ServicePublication::Committed =>
                {
                    owner.diagnostics.succeed()
                }
                Ok(publication) => owner.diagnostics.service_failure(failure(
                    publication
                        .error
                        .unwrap_or(ServiceFailure::ServiceUnavailable),
                )),
                Err(error) => owner.diagnostics.service_failure(*error),
            }
            let mut state = owner.state.lock().expect("notification operation");
            state.settled = Some(result);
            state.active = false;
            drop(state);
            owner.account.detach_result();
            owner.changed.notify_waiters();
        });
        Ok(())
    }
    pub fn publication(&self) -> Option<Result<NotificationPublication>> {
        self.0.state.lock().expect("notification operation").settled
    }
    pub async fn wait_submission(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<NotificationPublication> {
        if let Some(result) = self.publication() {
            return result;
        }
        {
            let mut state = self.0.state.lock().expect("notification operation");
            if state.waiter {
                return Err(failure(ServiceFailure::KnownApplicationDependency));
            }
            state.waiter = true;
        }
        let _waiter = NotificationWaiter(self.0.clone());
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(result) = self.publication() {
                return result;
            }
            if !self.0.state.lock().expect("notification operation").started {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(self.0.deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)) }
        }
    }
    pub fn cancel(&self) {
        self.0.cancellation.cancel();
        self.0.changed.notify_waiters();
    }
    pub fn close(&self) {
        self.cancel();
        let prepared = {
            let mut state = self.0.state.lock().expect("notification operation");
            state.closed = true;
            state.prepared.take()
        };
        drop(prepared);
        self.0
            .diagnostics
            .service_failure(failure(ServiceFailure::Closed));
        self.0.changed.notify_waiters();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let state = self.0.state.lock().expect("notification operation");
        let active = state.active;
        if !active && state.closed {
            self.0.diagnostics.closed();
        }
        CleanupStatus {
            complete: !active,
            cleanup_incomplete: active,
            pending_callbacks: u64::from(active),
        }
    }
    pub async fn wait_cleanup(&self, timeout: Duration) -> CleanupStatus {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(60));
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(deadline) => return self.cleanup_status() }
        }
    }
}
struct NotificationWaiter(Arc<NotificationOperationInner>);
impl Drop for NotificationWaiter {
    fn drop(&mut self) {
        self.0.state.lock().expect("notification operation").waiter = false;
        self.0.changed.notify_waiters();
    }
}
struct CoreWorker(Arc<Core>);
impl Drop for CoreWorker {
    fn drop(&mut self) {
        if self.0.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.charge.lock().expect("notification charge").take();
            self.0.tail.finish();
        }
        self.0.changed.notify_waiters();
    }
}
impl Core {
    fn check(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::Closed));
        }
        self.account.check()?;
        Ok(())
    }
    fn session(&self) -> Result<Session> {
        self.session
            .lock()
            .expect("notification Session")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::Closed))
    }
    fn cleanup(&self) -> CleanupStatus {
        let workers = self.workers.load(Ordering::Acquire);
        CleanupStatus {
            complete: workers == 0,
            cleanup_incomplete: workers != 0,
            pending_callbacks: workers as u64,
        }
    }
    fn close(self: &Arc<Self>) {
        self.workers.fetch_add(1, Ordering::AcqRel);
        let _closing = CoreWorker(self.clone());
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancellation.cancel();
        self.group.close();
        self.session.lock().expect("notification Session").take();
        let subscribers: Vec<_> = self
            .subscribers
            .lock()
            .expect("notification subscribers")
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for subscriber in subscribers {
            subscriber.close();
        }
        let streams = [
            self.incoming.lock().expect("notification input").take(),
            self.outgoing.lock().expect("notification output").take(),
        ];
        for stream in streams.into_iter().flatten() {
            self.workers.fetch_add(1, Ordering::AcqRel);
            let owner = self.clone();
            tokio::spawn(async move {
                let _tail = CoreWorker(owner);
                let _ = stream.reset().await;
                loop {
                    if stream.cleanup_status().complete {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
        }
        self.changed.notify_waiters();
    }
    async fn read(self: &Arc<Self>) -> Result<()> {
        let session = self.session()?;
        let request = tokio::select! { request = session.next_service_kind(KIND) => request.map_err(|_| failure(ServiceFailure::ServiceUnavailable))?,
        _ = self.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)) };
        let candidate = request
            .prepare_stream()
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        let permit = candidate
            .read_owner()
            .ok_or_else(|| failure(ServiceFailure::Protocol))?
            .acquire()
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        let stream = Arc::new(
            request
                .accept_prepared(candidate, 16384)
                .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?,
        );
        *self.incoming.lock().expect("notification input") = Some(stream.clone());
        let mut sequence = 0u64;
        loop {
            self.check()?;
            let mut prefix = [0; 2];
            if !read_exact(self, &stream, &permit, &mut prefix, None, true).await? {
                // Notification payloads use only the opener's direction. Join
                // its FIN by sealing the unused reverse direction, retaining
                // this original reader until both proofs and physical tails end.
                stream
                    .request_application_close_write()
                    .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
                Self::join_stream(&stream).await;
                return Ok(());
            }
            let length = u16::from_be_bytes(prefix) as usize;
            if length == 0 || length > 512 {
                return Err(failure(ServiceFailure::Protocol));
            }
            let mut encoded = [0; 512];
            read_exact(self, &stream, &permit, &mut encoded[..length], None, false).await?;
            let header = ApplicationHeader::decode(&encoded[..length])?;
            if !matches!(header.kind(), "observation_notify" | "execution_notify") {
                return Err(failure(ServiceFailure::Protocol));
            }
            let size = header.payload_bytes()?;
            if size > 1 << 20 {
                return Err(failure(ServiceFailure::Protocol));
            }
            let registration = self.registrations.iter().find(|entry| {
                entry.contract.type_id() == header.type_id().unwrap_or(0)
                    && entry.contract.digest() == header.bytes(6).unwrap_or([0; 32])
                    && (entry.execution.is_some()) == (header.kind() == "execution_notify")
            });
            let now = self.account.security_time()?;
            let legal = registration.is_some_and(|entry| {
                size as u64 <= entry.contract.uint(23).unwrap_or(0)
                    && now.upper_ms < header.uint(5).unwrap_or(0)
                    && header.uint(5).is_ok_and(|cap| {
                        cap <= now
                            .lower_ms
                            .saturating_add(entry.contract.uint(11).unwrap_or(0))
                    })
            });
            let deadline = Instant::now()
                + Duration::from_millis(
                    registration
                        .map_or(30000, |entry| entry.contract.uint(11).unwrap_or(30000))
                        .min(30000),
                );
            // Reserve outside the Session/security gate, then admit this exact
            // original payload under the same gate that closes for Drain.
            let charge = if legal {
                self.account
                    .reserve(ResourceLimits {
                        sdk_bytes: size as u64 + 4096,
                        items: 1,
                        ..ResourceLimits::default()
                    })
                    .ok()
            } else {
                None
            };
            let admission = if legal {
                session
                    .controller_publication_gate(|| {
                        charge.as_ref().map(|_| self.account.begin_business_work())
                    })
                    .ok()
            } else {
                None
            };
            let capacity_gap = matches!(&admission, Some(None));
            let accepted = charge.zip(admission.flatten());
            let Some((charge, business)) = accepted else {
                // Unavailable, unauthorized and post-Drain messages have no
                // response. Consume only their exact bounded frame body.
                let mut discarded = [0; 4096];
                let mut remaining = size;
                while remaining != 0 {
                    let count = remaining.min(discarded.len());
                    read_exact(
                        self,
                        &stream,
                        &permit,
                        &mut discarded[..count],
                        Some(deadline),
                        false,
                    )
                    .await?;
                    discarded[..count].fill(0);
                    remaining -= count;
                }
                if capacity_gap {
                    sequence = sequence
                        .checked_add(1)
                        .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
                    let subscribers: Vec<_> = self
                        .subscribers
                        .lock()
                        .expect("notification subscribers")
                        .values()
                        .filter_map(Weak::upgrade)
                        .filter(|subscriber| {
                            subscriber.type_id() == header.type_id().unwrap_or(0)
                                && subscriber.contract_digest()
                                    == header.bytes(6).unwrap_or([0; 32])
                        })
                        .collect();
                    for subscriber in subscribers {
                        subscriber.gap(sequence);
                    }
                }
                continue;
            };
            let mut payload = Zeroizing::new(vec![0; size]);
            read_exact(self, &stream, &permit, &mut payload, Some(deadline), false).await?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
            let mut input = Input {
                diagnostics: None,
                header,
                payload: Bytes::from_owner(Payload {
                    bytes: payload,
                    _charge: charge,
                    _business: business,
                }),
                sequence,
            };
            if let Some(sender) = self.execution.get(&input.header.type_id().unwrap_or(0)) {
                input.diagnostics = Some(
                    self.account
                        .diagnostic_activity(crate::DiagnosticPhase::Application, 1),
                );
                // A full execution mailbox refuses only this local admission.
                // Failed queue entries drop outside the original security gate.
                let rejected = self
                    .account
                    .with_security(|| sender.try_send(input).err())?;
                if rejected.is_some() {
                    self.account
                        .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::SlowConsumers);
                }
                drop(rejected);
            } else {
                let subscribers: Vec<_> = self.account.with_security(|| {
                    self.subscribers
                        .lock()
                        .expect("notification subscribers")
                        .values()
                        .filter_map(Weak::upgrade)
                        .filter(|subscriber| {
                            subscriber.type_id() == input.header.type_id().unwrap_or(0)
                                && subscriber.contract_digest()
                                    == input.header.bytes(6).unwrap_or([0; 32])
                        })
                        .collect()
                })?;
                for subscriber in subscribers {
                    subscriber.offer(input.clone());
                }
            }
        }
    }
    async fn join_stream(stream: &Stream) {
        let changed = stream.application_changed();
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if stream.cleanup_status().complete {
                break;
            }
            tokio::select! {
                _ = notified => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }
    async fn write(self: &Arc<Self>, mut receiver: mpsc::Receiver<Output>) -> Result<()> {
        let session = self.session()?;
        let changed = session.stream_pool_changed();
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if session.application_draining() {
                // Enqueue and Session Drain are ordered by the original Session
                // gate. Closing the existing queue retains all accepted output.
                receiver.close();
            }
            let output = tokio::select! {
                output = receiver.recv() => match output {
                    Some(output) => output,
                    None => break,
                },
                _ = notified => continue,
                _ = self.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
            };
            self.check()?;
            if output.cancellation.is_cancelled()
                || self.account.security_time()?.upper_ms >= output.header.uint(5)?
            {
                output
                    .diagnostics
                    .service_failure(failure(ServiceFailure::Canceled));
                let _ = output.result.send(Err(failure(ServiceFailure::Canceled)));
                continue;
            }
            let mut stream = self.outgoing.lock().expect("notification output").clone();
            if stream.is_none() {
                // An accepted local queue position does not grant a post-Drain
                // OPEN. Settle its original publication without touching the
                // independent incoming lane or inventing accepted wire bytes.
                let opened = if session.application_draining() {
                    Err(crate::SessionError::Closed)
                } else {
                    tokio::select! {
                        opened = session.open_service_stream(KIND) => opened,
                        _ = self.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                    }
                };
                let opened = match opened {
                    Ok(opened) => Arc::new(opened),
                    Err(_) if session.application_draining() => {
                        let mut encoded = [0; 512];
                        let length = output.header.encode(&mut encoded)?;
                        output
                            .diagnostics
                            .service_failure(failure(ServiceFailure::Closed));
                        let _ = output.result.send(Ok(NotificationPublication {
                            submitted: false,
                            accepted_bytes: 0,
                            requested_bytes: (2 + length + output.payload.len()) as u64,
                            publication: crate::ServicePublication::NotSubmitted,
                            error: Some(ServiceFailure::Closed),
                        }));
                        receiver.close();
                        continue;
                    }
                    Err(_) => return Err(failure(ServiceFailure::ServiceUnavailable)),
                };
                *self.outgoing.lock().expect("notification output") = Some(opened.clone());
                stream = Some(opened);
            }
            let stream = stream.expect("original notification output");
            let mut encoded = [0; 512];
            let length = output.header.encode(&mut encoded)?;
            let mut wire = Vec::with_capacity(2 + length + output.payload.len());
            wire.extend_from_slice(&(length as u16).to_be_bytes());
            wire.extend_from_slice(&encoded[..length]);
            wire.extend_from_slice(&output.payload);
            let cancellation = output.cancellation.clone();
            let cap = output.header.uint(5)?;
            let operation = WriteOperation::try_prepare_guarded(
                stream.clone(),
                Bytes::from(wire),
                Some(Arc::new(move |now| {
                    if cancellation.is_cancelled() {
                        return Err(crate::SessionError::Canceled);
                    }
                    if now.upper_ms >= cap {
                        return Err(crate::SessionError::Timeout);
                    }
                    Ok(())
                })),
            )
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
            operation
                .start()
                .await
                .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
            let progress = tokio::select! { progress = operation.wait() => progress,
            _ = self.cancellation.cancelled() => { operation.cancel(); operation.wait().await } }
            .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
            let complete = progress.accepted_bytes == progress.requested_bytes
                && progress.terminal_reason.as_deref() == Some("complete");
            let result = NotificationPublication {
                submitted: progress.accepted_bytes != 0,
                accepted_bytes: progress.accepted_bytes,
                requested_bytes: progress.requested_bytes,
                publication: if complete {
                    crate::ServicePublication::Committed
                } else if progress.accepted_bytes == 0 {
                    crate::ServicePublication::NotSubmitted
                } else {
                    crate::ServicePublication::Unknown
                },
                error: (!complete).then_some(match progress.terminal_reason.as_deref() {
                    Some("canceled") => ServiceFailure::Canceled,
                    Some("deadline_exceeded") => ServiceFailure::DeadlineExceeded,
                    _ => ServiceFailure::ServiceUnavailable,
                }),
            };
            if complete {
                output.diagnostics.succeed();
            } else {
                output.diagnostics.service_failure(failure(
                    result.error.unwrap_or(ServiceFailure::ServiceUnavailable),
                ));
            }
            let _ = output.result.send(Ok(result));
            if !complete && progress.accepted_bytes != 0 {
                let _ = stream.reset().await;
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
        }
        let stream = self.outgoing.lock().expect("notification output").clone();
        if let Some(stream) = stream {
            stream
                .request_application_close_write()
                .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
            Self::join_stream(&stream).await;
        }
        Ok(())
    }
    async fn execute(
        self: &Arc<Self>,
        registration: NotificationServiceRegistration,
        mut receiver: mpsc::Receiver<Input>,
    ) {
        while let Some(input) = tokio::select! { input = receiver.recv() => input, _ = self.cancellation.cancelled() => None }
        {
            let result: Result<()> = async {
                let handler = registration
                    .handler
                    .as_ref()
                    .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
                let charge = self.account.reserve(ResourceLimits {
                    sdk_bytes: registration.contract.uint(23)? + handler.application_bytes() + 4096,
                    items: 2,
                    tasks: 1,
                    ..ResourceLimits::default()
                })?;
                let admission =
                    self.group
                        .admit_ordinary(false, None, input.header.uint(7)? == 1)?;
                let position = tokio::select! { position = admission.position() => position?,
                _ = self.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)) };
                let invocation = position.enter()?;
                let cancellation = invocation.cancellation();
                let now = self.account.security_time()?;
                let cap = input
                    .header
                    .uint(5)?
                    .min(now.lower_ms.saturating_add(registration.contract.uint(18)?));
                let context = NotificationContext {
                    invocation: invocation.context(),
                    cancellation: cancellation.clone(),
                    sequence: input.sequence,
                    dropped_before: 0,
                    application_input_provided: false,
                };
                await_callback(
                    &self.account,
                    &self.cancellation,
                    &cancellation,
                    cap,
                    AssertUnwindSafe(handler.authorize(context.clone())).catch_unwind(),
                )
                .await??;
                self.check()?;
                let execution = registration
                    .execution
                    .as_ref()
                    .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
                let caller = registration
                    .caller
                    .as_ref()
                    .ok_or_else(|| failure(ServiceFailure::PermissionDenied))?;
                let offer = registration
                    .offer
                    .as_ref()
                    .ok_or_else(|| failure(ServiceFailure::AdmissionWindowClosed))?;
                let attempt = execution.admit(
                    &registration.contract,
                    offer,
                    caller,
                    &input.header,
                    &input.payload,
                    &self.account,
                    || self.check(),
                )?;
                if !attempt.created() {
                    return Ok(());
                }
                attempt.enter(|| self.check())?;
                let context = NotificationContext {
                    cancellation: attempt.cancellation()?,
                    application_input_provided: true,
                    ..context
                };
                let outcome = await_callback(
                    &self.account,
                    &self.cancellation,
                    &context.cancellation,
                    cap,
                    AssertUnwindSafe(handler.handle(&input.payload, context.clone()))
                        .catch_unwind(),
                )
                .await
                .and_then(|value| value);
                match outcome {
                    Ok(()) => {
                        attempt.finish(&[], None, cap, || self.check())?;
                    }
                    Err(error) => {
                        if let Some(diagnostics) = &input.diagnostics {
                            diagnostics.service_failure(error);
                        }
                        attempt.fail(error.0);
                    }
                }
                attempt.exit();
                drop(invocation);
                drop(position);
                drop(charge);
                Ok(())
            }
            .await;
            // A locally rejected/failed execution remains the original history
            // fact when one exists. Notification has no result/retry response.
            if let Some(diagnostics) = &input.diagnostics {
                diagnostics.service_outcome(&result);
            }
        }
    }
}
async fn read_exact(
    core: &Core,
    stream: &Stream,
    permit: &StreamReadPermit,
    output: &mut [u8],
    deadline: Option<Instant>,
    boundary: bool,
) -> Result<bool> {
    let mut used = 0;
    while used < output.len() {
        let read = tokio::select! {
            read = stream.read_with_permit((output.len() - used).min(16384), permit) => read.map_err(|_| failure(ServiceFailure::ServiceUnavailable))?,
            _ = core.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
            _ = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; } else { std::future::pending::<()>().await; } }
                => return Err(failure(ServiceFailure::DeadlineExceeded)),
        };
        output[used..used + read.data.len()].copy_from_slice(&read.data);
        used += read.data.len();
        if read.stream_status != ReadStreamStatus::Open {
            if boundary && used == 0 && read.stream_status == ReadStreamStatus::Eof {
                return Ok(false);
            }
            if used != output.len() || read.stream_status != ReadStreamStatus::Eof {
                return Err(failure(ServiceFailure::Protocol));
            }
        }
    }
    Ok(true)
}
pub(crate) async fn await_callback<T>(
    account: &ResourceAccount,
    closed: &CancellationToken,
    cancellation: &CancellationToken,
    cap: u64,
    callback: impl std::future::Future<
        Output = std::result::Result<Result<T>, Box<dyn std::any::Any + Send>>,
    >,
) -> Result<Result<T>> {
    tokio::pin!(callback);
    loop {
        tokio::select! {
            result = &mut callback => return result.map_err(|_| failure(ServiceFailure::ServiceFailed)),
            _ = cancellation.cancelled() => { let _ = callback.await; return Err(failure(ServiceFailure::Canceled)); },
            _ = closed.cancelled() => { cancellation.cancel(); let _ = callback.await; return Err(failure(ServiceFailure::Closed)); },
            _ = account.security_changed() => {},
            _ = tokio::time::sleep(account.next_security_check()) => {},
        }
        if let Err(error) = account.check().map_err(ServiceError::from).and_then(|_| {
            if account.security_time()?.upper_ms >= cap {
                Err(failure(ServiceFailure::DeadlineExceeded))
            } else {
                Ok(())
            }
        }) {
            cancellation.cancel();
            let _ = callback.await;
            return Err(error);
        }
    }
}
impl<T: Send + 'static> Subscriber<T> {
    async fn run(self: Arc<Self>) {
        let outcome: Result<()> = async {
            loop {
                let changed = self.changed.notified(); tokio::pin!(changed); changed.as_mut().enable();
                if self.cancellation.is_cancelled() { return Ok(()); }
                let scheduler = self.scheduler.clone();
                let local_latest = scheduler.is_none() && self.policy == NotificationDropPolicy::KeepLatest;
                let task = {
                    let _entry = local_latest.then(|| self.entry_gate.lock().expect("notification subscriber entry"));
                    let input = self.mailbox.lock().expect("notification mailbox").queue.pop_front();
                    input.map(|input| self.clone().encoded_task(input))
                };
                let Some(task) = task else {
                    tokio::select! { _ = changed => {}, _ = self.cancellation.cancelled() => return Ok(()) };
                    continue;
                };
                let Some(task) = task else { return Ok(()) };
                let delivery = if let Some(scheduler) = scheduler {
                    scheduler.schedule(task).await
                } else {
                    task.run().await
                };
                if let Err(error) = delivery
                    && (self.cancellation.is_cancelled()
                        || self.group.is_cancelled()
                        || self.mailbox.lock().expect("notification mailbox").closed)
                {
                    return Err(error);
                }
            }
        }.await;
        if let Err(error) = outcome {
            self.mailbox.lock().expect("notification mailbox").failure = Some(error);
        }
        self.close_owner();
        self.group.close();
        // A Controller owns the sole delivery worker, but this original source
        // keeps its subscriber slot until all queued and running inputs exit.
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.encoded_pending.load(Ordering::Acquire) == 0 {
                break;
            }
            changed.await;
        }
        self.charge
            .lock()
            .expect("notification subscriber charge")
            .take();
        self.active.store(false, Ordering::Release);
        if let Some(parent) = self.parent.upgrade() {
            parent
                .subscribers
                .lock()
                .expect("notification subscribers")
                .remove(&self.id);
        }
        self.changed.notify_waiters();
        if let Some(scheduler) = &self.scheduler {
            scheduler.source_changed();
        }
    }
}
impl Session {
    pub fn notifications(
        &self,
        registrations: Vec<NotificationServiceRegistration>,
    ) -> Result<NotificationPeer> {
        NotificationPeer::create(self, registrations)
    }
}
