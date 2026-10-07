//! Once-only typed server streaming over one original dedicated business Stream.
//! Public wait cancellation preserves the current cursor and actual callback;
//! only explicit abandonment closes future delivery and isolates that Stream.
use crate::{
    ApplicationErrorCodec, ApplicationInvocationContext, OperationReference,
    api_v4::CleanupStatus,
    application_executor_v4::CompletionOwner,
    application_tails_v4::ApplicationTail,
    crypto_v4::StreamPreparation,
    environment_v4::{ResourceAccount, ResourceCharge},
    rpc_stream_messages_v4::{StreamMessage, StreamMessages},
    rpc_wire_v4::ApplicationHeader,
    service_client_v4::{ServiceAdmission, ServiceStreamBinding, UnaryPrepareOptions},
    service_contract::{ApplicationErrorDefinition, ServiceError, ServiceFailure, StreamingLimits},
    service_operation_v4::{
        MessageCodecIdentity, ResponseCodec, ServicePublication, TypedUnaryValue,
    },
    service_peer_v4::PeerInner,
};
use futures_util::FutureExt;
use std::{
    fmt,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
#[derive(Clone, Debug)]
pub struct StreamingPrepareOptions {
    pub timeout: Duration,
    pub max_item_bytes: Option<u32>,
    pub admission_not_after_ms: Option<u64>,
    pub operation_id: Option<[u8; 32]>,
    pub context: Option<ApplicationInvocationContext>,
    pub admission: ServiceAdmission,
    pub application_error_codecs: Vec<ApplicationErrorCodec>,
}
impl Default for StreamingPrepareOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_item_bytes: None,
            admission_not_after_ms: None,
            operation_id: None,
            context: None,
            admission: ServiceAdmission::Queue,
            application_error_codecs: Vec::new(),
        }
    }
}
impl StreamingPrepareOptions {
    pub(crate) fn common(&self) -> UnaryPrepareOptions {
        UnaryPrepareOptions {
            timeout: self.timeout,
            response_limit_bytes: self.max_item_bytes,
            admission_not_after_ms: self.admission_not_after_ms,
            operation_id: self.operation_id,
            context: self.context.clone(),
            admission: self.admission,
            application_error_codecs: self.application_error_codecs.clone(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamingTerminal {
    Completed,
    ApplicationError(u32),
    Failed(ServiceFailure),
    Abandoned,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamingOperationProgress {
    pub started: bool,
    pub publication: ServicePublication,
    pub accepted_request_bytes: u64,
    pub requested_request_bytes: u64,
    pub complete_items: u32,
    pub complete_payload_bytes: u64,
    pub delivered_items: u32,
    pub delivered_payload_bytes: u64,
    pub decoder_started: bool,
    pub complete_terminal_input: bool,
    pub application_error_code: Option<u32>,
    pub terminal: Option<StreamingTerminal>,
}
#[derive(Debug)]
pub struct EncodedStreamingItem {
    pub payload: Vec<u8>,
    pub application_error_code: Option<u32>,
    pub codec_identity: Option<MessageCodecIdentity>,
    pub terminal: bool,
    _body_charge: Arc<ResourceCharge>,
    _codec_charge: Arc<ResourceCharge>,
}
#[derive(Debug)]
pub struct TypedStreamingItem<T> {
    pub value: TypedUnaryValue<T>,
    pub codec_identity: Option<MessageCodecIdentity>,
    pub terminal: bool,
    _body_charge: Arc<ResourceCharge>,
    _codec_charge: Arc<ResourceCharge>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Encoded,
    Typed,
}
enum Ready<T> {
    Encoded(EncodedStreamingItem),
    Typed(TypedStreamingItem<T>),
}
#[derive(Debug)]
pub(crate) enum StreamingTransport {
    Opening(StreamPreparation),
    Accepted,
    Resume,
}
struct State<T> {
    prepared: Option<Zeroizing<Vec<u8>>>,
    preparation: Option<StreamingTransport>,
    progress: StreamingOperationProgress,
    ready: Option<Ready<T>>,
    failure: Option<ServiceError>,
    reading: bool,
    mode: Option<Mode>,
    waiter: bool,
    closed: bool,
}
struct Core<T> {
    diagnostics: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    peer: Weak<PeerInner>,
    account: ResourceAccount,
    completion: CompletionOwner,
    messages: Arc<StreamMessages>,
    binding: ServiceStreamBinding,
    request: ApplicationHeader,
    deadline: Instant,
    limits: StreamingLimits,
    codec: ResponseCodec<T>,
    errors: Vec<ApplicationErrorDefinition>,
    error_codecs: Vec<ApplicationErrorCodec>,
    reference: Option<OperationReference>,
    caller_context: Option<ApplicationInvocationContext>,
    run_until_ms: AtomicU64,
    effective_deadline: Mutex<Instant>,
    start_gate: Mutex<()>,
    state: Mutex<State<T>>,
    cancellation: CancellationToken,
    changed: Notify,
    workers: AtomicUsize,
    handles: AtomicUsize,
    charge: Arc<ResourceCharge>,
    close_owner: fn(&Core<T>),
}
pub struct StreamingOperation<T>(Arc<Core<T>>);
impl<T> fmt::Debug for StreamingOperation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamingOperation { <opaque> }")
    }
}
impl<T> Clone for StreamingOperation<T> {
    fn clone(&self) -> Self {
        self.0.handles.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}
impl<T> Drop for StreamingOperation<T> {
    fn drop(&mut self) {
        if self.0.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            (self.0.close_owner)(&self.0);
        }
    }
}
struct Worker<T> {
    core: Arc<Core<T>>,
    _tail: ApplicationTail,
    _peer: crate::service_peer_v4::PeerWorker,
}
impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.core.workers.fetch_sub(1, Ordering::AcqRel);
        self.core.changed.notify_waiters();
    }
}
struct ReadWait<T>(Arc<Core<T>>);
impl<T> Drop for ReadWait<T> {
    fn drop(&mut self) {
        self.0.state.lock().expect("streaming operation").waiter = false;
        self.0.changed.notify_waiters();
    }
}
impl<T: Send + 'static> StreamingOperation<T> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Preparation transfers original publication, completion, codec and caller owners without reacquisition."
    )]
    pub(crate) fn prepare(
        peer: &Arc<PeerInner>,
        account: ResourceAccount,
        completion: CompletionOwner,
        charge: ResourceCharge,
        messages: Arc<StreamMessages>,
        preparation: StreamingTransport,
        binding: ServiceStreamBinding,
        request: ApplicationHeader,
        payload: Zeroizing<Vec<u8>>,
        deadline: Instant,
        limits: StreamingLimits,
        codec: ResponseCodec<T>,
        errors: Vec<ApplicationErrorDefinition>,
        error_codecs: Vec<ApplicationErrorCodec>,
        reference: Option<OperationReference>,
        caller_context: Option<ApplicationInvocationContext>,
    ) -> Result<Self> {
        let tail = peer.application_tail()?;
        let diagnostics = account.diagnostic_activity(crate::DiagnosticPhase::Application, 1);
        let core = Arc::new(Core {
            diagnostics,
            peer: Arc::downgrade(peer),
            account,
            completion,
            cancellation: messages.cancellation(),
            messages,
            binding,
            request,
            deadline,
            limits,
            codec,
            errors,
            error_codecs,
            reference,
            caller_context,
            run_until_ms: AtomicU64::new(0),
            effective_deadline: Mutex::new(deadline),
            start_gate: Mutex::new(()),
            state: Mutex::new(State {
                prepared: Some(payload),
                preparation: Some(preparation),
                progress: StreamingOperationProgress {
                    started: false,
                    publication: ServicePublication::Pending,
                    accepted_request_bytes: 0,
                    requested_request_bytes: 0,
                    complete_items: 0,
                    complete_payload_bytes: 0,
                    delivered_items: 0,
                    delivered_payload_bytes: 0,
                    decoder_started: false,
                    complete_terminal_input: false,
                    application_error_code: None,
                    terminal: None,
                },
                ready: None,
                failure: None,
                reading: false,
                mode: None,
                waiter: false,
                closed: false,
            }),
            changed: Notify::new(),
            workers: AtomicUsize::new(1),
            handles: AtomicUsize::new(1),
            charge: Arc::new(charge),
            close_owner: Core::close,
        });
        let timer = core.clone();
        let peer_cancel = peer.cancellation();
        let peer_worker = peer.retain_worker();
        tokio::spawn(async move {
            let _worker = Worker {
                core: timer.clone(),
                _tail: tail,
                _peer: peer_worker,
            };
            tokio::select! {
                _ = timer.deadline_expired() => timer.expire(),
                _ = timer.cancellation.cancelled() => timer.cancelled(),
                _ = peer_cancel.cancelled() => timer.cancelled(),
                _ = async { loop {
                    let changed = timer.changed.notified(); tokio::pin!(changed); changed.as_mut().enable();
                    if timer.state.lock().expect("streaming operation").progress.terminal.is_some() { break; }
                    changed.await;
                }} => {},
            }
        });
        Ok(Self(core))
    }
    pub fn start(&self) -> Result<()> {
        let _start = self
            .0
            .start_gate
            .lock()
            .expect("original streaming Start admission");
        {
            let state = self.0.state.lock().expect("streaming operation");
            if state.progress.started {
                return Ok(());
            }
            if matches!(state.preparation, Some(StreamingTransport::Resume)) {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
        }
        if let Some(context) = &self.0.caller_context {
            context.check_cancellation()?;
        }
        self.0.account.check()?;
        if Instant::now() >= self.0.deadline {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let peer = self
            .0
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        peer.check()?;
        let session = peer
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let tail = peer.application_tail()?;
        let peer_worker = peer.retain_worker();
        let publication = {
            let state = self.0.state.lock().expect("streaming operation");
            if state.progress.started {
                return Ok(());
            }
            if state.closed || state.progress.terminal.is_some() {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let payload = state
                .prepared
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
            let original = Arc::downgrade(&self.0);
            self.0.messages.try_prepare_publication(
                self.0.request.clone(),
                payload,
                self.0.request.uint(5)?,
                Some(Arc::new(move |now| {
                    let owner = original.upgrade().ok_or(crate::SessionError::Closed)?;
                    if owner.cancellation.is_cancelled() {
                        return Err(crate::SessionError::Closed);
                    }
                    if let Some(context) = &owner.caller_context {
                        context
                            .check_cancellation()
                            .map_err(|_| crate::SessionError::OperationFailed)?;
                    }
                    let until = owner.run_until_ms.load(Ordering::Acquire);
                    if until == 0 || now.upper_ms >= until {
                        return Err(crate::SessionError::Timeout);
                    }
                    Ok(())
                })),
            )?
        };
        let finish_wait = session
            .prepare_application_wait()
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        let admitted = self.0.account.with_security_time(|now| {
            let mut state = self.0.state.lock().expect("streaming operation");
            if state.progress.started {
                return Ok(None);
            }
            if state.closed || state.progress.terminal.is_some() {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let until = now
                .lower_ms
                .checked_add(self.0.limits.max_duration_ms)
                .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?
                .min(self.0.request.uint(5)?);
            if now.upper_ms >= until {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            let payload = state
                .prepared
                .take()
                .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
            let preparation = state
                .preparation
                .take()
                .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
            self.0.run_until_ms.store(until, Ordering::Release);
            *self
                .0
                .effective_deadline
                .lock()
                .expect("original streaming run cap") = self
                .0
                .deadline
                .min(Instant::now() + Duration::from_millis(until - now.upper_ms));
            state.progress.started = true;
            Ok(Some((payload, preparation)))
        })??;
        let Some((payload, preparation)) = admitted else {
            return Ok(());
        };
        self.0.changed.notify_waiters();
        self.0.workers.fetch_add(1, Ordering::AcqRel);
        let owner = self.0.clone();
        tokio::spawn(async move {
            let _worker = Worker {
                core: owner.clone(),
                _tail: tail,
                _peer: peer_worker,
            };
            let result = async {
                if let StreamingTransport::Opening(preparation) = preparation {
                    let attach = owner.messages.clone();
                    tokio::select! {
                        opened = session.open_stream_prepared(&owner.binding.stream_kind, owner.binding.stream_metadata.clone(), 16384, preparation,
                            move |stream| attach.attach(stream)) => opened.map_err(|_| failure(ServiceFailure::ServiceUnavailable))?,
                        _ = owner.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                        _ = tokio::time::sleep_until(owner.deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)),
                    }
                }
                owner.messages.activate();
                // Start publishes the exact original vector reserved above;
                // the immutable input may now retire independently.
                drop(payload);
                let publication = publication.publish().await?;
                {
                    let mut state = owner.state.lock().expect("streaming operation");
                    state.progress.publication = publication.publication;
                    state.progress.accepted_request_bytes = publication.accepted_bytes;
                    state.progress.requested_request_bytes = publication.requested_bytes;
                }
                owner.changed.notify_waiters();
                if publication.publication != ServicePublication::Committed { return Err(failure(ServiceFailure::ServiceUnavailable)); }
                owner.messages.close_write_prepared(finish_wait).await
            }.await;
            if let Err(error) = result {
                owner.fail(error);
            }
        });
        Ok(())
    }
    pub fn status(&self) -> crate::OperationStatus {
        let progress = self.progress();
        if !progress.started {
            return crate::OperationStatus::NotStarted;
        }
        match progress.terminal {
            Some(StreamingTerminal::Completed) => crate::OperationStatus::Completed,
            Some(_) => crate::OperationStatus::Failed,
            None if progress.publication == ServicePublication::Unknown => {
                crate::OperationStatus::Unknown
            }
            None => crate::OperationStatus::Pending,
        }
    }
    pub fn progress(&self) -> StreamingOperationProgress {
        self.0.state.lock().expect("streaming operation").progress
    }
    pub fn reference(&self) -> Option<OperationReference> {
        self.0.reference.clone()
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.0.deadline
    }
    pub async fn wait_status(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<StreamingOperationProgress> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let progress = self.progress();
            if progress.terminal.is_some() {
                return Ok(progress);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) }
        }
    }
    pub async fn read_next_encoded(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<EncodedStreamingItem>> {
        match self.read(Mode::Encoded, cancellation).await? {
            None => Ok(None),
            Some(Ready::Encoded(item)) => Ok(Some(item)),
            Some(Ready::Typed(_)) => Err(failure(ServiceFailure::ResultModeConflict)),
        }
    }
    pub async fn read_next(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<TypedStreamingItem<T>>> {
        match self.read(Mode::Typed, cancellation).await? {
            None => Ok(None),
            Some(Ready::Typed(item)) => Ok(Some(item)),
            Some(Ready::Encoded(_)) => Err(failure(ServiceFailure::ResultModeConflict)),
        }
    }
    async fn read(&self, mode: Mode, cancellation: &CancellationToken) -> Result<Option<Ready<T>>> {
        {
            let mut state = self.0.state.lock().expect("streaming operation");
            if state.waiter || state.mode.is_some_and(|current| current != mode) {
                return Err(failure(ServiceFailure::ResultModeConflict));
            }
            if !state.progress.started {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            state.waiter = true;
        }
        let _waiter = ReadWait(self.0.clone());
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let ready = self.0.account.with_security(|| {
                let mut state = self.0.state.lock().expect("streaming operation");
                if cancellation.is_cancelled() {
                    return Err(failure(ServiceFailure::Canceled));
                }
                if state.closed {
                    return Err(failure(ServiceFailure::Closed));
                }
                if let Some(ready) = state.ready.take() {
                    let terminal = match &ready {
                        Ready::Encoded(item) => item.terminal,
                        Ready::Typed(item) => item.terminal,
                    };
                    if !terminal {
                        state.progress.delivered_items += 1;
                        let length = state.progress.complete_payload_bytes
                            - state.progress.delivered_payload_bytes;
                        state.progress.delivered_payload_bytes += length;
                    }
                    state.mode = None;
                    return Ok(Some(Some(ready)));
                }
                if let Some(error) = state.failure
                    && !state.reading
                {
                    return Err(error);
                }
                if state.progress.terminal.is_some() && !state.reading {
                    return Ok(Some(None));
                }
                Ok(None)
            })??;
            if let Some(ready) = ready {
                self.0.changed.notify_waiters();
                return Ok(ready);
            }
            let start = {
                let mut state = self.0.state.lock().expect("streaming operation");
                if state.reading || state.ready.is_some() || state.progress.terminal.is_some() {
                    false
                } else {
                    state.reading = true;
                    state.mode = Some(mode);
                    true
                }
            };
            if start {
                let tail = match self
                    .0
                    .peer
                    .upgrade()
                    .ok_or_else(|| failure(ServiceFailure::Closed))
                    .and_then(|peer| {
                        peer.application_tail()
                            .map(|tail| (tail, peer.retain_worker()))
                    }) {
                    Ok(tail) => tail,
                    Err(error) => {
                        let mut state = self.0.state.lock().expect("streaming operation");
                        state.reading = false;
                        state.mode = None;
                        return Err(error);
                    }
                };
                let (tail, peer_worker) = tail;
                self.0.workers.fetch_add(1, Ordering::AcqRel);
                let owner = self.0.clone();
                tokio::spawn(async move {
                    let _worker = Worker {
                        core: owner.clone(),
                        _tail: tail,
                        _peer: peer_worker,
                    };
                    if let Err(error) = owner.read_item(mode).await {
                        owner.fail_read(error);
                        owner.state.lock().expect("streaming operation").reading = false;
                        owner.changed.notify_waiters();
                    }
                });
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) }
        }
    }
    /// Each iterator poll requests exactly one item through the same operation
    /// cursor. Dropping or cancelling an iterator leaves that original cursor.
    pub fn items(
        &self,
        cancellation: CancellationToken,
    ) -> impl futures_util::Stream<Item = Result<TypedStreamingItem<T>>> + Send {
        futures_util::stream::unfold(
            (self.clone(), cancellation, false),
            |(operation, cancellation, ended)| async move {
                if ended {
                    return None;
                }
                match operation.read_next(&cancellation).await {
                    Ok(Some(item)) => Some((Ok(item), (operation, cancellation, false))),
                    Ok(None) => None,
                    Err(error) => Some((Err(error), (operation, cancellation, true))),
                }
            },
        )
    }
    pub fn resume_state(&self) -> Result<crate::StreamingResumeState> {
        let state = self.0.state.lock().expect("streaming continuation capture");
        if !state.progress.started
            || state.reading
            || state.ready.is_some()
            || state.progress.complete_terminal_input
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        let reference = self
            .0
            .reference
            .clone()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        crate::StreamingResumeState::capture(
            self.0.account.environment_root(),
            self.0.request.clone(),
            reference,
            &self.0.limits,
            state.progress.complete_items,
            state.progress.complete_payload_bytes,
            self.0.run_until_ms.load(Ordering::Acquire),
        )
    }
    pub(crate) fn retain_resume_state(&self, original: &crate::StreamingResumeState) -> Result<()> {
        let now = self.0.account.security_time()?;
        if now.upper_ms >= original.until_ms() {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let mut state = self.0.state.lock().expect("original streaming counters");
        if state.progress.started || !matches!(state.preparation, Some(StreamingTransport::Resume))
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        let (items, bytes) = original.counters();
        state.progress.complete_items = items;
        state.progress.complete_payload_bytes = bytes;
        state.progress.delivered_items = items;
        state.progress.delivered_payload_bytes = bytes;
        self.0
            .run_until_ms
            .store(original.until_ms(), Ordering::Release);
        *self
            .0
            .effective_deadline
            .lock()
            .expect("original streaming run cap") = self
            .0
            .deadline
            .min(Instant::now() + Duration::from_millis(original.until_ms() - now.upper_ms));
        self.0.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn result_account(&self) -> ResourceAccount {
        self.0.account.clone()
    }
    pub fn abandon_result(&self) -> Result<()> {
        let discarded = {
            let mut state = self.0.state.lock().expect("streaming operation");
            if state.closed {
                return Err(failure(ServiceFailure::Closed));
            }
            state.closed = true;
            if state.progress.terminal.is_none() {
                state.progress.terminal = Some(StreamingTerminal::Abandoned);
            }
            state.ready.take()
        };
        drop(discarded);
        self.0
            .diagnostics
            .service_failure(failure(ServiceFailure::Canceled));
        self.0.cancellation.cancel();
        self.0.messages.close();
        self.0.account.detach_result();
        self.0.changed.notify_waiters();
        Ok(())
    }
    pub fn close(&self) {
        self.0.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let message = self.0.messages.cleanup_status();
        let workers = self.0.workers.load(Ordering::Acquire);
        if workers == 0
            && message.complete
            && self.0.state.lock().expect("streaming operation").closed
        {
            self.0.diagnostics.closed();
        }
        CleanupStatus {
            complete: workers == 0 && message.complete,
            cleanup_incomplete: workers != 0 || message.cleanup_incomplete,
            pending_callbacks: message.pending_callbacks.saturating_add(workers as u64),
        }
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = self.0.messages.wait_cleanup() => {},
            _ = tokio::time::sleep_until(deadline) => return self.cleanup_status() }
        }
    }
}
impl<T: Send + 'static> Core<T> {
    async fn deadline_expired(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let deadline = *self
                .effective_deadline
                .lock()
                .expect("streaming run deadline");
            tokio::select! { _ = tokio::time::sleep_until(deadline) => return, _ = changed => {} }
        }
    }
    fn close(&self) {
        let discarded = {
            let mut state = self.state.lock().expect("streaming operation");
            state.closed = true;
            if state.progress.terminal.is_none() {
                state.progress.terminal = Some(StreamingTerminal::Closed);
            }
            (
                state.ready.take(),
                state.prepared.take(),
                state.preparation.take(),
            )
        };
        drop(discarded);
        self.diagnostics
            .service_failure(failure(ServiceFailure::Closed));
        self.cancellation.cancel();
        self.messages.close();
        self.account.detach_result();
        self.changed.notify_waiters();
    }
    fn expire(&self) {
        if self
            .state
            .lock()
            .expect("streaming operation")
            .progress
            .terminal
            .is_none()
        {
            self.fail(failure(ServiceFailure::DeadlineExceeded));
        }
    }
    fn cancelled(&self) {
        if self
            .state
            .lock()
            .expect("streaming operation")
            .progress
            .terminal
            .is_none()
        {
            self.fail(failure(ServiceFailure::Closed));
        }
    }
    fn fail(&self, error: ServiceError) {
        self.fail_inner(error, false);
    }
    fn fail_read(&self, error: ServiceError) {
        self.fail_inner(error, true);
    }
    fn fail_inner(&self, error: ServiceError, read_failure: bool) {
        let discarded = {
            let mut state = self.state.lock().expect("streaming operation");
            if state.closed
                || state.progress.terminal.is_some()
                    && !matches!(
                        state.progress.terminal,
                        Some(StreamingTerminal::ApplicationError(_))
                    )
                    && !(state.reading && (read_failure || error.0 == ServiceFailure::DecodeFailed))
            {
                return;
            }
            state.failure = Some(error);
            state.progress.terminal = Some(StreamingTerminal::Failed(error.0));
            (
                state.ready.take(),
                state.prepared.take(),
                state.preparation.take(),
            )
        };
        drop(discarded);
        self.diagnostics.service_failure(error);
        self.cancellation.cancel();
        self.messages.close();
        self.account.detach_result();
        self.changed.notify_waiters();
    }
    async fn read_item(self: &Arc<Self>, mode: Mode) -> Result<()> {
        // A cancelled external waiter does not cancel this original advancement.
        // Exactly one current candidate remains owned until delivery/abandonment.
        let now = self.account.security_time()?;
        if now.upper_ms >= self.run_until_ms.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let message = self.messages.next(&self.cancellation).await?;
        let Some(message) = message else {
            {
                let mut state = self.state.lock().expect("streaming operation");
                if !state.closed && state.progress.terminal.is_none() {
                    state.progress.complete_terminal_input = true;
                    state.progress.terminal = Some(StreamingTerminal::Completed);
                }
            }
            self.account.detach_result();
            self.state.lock().expect("streaming operation").reading = false;
            self.changed.notify_waiters();
            let _ = self.messages.finish().await;
            self.diagnostics.succeed();
            return Ok(());
        };
        if message.header.sdk_error() {
            let error = ServiceError::from_sdk_payload(&message.payload)?;
            self.state
                .lock()
                .expect("streaming operation")
                .progress
                .complete_terminal_input = true;
            return Err(error);
        }
        let code = message
            .header
            .application_error()
            .then(|| message.header.uint(10))
            .transpose()?
            .map(|code| u32::try_from(code).map_err(|_| failure(ServiceFailure::Protocol)))
            .transpose()?;
        if let Some(code) = code {
            if self
                .errors
                .iter()
                .find(|error| error.code == code)
                .is_some_and(|error| message.payload.len() > error.max_payload_bytes as usize)
            {
                return Err(failure(ServiceFailure::DecodeFailed));
            }
            {
                let mut state = self.state.lock().expect("streaming operation");
                if state.progress.terminal.is_none() {
                    state.progress.complete_terminal_input = true;
                    state.progress.application_error_code = Some(code);
                    state.progress.terminal = Some(StreamingTerminal::ApplicationError(code));
                }
            }
            self.account.detach_result();
            self.changed.notify_waiters();
        } else {
            let mut state = self.state.lock().expect("streaming operation");
            let count = state
                .progress
                .complete_items
                .checked_add(1)
                .ok_or_else(|| failure(ServiceFailure::Protocol))?;
            let bytes = state
                .progress
                .complete_payload_bytes
                .checked_add(message.payload.len() as u64)
                .ok_or_else(|| failure(ServiceFailure::Protocol))?;
            if count > self.limits.max_item_count || bytes > self.limits.max_payload_bytes {
                return Err(failure(ServiceFailure::Protocol));
            }
            state.progress.complete_items = count;
            state.progress.complete_payload_bytes = bytes;
        }
        if message.following_terminal != crate::ReadStreamStatus::Open {
            {
                let mut state = self.state.lock().expect("streaming operation");
                if state.progress.terminal.is_none() {
                    state.progress.complete_terminal_input = true;
                    if message.following_terminal == crate::ReadStreamStatus::Eof {
                        state.progress.terminal = Some(StreamingTerminal::Completed);
                    } else {
                        state.progress.terminal = Some(StreamingTerminal::Failed(
                            ServiceFailure::ServiceUnavailable,
                        ));
                        state.failure = Some(failure(ServiceFailure::ServiceUnavailable));
                    }
                }
            }
            // Complete authenticated terminal input is a result fact. Detach
            // before waiting for the original Completion position or decoder,
            // so physical Session retirement cannot revoke that result.
            self.account.detach_result();
            self.changed.notify_waiters();
        }
        let following_terminal = message.following_terminal;
        let identity = match code {
            None => Some(MessageCodecIdentity::from(self.codec.definition())),
            Some(code) => self
                .errors
                .iter()
                .find(|error| error.code == code)
                .map(|error| MessageCodecIdentity::from(&error.message)),
        };
        let StreamMessage {
            header: _,
            payload,
            charge,
            following_terminal: _,
        } = message;
        let body_charge = Arc::new(charge);
        let ready = if mode == Mode::Encoded {
            Ready::Encoded(EncodedStreamingItem {
                payload: payload.to_vec(),
                application_error_code: code,
                codec_identity: identity,
                terminal: code.is_some(),
                _body_charge: body_charge,
                _codec_charge: self.charge.clone(),
            })
        } else {
            let value = if let Some(code) = code {
                if let Some(codec) = self
                    .error_codecs
                    .iter()
                    .find(|codec| codec.definition().code == code)
                {
                    let position = self.completion.position().await?;
                    let invocation = position.enter()?;
                    self.state
                        .lock()
                        .expect("streaming operation")
                        .progress
                        .decoder_started = true;
                    let callback = codec.decode(Arc::new(payload.to_vec()), invocation.context());
                    tokio::pin!(callback);
                    let value = tokio::select! { value = &mut callback => value,
                    _ = self.cancellation.cancelled() => { invocation.cancel(); callback.await } }
                    .map_err(|_| failure(ServiceFailure::DecodeFailed))?;
                    drop(invocation);
                    drop(position);
                    TypedUnaryValue::DecodedApplicationError { code, value }
                } else if identity.is_some() {
                    TypedUnaryValue::ApplicationError {
                        code,
                        payload: payload.to_vec(),
                    }
                } else {
                    TypedUnaryValue::UnknownApplicationError {
                        code,
                        raw_payload: payload.to_vec(),
                    }
                }
            } else {
                let position = self.completion.position().await?;
                let invocation = position.enter()?;
                self.state
                    .lock()
                    .expect("streaming operation")
                    .progress
                    .decoder_started = true;
                let context = invocation.context();
                let decoded = match &self.codec {
                    ResponseCodec::Sync(codec) if crate::message_codec_v4::controlled(codec.as_ref()) => codec.decode_with_context(&payload, &context),
                    ResponseCodec::Sync(codec) => {
                        let codec = codec.clone(); let bytes = payload.to_vec();
                        let task = tokio::task::spawn_blocking(move || std::panic::catch_unwind(AssertUnwindSafe(|| codec.decode_with_context(&bytes, &context)))
                            .unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed)))); tokio::pin!(task);
                        tokio::select! { result = &mut task => result,
                            _ = self.cancellation.cancelled() => { invocation.cancel(); task.await } }.map_err(|_| failure(ServiceFailure::DecodeFailed))?
                    }
                    ResponseCodec::Async(codec) => {
                        let callback = AssertUnwindSafe(codec.decode(&payload, context)).catch_unwind(); tokio::pin!(callback);
                        tokio::select! { result = &mut callback => result,
                            _ = self.cancellation.cancelled() => { invocation.cancel(); callback.await } }
                            .unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed)))
                    }
                }.map_err(|_| failure(ServiceFailure::DecodeFailed))?;
                drop(invocation);
                drop(position);
                TypedUnaryValue::Response(decoded)
            };
            Ready::Typed(TypedStreamingItem {
                value,
                codec_identity: identity,
                terminal: code.is_some(),
                _body_charge: body_charge,
                _codec_charge: self.charge.clone(),
            })
        };
        // Publish the complete owned candidate atomically with its local
        // delivery gate. Native callback exit precedes worker retirement.
        let mut candidate = Some(ready);
        self.account.with_security(|| {
            let mut state = self.state.lock().expect("streaming operation");
            let captured_terminal = code.is_some_and(|code| {
                state.progress.terminal == Some(StreamingTerminal::ApplicationError(code))
            }) || following_terminal == crate::ReadStreamStatus::Eof
                && state.progress.terminal == Some(StreamingTerminal::Completed)
                || following_terminal == crate::ReadStreamStatus::Aborted
                    && state.progress.terminal
                        == Some(StreamingTerminal::Failed(
                            ServiceFailure::ServiceUnavailable,
                        ));
            if !state.closed
                && (state.progress.terminal.is_none() && !self.cancellation.is_cancelled()
                    || captured_terminal)
            {
                state.ready = candidate.take();
                if let Some(code) = code {
                    state.progress.terminal = Some(StreamingTerminal::ApplicationError(code));
                }
            }
            // Release this logical advancement exactly once. The worker and
            // original application tail still cover its physical cleanup.
            state.reading = false;
        })?;
        drop(candidate);
        match self
            .state
            .lock()
            .expect("streaming operation")
            .progress
            .terminal
        {
            Some(StreamingTerminal::Completed | StreamingTerminal::ApplicationError(_)) => {
                self.diagnostics.succeed()
            }
            Some(StreamingTerminal::Failed(code)) => {
                self.diagnostics.service_failure(failure(code))
            }
            _ => {}
        }
        self.changed.notify_waiters();
        if code.is_some() {
            self.account.detach_result();
            self.messages.close();
        } else if following_terminal != crate::ReadStreamStatus::Open {
            self.account.detach_result();
            let _ = self.messages.finish().await;
        }
        Ok(())
    }
}

impl<T: Send + 'static> crate::streaming_resume_v4::ResumeContinuationOwner
    for StreamingOperation<T>
{
    fn request(&self) -> ApplicationHeader {
        self.0.request.clone()
    }
    fn activate(&self) -> Result<()> {
        if let Some(context) = &self.0.caller_context {
            context.check_cancellation()?;
        }
        let now = self.0.account.security_time()?;
        if Instant::now() >= self.0.deadline
            || now.upper_ms >= self.0.run_until_ms.load(Ordering::Acquire)
        {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let mut state = self.0.state.lock().expect("Resume continuation activation");
        if state.closed
            || state.progress.started
            || !matches!(state.preparation, Some(StreamingTransport::Resume))
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        state.preparation.take();
        state.prepared.take();
        state.progress.started = true;
        state.progress.publication = ServicePublication::Committed;
        self.0.changed.notify_waiters();
        Ok(())
    }
    fn refuse(&self, error: ServiceError) {
        self.0.fail(error);
    }
}
