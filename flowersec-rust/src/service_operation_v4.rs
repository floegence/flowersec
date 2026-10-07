//! The original prepared request, publication receipt and independent result
//! authorization are retained by one finite operation owner.
use crate::{
    ApplicationInvocationContext,
    api_v4::CleanupStatus,
    application_executor_v4::{ApplicationGroup, CompletionOwner},
    environment_v4::{ResourceAccount, ResourceCharge},
    rpc_channel_v4::{PublicationFact, PublicationReceipt},
    rpc_wire_v4::ApplicationHeader,
    service_contract::{
        ApplicationErrorDefinition, AsyncMessageCodec, MessageCodec, MessageDefinition,
        ServiceError, ServiceFailure,
    },
    service_peer_v4::PeerInner,
};
use futures_util::FutureExt;
use std::{
    fmt,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicePublication {
    Pending,
    NotSubmitted,
    InputAborted,
    Committed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStartRefusal {
    NotReady,
    ResourceExhausted,
    DependencyUnavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStartResult {
    Admitted,
    NotAdmitted {
        publication: ServicePublication,
        reason: ServiceStartRefusal,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnaryOperationProgress {
    pub started: bool,
    pub publication: ServicePublication,
    pub complete_input: bool,
    pub application_input_provided: bool,
    pub decoder_started: bool,
    pub worker_active: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageCodecIdentity {
    pub schema_digest: [u8; 32],
    pub revision: String,
}
impl From<&MessageDefinition> for MessageCodecIdentity {
    fn from(definition: &MessageDefinition) -> Self {
        Self {
            schema_digest: definition.schema_digest(),
            revision: definition.revision().to_owned(),
        }
    }
}
#[derive(Debug)]
pub struct EncodedUnaryResult {
    pub payload: Vec<u8>,
    pub application_error_code: Option<u32>,
    pub codec_identity: Option<MessageCodecIdentity>,
    pub application_input_provided: bool,
    _custody: Option<Arc<ResourceCharge>>,
}
#[derive(Debug)]
pub enum TypedUnaryValue<T> {
    Response(T),
    ApplicationError {
        code: u32,
        payload: Vec<u8>,
    },
    DecodedApplicationError {
        code: u32,
        value: crate::DecodedApplicationError,
    },
    UnknownApplicationError {
        code: u32,
        raw_payload: Vec<u8>,
    },
}
#[derive(Debug)]
pub struct TypedUnaryResult<T> {
    pub value: TypedUnaryValue<T>,
    pub codec_identity: Option<MessageCodecIdentity>,
    pub application_input_provided: bool,
    _custody: Option<Arc<ResourceCharge>>,
}
pub(crate) enum ResponseCodec<T> {
    Sync(Arc<dyn MessageCodec<T>>),
    Async(Arc<dyn AsyncMessageCodec<T>>),
}
impl<T> Clone for ResponseCodec<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Sync(codec) => Self::Sync(codec.clone()),
            Self::Async(codec) => Self::Async(codec.clone()),
        }
    }
}
impl<T: 'static> ResponseCodec<T> {
    pub(crate) fn application_input(&self) -> bool {
        match self {
            Self::Sync(codec) => !crate::message_codec_v4::controlled(codec.as_ref()),
            Self::Async(_) => true,
        }
    }
    pub(crate) fn definition(&self) -> &MessageDefinition {
        match self {
            Self::Sync(codec) => codec.definition(),
            Self::Async(codec) => codec.definition(),
        }
    }
}
struct CompleteResponse {
    payload: Zeroizing<Vec<u8>>,
    application_error_code: Option<u32>,
}
struct State<T> {
    header: ApplicationHeader,
    prepared: Option<Arc<Zeroizing<Vec<u8>>>>,
    progress: UnaryOperationProgress,
    complete: Option<CompleteResponse>,
    typed: Option<TypedUnaryValue<T>>,
    typed_code: Option<u32>,
    failure: Option<ServiceError>,
    waiter: bool,
    delivered: bool,
    closed: bool,
    scheduled: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ResumePublicationGate {
    Prepared,
    Publishing,
    Withdrawn,
}
#[derive(Clone)]
struct ResumeOperationTransport {
    messages: Arc<crate::rpc_stream_messages_v4::StreamMessages>,
    target: crate::checkpoint_v4::ResumeTargetBinding,
    gate: Arc<Mutex<ResumePublicationGate>>,
    token_expires_at_ms: u64,
    continuation: Option<Arc<dyn crate::streaming_resume_v4::ResumeContinuationOwner>>,
    handed_off: Arc<std::sync::atomic::AtomicBool>,
}
type ControllerSelector<T> =
    Arc<dyn Fn(&UnaryOperation<T>) -> Result<Option<(UnaryOperation<T>, u64)>> + Send + Sync>;
#[derive(Clone, Copy, Eq, PartialEq)]
enum ControllerPublicationGate {
    Prepared,
    Begun,
    Revoked,
    Closed,
}
struct ControllerRoute<T> {
    selector: Option<ControllerSelector<T>>,
    selected: Option<UnaryOperation<T>>,
    frozen: bool,
    selecting: bool,
    generation: u64,
    remaining: u8,
    current_generation: Arc<AtomicU64>,
    publication: Arc<Mutex<ControllerPublicationGate>>,
}
pub(crate) struct ControllerUnaryPreparation<T> {
    pub diagnostics: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    pub header: ApplicationHeader,
    pub payload: Arc<Zeroizing<Vec<u8>>>,
    pub codec: ResponseCodec<T>,
    pub deadline: Instant,
    pub context: Option<ApplicationInvocationContext>,
    pub error_codecs: Vec<crate::ApplicationErrorCodec>,
    pub reference: Option<crate::OperationReference>,
    pub offer: Option<crate::AdmissionOffer>,
    pub rpc_class: crate::RPCChannelClass,
}
pub(crate) struct OperationInner<T> {
    diagnostics: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    controller_route: Mutex<Option<ControllerRoute<T>>>,
    controller_start: Mutex<()>,
    peer: Weak<PeerInner>,
    account: ResourceAccount,
    _group: ApplicationGroup,
    completion: CompletionOwner,
    _callback_tail: crate::application_tails_v4::ApplicationTail,
    codec: ResponseCodec<T>,
    identity: MessageCodecIdentity,
    errors: Vec<ApplicationErrorDefinition>,
    error_codecs: Vec<crate::ApplicationErrorCodec>,
    charge: Mutex<Option<Arc<ResourceCharge>>>,
    _graph_charge: Arc<ResourceCharge>,
    state: Mutex<State<T>>,
    changed: Notify,
    physical_workers: AtomicU64,
    rpc_class: Mutex<crate::RPCChannelClass>,
    captured_offer: Mutex<Option<crate::AdmissionOffer>>,
    cancellation: CancellationToken,
    deadline: Instant,
    caller_context: Option<ApplicationInvocationContext>,
    reference: Option<crate::OperationReference>,
    resume: Mutex<Option<ResumeOperationTransport>>,
}
impl<T> fmt::Debug for OperationInner<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnaryOperation { <opaque> }")
    }
}
pub struct UnaryOperation<T>(pub(crate) Arc<OperationInner<T>>);
impl<T> Clone for UnaryOperation<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> fmt::Debug for UnaryOperation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnaryOperation { <opaque> }")
    }
}
struct OperationWorker<T>(Arc<OperationInner<T>>);
impl<T> Drop for OperationWorker<T> {
    fn drop(&mut self) {
        if self.0.physical_workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            let retired = {
                let state = self.0.state.lock().expect("unary callback retirement");
                state.closed && !state.progress.worker_active
            };
            if retired {
                self.0._callback_tail.finish();
            }
        }
        self.0.changed.notify_waiters();
    }
}
impl<T: Send + 'static> UnaryOperation<T> {
    #[expect(
        clippy::too_many_arguments,
        reason = "The unary owner takes original completion, charge, callback lifetime, codec and publication facts together."
    )]
    pub(crate) fn prepare(
        peer: &Arc<PeerInner>,
        account: ResourceAccount,
        group: ApplicationGroup,
        completion: CompletionOwner,
        callback_tail: crate::application_tails_v4::ApplicationTail,
        codec: ResponseCodec<T>,
        charge: ResourceCharge,
        header: ApplicationHeader,
        payload: impl Into<Arc<Zeroizing<Vec<u8>>>>,
        deadline: Instant,
        caller_context: Option<ApplicationInvocationContext>,
        errors: Vec<ApplicationErrorDefinition>,
        error_codecs: Vec<crate::ApplicationErrorCodec>,
        reference: Option<crate::OperationReference>,
        diagnostics: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
    ) -> Self {
        let identity = MessageCodecIdentity::from(codec.definition());
        let charge = Arc::new(charge);
        let diagnostics = diagnostics
            .unwrap_or_else(|| account.diagnostic_activity(crate::DiagnosticPhase::Application, 1));
        Self(Arc::new(OperationInner {
            diagnostics,
            controller_route: Mutex::new(None),
            controller_start: Mutex::new(()),
            peer: Arc::downgrade(peer),
            account,
            _group: group,
            completion,
            _callback_tail: callback_tail,
            codec,
            identity,
            errors,
            error_codecs,
            charge: Mutex::new(Some(charge.clone())),
            _graph_charge: charge,
            state: Mutex::new(State {
                header,
                prepared: Some(payload.into()),
                progress: UnaryOperationProgress {
                    started: false,
                    publication: ServicePublication::Pending,
                    complete_input: false,
                    application_input_provided: false,
                    decoder_started: false,
                    worker_active: false,
                },
                complete: None,
                typed: None,
                typed_code: None,
                failure: None,
                waiter: false,
                delivered: false,
                closed: false,
                scheduled: false,
            }),
            changed: Notify::new(),
            physical_workers: AtomicU64::new(0),
            rpc_class: Mutex::new(crate::RPCChannelClass::Interactive),
            captured_offer: Mutex::new(None),
            cancellation: CancellationToken::new(),
            deadline,
            caller_context,
            reference,
            resume: Mutex::new(None),
        }))
    }
    pub(crate) fn capture_rpc_class(&self, class: crate::RPCChannelClass) {
        *self
            .0
            .rpc_class
            .lock()
            .expect("captured RPC scheduling policy") = class;
    }
    pub(crate) fn capture_admission_offer(&self, offer: Option<crate::AdmissionOffer>) {
        *self
            .0
            .captured_offer
            .lock()
            .expect("original captured Offer") = offer;
    }
    pub(crate) fn attach_controller_selector(
        &self,
        selector: ControllerSelector<T>,
        current_generation: Arc<AtomicU64>,
        generation: u64,
        remaining: u8,
    ) -> Result<()> {
        let mut route = self
            .0
            .controller_route
            .lock()
            .expect("queued Controller selection");
        let state = self.0.state.lock().expect("original unary preparation");
        if route.is_some() || state.progress.started || state.closed || state.header.uint(7)? != 0 {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        *route = Some(ControllerRoute {
            selector: Some(selector),
            selected: None,
            frozen: false,
            selecting: false,
            generation,
            remaining,
            current_generation,
            publication: Arc::new(Mutex::new(ControllerPublicationGate::Prepared)),
        });
        Ok(())
    }
    fn selected_operation(&self) -> Option<Self> {
        self.0
            .controller_route
            .lock()
            .expect("fixed Controller unary selection")
            .as_ref()
            .and_then(|route| route.selected.clone())
    }
    async fn wait_controller_selection(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self>> {
        let mut current = self.clone();
        loop {
            let observed = current.0.clone();
            let changed = observed.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let (selected, unsettled) = {
                let route = current
                    .0
                    .controller_route
                    .lock()
                    .expect("queued unary selection observation");
                match route.as_ref() {
                    Some(route) => (
                        route.selected.clone(),
                        route.selecting
                            || route.selector.is_some()
                                && !route.frozen
                                && *route.publication.lock().expect("BEGIN observation")
                                    != ControllerPublicationGate::Begun,
                    ),
                    None => (None, false),
                }
            };
            if let Some(selected) = selected {
                current = selected;
                continue;
            }
            if !unsettled {
                return Ok((!Arc::ptr_eq(&current.0, &self.0)).then(|| current.clone()));
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) }
        }
    }
    pub(crate) fn controller_generation(&self) -> Option<u64> {
        self.0
            .controller_route
            .lock()
            .expect("original Controller generation")
            .as_ref()
            .map(|route| route.generation)
    }
    fn publication_begin_gate(&self) -> crate::rpc_channel_v4::BeginAdmissionGate {
        let original = self
            .0
            .controller_route
            .lock()
            .expect("original BEGIN gate")
            .as_ref()
            .map(|route| {
                (
                    route.publication.clone(),
                    route.current_generation.clone(),
                    route.generation,
                    !route.frozen,
                )
            });
        let owner = Arc::downgrade(&self.0);
        let offer = self
            .0
            .captured_offer
            .lock()
            .expect("scalar Offer admission")
            .clone();
        let cutoff = self
            .0
            .state
            .lock()
            .expect("original execution cutoff")
            .header
            .bytes(1)
            .ok()
            .map(|id| u64::from_be_bytes(id[..8].try_into().expect("fixed execution cutoff")));
        let canceled = self.0.cancellation.clone();
        let deadline = self.0.deadline;
        let context = self.0.caller_context.clone();
        Arc::new(move |now: crate::environment_v4::TrustedTimeSample| {
            let mut gate = original.as_ref().map(|(publication, _, _, _)| {
                publication.lock().expect("incarnation BEGIN/Close gate")
            });
            let local_error = if canceled.is_cancelled()
                || context
                    .as_ref()
                    .is_some_and(|context| context.check_cancellation().is_err())
            {
                Some(crate::SessionError::Canceled)
            } else if Instant::now() >= deadline
                || offer.as_ref().is_some_and(|offer| {
                    now.lower_ms < offer.not_before_ms()
                        || cutoff.is_none_or(|cutoff| {
                            now.upper_ms >= cutoff || cutoff > offer.not_after_ms()
                        })
                })
            {
                Some(crate::SessionError::Timeout)
            } else {
                None
            };
            if let Some(error) = local_error {
                if let Some(gate) = &mut gate {
                    **gate = ControllerPublicationGate::Closed;
                }
                return Err(error);
            }
            let Some((_, current_generation, generation, managed)) = &original else {
                return Ok(());
            };
            let gate = gate.as_mut().expect("original incarnation gate");
            match **gate {
                ControllerPublicationGate::Begun => return Ok(()),
                ControllerPublicationGate::Closed | ControllerPublicationGate::Revoked => {
                    return Err(crate::SessionError::Canceled);
                }
                ControllerPublicationGate::Prepared => {}
            }
            if *managed && current_generation.load(Ordering::Acquire) != *generation {
                **gate = ControllerPublicationGate::Revoked;
                return Err(crate::SessionError::Canceled);
            }
            **gate = ControllerPublicationGate::Begun;
            if let Some(owner) = owner.upgrade() {
                owner.changed.notify_waiters();
            }
            Ok(())
        })
    }
    pub(crate) fn freeze_controller_reference(&self) -> Result<()> {
        let _start = self
            .0
            .controller_start
            .lock()
            .expect("saved Controller reference selection");
        let mut route = self
            .0
            .controller_route
            .lock()
            .expect("saved Controller reference source");
        if route.is_some()
            && self
                .0
                .state
                .lock()
                .expect("saved unstarted Controller reference")
                .progress
                .started
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        if let Some(route) = route.as_mut() {
            if route.selected.is_some() {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            route.selector = None;
            route.frozen = true;
        }
        drop(route);
        self.0.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn controller_preparation(&self) -> Result<ControllerUnaryPreparation<T>> {
        let state = self
            .0
            .state
            .lock()
            .expect("original encoded unary transfer");
        if state.closed
            || self.0.cancellation.is_cancelled()
            || state.progress.publication != ServicePublication::Pending
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        Ok(ControllerUnaryPreparation {
            diagnostics: self.0.diagnostics.clone(),
            header: state.header.clone(),
            payload: state
                .prepared
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::Closed))?
                .clone(),
            codec: self.0.codec.clone(),
            deadline: self.0.deadline,
            context: self.0.caller_context.clone(),
            error_codecs: self.0.error_codecs.clone(),
            reference: self.0.reference.clone(),
            offer: self
                .0
                .captured_offer
                .lock()
                .expect("captured Offer transfer")
                .clone(),
            rpc_class: *self
                .0
                .rpc_class
                .lock()
                .expect("captured RPC scheduling policy"),
        })
    }
    fn settle_start_failure(&self, error: ServiceError) {
        let mut state = self.0.state.lock().expect("queued unary refusal");
        if state.progress.publication == ServicePublication::Pending {
            state.progress.started = true;
            state.progress.complete_input = true;
            state.progress.publication = ServicePublication::NotSubmitted;
            state.failure = Some(error);
            self.0.diagnostics.service_failure(error);
            state.prepared.take();
        }
        drop(state);
        if let Some(route) = self
            .0
            .controller_route
            .lock()
            .expect("sealed Controller attempt")
            .as_mut()
        {
            route.selector = None;
            route.selecting = false;
        }
        self.0.changed.notify_waiters();
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "The unary owner takes original completion, charge, callback lifetime, codec and publication facts together."
    )]
    pub(crate) fn prepare_resume(
        peer: &Arc<PeerInner>,
        account: ResourceAccount,
        group: ApplicationGroup,
        completion: CompletionOwner,
        callback_tail: crate::application_tails_v4::ApplicationTail,
        codec: ResponseCodec<T>,
        charge: ResourceCharge,
        header: ApplicationHeader,
        payload: Zeroizing<Vec<u8>>,
        deadline: Instant,
        caller_context: Option<ApplicationInvocationContext>,
        errors: Vec<ApplicationErrorDefinition>,
        error_codecs: Vec<crate::ApplicationErrorCodec>,
        reference: Option<crate::OperationReference>,
        messages: Arc<crate::rpc_stream_messages_v4::StreamMessages>,
        target: crate::checkpoint_v4::ResumeTargetBinding,
        token_expires_at_ms: u64,
    ) -> Self {
        let operation = Self::prepare(
            peer,
            account,
            group,
            completion,
            callback_tail,
            codec,
            charge,
            header,
            payload,
            deadline,
            caller_context,
            errors,
            error_codecs,
            reference,
            None,
        );
        *operation.0.resume.lock().expect("Resume transport") = Some(ResumeOperationTransport {
            messages,
            target,
            gate: Arc::new(Mutex::new(ResumePublicationGate::Prepared)),
            token_expires_at_ms,
            continuation: None,
            handed_off: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        operation
    }
    pub(crate) fn check_prepared_target(&self) -> Result<()> {
        if self.0.cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::Canceled));
        }
        if Instant::now() >= self.0.deadline {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let resume = self.0.resume.lock().expect("Resume transport").clone();
        if let Some(resume) = resume {
            let peer = self
                .0
                .peer
                .upgrade()
                .ok_or_else(|| failure(ServiceFailure::Closed))?;
            let session = peer
                .session
                .session()
                .map_err(|_| failure(ServiceFailure::Closed))?;
            resume
                .messages
                .check_resume_target(&session, &resume.target)?;
            if self.0.account.security_time()?.upper_ms >= resume.token_expires_at_ms {
                return Err(failure(ServiceFailure::PermissionDenied));
            }
        }
        Ok(())
    }
    pub(crate) fn resume_messages(
        &self,
    ) -> Result<Arc<crate::rpc_stream_messages_v4::StreamMessages>> {
        self.0
            .resume
            .lock()
            .expect("Resume transport")
            .as_ref()
            .map(|resume| resume.messages.clone())
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))
    }
    pub(crate) fn bind_resume_continuation(
        &self,
        continuation: Arc<dyn crate::streaming_resume_v4::ResumeContinuationOwner>,
    ) -> Result<()> {
        if self.progress().started {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        let mut transport = self.0.resume.lock().expect("Resume transport");
        let resume = transport
            .as_mut()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        if resume.continuation.is_some() {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        resume.continuation = Some(continuation);
        Ok(())
    }
    pub(crate) fn resume_token_deadline(&self) -> Option<u64> {
        self.0
            .resume
            .lock()
            .expect("Resume transport")
            .as_ref()
            .map(|resume| resume.token_expires_at_ms)
    }
    pub(crate) fn with_prepared_target<R>(&self, action: impl FnOnce() -> R) -> Result<R> {
        let resume = self.0.resume.lock().expect("Resume transport").clone();
        if let Some(resume) = resume {
            let peer = self
                .0
                .peer
                .upgrade()
                .ok_or_else(|| failure(ServiceFailure::Closed))?;
            let session = peer
                .session
                .session()
                .map_err(|_| failure(ServiceFailure::Closed))?;
            resume
                .messages
                .with_prepared_resume_target(&session, &resume.target, action)
        } else {
            Ok(action())
        }
    }
    pub fn start_on(&self, session: &crate::Session) -> Result<()> {
        if let Some(selected) = self.selected_operation() {
            return selected.start_on(session);
        }
        if !self
            .0
            .state
            .lock()
            .expect("fixed Start owner")
            .progress
            .started
        {
            self.freeze_controller_reference()?;
        }
        // Session identity is checked independently of temporary message
        // qualification, including joins after that qualification has settled.
        let peer = self
            .0
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        if !peer.account.same_owner(&session.application_account()) {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        if !self
            .0
            .state
            .lock()
            .expect("unary operation")
            .progress
            .started
            && let Some(resume) = self.0.resume.lock().expect("Resume transport").clone()
        {
            resume
                .messages
                .check_resume_target(session, &resume.target)?;
        }
        self.start()
    }
    /// A pure local try-now refusal retains the original preparation and target.
    /// Calling Start again joins the same admitted attempt after admission.
    pub fn try_start(&self) -> Result<ServiceStartResult> {
        match self.start() {
            Ok(()) => Ok(ServiceStartResult::Admitted),
            Err(error) => {
                let state = self.0.state.lock().expect("unary operation");
                if state.progress.started
                    || state.closed
                    || self.0.cancellation.is_cancelled()
                    || state.header.uint(7)? != 1
                {
                    return Err(error);
                }
                let reason = match error.0 {
                    ServiceFailure::ResourceExhausted => ServiceStartRefusal::ResourceExhausted,
                    ServiceFailure::ServiceUnavailable | ServiceFailure::NotReady => {
                        ServiceStartRefusal::NotReady
                    }
                    ServiceFailure::DependencyUnavailable
                    | ServiceFailure::CompletionDependencyUnavailable => {
                        ServiceStartRefusal::DependencyUnavailable
                    }
                    _ => return Err(error),
                };
                Ok(ServiceStartResult::NotAdmitted {
                    publication: ServicePublication::NotSubmitted,
                    reason,
                })
            }
        }
    }
    pub fn start(&self) -> Result<()> {
        let _start = self
            .0
            .controller_start
            .lock()
            .expect("one queued Controller Start");
        if let Some(selected) = self.selected_operation() {
            return selected.start();
        }
        if self
            .0
            .state
            .lock()
            .expect("joined unary Start")
            .progress
            .started
        {
            return self.start_fixed();
        }
        let selector = self
            .0
            .controller_route
            .lock()
            .expect("queued initial selection")
            .as_ref()
            .and_then(|route| route.selector.clone());
        if let Some(selector) = selector {
            match selector(self) {
                Ok(Some((selected, generation))) => {
                    let result = self.install_controller_selection(selected, generation);
                    if let Err(error) = result {
                        self.settle_start_failure(error);
                    }
                    return result;
                }
                Ok(None) => {}
                Err(error) => {
                    self.settle_start_failure(error);
                    return Err(error);
                }
            }
        }
        let result = self.start_fixed();
        let queued_controller = self
            .0
            .controller_route
            .lock()
            .expect("queued Controller refusal")
            .as_ref()
            .is_some_and(|route| !route.frozen);
        if queued_controller && let Err(error) = result {
            self.settle_start_failure(error);
        }
        result
    }
    // Caller holds controller_start. No I/O or blocking resource acquire runs
    // under the scalar publication gate; each new owner pays its full vector.
    fn install_controller_selection(&self, selected: Self, generation: u64) -> Result<()> {
        let admission = {
            let mut route = self
                .0
                .controller_route
                .lock()
                .expect("revoke original route");
            let route = route
                .as_mut()
                .ok_or_else(|| failure(ServiceFailure::OperationConflict))?;
            let mut publication = route
                .publication
                .lock()
                .expect("reselection/BEGIN/Close gate");
            if route.frozen
                || matches!(
                    *publication,
                    ControllerPublicationGate::Begun | ControllerPublicationGate::Closed
                )
                || self.0.cancellation.is_cancelled()
                || Instant::now() >= self.0.deadline
            {
                drop(publication);
                selected.close();
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            *publication = ControllerPublicationGate::Revoked;
            (
                route.selector.clone().expect("original selector"),
                route.current_generation.clone(),
                route.remaining,
            )
        };
        if let Err(error) =
            selected.attach_controller_selector(admission.0, admission.1, generation, admission.2)
        {
            selected.close();
            self.settle_start_failure(error);
            return Err(error);
        }
        {
            let mut state = self.0.state.lock().expect("retire old encoded preparation");
            state.prepared.take();
            state.progress.started = true;
        }
        {
            let mut route = self
                .0
                .controller_route
                .lock()
                .expect("install sole provisional route");
            let route = route.as_mut().expect("original Controller route");
            route.selected = Some(selected.clone());
            route.selector = None;
            route.selecting = false;
        }
        self.0.changed.notify_waiters();
        let result = selected.start_fixed();
        if let Err(error) = result {
            selected.settle_start_failure(error);
        }
        result
    }
    pub(crate) fn claim_controller_reselection(&self) -> Result<()> {
        let mut route = self
            .0
            .controller_route
            .lock()
            .expect("finite Controller choices");
        let route = route
            .as_mut()
            .ok_or_else(|| failure(ServiceFailure::OperationConflict))?;
        let mut publication = route
            .publication
            .lock()
            .expect("revoke before new reservation");
        if route.frozen
            || route.remaining == 0
            || matches!(
                *publication,
                ControllerPublicationGate::Begun | ControllerPublicationGate::Closed
            )
            || self.0.cancellation.is_cancelled()
            || Instant::now() >= self.0.deadline
        {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        *publication = ControllerPublicationGate::Revoked;
        route.remaining -= 1;
        route.selecting = true;
        Ok(())
    }
    fn reselect_not_submitted(&self) -> bool {
        let _start = self
            .0
            .controller_start
            .lock()
            .expect("queued pre-BEGIN reselection");
        let selector = self
            .0
            .controller_route
            .lock()
            .expect("unsubmitted incarnation")
            .as_ref()
            .filter(|route| route.current_generation.load(Ordering::Acquire) != route.generation)
            .and_then(|route| route.selector.clone());
        let Some(selector) = selector else {
            return false;
        };
        match selector(self) {
            Ok(Some((selected, generation))) => {
                let result = self.install_controller_selection(selected, generation);
                if let Err(error) = result {
                    self.settle_start_failure(error);
                }
                true
            }
            Ok(None) => false,
            Err(error) => {
                self.settle_start_failure(error);
                true
            }
        }
    }
    fn start_fixed(&self) -> Result<()> {
        {
            let state = self.0.state.lock().expect("unary operation");
            if state.progress.started {
                return state.failure.map_or(Ok(()), Err);
            }
            if state.closed {
                return Err(failure(ServiceFailure::Closed));
            }
        }
        self.0.account.check()?;
        if Instant::now() >= self.0.deadline {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        if let Some(context) = &self.0.caller_context {
            context.check_cancellation().map_err(ServiceError::from)?;
        }
        let peer = self
            .0
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        peer.check()?;
        let tail = peer.application_tail()?;
        self.check_prepared_target()?;
        let resume = self.0.resume.lock().expect("Resume transport").clone();
        if let Some(resume) = resume {
            let mut state = self.0.state.lock().expect("unary operation");
            if state.progress.started {
                return Ok(());
            }
            if state.closed || state.delivered {
                return Err(failure(ServiceFailure::Closed));
            }
            let header = state.header.clone();
            let payload = state
                .prepared
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
            // A local admission refusal keeps the same ID, digest, deadline,
            // target qualification, payload and reference. No Start is claimed.
            let (publication, decline) = self
                .0
                .prepare_resume_publication(&resume, &header, payload)?;
            resume.messages.activate_resume(self.0.deadline)?;
            state.progress.started = true;
            state.progress.worker_active = true;
            let payload = state
                .prepared
                .take()
                .expect("original prepared Resume request");
            drop(state);
            self.0.physical_workers.fetch_add(1, Ordering::AcqRel);
            let owner = self.0.clone();
            let worker = OperationWorker(owner.clone());
            tokio::spawn(async move {
                let _worker = worker;
                let _tail = tail;
                owner
                    .observe_resume(resume, header, payload, publication, decline)
                    .await;
            });
            return Ok(());
        }
        let account = self.0.account.clone();
        let cancellation = self.0.cancellation.clone();
        let deadline = self.0.deadline;
        let context = self.0.caller_context.clone();
        let guard: Arc<dyn Fn() -> Result<()> + Send + Sync> = Arc::new(move || {
            account.check()?;
            if cancellation.is_cancelled() {
                return Err(failure(ServiceFailure::Canceled));
            }
            if let Some(context) = &context {
                context.check_cancellation().map_err(ServiceError::from)?;
            }
            if Instant::now() >= deadline {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            Ok(())
        });
        let begin_gate = self.publication_begin_gate();
        let retain_encoding = self
            .0
            .controller_route
            .lock()
            .expect("encoded Controller custody")
            .as_ref()
            .is_some_and(|route| !route.frozen);
        let queued = self
            .0
            .state
            .lock()
            .expect("RPC queue admission")
            .header
            .uint(7)?
            == 0;
        if queued {
            {
                let mut state = self.0.state.lock().expect("queued RPC Start");
                if state.progress.started {
                    return Ok(());
                }
                state.progress.started = true;
                state.progress.worker_active = true;
            }
            self.0.physical_workers.fetch_add(1, Ordering::AcqRel);
            let operation = self.clone();
            let owner = self.0.clone();
            let worker = OperationWorker(owner.clone());
            tokio::spawn(async move {
                let _worker = worker;
                let _tail = tail;
                let class = *owner
                    .rpc_class
                    .lock()
                    .expect("captured RPC scheduling policy");
                let result = async {
                    loop {
                        peer.channel.wait_channel(class, &owner.cancellation, owner.deadline).await?;
                        match operation.publish_rpc(&peer, guard.clone(), begin_gate.clone(), retain_encoding) {
                            Err(error) if error.0 == ServiceFailure::NotReady || error.0 == ServiceFailure::ResourceExhausted => {
                                tokio::select! { _ = owner.cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
                                    _ = tokio::time::sleep_until(owner.deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)),
                                    _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {} }
                            },
                            result => return result,
                        }
                    }
                }.await;
                match result {
                    Ok(published) => owner.observe_input(peer, published).await,
                    Err(error) => {
                        if !operation.reselect_not_submitted() {
                            owner.set_failure(error, ServicePublication::NotSubmitted);
                        } else {
                            owner
                                .state
                                .lock()
                                .expect("old queued RPC callback exit")
                                .progress
                                .worker_active = false;
                            owner.changed.notify_waiters();
                        }
                    }
                }
            });
            return Ok(());
        }
        let published = self.publish_rpc(&peer, guard, begin_gate, retain_encoding)?;
        self.0.physical_workers.fetch_add(1, Ordering::AcqRel);
        let owner = self.0.clone();
        let worker = OperationWorker(owner.clone());
        tokio::spawn(async move {
            let _worker = worker;
            let _tail = tail;
            owner.observe_input(peer, published).await;
        });
        Ok(())
    }
    fn publish_rpc(
        &self,
        peer: &Arc<PeerInner>,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
        begin_gate: crate::rpc_channel_v4::BeginAdmissionGate,
        retain_encoding: bool,
    ) -> Result<crate::rpc_channel_v4::PublishedMessage> {
        let mut state = self.0.state.lock().expect("original RPC publication");
        if state.closed || state.delivered {
            return Err(failure(ServiceFailure::Closed));
        }
        let payload = state
            .prepared
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
        let class = *self
            .0
            .rpc_class
            .lock()
            .expect("captured RPC scheduling policy");
        let prepared = peer.channel.prepare_class(
            class,
            state.header.clone(),
            payload,
            self.0.cancellation.clone(),
            guard,
            begin_gate,
        )?;
        let published = peer.channel.send_prepared(prepared)?;
        state.progress.started = true;
        state.progress.worker_active = true;
        if !retain_encoding {
            state.prepared.take();
        }
        Ok(published)
    }
    pub(crate) fn result_account(&self) -> ResourceAccount {
        self.0.account.clone()
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.0.deadline
    }
    pub fn reference(&self) -> Option<crate::OperationReference> {
        self.selected_operation().map_or_else(
            || self.0.reference.clone(),
            |selected| selected.0.reference.clone(),
        )
    }
    pub fn status(&self) -> crate::OperationStatus {
        if let Some(selected) = self.selected_operation() {
            return selected.status();
        }
        let state = self.0.state.lock().expect("unary operation");
        if !state.progress.started {
            return crate::OperationStatus::NotStarted;
        }
        if state.progress.complete_input {
            return if state.failure.is_some() {
                crate::OperationStatus::Failed
            } else {
                crate::OperationStatus::Completed
            };
        }
        if state.progress.publication == ServicePublication::Unknown {
            return crate::OperationStatus::Unknown;
        }
        if state.failure.is_some() {
            return crate::OperationStatus::Failed;
        }
        crate::OperationStatus::Pending
    }
    pub async fn wait_status(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::OperationStatus> {
        if let Some(selected) = self.wait_controller_selection(&cancellation).await? {
            return selected.wait_status_fixed(cancellation).await;
        }
        self.wait_status_fixed(cancellation).await
    }
    async fn wait_status_fixed(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::OperationStatus> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.status();
            if !matches!(status, crate::OperationStatus::Pending) {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) }
        }
    }
    pub async fn wait_submission(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ServicePublication> {
        if let Some(selected) = self.wait_controller_selection(&cancellation).await? {
            return selected.wait_submission_fixed(cancellation).await;
        }
        self.wait_submission_fixed(cancellation).await
    }
    async fn wait_submission_fixed(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ServicePublication> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let publication = self.progress().publication;
            if publication != ServicePublication::Pending {
                return Ok(publication);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) }
        }
    }
    pub fn progress(&self) -> UnaryOperationProgress {
        self.selected_operation().map_or_else(
            || self.0.state.lock().expect("unary operation").progress,
            |selected| selected.progress(),
        )
    }
    pub fn cancel(&self) {
        let _start = self
            .0
            .controller_start
            .lock()
            .expect("cancel/selection gate");
        if let Some(route) = self
            .0
            .controller_route
            .lock()
            .expect("cancel original publication")
            .as_mut()
        {
            *route.publication.lock().expect("Close/BEGIN gate") =
                ControllerPublicationGate::Closed;
            route.selector = None;
            route.selecting = false;
        }
        if let Some(selected) = self.selected_operation() {
            selected.cancel();
        }
        if let Some(resume) = self.0.resume.lock().expect("Resume transport").as_ref() {
            let mut gate = resume.gate.lock().expect("Resume publication gate");
            if *gate == ResumePublicationGate::Prepared {
                *gate = ResumePublicationGate::Withdrawn;
            }
        }
        self.0.cancellation.cancel();
        self.0
            .diagnostics
            .service_failure(failure(ServiceFailure::Canceled));
        self.0.changed.notify_waiters();
    }
    pub fn close(&self) {
        // Close participates in the original physical worker count until its
        // retained input and results have been released outside their locks.
        self.0.physical_workers.fetch_add(1, Ordering::AcqRel);
        let _retirement = OperationWorker(self.0.clone());
        self.cancel();
        if let Some(selected) = self.selected_operation() {
            selected.close();
        }
        let resources = {
            let mut state = self.0.state.lock().expect("unary operation");
            state.closed = true;
            if state.progress.worker_active {
                None
            } else {
                Some((
                    state.prepared.take(),
                    state.complete.take(),
                    state.typed.take(),
                ))
            }
        };
        if resources.is_some() {
            if let Some(resume) = self.0.resume.lock().expect("Resume transport").as_ref()
                && !resume.handed_off.load(std::sync::atomic::Ordering::Acquire)
            {
                resume.messages.close();
            }
            self.0.charge.lock().expect("unary charge").take();
        }
        drop(resources);
        self.0.changed.notify_waiters();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let selected = self
            .selected_operation()
            .map(|selected| selected.cleanup_status());
        let active = self
            .0
            .state
            .lock()
            .expect("unary operation")
            .progress
            .worker_active;
        let physical_workers = self.0.physical_workers.load(Ordering::Acquire);
        let resume = self.0.resume.lock().expect("Resume transport").clone();
        let framing = resume
            .filter(|resume| !resume.handed_off.load(std::sync::atomic::Ordering::Acquire))
            .map_or(
                CleanupStatus {
                    complete: true,
                    cleanup_incomplete: false,
                    pending_callbacks: 0,
                },
                |resume| resume.messages.cleanup_status(),
            );
        if !active
            && physical_workers == 0
            && framing.complete
            && selected.as_ref().is_none_or(|status| status.complete)
            && self.0.state.lock().expect("unary operation").closed
        {
            self.0.diagnostics.closed();
        }
        CleanupStatus {
            complete: !active
                && physical_workers == 0
                && framing.complete
                && selected.as_ref().is_none_or(|status| status.complete),
            cleanup_incomplete: active
                || physical_workers != 0
                || !framing.complete
                || selected.as_ref().is_some_and(|status| !status.complete),
            pending_callbacks: physical_workers.max(u64::from(active))
                + framing.pending_callbacks
                + selected.map_or(0, |status| status.pending_callbacks),
        }
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            let resume = self.0.resume.lock().expect("Resume transport").clone();
            let selected = self.selected_operation();
            tokio::select! {
                _ = changed => {},
                _ = async { match selected { Some(selected) => { let _ = Box::pin(selected.wait_cleanup()).await; }, None => std::future::pending::<()>().await } } => {},
                _ = async { match resume {
                    Some(resume) if !resume.handed_off.load(std::sync::atomic::Ordering::Acquire) => { let _ = resume.messages.wait_cleanup().await; },
                    _ => std::future::pending::<()>().await,
                }} => {},
                _ = tokio::time::sleep_until(deadline) => return self.cleanup_status(),
            }
        }
    }
    pub(crate) async fn wait_physical_cleanup(&self) {
        // Internal owners use this after logical completion so a bounded public
        // cleanup observation cannot release the original unary tail early.
        loop {
            // Register before reading cleanup_status. A OperationWorker can
            // retire and notify between an early status read and subscription;
            // enabling this notification first makes that transition observable.
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.cleanup_status().complete {
                return;
            }
            let resume = self.0.resume.lock().expect("Resume transport").clone();
            let selected = self.selected_operation();
            tokio::select! {
                _ = changed => {},
                _ = async { match selected { Some(selected) => { Box::pin(selected.wait_physical_cleanup()).await }, None => std::future::pending::<()>().await } } => {},
                _ = async { match resume {
                    Some(resume) if !resume.handed_off.load(std::sync::atomic::Ordering::Acquire) => { let _ = resume.messages.wait_cleanup().await; },
                    _ => std::future::pending::<()>().await,
                }} => {},
            }
        }
    }
    pub async fn wait_encoded(
        &self,
        cancellation: CancellationToken,
    ) -> Result<EncodedUnaryResult> {
        if let Some(selected) = self.wait_controller_selection(&cancellation).await? {
            return selected.wait_encoded_fixed(cancellation).await;
        }
        self.wait_encoded_fixed(cancellation).await
    }
    async fn wait_encoded_fixed(
        &self,
        cancellation: CancellationToken,
    ) -> Result<EncodedUnaryResult> {
        self.0.claim_waiter()?;
        let _waiter = Waiter(self.0.clone());
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            // Keep the same operation-before-authority order as Start. Result
            // extraction remains atomic with close and security validation.
            let ready = {
                let mut state = self.0.state.lock().expect("unary operation");
                self.0.account.with_security(|| -> Result<_> {
                    if state.progress.decoder_started {
                        return Err(failure(ServiceFailure::ResultModeConflict));
                    }
                    if state.closed || state.delivered {
                        return Err(failure(ServiceFailure::Closed));
                    }
                    if let Some(failure) = state.failure {
                        return Err(failure);
                    }
                    let Some(response) = state.complete.take() else {
                        return Ok(None);
                    };
                    state.delivered = true;
                    Ok(Some(EncodedUnaryResult {
                        payload: response.payload.to_vec(),
                        application_error_code: response.application_error_code,
                        codec_identity: self
                            .0
                            .response_identity(response.application_error_code)?,
                        application_input_provided: false,
                        _custody: None,
                    }))
                })??
            };
            if let Some(mut result) = ready {
                result._custody = self.0.charge.lock().expect("unary charge").take();
                self.0.diagnostics.succeed();
                return Ok(result);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) }
        }
    }
    pub async fn wait_typed(&self, cancellation: CancellationToken) -> Result<TypedUnaryResult<T>> {
        if let Some(selected) = self.wait_controller_selection(&cancellation).await? {
            return selected.wait_typed_fixed(cancellation).await;
        }
        self.wait_typed_fixed(cancellation).await
    }
    async fn wait_typed_fixed(
        &self,
        cancellation: CancellationToken,
    ) -> Result<TypedUnaryResult<T>> {
        self.0.claim_waiter()?;
        let _waiter = Waiter(self.0.clone());
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let ready = {
                let mut state = self.0.state.lock().expect("unary operation");
                self.0.account.with_security(|| -> Result<_> {
                    if state.closed || state.delivered {
                        return Err(failure(ServiceFailure::Closed));
                    }
                    if let Some(failure) = state.failure {
                        return Err(failure);
                    }
                    let Some(value) = state.typed.take() else {
                        return Ok(None);
                    };
                    state.delivered = true;
                    Ok(Some(TypedUnaryResult {
                        value,
                        codec_identity: self.0.response_identity(state.typed_code)?,
                        application_input_provided: state.progress.application_input_provided,
                        _custody: None,
                    }))
                })??
            };
            if let Some(mut result) = ready {
                result._custody = self.0.charge.lock().expect("unary charge").take();
                self.0.diagnostics.succeed();
                return Ok(result);
            }
            let application_error = {
                let mut state = self.0.state.lock().expect("unary operation");
                self.0.account.with_security(|| -> Result<_> {
                    if state.closed || state.delivered {
                        return Err(failure(ServiceFailure::Closed));
                    }
                    if let Some(failure) = state.failure {
                        return Err(failure);
                    }
                    let code = state
                        .complete
                        .as_ref()
                        .and_then(|response| response.application_error_code);
                    let Some(code) = code.filter(|code| {
                        !self
                            .0
                            .error_codecs
                            .iter()
                            .any(|codec| codec.definition().code == *code)
                    }) else {
                        return Ok(None);
                    };
                    let response = state.complete.take().expect("complete application error");
                    state.delivered = true;
                    Ok(Some(TypedUnaryResult {
                        value: if self.0.errors.iter().any(|error| error.code == code) {
                            TypedUnaryValue::ApplicationError {
                                code,
                                payload: response.payload.to_vec(),
                            }
                        } else {
                            TypedUnaryValue::UnknownApplicationError {
                                code,
                                raw_payload: response.payload.to_vec(),
                            }
                        },
                        codec_identity: self.0.response_identity(Some(code))?,
                        application_input_provided: false,
                        _custody: None,
                    }))
                })??
            };
            if let Some(mut result) = application_error {
                result._custody = self.0.charge.lock().expect("unary charge").take();
                self.0.diagnostics.succeed();
                return Ok(result);
            }
            let complete = {
                let state = self.0.state.lock().expect("unary operation");
                state.complete.is_some() && !state.scheduled && !state.progress.decoder_started
            };
            if complete {
                let position = tokio::select! {
                    position = self.0.completion.position() => position?,
                    _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
                };
                let owner = self.0.clone();
                {
                    let mut state = owner.state.lock().expect("unary operation");
                    if state.closed || state.progress.decoder_started || state.scheduled {
                        return Err(failure(ServiceFailure::Closed));
                    }
                    state.scheduled = true;
                    state.progress.worker_active = true;
                    owner.physical_workers.fetch_add(1, Ordering::AcqRel);
                }
                let worker = OperationWorker(owner.clone());
                tokio::spawn(async move {
                    let _worker = worker;
                    owner.decode(position).await;
                });
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) }
        }
    }
}
struct Waiter<T>(Arc<OperationInner<T>>);
impl<T> Drop for Waiter<T> {
    fn drop(&mut self) {
        self.0.state.lock().expect("unary operation").waiter = false;
        self.0.changed.notify_waiters();
    }
}
impl<T: Send + 'static> OperationInner<T> {
    fn response_identity(
        &self,
        application_error: Option<u32>,
    ) -> Result<Option<MessageCodecIdentity>> {
        Ok(match application_error {
            None => Some(self.identity.clone()),
            Some(code) => self
                .errors
                .iter()
                .find(|error| error.code == code)
                .map(|error| MessageCodecIdentity::from(&error.message)),
        })
    }
    fn claim_waiter(&self) -> Result<()> {
        let mut state = self.state.lock().expect("unary operation");
        if state.waiter {
            return Err(failure(ServiceFailure::KnownApplicationDependency));
        }
        state.waiter = true;
        Ok(())
    }
    fn set_failure(&self, failure: ServiceError, publication: ServicePublication) {
        let mut state = self.state.lock().expect("unary operation");
        state.progress.publication = publication;
        state.progress.worker_active = false;
        state.failure = Some(failure);
        drop(state);
        self.diagnostics.service_failure(failure);
        self.account.detach_result();
        self.changed.notify_waiters();
    }
    fn prepare_resume_publication(
        &self,
        resume: &ResumeOperationTransport,
        header: &ApplicationHeader,
        payload: &[u8],
    ) -> Result<(
        crate::rpc_stream_messages_v4::PreparedStreamPublication,
        Arc<Mutex<Option<ServiceFailure>>>,
    )> {
        let gate = resume.gate.clone();
        let cancellation = self.cancellation.clone();
        let context = self.caller_context.clone();
        let token_expires = resume.token_expires_at_ms;
        let cap = header.uint(5).unwrap_or(0);
        let decline = Arc::new(Mutex::new(None));
        let gate_decline = decline.clone();
        let first_byte_gate = Arc::new(move |now: crate::environment_v4::TrustedTimeSample| {
            if now.upper_ms >= token_expires {
                *gate_decline.lock().expect("Resume refusal") =
                    Some(ServiceFailure::PermissionDenied);
                return Err(crate::SessionError::Timeout);
            }
            if let Some(context) = &context
                && context.check_cancellation().is_err()
            {
                *gate_decline.lock().expect("Resume refusal") = Some(ServiceFailure::Canceled);
                return Err(crate::SessionError::Canceled);
            }
            let mut state = gate.lock().expect("Resume publication gate");
            if *state == ResumePublicationGate::Withdrawn
                || *state == ResumePublicationGate::Prepared && cancellation.is_cancelled()
            {
                return Err(crate::SessionError::Canceled);
            }
            *state = ResumePublicationGate::Publishing;
            Ok(())
        });
        let publication = resume.messages.try_prepare_publication(
            header.clone(),
            payload,
            cap,
            Some(first_byte_gate),
        )?;
        Ok((publication, decline))
    }
    async fn observe_resume(
        self: Arc<Self>,
        resume: ResumeOperationTransport,
        header: ApplicationHeader,
        payload: Arc<Zeroizing<Vec<u8>>>,
        prepared: crate::rpc_stream_messages_v4::PreparedStreamPublication,
        decline: Arc<Mutex<Option<ServiceFailure>>>,
    ) {
        let cap = header.uint(5).unwrap_or(0);
        let publication = prepared.publish().await;
        let fact = match &publication {
            Ok(publication) => publication.publication,
            Err(_)
                if *resume.gate.lock().expect("Resume publication gate")
                    != ResumePublicationGate::Publishing =>
            {
                ServicePublication::NotSubmitted
            }
            Err(_) => ServicePublication::Unknown,
        };
        self.state
            .lock()
            .expect("unary operation")
            .progress
            .publication = fact;
        self.changed.notify_waiters();
        if fact != ServicePublication::Committed {
            if fact == ServicePublication::NotSubmitted {
                let _ = resume.messages.settle_unsubmitted_resume().await;
            } else {
                resume.messages.close();
                let _ = resume.messages.wait_cleanup().await;
            }
            let cause = *decline.lock().expect("Resume refusal");
            let cause = cause.or_else(|| {
                publication
                    .as_ref()
                    .ok()
                    .and_then(|receipt| receipt.failure)
            });
            self.set_failure(
                cause.map(failure).unwrap_or_else(|| {
                    publication
                        .err()
                        .unwrap_or_else(|| failure(ServiceFailure::ServiceUnavailable))
                }),
                fact,
            );
            return;
        }
        // Closing result delivery cannot discard a committed framing boundary.
        // This original late-response owner keeps reading until the fixed cap.
        let cleanup_cancellation = resume.messages.cancellation();
        let response = tokio::select! {
            response = resume.messages.next(&cleanup_cancellation) => response,
            _ = tokio::time::sleep_until(self.deadline) => Err(failure(ServiceFailure::DeadlineExceeded)),
        };
        let outcome = async {
            let response = response?.ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
            response.header.check_response(&header)?;
            if self.account.security_time()?.upper_ms >= cap {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            let application_error_code = response
                .header
                .has(10)
                .then(|| response.header.uint(10).unwrap_or(0) as u32);
            if let Some(code) = application_error_code {
                if self
                    .errors
                    .iter()
                    .find(|error| error.code == code)
                    .is_some_and(|error| response.payload.len() > error.max_payload_bytes as usize)
                {
                    return Err(failure(ServiceFailure::DecodeFailed));
                }
            } else {
                let result = crate::ApplicationResumeResult::capture(&response.payload)?;
                let original = crate::checkpoint_v4::ApplicationResumeRequest::capture(&payload)?;
                if result.status() == crate::ApplicationResumeStatus::Accepted
                    && result.progress().is_none_or(|progress| {
                        progress.checkpoint != original.expected
                            || original.generation.checked_add(1) != Some(progress.generation)
                    })
                {
                    return Err(failure(ServiceFailure::Protocol));
                }
            }
            let accepted = application_error_code.is_none()
                && crate::ApplicationResumeResult::capture(&response.payload)?.status()
                    == crate::ApplicationResumeStatus::Accepted;
            if let Some(continuation) = resume.continuation.as_ref().filter(|_| accepted) {
                resume
                    .messages
                    .continue_resume_input(continuation.request())
                    .await?;
                resume
                    .handed_off
                    .store(true, std::sync::atomic::Ordering::Release);
                if let Some(current) = self.resume.lock().expect("Resume handoff").as_mut() {
                    current.continuation.take();
                }
                if let Err(error) = continuation.activate() {
                    continuation.refuse(error);
                }
            } else {
                resume.messages.settle_resume().await?;
                if let Some(continuation) = &resume.continuation {
                    continuation.refuse(failure(ServiceFailure::OperationConflict));
                }
            }
            Ok(CompleteResponse {
                payload: response.payload,
                application_error_code,
            })
        }
        .await;
        match outcome {
            Ok(candidate) => {
                let mut state = self.state.lock().expect("unary operation");
                let saved = self.account.with_security(|| {
                    state.progress.complete_input = true;
                    state.progress.worker_active = false;
                    let caller_current = self
                        .caller_context
                        .as_ref()
                        .is_none_or(|context| context.check_cancellation().is_ok());
                    if !state.closed && !self.cancellation.is_cancelled() && caller_current {
                        state.complete = Some(candidate);
                    } else {
                        state.failure = Some(failure(ServiceFailure::Canceled));
                        self.diagnostics
                            .service_failure(failure(ServiceFailure::Canceled));
                    }
                });
                drop(state);
                self.account.detach_result();
                if let Err(error) = saved {
                    self.set_failure(error.into(), fact);
                }
            }
            Err(error) => {
                resume.messages.close();
                let _ = resume.messages.wait_cleanup().await;
                self.set_failure(error, fact);
            }
        }
        self.changed.notify_waiters();
    }
    async fn observe_input(
        self: Arc<Self>,
        peer: Arc<PeerInner>,
        published: crate::rpc_channel_v4::PublishedMessage,
    ) {
        let mut publication = published.publication;
        let mut canceled = None;
        let receipt = tokio::select! {
            receipt = &mut publication => receipt,
            _ = self.cancellation.cancelled() => { canceled = Some(failure(ServiceFailure::Canceled)); publication.await },
            _ = tokio::time::sleep_until(self.deadline) => {
                canceled = Some(failure(ServiceFailure::DeadlineExceeded)); self.cancellation.cancel(); publication.await
            }
        };
        let receipt = receipt.unwrap_or(PublicationReceipt {
            fact: PublicationFact::Unknown,
            error: Some(ServiceFailure::Closed),
        });
        let fact = match receipt.fact {
            PublicationFact::NotSubmitted => ServicePublication::NotSubmitted,
            PublicationFact::Committed => ServicePublication::Committed,
            PublicationFact::Aborted => ServicePublication::InputAborted,
            PublicationFact::Unknown => ServicePublication::Unknown,
        };
        if receipt.fact == PublicationFact::NotSubmitted && canceled.is_none() {
            let operation = UnaryOperation(self.clone());
            if operation.reselect_not_submitted() {
                self.state
                    .lock()
                    .expect("old publication callback exit")
                    .progress
                    .worker_active = false;
                self.changed.notify_waiters();
                return;
            }
        }
        {
            let mut state = self.state.lock().expect("unary operation");
            state.progress.publication = fact;
            state.prepared.take();
        }
        if let Some(route) = self
            .controller_route
            .lock()
            .expect("terminal Controller publication")
            .as_mut()
        {
            route.selector = None;
            route.selecting = false;
        }
        self.changed.notify_waiters();
        if let Some(error) = canceled {
            if receipt.fact == PublicationFact::Committed
                && let Ok(stop) = peer.channel.abandon(&published.origin, published.serial)
            {
                let _ = stop.await;
            }
            self.set_failure(error, fact);
            return;
        }
        if receipt.fact != PublicationFact::Committed {
            self.set_failure(
                failure(receipt.error.unwrap_or(ServiceFailure::ServiceUnavailable)),
                fact,
            );
            return;
        }
        let Some(response) = published.response else {
            self.set_failure(failure(ServiceFailure::Protocol), fact);
            return;
        };
        let result = tokio::select! {
            biased;
            response = response => response.map_err(|_| failure(ServiceFailure::Closed)).and_then(|response| response),
            _ = self.cancellation.cancelled() => Err(failure(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(self.deadline) => Err(failure(ServiceFailure::DeadlineExceeded)),
        };
        match result {
            Ok(response) if !response.aborted && !response.header.sdk_error() => {
                let cap = self
                    .state
                    .lock()
                    .expect("unary operation")
                    .header
                    .uint(5)
                    .unwrap_or(0);
                if response.completed_at_upper_ms >= cap {
                    self.set_failure(failure(ServiceFailure::DeadlineExceeded), fact);
                    return;
                }
                let application_error_code = response
                    .header
                    .has(10)
                    .then(|| response.header.uint(10).unwrap_or(0) as u32);
                if let Some(code) = application_error_code
                    && self
                        .errors
                        .iter()
                        .find(|error| error.code == code)
                        .is_some_and(|error| {
                            response.payload.len() > error.max_payload_bytes as usize
                        })
                {
                    self.state
                        .lock()
                        .expect("unary operation")
                        .progress
                        .complete_input = true;
                    self.set_failure(failure(ServiceFailure::DecodeFailed), fact);
                    return;
                }
                let candidate = CompleteResponse {
                    payload: response.payload,
                    application_error_code,
                };
                let mut state = self.state.lock().expect("unary operation");
                let settled = self.account.with_security(|| {
                    state.progress.complete_input = true;
                    state.progress.worker_active = false;
                    if !state.closed {
                        state.complete = Some(candidate);
                    }
                });
                drop(state);
                self.account.detach_result();
                if let Err(error) = settled {
                    self.set_failure(error.into(), fact);
                }
            }
            Ok(response) => self.set_failure(
                if response.header.sdk_error() {
                    ServiceError::from_sdk_payload(&response.payload)
                        .unwrap_or_else(|_| failure(ServiceFailure::Protocol))
                } else {
                    failure(ServiceFailure::ServiceUnavailable)
                },
                fact,
            ),
            Err(error) => {
                if let Ok(stop) = peer.channel.abandon(&published.origin, published.serial) {
                    let _ = stop.await;
                }
                self.set_failure(error, fact);
            }
        }
        drop(peer);
        self.changed.notify_waiters();
    }
    async fn decode(
        self: Arc<Self>,
        position: crate::application_executor_v4::ApplicationPosition,
    ) {
        let invocation = match position.enter() {
            Ok(invocation) => invocation,
            Err(error) => {
                let publication = self
                    .state
                    .lock()
                    .expect("unary operation")
                    .progress
                    .publication;
                self.set_failure(error.into(), publication);
                return;
            }
        };
        let payload = {
            let mut state = self.state.lock().expect("unary operation");
            self.account.with_security(|| {
                if state.closed || state.delivered || self.cancellation.is_cancelled() {
                    return None;
                }
                let response = state.complete.take()?;
                state.progress.decoder_started = true;
                state.typed_code = response.application_error_code;
                state.progress.application_input_provided =
                    response.application_error_code.is_some() || self.codec.application_input();
                Some(response)
            })
        };
        let payload = match payload {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                let mut state = self.state.lock().expect("unary operation");
                state.progress.worker_active = false;
                let release = state.closed || state.delivered;
                if !release {
                    state.failure = Some(failure(ServiceFailure::Canceled));
                    self.diagnostics
                        .service_failure(failure(ServiceFailure::Canceled));
                }
                drop(state);
                if release {
                    self.charge.lock().expect("unary charge").take();
                }
                self.changed.notify_waiters();
                return;
            }
            Err(error) => {
                let publication = self
                    .state
                    .lock()
                    .expect("unary operation")
                    .progress
                    .publication;
                self.set_failure(error.into(), publication);
                return;
            }
        };
        let context = invocation.context();
        let code = payload.application_error_code;
        let decoded = if let Some(code) = code {
            match self
                .error_codecs
                .iter()
                .find(|codec| codec.definition().code == code)
            {
                Some(codec) => {
                    let callback = codec.decode(Arc::new(payload.payload.to_vec()), context);
                    tokio::pin!(callback);
                    let value = tokio::select! {
                        value = &mut callback => value,
                        _ = self.cancellation.cancelled() => { invocation.cancel(); callback.await },
                    };
                    value.map(|value| TypedUnaryValue::DecodedApplicationError { code, value })
                }
                None => Err(failure(ServiceFailure::DecodeFailed)),
            }
        } else {
            match &self.codec {
            ResponseCodec::Sync(codec) => {
                if crate::message_codec_v4::controlled(codec.as_ref()) {
                    codec.decode_with_context(&payload.payload, &context)
                } else {
                    let codec = codec.clone(); let bytes = payload.payload.to_vec();
                    tokio::task::spawn_blocking(move || std::panic::catch_unwind(AssertUnwindSafe(|| codec.decode_with_context(&bytes, &context)))
                        .unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed))))
                        .await.unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed)))
                }
            },
            ResponseCodec::Async(codec) => {
                let callback = AssertUnwindSafe(codec.decode(&payload.payload, context)).catch_unwind(); tokio::pin!(callback);
                let outcome = tokio::select! {
                    outcome = &mut callback => outcome,
                    _ = self.cancellation.cancelled() => { invocation.cancel(); callback.await },
                };
                outcome.unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed)))
            }
        }.map(TypedUnaryValue::Response)
        };
        drop(invocation);
        drop(position);
        let mut state = self.state.lock().expect("unary operation");
        state.progress.worker_active = false;
        match decoded {
            Ok(value) if !state.closed => state.typed = Some(value),
            Ok(_) => {}
            Err(_) => {
                state.failure = Some(failure(ServiceFailure::DecodeFailed));
                self.diagnostics
                    .service_failure(failure(ServiceFailure::DecodeFailed));
            }
        }
        let release = state.closed || state.delivered;
        drop(state);
        if release {
            self.charge.lock().expect("unary charge").take();
        }
        self.changed.notify_waiters();
    }
}
