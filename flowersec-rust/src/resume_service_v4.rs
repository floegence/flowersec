//! Explicit recovery runs on the exact registered accepted business Stream.
//! The outer execution and checkpoint CAS share the original durable history.
use crate::{
    ApplicationBinding, ApplicationCheckpoint, ApplicationResumeResult, RawStreamHandler,
    RawStreamRegistration, ServeError, ServeFailure, ServicePublication, StreamAuthorization,
    StreamingItemSource, TransportEnvironment,
    checkpoint_v4::ApplicationResumeRequest,
    crypto_v4::{Metadata, OpenRequest, Stream},
    environment_v4::{EnvironmentCharge, ResourceAccount, ResourceCharge, ResourceLimits},
    execution_history::{
        ExecutionAttempt, ExecutionCallbackExit, ExecutionIdentity, ExecutionService,
    },
    rpc_stream_messages_v4::StreamMessages,
    rpc_wire_v4::ApplicationHeader,
    service_client_v4::ServiceResumeBinding,
    service_contract::{
        AdmissionOffer, ServiceContract, ServiceError, ServiceFailure, ServiceSemantics,
        ServiceShape,
    },
    service_peer_v4::{PeerInner, ServicePeer, UnaryRequestContext, UnaryResponse},
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{
    fmt,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn rejected() -> ServeError {
    ServeError::new(ServeFailure::Rejected)
}
const MEMBERSHIPS: usize = 128;
const RESUME_REQUEST_MAX: usize = 9345;
const RESUME_RESULT_MAX: usize = 4248;

#[async_trait]
pub trait UnaryResumeServiceHandler: fmt::Debug + Send + Sync + 'static {
    async fn authorize(
        &self,
        context: UnaryRequestContext,
        checkpoint: &ApplicationCheckpoint,
    ) -> Result<()>;
    /// The target is the same accepted Stream after the real Resume reader and
    /// sender have exited. The returned result belongs to the original execution.
    async fn resume(
        &self,
        context: UnaryRequestContext,
        checkpoint: ApplicationCheckpoint,
        target: Stream,
    ) -> Result<UnaryResponse>;
    fn application_bytes(&self) -> u64 {
        65536
    }
}
#[async_trait]
pub trait StreamingResumeServiceHandler: fmt::Debug + Send + Sync + 'static {
    async fn authorize(
        &self,
        context: UnaryRequestContext,
        checkpoint: &ApplicationCheckpoint,
    ) -> Result<()>;
    /// Produces only the continuation. The original request is never replayed.
    async fn resume(
        &self,
        context: UnaryRequestContext,
        checkpoint: ApplicationCheckpoint,
    ) -> Result<Box<dyn StreamingItemSource>>;
    fn application_bytes(&self) -> u64 {
        65536
    }
}
#[derive(Clone, Debug)]
pub enum ResumeServiceHandler {
    Unary(Arc<dyn UnaryResumeServiceHandler>),
    Streaming(Arc<dyn StreamingResumeServiceHandler>),
}
impl ResumeServiceHandler {
    fn application_bytes(&self) -> u64 {
        match self {
            Self::Unary(handler) => handler.application_bytes(),
            Self::Streaming(handler) => handler.application_bytes(),
        }
    }
    async fn authorize(
        &self,
        context: UnaryRequestContext,
        checkpoint: &ApplicationCheckpoint,
    ) -> Result<()> {
        match self {
            Self::Unary(handler) => handler.authorize(context, checkpoint).await,
            Self::Streaming(handler) => handler.authorize(context, checkpoint).await,
        }
    }
}
#[derive(Clone, Debug)]
pub struct ResumeServiceConfig {
    pub binding: ServiceResumeBinding,
    pub definition: crate::ServiceDefinition,
    pub method: crate::MethodDefinition,
    pub contract: ServiceContract,
    pub original_contract: ServiceContract,
    pub handler: ResumeServiceHandler,
    pub execution: ExecutionService,
    pub offer: Option<AdmissionOffer>,
    pub offer_window_ms: Option<u64>,
}
struct Declaration {
    config: ResumeServiceConfig,
    bindings: Mutex<Vec<SessionBinding>>,
    _charge: EnvironmentCharge,
}
#[derive(Clone)]
struct SessionBinding {
    account: ResourceAccount,
    peer: Weak<PeerInner>,
    caller: ExecutionIdentity,
    cancellation: CancellationToken,
    _charge: Arc<ResourceCharge>,
}
impl SessionBinding {
    fn check(&self) -> Result<()> {
        self.account.check()?;
        if self.cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::Closed));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct RegisteredResumeService(Arc<Declaration>);
impl fmt::Debug for RegisteredResumeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisteredResumeService { <opaque> }")
    }
}
#[derive(Clone, Debug)]
pub struct ResumeServiceRegistration {
    pub service: RegisteredResumeService,
    /// Supplied by the authenticated assembly, never reconstructed from payload.
    pub caller: ExecutionIdentity,
    pub query_allowed: bool,
}
pub(crate) struct ResumeMembership {
    declaration: Weak<Declaration>,
    account: ResourceAccount,
    cancellation: CancellationToken,
}
impl ResumeMembership {
    pub(crate) fn install(&self, peer: &ServicePeer) -> Result<()> {
        if !self.account.same_owner(&peer.0.account) || self.cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let declaration = self
            .declaration
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let mut bindings = declaration
            .bindings
            .lock()
            .expect("Resume Session registrations");
        let binding = bindings
            .iter_mut()
            .find(|binding| binding.account.same_owner(&self.account))
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        if binding.peer.strong_count() != 0 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        binding.peer = Arc::downgrade(&peer.0);
        Ok(())
    }
}
impl Drop for ResumeMembership {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(declaration) = self.declaration.upgrade() {
            let removed = {
                let mut bindings = declaration
                    .bindings
                    .lock()
                    .expect("Resume Session registrations");
                bindings
                    .iter()
                    .position(|binding| binding.account.same_owner(&self.account))
                    .map(|index| bindings.remove(index))
            };
            drop(removed);
        }
    }
}
impl RegisteredResumeService {
    pub fn new(environment: &TransportEnvironment, config: ResumeServiceConfig) -> Result<Self> {
        config.contract.check_environment(environment.root())?;
        config
            .original_contract
            .check_environment(environment.root())?;
        config
            .contract
            .check_method(&config.definition, &config.method)?;
        let matching_shape = matches!(
            (&config.handler, config.original_contract.shape()),
            (ResumeServiceHandler::Unary(_), ServiceShape::Unary)
                | (
                    ResumeServiceHandler::Streaming(_),
                    ServiceShape::ServerStreaming
                )
        );
        if !matching_shape
            || config.contract.shape() != ServiceShape::Unary
            || config.contract.semantics() != ServiceSemantics::Execution
            || config.original_contract.semantics() != ServiceSemantics::Execution
            || config.contract.optional_uint(13) != Some(1)
            || config.original_contract.optional_uint(13) != Some(1)
            || config.contract.optional_uint(15).unwrap_or(0) == 0
            || config.original_contract.field(20).is_none()
            || config.contract.namespace() != config.original_contract.namespace()
            || config.contract.type_id() == config.original_contract.type_id()
            || config.contract.uint(23)? < RESUME_REQUEST_MAX as u64
            || config.contract.uint(10)? < RESUME_RESULT_MAX as u64
            || !Arc::ptr_eq(&config.execution.0.root, environment.root())
            || !config.execution.recovery_configured()
            || config.binding.stream_kind.is_empty()
            || config.binding.stream_kind.len() > 128
            || config.binding.stream_kind.starts_with("flowersec.")
            || config.binding.stream_kind.starts_with("flowersec/")
            || config.binding.stream_metadata.is_typed()
            || config.handler.application_bytes() == 0
            || config.handler.application_bytes() > 1 << 30
            || config.offer.is_none() && config.offer_window_ms.is_none()
            || config.offer_window_ms.is_some_and(|window| {
                window == 0
                    || config
                        .contract
                        .uint(16)
                        .map_or(true, |maximum| window > maximum)
            })
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        if let Some(offer) = &config.offer {
            offer.check_interval(
                &config.contract,
                offer.not_after_ms(),
                offer.not_before_ms(),
                offer.not_before_ms(),
            )?;
        }
        let charge = environment.root().reserve_environment(ResourceLimits {
            sdk_bytes: 8192 + config.handler.application_bytes() + MEMBERSHIPS as u64 * 1024,
            items: MEMBERSHIPS as u64 + 1,
            ..ResourceLimits::default()
        })?;
        Ok(Self(Arc::new(Declaration {
            config,
            bindings: Mutex::new(Vec::with_capacity(MEMBERSHIPS)),
            _charge: charge,
        })))
    }
    pub fn raw_registration(&self) -> RawStreamRegistration {
        RawStreamRegistration {
            kind: self.0.config.binding.stream_kind.clone(),
            metadata: None,
            handler: Arc::new(Adapter(self.clone())),
        }
    }
    pub(crate) fn contract(&self) -> &ServiceContract {
        &self.0.config.contract
    }
    pub(crate) fn original_contract(&self) -> &ServiceContract {
        &self.0.config.original_contract
    }
    pub(crate) fn execution(&self) -> &ExecutionService {
        &self.0.config.execution
    }
    pub(crate) fn offer(&self, account: &ResourceAccount) -> Result<Option<AdmissionOffer>> {
        match self.0.config.offer_window_ms {
            Some(window) => {
                let now = account.security_time()?;
                Ok(Some(AdmissionOffer::current(
                    self.contract(),
                    now.lower_ms,
                    now.upper_ms,
                    window,
                )?))
            }
            None => Ok(self.0.config.offer.clone()),
        }
    }
    pub(crate) fn prepare_binding(
        &self,
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        caller: ExecutionIdentity,
    ) -> Result<ResumeMembership> {
        let charge = account.reserve(Self::preparation_limits())?;
        self.prepare_binding_prepaid(account, profile, identity, caller, charge)
    }
    pub(crate) fn preparation_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 1024,
            items: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn prepare_binding_prepaid(
        &self,
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        caller: ExecutionIdentity,
        charge: ResourceCharge,
    ) -> Result<ResumeMembership> {
        self.contract()
            .check_environment(account.environment_root())?;
        if profile != 2
            || caller.identity_digest != identity
            || caller.authority == [0; 32]
            || !crate::execution_history::id(&caller.subject)
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        if !charge.matches(account, Self::preparation_limits()) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let charge = Arc::new(charge);
        let cancellation = CancellationToken::new();
        let binding = SessionBinding {
            account: account.clone(),
            peer: Weak::new(),
            caller,
            cancellation: cancellation.clone(),
            _charge: charge,
        };
        {
            let mut bindings = self
                .0
                .bindings
                .lock()
                .expect("Resume Session registrations");
            if bindings.len() >= MEMBERSHIPS
                || bindings.iter().any(|old| old.account.same_owner(account))
            {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
            bindings.push(binding);
        }
        Ok(ResumeMembership {
            declaration: Arc::downgrade(&self.0),
            account: account.clone(),
            cancellation,
        })
    }
    pub(crate) fn bind(
        &self,
        peer: &ServicePeer,
        caller: ExecutionIdentity,
    ) -> Result<ResumeMembership> {
        peer.0.check()?;
        let session = peer
            .0
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let (_, profile, identity) = session
            .service_identity()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        let membership = self.prepare_binding(&peer.0.account, profile, identity, caller)?;
        membership.install(peer)?;
        Ok(membership)
    }
    fn find(&self, account: &ResourceAccount) -> Result<SessionBinding> {
        let bindings = self
            .0
            .bindings
            .lock()
            .expect("Resume Session registrations");
        let binding = bindings
            .iter()
            .find(|binding| binding.account.same_owner(account))
            .cloned()
            .ok_or_else(|| failure(ServiceFailure::PermissionDenied))?;
        binding.check()?;
        Ok(binding)
    }
}
#[derive(Debug)]
struct Adapter(RegisteredResumeService);
#[async_trait]
impl RawStreamHandler for Adapter {
    async fn authorize(
        &self,
        _: ApplicationBinding,
        _: Metadata,
        _: CancellationToken,
    ) -> std::result::Result<StreamAuthorization, ServeError> {
        Ok(StreamAuthorization::Reject)
    }
    async fn handle(
        &self,
        _: Stream,
        _: Metadata,
        _: CancellationToken,
    ) -> std::result::Result<(), ServeError> {
        Err(rejected())
    }
}
pub(crate) fn is_sdk_resume_handler(handler: &dyn RawStreamHandler) -> bool {
    let original: &dyn std::any::Any = handler;
    original.is::<Adapter>()
}
pub(crate) async fn handle_sdk_resume_open(
    handler: Arc<dyn RawStreamHandler>,
    request: OpenRequest,
    cancellation: CancellationToken,
) -> std::result::Result<(), ServeError> {
    let original: &dyn std::any::Any = handler.as_ref();
    original
        .downcast_ref::<Adapter>()
        .ok_or_else(rejected)?
        .handle_original_open(request, cancellation)
        .await
}
impl Adapter {
    async fn handle_original_open(
        &self,
        request: OpenRequest,
        parent: CancellationToken,
    ) -> std::result::Result<(), ServeError> {
        let diagnostics = request
            .account()
            .diagnostic_activity(crate::DiagnosticPhase::Application, 1);
        let result = async {
        let config = self.0.0.config.clone();
        if request.kind() != config.binding.stream_kind
            || request.metadata() != &config.binding.stream_metadata
        {
            return Err(rejected());
        }
        let binding = self.0.find(&request.account()).map_err(|_| rejected())?;
        let peer = binding.peer.upgrade().ok_or_else(rejected)?;
        let session = peer.session.session().map_err(|_| rejected())?;
        let original_limit = config.original_contract.uint(10).map_err(|_| rejected())? as usize;
        // Reserve the entire callback/capture/output graph while OPEN is pending.
        let charge = binding
            .account
            .reserve(ResourceLimits {
                sdk_bytes: config.handler.application_bytes()
                    + RESUME_REQUEST_MAX as u64
                    + 2 * original_limit.max(RESUME_RESULT_MAX) as u64
                    + 65536,
                items: 8,
                tasks: 2,
                work_slots: 1,
                timers: 2,
                ..ResourceLimits::default()
            })
            .map_err(|_| rejected())?;
        let tail = peer.application_tail().map_err(|_| rejected())?;
        let peer_worker = peer.retain_worker();
        let initial_deadline = Instant::now() + Duration::from_secs(60);
        let (messages, captured_target) = StreamMessages::accept_resume(
            request,
            &peer.channel,
            &config.binding.stream_kind,
            RESUME_REQUEST_MAX
                .max(original_limit)
                .max(RESUME_RESULT_MAX),
            initial_deadline,
        )
        .map_err(|_| rejected())?;
        messages.retain_peer(&peer);
        messages.bind_cancellation(binding.cancellation.clone());
        let messages = Arc::new(messages);
        let input = tokio::select! {
            input = messages.next(&parent) => input.map_err(|_| rejected())?,
            _ = binding.cancellation.cancelled() => return Err(rejected()),
            _ = tokio::time::sleep_until(initial_deadline) => return Err(rejected()),
        }
        .ok_or_else(rejected)?;
        let header = input.header;
        messages
            .bind_response(header.clone())
            .map_err(|_| rejected())?;
        let request = ApplicationResumeRequest::capture(&input.payload).map_err(|_| rejected())?;
        let now = binding.account.security_time().map_err(|_| rejected())?;
        let wire_cap = header.uint(5).map_err(|_| rejected())?;
        if request.target != captured_target
            || header.kind() != "resume_request"
            || header.type_id().map_err(|_| rejected())? != config.contract.type_id()
            || header.bytes(6).map_err(|_| rejected())? != config.contract.digest()
            || header.uint(8).map_err(|_| rejected())? < RESUME_RESULT_MAX as u64
            || header.uint(8).map_err(|_| rejected())?
                > config.contract.uint(10).map_err(|_| rejected())?
            || now.upper_ms >= wire_cap
            || wire_cap
                > now
                    .lower_ms
                    .saturating_add(config.contract.uint(17).map_err(|_| rejected())?)
            || crate::rpc_wire_v4::execution_digest(
                config.contract.encoded(),
                &header,
                &input.payload,
            )
            .map_err(|_| rejected())?
                != header.bytes(4).map_err(|_| rejected())?
        {
            let _ = publish_confirmation(
                &messages,
                &header,
                &ApplicationResumeResult::refused(false),
                wire_cap,
            )
            .await;
            let _ = messages.settle_resume().await;
            return Err(rejected());
        }
        let deadline =
            Instant::now() + Duration::from_millis(wire_cap.saturating_sub(now.upper_ms));
        let admission = match peer.group.admit_ordinary(
            true,
            None,
            header.uint(7).map_err(|_| rejected())? == 1,
        ) {
            Ok(admission) => admission,
            Err(_) => {
                let _ = publish_confirmation(
                    &messages,
                    &header,
                    &ApplicationResumeResult::refused(false),
                    wire_cap,
                )
                .await;
                let _ = messages.settle_resume().await;
                return Err(rejected());
            }
        };
        let position = tokio::select! {
            position = admission.position() => position.map_err(|_| rejected())?,
            _ = parent.cancelled() => return Err(rejected()),
            _ = binding.cancellation.cancelled() => return Err(rejected()),
            _ = tokio::time::sleep_until(deadline) => return Err(rejected()),
        };
        let invocation = position.enter().map_err(|_| rejected())?;
        let callback_cancel = parent.child_token();
        let context = UnaryRequestContext {
            invocation: invocation.context(),
            cancellation: callback_cancel.clone(),
            execution_identity: Some(binding.caller.clone()),
            execution: None,
            publication: crate::ResponsePublication::not_applicable(),
            maintenance: session.maintenance_owner().ok(),
        };
        // The real callback and original executor/tail are never aborted by the
        // bounded wire owner when application code ignores cancellation.
        let (handoff, mut confirmed) = tokio::sync::oneshot::channel();
        let worker_messages = messages.clone();
        let worker_binding = binding.clone();
        let worker_peer = peer.clone();
        let worker_cancel = callback_cancel.clone();
        let physical_diagnostics = diagnostics.clone();
        let worker = tokio::spawn(async move {
            let _charge = charge;
            let _tail = tail;
            let _peer_worker = peer_worker;
            let _position = position;
            let _invocation = invocation;
            let _input_charge = input.charge;
            let result = run_resume(
                config,
                worker_binding,
                worker_peer,
                session,
                worker_messages,
                header,
                input.payload,
                request,
                context,
                handoff,
            )
            .await;
            physical_diagnostics.service_outcome(&result);
            result
        });
        let outcome = tokio::select! {
            outcome = worker => return outcome.map_err(|_| rejected())?.map_err(|_| rejected()),
            result = &mut confirmed => {
                if result.is_ok() { return Ok(()); }
                Err(failure(ServiceFailure::ServiceUnavailable))
            },
            _ = parent.cancelled() => Err(failure(ServiceFailure::Canceled)),
            _ = binding.cancellation.cancelled() => Err(failure(ServiceFailure::Closed)),
            _ = tokio::time::sleep_until(deadline) => Err(failure(ServiceFailure::DeadlineExceeded)),
        };
        diagnostics.service_outcome(&outcome);
        worker_cancel.cancel();
        messages.close();
        // A JoinHandle dropped here detaches the original retained callback. Its
        // resources remain with that callback until its actual exit.
        outcome.map_err(|_| rejected())
        }.await;
        if let Err(error) = &result {
            diagnostics.serve_outcome::<()>(&Err(error.clone()));
        }
        result
    }
}
async fn await_application<T>(
    callback: impl Future<Output = Result<T>>,
    binding: &SessionBinding,
    cancellation: &CancellationToken,
    parent: &CancellationToken,
    cap: u64,
) -> Result<T> {
    let callback = AssertUnwindSafe(callback).catch_unwind();
    tokio::pin!(callback);
    loop {
        tokio::select! {
            value = &mut callback => return value.unwrap_or_else(|_| Err(failure(ServiceFailure::ServiceFailed))),
            _ = cancellation.cancelled() => { let _ = callback.await; return Err(failure(ServiceFailure::Canceled)); },
            _ = parent.cancelled() => { cancellation.cancel(); let _ = callback.await; return Err(failure(ServiceFailure::Canceled)); },
            _ = binding.cancellation.cancelled() => { cancellation.cancel(); let _ = callback.await; return Err(failure(ServiceFailure::Closed)); },
            _ = binding.account.security_changed() => {},
            _ = tokio::time::sleep(binding.account.next_security_check()) => {},
        }
        if let Err(error) = binding.check().and_then(|_| {
            if binding.account.security_time()?.upper_ms >= cap {
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
async fn publish_confirmation(
    messages: &StreamMessages,
    header: &ApplicationHeader,
    result: &ApplicationResumeResult,
    cap: u64,
) -> Result<()> {
    let payload = result.encoded()?;
    let publication = messages
        .write(
            header.response("resume_response", payload.len() as u32, None)?,
            &payload,
            cap,
        )
        .await?;
    if publication.publication != ServicePublication::Committed {
        return Err(failure(
            publication
                .failure
                .unwrap_or(ServiceFailure::ServiceUnavailable),
        ));
    }
    Ok(())
}
#[expect(
    clippy::too_many_arguments,
    reason = "Resume execution binds the original attempt, request, checkpoint and continuation publication lifetime."
)]
async fn run_resume(
    config: ResumeServiceConfig,
    binding: SessionBinding,
    peer: Arc<PeerInner>,
    session: crate::crypto_v4::Session,
    messages: Arc<StreamMessages>,
    header: ApplicationHeader,
    payload: zeroize::Zeroizing<Vec<u8>>,
    request: ApplicationResumeRequest,
    context: UnaryRequestContext,
    handoff: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    let wire_cap = header.uint(5)?;
    if let Err(error) = await_application(
        config.handler.authorize(context.clone(), &request.expected),
        &binding,
        &context.cancellation,
        &context.cancellation,
        wire_cap,
    )
    .await
    {
        let _ = publish_confirmation(
            &messages,
            &header,
            &ApplicationResumeResult::refused(false),
            wire_cap,
        )
        .await;
        let _ = messages.settle_resume().await;
        return Err(error);
    }
    binding.check()?;
    let offer = match config.offer_window_ms {
        Some(window) => {
            let now = binding.account.security_time()?;
            AdmissionOffer::current(&config.contract, now.lower_ms, now.upper_ms, window)?
        }
        None => config
            .offer
            .clone()
            .ok_or_else(|| failure(ServiceFailure::AdmissionWindowClosed))?,
    };
    let exchange = Arc::new(config.execution.admit(
        &config.contract,
        &offer,
        &binding.caller,
        &header,
        &payload,
        &binding.account,
        || binding.check(),
    )?);
    let _exchange_exit = ExecutionCallbackExit::new(exchange.clone());
    if !exchange.created() {
        let waited = tokio::time::timeout(
            Duration::from_millis(
                wire_cap.saturating_sub(binding.account.security_time()?.upper_ms),
            ),
            exchange.wait_terminal(&context.cancellation),
        )
        .await
        .map_err(|_| failure(ServiceFailure::DeadlineExceeded))?;
        waited?;
        let mut retained = vec![0; RESUME_RESULT_MAX];
        let (count, code) = exchange.copy_result(&mut retained)?;
        if code.is_some() {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let result = ApplicationResumeResult::capture(&retained[..count])?;
        publish_confirmation(&messages, &header, &result, wire_cap).await?;
        messages.wait_resume_boundary().await?;
        messages.settle_resume().await?;
        return Ok(());
    }
    exchange.enter(|| binding.check())?;
    let exchange_cap = exchange.execution_cap(wire_cap, config.contract.uint(18)?)?;
    let target = config.execution.resume_execution_target(
        &binding.caller,
        &request,
        &config.original_contract,
    )?;
    let target_stream = messages.resume_stream()?;
    let consumed = config.execution.consume_checkpoint(
        &session,
        &target,
        &binding.caller,
        &config.original_contract,
        &request.token,
        &request.expected,
        request.generation,
        &exchange,
        &config.contract,
        &target_stream,
    );
    let (original, confirmation) = match consumed {
        Ok(consumed) => consumed,
        Err(error) => {
            let unknown = matches!(
                error.0,
                ServiceFailure::ServiceUnavailable
                    | ServiceFailure::HistoryUnknown
                    | ServiceFailure::Closed
            );
            let result = ApplicationResumeResult::refused(unknown);
            let encoded = result.encoded()?;
            if let Err(persist) = exchange.finish(&encoded, None, exchange_cap, || binding.check())
            {
                exchange.fail(persist.0);
            }
            let _ = publish_confirmation(&messages, &header, &result, exchange_cap).await;
            let _ = messages.settle_resume().await;
            return Err(error);
        }
    };
    // Attach the guard before any fallible publication. If confirmation is
    // lost, the consumed token and original Unknown progress remain durable.
    let _original_exit = ExecutionCallbackExit::new(original.clone());
    if let Err(error) = publish_confirmation(&messages, &header, &confirmation, exchange_cap).await
    {
        original.fail(error.0);
        return Err(error);
    }
    messages.wait_resume_boundary().await?;
    // The outer durable result is complete. The original execution and its
    // actual callback keep their own active claim and resources from here.
    drop(_exchange_exit);
    let duration = config.original_contract.uint(18)?.min(
        if config.original_contract.shape() == ServiceShape::ServerStreaming {
            config.original_contract.uint(26)?
        } else {
            u64::MAX
        },
    );
    let original_cap = original.execution_cap(u64::MAX, duration)?;
    let parent = context.cancellation.clone();
    if parent.is_cancelled() {
        original.fail(ServiceFailure::Canceled);
        return Err(failure(ServiceFailure::Canceled));
    }
    let context = UnaryRequestContext {
        cancellation: original.cancellation()?,
        execution: crate::ExecutionInvocation::for_request(
            original.clone(),
            peer.session.clone(),
            &config.original_contract,
        )?,
        ..context
    };
    match &config.handler {
        ResumeServiceHandler::Unary(handler) => {
            let raw_target = messages.resume_raw_stream()?;
            messages.settle_resume().await?;
            // The outer response deadline now owns no running business work.
            // The original callback continues under its original cap and owner.
            handoff
                .send(())
                .map_err(|_| failure(ServiceFailure::Canceled))?;
            original.enter(|| {
                binding.check()?;
                if parent.is_cancelled() {
                    return Err(failure(ServiceFailure::Canceled));
                }
                context
                    .invocation
                    .check_cancellation()
                    .map_err(ServiceError::from)
            })?;
            context
                .invocation
                .check_cancellation()
                .map_err(|_| failure(ServiceFailure::Closed))?;
            let response = await_application(
                handler.resume(context.clone(), request.expected, raw_target),
                &binding,
                &context.cancellation,
                &parent,
                original_cap,
            )
            .await;
            match response {
                Ok(response) => {
                    if response.payload.len() as u64
                        > u64::from(original.original_response_limit()?)
                        || response.payload.len() as u64
                            > config
                                .original_contract
                                .response_payload_limit(response.application_error_code)?
                    {
                        original.fail(ServiceFailure::ResourceExhausted);
                        return Err(failure(ServiceFailure::ResourceExhausted));
                    }
                    original.finish(
                        &response.payload,
                        response.application_error_code,
                        original_cap,
                        || binding.check(),
                    )
                }
                Err(error) => {
                    original.fail(error.0);
                    Err(error)
                }
            }
        }
        ResumeServiceHandler::Streaming(handler) => {
            let original_header = original.original_stream_request()?;
            messages
                .continue_resume_output(original_header.clone())
                .await?;
            handoff
                .send(())
                .map_err(|_| failure(ServiceFailure::Canceled))?;
            original.enter(|| {
                binding.check()?;
                if parent.is_cancelled() {
                    return Err(failure(ServiceFailure::Canceled));
                }
                context
                    .invocation
                    .check_cancellation()
                    .map_err(ServiceError::from)
            })?;
            context
                .invocation
                .check_cancellation()
                .map_err(|_| failure(ServiceFailure::Closed))?;
            let outcome = produce_continuation(
                handler.as_ref(),
                &config.original_contract,
                &binding,
                &messages,
                &original_header,
                &original,
                context,
                &parent,
                request.expected,
                original_cap,
            )
            .await;
            if let Err(error) = outcome {
                original.fail(error.0);
            }
            messages.close();
            outcome
        }
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Resume execution binds the original attempt, request, checkpoint and continuation publication lifetime."
)]
async fn produce_continuation(
    handler: &dyn StreamingResumeServiceHandler,
    contract: &ServiceContract,
    binding: &SessionBinding,
    messages: &StreamMessages,
    header: &ApplicationHeader,
    attempt: &Arc<ExecutionAttempt>,
    context: UnaryRequestContext,
    parent: &CancellationToken,
    checkpoint: ApplicationCheckpoint,
    cap: u64,
) -> Result<()> {
    let mut source = await_application(
        handler.resume(context.clone(), checkpoint),
        binding,
        &context.cancellation,
        parent,
        cap,
    )
    .await?;
    loop {
        binding.check()?;
        let item = await_application(
            source.next(context.clone()),
            binding,
            &context.cancellation,
            parent,
            cap,
        )
        .await?;
        let Some(item) = item else {
            attempt.finish(&[], None, cap, || binding.check())?;
            messages.finish().await?;
            return Ok(());
        };
        if item.payload.len() as u64 > header.uint(8)?
            || item.payload.len() as u64
                > contract.response_payload_limit(item.application_error_code)?
        {
            return Err(failure(ServiceFailure::ResourceExhausted));
        }
        if item.application_error_code.is_none() {
            attempt.reserve_stream_item(item.payload.len() as u64, cap, || binding.check())?;
        } else {
            attempt.finish(&[], item.application_error_code, cap, || binding.check())?;
        }
        let response = header.response(
            if item.application_error_code.is_some() {
                "execution_stream_application_error"
            } else {
                "execution_stream_item"
            },
            item.payload.len() as u32,
            item.application_error_code,
        )?;
        let published = messages.write(response, &item.payload, cap).await?;
        if published.publication != ServicePublication::Committed {
            return Err(failure(
                published
                    .failure
                    .unwrap_or(ServiceFailure::ServiceUnavailable),
            ));
        }
        if item.application_error_code.is_some() {
            messages.finish().await?;
            return Ok(());
        }
    }
}
