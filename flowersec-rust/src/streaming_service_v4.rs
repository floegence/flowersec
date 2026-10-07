//! Frozen business Stream registrations. Their ordinary raw-kind collision gate,
//! authenticated Session membership and fixed query catalog share one owner.
use crate::{
    ApplicationBinding, ApplicationInvocationContext, RawStreamHandler, RawStreamRegistration,
    ServeError, ServeFailure, StreamAuthorization, TransportEnvironment,
    crypto_v4::{Metadata, OpenRequest, Stream},
    environment_v4::{EnvironmentCharge, ResourceAccount, ResourceCharge, ResourceLimits},
    execution_history::{ExecutionAttempt, ExecutionIdentity, ExecutionService},
    rpc_stream_messages_v4::StreamMessages,
    rpc_wire_v4::ApplicationHeader,
    service_client_v4::ServiceStreamBinding,
    service_contract::{
        AdmissionOffer, ServiceContract, ServiceError, ServiceFailure, ServiceSemantics,
        ServiceShape,
    },
    service_peer_v4::{PeerInner, ServicePeer, UnaryRequestContext},
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{
    fmt,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn rejected() -> ServeError {
    ServeError::new(ServeFailure::Rejected)
}
const SESSION_BINDINGS: usize = 128;
#[derive(Debug)]
pub struct ServiceStreamItem {
    pub payload: Vec<u8>,
    pub application_error_code: Option<u32>,
}
#[async_trait]
pub trait StreamingItemSource: Send + 'static {
    /// Return exactly the next bounded item. The SDK never calls this method
    /// again until the previous item's complete publication has been accepted.
    async fn next(&mut self, context: UnaryRequestContext) -> Result<Option<ServiceStreamItem>>;
}
#[async_trait]
pub trait StreamingServiceHandler: std::any::Any + fmt::Debug + Send + Sync + 'static {
    async fn authorize(&self, context: UnaryRequestContext) -> Result<()>;
    async fn start(
        &self,
        context: UnaryRequestContext,
        request: &[u8],
    ) -> Result<Box<dyn StreamingItemSource>>;
    fn application_bytes(&self) -> u64 {
        65536
    }
}
#[derive(Clone, Debug)]
pub struct StreamingServiceConfig {
    pub binding: ServiceStreamBinding,
    pub definition: crate::ServiceDefinition,
    pub method: crate::MethodDefinition,
    pub contract: ServiceContract,
    pub handler: Arc<dyn StreamingServiceHandler>,
    pub execution: Option<ExecutionService>,
    pub offer: Option<AdmissionOffer>,
    pub offer_window_ms: Option<u64>,
}
struct Declaration {
    config: StreamingServiceConfig,
    bindings: Mutex<Vec<SessionBinding>>,
    _charge: EnvironmentCharge,
}
#[derive(Clone)]
struct SessionBinding {
    account: ResourceAccount,
    peer: Weak<PeerInner>,
    caller: Option<ExecutionIdentity>,
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
pub struct RegisteredStreamingService(Arc<Declaration>);
impl fmt::Debug for RegisteredStreamingService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisteredStreamingService { <opaque> }")
    }
}
#[derive(Clone, Debug)]
pub struct StreamingServiceRegistration {
    pub service: RegisteredStreamingService,
    pub caller: Option<ExecutionIdentity>,
    pub query_allowed: bool,
}
pub(crate) struct StreamingMembership {
    declaration: Weak<Declaration>,
    account: ResourceAccount,
    cancellation: CancellationToken,
}
impl StreamingMembership {
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
            .expect("streaming Session registrations");
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
impl Drop for StreamingMembership {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(declaration) = self.declaration.upgrade() {
            let removed = {
                let mut bindings = declaration
                    .bindings
                    .lock()
                    .expect("streaming Session registrations");
                bindings
                    .iter()
                    .position(|binding| binding.account.same_owner(&self.account))
                    .map(|index| bindings.remove(index))
            };
            drop(removed);
        }
    }
}
impl RegisteredStreamingService {
    pub fn new(environment: &TransportEnvironment, config: StreamingServiceConfig) -> Result<Self> {
        config.contract.check_environment(environment.root())?;
        config
            .contract
            .check_method(&config.definition, &config.method)?;
        if config.contract.shape() != ServiceShape::ServerStreaming
            || config.binding.stream_kind.is_empty()
            || config.binding.stream_kind.len() > 128
            || config.binding.stream_kind.starts_with("flowersec.")
            || config.binding.stream_kind.starts_with("flowersec/")
            || config.binding.stream_metadata.is_typed()
            || config.handler.application_bytes() == 0
            || config.handler.application_bytes() > 1 << 30
            || (config.contract.semantics() == ServiceSemantics::Execution)
                != config.execution.is_some()
            || config
                .execution
                .as_ref()
                .is_some_and(|service| !Arc::ptr_eq(&service.0.root, environment.root()))
            || config.contract.field(20).is_some()
                && config
                    .execution
                    .as_ref()
                    .is_none_or(|service| !service.recovery_configured())
            || config.offer_window_ms.is_some_and(|window| {
                window == 0
                    || config
                        .contract
                        .uint(16)
                        .map_or(true, |maximum| window > maximum)
            })
            || config.contract.semantics() == ServiceSemantics::Execution
                && config.offer.is_none()
                && config.offer_window_ms.is_none()
            || config.contract.semantics() != ServiceSemantics::Execution
                && (config.offer.is_some() || config.offer_window_ms.is_some())
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
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
            sdk_bytes: config.handler.application_bytes() + 8192 + SESSION_BINDINGS as u64 * 1024,
            items: SESSION_BINDINGS as u64 + 1,
            ..ResourceLimits::default()
        })?;
        Ok(Self(Arc::new(Declaration {
            config,
            bindings: Mutex::new(Vec::with_capacity(SESSION_BINDINGS)),
            _charge: charge,
        })))
    }
    /// Install this entry in the ordinary frozen HandlerPlan. Raw and service
    /// kinds cannot bypass the existing one-registration-per-kind gate.
    pub fn raw_registration(&self) -> RawStreamRegistration {
        RawStreamRegistration {
            kind: self.0.config.binding.stream_kind.clone(),
            metadata: None,
            handler: Arc::new(Adapter(self.clone())),
        }
    }
    pub(crate) fn execution_service(&self) -> Option<&ExecutionService> {
        self.0.config.execution.as_ref()
    }
    pub(crate) fn contract(&self) -> &ServiceContract {
        &self.0.config.contract
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
    pub(crate) fn bind(
        &self,
        peer: &ServicePeer,
        caller: Option<ExecutionIdentity>,
    ) -> Result<StreamingMembership> {
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
    pub(crate) fn prepare_binding(
        &self,
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        caller: Option<ExecutionIdentity>,
    ) -> Result<StreamingMembership> {
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
        caller: Option<ExecutionIdentity>,
        charge: ResourceCharge,
    ) -> Result<StreamingMembership> {
        self.contract()
            .check_environment(account.environment_root())?;
        let execution = self.contract().semantics() == ServiceSemantics::Execution;
        if profile == 0
            || execution && profile != 2
            || execution != caller.is_some()
            || caller.as_ref().is_some_and(|caller| {
                caller.identity_digest != identity
                    || caller.authority == [0; 32]
                    || caller.subject.is_empty()
                    || caller.subject.len() > 128
            })
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
                .expect("streaming Session registrations");
            if bindings.len() >= SESSION_BINDINGS
                || bindings
                    .iter()
                    .any(|old| old.account.same_owner(&binding.account))
            {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
            bindings.push(binding);
        }
        Ok(StreamingMembership {
            declaration: Arc::downgrade(&self.0),
            account: account.clone(),
            cancellation,
        })
    }
    fn find(&self, account: &ResourceAccount) -> Result<SessionBinding> {
        let binding = self
            .0
            .bindings
            .lock()
            .expect("streaming Session registrations")
            .iter()
            .find(|binding| binding.account.same_owner(account))
            .cloned()
            .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
        binding.check()?;
        Ok(binding)
    }
}
#[derive(Debug)]
struct Adapter(RegisteredStreamingService);
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
    async fn handle_open_with_context(
        &self,
        request: OpenRequest,
        _: ApplicationBinding,
        cancellation: CancellationToken,
        context: ApplicationInvocationContext,
    ) -> std::result::Result<(), ServeError> {
        self.handle_original_open(request, cancellation, Some(context))
            .await
    }
}
pub(crate) fn is_sdk_streaming_handler(handler: &dyn RawStreamHandler) -> bool {
    let original: &dyn std::any::Any = handler;
    original.is::<Adapter>()
}
pub(crate) async fn handle_sdk_streaming_open(
    handler: Arc<dyn RawStreamHandler>,
    request: OpenRequest,
    cancellation: CancellationToken,
) -> std::result::Result<(), ServeError> {
    let original: &dyn std::any::Any = handler.as_ref();
    let adapter = original.downcast_ref::<Adapter>().ok_or_else(rejected)?;
    adapter
        .handle_original_open(request, cancellation, None)
        .await
}
impl Adapter {
    async fn handle_original_open(
        &self,
        request: OpenRequest,
        cancellation: CancellationToken,
        context: Option<ApplicationInvocationContext>,
    ) -> std::result::Result<(), ServeError> {
        let diagnostics = request
            .account()
            .diagnostic_activity(crate::DiagnosticPhase::Application, 1);
        let result = async {
        if request.kind() != self.0.0.config.binding.stream_kind
            || request.metadata() != &self.0.0.config.binding.stream_metadata
        {
            return Err(rejected());
        }
        let binding = self.0.find(&request.account()).map_err(|_| rejected())?;
        let peer = binding.peer.upgrade().ok_or_else(rejected)?;
        let config = self.0.0.config.clone();
        let input_limit = config.contract.uint(23).map_err(|_| rejected())? as usize;
        let output_limit = config.contract.uint(10).map_err(|_| rejected())? as usize;
        let charge = Arc::new(
            binding
                .account
                .reserve(ResourceLimits {
                    sdk_bytes: config.handler.application_bytes()
                        + input_limit as u64
                        + 2 * output_limit.max(256) as u64
                        + 8192,
                    items: 5,
                    tasks: 2,
                    timers: 2,
                    ..ResourceLimits::default()
                })
                .map_err(|_| rejected())?,
        );
        let tail = peer.application_tail().map_err(|_| rejected())?;
        let peer_worker = peer.retain_worker();
        let messages =
            StreamMessages::accept(request, &peer.channel, input_limit.max(output_limit))
                .map_err(|_| rejected())?;
        messages.retain_peer(&peer);
        messages.bind_cancellation(binding.cancellation.clone());
        let group = peer.group.clone();
        drop(peer);
        let input = tokio::select! { input = messages.next(&cancellation) => input.map_err(|_| rejected())?,
        _ = binding.cancellation.cancelled() => return Err(rejected()) };
        let Some(input) = input else {
            return Err(rejected());
        };
        let header = input.header;
        messages
            .bind_response(header.clone())
            .map_err(|_| rejected())?;
        let admitted = validate_input(&config, &binding, &header, &input.payload);
        if let Err(error) = admitted {
            refuse(&messages, &binding.account, &header, error).await;
            return Err(rejected());
        }
        let now = binding.account.security_time().map_err(|_| rejected())?;
        let mut deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(
                header
                    .uint(5)
                    .map_err(|_| rejected())?
                    .saturating_sub(now.upper_ms),
            );
        // One complete unary initial request, followed by actual FIN. No extra
        // input items are admitted for this server-streaming method.
        let eof = tokio::select! { eof = messages.next(&cancellation) => eof,
        _ = binding.cancellation.cancelled() => Err(failure(ServiceFailure::Closed)),
        _ = tokio::time::sleep_until(deadline) => Err(failure(ServiceFailure::DeadlineExceeded)) };
        if !matches!(eof, Ok(None)) {
            refuse(
                &messages,
                &binding.account,
                &header,
                failure(ServiceFailure::Protocol),
            )
            .await;
            return Err(rejected());
        }
        // Empty preaccepted Streams wait only in their original SDK graph.
        // The real application lane is claimed after a complete request and FIN.
        let ordinary = if context.is_none() {
            let admission = match group.admit_ordinary(
                true,
                None,
                header.uint(7).map_err(|_| rejected())? == 1,
            ) {
                Ok(admission) => admission,
                Err(error) => {
                    refuse(&messages, &binding.account, &header, error.into()).await;
                    return Err(rejected());
                }
            };
            let position = tokio::select! {
                result = admission.position() => match result { Ok(position) => position, Err(error) => {
                    refuse(&messages, &binding.account, &header, error.into()).await; return Err(rejected());
                } },
                _ = cancellation.cancelled() => return Err(rejected()),
                _ = binding.cancellation.cancelled() => return Err(rejected()),
                _ = tokio::time::sleep_until(deadline) => { refuse(&messages, &binding.account, &header, failure(ServiceFailure::DeadlineExceeded)).await; return Err(rejected()); },
            };
            let invocation = position.enter().map_err(|_| rejected())?;
            Some((position, invocation))
        } else {
            None
        };
        let context = match context {
            Some(context) => context,
            None => ordinary
                .as_ref()
                .expect("original streaming application position")
                .1
                .context(),
        };
        let (events, mut receiver) = mpsc::channel(1);
        let source_cancel = cancellation.child_token();
        let callback_cancel = source_cancel.clone();
        let current_binding = binding.clone();
        let current_header = header.clone();
        let physical_diagnostics = diagnostics.clone();
        let worker = tokio::spawn(async move {
            let _physical_diagnostics = physical_diagnostics;
            let _tail = tail;
            let _charge = charge;
            let _input_charge = input.charge;
            let _ordinary = ordinary;
            let _peer_worker = peer_worker;
            produce(
                config,
                current_binding,
                current_header,
                input.payload,
                context,
                callback_cancel,
                events,
            )
            .await
        });
        let outcome = loop {
            let event = tokio::select! {
                event = receiver.recv() => event,
                _ = tokio::time::sleep_until(deadline) => break Err(failure(ServiceFailure::DeadlineExceeded)),
                _ = cancellation.cancelled() => break Err(failure(ServiceFailure::Closed)),
                _ = binding.cancellation.cancelled() => break Err(failure(ServiceFailure::Closed)),
                _ = binding.account.security_changed() => { if let Err(error) = binding.check() { break Err(error); } else { continue; } },
                _ = tokio::time::sleep(binding.account.next_security_check()) => { if let Err(error) = binding.check() { break Err(error); } else { continue; } },
            };
            match event {
                Some(Event::Started { cap }) => {
                    let now = match binding.account.security_time() {
                        Ok(now) => now,
                        Err(error) => break Err(error.into()),
                    };
                    deadline = deadline.min(
                        tokio::time::Instant::now()
                            + std::time::Duration::from_millis(cap.saturating_sub(now.upper_ms)),
                    );
                }
                Some(Event::Item {
                    item,
                    cap,
                    completion,
                }) => {
                    let kind = if header.has(1) {
                        if item.application_error_code.is_some() {
                            "execution_stream_application_error"
                        } else {
                            "execution_stream_item"
                        }
                    } else {
                        if item.application_error_code.is_some() {
                            "transient_stream_application_error"
                        } else {
                            "transient_stream_item"
                        }
                    };
                    let publication = async {
                        let response = header.response(
                            kind,
                            item.payload.len() as u32,
                            item.application_error_code,
                        )?;
                        let published = messages.write(response, &item.payload, cap).await?;
                        if published.publication != crate::ServicePublication::Committed {
                            return Err(failure(ServiceFailure::ServiceUnavailable));
                        }
                        Ok(())
                    }
                    .await;
                    let terminal = item.application_error_code.is_some();
                    let _ = completion.send(publication);
                    if let Err(error) = publication {
                        break Err(error);
                    }
                    if terminal {
                        break Ok(());
                    }
                }
                Some(Event::End) => break Ok(()),
                Some(Event::Failure(error)) => break Err(error),
                None => break Err(failure(ServiceFailure::ServiceFailed)),
            }
        };
        // Seal production immediately when the wire driver ends. A bounded
        // refusal or physical Finish must not postpone callback cancellation.
        source_cancel.cancel();
        if let Err(error) = outcome {
            diagnostics.service_failure(error);
            refuse(&messages, &binding.account, &header, error).await;
        } else {
            let finished = messages.finish().await;
            diagnostics.service_outcome(&finished);
        }
        messages.close();
        // Retire the Stream graph before waiting for a noncooperative native
        // callback. Its compact source task and real ordinary invocation remain.
        drop(messages);
        drop(binding);
        drop(receiver);
        let _ = worker.await;
        outcome.map_err(|_| rejected())
        }.await;
        diagnostics.serve_outcome(&result);
        result
    }
}
fn validate_input(
    config: &StreamingServiceConfig,
    binding: &SessionBinding,
    header: &ApplicationHeader,
    payload: &[u8],
) -> Result<()> {
    binding.check()?;
    let execution = config.contract.semantics() == ServiceSemantics::Execution;
    if header.kind()
        != if execution {
            "execution_stream_request"
        } else {
            "transient_stream_request"
        }
        || header.type_id()? != config.contract.type_id()
        || header.bytes(6)? != config.contract.digest()
        || payload.len() as u64 > config.contract.uint(23)?
        || header.uint(8)? < config.contract.uint(9)?
        || header.uint(8)? > config.contract.uint(10)?
    {
        return Err(failure(ServiceFailure::ContractMismatch));
    }
    let now = binding.account.security_time()?;
    if now.upper_ms >= header.uint(5)?
        || header.uint(5)?
            > now
                .lower_ms
                .saturating_add(config.contract.uint(if execution { 17 } else { 11 })?)
    {
        return Err(failure(ServiceFailure::DeadlineExceeded));
    }
    if execution
        && crate::rpc_wire_v4::execution_digest(config.contract.encoded(), header, payload)?
            != header.bytes(4)?
    {
        return Err(failure(ServiceFailure::Protocol));
    }
    Ok(())
}
enum Event {
    Started {
        cap: u64,
    },
    Item {
        item: ServiceStreamItem,
        cap: u64,
        completion: oneshot::Sender<Result<()>>,
    },
    End,
    Failure(ServiceError),
}
// This private gate is shared by the exact request decoder, handler and
// returned generator. Applications cannot assert the SDK adapter classification.
struct RunStart {
    binding: SessionBinding,
    invocation: ApplicationInvocationContext,
    cancellation: CancellationToken,
    parent: CancellationToken,
    attempt: Option<Arc<ExecutionAttempt>>,
    requested_cap: u64,
    duration_ms: u64,
    cap: Mutex<Option<u64>>,
    events: mpsc::Sender<Event>,
}
impl RunStart {
    fn current_cap(&self) -> u64 {
        self.cap
            .lock()
            .expect("streaming run origin")
            .unwrap_or(self.requested_cap)
    }
    fn enter(&self) -> Result<()> {
        self.binding.check()?;
        self.invocation.check_cancellation()?;
        if self.parent.is_cancelled() || self.cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::Canceled));
        }
        let mut original = self.cap.lock().expect("streaming run origin");
        if let Some(cap) = *original {
            if self.binding.account.security_time()?.upper_ms >= cap {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            return Ok(());
        }
        if let Some(attempt) = &self.attempt {
            attempt.enter(|| {
                self.binding.check()?;
                if self.parent.is_cancelled() || self.cancellation.is_cancelled() {
                    return Err(failure(ServiceFailure::Canceled));
                }
                Ok(())
            })?;
        }
        let now = self.binding.account.security_time()?;
        let cap = if let Some(attempt) = &self.attempt {
            attempt.execution_cap(self.requested_cap, self.duration_ms)?
        } else {
            self.requested_cap.min(
                now.lower_ms
                    .checked_add(self.duration_ms)
                    .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?,
            )
        };
        if now.upper_ms >= cap {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        // Started is the first source event, so its original one-event queue
        // must be available. Refusal prevents entry rather than waiting here.
        self.events
            .try_send(Event::Started { cap })
            .map_err(|_| failure(ServiceFailure::Closed))?;
        *original = Some(cap);
        Ok(())
    }
}

async fn await_callback<T>(
    callback: impl Future<Output = Result<T>>,
    binding: &SessionBinding,
    cancellation: &CancellationToken,
    parent: &CancellationToken,
    cap: u64,
    run: Option<&RunStart>,
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
        let checked = binding.check().and_then(|_| {
            let current_cap = run.map(RunStart::current_cap).unwrap_or(cap);
            if binding.account.security_time()?.upper_ms >= current_cap {
                Err(failure(ServiceFailure::DeadlineExceeded))
            } else {
                Ok(())
            }
        });
        if let Err(error) = checked {
            cancellation.cancel();
            let _ = callback.await;
            return Err(error);
        }
    }
}
async fn produce(
    config: StreamingServiceConfig,
    binding: SessionBinding,
    header: ApplicationHeader,
    payload: Zeroizing<Vec<u8>>,
    invocation: ApplicationInvocationContext,
    cancellation: CancellationToken,
    events: mpsc::Sender<Event>,
) {
    let mut attempt: Option<Arc<ExecutionAttempt>> = None;
    let mut callback_exit: Option<crate::execution_history::ExecutionCallbackExit> = None;
    let outcome = async {
        let context = UnaryRequestContext { invocation, cancellation: cancellation.clone(), execution_identity: binding.caller.clone(), execution: None, publication: crate::ResponsePublication::not_applicable(), maintenance: binding.peer.upgrade().and_then(|peer| peer.session.session().ok()).and_then(|session| session.maintenance_owner().ok()) };
        await_callback(config.handler.authorize(context.clone()), &binding, &context.cancellation, &cancellation, header.uint(5)?, None).await?;
        validate_input(&config, &binding, &header, &payload)?;
        if let Some(execution) = &config.execution {
            let now = binding.account.security_time()?;
            let offer = match config.offer_window_ms { Some(window) => AdmissionOffer::current(&config.contract, now.lower_ms, now.upper_ms, window)?,
                None => config.offer.clone().ok_or_else(|| failure(ServiceFailure::AdmissionWindowClosed))? };
            let admitted = execution.admit(&config.contract, &offer, binding.caller.as_ref().ok_or_else(|| failure(ServiceFailure::PermissionDenied))?,
                &header, &payload, &binding.account, || binding.check())?;
            if !admitted.created() { return Err(failure(ServiceFailure::ServiceUnavailable)); }
            attempt = Some(Arc::new(admitted));
        }
        callback_exit = attempt.as_ref().map(|attempt|
            crate::execution_history::ExecutionCallbackExit::new(attempt.clone()));
        let duration = config.contract.uint(26)?.min(config.contract.uint(if config.execution.is_some() { 18 } else { 12 })?);
        let context = if let Some(attempt) = &attempt {
            let peer = binding.peer.upgrade().ok_or_else(|| failure(ServiceFailure::Closed))?;
            UnaryRequestContext { cancellation: attempt.cancellation()?,
                execution: crate::ExecutionInvocation::for_request(attempt.clone(), peer.session.clone(), &config.contract)?, ..context }
        } else { context };
        let run = Arc::new(RunStart { binding: binding.clone(), invocation: context.invocation.clone(),
            cancellation: context.cancellation.clone(), parent: cancellation.clone(), attempt: attempt.clone(),
            requested_cap: header.uint(5)?, duration_ms: duration, cap: Mutex::new(None), events: events.clone() });
        let start = async {
            let handler = config.handler.as_ref() as &dyn std::any::Any;
            if let Some(typed) = handler.downcast_ref::<ErasedTypedHandler>() {
                typed.inner.start_original(context.clone(), &payload, Some(run.clone())).await
            } else {
                run.enter()?;
                config.handler.start(context.clone(), &payload).await
            }
        };
        let mut source = await_callback(start, &binding, &context.cancellation, &cancellation, header.uint(5)?, Some(&run)).await?;
        let cap = run.current_cap();
        let mut count = 0u64; let mut bytes = 0u64;
        loop {
            binding.check()?;
            if cancellation.is_cancelled() { context.cancellation.cancel(); return Err(failure(ServiceFailure::Canceled)); }
            let next = await_callback(source.next(context.clone()), &binding, &context.cancellation, &cancellation, cap, Some(&run)).await?;
            let Some(item) = next else { if let Some(attempt) = &attempt { attempt.finish(&[], None, cap, || binding.check())?; }
                events.send(Event::End).await.map_err(|_| failure(ServiceFailure::Closed))?; return Ok(()); };
            if item.payload.len() as u64 > header.uint(8)? || item.payload.len() as u64 > config.contract.response_payload_limit(item.application_error_code)? {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            if item.application_error_code.is_none() {
                if let Some(attempt) = &attempt {
                    attempt.reserve_stream_item(item.payload.len() as u64, cap, || binding.check())?;
                } else {
                    count = count.checked_add(1).ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
                    bytes = bytes.checked_add(item.payload.len() as u64).ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
                    if count > config.contract.uint(24)? || bytes > config.contract.uint(25)? { return Err(failure(ServiceFailure::ResourceExhausted)); }
                }
            }
            let code = item.application_error_code; let (sender, receiver) = oneshot::channel();
            events.send(Event::Item { item, cap, completion: sender }).await.map_err(|_| failure(ServiceFailure::Closed))?;
            // No source prefetch: the original item's complete publication must
            // settle before the source can produce the next application value.
            let accepted = tokio::select! { accepted = receiver => accepted.map_err(|_| failure(ServiceFailure::Closed))?,
                _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) };
            accepted?;
            if let Some(code) = code { if let Some(attempt) = &attempt { attempt.finish(&[], Some(code), cap, || binding.check())?; } return Ok(()); }
        }
    }.await;
    if let Err(error) = &outcome
        && let Some(attempt) = &attempt
    {
        attempt.fail(error.0);
    }
    // Record the real failure before the unwind fallback, and revoke callback
    // authority before waiting for terminal-output backpressure.
    drop(callback_exit);
    if let Err(error) = outcome {
        let _ = events.send(Event::Failure(error)).await;
    }
}
async fn refuse(
    messages: &StreamMessages,
    account: &ResourceAccount,
    request: &ApplicationHeader,
    error: ServiceError,
) {
    let code = match error.0 {
        ServiceFailure::ContractMismatch => 3,
        ServiceFailure::ResponseLimitUnsupported => 4,
        ServiceFailure::ResourceExhausted | ServiceFailure::DependencyUnavailable => 5,
        ServiceFailure::PermissionDenied => 7,
        ServiceFailure::DeadlineExceeded => 8,
        ServiceFailure::ServiceFailed => 9,
        ServiceFailure::OperationConflict => 11,
        ServiceFailure::ResultExpired => 12,
        _ => 10,
    };
    let payload = [0xa1, 0, code];
    let kind = if request.has(1) {
        "execution_stream_sdk_error"
    } else {
        "transient_stream_sdk_error"
    };
    if let (Ok(header), Ok(now)) = (
        request.response(kind, payload.len() as u32, None),
        account.security_time(),
    ) && let Some(cap) = now.lower_ms.checked_add(5000)
    {
        let _ = messages.write(header, &payload, cap).await;
    }
    let _ = messages.close_write().await;
}

/// Typed business callbacks share the original resident invocation and exact
/// local method schemas. They do not receive a Session or transport scope.
#[async_trait]
pub trait TypedStreamingService<I, O>: fmt::Debug + Send + Sync + 'static {
    async fn authorize(&self, context: UnaryRequestContext) -> Result<()>;
    async fn start(
        &self,
        context: UnaryRequestContext,
        request: I,
    ) -> Result<Box<dyn TypedStreamingItemSource<O>>>;
    fn application_bytes(&self) -> u64 {
        65536
    }
}
#[async_trait]
pub trait TypedStreamingItemSource<O>: Send + 'static {
    async fn next(&mut self, context: UnaryRequestContext) -> Result<Option<O>>;
}
pub struct TypedStreamingServiceAdapter<I, O> {
    method: crate::MethodDefinition,
    request: Arc<dyn crate::MessageCodec<I>>,
    item: Arc<dyn crate::MessageCodec<O>>,
    handler: Arc<dyn TypedStreamingService<I, O>>,
    allowance: u64,
}
impl<I, O> fmt::Debug for TypedStreamingServiceAdapter<I, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TypedStreamingServiceAdapter { <opaque> }")
    }
}
#[async_trait]
trait ErasedTypedStart: Send + Sync {
    async fn authorize(&self, context: UnaryRequestContext) -> Result<()>;
    async fn start_original(
        &self,
        context: UnaryRequestContext,
        request: &[u8],
        run: Option<Arc<RunStart>>,
    ) -> Result<Box<dyn StreamingItemSource>>;
    fn application_bytes(&self) -> u64;
}
struct ErasedTypedHandler {
    inner: Arc<dyn ErasedTypedStart>,
}
impl fmt::Debug for ErasedTypedHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TypedStreamingServiceHandler { <opaque> }")
    }
}
#[async_trait]
impl StreamingServiceHandler for ErasedTypedHandler {
    async fn authorize(&self, context: UnaryRequestContext) -> Result<()> {
        self.inner.authorize(context).await
    }
    async fn start(
        &self,
        context: UnaryRequestContext,
        request: &[u8],
    ) -> Result<Box<dyn StreamingItemSource>> {
        self.inner.start_original(context, request, None).await
    }
    fn application_bytes(&self) -> u64 {
        self.inner.application_bytes()
    }
}

impl<I: Send + 'static, O: Send + 'static> TypedStreamingServiceAdapter<I, O> {
    pub fn new(
        method: crate::MethodDefinition,
        request: Arc<dyn crate::MessageCodec<I>>,
        item: Arc<dyn crate::MessageCodec<O>>,
        handler: Arc<dyn TypedStreamingService<I, O>>,
    ) -> Result<Self> {
        if method.shape() != ServiceShape::ServerStreaming
            || request.definition() != &method.options().request
            || method.options().response.as_ref() != Some(item.definition())
            || request.application_bytes() == 0
            || item.application_bytes() == 0
            || handler.application_bytes() == 0
            || [
                request.application_bytes(),
                item.application_bytes(),
                handler.application_bytes(),
            ]
            .iter()
            .any(|bytes| *bytes > 1 << 30)
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let allowance = request
            .application_bytes()
            .checked_add(item.application_bytes())
            .and_then(|bytes| bytes.checked_add(handler.application_bytes()))
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        Ok(Self {
            method,
            request,
            item,
            handler,
            allowance,
        })
    }
    pub fn into_handler(self) -> Arc<dyn StreamingServiceHandler> {
        Arc::new(ErasedTypedHandler {
            inner: Arc::new(self),
        })
    }
}
#[async_trait]
impl<I: Send + 'static, O: Send + 'static> ErasedTypedStart for TypedStreamingServiceAdapter<I, O> {
    async fn authorize(&self, context: UnaryRequestContext) -> Result<()> {
        self.handler.authorize(context).await
    }
    async fn start_original(
        &self,
        context: UnaryRequestContext,
        request: &[u8],
        run: Option<Arc<RunStart>>,
    ) -> Result<Box<dyn StreamingItemSource>> {
        if request.len() > self.method.options().request_max_bytes as usize {
            return Err(failure(ServiceFailure::Protocol));
        }
        let value = if crate::message_codec_v4::controlled(self.request.as_ref()) {
            self.request
                .decode_with_context(request, &context.invocation)?
        } else {
            let codec = self.request.clone();
            let bytes = Zeroizing::new(request.to_vec());
            let invocation = context.invocation.clone();
            let entry = run.clone();
            tokio::task::spawn_blocking(move || {
                if let Some(entry) = &entry {
                    entry.enter()?;
                }
                invocation.check_cancellation()?;
                std::panic::catch_unwind(AssertUnwindSafe(|| {
                    codec.decode_with_context(&bytes, &invocation)
                }))
                .unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed)))
                .map_err(|_| failure(ServiceFailure::DecodeFailed))
            })
            .await
            .map_err(|_| failure(ServiceFailure::DecodeFailed))??
        };
        // Controlled SDK parsing is not an application entry. A custom decoder
        // above enters inside its actual blocking task, after its queue wait.
        if let Some(entry) = &run {
            entry.enter()?;
        }
        context.invocation.check_cancellation()?;
        let source = self.handler.start(context, value).await?;
        Ok(Box::new(TypedSource {
            source,
            codec: self.item.clone(),
            limit: self.method.options().max_response_bytes as usize,
        }))
    }
    fn application_bytes(&self) -> u64 {
        self.allowance
    }
}
struct TypedSource<O> {
    source: Box<dyn TypedStreamingItemSource<O>>,
    codec: Arc<dyn crate::MessageCodec<O>>,
    limit: usize,
}
#[async_trait]
impl<O: Send + 'static> StreamingItemSource for TypedSource<O> {
    async fn next(&mut self, context: UnaryRequestContext) -> Result<Option<ServiceStreamItem>> {
        let Some(value) = self.source.next(context.clone()).await? else {
            return Ok(None);
        };
        let mut payload = Zeroizing::new(vec![0; self.limit]);
        let length = if crate::message_codec_v4::controlled(self.codec.as_ref()) {
            self.codec
                .encode_with_context(&value, &mut payload, &context.invocation)?
        } else {
            let codec = self.codec.clone();
            let invocation = context.invocation.clone();
            let limit = self.limit;
            let encoded = tokio::task::spawn_blocking(move || {
                let mut payload = Zeroizing::new(vec![0; limit]);
                let length = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    codec.encode_with_context(&value, &mut payload, &invocation)
                }))
                .unwrap_or_else(|_| Err(failure(ServiceFailure::EncodeFailed)))?;
                if length > limit {
                    return Err(failure(ServiceFailure::EncodeFailed));
                }
                payload.truncate(length);
                Ok::<_, ServiceError>(payload)
            })
            .await
            .map_err(|_| failure(ServiceFailure::EncodeFailed))??;
            payload = encoded;
            payload.len()
        };
        if length > self.limit {
            return Err(failure(ServiceFailure::EncodeFailed));
        }
        payload.truncate(length);
        Ok(Some(ServiceStreamItem {
            payload: payload.to_vec(),
            application_error_code: None,
        }))
    }
}
