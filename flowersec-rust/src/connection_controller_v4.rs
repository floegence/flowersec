//! Current material-source controller. Every connection attempt performs one
//! ordinary SDK Acquire; publication follows READY and one candidate initializer.
//! Captured Session handles retain their original routing through replacement.
use crate::{
    ConnectionError, ConnectionMaterialSource, ConnectionRequest, FixedContractQuery,
    MaterialSourceError, ServiceBindingOptions, ServiceClient, ServiceDefinition, Session,
    TransportConnectError,
    api_v4::{CleanupStatus, TransportEnvironment},
    environment_v4::{EnvironmentCharge, ResourceCharge, ResourceLimits},
};
use async_trait::async_trait;
use std::{
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterialSourceOwnership {
    Owned,
    Borrowed,
}
#[derive(Clone, Debug)]
pub struct ControllerMaterialSource {
    pub source: ConnectionMaterialSource,
    pub ownership: MaterialSourceOwnership,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MaterialControllerError {
    #[error("controller_configuration_invalid")]
    Configuration,
    #[error("configuration_capacity")]
    Capacity,
    #[error("controller_closed")]
    Closed,
    #[error("controller_wait_canceled")]
    Canceled,
    #[error("controller_connection_failed")]
    ConnectionFailed,
    #[error("controller_generation_changed")]
    GenerationChanged,
    #[error("controller_not_ready")]
    NotReady,
    #[error("controller_service_unavailable")]
    ServiceUnavailable,
    #[error("controller_service_binding_failed")]
    ServiceBindingFailed,
    #[error("controller_retirement_unavailable")]
    RetirementUnavailable,
    #[error("controller_initialization_failed")]
    InitializationFailed,
    #[error("controller_initialization_unknown")]
    InitializationUnknown,
    #[error("controller_live_authorization_unknown")]
    AuthorizationUnknown,
    #[error("controller_credential_spent")]
    CredentialSpent,
    #[error("cleanup_incomplete")]
    CleanupIncomplete,
}
#[async_trait]
pub trait CandidateSessionInitializer: fmt::Debug + Send + Sync + 'static {
    /// The fixed READY candidate is not current yet. Errors stop automatic
    /// acquisition: this callback may have submitted an application operation.
    async fn initialize(
        &self,
        session: Session,
        cancellation: CancellationToken,
    ) -> Result<(), MaterialControllerError>;
    async fn initialize_candidate(
        &self,
        session: Session,
        _services: &[ManagedServiceClient],
        cancellation: CancellationToken,
    ) -> Result<(), MaterialControllerError> {
        self.initialize(session, cancellation).await
    }
    fn application_bytes(&self) -> u64 {
        65536
    }
}
#[derive(Clone, Debug)]
pub struct ManagedServiceConfiguration {
    pub definition: ServiceDefinition,
    pub query: FixedContractQuery,
    pub methods: Vec<ServiceBindingOptions>,
    pub bind_timeout: Duration,
    pub initial_methods: Option<Vec<crate::MethodDefinition>>,
    pub offer_renewal: Option<crate::ManagedOfferRenewal>,
}
impl ManagedServiceConfiguration {
    pub fn new(
        definition: ServiceDefinition,
        query: FixedContractQuery,
        methods: Vec<ServiceBindingOptions>,
        bind_timeout: Duration,
    ) -> Self {
        Self {
            definition,
            query,
            methods,
            bind_timeout,
            initial_methods: None,
            offer_renewal: Some(crate::ManagedOfferRenewal::default()),
        }
    }
}
#[derive(Clone, Debug)]
pub struct ManagedServiceClient {
    definition: ServiceDefinition,
    client: ServiceClient,
}
impl ManagedServiceClient {
    pub fn definition(&self) -> &ServiceDefinition {
        &self.definition
    }
    pub fn client(&self) -> &ServiceClient {
        &self.client
    }
}
/// A controller facade captures one already bound client at preparation.
/// The returned operation retains that Session across replacement and never
/// reacquires material, rebinds a contract or replays an application request.
#[derive(Debug)]
pub struct ControllerServiceClient {
    controller: MaterialConnectionController,
    namespace: String,
    secondary: Option<(MaterialConnectionController, Vec<crate::MethodDefinition>)>,
    mapped_authority: Option<(u8, u8, [[u8; 32]; 2])>,
    _charge: EnvironmentCharge,
}
#[derive(Clone, Debug)]
pub struct CapturedControllerService {
    generation: u64,
    client: ServiceClient,
    notifications: Option<crate::NotificationPeer>,
    authenticated_peer: (u8, u8, [[u8; 32]; 2]),
}
impl CapturedControllerService {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn client(&self) -> &ServiceClient {
        &self.client
    }
    pub fn notifications(&self) -> Option<&crate::NotificationPeer> {
        self.notifications.as_ref()
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ControllerServiceError {
    #[error(transparent)]
    Controller(#[from] MaterialControllerError),
    #[error(transparent)]
    Service(#[from] crate::ServiceError),
}
impl ControllerServiceClient {
    pub fn capture(&self) -> Result<CapturedControllerService, MaterialControllerError> {
        let owner = &self.controller.0;
        let state = owner.state.lock().expect("controller service capture");
        if state.closed || owner.cancellation.is_cancelled() || owner.environment.root().is_closed()
        {
            return Err(MaterialControllerError::Closed);
        }
        if state.state == MaterialControllerState::Failed {
            return Err(state
                .failure
                .unwrap_or(MaterialControllerError::ConnectionFailed));
        }
        let current = state
            .current
            .as_ref()
            .filter(|current| current.session.termination_cause().is_none())
            .ok_or(MaterialControllerError::NotReady)?;
        current
            .session
            .controller_dispatch_eligible()
            .map_err(|_| MaterialControllerError::NotReady)?;
        let client = current
            .service(&self.namespace)
            .ok_or(MaterialControllerError::ServiceUnavailable)?;
        let notifications = current
            .session
            .configured_services()
            .and_then(|services| services.notifications());
        let authenticated_peer = current
            .session
            .controller_service_authority()
            .map_err(|_| MaterialControllerError::NotReady)?;
        if self
            .mapped_authority
            .is_some_and(|expected| expected != authenticated_peer)
        {
            return Err(MaterialControllerError::ServiceUnavailable);
        }
        Ok(CapturedControllerService {
            generation: current.generation,
            client,
            notifications,
            authenticated_peer,
        })
    }
    /// Select a configured source without acquisition or contract queries.
    /// Both sources must authenticate the same logical peer and profile.
    pub fn capture_method(
        &self,
        method: &crate::MethodDefinition,
    ) -> Result<CapturedControllerService, MaterialControllerError> {
        if let Some((secondary, methods)) = &self.secondary
            && methods.iter().any(|selected| selected.same(method))
        {
            let state = secondary
                .0
                .state
                .lock()
                .expect("secondary method source capture");
            if state.closed
                || state.state == MaterialControllerState::Failed
                || secondary.0.cancellation.is_cancelled()
            {
                return Err(MaterialControllerError::NotReady);
            }
            let current = state
                .current
                .as_ref()
                .ok_or(MaterialControllerError::NotReady)?;
            current
                .session
                .controller_dispatch_eligible()
                .map_err(|_| MaterialControllerError::NotReady)?;
            let authenticated_peer = current
                .session
                .controller_service_authority()
                .map_err(|_| MaterialControllerError::NotReady)?;
            if Some(authenticated_peer) != self.mapped_authority {
                return Err(MaterialControllerError::Configuration);
            }
            let client = current
                .service(&self.namespace)
                .ok_or(MaterialControllerError::ServiceUnavailable)?;
            let notifications = current
                .session
                .configured_services()
                .and_then(|services| services.notifications());
            return Ok(CapturedControllerService {
                generation: current.generation,
                client,
                notifications,
                authenticated_peer,
            });
        }
        self.capture()
    }
    /// One bounded explicit assignment of methods to a second existing owner.
    pub fn with_method_source(
        mut self,
        secondary: MaterialConnectionController,
        methods: Vec<crate::MethodDefinition>,
    ) -> Result<Self, MaterialControllerError> {
        if self.secondary.is_some()
            || methods.is_empty()
            || methods.len() > 256
            || !Arc::ptr_eq(
                self.controller.0.environment.root(),
                secondary.0.environment.root(),
            )
        {
            return Err(MaterialControllerError::Configuration);
        }
        let primary = self
            .controller
            .0
            .options
            .managed_services
            .iter()
            .find(|service| service.definition.namespace() == self.namespace)
            .ok_or(MaterialControllerError::ServiceUnavailable)?;
        let alternative = secondary
            .0
            .options
            .managed_services
            .iter()
            .find(|service| service.definition.namespace() == self.namespace)
            .ok_or(MaterialControllerError::ServiceUnavailable)?;
        if methods.iter().enumerate().any(|(index, method)| {
            !primary.definition.contains(method)
                || !alternative.definition.contains(method)
                || methods[..index].iter().any(|old| old.same(method))
        }) {
            return Err(MaterialControllerError::Configuration);
        }
        let authority = self.capture()?.authenticated_peer;
        let current = secondary.capture_session()?;
        if current
            .controller_service_authority()
            .map_err(|_| MaterialControllerError::NotReady)?
            != authority
        {
            return Err(MaterialControllerError::Configuration);
        }
        self.mapped_authority = Some(authority);
        self.secondary = Some((secondary, methods));
        Ok(self)
    }
    pub fn prepare_unary<I: Sync + 'static, O: Send + 'static>(
        &self,
        method: &crate::MethodDefinition,
        value: &I,
        request_codec: Arc<dyn crate::MessageCodec<I>>,
        response_codec: Arc<dyn crate::MessageCodec<O>>,
        options: crate::UnaryPrepareOptions,
    ) -> Result<crate::UnaryOperation<O>, ControllerServiceError> {
        let fixed = self.capture_method(method)?;
        let queued = options.admission == crate::ServiceAdmission::Queue;
        let operation =
            fixed
                .client
                .prepare_unary(method, value, request_codec, response_codec, options)?;
        if queued {
            self.attach_unary_selection(&operation, method, &fixed)?;
        }
        Ok(operation)
    }
    pub async fn prepare_unary_async<I: Send + Sync + 'static, O: Send + 'static>(
        &self,
        method: &crate::MethodDefinition,
        value: Arc<I>,
        request_codec: Arc<dyn crate::AsyncMessageCodec<I>>,
        response_codec: Arc<dyn crate::AsyncMessageCodec<O>>,
        options: crate::UnaryPrepareOptions,
        cancellation: CancellationToken,
    ) -> Result<crate::UnaryOperation<O>, ControllerServiceError> {
        let fixed = self.capture_method(method)?;
        let queued = options.admission == crate::ServiceAdmission::Queue;
        let operation = fixed
            .client
            .prepare_unary_async(
                method,
                value,
                request_codec,
                response_codec,
                options,
                cancellation,
            )
            .await?;
        if queued {
            self.attach_unary_selection(&operation, method, &fixed)?;
        }
        Ok(operation)
    }
    fn attach_unary_selection<O: Send + 'static>(
        &self,
        operation: &crate::UnaryOperation<O>,
        method: &crate::MethodDefinition,
        original: &CapturedControllerService,
    ) -> Result<(), ControllerServiceError> {
        let mut selector = self.controller.service(&self.namespace)?;
        selector.secondary = self.secondary.clone();
        selector.mapped_authority = self.mapped_authority;
        let current_generation = if self
            .secondary
            .as_ref()
            .is_some_and(|(_, methods)| methods.iter().any(|mapped| mapped.same(method)))
        {
            self.secondary
                .as_ref()
                .expect("mapped source")
                .0
                .0
                .publication_generation
                .clone()
        } else {
            self.controller.0.publication_generation.clone()
        };
        let method = method.clone();
        let generation = original.generation;
        let identity = original.authenticated_peer;
        operation.attach_controller_selector(
            Arc::new(move |prepared| {
                let current = selector.capture_method(&method).map_err(|error| {
                    crate::ServiceError(match error {
                        MaterialControllerError::Closed => crate::ServiceFailure::Closed,
                        MaterialControllerError::Capacity => {
                            crate::ServiceFailure::ResourceExhausted
                        }
                        _ => crate::ServiceFailure::NotReady,
                    })
                })?;
                if current.authenticated_peer != identity {
                    return Err(crate::ServiceError(crate::ServiceFailure::PermissionDenied));
                }
                if Some(current.generation) == prepared.controller_generation() {
                    return Ok(None);
                }
                // Revoke and spend one original choice before any replacement
                // Session result/K/completion reservation is acquired.
                prepared.claim_controller_reselection()?;
                Ok(Some((
                    current.client.reselect_unary(&method, prepared)?,
                    current.generation,
                )))
            }),
            current_generation,
            generation,
            2,
        )?;
        Ok(())
    }
    pub fn prepare_stream_operation<I: Sync + 'static, O: Send + 'static>(
        &self,
        method: &crate::MethodDefinition,
        value: &I,
        request_codec: Arc<dyn crate::MessageCodec<I>>,
        item_codec: Arc<dyn crate::MessageCodec<O>>,
        options: crate::StreamingPrepareOptions,
    ) -> Result<crate::StreamingOperation<O>, ControllerServiceError> {
        let fixed = self.capture_method(method)?;
        Ok(fixed.client.prepare_stream_operation(
            method,
            value,
            request_codec,
            item_codec,
            options,
        )?)
    }
    pub async fn prepare_notification<T: Send + Sync + 'static>(
        &self,
        method: &crate::MethodDefinition,
        value: Arc<T>,
        codec: Arc<dyn crate::MessageCodec<T>>,
        options: crate::NotificationPrepareOptions,
        cancellation: CancellationToken,
    ) -> Result<crate::NotificationOperation, ControllerServiceError> {
        let fixed = self.capture_method(method)?;
        let notifications = fixed
            .notifications
            .as_ref()
            .ok_or(MaterialControllerError::ServiceUnavailable)?;
        Ok(fixed
            .client
            .prepare_notification(notifications, method, value, codec, options, cancellation)
            .await?)
    }
    pub fn prepare_resume(
        &self,
        method: &crate::MethodDefinition,
        target: &crate::Stream,
        token: &crate::ApplicationCheckpointToken,
        options: crate::UnaryPrepareOptions,
    ) -> Result<crate::UnaryOperation<crate::ApplicationResumeResult>, ControllerServiceError> {
        let fixed = self.capture_method(method)?;
        Ok(fixed
            .client
            .prepare_resume(method, target, token, options)?)
    }
}

/// Retirement is fixed for this replacement before any source acquisition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MaterialSessionRetirement {
    #[default]
    Drain,
    Retain {
        retain_until_ms: u64,
    },
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaterialSessionReplaceOptions {
    pub retirement: MaterialSessionRetirement,
}
#[derive(Clone, Debug)]
pub struct MaterialSessionReplaceResult {
    pub current: MaterialConnectionSnapshot,
    pub previous: Option<Session>,
    pub retirement: MaterialSessionRetirement,
    pub retirement_deadline: Option<Instant>,
}
impl MaterialSessionReplaceResult {
    pub fn previous_cleanup_status(&self) -> CleanupStatus {
        self.previous.as_ref().map_or(
            CleanupStatus {
                complete: true,
                cleanup_incomplete: false,
                pending_callbacks: 0,
            },
            Session::cleanup_status,
        )
    }
}
#[derive(Clone, Copy)]
enum FixedRetirement {
    Drain,
    Retain {
        retain_until_ms: u64,
        deadline: Instant,
    },
}
impl FixedRetirement {
    fn selection(self) -> MaterialSessionRetirement {
        match self {
            Self::Drain => MaterialSessionRetirement::Drain,
            Self::Retain {
                retain_until_ms, ..
            } => MaterialSessionRetirement::Retain { retain_until_ms },
        }
    }
}

#[derive(Clone, Debug)]
pub struct MaterialControllerOptions {
    pub sources: Vec<ControllerMaterialSource>,
    pub managed_services: Vec<ManagedServiceConfiguration>,
    pub request: ConnectionRequest,
    pub parent: CancellationToken,
    pub initialize_session: Option<Arc<dyn CandidateSessionInitializer>>,
    pub max_attempts_per_outage: u32,
    pub retry_after: Duration,
    pub candidate_timeout: Duration,
    pub retain_replaced_for: Duration,
    pub drain_timeout: Duration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterialControllerState {
    Connecting,
    Initializing,
    Ready,
    Retrying,
    Failed,
    Closed,
}
#[derive(Clone, Debug)]
pub struct MaterialConnectionSnapshot {
    pub generation: u64,
    pub source_index: usize,
    pub session: Session,
    managed_services: Arc<[ManagedServiceClient]>,
    _candidate_charge: Arc<ResourceCharge>,
}
impl MaterialConnectionSnapshot {
    pub fn managed_services(&self) -> &[ManagedServiceClient] {
        &self.managed_services
    }
    pub fn service(&self, namespace: &str) -> Option<ServiceClient> {
        self.managed_services
            .iter()
            .find(|managed| managed.definition.namespace() == namespace)
            .map(|managed| managed.client.clone())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterialControllerProgress {
    pub state: MaterialControllerState,
    pub generation: u64,
    pub attempts: u32,
    pub failure: Option<MaterialControllerError>,
    pub retained_session: bool,
    pub connection_facts: Option<crate::ConnectionAttemptFacts>,
}
struct State {
    current: Option<MaterialConnectionSnapshot>,
    candidate: Option<Session>,
    candidate_charge: Option<Arc<ResourceCharge>>,
    retained: Option<Session>,
    generation: u64,
    attempts: u32,
    state: MaterialControllerState,
    failure: Option<MaterialControllerError>,
    closed: bool,
    replacement_active: bool,
    candidate_cleanup: bool,
    source_profile_anchor: usize,
    service_baselines: Vec<crate::service_client_v4::ServiceRebindBaseline>,
    connection_facts: Option<crate::ConnectionAttemptFacts>,
    connection_cleanup: Option<Arc<crate::crypto_v4::connect::ConnectCleanup>>,
}
impl State {
    fn connection_cleanup_status(&mut self) -> CleanupStatus {
        let status = self.connection_cleanup.as_ref().map_or(
            CleanupStatus {
                complete: true,
                cleanup_incomplete: false,
                pending_callbacks: 0,
            },
            |cleanup| cleanup.status(),
        );
        if status.complete {
            self.connection_cleanup = None;
        }
        status
    }
}
struct Replacement {
    expected_generation: u64,
    cancellation: CancellationToken,
    retirement: FixedRetirement,
    completion: oneshot::Sender<Result<MaterialSessionReplaceResult, MaterialControllerError>>,
}
struct PreparedManagedService {
    bind_definition: ServiceDefinition,
    client_definition: ServiceDefinition,
    initializer_definition: ServiceDefinition,
    methods: Vec<ServiceBindingOptions>,
    bind_timeout: Duration,
    selection: crate::ServiceBindingSelection,
    offer_renewal: Option<crate::ManagedOfferRenewal>,
    baseline: Option<crate::service_client_v4::ServiceRebindBaseline>,
}
#[path = "controller_notifications_v4.rs"]
mod notifications;
pub use notifications::{
    ControllerNotificationEvent, ControllerNotificationGap, ControllerNotificationGapReason,
    ControllerNotificationObservation, ControllerNotificationObserver,
    ControllerNotificationOptions, ControllerNotificationSnapshot,
    ControllerNotificationSourcePhase, ControllerNotificationSubscription,
};
#[cfg(test)]
pub(crate) use notifications::{
    NotificationLockOrderProbe, NotificationLockOrderStage, close_test_notification_root,
    exercise_test_notification_publication, exercise_test_old_input_rejection,
    install_notification_lock_order_probe, new_test_notification_root,
    start_test_notification_root, test_notification_root_attached,
};

pub(crate) trait NotificationCandidateHook: Send + Sync {
    fn candidate(&self, session: Session);
    fn publication_stage(&self, _generation: u64) {}
    fn publication_flush(&self, _generation: u64, _session: &Session) {}
}

pub(crate) struct Owner {
    environment: Arc<TransportEnvironment>,
    options: MaterialControllerOptions,
    state: Mutex<State>,
    publication_generation: Arc<AtomicU64>,
    cancellation: CancellationToken,
    changed: Notify,
    replace: mpsc::Sender<Replacement>,
    workers: AtomicUsize,
    handles: AtomicUsize,
    notification_roots: AtomicUsize,
    notification_candidate_hooks: Mutex<Vec<Weak<dyn NotificationCandidateHook>>>,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for Owner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaterialControllerOwner { <opaque> }")
    }
}
pub struct MaterialConnectionController(Arc<Owner>);
impl fmt::Debug for MaterialConnectionController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaterialConnectionController { <opaque> }")
    }
}
impl Clone for MaterialConnectionController {
    fn clone(&self) -> Self {
        self.0.handles.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}
impl Drop for MaterialConnectionController {
    fn drop(&mut self) {
        if self.0.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.close();
        }
    }
}
struct Worker(Arc<Owner>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.workers.fetch_sub(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}
impl Owner {
    fn register_notification_candidate_hook(&self, hook: Weak<dyn NotificationCandidateHook>) {
        let mut hooks = self
            .notification_candidate_hooks
            .lock()
            .expect("controller notification candidate hooks");
        hooks.retain(|hook| hook.strong_count() != 0);
        hooks.push(hook);
    }

    fn notify_notification_candidate(&self, session: Session) {
        let hooks = {
            let mut registered = self
                .notification_candidate_hooks
                .lock()
                .expect("controller notification candidate hooks");
            let mut hooks = Vec::with_capacity(registered.len());
            registered.retain(|hook| {
                if let Some(hook) = hook.upgrade() {
                    hooks.push(hook);
                    true
                } else {
                    false
                }
            });
            hooks
        };
        for hook in hooks {
            hook.candidate(session.clone());
        }
    }

    fn notification_hooks(&self) -> Vec<Arc<dyn NotificationCandidateHook>> {
        let mut registered = self
            .notification_candidate_hooks
            .lock()
            .expect("controller notification hooks");
        let mut hooks = Vec::with_capacity(registered.len());
        registered.retain(|hook| {
            if let Some(hook) = hook.upgrade() {
                hooks.push(hook);
                true
            } else {
                false
            }
        });
        hooks
    }

    fn notify_notification_publication_stage(
        &self,
        generation: u64,
    ) -> Vec<Arc<dyn NotificationCandidateHook>> {
        let hooks = self.notification_hooks();
        for hook in &hooks {
            hook.publication_stage(generation);
        }
        hooks
    }

    fn notify_notification_publication_flush(
        hooks: &[Arc<dyn NotificationCandidateHook>],
        generation: u64,
        session: &Session,
    ) {
        for hook in hooks {
            hook.publication_flush(generation, session);
        }
    }
}
impl NotificationCandidateHook for Owner {
    fn candidate(&self, session: Session) {
        self.notify_notification_candidate(session);
    }
}
impl MaterialConnectionController {
    pub fn new(
        environment: Arc<TransportEnvironment>,
        options: MaterialControllerOptions,
    ) -> Result<Self, MaterialControllerError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| MaterialControllerError::Configuration)?;
        if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread
            || options.sources.is_empty()
            || options.sources.len() > 8
            || options.sources.capacity() > 8
            || !(1..=16).contains(&options.max_attempts_per_outage)
            || options.managed_services.len() > 32
            || options.managed_services.capacity() > 32
            || options
                .managed_services
                .iter()
                .enumerate()
                .any(|(index, service)| {
                    service.methods.is_empty()
                        || service.methods.len() > 256
                        || service.methods.capacity() > 256
                        || service.query.type_id == 0
                        || service.query.contract_digest == [0; 32]
                        || service.bind_timeout.is_zero()
                        || service.bind_timeout > Duration::from_secs(30)
                        || service.initial_methods.as_ref().is_some_and(|initial| {
                            initial.len() > service.methods.len()
                                || initial.capacity() > 256
                                || initial.iter().enumerate().any(|(index, method)| {
                                    !service.definition.contains(method)
                                        || initial[..index].iter().any(|old| old.same(method))
                                })
                        })
                        || service.offer_renewal.as_ref().is_some_and(|renewal| {
                            renewal.renew_before.is_zero()
                                || renewal.query_timeout.is_zero()
                                || renewal.query_timeout > Duration::from_secs(60)
                                || renewal.retry_after.is_zero()
                                || renewal.retry_after > Duration::from_secs(60)
                        })
                        || options.managed_services[..index]
                            .iter()
                            .any(|old| old.definition.namespace() == service.definition.namespace())
                        || options
                            .managed_services
                            .first()
                            .is_some_and(|first| first.query != service.query)
                })
            || options.retry_after < Duration::from_millis(10)
            || options.retry_after > Duration::from_secs(30)
            || options.candidate_timeout.is_zero()
            || options.candidate_timeout > Duration::from_secs(90)
            || options.retain_replaced_for > Duration::from_secs(30)
            || options.drain_timeout.is_zero()
            || options.drain_timeout > Duration::from_secs(30)
            || options.sources.iter().enumerate().any(|(index, source)| {
                !source.source.belongs_to(&environment)
                    || options.sources[..index]
                        .iter()
                        .any(|previous| previous.source.same_owner(&source.source))
            })
        {
            return Err(MaterialControllerError::Configuration);
        }
        if options.parent.is_cancelled() || environment.root().is_closed() {
            return Err(MaterialControllerError::Closed);
        }
        let callback_bytes = options
            .initialize_session
            .as_ref()
            .map_or(0, |initializer| initializer.application_bytes());
        if callback_bytes > 16 * 1024 * 1024 {
            return Err(MaterialControllerError::Capacity);
        }
        let configured_methods = options
            .managed_services
            .iter()
            .map(|service| service.methods.len() as u64)
            .sum::<u64>();
        let charge = environment
            .root()
            .reserve_environment(ResourceLimits {
                sdk_bytes: 8192
                    + callback_bytes
                    + options.managed_services.len() as u64 * 4096
                    + configured_methods * 4096,
                items: 16 + options.managed_services.len() as u64 + configured_methods,
                tasks: 5,
                timers: 5,
                work_slots: 5,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialControllerError::Capacity)?;
        let (replace, receiver) = mpsc::channel(1);
        let cancellation = options.parent.child_token();
        let owner = Arc::new(Owner {
            environment,
            options,
            publication_generation: Arc::new(AtomicU64::new(0)),
            state: Mutex::new(State {
                current: None,
                candidate: None,
                candidate_charge: None,
                retained: None,
                generation: 0,
                attempts: 0,
                state: MaterialControllerState::Connecting,
                failure: None,
                closed: false,
                replacement_active: false,
                candidate_cleanup: false,
                source_profile_anchor: 0,
                service_baselines: Vec::new(),
                connection_facts: None,
                connection_cleanup: None,
            }),
            cancellation,
            changed: Notify::new(),
            replace,
            workers: AtomicUsize::new(1),
            handles: AtomicUsize::new(1),
            notification_roots: AtomicUsize::new(0),
            notification_candidate_hooks: Mutex::new(Vec::new()),
            _charge: charge,
        });
        owner
            .environment
            .root()
            .register_material_controller(&owner)
            .map_err(|_| MaterialControllerError::Capacity)?;
        let worker = owner.clone();
        runtime.spawn(async move {
            let _worker = Worker(worker.clone());
            worker.run(receiver).await;
        });
        Ok(Self(owner))
    }
    pub fn service(
        &self,
        namespace: &str,
    ) -> Result<ControllerServiceClient, MaterialControllerError> {
        if !self
            .0
            .options
            .managed_services
            .iter()
            .any(|service| service.definition.namespace() == namespace)
        {
            return Err(MaterialControllerError::ServiceUnavailable);
        }
        let charge = self
            .0
            .environment
            .root()
            .reserve_environment(ResourceLimits {
                sdk_bytes: namespace.len() as u64 + 4096,
                items: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialControllerError::Capacity)?;
        Ok(ControllerServiceClient {
            controller: self.clone(),
            namespace: namespace.to_owned(),
            secondary: None,
            mapped_authority: None,
            _charge: charge,
        })
    }
    pub fn current(&self) -> Option<MaterialConnectionSnapshot> {
        let state = self.0.state.lock().expect("current material Session");
        if state.closed
            || state.state == MaterialControllerState::Failed
            || self.0.cancellation.is_cancelled()
            || self.0.environment.root().is_closed()
        {
            return None;
        }
        state
            .current
            .as_ref()
            .filter(|snapshot| snapshot.session.termination_cause().is_none())
            .cloned()
    }
    /// Capture the accepting current Session once for a complete fixed
    /// interaction. Later replacements never rewrite this public handle.
    pub fn capture_session(&self) -> Result<Session, MaterialControllerError> {
        let state = self
            .0
            .state
            .lock()
            .expect("controller fixed Session dispatch");
        if state.closed
            || self.0.cancellation.is_cancelled()
            || self.0.environment.root().is_closed()
        {
            return Err(MaterialControllerError::Closed);
        }
        if state.state == MaterialControllerState::Failed {
            return Err(state
                .failure
                .unwrap_or(MaterialControllerError::ConnectionFailed));
        }
        let current = state
            .current
            .as_ref()
            .ok_or(MaterialControllerError::NotReady)?;
        current
            .session
            .controller_dispatch_eligible()
            .map_err(|_| MaterialControllerError::NotReady)?;
        Ok(current.session.clone())
    }
    pub fn progress(&self) -> MaterialControllerProgress {
        let state = self.0.state.lock().expect("material controller progress");
        MaterialControllerProgress {
            state: state.state,
            generation: state.generation,
            attempts: state.attempts,
            failure: state.failure,
            retained_session: state.retained.is_some(),
            connection_facts: state.connection_facts,
        }
    }
    pub async fn wait_current(
        &self,
        after_generation: u64,
        cancellation: &CancellationToken,
    ) -> Result<MaterialConnectionSnapshot, MaterialControllerError> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if cancellation.is_cancelled() {
                return Err(MaterialControllerError::Canceled);
            }
            if let Some(current) = self
                .current()
                .filter(|snapshot| snapshot.generation > after_generation)
            {
                return Ok(current);
            }
            let progress = self.progress();
            if matches!(
                progress.state,
                MaterialControllerState::Closed | MaterialControllerState::Failed
            ) {
                return Err(progress.failure.unwrap_or(MaterialControllerError::Closed));
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(MaterialControllerError::Canceled),
            _ = self.0.cancellation.cancelled() => return Err(MaterialControllerError::Closed) }
        }
    }
    /// Explicit replacement keeps the currently published Session while one
    /// new candidate connects and initializes. Canceling before publication
    /// withdraws that switch; the physical candidate still owns all work until
    /// actual exit. A published generation is never revoked by wait cancellation.
    pub async fn replace_session(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<MaterialConnectionSnapshot, MaterialControllerError> {
        // An explicitly configured retention duration remains supported, but
        // its absolute cutoff is frozen before acquisition rather than after
        // publication. The per-attempt API defaults to ordinary Drain.
        let retirement = if self.0.options.retain_replaced_for.is_zero()
            || self
                .0
                .state
                .lock()
                .expect("optional replacement current")
                .current
                .is_none()
        {
            MaterialSessionRetirement::Drain
        } else {
            let current = self.capture_session()?;
            let retain_until_ms = current
                .controller_retain_until(self.0.options.retain_replaced_for)
                .map_err(|_| MaterialControllerError::RetirementUnavailable)?;
            MaterialSessionRetirement::Retain { retain_until_ms }
        };
        Ok(self
            .replace_session_with_options(
                MaterialSessionReplaceOptions { retirement },
                cancellation,
            )
            .await?
            .current)
    }
    pub async fn replace_session_with_options(
        &self,
        options: MaterialSessionReplaceOptions,
        cancellation: &CancellationToken,
    ) -> Result<MaterialSessionReplaceResult, MaterialControllerError> {
        if cancellation.is_cancelled() {
            return Err(MaterialControllerError::Canceled);
        }
        let (expected_generation, retirement) = {
            let mut state = self.0.state.lock().expect("replacement eligibility");
            if state.closed
                || self.0.cancellation.is_cancelled()
                || self.0.environment.root().is_closed()
            {
                return Err(MaterialControllerError::Closed);
            }
            // This explicit application action admits a fresh attempt after
            // authoritative recovery. Failed attempts retain no publication right.
            if !state.connection_cleanup_status().complete {
                return Err(MaterialControllerError::CleanupIncomplete);
            }
            if state.replacement_active || state.retained.is_some() || state.candidate.is_some() {
                return Err(MaterialControllerError::Capacity);
            }
            let retirement = match (state.current.as_ref(), options.retirement) {
                (_, MaterialSessionRetirement::Drain) | (None, _) => FixedRetirement::Drain,
                (Some(current), MaterialSessionRetirement::Retain { retain_until_ms }) => {
                    FixedRetirement::Retain {
                        retain_until_ms,
                        deadline: current
                            .session
                            .controller_retain_deadline(retain_until_ms)
                            .map_err(|_| MaterialControllerError::RetirementUnavailable)?,
                    }
                }
            };
            state.replacement_active = true;
            (state.generation, retirement)
        };
        let original_cancellation = CancellationToken::new();
        let _observer = ReplacementObserver {
            owner: self.0.clone(),
            expected_generation,
            cancellation: original_cancellation.clone(),
        };
        let (completion, result) = oneshot::channel();
        if let Err(error) = self.0.replace.try_send(Replacement {
            expected_generation,
            cancellation: original_cancellation,
            retirement,
            completion,
        }) {
            self.0
                .state
                .lock()
                .expect("replacement queue refusal")
                .replacement_active = false;
            return Err(match error {
                mpsc::error::TrySendError::Full(_) => MaterialControllerError::Capacity,
                mpsc::error::TrySendError::Closed(_) => MaterialControllerError::Closed,
            });
        }
        tokio::select! { result = result => result.map_err(|_| MaterialControllerError::Closed)?,
        _ = cancellation.cancelled() => Err(MaterialControllerError::Canceled) }
    }
    pub fn close(&self) {
        self.0.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.0.cleanup_status()
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(until) => return self.cleanup_status() }
        }
    }
}
// A dropped wait withdraws only a switch that has not crossed the original
// publication gate. It cannot cancel the newly published current Session.
struct ReplacementObserver {
    owner: Arc<Owner>,
    expected_generation: u64,
    cancellation: CancellationToken,
}
impl Drop for ReplacementObserver {
    fn drop(&mut self) {
        let state = self
            .owner
            .state
            .lock()
            .expect("replacement observer withdrawal");
        if state.generation == self.expected_generation {
            self.cancellation.cancel();
        }
    }
}
impl Owner {
    pub(crate) fn close(&self) {
        let sessions = {
            let mut state = self.state.lock().expect("close material controller");
            if state.closed {
                return;
            }
            state.closed = true;
            state.state = MaterialControllerState::Closed;
            self.publication_generation
                .store(u64::MAX, Ordering::Release);
            [
                state
                    .current
                    .as_ref()
                    .map(|current| current.session.clone()),
                state.candidate.clone(),
                state.retained.clone(),
            ]
        };
        self.cancellation.cancel();
        for session in sessions.into_iter().flatten() {
            session.close();
        }
        for source in &self.options.sources {
            if source.ownership == MaterialSourceOwnership::Owned {
                source.source.close();
            }
        }
        self.changed.notify_waiters();
    }
    fn cleanup_status(&self) -> CleanupStatus {
        let mut state = self.state.lock().expect("material controller cleanup");
        let unpublished = state.connection_cleanup_status();
        let mut callbacks = (self.workers.load(Ordering::Acquire) as u64)
            .saturating_add(unpublished.pending_callbacks);
        let mut physical = unpublished.complete;
        for session in [
            state.current.as_ref().map(|current| &current.session),
            state.candidate.as_ref(),
            state.retained.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            let status = session.cleanup_status();
            physical &= status.complete;
            callbacks = callbacks.saturating_add(status.pending_callbacks);
        }
        let complete = state.closed && callbacks == 0 && physical;
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: callbacks,
        }
    }
    fn record_connection_error(
        &self,
        error: ConnectionError,
        cleanup: &Arc<crate::crypto_v4::connect::ConnectCleanup>,
    ) -> MaterialControllerError {
        let mut state = self
            .state
            .lock()
            .expect("detached original connection failure");
        state.connection_facts = Some(error.connection_facts());
        // Connect has settled, so no successful Session or not-yet-started
        // preparation can be mistaken for an unpublished physical tail.
        state.connection_cleanup = (!cleanup.complete()).then(|| cleanup.clone());
        classify_connection(error)
    }
    fn record_ready(&self, profile: crate::ConnectionSourceProfile) {
        self.state
            .lock()
            .expect("original READY candidate delivery")
            .connection_facts = Some(crate::ConnectionAttemptFacts {
            phase: crate::ConnectionPhase::Ready,
            spend_state: crate::ConnectionSpendState::Spent,
            admission_state: crate::ConnectionAdmissionState::Admitted,
            network_ready: crate::ConnectionNetworkReady::Ready,
            application_publish: crate::ConnectionApplicationPublish::NotStarted,
            source_profile: Some(profile),
            query_availability: crate::ConnectionQueryAvailability::Unavailable,
        });
    }
    fn fail(&self, failure: MaterialControllerError) {
        let mut state = self.state.lock().expect("material controller failure");
        if let Some(facts) = &mut state.connection_facts {
            if matches!(
                failure,
                MaterialControllerError::InitializationFailed
                    | MaterialControllerError::ServiceBindingFailed
            ) {
                facts.application_publish = crate::ConnectionApplicationPublish::Failed;
            } else if failure == MaterialControllerError::InitializationUnknown {
                facts.application_publish = crate::ConnectionApplicationPublish::Unknown;
            }
        }
        if !state.closed {
            state.state = MaterialControllerState::Failed;
            state.failure = Some(failure);
        }
        drop(state);
        self.changed.notify_waiters();
    }
    async fn candidate(
        self: &Arc<Self>,
        source_index: usize,
        replacement: Option<&CancellationToken>,
    ) -> Result<
        (
            Session,
            Vec<ManagedServiceClient>,
            Arc<ResourceCharge>,
            Vec<crate::service_client_v4::ServiceRebindBaseline>,
        ),
        MaterialControllerError,
    > {
        let cancellation = replacement.map_or_else(
            || self.cancellation.child_token(),
            CancellationToken::child_token,
        );
        if cancellation.is_cancelled() {
            return Err(MaterialControllerError::Canceled);
        }
        let deadline = Instant::now()
            .checked_add(self.options.candidate_timeout)
            .ok_or(MaterialControllerError::Configuration)?;
        {
            let mut state = self
                .state
                .lock()
                .expect("new original controller attempt facts");
            if !state.connection_cleanup_status().complete {
                return Err(MaterialControllerError::CleanupIncomplete);
            }
            state.connection_facts = None;
        }
        let handlers = self
            .options
            .request
            .handlers
            .as_ref()
            .map(|(plan, limits)| {
                let captured = plan
                    .capture(self.environment.root())
                    .map_err(|_| MaterialControllerError::Configuration)?;
                captured
                    .validate_limits(*limits)
                    .map_err(|_| MaterialControllerError::Configuration)?;
                Ok::<_, MaterialControllerError>((captured, *limits))
            })
            .transpose()?;
        let configured_methods = self
            .options
            .managed_services
            .iter()
            .map(|service| service.methods.len() as u64)
            .sum::<u64>();
        let mut candidate_backing = self
            .environment
            .root()
            .reserve_environment(ResourceLimits {
                sdk_bytes: 8192
                    + self.options.managed_services.len() as u64 * 4096
                    + configured_methods * 4096,
                items: 8 + self.options.managed_services.len() as u64 + configured_methods,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialControllerError::Capacity)?;
        let mut managed_services = Vec::new();
        managed_services
            .try_reserve_exact(self.options.managed_services.len())
            .map_err(|_| MaterialControllerError::Capacity)?;
        let mut initializer_services = Vec::new();
        if self.options.initialize_session.is_some() {
            initializer_services
                .try_reserve_exact(self.options.managed_services.len())
                .map_err(|_| MaterialControllerError::Capacity)?;
        }
        let mut prepared_services = Vec::new();
        prepared_services
            .try_reserve_exact(self.options.managed_services.len())
            .map_err(|_| MaterialControllerError::Capacity)?;
        let baselines = self.service_baselines()?;
        for configuration in &self.options.managed_services {
            let mut methods = Vec::new();
            methods
                .try_reserve_exact(configuration.methods.len())
                .map_err(|_| MaterialControllerError::Capacity)?;
            methods.extend(configuration.methods.iter().cloned());
            prepared_services.push(PreparedManagedService {
                bind_definition: configuration.definition.clone(),
                client_definition: configuration.definition.clone(),
                initializer_definition: configuration.definition.clone(),
                methods,
                bind_timeout: configuration.bind_timeout,
                selection: crate::ServiceBindingSelection {
                    initial_methods: configuration.initial_methods.clone(),
                },
                offer_renewal: configuration.offer_renewal.clone(),
                baseline: baselines
                    .iter()
                    .find(|old| old.namespace() == configuration.definition.namespace())
                    .cloned(),
            });
        }
        let (material, candidate_charge, mut prepaid) = {
            let acquisition = self.options.sources[source_index]
                .source
                .acquire_with_backing(
                    &self.environment,
                    &self.options.request,
                    &cancellation,
                    &mut candidate_backing,
                    handlers.as_ref(),
                    &self.options.managed_services,
                );
            tokio::pin!(acquisition);
            tokio::select! {
                result = &mut acquisition => result.map_err(classify_material_source)?,
                _ = self.cancellation.cancelled() => { cancellation.cancel(); let _ = acquisition.await; return Err(MaterialControllerError::Closed); },
                _ = cancellation.cancelled() => { let _ = acquisition.await; return Err(MaterialControllerError::Canceled); },
                _ = tokio::time::sleep_until(deadline) => { cancellation.cancel(); let _ = acquisition.await; return Err(MaterialControllerError::ConnectionFailed); },
            }
        };
        let source_profile = material.source_profile();
        let candidate_charge = Arc::new(candidate_charge);
        let mut binding_charges = prepaid.take_bindings().into_iter();
        let cleanup = prepaid.cleanup_observer();
        let notification_hook: Arc<dyn NotificationCandidateHook> = self.clone();
        let future = self.environment.connect_material_with_controller_prepaid(
            material,
            handlers,
            cancellation.clone(),
            prepaid,
            notification_hook,
        );
        tokio::pin!(future);
        let acquired = tokio::select! {
            result = &mut future => result.map_err(|error| self.record_connection_error(error, &cleanup)),
            _ = self.cancellation.cancelled() => {
                cancellation.cancel();
                match future.await {
                    Ok(session) => { self.record_ready(source_profile); self.retain_until_cleanup(session, candidate_charge); },
                    Err(error) => {
                        if self.record_connection_error(error, &cleanup) == MaterialControllerError::CleanupIncomplete {
                            return Err(MaterialControllerError::CleanupIncomplete);
                        }
                    },
                }
                return Err(MaterialControllerError::Closed);
            },
            _ = cancellation.cancelled() => {
                match future.await {
                    Ok(session) => { self.record_ready(source_profile); self.retain_until_cleanup(session, candidate_charge); },
                    Err(error) => {
                        if self.record_connection_error(error, &cleanup) == MaterialControllerError::CleanupIncomplete {
                            return Err(MaterialControllerError::CleanupIncomplete);
                        }
                    },
                }
                return Err(MaterialControllerError::Canceled);
            },
            _ = tokio::time::sleep_until(deadline) => {
                cancellation.cancel();
                let failure = match future.await {
                    Ok(session) => {
                        self.record_ready(source_profile); self.retain_until_cleanup(session, candidate_charge);
                        MaterialControllerError::CredentialSpent
                    },
                    Err(error) => self.record_connection_error(error, &cleanup),
                };
                return Err(failure);
            },
        };
        let session = acquired?;
        self.record_ready(source_profile);
        {
            let mut state = self
                .state
                .lock()
                .expect("material candidate initialization");
            if state.closed {
                session.close();
                drop(state);
                self.retain_until_cleanup(session, candidate_charge);
                return Err(MaterialControllerError::Closed);
            }
            state.candidate = Some(session.clone());
            state.candidate_charge = Some(candidate_charge.clone());
            state.state = MaterialControllerState::Initializing;
        }
        self.changed.notify_waiters();
        if let Some(first) = self.options.managed_services.first() {
            let peer = match session.configured_services() {
                Some(services) => {
                    let peer = services.service_peer();
                    if !peer.uses_query(first.query) {
                        session.close();
                        return Err(MaterialControllerError::InitializationFailed);
                    }
                    peer
                }
                None => match session.services(first.query, Vec::new()) {
                    Ok(peer) => peer,
                    Err(_) => {
                        session.close();
                        let _ = session.wait_cleanup().await;
                        return Err(MaterialControllerError::InitializationFailed);
                    }
                },
            };
            for configuration in prepared_services {
                let bind_cancel = cancellation.child_token();
                let bind_deadline = (Instant::now() + configuration.bind_timeout).min(deadline);
                let bind_timeout = bind_deadline.saturating_duration_since(Instant::now());
                let binding_charge = binding_charges
                    .next()
                    .ok_or(MaterialControllerError::Configuration)?;
                let bind = peer.bind_replacement_selected_prepaid(
                    configuration.bind_definition,
                    configuration.methods,
                    configuration.selection,
                    bind_timeout,
                    bind_cancel.clone(),
                    binding_charge,
                    configuration.baseline,
                );
                tokio::pin!(bind);
                let result = tokio::select! {
                    result = &mut bind => result,
                    _ = self.cancellation.cancelled() => { bind_cancel.cancel(); let _ = bind.await; Err(crate::ServiceError(crate::ServiceFailure::Closed)) },
                    _ = cancellation.cancelled() => { bind_cancel.cancel(); let _ = bind.await; Err(crate::ServiceError(crate::ServiceFailure::Closed)) },
                    _ = tokio::time::sleep_until(bind_deadline) => { bind_cancel.cancel(); let _ = bind.await; Err(crate::ServiceError(crate::ServiceFailure::DeadlineExceeded)) },
                };
                match result {
                    Ok(client) => {
                        if let Some(renewal) = configuration.offer_renewal {
                            client
                                .start_managed_offer_renewal(renewal)
                                .map_err(|_| MaterialControllerError::ServiceBindingFailed)?;
                        }
                        managed_services.push(ManagedServiceClient {
                            definition: configuration.client_definition,
                            client: client.clone(),
                        });
                        if self.options.initialize_session.is_some() {
                            initializer_services.push(ManagedServiceClient {
                                definition: configuration.initializer_definition,
                                client,
                            });
                        }
                    }
                    Err(_) => {
                        peer.close();
                        session.close();
                        let _ = session.wait_cleanup().await;
                        return Err(MaterialControllerError::ServiceBindingFailed);
                    }
                }
            }
        }
        if let Some(initializer) = &self.options.initialize_session {
            let initializer = initializer.clone();
            let target = session.clone();
            let callback_cancel = cancellation.clone();
            self.workers.fetch_add(1, Ordering::AcqRel);
            let callback_owner = self.clone();
            let callback_charge = candidate_charge.clone();
            let callback = tokio::spawn(async move {
                let _worker = Worker(callback_owner);
                let _candidate_charge = callback_charge;
                initializer
                    .initialize_candidate(target, &initializer_services, callback_cancel)
                    .await
            });
            tokio::pin!(callback);
            let initialized = tokio::select! {
                result = &mut callback => result.unwrap_or(Err(MaterialControllerError::InitializationFailed)),
                _ = self.cancellation.cancelled() => {
                    cancellation.cancel(); session.close();
                    // Dropping the JoinHandle detaches only observation. The
                    // prepaid callback worker retains the candidate and owner
                    // until actual exit, including after bounded Close.
                    Err(MaterialControllerError::InitializationUnknown)
                },
                _ = cancellation.cancelled() => {
                    session.close(); self.fail(MaterialControllerError::InitializationUnknown);
                    Err(MaterialControllerError::InitializationUnknown)
                },
                _ = tokio::time::sleep_until(deadline) => {
                    cancellation.cancel(); session.close();
                    self.fail(MaterialControllerError::InitializationUnknown);
                    Err(MaterialControllerError::InitializationUnknown)
                },
            };
            if initialized.is_err() {
                session.close();
                return Err(initialized.err().unwrap());
            }
        }
        if self.cancellation.is_cancelled()
            || cancellation.is_cancelled()
            || session.termination_cause().is_some()
        {
            session.close();
            return Err(MaterialControllerError::InitializationUnknown);
        }
        Ok((session, managed_services, candidate_charge, baselines))
    }
    fn service_baselines(
        &self,
    ) -> Result<Vec<crate::service_client_v4::ServiceRebindBaseline>, MaterialControllerError> {
        let state = self
            .state
            .lock()
            .expect("fixed controller service source generation");
        if let Some(current) = &state.current {
            return capture_service_baselines(current.managed_services());
        }
        let mut captured = Vec::new();
        captured
            .try_reserve_exact(state.service_baselines.len())
            .map_err(|_| MaterialControllerError::Capacity)?;
        captured.extend(state.service_baselines.iter().cloned());
        Ok(captured)
    }
    fn publish(
        self: &Arc<Self>,
        session: Session,
        source_index: usize,
        managed_services: Vec<ManagedServiceClient>,
        candidate_charge: Arc<ResourceCharge>,
        replacement: Option<(&CancellationToken, FixedRetirement)>,
        expected_baselines: Vec<crate::service_client_v4::ServiceRebindBaseline>,
    ) -> Result<
        (
            MaterialConnectionSnapshot,
            Option<MaterialSessionReplaceResult>,
        ),
        MaterialControllerError,
    > {
        let service_baselines = capture_service_baselines(&managed_services)?;
        let (snapshot, replaced, retirement, displaced, publication_hooks) = {
            let mut state = self.state.lock().expect("material current publication");
            if state.closed
                || self.cancellation.is_cancelled()
                || self.environment.root().is_closed()
            {
                session.close();
                return Err(MaterialControllerError::Closed);
            }
            if replacement.is_some_and(|(cancel, _)| cancel.is_cancelled()) {
                session.close();
                return Err(MaterialControllerError::Canceled);
            }
            if state.retained.is_some() {
                session.close();
                return Err(MaterialControllerError::Capacity);
            }
            let original_current = state.current.clone();
            let mut source_guards = Vec::new();
            if let Some(current) = &original_current {
                if current.managed_services().len() != expected_baselines.len() {
                    return Err(MaterialControllerError::GenerationChanged);
                }
                source_guards
                    .try_reserve_exact(expected_baselines.len())
                    .map_err(|_| MaterialControllerError::Capacity)?;
                for service in current.managed_services() {
                    let expected = expected_baselines
                        .iter()
                        .find(|expected| expected.namespace() == service.definition.namespace())
                        .ok_or(MaterialControllerError::GenerationChanged)?;
                    source_guards.push(
                        service
                            .client
                            .retain_rebind_source(expected)
                            .map_err(|_| MaterialControllerError::GenerationChanged)?,
                    );
                }
            } else if state.service_baselines.len() != expected_baselines.len()
                || state.service_baselines.iter().any(|old| {
                    expected_baselines
                        .iter()
                        .find(|expected| expected.namespace() == old.namespace())
                        .is_none_or(|expected| !old.same_revision(expected))
                })
            {
                session.close();
                return Err(MaterialControllerError::GenerationChanged);
            }
            let Some(generation) = state.generation.checked_add(1) else {
                session.close();
                return Err(MaterialControllerError::Capacity);
            };
            let retirement = match (state.current.as_ref(), replacement) {
                (Some(previous), Some((_, selected))) => {
                    let deadline = match selected {
                        FixedRetirement::Drain => previous
                            .session
                            .controller_retirement_deadline(self.options.drain_timeout)
                            .unwrap_or_else(|_| Instant::now()),
                        FixedRetirement::Retain { deadline, .. } => {
                            previous
                                .session
                                .controller_dispatch_eligible()
                                .map_err(|_| MaterialControllerError::RetirementUnavailable)?;
                            let deadline = deadline.min(
                                previous
                                    .session
                                    .controller_retirement_deadline(
                                        deadline.saturating_duration_since(Instant::now()),
                                    )
                                    .map_err(|_| MaterialControllerError::RetirementUnavailable)?,
                            );
                            if deadline <= Instant::now() {
                                session.close();
                                return Err(MaterialControllerError::RetirementUnavailable);
                            }
                            deadline
                        }
                    };
                    Some((selected, deadline))
                }
                (None, None) | (None, Some((_, FixedRetirement::Drain))) => None,
                _ => {
                    session.close();
                    return Err(MaterialControllerError::GenerationChanged);
                }
            };
            let mut staged_services = Some(managed_services);
            let mut staged_charge = Some(candidate_charge);
            let mut staged_baselines = Some(service_baselines);
            let retained_authority =
                matches!(retirement, Some((FixedRetirement::Retain { .. }, _))).then(|| {
                    &original_current
                        .as_ref()
                        .expect("checked retained source")
                        .session
                });
            let mut publish = || {
                session
                    .controller_publication_gate_with_retained(retained_authority, || {
                        if self.cancellation.is_cancelled()
                            || replacement.is_some_and(|(cancel, _)| cancel.is_cancelled())
                        {
                            return Err(MaterialControllerError::Canceled);
                        }
                        if retirement.is_some_and(|(selected, deadline)| {
                            matches!(selected, FixedRetirement::Retain { .. })
                                && deadline <= Instant::now()
                        }) {
                            return Err(MaterialControllerError::RetirementUnavailable);
                        }
                        let retirement = retirement.map(|(selected, deadline)| {
                            (
                                selected,
                                state
                                    .current
                                    .as_ref()
                                    .expect("checked original current")
                                    .session
                                    .controller_install_retirement_deadline(deadline),
                            )
                        });
                        let snapshot = MaterialConnectionSnapshot {
                            generation,
                            source_index,
                            session: session.clone(),
                            managed_services: staged_services
                                .take()
                                .expect("checked candidate services")
                                .into(),
                            _candidate_charge: staged_charge
                                .take()
                                .expect("checked candidate backing"),
                        };
                        state.source_profile_anchor = source_index;
                        // Keep displaced backing alive until the Environment gate has
                        // released; ResourceCharge destruction reacquires that root.
                        let old_baselines = std::mem::replace(
                            &mut state.service_baselines,
                            staged_baselines
                                .take()
                                .expect("checked candidate baselines"),
                        );
                        let old_candidate = state.candidate.take();
                        let old_candidate_charge = state.candidate_charge.take();
                        let replaced = state.current.replace(snapshot.clone());
                        state.generation = generation;
                        self.publication_generation
                            .store(generation, Ordering::Release);
                        state.candidate = None;
                        state.candidate_charge = None;
                        state.state = MaterialControllerState::Ready;
                        state.failure = None;
                        state.attempts = 0;
                        if let Some(facts) = &mut state.connection_facts {
                            facts.application_publish =
                                crate::ConnectionApplicationPublish::Published;
                        }
                        if let Some(previous) = &replaced {
                            state.retained = Some(previous.session.clone());
                        }
                        let publication_hooks =
                            self.notify_notification_publication_stage(generation);
                        Ok((
                            snapshot,
                            replaced,
                            retirement,
                            (old_baselines, old_candidate, old_candidate_charge),
                            publication_hooks,
                        ))
                    })
                    .map_err(|_| MaterialControllerError::NotReady)
            };
            if matches!(retirement, Some((FixedRetirement::Retain { .. }, _))) {
                let previous = original_current
                    .as_ref()
                    .ok_or(MaterialControllerError::GenerationChanged)?;
                if previous.session.same_original(&session) {
                    return Err(MaterialControllerError::GenerationChanged);
                }
                let admitted = previous
                    .session
                    .controller_retention_gate(publish)
                    .map_err(|_| MaterialControllerError::RetirementUnavailable)?;
                admitted??
            } else {
                publish()??
            }
        };
        Owner::notify_notification_publication_flush(
            &publication_hooks,
            snapshot.generation,
            &snapshot.session,
        );
        drop(publication_hooks);
        drop(displaced);
        self.changed.notify_waiters();
        let result = if let Some(previous) = replaced {
            let (selected, deadline) =
                retirement.ok_or(MaterialControllerError::RetirementUnavailable)?;
            let result = MaterialSessionReplaceResult {
                current: snapshot.clone(),
                previous: Some(previous.session.clone()),
                retirement: selected.selection(),
                retirement_deadline: Some(deadline),
            };
            self.retire(previous, selected, deadline);
            Some(result)
        } else if replacement.is_some() {
            Some(MaterialSessionReplaceResult {
                current: snapshot.clone(),
                previous: None,
                retirement: MaterialSessionRetirement::Drain,
                retirement_deadline: None,
            })
        } else {
            None
        };
        Ok((snapshot, result))
    }
    fn reap_unpublished(self: &Arc<Self>) {
        let (session, candidate_charge) = {
            let mut state = self
                .state
                .lock()
                .expect("unpublished candidate cleanup gate");
            if state.candidate_cleanup {
                return;
            }
            let Some(session) = state.candidate.clone() else {
                return;
            };
            state.candidate_cleanup = true;
            (session, state.candidate_charge.clone())
        };
        self.retain_candidate_until_cleanup(session, candidate_charge, None);
    }
    fn retain_until_cleanup(
        self: &Arc<Self>,
        session: Session,
        candidate_charge: Arc<ResourceCharge>,
    ) {
        self.retain_candidate_until_cleanup(session, Some(candidate_charge), None);
    }
    fn retain_candidate_until_cleanup(
        self: &Arc<Self>,
        session: Session,
        candidate_charge: Option<Arc<ResourceCharge>>,
        snapshot: Option<MaterialConnectionSnapshot>,
    ) {
        session.close();
        self.workers.fetch_add(1, Ordering::AcqRel);
        let owner = self.clone();
        tokio::spawn(async move {
            let _worker = Worker(owner.clone());
            let _candidate_charge = candidate_charge;
            let _snapshot = snapshot;
            while !session.cleanup_status().complete {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut state = owner
                .state
                .lock()
                .expect("unpublished candidate actual exit");
            if state
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.same_original(&session))
            {
                state.candidate = None;
                state.candidate_charge = None;
            }
            state.candidate_cleanup = false;
            drop(state);
            owner.changed.notify_waiters();
        });
    }
    fn retire(
        self: &Arc<Self>,
        previous: MaterialConnectionSnapshot,
        selected: FixedRetirement,
        deadline: Instant,
    ) {
        self.workers.fetch_add(1, Ordering::AcqRel);
        let owner = self.clone();
        tokio::spawn(async move {
            let _worker = Worker(owner.clone());
            let session = previous.session.clone();
            if matches!(selected, FixedRetirement::Drain) {
                if let Ok(drain) = session.drain(deadline.saturating_duration_since(Instant::now()))
                {
                    tokio::select! { _ = drain.wait() => {}, _ = owner.cancellation.cancelled() => {},
                    _ = tokio::time::sleep_until(deadline) => {} }
                }
            } else {
                tokio::select! { _ = tokio::time::sleep_until(deadline) => {}, _ = owner.cancellation.cancelled() => {} }
            }
            session.close();
            // Bounded Close does not release the retained position. This
            // original prepaid worker owns it until physical cleanup exits.
            loop {
                let changed = owner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if session.cleanup_status().complete {
                    break;
                }
                tokio::select! { _ = changed => {}, _ = tokio::time::sleep(Duration::from_millis(20)) => {} }
            }
            owner
                .state
                .lock()
                .expect("retired material Session")
                .retained = None;
            drop(previous);
            owner.changed.notify_waiters();
        });
    }
    async fn acquire_current(
        self: &Arc<Self>,
    ) -> Result<MaterialConnectionSnapshot, MaterialControllerError> {
        let anchor = self
            .state
            .lock()
            .expect("captured controller source profile")
            .source_profile_anchor;
        let anchor_source = &self.options.sources[anchor].source;
        let eligible: Vec<usize> = (0..self.options.sources.len())
            .filter(|index| {
                self.options.sources[*index]
                    .source
                    .same_activation_profile(anchor_source)
            })
            .collect();
        for attempt in 0..self.options.max_attempts_per_outage {
            if self.cancellation.is_cancelled() {
                return Err(MaterialControllerError::Closed);
            }
            {
                let mut state = self.state.lock().expect("bounded controller retry");
                state.attempts = attempt + 1;
                state.state = MaterialControllerState::Connecting;
            }
            self.changed.notify_waiters();
            let source_index = eligible[attempt as usize % eligible.len()];
            match self.candidate(source_index, None).await {
                Ok((session, managed_services, candidate_charge, baselines)) => {
                    return self
                        .publish(
                            session,
                            source_index,
                            managed_services,
                            candidate_charge,
                            None,
                            baselines,
                        )
                        .map(|(current, _)| current);
                }
                Err(MaterialControllerError::ConnectionFailed)
                    if attempt + 1 < self.options.max_attempts_per_outage =>
                {
                    self.state.lock().expect("material retry interval").state =
                        MaterialControllerState::Retrying;
                    self.changed.notify_waiters();
                    tokio::select! { _ = tokio::time::sleep(self.options.retry_after) => {}, _ = self.cancellation.cancelled() => return Err(MaterialControllerError::Closed) }
                }
                Err(error) => return Err(error),
            }
        }
        Err(MaterialControllerError::ConnectionFailed)
    }
    async fn run(self: &Arc<Self>, mut replacements: mpsc::Receiver<Replacement>) {
        if let Err(error) = self.acquire_current().await {
            self.reap_unpublished();
            if error == MaterialControllerError::Closed {
                self.close();
            } else {
                self.fail(error);
            }
        }
        loop {
            if self.cancellation.is_cancelled() {
                self.close();
                break;
            }
            let current = {
                let state = self
                    .state
                    .lock()
                    .expect("material controller current worker");
                (state.state != MaterialControllerState::Failed)
                    .then(|| state.current.clone())
                    .flatten()
            };
            // Failed publication disables automatic progression and new
            // dispatch, but preserves the explicit replacement receiver.
            let termination = async {
                if let Some(current) = &current {
                    current.session.wait_termination().await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            // The existing controller worker also retires unpublished Connect
            // observations after a bounded Connect return. This uses its
            // original timer and creates no replacement cleanup task.
            let connection_cleanup = async {
                let pending = self
                    .state
                    .lock()
                    .expect("unpublished connection observation")
                    .connection_cleanup
                    .is_some();
                if !pending {
                    std::future::pending::<()>().await;
                }
                loop {
                    if self
                        .state
                        .lock()
                        .expect("unpublished connection actual exit")
                        .connection_cleanup_status()
                        .complete
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            };
            tokio::select! {
                _ = self.cancellation.cancelled() => { self.close(); break; },
                _ = connection_cleanup => { self.changed.notify_waiters(); },
                _ = termination => {
                    let current = current.as_ref().expect("termination requires a current Session");
                    let baselines = match capture_service_baselines(current.managed_services()) {
                        Ok(baselines) => baselines,
                        Err(error) => { self.fail(error); continue; },
                    };
                    let previous = {
                        let mut state = self.state.lock().expect("retired disconnected current");
                        let previous = state.current.take();
                        state.service_baselines = baselines;
                        state.candidate = previous.as_ref().map(|snapshot| snapshot.session.clone());
                        state.candidate_charge = previous.as_ref().map(|snapshot| snapshot._candidate_charge.clone());
                        previous
                    };
                    if let Some(previous) = previous {
                        // Keep each physical owner in a distinct original slot
                        // while an earlier replacement is still retiring.
                        loop {
                            let changed = self.changed.notified(); tokio::pin!(changed); changed.as_mut().enable();
                            if self.state.lock().expect("bounded old Session retention").retained.is_none() { break; }
                            tokio::select! { _ = changed => {}, _ = self.cancellation.cancelled() => { previous.session.close(); break; } }
                        }
                        if self.cancellation.is_cancelled() {
                            self.state.lock().expect("disconnected current cleanup gate").candidate_cleanup = true;
                            self.retain_candidate_until_cleanup(previous.session.clone(), Some(previous._candidate_charge.clone()), Some(previous));
                            self.close(); break;
                        }
                        let status = previous.session.wait_cleanup().await;
                        if !status.complete {
                            self.state.lock().expect("disconnected current cleanup gate").candidate_cleanup = true;
                            self.retain_candidate_until_cleanup(previous.session.clone(), Some(previous._candidate_charge.clone()), Some(previous));
                            self.fail(MaterialControllerError::Capacity); continue;
                        }
                        {
                            let mut state = self.state.lock().expect("completed disconnected current");
                            state.candidate = None;
                            state.candidate_charge = None;
                        }
                    }
                    if let Err(error) = self.acquire_current().await { self.reap_unpublished(); self.fail(error); }
                },
                replacement = replacements.recv() => {
                    let Some(replacement) = replacement else { self.close(); break; };
                    let eligibility = {
                        let mut state = self.state.lock().expect("replace current Session");
                        if state.closed { Err(MaterialControllerError::Closed) }
                        else if state.generation != replacement.expected_generation { Err(MaterialControllerError::GenerationChanged) }
                        else if !state.connection_cleanup_status().complete { Err(MaterialControllerError::CleanupIncomplete) }
                        else if state.retained.is_some() || state.candidate.is_some() { Err(MaterialControllerError::Capacity) }
                        else { Ok(()) }
                    };
                    let outcome = match eligibility {
                        Ok(()) => {
                            let source_index = { let state = self.state.lock().expect("one replacement source");
                                state.current.as_ref().map_or(state.source_profile_anchor, |current| current.source_index) };
                            // One explicit replacement performs exactly one
                            // ordinary Acquire and never rotates/replays it.
                            match self.candidate(source_index, Some(&replacement.cancellation)).await {
                                Ok((session, services, candidate_charge, baselines)) => self.publish(session, source_index, services, candidate_charge,
                                    Some((&replacement.cancellation, replacement.retirement)), baselines)
                                    .and_then(|(_, result)| result.ok_or(MaterialControllerError::GenerationChanged)),
                                Err(error) => Err(error),
                            }
                        },
                        Err(error) => Err(error),
                    };
                    self.state.lock().expect("replacement dispatch completion").replacement_active = false;
                    if let Err(error) = outcome.as_ref() {
                        self.reap_unpublished();
                        if matches!(error, MaterialControllerError::InitializationFailed | MaterialControllerError::InitializationUnknown) {
                            self.fail(*error);
                        } else {
                            let mut state = self.state.lock().expect("unpublished replacement refusal");
                            if !state.closed && state.current.is_some() && state.state != MaterialControllerState::Failed {
                                state.state = MaterialControllerState::Ready; state.failure = Some(*error);
                                if let Some(facts) = &mut state.connection_facts
                                    && facts.network_ready == crate::ConnectionNetworkReady::Ready {
                                        facts.application_publish = crate::ConnectionApplicationPublish::Failed;
                                    }
                            }
                            drop(state); self.changed.notify_waiters();
                        }
                    }
                    let _ = replacement.completion.send(outcome);
                },
            }
        }
        replacements.close();
        while let Ok(replacement) = replacements.try_recv() {
            let _ = replacement
                .completion
                .send(Err(MaterialControllerError::Closed));
        }
        let sessions = {
            let state = self.state.lock().expect("controller physical cleanup");
            [
                state
                    .current
                    .as_ref()
                    .map(|current| current.session.clone()),
                state.candidate.clone(),
                state.retained.clone(),
            ]
        };
        for session in sessions.into_iter().flatten() {
            session.close();
            while !session.cleanup_status().complete {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        loop {
            if self
                .state
                .lock()
                .expect("controller unpublished physical cleanup")
                .connection_cleanup_status()
                .complete
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut state = self
            .state
            .lock()
            .expect("controller final physical release");
        state.current = None;
        state.candidate = None;
        state.candidate_charge = None;
        state.retained = None;
        state.service_baselines.clear();
        drop(state);
        self.changed.notify_waiters();
    }
}
fn capture_service_baselines(
    services: &[ManagedServiceClient],
) -> Result<Vec<crate::service_client_v4::ServiceRebindBaseline>, MaterialControllerError> {
    let mut baselines = Vec::new();
    baselines
        .try_reserve_exact(services.len())
        .map_err(|_| MaterialControllerError::Capacity)?;
    for service in services {
        baselines.push(
            service
                .client
                .rebind_baseline()
                .map_err(|_| MaterialControllerError::ServiceBindingFailed)?,
        );
    }
    Ok(baselines)
}

fn classify_connection(error: ConnectionError) -> MaterialControllerError {
    match error {
        ConnectionError::Connect(TransportConnectError::CleanupIncomplete { .. }) => {
            MaterialControllerError::CleanupIncomplete
        }
        ConnectionError::Source(MaterialSourceError::Canceled)
        | ConnectionError::Connect(TransportConnectError::Canceled) => {
            MaterialControllerError::Closed
        }
        ConnectionError::Source(MaterialSourceError::ConfigurationCapacity)
        | ConnectionError::Connect(TransportConnectError::Capacity) => {
            MaterialControllerError::Capacity
        }
        ConnectionError::Source(
            MaterialSourceError::MaterialUnavailable
            | MaterialSourceError::SourceExhausted
            | MaterialSourceError::SourceUnavailable,
        )
        | ConnectionError::Connect(
            TransportConnectError::Carrier | TransportConnectError::Deadline,
        ) => MaterialControllerError::ConnectionFailed,
        ConnectionError::Source(MaterialSourceError::SpentUnknown) => {
            MaterialControllerError::CredentialSpent
        }
        ConnectionError::Connect(TransportConnectError::LiveAuthorizationUnknown) => {
            MaterialControllerError::AuthorizationUnknown
        }
        ConnectionError::Connect(
            TransportConnectError::Spent(_)
            | TransportConnectError::LiveAuthorized(_)
            | TransportConnectError::AdmissionUnknown { .. }
            | TransportConnectError::Admitted { .. }
            | TransportConnectError::Ready { .. },
        ) => MaterialControllerError::CredentialSpent,
        _ => MaterialControllerError::Configuration,
    }
}
fn classify_material_source(error: MaterialSourceError) -> MaterialControllerError {
    match error {
        MaterialSourceError::Canceled => MaterialControllerError::Closed,
        MaterialSourceError::ConfigurationCapacity => MaterialControllerError::Capacity,
        MaterialSourceError::MaterialUnavailable
        | MaterialSourceError::SourceExhausted
        | MaterialSourceError::SourceUnavailable => MaterialControllerError::ConnectionFailed,
        MaterialSourceError::SourceContractInvalid => MaterialControllerError::Configuration,
        MaterialSourceError::SpentUnknown => MaterialControllerError::CredentialSpent,
        MaterialSourceError::ConnectionRequirementUnavailable
        | MaterialSourceError::RequiredGuaranteeUnavailable => {
            MaterialControllerError::Configuration
        }
    }
}

#[cfg(test)]
#[path = "controller_connection_cleanup_v4_tests.rs"]
mod connection_cleanup_tests;

#[cfg(test)]
mod connection_outcome_tests {
    use super::*;
    #[test]
    fn controller_never_reacquires_after_confirmed_or_uncertain_authorization() {
        assert_eq!(
            classify_connection(ConnectionError::Connect(TransportConnectError::Spent(
                crate::PostSpendFailure::Carrier
            ))),
            MaterialControllerError::CredentialSpent
        );
        assert_eq!(
            classify_connection(ConnectionError::Connect(
                TransportConnectError::LiveAuthorized(crate::PostAuthorizationFailure::Deadline)
            )),
            MaterialControllerError::CredentialSpent
        );
        assert_eq!(
            classify_connection(ConnectionError::Connect(
                TransportConnectError::LiveAuthorizationUnknown
            )),
            MaterialControllerError::AuthorizationUnknown
        );
        let uncertain_admission = TransportConnectError::AdmissionUnknown {
            profile: crate::ConnectionSourceProfile::PreauthorizedPool,
            failure: crate::PostSpendFailure::Canceled,
        };
        assert_eq!(
            uncertain_admission.connection_facts().admission_state,
            crate::ConnectionAdmissionState::Unknown
        );
        assert_eq!(
            uncertain_admission.connection_facts().phase,
            crate::ConnectionPhase::Unknown
        );
        assert_eq!(
            classify_connection(ConnectionError::Connect(uncertain_admission)),
            MaterialControllerError::CredentialSpent
        );
        assert_eq!(
            classify_connection(ConnectionError::Connect(TransportConnectError::Carrier)),
            MaterialControllerError::ConnectionFailed
        );
        for original in [TransportConnectError::Carrier, uncertain_admission] {
            let incomplete = TransportConnectError::CleanupIncomplete {
                facts: original.connection_facts(),
                failure: crate::PostSpendFailure::Carrier,
            };
            assert_eq!(incomplete.connection_facts(), original.connection_facts());
            assert_eq!(
                classify_connection(ConnectionError::Connect(incomplete)),
                MaterialControllerError::CleanupIncomplete
            );
        }
    }
}
