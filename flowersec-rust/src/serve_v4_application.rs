//! Frozen application declarations and one accepted invocation's original
//! callback/lease responsibility. No callback executes under a protocol gate.
use super::*;
use crate::transport::ByteStream;
use crate::{
    application_lifetime_v4::{ApplicationLifetime, CallbackKind},
    crypto_v4::{Metadata, OpenRequest, RawStreamMetadataContract, Stream},
};
use futures_util::FutureExt;
use std::result::Result;
use std::{future::Future, panic::AssertUnwindSafe};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeFailure {
    Configuration,
    Capacity,
    Closed,
    Canceled,
    Rejected,
    AuthorizationUnknown,
    Failed,
}
/// Opaque failure projection. Application messages, credentials and request
/// headers are never included in diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("v4 serving failed: {code:?}")]
pub struct ServeError {
    pub code: ServeFailure,
    pub cleanup: CleanupStatus,
}
impl ServeError {
    pub fn new(code: ServeFailure) -> Self {
        Self {
            code,
            cleanup: complete(),
        }
    }
}
impl From<EnvironmentError> for ServeError {
    fn from(value: EnvironmentError) -> Self {
        Self::new(match value {
            EnvironmentError::Capacity => ServeFailure::Capacity,
            EnvironmentError::Closed => ServeFailure::Closed,
            _ => ServeFailure::Configuration,
        })
    }
}
impl From<ConnectError> for ServeError {
    fn from(value: ConnectError) -> Self {
        Self::new(match value {
            ConnectError::Configuration => ServeFailure::Configuration,
            ConnectError::Capacity => ServeFailure::Capacity,
            ConnectError::Canceled => ServeFailure::Canceled,
            ConnectError::Authorization => ServeFailure::Rejected,
            _ => ServeFailure::Failed,
        })
    }
}
pub(super) fn complete() -> CleanupStatus {
    CleanupStatus {
        complete: true,
        cleanup_incomplete: false,
        pending_callbacks: 0,
    }
}
fn incomplete() -> CleanupStatus {
    CleanupStatus {
        complete: false,
        cleanup_incomplete: true,
        pending_callbacks: 1,
    }
}
pub(super) async fn callback<T>(
    future: impl Future<Output = Result<T, ServeError>>,
) -> Result<T, ServeError> {
    AssertUnwindSafe(future)
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(ServeError::new(ServeFailure::Failed)))
}

/// Bounded carrier policy input. It grants no authenticated peer identity.
pub struct ServeRequestContext {
    pub method: String,
    pub target: String,
    pub authority: String,
    pub origin: Option<String>,
    pub headers: Vec<(String, Vec<u8>)>,
    pub local_address: std::net::SocketAddr,
    pub remote_address: std::net::SocketAddr,
    pub cancellation: CancellationToken,
}
impl fmt::Debug for ServeRequestContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServeRequestContext { <opaque> }")
    }
}
/// Detached authenticated association. Digests are inspection values, never
/// execution, replay or durable admission authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApplicationBinding {
    pub artifact: [u8; 32],
    pub client_identity: [u8; 32],
    pub server_identity: [u8; 32],
    pub route: [u8; 32],
    pub attempt: [u8; 16],
    pub candidate: [u8; 16],
}
impl fmt::Debug for ApplicationBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicationBinding { <opaque> }")
    }
}
#[derive(Clone)]
pub struct AuthenticatedRequestContext {
    invocation: Arc<Invocation>,
    binding: ApplicationBinding,
}
impl fmt::Debug for AuthenticatedRequestContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedRequestContext { <opaque> }")
    }
}
impl AuthenticatedRequestContext {
    pub fn response_publication(&self) -> crate::ResponsePublication {
        crate::ResponsePublication::not_applicable()
    }
    pub fn maintenance_owner(&self) -> Result<crate::MaintenanceOwner, crate::ServiceError> {
        let services = self.services().ok_or(crate::ServiceError(
            crate::ServiceFailure::ServiceUnavailable,
        ))?;
        services.service_peer().maintenance_owner()
    }
    pub fn binding(&self) -> ApplicationBinding {
        self.binding
    }
    /// Available only after the original Session publication gate succeeds.
    pub fn services(&self) -> Option<AcceptedServices> {
        let state = self.invocation.state.lock().expect("Serve invocation");
        if !state.published || self.invocation.cancel.is_cancelled() {
            return None;
        }
        state.services.clone()
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.invocation.cancel.clone()
    }
    /// Register responsibility immediately when the application reserve
    /// succeeds, including late success. Later cancellation, rejection or a
    /// callback panic cannot discard this original lease. Only one is allowed.
    /// Success records cleanup ownership; it grants no new execution authority.
    pub fn reserve_lease(
        &self,
        binding: ApplicationBinding,
        lease: Arc<dyn ApplicationAuthorizationLease>,
    ) -> Result<(), ServeError> {
        let mut state = self.invocation.state.lock().expect("Serve invocation");
        if binding != self.binding || !state.authorizing || state.lease.is_some() {
            return Err(ServeError::new(ServeFailure::Rejected));
        }
        state.lease = Some(lease);
        drop(state);
        self.invocation.observe_cancellation();
        Ok(())
    }
}
#[async_trait]
pub trait ApplicationAuthorizationLease: fmt::Debug + Send + Sync + 'static {
    /// Burn future use once. Already running application work remains owned.
    fn close(&self);
    /// Observe real cleanup. Incomplete observations may be repeated, serially;
    /// an error is terminal and never authorizes retrying acquisition.
    /// Cleanup must progress after Close independently of Serve's Release call.
    async fn wait_cleanup(&self) -> Result<CleanupStatus, ServeError>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationAuthorization {
    NotStarted,
    Authorized,
    Rejected,
    Unknown,
}
#[derive(Debug)]
pub enum AuthorizeApplicationResult {
    Authorized { handlers: HandlerPlan },
    Rejected,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestAuthorization {
    pub allowed: bool,
}
/// OnSession chooses the single application handoff. Queue transfers to the
/// original ServeHandle::accept queue; Retained means the callback took it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionAcceptance {
    Retained,
    Queue,
    Rejected,
}
#[derive(Clone, Debug)]
pub struct ServeReleaseContext {
    pub authentication: Option<ApplicationBinding>,
    pub authorization: ApplicationAuthorization,
    pub published: bool,
    pub cleanup: CleanupStatus,
}
#[async_trait]
/// Each callback retains its owned work until its future exits. Independently
/// retained application work belongs to the registered lease; an error cleanup
/// snapshot does not register an additional background owner.
pub trait ServeCallbacks: fmt::Debug + Send + Sync + 'static {
    async fn authorize_request(
        &self,
        context: ServeRequestContext,
    ) -> Result<RequestAuthorization, ServeError>;
    async fn resolve_handlers(
        &self,
        context: AuthenticatedRequestContext,
    ) -> Result<HandlerPlan, ServeError>;
    async fn authorize_application(
        &self,
        context: AuthenticatedRequestContext,
        handlers: HandlerPlan,
    ) -> Result<AuthorizeApplicationResult, ServeError>;
    async fn on_session(
        &self,
        session: Session,
        context: AuthenticatedRequestContext,
    ) -> Result<SessionAcceptance, ServeError>;
    /// Invoked exactly once. Keep this future pending until real application
    /// cleanup finishes. An incomplete return or error cannot be confirmed by
    /// calling Release again and retains the original charged responsibility.
    async fn release(&self, context: ServeReleaseContext) -> Result<CleanupStatus, ServeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamAuthorization {
    Accept { receive_window: u64 },
    Reject,
}
#[async_trait]
pub trait RawStreamHandler: fmt::Debug + Send + Sync + std::any::Any + 'static {
    fn message_definition(&self) -> Option<[u8; 32]> {
        None
    }
    /// One original pending OPEN remains responsible for either acceptance or
    /// rejection while a specialized adapter reserves its finite ownership.
    async fn handle_open_with_context(
        &self,
        request: OpenRequest,
        authentication: ApplicationBinding,
        cancel: CancellationToken,
        context: crate::ApplicationInvocationContext,
    ) -> Result<(), ServeError> {
        let metadata = request.metadata().clone();
        let decision = self
            .authorize_with_context(
                authentication,
                metadata.clone(),
                cancel.clone(),
                context.clone(),
            )
            .await?;
        if let StreamAuthorization::Accept { receive_window } = decision {
            let stream = request
                .accept(receive_window)
                .map_err(|_| ServeError::new(ServeFailure::Rejected))?;
            let handled = self
                .handle_with_context(stream.clone(), metadata, cancel, context)
                .await;
            if handled.is_err() || stream.finish().await.is_err() {
                let _ = stream.reset().await;
            }
            handled
        } else {
            let _ = request.reject();
            Ok(())
        }
    }
    /// Context-aware callbacks borrow the actual ordinary invocation. Existing
    /// implementations keep their original callback semantics through defaults.
    async fn authorize_with_context(
        &self,
        authentication: ApplicationBinding,
        metadata: Metadata,
        cancellation: CancellationToken,
        context: crate::ApplicationInvocationContext,
    ) -> Result<StreamAuthorization, ServeError> {
        context
            .check_cancellation()
            .map_err(|_| ServeError::new(ServeFailure::Canceled))?;
        self.authorize(authentication, metadata, cancellation).await
    }
    async fn handle_with_context(
        &self,
        stream: Stream,
        metadata: Metadata,
        cancellation: CancellationToken,
        context: crate::ApplicationInvocationContext,
    ) -> Result<(), ServeError> {
        context
            .check_cancellation()
            .map_err(|_| ServeError::new(ServeFailure::Canceled))?;
        self.handle(stream, metadata, cancellation).await
    }

    async fn authorize(
        &self,
        authentication: ApplicationBinding,
        metadata: Metadata,
        cancellation: CancellationToken,
    ) -> Result<StreamAuthorization, ServeError>;
    async fn handle(
        &self,
        stream: Stream,
        metadata: Metadata,
        cancellation: CancellationToken,
    ) -> Result<(), ServeError>;
}
#[derive(Clone, Debug)]
pub struct RawStreamRegistration {
    pub kind: String,
    pub metadata: Option<RawStreamMetadataContract>,
    pub handler: Arc<dyn RawStreamHandler>,
}
#[derive(Clone, Debug)]
pub enum StreamDispatch {
    /// The application explicitly owns next_open and its bounded requests.
    Manual,
    /// Only frozen registrations may accept inbound raw Streams.
    Registered(Vec<RawStreamRegistration>),
    /// Frozen SDK/business kinds use the dispatcher; all other business kinds
    /// remain in the original bounded pending OPEN slots for next_open.
    Reserved(Vec<RawStreamRegistration>),
}
#[derive(Clone, Debug)]
pub struct HandlerPlanOptions {
    pub streams: StreamDispatch,
    pub application_bytes: u64,
}
struct PlanOwner {
    root: Arc<EnvironmentRoot>,
    options: HandlerPlanOptions,
    services: Option<ServicePlan>,
    maintenance: Option<crate::MaintenanceOwner>,
    closed: AtomicBool,
    _charge: EnvironmentCharge,
}
/// An immutable reusable declaration bound to one Environment. Closing seals
/// future captures; existing Sessions retain their original frozen dispatch.
#[derive(Clone)]
pub struct HandlerPlan(Arc<PlanOwner>);
impl fmt::Debug for HandlerPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HandlerPlan { <opaque> }")
    }
}
impl HandlerPlan {
    pub(crate) fn new(
        root: Arc<EnvironmentRoot>,
        options: HandlerPlanOptions,
    ) -> Result<Self, ServeError> {
        Self::new_with_services(root, options, None, None)
    }
    fn new_with_services(
        root: Arc<EnvironmentRoot>,
        mut options: HandlerPlanOptions,
        services: Option<ServicePlan>,
        maintenance: Option<crate::MaintenanceOwner>,
    ) -> Result<Self, ServeError> {
        if let Some(owner) = &maintenance {
            owner
                .check_root(&root)
                .map_err(|_| ServeError::new(ServeFailure::Closed))?;
        }
        let services = services.map(|plan| plan.capture(&root)).transpose()?;
        if let Some(plan) = services
            .as_ref()
            .filter(|plan| !plan.streaming.is_empty() || !plan.resume.is_empty())
        {
            let registrations = plan
                .streaming
                .iter()
                .map(|entry| entry.service.raw_registration())
                .chain(
                    plan.resume
                        .iter()
                        .map(|entry| entry.service.raw_registration()),
                );
            match &mut options.streams {
                StreamDispatch::Manual => {
                    options.streams = StreamDispatch::Reserved(registrations.collect())
                }
                StreamDispatch::Registered(entries) | StreamDispatch::Reserved(entries) => {
                    entries.extend(registrations)
                }
            }
        }
        if !(256..=1 << 30).contains(&options.application_bytes) {
            return Err(ServeError::new(ServeFailure::Configuration));
        }
        let count = match &options.streams {
            StreamDispatch::Manual => 0,
            StreamDispatch::Registered(entries) | StreamDispatch::Reserved(entries) => {
                entries.len()
            }
        };
        if count > 128 {
            return Err(ServeError::new(ServeFailure::Configuration));
        }
        let service_count = services.as_ref().map_or(0, |plan| {
            plan.unary.len()
                + plan.notifications.len()
                + plan.streaming.len()
                + plan.resume.len()
                + plan
                    .result_read
                    .as_ref()
                    .map_or(0, |read| read.grants.len())
                + plan.management.as_ref().map_or(0, Vec::len)
        });
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: options.application_bytes
                + 4096
                + count as u64 * 16384
                + service_count as u64 * 4096,
            items: 1 + count as u64 + service_count as u64,
            ..ResourceLimits::default()
        })?;
        match &mut options.streams {
            StreamDispatch::Manual => 0,
            StreamDispatch::Registered(entries) | StreamDispatch::Reserved(entries) => {
                if entries.len() > 128 {
                    return Err(ServeError::new(ServeFailure::Configuration));
                }
                let mut kinds = std::collections::BTreeSet::new();
                for entry in entries.iter_mut() {
                    if entry.kind.is_empty()
                        || entry.kind.len() > 128
                        || entry.kind.starts_with("flowersec.")
                        || entry.kind.starts_with("flowersec/")
                        || !kinds.insert(entry.kind.clone())
                    {
                        return Err(ServeError::new(ServeFailure::Configuration));
                    }
                    if let Some(contract) = entry.metadata.take() {
                        entry.metadata = Some(
                            contract
                                .capture()
                                .map_err(|_| ServeError::new(ServeFailure::Configuration))?,
                        );
                    }
                }
                entries.len()
            }
        };
        Ok(Self(Arc::new(PlanOwner {
            root,
            options,
            services,
            maintenance,
            closed: AtomicBool::new(false),
            _charge: charge,
        })))
    }
    /// Capture the complete service directory at handler resolution, before
    /// application authorization and the accepted handshake's irreversible spend.
    pub fn with_services(self, services: ServicePlan) -> Result<Self, ServeError> {
        if self.0.services.is_some() || self.0.closed.load(Ordering::Acquire) {
            return Err(ServeError::new(ServeFailure::Configuration));
        }
        Self::new_with_services(
            self.0.root.clone(),
            self.0.options.clone(),
            Some(services),
            self.0.maintenance.clone(),
        )
    }
    /// Capture the Runtime's finite maintenance observation capability for both
    /// outbound Connect and inbound Serve before method admission.
    pub fn with_maintenance_owner(
        self,
        owner: crate::MaintenanceOwner,
    ) -> Result<Self, ServeError> {
        if self.0.closed.load(Ordering::Acquire) || self.0.maintenance.is_some() {
            return Err(ServeError::new(ServeFailure::Configuration));
        }
        Self::new_with_services(
            self.0.root.clone(),
            self.0.options.clone(),
            self.0.services.clone(),
            Some(owner),
        )
    }
    fn check_restart_maintenance(&self) -> Result<(), ServeError> {
        if self.0.services.as_ref().is_some_and(|plan| {
            plan.unary
                .iter()
                .any(|entry| entry.contract.bool(21).unwrap_or(false))
        }) {
            self.0
                .maintenance
                .as_ref()
                .ok_or(ServeError::new(ServeFailure::Configuration))?
                .check_root(&self.0.root)
                .map_err(|_| ServeError::new(ServeFailure::Closed))?;
        }
        Ok(())
    }
    pub(crate) fn reserve_services(
        &self,
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
    ) -> Result<Option<super::services::PreparedServicePlan>, ServeError> {
        self.check_restart_maintenance()?;
        self.0
            .services
            .as_ref()
            .map(|plan| {
                let mut prepared = plan.reserve(account, profile, identity)?;
                prepared.maintenance = self.0.maintenance.clone();
                Ok(prepared)
            })
            .transpose()
    }
    pub(crate) fn service_preparation_limits(&self) -> Result<Option<ResourceLimits>, ServeError> {
        self.0
            .services
            .as_ref()
            .map(ServicePlan::preparation_limits)
            .transpose()
    }
    pub(crate) fn has_management_plan(&self) -> bool {
        self.0
            .services
            .as_ref()
            .is_some_and(|plan| plan.management.is_some())
    }
    pub(crate) fn reserve_services_prepaid(
        &self,
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        charge: Option<ResourceCharge>,
    ) -> Result<Option<super::services::PreparedServicePlan>, ServeError> {
        self.check_restart_maintenance()?;
        match (&self.0.services, charge) {
            (Some(plan), Some(charge)) => {
                let mut prepared = plan.reserve_prepaid(account, profile, identity, charge)?;
                prepared.maintenance = self.0.maintenance.clone();
                Ok(Some(prepared))
            }
            (None, None) => Ok(None),
            _ => Err(ServeError::new(ServeFailure::Configuration)),
        }
    }
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
    }
    pub(crate) fn bind(&self, session: &Session) {
        session.install_maintenance_owner(self.0.maintenance.clone());
        match &self.0.options.streams {
            StreamDispatch::Registered(_) => session.bind_registered_dispatch(),
            StreamDispatch::Reserved(entries) => session.bind_reserved_dispatch(
                entries
                    .iter()
                    .map(|entry| entry.kind.clone())
                    .collect::<Vec<_>>()
                    .into(),
            ),
            StreamDispatch::Manual => {}
        }
    }
    pub(crate) fn validate_limits(&self, limits: ApplicationLimits) -> Result<(), ServeError> {
        if matches!(
            &self.0.options.streams,
            StreamDispatch::Registered(_) | StreamDispatch::Reserved(_)
        ) && limits.ordinary_callback_bytes < 32768
        {
            return Err(ServeError::new(ServeFailure::Configuration));
        }
        Ok(())
    }
    pub(crate) fn capture(&self, root: &Arc<EnvironmentRoot>) -> Result<Self, ServeError> {
        self.check_restart_maintenance()?;
        if !Arc::ptr_eq(root, &self.0.root)
            || self.0.root.is_closed()
            || self.0.closed.load(Ordering::Acquire)
        {
            return Err(ServeError::new(ServeFailure::Closed));
        }
        Ok(self.clone())
    }
    pub(crate) fn dispatch(
        &self,
        session: Session,
        context: ApplicationBinding,
        lifetime: Arc<ApplicationLifetime>,
    ) {
        if matches!(&self.0.options.streams, StreamDispatch::Manual) {
            return;
        }
        let Ok(dispatcher) = lifetime.enter(CallbackKind::Dispatcher) else {
            return;
        };
        let plan = self.clone();
        tokio::spawn(async move {
            let _dispatcher = dispatcher;
            let cancel = lifetime.cancellation();
            let mut running = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    Some(_) = running.join_next(), if !running.is_empty() => {},
                    request = async {
                        match &plan.0.options.streams {
                            StreamDispatch::Reserved(_) => session.next_reserved_open().await,
                            _ => session.next_registered_open().await,
                        }
                    } => {
                        let Ok(request) = request else { session.close(); break };
                        while running.try_join_next().is_some() {}
                        let entries = match &plan.0.options.streams {
                            StreamDispatch::Registered(entries) | StreamDispatch::Reserved(entries) => entries,
                            StreamDispatch::Manual => unreachable!(),
                        };
                        let Some(entry) = entries.iter().find(|r| r.kind == request.kind()) else { drop(request); continue };
                        if entry.handler.message_definition() != request.metadata().typed_definition() { drop(request); continue; }
                        if entry.metadata.as_ref().is_some_and(|contract| request.metadata().project_raw(contract).is_err()) { drop(request); continue; }
                        if crate::resume_service_v4::is_sdk_resume_handler(entry.handler.as_ref()) {
                            let capacity = session.stream_dispatch_capacity().unwrap_or(0);
                            if running.len() >= capacity { drop(request); continue; }
                            let handler = entry.handler.clone(); let cancel = cancel.clone();
                            running.spawn(async move {
                                let _ = crate::resume_service_v4::handle_sdk_resume_open(handler, request, cancel).await;
                            });
                            continue;
                        }
                        if crate::streaming_service_v4::is_sdk_streaming_handler(entry.handler.as_ref()) {
                            let capacity = session.stream_dispatch_capacity().unwrap_or(0);
                            if running.len() >= capacity { drop(request); continue; }
                            let handler = entry.handler.clone(); let cancel = cancel.clone();
                            running.spawn(async move {
                                let _ = crate::streaming_service_v4::handle_sdk_streaming_open(handler, request, cancel).await;
                            });
                            continue;
                        }
                        let group = lifetime.application_group();
                        let Ok(position) = group.try_ordinary(true, None) else { drop(request); continue };
                        let Ok(guard) = lifetime.enter(CallbackKind::Ordinary) else { drop(request); continue };
                        let handler = entry.handler.clone();
                        let cancel = cancel.clone();
                        running.spawn(async move {
                            let _guard = guard;
                            let Ok(invocation) = position.enter() else { drop(request); return };
                            handle_stream(handler, request, context, cancel, invocation.context()).await;
                            drop(invocation);
                        });
                    }
                }
            }
            // Never abort a still-running application future and declare its
            // budget free. The original guards remain until actual exit.
            while running.join_next().await.is_some() {}
        });
    }
}
async fn handle_stream(
    handler: Arc<dyn RawStreamHandler>,
    request: OpenRequest,
    authentication: ApplicationBinding,
    cancel: CancellationToken,
    context: crate::ApplicationInvocationContext,
) {
    let _ =
        callback(handler.handle_open_with_context(request, authentication, cancel, context)).await;
}

struct InvocationState {
    authentication: Option<ApplicationBinding>,
    authorization: ApplicationAuthorization,
    authorizing: bool,
    lease: Option<Arc<dyn ApplicationAuthorizationLease>>,
    application: Option<Arc<ApplicationLifetime>>,
    services: Option<AcceptedServices>,
    published: bool,
    lease_close_started: bool,
    lease_close_finished: bool,
    lease_close_failed: bool,
}
pub(super) struct Invocation {
    state: Mutex<InvocationState>,
    pub(super) cancel: CancellationToken,
    pub(super) failed_cleanup: AtomicBool,
    pub(super) complete: AtomicBool,
    charge: Mutex<Option<EnvironmentCharge>>,
    runtime: tokio::runtime::Handle,
}
impl Invocation {
    pub(super) fn new(cancel: CancellationToken, charge: EnvironmentCharge) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(InvocationState {
                authentication: None,
                authorization: ApplicationAuthorization::NotStarted,
                authorizing: false,
                lease: None,
                application: None,
                services: None,
                published: false,
                lease_close_started: false,
                lease_close_finished: false,
                lease_close_failed: false,
            }),
            cancel,
            failed_cleanup: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            charge: Mutex::new(Some(charge)),
            runtime: tokio::runtime::Handle::current(),
        })
    }
    pub(super) fn authenticated(
        self: &Arc<Self>,
        binding: ApplicationBinding,
        application: Arc<ApplicationLifetime>,
    ) -> AuthenticatedRequestContext {
        let mut state = self.state.lock().expect("Serve invocation");
        state.authentication = Some(binding);
        state.application = Some(application);
        AuthenticatedRequestContext {
            invocation: self.clone(),
            binding,
        }
    }
    pub(super) fn authorizing(&self) {
        let mut state = self.state.lock().expect("Serve invocation");
        state.authorizing = true;
        state.authorization = ApplicationAuthorization::Unknown;
    }
    pub(super) fn authorized(&self, authorization: ApplicationAuthorization) -> bool {
        let mut state = self.state.lock().expect("Serve invocation");
        state.authorizing = false;
        state.authorization =
            if authorization == ApplicationAuthorization::Authorized && state.lease.is_none() {
                ApplicationAuthorization::Unknown
            } else {
                authorization
            };
        state.lease.is_some()
    }
    pub(super) fn install_services(&self, services: AcceptedServices) -> Result<(), ServeError> {
        let mut state = self.state.lock().expect("Serve invocation");
        if state.published || state.services.is_some() || self.cancel.is_cancelled() {
            drop(state);
            services.close();
            return Err(ServeError::new(ServeFailure::Closed));
        }
        state.services = Some(services);
        Ok(())
    }
    pub(super) fn published(&self) {
        self.state.lock().expect("Serve invocation").published = true;
    }
    pub(super) fn retire(&self) {
        let services = {
            let mut state = self.state.lock().expect("Serve invocation");
            state.application = None;
            state.services.take()
        };
        if let Some(services) = services {
            services.close();
        }
        self.charge.lock().expect("Serve invocation charge").take();
        self.complete.store(true, Ordering::Release);
    }
    pub(super) fn observe_cancellation(self: &Arc<Self>) {
        if self.cancel.is_cancelled() {
            self.revoke();
        }
    }
    pub(super) fn revoke(self: &Arc<Self>) {
        self.cancel.cancel();
        let (claimed, application, services) = {
            let mut state = self.state.lock().expect("Serve invocation");
            let lease = if state.lease_close_started {
                None
            } else {
                state.lease.clone()
            };
            if lease.is_some() {
                state.lease_close_started = true;
            }
            (lease, state.application.clone(), state.services.clone())
        };
        if let Some(services) = services {
            services.close();
        }
        if let Some(application) = &application {
            application.close();
        }
        let Some(lease) = claimed else { return };
        let invocation = self.clone();
        // One prepaid cleanup task, claimed once even by a late reservation.
        // Application code never runs under any SDK admission or drive gate.
        self.runtime.spawn(async move {
            let guard = application.as_ref().map(|a| {
                a.enter(CallbackKind::Cleanup)
                    .expect("original lease close position")
            });
            let failed = std::panic::catch_unwind(AssertUnwindSafe(|| lease.close())).is_err();
            drop(guard);
            let mut state = invocation.state.lock().expect("Serve invocation");
            state.lease_close_failed = failed;
            state.lease_close_finished = true;
            if failed {
                invocation.failed_cleanup.store(true, Ordering::Release);
            }
        });
    }
    pub(super) async fn finish(
        self: &Arc<Self>,
        callbacks: &Arc<dyn ServeCallbacks>,
        mut core: CleanupStatus,
    ) {
        self.revoke();
        self.cancel.cancel();
        let (application, lease, mut context) = {
            let mut state = self.state.lock().expect("Serve invocation");
            state.authorizing = false;
            (
                state.application.clone(),
                state.lease.take(),
                ServeReleaseContext {
                    authentication: state.authentication,
                    authorization: state.authorization,
                    published: state.published,
                    cleanup: core.clone(),
                },
            )
        };
        if let Some(application) = &application {
            application.close();
        }
        // Release observes callbacks that actually left, or a bounded explicit
        // incomplete result. It never waits on its own final Release receipt.
        if let Some(application) = &application {
            loop {
                let status = application.cleanup_status();
                if status.pending_callbacks == 0 {
                    break;
                }
                if !core.complete || status.cleanup_incomplete {
                    core = merge(
                        core,
                        CleanupStatus {
                            complete: false,
                            cleanup_incomplete: true,
                            pending_callbacks: status.pending_callbacks,
                        },
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        let lease_close_failed = loop {
            let observation = {
                let state = self.state.lock().expect("Serve invocation");
                if !state.lease_close_started || state.lease_close_finished {
                    Some(state.lease_close_failed)
                } else {
                    None
                }
            };
            if let Some(failed) = observation {
                break failed;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let release_guard = application.as_ref().map(|a| {
            a.enter(CallbackKind::Cleanup)
                .expect("original Release position")
        });
        let mut lease_complete = lease.is_none();
        let mut lease_failed = lease_close_failed;
        if let Some(lease) = &lease {
            if lease_failed {
                core = merge(core, incomplete());
            } else {
                match callback(lease.wait_cleanup()).await {
                    Ok(status) => {
                        lease_complete = status.complete
                            && !status.cleanup_incomplete
                            && status.pending_callbacks == 0;
                        core = merge(core, status);
                    }
                    Err(_) => {
                        lease_failed = true;
                        core = merge(core, incomplete());
                    }
                }
            }
        }
        context.cleanup = core;
        let release = callback(callbacks.release(context)).await;
        let release_complete = release.is_ok_and(|status| {
            status.complete && !status.cleanup_incomplete && status.pending_callbacks == 0
        });
        if !release_complete || lease_failed {
            self.failed_cleanup.store(true, Ordering::Release);
        }
        // The same original invocation observes the lease; incomplete is not
        // acquisition retry authority and Release is never called twice.
        while !lease_complete && !lease_failed {
            tokio::time::sleep(Duration::from_millis(100)).await;
            match callback(lease.as_ref().expect("original lease").wait_cleanup()).await {
                Ok(status) => {
                    lease_complete = status.complete
                        && !status.cleanup_incomplete
                        && status.pending_callbacks == 0;
                }
                Err(_) => {
                    lease_failed = true;
                    self.failed_cleanup.store(true, Ordering::Release);
                }
            }
        }
        drop(release_guard);
        if let Some(application) = &application {
            application
                .release(release_complete && !lease_failed)
                .expect("one final Release receipt");
        }
        if !release_complete || lease_failed {
            // Terminal unknown ownership cannot be refunded by dropping the
            // worker or slot. No timer, retry or new callback is installed.
            std::future::pending::<()>().await;
        }
    }
}
fn merge(a: CleanupStatus, b: CleanupStatus) -> CleanupStatus {
    CleanupStatus {
        complete: a.complete && b.complete,
        cleanup_incomplete: a.cleanup_incomplete || b.cleanup_incomplete,
        pending_callbacks: a.pending_callbacks.saturating_add(b.pending_callbacks),
    }
}
