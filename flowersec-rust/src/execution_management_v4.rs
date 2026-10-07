//! Fixed SDK history methods on the authenticated reserved M Stream. Local
//! grants map the real Session identity to a principal; request fields never
//! install a grant or select a different history store.
use crate::{
    api_v4::CleanupStatus,
    application_executor_v4::{ApplicationGroup, ApplicationInvocation},
    codec_v4::{self as codec, Limits, Value},
    crypto_v4::{Session, Stream},
    environment_v4::{ApplicationServiceCharge, ResourceAccount, ResourceCharge, ResourceLimits},
    execution_history::{
        ExecutionAbsence, ExecutionCancelResult, ExecutionIdentity, ExecutionManagementResult,
        ExecutionObservation, ExecutionService, ExecutionState, ExecutionTarget,
    },
    operation_reference_v4::{OperationReference, encode_target},
    rpc_wire_v4::{ApplicationHeader, HeaderScalar},
    service_contract::{ServiceError, ServiceFailure},
    transport::ByteStream,
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
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
fn parse<T>(value: codec::Result<T>) -> Result<T> {
    value.map_err(|_| failure(ServiceFailure::Protocol))
}
fn head(bytes: &mut Vec<u8>, major: u8, value: u64) {
    codec::encode_head(bytes, major, value);
}
fn uint(bytes: &mut Vec<u8>, field: u64, value: u64) {
    head(bytes, 0, field);
    head(bytes, 0, value);
}
fn boolean(bytes: &mut Vec<u8>, field: u64, value: bool) {
    head(bytes, 0, field);
    bytes.push(if value { 0xf5 } else { 0xf4 });
}
fn blob(bytes: &mut Vec<u8>, field: u64, value: &[u8]) {
    head(bytes, 0, field);
    head(bytes, 2, value.len() as u64);
    bytes.extend_from_slice(value);
}
const KIND: &str = "flowersec.execution-management.v4";
const ENVELOPE: usize = 1538;

/// Trusted local history access, independent of current business registration.
/// Construct it against the original authenticated Session before attaching it.
#[derive(Clone, Debug)]
pub struct ExecutionHistoryGrant {
    service: ExecutionService,
    principal: ExecutionIdentity,
    peer_identity: [u8; 32],
    query: bool,
    cancel: bool,
    administrator: bool,
}
impl ExecutionHistoryGrant {
    pub fn own_history(
        session: &Session,
        service: ExecutionService,
        principal: ExecutionIdentity,
        query: bool,
        cancel: bool,
    ) -> Result<Self> {
        Self::create(session, service, principal, query, cancel, false)
    }
    /// This is an explicit trusted application policy decision. Administrator
    /// access retains the actual querying principal throughout every gate.
    pub fn administrator(
        session: &Session,
        service: ExecutionService,
        principal: ExecutionIdentity,
        query: bool,
        cancel: bool,
    ) -> Result<Self> {
        Self::create(session, service, principal, query, cancel, true)
    }
    fn create(
        session: &Session,
        service: ExecutionService,
        principal: ExecutionIdentity,
        query: bool,
        cancel: bool,
        administrator: bool,
    ) -> Result<Self> {
        let (_, profile, peer_identity) = session
            .service_identity()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        if profile != 2
            || principal.identity_digest != peer_identity
            || principal.authority == [0; 32]
            || principal.subject.is_empty()
            || principal.subject.len() > 128
            || (!query && !cancel)
            || !session.application_account().belongs_to(&service.0.root)
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok(Self {
            service,
            principal,
            peer_identity,
            query,
            cancel,
            administrator,
        })
    }
    /// Freeze trusted local history policy against the original authenticated
    /// request. Session installation still checks the same peer and Environment.
    pub fn for_authenticated_request(
        context: &crate::AuthenticatedRequestContext,
        service: ExecutionService,
        principal: ExecutionIdentity,
        query: bool,
        cancel: bool,
        administrator: bool,
    ) -> Result<Self> {
        let identity = context.binding().client_identity;
        if principal.identity_digest != identity
            || principal.authority == [0; 32]
            || principal.subject.is_empty()
            || principal.subject.len() > 128
            || (!query && !cancel)
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok(Self {
            service,
            principal,
            peer_identity: identity,
            query,
            cancel,
            administrator,
        })
    }
    pub(crate) fn validate_environment(
        &self,
        root: &Arc<crate::environment_v4::EnvironmentRoot>,
    ) -> Result<()> {
        if !Arc::ptr_eq(root, &self.service.0.root) {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok(())
    }
    pub(crate) fn validate_binding(
        &self,
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
    ) -> Result<()> {
        if profile != 2
            || self.peer_identity != identity
            || self.principal.identity_digest != identity
            || !account.belongs_to(&self.service.0.root)
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok(())
    }
    pub(crate) fn check(
        &self,
        account: &ResourceAccount,
        target: &ExecutionTarget,
        cancel: bool,
    ) -> Result<()> {
        account.check()?;
        let domain = self.service.options();
        if target.tenant != domain.tenant
            || target.audience != domain.audience
            || target.namespace != domain.namespace
            || (!self.administrator
                && (target.caller_authority != self.principal.authority
                    || target.caller_subject != self.principal.subject))
            || if cancel { !self.cancel } else { !self.query }
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok(())
    }
    pub(crate) fn read(
        &self,
        account: &ResourceAccount,
        target: &ExecutionTarget,
        destination: &mut [u8],
    ) -> Result<(usize, Option<u32>)> {
        self.service.read_authorized(
            target,
            &self.principal,
            account,
            self.administrator,
            destination,
            || self.check(account, target, false),
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Method {
    Query,
    Cancel,
}
impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Cancel => "cancel",
        }
    }
    fn request(self) -> &'static str {
        match self {
            Self::Query => "query_operation_request",
            Self::Cancel => "request_cancel_request",
        }
    }
    fn response(self) -> &'static str {
        match self {
            Self::Query => "query_operation_response",
            Self::Cancel => "request_cancel_response",
        }
    }
    fn type_id(self) -> u64 {
        match self {
            Self::Query => 1,
            Self::Cancel => 2,
        }
    }
    fn digest(self) -> Result<[u8; 32]> {
        let value = &codec::application_header_registry()["management"]["methods"][self.name()];
        let hex = value["contract_digest_hex"]
            .as_str()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        if hex.len() != 64 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let mut bytes = [0; 32];
        for (index, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let text = std::str::from_utf8(pair)
                .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?;
            bytes[index] = u8::from_str_radix(text, 16)
                .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?;
        }
        Ok(bytes)
    }
    fn from(header: &ApplicationHeader) -> Result<Self> {
        let method = match header.kind() {
            "query_operation_request" | "query_operation_response" => Self::Query,
            "request_cancel_request" | "request_cancel_response" => Self::Cancel,
            _ => return Err(failure(ServiceFailure::Protocol)),
        };
        if header.uint(2)? != method.type_id()
            || header.bytes(6)? != method.digest()?
            || header.payload_bytes()? > 1024
        {
            return Err(failure(ServiceFailure::Protocol));
        }
        Ok(method)
    }
}
pub(crate) struct ManagementPreparation {
    group: ApplicationGroup,
    charge: ResourceCharge,
    tail: ResourceCharge,
    wait: ResourceCharge,
    io_waits: [ResourceCharge; 3],
    positions: [Arc<ApplicationServiceCharge>; 4],
    stream: Arc<ResourceCharge>,
}
struct Pending {
    diagnostics: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    request: ApplicationHeader,
    submitted: bool,
    response: Option<oneshot::Sender<Result<ExecutionManagementResult>>>,
    _charge: Arc<ResourceCharge>,
}
struct State {
    next: u64,
    outbound: u64,
    highwater: u64,
    preparing: usize,
    pending: BTreeMap<u64, Pending>,
}
struct Output {
    header: ApplicationHeader,
    payload: Zeroizing<Vec<u8>>,
    _charge: Arc<ResourceCharge>,
    invocation: Option<ApplicationInvocation>,
    access: Option<(ExecutionHistoryGrant, ExecutionTarget)>,
    deadline: u64,
    diagnostics: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    diagnostic_failure: Option<ServiceError>,
}
struct Core {
    account: ResourceAccount,
    group: Mutex<Option<ApplicationGroup>>,
    positions: Mutex<Option<[Arc<ApplicationServiceCharge>; 4]>>,
    grants: Mutex<ManagementGrants>,
    session: crate::crypto_v4::SessionLink,
    stream: Mutex<Option<Arc<Stream>>>,
    state: Mutex<State>,
    output: mpsc::Sender<Output>,
    cancellation: CancellationToken,
    workers: AtomicUsize,
    calls: AtomicUsize,
    cleanup_started: AtomicBool,
    cleanup_finished: AtomicBool,
    handles: AtomicUsize,
    changed: Notify,
    closed: AtomicBool,
    unavailable: AtomicBool,
    ready: AtomicBool,
    channel_cancel: Mutex<CancellationToken>,
    charge: Mutex<Option<Arc<ResourceCharge>>>,
    tail: Mutex<Option<crate::application_tails_v4::ApplicationTail>>,
}
struct ManagementGrants {
    configured: bool,
    values: Arc<[ExecutionHistoryGrant]>,
    _charge: Option<ResourceCharge>,
}
impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecutionManagement { <opaque> }")
    }
}
#[derive(Debug)]
pub struct ExecutionManagement(Arc<Core>);
impl Clone for ExecutionManagement {
    fn clone(&self) -> Self {
        self.0.handles.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}
impl Drop for ExecutionManagement {
    fn drop(&mut self) {
        if self.0.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.close();
        }
    }
}
impl ExecutionManagement {
    pub(crate) async fn create(
        session: &Session,
        grants: Vec<ExecutionHistoryGrant>,
    ) -> Result<Self> {
        let management = match session.installed_management() {
            Some(management) => {
                management.configure_grants(session, grants)?;
                management
            }
            None => Self::prepare(session, grants, None)?,
        };
        // Capturing the installed owner does not add a second readiness wait.
        // Query/Cancel carry their own original deadline and cancellation.
        Ok(management)
    }
    fn configure_grants(
        &self,
        session: &Session,
        grants: Vec<ExecutionHistoryGrant>,
    ) -> Result<()> {
        self.0.check_lifetime()?;
        // An empty argument simply captures the original manager. Explicit
        // trusted grants can fill the default deny-all policy once, without
        // replacing its Stream, serials or already captured request authority.
        if grants.is_empty() {
            return Ok(());
        }
        let (_, profile, identity) = session
            .service_identity()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        Self::validate_installation(&self.0.account, profile, identity, &grants)?;
        let mut original = self.0.grants.lock().expect("management grants");
        if original.configured {
            let same = original.values.len() == grants.len()
                && original.values.iter().zip(&grants).all(|(old, new)| {
                    Arc::ptr_eq(&old.service.0, &new.service.0)
                        && old.principal.authority == new.principal.authority
                        && old.principal.subject == new.principal.subject
                        && old.principal.identity_digest == new.principal.identity_digest
                        && old.peer_identity == new.peer_identity
                        && old.query == new.query
                        && old.cancel == new.cancel
                        && old.administrator == new.administrator
                });
            return if same {
                Ok(())
            } else {
                Err(failure(ServiceFailure::ConfigurationCapacity))
            };
        }
        let charge = self.0.account.reserve(ResourceLimits {
            sdk_bytes: grants.len() as u64 * 1024,
            items: grants.len() as u64,
            ..ResourceLimits::default()
        })?;
        self.0.check_lifetime()?;
        original.values = grants.into();
        original.configured = true;
        original._charge = Some(charge);
        Ok(())
    }
    pub(crate) fn prepare_default(
        session: &Session,
        reserved: ManagementPreparation,
    ) -> Result<Self> {
        Self::prepare_inner(session, Vec::new(), false, Some(reserved))
    }
    pub(crate) fn validate_installation(
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        grants: &[ExecutionHistoryGrant],
    ) -> Result<()> {
        if profile != 2
            || grants.len() > 128
            || grants.iter().enumerate().any(|(index, grant)| {
                grants[..index].iter().any(|old| {
                    old.service.options().tenant == grant.service.options().tenant
                        && old.service.options().audience == grant.service.options().audience
                        && old.service.options().namespace == grant.service.options().namespace
                })
            })
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        for grant in grants {
            grant.validate_binding(account, profile, identity)?;
        }
        Ok(())
    }
    pub(crate) fn prepare_installation(
        account: &ResourceAccount,
        role: u8,
        profile: u8,
        identity: [u8; 32],
        grants: &[ExecutionHistoryGrant],
    ) -> Result<ManagementPreparation> {
        let charge = account.reserve(Self::preparation_limits(grants.len(), role)?)?;
        Self::prepare_installation_prepaid(account, role, profile, identity, grants, charge)
    }
    pub(crate) fn preparation_limits(grants: usize, role: u8) -> Result<ResourceLimits> {
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            Self::resources(grants)?,
            crate::application_tails_v4::ApplicationTails::resources(),
        )?;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            ResourceLimits {
                sdk_bytes: if role == 0 { 256 } else { 8192 },
                items: 1,
                work_slots: 1,
                tasks: 1,
                ..ResourceLimits::default()
            },
        )?;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            ApplicationGroup::preparation_limits(),
        )?;
        let limits =
            crate::crypto_v4::connect::candidate_add_limits(limits, Stream::message_wait_limits())?;
        let limits =
            crate::crypto_v4::connect::candidate_add_limits(limits, Stream::message_wait_limits())?;
        let mut limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            Stream::management_publication_limits(),
        )?;
        for _ in 0..4 {
            limits = crate::crypto_v4::connect::candidate_add_limits(
                limits,
                ApplicationGroup::management_position_limits(),
            )?;
        }
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            limits,
            crate::crypto_v4::StreamPreparation::preparation_limits(),
        )?)
    }
    pub(crate) fn prepare_installation_prepaid(
        account: &ResourceAccount,
        role: u8,
        profile: u8,
        identity: [u8; 32],
        grants: &[ExecutionHistoryGrant],
        mut backing: ResourceCharge,
    ) -> Result<ManagementPreparation> {
        Self::validate_installation(account, profile, identity, grants)?;
        if !backing.matches(account, Self::preparation_limits(grants.len(), role)?) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let charge = backing.split(Self::resources(grants.len())?)?;
        let tail = backing.split(crate::application_tails_v4::ApplicationTails::resources())?;
        let wait = backing.split(ResourceLimits {
            sdk_bytes: if role == 0 { 256 } else { 8192 },
            items: 1,
            work_slots: 1,
            tasks: 1,
            ..ResourceLimits::default()
        })?;
        let group_charge = backing.split(ApplicationGroup::preparation_limits())?;
        let io_waits = [
            backing.split(Stream::message_wait_limits())?,
            backing.split(Stream::message_wait_limits())?,
            backing.split(Stream::management_publication_limits())?,
        ];
        let group = account.application_group_prepaid(group_charge)?;
        let positions = [
            group.prepare_management_position(
                backing.split(ApplicationGroup::management_position_limits())?,
            )?,
            group.prepare_management_position(
                backing.split(ApplicationGroup::management_position_limits())?,
            )?,
            group.prepare_management_position(
                backing.split(ApplicationGroup::management_position_limits())?,
            )?,
            group.prepare_management_position(
                backing.split(ApplicationGroup::management_position_limits())?,
            )?,
        ];
        Ok(ManagementPreparation {
            group,
            charge,
            tail,
            wait,
            io_waits,
            positions,
            stream: Arc::new(backing),
        })
    }
    pub(crate) fn prepare(
        session: &Session,
        grants: Vec<ExecutionHistoryGrant>,
        reserved: Option<ManagementPreparation>,
    ) -> Result<Self> {
        Self::prepare_inner(session, grants, true, reserved)
    }
    fn prepare_inner(
        session: &Session,
        grants: Vec<ExecutionHistoryGrant>,
        configured: bool,
        reserved: Option<ManagementPreparation>,
    ) -> Result<Self> {
        let (role, profile, identity) = session
            .service_identity()
            .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
        let account = session.application_account();
        Self::validate_installation(&account, profile, identity, &grants)?;
        let ManagementPreparation {
            group,
            charge,
            tail: tail_charge,
            wait,
            io_waits,
            positions,
            stream: stream_prepared,
        } = match reserved {
            Some(prepared) => prepared,
            None => Self::prepare_installation(&account, role, profile, identity, &grants)?,
        };
        let tail = session
            .application_tail_reserved(tail_charge)
            .map_err(|_| failure(ServiceFailure::Closed))?;
        // Claim before publishing OPEN. Cancellation cannot manufacture another
        // concurrent generation or forget a possibly submitted OPEN.
        session
            .claim_management()
            .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
        let (sender, receiver) = mpsc::channel(4);
        let core = Arc::new(Core {
            account,
            group: Mutex::new(Some(group)),
            positions: Mutex::new(Some(positions)),
            grants: Mutex::new(ManagementGrants {
                configured,
                values: grants.into(),
                _charge: None,
            }),
            session: session.link(),
            stream: Mutex::new(None),
            state: Mutex::new(State {
                next: 1,
                outbound: 0,
                highwater: 0,
                preparing: 0,
                pending: BTreeMap::new(),
            }),
            output: sender,
            cancellation: tail.cancellation(),
            tail: Mutex::new(Some(tail)),
            workers: AtomicUsize::new(1),
            calls: AtomicUsize::new(0),
            cleanup_started: AtomicBool::new(false),
            cleanup_finished: AtomicBool::new(false),
            handles: AtomicUsize::new(1),
            changed: Notify::new(),
            closed: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            channel_cancel: Mutex::new(CancellationToken::new()),
            charge: Mutex::new(Some(Arc::new(charge))),
        });
        // Retain the one manager before its task can publish OPEN or finish.
        // Channel replacements stay inside this owner and reuse its backing.
        let management = Self(core.clone());
        session.retain_management(&management);
        let session = session.clone();
        tokio::spawn(async move {
            let _supervisor = Worker(core.clone());
            run_channels(
                &core,
                session,
                role,
                stream_prepared,
                Arc::new(wait),
                io_waits,
                receiver,
            )
            .await;
            core.close();
        });
        Ok(management)
    }
    pub(crate) fn resources(grants: usize) -> Result<ResourceLimits> {
        if grants > 128 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(ResourceLimits {
            // Two original caller associations, four queued outputs, one
            // writer, at most four admitted/queued store jobs and one parser
            // retain their actual bytes in this fixed pre-READY envelope.
            sdk_bytes: 65536 + grants as u64 * 1024,
            items: grants as u64 + 32,
            tasks: 3,
            timers: 6,
            work_slots: 2,
            ..ResourceLimits::default()
        })
    }
    pub async fn query_operation(
        &self,
        reference: &OperationReference,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionManagementResult> {
        self.call(Method::Query, &reference.target(), timeout_ms, cancellation)
            .await
    }
    pub async fn request_cancel(
        &self,
        reference: &OperationReference,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionManagementResult> {
        self.call(
            Method::Cancel,
            &reference.target(),
            timeout_ms,
            cancellation,
        )
        .await
    }
    async fn call(
        &self,
        method: Method,
        target: &ExecutionTarget,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionManagementResult> {
        target.validate()?;
        self.0.check_lifetime()?;
        let _call = {
            let _state = self.0.state.lock().expect("management associations");
            self.0.check_active()?;
            if self.0.calls.load(Ordering::Acquire) >= 2 {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            self.0.calls.fetch_add(1, Ordering::AcqRel);
            ManagementCall(self.0.clone())
        };
        if timeout_ms == 0 || timeout_ms > 30000 {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let now = self.0.account.security_time()?;
        let deadline = now
            .lower_ms
            .checked_add(timeout_ms)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        if deadline <= now.upper_ms {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let pending_charge = self.0.output_charge()?;
        let mut readiness = {
            let mut state = self.0.state.lock().expect("management associations");
            if state.preparing + state.pending.len() >= 2 {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            state.preparing += 1;
            ReadinessWait {
                core: &self.0,
                active: true,
            }
        };
        // The READY initializer owns the only OPEN/accept task. A first call
        // may race that task, but never opens another channel or restarts its
        // own deadline when the channel becomes usable.
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.0.check_lifetime()?;
            if cancellation.is_cancelled() {
                return Err(failure(ServiceFailure::Canceled));
            }
            let now = self.0.account.security_time()?;
            if now.upper_ms >= deadline {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            if self.0.ready.load(Ordering::Acquire) {
                break;
            }
            let session = self
                .0
                .session
                .session()
                .map_err(|_| failure(ServiceFailure::Closed))?;
            if session.application_draining() {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let session_changed = session.stream_pool_changed();
            let session_changed = session_changed.notified();
            tokio::pin!(session_changed);
            session_changed.as_mut().enable();
            if session.application_draining() {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let remaining = std::time::Duration::from_millis(deadline - now.upper_ms);
            tokio::select! {
                _ = changed => {},
                _ = session_changed => {},
                _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
                _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                _ = self.0.account.security_changed() => {},
                _ = tokio::time::sleep(remaining.min(self.0.account.next_security_check())) => {},
            }
        }
        let mut payload = Zeroizing::new(Vec::with_capacity(1024));
        encode_target(&mut payload, target);
        let mut payload = Some(payload);
        let mut output_charge = Some(self.0.output_charge()?);
        let mut pending_charge = Some(pending_charge);
        let diagnostics = self
            .0
            .account
            .diagnostic_activity(crate::DiagnosticPhase::Application, 1);
        let (send, mut receive) = oneshot::channel();
        let mut send = Some(send);
        let (serial, deadline) = self.0.admit(|drain| {
            self.0.account.with_security_time(|time| {
                let deadline = drain.map_or(deadline, |drain| {
                    deadline.min(
                        time.lower_ms.saturating_add(
                            u64::try_from(
                                drain
                                    .saturating_duration_since(time.monotonic_sample)
                                    .as_millis(),
                            )
                            .unwrap_or(u64::MAX),
                        ),
                    )
                });
                self.0.check_open()?;
                if time.upper_ms >= deadline {
                    return Err(failure(ServiceFailure::DeadlineExceeded));
                }
                if cancellation.is_cancelled() {
                    return Err(failure(ServiceFailure::Canceled));
                }
                let mut state = self.0.state.lock().expect("management associations");
                self.0.check_open()?;
                state.preparing -= 1;
                readiness.active = false;
                if state.pending.len() >= 2 || state.outbound == u64::MAX {
                    return Err(failure(ServiceFailure::ResourceExhausted));
                }
                let serial = state.next;
                state.next = serial
                    .checked_add(1)
                    .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
                let header = request_header(
                    method,
                    serial,
                    deadline,
                    payload.as_ref().expect("original payload").len(),
                )?;
                // The bounded queue accepts complete responsibility, including the
                // first prefix byte. The sole writer retains it through true exit.
                if let Err(rejected) = self.0.output.try_send(Output {
                    header: header.clone(),
                    payload: payload.take().expect("original payload"),
                    _charge: output_charge.take().expect("original output charge"),
                    invocation: None,
                    access: None,
                    deadline,
                    diagnostics: diagnostics.clone(),
                    diagnostic_failure: None,
                }) {
                    // Resource refunds must happen after the original Session and
                    // trusted-time gates unlock, including a full/closed queue.
                    let rejected = rejected.into_inner();
                    payload = Some(rejected.payload);
                    output_charge = Some(rejected._charge);
                    return Err(failure(ServiceFailure::ResourceExhausted));
                }
                state.pending.insert(
                    serial,
                    Pending {
                        diagnostics: diagnostics.clone(),
                        request: header,
                        submitted: false,
                        response: send.take(),
                        _charge: pending_charge.take().expect("original pending charge"),
                    },
                );
                Ok((serial, deadline))
            })?
        })?;
        let _wait = PendingWait {
            core: Arc::downgrade(&self.0),
            serial,
        };
        loop {
            let now = self.0.account.security_time()?;
            if now.upper_ms >= deadline {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            let remaining = std::time::Duration::from_millis(deadline - now.upper_ms);
            tokio::select! {
                response = &mut receive => {
                    self.0.check()?;
                    self.0.admit(|_| Ok(()))?;
                    if self.0.account.security_time()?.upper_ms >= deadline {
                        return Err(failure(ServiceFailure::DeadlineExceeded));
                    }
                    return response.map_err(|_| failure(ServiceFailure::Closed))?;
                },
                _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
                _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                _ = self.0.account.security_changed() => {},
                _ = tokio::time::sleep(remaining.min(self.0.account.next_security_check())) => {},
            }
            self.0.check()?;
            self.0.admit(|_| Ok(()))?;
            if self.0.account.security_time()?.upper_ms >= deadline {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
        }
    }
    pub fn close(&self) {
        self.0.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let workers = self.0.workers.load(Ordering::Acquire);
        let stream = self.0.stream.lock().expect("management stream").clone();
        let stream = stream.as_ref().map(|stream| stream.cleanup_status());
        let calls = self.0.calls.load(Ordering::Acquire);
        let complete = self.0.cleanup_finished.load(Ordering::Acquire)
            && stream.is_none_or(|stream| stream.complete);
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: (workers + calls) as u64,
        }
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
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
// One supervisor owns initialization, each physical retirement, and the finite
// rebuild budget. Calls only wait for this owner; they never allocate Streams.
async fn run_channels(
    core: &Arc<Core>,
    session: Session,
    role: u8,
    stream_backing: Arc<ResourceCharge>,
    wait: Arc<ResourceCharge>,
    io_waits: [ResourceCharge; 3],
    mut receiver: mpsc::Receiver<Output>,
) {
    let mut deadline = Instant::now() + std::time::Duration::from_secs(30);
    // The Stream engine counts actual lifetime allocations (at most 16).
    // A pre-allocation capacity/freeze miss consumes only this episode's
    // original deadline, not an allocation that never happened.
    loop {
        if core.check_lifetime().is_err()
            || session.application_draining()
            || Instant::now() >= deadline
        {
            break;
        }
        if role == 0 && session.management_allocations_exhausted() {
            break;
        }
        let cancellation = core.cancellation.child_token();
        *core
            .channel_cancel
            .lock()
            .expect("management channel cancellation") = cancellation.clone();
        let opening = async {
            if role == 0 {
                session
                    .open_management_stream_prepared(
                        stream_backing.clone(),
                        wait.clone(),
                        &io_waits[2],
                        |stream| {
                            *core.stream.lock().expect("management stream") =
                                Some(Arc::new(stream));
                        },
                    )
                    .await
            } else {
                let request = session.next_service_kind_shared(KIND, wait.clone()).await?;
                let prepared = crate::crypto_v4::StreamPreparation::new_shared(
                    core.account.clone(),
                    stream_backing.clone(),
                )?;
                let stream = request.prepare_stream_reserved(prepared)?;
                // Retain even a failed accept until its actual rejection and
                // provider cleanup have exited, using the same protected slot.
                *core.stream.lock().expect("management stream") = Some(Arc::new(stream.clone()));
                request
                    .accept_prepared_with_publication(stream, 16384, Some(&io_waits[2]))
                    .map(|_| ())
            }
        };
        let changes = session.stream_pool_changed();
        let accepted = {
            tokio::pin!(opening);
            loop {
                let changed = changes.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break false,
                    // A channel accepted before Drain remains eligible for
                    // its fixed management exception during business cleanup.
                    result = &mut opening => break result.is_ok(),
                    _ = tokio::time::sleep_until(deadline) => break false,
                    _ = changed => if session.application_draining() { break false; },
                }
            }
        };
        if accepted && core.check_lifetime().is_ok() {
            let stream = core.stream.lock().expect("management stream").clone();
            if let Some(stream) = stream {
                core.ready.store(true, Ordering::Release);
                core.changed.notify_waiters();
                tokio::join!(
                    async {
                        let _ = read_loop(core, &stream, &io_waits[0], &cancellation).await;
                        core.ready.store(false, Ordering::Release);
                        cancellation.cancel();
                    },
                    async {
                        let _ = write_loop(
                            core,
                            &stream,
                            &io_waits[1],
                            &io_waits[2],
                            &mut receiver,
                            &cancellation,
                        )
                        .await;
                        core.ready.store(false, Ordering::Release);
                        cancellation.cancel();
                    },
                );
            }
        }
        core.ready.store(false, Ordering::Release);
        cancellation.cancel();
        if accepted {
            // Cleanup consumes this rebuild episode's deadline too.
            deadline = Instant::now() + std::time::Duration::from_secs(30);
        }
        if session.application_draining() || (!accepted && Instant::now() >= deadline) {
            core.unavailable.store(true, Ordering::Release);
        }
        core.fail_pending();
        // No old store invocation, publication, or proof reference can survive
        // into another channel. Cleanup is not abandoned when a deadline ends.
        loop {
            let changed = core.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if core.workers.load(Ordering::Acquire) == 1 {
                break;
            }
            changed.await;
        }
        while receiver.try_recv().is_ok() {}
        // Wire serials are channel-local. Local caller identities stay
        // monotonic so a late waiter cannot detach a newer association.
        {
            let mut state = core.state.lock().expect("management associations");
            state.highwater = 0;
            state.outbound = 0;
        }
        let stream = core.stream.lock().expect("management stream").take();
        if let Some(stream) = stream {
            let _ = stream.reset().await;
            while !stream.management_cleanup_complete() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            drop(stream);
        }
        while Arc::strong_count(&stream_backing) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Matching slots belong to the original channel until its proof,
        // provider and worker responsibilities have all actually returned.
        let retired =
            std::mem::take(&mut core.state.lock().expect("management associations").pending);
        drop(retired);
        core.changed.notify_waiters();
        if core.check_lifetime().is_err()
            || session.application_draining()
            || Instant::now() >= deadline
        {
            break;
        }
        tokio::select! {
            _ = core.cancellation.cancelled() => break,
            _ = tokio::time::sleep_until(deadline.min(Instant::now() + std::time::Duration::from_millis(20))) => {},
        }
    }
    if !core.cancellation.is_cancelled() {
        core.unavailable.store(true, Ordering::Release);
        core.changed.notify_waiters();
    }
}
impl Core {
    fn admit<T>(&self, admit: impl FnOnce(Option<Instant>) -> Result<T>) -> Result<T> {
        self.check_open()?;
        let stream = self
            .stream
            .lock()
            .expect("management stream")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
        stream
            .management_admission_gate(admit)
            .map_err(|_| failure(ServiceFailure::Closed))?
    }
    fn check_active(&self) -> Result<()> {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        if self.closed.load(Ordering::Acquire) || self.cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::Closed));
        }
        Ok(())
    }
    fn check_lifetime(&self) -> Result<()> {
        self.check_active()?;
        self.account.check()?;
        Ok(())
    }
    fn check_open(&self) -> Result<()> {
        self.check_active()?;
        if !self.ready.load(Ordering::Acquire)
            || self
                .stream
                .lock()
                .expect("management stream")
                .as_ref()
                .is_some_and(|stream| stream.application_read_ended())
        {
            Err(failure(ServiceFailure::Closed))
        } else {
            Ok(())
        }
    }
    fn check(&self) -> Result<()> {
        self.check_open()?;
        self.account.check()?;
        Ok(())
    }
    async fn wait_request_end(&self, deadline: u64) -> ServiceError {
        loop {
            let stream = self.stream.lock().expect("management stream").clone();
            let Some(stream) = stream else {
                return failure(ServiceFailure::Closed);
            };
            let changed = stream.application_changed();
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Err(error) = self.check().and_then(|()| self.admit(|_| Ok(()))) {
                return error;
            }
            let remaining = match self.account.security_time() {
                Ok(now) if now.upper_ms >= deadline => {
                    return failure(ServiceFailure::DeadlineExceeded);
                }
                Err(error) => return error.into(),
                Ok(now) => std::time::Duration::from_millis(deadline - now.upper_ms),
            };
            tokio::select! {
                _ = self.cancellation.cancelled() => return failure(ServiceFailure::Closed),
                _ = notified => {},
                _ = self.account.security_changed() => {},
                _ = tokio::time::sleep(remaining.min(self.account.next_security_check())) => {},
            }
        }
    }
    fn output_charge(&self) -> Result<Arc<ResourceCharge>> {
        // Queue, caller and admission bounds protect this original shared
        // envelope. Ordinary work cannot consume M's reserved small output.
        self.charge
            .lock()
            .expect("management charge")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::Closed))
    }
    fn management_position(&self) -> Result<crate::application_executor_v4::ManagementAdmission> {
        let charge = self
            .positions
            .lock()
            .expect("management positions")
            .as_ref()
            .and_then(|positions| {
                positions
                    .iter()
                    .find(|charge| Arc::strong_count(charge) == 1)
                    .cloned()
            })
            .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
        self.group
            .lock()
            .expect("management group")
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::Closed))?
            .management(charge)
            .map_err(ServiceError::from)
    }
    fn close(self: &Arc<Self>) {
        self.workers.fetch_add(1, Ordering::AcqRel);
        let _closing = Worker(self.clone());
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancellation.cancel();
        if let Some(group) = self.group.lock().expect("management group").as_ref() {
            group.close();
        }
        self.ready.store(false, Ordering::Release);
        self.channel_cancel
            .lock()
            .expect("management channel cancellation")
            .cancel();
        self.fail_pending();
        self.changed.notify_waiters();
    }
    fn fail_pending(&self) {
        let responses = self
            .state
            .lock()
            .expect("management associations")
            .pending
            .values_mut()
            .filter_map(|pending| {
                pending
                    .response
                    .take()
                    .map(|response| (response, pending.diagnostics.clone()))
            })
            .collect::<Vec<_>>();
        for (response, diagnostics) in responses {
            diagnostics.service_failure(failure(ServiceFailure::Closed));
            let _ = response.send(Err(failure(ServiceFailure::Closed)));
        }
        self.changed.notify_waiters();
    }
    fn grant(&self, target: &ExecutionTarget, cancel: bool) -> Result<ExecutionHistoryGrant> {
        self.check()?;
        let grant = self
            .grants
            .lock()
            .expect("management grants")
            .values
            .iter()
            .find(|grant| {
                let domain = grant.service.options();
                target.tenant == domain.tenant
                    && target.audience == domain.audience
                    && target.namespace == domain.namespace
            })
            .cloned()
            .ok_or_else(|| failure(ServiceFailure::PermissionDenied))?;
        grant.check(&self.account, target, cancel)?;
        Ok(grant)
    }
    fn finish_cleanup(&self) {
        let state = self.state.lock().expect("management associations");
        if !self.closed.load(Ordering::Acquire)
            || self.workers.load(Ordering::Acquire) != 0
            || self.calls.load(Ordering::Acquire) != 0
            || self.cleanup_started.swap(true, Ordering::AcqRel)
        {
            return;
        }
        drop(state);
        self.stream.lock().expect("management stream").take();
        let mut grants = self.grants.lock().expect("management grants");
        grants.values = Arc::from([]);
        grants._charge.take();
        drop(grants);
        self.group.lock().expect("management group").take();
        self.positions.lock().expect("management positions").take();
        self.charge.lock().expect("management charge").take();
        if let Some(tail) = self.tail.lock().expect("management tail").take() {
            tail.finish();
        }
        self.cleanup_finished.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}
struct ManagementCall(Arc<Core>);
impl Drop for ManagementCall {
    fn drop(&mut self) {
        self.0.calls.fetch_sub(1, Ordering::AcqRel);
        self.0.finish_cleanup();
        self.0.changed.notify_waiters();
    }
}
struct PendingWait {
    core: Weak<Core>,
    serial: u64,
}
struct ReadinessWait<'a> {
    core: &'a Core,
    active: bool,
}
impl Drop for ReadinessWait<'_> {
    fn drop(&mut self) {
        if self.active {
            self.core
                .state
                .lock()
                .expect("management associations")
                .preparing -= 1;
        }
    }
}
impl Drop for PendingWait {
    fn drop(&mut self) {
        if let Some(core) = self.core.upgrade() {
            // A canceled caller does not retract bytes already queued or create
            // a new serial slot. The original tombstone survives its response.
            if let Some(pending) = core
                .state
                .lock()
                .expect("management associations")
                .pending
                .get_mut(&self.serial)
            {
                pending.response = None;
            }
        }
    }
}
struct Worker(Arc<Core>);
impl Drop for Worker {
    fn drop(&mut self) {
        if self.0.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.finish_cleanup();
        }
        self.0.changed.notify_waiters();
    }
}
fn request_header(
    method: Method,
    serial: u64,
    deadline: u64,
    length: usize,
) -> Result<ApplicationHeader> {
    let mut fields = [None; 11];
    fields[2] = Some(HeaderScalar::Uint(method.type_id()));
    fields[3] = Some(HeaderScalar::Uint(length as u64));
    fields[5] = Some(HeaderScalar::Uint(deadline));
    fields[6] = Some(HeaderScalar::Bytes(method.digest()?));
    fields[9] = Some(HeaderScalar::Uint(serial));
    ApplicationHeader::create(method.request(), fields)
}
fn response_header(method: Method, serial: u64, length: usize) -> Result<ApplicationHeader> {
    let mut fields = [None; 11];
    fields[2] = Some(HeaderScalar::Uint(method.type_id()));
    fields[3] = Some(HeaderScalar::Uint(length as u64));
    fields[6] = Some(HeaderScalar::Bytes(method.digest()?));
    fields[9] = Some(HeaderScalar::Uint(serial));
    ApplicationHeader::create(method.response(), fields)
}
pub(crate) fn target_decode(payload: &[u8]) -> Result<ExecutionTarget> {
    let value = parse(codec::decode(
        payload,
        "ExecutionManagementTarget",
        Limits {
            bytes: 1024,
            nodes: 20,
        },
        None,
    ))?;
    let string = |name| {
        parse(
            value
                .field("ExecutionManagementTarget", name)
                .and_then(Value::text),
        )
        .map(str::to_owned)
    };
    let target = ExecutionTarget {
        tenant: string("tenant_id")?,
        audience: string("audience")?,
        namespace: string("service_namespace")?,
        caller_subject: string("caller_subject")?,
        caller_authority: parse(value.b("ExecutionManagementTarget", "caller_authority"))?,
        operation_id: parse(value.b("ExecutionManagementTarget", "operation_id"))?,
        request_digest: parse(value.b("ExecutionManagementTarget", "request_digest"))?,
        contract_digest: parse(value.b("ExecutionManagementTarget", "service_contract_digest"))?,
    };
    target.validate()?;
    Ok(target)
}
async fn read_loop(
    core: &Arc<Core>,
    stream: &Arc<Stream>,
    wait: &ResourceCharge,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut wire = Zeroizing::new(Vec::with_capacity(ENVELOPE));
    let mut input = Zeroizing::new([0; ENVELOPE]);
    let mut admitted = None;
    let mut assembly_deadline: Option<Instant> = None;
    let mut request_deadline: Option<u64> = None;
    loop {
        core.check()?;
        let target = if wire.len() < 2 {
            2
        } else {
            let header_length = u16::from_be_bytes([wire[0], wire[1]]) as usize;
            if header_length == 0 || header_length > 512 {
                return Err(failure(ServiceFailure::Protocol));
            }
            let header_end = 2 + header_length;
            if wire.len() < header_end {
                header_end
            } else {
                let header = ApplicationHeader::decode(&wire[2..header_end])?;
                Method::from(&header)?;
                request_deadline = if header.is_response() {
                    let state = core.state.lock().expect("management associations");
                    let serial = header.uint(9)?;
                    if serial == 0 || serial > state.outbound {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    if let Some(pending) = state.pending.values().find(|pending| {
                        pending.submitted && pending.request.uint(9).ok() == Some(serial)
                    }) {
                        header.check_response(&pending.request)?;
                    }
                    // Caller expiry ends result delivery, not this original
                    // bounded matching/assembly owner or another live call.
                    None
                } else {
                    Some(header.uint(5)?)
                };
                if !header.is_response() && admitted.is_none() {
                    let serial = header.uint(9)?;
                    {
                        let mut state = core.state.lock().expect("management associations");
                        if Some(serial) != state.highwater.checked_add(1) {
                            return Err(failure(ServiceFailure::Protocol));
                        }
                        state.highwater = serial;
                    }
                    let now = core.account.security_time()?;
                    if header.uint(5)? > now.lower_ms.saturating_add(30000) {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    // Original header admission owns the finite protected
                    // position and small response before body credit advances.
                    let charge = core.output_charge()?;
                    admitted = Some((
                        core.admit(|_| core.management_position()),
                        charge,
                        core.account
                            .diagnostic_activity(crate::DiagnosticPhase::Application, 1),
                    ));
                }
                let end = header_end + header.payload_bytes()?;
                if wire.len() == end {
                    dispatch(
                        core,
                        header,
                        &wire[header_end..],
                        admitted.take(),
                        cancellation.clone(),
                    )
                    .await?;
                    wire.fill(0);
                    wire.clear();
                    assembly_deadline = None;
                    request_deadline = None;
                    continue;
                }
                end
            }
        };
        let read = {
            let pending = stream.read_rpc_prepared(&mut input[..target - wire.len()], wait);
            tokio::pin!(pending);
            let changed = stream.application_changed();
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let drain = core.admit(Ok)?;
                let deadline = match (assembly_deadline, drain) {
                    (Some(original), Some(drain)) => Some(original.min(drain)),
                    (original, drain) => original.or(drain),
                };
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(failure(ServiceFailure::DeadlineExceeded));
                }
                let security_wait = match request_deadline {
                    Some(deadline) => {
                        let now = core.account.security_time()?;
                        if now.upper_ms >= deadline {
                            return Err(failure(ServiceFailure::DeadlineExceeded));
                        }
                        std::time::Duration::from_millis(deadline - now.upper_ms)
                            .min(core.account.next_security_check())
                    }
                    None => core.account.next_security_check(),
                };
                core.check()?;
                tokio::select! {
                    _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                    value = &mut pending => break value.map_err(|_| failure(ServiceFailure::ServiceUnavailable))?,
                    _ = notified => {},
                    _ = core.account.security_changed() => {},
                    _ = tokio::time::sleep(security_wait) => {},
                    _ = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; } else { std::future::pending::<()>().await; } } => {},
                }
            }
        };
        let count = read.ok_or_else(|| failure(ServiceFailure::Closed))?;
        if count != 0 && assembly_deadline.is_none() {
            assembly_deadline = Some(Instant::now() + std::time::Duration::from_secs(30));
        }
        wire.extend_from_slice(&input[..count]);
        input[..count].fill(0);
    }
}
async fn dispatch(
    core: &Arc<Core>,
    header: ApplicationHeader,
    payload: &[u8],
    admission: Option<(
        Result<crate::application_executor_v4::ManagementAdmission>,
        Arc<ResourceCharge>,
        Arc<crate::diagnostics_v4::DiagnosticActivity>,
    )>,
    cancellation: CancellationToken,
) -> Result<()> {
    let method = Method::from(&header)?;
    let serial = header.uint(9)?;
    if header.is_response() {
        let decoded = decode_response(method, payload);
        if matches!(&decoded, Err(error) if error.0 == ServiceFailure::Protocol) {
            return Err(failure(ServiceFailure::Protocol));
        }
        let pending = {
            let mut state = core.state.lock().expect("management associations");
            if serial == 0 || serial > state.outbound {
                return Err(failure(ServiceFailure::Protocol));
            }
            let local = state.pending.iter().find_map(|(local, pending)| {
                (pending.submitted && pending.request.uint(9).ok() == Some(serial))
                    .then_some(*local)
            });
            local.and_then(|local| state.pending.remove(&local))
        };
        // The channel high-water mark and finite live index classify a fully
        // settled duplicate without retaining unbounded per-serial history.
        let Some(pending) = pending else {
            return Ok(());
        };
        header.check_response(&pending.request)?;
        let result = if core.account.security_time()?.upper_ms >= pending.request.uint(5)? {
            Err(failure(ServiceFailure::DeadlineExceeded))
        } else {
            decoded
        };
        match &result {
            Ok(_) => pending.diagnostics.succeed(),
            Err(error) => pending.diagnostics.service_failure(*error),
        }
        if let Some(response) = pending.response {
            let _ = response.send(result);
        }
        core.changed.notify_waiters();
        return Ok(());
    }
    let target = target_decode(payload)?;
    let original_deadline = header.uint(5)?;
    let deadline = core.admit(|drain| {
        let now = core.account.security_time()?;
        Ok(drain.map_or(original_deadline, |drain| {
            original_deadline.min(
                now.lower_ms.saturating_add(
                    u64::try_from(
                        drain
                            .saturating_duration_since(now.monotonic_sample)
                            .as_millis(),
                    )
                    .unwrap_or(u64::MAX),
                ),
            )
        }))
    })?;
    let (position, charge, diagnostics) =
        admission.ok_or_else(|| failure(ServiceFailure::Protocol))?;
    let position = match position {
        Ok(position) => position,
        Err(error) => {
            let payload = encode_response(method, Err(error));
            let header = response_header(method, serial, payload.len())?;
            core.output
                .try_send(Output {
                    header,
                    payload: Zeroizing::new(payload),
                    _charge: charge,
                    invocation: None,
                    access: None,
                    deadline,
                    diagnostics,
                    diagnostic_failure: Some(error),
                })
                .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
            return Ok(());
        }
    };
    core.workers.fetch_add(1, Ordering::AcqRel);
    let owner = core.clone();
    tokio::spawn(async move {
        let _worker = Worker(owner.clone());
        let invocation = match tokio::select! {
            _ = cancellation.cancelled() => return,
            error = owner.wait_request_end(deadline) => Err(error),
            invocation = position.enter() => invocation.map_err(ServiceError::from),
        } {
            Ok(invocation) => invocation,
            Err(error) => {
                // The original queued position has exited. Publish only its
                // bounded refusal using the already reserved response owner.
                let payload = encode_response(method, Err(error));
                let Ok(header) = response_header(method, serial, payload.len()) else {
                    cancellation.cancel();
                    return;
                };
                let output = Output {
                    header,
                    payload: Zeroizing::new(payload),
                    _charge: charge,
                    invocation: None,
                    access: None,
                    deadline,
                    diagnostics,
                    diagnostic_failure: Some(error),
                };
                tokio::select! {
                    _ = cancellation.cancelled() => {},
                    result = owner.output.send(output) => if result.is_err() { cancellation.cancel(); },
                }
                return;
            }
        };
        let drain = match owner.admit(Ok) {
            Ok(drain) => drain,
            Err(_) => return,
        };
        let stream = owner
            .stream
            .lock()
            .expect("original management store boundary")
            .clone();
        let Some(stream) = stream else {
            return;
        };
        let store_deadline = crate::execution_history::ObservationDeadline {
            upper_ms: deadline,
            drain,
            stream,
        };
        let grant = owner.grant(&target, method == Method::Cancel);
        let outcome = grant.as_ref().map_err(|error| *error).and_then(|grant| {
            if owner.account.security_time()?.upper_ms >= deadline {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            grant.service.observe_authorized(
                &target,
                &grant.principal,
                &owner.account,
                method == Method::Cancel,
                grant.administrator,
                Some(&store_deadline),
                || {
                    owner.check()?;
                    if owner.account.security_time()?.upper_ms >= deadline {
                        return Err(failure(ServiceFailure::DeadlineExceeded));
                    }
                    grant.check(&owner.account, &target, method == Method::Cancel)
                },
            )
        });
        let access = if outcome.is_ok() {
            grant.ok().map(|grant| (grant, target))
        } else {
            None
        };
        let diagnostic_failure = outcome.as_ref().err().copied();
        let payload = encode_response(method, outcome);
        let header = match response_header(method, serial, payload.len()) {
            Ok(header) => header,
            Err(_) => {
                cancellation.cancel();
                return;
            }
        };
        let output = Output {
            header,
            payload: Zeroizing::new(payload),
            _charge: charge,
            invocation: Some(invocation),
            access,
            deadline,
            diagnostics,
            diagnostic_failure,
        };
        tokio::select! {
            _ = cancellation.cancelled() => {},
            response = owner.output.send(output) => if response.is_err() { cancellation.cancel(); },
        }
    });
    Ok(())
}
async fn write_loop(
    core: &Arc<Core>,
    stream: &Arc<Stream>,
    wait: &ResourceCharge,
    publication: &ResourceCharge,
    receiver: &mut mpsc::Receiver<Output>,
    cancellation: &CancellationToken,
) -> Result<()> {
    loop {
        let mut output = tokio::select! { _ = cancellation.cancelled() => break,
        output = receiver.recv() => match output { Some(output) => output, None => break } };
        core.check()?;
        core.admit(|_| Ok(()))?;
        if core.account.security_time()?.upper_ms >= output.deadline {
            if !output.header.is_response() {
                let pending = core
                    .state
                    .lock()
                    .expect("management associations")
                    .pending
                    .remove(&output.header.uint(9)?);
                if let Some(pending) = pending {
                    pending
                        .diagnostics
                        .service_failure(failure(ServiceFailure::DeadlineExceeded));
                    if let Some(response) = pending.response {
                        let _ = response.send(Err(failure(ServiceFailure::DeadlineExceeded)));
                    }
                }
                continue;
            }
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        if let Some((grant, target)) = &output.access {
            grant.check(
                &core.account,
                target,
                output.header.kind() == "request_cancel_response",
            )?;
        }
        let local = if !output.header.is_response() {
            let local = output.header.uint(9)?;
            let mut state = core.state.lock().expect("management associations");
            if state
                .pending
                .get(&local)
                .is_some_and(|pending| pending.response.is_none())
            {
                // An observer that exits before publication leaves no wire
                // serial behind. Release its original local association after
                // unlocking, without sending a canceled store operation.
                let pending = state.pending.remove(&local);
                drop(state);
                drop(pending);
                continue;
            }
            let Some(serial) = state.outbound.checked_add(1) else {
                let pending = state.pending.remove(&local);
                drop(state);
                if let Some(pending) = pending {
                    let error = failure(ServiceFailure::ResourceExhausted);
                    pending.diagnostics.service_failure(error);
                    if let Some(response) = pending.response {
                        let _ = response.send(Err(error));
                    }
                }
                core.changed.notify_waiters();
                // Exhaustion seals new requests in this direction while the
                // same channel continues matching every committed request.
                continue;
            };
            let header = request_header(
                Method::from(&output.header)?,
                serial,
                output.deadline,
                output.payload.len(),
            )?;
            output.header = header;
            Some(local)
        } else {
            None
        };
        let _invocation = &output.invocation;
        let mut header = [0; 512];
        let length = output.header.encode(&mut header)?;
        let mut bytes = Vec::with_capacity(2 + length + output.payload.len());
        bytes.extend_from_slice(&(length as u16).to_be_bytes());
        bytes.extend_from_slice(&header[..length]);
        bytes.extend_from_slice(&output.payload);
        let deadline = output.deadline;
        if let Err((accepted, error)) = stream
            .write_management_prepared(
                &bytes,
                wait,
                publication,
                Some(deadline),
                cancellation,
                || {
                    if let Some((grant, target)) = &output.access {
                        grant
                            .check(
                                &core.account,
                                target,
                                output.header.kind() == "request_cancel_response",
                            )
                            .map_err(|_| crate::SessionError::OperationFailed)?;
                    }
                    if let Some(local) = local {
                        let mut state = core
                            .state
                            .lock()
                            .expect("management publication association");
                        let pending = state
                            .pending
                            .get_mut(&local)
                            .ok_or(crate::SessionError::Closed)?;
                        if !pending.submitted {
                            if pending.response.is_none() {
                                return Err(crate::SessionError::Canceled);
                            }
                            pending.request = output.header.clone();
                            pending.submitted = true;
                            state.outbound = output
                                .header
                                .uint(9)
                                .map_err(|_| crate::SessionError::OperationFailed)?;
                        }
                    }
                    Ok(())
                },
            )
            .await
        {
            if let Some(local) = local {
                let pending = {
                    let mut state = core
                        .state
                        .lock()
                        .expect("management unpublished association");
                    if accepted == 0
                        && state
                            .pending
                            .get(&local)
                            .is_some_and(|pending| !pending.submitted)
                        && matches!(
                            error,
                            crate::SessionError::Canceled | crate::SessionError::Timeout
                        )
                    {
                        state.pending.remove(&local)
                    } else {
                        None
                    }
                };
                if let Some(pending) = pending {
                    let error = failure(if error == crate::SessionError::Timeout {
                        ServiceFailure::DeadlineExceeded
                    } else {
                        ServiceFailure::Canceled
                    });
                    pending.diagnostics.service_failure(error);
                    if let Some(response) = pending.response {
                        let _ = response.send(Err(error));
                    }
                    core.changed.notify_waiters();
                    continue;
                }
            }
            if accepted != 0 {
                let _ = stream.reset().await;
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            return Err(failure(if error == crate::SessionError::Timeout {
                ServiceFailure::DeadlineExceeded
            } else {
                ServiceFailure::ServiceUnavailable
            }));
        }
        if output.header.is_response() {
            if let Some(error) = output.diagnostic_failure {
                output.diagnostics.service_failure(error);
            } else {
                output.diagnostics.succeed();
            }
        }
    }
    let _ = stream.reset().await;
    Ok(())
}
fn encode_response(method: Method, result: Result<ExecutionManagementResult>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(512);
    match result {
        Err(error) => {
            head(&mut bytes, 5, 1);
            uint(
                &mut bytes,
                0,
                match error.0 {
                    ServiceFailure::PermissionDenied => 2,
                    ServiceFailure::OperationConflict => 3,
                    ServiceFailure::DeadlineExceeded => 5,
                    _ => 1,
                },
            );
        }
        Ok(result) => {
            if result.cancellation == Some(ExecutionCancelResult::Unsupported) {
                head(&mut bytes, 5, 1);
                uint(&mut bytes, 0, 4);
                return bytes;
            }
            let cancel = if method == Method::Cancel {
                result.cancellation
            } else {
                None
            };
            head(&mut bytes, 5, 2 + u64::from(cancel.is_some()));
            let status = if method == Method::Query {
                match &result.observation {
                    Some(observation) if observation.result_deleted => 6,
                    Some(_) => 0,
                    None if result.absence == Some(ExecutionAbsence::NotRegistered) => 7,
                    None => 8,
                }
            } else {
                0
            };
            uint(&mut bytes, 0, status);
            head(&mut bytes, 0, 1);
            encode_observation(&mut bytes, &result);
            if let Some(cancel) = cancel {
                uint(
                    &mut bytes,
                    2,
                    match cancel {
                        ExecutionCancelResult::Requested => 0,
                        ExecutionCancelResult::Terminal => 1,
                        ExecutionCancelResult::NotRegistered => 2,
                        ExecutionCancelResult::HistoryUnknown => 3,
                        ExecutionCancelResult::Unsupported => unreachable!(),
                    },
                );
            }
        }
    }
    bytes
}
fn encode_observation(bytes: &mut Vec<u8>, result: &ExecutionManagementResult) {
    let Some(observation) = &result.observation else {
        head(bytes, 5, 2);
        boolean(bytes, 0, false);
        uint(
            bytes,
            1,
            if result.absence == Some(ExecutionAbsence::NotRegistered) {
                5
            } else {
                6
            },
        );
        return;
    };
    head(bytes, 5, 13);
    boolean(bytes, 0, true);
    uint(
        bytes,
        1,
        match observation.error {
            None => 0,
            Some(ServiceFailure::Canceled) => 1,
            Some(ServiceFailure::DeadlineExceeded) => 4,
            _ if observation.state == ExecutionState::Unknown => 3,
            _ => 2,
        },
    );
    uint(
        bytes,
        2,
        match observation.state {
            ExecutionState::Accepted => 1,
            ExecutionState::Executing => 2,
            ExecutionState::Completed => 3,
            ExecutionState::Failed => 4,
            ExecutionState::Unknown => 5,
        },
    );
    boolean(bytes, 3, observation.cancel_requested);
    boolean(bytes, 4, observation.dispatched);
    boolean(bytes, 5, observation.work_active);
    uint(bytes, 6, observation.history_not_before_gc_ms);
    uint(bytes, 7, observation.result_not_after_ms.unwrap_or(0));
    boolean(bytes, 8, observation.result_available);
    boolean(bytes, 9, observation.result_deleted);
    uint(bytes, 10, u64::from(observation.result_bytes));
    uint(
        bytes,
        11,
        u64::from(observation.application_error_code.unwrap_or(0)),
    );
    blob(bytes, 12, &observation.result_digest);
}
fn decode_response(method: Method, payload: &[u8]) -> Result<ExecutionManagementResult> {
    let name = if method == Method::Query {
        "QueryOperationResponse"
    } else {
        "RequestCancelResponse"
    };
    let value = parse(codec::decode(
        payload,
        name,
        Limits {
            bytes: 512,
            nodes: 40,
        },
        None,
    ))?;
    let status = parse(value.u(name, "status"))?;
    let has_observation = status == 0 || method == Method::Query && matches!(status, 6..=8);
    if !has_observation {
        if parse(value.optional(name, "observation"))?.is_some() {
            return Err(failure(ServiceFailure::Protocol));
        }
        return Err(failure(match status {
            2 => ServiceFailure::PermissionDenied,
            3 => ServiceFailure::OperationConflict,
            4 => ServiceFailure::ServiceUnavailable,
            5 => ServiceFailure::DeadlineExceeded,
            _ => ServiceFailure::ServiceUnavailable,
        }));
    }
    let observation = parse(value.field(name, "observation"))?;
    let schema = "ExecutionManagementObservation";
    let found = parse(observation.field(schema, "found").and_then(Value::boolean))?;
    let reason = parse(observation.u(schema, "reason"))?;
    let cancellation = if method == Method::Cancel {
        Some(match parse(value.u(name, "cancel_result"))? {
            0 => ExecutionCancelResult::Requested,
            1 => ExecutionCancelResult::Terminal,
            2 => ExecutionCancelResult::NotRegistered,
            3 => ExecutionCancelResult::HistoryUnknown,
            _ => return Err(failure(ServiceFailure::Protocol)),
        })
    } else {
        None
    };
    if !found {
        if parse(observation.len())? != 2 || !matches!(reason, 5 | 6) {
            return Err(failure(ServiceFailure::Protocol));
        }
        if method == Method::Query && status != reason + 2 {
            return Err(failure(ServiceFailure::Protocol));
        }
        let absence = if reason == 5 {
            ExecutionAbsence::NotRegistered
        } else {
            ExecutionAbsence::HistoryUnknown
        };
        if cancellation.is_some_and(|cancel| {
            cancel
                != if reason == 5 {
                    ExecutionCancelResult::NotRegistered
                } else {
                    ExecutionCancelResult::HistoryUnknown
                }
        }) {
            return Err(failure(ServiceFailure::Protocol));
        }
        return Ok(ExecutionManagementResult {
            observation: None,
            absence: Some(absence),
            cancellation,
        });
    }
    if reason > 4 || method == Method::Query && !matches!(status, 0 | 6) {
        return Err(failure(ServiceFailure::Protocol));
    }
    let flag = |name| parse(observation.field(schema, name).and_then(Value::boolean));
    let optional_uint = |name| -> Result<Option<u64>> {
        let value = parse(observation.u(schema, name))?;
        Ok((value != 0).then_some(value))
    };
    let observation = ExecutionObservation {
        state: match parse(observation.u(schema, "state"))? {
            1 => ExecutionState::Accepted,
            2 => ExecutionState::Executing,
            3 => ExecutionState::Completed,
            4 => ExecutionState::Failed,
            5 => ExecutionState::Unknown,
            _ => return Err(failure(ServiceFailure::Protocol)),
        },
        cancel_requested: flag("cancel_requested")?,
        dispatched: flag("dispatched")?,
        work_active: flag("work_active")?,
        history_not_before_gc_ms: parse(observation.u(schema, "history_not_before_gc_ms"))?,
        result_not_after_ms: optional_uint("result_not_after_ms")?,
        result_available: flag("result_available")?,
        result_deleted: flag("result_deleted")?,
        result_bytes: parse(observation.u(schema, "result_bytes"))? as u32,
        result_digest: parse(observation.b(schema, "result_digest"))?,
        application_error_code: optional_uint("application_error_code")?.map(|value| value as u32),
        error: match reason {
            0 => None,
            1 => Some(ServiceFailure::Canceled),
            4 => Some(ServiceFailure::DeadlineExceeded),
            _ => Some(ServiceFailure::ServiceUnavailable),
        },
    };
    if method == Method::Query && (status == 6) != observation.result_deleted
        || observation.result_available
            && (observation.result_deleted || observation.result_not_after_ms.is_none())
        || cancellation.is_some_and(|cancel| {
            matches!(
                cancel,
                ExecutionCancelResult::NotRegistered | ExecutionCancelResult::HistoryUnknown
            )
        })
    {
        return Err(failure(ServiceFailure::Protocol));
    }
    Ok(ExecutionManagementResult {
        observation: Some(observation),
        absence: None,
        cancellation,
    })
}

#[cfg(test)]
mod response_tests {
    use super::*;

    fn observed(deleted: bool) -> ExecutionManagementResult {
        ExecutionManagementResult {
            observation: Some(ExecutionObservation {
                state: ExecutionState::Completed,
                cancel_requested: false,
                dispatched: true,
                work_active: false,
                history_not_before_gc_ms: 2000,
                result_not_after_ms: Some(1000),
                result_available: !deleted,
                result_deleted: deleted,
                result_bytes: 3,
                result_digest: [7; 32],
                application_error_code: None,
                error: None,
            }),
            absence: None,
            cancellation: None,
        }
    }

    #[test]
    fn query_and_cancel_preserve_observations_across_finite_wire_statuses() {
        let cases = [
            (observed(false), 0),
            (observed(true), 6),
            (
                ExecutionManagementResult {
                    observation: None,
                    absence: Some(ExecutionAbsence::NotRegistered),
                    cancellation: None,
                },
                7,
            ),
            (
                ExecutionManagementResult {
                    observation: None,
                    absence: Some(ExecutionAbsence::HistoryUnknown),
                    cancellation: None,
                },
                8,
            ),
        ];
        for (result, status) in cases {
            let bytes = encode_response(Method::Query, Ok(result.clone()));
            assert_eq!(bytes[2], status);
            assert_eq!(decode_response(Method::Query, &bytes).unwrap(), result);
            let mut wrong_status = bytes.clone();
            wrong_status[2] = if status == 0 { 7 } else { 0 };
            assert_eq!(
                decode_response(Method::Query, &wrong_status).unwrap_err().0,
                ServiceFailure::Protocol
            );

            let mut cancel = result;
            cancel.cancellation = Some(match cancel.absence {
                Some(ExecutionAbsence::NotRegistered) => ExecutionCancelResult::NotRegistered,
                Some(ExecutionAbsence::HistoryUnknown) => ExecutionCancelResult::HistoryUnknown,
                None => ExecutionCancelResult::Terminal,
            });
            let bytes = encode_response(Method::Cancel, Ok(cancel.clone()));
            assert_eq!(bytes[2], 0);
            assert_eq!(decode_response(Method::Cancel, &bytes).unwrap(), cancel);
        }
        let mut running = observed(false);
        let observation = running.observation.as_mut().unwrap();
        observation.state = ExecutionState::Executing;
        observation.work_active = true;
        observation.result_available = false;
        observation.result_not_after_ms = None;
        observation.result_bytes = 0;
        observation.result_digest = [0; 32];
        assert_eq!(
            decode_response(
                Method::Query,
                &encode_response(Method::Query, Ok(running.clone()))
            )
            .unwrap(),
            running
        );
        for method in [Method::Query, Method::Cancel] {
            for code in [
                ServiceFailure::PermissionDenied,
                ServiceFailure::OperationConflict,
                ServiceFailure::DeadlineExceeded,
                ServiceFailure::ServiceUnavailable,
            ] {
                assert_eq!(
                    decode_response(method, &encode_response(method, Err(failure(code))))
                        .unwrap_err()
                        .0,
                    code
                );
            }
        }
    }
}
