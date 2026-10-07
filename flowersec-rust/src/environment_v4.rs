//! Shared resource and security ownership for the current transport runtime.
//! No system wall-clock fallback or caller-supplied authorization grant exists.

use crate::namespace_v4::{
    NamespaceAnchor, NamespaceBinding, NamespaceKey, NamespaceRegistry, PendingNamespaceCandidate,
    SubscriptionId, VerifiedNamespaceHead, VerifiedNamespaceUpdate,
};
use std::{
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EnvironmentError {
    #[error("Flowersec environment configuration is invalid")]
    Configuration,
    #[error("Flowersec environment resource capacity is exhausted")]
    Capacity,
    #[error("Flowersec environment is closed")]
    Closed,
    #[error("Flowersec trusted time is unavailable")]
    TimeUnavailable,
    #[error("Flowersec trusted time has not proved the required lower bound")]
    TimePending,
    #[error("Flowersec trusted time was not proven within the original wait window")]
    TimeNotProven,
    #[error("Flowersec signed issuance is later than the trusted time upper bound")]
    FutureTimestamp,
    #[error("Flowersec original bootstrap acquisition window expired")]
    BootstrapDeadline,
    #[error("Flowersec signed namespace material expired")]
    MaterialExpired,
    #[error("Flowersec authorization is no longer valid")]
    AuthorizationDenied,
}

/// Every dimension is checked and transferred atomically at the original root,
/// tenant and Session accounts. Provider/disk memory cannot spend SDK bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceLimits {
    pub sdk_bytes: u64,
    pub provider_bytes: u64,
    pub disk_bytes: u64,
    pub items: u64,
    pub work_slots: u64,
    pub tasks: u64,
    pub timers: u64,
    pub connections: u64,
    pub tls_handshakes: u64,
    pub sessions: u64,
    pub native_handles: u64,
}
impl ResourceLimits {
    pub const DIMENSIONS: [&'static str; 11] = [
        "sdk_bytes",
        "provider_bytes",
        "disk_bytes",
        "items",
        "work_slots",
        "tasks",
        "timers",
        "connections",
        "tls_handshakes",
        "sessions",
        "native_handles",
    ];
    pub fn values(self) -> [u64; 11] {
        [
            self.sdk_bytes,
            self.provider_bytes,
            self.disk_bytes,
            self.items,
            self.work_slots,
            self.tasks,
            self.timers,
            self.connections,
            self.tls_handshakes,
            self.sessions,
            self.native_handles,
        ]
    }
    fn checked_add(self, rhs: Self) -> Option<Self> {
        Some(Self {
            sdk_bytes: self.sdk_bytes.checked_add(rhs.sdk_bytes)?,
            provider_bytes: self.provider_bytes.checked_add(rhs.provider_bytes)?,
            disk_bytes: self.disk_bytes.checked_add(rhs.disk_bytes)?,
            items: self.items.checked_add(rhs.items)?,
            work_slots: self.work_slots.checked_add(rhs.work_slots)?,
            tasks: self.tasks.checked_add(rhs.tasks)?,
            timers: self.timers.checked_add(rhs.timers)?,
            connections: self.connections.checked_add(rhs.connections)?,
            tls_handshakes: self.tls_handshakes.checked_add(rhs.tls_handshakes)?,
            sessions: self.sessions.checked_add(rhs.sessions)?,
            native_handles: self.native_handles.checked_add(rhs.native_handles)?,
        })
    }
    fn fits(self, cap: Self) -> bool {
        self.values()
            .into_iter()
            .zip(cap.values())
            .all(|(value, limit)| value <= limit)
    }
    fn subtract(&mut self, rhs: Self) {
        self.sdk_bytes = self
            .sdk_bytes
            .checked_sub(rhs.sdk_bytes)
            .expect("original resource charge");
        self.provider_bytes = self
            .provider_bytes
            .checked_sub(rhs.provider_bytes)
            .expect("original resource charge");
        self.disk_bytes = self
            .disk_bytes
            .checked_sub(rhs.disk_bytes)
            .expect("original resource charge");
        self.items = self
            .items
            .checked_sub(rhs.items)
            .expect("original resource charge");
        self.work_slots = self
            .work_slots
            .checked_sub(rhs.work_slots)
            .expect("original resource charge");
        self.tasks = self
            .tasks
            .checked_sub(rhs.tasks)
            .expect("original resource charge");
        self.timers = self
            .timers
            .checked_sub(rhs.timers)
            .expect("original resource charge");
        self.connections = self
            .connections
            .checked_sub(rhs.connections)
            .expect("original resource charge");
        self.tls_handshakes = self
            .tls_handshakes
            .checked_sub(rhs.tls_handshakes)
            .expect("original resource charge");
        self.sessions = self
            .sessions
            .checked_sub(rhs.sessions)
            .expect("original resource charge");
        self.native_handles = self
            .native_handles
            .checked_sub(rhs.native_handles)
            .expect("original resource charge");
    }
}

/// Explicit deployment policy for the authenticated Session maintenance path.
/// No automatic sample runs unless this policy is supplied at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomaticLivenessPolicy {
    pub interval_ms: u64,
    pub submission_ms: u64,
    pub response_ms: u64,
    pub miss_threshold: u32,
}
impl AutomaticLivenessPolicy {
    pub(crate) fn validate(self, profile: TrustedTimeProfile) -> Result<(), EnvironmentError> {
        let total = self
            .submission_ms
            .checked_add(self.response_ms)
            .ok_or(EnvironmentError::Configuration)?;
        if self.miss_threshold == 0 {
            return Err(EnvironmentError::Configuration);
        }
        for duration in [
            self.interval_ms,
            self.submission_ms,
            self.response_ms,
            total,
        ] {
            if duration <= profile.elapsed(Duration::ZERO)?.1 {
                return Err(EnvironmentError::Configuration);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TransportEnvironmentOptions {
    pub application_executor: crate::application_profile_v4::ApplicationExecutorConfig,
    /// Optional detailed production observations on an independent bounded lane.
    pub diagnostics: Option<crate::DiagnosticSinkConfiguration>,
    pub root_limits: ResourceLimits,
    pub tenant_limits: ResourceLimits,
    pub session_limits: ResourceLimits,
    pub max_tenants: u16,
    pub max_sessions: u16,
    pub max_results: u16,
    pub max_namespaces: u16,
    pub max_namespace_subscribers: u16,
    pub max_namespace_state_bytes: u32,
    pub clock: Option<Arc<dyn TrustedTimeSource>>,
    pub time_profile: TrustedTimeProfile,
    pub automatic_liveness: Option<AutomaticLivenessPolicy>,
}
impl Default for TransportEnvironmentOptions {
    fn default() -> Self {
        Self {
            application_executor: crate::application_profile_v4::ApplicationExecutorConfig::default(
            ),
            root_limits: ResourceLimits {
                sdk_bytes: 67108864,
                provider_bytes: 134217728,
                disk_bytes: 268435456,
                items: 65536,
                work_slots: 4096,
                tasks: 4096,
                timers: 32768,
                connections: 64,
                tls_handshakes: 16,
                sessions: 32,
                native_handles: 256,
            },
            tenant_limits: ResourceLimits {
                sdk_bytes: 16777216,
                provider_bytes: 33554432,
                disk_bytes: 67108864,
                items: 32768,
                work_slots: 1024,
                tasks: 1024,
                timers: 8192,
                connections: 16,
                tls_handshakes: 8,
                sessions: 8,
                native_handles: 64,
            },
            session_limits: ResourceLimits {
                sdk_bytes: 2097152,
                provider_bytes: 8388608,
                disk_bytes: 0,
                items: 8192,
                work_slots: 128,
                tasks: 128,
                timers: 2048,
                connections: 1,
                tls_handshakes: 1,
                sessions: 1,
                native_handles: 16,
            },
            max_tenants: 16,
            max_sessions: 32,
            max_results: 4096,
            max_namespaces: 8,
            max_namespace_subscribers: 1024,
            max_namespace_state_bytes: 1 << 20,
            clock: None,
            time_profile: TrustedTimeProfile::default(),
            automatic_liveness: None,
            diagnostics: None,
        }
    }
}

/// The explicitly trusted host source authenticates its original time evidence.
/// Samples use the native monotonic clock covered by the configured rate and
/// suspension model; returning a plausible wall-clock value is insufficient.
pub trait TrustedTimeSource: fmt::Debug + Send + Sync + 'static {
    fn sample(&self) -> Result<TrustedTimeSample, EnvironmentError>;
}
#[derive(Clone, Copy, Debug)]
pub struct TrustedTimeSample {
    pub lower_ms: u64,
    pub upper_ms: u64,
    pub monotonic_sample: Instant,
    pub clock_incarnation: u64,
    pub anchor_age_upper_ms: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct TrustedTimeProfile {
    pub rate_numerator: u64,
    pub rate_denominator: u64,
    pub quantization_ms: u64,
    pub max_width_ms: u64,
    pub max_anchor_age_ms: u64,
}
impl Default for TrustedTimeProfile {
    fn default() -> Self {
        Self {
            rate_numerator: 1,
            rate_denominator: 10_000,
            quantization_ms: 1,
            max_width_ms: 2_000,
            max_anchor_age_ms: 60_000,
        }
    }
}
impl TrustedTimeProfile {
    fn validate(self) -> Result<(), EnvironmentError> {
        if self.rate_denominator == 0
            || self.rate_numerator >= self.rate_denominator
            || self.max_width_ms == 0
            || self.max_anchor_age_ms == 0
        {
            return Err(EnvironmentError::Configuration);
        }
        Ok(())
    }
    pub(crate) fn elapsed(self, delta: Duration) -> Result<(u64, u64), EnvironmentError> {
        let floor =
            u64::try_from(delta.as_millis()).map_err(|_| EnvironmentError::TimeUnavailable)?;
        let ceil = floor
            .checked_add(u64::from(!delta.subsec_nanos().is_multiple_of(1_000_000)))
            .ok_or(EnvironmentError::TimeUnavailable)?;
        let denominator = u128::from(self.rate_denominator);
        let numerator = u128::from(self.rate_numerator);
        let lo = u128::from(floor.saturating_sub(self.quantization_ms)) * denominator
            / (denominator + numerator);
        let hi = u128::from(
            ceil.checked_add(self.quantization_ms)
                .ok_or(EnvironmentError::TimeUnavailable)?,
        ) * denominator;
        Ok((
            u64::try_from(lo).map_err(|_| EnvironmentError::TimeUnavailable)?,
            u64::try_from(hi.div_ceil(denominator - numerator))
                .map_err(|_| EnvironmentError::TimeUnavailable)?,
        ))
    }
    pub(crate) fn project(
        self,
        sample: TrustedTimeSample,
        now: Instant,
    ) -> Result<TrustedTimeSample, EnvironmentError> {
        if sample.clock_incarnation == 0 || sample.lower_ms > sample.upper_ms {
            return Err(EnvironmentError::TimeUnavailable);
        }
        let delta = now
            .checked_duration_since(sample.monotonic_sample)
            .ok_or(EnvironmentError::TimeUnavailable)?;
        let (lo, hi) = self.elapsed(delta)?;
        let value = TrustedTimeSample {
            lower_ms: sample
                .lower_ms
                .checked_add(lo)
                .ok_or(EnvironmentError::TimeUnavailable)?,
            upper_ms: sample
                .upper_ms
                .checked_add(hi)
                .ok_or(EnvironmentError::TimeUnavailable)?,
            monotonic_sample: now,
            clock_incarnation: sample.clock_incarnation,
            anchor_age_upper_ms: sample
                .anchor_age_upper_ms
                .checked_add(hi)
                .ok_or(EnvironmentError::TimeUnavailable)?,
        };
        if value.upper_ms - value.lower_ms > self.max_width_ms
            || value.anchor_age_upper_ms > self.max_anchor_age_ms
        {
            return Err(EnvironmentError::TimeUnavailable);
        }
        Ok(value)
    }
}

#[derive(Debug)]
struct AccountSlot {
    generation: u64,
    parent: usize,
    limit: ResourceLimits,
    used: ResourceLimits,
    references: usize,
    active: bool,
    closed: bool,
    tenant_key: Option<[u8; 32]>,
    authorization: Option<AuthorizationBounds>,
    authorization_deadline: Option<Instant>,
    security_closed: Option<Arc<AtomicBool>>,
    attached_session: Option<usize>,
    is_result: bool,
}
impl AccountSlot {
    fn empty() -> Self {
        Self {
            generation: 0,
            parent: 0,
            limit: ResourceLimits::default(),
            used: ResourceLimits::default(),
            references: 0,
            active: false,
            closed: false,
            tenant_key: None,
            authorization: None,
            authorization_deadline: None,
            security_closed: None,
            attached_session: None,
            is_result: false,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthorizationBounds {
    pub(crate) not_before_ms: u64,
    pub(crate) not_after_ms: u64,
    pub(crate) freshness_not_after_ms: u64,
}
#[derive(Debug)]
pub(crate) struct EnvironmentRoot {
    state: Mutex<RootState>,
    options: TransportEnvironmentOptions,
    pub(crate) changed: Notify,
    pool_backings: Mutex<Vec<Arc<crate::pool_v4::Backing>>>,
    pool_stores: Mutex<Vec<Weak<crate::pool_v4::SQLitePoolStore>>>,
    execution_services: Mutex<Vec<Arc<crate::execution_history::HistoryOwner>>>,
    reference_stores: Mutex<Vec<Arc<crate::sqlite_reference_store_v4::ReferenceOwner>>>,
    execution_stores: Mutex<Vec<Arc<crate::sqlite_execution_store_v4::ExecutionStoreOwner>>>,
    application_service: Mutex<Weak<crate::application_executor_v4::ApplicationServices>>,
    material_controllers: Mutex<Vec<Weak<crate::connection_controller_v4::Owner>>>,
    material_sources: Mutex<Vec<Weak<crate::material_source_v4::Owner>>>,
    diagnostic_sinks: Mutex<Vec<Weak<crate::diagnostics_v4::Inner>>>,
    production_diagnostics: Mutex<Option<crate::DiagnosticSink>>,
    diagnostic_counters: Arc<crate::diagnostics_v4::DiagnosticCounters>,
    cleanup_timeout_reported: AtomicBool,
}
#[derive(Debug)]
struct RootState {
    accounts: Vec<AccountSlot>,
    closed: bool,
    close_deadline: Option<Instant>,
    clock_sample: Option<TrustedTimeSample>,
    namespaces: NamespaceRegistry,
}
#[derive(Clone, Debug)]
pub(crate) struct ResourceAccount {
    root: Arc<EnvironmentRoot>,
    index: usize,
    generation: u64,
    _lease: Arc<AccountLease>,
}
#[derive(Debug)]
struct AccountLease {
    root: Arc<EnvironmentRoot>,
    index: usize,
    generation: u64,
    source: Mutex<Option<ResourceAccount>>,
    subscriptions: Mutex<Option<Arc<NamespaceSubscriptions>>>,
    business_work: AtomicUsize,
}
#[derive(Debug)]
// Candidate namespace closures contain at most eight references. These fixed
// positions are included in the Environment account backing prepayment.
struct NamespaceSubscriptions {
    root: Arc<EnvironmentRoot>,
    ids: [Option<SubscriptionId>; 8],
    wakes: [Option<Arc<Notify>>; 8],
}
impl Drop for NamespaceSubscriptions {
    fn drop(&mut self) {
        let mut state = self.root.state.lock().expect("environment root lock");
        for id in self.ids.into_iter().flatten() {
            state.namespaces.release(id);
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct WeakResourceAccount {
    root: Weak<EnvironmentRoot>,
    index: usize,
    generation: u64,
    lease: Weak<AccountLease>,
}
impl WeakResourceAccount {
    pub(crate) fn upgrade(&self) -> Option<ResourceAccount> {
        Some(ResourceAccount {
            root: self.root.upgrade()?,
            index: self.index,
            generation: self.generation,
            _lease: self.lease.upgrade()?,
        })
    }
}
fn account_chain(state: &RootState, index: usize) -> [Option<usize>; 4] {
    [
        Some(0),
        Some(state.accounts[index].parent),
        Some(index),
        state.accounts[index].attached_session,
    ]
}
impl Drop for AccountLease {
    fn drop(&mut self) {
        let mut state = self.root.state.lock().expect("environment root lock");
        let parent = state.accounts[self.index].parent;
        assert_eq!(state.accounts[self.index].generation, self.generation);
        let sessions = u64::from(!state.accounts[self.index].is_result);
        for i in account_chain(&state, self.index).into_iter().flatten() {
            state.accounts[i].used.sessions -= sessions;
            state.accounts[i].references -= 1;
        }
        state.accounts[self.index].active = false;
        if state.accounts[parent].references == 0 {
            state.accounts[parent].active = false;
            state.accounts[parent].tenant_key = None;
        }
        drop(state);
        self.root.changed.notify_waiters();
    }
}
#[derive(Debug)]
pub(crate) struct ResourceCharge {
    account: ResourceAccount,
    value: ResourceLimits,
}
#[derive(Debug)]
pub(crate) struct EnvironmentCharge {
    root: Arc<EnvironmentRoot>,
    value: ResourceLimits,
    transferred: bool,
}
impl EnvironmentCharge {
    /// Reduce the original root reservation to its verified exact geometry.
    /// The retained dimensions never leave the original reservation and are
    /// not reacquired, so another owner cannot consume them between stages.
    pub(crate) fn shrink_to(&mut self, value: ResourceLimits) -> Result<(), EnvironmentError> {
        if self.transferred || !value.fits(self.value) {
            return Err(EnvironmentError::Configuration);
        }
        let mut released = self.value;
        released.subtract(value);
        let mut state = self
            .root
            .state
            .lock()
            .expect("original backing contraction");
        state.accounts[0].used.subtract(released);
        self.value = value;
        drop(state);
        self.root.changed.notify_waiters();
        Ok(())
    }
    /// Replace speculative preauth backing with the exact original account
    /// reservation made before native preparation. The physical owner keeps
    /// that reservation; only duplicate root prepayment is removed here.
    pub(crate) fn attach_prepaid(
        &mut self,
        account: &ResourceAccount,
        prepaid: ResourceCharge,
    ) -> Result<ResourceCharge, EnvironmentError> {
        if self.transferred
            || !Arc::ptr_eq(&self.root, &account.root)
            || !Arc::ptr_eq(&prepaid.account.root, &account.root)
            || prepaid.account.index != account.index
            || prepaid.account.generation != account.generation
            || !self.value.fits(prepaid.value)
            || !prepaid.value.fits(self.value)
        {
            return Err(EnvironmentError::Configuration);
        }
        let sample = self.root.sample()?;
        let mut state = self
            .root
            .state
            .lock()
            .expect("original prepared backing transfer");
        account.validate_locked(&mut state, sample)?;
        state.accounts[0].used.subtract(self.value);
        state.accounts[0].references -= 1;
        self.transferred = true;
        drop(state);
        self.root.changed.notify_waiters();
        Ok(prepaid)
    }
    /// Transfer actual preauth backing into the authenticated tenant/Session
    /// chain without refunding or reacquiring its existing root charge.
    pub(crate) fn attach(
        &mut self,
        account: &ResourceAccount,
    ) -> Result<ResourceCharge, EnvironmentError> {
        if self.transferred || !Arc::ptr_eq(&self.root, &account.root) {
            return Err(EnvironmentError::Configuration);
        }
        let sample = self.root.sample()?;
        let mut state = self.root.state.lock().expect("preauth charge transfer");
        let chain = account.validate_locked(&mut state, sample)?;
        for i in chain.into_iter().flatten().filter(|i| *i != 0) {
            state.accounts[i]
                .used
                .checked_add(self.value)
                .filter(|v| v.fits(state.accounts[i].limit))
                .ok_or(EnvironmentError::Capacity)?;
            state.accounts[i]
                .references
                .checked_add(1)
                .ok_or(EnvironmentError::Capacity)?;
        }
        for i in chain.into_iter().flatten().filter(|i| *i != 0) {
            state.accounts[i].used = state.accounts[i]
                .used
                .checked_add(self.value)
                .expect("checked transfer");
            state.accounts[i].references += 1;
        }
        self.transferred = true;
        Ok(ResourceCharge {
            account: account.clone(),
            value: self.value,
        })
    }
}
impl Drop for EnvironmentCharge {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        let mut state = self.root.state.lock().expect("environment root lock");
        state.accounts[0].used.subtract(self.value);
        state.accounts[0].references -= 1;
        drop(state);
        self.root.changed.notify_waiters();
    }
}
#[derive(Debug)]
pub(crate) struct ApplicationServiceBacking {
    physical: EnvironmentCharge,
}
#[derive(Debug)]
pub(crate) struct ApplicationServiceCharge {
    account: Option<ResourceAccount>,
    value: ResourceLimits,
    _backing: Arc<ApplicationServiceBacking>,
}
impl ApplicationServiceBacking {
    pub(crate) fn new(
        root: &Arc<EnvironmentRoot>,
        value: ResourceLimits,
    ) -> Result<Arc<Self>, EnvironmentError> {
        Ok(Arc::new(Self {
            physical: root.reserve_environment(value)?,
        }))
    }
    pub(crate) fn borrow(
        self: &Arc<Self>,
        account: &ResourceAccount,
        value: ResourceLimits,
    ) -> Result<ApplicationServiceCharge, EnvironmentError> {
        if !Arc::ptr_eq(&self.physical.root, &account.root) || !value.fits(self.physical.value) {
            return Err(EnvironmentError::Configuration);
        }
        let sample = account.root.sample()?;
        let mut state = account
            .root
            .state
            .lock()
            .expect("application service attachment");
        let chain = account.validate_locked(&mut state, sample)?;
        for index in chain.into_iter().flatten().filter(|index| *index != 0) {
            state.accounts[index]
                .used
                .checked_add(value)
                .filter(|used| used.fits(state.accounts[index].limit))
                .ok_or(EnvironmentError::Capacity)?;
            state.accounts[index]
                .references
                .checked_add(1)
                .ok_or(EnvironmentError::Capacity)?;
        }
        for index in chain.into_iter().flatten().filter(|index| *index != 0) {
            state.accounts[index].used = state.accounts[index]
                .used
                .checked_add(value)
                .expect("checked service attachment");
            state.accounts[index].references += 1;
        }
        drop(state);
        Ok(ApplicationServiceCharge {
            account: Some(account.clone()),
            value,
            _backing: self.clone(),
        })
    }
    /// Local metadata callbacks borrow the same prepaid executor capacity,
    /// without creating an authenticated Session or granting network authority.
    pub(crate) fn borrow_local(
        self: &Arc<Self>,
        root: &Arc<EnvironmentRoot>,
        value: ResourceLimits,
    ) -> Result<ApplicationServiceCharge, EnvironmentError> {
        if !Arc::ptr_eq(&self.physical.root, root) || !value.fits(self.physical.value) {
            return Err(EnvironmentError::Configuration);
        }
        if root.is_closed() {
            return Err(EnvironmentError::Closed);
        }
        Ok(ApplicationServiceCharge {
            account: None,
            value,
            _backing: self.clone(),
        })
    }
    pub(crate) fn attach_prepaid(
        self: &Arc<Self>,
        account: &ResourceAccount,
        mut prepaid: ResourceCharge,
    ) -> Result<ApplicationServiceCharge, EnvironmentError> {
        let value = prepaid.value;
        if !prepaid.belongs_to(account)
            || !Arc::ptr_eq(&self.physical.root, &account.root)
            || !value.fits(self.physical.value)
        {
            return Err(EnvironmentError::Configuration);
        }
        let sample = account.root.sample()?;
        let mut state = account
            .root
            .state
            .lock()
            .expect("prepaid service attachment");
        let chain = account.validate_locked(&mut state, sample)?;
        for index in chain.into_iter().flatten().filter(|index| *index != 0) {
            state.accounts[index]
                .references
                .checked_add(1)
                .ok_or(EnvironmentError::Capacity)?;
        }
        for index in chain.into_iter().flatten().filter(|index| *index != 0) {
            state.accounts[index].references += 1;
        }
        state.accounts[0].used.subtract(value);
        prepaid.value = ResourceLimits::default();
        drop(state);
        drop(prepaid);
        Ok(ApplicationServiceCharge {
            account: Some(account.clone()),
            value,
            _backing: self.clone(),
        })
    }
}
impl ApplicationServiceCharge {
    pub(crate) fn matches(&self, account: &ResourceAccount, value: ResourceLimits) -> bool {
        self.account
            .as_ref()
            .is_some_and(|owner| owner.same_owner(account))
            && self.value.fits(value)
            && value.fits(self.value)
    }
}
impl Drop for ApplicationServiceCharge {
    fn drop(&mut self) {
        let Some(account) = &self.account else { return };
        let mut state = account
            .root
            .state
            .lock()
            .expect("application service return");
        assert_eq!(state.accounts[account.index].generation, account.generation);
        for index in account_chain(&state, account.index)
            .into_iter()
            .flatten()
            .filter(|index| *index != 0)
        {
            state.accounts[index].used.subtract(self.value);
            state.accounts[index].references -= 1;
        }
        drop(state);
        account.root.changed.notify_waiters();
    }
}

impl EnvironmentRoot {
    pub(crate) fn security_time_profile(&self) -> TrustedTimeProfile {
        self.options.time_profile
    }
    pub(crate) fn new(
        mut options: TransportEnvironmentOptions,
    ) -> Result<Arc<Self>, EnvironmentError> {
        let diagnostics = options.diagnostics.take();
        if diagnostics
            .as_ref()
            .is_some_and(|config| config.options.sampling_basis_points > 100)
        {
            return Err(EnvironmentError::Configuration);
        }
        options.application_executor.validate()?;
        options.time_profile.validate()?;
        if let Some(policy) = options.automatic_liveness {
            policy.validate(options.time_profile)?;
        }
        if options.max_tenants == 0
            || options.max_sessions == 0
            || options.max_results == 0
            || !options.tenant_limits.fits(options.root_limits)
            || !options.session_limits.fits(options.tenant_limits)
            || options.session_limits.sessions == 0
        {
            return Err(EnvironmentError::Configuration);
        }
        let slots = 1
            + usize::from(options.max_tenants)
            + usize::from(options.max_sessions)
            + usize::from(options.max_results);
        let backing = u64::try_from(
            slots
                .checked_mul(std::mem::size_of::<AccountSlot>())
                .ok_or(EnvironmentError::Configuration)?,
        )
        .map_err(|_| EnvironmentError::Configuration)?;
        let backing =
            backing
                .checked_add(
                    std::mem::size_of::<Self>() as u64
                        + std::mem::size_of::<crate::diagnostics_v4::DiagnosticCounters>() as u64
                        + 64 * std::mem::size_of::<Weak<crate::diagnostics_v4::Inner>>() as u64
                        + 64 * (std::mem::size_of::<Arc<crate::pool_v4::Backing>>()
                            + std::mem::size_of::<Weak<crate::pool_v4::SQLitePoolStore>>()
                            + std::mem::size_of::<Arc<crate::execution_history::HistoryOwner>>()
                            + std::mem::size_of::<
                                Arc<crate::sqlite_reference_store_v4::ReferenceOwner>,
                            >()
                            + std::mem::size_of::<Weak<crate::connection_controller_v4::Owner>>()
                            + std::mem::size_of::<Weak<crate::material_source_v4::Owner>>())
                            as u64,
                )
                .and_then(|n| n.checked_add(crate::codec_v4::registry_backing_bound()))
                .and_then(|n| {
                    n.checked_add(
                        (slots
                            * (std::mem::size_of::<AccountLease>()
                                + std::mem::size_of::<NamespaceSubscriptions>()
                                + 4 * std::mem::size_of::<usize>())) as u64,
                    )
                })
                .and_then(|n| {
                    n.checked_add(
                        NamespaceRegistry::backing_bytes(
                            options.max_namespaces,
                            options.max_namespace_subscribers,
                            options.max_namespace_state_bytes,
                        )
                        .ok()?,
                    )
                })
                .ok_or(EnvironmentError::Configuration)?;
        let backing_charge = ResourceLimits {
            sdk_bytes: backing,
            items: (slots
                + 128
                + usize::from(options.max_namespaces)
                + usize::from(options.max_namespace_subscribers)) as u64,
            ..ResourceLimits::default()
        };
        if !backing_charge.fits(options.root_limits) {
            return Err(EnvironmentError::Capacity);
        }
        let mut accounts = Vec::new();
        accounts
            .try_reserve_exact(slots)
            .map_err(|_| EnvironmentError::Capacity)?;
        accounts.resize_with(slots, AccountSlot::empty);
        accounts[0] = AccountSlot {
            generation: 1,
            parent: 0,
            limit: options.root_limits,
            used: backing_charge,
            references: 0,
            active: true,
            closed: false,
            tenant_key: None,
            authorization: None,
            authorization_deadline: None,
            security_closed: None,
            attached_session: None,
            is_result: false,
        };
        let mut pool_backings = Vec::new();
        pool_backings
            .try_reserve_exact(64)
            .map_err(|_| EnvironmentError::Capacity)?;
        let mut pool_stores = Vec::new();
        pool_stores
            .try_reserve_exact(64)
            .map_err(|_| EnvironmentError::Capacity)?;
        let root = Arc::new(Self {
            state: Mutex::new(RootState {
                accounts,
                closed: false,
                close_deadline: None,
                clock_sample: None,
                namespaces: NamespaceRegistry::new(
                    options.max_namespaces,
                    options.max_namespace_subscribers,
                    options.max_namespace_state_bytes,
                )?,
            }),
            options,
            changed: Notify::new(),
            pool_backings: Mutex::new(pool_backings),
            pool_stores: Mutex::new(pool_stores),
            execution_services: Mutex::new(Vec::with_capacity(64)),
            reference_stores: Mutex::new(Vec::with_capacity(64)),
            execution_stores: Mutex::new(Vec::with_capacity(64)),
            application_service: Mutex::new(Weak::new()),
            material_controllers: Mutex::new(Vec::with_capacity(64)),
            material_sources: Mutex::new(Vec::with_capacity(64)),
            diagnostic_sinks: Mutex::new(Vec::with_capacity(64)),
            production_diagnostics: Mutex::new(None),
            diagnostic_counters: Arc::new(crate::diagnostics_v4::DiagnosticCounters::default()),
            cleanup_timeout_reported: AtomicBool::new(false),
        });
        if let Some(config) = diagnostics {
            let sink = root.create_diagnostic_sink(config.options, config.callback)?;
            *root
                .production_diagnostics
                .lock()
                .expect("production diagnostics") = Some(sink);
        }
        Ok(root)
    }
    pub(crate) fn register_material_source(
        &self,
        source: &Arc<crate::material_source_v4::Owner>,
    ) -> Result<(), EnvironmentError> {
        let mut sources = self
            .material_sources
            .lock()
            .expect("material source registry");
        if self.is_closed() {
            return Err(EnvironmentError::Closed);
        }
        sources.retain(|owner| owner.strong_count() != 0);
        if sources.len() >= 64 {
            return Err(EnvironmentError::Capacity);
        }
        sources.push(Arc::downgrade(source));
        Ok(())
    }
    pub(crate) fn register_material_controller(
        &self,
        controller: &Arc<crate::connection_controller_v4::Owner>,
    ) -> Result<(), EnvironmentError> {
        let mut controllers = self
            .material_controllers
            .lock()
            .expect("material controller registry");
        if self.is_closed() {
            return Err(EnvironmentError::Closed);
        }
        controllers.retain(|owner| owner.strong_count() != 0);
        if controllers.len() >= 64 {
            return Err(EnvironmentError::Capacity);
        }
        controllers.push(Arc::downgrade(controller));
        Ok(())
    }
    pub(crate) fn diagnostic_sink(
        self: &Arc<Self>,
        options: crate::DiagnosticSinkOptions,
        callback: crate::DiagnosticCallback,
    ) -> Result<crate::DiagnosticSink, EnvironmentError> {
        self.create_diagnostic_sink(options, Arc::new(move |event, _| callback(event)))
    }
    fn create_diagnostic_sink(
        self: &Arc<Self>,
        options: crate::DiagnosticSinkOptions,
        callback: crate::CancellableDiagnosticCallback,
    ) -> Result<crate::DiagnosticSink, EnvironmentError> {
        if options.sampling_basis_points > 100 {
            return Err(EnvironmentError::Configuration);
        }
        if self.is_closed() {
            return Err(EnvironmentError::Closed);
        }
        let charge = self.reserve_environment(ResourceLimits {
            sdk_bytes: (2 << 20) + 128 * 1024,
            items: 5120,
            work_slots: 1,
            tasks: 2,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        let sink = crate::diagnostics_v4::DiagnosticSink::new(
            options,
            callback,
            charge,
            self.diagnostic_counters.clone(),
        )
        .map_err(|error| match error {
            crate::DiagnosticSinkError::InvalidSampling => EnvironmentError::Configuration,
            crate::DiagnosticSinkError::Closed | crate::DiagnosticSinkError::Capacity => {
                EnvironmentError::Capacity
            }
        })?;
        let mut sinks = self
            .diagnostic_sinks
            .lock()
            .expect("diagnostic sink registry");
        sinks.retain(|entry| entry.strong_count() != 0);
        if self.is_closed() || sinks.len() >= 64 {
            sink.close();
            return Err(EnvironmentError::Capacity);
        }
        sinks.push(Arc::downgrade(&sink.inner));
        Ok(sink)
    }
    pub(crate) fn diagnostic_activity(
        &self,
        phase: crate::DiagnosticPhase,
        ordinal: u32,
    ) -> Arc<crate::diagnostics_v4::DiagnosticActivity> {
        let sink = self
            .production_diagnostics
            .lock()
            .expect("production diagnostics");
        crate::diagnostics_v4::DiagnosticActivity::new(
            sink.as_ref(),
            self.diagnostic_counters.clone(),
            phase,
            ordinal,
        )
    }
    pub(crate) fn diagnostic_count(&self, counter: crate::diagnostics_v4::DiagnosticCounter) {
        self.diagnostic_counters.increment(counter);
    }
    pub(crate) fn diagnostic_metric(
        &self,
        metric: crate::DiagnosticMetric,
    ) -> crate::DiagnosticMetricCounts {
        self.diagnostic_counters.metric(metric)
    }
    pub(crate) fn diagnostic_counts(&self) -> crate::TransportDiagnosticCounts {
        self.diagnostic_counters.snapshot()
    }
    #[cfg(test)]
    pub(crate) fn install_test_diagnostics(&self, sink: crate::DiagnosticSink) {
        *self
            .production_diagnostics
            .lock()
            .expect("production diagnostics") = Some(sink);
    }
    pub(crate) fn configured_diagnostic_sink(&self) -> Option<crate::DiagnosticSink> {
        self.production_diagnostics
            .lock()
            .expect("production diagnostics")
            .clone()
    }
    pub(crate) fn diagnostic_pending_callbacks(&self) -> u64 {
        self.diagnostic_sinks
            .lock()
            .expect("diagnostic sink registry")
            .iter()
            .filter_map(Weak::upgrade)
            .map(|sink| sink.cleanup_status().pending_callbacks as u64)
            .sum()
    }

    pub(crate) fn application_config(
        &self,
    ) -> &crate::application_profile_v4::ApplicationExecutorConfig {
        &self.options.application_executor
    }
    pub(crate) fn application_snapshot(&self) -> crate::ApplicationExecutorSnapshot {
        let service = self
            .application_service
            .lock()
            .expect("application service registry")
            .upgrade();
        match service {
            Some(service) => service.snapshot(),
            None => {
                crate::ApplicationExecutorSnapshot::empty(self.options.application_executor.profile)
            }
        }
    }
    pub(crate) fn application_services(
        self: &Arc<Self>,
    ) -> Result<Arc<crate::application_executor_v4::ApplicationServices>, EnvironmentError> {
        let mut slot = self
            .application_service
            .lock()
            .expect("application service registry");
        if self.is_closed() {
            return Err(EnvironmentError::Closed);
        }
        if let Some(service) = slot.upgrade() {
            return Ok(service);
        }
        let service = crate::application_executor_v4::ApplicationServices::new(self.clone())?;
        *slot = Arc::downgrade(&service);
        Ok(service)
    }

    pub(crate) fn execution_service(
        self: &Arc<Self>,
        options: crate::execution_history::ExecutionServiceOptions,
        store: Option<crate::SQLiteExecutionStoreOptions>,
    ) -> std::result::Result<
        crate::execution_history::ExecutionService,
        crate::service_contract::ServiceError,
    > {
        use crate::{
            execution_history::ExecutionService,
            service_contract::{ServiceError, ServiceFailure},
        };
        let mut services = self
            .execution_services
            .lock()
            .expect("execution service registry");
        if self.is_closed() {
            return Err(ServiceError(ServiceFailure::Closed));
        }
        if let Some(owner) = services.iter().find(|owner| owner.matches(&options)) {
            if !owner.configured(&options, store.as_ref()) {
                return Err(ServiceError(ServiceFailure::ConfigurationCapacity));
            }
            return Ok(ExecutionService(owner.clone()));
        }
        if services.len() >= 64 {
            return Err(ServiceError(ServiceFailure::ResourceExhausted));
        }
        let service = ExecutionService::create(self.clone(), options, store)?;
        services.push(service.0.clone());
        Ok(service)
    }
    pub(crate) fn register_execution_store(
        &self,
        store: Arc<crate::sqlite_execution_store_v4::ExecutionStoreOwner>,
    ) -> std::result::Result<(), crate::ServiceError> {
        let mut stores = self
            .execution_stores
            .lock()
            .expect("execution database registry");
        if self.is_closed() {
            return Err(crate::ServiceError(crate::ServiceFailure::Closed));
        }
        if stores.len() >= 64 {
            return Err(crate::ServiceError(
                crate::ServiceFailure::ResourceExhausted,
            ));
        }
        if stores.iter().any(|old| old.path() == store.path()) {
            return Err(crate::ServiceError(
                crate::ServiceFailure::ConfigurationCapacity,
            ));
        }
        stores.push(store);
        Ok(())
    }
    pub(crate) fn release_execution_store(
        &self,
        store: &Arc<crate::sqlite_execution_store_v4::ExecutionStoreOwner>,
    ) {
        self.execution_stores
            .lock()
            .expect("execution database registry")
            .retain(|old| !Arc::ptr_eq(old, store));
    }
    pub(crate) fn register_reference_store(
        &self,
        store: Arc<crate::sqlite_reference_store_v4::ReferenceOwner>,
    ) -> Result<(), EnvironmentError> {
        let mut stores = self
            .reference_stores
            .lock()
            .expect("reference store registry");
        if self.is_closed() {
            return Err(EnvironmentError::Closed);
        }
        if stores.len() >= 64 {
            return Err(EnvironmentError::Capacity);
        }
        if stores.iter().any(|old| old.path() == store.path()) {
            return Err(EnvironmentError::Configuration);
        }
        stores.push(store);
        Ok(())
    }
    pub(crate) fn reference_store(
        &self,
        path: &std::path::Path,
    ) -> Option<Arc<crate::sqlite_reference_store_v4::ReferenceOwner>> {
        self.reference_stores
            .lock()
            .expect("reference store registry")
            .iter()
            .find(|store| store.path() == path)
            .cloned()
    }
    pub(crate) fn release_reference_store(
        &self,
        store: &Arc<crate::sqlite_reference_store_v4::ReferenceOwner>,
    ) {
        self.reference_stores
            .lock()
            .expect("reference store registry")
            .retain(|old| !Arc::ptr_eq(old, store));
    }
    pub(crate) fn register_pool_backing(
        &self,
        backing: Arc<crate::pool_v4::Backing>,
    ) -> Result<(), EnvironmentError> {
        let mut entries = self.pool_backings.lock().expect("pool backing registry");
        if self.is_closed() {
            return Err(EnvironmentError::Closed);
        }
        if entries.len() >= 64 {
            return Err(EnvironmentError::Capacity);
        }
        entries
            .try_reserve_exact(1)
            .map_err(|_| EnvironmentError::Capacity)?;
        entries.push(backing);
        Ok(())
    }
    pub(crate) fn release_pool_backing(&self, backing: &Arc<crate::pool_v4::Backing>) {
        self.pool_backings
            .lock()
            .expect("pool backing registry")
            .retain(|old| !Arc::ptr_eq(old, backing));
    }
    pub(crate) fn register_pool_store(
        &self,
        store: &Arc<crate::pool_v4::SQLitePoolStore>,
    ) -> Result<(), EnvironmentError> {
        let mut entries = self.pool_stores.lock().expect("pool store registry");
        if self.is_closed() {
            return Err(EnvironmentError::Closed);
        }
        entries.retain(|entry| entry.strong_count() != 0);
        if entries.len() >= 64 {
            return Err(EnvironmentError::Capacity);
        }
        entries
            .try_reserve_exact(1)
            .map_err(|_| EnvironmentError::Capacity)?;
        entries.push(Arc::downgrade(store));
        Ok(())
    }
    pub(crate) fn reserve_environment(
        self: &Arc<Self>,
        value: ResourceLimits,
    ) -> Result<EnvironmentCharge, EnvironmentError> {
        let mut state = self.state.lock().expect("environment root lock");
        if state.closed {
            return Err(EnvironmentError::Closed);
        }
        let account = &mut state.accounts[0];
        let used = account
            .used
            .checked_add(value)
            .filter(|v| v.fits(account.limit))
            .ok_or_else(|| {
                self.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::ResourceRejections);
                EnvironmentError::Capacity
            })?;
        let refs = account.references.checked_add(1).ok_or_else(|| {
            self.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::ResourceRejections);
            EnvironmentError::Capacity
        })?;
        account.used = used;
        account.references = refs;
        Ok(EnvironmentCharge {
            root: self.clone(),
            value,
            transferred: false,
        })
    }
    pub(crate) fn close(&self) {
        let mut state = self.state.lock().expect("environment root lock");
        if !state.closed {
            state.closed = true;
            state.close_deadline = Instant::now().checked_add(Duration::from_secs(5));
            for account in &mut state.accounts {
                account.closed = true;
            }
            state.namespaces.close();
        }
        drop(state);
        self.changed.notify_waiters();
        let sinks: Vec<_> = self
            .diagnostic_sinks
            .lock()
            .expect("diagnostic sink registry")
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for sink in sinks {
            sink.close();
        }
        // Break the root -> configured sink -> original charge cycle on Close.
        drop(
            self.production_diagnostics
                .lock()
                .expect("production diagnostics")
                .take(),
        );
        if let Some(service) = self
            .application_service
            .lock()
            .expect("application service registry")
            .upgrade()
        {
            service.close();
        }
        let controllers: Vec<_> = self
            .material_controllers
            .lock()
            .expect("material controller registry")
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for controller in controllers {
            controller.close();
        }
        let sources: Vec<_> = self
            .material_sources
            .lock()
            .expect("material source registry")
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for source in sources {
            source.close();
        }

        let histories = std::mem::take(
            &mut *self
                .execution_services
                .lock()
                .expect("execution service registry"),
        );
        for history in histories {
            history.close();
        }
        for store in self
            .reference_stores
            .lock()
            .expect("reference store registry")
            .iter()
        {
            store.close();
        }
        for store in self
            .pool_stores
            .lock()
            .expect("pool store registry")
            .iter()
            .filter_map(Weak::upgrade)
        {
            store.close();
        }
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().expect("environment root lock").closed
    }
    pub(crate) fn cleanup(&self) -> (bool, bool) {
        let state = self.state.lock().expect("environment root lock");
        let complete = state.closed && state.accounts.iter().all(|a| a.references == 0);
        let incomplete = !complete && state.close_deadline.is_some_and(|d| Instant::now() >= d);
        if incomplete && !self.cleanup_timeout_reported.swap(true, Ordering::AcqRel) {
            self.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::CleanupTimeouts);
        }
        (complete, incomplete)
    }
    pub(crate) fn cleanup_deadline(&self) -> Option<Instant> {
        self.state
            .lock()
            .expect("environment root lock")
            .close_deadline
    }
    pub(crate) fn charged(&self) -> ResourceLimits {
        self.state.lock().expect("environment root lock").accounts[0].used
    }
    pub(crate) fn sample(&self) -> Result<TrustedTimeSample, EnvironmentError> {
        // Source execution is outside every resource/security gate. The source
        // is an explicit Environment dependency, never selected by a peer.
        let raw = self
            .options
            .clock
            .as_ref()
            .ok_or(EnvironmentError::TimeUnavailable)?
            .sample();
        let mut state = self.state.lock().expect("environment root lock");
        if state.closed {
            return Err(EnvironmentError::Closed);
        }
        let now = Instant::now();
        let mut sample = match raw {
            Ok(raw) => self.options.time_profile.project(raw, now)?,
            Err(EnvironmentError::TimeUnavailable) => {
                // A temporarily unavailable source does not discard an original
                // envelope that still satisfies the same age and width caps.
                return self.options.time_profile.project(
                    state
                        .clock_sample
                        .ok_or(EnvironmentError::TimeUnavailable)?,
                    now,
                );
            }
            Err(error) => return Err(error),
        };
        if let Some(old) = state.clock_sample {
            if old.clock_incarnation != sample.clock_incarnation {
                // This owner cannot establish continuity across host clock
                // incarnations. Original accounts stay permanently sealed.
                for account in state
                    .accounts
                    .iter_mut()
                    .filter(|a| a.authorization.is_some())
                {
                    account.closed = true;
                    if let Some(security) = &account.security_closed {
                        security.store(true, Ordering::Release);
                    }
                }
                state.clock_sample = Some(sample);
                drop(state);
                self.changed.notify_waiters();
                return Err(EnvironmentError::TimeUnavailable);
            }
            if let Ok(old) = self.options.time_profile.project(old, now) {
                sample.lower_ms = sample.lower_ms.max(old.lower_ms);
                sample.upper_ms = sample.upper_ms.min(old.upper_ms);
                if sample.lower_ms > sample.upper_ms {
                    // Contradictory evidence never chooses a more convenient
                    // clock. Existing authorization owners cannot reopen.
                    for account in state
                        .accounts
                        .iter_mut()
                        .filter(|a| a.authorization.is_some())
                    {
                        account.closed = true;
                        if let Some(security) = &account.security_closed {
                            security.store(true, Ordering::Release);
                        }
                    }
                    state.clock_sample = None;
                    drop(state);
                    self.changed.notify_waiters();
                    return Err(EnvironmentError::TimeUnavailable);
                }
            }
        }
        state.clock_sample = Some(sample);
        Ok(sample)
    }
    pub(crate) fn check_namespace_binding(
        &self,
        binding: NamespaceBinding,
    ) -> Result<(), EnvironmentError> {
        let now = self.sample()?;
        self.state
            .lock()
            .expect("configured namespace dependency")
            .namespaces
            .check_binding(binding, now)
    }
    pub(crate) fn claim_namespace_verifier(
        &self,
        key: NamespaceKey,
        owner: &Arc<AtomicBool>,
    ) -> Result<(), EnvironmentError> {
        self.state
            .lock()
            .expect("environment root lock")
            .namespaces
            .claim_verifier(key, owner)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn install_verified_namespace(
        &self,
        update: &VerifiedNamespaceUpdate,
        owner: &Arc<AtomicBool>,
        time_pending: bool,
        security_cap: u64,
        security_deadline: Instant,
        head_deadline: Instant,
        work_deadline: Option<(Instant, EnvironmentError)>,
        pending_candidate: Option<PendingNamespaceCandidate>,
    ) -> Result<(), EnvironmentError> {
        let sample = self.sample()?;
        let mut state = self.state.lock().expect("environment root lock");
        let now = self.options.time_profile.project(sample, Instant::now())?;
        if now.upper_ms >= security_cap {
            return Err(EnvironmentError::MaterialExpired);
        }
        if Instant::now() >= security_deadline || Instant::now() >= head_deadline {
            return Err(EnvironmentError::MaterialExpired);
        }
        if let Some((deadline, failure)) = work_deadline
            && Instant::now() >= deadline
        {
            return Err(failure);
        }
        let result = state.namespaces.install_verified(
            update,
            owner,
            now,
            time_pending,
            head_deadline,
            pending_candidate,
        );
        drop(state);
        self.changed.notify_waiters();
        result
    }
    pub(crate) fn observe_verified_namespace_head(
        &self,
        proof: &VerifiedNamespaceHead,
        owner: &Arc<AtomicBool>,
        time_pending: bool,
        security_cap: u64,
        security_deadline: Instant,
    ) -> Result<Instant, EnvironmentError> {
        let sample = self.sample()?;
        let mut state = self.state.lock().expect("environment root lock");
        let now = self.options.time_profile.project(sample, Instant::now())?;
        if now.upper_ms >= security_cap || Instant::now() >= security_deadline {
            return Err(EnvironmentError::MaterialExpired);
        }
        let result =
            state
                .namespaces
                .observe_verified(proof, owner, now, time_pending, security_deadline);
        drop(state);
        self.changed.notify_waiters();
        result
    }
    pub(crate) fn observe_verified_namespace_denials(
        &self,
        update: &VerifiedNamespaceUpdate,
        owner: &Arc<AtomicBool>,
    ) -> Result<(), EnvironmentError> {
        let sample = self.sample()?;
        let mut state = self.state.lock().expect("environment root lock");
        let now = self.options.time_profile.project(sample, Instant::now())?;
        let result = state
            .namespaces
            .observe_verified_denials(update, owner, now);
        drop(state);
        self.changed.notify_waiters();
        result
    }
    pub(crate) fn reject_namespace_signers(
        &self,
        key: NamespaceKey,
        rejected: &[Option<[u8; 16]>; 64],
    ) -> Result<(), EnvironmentError> {
        let result = self
            .state
            .lock()
            .expect("environment root lock")
            .namespaces
            .reject_signers(key, rejected);
        self.changed.notify_waiters();
        result
    }
    pub(crate) fn reject_namespace_issuers(
        &self,
        key: NamespaceKey,
        rejected: &[Option<[u8; 16]>; 64],
    ) -> Result<(), EnvironmentError> {
        let now = self.sample()?;
        let result = self
            .state
            .lock()
            .expect("environment root lock")
            .namespaces
            .reject_issuers(key, rejected, now);
        self.changed.notify_waiters();
        result
    }
    /// Trust anchors come only from the original independently authenticated
    /// Environment configuration. Registering one does not install valid State.
    #[allow(dead_code)]
    pub(crate) fn register_namespace(
        &self,
        anchor: NamespaceAnchor,
    ) -> Result<(), EnvironmentError> {
        self.state
            .lock()
            .expect("environment root lock")
            .namespaces
            .register(anchor)
    }
    #[allow(dead_code)]
    pub(crate) fn install_namespace(
        &self,
        update: &VerifiedNamespaceUpdate,
    ) -> Result<(), EnvironmentError> {
        let sample = self.sample()?;
        let mut state = self.state.lock().expect("environment root lock");
        if state.closed {
            return Err(EnvironmentError::Closed);
        }
        let current = self.options.time_profile.project(sample, Instant::now())?;
        let result = state.namespaces.install(update, current);
        drop(state);
        self.changed.notify_waiters();
        result
    }
    #[allow(dead_code)]
    pub(crate) fn terminate_namespace(&self, key: NamespaceKey) -> Result<(), EnvironmentError> {
        let result = self
            .state
            .lock()
            .expect("environment root lock")
            .namespaces
            .terminate(key);
        self.changed.notify_waiters();
        result
    }
    /// Only the authenticated admission assembly may create tenant/session
    /// accounts. Neither peer labels nor public resource constructors call this.
    #[allow(dead_code)]
    pub(crate) fn admit(
        self: &Arc<Self>,
        tenant: [u8; 32],
        authorization: AuthorizationBounds,
    ) -> Result<ResourceAccount, EnvironmentError> {
        if tenant == [0; 32] || authorization.not_before_ms >= authorization.not_after_ms {
            return Err(EnvironmentError::Configuration);
        }
        let sample = self.sample()?;
        let mut state = self.state.lock().expect("environment root lock");
        if state.closed {
            return Err(EnvironmentError::Closed);
        }
        let now = Instant::now();
        let sample = self.options.time_profile.project(sample, now)?;
        check_bounds(authorization, sample)?;
        // Pin the earliest conservative monotonic deadline once. Refining a
        // later time envelope cannot extend an existing account's lifetime.
        let remaining = authorization
            .not_after_ms
            .checked_sub(sample.upper_ms)
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let profile = self.options.time_profile;
        let duration = u128::from(
            remaining
                .saturating_sub(profile.quantization_ms)
                .saturating_sub(1),
        ) * u128::from(profile.rate_denominator - profile.rate_numerator)
            / u128::from(profile.rate_denominator);
        let duration = u64::try_from(duration).map_err(|_| EnvironmentError::TimeUnavailable)?;
        let authorization_deadline = now
            .checked_add(Duration::from_millis(duration))
            .ok_or(EnvironmentError::TimeUnavailable)?;
        if authorization_deadline <= now {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let end = 1 + usize::from(self.options.max_tenants);
        let existing = (1..end)
            .find(|i| state.accounts[*i].active && state.accounts[*i].tenant_key == Some(tenant));
        let tenant_index = existing
            .or_else(|| (1..end).find(|i| !state.accounts[*i].active))
            .ok_or(EnvironmentError::Capacity)?;
        let i = (end..end + usize::from(self.options.max_sessions))
            .find(|i| !state.accounts[*i].active)
            .ok_or(EnvironmentError::Capacity)?;
        let session = ResourceLimits {
            sessions: 1,
            ..ResourceLimits::default()
        };
        state.accounts[0]
            .used
            .checked_add(session)
            .filter(|v| v.fits(state.accounts[0].limit))
            .ok_or(EnvironmentError::Capacity)?;
        let tenant_used = existing.map_or(ResourceLimits::default(), |n| state.accounts[n].used);
        tenant_used
            .checked_add(session)
            .filter(|v| v.fits(self.options.tenant_limits))
            .ok_or(EnvironmentError::Capacity)?;
        let generation = state.accounts[i]
            .generation
            .checked_add(1)
            .ok_or(EnvironmentError::Capacity)?;
        if existing.is_none() {
            let generation = state.accounts[tenant_index]
                .generation
                .checked_add(1)
                .ok_or(EnvironmentError::Capacity)?;
            state.accounts[tenant_index] = AccountSlot {
                generation,
                parent: 0,
                limit: self.options.tenant_limits,
                used: ResourceLimits::default(),
                references: 0,
                active: true,
                closed: false,
                tenant_key: Some(tenant),
                authorization: None,
                authorization_deadline: None,
                security_closed: None,
                attached_session: None,
                is_result: false,
            };
        }
        for n in [0, tenant_index] {
            state.accounts[n].used.sessions += 1;
            state.accounts[n].references += 1;
        }
        state.accounts[i] = AccountSlot {
            generation,
            parent: tenant_index,
            limit: self.options.session_limits,
            used: session,
            references: 1,
            active: true,
            closed: false,
            tenant_key: None,
            authorization: Some(authorization),
            authorization_deadline: Some(authorization_deadline),
            security_closed: Some(Arc::new(AtomicBool::new(false))),
            attached_session: None,
            is_result: false,
        };
        Ok(ResourceAccount {
            root: self.clone(),
            index: i,
            generation,
            _lease: Arc::new(AccountLease {
                root: self.clone(),
                index: i,
                generation,
                source: Mutex::new(None),
                subscriptions: Mutex::new(None),
                business_work: AtomicUsize::new(0),
            }),
        })
    }
}
fn check_bounds(
    bounds: AuthorizationBounds,
    sample: TrustedTimeSample,
) -> Result<(), EnvironmentError> {
    if sample.upper_ms >= bounds.not_after_ms || sample.upper_ms >= bounds.freshness_not_after_ms {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    if sample.lower_ms < bounds.not_before_ms {
        return Err(EnvironmentError::TimePending);
    }
    Ok(())
}
#[derive(Debug)]
pub(crate) struct BusinessActivity {
    lease: Arc<AccountLease>,
}
impl Drop for BusinessActivity {
    fn drop(&mut self) {
        self.lease.business_work.fetch_sub(1, Ordering::AcqRel);
        self.lease.root.changed.notify_waiters();
    }
}

impl ResourceAccount {
    pub(crate) fn begin_business_work(&self) -> BusinessActivity {
        self._lease.business_work.fetch_add(1, Ordering::AcqRel);
        BusinessActivity {
            lease: self._lease.clone(),
        }
    }
    pub(crate) fn business_work_pending(&self) -> bool {
        self._lease.business_work.load(Ordering::Acquire) != 0
    }
    pub(crate) fn diagnostic_activity(
        &self,
        phase: crate::DiagnosticPhase,
        ordinal: u32,
    ) -> Arc<crate::diagnostics_v4::DiagnosticActivity> {
        self.root.diagnostic_activity(phase, ordinal)
    }
    pub(crate) fn diagnostic_count(&self, counter: crate::diagnostics_v4::DiagnosticCounter) {
        self.root.diagnostic_count(counter);
    }
    pub(crate) fn environment_root(&self) -> &Arc<EnvironmentRoot> {
        &self.root
    }
    pub(crate) fn application_group(
        &self,
    ) -> Result<crate::application_executor_v4::ApplicationGroup, EnvironmentError> {
        crate::application_executor_v4::ApplicationGroup::new(
            self.clone(),
            self.root.application_services()?,
        )
    }
    pub(crate) fn application_group_prepaid(
        &self,
        charge: ResourceCharge,
    ) -> Result<crate::application_executor_v4::ApplicationGroup, EnvironmentError> {
        crate::application_executor_v4::ApplicationGroup::new_prepaid(
            self.clone(),
            self.root.application_services()?,
            charge,
        )
    }
    pub(crate) fn belongs_to(&self, environment: &Arc<EnvironmentRoot>) -> bool {
        Arc::ptr_eq(&self.root, environment)
    }
    pub(crate) fn automatic_liveness(&self) -> Option<AutomaticLivenessPolicy> {
        self.root.options.automatic_liveness
    }
    pub(crate) fn security_time_profile(&self) -> TrustedTimeProfile {
        self.root.options.time_profile
    }
    /// A private crypto owner samples the same original clock and cannot
    /// substitute a wall clock or restart an authorization interval.
    pub(crate) fn security_time(&self) -> Result<TrustedTimeSample, EnvironmentError> {
        let sample = self.root.sample()?;
        let mut state = self.root.state.lock().expect("environment root lock");
        self.validate_locked(&mut state, sample)?;
        self.root
            .options
            .time_profile
            .project(sample, Instant::now())
    }
    fn chain(&self, state: &RootState) -> Result<[Option<usize>; 4], EnvironmentError> {
        let account = state
            .accounts
            .get(self.index)
            .ok_or(EnvironmentError::Closed)?;
        if state.closed
            || !account.active
            || account.closed
            || account.generation != self.generation
            || state.accounts[account.parent].closed
            || account
                .security_closed
                .as_ref()
                .is_some_and(|closed| closed.load(Ordering::Acquire))
        {
            return Err(EnvironmentError::Closed);
        }
        Ok(account_chain(state, self.index))
    }
    /// Complete the prepared live owner with its one additional independently
    /// verified activation dependency. Bounds and monotonic expiry only tighten;
    /// the account and its original native reservations are never replaced.
    pub(crate) fn install_live_activation(
        &self,
        binding: NamespaceBinding,
        bounds: AuthorizationBounds,
    ) -> Result<(), EnvironmentError> {
        let sample = self.root.sample()?;
        let mut state = self
            .root
            .state
            .lock()
            .expect("original live activation installation");
        self.validate_locked(&mut state, sample)?;
        let current = self
            .root
            .options
            .time_profile
            .project(sample, Instant::now())?;
        let old = state.accounts[self.index]
            .authorization
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let tightened = AuthorizationBounds {
            not_before_ms: old.not_before_ms.max(bounds.not_before_ms),
            not_after_ms: old.not_after_ms.min(bounds.not_after_ms),
            freshness_not_after_ms: old
                .freshness_not_after_ms
                .min(bounds.freshness_not_after_ms),
        };
        check_bounds(tightened, current)?;
        if state.accounts[self.index].is_result
            || binding.namespace.tenant
                != state.accounts[state.accounts[self.index].parent]
                    .tenant_key
                    .ok_or(EnvironmentError::Configuration)?
        {
            return Err(EnvironmentError::Configuration);
        }
        let mut subscriptions = self
            ._lease
            .subscriptions
            .lock()
            .expect("original live namespace dependencies");
        let original = subscriptions
            .as_mut()
            .and_then(Arc::get_mut)
            .ok_or(EnvironmentError::Configuration)?;
        let index = original
            .ids
            .iter()
            .position(Option::is_none)
            .ok_or(EnvironmentError::Capacity)?;
        let closed = state.accounts[self.index]
            .security_closed
            .as_ref()
            .ok_or(EnvironmentError::Configuration)?
            .clone();
        let (id, wake) = state.namespaces.subscribe(binding, &closed, current)?;
        let remaining = tightened
            .not_after_ms
            .checked_sub(current.upper_ms)
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let profile = self.root.options.time_profile;
        let duration = u128::from(
            remaining
                .saturating_sub(profile.quantization_ms)
                .saturating_sub(1),
        ) * u128::from(profile.rate_denominator - profile.rate_numerator)
            / u128::from(profile.rate_denominator);
        let duration = match u64::try_from(duration) {
            Ok(duration) => duration,
            Err(_) => {
                state.namespaces.release(id);
                return Err(EnvironmentError::TimeUnavailable);
            }
        };
        let deadline = match Instant::now().checked_add(Duration::from_millis(duration)) {
            Some(deadline) if deadline > Instant::now() => deadline,
            _ => {
                state.namespaces.release(id);
                return Err(EnvironmentError::AuthorizationDenied);
            }
        };
        original.ids[index] = Some(id);
        original.wakes[index] = Some(wake);
        let account = &mut state.accounts[self.index];
        account.authorization = Some(tightened);
        account.authorization_deadline = Some(
            account
                .authorization_deadline
                .ok_or(EnvironmentError::AuthorizationDenied)?
                .min(deadline),
        );
        drop(subscriptions);
        drop(state);
        self.root.changed.notify_waiters();
        Ok(())
    }
    /// Attach a bounded set of original namespace dependencies before any
    /// operation/result allocation. Binding never creates or refreshes State.
    #[allow(dead_code)]
    pub(crate) fn bind_namespaces(
        &self,
        bindings: &[NamespaceBinding],
    ) -> Result<(), EnvironmentError> {
        if bindings.is_empty() || bindings.len() > 8 {
            return Err(EnvironmentError::Configuration);
        }
        let sample = self.root.sample()?;
        let mut state = self.root.state.lock().expect("environment root lock");
        self.validate_locked(&mut state, sample)?;
        let mut subscriptions = self
            ._lease
            .subscriptions
            .lock()
            .expect("namespace subscription lock");
        if subscriptions.is_some()
            || state.accounts[self.index].is_result
            || state.accounts[self.index].references != 1
        {
            return Err(EnvironmentError::Configuration);
        }
        let tenant = state.accounts[state.accounts[self.index].parent]
            .tenant_key
            .expect("tenant binding");
        for (i, binding) in bindings.iter().enumerate() {
            if binding.namespace.tenant != tenant || bindings[..i].contains(binding) {
                return Err(EnvironmentError::Configuration);
            }
        }
        let closed = state.accounts[self.index]
            .security_closed
            .as_ref()
            .expect("authorization gate")
            .clone();
        let mut ids = [None; 8];
        let mut wakes = std::array::from_fn(|_| None);
        for (i, binding) in bindings.iter().enumerate() {
            match state.namespaces.subscribe(*binding, &closed, sample) {
                Ok((id, wake)) => {
                    ids[i] = Some(id);
                    wakes[i] = Some(wake);
                }
                Err(error) => {
                    for id in ids.into_iter().flatten() {
                        state.namespaces.release(id);
                    }
                    return Err(error);
                }
            }
        }
        *subscriptions = Some(Arc::new(NamespaceSubscriptions {
            root: self.root.clone(),
            ids,
            wakes,
        }));
        Ok(())
    }
    pub(crate) fn same_owner(&self, other: &ResourceAccount) -> bool {
        Arc::ptr_eq(&self.root, &other.root)
            && self.index == other.index
            && self.generation == other.generation
            && Arc::ptr_eq(&self._lease, &other._lease)
    }
    pub(crate) fn downgrade(&self) -> WeakResourceAccount {
        WeakResourceAccount {
            root: Arc::downgrade(&self.root),
            index: self.index,
            generation: self.generation,
            lease: Arc::downgrade(&self._lease),
        }
    }
    /// Reserve the independent result slot before consuming input. While input
    /// is incomplete, every charge also belongs to the original Session.
    pub(crate) fn reserve_result(&self) -> Result<Self, EnvironmentError> {
        let sample = self.root.sample()?;
        let mut state = self.root.state.lock().expect("environment root lock");
        self.validate_locked(&mut state, sample)?;
        if state.accounts[self.index].is_result {
            return Err(EnvironmentError::Configuration);
        }
        let first = 1
            + usize::from(self.root.options.max_tenants)
            + usize::from(self.root.options.max_sessions);
        let index = (first..state.accounts.len())
            .find(|i| !state.accounts[*i].active)
            .ok_or(EnvironmentError::Capacity)?;
        let generation = state.accounts[index]
            .generation
            .checked_add(1)
            .ok_or(EnvironmentError::Capacity)?;
        let original = &state.accounts[self.index];
        let result = AccountSlot {
            generation,
            parent: original.parent,
            limit: original.limit,
            used: ResourceLimits::default(),
            references: 1,
            active: true,
            closed: false,
            tenant_key: None,
            authorization: original.authorization,
            authorization_deadline: original.authorization_deadline,
            security_closed: original.security_closed.clone(),
            attached_session: Some(self.index),
            is_result: true,
        };
        for i in [0, result.parent, self.index] {
            state.accounts[i]
                .references
                .checked_add(1)
                .ok_or(EnvironmentError::Capacity)?;
        }
        for i in [0, result.parent, self.index] {
            state.accounts[i].references += 1;
        }
        state.accounts[index] = result;
        Ok(Self {
            root: self.root.clone(),
            index,
            generation,
            _lease: Arc::new(AccountLease {
                root: self.root.clone(),
                index,
                generation,
                source: Mutex::new(Some(self.clone())),
                subscriptions: Mutex::new(
                    self._lease
                        .subscriptions
                        .lock()
                        .expect("namespace subscription lock")
                        .clone(),
                ),
                business_work: AtomicUsize::new(0),
            }),
        })
    }
    /// Complete private candidates retain root/tenant/result charges and the
    /// original authorization gate, but release their entire Session scope.
    pub(crate) fn detach_result(&self) {
        let mut state = self.root.state.lock().expect("environment root lock");
        let slot = &state.accounts[self.index];
        assert_eq!(slot.generation, self.generation);
        if !slot.is_result {
            return;
        }
        if let Some(source) = slot.attached_session {
            let value = slot.used;
            let references = slot.references;
            state.accounts[source].used.subtract(value);
            state.accounts[source].references -= references;
            state.accounts[self.index].attached_session = None;
        }
        drop(state);
        // A source lease can be the last native Session accounting reference.
        // Drop it only after leaving the root gate.
        let source = self
            ._lease
            .source
            .lock()
            .expect("result source lock")
            .take();
        drop(source);
        self.root.changed.notify_waiters();
    }
    pub(crate) fn retirement_deadline(
        &self,
        maximum: Duration,
    ) -> Result<Instant, EnvironmentError> {
        self.check()?;
        let state = self
            .root
            .state
            .lock()
            .expect("original authorization retirement deadline");
        let _ = self.chain(&state)?;
        let authorization = state.accounts[self.index]
            .authorization_deadline
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let requested = Instant::now()
            .checked_add(maximum)
            .ok_or(EnvironmentError::Configuration)?;
        Ok(authorization.min(requested))
    }
    pub(crate) fn check(&self) -> Result<(), EnvironmentError> {
        self.with_security(|| ())
    }
    fn validate_locked(
        &self,
        state: &mut RootState,
        sample: TrustedTimeSample,
    ) -> Result<[Option<usize>; 4], EnvironmentError> {
        let chain = self.chain(state)?;
        let account = &mut state.accounts[self.index];
        if account
            .authorization_deadline
            .is_none_or(|d| Instant::now() >= d)
        {
            account.closed = true;
            if let Some(security) = &account.security_closed {
                security.store(true, Ordering::Release);
            }
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let current = self
            .root
            .options
            .time_profile
            .project(sample, Instant::now())?;
        let bounds = account
            .authorization
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let subscriptions = self
            ._lease
            .subscriptions
            .lock()
            .expect("namespace subscription lock");
        // Live namespace subscriptions replace only the bootstrap freshness
        // snapshot. The original authorization cap and its pinned monotonic
        // deadline remain unchanged across every refresh.
        let checked_bounds = if subscriptions.is_some() {
            AuthorizationBounds {
                freshness_not_after_ms: u64::MAX,
                ..bounds
            }
        } else {
            bounds
        };
        if let Err(error) = check_bounds(checked_bounds, current) {
            if error == EnvironmentError::AuthorizationDenied {
                account.closed = true;
                if let Some(security) = &account.security_closed {
                    security.store(true, Ordering::Release);
                }
            }
            return Err(error);
        }
        if let Some(subscriptions) = subscriptions.as_ref() {
            for id in subscriptions.ids.into_iter().flatten() {
                state.namespaces.check(id, current)?;
            }
        }
        Ok(chain)
    }
    pub(crate) fn with_security_time<T>(
        &self,
        action: impl FnOnce(TrustedTimeSample) -> T,
    ) -> Result<T, EnvironmentError> {
        let sample = self.root.sample()?;
        let mut state = self.root.state.lock().expect("environment root lock");
        self.validate_locked(&mut state, sample)?;
        let current = self
            .root
            .options
            .time_profile
            .project(sample, Instant::now())?;
        Ok(action(current))
    }
    pub(crate) fn with_security_pair<T>(
        &self,
        other: &Self,
        action: impl FnOnce() -> T,
    ) -> Result<T, EnvironmentError> {
        if !Arc::ptr_eq(&self.root, &other.root) {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let sample = self.root.sample()?;
        let mut state = self
            .root
            .state
            .lock()
            .expect("paired original security publication");
        self.validate_locked(&mut state, sample)?;
        other.validate_locked(&mut state, sample)?;
        Ok(action())
    }
    pub(crate) fn with_security<T>(
        &self,
        action: impl FnOnce() -> T,
    ) -> Result<T, EnvironmentError> {
        let sample = self.root.sample()?;
        let mut state = self.root.state.lock().expect("environment root lock");
        self.validate_locked(&mut state, sample)?;
        Ok(action())
    }
    pub(crate) fn reserve(
        &self,
        value: ResourceLimits,
    ) -> Result<ResourceCharge, EnvironmentError> {
        let sample = self.root.sample()?;
        let mut state = self.root.state.lock().expect("environment root lock");
        let chain = self.validate_locked(&mut state, sample)?;
        for i in chain.into_iter().flatten() {
            state.accounts[i]
                .used
                .checked_add(value)
                .filter(|v| v.fits(state.accounts[i].limit))
                .ok_or_else(|| {
                    self.root.diagnostic_count(
                        crate::diagnostics_v4::DiagnosticCounter::ResourceRejections,
                    );
                    EnvironmentError::Capacity
                })?;
            state.accounts[i].references.checked_add(1).ok_or_else(|| {
                self.root
                    .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::ResourceRejections);
                EnvironmentError::Capacity
            })?;
        }
        for i in chain.into_iter().flatten() {
            state.accounts[i].used = state.accounts[i]
                .used
                .checked_add(value)
                .expect("validated resource vector");
            state.accounts[i].references += 1;
        }
        Ok(ResourceCharge {
            account: self.clone(),
            value,
        })
    }
    #[allow(dead_code)]
    pub(crate) fn revoke(&self) {
        let mut state = self.root.state.lock().expect("environment root lock");
        if state.accounts[self.index].generation == self.generation {
            state.accounts[self.index].closed = true;
            if let Some(security) = &state.accounts[self.index].security_closed {
                security.store(true, Ordering::Release);
            }
        }
        drop(state);
        self.root.changed.notify_waiters();
    }
    pub(crate) async fn security_changed(&self) {
        async fn wait(wake: Option<Arc<Notify>>) {
            if let Some(wake) = wake {
                wake.notified().await;
            } else {
                std::future::pending::<()>().await;
            }
        }
        let wakes = self
            ._lease
            .subscriptions
            .lock()
            .expect("namespace subscription lock")
            .as_ref()
            .map(|subscriptions| subscriptions.wakes.clone())
            .unwrap_or_else(|| std::array::from_fn(|_| None));
        let [a, b, c, d, e, f, g, h] = wakes;
        tokio::select! {
            _ = self.root.changed.notified() => {},
            _ = wait(a) => {}, _ = wait(b) => {}, _ = wait(c) => {},
            _ = wait(d) => {}, _ = wait(e) => {},
            _ = wait(f) => {}, _ = wait(g) => {}, _ = wait(h) => {},
        }
    }
    pub(crate) fn next_security_check(&self) -> Duration {
        // This is a wakeup hint only; every protected action samples and checks
        // the actual original bounds again. No timer manufactures authorization.
        Duration::from_millis(100)
    }
}
impl ResourceCharge {
    /// Charge physical work to this original Account and environment. A
    /// retained control owner cannot fund a replacement or foreign Account.
    pub(crate) fn reserve_related(
        &self,
        root: &Arc<EnvironmentRoot>,
        value: ResourceLimits,
    ) -> Result<Self, EnvironmentError> {
        if !Arc::ptr_eq(&self.account.root, root) {
            return Err(EnvironmentError::Configuration);
        }
        self.account.reserve(value)
    }
    pub(crate) fn belongs_to(&self, account: &ResourceAccount) -> bool {
        self.account.same_owner(account)
    }
    pub(crate) fn covers(&self, account: &ResourceAccount, value: ResourceLimits) -> bool {
        self.account.same_owner(account) && value.fits(self.value)
    }
    pub(crate) fn matches(&self, account: &ResourceAccount, value: ResourceLimits) -> bool {
        self.account.same_owner(account) && self.value.fits(value) && value.fits(self.value)
    }
    pub(crate) fn split(&mut self, value: ResourceLimits) -> Result<Self, EnvironmentError> {
        if !value.fits(self.value) {
            return Err(EnvironmentError::Configuration);
        }
        let mut state = self
            .account
            .root
            .state
            .lock()
            .expect("environment root lock");
        let chain = account_chain(&state, self.account.index);
        for i in chain.into_iter().flatten() {
            state.accounts[i]
                .references
                .checked_add(1)
                .ok_or(EnvironmentError::Capacity)?;
        }
        for i in chain.into_iter().flatten() {
            state.accounts[i].references += 1;
        }
        self.value.subtract(value);
        Ok(Self {
            account: self.account.clone(),
            value,
        })
    }
}
impl Drop for ResourceCharge {
    fn drop(&mut self) {
        let mut state = self
            .account
            .root
            .state
            .lock()
            .expect("environment root lock");
        let session = &state.accounts[self.account.index];
        assert_eq!(session.generation, self.account.generation);
        for i in account_chain(&state, self.account.index)
            .into_iter()
            .flatten()
        {
            state.accounts[i].used.subtract(self.value);
            state.accounts[i].references -= 1;
        }
        drop(state);
        self.account.root.changed.notify_waiters();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    pub(crate) struct TestClock {
        pub(crate) value: Mutex<TrustedTimeSample>,
        unavailable: AtomicBool,
    }
    impl TestClock {
        pub(crate) fn new(lower_ms: u64, upper_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                value: Mutex::new(TrustedTimeSample {
                    lower_ms,
                    upper_ms,
                    monotonic_sample: Instant::now(),
                    clock_incarnation: 1,
                    anchor_age_upper_ms: 0,
                }),
                unavailable: AtomicBool::new(false),
            })
        }
    }
    impl TrustedTimeSource for TestClock {
        fn sample(&self) -> Result<TrustedTimeSample, EnvironmentError> {
            if self.unavailable.load(Ordering::Acquire) {
                return Err(EnvironmentError::TimeUnavailable);
            }
            Ok(*self.value.lock().unwrap())
        }
    }
    pub(crate) fn bounds() -> AuthorizationBounds {
        AuthorizationBounds {
            not_before_ms: 1,
            not_after_ms: 100_000,
            freshness_not_after_ms: 50_000,
        }
    }
    pub(crate) fn environment() -> Arc<EnvironmentRoot> {
        EnvironmentRoot::new(TransportEnvironmentOptions {
            clock: Some(TestClock::new(1_000, 1_010)),
            ..TransportEnvironmentOptions::default()
        })
        .unwrap()
    }

    #[test]
    fn detached_result_releases_session_slot_but_keeps_original_authorization() {
        let root = environment();
        let baseline = root.charged();
        let session = root.admit([1; 32], bounds()).unwrap();
        let result = session.reserve_result().unwrap();
        let charge = result
            .reserve(ResourceLimits {
                sdk_bytes: 64,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .unwrap();
        let session_index = session.index;
        assert_eq!(
            root.state.lock().unwrap().accounts[session_index]
                .used
                .sdk_bytes,
            64
        );
        drop(session);
        assert_eq!(root.charged().sessions, 1);
        result.detach_result();
        assert_eq!(root.charged().sessions, 0);
        assert_eq!(root.charged().sdk_bytes, baseline.sdk_bytes + 64);
        assert!(!root.state.lock().unwrap().accounts[session_index].active);
        result.check().unwrap();
        let replacement = root.admit([1; 32], bounds()).unwrap();
        assert_eq!(replacement.index, session_index);
        replacement.revoke();
        result.check().unwrap();
        root.close();
        assert_eq!(result.check(), Err(EnvironmentError::Closed));
        drop((result, charge, replacement));
        assert_eq!(root.charged(), baseline);
        assert!(root.cleanup().0);
    }

    #[tokio::test]
    async fn namespace_freshness_uses_live_subscription_without_extending_hard_cap() {
        use crate::namespace_v4::tests::{anchor, binding, update};
        let root = environment();
        root.register_namespace(anchor()).unwrap();
        root.install_namespace(&update(1)).unwrap();
        let account = root
            .admit(
                [1; 32],
                AuthorizationBounds {
                    freshness_not_after_ms: 1_060,
                    ..bounds()
                },
            )
            .unwrap();
        account.bind_namespaces(&[binding()]).unwrap();
        let original_deadline =
            root.state.lock().unwrap().accounts[account.index].authorization_deadline;
        tokio::time::sleep(Duration::from_millis(70)).await;
        account.check().unwrap();
        assert_eq!(
            root.state.lock().unwrap().accounts[account.index].authorization_deadline,
            original_deadline
        );
    }

    #[test]
    fn original_namespace_subscription_survives_result_detachment() {
        use crate::namespace_v4::tests::{anchor, binding, update};
        let root = environment();
        root.register_namespace(anchor()).unwrap();
        root.install_namespace(&update(1)).unwrap();
        let session = root.admit([1; 32], bounds()).unwrap();
        session.bind_namespaces(&[binding()]).unwrap();
        let result = session.reserve_result().unwrap();
        result.detach_result();
        drop(session);
        assert_eq!(root.charged().sessions, 0);
        result.check().unwrap();
        root.terminate_namespace(anchor().key).unwrap();
        assert_eq!(
            result.with_security(|| panic!("revoked result transfer")),
            Err(EnvironmentError::Closed)
        );
    }

    #[test]
    fn missing_clock_never_admits_an_authorization_owner() {
        let root = EnvironmentRoot::new(TransportEnvironmentOptions::default()).unwrap();
        assert_eq!(
            root.admit([1; 32], bounds()).unwrap_err(),
            EnvironmentError::TimeUnavailable
        );
        assert_eq!(root.charged().sessions, 0);
    }

    #[test]
    fn root_tenant_and_session_limits_are_one_atomic_reservation() {
        let mut options = TransportEnvironmentOptions {
            clock: Some(TestClock::new(1_000, 1_010)),
            ..TransportEnvironmentOptions::default()
        };
        options.root_limits.work_slots = 3;
        options.tenant_limits.work_slots = 2;
        options.session_limits.work_slots = 1;
        let root = EnvironmentRoot::new(options).unwrap();
        let baseline = root.charged();
        let a = root.admit([1; 32], bounds()).unwrap();
        let b = root.admit([1; 32], bounds()).unwrap();
        let c = root.admit([1; 32], bounds()).unwrap();
        let d = root.admit([2; 32], bounds()).unwrap();
        let e = root.admit([3; 32], bounds()).unwrap();
        let cost = ResourceLimits {
            sdk_bytes: 32,
            work_slots: 1,
            tasks: 1,
            sessions: 0,
            ..ResourceLimits::default()
        };
        let first = a.reserve(cost).unwrap();
        assert_eq!(a.reserve(cost).unwrap_err(), EnvironmentError::Capacity);
        let second = b.reserve(cost).unwrap();
        assert_eq!(c.reserve(cost).unwrap_err(), EnvironmentError::Capacity);
        let third = d.reserve(cost).unwrap();
        assert_eq!(e.reserve(cost).unwrap_err(), EnvironmentError::Capacity);
        assert_eq!(root.charged().work_slots, 3);
        assert_eq!(root.charged().sdk_bytes, baseline.sdk_bytes + 96);
        drop((a, b, c, d, e));
        assert_eq!(root.charged().sessions, 3);
        root.close();
        assert_eq!(root.cleanup(), (false, false));
        drop((first, second, third));
        assert_eq!(root.charged(), baseline);
        assert_eq!(root.cleanup(), (true, false));
    }

    #[test]
    fn lower_bound_wait_and_expiration_equality_are_distinct() {
        let sample = *TestClock::new(1_000, 1_010).value.lock().unwrap();
        assert_eq!(
            check_bounds(
                AuthorizationBounds {
                    not_before_ms: 1_005,
                    ..bounds()
                },
                sample
            ),
            Err(EnvironmentError::TimePending)
        );
        assert_eq!(
            check_bounds(
                AuthorizationBounds {
                    not_after_ms: 1_010,
                    ..bounds()
                },
                sample
            ),
            Err(EnvironmentError::AuthorizationDenied)
        );
        assert_eq!(
            check_bounds(
                AuthorizationBounds {
                    freshness_not_after_ms: 1_010,
                    ..bounds()
                },
                sample
            ),
            Err(EnvironmentError::AuthorizationDenied)
        );
    }

    #[test]
    fn unavailable_source_can_use_only_the_still_valid_original_envelope() {
        let clock = TestClock::new(1_000, 1_010);
        let root = EnvironmentRoot::new(TransportEnvironmentOptions {
            clock: Some(clock.clone()),
            ..TransportEnvironmentOptions::default()
        })
        .unwrap();
        let account = root.admit([1; 32], bounds()).unwrap();
        clock.unavailable.store(true, Ordering::Release);
        account.check().unwrap();
        root.state
            .lock()
            .unwrap()
            .clock_sample
            .as_mut()
            .unwrap()
            .anchor_age_upper_ms = 60_001;
        assert_eq!(account.check(), Err(EnvironmentError::TimeUnavailable));
    }

    #[test]
    fn clock_discontinuity_and_contradiction_seal_original_owners() {
        for discontinuity in [false, true] {
            let clock = TestClock::new(1_000, 1_010);
            let root = EnvironmentRoot::new(TransportEnvironmentOptions {
                clock: Some(clock.clone()),
                ..TransportEnvironmentOptions::default()
            })
            .unwrap();
            let account = root.admit([1; 32], bounds()).unwrap();
            {
                let mut sample = clock.value.lock().unwrap();
                if discontinuity {
                    sample.clock_incarnation += 1;
                } else {
                    sample.lower_ms += 5_000;
                    sample.upper_ms += 5_000;
                }
            }
            assert_eq!(account.check(), Err(EnvironmentError::TimeUnavailable));
            assert_eq!(
                account.with_security(|| panic!("sealed transfer")),
                Err(EnvironmentError::Closed)
            );
        }
    }

    #[tokio::test]
    async fn refined_anchor_never_extends_an_original_deadline() {
        let clock = TestClock::new(1_000, 1_060);
        let root = EnvironmentRoot::new(TransportEnvironmentOptions {
            clock: Some(clock.clone()),
            ..TransportEnvironmentOptions::default()
        })
        .unwrap();
        let account = root
            .admit(
                [1; 32],
                AuthorizationBounds {
                    not_after_ms: 1_100,
                    ..bounds()
                },
            )
            .unwrap();
        clock.value.lock().unwrap().upper_ms = 1_001;
        account.check().unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(account.check(), Err(EnvironmentError::AuthorizationDenied));
        assert_eq!(account.check(), Err(EnvironmentError::Closed));
    }

    #[test]
    fn revocation_and_environment_close_share_the_actual_transfer_gate() {
        use std::sync::Barrier;
        let root = environment();
        let account = root.admit([1; 32], bounds()).unwrap();
        let entered = Barrier::new(2);
        let release = Barrier::new(2);
        std::thread::scope(|scope| {
            let transferring = scope.spawn(|| {
                account.with_security(|| {
                    entered.wait();
                    release.wait();
                    17
                })
            });
            entered.wait();
            let closing = scope.spawn(|| root.close());
            release.wait();
            assert_eq!(transferring.join().unwrap(), Ok(17));
            closing.join().unwrap();
        });
        assert_eq!(account.with_security(|| 23), Err(EnvironmentError::Closed));
        let other = environment().admit([2; 32], bounds()).unwrap();
        other.revoke();
        assert_eq!(other.with_security(|| 23), Err(EnvironmentError::Closed));
    }
    fn unit(dimension: usize, amount: u64) -> ResourceLimits {
        let mut value = ResourceLimits::default();
        *match dimension {
            0 => &mut value.sdk_bytes,
            1 => &mut value.provider_bytes,
            2 => &mut value.disk_bytes,
            3 => &mut value.items,
            4 => &mut value.work_slots,
            5 => &mut value.tasks,
            6 => &mut value.timers,
            7 => &mut value.connections,
            8 => &mut value.tls_handshakes,
            9 => &mut value.sessions,
            10 => &mut value.native_handles,
            _ => unreachable!(),
        } = amount;
        value
    }
    #[test]
    fn every_dimension_is_bounded_and_split_retains_original_cleanup() {
        let options = TransportEnvironmentOptions {
            clock: Some(TestClock::new(1000, 1010)),
            session_limits: ResourceLimits {
                disk_bytes: 1024,
                ..TransportEnvironmentOptions::default().session_limits
            },
            ..TransportEnvironmentOptions::default()
        };
        let limits = options.session_limits;
        for dimension in 0..ResourceLimits::DIMENSIONS.len() {
            let root = EnvironmentRoot::new(options.clone()).unwrap();
            let baseline = root.charged();
            let account = root.admit([1; 32], bounds()).unwrap();
            let available = limits.values()[dimension] - u64::from(dimension == 9);
            let mut charge = account.reserve(unit(dimension, available)).unwrap();
            let full = root.charged();
            assert_eq!(
                account.reserve(unit(dimension, 1)).unwrap_err(),
                EnvironmentError::Capacity,
                "{}",
                ResourceLimits::DIMENSIONS[dimension]
            );
            assert_eq!(root.charged(), full);
            let tail = charge.split(unit(dimension, available)).unwrap();
            assert_eq!(root.charged(), full);
            root.close();
            drop(charge);
            drop(account);
            assert_eq!(root.cleanup(), (false, false));
            assert_eq!(root.charged().values()[dimension], full.values()[dimension]);
            drop(tail);
            assert_eq!(root.charged(), baseline);
            assert_eq!(root.cleanup(), (true, false));
        }
    }
    #[test]
    fn independent_provider_disk_and_sdk_bytes_never_substitute_and_overflow_fails() {
        let root = environment();
        let account = root.admit([1; 32], bounds()).unwrap();
        let baseline = root.charged();
        assert_eq!(
            account
                .reserve(ResourceLimits {
                    disk_bytes: 1,
                    ..ResourceLimits::default()
                })
                .unwrap_err(),
            EnvironmentError::Capacity
        );
        assert_eq!(root.charged(), baseline);
        for dimension in 0..ResourceLimits::DIMENSIONS.len() {
            assert!(
                unit(dimension, u64::MAX)
                    .checked_add(unit(dimension, 1))
                    .is_none()
            );
        }
        let provider = account
            .reserve(ResourceLimits {
                provider_bytes: 4096,
                ..ResourceLimits::default()
            })
            .unwrap();
        let used = root.charged();
        assert_eq!(used.sdk_bytes, baseline.sdk_bytes);
        assert_eq!(used.disk_bytes, baseline.disk_bytes);
        assert_eq!(used.provider_bytes, baseline.provider_bytes + 4096);
        drop(provider);
        assert_eq!(root.charged(), baseline);
    }
}
