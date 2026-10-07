//! One finite ordinary and Completion service per actual Environment root.
//! Contexts borrow real invocations; they cannot create execution authority.
use crate::environment_v4::{
    ApplicationServiceBacking, ApplicationServiceCharge, EnvironmentCharge, EnvironmentError,
    EnvironmentRoot, ResourceAccount, ResourceCharge, ResourceLimits,
};
use std::{
    collections::VecDeque,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread::ThreadId,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApplicationInvocationError {
    #[error("application dependency is unavailable")]
    DependencyUnavailable,
    #[error("known application dependency cannot wait for its own exit")]
    KnownApplicationDependency,
    #[error("completion dependency is unavailable")]
    CompletionDependencyUnavailable,
    #[error("application execution capacity is exhausted")]
    ResourceExhausted,
    #[error("application invocation is canceled")]
    Canceled,
    #[error("application execution service is closed")]
    Closed,
}
type Result<T> = std::result::Result<T, ApplicationInvocationError>;
impl From<EnvironmentError> for ApplicationInvocationError {
    fn from(error: EnvironmentError) -> Self {
        match error {
            EnvironmentError::Capacity => Self::ResourceExhausted,
            EnvironmentError::Closed => Self::Closed,
            _ => Self::DependencyUnavailable,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationLane {
    Short,
    Resident,
    Completion,
    ContractQuery,
    Management,
}
struct State {
    ordinary_reserved: usize,
    resident_reserved: usize,
    ordinary_running: usize,
    resident_running: usize,
    completion_reserved: usize,
    completion_running: usize,
    claims: usize,
    management_reserved: usize,
    management_running: usize,
    query_reserved: usize,
    query_running: usize,
    closed: bool,
    completion_index: Vec<Option<Weak<Mutex<CompletionState>>>>,
    completion_ready: VecDeque<usize>,
    ordinary_ready: VecDeque<Weak<OrdinaryWaiter>>,
    next_resident: bool,
    last_group: Weak<GroupInner>,
    query_ready: VecDeque<Weak<QueryWaiter>>,
    management_ready: VecDeque<Weak<ManagementWaiter>>,
    query_owners: usize,
    completion_cursor: usize,
}
pub(crate) struct ApplicationServices {
    root: Arc<EnvironmentRoot>,
    config: crate::ApplicationExecutorConfig,
    ordinary: Arc<ApplicationServiceBacking>,
    completion: Arc<ApplicationServiceBacking>,
    management: Option<Arc<ApplicationServiceBacking>>,
    query: Mutex<Option<Arc<ApplicationServiceBacking>>>,
    state: Mutex<State>,
    cancellation: CancellationToken,
    changed: Notify,
}
impl fmt::Debug for ApplicationServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicationServices { <opaque> }")
    }
}
impl ApplicationServices {
    pub(crate) fn new(
        root: Arc<EnvironmentRoot>,
    ) -> std::result::Result<Arc<Self>, EnvironmentError> {
        let config = root.application_config().clone();
        config.validate()?;
        let slots = (config.running + config.ready) as u64;
        let ordinary = ApplicationServiceBacking::new(
            &root,
            ResourceLimits {
                sdk_bytes: config.ordinary_bytes,
                items: slots + 2,
                tasks: slots,
                work_slots: slots,
                ..ResourceLimits::default()
            },
        )?;
        let completion = ApplicationServiceBacking::new(
            &root,
            ResourceLimits {
                sdk_bytes: 256 << 10,
                items: 4104,
                tasks: 6,
                work_slots: 6,
                ..ResourceLimits::default()
            },
        )?;
        let management = if config.execution {
            Some(ApplicationServiceBacking::new(
                &root,
                ResourceLimits {
                    sdk_bytes: 256 << 10,
                    items: 8,
                    tasks: 4,
                    work_slots: 4,
                    ..ResourceLimits::default()
                },
            )?)
        } else {
            None
        };
        let reserved = config.completion_reserved;
        let ready = config.ready;
        Ok(Arc::new(Self {
            root,
            config,
            ordinary,
            completion,
            management,
            query: Mutex::new(None),
            state: Mutex::new(State {
                ordinary_reserved: 0,
                resident_reserved: 0,
                ordinary_running: 0,
                resident_running: 0,
                completion_reserved: 0,
                completion_running: 0,
                claims: 0,
                management_reserved: 0,
                management_running: 0,
                query_reserved: 0,
                query_running: 0,
                closed: false,
                completion_index: (0..reserved).map(|_| None).collect(),
                completion_ready: VecDeque::with_capacity(4),
                ordinary_ready: VecDeque::with_capacity(ready),
                next_resident: false,
                last_group: Weak::new(),
                query_ready: VecDeque::with_capacity(4),
                management_ready: VecDeque::with_capacity(2),
                query_owners: 0,
                completion_cursor: 0,
            }),
            cancellation: CancellationToken::new(),
            changed: Notify::new(),
        }))
    }
    pub(crate) fn snapshot(&self) -> crate::ApplicationExecutorSnapshot {
        let state = self.state.lock().expect("application services");
        let mut snapshot = crate::ApplicationExecutorSnapshot::empty(self.config.profile);
        snapshot.management_running = state.management_running;
        snapshot.management_reserved = state.management_reserved;
        snapshot.management_ready = state
            .management_ready
            .iter()
            .filter(|item| item.strong_count() != 0)
            .count();
        snapshot.ordinary_running = state.ordinary_running;
        snapshot.ordinary_reserved = state.ordinary_reserved;
        snapshot.resident_running = state.resident_running;
        snapshot.resident_reserved = state.resident_reserved;
        for waiter in state.ordinary_ready.iter().filter_map(Weak::upgrade) {
            snapshot.ordinary_ready += 1;
            if waiter.resident {
                snapshot.resident_ready += 1;
            }
        }
        snapshot.completion_running = state.completion_running;
        snapshot.completion_reserved = state.completion_reserved;
        snapshot.completion_claims = state.claims;
        snapshot.completion_ready = state.completion_ready.len();
        for owner in state
            .completion_index
            .iter()
            .flatten()
            .filter_map(Weak::upgrade)
        {
            snapshot.completion_owners += 1;
            let owner = owner.lock().expect("Completion owner");
            if owner.waiting && !owner.closed {
                snapshot.completion_eligible += 1;
            }
        }
        snapshot.query_running = state.query_running;
        snapshot.query_reserved = state.query_reserved;
        snapshot.query_ready = state
            .query_ready
            .iter()
            .filter(|waiter| waiter.strong_count() != 0)
            .count();
        snapshot.query_owners = state.query_owners;
        snapshot
    }
    pub(crate) fn close(&self) {
        self.state.lock().expect("application services").closed = true;
        self.cancellation.cancel();
        self.changed.notify_waiters();
    }
}
struct ApplicationDescriptor {
    _account: Option<ResourceCharge>,
    _local: Option<EnvironmentCharge>,
}
impl From<ResourceCharge> for ApplicationDescriptor {
    fn from(charge: ResourceCharge) -> Self {
        Self {
            _account: Some(charge),
            _local: None,
        }
    }
}
struct GroupInner {
    service: Arc<ApplicationServices>,
    account: Option<ResourceAccount>,
    cancellation: CancellationToken,
    descriptor: Mutex<Option<ApplicationDescriptor>>,
}
#[derive(Clone)]
pub(crate) struct ApplicationGroup(Arc<GroupInner>);
impl ApplicationGroup {
    pub(crate) fn preparation_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn new(
        account: ResourceAccount,
        service: Arc<ApplicationServices>,
    ) -> std::result::Result<Self, EnvironmentError> {
        if !account.belongs_to(&service.root) {
            return Err(EnvironmentError::Configuration);
        }
        let descriptor = account.reserve(Self::preparation_limits())?;
        Self::new_prepaid(account, service, descriptor)
    }
    pub(crate) fn new_prepaid(
        account: ResourceAccount,
        service: Arc<ApplicationServices>,
        descriptor: ResourceCharge,
    ) -> std::result::Result<Self, EnvironmentError> {
        if !account.belongs_to(&service.root)
            || !descriptor.matches(&account, Self::preparation_limits())
        {
            return Err(EnvironmentError::Configuration);
        }
        Ok(Self(Arc::new(GroupInner {
            service,
            account: Some(account),
            cancellation: CancellationToken::new(),
            descriptor: Mutex::new(Some(descriptor.into())),
        })))
    }
    /// A local metadata callback shares ordinary scheduling and accounting,
    /// but cannot acquire query, management or Completion authority.
    pub(crate) fn new_local(
        service: Arc<ApplicationServices>,
        cancellation: CancellationToken,
    ) -> std::result::Result<Self, EnvironmentError> {
        let descriptor = service
            .root
            .reserve_environment(Self::preparation_limits())?;
        Ok(Self(Arc::new(GroupInner {
            service,
            account: None,
            cancellation,
            descriptor: Mutex::new(Some(ApplicationDescriptor {
                _account: None,
                _local: Some(descriptor),
            })),
        })))
    }
    fn authenticated_account(&self) -> Result<&ResourceAccount> {
        self.0
            .account
            .as_ref()
            .ok_or(ApplicationInvocationError::DependencyUnavailable)
    }
    fn invocation_descriptor(&self) -> Result<ApplicationDescriptor> {
        let limits = Self::preparation_limits();
        match &self.0.account {
            Some(account) => Ok(account.reserve(limits)?.into()),
            None => Ok(ApplicationDescriptor {
                _account: None,
                _local: Some(self.0.service.root.reserve_environment(limits)?),
            }),
        }
    }
    fn ordinary_charge(&self) -> Result<ApplicationServiceCharge> {
        let limits = ResourceLimits {
            sdk_bytes: self.0.service.config.ordinary_slice(),
            items: 1,
            tasks: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        };
        Ok(match &self.0.account {
            Some(account) => self.0.service.ordinary.borrow(account, limits)?,
            None => self
                .0
                .service
                .ordinary
                .borrow_local(&self.0.service.root, limits)?,
        })
    }
    pub(crate) async fn local_ordinary(&self) -> Result<ApplicationPosition> {
        if self.0.account.is_some() {
            return Err(ApplicationInvocationError::DependencyUnavailable);
        }
        loop {
            let changed = self.0.service.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.ordinary_ticket(false) {
                Ok(ticket) => return ticket.position().await,
                Err(ApplicationInvocationError::ResourceExhausted) => {}
                Err(error) => return Err(error),
            }
            tokio::select! {
                _ = changed => {},
                _ = self.0.cancellation.cancelled() => return Err(ApplicationInvocationError::Closed),
                _ = self.0.service.cancellation.cancelled() => return Err(ApplicationInvocationError::Closed),
            }
        }
    }
    pub(crate) fn release_descriptor(&self) {
        self.0
            .descriptor
            .lock()
            .expect("application group descriptor")
            .take();
    }
    fn check(&self) -> Result<()> {
        if self.0.cancellation.is_cancelled() || self.0.service.cancellation.is_cancelled() {
            return Err(ApplicationInvocationError::Closed);
        }
        if let Some(account) = &self.0.account {
            account.check()?;
        } else if self.0.service.root.is_closed() {
            return Err(ApplicationInvocationError::Closed);
        }
        Ok(())
    }
    fn ancestors(
        &self,
        context: Option<&ApplicationInvocationContext>,
    ) -> Result<Vec<Arc<Invocation>>> {
        let Some(context) = context else {
            return Ok(Vec::new());
        };
        context.check_cancellation()?;
        let owner = context
            .owner
            .upgrade()
            .ok_or(ApplicationInvocationError::DependencyUnavailable)?;
        if !Arc::ptr_eq(&owner.group.0.service, &self.0.service) {
            return Err(ApplicationInvocationError::DependencyUnavailable);
        }
        let mut ancestors = Vec::with_capacity(8);
        ancestors.push(owner.clone());
        ancestors.extend(
            owner
                .ancestors
                .iter()
                .filter(|parent| parent.active.load(Ordering::Acquire))
                .cloned(),
        );
        if ancestors.len() > 8 {
            return Err(ApplicationInvocationError::DependencyUnavailable);
        }
        Ok(ancestors)
    }
    pub(crate) fn try_ordinary(
        &self,
        resident: bool,
        context: Option<&ApplicationInvocationContext>,
    ) -> Result<ApplicationPosition> {
        self.check()?;
        let ancestors = self.ancestors(context)?;
        let resident = resident
            || ancestors
                .iter()
                .any(|owner| owner.lane == ApplicationLane::Resident);
        let mut state = self.0.service.state.lock().expect("application services");
        if state.closed {
            return Err(ApplicationInvocationError::Closed);
        }
        if state.ordinary_reserved >= self.0.service.config.running
            || resident && state.resident_reserved >= self.0.service.config.resident_running
        {
            return Err(ApplicationInvocationError::DependencyUnavailable);
        }
        let charge = self.ordinary_charge()?;
        state.ordinary_reserved += 1;
        if resident {
            state.resident_reserved += 1;
        }
        drop(state);
        Ok(ApplicationPosition(Arc::new(PositionInner {
            group: self.clone(),
            lane: if resident {
                ApplicationLane::Resident
            } else {
                ApplicationLane::Short
            },
            ancestors,
            active: AtomicBool::new(false),
            synchronous: Mutex::new(SynchronousState {
                thread: None,
                depth: 0,
            }),
            _charge: charge.into(),
        })))
    }
    pub(crate) fn admit_ordinary(
        &self,
        resident: bool,
        context: Option<&ApplicationInvocationContext>,
        try_now: bool,
    ) -> Result<OrdinaryAdmission> {
        if try_now || context.is_some() {
            return self
                .try_ordinary(resident, context)
                .map(OrdinaryAdmission::Position);
        }
        self.ordinary_ticket(resident)
            .map(OrdinaryAdmission::Waiting)
    }
    fn ordinary_ticket(&self, resident: bool) -> Result<OrdinaryTicket> {
        self.check()?;
        let charge = self.ordinary_charge()?;
        let waiter = Arc::new(OrdinaryWaiter {
            group: self.clone(),
            resident,
            charge: Mutex::new(Some(charge)),
        });
        {
            let mut state = self.0.service.state.lock().expect("application services");
            state.ordinary_ready.retain(|item| item.strong_count() != 0);
            if state.closed {
                return Err(ApplicationInvocationError::Closed);
            }
            if state.ordinary_ready.len() >= self.0.service.config.ready
                || resident
                    && state
                        .ordinary_ready
                        .iter()
                        .filter_map(Weak::upgrade)
                        .filter(|item| item.resident)
                        .count()
                        >= self.0.service.config.resident_ready
            {
                return Err(ApplicationInvocationError::ResourceExhausted);
            }
            state.ordinary_ready.push_back(Arc::downgrade(&waiter));
        }
        Ok(OrdinaryTicket(waiter))
    }
    pub(crate) async fn ordinary(
        &self,
        resident: bool,
        context: Option<&ApplicationInvocationContext>,
    ) -> Result<ApplicationPosition> {
        if context.is_some() {
            return self.try_ordinary(resident, context);
        }
        self.ordinary_ticket(resident)?.position().await
    }

    pub(crate) fn try_contract_query(&self) -> Result<ApplicationPosition> {
        self.check()?;
        let backing = {
            let mut query = self.0.service.query.lock().expect("fixed query service");
            if query.is_none() {
                *query = Some(ApplicationServiceBacking::new(
                    &self.0.service.root,
                    ResourceLimits {
                        sdk_bytes: 256 << 10,
                        items: 6,
                        tasks: 5,
                        work_slots: 5,
                        ..ResourceLimits::default()
                    },
                )?);
            }
            query.as_ref().expect("fixed query backing").clone()
        };
        let mut state = self.0.service.state.lock().expect("application services");
        if state.closed {
            return Err(ApplicationInvocationError::Closed);
        }
        state
            .query_ready
            .retain(|waiter| waiter.strong_count() != 0);
        if state.query_reserved >= 1 || !state.query_ready.is_empty() {
            return Err(ApplicationInvocationError::ResourceExhausted);
        }
        let charge = backing.borrow(
            self.authenticated_account()?,
            ResourceLimits {
                sdk_bytes: (256 << 10) / 5,
                items: 1,
                tasks: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            },
        )?;
        state.query_reserved += 1;
        drop(state);
        Ok(ApplicationPosition(Arc::new(PositionInner {
            group: self.clone(),
            lane: ApplicationLane::ContractQuery,
            ancestors: Vec::new(),
            active: AtomicBool::new(false),
            synchronous: Mutex::new(SynchronousState {
                thread: None,
                depth: 0,
            }),
            _charge: charge.into(),
        })))
    }

    pub(crate) fn contract_query(&self) -> Result<QueryAdmission> {
        if let Ok(position) = self.try_contract_query() {
            return Ok(QueryAdmission::Position(position));
        }
        self.check()?;
        let backing = self
            .0
            .service
            .query
            .lock()
            .expect("fixed query service")
            .as_ref()
            .cloned()
            .ok_or(ApplicationInvocationError::ResourceExhausted)?;
        let charge = backing.borrow(
            self.authenticated_account()?,
            ResourceLimits {
                sdk_bytes: (256 << 10) / 5,
                items: 1,
                tasks: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            },
        )?;
        let waiter = Arc::new(QueryWaiter {
            group: self.clone(),
            charge: Mutex::new(Some(charge)),
        });
        let mut state = self.0.service.state.lock().expect("application services");
        state
            .query_ready
            .retain(|waiter| waiter.strong_count() != 0);
        if state.closed {
            return Err(ApplicationInvocationError::Closed);
        }
        if state.query_ready.len() >= 4 {
            return Err(ApplicationInvocationError::ResourceExhausted);
        }
        state.query_ready.push_back(Arc::downgrade(&waiter));
        Ok(QueryAdmission::Waiting(QueryTicket(waiter)))
    }
    pub(crate) fn management_position_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: (256 << 10) / 4,
            items: 1,
            tasks: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn prepare_management_position(
        &self,
        charge: ResourceCharge,
    ) -> Result<Arc<ApplicationServiceCharge>> {
        let account = self.authenticated_account()?;
        if !charge.matches(account, Self::management_position_limits()) {
            return Err(ApplicationInvocationError::DependencyUnavailable);
        }
        let backing = self
            .0
            .service
            .management
            .as_ref()
            .ok_or(ApplicationInvocationError::DependencyUnavailable)?;
        Ok(Arc::new(backing.attach_prepaid(account, charge)?))
    }
    pub(crate) fn management(
        &self,
        charge: Arc<ApplicationServiceCharge>,
    ) -> Result<ManagementAdmission> {
        self.check()?;
        if !charge.as_ref().matches(
            self.authenticated_account()?,
            Self::management_position_limits(),
        ) {
            return Err(ApplicationInvocationError::DependencyUnavailable);
        }
        let mut state = self.0.service.state.lock().expect("application services");
        if state.closed {
            return Err(ApplicationInvocationError::Closed);
        }
        state
            .management_ready
            .retain(|item| item.strong_count() != 0);
        if state.management_reserved < 2 && state.management_ready.is_empty() {
            state.management_reserved += 1;
            return Ok(ManagementAdmission::Position(ApplicationPosition(
                Arc::new(PositionInner {
                    group: self.clone(),
                    lane: ApplicationLane::Management,
                    ancestors: Vec::new(),
                    active: AtomicBool::new(false),
                    synchronous: Mutex::new(SynchronousState {
                        thread: None,
                        depth: 0,
                    }),
                    _charge: charge.into(),
                }),
            )));
        }
        if state.management_ready.len() >= 2 {
            return Err(ApplicationInvocationError::ResourceExhausted);
        }
        let waiter = Arc::new(ManagementWaiter {
            group: self.clone(),
            charge: Mutex::new(Some(charge)),
        });
        state.management_ready.push_back(Arc::downgrade(&waiter));
        Ok(ManagementAdmission::Waiting(ManagementTicket(waiter)))
    }
    pub(crate) fn query_preparation_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 4096,
            items: 1,
            tasks: 1,
            timers: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn query_owner(&self) -> Result<QueryOwner> {
        self.check()?;
        let charge = self
            .authenticated_account()?
            .reserve(Self::query_preparation_limits())?;
        self.query_owner_prepaid(charge)
    }
    pub(crate) fn query_owner_prepaid(&self, charge: ResourceCharge) -> Result<QueryOwner> {
        self.check()?;
        if !charge.matches(
            self.authenticated_account()?,
            Self::query_preparation_limits(),
        ) {
            return Err(EnvironmentError::Configuration.into());
        }
        let mut state = self.0.service.state.lock().expect("application services");
        if state.closed {
            return Err(ApplicationInvocationError::Closed);
        }
        if state.query_owners >= self.0.service.config.query_owners {
            return Err(ApplicationInvocationError::ResourceExhausted);
        }
        state.query_owners += 1;
        Ok(QueryOwner {
            group: self.clone(),
            _charge: charge,
        })
    }
    pub(crate) fn completion_owner(
        &self,
        context: Option<&ApplicationInvocationContext>,
    ) -> Result<CompletionOwner> {
        self.check()?;
        let ancestors = self.ancestors(context)?;
        let dependency = ancestors
            .iter()
            .any(|owner| owner.lane == ApplicationLane::Completion);
        let descriptor = self.authenticated_account()?.reserve(ResourceLimits {
            sdk_bytes: 4096,
            items: 1,
            ..ResourceLimits::default()
        })?;
        let mut state = self.0.service.state.lock().expect("application services");
        if state.closed {
            return Err(ApplicationInvocationError::Closed);
        }
        let index = state
            .completion_index
            .iter()
            .position(Option::is_none)
            .ok_or(ApplicationInvocationError::ResourceExhausted)?;
        if dependency && state.completion_reserved + state.claims >= 2 {
            return Err(ApplicationInvocationError::CompletionDependencyUnavailable);
        }
        let owner = Arc::new(CompletionInner {
            group: self.clone(),
            ancestors,
            index,
            state: Arc::new(Mutex::new(CompletionState {
                waiting: false,
                ready: false,
                claim: dependency,
                closed: false,
            })),
            _descriptor: descriptor,
        });
        if dependency {
            state.claims += 1;
        }
        state.completion_index[index] = Some(Arc::downgrade(&owner.state));
        drop(state);
        Ok(CompletionOwner(owner))
    }
    pub(crate) fn synchronous_stage<T>(
        &self,
        context: &ApplicationInvocationContext,
        callback: impl FnOnce(ApplicationInvocationContext) -> T,
    ) -> Result<T> {
        self.check()?;
        let ancestors = self.ancestors(Some(context))?;
        let parent = ancestors
            .first()
            .ok_or(ApplicationInvocationError::DependencyUnavailable)?;
        let position = parent
            .position
            .upgrade()
            .ok_or(ApplicationInvocationError::DependencyUnavailable)?;
        if !matches!(
            position.lane,
            ApplicationLane::Short | ApplicationLane::Resident
        ) || !position.active.load(Ordering::Acquire)
        {
            return Err(ApplicationInvocationError::DependencyUnavailable);
        }
        let thread = std::thread::current().id();
        let mut synchronous = position
            .synchronous
            .lock()
            .expect("synchronous application stage");
        if synchronous.depth >= 8 || synchronous.thread.is_some_and(|owner| owner != thread) {
            return Err(ApplicationInvocationError::KnownApplicationDependency);
        }
        let descriptor = self
            .authenticated_account()?
            .reserve(Self::preparation_limits())?
            .into();
        synchronous.thread = Some(thread);
        synchronous.depth += 1;
        drop(synchronous);
        let invocation = Arc::new(Invocation {
            group: self.clone(),
            lane: position.lane,
            position: Arc::downgrade(&position),
            ancestors,
            active: AtomicBool::new(true),
            cancellation: CancellationToken::new(),
            _descriptor: descriptor,
        });
        let guard = ApplicationInvocation {
            owner: invocation,
            position,
            direct: true,
        };
        Ok(callback(guard.context()))
    }
    pub(crate) fn close(&self) {
        self.0.cancellation.cancel();
        self.0.service.changed.notify_waiters();
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.cancellation.is_cancelled() || self.0.service.cancellation.is_cancelled()
    }
}
struct OrdinaryWaiter {
    group: ApplicationGroup,
    resident: bool,
    charge: Mutex<Option<ApplicationServiceCharge>>,
}
pub(crate) struct OrdinaryTicket(Arc<OrdinaryWaiter>);
impl OrdinaryTicket {
    async fn position(&self) -> Result<ApplicationPosition> {
        loop {
            let changed = self.0.group.0.service.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.0.group.check()?;
            {
                let mut state = self
                    .0
                    .group
                    .0
                    .service
                    .state
                    .lock()
                    .expect("application services");
                state.ordinary_ready.retain(|item| item.strong_count() != 0);
                let resident = self.0.resident;
                let available = state.ordinary_reserved < self.0.group.0.service.config.running
                    && (!resident
                        || state.resident_reserved
                            < self.0.group.0.service.config.resident_running);
                let last = state.last_group.upgrade();
                let eligible = |item: &OrdinaryWaiter| {
                    !item.resident
                        || state.resident_reserved < self.0.group.0.service.config.resident_running
                };
                let different = |item: &OrdinaryWaiter| {
                    last.as_ref()
                        .is_none_or(|last| !Arc::ptr_eq(last, &item.group.0))
                };
                let preferred =
                    state
                        .ordinary_ready
                        .iter()
                        .filter_map(Weak::upgrade)
                        .find(|item| {
                            item.resident == state.next_resident
                                && eligible(item)
                                && different(item)
                        });
                let first = preferred
                    .or_else(|| {
                        state
                            .ordinary_ready
                            .iter()
                            .filter_map(Weak::upgrade)
                            .find(|item| eligible(item) && different(item))
                    })
                    .or_else(|| {
                        state
                            .ordinary_ready
                            .iter()
                            .filter_map(Weak::upgrade)
                            .find(|item| eligible(item))
                    });
                if available
                    && first
                        .as_ref()
                        .is_some_and(|first| Arc::ptr_eq(first, &self.0))
                {
                    state.ordinary_ready.retain(|item| {
                        item.upgrade()
                            .is_some_and(|item| !Arc::ptr_eq(&item, &self.0))
                    });
                    state.ordinary_reserved += 1;
                    if resident {
                        state.resident_reserved += 1;
                    }
                    state.next_resident = !resident;
                    state.last_group = Arc::downgrade(&self.0.group.0);
                    let charge = self
                        .0
                        .charge
                        .lock()
                        .expect("ordinary waiter charge")
                        .take()
                        .expect("original ordinary charge");
                    drop(state);
                    self.0.group.0.service.changed.notify_waiters();
                    return Ok(ApplicationPosition(Arc::new(PositionInner {
                        group: self.0.group.clone(),
                        lane: if resident {
                            ApplicationLane::Resident
                        } else {
                            ApplicationLane::Short
                        },
                        ancestors: Vec::new(),
                        active: AtomicBool::new(false),
                        synchronous: Mutex::new(SynchronousState {
                            thread: None,
                            depth: 0,
                        }),
                        _charge: charge.into(),
                    })));
                }
                drop(state);
            }
            tokio::select! { _ = changed => {}, _ = self.0.group.0.cancellation.cancelled() => return Err(ApplicationInvocationError::Canceled) }
        }
    }
}
impl Drop for OrdinaryTicket {
    fn drop(&mut self) {
        let service = &self.0.group.0.service;
        service
            .state
            .lock()
            .expect("application services")
            .ordinary_ready
            .retain(|item| {
                item.upgrade()
                    .is_some_and(|item| !Arc::ptr_eq(&item, &self.0))
            });
        service.changed.notify_waiters();
    }
}
pub(crate) enum OrdinaryAdmission {
    Position(ApplicationPosition),
    Waiting(OrdinaryTicket),
}
impl OrdinaryAdmission {
    pub(crate) async fn position(self) -> Result<ApplicationPosition> {
        match self {
            Self::Position(position) => Ok(position),
            Self::Waiting(ticket) => ticket.position().await,
        }
    }
}

struct SynchronousState {
    thread: Option<ThreadId>,
    depth: u8,
}
// Ordinary positions own their allocation. Management positions borrow one
// pre-READY slot whose original owner retains it through channel cleanup.
enum PositionCharge {
    Owned {
        _charge: ApplicationServiceCharge,
    },
    Shared {
        _charge: Arc<ApplicationServiceCharge>,
    },
}
impl From<ApplicationServiceCharge> for PositionCharge {
    fn from(charge: ApplicationServiceCharge) -> Self {
        Self::Owned { _charge: charge }
    }
}
impl From<Arc<ApplicationServiceCharge>> for PositionCharge {
    fn from(charge: Arc<ApplicationServiceCharge>) -> Self {
        Self::Shared { _charge: charge }
    }
}
struct PositionInner {
    group: ApplicationGroup,
    lane: ApplicationLane,
    ancestors: Vec<Arc<Invocation>>,
    active: AtomicBool,
    synchronous: Mutex<SynchronousState>,
    _charge: PositionCharge,
}
pub(crate) struct ApplicationPosition(Arc<PositionInner>);
impl ApplicationPosition {
    pub(crate) fn enter(&self) -> Result<ApplicationInvocation> {
        self.0.group.check()?;
        if self
            .0
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ApplicationInvocationError::KnownApplicationDependency);
        }
        let descriptor = match self.0.group.invocation_descriptor() {
            Ok(descriptor) => descriptor,
            Err(error) => {
                self.0.active.store(false, Ordering::Release);
                return Err(error);
            }
        };
        let mut state = self
            .0
            .group
            .0
            .service
            .state
            .lock()
            .expect("application services");
        if state.closed {
            self.0.active.store(false, Ordering::Release);
            return Err(ApplicationInvocationError::Closed);
        }
        match self.0.lane {
            ApplicationLane::Short => state.ordinary_running += 1,
            ApplicationLane::Resident => {
                state.ordinary_running += 1;
                state.resident_running += 1;
            }
            ApplicationLane::Completion => state.completion_running += 1,
            ApplicationLane::ContractQuery => state.query_running += 1,
            ApplicationLane::Management => state.management_running += 1,
        }
        drop(state);
        Ok(ApplicationInvocation {
            owner: Arc::new(Invocation {
                group: self.0.group.clone(),
                lane: self.0.lane,
                position: Arc::downgrade(&self.0),
                ancestors: self.0.ancestors.clone(),
                active: AtomicBool::new(true),
                cancellation: CancellationToken::new(),
                _descriptor: descriptor,
            }),
            position: self.0.clone(),
            direct: false,
        })
    }
}
impl Drop for PositionInner {
    fn drop(&mut self) {
        let mut state = self
            .group
            .0
            .service
            .state
            .lock()
            .expect("application services");
        match self.lane {
            ApplicationLane::Completion => state.completion_reserved -= 1,
            ApplicationLane::ContractQuery => state.query_reserved -= 1,
            ApplicationLane::Management => state.management_reserved -= 1,
            ApplicationLane::Short => state.ordinary_reserved -= 1,
            ApplicationLane::Resident => {
                state.ordinary_reserved -= 1;
                state.resident_reserved -= 1;
            }
        }
        drop(state);
        self.group.0.service.changed.notify_waiters();
    }
}
struct Invocation {
    group: ApplicationGroup,
    lane: ApplicationLane,
    position: Weak<PositionInner>,
    ancestors: Vec<Arc<Invocation>>,
    active: AtomicBool,
    cancellation: CancellationToken,
    _descriptor: ApplicationDescriptor,
}
/// A borrowed, unforgeable reference to one actual application callback. Cloning
/// the context does not retain its permit or revive it after actual return.
#[derive(Clone)]
pub struct ApplicationInvocationContext {
    owner: Weak<Invocation>,
}
impl fmt::Debug for ApplicationInvocationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicationInvocationContext { <opaque> }")
    }
}
impl ApplicationInvocationContext {
    pub fn check_cancellation(&self) -> Result<()> {
        let owner = self
            .owner
            .upgrade()
            .ok_or(ApplicationInvocationError::DependencyUnavailable)?;
        if !owner.active.load(Ordering::Acquire) {
            return Err(ApplicationInvocationError::DependencyUnavailable);
        }
        if owner.cancellation.is_cancelled()
            || owner.group.0.cancellation.is_cancelled()
            || owner.group.0.service.cancellation.is_cancelled()
            || owner.ancestors.iter().any(|parent| {
                parent.active.load(Ordering::Acquire) && parent.cancellation.is_cancelled()
            })
        {
            return Err(ApplicationInvocationError::Canceled);
        }
        Ok(())
    }
}
pub(crate) struct ApplicationInvocation {
    owner: Arc<Invocation>,
    position: Arc<PositionInner>,
    direct: bool,
}
impl ApplicationInvocation {
    pub(crate) fn context(&self) -> ApplicationInvocationContext {
        ApplicationInvocationContext {
            owner: Arc::downgrade(&self.owner),
        }
    }
    pub(crate) fn cancel(&self) {
        self.owner.cancellation.cancel();
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.owner.cancellation.clone()
    }
}
impl Drop for ApplicationInvocation {
    fn drop(&mut self) {
        self.owner.active.store(false, Ordering::Release);
        if self.direct {
            let mut synchronous = self
                .position
                .synchronous
                .lock()
                .expect("synchronous application stage");
            synchronous.depth -= 1;
            if synchronous.depth == 0 {
                synchronous.thread = None;
            }
            return;
        }
        self.position.active.store(false, Ordering::Release);
        let mut state = self
            .position
            .group
            .0
            .service
            .state
            .lock()
            .expect("application services");
        match self.position.lane {
            ApplicationLane::Short => state.ordinary_running -= 1,
            ApplicationLane::Resident => {
                state.ordinary_running -= 1;
                state.resident_running -= 1;
            }
            ApplicationLane::Completion => state.completion_running -= 1,
            ApplicationLane::ContractQuery => state.query_running -= 1,
            ApplicationLane::Management => state.management_running -= 1,
        }
        drop(state);
        self.position.group.0.service.changed.notify_waiters();
    }
}
struct CompletionState {
    waiting: bool,
    ready: bool,
    claim: bool,
    closed: bool,
}
struct CompletionInner {
    group: ApplicationGroup,
    ancestors: Vec<Arc<Invocation>>,
    index: usize,
    state: Arc<Mutex<CompletionState>>,
    _descriptor: ResourceCharge,
}
pub(crate) struct CompletionOwner(Arc<CompletionInner>);
fn refill_completion_ready(state: &mut State) {
    let capacity = state.completion_index.len();
    for _ in 0..capacity {
        if state.completion_ready.len() >= 4 {
            break;
        }
        let index = state.completion_cursor;
        state.completion_cursor = (state.completion_cursor + 1) % capacity;
        let Some(owner) = state.completion_index[index]
            .as_ref()
            .and_then(Weak::upgrade)
        else {
            continue;
        };
        let mut owner = owner.lock().expect("Completion owner");
        if owner.waiting && !owner.ready && !owner.claim && !owner.closed {
            owner.ready = true;
            state.completion_ready.push_back(index);
        }
    }
}
impl CompletionOwner {
    /// Only a complete current input and a real waiting caller make a decoder
    /// eligible. No second reader or decoder queue is created here.
    pub(crate) async fn position(&self) -> Result<ApplicationPosition> {
        let service = &self.0.group.0.service;
        {
            let mut state = service.state.lock().expect("application services");
            let mut owner = self.0.state.lock().expect("Completion owner");
            if owner.waiting || owner.closed {
                return Err(ApplicationInvocationError::KnownApplicationDependency);
            }
            let dependent = self.0.ancestors.iter().any(|ancestor| {
                ancestor.active.load(Ordering::Acquire)
                    && ancestor.lane == ApplicationLane::Completion
            });
            if dependent && !owner.claim {
                if state.completion_reserved + state.claims >= service.config.completion_running {
                    return Err(ApplicationInvocationError::CompletionDependencyUnavailable);
                }
                state.claims += 1;
                owner.claim = true;
            }
            owner.waiting = true;
            drop(owner);
            refill_completion_ready(&mut state);
        }
        let _wait = CompletionWait(self.0.clone());
        loop {
            let changed = service.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.0.group.check()?;
            {
                let mut state = service.state.lock().expect("application services");
                refill_completion_ready(&mut state);
                let mut owner = self.0.state.lock().expect("Completion owner");
                if owner.closed || state.closed {
                    return Err(ApplicationInvocationError::Closed);
                }
                let first = state.completion_ready.front().copied();
                let available = owner.claim || state.completion_reserved + state.claims < 2;
                if available && (owner.claim || first.is_none() || first == Some(self.0.index)) {
                    let charge = service.completion.borrow(
                        self.0.group.authenticated_account()?,
                        ResourceLimits {
                            sdk_bytes: (256 << 10) / 6,
                            items: 1,
                            tasks: 1,
                            work_slots: 1,
                            ..ResourceLimits::default()
                        },
                    )?;
                    if owner.claim {
                        state.claims -= 1;
                        owner.claim = false;
                    }
                    state
                        .completion_ready
                        .retain(|index| *index != self.0.index);
                    owner.ready = false;
                    owner.waiting = false;
                    state.completion_reserved += 1;
                    drop(owner);
                    refill_completion_ready(&mut state);
                    drop(state);
                    return Ok(ApplicationPosition(Arc::new(PositionInner {
                        group: self.0.group.clone(),
                        lane: ApplicationLane::Completion,
                        ancestors: self.0.ancestors.clone(),
                        active: AtomicBool::new(false),
                        synchronous: Mutex::new(SynchronousState {
                            thread: None,
                            depth: 0,
                        }),
                        _charge: charge.into(),
                    })));
                }
                drop(owner);
                drop(state);
            }
            tokio::select! { _ = changed => {}, _ = self.0.group.0.cancellation.cancelled() => return Err(ApplicationInvocationError::Canceled) }
        }
    }
}
struct CompletionWait(Arc<CompletionInner>);
impl Drop for CompletionWait {
    fn drop(&mut self) {
        let service = &self.0.group.0.service;
        let mut state = service.state.lock().expect("application services");
        let mut owner = self.0.state.lock().expect("Completion owner");
        owner.waiting = false;
        owner.ready = false;
        state
            .completion_ready
            .retain(|index| *index != self.0.index);
        if owner.claim {
            state.claims -= 1;
            owner.claim = false;
        }
        drop(owner);
        refill_completion_ready(&mut state);
        drop(state);
        service.changed.notify_waiters();
    }
}
impl Drop for CompletionInner {
    fn drop(&mut self) {
        let mut state = self
            .group
            .0
            .service
            .state
            .lock()
            .expect("application services");
        let owner = self.state.lock().expect("Completion owner");
        state.completion_index[self.index] = None;
        state.completion_ready.retain(|index| *index != self.index);
        if owner.claim {
            state.claims -= 1;
        }
        drop(state);
        self.group.0.service.changed.notify_waiters();
    }
}

pub(crate) enum QueryAdmission {
    Position(ApplicationPosition),
    Waiting(QueryTicket),
}
impl QueryAdmission {
    pub(crate) async fn enter(self) -> Result<ApplicationInvocation> {
        let position = match self {
            Self::Position(position) => position,
            Self::Waiting(ticket) => ticket.position().await?,
        };
        position.enter()
    }
}
struct QueryWaiter {
    group: ApplicationGroup,
    charge: Mutex<Option<ApplicationServiceCharge>>,
}
pub(crate) struct QueryTicket(Arc<QueryWaiter>);
impl QueryTicket {
    async fn position(&self) -> Result<ApplicationPosition> {
        let service = &self.0.group.0.service;
        loop {
            let changed = service.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.0.group.check()?;
            let position = {
                let mut state = service.state.lock().expect("application services");
                state
                    .query_ready
                    .retain(|waiter| waiter.strong_count() != 0);
                if state.closed {
                    return Err(ApplicationInvocationError::Closed);
                }
                let first = state.query_ready.front().and_then(Weak::upgrade);
                if state.query_reserved < 1
                    && first.is_some_and(|first| Arc::ptr_eq(&first, &self.0))
                {
                    state.query_ready.pop_front();
                    state.query_reserved += 1;
                    let charge = self
                        .0
                        .charge
                        .lock()
                        .expect("query ticket")
                        .take()
                        .expect("original query ticket");
                    Some(ApplicationPosition(Arc::new(PositionInner {
                        group: self.0.group.clone(),
                        lane: ApplicationLane::ContractQuery,
                        ancestors: Vec::new(),
                        active: AtomicBool::new(false),
                        synchronous: Mutex::new(SynchronousState {
                            thread: None,
                            depth: 0,
                        }),
                        _charge: charge.into(),
                    })))
                } else {
                    None
                }
            };
            if let Some(position) = position {
                return Ok(position);
            }
            tokio::select! { _ = changed => {}, _ = self.0.group.0.cancellation.cancelled() => return Err(ApplicationInvocationError::Canceled) }
        }
    }
}
impl Drop for QueryTicket {
    fn drop(&mut self) {
        let service = &self.0.group.0.service;
        service
            .state
            .lock()
            .expect("application services")
            .query_ready
            .retain(|item| {
                item.upgrade()
                    .is_some_and(|item| !Arc::ptr_eq(&item, &self.0))
            });
        service.changed.notify_waiters();
    }
}
pub(crate) struct QueryOwner {
    group: ApplicationGroup,
    _charge: ResourceCharge,
}
impl Drop for QueryOwner {
    fn drop(&mut self) {
        self.group
            .0
            .service
            .state
            .lock()
            .expect("application services")
            .query_owners -= 1;
        self.group.0.service.changed.notify_waiters();
    }
}

// A protected SDK position is independent of ordinary application execution.
// Its ticket retains the original backing until the request really settles.
pub(crate) enum ManagementAdmission {
    Position(ApplicationPosition),
    Waiting(ManagementTicket),
}
impl ManagementAdmission {
    pub(crate) async fn enter(self) -> Result<ApplicationInvocation> {
        let position = match self {
            Self::Position(position) => position,
            Self::Waiting(ticket) => ticket.position().await?,
        };
        position.enter()
    }
}
struct ManagementWaiter {
    group: ApplicationGroup,
    charge: Mutex<Option<Arc<ApplicationServiceCharge>>>,
}
pub(crate) struct ManagementTicket(Arc<ManagementWaiter>);
impl ManagementTicket {
    async fn position(&self) -> Result<ApplicationPosition> {
        let service = &self.0.group.0.service;
        loop {
            let changed = service.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.0.group.check()?;
            let position = {
                let mut state = service.state.lock().expect("application services");
                if state.closed {
                    return Err(ApplicationInvocationError::Closed);
                }
                state
                    .management_ready
                    .retain(|item| item.strong_count() != 0);
                let first = state.management_ready.front().and_then(Weak::upgrade);
                if state.management_reserved < 2
                    && first.is_some_and(|first| Arc::ptr_eq(&first, &self.0))
                {
                    state.management_ready.pop_front();
                    state.management_reserved += 1;
                    let charge = self
                        .0
                        .charge
                        .lock()
                        .expect("management ticket")
                        .take()
                        .expect("original ticket backing");
                    Some(ApplicationPosition(Arc::new(PositionInner {
                        group: self.0.group.clone(),
                        lane: ApplicationLane::Management,
                        ancestors: Vec::new(),
                        active: AtomicBool::new(false),
                        synchronous: Mutex::new(SynchronousState {
                            thread: None,
                            depth: 0,
                        }),
                        _charge: charge.into(),
                    })))
                } else {
                    None
                }
            };
            if let Some(position) = position {
                return Ok(position);
            }
            tokio::select! { _ = changed => {}, _ = self.0.group.0.cancellation.cancelled() => return Err(ApplicationInvocationError::Canceled) }
        }
    }
}
impl Drop for ManagementTicket {
    fn drop(&mut self) {
        let service = &self.0.group.0.service;
        service
            .state
            .lock()
            .expect("application services")
            .management_ready
            .retain(|item| {
                item.upgrade()
                    .is_some_and(|item| !Arc::ptr_eq(&item, &self.0))
            });
        service.changed.notify_waiters();
    }
}

#[cfg(test)]
mod management_capacity_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn pre_ready_management_positions_bound_running_and_queued_work() {
        let root = EnvironmentRoot::new(crate::TransportEnvironmentOptions {
            clock: Some(crate::environment_v4::tests::TestClock::new(1000, 1010)),
            application_executor: crate::ApplicationExecutorConfig {
                execution: true,
                ..crate::ApplicationExecutorConfig::default()
            },
            ..crate::TransportEnvironmentOptions::default()
        })
        .unwrap();
        let account = root
            .admit([7; 32], crate::environment_v4::tests::bounds())
            .unwrap();
        let service = ApplicationServices::new(root.clone()).unwrap();
        let descriptor = account
            .reserve(ApplicationGroup::preparation_limits())
            .unwrap();
        let group =
            ApplicationGroup::new_prepaid(account.clone(), service.clone(), descriptor).unwrap();
        let baseline = root.charged();
        let positions = [(); 4].map(|_| {
            group
                .prepare_management_position(
                    account
                        .reserve(ApplicationGroup::management_position_limits())
                        .unwrap(),
                )
                .unwrap()
        });
        assert!(
            positions
                .iter()
                .all(|charge| Arc::strong_count(charge) == 1)
        );

        let take = || {
            positions
                .iter()
                .find(|charge| Arc::strong_count(charge) == 1)
                .cloned()
        };
        let running_a = group
            .management(take().unwrap())
            .unwrap()
            .enter()
            .await
            .unwrap();
        let running_b = group
            .management(take().unwrap())
            .unwrap()
            .enter()
            .await
            .unwrap();
        assert_eq!(service.snapshot().management_reserved, 2);
        assert_eq!(service.snapshot().management_running, 2);
        assert!(
            positions
                .iter()
                .take(2)
                .all(|charge| Arc::strong_count(charge) == 2)
        );
        assert!(
            positions
                .iter()
                .skip(2)
                .all(|charge| Arc::strong_count(charge) == 1)
        );

        let queued_a = group.management(take().unwrap()).unwrap();
        let queued_b = group.management(take().unwrap()).unwrap();
        assert_eq!(service.snapshot().management_reserved, 2);
        assert_eq!(service.snapshot().management_ready, 2);
        assert!(take().is_none());
        assert!(
            positions
                .iter()
                .all(|charge| Arc::strong_count(charge) == 2)
        );

        drop(queued_a);
        assert_eq!(service.snapshot().management_reserved, 2);
        assert_eq!(service.snapshot().management_running, 2);
        assert_eq!(service.snapshot().management_ready, 1);

        drop(running_a);
        assert_eq!(service.snapshot().management_reserved, 1);
        assert_eq!(service.snapshot().management_running, 1);
        let promoted = queued_b.enter().await.unwrap();
        assert_eq!(service.snapshot().management_reserved, 2);
        assert_eq!(service.snapshot().management_running, 2);

        drop(running_b);
        drop(promoted);
        assert_eq!(service.snapshot().management_reserved, 0);
        assert_eq!(service.snapshot().management_running, 0);
        assert_eq!(service.snapshot().management_ready, 0);
        assert!(
            positions
                .iter()
                .all(|charge| Arc::strong_count(charge) == 1)
        );

        drop(positions);
        assert_eq!(root.charged(), baseline);
        drop(group);
        drop(account);
        drop(service);
        root.close();
        assert!(root.cleanup().0);
    }
}
