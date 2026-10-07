//! Read-only observation of the original response's provider handoff. A
//! maintenance transfer cannot encode, resend, migrate, or change that response.
use crate::environment_v4::{
    EnvironmentCharge, EnvironmentRoot, ResourceAccount, ResourceCharge, ResourceLimits,
};
use crate::rpc_channel_v4::{PublicationFact, PublicationReceipt};
use crate::{CleanupStatus, ServiceError, ServiceFailure, TransportEnvironment};
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

tokio::task_local! { static HANDLER_RESPONSE: usize; }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponsePublicationState {
    NotApplicable,
    Pending,
    Flushed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponsePublicationCause {
    ResponseSuperseded,
    ResponseAborted,
    OwnerUnavailable,
    Deadline,
    PublishFailed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponsePublicationStatus {
    pub state: ResponsePublicationState,
    pub cause: Option<ResponsePublicationCause>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseTransferResult {
    Success,
    AlreadyTransferred,
    OwnerUnavailable,
    Expired,
    Invalid,
}
#[derive(Clone, Copy, Debug)]
pub struct MaintenanceOwnerOptions {
    pub max_observations: usize,
}
struct MaintenanceRuntime {
    root: Arc<EnvironmentRoot>,
    stop: CancellationToken,
    capacity: usize,
    observations: AtomicUsize,
    gate: Mutex<()>,
    changed: Notify,
    _charge: EnvironmentCharge,
}
/// Runtime capability captured by the same HandlerPlan for Connect and Serve.
#[derive(Clone)]
pub struct MaintenanceOwner(Arc<MaintenanceRuntime>);
impl fmt::Debug for MaintenanceOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MaintenanceOwner { <opaque> }")
    }
}
impl TransportEnvironment {
    pub fn maintenance_owner(
        &self,
        options: MaintenanceOwnerOptions,
    ) -> Result<MaintenanceOwner, ServiceError> {
        if options.max_observations == 0 || options.max_observations > 128 {
            return Err(ServiceError(ServiceFailure::ConfigurationCapacity));
        }
        let charge = self.root().reserve_environment(ResourceLimits {
            sdk_bytes: 4096 + options.max_observations as u64 * 256,
            items: options.max_observations as u64,
            ..ResourceLimits::default()
        })?;
        Ok(MaintenanceOwner(Arc::new(MaintenanceRuntime {
            root: self.root().clone(),
            stop: CancellationToken::new(),
            capacity: options.max_observations,
            observations: AtomicUsize::new(0),
            gate: Mutex::new(()),
            changed: Notify::new(),
            _charge: charge,
        })))
    }
}
impl MaintenanceOwner {
    pub(crate) fn check_available(&self) -> Result<(), ServiceError> {
        self.check_root(&self.0.root)
    }
    pub(crate) fn check_root(&self, root: &Arc<EnvironmentRoot>) -> Result<(), ServiceError> {
        if !Arc::ptr_eq(&self.0.root, root) || self.0.stop.is_cancelled() || root.is_closed() {
            return Err(ServiceError(ServiceFailure::Closed));
        }
        Ok(())
    }
    pub fn close(&self) {
        let _gate = self
            .0
            .gate
            .lock()
            .expect("maintenance observation admission");
        self.0.stop.cancel();
        self.0.changed.notify_waiters();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let count = self.0.observations.load(Ordering::Acquire) as u64;
        let complete = self.0.stop.is_cancelled() && count == 0;
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: count,
        }
    }
    pub async fn wait_cleanup(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<CleanupStatus, ServiceError> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ServiceError(ServiceFailure::Canceled)) }
        }
    }
}
struct MaintenanceLease(MaintenanceOwner);
impl Drop for MaintenanceLease {
    fn drop(&mut self) {
        self.0.0.observations.fetch_sub(1, Ordering::AcqRel);
        self.0.0.changed.notify_waiters();
    }
}
struct PublicationState {
    status: ResponsePublicationStatus,
    handler_active: bool,
    transferred: bool,
    deadline: Option<Instant>,
    maintenance: Option<MaintenanceLease>,
    maintenance_stop: Option<CancellationToken>,
    exact_response: Option<(u64, [u8; 32])>,
}
pub(crate) struct ResponseOwner {
    state: Mutex<PublicationState>,
    changed: Notify,
    account: ResourceAccount,
    flush_ms: u64,
    wire_cap: u64,
    request_serial: u64,
    channel_generation: u64,
    original_maintenance: MaintenanceOwner,
    waiters: AtomicUsize,
    _charge: ResourceCharge,
}
pub(crate) struct ResponsePublicationTail(ResponsePublication);
impl Drop for ResponsePublicationTail {
    fn drop(&mut self) {
        self.0.unknown(ResponsePublicationCause::OwnerUnavailable);
        // The lease belongs to the shared observation owner. Publisher tails
        // and every detached view must exit before that slot can be reused.
    }
}
/// Detached finite observation; repeated getters refer to one original owner.
#[derive(Clone)]
pub struct ResponsePublication {
    owner: Option<Arc<ResponseOwner>>,
}
impl fmt::Debug for ResponsePublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponsePublication { <opaque> }")
    }
}
impl ResponsePublication {
    pub(crate) fn not_applicable() -> Self {
        Self { owner: None }
    }
    pub(crate) fn prepare(
        account: ResourceAccount,
        flush_ms: u64,
        wire_cap: u64,
        serial: u64,
        generation: u64,
        maintenance: MaintenanceOwner,
    ) -> Result<Self, ServiceError> {
        maintenance.check_root(account.environment_root())?;
        if !(1..=120000).contains(&flush_ms) {
            return Err(ServiceError(ServiceFailure::ConfigurationCapacity));
        }
        let charge = account.reserve(ResourceLimits {
            sdk_bytes: 1024,
            items: 1,
            tasks: 1,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        Ok(Self {
            owner: Some(Arc::new(ResponseOwner {
                state: Mutex::new(PublicationState {
                    status: ResponsePublicationStatus {
                        state: ResponsePublicationState::Pending,
                        cause: None,
                    },
                    handler_active: true,
                    transferred: false,
                    deadline: None,
                    maintenance: None,
                    maintenance_stop: None,
                    exact_response: None,
                }),
                changed: Notify::new(),
                account,
                flush_ms,
                wire_cap,
                request_serial: serial,
                channel_generation: generation,
                original_maintenance: maintenance,
                waiters: AtomicUsize::new(0),
                _charge: charge,
            })),
        })
    }
    pub(crate) async fn within_handler<T>(
        &self,
        callback: impl std::future::Future<Output = T>,
    ) -> T {
        match &self.owner {
            Some(owner) => {
                HANDLER_RESPONSE
                    .scope(Arc::as_ptr(owner) as usize, callback)
                    .await
            }
            None => callback.await,
        }
    }
    pub(crate) fn tail(&self) -> ResponsePublicationTail {
        ResponsePublicationTail(self.clone())
    }
    pub fn state(&self) -> ResponsePublicationStatus {
        self.owner.as_ref().map_or(
            ResponsePublicationStatus {
                state: ResponsePublicationState::NotApplicable,
                cause: None,
            },
            |owner| owner.state.lock().expect("response publication").status,
        )
    }
    pub async fn wait(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<ResponsePublicationStatus, ServiceError> {
        let Some(owner) = &self.owner else {
            return Ok(self.state());
        };
        if HANDLER_RESPONSE
            .try_with(|original| *original == Arc::as_ptr(owner) as usize)
            .unwrap_or(false)
            && owner
                .state
                .lock()
                .expect("response wait dependency")
                .handler_active
        {
            return Err(ServiceError(ServiceFailure::KnownApplicationDependency));
        }
        if owner
            .waiters
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |waiters| {
                (waiters < 4).then_some(waiters + 1)
            })
            .is_err()
        {
            return Err(ServiceError(ServiceFailure::ConfigurationCapacity));
        }
        let _waiter = PublicationWaiter(owner.clone());
        loop {
            let changed = owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let maintenance_stop = owner
                .state
                .lock()
                .expect("maintenance observation")
                .maintenance_stop
                .clone();
            if maintenance_stop
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                return Err(ServiceError(ServiceFailure::Closed));
            }
            let status = self.state();
            if status.state != ResponsePublicationState::Pending {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ServiceError(ServiceFailure::Canceled)),
            _ = async { if let Some(stop) = maintenance_stop { stop.cancelled().await; } else { std::future::pending::<()>().await; } } => return Err(ServiceError(ServiceFailure::Closed)) }
        }
    }
    pub fn transfer_to(&self, maintenance: &MaintenanceOwner) -> ResponseTransferResult {
        let Some(owner) = &self.owner else {
            return ResponseTransferResult::Invalid;
        };
        let mut state = owner.state.lock().expect("response transfer gate");
        if state.transferred {
            return ResponseTransferResult::AlreadyTransferred;
        }
        if !state.handler_active {
            return ResponseTransferResult::Invalid;
        }
        if owner
            .account
            .security_time()
            .map_or(true, |now| now.upper_ms >= owner.wire_cap)
            || state
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return ResponseTransferResult::Expired;
        }
        let _gate = maintenance
            .0
            .gate
            .lock()
            .expect("original maintenance transfer");
        if !Arc::ptr_eq(&maintenance.0, &owner.original_maintenance.0)
            || maintenance
                .check_root(owner.account.environment_root())
                .is_err()
        {
            return ResponseTransferResult::OwnerUnavailable;
        }
        if maintenance
            .0
            .observations
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < maintenance.0.capacity).then_some(count + 1)
            })
            .is_err()
        {
            return ResponseTransferResult::OwnerUnavailable;
        }
        state.maintenance_stop = Some(maintenance.0.stop.clone());
        state.maintenance = Some(MaintenanceLease(maintenance.clone()));
        state.transferred = true;
        ResponseTransferResult::Success
    }
    pub(crate) fn handler_returned(&self) {
        if let Some(owner) = &self.owner {
            owner
                .state
                .lock()
                .expect("response callback gate")
                .handler_active = false;
        }
    }
    pub(crate) fn publication_failed(&self, failure: ServiceError) {
        self.unknown(match failure.0 {
            ServiceFailure::DeadlineExceeded => ResponsePublicationCause::Deadline,
            ServiceFailure::Closed => ResponsePublicationCause::OwnerUnavailable,
            ServiceFailure::Canceled | ServiceFailure::RequestMessageAborted => {
                ResponsePublicationCause::ResponseAborted
            }
            _ => ResponsePublicationCause::PublishFailed,
        });
    }
    pub(crate) fn unknown(&self, cause: ResponsePublicationCause) {
        if let Some(owner) = &self.owner {
            owner.finish(ResponsePublicationStatus {
                state: ResponsePublicationState::Unknown,
                cause: Some(cause),
            });
        }
    }
    pub(crate) fn bind_response(&self, payload: &[u8]) -> Result<Option<Instant>, ServiceError> {
        use sha2::{Digest, Sha256};
        let Some(owner) = &self.owner else {
            return Ok(None);
        };
        let now = owner.account.security_time()?;
        let remaining = owner
            .wire_cap
            .checked_sub(now.upper_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or(ServiceError(ServiceFailure::DeadlineExceeded))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(owner.flush_ms.min(remaining)))
            .ok_or(ServiceError(ServiceFailure::DeadlineExceeded))?;
        let mut state = owner.state.lock().expect("exact response selection");
        if state.handler_active
            || state.exact_response.is_some()
            || state.status.state != ResponsePublicationState::Pending
        {
            return Err(ServiceError(ServiceFailure::OperationConflict));
        }
        state.exact_response = Some((payload.len() as u64, Sha256::digest(payload).into()));
        state.deadline = Some(deadline);
        let _original_binding = (owner.request_serial, owner.channel_generation);
        Ok(Some(deadline))
    }
    pub(crate) fn handoff_observer(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let owner = self.owner.as_ref()?.clone();
        Some(Arc::new(move || {
            let now = owner.account.security_time();
            let mut state = owner
                .state
                .lock()
                .expect("original response provider handoff");
            if state.status.state != ResponsePublicationState::Pending {
                return;
            }
            let cause = if state.handler_active || state.exact_response.is_none() {
                Some(ResponsePublicationCause::OwnerUnavailable)
            } else if state
                .deadline
                .is_none_or(|deadline| Instant::now() >= deadline)
                || now.as_ref().is_ok_and(|now| now.upper_ms >= owner.wire_cap)
            {
                Some(ResponsePublicationCause::Deadline)
            } else if now.is_err() {
                Some(ResponsePublicationCause::OwnerUnavailable)
            } else {
                None
            };
            state.status = match cause {
                Some(cause) => ResponsePublicationStatus {
                    state: ResponsePublicationState::Unknown,
                    cause: Some(cause),
                },
                None => ResponsePublicationStatus {
                    state: ResponsePublicationState::Flushed,
                    cause: None,
                },
            };
            drop(state);
            owner.changed.notify_waiters();
        }))
    }
    pub(crate) async fn observe(&self, receipt: oneshot::Receiver<PublicationReceipt>) {
        let Some(owner) = &self.owner else {
            let _ = receipt.await;
            return;
        };
        let deadline = owner
            .state
            .lock()
            .expect("response publication deadline")
            .deadline;
        let Some(deadline) = deadline else {
            self.unknown(ResponsePublicationCause::OwnerUnavailable);
            return;
        };
        tokio::pin!(receipt);
        tokio::select! {
            biased;
            result = &mut receipt => match result {
                Ok(PublicationReceipt { fact: PublicationFact::Committed, error: None }) => owner.finish(ResponsePublicationStatus { state: ResponsePublicationState::Flushed, cause: None }),
                Ok(PublicationReceipt { fact: PublicationFact::Aborted, .. }) => self.unknown(ResponsePublicationCause::ResponseAborted),
                Ok(PublicationReceipt { error: Some(failure), .. }) => self.publication_failed(ServiceError(failure)),
                _ => self.unknown(ResponsePublicationCause::PublishFailed),
            },
            _ = tokio::time::sleep_until(deadline) => { self.unknown(ResponsePublicationCause::Deadline); let _ = receipt.await; }
        }
    }
}
struct PublicationWaiter(Arc<ResponseOwner>);
impl Drop for PublicationWaiter {
    fn drop(&mut self) {
        self.0.waiters.fetch_sub(1, Ordering::AcqRel);
    }
}
impl ResponseOwner {
    fn finish(&self, status: ResponsePublicationStatus) {
        let mut state = self.state.lock().expect("response publication transition");
        if state.status.state != ResponsePublicationState::Pending {
            return;
        }
        state.status = status;
        drop(state);
        self.changed.notify_waiters();
    }
}
