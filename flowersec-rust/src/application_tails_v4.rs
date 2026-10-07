//! Original Session-owned application task lifetimes. The registry retains
//! only cancellation and charged descriptors, never application/provider graphs.
use crate::api_v4::CleanupStatus;
use crate::environment_v4::{EnvironmentError, ResourceAccount, ResourceCharge, ResourceLimits};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const MAX_TAILS: usize = 4096;
struct Entry {
    cancellation: CancellationToken,
    _charge: Arc<ResourceCharge>,
}
struct State {
    closed: bool,
    deadline: Option<Instant>,
    next: u64,
    entries: BTreeMap<u64, Entry>,
}
pub(crate) struct ApplicationTails {
    state: Mutex<State>,
    changed: Arc<Notify>,
    account: ResourceAccount,
}
pub(crate) struct ApplicationTail {
    registry: Weak<ApplicationTails>,
    id: u64,
    cancellation: CancellationToken,
    finished: AtomicBool,
    _charge: Arc<ResourceCharge>,
}
impl ApplicationTails {
    pub(crate) fn new(account: ResourceAccount, changed: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                closed: false,
                deadline: None,
                next: 1,
                entries: BTreeMap::new(),
            }),
            changed,
            account,
        })
    }
    pub(crate) fn register(
        self: &Arc<Self>,
        account: &ResourceAccount,
    ) -> Result<ApplicationTail, EnvironmentError> {
        if !account.same_owner(&self.account) {
            return Err(EnvironmentError::Closed);
        }
        let charge = account.reserve(Self::resources())?;
        self.register_reserved(account, charge)
    }
    pub(crate) fn resources() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 512,
            items: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn register_reserved(
        self: &Arc<Self>,
        account: &ResourceAccount,
        charge: ResourceCharge,
    ) -> Result<ApplicationTail, EnvironmentError> {
        if !account.same_owner(&self.account) {
            return Err(EnvironmentError::Closed);
        }
        self.register_shared(account, Arc::new(charge))
    }
    pub(crate) fn register_shared(
        self: &Arc<Self>,
        account: &ResourceAccount,
        charge: Arc<ResourceCharge>,
    ) -> Result<ApplicationTail, EnvironmentError> {
        if !account.same_owner(&self.account) || !charge.matches(account, Self::resources()) {
            return Err(EnvironmentError::Closed);
        }
        let cancellation = CancellationToken::new();
        let id = {
            let mut state = self.state.lock().expect("Session application tails");
            if state.closed {
                return Err(EnvironmentError::Closed);
            }
            if state.entries.len() >= MAX_TAILS {
                return Err(EnvironmentError::Capacity);
            }
            let id = state.next;
            state.next = id.checked_add(1).ok_or(EnvironmentError::Capacity)?;
            state.entries.insert(
                id,
                Entry {
                    cancellation: cancellation.clone(),
                    _charge: charge.clone(),
                },
            );
            id
        };
        Ok(ApplicationTail {
            registry: Arc::downgrade(self),
            id,
            cancellation,
            finished: AtomicBool::new(false),
            _charge: charge,
        })
    }
    pub(crate) fn close(&self) {
        let cancellations = {
            let mut state = self.state.lock().expect("Session application tails");
            if state.closed {
                return;
            }
            state.closed = true;
            state.deadline = Some(Instant::now() + Duration::from_secs(5));
            state
                .entries
                .values()
                .map(|entry| entry.cancellation.clone())
                .collect::<Vec<_>>()
        };
        // Cancellation may wake arbitrary application tasks. Never wake them
        // while holding the registry or reliable-core mutex.
        for cancellation in cancellations {
            cancellation.cancel();
        }
        self.changed.notify_waiters();
    }
    pub(crate) fn status(&self) -> CleanupStatus {
        let state = self.state.lock().expect("Session application tails");
        let complete = state.closed && state.entries.is_empty();
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete
                && state
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline),
            pending_callbacks: state.entries.len() as u64,
        }
    }
    pub(crate) async fn wait(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.status().complete {
                return;
            }
            changed.await;
        }
    }
}
impl ApplicationTail {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    pub(crate) fn sibling(&self) -> Result<ApplicationTail, EnvironmentError> {
        let registry = self.registry.upgrade().ok_or(EnvironmentError::Closed)?;
        registry.register(&registry.account)
    }
    pub(crate) fn finish(&self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(registry) = self.registry.upgrade() {
            let retired = registry
                .state
                .lock()
                .expect("Session application tails")
                .entries
                .remove(&self.id);
            drop(retired);
            registry.changed.notify_waiters();
        }
    }
}
impl Drop for ApplicationTail {
    fn drop(&mut self) {
        self.finish();
    }
}
