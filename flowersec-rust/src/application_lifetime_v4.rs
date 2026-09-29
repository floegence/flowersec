//! Original application ownership shared by authenticated Session assembly,
//! callbacks and physical cleanup. Cancellation revokes work; only actual
//! callback exit and the final release receipt return the prepaid capacity.
use crate::{
    api_v4::CleanupStatus,
    environment_v4::{EnvironmentError, ResourceAccount, ResourceCharge, ResourceLimits},
};
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;

/// Captured before spend/admission. One control callback can coexist with
/// ordinary application callbacks and one protected cleanup callback.
#[derive(Clone, Copy, Debug)]
pub struct ApplicationLimits {
    pub ordinary_callbacks: usize,
    pub ordinary_callback_bytes: u64,
    pub control_callback_bytes: u64,
}
impl ApplicationLimits {
    pub(crate) fn charge(self) -> Result<ResourceLimits, EnvironmentError> {
        if !(1..=128).contains(&self.ordinary_callbacks)
            || !(256..=1 << 30).contains(&self.ordinary_callback_bytes)
            || !(256..=1 << 30).contains(&self.control_callback_bytes)
        {
            return Err(EnvironmentError::Configuration);
        }
        let ordinary = self.ordinary_callbacks as u64;
        let bytes = self
            .ordinary_callback_bytes
            .checked_add(1024)
            .and_then(|v| v.checked_mul(ordinary))
            .and_then(|v| {
                self.control_callback_bytes
                    .checked_mul(2)
                    .and_then(|c| v.checked_add(c))
            })
            .and_then(|v| v.checked_add(8192))
            .ok_or(EnvironmentError::Capacity)?;
        Ok(ResourceLimits {
            sdk_bytes: bytes,
            items: ordinary + 4,
            tasks: ordinary + 3,
            timers: 1,
            work_slots: ordinary + 2,
            ..ResourceLimits::default()
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallbackKind {
    Control,
    Ordinary,
    Cleanup,
    Dispatcher,
}

struct State {
    control: bool,
    ordinary: usize,
    cleanup: bool,
    dispatcher: bool,
    sealed: bool,
    closing: bool,
    release: Release,
    deadline: Option<Instant>,
    charge: Option<ResourceCharge>,
    parent_wake: Option<Arc<Notify>>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Release {
    Pending,
    Confirmed,
    Unconfirmed,
}

/// One immutable admission owner, independent of any particular callback
/// future. Session core termination and application termination stay distinct.
pub(crate) struct ApplicationLifetime {
    account: ResourceAccount,
    limits: ApplicationLimits,
    state: Mutex<State>,
    ordinary: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    changed: Arc<Notify>,
}
impl fmt::Debug for ApplicationLifetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicationLifetime { <opaque> }")
    }
}
impl ApplicationLifetime {
    #[cfg(test)]
    pub(crate) fn new(
        account: ResourceAccount,
        limits: ApplicationLimits,
    ) -> Result<Arc<Self>, EnvironmentError> {
        Self::with_cancellation(account, limits, CancellationToken::new())
    }
    pub(crate) fn with_cancellation(
        account: ResourceAccount,
        limits: ApplicationLimits,
        cancellation: CancellationToken,
    ) -> Result<Arc<Self>, EnvironmentError> {
        let charge = account.reserve(limits.charge()?)?;
        Ok(Arc::new(Self {
            account,
            limits,
            state: Mutex::new(State {
                control: false,
                ordinary: 0,
                cleanup: false,
                dispatcher: false,
                sealed: false,
                closing: false,
                release: Release::Pending,
                deadline: None,
                charge: Some(charge),
                parent_wake: None,
            }),
            ordinary: Arc::new(AtomicUsize::new(0)),
            cancellation,
            changed: Arc::new(Notify::new()),
        }))
    }
    pub(crate) fn belongs_to(&self, account: &ResourceAccount) -> bool {
        self.account.same_owner(account)
    }
    /// Install only original Session fields while its drive gate is held. The
    /// state gate orders this one attachment against Close and Release; the
    /// closure must never run user code or perform I/O.
    pub(crate) fn attach(
        &self,
        wake: Arc<Notify>,
        install: impl FnOnce(),
    ) -> Result<(), EnvironmentError> {
        let mut state = self.state.lock().expect("application callback gate");
        if state.parent_wake.is_some() {
            return Err(EnvironmentError::Configuration);
        }
        if self.cancellation.is_cancelled()
            || state.sealed
            || state.closing
            || state.release != Release::Pending
            || state.charge.is_none()
        {
            return Err(EnvironmentError::Closed);
        }
        state.parent_wake = Some(wake);
        install();
        Ok(())
    }
    pub(crate) fn ordinary_count(&self) -> Arc<AtomicUsize> {
        self.ordinary.clone()
    }
    pub(crate) fn ordinary_capacity(&self) -> usize {
        self.limits.ordinary_callbacks
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    pub(crate) fn changed(&self) -> Arc<Notify> {
        self.changed.clone()
    }

    pub(crate) fn enter(
        self: &Arc<Self>,
        kind: CallbackKind,
    ) -> Result<Callback, EnvironmentError> {
        if kind != CallbackKind::Cleanup {
            self.account.check()?;
        }
        let mut state = self.state.lock().expect("application callback gate");
        if state.release != Release::Pending
            || state.charge.is_none()
            || (kind != CallbackKind::Cleanup
                && (self.cancellation.is_cancelled() || state.closing || state.sealed))
        {
            return Err(EnvironmentError::Closed);
        }
        match kind {
            CallbackKind::Control if !state.control => state.control = true,
            CallbackKind::Cleanup if !state.cleanup => state.cleanup = true,
            CallbackKind::Dispatcher if !state.dispatcher => state.dispatcher = true,
            CallbackKind::Ordinary if state.ordinary < self.limits.ordinary_callbacks => {
                state.ordinary += 1;
                self.ordinary.store(state.ordinary, Ordering::Release);
            }
            _ => return Err(EnvironmentError::Capacity),
        }
        Ok(Callback {
            owner: self.clone(),
            kind,
        })
    }
    /// Drain seals future application dispatch without canceling admitted work.
    pub(crate) fn seal(&self) {
        self.state.lock().expect("application callback gate").sealed = true;
        self.wake();
    }
    /// Close preserves running work and its original lease responsibility.
    pub(crate) fn close(&self) {
        {
            let mut state = self.state.lock().expect("application callback gate");
            state.sealed = true;
            state.closing = true;
            if state.deadline.is_none() {
                state.deadline = Instant::now().checked_add(Duration::from_secs(5));
            }
        }
        self.cancellation.cancel();
        self.wake();
    }
    /// Exactly one final cleanup receipt. An uncertain receipt has no retry
    /// authority and never releases the original owner's capacity.
    pub(crate) fn release(&self, confirmed: bool) -> Result<(), EnvironmentError> {
        let mut state = self.state.lock().expect("application callback gate");
        if state.release != Release::Pending {
            return Err(EnvironmentError::Configuration);
        }
        state.sealed = true;
        state.closing = true;
        if state.deadline.is_none() {
            state.deadline = Instant::now().checked_add(Duration::from_secs(5));
        }
        state.release = if confirmed {
            Release::Confirmed
        } else {
            Release::Unconfirmed
        };
        Self::collect(&mut state);
        drop(state);
        self.cancellation.cancel();
        self.wake();
        Ok(())
    }
    fn collect(state: &mut State) {
        if state.release == Release::Confirmed
            && !state.control
            && state.ordinary == 0
            && !state.cleanup
            && !state.dispatcher
        {
            state.charge.take();
        }
    }
    pub(crate) fn cleanup_status(&self) -> CleanupStatus {
        let state = self.state.lock().expect("application callback gate");
        let pending = usize::from(state.control)
            + state.ordinary
            + usize::from(state.cleanup)
            + usize::from(state.dispatcher);
        let complete = state.release == Release::Confirmed && pending == 0;
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete
                && (state.release == Release::Unconfirmed
                    || state.deadline.is_some_and(|d| Instant::now() >= d)),
            pending_callbacks: pending as u64 + u64::from(state.release == Release::Unconfirmed),
        }
    }
    fn wake(&self) {
        self.changed.notify_waiters();
        if let Some(parent) = self
            .state
            .lock()
            .expect("application callback gate")
            .parent_wake
            .as_ref()
        {
            parent.notify_waiters();
        }
    }
}
pub(crate) struct Callback {
    owner: Arc<ApplicationLifetime>,
    kind: CallbackKind,
}
impl Drop for Callback {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().expect("application callback gate");
        match self.kind {
            CallbackKind::Control => state.control = false,
            CallbackKind::Cleanup => state.cleanup = false,
            CallbackKind::Dispatcher => state.dispatcher = false,
            CallbackKind::Ordinary => {
                state.ordinary -= 1;
                self.owner.ordinary.store(state.ordinary, Ordering::Release);
            }
        }
        ApplicationLifetime::collect(&mut state);
        drop(state);
        self.owner.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment_v4::tests::{bounds, environment};
    fn limits() -> ApplicationLimits {
        ApplicationLimits {
            ordinary_callbacks: 2,
            ordinary_callback_bytes: 1024,
            control_callback_bytes: 1024,
        }
    }
    #[test]
    fn callbacks_are_prepaid_and_cancellation_never_refunds_running_work() {
        let root = environment();
        let account = root.admit([1; 32], bounds()).unwrap();
        let baseline = root.charged();
        let owner = ApplicationLifetime::new(account, limits()).unwrap();
        let admitted = root.charged();
        let control = owner.enter(CallbackKind::Control).unwrap();
        let ordinary = owner.enter(CallbackKind::Ordinary).unwrap();
        let second = owner.enter(CallbackKind::Ordinary).unwrap();
        assert!(matches!(
            owner.enter(CallbackKind::Control),
            Err(EnvironmentError::Capacity)
        ));
        assert!(matches!(
            owner.enter(CallbackKind::Ordinary),
            Err(EnvironmentError::Capacity)
        ));
        owner.seal();
        assert!(!owner.cancellation().is_cancelled());
        assert!(matches!(
            owner.enter(CallbackKind::Ordinary),
            Err(EnvironmentError::Closed)
        ));
        owner.close();
        assert!(owner.cancellation().is_cancelled());
        assert_eq!(root.charged(), admitted);
        let cleanup = owner.enter(CallbackKind::Cleanup).unwrap();
        owner.release(true).unwrap();
        assert_eq!(owner.cleanup_status().pending_callbacks, 4);
        assert!(!owner.cleanup_status().complete);
        drop(control);
        drop(ordinary);
        drop(second);
        assert_eq!(root.charged(), admitted);
        drop(cleanup);
        assert!(owner.cleanup_status().complete);
        assert_eq!(root.charged(), baseline);
        assert!(owner.release(true).is_err());
    }
    #[test]
    fn unknown_release_is_terminal_and_protected_cleanup_survives_root_close() {
        let root = environment();
        let account = root.admit([1; 32], bounds()).unwrap();
        let owner = ApplicationLifetime::new(account, limits()).unwrap();
        let admitted = root.charged();
        root.close();
        owner.close();
        assert!(owner.enter(CallbackKind::Control).is_err());
        let cleanup = owner.enter(CallbackKind::Cleanup).unwrap();
        owner.release(false).unwrap();
        drop(cleanup);
        let status = owner.cleanup_status();
        assert!(!status.complete && status.cleanup_incomplete);
        assert_eq!(status.pending_callbacks, 1);
        assert_eq!(root.charged(), admitted);
        assert!(owner.release(true).is_err());
    }
    #[test]
    fn application_owner_matches_the_exact_original_session_account() {
        let root = environment();
        let account = root.admit([1; 32], bounds()).unwrap();
        let other = root.admit([1; 32], bounds()).unwrap();
        let owner = ApplicationLifetime::new(account.clone(), limits()).unwrap();
        assert!(owner.belongs_to(&account));
        assert!(!owner.belongs_to(&other));
        assert!(owner.attach(Arc::new(Notify::new()), || {}).is_ok());
        assert!(owner.attach(Arc::new(Notify::new()), || {}).is_err());
        let callback = owner.enter(CallbackKind::Ordinary).unwrap();
        assert_eq!(owner.ordinary_count().load(Ordering::Acquire), 1);
        drop(callback);
        assert_eq!(owner.ordinary_count().load(Ordering::Acquire), 0);
        owner.release(true).unwrap();
    }
}
