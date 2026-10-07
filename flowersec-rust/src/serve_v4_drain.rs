//! One irreversible aggregate result over the original live child owners.
use super::*;
use crate::transport::SessionError;

pub(super) struct DrainState {
    started_at: Instant,
    deadline: Instant,
    pub(super) outcome: DrainOutcome,
    pub(super) error: Option<SessionError>,
    child_outcome: DrainOutcome,
}
impl DrainState {
    pub(super) fn closed() -> Self {
        let now = Instant::now();
        Self {
            started_at: now,
            deadline: now,
            outcome: DrainOutcome::Failed,
            error: Some(SessionError::Closed),
            child_outcome: DrainOutcome::Failed,
        }
    }
    fn observe(&mut self, outcome: DrainOutcome, error: Option<SessionError>) {
        if self.outcome != DrainOutcome::Pending {
            return;
        }
        self.child_outcome = match (self.child_outcome, outcome) {
            (DrainOutcome::Failed, _) | (_, DrainOutcome::Failed) => DrainOutcome::Failed,
            (DrainOutcome::DeadlineAborted, _) | (_, DrainOutcome::DeadlineAborted) => {
                DrainOutcome::DeadlineAborted
            }
            _ => DrainOutcome::Drained,
        };
        if outcome == DrainOutcome::Failed && self.error.is_none() {
            self.error = Some(error.unwrap_or(SessionError::OperationFailed));
        }
    }
}

/// The original group's business outcome and a current physical cleanup view.
/// A terminal outcome never implies that callbacks or native work have exited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServeDrainResult {
    pub outcome: DrainOutcome,
    pub error: Option<SessionError>,
    pub cleanup: CleanupStatus,
}

/// Observes the same irreversible Serve Drain. Dropping a waiter does not
/// cancel the group, reopen admission, or change any child deadline.
#[derive(Clone, Debug)]
pub struct ServeDrainOperation {
    owner: Arc<ServeOwner>,
}
impl ServeDrainOperation {
    pub fn result(&self) -> ServeDrainResult {
        self.owner.drain_result()
    }
    pub async fn wait(&self) -> ConnectResult<ServeDrainResult> {
        wait(&self.owner).await
    }
}
pub(super) async fn wait(owner: &Arc<ServeOwner>) -> ConnectResult<ServeDrainResult> {
    let result = owner.drain_result();
    if result.outcome != DrainOutcome::Pending {
        return Ok(result);
    }
    let Some(_wait) = owner.observe()? else {
        return Ok(owner.drain_result());
    };
    loop {
        let notified = owner.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let result = owner.drain_result();
        if result.outcome != DrainOutcome::Pending {
            return Ok(result);
        }
        notified.await;
    }
}
impl ServeHandle {
    pub fn drain(&self, timeout: Duration) -> ConnectResult<ServeDrainOperation> {
        start(&self.owner, timeout)
    }
    pub async fn wait_drain(&self) -> ConnectResult<ServeDrainResult> {
        wait(&self.owner).await
    }
}
pub(super) fn start(
    owner: &Arc<ServeOwner>,
    timeout: Duration,
) -> ConnectResult<ServeDrainOperation> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(ConnectError::Configuration);
    }
    {
        let mut gate = owner.gate.lock().expect("Serve publication gate");
        if gate.drain.is_none() {
            let started_at = Instant::now();
            let deadline = started_at
                .checked_add(timeout)
                .ok_or(ConnectError::Configuration)?;
            gate.closed = true;
            gate.drain = Some(DrainState {
                started_at,
                deadline,
                outcome: DrainOutcome::Pending,
                error: None,
                child_outcome: DrainOutcome::Drained,
            });
            for slot in gate.slots.iter().flatten() {
                if slot.pending {
                    slot.cancel.cancel();
                }
            }
        }
    }
    owner.stop.cancel();
    owner.poll_drain();
    owner.changed.notify_waiters();
    Ok(ServeDrainOperation {
        owner: owner.clone(),
    })
}

pub(super) struct Observer<'a>(&'a ServeOwner);
impl Drop for Observer<'_> {
    fn drop(&mut self) {
        if self.0.observers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.cleanup();
        }
    }
}
impl ServeOwner {
    pub(super) fn observe(&self) -> ConnectResult<Option<Observer<'_>>> {
        // Admission and the final prepaid-vector refund share this gate. A
        // concurrently completed group needs only its existing terminal view.
        let charge = self.charge.lock().expect("Serve charge");
        if charge.is_none() {
            return Ok(None);
        }
        self.observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_OBSERVERS).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        Ok(Some(Observer(self)))
    }
    fn drain_result(&self) -> ServeDrainResult {
        let cleanup = self.cleanup();
        let gate = self.gate.lock().expect("Serve publication gate");
        ServeDrainResult {
            outcome: gate
                .drain
                .as_ref()
                .map_or(DrainOutcome::Pending, |d| d.outcome),
            error: gate.drain.as_ref().and_then(|d| d.error),
            cleanup,
        }
    }
    pub(super) fn observe_child(&self, index: usize, generation: u64) {
        let (session, operation, started_at, deadline) = {
            let mut gate = self.gate.lock().expect("Serve publication gate");
            let Some(drain) = &gate.drain else { return };
            if drain.outcome != DrainOutcome::Pending {
                return;
            }
            let deadline = drain.deadline;
            let started_at = drain.started_at;
            let Some(slot) = &mut gate.slots[index] else {
                return;
            };
            if slot.generation != generation
                || slot.pending
                || slot.drain_done
                || slot.drain_starting
            {
                return;
            }
            let Some(session) = &slot.session else { return };
            slot.drain_starting = true;
            (session.clone(), slot.drain.clone(), started_at, deadline)
        };
        // Session locks, trusted-time callbacks and close run outside the
        // Serve publication gate. A concurrent observer joins the same Drain.
        let started = match operation {
            Some(operation) => Ok(Some(operation)),
            None => session.drain_for_serve(started_at, deadline),
        };
        let (operation, outcome, failure) = match started {
            Ok(Some(operation)) => {
                operation.expire_for_serve(Instant::now());
                let outcome = operation.result().outcome;
                (Some(operation), outcome, session.termination_cause())
            }
            Ok(None) => (None, DrainOutcome::Drained, None),
            Err(error) => {
                session.close();
                (None, DrainOutcome::Failed, Some(error))
            }
        };
        let mut gate = self.gate.lock().expect("Serve publication gate");
        let Some(slot) = &mut gate.slots[index] else {
            return;
        };
        if slot.generation != generation || slot.drain_done {
            return;
        }
        slot.drain_starting = false;
        slot.drain = operation;
        slot.drain_done = outcome != DrainOutcome::Pending;
        if slot.drain_done {
            gate.drain
                .as_mut()
                .expect("original Serve Drain")
                .observe(outcome, failure);
        }
        drop(gate);
        self.changed.notify_waiters();
    }
    pub(super) fn finish_drain(&self) {
        let finished = {
            let mut gate = self.gate.lock().expect("Serve publication gate");
            if gate
                .slots
                .iter()
                .flatten()
                .any(|s| !s.pending && !s.drain_done)
            {
                return;
            }
            let Some(drain) = &mut gate.drain else { return };
            if drain.outcome == DrainOutcome::Pending {
                drain.outcome = drain.child_outcome;
                true
            } else {
                false
            }
        };
        if finished {
            let mut deadline = self
                .cleanup_deadline
                .lock()
                .expect("Serve cleanup deadline");
            if deadline.is_none() {
                *deadline = Instant::now().checked_add(Duration::from_secs(5));
            }
            self.changed.notify_waiters();
        }
    }
    pub(super) fn poll_drain(&self) {
        if self.root.is_closed() {
            self.close();
        }
        let count = self
            .gate
            .lock()
            .expect("Serve publication gate")
            .slots
            .len();
        for index in 0..count {
            let generation = self.gate.lock().expect("Serve publication gate").slots[index]
                .as_ref()
                .map(|s| s.generation);
            if let Some(generation) = generation {
                self.observe_child(index, generation);
            }
        }
        self.collect_finished();
        self.finish_drain();
        self.changed.notify_waiters();
    }
    pub(super) fn collect_finished(&self) {
        let count = self
            .gate
            .lock()
            .expect("Serve publication gate")
            .slots
            .len();
        for index in 0..count {
            let candidate = {
                let invocation = self.gate.lock().expect("Serve publication gate").slots[index]
                    .as_ref()
                    .and_then(|slot| slot.invocation.clone());
                if let Some(invocation) = invocation {
                    invocation.observe_cancellation();
                }
                let gate = self.gate.lock().expect("Serve publication gate");
                let draining = gate
                    .drain
                    .as_ref()
                    .is_some_and(|d| d.outcome == DrainOutcome::Pending);
                gate.slots[index]
                    .as_ref()
                    .filter(|s| {
                        s.tail_done
                            && !s.drain_starting
                            && (!draining || s.pending || s.drain_done)
                            && s.invocation
                                .as_ref()
                                .is_none_or(|i| i.complete.load(Ordering::Acquire))
                    })
                    .map(|s| (s.generation, s.session.clone(), s.provider.clone()))
            };
            let Some((generation, session, provider)) = candidate else {
                continue;
            };
            if session
                .as_ref()
                .is_some_and(|s| !s.cleanup_status().complete)
                || provider.as_ref().is_some_and(|p| !p.cleanup().complete)
            {
                continue;
            }
            let mut gate = self.gate.lock().expect("Serve publication gate");
            let draining = gate
                .drain
                .as_ref()
                .is_some_and(|d| d.outcome == DrainOutcome::Pending);
            if gate.slots[index].as_ref().is_some_and(|s| {
                s.generation == generation
                    && s.tail_done
                    && !s.drain_starting
                    && (!draining || s.pending || s.drain_done)
            }) {
                if let Some(diagnostic) = gate.slots[index]
                    .as_ref()
                    .and_then(|slot| slot.diagnostic.as_ref())
                {
                    diagnostic.fail(
                        crate::DiagnosticCode::Closed,
                        crate::DiagnosticRetryDisposition::DoNotRetry,
                    );
                    diagnostic.closed();
                }
                gate.slots[index] = None;
            }
        }
    }
    pub(super) fn close_finished_child(&self, index: usize, generation: u64) {
        let native = {
            let gate = self.gate.lock().expect("Serve publication gate");
            gate.slots[index]
                .as_ref()
                .filter(|s| s.generation == generation && s.tail_done)
                .map(|s| (s.session.clone(), s.provider.clone()))
        };
        if let Some((session, provider)) = native {
            if let Some(session) = session {
                session.close();
            }
            if let Some(provider) = provider {
                provider.close();
            }
        }
    }
}

#[cfg(test)]
#[path = "serve_v4_drain_tests.rs"]
mod tests;
