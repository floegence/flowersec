//! Original, fixed-capacity preauth input and work ownership. A candidate and
//! every DNS/address/TLS/H3 tail retain the same aggregate accounting state.
//! Work units count one resolver job, one address setup, and each received UDP
//! segment before its QUIC/TLS/H3 processing. Transmitted bytes are not input.
use crate::quic_provider::{AsyncUdpSocket, UdpPoller};
use std::{
    fmt, io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use udp::{RecvMeta, Transmit};

const CANDIDATES: usize = 16;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreparationLimits {
    pub preauth_input_bytes: u64,
    pub address_attempts: u32,
    pub work_units: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreparationUsage {
    pub preauth_input_bytes: u64,
    pub address_attempts: u32,
    pub work_units: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PreparationBudgetError {
    #[error("invalid preparation budget")]
    Invalid,
    #[error("preparation budget is exhausted")]
    Exhausted,
    #[error("preparation budget is closed")]
    Closed,
}
#[derive(Clone, Copy, Debug, Default)]
struct Candidate {
    limits: PreparationLimits,
    used: PreparationUsage,
    failed: bool,
    finished: bool,
}
#[derive(Debug)]
struct State {
    limits: Option<PreparationLimits>,
    used: PreparationUsage,
    candidates: [Candidate; CANDIDATES],
    count: usize,
    closed: bool,
    winner: Option<usize>,
    incoming_slot: Option<IncomingPreparationSlot>,
}
#[derive(Clone, Debug)]
pub struct PreparationBudget {
    state: Arc<Mutex<State>>,
}
impl Default for PreparationBudget {
    fn default() -> Self {
        Self::new()
    }
}
impl PreparationBudget {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                limits: None,
                used: PreparationUsage::default(),
                candidates: [Candidate::default(); CANDIDATES],
                count: 0,
                closed: false,
                winner: None,
                incoming_slot: None,
            })),
        }
    }
    pub fn with_capacity(limits: PreparationLimits) -> Result<Self, PreparationBudgetError> {
        let budget = Self::new();
        budget.configure(limits)?;
        Ok(budget)
    }
    pub fn configure(&self, limits: PreparationLimits) -> Result<(), PreparationBudgetError> {
        valid(limits)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PreparationBudgetError::Closed)?;
        if state.closed || state.limits.is_some() {
            return Err(PreparationBudgetError::Closed);
        }
        state.limits = Some(limits);
        Ok(())
    }
    pub fn begin_candidate(
        &self,
        limits: PreparationLimits,
    ) -> Result<CandidatePreparationBudget, PreparationBudgetError> {
        valid(limits)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PreparationBudgetError::Closed)?;
        if state.closed || state.winner.is_some() {
            return Err(PreparationBudgetError::Closed);
        }
        let total = state.limits.ok_or(PreparationBudgetError::Invalid)?;
        if state.count == CANDIDATES
            || state.used.preauth_input_bytes >= total.preauth_input_bytes
            || state.used.address_attempts >= total.address_attempts
            || state.used.work_units >= total.work_units
        {
            return Err(PreparationBudgetError::Exhausted);
        }
        let index = state.count;
        state.count += 1;
        state.candidates[index].limits = limits;
        Ok(CandidatePreparationBudget {
            owner: self.clone(),
            index,
        })
    }
    pub fn usage(&self) -> PreparationUsage {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .used
    }
    pub fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed = true;
    }
}
/// Trusted listener policy installed before its UDP driver starts. A permit
/// belongs to one original incoming/CID through failure cleanup, or until its
/// successful physical Prepare transfers into the already prepaid Session.
#[derive(Clone, Debug)]
pub(crate) struct IncomingPreparationPool {
    limits: PreparationLimits,
    maximum: usize,
    pending: Arc<AtomicUsize>,
}
#[derive(Debug)]
struct IncomingPreparationSlot {
    pending: Arc<AtomicUsize>,
}
impl Drop for IncomingPreparationSlot {
    fn drop(&mut self) {
        self.pending.fetch_sub(1, Ordering::AcqRel);
    }
}
impl IncomingPreparationPool {
    pub(crate) fn new(
        limits: PreparationLimits,
        maximum: usize,
    ) -> Result<Self, PreparationBudgetError> {
        valid(limits)?;
        if !(1..=4096).contains(&maximum) {
            return Err(PreparationBudgetError::Invalid);
        }
        Ok(Self {
            limits,
            maximum,
            pending: Arc::new(AtomicUsize::new(0)),
        })
    }
    pub(crate) fn begin(&self) -> Result<CandidatePreparationBudget, PreparationBudgetError> {
        self.pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                (pending < self.maximum).then_some(pending + 1)
            })
            .map_err(|_| PreparationBudgetError::Exhausted)?;
        let slot = IncomingPreparationSlot {
            pending: self.pending.clone(),
        };
        let owner = PreparationBudget::with_capacity(self.limits)?;
        owner
            .state
            .lock()
            .map_err(|_| PreparationBudgetError::Closed)?
            .incoming_slot = Some(slot);
        let candidate = owner.begin_candidate(self.limits)?;
        candidate.debit_address()?;
        Ok(candidate)
    }
}
#[derive(Clone, Debug)]
pub struct CandidatePreparationBudget {
    owner: PreparationBudget,
    index: usize,
}
impl CandidatePreparationBudget {
    fn debit(&self, bytes: u64, addresses: u32, work: u64) -> Result<(), PreparationBudgetError> {
        let mut state = self
            .owner
            .state
            .lock()
            .map_err(|_| PreparationBudgetError::Closed)?;
        let candidate = state.candidates[self.index];
        if candidate.finished {
            return Ok(());
        }
        if candidate.failed {
            return Err(PreparationBudgetError::Exhausted);
        }
        if state.closed || state.winner.is_some() {
            return Err(PreparationBudgetError::Closed);
        }
        let total = state.limits.ok_or(PreparationBudgetError::Invalid)?;
        let used = increment(state.used, bytes, addresses, work);
        let local = increment(candidate.used, bytes, addresses, work);
        // No network input is handed to QUIC when either debit fails. A
        // rejected datagram is not processed or credited as accepted input.
        match (used, local) {
            (Some(used), Some(local)) if within(used, total) && within(local, candidate.limits) => {
                state.used = used;
                state.candidates[self.index].used = local;
                Ok(())
            }
            _ => {
                state.candidates[self.index].failed = true;
                Err(PreparationBudgetError::Exhausted)
            }
        }
    }
    pub fn debit_address(&self) -> Result<(), PreparationBudgetError> {
        self.debit(0, 1, 1)
    }
    pub fn debit_work(&self, units: u64) -> Result<(), PreparationBudgetError> {
        self.debit(0, 0, units)
    }
    pub fn debit_input(&self, bytes: u64, segments: u64) -> Result<(), PreparationBudgetError> {
        self.debit(bytes, 0, segments)
    }
    pub fn usage(&self) -> PreparationUsage {
        self.owner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .candidates[self.index]
            .used
    }
    pub fn check(&self) -> Result<(), PreparationBudgetError> {
        let state = self
            .owner
            .state
            .lock()
            .map_err(|_| PreparationBudgetError::Closed)?;
        let candidate = state.candidates[self.index];
        if candidate.finished {
            return Ok(());
        }
        if candidate.failed {
            return Err(PreparationBudgetError::Exhausted);
        }
        if state.closed || state.winner.is_some() {
            return Err(PreparationBudgetError::Closed);
        }
        Ok(())
    }
    /// Only the original physical Prepare winner may end network preparation.
    /// This precedes durable spend and activated HOP's separate Grant quota.
    /// Counters remain immutable history; another candidate cannot upgrade.
    pub fn complete(&self) -> Result<(), PreparationBudgetError> {
        let mut state = self
            .owner
            .state
            .lock()
            .map_err(|_| PreparationBudgetError::Closed)?;
        if state.closed
            || state.candidates[self.index].failed
            || state.candidates[self.index].finished
            || state.winner.is_some()
        {
            return Err(PreparationBudgetError::Closed);
        }
        state.winner = Some(self.index);
        state.candidates[self.index].finished = true;
        // Releasing a pending permit never resets this original owner's
        // counters; the established connection keeps them through termination.
        state.incoming_slot.take();
        Ok(())
    }
    pub(crate) fn socket(&self, inner: Arc<dyn AsyncUdpSocket>) -> Arc<dyn AsyncUdpSocket> {
        Arc::new(MeteredSocket {
            inner,
            budget: self.clone(),
        })
    }
}
fn valid(limits: PreparationLimits) -> Result<(), PreparationBudgetError> {
    if limits.preauth_input_bytes == 0 || limits.address_attempts == 0 || limits.work_units == 0 {
        return Err(PreparationBudgetError::Invalid);
    }
    Ok(())
}
fn increment(
    used: PreparationUsage,
    bytes: u64,
    addresses: u32,
    work: u64,
) -> Option<PreparationUsage> {
    Some(PreparationUsage {
        preauth_input_bytes: used.preauth_input_bytes.checked_add(bytes)?,
        address_attempts: used.address_attempts.checked_add(addresses)?,
        work_units: used.work_units.checked_add(work)?,
    })
}
fn within(used: PreparationUsage, limits: PreparationLimits) -> bool {
    used.preauth_input_bytes <= limits.preauth_input_bytes
        && used.address_attempts <= limits.address_attempts
        && used.work_units <= limits.work_units
}
struct MeteredSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    budget: CandidatePreparationBudget,
}
impl fmt::Debug for MeteredSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeteredSocket")
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}
impl AsyncUdpSocket for MeteredSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.budget.check().map_err(io::Error::other)?;
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.budget.check() {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                let mut bytes = 0u64;
                let mut segments = 0u64;
                for item in &meta[..count] {
                    bytes = match bytes.checked_add(item.len as u64) {
                        Some(value) => value,
                        None => {
                            return Poll::Ready(Err(io::Error::other(
                                PreparationBudgetError::Exhausted,
                            )));
                        }
                    };
                    segments = match segments.checked_add(if item.len == 0 {
                        1
                    } else {
                        (item.len as u64 - 1) / item.stride.max(1) as u64 + 1
                    }) {
                        Some(value) => value,
                        None => {
                            return Poll::Ready(Err(io::Error::other(
                                PreparationBudgetError::Exhausted,
                            )));
                        }
                    };
                }
                match self.budget.debit_input(bytes, segments) {
                    Ok(()) => Poll::Ready(Ok(count)),
                    Err(error) => Poll::Ready(Err(io::Error::other(error))),
                }
            }
            result => result,
        }
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits(bytes: u64, addresses: u32, work: u64) -> PreparationLimits {
        PreparationLimits {
            preauth_input_bytes: bytes,
            address_attempts: addresses,
            work_units: work,
        }
    }
    #[test]
    fn failed_address_retry_and_clone_keep_original_aggregate_usage() {
        let owner = PreparationBudget::with_capacity(limits(1024, 2, 20)).unwrap();
        let candidate = owner.begin_candidate(limits(512, 8, 10)).unwrap();
        candidate.debit_address().unwrap();
        let retry = candidate.clone();
        retry.debit_address().unwrap();
        assert_eq!(
            retry.debit_address(),
            Err(PreparationBudgetError::Exhausted)
        );
        assert_eq!(candidate.usage().address_attempts, 2);
        assert_eq!(owner.usage().address_attempts, 2);
        assert!(matches!(
            owner.begin_candidate(limits(512, 8, 10)),
            Err(PreparationBudgetError::Exhausted)
        ));
        assert_eq!(owner.usage().work_units, 2);
    }
    #[test]
    fn shared_incoming_failure_does_not_close_another_original_connection() {
        let pool = IncomingPreparationPool::new(limits(4, 1, 8), 2).unwrap();
        let first = pool.begin().unwrap();
        let second = pool.begin().unwrap();
        assert_eq!(
            first.debit_input(5, 1),
            Err(PreparationBudgetError::Exhausted)
        );
        second.debit_input(2, 1).unwrap();
        assert_eq!(second.check(), Ok(()));
        assert!(matches!(
            pool.begin(),
            Err(PreparationBudgetError::Exhausted)
        ));
        drop(first);
        let replacement = pool.begin().unwrap();
        assert_eq!(replacement.usage().preauth_input_bytes, 0);
        assert_eq!(second.usage().preauth_input_bytes, 2);
    }
    #[test]
    fn shared_prepare_completion_releases_only_its_pending_permit_and_keeps_history() {
        let pool = IncomingPreparationPool::new(limits(8, 1, 8), 1).unwrap();
        let original = pool.begin().unwrap();
        original.debit_input(3, 1).unwrap();
        original.complete().unwrap();
        let incoming = pool.begin().unwrap();
        assert_eq!(original.usage().preauth_input_bytes, 3);
        assert_eq!(incoming.usage().preauth_input_bytes, 0);
        original.debit_input(4096, 4096).unwrap();
        assert_eq!(original.usage().preauth_input_bytes, 3);
        assert_eq!(
            incoming.debit_input(9, 1),
            Err(PreparationBudgetError::Exhausted)
        );
        assert_eq!(original.check(), Ok(()));
    }
    #[test]
    fn failed_incoming_permit_remains_owned_through_cloned_native_tails() {
        let pool = IncomingPreparationPool::new(limits(4, 1, 8), 1).unwrap();
        let original = pool.begin().unwrap();
        let native_tail = original.clone();
        assert_eq!(
            original.debit_input(5, 1),
            Err(PreparationBudgetError::Exhausted)
        );
        drop(original);
        assert!(matches!(
            pool.begin(),
            Err(PreparationBudgetError::Exhausted)
        ));
        drop(native_tail);
        assert!(pool.begin().is_ok());
    }
    #[test]
    fn zero_length_input_still_consumes_one_processing_unit() {
        let owner = PreparationBudget::with_capacity(limits(8, 1, 2)).unwrap();
        let candidate = owner.begin_candidate(limits(8, 1, 2)).unwrap();
        candidate.debit_input(0, 1).unwrap();
        assert_eq!(candidate.usage().preauth_input_bytes, 0);
        assert_eq!(candidate.usage().work_units, 1);
    }
}
