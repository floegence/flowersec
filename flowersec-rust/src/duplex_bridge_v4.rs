//! One bounded operation over the two original Stream I/O owners.
use crate::{
    api_v4::{
        BridgeWriteReservation, CleanupStatus, ReadStreamStatus, StreamReadPermit, WriteOperation,
    },
    application_tails_v4::ApplicationTail,
    crypto_v4::Stream,
    environment_v4::{EnvironmentError, ResourceAccount, ResourceCharge, ResourceLimits},
    native_tcp_duplex_v4::{NativeTcpClaim, NativeTcpDuplex},
    transport::{ByteStream, SessionError},
};
use bytes::Bytes;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::Notify,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

/// Upper bound for either directional chunk.  No next read starts while the
/// previous chunk has an unaccepted suffix.
pub const DUPLEX_BRIDGE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct DuplexBridgeOptions {
    pub chunk_bytes: usize,
    pub overall_timeout: Duration,
    pub cleanup_timeout: Duration,
}
impl Default for DuplexBridgeOptions {
    fn default() -> Self {
        Self {
            chunk_bytes: 16 * 1024,
            overall_timeout: Duration::from_secs(60),
            cleanup_timeout: Duration::from_secs(5),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplexDirectionTerminal {
    Eof,
    Failed(SessionError),
    Aborted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplexOutcome {
    Normal,
    Failed,
    Aborted,
}
/// Completion proof belongs to the endpoint's actual transport owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplexSendCompletion {
    AuthenticatedStreamDrained,
    NativeTcpWriteShutdownQueued,
}

/// Detached bytes retain their original bounded payload charge, without
/// retaining either Stream or Session.  Clones share the same finite backing.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TransferProgress {
    pub source_read_bytes: u64,
    pub destination_accepted_bytes: u64,
    pub unaccepted_tail: Bytes,
    pub terminal: Option<DuplexDirectionTerminal>,
    pub close_write_complete: bool,
    pub finish_complete: bool,
    pub send_completion: Option<DuplexSendCompletion>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplexProgress {
    pub a_to_b: TransferProgress,
    pub b_to_a: TransferProgress,
    pub outcome: Option<DuplexOutcome>,
    pub first_error: Option<SessionError>,
    /// True only after both pumps have exited and neither acceptance frontier
    /// nor retained tail can advance. Cleanup observation alone cannot seal it.
    pub transfer_sealed: bool,
    pub cleanup: CleanupStatus,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplexResult {
    pub a_to_b: TransferProgress,
    pub b_to_a: TransferProgress,
    pub outcome: DuplexOutcome,
    pub first_error: Option<SessionError>,
    pub cleanup: CleanupStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DuplexBridgeErrorReason {
    #[error("invalid bridge options")]
    InvalidOptions,
    #[error("both endpoints identify the same underlying endpoint")]
    SameEndpoint,
    #[error("the original complete endpoint I/O owner is unavailable")]
    OwnerUnavailable,
    #[error("bridge resource capacity is exhausted")]
    Capacity,
    #[error("the bridge is closed")]
    Closed,
    #[error("the bridge failed")]
    Failed,
    #[error("the bridge was aborted")]
    Aborted,
}
/// Failure includes the original partial result, including its bounded tail.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec duplex bridge failed: {reason}")]
pub struct DuplexBridgeError {
    pub reason: DuplexBridgeErrorReason,
    pub progress: DuplexProgress,
}
struct Direction {
    progress: TransferProgress,
    write: Option<Arc<WriteOperation>>,
}
impl Direction {
    fn snapshot(&self) -> TransferProgress {
        let mut result = self.progress.clone();
        if let Some(write) = &self.write {
            let accepted = write.progress().accepted_bytes;
            // The original admission owner never reports more than its input.
            result.destination_accepted_bytes = result
                .destination_accepted_bytes
                .checked_add(accepted)
                .expect("bounded transfer counter");
            result.unaccepted_tail = result.unaccepted_tail.slice(accepted as usize..);
        }
        result
    }
}
struct State {
    started: bool,
    sealed: bool,
    directions: [Direction; 2],
    outcome: Option<DuplexOutcome>,
    first_error: Option<SessionError>,
    cleanup: CleanupStatus,
}
impl State {
    fn snapshot(&self) -> DuplexProgress {
        DuplexProgress {
            a_to_b: self.directions[0].snapshot(),
            b_to_a: self.directions[1].snapshot(),
            outcome: self.outcome,
            first_error: self.first_error,
            transfer_sealed: self.sealed,
            cleanup: self.cleanup.clone(),
        }
    }
}
struct Owner {
    state: Mutex<State>,
    changed: Notify,
    read_gate: Mutex<()>,
    native_write_gate: Mutex<()>,
    stop: CancellationToken,
    waiters: AtomicUsize,
    // Result accounts become independent of the Sessions when workers exit.
    result_accounts: [ResourceAccount; 2],
    _result_charges: [ResourceCharge; 2],
}

impl Owner {
    fn snapshot(&self) -> DuplexProgress {
        // Reads and native writes commit their real syscall result while
        // holding these gates. Never project a count/tail between the actual
        // native acceptance and its synchronous original-owner publication.
        let _read = self.read_gate.lock().expect("bridge read gate");
        let _write = self
            .native_write_gate
            .lock()
            .expect("bridge native write gate");
        self.state.lock().expect("bridge state").snapshot()
    }
}

/// Complete ownership of two byte endpoints, at least one of which is an
/// unused accepted Flowersec Stream.  Native TCP endpoints must have been
/// created by the SDK; arbitrary external sockets cannot establish ownership.
pub struct DuplexBridge {
    owner: Arc<Owner>,
}
impl std::fmt::Debug for DuplexBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuplexBridge")
            .field("progress", &self.progress())
            .finish()
    }
}
impl DuplexBridge {
    #[expect(
        clippy::result_large_err,
        reason = "The public error retains the complete fixed duplex progress snapshot without allocating during failure."
    )]
    pub fn new(
        a: Stream,
        b: Stream,
        options: DuplexBridgeOptions,
    ) -> Result<Self, DuplexBridgeError> {
        let reject = |reason| DuplexBridgeError {
            reason,
            progress: empty_progress(),
        };
        if options.chunk_bytes == 0
            || options.chunk_bytes > DUPLEX_BRIDGE_CHUNK_BYTES
            || options.overall_timeout.is_zero()
            || options.overall_timeout > Duration::from_secs(24 * 60 * 60)
            || options.cleanup_timeout.is_zero()
            || options.cleanup_timeout > Duration::from_secs(5)
        {
            return Err(reject(DuplexBridgeErrorReason::InvalidOptions));
        }
        if a.same_bridge_endpoint(&b) {
            return Err(reject(DuplexBridgeErrorReason::SameEndpoint));
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| reject(DuplexBridgeErrorReason::OwnerUnavailable))?;
        let deadline = Instant::now()
            .checked_add(options.overall_timeout)
            .ok_or_else(|| reject(DuplexBridgeErrorReason::InvalidOptions))?;
        // All construction backing and both original task responsibilities are
        // reserved before either I/O gate changes or the operation is published.
        let accounts = [a.account(), b.account()];
        let result_a = accounts[0]
            .reserve_result()
            .map_err(|e| reject(resource_reason(e)))?;
        let result_b = accounts[1]
            .reserve_result()
            .map_err(|e| reject(resource_reason(e)))?;
        let result_limits = ResourceLimits {
            sdk_bytes: std::mem::size_of::<Owner>() as u64 + 1024,
            items: 1,
            work_slots: 4,
            ..ResourceLimits::default()
        };
        let result_charges = [
            result_a
                .reserve(result_limits)
                .map_err(|e| reject(resource_reason(e)))?,
            result_b
                .reserve(result_limits)
                .map_err(|e| reject(resource_reason(e)))?,
        ];
        let work_limits = ResourceLimits {
            sdk_bytes: 4096 + options.chunk_bytes as u64 * 3,
            items: 4,
            tasks: 3,
            timers: 1,
            work_slots: 4,
            ..ResourceLimits::default()
        };
        let work = [
            accounts[0]
                .reserve(work_limits)
                .map_err(|e| reject(resource_reason(e)))?,
            accounts[1]
                .reserve(work_limits)
                .map_err(|e| reject(resource_reason(e)))?,
        ];
        let tails = [
            a.application_tail()
                .map_err(|_| reject(DuplexBridgeErrorReason::Closed))?,
            b.application_tail()
                .map_err(|_| reject(DuplexBridgeErrorReason::Closed))?,
        ];
        let writes = [
            WriteOperation::reserve_bridge_write(&b, options.chunk_bytes)
                .map_err(|_| reject(DuplexBridgeErrorReason::Capacity))?,
            WriteOperation::reserve_bridge_write(&a, options.chunk_bytes)
                .map_err(|_| reject(DuplexBridgeErrorReason::Capacity))?,
        ];
        let ((a, a_read), (b, b_read)) = Stream::claim_bridge_pair(&a, &b)
            .map_err(|_| reject(DuplexBridgeErrorReason::OwnerUnavailable))?;
        let owner = Arc::new(Owner {
            state: Mutex::new(State {
                started: false,
                sealed: false,
                directions: std::array::from_fn(|_| Direction {
                    progress: TransferProgress::default(),
                    write: None,
                }),
                outcome: None,
                first_error: None,
                cleanup: CleanupStatus {
                    complete: false,
                    cleanup_incomplete: false,
                    pending_callbacks: 1,
                },
            }),
            changed: Notify::new(),
            read_gate: Mutex::new(()),
            native_write_gate: Mutex::new(()),
            stop: CancellationToken::new(),
            waiters: AtomicUsize::new(0),
            result_accounts: [result_a, result_b],
            _result_charges: result_charges,
        });
        runtime.spawn(run(
            owner.clone(),
            Endpoint::Stream {
                stream: a,
                permit: a_read,
            },
            Endpoint::Stream {
                stream: b,
                permit: b_read,
            },
            options,
            deadline,
            work,
            tails,
            writes.map(Some),
        ));
        Ok(Self { owner })
    }
    /// Bridge an original Stream (direction A) and an SDK-created native TCP
    /// endpoint (direction B).  Existing aliases of either facade cannot do
    /// I/O after the single original full-owner claim is installed.
    #[expect(
        clippy::result_large_err,
        reason = "The public error retains the complete fixed duplex progress snapshot without allocating during failure."
    )]
    pub fn with_native_tcp(
        stream: Stream,
        native: NativeTcpDuplex,
        options: DuplexBridgeOptions,
    ) -> Result<Self, DuplexBridgeError> {
        let reject = |reason| DuplexBridgeError {
            reason,
            progress: empty_progress(),
        };
        if options.chunk_bytes == 0
            || options.chunk_bytes > DUPLEX_BRIDGE_CHUNK_BYTES
            || options.overall_timeout.is_zero()
            || options.overall_timeout > Duration::from_secs(24 * 60 * 60)
            || options.cleanup_timeout.is_zero()
            || options.cleanup_timeout > Duration::from_secs(5)
        {
            return Err(reject(DuplexBridgeErrorReason::InvalidOptions));
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| reject(DuplexBridgeErrorReason::OwnerUnavailable))?;
        let deadline = Instant::now()
            .checked_add(options.overall_timeout)
            .ok_or_else(|| reject(DuplexBridgeErrorReason::InvalidOptions))?;
        native
            .check_bridge_owner(&stream)
            .map_err(|_| reject(DuplexBridgeErrorReason::OwnerUnavailable))?;
        let account = stream.account();
        let result_a = account
            .reserve_result()
            .map_err(|e| reject(resource_reason(e)))?;
        let result_b = account
            .reserve_result()
            .map_err(|e| reject(resource_reason(e)))?;
        let result_limits = ResourceLimits {
            sdk_bytes: std::mem::size_of::<Owner>() as u64 + 1024,
            items: 1,
            work_slots: 4,
            ..ResourceLimits::default()
        };
        let result_charges = [
            result_a
                .reserve(result_limits)
                .map_err(|e| reject(resource_reason(e)))?,
            result_b
                .reserve(result_limits)
                .map_err(|e| reject(resource_reason(e)))?,
        ];
        let work_limits = ResourceLimits {
            sdk_bytes: 4096 + options.chunk_bytes as u64 * 3,
            items: 4,
            tasks: 3,
            timers: 1,
            work_slots: 4,
            ..ResourceLimits::default()
        };
        let work = [
            account
                .reserve(work_limits)
                .map_err(|e| reject(resource_reason(e)))?,
            account
                .reserve(work_limits)
                .map_err(|e| reject(resource_reason(e)))?,
        ];
        let tails = [
            stream
                .application_tail()
                .map_err(|_| reject(DuplexBridgeErrorReason::Closed))?,
            stream
                .application_tail()
                .map_err(|_| reject(DuplexBridgeErrorReason::Closed))?,
        ];
        let writes = [
            None,
            Some(
                WriteOperation::reserve_bridge_write(&stream, options.chunk_bytes)
                    .map_err(|_| reject(DuplexBridgeErrorReason::Capacity))?,
            ),
        ];
        let native_charge = account
            .reserve(NativeTcpDuplex::bridge_resources())
            .map_err(|e| reject(resource_reason(e)))?;
        // Native and original Stream claim gates change only after the full
        // vector exists; a refused claim consumes no application/socket byte.
        let (native_claim, stream, permit) = native
            .claim_with_stream(&stream, native_charge)
            .map_err(|_| reject(DuplexBridgeErrorReason::OwnerUnavailable))?;
        let owner = Arc::new(Owner {
            state: Mutex::new(State {
                started: false,
                sealed: false,
                directions: std::array::from_fn(|_| Direction {
                    progress: TransferProgress::default(),
                    write: None,
                }),
                outcome: None,
                first_error: None,
                cleanup: CleanupStatus {
                    complete: false,
                    cleanup_incomplete: false,
                    pending_callbacks: 1,
                },
            }),
            changed: Notify::new(),
            read_gate: Mutex::new(()),
            native_write_gate: Mutex::new(()),
            stop: CancellationToken::new(),
            waiters: AtomicUsize::new(0),
            result_accounts: [result_a, result_b],
            _result_charges: result_charges,
        });
        runtime.spawn(run(
            owner.clone(),
            Endpoint::Stream { stream, permit },
            Endpoint::Native {
                endpoint: native_claim,
                account,
            },
            options,
            deadline,
            work,
            tails,
            writes,
        ));
        Ok(Self { owner })
    }
    /// Repeated Start joins the same operation; it never starts another pump.
    #[expect(
        clippy::result_large_err,
        reason = "The public error retains the complete fixed duplex progress snapshot without allocating during failure."
    )]
    pub fn start(&self) -> Result<(), DuplexBridgeError> {
        let mut state = self.owner.state.lock().expect("bridge state");
        if state.started {
            return Ok(());
        }
        if state.sealed || self.owner.stop.is_cancelled() {
            return Err(DuplexBridgeError {
                reason: DuplexBridgeErrorReason::Closed,
                progress: state.snapshot(),
            });
        }
        state.started = true;
        drop(state);
        self.owner.changed.notify_waiters();
        Ok(())
    }
    /// Stop new reads and write acceptance.  Actual callbacks and provider
    /// cleanup remain owned and charged until they exit.
    pub fn abort(&self) {
        {
            let _read_gate = self.owner.read_gate.lock().expect("bridge read gate");
            self.owner.stop.cancel();
        }
        {
            let _write_gate = self
                .owner
                .native_write_gate
                .lock()
                .expect("bridge native write gate");
        }
        stop_writes(&self.owner);
        self.owner.changed.notify_waiters();
    }
    pub fn progress(&self) -> DuplexProgress {
        self.owner.snapshot()
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.progress().cleanup
    }
    /// Bounded cleanup observation.  A timeout does not terminate live work or
    /// return its buffers; it reports the remaining actual responsibilities.
    pub async fn wait_cleanup(&self, timeout: Duration) -> CleanupStatus {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(5));
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let mut status = self.cleanup_status();
            if status.complete || status.cleanup_incomplete {
                return status;
            }
            if Instant::now() >= deadline {
                status.cleanup_incomplete = true;
                return status;
            }
            tokio::select! { _ = changed => {}, _ = sleep_until(deadline) => {} }
        }
    }
    /// A dropped wait future has no effect on the bridge, its I/O, or its tail.
    #[expect(
        clippy::result_large_err,
        reason = "The public error retains the complete fixed duplex progress snapshot without allocating during failure."
    )]
    pub async fn wait(&self) -> Result<DuplexResult, DuplexBridgeError> {
        let _waiter = Waiter::new(self.owner.clone())?;
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let snapshot = self.owner.snapshot();
            let terminal = ((snapshot.transfer_sealed && snapshot.cleanup.complete)
                || snapshot.cleanup.cleanup_incomplete)
                .then_some(snapshot);
            if let Some(progress) = terminal {
                let outcome = progress
                    .outcome
                    .unwrap_or(if progress.first_error.is_some() {
                        DuplexOutcome::Failed
                    } else {
                        DuplexOutcome::Aborted
                    });
                return if outcome == DuplexOutcome::Normal && progress.cleanup.complete {
                    Ok(DuplexResult {
                        a_to_b: progress.a_to_b,
                        b_to_a: progress.b_to_a,
                        outcome,
                        first_error: progress.first_error,
                        cleanup: progress.cleanup,
                    })
                } else {
                    Err(DuplexBridgeError {
                        reason: if outcome == DuplexOutcome::Aborted {
                            DuplexBridgeErrorReason::Aborted
                        } else {
                            DuplexBridgeErrorReason::Failed
                        },
                        progress,
                    })
                };
            }
            changed.await;
        }
    }
}
impl Drop for DuplexBridge {
    fn drop(&mut self) {
        self.abort();
    }
}
struct Waiter(Arc<Owner>);
impl Waiter {
    #[expect(
        clippy::result_large_err,
        reason = "The public error retains the complete fixed duplex progress snapshot without allocating during failure."
    )]
    fn new(owner: Arc<Owner>) -> Result<Self, DuplexBridgeError> {
        owner
            .waiters
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 4).then_some(count + 1)
            })
            .map_err(|_| DuplexBridgeError {
                reason: DuplexBridgeErrorReason::Capacity,
                progress: owner.snapshot(),
            })?;
        Ok(Self(owner))
    }
}
impl Drop for Waiter {
    fn drop(&mut self) {
        self.0.waiters.fetch_sub(1, Ordering::AcqRel);
    }
}
fn resource_reason(error: EnvironmentError) -> DuplexBridgeErrorReason {
    if error == EnvironmentError::Capacity {
        DuplexBridgeErrorReason::Capacity
    } else {
        DuplexBridgeErrorReason::Closed
    }
}
fn empty_progress() -> DuplexProgress {
    DuplexProgress {
        a_to_b: TransferProgress::default(),
        b_to_a: TransferProgress::default(),
        outcome: None,
        first_error: None,
        transfer_sealed: false,
        cleanup: CleanupStatus {
            complete: true,
            cleanup_incomplete: false,
            pending_callbacks: 0,
        },
    }
}

enum Endpoint {
    Stream {
        stream: Stream,
        permit: StreamReadPermit,
    },
    Native {
        endpoint: NativeTcpClaim,
        account: ResourceAccount,
    },
}
impl Endpoint {
    fn reserve_write(
        &self,
        maximum: usize,
    ) -> Result<Option<BridgeWriteReservation>, SessionError> {
        match self {
            Self::Stream { stream, .. } => {
                WriteOperation::reserve_bridge_write(stream, maximum).map(Some)
            }
            Self::Native { .. } => Ok(None),
        }
    }
    async fn read(
        &self,
        maximum: usize,
        owner: &Owner,
        direction: usize,
    ) -> Result<ReadStreamStatus, SessionError> {
        let commit = |data: Bytes| {
            let mut state = owner.state.lock().expect("bridge state");
            let progress = &mut state.directions[direction].progress;
            progress.source_read_bytes += data.len() as u64;
            progress.unaccepted_tail = data;
            drop(state);
            owner.changed.notify_waiters();
        };
        match self {
            Self::Stream { stream, permit } => {
                stream
                    .read_bridge_piece(
                        maximum,
                        permit,
                        &owner.stop,
                        &owner.read_gate,
                        |data, _status| commit(data),
                    )
                    .await
            }
            Self::Native { endpoint, account } => {
                endpoint
                    .read_piece(account, maximum, &owner.stop, &owner.read_gate, commit)
                    .await
            }
        }
    }
    async fn close_write(&self) -> Result<(), SessionError> {
        match self {
            Self::Stream { stream, .. } => stream.close_write().await,
            Self::Native { endpoint, .. } => endpoint.close_write(),
        }
    }
    async fn finish(&self) -> Result<DuplexSendCompletion, SessionError> {
        match self {
            Self::Stream { stream, .. } => stream
                .finish()
                .await
                .map(|_| DuplexSendCompletion::AuthenticatedStreamDrained),
            Self::Native { endpoint, .. } => endpoint
                .finish()
                .map(|_| DuplexSendCompletion::NativeTcpWriteShutdownQueued),
        }
    }
    async fn reset(&self) -> Result<(), SessionError> {
        match self {
            Self::Stream { stream, .. } => stream.reset().await,
            Self::Native { endpoint, .. } => {
                endpoint.retire();
                Ok(())
            }
        }
    }
    fn retire_native(&self) {
        if let Self::Native { endpoint, .. } = self {
            endpoint.retire();
        }
    }
    fn cleanup_status(&self) -> CleanupStatus {
        match self {
            Self::Stream { stream, .. } => stream.cleanup_status(),
            Self::Native { endpoint, .. } => endpoint.cleanup_status(),
        }
    }
    async fn wait_cleanup(&self) -> CleanupStatus {
        match self {
            Self::Stream { stream, .. } => stream.wait_cleanup().await,
            Self::Native { endpoint, .. } => endpoint.wait_cleanup().await,
        }
    }
    fn replenish(&self, maximum: usize) -> Result<(), SessionError> {
        match self {
            Self::Stream { stream, .. } => stream.replenish_bridge_credit(maximum),
            Self::Native { .. } => Ok(()),
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Both bridge directions receive their original endpoints and separately prepaid work, tail and write owners."
)]
async fn run(
    owner: Arc<Owner>,
    a: Endpoint,
    b: Endpoint,
    options: DuplexBridgeOptions,
    deadline: Instant,
    work: [ResourceCharge; 2],
    tails: [ApplicationTail; 2],
    writes: [Option<BridgeWriteReservation>; 2],
) {
    let a_closed = tails[0].cancellation();
    let b_closed = tails[1].cancellation();
    loop {
        let changed = owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if owner.state.lock().expect("bridge state").started || owner.stop.is_cancelled() {
            break;
        }
        tokio::select! {
            _ = changed => {},
            _ = owner.stop.cancelled() => break,
            _ = a_closed.cancelled() => { fail(&owner, None, SessionError::Closed); break; },
            _ = b_closed.cancelled() => { fail(&owner, None, SessionError::Closed); break; },
            _ = sleep_until(deadline) => { fail(&owner, None, SessionError::Timeout); break; },
        }
    }
    let cleanup = {
        let [a_write, b_write] = writes;
        let pumps = async {
            tokio::join!(
                pump(&owner, &a, &b, 0, options.chunk_bytes, a_write),
                pump(&owner, &b, &a, 1, options.chunk_bytes, b_write)
            );
        };
        tokio::pin!(pumps);
        let pumps_done = tokio::select! {
            biased;
            _ = owner.stop.cancelled() => false,
            _ = a_closed.cancelled() => { fail(&owner, None, SessionError::Closed); false },
            _ = b_closed.cancelled() => { fail(&owner, None, SessionError::Closed); false },
            _ = sleep_until(deadline) => { fail(&owner, None, SessionError::Timeout); false },
            _ = &mut pumps => true,
        };
        let mut normal = pumps_done && !owner.stop.is_cancelled();
        if normal {
            // FIN is submitted independently by each pump.  Only after both have
            // exited do we wait for the original two authenticated drain owners.
            let finished = tokio::select! {
                biased;
                _ = owner.stop.cancelled() => None,
                _ = a_closed.cancelled() => { fail(&owner, None, SessionError::Closed); None },
                _ = b_closed.cancelled() => { fail(&owner, None, SessionError::Closed); None },
                _ = sleep_until(deadline) => { fail(&owner, None, SessionError::Timeout); None },
                result = async { tokio::join!(finish(&owner, &a, 1), finish(&owner, &b, 0)) } => Some(result),
            };
            normal =
                finished.is_some_and(|(a, b)| a.is_ok() && b.is_ok()) && !owner.stop.is_cancelled();
        }
        if normal {
            a.retire_native();
            b.retire_native();
        }
        let cleanup_deadline = Instant::now() + options.cleanup_timeout;
        if !normal {
            stop_writes(&owner);
            let _ = tokio::join!(a.reset(), b.reset());
            if !pumps_done {
                tokio::select! {
                    _ = &mut pumps => {},
                    _ = sleep_until(cleanup_deadline) => {
                        {
                            let mut state = owner.state.lock().expect("bridge state");
                            state.cleanup = CleanupStatus { complete: false, cleanup_incomplete: true, pending_callbacks: 1 };
                        }
                        owner.changed.notify_waiters();
                        // The deadline ends observation, not the actual callback.
                        // Retain the original task/tail/buffer charges through exit.
                        pumps.await;
                    },
                }
            }
        }
        let cleanup = tokio::select! {
            result = async { tokio::join!(a.wait_cleanup(), b.wait_cleanup()) } => combine_cleanup(result.0, result.1),
            _ = sleep_until(cleanup_deadline) => {
                let mut status = combine_cleanup(a.cleanup_status(), b.cleanup_status());
                if !status.complete { status.cleanup_incomplete = true; }
                status
            },
        };
        let mut observing = cleanup.clone();
        observing.complete = false;
        observing.pending_callbacks = observing.pending_callbacks.saturating_add(1);
        seal(&owner, normal, observing);
        cleanup
    };
    // Worker borrows and endpoint owners disappear before detached result
    // accounts release their original Session ancestry.
    if !cleanup.complete {
        // Incomplete cleanup is an observation, never a resource release.  The
        // original two Session tails continue to account for this supervisor.
        loop {
            let status = combine_cleanup(a.cleanup_status(), b.cleanup_status());
            if status.complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    drop(a);
    drop(b);
    drop(work);
    drop(tails);
    for account in &owner.result_accounts {
        account.detach_result();
    }
    let mut state = owner.state.lock().expect("bridge state");
    state.cleanup = CleanupStatus {
        complete: true,
        cleanup_incomplete: false,
        pending_callbacks: 0,
    };
    // The worker has now observed both endpoint cleanups and dropped the
    // endpoint owners, so no source frontier or charged tail can advance.
    state.sealed = true;
    drop(state);
    owner.changed.notify_waiters();
}

async fn pump(
    owner: &Arc<Owner>,
    source: &Endpoint,
    destination: &Endpoint,
    direction: usize,
    chunk_bytes: usize,
    initial_write: Option<BridgeWriteReservation>,
) {
    let mut reserved_write = initial_write;
    loop {
        if owner.state.lock().expect("bridge state").directions[direction]
            .progress
            .source_read_bytes
            .checked_add(chunk_bytes as u64)
            .is_none()
        {
            fail(owner, Some(direction), SessionError::OperationFailed);
            return;
        }
        if reserved_write.is_none() {
            reserved_write = match destination.reserve_write(chunk_bytes) {
                Ok(reservation) => reservation,
                Err(error) => {
                    fail(owner, Some(direction), error);
                    return;
                }
            };
        }
        let status = tokio::select! {
            biased;
            _ = owner.stop.cancelled() => { abort_direction(owner, direction); return; },
            status = source.read(chunk_bytes, owner, direction) => status,
        };
        let status = match status {
            Ok(status) => status,
            Err(error) if owner.stop.is_cancelled() => {
                let _ = error;
                abort_direction(owner, direction);
                return;
            }
            Err(error) => {
                fail(owner, Some(direction), error);
                return;
            }
        };
        let eof = status == ReadStreamStatus::Eof;
        if status == ReadStreamStatus::Aborted || status == ReadStreamStatus::Error {
            fail(owner, Some(direction), SessionError::StreamReset);
            return;
        }
        let payload = owner.state.lock().expect("bridge state").directions[direction]
            .progress
            .unaccepted_tail
            .clone();
        if payload.is_empty() && !eof {
            fail(owner, Some(direction), SessionError::OperationFailed);
            return;
        }
        if !payload.is_empty() {
            if owner.stop.is_cancelled() {
                abort_direction(owner, direction);
                return;
            }
            let requested = payload.len() as u64;
            if owner.state.lock().expect("bridge state").directions[direction]
                .progress
                .destination_accepted_bytes
                .checked_add(requested)
                .is_none()
            {
                fail(owner, Some(direction), SessionError::OperationFailed);
                return;
            }
            match destination {
                Endpoint::Stream { stream, .. } => {
                    let operation = match WriteOperation::try_prepare_bridge(
                        Arc::new(stream.clone()),
                        payload,
                        reserved_write.take().expect("reserved bridge write"),
                        &owner.stop,
                    ) {
                        Ok(operation) => Arc::new(operation),
                        Err(error) => {
                            fail(owner, Some(direction), error);
                            return;
                        }
                    };
                    {
                        let mut state = owner.state.lock().expect("bridge state");
                        state.directions[direction].write = Some(operation.clone());
                    }
                    if owner.stop.is_cancelled() {
                        operation.cancel();
                    }
                    let start = operation.start().await;
                    let waited = tokio::select! {
                        biased;
                        _ = owner.stop.cancelled() => { operation.cancel(); operation.wait().await },
                        result = operation.wait() => result,
                    };
                    let accepted = operation.progress().accepted_bytes;
                    {
                        let mut state = owner.state.lock().expect("bridge state");
                        let entry = &mut state.directions[direction];
                        // Removing the active owner and installing its stable frontier
                        // share the snapshot gate; observers never double-count it.
                        entry.write = None;
                        let Some(total) = entry
                            .progress
                            .destination_accepted_bytes
                            .checked_add(accepted)
                        else {
                            drop(state);
                            fail(owner, Some(direction), SessionError::OperationFailed);
                            return;
                        };
                        entry.progress.destination_accepted_bytes = total;
                        entry.progress.unaccepted_tail =
                            entry.progress.unaccepted_tail.slice(accepted as usize..);
                    }
                    owner.changed.notify_waiters();
                    if owner.stop.is_cancelled() {
                        abort_direction(owner, direction);
                        return;
                    }
                    if let Err(error) = start {
                        fail(owner, Some(direction), error);
                        return;
                    }
                    match waited {
                        Err(error) => {
                            fail(owner, Some(direction), error);
                            return;
                        }
                        Ok(progress) if progress.terminal_reason.as_deref() != Some("complete") => {
                            let error = match progress.terminal_reason.as_deref() {
                                Some("deadline_exceeded") => SessionError::Timeout,
                                Some("closed") => SessionError::Closed,
                                Some("canceled") => SessionError::Canceled,
                                Some("stream_reset") => SessionError::StreamReset,
                                _ => SessionError::OperationFailed,
                            };
                            fail(owner, Some(direction), error);
                            return;
                        }
                        Ok(_) => {}
                    }
                    if accepted != requested {
                        fail(owner, Some(direction), SessionError::OperationFailed);
                        return;
                    }
                }
                Endpoint::Native { endpoint, account } => {
                    let mut accepted = 0usize;
                    while accepted < payload.len() {
                        let result = tokio::select! {
                            biased;
                            _ = owner.stop.cancelled() => { abort_direction(owner, direction); return; },
                            result = endpoint.write_piece(account, &payload[accepted..], &owner.stop, &owner.native_write_gate, |count| {
                                let mut state = owner.state.lock().expect("bridge state");
                                let progress = &mut state.directions[direction].progress;
                                progress.destination_accepted_bytes += count as u64;
                                progress.unaccepted_tail = progress.unaccepted_tail.slice(count..);
                                drop(state); owner.changed.notify_waiters();
                            }) => result,
                        };
                        match result {
                            Ok(count) => accepted += count,
                            Err(_) if owner.stop.is_cancelled() => {
                                abort_direction(owner, direction);
                                return;
                            }
                            Err(error) => {
                                fail(owner, Some(direction), error);
                                return;
                            }
                        }
                    }
                }
            }
        }
        if eof {
            let closed = tokio::select! {
                biased;
                _ = owner.stop.cancelled() => { abort_direction(owner, direction); return; },
                result = destination.close_write() => result,
            };
            if let Err(error) = closed {
                fail(owner, Some(direction), error);
                return;
            }
            let mut state = owner.state.lock().expect("bridge state");
            let progress = &mut state.directions[direction].progress;
            progress.terminal = Some(DuplexDirectionTerminal::Eof);
            progress.close_write_complete = true;
            drop(state);
            owner.changed.notify_waiters();
            return;
        }
        // Release only the receiver's original finite window after this
        // direction's entire current chunk has been locally accepted.
        if let Err(error) = source.replenish(chunk_bytes) {
            if owner.stop.is_cancelled() {
                abort_direction(owner, direction);
            } else {
                fail(owner, Some(direction), error);
            }
            return;
        }
    }
}
async fn finish(owner: &Owner, endpoint: &Endpoint, direction: usize) -> Result<(), SessionError> {
    match endpoint.finish().await {
        Ok(completion) => {
            {
                let mut state = owner.state.lock().expect("bridge state");
                state.directions[direction].progress.finish_complete = true;
                state.directions[direction].progress.send_completion = Some(completion);
            }
            owner.changed.notify_waiters();
            Ok(())
        }
        Err(error) => {
            fail(owner, Some(direction), error);
            Err(error)
        }
    }
}
fn fail(owner: &Owner, direction: Option<usize>, error: SessionError) {
    {
        let mut state = owner.state.lock().expect("bridge state");
        if state.first_error.is_none() {
            state.first_error = Some(error);
        }
        if let Some(direction) = direction {
            state.directions[direction].progress.terminal =
                Some(DuplexDirectionTerminal::Failed(error));
        }
    }
    {
        let _read_gate = owner.read_gate.lock().expect("bridge read gate");
        owner.stop.cancel();
    }
    {
        let _write_gate = owner
            .native_write_gate
            .lock()
            .expect("bridge native write gate");
    }
    stop_writes(owner);
    owner.changed.notify_waiters();
}
fn abort_direction(owner: &Owner, direction: usize) {
    let mut state = owner.state.lock().expect("bridge state");
    let progress = &mut state.directions[direction].progress;
    if progress.terminal.is_none() {
        progress.terminal = Some(DuplexDirectionTerminal::Aborted);
    }
    drop(state);
    owner.changed.notify_waiters();
}
fn stop_writes(owner: &Owner) {
    let writes: [Option<Arc<WriteOperation>>; 2] = {
        let state = owner.state.lock().expect("bridge state");
        std::array::from_fn(|i| state.directions[i].write.clone())
    };
    for write in writes.into_iter().flatten() {
        write.cancel();
    }
}
fn combine_cleanup(a: CleanupStatus, b: CleanupStatus) -> CleanupStatus {
    CleanupStatus {
        complete: a.complete && b.complete,
        cleanup_incomplete: a.cleanup_incomplete || b.cleanup_incomplete,
        pending_callbacks: a.pending_callbacks.saturating_add(b.pending_callbacks),
    }
}
fn seal(owner: &Owner, normal: bool, mut cleanup: CleanupStatus) {
    let mut state = owner.state.lock().expect("bridge state");
    let still_pumping = state
        .directions
        .iter()
        .any(|direction| direction.progress.terminal.is_none() || direction.write.is_some());
    if still_pumping {
        cleanup.complete = false;
        cleanup.cleanup_incomplete = true;
        cleanup.pending_callbacks = cleanup.pending_callbacks.saturating_add(1);
    }
    state.outcome = Some(
        if normal && state.first_error.is_none() && !owner.stop.is_cancelled() {
            DuplexOutcome::Normal
        } else if state.first_error.is_some() {
            DuplexOutcome::Failed
        } else {
            DuplexOutcome::Aborted
        },
    );
    state.cleanup = cleanup;
    state.sealed = !still_pumping;
    drop(state);
    owner.changed.notify_waiters();
}
