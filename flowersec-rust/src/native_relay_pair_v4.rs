//! Bounded opaque native/mixed forwarding. Visible scopes are routing labels,
//! never accepted endpoint streams. Every physical tail retains its position.
use super::*;
use crate::namespace_v4::verifier::credential::tunnel::TunnelLimits;
use flowersec_native_transport::{Cancellation as NativeCancellation, RawQuicError, RawQuicStream};
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::task::TaskTracker;

struct BufferBank {
    buffers: Mutex<Vec<Vec<u8>>>,
    available: Arc<Semaphore>,
    wake: [Arc<Notify>; 2],
}
impl BufferBank {
    fn new(count: usize, maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            buffers: Mutex::new((0..count).map(|_| Vec::with_capacity(maximum)).collect()),
            available: Arc::new(Semaphore::new(count)),
            wake: [Arc::new(Notify::new()), Arc::new(Notify::new())],
        })
    }
    fn wake(&self, role: usize) -> Arc<Notify> {
        self.wake[role].clone()
    }
    fn try_take(self: &Arc<Self>) -> ConnectResult<Frame> {
        let permit = self
            .available
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConnectError::Capacity)?;
        let wire = self
            .buffers
            .lock()
            .expect("original relay frame slab")
            .pop()
            .ok_or(ConnectError::Capacity)?;
        Ok(Frame {
            wire,
            bank: self.clone(),
            permit: Some(permit),
        })
    }
    async fn take(
        self: &Arc<Self>,
        cancellation: &CancellationToken,
        direction_cancel: &CancellationToken,
    ) -> ConnectResult<Frame> {
        let permit = tokio::select! {
            _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = direction_cancel.cancelled() => return Err(ConnectError::Canceled),
            result = self.available.clone().acquire_owned() =>
                result.map_err(|_| ConnectError::Carrier)?,
        };
        let wire = self
            .buffers
            .lock()
            .expect("original relay frame slab")
            .pop()
            .ok_or(ConnectError::Capacity)?;
        Ok(Frame {
            wire,
            bank: self.clone(),
            permit: Some(permit),
        })
    }
}

struct Frame {
    wire: Vec<u8>,
    bank: Arc<BufferBank>,
    permit: Option<OwnedSemaphorePermit>,
}
impl std::ops::Deref for Frame {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.wire
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        let mut wire = std::mem::take(&mut self.wire);
        wire.fill(0);
        wire.clear();
        self.bank
            .buffers
            .lock()
            .expect("original relay frame return after I/O")
            .push(wire);
        drop(self.permit.take());
        for wake in &self.bank.wake {
            wake.notify_one();
        }
    }
}
struct Mapping {
    scope: u64,
    opener: usize,
    epoch: u32,
    senders: [mpsc::Sender<Frame>; 2],
    streams: Mutex<[Option<RawQuicStream>; 2]>,
    done: std::sync::atomic::AtomicBool,
    direction_stopped: [std::sync::atomic::AtomicBool; 2],
    wake: [Arc<Notify>; 2],
}
impl Mapping {
    fn cancel(&self) {
        for stream in self
            .streams
            .lock()
            .expect("original relay mapping handles")
            .iter()
            .flatten()
        {
            stream.cancel_current();
        }
    }
}
struct DirectionInput<'a> {
    mapping: &'a Mapping,
    role: usize,
    receiver: Option<mpsc::Receiver<Frame>>,
}
impl Drop for DirectionInput<'_> {
    fn drop(&mut self) {
        self.mapping.direction_stopped[self.role].store(true, Ordering::Release);
        drop(self.receiver.take());
        self.mapping.wake[self.role].notify_one();
    }
}
struct Directory {
    slots: Vec<Option<Arc<Mapping>>>,
    used: Vec<u64>,
    // Direction bits share the fixed used-scope index and never retain a
    // mapping or provider handle after physical retirement.
    retired: Vec<u8>,
    used_count: u64,
    seed: RandomState,
}
impl Directory {
    fn claim_scope(&mut self, scope: u64, maximum: u64) -> ConnectResult<()> {
        if self.used_count >= maximum {
            return Err(ConnectError::Capacity);
        }

        let mask = self.used.len() - 1;
        let mut index = self.seed.hash_one(scope) as usize & mask;
        for _ in 0..self.used.len() {
            if self.used[index] == scope {
                return Err(ConnectError::Protocol);
            }
            if self.used[index] == 0 {
                self.used[index] = scope;
                self.retired[index] = 0;
                self.used_count += 1;
                return Ok(());
            }
            index = (index + 1) & mask;
        }
        Err(ConnectError::Capacity)
    }
    fn retire_scope(&mut self, scope: u64, directions: u8) -> ConnectResult<()> {
        let mask = self.used.len() - 1;
        let mut index = self.seed.hash_one(scope) as usize & mask;
        for _ in 0..self.used.len() {
            if self.used[index] == scope {
                self.retired[index] |= directions & 0b11;
                return Ok(());
            }
            if self.used[index] == 0 {
                return Err(ConnectError::Protocol);
            }
            index = (index + 1) & mask;
        }
        Err(ConnectError::Protocol)
    }
    fn is_retired(&self, scope: u64, role: usize) -> bool {
        let mask = self.used.len() - 1;
        let mut index = self.seed.hash_one(scope) as usize & mask;
        for _ in 0..self.used.len() {
            if self.used[index] == scope {
                return self.retired[index] & (1 << role) != 0;
            }
            if self.used[index] == 0 {
                return false;
            }
            index = (index + 1) & mask;
        }
        false
    }
}
struct Accepted {
    role: usize,
    stream: Option<RawQuicStream>,
    first: Option<Frame>,
    pending: Option<OwnedSemaphorePermit>,
    workers: TaskTracker,
}
impl Drop for Accepted {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let pending = self.pending.take();
            stream.cancel_current();
            self.workers.spawn(async move {
                stream.wait_termination_current().await;
                drop(pending);
            });
        }
    }
}
enum Event {
    Accepted(Accepted),
    Failure(ConnectError),
}
struct PendingWire {
    role: usize,
    wire: Vec<u8>,
    mapping: Option<Arc<Mapping>>,
    open: bool,
    buffer_wake: Arc<Notify>,
}
impl PendingWire {
    fn attach_mapping(&mut self, mapping: Arc<Mapping>) {
        if self.mapping.is_none() {
            self.mapping = Some(mapping);
        }
    }
}
enum PairInput {
    Event(Event),
    Wire(PendingWire),
}
enum LaneOutcome {
    Done,
    Retry(PendingWire),
}

async fn wait_for_pending_wake(
    mapping_wake: Option<Arc<Notify>>,
    buffer_wake: Option<Arc<Notify>>,
) {
    match (mapping_wake, buffer_wake) {
        (Some(mapping_wake), Some(buffer_wake)) => {
            tokio::select! {
                _ = mapping_wake.notified() => {}
                _ = buffer_wake.notified() => {}
            }
        }
        (Some(mapping_wake), None) => mapping_wake.notified().await,
        (None, Some(buffer_wake)) => buffer_wake.notified().await,
        (None, None) => std::future::pending::<()>().await,
    }
}
enum ReadFrame {
    Frame(Frame),
    Eof,
    Reset(bool),
}
pub(super) struct Pair {
    maximum: usize,
    pending: usize,
    resident: usize,
    total: u64,
    datagram: usize,
    queue_bytes: u64,
    timeout: Duration,
    buffers: Arc<BufferBank>,
    directory: Mutex<Directory>,
    failure: Mutex<Option<ConnectError>>,
    created: AtomicU64,
    meters: [Arc<wss::RelayBudget>; 2],
    workers: TaskTracker,
    cancellation: CancellationToken,
    native_cancel: NativeCancellation,
    events: mpsc::Sender<Event>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<Event>>,
    shared_writes: [tokio::sync::Mutex<()>; 2],
    #[cfg(test)]
    publication_waiting: [Arc<Notify>; 2],
    mapping_positions: Arc<Semaphore>,
    input_positions: Arc<Semaphore>,
    datagram_forwarded: [std::sync::atomic::AtomicBool; 2],
    cleanup_done: Arc<std::sync::atomic::AtomicBool>,
    _charges: [ResourceCharge; 2],
}
impl Pair {
    pub(super) fn datagram_forwarded(&self) -> bool {
        self.datagram_forwarded
            .iter()
            .all(|direction| direction.load(Ordering::Acquire))
    }
    pub(super) fn new(
        accounts: &[ResourceAccount; 2],
        limits: [TunnelLimits; 2],
        policies: &[wss::Policy],
        timeout: Duration,
        provider_queues: [usize; 2],
    ) -> ConnectResult<Option<Arc<Self>>> {
        if policies.len() != 2 || timeout.is_zero() || timeout > Duration::from_secs(5) {
            return Err(ConnectError::Configuration);
        }
        if policies.iter().all(|policy| policy.carrier == 1) {
            if limits.iter().any(|limit| {
                limit.max_pending_native_mappings != 0
                    || limit.max_resident_native_mappings != 0
                    || limit.max_total_native_mappings != 0
                    || limit.max_datagram_bytes != 0
            }) {
                return Err(ConnectError::Configuration);
            }
            return Ok(None);
        }
        let pending = limits
            .iter()
            .map(|limit| limit.max_pending_native_mappings)
            .min()
            .unwrap_or(0);
        let resident = limits
            .iter()
            .map(|limit| limit.max_resident_native_mappings)
            .min()
            .unwrap_or(0);
        let total = limits
            .iter()
            .map(|limit| limit.max_total_native_mappings)
            .min()
            .unwrap_or(0);
        let maximum = limits
            .iter()
            .map(|limit| limit.max_envelope_bytes)
            .min()
            .unwrap_or(0);
        let datagram = limits[0].max_datagram_bytes;
        if !(3..=128).contains(&pending)
            || resident == 0
            || resident > 2048
            || total < resident
            || total > (1 << 20)
            || !(10354..=(1 << 20) + 8).contains(&maximum)
            || datagram != limits[1].max_datagram_bytes
            || datagram > 1200
            || datagram != 0 && (datagram < 44 || policies.iter().any(|policy| policy.carrier == 1))
        {
            return Err(ConnectError::Configuration);
        }
        let positions = pending
            .checked_add(resident)
            .ok_or(ConnectError::Capacity)?;
        let provider_items = (provider_queues[0] as u64)
            .checked_add(provider_queues[1] as u64)
            .and_then(|value| value.checked_add(4))
            .ok_or(ConnectError::Capacity)?;
        let queue_items = positions
            .checked_mul(2)
            .and_then(|value| value.checked_add(provider_items))
            .ok_or(ConnectError::Capacity)?;
        let queue_bytes = positions
            .checked_mul(2)
            .and_then(|value| value.checked_add(provider_items))
            .and_then(|value| value.checked_mul(maximum))
            .and_then(|value| value.checked_add(datagram * 2))
            .ok_or(ConnectError::Capacity)?;
        if limits
            .iter()
            .any(|limit| limit.max_queue_items < queue_items || limit.max_queue_bytes < queue_bytes)
        {
            return Err(ConnectError::Capacity);
        }
        let vector = ResourceLimits {
            // The four provider positions cover one in-flight provider read
            // and one detached Pair input per role, in addition to each full
            // input queue. Each pending input may retain one retired mapping,
            // including its channel allocations, after its slot is reused.
            // The directory has at most four hash slots per allowed scope;
            // each holds eight scope bytes and one retired-direction byte,
            // within the existing 64-byte allowance per total mapping.
            sdk_bytes: queue_bytes
                .checked_mul(2)
                .and_then(|value| value.checked_add(positions * 4096))
                .and_then(|value| value.checked_add(total * 64))
                .and_then(|value| {
                    value.checked_add(2 * (std::mem::size_of::<PendingWire>() as u64 + 4096))
                })
                .and_then(|value| {
                    value.checked_add(2 * std::mem::size_of::<tokio::sync::Mutex<()>>() as u64)
                })
                .ok_or(ConnectError::Capacity)?,
            items: queue_items + total + 2,
            tasks: positions * 4 + 8,
            work_slots: positions * 4 + 8,
            timers: positions * 4 + 8,
            native_handles: positions * 2 + 4,
            ..ResourceLimits::default()
        };
        let a = accounts[0].reserve(vector)?;
        let b = accounts[1].reserve(vector)?;
        let (events, incoming) = mpsc::channel(pending as usize + 4);
        Ok(Some(Arc::new(Self {
            maximum: maximum as usize,
            pending: pending as usize,
            resident: resident as usize,
            total,
            datagram: datagram as usize,
            queue_bytes,
            timeout,
            buffers: BufferBank::new(positions as usize * 2, maximum as usize),
            directory: Mutex::new(Directory {
                slots: (0..positions).map(|_| None).collect(),
                used: vec![0; (total as usize * 2).next_power_of_two()],
                retired: vec![0; (total as usize * 2).next_power_of_two()],
                used_count: 0,
                seed: RandomState::new(),
            }),
            failure: Mutex::new(None),
            created: AtomicU64::new(0),
            meters: [
                policies[0]
                    .relay_budget
                    .clone()
                    .ok_or(ConnectError::Configuration)?,
                policies[1]
                    .relay_budget
                    .clone()
                    .ok_or(ConnectError::Configuration)?,
            ],
            workers: TaskTracker::new(),
            cancellation: CancellationToken::new(),
            native_cancel: NativeCancellation::new(),
            events,
            incoming: tokio::sync::Mutex::new(incoming),
            shared_writes: [tokio::sync::Mutex::new(()), tokio::sync::Mutex::new(())],
            #[cfg(test)]
            publication_waiting: [Arc::new(Notify::new()), Arc::new(Notify::new())],
            mapping_positions: Arc::new(Semaphore::new(resident as usize)),
            input_positions: Arc::new(Semaphore::new(pending as usize)),
            datagram_forwarded: [
                std::sync::atomic::AtomicBool::new(false),
                std::sync::atomic::AtomicBool::new(false),
            ],
            cleanup_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            _charges: [a, b],
        })))
    }
    pub(super) fn mapping_capacity(&self) -> usize {
        self.pending + self.resident
    }
    pub(super) fn queue_bytes(&self) -> u64 {
        self.queue_bytes
    }
    fn fail(&self, failure: ConnectError) {
        self.failure
            .lock()
            .expect("first original native relay failure")
            .get_or_insert(failure);
        let _ = self.events.try_send(Event::Failure(failure));
        self.cancellation.cancel();
        self.native_cancel.cancel();
    }
    fn failure(&self) -> ConnectError {
        self.failure
            .lock()
            .expect("original relay failure projection")
            .unwrap_or(ConnectError::Canceled)
    }
    pub(super) fn close(&self) {
        self.cancellation.cancel();
        self.native_cancel.cancel();
        for mapping in self
            .directory
            .lock()
            .expect("original mapping cancellation")
            .slots
            .iter()
            .flatten()
        {
            mapping.cancel();
        }
    }
    pub(super) async fn wait_cleanup(&self) {
        self.close();
        let mut events = self.incoming.lock().await;
        events.close();
        while let Ok(event) = events.try_recv() {
            if let Event::Accepted(accepted) = event
                && let Some(stream) = &accepted.stream
            {
                stream.cancel_current();
                stream.wait_termination_current().await;
            }
        }
        drop(events);
        self.workers.close();
        self.workers.wait().await;
        self.directory
            .lock()
            .expect("retired mapping table")
            .slots
            .clear();
        self.cleanup_done.store(true, Ordering::Release);
    }
    pub(super) async fn run(
        self: &Arc<Self>,
        a: &mut mpsc::Receiver<Vec<u8>>,
        b: &mut mpsc::Receiver<Vec<u8>>,
        providers: [direct_carrier::Provider; 2],
        check: impl Fn() -> ConnectResult<()>,
    ) -> ConnectResult<()> {
        let mut connections = [None, None];
        for role in 0..2 {
            if let direct_carrier::Provider::Native(provider) = &providers[role] {
                provider.retain_relay_cleanup(self.cleanup_done.clone())?;
                let connection = provider.relay_connection()?;
                if connection.capacity() < self.pending + self.resident + 3
                    || self.datagram != 0
                        && connection
                            .datagram_maximum()
                            .is_none_or(|maximum| maximum < self.datagram)
                {
                    return Err(ConnectError::Capacity);
                }
                connections[role] = Some(connection);
            }
        }
        for (role, connection) in connections.iter().enumerate() {
            if let Some(connection) = connection.clone() {
                let pair = self.clone();
                self.workers.spawn(async move {
                    pair.accept(role, connection).await;
                });
            }
        }
        if self.datagram != 0 {
            for role in 0..2 {
                let source = connections[role]
                    .clone()
                    .ok_or(ConnectError::Configuration)?;
                let target = connections[1 - role]
                    .clone()
                    .ok_or(ConnectError::Configuration)?;
                let pair = self.clone();
                self.workers.spawn(async move {
                    pair.datagrams(role, source, target).await;
                });
            }
        }
        let mut pending_wires: [Option<PendingWire>; 2] = [None, None];
        let mut events = self.incoming.lock().await;
        loop {
            check()?;
            let input = tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return Err(self.failure()),
                event = events.recv() => match event {
                    Some(event) => PairInput::Event(event),
                    None => return Err(ConnectError::Carrier),
                },
                wire = a.recv(), if pending_wires[0].is_none() => {
                    let wire = wire.ok_or(ConnectError::Carrier)?;
                    PairInput::Wire(PendingWire {
                        role: 0,
                        open: wire.get(4) == Some(&7),
                        wire,
                        mapping: None,
                        buffer_wake: self.buffers.wake(0),
                    })
                },
                wire = b.recv(), if pending_wires[1].is_none() => {
                    let wire = wire.ok_or(ConnectError::Carrier)?;
                    PairInput::Wire(PendingWire {
                        role: 1,
                        open: wire.get(4) == Some(&7),
                        wire,
                        mapping: None,
                        buffer_wake: self.buffers.wake(1),
                    })
                },
                _ = wait_for_pending_wake(
                    pending_wires[0].as_ref().and_then(|pending| pending.mapping.as_ref().map(|mapping| mapping.wake[0].clone())),
                    pending_wires[0].as_ref().map(|pending| pending.buffer_wake.clone()),
                ), if pending_wires[0].is_some() =>
                    PairInput::Wire(pending_wires[0].take().expect("pending role A wire")),
                _ = wait_for_pending_wake(
                    pending_wires[1].as_ref().and_then(|pending| pending.mapping.as_ref().map(|mapping| mapping.wake[1].clone())),
                    pending_wires[1].as_ref().map(|pending| pending.buffer_wake.clone()),
                ), if pending_wires[1].is_some() =>
                    PairInput::Wire(pending_wires[1].take().expect("pending role B wire")),
            };
            match input {
                PairInput::Wire(pending) => {
                    let role = pending.role;
                    match self.lane(pending, &providers, &connections).await {
                        Ok(LaneOutcome::Done) => {}
                        Ok(LaneOutcome::Retry(pending)) => pending_wires[role] = Some(pending),
                        Err(failure) => {
                            return Err(failure);
                        }
                    }
                }
                PairInput::Event(Event::Failure(failure)) => return Err(failure),
                PairInput::Event(Event::Accepted(accepted)) => {
                    let first = accepted.first.as_ref().ok_or(ConnectError::Configuration)?;
                    let scope = scope(first)?;
                    if first[4] != 7 {
                        return Err(ConnectError::Protocol);
                    }
                    self.create(
                        scope,
                        accepted.role,
                        Some(accepted),
                        None,
                        &providers,
                        &connections,
                    )?;
                }
            }
        }
    }
    async fn lane(
        self: &Arc<Self>,
        mut pending: PendingWire,
        providers: &[direct_carrier::Provider; 2],
        connections: &[Option<native::Connection>; 2],
    ) -> ConnectResult<LaneOutcome> {
        let role = pending.role;
        frame(&pending.wire, self.maximum)?;
        if matches!(pending.wire[4], 7 | 8) {
            if connections[role].is_some() {
                return Err(ConnectError::Protocol);
            }
            let scope = scope(&pending.wire)?;
            let mapping = if let Some(mapping) = pending.mapping.clone() {
                if mapping.done.load(Ordering::Acquire) {
                    return Ok(LaneOutcome::Done);
                }
                Some(mapping)
            } else if pending.open {
                None
            } else {
                self.directory
                    .lock()
                    .expect("opaque visible scope routing")
                    .slots
                    .iter()
                    .flatten()
                    .find(|mapping| mapping.scope == scope && !mapping.done.load(Ordering::Acquire))
                    .cloned()
            };
            if let Some(mapping) = mapping {
                if pending.wire[4] == 7 {
                    return Err(ConnectError::Protocol);
                }
                if mapping.direction_stopped[role].load(Ordering::Acquire) {
                    return Ok(LaneOutcome::Done);
                }
                let sender = mapping.senders[role].clone();
                let permit = match sender.try_reserve() {
                    Ok(permit) => permit,
                    Err(mpsc::error::TrySendError::Full(())) => {
                        pending.attach_mapping(mapping.clone());
                        return Ok(LaneOutcome::Retry(pending));
                    }
                    Err(mpsc::error::TrySendError::Closed(())) => {
                        return if mapping.direction_stopped[role].load(Ordering::Acquire)
                            || mapping.done.load(Ordering::Acquire)
                        {
                            Ok(LaneOutcome::Done)
                        } else {
                            Err(ConnectError::Carrier)
                        };
                    }
                };
                let mut frame = match self.buffers.try_take() {
                    Ok(frame) => frame,
                    Err(ConnectError::Capacity) => {
                        pending.attach_mapping(mapping);
                        return Ok(LaneOutcome::Retry(pending));
                    }
                    Err(failure) => return Err(failure),
                };
                frame.wire.extend_from_slice(&pending.wire);
                permit.send(frame);
            } else {
                if pending.wire[4] == 8
                    && self
                        .directory
                        .lock()
                        .expect("retired native mapping scope")
                        .is_retired(scope, role)
                {
                    return Ok(LaneOutcome::Done);
                }
                if !pending.open || pending.wire[4] != 7 {
                    return Err(ConnectError::Protocol);
                }
                let mut first = match self.buffers.try_take() {
                    Ok(frame) => frame,
                    Err(ConnectError::Capacity) => {
                        return Ok(LaneOutcome::Retry(pending));
                    }
                    Err(failure) => return Err(failure),
                };
                first.wire.extend_from_slice(&pending.wire);
                self.create(scope, role, None, Some(first), providers, connections)?;
            }
            Ok(LaneOutcome::Done)
        } else {
            if !matches!(pending.wire[4], 6 | 9 | 11..=15)
                || pending.wire.len() < 44
                || pending.wire[12..20] != [0; 8]
            {
                return Err(ConnectError::Protocol);
            }
            // One bounded maintenance publisher preserves order and has a
            // separate position from every mapping. No fire-and-forget writes.
            self.publish_shared(
                1 - role,
                &providers[1 - role],
                &pending.wire,
                &self.cancellation,
            )
            .await?;
            Ok(LaneOutcome::Done)
        }
    }
    /// A shared carrier has one original provider publication position.
    /// Mapping DATA and maintenance retain their prepaid input while waiting
    /// for that position; only its owner makes the provider's send copy.
    async fn publish_shared(
        &self,
        role: usize,
        provider: &direct_carrier::Provider,
        wire: &[u8],
        direction_cancel: &CancellationToken,
    ) -> ConnectResult<()> {
        let deadline = Instant::now() + self.timeout;
        #[cfg(test)]
        self.publication_waiting[role].notify_one();
        let _publication = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = direction_cancel.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline),
            position = self.shared_writes[role].lock() => position,
        };
        let sending = provider.send(wire.to_vec());
        tokio::pin!(sending);
        tokio::select! {
            result = &mut sending => result,
            _ = self.cancellation.cancelled() => {
                provider.close();
                let _ = sending.await;
                Err(ConnectError::Canceled)
            },
            _ = tokio::time::sleep_until(deadline) => {
                self.close();
                provider.close();
                let _ = sending.await;
                Err(ConnectError::Deadline)
            },
        }
    }
    fn create(
        self: &Arc<Self>,
        scope: u64,
        role: usize,
        accepted: Option<Accepted>,
        first: Option<Frame>,
        providers: &[direct_carrier::Provider; 2],
        connections: &[Option<native::Connection>; 2],
    ) -> ConnectResult<()> {
        let permit = self
            .mapping_positions
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConnectError::Capacity)?;
        let (send_a, input_a) = mpsc::channel(1);
        let (send_b, input_b) = mpsc::channel(1);
        let first_wire = accepted
            .as_ref()
            .and_then(|accepted| accepted.first.as_ref())
            .or(first.as_ref())
            .ok_or(ConnectError::Configuration)?;
        let epoch = u32::from_be_bytes(
            first_wire[8..12]
                .try_into()
                .map_err(|_| ConnectError::Protocol)?,
        );
        let mapping = Arc::new(Mapping {
            scope,
            opener: role,
            epoch,
            senders: [send_a, send_b],
            streams: Mutex::new([None, None]),
            done: std::sync::atomic::AtomicBool::new(false),
            direction_stopped: [
                std::sync::atomic::AtomicBool::new(false),
                std::sync::atomic::AtomicBool::new(false),
            ],
            wake: [Arc::new(Notify::new()), Arc::new(Notify::new())],
        });
        {
            let mut directory = self.directory.lock().expect("original native mapping slot");
            let index = directory
                .slots
                .iter()
                .position(|slot| {
                    slot.as_ref()
                        .is_none_or(|mapping| mapping.done.load(Ordering::Acquire))
                })
                .ok_or(ConnectError::Capacity)?;
            directory.claim_scope(scope, self.total)?;
            directory.slots[index] = Some(mapping.clone());
        }
        let pair = self.clone();
        let providers = (*providers).clone();
        let connections = (*connections).clone();
        self.workers.spawn(async move {
            let _permit = permit;
            let result = pair
                .mapping(
                    mapping.clone(),
                    accepted,
                    first,
                    [input_a, input_b],
                    providers,
                    connections,
                )
                .await;
            mapping.cancel();
            let streams = mapping
                .streams
                .lock()
                .expect("mapping original cleanup snapshot")
                .clone();
            for stream in streams.iter().flatten() {
                stream.wait_termination_current().await;
            }
            *mapping.streams.lock().expect("mapping actual cleanup exit") = [None, None];
            // Publish the retired scope/direction facts while holding the same
            // directory lock that admits slot reuse. A subsequent DATA frame
            // can therefore never observe done=true before its bounded
            // retired-direction discard decision is visible.
            let retirement = {
                let mut directory = pair.directory.lock().expect("retired native mapping scope");
                let result = directory.retire_scope(mapping.scope, 0b11);
                mapping.done.store(true, Ordering::Release);
                result
            };
            for wake in &mapping.wake {
                wake.notify_one();
            }
            if let Err(failure) = retirement {
                pair.fail(failure);
            }
            if let Err(failure) = result {
                pair.fail(failure);
            }
        });
        Ok(())
    }
    async fn accept(self: Arc<Self>, role: usize, connection: native::Connection) {
        loop {
            let permit = tokio::select! { _ = self.cancellation.cancelled() => return,
            result = self.input_positions.clone().acquire_owned() => match result { Ok(permit) => permit, Err(_) => return } };
            // Count an original handle attempt before Accept. Every failed or
            // canceled attempt remains charged against the signed total.
            if self
                .created
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < self.total).then_some(count + 1)
                })
                .is_err()
            {
                self.fail(ConnectError::Capacity);
                return;
            }
            let stream = match connection.accept_stream(&self.native_cancel).await {
                Ok(stream) => stream,
                Err(_) => {
                    if !self.cancellation.is_cancelled() {
                        self.fail(ConnectError::Carrier);
                    }
                    return;
                }
            };
            let pair = self.clone();
            self.workers.spawn(async move {
                pair.read_first(role, stream, permit).await;
            });
        }
    }
    async fn read_first(
        self: Arc<Self>,
        role: usize,
        stream: RawQuicStream,
        permit: OwnedSemaphorePermit,
    ) {
        let first = {
            let original = self.read(role, &stream, &self.native_cancel, &self.cancellation);
            tokio::pin!(original);
            tokio::select! {
                result = &mut original => match result {
                    Ok(ReadFrame::Frame(first)) => Some(first), _ => None,
                },
                _ = tokio::time::sleep(self.timeout) => {
                    stream.cancel_current(); let _ = original.await; None
                },
                _ = self.cancellation.cancelled() => {
                    stream.cancel_current(); let _ = original.await; None
                },
            }
        };
        let Some(first) = first else {
            stream.cancel_current();
            stream.wait_termination_current().await;
            if !self.cancellation.is_cancelled() {
                self.fail(ConnectError::Protocol);
            }
            return;
        };
        let accepted = Accepted {
            role,
            stream: Some(stream),
            first: Some(first),
            pending: Some(permit),
            workers: self.workers.clone(),
        };
        if let Err(failure) = self.events.try_send(Event::Accepted(accepted)) {
            if let Event::Accepted(accepted) = failure.into_inner()
                && let Some(stream) = &accepted.stream
            {
                stream.cancel_current();
                stream.wait_termination_current().await;
            }
            self.fail(ConnectError::Capacity);
        }
    }
    async fn mapping(
        self: &Arc<Self>,
        mapping: Arc<Mapping>,
        mut accepted: Option<Accepted>,
        first: Option<Frame>,
        inputs: [mpsc::Receiver<Frame>; 2],
        providers: [direct_carrier::Provider; 2],
        connections: [Option<native::Connection>; 2],
    ) -> ConnectResult<()> {
        let first = if let Some(accepted) = accepted.as_mut() {
            mapping.streams.lock().expect("original accepted mapping")[mapping.opener] =
                accepted.stream.clone();
            accepted.first.take().ok_or(ConnectError::Configuration)?
        } else {
            first.ok_or(ConnectError::Configuration)?
        };
        let peer = 1 - mapping.opener;
        if let Some(connection) = &connections[peer] {
            if self
                .created
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < self.total).then_some(count + 1)
                })
                .is_err()
            {
                return Err(ConnectError::Capacity);
            }
            let original = connection.open_stream(&self.native_cancel);
            tokio::pin!(original);
            let stream = tokio::select! {
                result = &mut original => result.map_err(|_| ConnectError::Carrier)?,
                _ = self.cancellation.cancelled() => {
                    self.close();
                    if let Ok(stream) = original.await {
                        stream.cancel_current();
                        stream.wait_termination_current().await;
                    }
                    return Err(ConnectError::Canceled);
                }
                _ = tokio::time::sleep(self.timeout) => {
                    self.close();
                    if let Ok(stream) = original.await { stream.cancel_current(); stream.wait_termination_current().await; }
                    return Err(ConnectError::Deadline);
                }
            };
            mapping.streams.lock().expect("original opened mapping")[peer] = Some(stream);
        }
        // The pending accepted position retires only after the exact peer Open
        // returned and both original native objects are installed.
        if let Some(mut accepted) = accepted.take() {
            accepted.stream.take();
            drop(accepted);
        }
        let [a, b] = inputs;
        let streams = mapping
            .streams
            .lock()
            .expect("mapping direction snapshot")
            .clone();
        let (first_a, first_b) = if mapping.opener == 0 {
            (Some(first), None)
        } else {
            (None, Some(first))
        };
        let left = self.direction_checked(
            &mapping,
            0,
            streams[0].as_ref(),
            streams[1].as_ref(),
            a,
            first_a,
            &providers[1],
        );
        let right = self.direction_checked(
            &mapping,
            1,
            streams[1].as_ref(),
            streams[0].as_ref(),
            b,
            first_b,
            &providers[0],
        );
        let (left, right) = tokio::join!(left, right);
        left?;
        right?;
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Each direction borrows the original mapping, native endpoints, queues and distinct cancellation scopes."
    )]
    async fn direction_checked(
        &self,
        mapping: &Mapping,
        role: usize,
        source: Option<&RawQuicStream>,
        target: Option<&RawQuicStream>,
        messages: mpsc::Receiver<Frame>,
        first: Option<Frame>,
        provider: &direct_carrier::Provider,
    ) -> ConnectResult<()> {
        let direction_cancel = CancellationToken::new();
        let native_read_cancel = NativeCancellation::new();
        let forwarding = self.direction(
            mapping,
            role,
            source,
            target,
            messages,
            first,
            provider,
            &native_read_cancel,
            &direction_cancel,
        );
        tokio::pin!(forwarding);
        let result = if let Some(target) = target {
            tokio::select! {
                result = &mut forwarding => result,
                _ = self.cancellation.cancelled() => {
                    direction_cancel.cancel(); native_read_cancel.cancel(); mapping.cancel();
                    let _ = forwarding.await; Err(ConnectError::Canceled)
                },
                reason = target.wait_write_failure() => {
                    direction_cancel.cancel();
                    native_read_cancel.cancel();
                    // Keep the reverse direction alive. The same write/read
                    // future must exit before its slab is returned. Its read
                    // path may still hold the native receive lock that
                    // stop_sending_current needs.
                    let _ = forwarding.await;
                    if let Some(source) = source {
                        let normal = matches!(reason, Some(flowersec_native_transport::NativeDirectionFailure::NormalDrained));
                        let _ = source.stop_sending_current(normal).await;
                    }
                    Ok(())
                }
            }
        } else {
            tokio::select! { result = &mut forwarding => result,
            _ = self.cancellation.cancelled() => {
                direction_cancel.cancel(); native_read_cancel.cancel(); mapping.cancel();
                let _ = forwarding.await; Err(ConnectError::Canceled)
            } }
        };
        if let Err(failure) = result {
            self.fail(failure);
        }
        result
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Each direction borrows the original mapping, native endpoints, queues and distinct cancellation scopes."
    )]
    async fn direction(
        &self,
        mapping: &Mapping,
        role: usize,
        source: Option<&RawQuicStream>,
        target: Option<&RawQuicStream>,
        messages: mpsc::Receiver<Frame>,
        mut first: Option<Frame>,
        provider: &direct_carrier::Provider,
        native_read_cancel: &NativeCancellation,
        direction_cancel: &CancellationToken,
    ) -> ConnectResult<()> {
        let mut messages = DirectionInput {
            mapping,
            role,
            receiver: Some(messages),
        };
        let mut initial = true;
        loop {
            let wire = if let Some(first) = first.take() {
                first
            } else if let Some(stream) = source {
                match self
                    .read(role, stream, native_read_cancel, direction_cancel)
                    .await
                {
                    Ok(ReadFrame::Frame(wire)) => wire,
                    Ok(ReadFrame::Eof) => {
                        if let Some(target) = target {
                            target
                                .close_write_current()
                                .await
                                .map_err(|_| ConnectError::Carrier)?;
                        }
                        return Ok(());
                    }
                    Ok(ReadFrame::Reset(normal)) => {
                        if let Some(target) = target {
                            target
                                .reset_write_current_with_reason(normal)
                                .await
                                .map_err(|_| ConnectError::Carrier)?;
                        }
                        return Ok(());
                    }
                    Err(failure) => return Err(failure),
                }
            } else {
                tokio::select! { _ = direction_cancel.cancelled() => return Err(ConnectError::Canceled),
                _ = self.cancellation.cancelled() => return Err(ConnectError::Canceled),
                wire = messages
                    .receiver
                    .as_mut()
                    .expect("direction input receiver")
                    .recv() => {
                    let wire = wire.ok_or(ConnectError::Carrier)?;
                    mapping.wake[role].notify_one();
                    wire
                } }
            };
            frame(&wire, self.maximum)?;
            if !matches!(wire[4], 7 | 8)
                || scope(&wire)? != mapping.scope
                || wire[4] == 7
                    && (!initial
                        || role != mapping.opener
                        || u32::from_be_bytes(
                            wire[8..12].try_into().map_err(|_| ConnectError::Protocol)?,
                        ) != mapping.epoch)
            {
                return Err(ConnectError::Protocol);
            }
            initial = false;
            if let Some(target) = target {
                self.meters[1 - role]
                    .reserve(wire.len(), direction_cancel)
                    .await?;
                let writing = target.write_all_current(&wire);
                tokio::pin!(writing);
                let outcome = tokio::select! {
                    result = &mut writing => result,
                    _ = tokio::time::sleep(self.timeout) => {
                        self.close(); target.cancel_current(); let _ = writing.await;
                        return Err(ConnectError::Deadline);
                    }
                };
                match outcome {
                    Ok(()) => {}
                    Err(error) => {
                        if let Some(source) = source {
                            let _ = source
                                .stop_sending_current(matches!(error, RawQuicError::NormalDrained))
                                .await;
                        }
                        if matches!(
                            error,
                            RawQuicError::NormalDrained | RawQuicError::DirectionReset
                        ) {
                            return Ok(());
                        }
                        return Err(ConnectError::Carrier);
                    }
                }
            } else {
                // The WSS provider owns a separately prepaid bounded native send
                // copy. Keep this slab until that original send has returned.
                self.publish_shared(1 - role, provider, &wire, direction_cancel)
                    .await?;
            }
        }
    }
    async fn read(
        &self,
        role: usize,
        stream: &RawQuicStream,
        native_read_cancel: &NativeCancellation,
        direction_cancel: &CancellationToken,
    ) -> ConnectResult<ReadFrame> {
        let mut wire = self
            .buffers
            .take(&self.cancellation, direction_cancel)
            .await?;
        let mut desired = 8;
        loop {
            let remaining = desired - wire.len();
            let bytes = match stream
                .read_current(remaining.min(65536), native_read_cancel)
                .await
            {
                Ok(Some(bytes)) => bytes,
                Ok(None) if wire.is_empty() => return Ok(ReadFrame::Eof),
                Ok(None) => return Err(ConnectError::Protocol),
                Err(RawQuicError::NormalDrained) => return Ok(ReadFrame::Reset(true)),
                Err(RawQuicError::DirectionReset) => return Ok(ReadFrame::Reset(false)),
                Err(RawQuicError::Canceled) => return Err(ConnectError::Canceled),
                Err(_) => return Err(ConnectError::Carrier),
            };
            self.meters[role]
                .reserve(bytes.len(), direction_cancel)
                .await?;
            wire.wire.extend_from_slice(&bytes);
            if wire.len() == 8 && desired == 8 {
                desired =
                    u32::from_be_bytes(wire[..4].try_into().map_err(|_| ConnectError::Protocol)?)
                        as usize
                        + 8;
                if desired > self.maximum || desired < 44 || wire[5..8] != [0; 3] {
                    return Err(ConnectError::Protocol);
                }
            }
            if wire.len() == desired {
                return Ok(ReadFrame::Frame(wire));
            }
        }
    }
    async fn datagrams(
        self: Arc<Self>,
        role: usize,
        source: native::Connection,
        target: native::Connection,
    ) {
        loop {
            let wire = match source
                .receive_datagram(self.datagram, &self.native_cancel)
                .await
            {
                Ok(wire) => wire,
                Err(_) => return,
            };
            let result = async {
                self.meters[role]
                    .reserve(wire.len(), &self.cancellation)
                    .await?;
                frame(&wire, self.datagram)?;
                if wire[4] != 10 || wire.len() < 44 {
                    return Err(ConnectError::Protocol);
                }
                self.meters[1 - role]
                    .reserve(wire.len(), &self.cancellation)
                    .await?;
                let submission = target.submit_datagram(wire).ok_or(ConnectError::Carrier)?;
                // Submission already means the original native queue accepted
                // this frame. Completion observes its actual buffer release;
                // it does not assert remote receipt of an unreliable packet.
                submission.completion().await;
                self.datagram_forwarded[role].store(true, Ordering::Release);
                Ok::<_, ConnectError>(())
            }
            .await;
            if let Err(failure) = result {
                self.fail(failure);
                return;
            }
        }
    }
}
fn frame(wire: &[u8], maximum: usize) -> ConnectResult<()> {
    if wire.len() < 8
        || wire.len() > maximum
        || wire[5..8] != [0; 3]
        || u32::from_be_bytes(wire[..4].try_into().map_err(|_| ConnectError::Protocol)?) as usize
            + 8
            != wire.len()
        || !(1..=15).contains(&wire[4])
    {
        return Err(ConnectError::Protocol);
    }
    Ok(())
}
fn scope(wire: &[u8]) -> ConnectResult<u64> {
    if wire.len() < 44 {
        return Err(ConnectError::Protocol);
    }
    let scope = u64::from_be_bytes(
        wire[12..20]
            .try_into()
            .map_err(|_| ConnectError::Protocol)?,
    );
    if scope == 0 {
        return Err(ConnectError::Protocol);
    }
    Ok(scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn visible_scope_tombstone_survives_mapping_slot_retirement() {
        let mut directory = Directory {
            slots: vec![None],
            used: vec![0; 8],
            retired: vec![0; 8],
            used_count: 0,
            seed: RandomState::new(),
        };
        directory.claim_scope(19, 3).unwrap();
        directory.slots[0] = None;
        assert_eq!(directory.claim_scope(19, 3), Err(ConnectError::Protocol));
        directory.claim_scope(21, 3).unwrap();
        directory.claim_scope(23, 3).unwrap();
        assert_eq!(directory.claim_scope(25, 3), Err(ConnectError::Capacity));
        assert_eq!(directory.used_count, 3);
    }
    #[test]
    fn opaque_framing_refuses_hop_reentry_truncation_and_length_mismatch() {
        let mut wire = vec![0; 44];
        wire[..4].copy_from_slice(&36u32.to_be_bytes());
        wire[4] = 8;
        wire[12..20].copy_from_slice(&17u64.to_be_bytes());
        assert!(frame(&wire, 44).is_ok());
        assert_eq!(scope(&wire), Ok(17));
        wire[4] = 16;
        assert_eq!(frame(&wire, 44), Err(ConnectError::Protocol));
        wire[4] = 8;
        wire[5] = 1;
        assert_eq!(frame(&wire, 44), Err(ConnectError::Protocol));
        wire[5] = 0;
        assert_eq!(frame(&wire[..43], 44), Err(ConnectError::Protocol));
        assert_eq!(frame(&wire, 43), Err(ConnectError::Protocol));
        wire[12..20].fill(0);
        assert_eq!(scope(&wire), Err(ConnectError::Protocol));
    }
}

#[cfg(test)]
mod provider_regression_tests {
    use super::*;
    use flowersec_native_transport::{
        Cancellation as NativeCancellation, PathProfile, RawQuicLimits, RawQuicListener,
        RawQuicServerConfig,
    };
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    pub(super) fn test_root() -> Arc<EnvironmentRoot> {
        let mut options = crate::environment_v4::TransportEnvironmentOptions {
            clock: Some(crate::environment_v4::tests::TestClock::new(1_000, 1_010)),
            ..Default::default()
        };
        options.session_limits.sdk_bytes = 16 << 20;
        options.session_limits.provider_bytes = 32 << 20;
        options.session_limits.native_handles = 64;
        EnvironmentRoot::new(options).unwrap()
    }

    pub(super) fn limits() -> TunnelLimits {
        TunnelLimits {
            max_envelope_bytes: 10_354,
            max_total_bytes: 1 << 30,
            max_datagram_bytes: 0,
            max_rate_bytes_per_s: 64 << 20,
            max_queue_bytes: 1 << 20,
            max_pending_native_mappings: 3,
            max_resident_native_mappings: 1,
            max_total_native_mappings: 4,
            max_queue_items: 32,
        }
    }

    fn options() -> WssConnectOptions {
        WssConnectOptions {
            binding_mode: BindingMode::AuthenticatedContext,
            remote_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            origin: None,
            ca_certificates_der: Vec::new(),
            timeout: Duration::from_secs(5),
            publication_timeout: Duration::from_secs(1),
            queue_messages: 4,
            prepare_bytes: 16_384,
            native_runtime_bytes: 1 << 20,
        }
    }

    fn native_options() -> WssConnectOptions {
        WssConnectOptions {
            native_runtime_bytes: 3 << 20,
            ..options()
        }
    }

    pub(super) fn wire(kind: u8, scope: u64, epoch: u32) -> Vec<u8> {
        let mut wire = vec![0; 44];
        wire[..4].copy_from_slice(&36u32.to_be_bytes());
        wire[4] = kind;
        wire[8..12].copy_from_slice(&epoch.to_be_bytes());
        wire[12..20].copy_from_slice(&scope.to_be_bytes());
        wire
    }

    fn server_tls(identity: &serve::WssServerIdentity) -> Arc<rustls::ServerConfig> {
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                identity
                    .certificate_chain_der
                    .iter()
                    .cloned()
                    .map(CertificateDer::from)
                    .collect(),
                PrivatePkcs8KeyDer::from(identity.private_key_der.clone()).into(),
            )
            .map(|mut config| {
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                config
            })
            .unwrap(),
        )
    }

    pub(super) async fn accepted_wss_pair(
        root: Arc<EnvironmentRoot>,
        account: &ResourceAccount,
        limits: TunnelLimits,
    ) -> ConnectResult<(
        direct_carrier::Provider,
        mpsc::Receiver<Vec<u8>>,
        direct_carrier::Provider,
        mpsc::Receiver<Vec<u8>>,
        Arc<wss::Provider>,
        Arc<wss::RelayBudget>,
    )> {
        let (identity, ca, digest) = super::super::tests::tls_provisioning();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| ConnectError::Carrier)?;
        let address = listener.local_addr().map_err(|_| ConnectError::Carrier)?;
        let client_budget = wss::test_relay_budget(account.clone(), limits)?;
        let server_budget = wss::test_relay_budget(account.clone(), limits)?;
        let mut client_policy = wss::Policy::test_policy(
            limits,
            1,
            "example.com".into(),
            address.port(),
            vec![ca.clone()],
            Some(digest),
            client_budget,
        )?;
        let connect_options = options();
        let client_charge = account.reserve(client_policy.preparation_limits(&connect_options)?)?;
        client_policy.fund_prepaid(account, &connect_options, client_charge)?;
        let client = tokio::spawn(wss::Provider::prepare(
            account.clone(),
            client_policy,
            connect_options,
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
        ));
        let (tcp, _) = listener.accept().await.map_err(|_| ConnectError::Carrier)?;
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: 1 << 20,
            provider_bytes: 2 << 20,
            items: 32,
            tasks: 16,
            work_slots: 16,
            timers: 8,
            connections: 1,
            native_handles: 16,
            ..ResourceLimits::default()
        })?;
        let tls_charge = root.reserve_environment(ResourceLimits {
            tls_handshakes: 1,
            ..ResourceLimits::default()
        })?;
        let accept = tokio::spawn(wss::Provider::accept(
            root,
            tcp.into_std().map_err(|_| ConnectError::Carrier)?,
            serve::SocketPolicy {
                relay_unassigned: false,
                relay_budget: Some(server_budget.clone()),
                path_kind: 1,
                binding_mode: BindingMode::AuthenticatedContext,
                tls: server_tls(&identity),
                host: "example.com".into(),
                authority: format!("example.com:{}", address.port()),
                allow_absent_origin: true,
                origins: Vec::new(),
                validity: (0, u64::MAX),
                maximum: limits.max_envelope_bytes as usize,
                publication_timeout: Duration::from_secs(1),
                queue_messages: 4,
                prepare_bytes: 16_384,
            },
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            (charge.into(), tls_charge.into()),
            wss::AcceptHooks {
                retain: |_| {},
                authorize: |_| {
                    Box::pin(async { Ok(serve::RequestAuthorization { allowed: true }) })
                        as wss::RequestAuthorizationFuture
                },
            },
        ));
        let client = match client.await.map_err(|_| ConnectError::Carrier)? {
            Ok(value) => value,
            Err(error) => panic!("WSS client prepare failed: {error:?}"),
        };
        let accepted = match accept.await.map_err(|_| ConnectError::Carrier)? {
            Ok(value) => value,
            Err(error) => panic!("WSS server accept failed: {error:?}"),
        };
        let (client_provider, client_incoming) = client;
        let (server_provider, incoming) = accepted;
        server_provider.activate();
        client_provider.activate();
        Ok((
            direct_carrier::Provider::WebSocket(server_provider.clone()),
            incoming,
            direct_carrier::Provider::WebSocket(client_provider),
            client_incoming,
            server_provider,
            server_budget,
        ))
    }

    async fn read_wire(
        stream: &RawQuicStream,
        cancellation: &NativeCancellation,
    ) -> std::result::Result<Vec<u8>, flowersec_native_transport::RawQuicError> {
        let mut bytes = Vec::new();
        while bytes.len() < 44 {
            let Some(chunk) = stream.read(4096, cancellation).await? else {
                break;
            };
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    pub(super) async fn read_wss_wire(incoming: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(3), incoming.recv())
            .await
            .unwrap()
            .unwrap()
    }

    pub(super) async fn wait_provider_cleanup(provider: &direct_carrier::Provider) {
        provider.close();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if provider.cleanup().complete {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pair_run_uses_real_wss_accept_and_native_stream_retirement() {
        let root = test_root();
        let accounts = [
            root.admit([1; 32], crate::environment_v4::tests::bounds())
                .unwrap(),
            root.admit([2; 32], crate::environment_v4::tests::bounds())
                .unwrap(),
        ];
        let limits = limits();
        let baseline = root.charged();
        let (
            wss_provider,
            mut wss_input,
            wss_client,
            mut wss_client_incoming,
            accepted,
            wss_budget,
        ) = accepted_wss_pair(root.clone(), &accounts[0], limits)
            .await
            .unwrap();

        let (identity, ca, digest) = super::super::tests::tls_provisioning();
        let native_limits = RawQuicLimits::for_session(32, Duration::from_secs(5)).unwrap();
        let native_listener = RawQuicListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            RawQuicServerConfig::new(
                PathProfile::TunnelV4,
                identity.certificate_chain_der.clone(),
                identity.private_key_der.clone(),
                native_limits,
            )
            .unwrap(),
        )
        .unwrap();
        let native_address = native_listener.local_address().unwrap();
        let native_budget = wss::test_relay_budget(accounts[1].clone(), limits).unwrap();
        let mut native_policy = wss::Policy::test_policy(
            limits,
            0,
            "example.com".into(),
            native_address.port(),
            vec![ca],
            Some(digest),
            native_budget.clone(),
        )
        .unwrap();
        let connect_options = native_options();
        let native_charge = accounts[1]
            .reserve(native_policy.preparation_limits(&connect_options).unwrap())
            .unwrap();
        native_policy
            .fund_prepaid(&accounts[1], &connect_options, native_charge)
            .unwrap();
        let native_cancel = NativeCancellation::new();
        let accepted_native = tokio::spawn({
            let native_cancel = native_cancel.clone();
            async move { native_listener.accept(&native_cancel).await }
        });
        let native_prepare = tokio::spawn(native::Provider::prepare(
            accounts[1].clone(),
            native_policy.clone(),
            connect_options,
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
        ));
        let native_session = tokio::time::timeout(Duration::from_secs(3), async {
            accepted_native
                .await
                .unwrap()
                .map_err(|_| ConnectError::Carrier)
        })
        .await
        .unwrap()
        .unwrap();
        let (native_provider, mut native_input) = native_prepare.await.unwrap().unwrap();
        let native_provider_raw_handle = native_provider.clone();
        let native_provider = direct_carrier::Provider::Native(native_provider);
        native_provider.activate();
        // Prepare opens one dedicated native maintenance stream before Pair
        // accepts application siblings. Consume it with a real maintenance
        // frame so the later accept_stream is unambiguously the Pair sibling.
        let maintenance_accept = {
            let session = native_session.clone();
            let cancellation = native_cancel.clone();
            tokio::spawn(async move { session.accept_stream(&cancellation).await })
        };
        native_provider.send(wire(6, 0, 1)).await.unwrap();
        let maintenance_stream = tokio::time::timeout(Duration::from_secs(3), maintenance_accept)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let maintenance_probe = read_wire(&maintenance_stream, &NativeCancellation::new())
            .await
            .unwrap();
        assert_eq!(maintenance_probe[4], 6);
        // Prove the accepted WSS provider and its client incoming receiver are
        // live before Pair starts publishing shared frames.
        accepted.send(wire(6, 0, 1)).await.unwrap();
        let direct_probe = read_wss_wire(&mut wss_client_incoming).await;
        assert_eq!(direct_probe[4], 6);
        let wss_provider_handle = wss_provider.clone();
        let wss_client_handle = wss_client.clone();
        let native_provider_handle = native_provider.clone();

        let policies = [
            wss::Policy::test_policy(
                limits,
                1,
                "example.com".into(),
                1,
                Vec::new(),
                None,
                wss_budget.clone(),
            )
            .unwrap(),
            native_policy,
        ];
        let pair = Pair::new(
            &accounts,
            [limits; 2],
            &policies,
            Duration::from_secs(3),
            [4, 4],
        )
        .unwrap()
        .unwrap();
        let pair_runner = tokio::spawn({
            let pair = pair.clone();
            async move {
                pair.run(
                    &mut wss_input,
                    &mut native_input,
                    [wss_provider, native_provider],
                    || Ok(()),
                )
                .await
            }
        });

        let native_stream = native_session.open_stream(&native_cancel).await.unwrap();
        let wss_meter_start = wss_budget.test_reserved_bytes();
        native_stream
            .write_all_current(&wire(7, 0x51, 1))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if pair
                    .directory
                    .lock()
                    .unwrap()
                    .slots
                    .iter()
                    .flatten()
                    .any(|mapping| mapping.scope == 0x51 && !mapping.done.load(Ordering::Acquire))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let initial_slot = {
            let directory = pair.directory.lock().unwrap();
            let (index, mapping) = directory
                .slots
                .iter()
                .enumerate()
                .find_map(|(index, mapping)| {
                    mapping
                        .as_ref()
                        .filter(|mapping| mapping.scope == 0x51)
                        .map(|mapping| (index, Arc::clone(mapping)))
                })
                .unwrap();
            assert_eq!(mapping.epoch, 1);
            (index, mapping)
        };
        let (initial_slot, initial_mapping) = initial_slot;
        let read_cancel = NativeCancellation::new();
        let initial_wss_open = read_wss_wire(&mut wss_client_incoming).await;
        assert_eq!(initial_wss_open[4], 7);
        assert!(
            initial_wss_open
                .windows(8)
                .any(|window| window == 0x51u64.to_be_bytes())
        );
        // Consume the publication notification for the initial OPEN before
        // registering the notification used by the buffered-tail gate.
        tokio::time::timeout(
            Duration::from_secs(3),
            pair.publication_waiting[0].notified(),
        )
        .await
        .unwrap();
        wss_client.send(wire(8, 0x51, 1)).await.unwrap();
        let observed_data = read_wire(&native_stream, &read_cancel).await.unwrap();
        assert_eq!(observed_data[4], 8);
        assert!(
            observed_data
                .windows(8)
                .any(|window| window == 0x51u64.to_be_bytes())
        );

        // Exercise malformed routing against the live pair while both real
        // providers remain active. An unknown DATA scope is a protocol error,
        // and a second OPEN for an admitted scope must not create a mapping or
        // advance its generation.
        let negative_providers = [wss_provider_handle.clone(), native_provider_handle.clone()];
        let negative_connections = [
            None,
            Some(native_provider_raw_handle.relay_connection().unwrap()),
        ];
        let unknown_scope = PendingWire {
            role: 0,
            wire: wire(8, 0xdead, 1),
            mapping: None,
            open: false,
            buffer_wake: pair.buffers.wake(0),
        };
        assert!(matches!(
            pair.lane(unknown_scope, &negative_providers, &negative_connections)
                .await,
            Err(ConnectError::Protocol)
        ));
        let duplicate_open = PendingWire {
            role: 0,
            wire: wire(7, 0x51, 1),
            mapping: Some(initial_mapping.clone()),
            open: true,
            buffer_wake: pair.buffers.wake(0),
        };
        assert!(matches!(
            pair.lane(duplicate_open, &negative_providers, &negative_connections)
                .await,
            Err(ConnectError::Protocol)
        ));
        drop(negative_connections);
        drop(negative_providers);
        drop(native_provider_raw_handle);

        // Hold the WSS publication position and wait until Pair has received
        // a real native maintenance frame and is blocked on that position.
        // This freezes Pair's WSS input read while the provider still accepts
        // incoming DATA into its own bounded queue.
        let publication_gate = pair.shared_writes[0].lock().await;
        let publication_waiting = pair.publication_waiting[0].notified();
        maintenance_stream
            .write_all_current(&wire(6, 0, 1))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), publication_waiting)
            .await
            .unwrap();

        let late_count = 3u64;
        let late_meter_before = wss_budget.test_reserved_bytes();
        for _ in 0..late_count {
            wss_client.send(wire(8, 0x51, 1)).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let observed = wss_budget.test_reserved_bytes();
                if observed - late_meter_before == late_count * 44 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            wss_budget.test_reserved_bytes() - late_meter_before,
            late_count * 44
        );

        // Retire the native direction while all three late DATA frames remain
        // buffered behind the publication gate. Their native stream is closed
        // before Pair is allowed to consume the provider input queue.
        native_stream.close_write_current().await.unwrap();
        native_stream.stop_sending().await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if pair
                    .directory
                    .lock()
                    .unwrap()
                    .slots
                    .iter()
                    .flatten()
                    .any(|mapping| mapping.scope == 0x51 && mapping.done.load(Ordering::Acquire))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        drop(publication_gate);

        // The maintenance frame that blocked the gate is now forwarded through
        // the real WSS provider, proving the gate was on Pair publication.
        let maintenance_forwarded = read_wss_wire(&mut wss_client_incoming).await;
        assert_eq!(maintenance_forwarded[4], 6);
        assert_eq!(maintenance_forwarded[12..20], [0; 8]);

        // Reuse the exact physical directory slot with a new mapping Arc. The
        // native maintenance stream was consumed above, so this accept is the
        // actual sibling opened by Pair::create.
        let sibling_accept = {
            let session = native_session.clone();
            let cancellation = native_cancel.clone();
            tokio::spawn(async move { session.accept_stream(&cancellation).await })
        };
        wss_client.send(wire(7, 0x52, 1)).await.unwrap();
        let sibling = tokio::time::timeout(Duration::from_secs(3), sibling_accept)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let sibling_open = read_wire(&sibling, &read_cancel).await.unwrap();
        assert_eq!(sibling_open[4], 7);
        assert!(
            sibling_open
                .windows(8)
                .any(|window| window == 0x52u64.to_be_bytes())
        );
        wss_client.send(wire(8, 0x52, 1)).await.unwrap();
        let sibling_data = read_wire(&sibling, &read_cancel).await.unwrap();
        assert_eq!(sibling_data[4], 8);
        assert!(
            sibling_data
                .windows(8)
                .any(|window| window == 0x52u64.to_be_bytes())
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if pair
                    .directory
                    .lock()
                    .unwrap()
                    .slots
                    .iter()
                    .flatten()
                    .any(|mapping| mapping.scope == 0x52 && !mapping.done.load(Ordering::Acquire))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        {
            let directory = pair.directory.lock().unwrap();
            let second = directory
                .slots
                .iter()
                .enumerate()
                .find_map(|(index, mapping)| {
                    mapping
                        .as_ref()
                        .filter(|mapping| mapping.scope == 0x52)
                        .map(|mapping| {
                            (
                                index,
                                Arc::clone(mapping),
                                mapping.epoch,
                                mapping.done.load(Ordering::Acquire),
                            )
                        })
                })
                .unwrap();
            assert_eq!(second.0, initial_slot);
            assert_eq!(second.2, 1);
            assert!(!second.3);
            assert!(!Arc::ptr_eq(&initial_mapping, &second.1));
            assert!(directory.is_retired(0x51, 0));
        }

        // After the retired slot has been replaced, send maintenance from the
        // WSS client through Pair and observe the real native maintenance
        // stream. This proves the reverse direction remains live after
        // retirement and physical slot reuse.
        let reverse_maintenance = wire(6, 0, 1);
        wss_client.send(reverse_maintenance.clone()).await.unwrap();
        let reverse_forwarded = read_wire(&maintenance_stream, &read_cancel).await.unwrap();
        assert_eq!(reverse_forwarded, reverse_maintenance);
        assert_eq!(wss_budget.test_reserved_bytes() - wss_meter_start, 9 * 44);

        let forward_maintenance = wire(9, 0, 1);
        maintenance_stream
            .write_all_current(&forward_maintenance)
            .await
            .unwrap();
        assert_eq!(
            read_wss_wire(&mut wss_client_incoming).await,
            forward_maintenance
        );
        // Both meters are the original budgets installed on the real
        // providers and Pair. Counts include probes, OPEN/DATA forwarding,
        // all three discarded late DATA frames, and maintenance in both
        // directions after the physical directory slot has been reused.
        assert_eq!(wss_budget.test_reserved_bytes(), 11 * 44);
        assert_eq!(native_budget.test_reserved_bytes(), 8 * 44);

        pair.close();
        let runner_result = tokio::time::timeout(Duration::from_secs(3), pair_runner)
            .await
            .unwrap()
            .unwrap();
        assert!(runner_result.is_err());
        let (retired, live_replacement) =
            {
                let directory = pair.directory.lock().unwrap();
                (
                    directory.is_retired(0x51, 0),
                    directory.slots.iter().flatten().any(|mapping| {
                        mapping.scope == 0x52 && !mapping.done.load(Ordering::Acquire)
                    }),
                )
            };
        assert!(retired);
        assert!(live_replacement);
        pair.wait_cleanup().await;
        drop(pair);
        drop(accepted);
        drop(policies);
        drop(sibling);
        drop(maintenance_stream);
        drop(native_stream);
        drop(native_session);
        drop(wss_client_incoming);
        wait_provider_cleanup(&wss_provider_handle).await;
        wait_provider_cleanup(&wss_client_handle).await;
        wait_provider_cleanup(&native_provider_handle).await;
        drop(wss_provider_handle);
        drop(wss_client_handle);
        drop(native_provider_handle);
        drop(wss_client);
        drop(initial_mapping);
        drop(wss_budget);
        drop(native_budget);
        assert_eq!(root.charged(), baseline);
        drop(accounts);
    }
}

#[cfg(test)]
#[path = "native_relay_publication_tests.rs"]
mod publication_regression_tests;
