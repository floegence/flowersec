//! The private reliable Session owner. Every transition comes from this owner’s
//! actual record ticket, authenticated input, or synchronous application read.
//! Stream handles carry only an original owner identity, never terminal proof.
use super::*;
use crate::crypto_v4::{Context, Value, codec, decode};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::time::Instant;

#[path = "crypto_v4_controls.rs"]
mod controls;
pub(crate) use controls::ProbePublication;
pub use controls::{DrainOutcome, DrainResult, ProbeOutcome, ProbeResult};

#[path = "session_v4.rs"]
mod session;
pub use session::{
    DrainOperation, Metadata, OpenRequest, RawStreamMetadataContract, RawStreamMetadataField,
    RawStreamMetadataType, Session, Stream, UnreliableMessages,
};
#[cfg(test)]
pub(crate) use session::{
    MaintenanceReceiveProbe, TerminalPublicationProbe, install_maintenance_receive_probe,
    install_terminal_publication_probe,
};
pub(crate) use session::{
    NativeStreamBinding, ResumeMessageClaim, SessionLink, SessionReceiver, SessionTransport,
    StreamPreparation, StreamPublicationAdmission,
};

const VIEW_BYTES: u64 =
    (std::mem::size_of::<StreamView>() + std::mem::size_of::<std::sync::Mutex<()>>() + 64) as u64;
const USED_BYTES: usize = 524_292;
const REJECT_RESERVED: usize = 128;
const INGRESS: usize = 128;
const BATCH: usize = 1024;
const RPC: &str = "flowersec.rpc.v4";
const NOTIFY: &str = "flowersec.notify.v4";
const MANAGEMENT: &str = "flowersec.execution-management.v4";
pub(crate) struct StreamView {
    _charge: Arc<ResourceCharge>,
    management: bool,
    end: AtomicU8,
    fin_submitted: AtomicBool,
    native_bound: AtomicBool,
    rejected: AtomicBool,
    normal_drained: AtomicBool,
    native_send_end: AtomicU8,
    native_receive_end: AtomicU8,
    send_end: AtomicU8,
    accepted: AtomicU64,
    authenticated: AtomicU64,
    authentication_waiters: AtomicUsize,
    receive_owner: Arc<std::sync::Mutex<()>>,
    pub(super) receive_disabled: AtomicBool,
    pub(super) send_aborted: AtomicBool,
}
#[derive(Clone)]
pub(crate) struct StreamHandle {
    owner: [u8; 16],
    scope: u64,
    view: Arc<StreamView>,
}
impl std::fmt::Debug for StreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamHandle")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
impl StreamHandle {
    pub(crate) fn is_management(&self) -> bool {
        self.view.management
    }
    pub(crate) fn scope(&self) -> u64 {
        self.scope
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenDecision {
    Accept { receive_window: u64 },
    Reject(Rejection),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Rejection {
    Resource = 1,
    Metadata = 2,
    Kind = 3,
    Application = 4,
    Draining = 5,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadState {
    Data(usize),
    Pending,
    Eof,
    Aborted,
}
/// A shared reader may continue only on a disposition produced by the original
/// receive owner. A failed tag or header never manufactures local attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiveDisposition {
    Applied,
    Isolated { scope: u64 },
    Discarded { scope: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamPhase {
    Opening,
    Pending,
    Accepted,
    Recent,
    Stable,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Tuple {
    pub(super) epoch: u32,
    pub(super) next: u64,
    pub(super) offset: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DrainProof {
    terminal: Tuple,
    observed: Tuple,
    aborted: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Opening,
    Pending,
    Accepted,
    Recent,
    Held,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    Business,
    Rpc,
    Notify,
    Management,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Token {
    None,
    Positive,
    Rejection,
}
#[derive(Clone, Copy)]
struct Direction {
    current: Tuple,
    last: Tuple,
    initial_epoch: u32,
    terminal: Option<Tuple>,
    proof: Option<DrainProof>,
    limit: u64,
    committed_limit: u64,
    ack: u64,
    released: u64,
    stop: bool,
    stop_sent: bool,
    stopped_sent: bool,
    stopped_requested: bool,
    drain_sent: bool,
    fin: bool,
    fin_requested: bool,
    disabled: bool,
    deadline: Option<Instant>,
    normal_deadline: Option<Instant>,
    quarantined: bool,
    first_error: Option<CryptoError>,
}
impl Direction {
    fn new(epoch: u32, limit: u64) -> Self {
        Self {
            current: Tuple {
                epoch,
                ..Tuple::default()
            },
            last: Tuple {
                epoch,
                ..Tuple::default()
            },
            initial_epoch: epoch,
            terminal: None,
            proof: None,
            limit,
            committed_limit: limit,
            ack: 0,
            released: 0,
            stop: false,
            stop_sent: false,
            stopped_sent: false,
            stopped_requested: false,
            drain_sent: false,
            fin: false,
            fin_requested: false,
            disabled: false,
            deadline: None,
            normal_deadline: None,
            quarantined: false,
            first_error: None,
        }
    }
    fn in_epoch(&self, epoch: u32) -> Result<Tuple> {
        if epoch == self.current.epoch {
            return Ok(self.current);
        }
        if epoch == self.last.epoch {
            return Ok(self.last);
        }
        if epoch >= self.initial_epoch && epoch > self.last.epoch && epoch < self.current.epoch {
            return Ok(Tuple {
                epoch,
                next: 0,
                offset: self.last.offset,
            });
        }
        Err(CryptoError::Authentication)
    }
    fn begin(&mut self, now: Instant, aborted: bool) -> Result<()> {
        let cap = now
            .checked_add(Duration::from_secs(if aborted { 10 } else { 15 }))
            .ok_or(CryptoError::Deadline)?;
        self.deadline = Some(self.deadline.map_or(cap, |old| old.min(cap)));
        if aborted {
            self.quarantined = true;
            self.normal_deadline = None;
        } else if !self.quarantined && self.normal_deadline.is_none() {
            self.normal_deadline = Some(now + Duration::from_secs(5));
        }
        Ok(())
    }
    fn complete(&self) -> bool {
        self.proof.is_some()
    }
}
struct SlotSeed<'a> {
    scope: u64,
    opener: u8,
    kind: &'a str,
    metadata: &'a [u8],
    local_window: u64,
    peer_window: u64,
    epoch: u32,
    token: Token,
    bootstrap: bool,
}
struct Slot {
    scope: u64,
    view: Arc<StreamView>,
    opener: u8,
    class: Class,
    kind: String,
    metadata: Vec<u8>,
    phase: Phase,
    token: Token,
    open_epoch: u32,
    open_digest: [u8; 32],
    open_digest_ready: bool,
    bootstrap: bool,
    prefix: bool,
    cancel: bool,
    directions: [Direction; 2],
    queue: VecDeque<u8>,
    capacity: usize,
    opening_deadline: Option<Instant>,
    barrier_refs: u8,
    unpublished: u8,
    batch_refs: u8,
    credit_dirty: bool,
    recent_at: Option<Instant>,
    forced_rejection: Option<Rejection>,
    outcome: Option<OpenDecision>,
    claimed: bool,
    receive_progress: Option<Instant>,
    send_progress: Option<Instant>,
}
impl Slot {
    fn active(&self) -> bool {
        matches!(self.phase, Phase::Opening | Phase::Accepted)
    }
    fn known(&self) -> bool {
        self.phase != Phase::Held
    }
    fn accepted(&self) -> bool {
        self.bootstrap || matches!(self.outcome, Some(OpenDecision::Accept { .. }))
    }
}
struct BatchState {
    sequence: u64,
    digest: [u8; 32],
    digest_ready: bool,
    ids: Vec<u64>,
    deadline: Instant,
    submitted: bool,
}
/// One pre-admitted shared ingress allowance, retained for the Session's full
/// lifetime. Neither a scope's retirement nor an epoch change renews it.
#[derive(Default)]
struct SharedDiscard {
    records: u64,
    bytes: u64,
    deadline: Option<Instant>,
}
impl SharedDiscard {
    fn reject(&mut self, now: Instant, bytes: usize) -> Result<()> {
        let deadline = match self.deadline {
            Some(deadline) => deadline,
            None => {
                let deadline = now
                    .checked_add(Duration::from_secs(10))
                    .ok_or(CryptoError::Deadline)?;
                self.deadline = Some(deadline);
                deadline
            }
        };
        if now >= deadline {
            return Err(CryptoError::Deadline);
        }
        let bytes = u64::try_from(bytes).map_err(|_| CryptoError::Capacity)?;
        if self.records >= 16 || bytes > 65_536 - self.bytes {
            return Err(CryptoError::Capacity);
        }
        self.records += 1;
        self.bytes += bytes;
        Ok(())
    }
}
pub(super) struct State {
    pub(super) controls: controls::State,
    _charge: ResourceCharge,
    bootstrap_view_charge: Option<ResourceCharge>,
    management_view_charge: Option<Arc<ResourceCharge>>,
    maintenance_publication: Option<ResourceCharge>,
    account: ResourceAccount,
    owner: [u8; 16],
    role: u8,
    profile: u8,
    max_active: usize,
    max_credit: u64,
    used: Vec<u8>,
    // ID consumption alone is not authenticated input/retirement evidence.
    // This fixed bitmap records only completed original retirement proofs.
    authenticated_stable: Vec<u8>,
    slots: Vec<Slot>,
    max_slots: usize,
    max_tokens: usize,
    next_ordinal: u64,
    lifetime: [[u64; 3]; 2],
    positive_tokens: usize,
    reject_tokens: usize,
    promised: u64,
    backing: usize,
    ingress_bytes: usize,
    closed: bool,
    draining: bool,
    output: Vec<u8>,
    input_pool: Arc<ReceivePool>,
    shared_discard: SharedDiscard,
    body: Vec<u8>,
    outgoing: Option<BatchState>,
    incoming: Option<BatchState>,
    last_out: u64,
    last_out_digest: [u8; 32],
    last_in: u64,
    last_in_digest: [u8; 32],
    repeat_ack: bool,
}
impl State {
    fn maintenance_publication_limits(shape: &super::super::RecordShape) -> Result<ResourceLimits> {
        let tails = shape
            .max_streams
            .checked_add(1)
            .ok_or(CryptoError::Capacity)?;
        let metadata = std::mem::size_of::<crate::crypto_v4::DeferredPublication>()
            + std::mem::size_of::<Vec<u8>>()
            + std::mem::size_of::<RecordWork>()
            + std::mem::size_of::<RecordPublication>()
            + std::mem::size_of::<CryptoTail>()
            + std::mem::size_of::<ResourceCharge>();
        let bytes = tails
            .checked_mul(metadata)
            // Every maintenance quantum fits the protocol's 64 KiB normal
            // lane; application max_frame belongs to the input/output owners.
            .and_then(|bytes| bytes.checked_add(shape.max_frame.min(65_536)))
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or(CryptoError::Capacity)?;
        Ok(ResourceLimits {
            sdk_bytes: bytes as u64,
            items: tails as u64,
            ..ResourceLimits::default()
        })
    }
    pub(super) fn preparation_limits(
        shape: &super::super::RecordShape,
        automatic: bool,
    ) -> Result<ResourceLimits> {
        if shape.max_streams > 1035 || shape.max_frame > 1_048_576 || shape.max_credit > 8 << 20 {
            return Err(CryptoError::Capacity);
        }
        let max_tokens = (2 * shape.max_streams + REJECT_RESERVED).min(4096);
        let max_slots = max_tokens + INGRESS;
        let bytes = std::mem::size_of::<State>()
            + 2 * USED_BYTES
            + max_slots * std::mem::size_of::<Slot>()
            + max_tokens * 2048
            + INGRESS * 4096
            + 2 * (2048 + 64 * BATCH)
            + 2 * (shape.max_frame + 8)
            + 2 * shape.max_credit as usize;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            ResourceLimits {
                sdk_bytes: bytes as u64,
                items: (max_slots + max_tokens + INGRESS + 5) as u64,
                timers: (max_slots * 5 + 4) as u64,
                // The three input jobs transfer existing scratch-work slots.
                work_slots: 7,
                tasks: 1,
                ..ResourceLimits::default()
            },
            controls::State::preparation_limits(automatic),
        )?;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            Self::maintenance_publication_limits(shape)?,
        )?;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            ReceivePool::limits(shape.max_frame),
        )?;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            if shape.application_profile != 0 {
                ResourceLimits {
                    sdk_bytes: VIEW_BYTES,
                    items: 1,
                    ..ResourceLimits::default()
                }
            } else {
                ResourceLimits::default()
            },
        )?;
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            limits,
            if shape.application_profile == 2 {
                // Every actual M ordinal may retain its original view until
                // proof and physical cleanup finish; lifetime is capped at 16.
                ResourceLimits {
                    sdk_bytes: 16 * VIEW_BYTES,
                    items: 16,
                    ..ResourceLimits::default()
                }
            } else {
                ResourceLimits::default()
            },
        )?)
    }
    pub(super) fn prepare_prepaid(
        account: ResourceAccount,
        shape: &super::super::RecordShape,
        role: super::super::Role,
        mut charge: ResourceCharge,
    ) -> Result<Self> {
        let automatic = account.automatic_liveness().is_some();
        if !charge.matches(&account, Self::preparation_limits(shape, automatic)?) {
            return Err(CryptoError::Configuration);
        }
        let maintenance_publication =
            Some(charge.split(Self::maintenance_publication_limits(shape)?)?);
        let input_pool = ReceivePool::new(
            shape.max_frame,
            charge.split(ReceivePool::limits(shape.max_frame))?,
        )?;
        let control_charge = if automatic {
            Some(charge.split(controls::State::preparation_limits(true))?)
        } else {
            None
        };
        let bootstrap_view_charge = if shape.application_profile != 0 {
            Some(charge.split(ResourceLimits {
                sdk_bytes: VIEW_BYTES,
                items: 1,
                ..ResourceLimits::default()
            })?)
        } else {
            None
        };
        let management_view_charge = if shape.application_profile == 2 {
            Some(Arc::new(charge.split(ResourceLimits {
                sdk_bytes: 16 * VIEW_BYTES,
                items: 16,
                ..ResourceLimits::default()
            })?))
        } else {
            None
        };
        let max_tokens = (2 * shape.max_streams + REJECT_RESERVED).min(4096);
        let max_slots = max_tokens + INGRESS;
        let max_credit = shape.max_credit;
        if max_credit > 8 << 20 {
            return Err(CryptoError::Capacity);
        }
        if shape.application_profile > 2 || (shape.application_profile != 0 && max_credit < 16_384)
        {
            return Err(CryptoError::Configuration);
        }
        let mut used = Vec::new();
        used.try_reserve_exact(USED_BYTES)
            .map_err(|_| CryptoError::Capacity)?;
        used.resize(USED_BYTES, 0);
        let mut authenticated_stable = Vec::new();
        authenticated_stable
            .try_reserve_exact(USED_BYTES)
            .map_err(|_| CryptoError::Capacity)?;
        authenticated_stable.resize(USED_BYTES, 0);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(max_slots)
            .map_err(|_| CryptoError::Capacity)?;
        let buffer = |cap: usize| -> Result<Vec<u8>> {
            let mut out = Vec::new();
            out.try_reserve_exact(cap)
                .map_err(|_| CryptoError::Capacity)?;
            out.resize(cap, 0);
            Ok(out)
        };
        let mut owner = [0; 16];
        SystemRandom::new()
            .fill(&mut owner)
            .map_err(|_| CryptoError::Key)?;
        let mut state = Self {
            controls: controls::State::new_prepaid(
                shape.idle_duration_ms,
                &account,
                control_charge,
            )?,
            _charge: charge,
            bootstrap_view_charge,
            management_view_charge,
            maintenance_publication,
            account,
            owner,
            role: role.index() as u8,
            profile: shape.application_profile,
            max_active: shape.max_streams,
            max_credit,
            used,
            authenticated_stable,
            slots,
            max_slots,
            max_tokens,
            next_ordinal: 1,
            lifetime: [[0; 3]; 2],
            positive_tokens: 0,
            reject_tokens: 0,
            promised: 0,
            backing: 0,
            ingress_bytes: 0,
            closed: false,
            draining: false,
            output: buffer(shape.max_frame + 8)?,
            input_pool,
            shared_discard: SharedDiscard::default(),
            body: Vec::new(),
            outgoing: None,
            incoming: None,
            last_out: 0,
            last_out_digest: [0; 32],
            last_in: 0,
            last_in_digest: [0; 32],
            repeat_ack: false,
        };
        if shape.application_profile != 0 {
            let token = state.take_token(false)?;
            let mut slot = state.slot(SlotSeed {
                scope: 1,
                opener: 0,
                kind: RPC,
                metadata: &[],
                local_window: 16_384,
                peer_window: 16_384,
                epoch: 0,
                token,
                bootstrap: true,
            })?;
            slot.phase = Phase::Accepted;
            slot.opening_deadline = None;
            state.set_used(1)?;
            state.lifetime[0][1] = 1;
            state.controls.highest_accepted[0] = 1;
            if state.role == 0 {
                state.next_ordinal = 2;
            }
            state.slots.push(slot);
        }
        Ok(state)
    }
    fn valid(scope: u64) -> bool {
        scope > 0
            && scope <= 4_194_335
            && if scope & 1 == 1 {
                scope.div_ceil(2) <= 2_097_168
            } else {
                scope / 2 <= 2_097_152
            }
    }
    fn opener(scope: u64) -> u8 {
        ((scope + 1) % 2) as u8
    }
    fn bit(scope: u64) -> Result<(usize, u8)> {
        if !Self::valid(scope) {
            return Err(CryptoError::Authentication);
        }
        let i = usize::try_from(scope - 1).map_err(|_| CryptoError::Capacity)?;
        Ok((i / 8, 1 << (i % 8)))
    }
    fn used(&self, scope: u64) -> Result<bool> {
        let (i, b) = Self::bit(scope)?;
        Ok(self.used[i] & b != 0)
    }
    fn set_used(&mut self, scope: u64) -> Result<()> {
        let (i, b) = Self::bit(scope)?;
        self.used[i] |= b;
        Ok(())
    }
    fn authenticated_stable(&self, scope: u64) -> Result<bool> {
        let (i, b) = Self::bit(scope)?;
        Ok(self.authenticated_stable[i] & b != 0)
    }
    fn index(&self, scope: u64) -> Option<usize> {
        self.slots.iter().position(|s| s.scope == scope)
    }
    fn class(&self, kind: &str, opener: u8) -> Result<Class> {
        if kind.is_empty() || kind.len() > 128 {
            return Err(CryptoError::Configuration);
        }
        match kind {
            RPC if self.profile != 0 => Ok(Class::Rpc),
            NOTIFY if self.profile != 0 => Ok(Class::Notify),
            MANAGEMENT if self.profile == 2 && opener == 0 => Ok(Class::Management),
            _ if kind.starts_with("flowersec.") || kind.starts_with("flowersec/") => {
                Err(CryptoError::Configuration)
            }
            _ => Ok(Class::Business),
        }
    }
    fn class_index(class: Class) -> usize {
        match class {
            Class::Business => 0,
            Class::Rpc | Class::Notify => 1,
            Class::Management => 2,
        }
    }
    fn check_lifetime(&self, opener: u8, class: Class) -> Result<()> {
        let c = Self::class_index(class);
        let max = if c == 2 { 16 } else { 1 << 20 };
        if self.lifetime[usize::from(opener)][c] >= max {
            return Err(CryptoError::Capacity);
        }
        Ok(())
    }
    fn count_lifetime(&mut self, opener: u8, class: Class) -> Result<()> {
        self.check_lifetime(opener, class)?;
        self.lifetime[usize::from(opener)][Self::class_index(class)] += 1;
        Ok(())
    }
    fn rpc_lane(metadata: &[u8]) -> Option<u8> {
        if metadata.is_empty() {
            return Some(0);
        }
        let metadata = Metadata::from_encoded(metadata).ok()?;
        if metadata.namespace() != Some("sdk.flowersec/rpc") || metadata.version() != Some(1) {
            return None;
        }
        let fields = metadata.byte_values();
        if fields.len() != 1 {
            return None;
        }
        match fields.get("class")?.as_ref() {
            b"interactive" => Some(0),
            b"bulk" => Some(1),
            _ => None,
        }
    }
    fn active_room(&self, class: Class, opener: u8, metadata: &[u8]) -> bool {
        let active = self.slots.iter().filter(|s| s.active()).count();
        if active >= self.max_active {
            return false;
        }
        if class == Class::Business {
            // Business admissions leave room for all future original I10/M1
            // channels, including physically unfinished old channel tails.
            let internal_floor = if self.profile == 0 {
                0
            } else {
                10 + usize::from(self.profile == 2)
            };
            return self
                .slots
                .iter()
                .filter(|s| s.active() && s.class == Class::Business)
                .count()
                < 1024.min(self.max_active.saturating_sub(internal_floor));
        }
        let cap = if class == Class::Rpc { 4 } else { 1 };
        let used = self
            .slots
            .iter()
            .filter(|s| s.active() && s.class == class && s.opener == opener)
            .count();
        if used >= cap {
            return false;
        }
        if class == Class::Rpc {
            let Some(lane) = Self::rpc_lane(metadata) else {
                return false;
            };
            return self
                .slots
                .iter()
                .filter(|s| {
                    s.active()
                        && s.class == class
                        && s.opener == opener
                        && Self::rpc_lane(&s.metadata) == Some(lane)
                })
                .count()
                < 2;
        }
        true
    }
    fn take_token(&mut self, rejected: bool) -> Result<Token> {
        if rejected && self.reject_tokens < REJECT_RESERVED {
            self.reject_tokens += 1;
            return Ok(Token::Rejection);
        }
        if self.positive_tokens >= self.max_tokens - REJECT_RESERVED {
            return Err(CryptoError::Capacity);
        }
        self.positive_tokens += 1;
        Ok(Token::Positive)
    }
    fn return_token(&mut self, token: Token) {
        match token {
            Token::Positive => self.positive_tokens -= 1,
            Token::Rejection => self.reject_tokens -= 1,
            Token::None => {}
        }
    }
    fn future_internal_credit(&self) -> u64 {
        if self.profile == 0 {
            return 0;
        }
        let total = 10 + usize::from(self.profile == 2);
        let existing = self
            .slots
            .iter()
            .filter(|slot| slot.active() && slot.class != Class::Business)
            .count();
        total.saturating_sub(existing) as u64 * 16384
    }
    fn credit_room(&self, class: Class, delta: u64, initial: bool) -> bool {
        let mut protected = self.future_internal_credit();
        if class != Class::Business && initial {
            protected = protected.saturating_sub(16384);
        }
        delta
            <= self
                .max_credit
                .saturating_sub(self.promised)
                .saturating_sub(protected)
    }
    fn reserve_window(&mut self, window: u64) -> Result<VecDeque<u8>> {
        let size = usize::try_from(window).map_err(|_| CryptoError::Capacity)?;
        if window > self.max_credit - self.promised
            || size > self.max_credit as usize - self.backing
        {
            return Err(CryptoError::Capacity);
        }
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(size)
            .map_err(|_| CryptoError::Capacity)?;
        let physical = queue.capacity();
        if physical > self.max_credit as usize - self.backing {
            return Err(CryptoError::Capacity);
        }
        self.promised += window;
        self.backing += physical;
        Ok(queue)
    }
    fn slot(&mut self, seed: SlotSeed<'_>) -> Result<Slot> {
        let SlotSeed {
            scope,
            opener,
            kind,
            metadata,
            local_window,
            peer_window,
            epoch,
            token,
            bootstrap,
        } = seed;
        if self.slots.len() >= self.max_slots || metadata.len() > 4096 {
            return Err(CryptoError::Capacity);
        }
        let class = self.class(kind, opener).unwrap_or(Class::Business);
        let view_charge = if bootstrap {
            Arc::new(
                self.bootstrap_view_charge
                    .take()
                    .ok_or(CryptoError::Configuration)?,
            )
        } else if class == Class::Management {
            self.management_view_charge
                .as_ref()
                .ok_or(CryptoError::Configuration)?
                .clone()
        } else {
            Arc::new(self.account.reserve(ResourceLimits {
                sdk_bytes: VIEW_BYTES,
                items: 1,
                ..ResourceLimits::default()
            })?)
        };
        let view = Arc::new(StreamView {
            _charge: view_charge,
            management: class == Class::Management,
            end: AtomicU8::new(0),
            fin_submitted: AtomicBool::new(false),
            native_bound: AtomicBool::new(false),
            rejected: AtomicBool::new(false),
            normal_drained: AtomicBool::new(false),
            native_send_end: AtomicU8::new(0),
            native_receive_end: AtomicU8::new(0),
            send_end: AtomicU8::new(0),
            accepted: AtomicU64::new(0),
            authenticated: AtomicU64::new(0),
            authentication_waiters: AtomicUsize::new(0),
            receive_owner: Arc::new(std::sync::Mutex::new(())),
            receive_disabled: AtomicBool::new(false),
            send_aborted: AtomicBool::new(false),
        });
        if !bootstrap && !self.credit_room(class, local_window, true) {
            return Err(CryptoError::Capacity);
        }
        let queue = self.reserve_window(local_window)?;
        let physical = queue.capacity();
        let mut directions = [Direction::new(epoch, 0); 2];
        directions[usize::from(self.role)].limit = peer_window;
        directions[usize::from(self.role)].committed_limit = peer_window;
        directions[usize::from(1 - self.role)].limit = local_window;
        directions[usize::from(1 - self.role)].committed_limit = local_window;
        Ok(Slot {
            scope,
            view,
            opener,
            class,
            kind: kind.into(),
            metadata: metadata.to_vec(),
            phase: if opener == self.role {
                Phase::Opening
            } else {
                Phase::Pending
            },
            token,
            open_epoch: epoch,
            open_digest: [0; 32],
            open_digest_ready: false,
            bootstrap,
            prefix: false,
            cancel: false,
            directions,
            queue,
            capacity: physical,
            opening_deadline: Some(
                self.account.security_time()?.monotonic_sample + Duration::from_secs(10),
            ),
            barrier_refs: 0,
            unpublished: 0,
            batch_refs: 0,
            credit_dirty: false,
            recent_at: None,
            forced_rejection: None,
            outcome: None,
            claimed: false,
            receive_progress: None,
            send_progress: None,
        })
    }
    fn handle(&self, scope: u64) -> StreamHandle {
        StreamHandle {
            owner: self.owner,
            scope,
            view: self.slots[self.index(scope).expect("original stream slot")]
                .view
                .clone(),
        }
    }
    fn resolve(&self, handle: &StreamHandle) -> Result<usize> {
        if handle.owner != self.owner || self.closed {
            return Err(CryptoError::State);
        }
        self.index(handle.scope).ok_or(CryptoError::State)
    }
    fn release_queue(&mut self, index: usize) {
        let s = &mut self.slots[index];
        let d = &mut s.directions[usize::from(1 - self.role)];
        let bytes = s.queue.len() as u64;
        s.queue.clear();
        s.receive_progress = None;
        d.released += bytes;
        self.promised -= bytes;
    }
    fn discard_backing(&mut self, index: usize) {
        let s = &mut self.slots[index];
        if s.queue.is_empty() {
            self.backing -= s.capacity;
            s.capacity = 0;
            s.queue = VecDeque::new();
        }
    }
    fn trim_promise(&mut self, index: usize, final_offset: u64) -> Result<()> {
        let d = &mut self.slots[index].directions[usize::from(1 - self.role)];
        if final_offset > d.limit || final_offset < d.released {
            return Err(CryptoError::Authentication);
        }
        self.promised -= d.limit - final_offset;
        d.limit = final_offset;
        d.committed_limit = d.committed_limit.min(final_offset);
        Ok(())
    }
    fn recent(&mut self, index: usize, now: Instant) {
        let slot = &mut self.slots[index];
        if slot.directions.iter().all(Direction::complete)
            && !matches!(slot.phase, Phase::Recent | Phase::Held)
        {
            slot.phase = Phase::Recent;
            slot.recent_at = Some(now);
            slot.opening_deadline = None;
            slot.metadata.clear();
            for d in &mut slot.directions {
                d.deadline = None;
            }
        }
    }
    fn collect(&mut self) {
        let mut i = 0;
        while i < self.slots.len() {
            let s = &self.slots[i];
            if s.phase == Phase::Held
                && s.barrier_refs == 0
                && s.batch_refs == 0
                && s.queue.is_empty()
            {
                let slot = self.slots.swap_remove(i);
                self.backing -= slot.capacity;
                self.return_token(slot.token);
            } else {
                i += 1
            }
        }
    }
    pub(super) fn record_view(&self, scope: u64) -> Option<Arc<StreamView>> {
        self.index(scope)
            .map(|index| self.slots[index].view.clone())
    }
    pub(super) fn crypto_deadline(&self, scope: u64, direction: u8) -> Option<Instant> {
        let drain = self.controls.drain.as_ref().map(|drain| drain.deadline());
        let direction = self
            .index(scope)
            .and_then(|index| self.slots[index].directions[usize::from(direction)].deadline);
        drain.into_iter().chain(direction).min()
    }
    pub(super) fn check_deadlines(&self, sample: TrustedTimeSample) -> Result<()> {
        if self.closed {
            return Err(CryptoError::State);
        }
        self.controls.check_idle(sample)?;
        let now = sample.monotonic_sample;
        if self.slots.iter().any(|s| {
            s.opening_deadline.is_some_and(|d| now >= d)
                || s.directions
                    .iter()
                    .any(|d| !d.complete() && d.deadline.is_some_and(|cap| now >= cap))
        }) || self.outgoing.as_ref().is_some_and(|b| now >= b.deadline)
            || self.incoming.as_ref().is_some_and(|b| now >= b.deadline)
        {
            return Err(CryptoError::Deadline);
        }
        Ok(())
    }
    pub(super) fn close(&mut self) {
        self.closed = true;
        self.controls.close();
        for slot in &mut self.slots {
            let receive = &slot.directions[usize::from(1 - self.role)];
            // Retain normal EOF only when no authenticated payload is lost.
            // FIN alone is insufficient if a close discards unread bytes or
            // interrupts the original direction proof.
            if !slot.queue.is_empty()
                || !receive.fin
                || !receive.proof.is_some_and(|proof| !proof.aborted)
            {
                slot.view.end.store(2, Ordering::Release);
            }
            slot.queue.clear();
            slot.metadata.clear();
        }
        self.output.as_mut_slice().zeroize();
        self.input_pool.close();
        self.body.as_mut_slice().zeroize();
    }
    pub(super) fn install_epoch(&mut self, epoch: u32) {
        for slot in &mut self.slots {
            for d in &mut slot.directions {
                if d.current.epoch < epoch {
                    d.current = Tuple {
                        epoch,
                        next: 0,
                        offset: d.current.offset,
                    };
                }
            }
        }
    }
    pub(super) fn hold(&mut self, scope: u64, outgoing: bool) -> Result<()> {
        if let Some(i) = self.index(scope) {
            let s = &mut self.slots[i];
            s.barrier_refs = s.barrier_refs.checked_add(1).ok_or(CryptoError::Capacity)?;
            s.unpublished += u8::from(outgoing);
        }
        Ok(())
    }
    pub(super) fn release(&mut self, scope: u64) {
        if let Some(i) = self.index(scope) {
            self.slots[i].barrier_refs -= 1;
        }
        self.collect();
    }
    pub(super) fn published(&mut self, scope: u64) {
        if let Some(i) = self.index(scope) {
            self.slots[i].unpublished = self.slots[i].unpublished.saturating_sub(1);
        }
    }
    pub(super) fn snapshot(&self, epoch: u32) -> Vec<(u64, u64)> {
        self.slots
            .iter()
            .filter(|s| s.active())
            .map(|s| {
                (
                    s.scope,
                    s.directions[usize::from(self.role)]
                        .in_epoch(epoch)
                        .map_or(0, |t| t.next),
                )
            })
            .collect()
    }
    pub(super) fn has_bootstrap(&self) -> bool {
        self.profile != 0
    }
    pub(super) fn exists(&self, scope: u64) -> bool {
        self.index(scope).is_some()
    }
    pub(super) fn terminal(&self, scope: u64, direction: u8) -> bool {
        self.index(scope)
            .is_some_and(|i| self.slots[i].directions[usize::from(direction)].complete())
    }
    pub(super) fn barrier(
        &self,
        scope: u64,
        epoch: u32,
        next: u64,
        new: bool,
    ) -> Result<Option<bool>> {
        let Some(i) = self.index(scope) else {
            if self.used(scope)? {
                return Err(CryptoError::Authentication);
            }
            return Ok(None);
        };
        let s = &self.slots[i];
        if new && !s.known() {
            return Err(CryptoError::Authentication);
        }
        let d = &s.directions[usize::from(1 - self.role)];
        if let Some(proof) = d.proof {
            let required = if epoch == proof.terminal.epoch {
                proof.terminal.next
            } else if epoch > proof.terminal.epoch {
                0
            } else {
                return Err(CryptoError::Authentication);
            };
            if next != required {
                return Err(CryptoError::Authentication);
            }
            return Ok(Some(
                d.drain_sent || s.phase == Phase::Recent || s.phase == Phase::Held,
            ));
        }
        let observed = d.in_epoch(epoch)?;
        if next < observed.next {
            return Err(CryptoError::Authentication);
        }
        if let Some(final_tuple) = d.terminal {
            let final_next = if final_tuple.epoch == epoch {
                final_tuple.next
            } else if final_tuple.epoch < epoch {
                0
            } else {
                return Err(CryptoError::Authentication);
            };
            if next != final_next {
                return Err(CryptoError::Authentication);
            }
        }
        Ok(Some(!d.disabled && next == observed.next))
    }
}

/// This facade is constructed only by consuming a completed original READY
/// owner. It owns all reliable receive gates and the sole ordered publisher.
pub(crate) struct ReliableSession {
    engine: RecordEngine,
    application: Option<Arc<crate::application_lifetime_v4::ApplicationLifetime>>,
}
impl std::fmt::Debug for ReliableSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReliableSession { <redacted> }")
    }
}
impl RecordEngine {
    pub(crate) fn into_session(self) -> Result<ReliableSession> {
        self.check()?;
        if !self.ready {
            return Err(CryptoError::State);
        }
        Ok(ReliableSession {
            engine: self,
            application: None,
        })
    }
}
fn uint(out: &mut Vec<u8>, value: u64) {
    codec::encode_head(out, 0, value)
}
fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    codec::encode_head(out, 2, value.len() as u64);
    out.extend_from_slice(value)
}
fn text_value(out: &mut Vec<u8>, value: &str) {
    codec::encode_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes())
}
fn map(count: u64, cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(cap)
        .map_err(|_| CryptoError::Capacity)?;
    codec::encode_head(&mut out, 5, count);
    Ok(out)
}
fn tuple(out: &mut Vec<u8>, value: Tuple) {
    codec::encode_head(out, 5, 3);
    uint(out, 0);
    uint(out, u64::from(value.epoch));
    uint(out, 1);
    uint(out, value.next);
    uint(out, 2);
    uint(out, value.offset)
}
fn tuple_value(value: Value<'_>) -> Result<Tuple> {
    Ok(Tuple {
        epoch: value.u("terminal_tuple", "epoch")? as u32,
        next: value.u("terminal_tuple", "next_sequence")?,
        offset: value.u("terminal_tuple", "offset")?,
    })
}
fn record_header(wire: &[u8]) -> Result<Tuple> {
    if wire.len() < 44 {
        return Err(CryptoError::Authentication);
    }
    Ok(Tuple {
        epoch: u32::from_be_bytes(
            wire[8..12]
                .try_into()
                .map_err(|_| CryptoError::Authentication)?,
        ),
        next: u64::from_be_bytes(
            wire[20..28]
                .try_into()
                .map_err(|_| CryptoError::Authentication)?,
        ),
        offset: 0,
    })
}
fn open_digest(value: Value<'_>) -> Result<[u8; 32]> {
    if value.len()? != 9 {
        return Err(CryptoError::Authentication);
    }
    let omitted = value.field("OPEN_STREAM", "open_digest")?.raw().len() + 1;
    let length = value
        .raw()
        .len()
        .checked_sub(omitted)
        .ok_or(CryptoError::Authentication)?;
    let mut digest = Sha256::new();
    digest.update(b"flowersec/v4/open\0");
    digest.update((length as u32).to_be_bytes());
    digest.update([0xa8]);
    let mut fields = value.children()?;
    while let Some(id) = fields.next() {
        let id = id?;
        let value = fields.next().ok_or(CryptoError::Authentication)??;
        if id.uint()? != 8 {
            digest.update(id.raw());
            digest.update(value.raw());
        }
    }
    Ok(digest.finalize().into())
}

fn retirement_digest(hash: &[u8; 32], profile: Profile, role: u8, body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"flowersec/v4/retire-batch\0");
    for part in [hash.as_slice(), profile.name().as_bytes()] {
        digest.update((part.len() as u32).to_be_bytes());
        digest.update(part);
    }
    digest.update([role]);
    digest.update((body.len() as u32).to_be_bytes());
    digest.update(body);
    digest.finalize().into()
}

pub(super) struct StreamSealPatch {
    pub(super) hash: [u8; 32],
    pub(super) profile: Profile,
    pub(super) role: u8,
    pub(super) scope: u64,
    pub(super) epoch: u32,
    pub(super) frame: u8,
}
pub(super) enum StreamSealCompletion {
    Open {
        scope: u64,
        epoch: u32,
        digest: [u8; 32],
    },
    Retirement {
        sequence: u64,
        digest: [u8; 32],
    },
}
impl StreamSealPatch {
    pub(super) fn execute(self, body: &mut [u8]) -> Result<StreamSealCompletion> {
        if self.frame == 7 {
            let value = decode(body, "OPEN_STREAM", body.len(), Context::default())?;
            let digest = open_digest(value)?;
            let start = body
                .len()
                .checked_sub(32)
                .ok_or(CryptoError::Authentication)?;
            body[start..].copy_from_slice(&digest);
            Ok(StreamSealCompletion::Open {
                scope: self.scope,
                epoch: self.epoch,
                digest,
            })
        } else {
            let value = decode(
                body,
                "STREAM_ACK_RETIRE_BATCH",
                body.len(),
                Context::default(),
            )?;
            let sequence = value.u("STREAM_ACK_RETIRE_BATCH", "batch_seq")?;
            Ok(StreamSealCompletion::Retirement {
                sequence,
                digest: retirement_digest(&self.hash, self.profile, self.role, body),
            })
        }
    }
}

impl ReliableSession {
    fn check(&mut self) -> Result<()> {
        let r = self.engine.check();
        if matches!(
            r,
            Err(CryptoError::Authorization(
                crate::environment_v4::EnvironmentError::TimeUnavailable
            ))
        ) {
            self.engine
                .streams
                .controls
                .interrupt(ProbeOutcome::TimeUnavailable, None);
        }
        if r.is_err() {
            self.engine.fail();
            return r;
        }
        if let Some(drain) = &self.engine.streams.controls.drain
            && self.engine.account.security_time()?.monotonic_sample >= drain.deadline()
        {
            drain.finish(DrainOutcome::DeadlineAborted);
            self.engine.fail();
            return Err(CryptoError::Deadline);
        }
        Ok(())
    }
    fn send(
        &mut self,
        scope: u64,
        frame: u8,
        body: &[u8],
        protected: bool,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<()> {
        self.send_observed(scope, frame, body, protected, publisher, None)
    }
    fn send_observed(
        &mut self,
        scope: u64,
        frame: u8,
        body: &[u8],
        protected: bool,
        publisher: &mut dyn RecordPublisher,
        handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<()> {
        if let Err(error) = publisher
            .prepare_publication(body.len().checked_add(44).ok_or(CryptoError::Capacity)?, 1)
        {
            self.engine.fail();
            return Err(error);
        }
        self.local_liveness_stall();
        let mut out = std::mem::take(&mut self.engine.streams.output);
        let result = (|| {
            let (size, work) = self
                .engine
                .prepare_seal(scope, frame, body, &mut out, false, protected)?;
            publisher.publish_seal(work, &mut out[..size])?;
            if publisher.is_deferred() {
                publisher
                    .defer_publication(crate::crypto_v4::DeferredPublication::handoff(handoff));
                return Ok(());
            }
            // Only SDK-owned scalar observers run here, after the original
            // provider has accepted the complete record and before later tails.
            if let Some(handoff) = handoff {
                handoff();
            }
            self.engine.check()?;
            let now = self.engine.account.security_time()?;
            self.engine.streams.controls.activity(now)
        })();
        out.as_mut_slice().zeroize();
        self.engine.streams.output = out;
        if result.is_err() {
            if scope != 0 && frame == 8 {
                if let Some(normal) = publisher.failed_stream_publication(scope) {
                    let handle = self.engine.streams.handle(scope);
                    self.native_hint(&handle, true, normal)?;
                } else {
                    self.engine.fail();
                }
            } else {
                self.engine.fail();
            }
        }
        result
    }
    fn current_epoch(&self) -> u32 {
        self.engine.epoch + u32::from(self.engine.candidate.as_ref().is_some_and(|c| c.sent))
    }
    fn open_body(
        &self,
        scope: u64,
        kind: &str,
        metadata: &[u8],
        window: u64,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let epoch = self.current_epoch();
        let mut body = map(8, metadata.len() + kind.len() + 128)?;
        for (key, value) in [
            (0, scope),
            (1, u64::from(self.engine.role)),
            (2, scope),
            (3, u64::from(epoch)),
            (4, 0),
        ] {
            uint(&mut body, key);
            uint(&mut body, value)
        }
        uint(&mut body, 5);
        text_value(&mut body, kind);
        uint(&mut body, 6);
        bytes(&mut body, metadata);
        uint(&mut body, 7);
        uint(&mut body, window);
        let digest: [u8; 32] = if self.engine.deferred_crypto {
            [0; 32]
        } else {
            Sha256::digest(domain(b"flowersec/v4/open\0", &[&body])?).into()
        };
        body[0] += 1;
        uint(&mut body, 8);
        bytes(&mut body, &digest);
        Ok((body, digest))
    }
    /// A trusted local kind registration chooses business use here. Reserved
    /// service kinds are unavailable through this ordinary Stream entry.
    #[cfg(test)]
    pub(crate) fn open_stream(
        &mut self,
        kind: &str,
        metadata: &[u8],
        receive_window: u64,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<StreamHandle> {
        self.open_stream_class(kind, metadata, receive_window, Class::Business, publisher)
    }
    pub(crate) fn open_stream_prepared(
        &mut self,
        kind: &str,
        metadata: &[u8],
        receive_window: u64,
        publisher: &mut dyn RecordPublisher,
        before_commit: impl FnOnce(StreamHandle),
    ) -> Result<StreamHandle> {
        self.open_stream_class_prepared(
            kind,
            metadata,
            receive_window,
            Class::Business,
            publisher,
            before_commit,
        )
    }
    pub(crate) fn open_service_stream_prepared(
        &mut self,
        kind: &str,
        receive_window: u64,
        publisher: &mut dyn RecordPublisher,
        before_commit: impl FnOnce(StreamHandle),
    ) -> Result<StreamHandle> {
        let class = self.engine.streams.class(kind, self.engine.role)?;
        if !matches!(class, Class::Notify | Class::Management) || receive_window != 16384 {
            return Err(CryptoError::Configuration);
        }
        self.open_stream_class_prepared(kind, &[], receive_window, class, publisher, before_commit)
    }
    pub(crate) fn open_rpc_stream_prepared(
        &mut self,
        metadata: &[u8],
        publisher: &mut dyn RecordPublisher,
        before_commit: impl FnOnce(StreamHandle),
    ) -> Result<StreamHandle> {
        if metadata.is_empty() || State::rpc_lane(metadata).is_none() {
            return Err(CryptoError::Configuration);
        }
        self.open_stream_class_prepared(RPC, metadata, 16384, Class::Rpc, publisher, before_commit)
    }
    #[cfg(test)]
    fn open_stream_class(
        &mut self,
        kind: &str,
        metadata: &[u8],
        receive_window: u64,
        class: Class,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<StreamHandle> {
        self.open_stream_class_prepared(kind, metadata, receive_window, class, publisher, |_| {})
    }
    fn open_stream_class_prepared(
        &mut self,
        kind: &str,
        metadata: &[u8],
        receive_window: u64,
        class: Class,
        publisher: &mut dyn RecordPublisher,
        before_commit: impl FnOnce(StreamHandle),
    ) -> Result<StreamHandle> {
        self.check()?;
        let role = self.engine.role;
        if self.engine.frozen
            || self.engine.streams.draining
            || self.engine.streams.controls.peer_goaway.is_some()
            || self.engine.streams.class(kind, role)? != class
            || metadata.len() > 4096
        {
            return Err(CryptoError::State);
        }
        let state = &mut self.engine.streams;
        // Reject exhausted lifetime capacity before publishing a facade. No
        // later observer may retain a handle for an ordinal never allocated.
        state.check_lifetime(role, class)?;
        if !state.active_room(class, role, metadata)
            || state
                .slots
                .iter()
                .filter(|s| s.phase == Phase::Opening)
                .count()
                >= INGRESS
        {
            return Err(CryptoError::Capacity);
        }
        if class == Class::Business
            && role == 1
            && state
                .slots
                .iter()
                .any(|s| s.phase == Phase::Pending && s.opener == 0 && s.class == Class::Business)
        {
            return Err(CryptoError::Capacity);
        }
        let ordinal = state.next_ordinal;
        let scope = ordinal
            .checked_mul(2)
            .and_then(|s| s.checked_sub(u64::from(role == 0)))
            .ok_or(CryptoError::Capacity)?;
        if !State::valid(scope) {
            return Err(CryptoError::Capacity);
        }
        let (body, digest) = self.open_body(scope, kind, metadata, receive_window)?;
        let epoch = self.current_epoch();
        let state = &mut self.engine.streams;
        let token = state.take_token(false)?;
        let slot = match state.slot(SlotSeed {
            scope,
            opener: role,
            kind,
            metadata,
            local_window: receive_window,
            peer_window: 0,
            epoch,
            token,
            bootstrap: false,
        }) {
            Ok(s) => s,
            Err(e) => {
                state.return_token(token);
                return Err(e);
            }
        };
        if class == Class::Management
            && let Err(error) = publisher.prepare_management_stream(scope)
        {
            state.promised -= receive_window;
            state.backing -= slot.capacity;
            state.return_token(token);
            return Err(error);
        }
        // The local facade and adapter are complete before the ordinal,
        // lifetime budget, record scope, or OPEN become irreversible.
        before_commit(StreamHandle {
            owner: state.owner,
            scope,
            view: slot.view.clone(),
        });
        if let Err(e) = state.count_lifetime(role, class) {
            state.promised -= receive_window;
            state.backing -= slot.capacity;
            state.return_token(token);
            return Err(e);
        }
        state.next_ordinal += 1;
        if let Err(e) = self.engine.install(scope) {
            self.engine.streams.set_used(scope)?;
            self.engine.streams.return_token(token);
            self.engine.streams.promised -= receive_window;
            self.engine.streams.backing -= slot.capacity;
            self.engine.fail();
            return Err(e);
        }
        let mut slot = slot;
        slot.open_digest = digest;
        slot.open_digest_ready = !self.engine.deferred_crypto;
        slot.prefix = true;
        slot.directions[usize::from(role)].current.next = 1;
        slot.directions[usize::from(role)].last = slot.directions[usize::from(role)].current;
        let account = self.engine.account.clone();
        let commit = account
            .with_security(|| {
                self.engine.streams.set_used(scope)?;
                self.engine.streams.slots.push(slot);
                Ok::<_, CryptoError>(())
            })
            .map_err(CryptoError::from)
            .and_then(|result| result);
        if let Err(error) = commit {
            self.engine.fail();
            return Err(error);
        }
        self.send(scope, 7, &body, false, publisher)?;
        Ok(self.engine.streams.handle(scope))
    }
    pub(crate) fn bootstrap_stream_handle(&mut self) -> Result<StreamHandle> {
        self.check()?;
        if !self.engine.streams.has_bootstrap() {
            return Err(CryptoError::State);
        }
        let i = self.engine.streams.index(1).ok_or(CryptoError::State)?;
        let slot = &self.engine.streams.slots[i];
        if !slot.bootstrap
            || slot
                .directions
                .iter()
                .any(|direction| direction.terminal.is_some())
        {
            return Err(CryptoError::State);
        }
        Ok(self.engine.streams.handle(1))
    }
    pub(crate) fn materialize_bootstrap(
        &mut self,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<StreamHandle> {
        self.check()?;
        if self.engine.role != 0 || self.engine.frozen {
            return Err(CryptoError::State);
        }
        let i = self.engine.streams.index(1).ok_or(CryptoError::State)?;
        let s = &self.engine.streams.slots[i];
        if !s.bootstrap || s.prefix || s.directions.iter().any(|d| d.terminal.is_some()) {
            return Err(CryptoError::State);
        }
        let (body, digest) = self.open_body(1, RPC, &[], 16_384)?;
        let epoch = self.current_epoch();
        let s = &mut self.engine.streams.slots[i];
        s.prefix = true;
        s.open_epoch = epoch;
        s.open_digest = digest;
        s.open_digest_ready = !self.engine.deferred_crypto;
        s.directions[0].current = Tuple {
            epoch,
            next: 1,
            offset: 0,
        };
        s.directions[0].last = s.directions[0].current;
        self.send(1, 7, &body, false, publisher)?;
        Ok(self.engine.streams.handle(1))
    }
    /// Claiming pending input obtains its one terminal token before metadata is
    /// available to any application authorizer. It is not an accepted Stream.
    pub(crate) fn pending_open(&mut self) -> Result<Option<StreamHandle>> {
        self.pending_open_class(false, None)
    }
    pub(crate) fn pending_service_open(&mut self) -> Result<Option<StreamHandle>> {
        self.pending_open_class(true, None)
    }
    pub(crate) fn pending_service_kind(&mut self, kind: &str) -> Result<Option<StreamHandle>> {
        self.pending_open_class(true, Some(kind))
    }
    pub(crate) fn pending_business_kinds(
        &mut self,
        kinds: &[String],
        include: bool,
    ) -> Result<Option<StreamHandle>> {
        self.pending_open_matching(false, |kind| {
            kinds.iter().any(|reserved| reserved == kind) == include
        })
    }
    fn pending_open_class(
        &mut self,
        service: bool,
        kind: Option<&str>,
    ) -> Result<Option<StreamHandle>> {
        self.pending_open_matching(service, |candidate| {
            kind.is_none_or(|kind| candidate == kind)
        })
    }
    fn pending_open_matching(
        &mut self,
        service: bool,
        matches: impl Fn(&str) -> bool,
    ) -> Result<Option<StreamHandle>> {
        self.check()?;
        let Some(i) = self.engine.streams.slots.iter().position(|s| {
            s.phase == Phase::Pending
                && !s.claimed
                && s.forced_rejection.is_none()
                && (s.class != Class::Business) == service
                && matches(&s.kind)
        }) else {
            return Ok(None);
        };
        if self.engine.streams.slots[i].token == Token::None {
            let token = self.engine.streams.take_token(false)?;
            self.engine.streams.slots[i].token = token;
        }
        self.engine.streams.slots[i].claimed = true;
        Ok(Some(
            self.engine
                .streams
                .handle(self.engine.streams.slots[i].scope),
        ))
    }
    pub(crate) fn pending_metadata(&self, handle: &StreamHandle) -> Result<(&str, &[u8])> {
        self.engine.check()?;
        let i = self.engine.streams.resolve(handle)?;
        let s = &self.engine.streams.slots[i];
        if s.phase != Phase::Pending || s.token == Token::None {
            return Err(CryptoError::State);
        }
        Ok((&s.kind, &s.metadata))
    }
    fn outcome_body(&self, index: usize, decision: OpenDecision) -> Result<Vec<u8>> {
        let s = &self.engine.streams.slots[index];
        let rejected = matches!(decision, OpenDecision::Reject(_));
        let mut body = map(if rejected { 12 } else { 8 }, 256)?;
        for (k, v) in [
            (0, s.scope),
            (1, u64::from(s.opener)),
            (2, u64::from(rejected)),
            (3, u64::from(s.open_epoch)),
            (4, 0),
        ] {
            uint(&mut body, k);
            uint(&mut body, v)
        }
        uint(&mut body, 5);
        bytes(&mut body, &s.open_digest);
        uint(&mut body, 6);
        uint(
            &mut body,
            match decision {
                OpenDecision::Accept { receive_window } => receive_window,
                _ => 0,
            },
        );
        if rejected {
            for (k, v) in [(7, u64::from(s.open_epoch)), (8, 1), (9, 0)] {
                uint(&mut body, k);
                uint(&mut body, v)
            }
        }
        uint(&mut body, 10);
        uint(&mut body, 1);
        if let OpenDecision::Reject(reason) = decision {
            uint(&mut body, 11);
            uint(&mut body, reason as u64)
        }
        Ok(body)
    }
    fn rejected(&mut self, index: usize) -> Result<()> {
        let s = &self.engine.streams.slots[index];
        if s.bootstrap
            || s.directions.iter().any(|d| d.current.offset != 0)
            || s.directions[usize::from(1 - s.opener)].current.next != 0
        {
            return Err(CryptoError::Authentication);
        }
        let receive = usize::from(1 - self.engine.role);
        let remaining = s.directions[receive].limit - s.directions[receive].released;
        self.engine.streams.promised -= remaining;
        let s = &mut self.engine.streams.slots[index];
        s.view.end.store(2, Ordering::Release);
        s.view.rejected.store(true, Ordering::Release);
        for direction in 0..2 {
            let final_tuple = Tuple {
                epoch: s.open_epoch,
                next: u64::from(direction == usize::from(s.opener)),
                offset: 0,
            };
            let d = &mut s.directions[direction];
            d.terminal = Some(final_tuple);
            d.proof = Some(DrainProof {
                terminal: final_tuple,
                observed: final_tuple,
                aborted: false,
            });
            d.drain_sent = true;
            d.limit = 0;
            d.stop = true;
        }
        self.engine
            .streams
            .recent(index, self.engine.account.security_time()?.monotonic_sample);
        self.engine.streams.discard_backing(index);
        self.retire_keys();
        Ok(())
    }
    pub(crate) fn decide_open(
        &mut self,
        handle: &StreamHandle,
        mut decision: OpenDecision,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<()> {
        self.check()?;
        let i = self.engine.streams.resolve(handle)?;
        let s = &self.engine.streams.slots[i];
        if s.phase != Phase::Pending || s.bootstrap {
            return Err(CryptoError::State);
        }
        if self.engine.streams.draining {
            decision = OpenDecision::Reject(Rejection::Draining)
        }
        if self.engine.streams.class(&s.kind, s.opener).is_err() {
            decision = OpenDecision::Reject(Rejection::Kind)
        }
        if !s.metadata.is_empty()
            && decode(&s.metadata, "StreamMetadata", 4096, Context::default()).is_err()
            && decode(
                &s.metadata,
                "TypedMessageMetadata",
                4096,
                Context::default(),
            )
            .is_err()
        {
            decision = OpenDecision::Reject(Rejection::Metadata);
        }
        if matches!(decision, OpenDecision::Accept { .. })
            && !self
                .engine
                .streams
                .active_room(s.class, s.opener, &s.metadata)
        {
            if self.engine.role == 1
                && s.opener == 0
                && self
                    .engine
                    .streams
                    .slots
                    .iter()
                    .any(|s| s.phase == Phase::Opening && s.class == Class::Business)
            {
                return Err(CryptoError::Capacity);
            }
            decision = OpenDecision::Reject(Rejection::Resource);
        }
        if self.engine.streams.slots[i].token == Token::None {
            let token = self
                .engine
                .streams
                .take_token(matches!(decision, OpenDecision::Reject(_)))?;
            self.engine.streams.slots[i].token = token;
        }
        let body = self.outcome_body(i, decision)?;
        if let OpenDecision::Accept { receive_window } = decision {
            if !self.engine.streams.credit_room(
                self.engine.streams.slots[i].class,
                receive_window,
                true,
            ) {
                return Err(CryptoError::Capacity);
            }
            let queue = self.engine.streams.reserve_window(receive_window)?;
            let s = &mut self.engine.streams.slots[i];
            s.capacity = queue.capacity();
            s.queue = queue;
            s.directions[usize::from(1 - self.engine.role)].limit = receive_window;
            s.directions[usize::from(1 - self.engine.role)].committed_limit = receive_window;
            s.phase = Phase::Accepted;
            s.opening_deadline = None;
            let opener = usize::from(s.opener);
            self.engine.streams.controls.highest_accepted[opener] =
                self.engine.streams.controls.highest_accepted[opener].max(s.scope);
        }
        let scope = self.engine.streams.slots[i].scope;
        self.engine.streams.set_used(scope)?;
        self.engine.streams.slots[i].outcome = Some(decision);
        self.engine.streams.ingress_bytes -= self.engine.streams.slots[i].metadata.len();
        if let OpenDecision::Reject(_) = decision {
            self.rejected(i)?;
        }
        self.engine.streams.slots[i].metadata.clear();
        self.engine.streams.slots[i].forced_rejection = None;
        self.send(0, 9, &body, true, publisher)
    }
    pub(crate) fn write(
        &mut self,
        handle: &StreamHandle,
        data: &[u8],
        fin: bool,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<usize> {
        self.write_with_admission(handle, data, fin, None, publisher)
    }
    fn write_with_admission(
        &mut self,
        handle: &StreamHandle,
        data: &[u8],
        fin: bool,
        admission: Option<&crate::api_v4::WriteRequestAdmission>,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<usize> {
        self.write_with_admission_observed(handle, data, fin, admission, publisher, None, None)
    }
    pub(crate) fn write_management(
        &mut self,
        handle: &StreamHandle,
        data: &[u8],
        publisher: &mut dyn RecordPublisher,
        before_accept: &mut dyn FnMut() -> Result<()>,
    ) -> Result<usize> {
        self.write_with_admission_observed(
            handle,
            data,
            false,
            None,
            publisher,
            None,
            Some(before_accept),
        )
    }
    #[cfg(test)]
    pub(super) fn publication_frontier_for_test(
        &self,
        handle: &StreamHandle,
    ) -> Result<(Tuple, bool)> {
        let index = self.engine.streams.resolve(handle)?;
        let direction = self.engine.streams.slots[index].directions[usize::from(self.engine.role)];
        Ok((direction.current, direction.fin))
    }
    #[allow(clippy::too_many_arguments)] // Original write owners and its two admission observers.
    fn write_with_admission_observed(
        &mut self,
        handle: &StreamHandle,
        data: &[u8],
        fin: bool,
        admission: Option<&crate::api_v4::WriteRequestAdmission>,
        publisher: &mut dyn RecordPublisher,
        handoff: Option<Arc<dyn Fn() + Send + Sync>>,
        before_accept: Option<&mut dyn FnMut() -> Result<()>>,
    ) -> Result<usize> {
        self.check()?;
        if self.engine.frozen {
            return Err(CryptoError::State);
        }
        let i = self.engine.streams.resolve(handle)?;
        let role = usize::from(self.engine.role);
        let s = &self.engine.streams.slots[i];
        let d = s.directions[role];
        if s.phase != Phase::Accepted
            || !s.prefix
            || d.stop
            || d.terminal.is_some()
            || (d.fin_requested && !fin)
        {
            return Err(CryptoError::State);
        }
        let end = d
            .current
            .offset
            .checked_add(data.len() as u64)
            .ok_or(CryptoError::Capacity)?;
        if end > d.limit || data.len() + 128 > self.engine.max_frame {
            return Err(CryptoError::Capacity);
        }
        let epoch = self.current_epoch();
        let sequence = self
            .engine
            .keys_for(self.engine.candidate.as_ref().is_some_and(|c| c.sent))?[self
            .engine
            .slot_for(
                self.engine.candidate.as_ref().is_some_and(|c| c.sent),
                s.scope,
                self.engine.role,
            )?]
        .next;
        let mut body = map(7, data.len() + 96)?;
        for (k, v) in [
            (0, s.scope),
            (1, role as u64),
            (2, u64::from(epoch)),
            (3, sequence),
            (4, d.current.offset),
        ] {
            uint(&mut body, k);
            uint(&mut body, v)
        }
        uint(&mut body, 5);
        body.push(if fin { 0xf5 } else { 0xf4 });
        uint(&mut body, 6);
        bytes(&mut body, data);
        let current = Tuple {
            epoch,
            next: sequence.checked_add(1).ok_or(CryptoError::Sequence)?,
            offset: end,
        };
        // Both the wire bytes and the accepted/FIN completion metadata are
        // prepaid before admission and the reliable direction frontier move.
        let unpublished = if publisher.is_deferred() {
            Some(
                self.engine.streams.slots[i]
                    .unpublished
                    .checked_add(1)
                    .ok_or(CryptoError::Capacity)?,
            )
        } else {
            None
        };
        publisher
            .prepare_publication(body.len().checked_add(44).ok_or(CryptoError::Capacity)?, 2)?;
        let mut direction = d;
        direction.current = current;
        direction.last = current;
        if fin {
            direction.terminal = Some(current);
            direction.fin = true;
            direction.stop = true;
            direction.begin(self.engine.account.security_time()?.monotonic_sample, false)?;
        }
        if let Some(admission) = admission {
            admission
                .accept(data.len())
                .map_err(|_| CryptoError::State)?;
        }
        // M serial allocation shares the irreversible DATA admission gate,
        // after complete encoding and publication capacity are available.
        if let Some(before_accept) = before_accept {
            before_accept()?;
        }
        self.engine.streams.slots[i].directions[role] = direction;
        // The caller-visible frontier is committed only after the native
        // publisher accepts the complete encrypted record. Until then the
        // handle remains at its prior accepted offset, so a failed provider
        // write cannot be observed as an accepted application write.
        self.send_observed(handle.scope, 8, &body, false, publisher, handoff)?;
        if publisher.is_deferred() {
            self.engine.streams.slots[i].unpublished = unpublished.ok_or(CryptoError::State)?;
            publisher.defer_publication(crate::crypto_v4::DeferredPublication::stream(
                handle.view.clone(),
                handle.scope,
                end,
                fin,
            ));
        } else {
            handle.view.accepted.store(end, Ordering::Release);
            if fin {
                handle.view.fin_submitted.store(true, Ordering::Release);
            }
        }
        Ok(data.len())
    }
    /// Seal application admission synchronously. The original Session driver
    /// owns FIN publication even when the caller drops its waiting future.
    pub(crate) fn request_close_write(&mut self, handle: &StreamHandle) -> Result<()> {
        self.check()?;
        let i = self.engine.streams.resolve(handle)?;
        let now = self.engine.account.security_time()?.monotonic_sample;
        let d = &mut self.engine.streams.slots[i].directions[usize::from(self.engine.role)];
        if d.fin {
            return Ok(());
        }
        if d.stop || d.terminal.is_some() {
            return Err(CryptoError::State);
        }
        d.fin_requested = true;
        d.begin(now, false)
    }
    pub(crate) fn read(&mut self, handle: &StreamHandle, out: &mut [u8]) -> Result<ReadState> {
        self.check()?;
        if handle.owner != self.engine.streams.owner {
            return Err(CryptoError::State);
        }
        let Some(i) = self.engine.streams.index(handle.scope) else {
            return match handle.view.end.load(Ordering::Acquire) {
                1 => Ok(ReadState::Eof),
                2 => Ok(ReadState::Aborted),
                _ => Err(CryptoError::State),
            };
        };
        let s = &self.engine.streams.slots[i];
        let d = &s.directions[usize::from(1 - self.engine.role)];
        if d.stop && !d.fin {
            return Ok(ReadState::Aborted);
        }
        if !s.accepted() || d.current.epoch > self.engine.epoch {
            return Ok(ReadState::Pending);
        }
        let count = out.len().min(s.queue.len());
        if count == 0 {
            return Ok(if s.queue.is_empty() && d.fin && d.proof.is_some() {
                ReadState::Eof
            } else {
                ReadState::Pending
            });
        }
        let account = self.engine.account.clone();
        let now = account.security_time()?.monotonic_sample;
        account.with_security(|| {
            let s = &mut self.engine.streams.slots[i];
            for byte in &mut out[..count] {
                *byte = s.queue.pop_front().expect("reserved queued byte")
            }
            s.receive_progress = (!s.queue.is_empty()).then_some(now);
            s.directions[usize::from(1 - self.engine.role)].released += count as u64;
            self.engine.streams.promised -= count as u64;
        })?;
        if self.engine.streams.slots[i].directions[usize::from(1 - self.engine.role)].complete() {
            self.engine.streams.discard_backing(i);
            self.engine.streams.collect();
        }
        Ok(ReadState::Data(count))
    }
    pub(crate) fn grant(&mut self, handle: &StreamHandle, limit: u64) -> Result<()> {
        self.check()?;
        let i = self.engine.streams.resolve(handle)?;
        let direction = usize::from(1 - self.engine.role);
        let s = &self.engine.streams.slots[i];
        let d = s.directions[direction];
        if !s.accepted() || d.stop || d.terminal.is_some() || limit < d.limit {
            return Err(CryptoError::State);
        }
        let delta = limit - d.limit;
        let required = usize::try_from(limit - d.released).map_err(|_| CryptoError::Capacity)?;
        let growth = required.saturating_sub(s.capacity);
        if !self.engine.streams.credit_room(s.class, delta, false)
            || growth > self.engine.streams.max_credit as usize - self.engine.streams.backing
        {
            return Err(CryptoError::Capacity);
        }
        let mut replacement = None;
        let physical_growth = if growth != 0 {
            let mut queue = VecDeque::new();
            queue
                .try_reserve_exact(required)
                .map_err(|_| CryptoError::Capacity)?;
            let actual = queue.capacity();
            let growth = actual.saturating_sub(s.capacity);
            if growth > self.engine.streams.max_credit as usize - self.engine.streams.backing {
                return Err(CryptoError::Capacity);
            }
            queue.extend(s.queue.iter().copied());
            replacement = Some(queue);
            growth
        } else {
            0
        };
        let s = &mut self.engine.streams.slots[i];
        if let Some(queue) = replacement {
            s.queue = queue;
        }
        s.capacity += physical_growth;
        s.directions[direction].limit = limit;
        s.credit_dirty = true;
        self.engine.streams.promised += delta;
        self.engine.streams.backing += physical_growth;
        Ok(())
    }
    fn reset_index(&mut self, index: usize, failure: bool) -> Result<()> {
        if self.engine.streams.slots[index].phase == Phase::Opening {
            self.engine.streams.slots[index].cancel = true;
            return Ok(());
        }
        if !self.engine.streams.slots[index].accepted() {
            return Err(CryptoError::State);
        }
        let now = self.engine.account.security_time()?.monotonic_sample;
        let role = usize::from(self.engine.role);
        let peer = 1 - role;
        let s = &mut self.engine.streams.slots[index];
        s.cancel = true;
        s.view.end.store(2, Ordering::Release);
        let send = &mut s.directions[role];
        send.stop = true;
        if !send.complete() {
            send.stopped_requested = true;
        }
        if send.terminal.is_none() {
            send.terminal = Some(send.current)
        }
        send.begin(now, failure)?;
        let receive = &mut s.directions[peer];
        receive.stop = true;
        receive.fin = false;
        receive.begin(now, failure)?;
        if failure {
            s.view.receive_disabled.store(true, Ordering::Release);
            receive.disabled = true;
            for key in &mut self.engine.keys {
                if key.scope == s.scope && key.direction == peer as u8 {
                    key.disabled = true
                }
            }
            if let Some(c) = &mut self.engine.candidate {
                for key in &mut c.keys {
                    if key.scope == s.scope && key.direction == peer as u8 {
                        key.disabled = true
                    }
                }
            }
        }
        self.engine.streams.release_queue(index);
        Ok(())
    }
    fn isolate_input_error(&mut self, index: usize, cause: CryptoError) -> Result<()> {
        self.engine.streams.slots[index].directions[usize::from(1 - self.engine.role)]
            .first_error
            .get_or_insert(cause);
        self.reset_index(index, true)
    }
    pub(crate) fn reset(&mut self, handle: &StreamHandle) -> Result<()> {
        self.check()?;
        let i = self.engine.streams.resolve(handle)?;
        self.reset_index(i, false)
    }
    fn retire_keys(&mut self) {
        let state = &self.engine.streams;
        self.engine
            .keys
            .retain(|k| k.scope == 0 || !state.terminal(k.scope, k.direction));
        if let Some(c) = &mut self.engine.candidate {
            c.keys
                .retain(|k| k.scope == 0 || !state.terminal(k.scope, k.direction));
        }
    }
}
fn open_decision(value: Value<'_>) -> Result<OpenDecision> {
    Ok(match value.u("OPEN_ACCEPT", "result")? {
        0 => OpenDecision::Accept {
            receive_window: value.u("OPEN_ACCEPT", "initial_receive_limit")?,
        },
        1 => OpenDecision::Reject(match value.u("OPEN_ACCEPT", "reason")? {
            1 => Rejection::Resource,
            2 => Rejection::Metadata,
            3 => Rejection::Kind,
            4 => Rejection::Application,
            5 => Rejection::Draining,
            _ => return Err(CryptoError::Authentication),
        }),
        _ => return Err(CryptoError::Authentication),
    })
}
fn control_schema(body: &[u8]) -> Result<&'static str> {
    if matches!(body.first(), Some(0xa8 | 0xac)) {
        return Ok("OPEN_ACCEPT");
    }
    if body.len() < 3 || body[1] != 0 {
        return Err(CryptoError::Authentication);
    }
    match body[2] {
        0 => Ok("STREAM_ACK_CREDIT"),
        2 => Ok("STREAM_ACK_STOP"),
        3 => Ok("STREAM_ACK_STOPPED"),
        4 => Ok("STREAM_ACK_DRAINED"),
        5 => Ok("STREAM_ACK_RETIRE_BATCH"),
        6 => Ok("STREAM_ACK_RETIRE_ACK"),
        _ => Err(CryptoError::Authentication),
    }
}
impl RecordEngine {
    fn validate_stream_input(
        &self,
        scope: u64,
        header: Tuple,
        frame: u8,
        body: &[u8],
        digest: Option<[u8; 32]>,
    ) -> Result<()> {
        let state = &self.streams;
        if matches!(frame, 12..=15) {
            return self.validate_control(scope, header, frame, body);
        }
        if frame == 7 {
            let v = decode(body, "OPEN_STREAM", self.max_frame, Context::default())?;
            if State::opener(scope) != 1 - self.role
                || header.next != 0
                || v.u("OPEN_STREAM", "stream_id")? != scope
                || v.u("OPEN_STREAM", "scope")? != scope
                || v.u("OPEN_STREAM", "direction")? != u64::from(1 - self.role)
                || v.u("OPEN_STREAM", "epoch")? != u64::from(header.epoch)
                || v.u("OPEN_STREAM", "sequence")? != 0
                || Some(v.b::<32>("OPEN_STREAM", "open_digest")?) != digest
            {
                return Err(CryptoError::Authentication);
            }
            if let Some(i) = state.index(scope) {
                let s = &state.slots[i];
                if !s.bootstrap
                    || s.prefix
                    || s.directions.iter().any(|d| d.terminal.is_some())
                    || v.field("OPEN_STREAM", "kind")?.text()? != RPC
                    || !v.field("OPEN_STREAM", "metadata")?.bytes()?.is_empty()
                    || v.u("OPEN_STREAM", "initial_receive_limit")? != 16_384
                {
                    return Err(CryptoError::Authentication);
                }
            } else if state.used(scope)? {
                return Err(CryptoError::Authentication);
            }
            return Ok(());
        }
        if frame == 8 {
            let v = decode(body, "STREAM_DATA", self.max_frame, Context::default())?;
            let i = state.index(scope).ok_or(CryptoError::Authentication)?;
            let s = &state.slots[i];
            let d = s.directions[usize::from(1 - self.role)];
            if !s.prefix
                || (!s.accepted() && !(s.phase == Phase::Opening && s.opener == self.role))
                || d.disabled
                || d.proof.is_some()
                || v.u("STREAM_DATA", "stream_id")? != scope
                || v.u("STREAM_DATA", "direction")? != u64::from(1 - self.role)
                || v.u("STREAM_DATA", "epoch")? != u64::from(header.epoch)
                || v.u("STREAM_DATA", "sequence")? != header.next
            {
                return Err(CryptoError::Authentication);
            }
            let offset = v.u("STREAM_DATA", "offset")?;
            let data = v.field("STREAM_DATA", "data")?.bytes()?;
            let end = offset
                .checked_add(data.len() as u64)
                .ok_or(CryptoError::Capacity)?;
            if offset != d.current.offset
                || end > d.committed_limit
                || header.epoch < d.current.epoch
                || header.epoch > self.epoch + u32::from(self.candidate.is_some())
                || d.fin
            {
                return Err(CryptoError::Authentication);
            }
            let next = header.next.checked_add(1).ok_or(CryptoError::Sequence)?;
            if let Some(final_tuple) = d.terminal
                && (header.epoch != final_tuple.epoch
                    || next > final_tuple.next
                    || end > final_tuple.offset)
            {
                return Err(CryptoError::Authentication);
            }
            if !d.stop && data.len() > s.capacity - s.queue.len() {
                return Err(CryptoError::Capacity);
            }
            return Ok(());
        }
        if frame != 9 || scope != 0 {
            return Err(CryptoError::Authentication);
        }
        let name = control_schema(body)?;
        let v = decode(body, name, self.max_frame, Context::default())?;
        if name == "STREAM_ACK_RETIRE_BATCH" || name == "STREAM_ACK_RETIRE_ACK" {
            return self.validate_retirement(v, name, digest);
        }
        let target = v.u(name, "stream_id")?;
        let direction = v.u(name, "direction")?;
        let expected = if name == "STREAM_ACK_STOPPED" {
            1 - self.role
        } else {
            self.role
        };
        if direction != u64::from(expected) || !State::valid(target) {
            return Err(CryptoError::Authentication);
        }
        let Some(i) = state.index(target) else {
            if state.used(target)? && !(name == "OPEN_ACCEPT" && target == 1 && state.profile != 0)
            {
                return Ok(());
            }
            return Err(CryptoError::Authentication);
        };
        let s = &state.slots[i];
        if s.phase == Phase::Held {
            return Ok(());
        }
        if name == "OPEN_ACCEPT" {
            if s.bootstrap
                || !s.open_digest_ready
                || s.opener != self.role
                || v.u(name, "open_epoch")? != u64::from(s.open_epoch)
                || v.u(name, "open_sequence")? != 0
                || v.b::<32>(name, "open_digest")? != s.open_digest
            {
                return Err(CryptoError::Authentication);
            }
            let decision = open_decision(v)?;
            let accepted = matches!(decision, OpenDecision::Accept { .. });
            if accepted
                && state
                    .controls
                    .peer_goaway
                    .is_some_and(|g| target > g.ceiling)
            {
                return Err(CryptoError::Authentication);
            }
            if s.phase != Phase::Opening {
                if Some(decision) == s.outcome {
                    return Ok(());
                }
                return Err(CryptoError::Authentication);
            }
            if !accepted
                && (s.directions.iter().any(|d| d.current.offset != 0)
                    || s.directions[usize::from(1 - self.role)].current.next != 0)
            {
                return Err(CryptoError::Authentication);
            }
            return Ok(());
        }
        if !s.accepted() {
            return Err(CryptoError::Authentication);
        }
        let d = s.directions[direction as usize];
        match name {
            "STREAM_ACK_CREDIT" => {
                let ack = v.u(name, "ack_offset")?;
                let limit = v.u(name, "receive_limit")?;
                if ack > d.current.offset
                    || limit < ack
                    || !((ack >= d.ack && limit >= d.limit) || (ack <= d.ack && limit <= d.limit))
                {
                    return Err(CryptoError::Authentication);
                }
            }
            "STREAM_ACK_STOP" => {}
            "STREAM_ACK_STOPPED" => {
                let final_tuple = Tuple {
                    epoch: v.u(name, "final_epoch")? as u32,
                    next: v.u(name, "final_next_sequence")?,
                    offset: v.u(name, "final_offset")?,
                };
                let observed = d.in_epoch(final_tuple.epoch)?;
                if d.terminal.is_some_and(|old| old != final_tuple)
                    || observed.next > final_tuple.next
                    || observed.offset > final_tuple.offset
                    || final_tuple.offset > d.committed_limit
                {
                    return Err(CryptoError::Authentication);
                }
            }
            "STREAM_ACK_DRAINED" => {
                let final_tuple = tuple_value(v.field(name, "terminal_tuple")?)?;
                let observed = tuple_value(v.field(name, "observed_tuple")?)?;
                let aborted = v.u(name, "outcome")? == 1;
                if d.terminal != Some(final_tuple)
                    || observed.epoch != final_tuple.epoch
                    || observed.next > final_tuple.next
                    || observed.offset > final_tuple.offset
                    || (!aborted && observed != final_tuple)
                    || d.proof.is_some_and(|p| {
                        p != DrainProof {
                            terminal: final_tuple,
                            observed,
                            aborted,
                        }
                    })
                {
                    return Err(CryptoError::Authentication);
                }
            }
            _ => return Err(CryptoError::Authentication),
        }
        Ok(())
    }
    fn validate_retirement(
        &self,
        v: Value<'_>,
        name: &str,
        digest: Option<[u8; 32]>,
    ) -> Result<()> {
        let state = &self.streams;
        let seq = v.u(name, "batch_seq")?;
        if name == "STREAM_ACK_RETIRE_ACK" {
            let digest = v.b::<32>(name, "batch_digest")?;
            if seq < state.last_out {
                return Ok(());
            }
            if seq == state.last_out {
                return if digest == state.last_out_digest {
                    Ok(())
                } else {
                    Err(CryptoError::Authentication)
                };
            }
            let b = state.outgoing.as_ref().ok_or(CryptoError::Authentication)?;
            if !b.submitted || !b.digest_ready || seq != b.sequence || digest != b.digest {
                return Err(CryptoError::Authentication);
            }
            return Ok(());
        }
        let digest = digest.ok_or(CryptoError::Authentication)?;
        if seq < state.last_in {
            return Ok(());
        }
        if seq == state.last_in {
            return if digest == state.last_in_digest {
                Ok(())
            } else {
                Err(CryptoError::Authentication)
            };
        }
        if let Some(b) = &state.incoming {
            return if seq == b.sequence && digest == b.digest {
                Ok(())
            } else {
                Err(CryptoError::Authentication)
            };
        }
        if seq != state.last_in.checked_add(1).ok_or(CryptoError::Capacity)? {
            return Err(CryptoError::Authentication);
        }
        for id in v.field(name, "scope_ids")?.children()? {
            let scope = id?.uint()?;
            if !State::valid(scope) || State::opener(scope) != 1 - self.role {
                return Err(CryptoError::Authentication);
            }
            let i = state.index(scope).ok_or(CryptoError::Authentication)?;
            if state.slots[i].phase != Phase::Recent
                || !state.slots[i].directions.iter().all(Direction::complete)
            {
                return Err(CryptoError::Authentication);
            }
        }
        Ok(())
    }
    pub(super) fn finish_stream_seal(&mut self, completion: StreamSealCompletion) -> Result<()> {
        self.check()?;
        match completion {
            StreamSealCompletion::Open {
                scope,
                epoch,
                digest,
            } => {
                let index = self.streams.index(scope).ok_or(CryptoError::State)?;
                let slot = &mut self.streams.slots[index];
                if slot.open_digest_ready
                    || !slot.prefix
                    || slot.open_epoch != epoch
                    || slot.opener != self.role
                    || !matches!(slot.phase, Phase::Opening | Phase::Accepted)
                {
                    return Err(CryptoError::State);
                }
                slot.open_digest = digest;
                slot.open_digest_ready = true;
            }
            StreamSealCompletion::Retirement { sequence, digest } => {
                let batch = self.streams.outgoing.as_mut().ok_or(CryptoError::State)?;
                if batch.sequence != sequence || batch.digest_ready {
                    return Err(CryptoError::State);
                }
                batch.digest = digest;
                batch.digest_ready = true;
            }
        }
        Ok(())
    }
}
/// Three original pre-admitted input slots: two independent application
/// directions and a reserved maintenance direction. Waiting never holds drive.
pub(crate) struct ReceivePool {
    slots: std::sync::Mutex<[Option<Vec<u8>>; 3]>,
    changed: std::sync::Condvar,
    closed: AtomicBool,
    _charge: ResourceCharge,
}
pub(crate) struct ReceiveLease {
    pool: Arc<ReceivePool>,
    index: usize,
    bytes: Vec<u8>,
}
impl ReceivePool {
    fn limits(frame: usize) -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: (3 * (frame + 8)
                + std::mem::size_of::<Self>()
                + 3 * std::mem::size_of::<ReceiveInput>()) as u64,
            items: 3,
            work_slots: 3,
            ..ResourceLimits::default()
        }
    }
    fn new(frame: usize, charge: ResourceCharge) -> Result<Arc<Self>> {
        let mut slots = [None, None, None];
        for slot in &mut slots {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(frame + 8)
                .map_err(|_| CryptoError::Capacity)?;
            bytes.resize(frame + 8, 0);
            *slot = Some(bytes);
        }
        Ok(Arc::new(Self {
            slots: std::sync::Mutex::new(slots),
            changed: std::sync::Condvar::new(),
            closed: AtomicBool::new(false),
            _charge: charge,
        }))
    }
    pub(crate) fn acquire(self: &Arc<Self>, maintenance: bool) -> Result<ReceiveLease> {
        let mut slots = self.slots.lock().expect("original receive slots");
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(CryptoError::State);
            }
            let range = if maintenance { 2..3 } else { 0..2 };
            if let Some(index) = range.into_iter().find(|index| slots[*index].is_some()) {
                return Ok(ReceiveLease {
                    pool: self.clone(),
                    index,
                    bytes: slots[index].take().expect("available receive slot"),
                });
            }
            slots = self
                .changed
                .wait(slots)
                .expect("original receive slot wait");
        }
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let mut slots = self.slots.lock().expect("original receive slot closure");
        for bytes in slots.iter_mut().flatten() {
            bytes.as_mut_slice().zeroize();
        }
        self.changed.notify_all();
    }
}
impl Drop for ReceiveLease {
    fn drop(&mut self) {
        // Erase the storage while retaining the original fixed slot length.
        self.bytes.as_mut_slice().zeroize();
        let mut slots = self
            .pool
            .slots
            .lock()
            .expect("original receive slot return");
        slots[self.index] = Some(std::mem::take(&mut self.bytes));
        self.pool.changed.notify_all();
    }
}
pub(crate) struct ReceiveInput {
    ticket: RecordOpen,
    lease: ReceiveLease,
    scope: u64,
    header: Tuple,
    frame: u8,
    known: bool,
    accepted: bool,
    bound: bool,
    rekey: Option<(u8, bool)>,
    rekey_authentication: Option<rekey::RekeyAuthentication>,
    digest_context: ([u8; 32], Profile, u8),
    stream_digest: Option<[u8; 32]>,
}
impl ReceiveInput {
    pub(crate) fn execute(&mut self, wire: &[u8]) -> Result<usize> {
        let n = self.ticket.execute(wire, &mut self.lease.bytes)?;
        if let Some(authentication) = &self.rekey_authentication {
            authentication.verify(&self.lease.bytes[..n])?;
        }
        let body = &self.lease.bytes[..n];
        self.stream_digest = if self.frame == 7 {
            Some(open_digest(decode(
                body,
                "OPEN_STREAM",
                body.len(),
                Context::default(),
            )?)?)
        } else if self.frame == 9 && control_schema(body)? == "STREAM_ACK_RETIRE_BATCH" {
            Some(retirement_digest(
                &self.digest_context.0,
                self.digest_context.1,
                self.digest_context.2,
                body,
            ))
        } else {
            None
        };
        #[cfg(test)]
        if self.stream_digest.is_some() {
            self.ticket.test_hold(wire);
        }
        Ok(n)
    }
}
impl ReliableSession {
    /// scope is supplied by the original bounded native/shared input owner. A
    /// new OPEN gets only a charged provisional key until its real AEAD passes.
    #[cfg(test)]
    pub(crate) fn receive(&mut self, scope: u64, wire: &[u8]) -> Result<()> {
        self.receive_input(scope, wire, None)
    }
    pub(crate) fn capture_native_binding(&mut self, scope: u64) -> Result<StreamHandle> {
        self.check()?;
        let index = self.engine.streams.index(scope).ok_or(CryptoError::State)?;
        let slot = &self.engine.streams.slots[index];
        if !slot.prefix || slot.phase == Phase::Held {
            return Err(CryptoError::State);
        }
        slot.view
            .native_bound
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CryptoError::State)?;
        Ok(self.engine.streams.handle(scope))
    }
    pub(crate) fn native_hint(
        &mut self,
        handle: &StreamHandle,
        sending: bool,
        normal: bool,
    ) -> Result<()> {
        self.check()?;
        if self.phase(handle)? == StreamPhase::Stable {
            return Ok(());
        }
        let index = self.engine.streams.resolve(handle)?;
        let view = &self.engine.streams.slots[index].view;
        let flag = if sending {
            &view.native_send_end
        } else {
            &view.native_receive_end
        };
        // These are physical direction facts, never acceptance or drain proof.
        // A stronger abnormal observation cannot be weakened by a later hint.
        flag.fetch_max(if normal { 1 } else { 2 }, Ordering::AcqRel);
        self.apply_native_hints(index)
    }
    fn apply_native_hints(&mut self, index: usize) -> Result<()> {
        if !self.engine.streams.slots[index].accepted() {
            return Ok(());
        }
        let now = self.engine.account.security_time()?.monotonic_sample;
        let role = usize::from(self.engine.role);
        let send_hint = self.engine.streams.slots[index]
            .view
            .native_send_end
            .load(Ordering::Acquire);
        let read_hint = self.engine.streams.slots[index]
            .view
            .native_receive_end
            .load(Ordering::Acquire);
        if send_hint != 0 {
            let fin_submitted = self.engine.streams.slots[index]
                .view
                .fin_submitted
                .load(Ordering::Acquire);
            let direction = &mut self.engine.streams.slots[index].directions[role];
            if !direction.complete() {
                direction.stop = true;
                if !fin_submitted {
                    direction.stopped_requested = true;
                }
                if direction.terminal.is_none() {
                    direction.terminal = Some(direction.current);
                }
                direction.begin(now, send_hint == 2)?;
            }
        }
        if read_hint != 0 {
            let direction = &mut self.engine.streams.slots[index].directions[1 - role];
            if !direction.complete() {
                direction.begin(now, read_hint == 2)?;
                if read_hint == 2 {
                    direction.stop = true;
                    direction.disabled = true;
                    direction.fin = false;
                }
            }
            if read_hint == 2 {
                self.engine.streams.slots[index]
                    .view
                    .receive_disabled
                    .store(true, Ordering::Release);
                for key in &mut self.engine.keys {
                    if key.scope == self.engine.streams.slots[index].scope
                        && key.direction == (1 - role) as u8
                    {
                        key.disabled = true;
                    }
                }
                if let Some(candidate) = &mut self.engine.candidate {
                    for key in &mut candidate.keys {
                        if key.scope == self.engine.streams.slots[index].scope
                            && key.direction == (1 - role) as u8
                        {
                            key.disabled = true;
                        }
                    }
                }
                self.engine.streams.release_queue(index);
            }
        }
        Ok(())
    }
    pub(crate) fn native_projection(
        &mut self,
        handle: &StreamHandle,
    ) -> Result<session::NativeStreamProjection> {
        self.check()?;
        if self.phase(handle)? == StreamPhase::Stable {
            let rejected = handle.view.rejected.load(Ordering::Acquire);
            let normal_read = rejected || handle.view.normal_drained.load(Ordering::Acquire);
            let send_end = handle.view.send_end.load(Ordering::Acquire);
            return Ok(session::NativeStreamProjection {
                accepted: !rejected,
                retired: true,
                close_write: rejected || handle.view.fin_submitted.load(Ordering::Acquire),
                reset_write: !rejected && send_end == 2,
                stop_read: true,
                normal_read,
            });
        }
        let index = self.engine.streams.resolve(handle)?;
        self.apply_native_hints(index)?;
        let slot = &self.engine.streams.slots[index];
        let send = slot.directions[usize::from(self.engine.role)];
        let receive = slot.directions[usize::from(1 - self.engine.role)];
        let rejected = matches!(slot.outcome, Some(OpenDecision::Reject(_)));
        let normal_read = rejected
            || receive.drain_sent
                && receive
                    .proof
                    .is_some_and(|proof| !proof.aborted && proof.observed == proof.terminal)
                && receive.terminal == receive.proof.map(|proof| proof.terminal);
        Ok(session::NativeStreamProjection {
            accepted: slot.accepted() && slot.prefix,
            retired: false,
            // Sealing FIN only stages its authenticated record. The native
            // writer must stay open until the provider accepts that record.
            close_write: rejected || handle.view.fin_submitted.load(Ordering::Acquire),
            reset_write: !rejected
                && send.stopped_sent
                && !handle.view.fin_submitted.load(Ordering::Acquire),
            stop_read: normal_read || receive.disabled || receive.quarantined,
            normal_read,
        })
    }
    /// The native input owner retains this original authenticated association.
    /// Shared carrier input always uses receive and cannot project a bad tag
    /// onto a Stream merely by inspecting its unauthenticated header.
    #[cfg(test)]
    pub(crate) fn receive_bound(&mut self, handle: &StreamHandle, wire: &[u8]) -> Result<()> {
        self.check()?;
        let i = self.engine.streams.resolve(handle)?;
        let slot = &self.engine.streams.slots[i];
        if !slot.accepted() || !slot.prefix {
            return Err(CryptoError::State);
        }
        if wire.len() < 44 || wire[4] != 8 || wire[12..20] != handle.scope().to_be_bytes() {
            self.reset_index(i, true)?;
            return Err(CryptoError::Authentication);
        }
        self.receive_input(handle.scope(), wire, Some(handle))
    }
    #[cfg(test)]
    fn receive_input(
        &mut self,
        scope: u64,
        wire: &[u8],
        bound: Option<&StreamHandle>,
    ) -> Result<()> {
        let lease = self.engine.streams.input_pool.acquire(scope == 0)?;
        let Some(mut input) = self.prepare_receive_input(scope, wire, bound, lease)? else {
            return Ok(());
        };
        let opened = input.execute(wire);
        self.finish_receive_input(input, wire, opened).map(|_| ())
    }
    /// Headers here can only reject a direction already permanently closed by
    /// its original owner or authenticated terminal evidence. They never bind
    /// a scope, select a key, or advance a protocol frontier.
    fn reject_closed_data(
        &mut self,
        scope: u64,
        wire: &[u8],
        header: Tuple,
        shared: bool,
    ) -> Result<bool> {
        if wire.get(4) != Some(&8) {
            return Ok(false);
        }
        let known = self.engine.streams.index(scope);
        let terminal = match known {
            Some(index) => {
                let slot = &self.engine.streams.slots[index];
                let direction = slot.directions[usize::from(1 - self.engine.role)];
                // Shared input needs its own authenticated-error fence or
                // actual terminal evidence. An ordinary Reset/quarantine is
                // still responsible for its previously promised input.
                direction.complete()
                    || direction.first_error.is_some()
                        && slot.view.receive_disabled.load(Ordering::Acquire)
                    || !shared
                        && (direction.disabled
                            || slot.view.receive_disabled.load(Ordering::Acquire))
                    || direction.fin && direction.terminal.is_some()
            }
            // Collected scopes must have real retirement evidence. The
            // Session's consecutive installed roots 0..current supply only a
            // bounded rejection range; no retired key is selected or revived.
            None => self.engine.streams.authenticated_stable(scope)?,
        };
        if !terminal {
            return Ok(false);
        }
        if wire.len() < 44
            || wire.len() > self.engine.max_frame + 8
            || wire[5..8] != [0, 0, 0]
            || wire[12..20] != scope.to_be_bytes()
            || u32::from_be_bytes(
                wire[..4]
                    .try_into()
                    .map_err(|_| CryptoError::Authentication)?,
            ) as usize
                != wire.len() - 8
            || header.epoch > self.engine.epoch
            || known.is_some_and(|index| {
                header.epoch
                    < self.engine.streams.slots[index].directions[usize::from(1 - self.engine.role)]
                        .initial_epoch
            })
        {
            return Err(CryptoError::Authentication);
        }
        if shared {
            let now = self.engine.account.security_time()?.monotonic_sample;
            self.engine.streams.shared_discard.reject(now, wire.len())?;
        }
        Ok(true)
    }
    pub(crate) fn prepare_receive_input(
        &mut self,
        scope: u64,
        wire: &[u8],
        bound: Option<&StreamHandle>,
        lease: ReceiveLease,
    ) -> Result<Option<ReceiveInput>> {
        self.check()?;
        if let Some(handle) = bound {
            let i = self.engine.streams.resolve(handle)?;
            let slot = &self.engine.streams.slots[i];
            if !slot.accepted() || !slot.prefix {
                return Err(CryptoError::State);
            }
            if wire.len() < 44 || wire[4] != 8 || wire[12..20] != handle.scope().to_be_bytes() {
                self.isolate_input_error(i, CryptoError::Authentication)?;
                return Err(CryptoError::Authentication);
            }
        }
        if wire.get(4) == Some(&6) {
            let expected = self.engine.expected_phase(wire)?;
            let marker = expected >= 3 && wire[8..12] == (self.engine.epoch + 1).to_be_bytes();
            let ticket = self.engine.prepare_open(0, wire, marker)?;
            return Ok(Some(ReceiveInput {
                ticket,
                lease,
                scope,
                header: record_header(wire)?,
                frame: 6,
                known: false,
                accepted: false,
                bound: false,
                rekey: Some((expected, marker)),
                rekey_authentication: self
                    .engine
                    .deferred_crypto
                    .then(|| self.engine.rekey_authentication(expected, marker))
                    .transpose()?,
                digest_context: (self.engine.hash, self.engine.profile, 1 - self.engine.role),
                stream_digest: None,
            }));
        }
        let header = match record_header(wire) {
            Ok(header) => header,
            Err(error) => {
                self.engine.fail();
                return Err(error);
            }
        };
        let frame = wire[4];
        let known = self.engine.streams.index(scope);
        if (scope != 0 && !State::valid(scope)) || (scope == 0 && matches!(frame, 7 | 8)) {
            self.engine.fail();
            return Err(CryptoError::Authentication);
        }
        if frame == 8 {
            match self.reject_closed_data(scope, wire, header, bound.is_none()) {
                Ok(true) => return Ok(None),
                Ok(false) => {}
                Err(cause) => {
                    self.engine.fail();
                    return Err(cause);
                }
            }
        }
        let new_open = frame == 7 && known.is_none();
        if new_open {
            if self.engine.streams.used(scope)?
                || State::opener(scope) != 1 - self.engine.role
                || header.epoch != self.engine.epoch
                || header.next != 0
            {
                self.engine.fail();
                return Err(CryptoError::Authentication);
            }
            if let Err(e) = self.engine.install(scope) {
                self.engine.fail();
                return Err(e);
            }
        }
        let ticket = match self.engine.prepare_open(scope, wire, false) {
            Ok(ticket) => ticket,
            Err(error) => {
                if frame == 8
                    && bound.is_some()
                    && known.is_some_and(|i| self.engine.streams.slots[i].accepted())
                    && !matches!(error, CryptoError::Authorization(_) | CryptoError::Deadline)
                {
                    self.isolate_input_error(known.expect("known accepted scope"), error)?;
                } else {
                    self.engine.fail();
                }
                return Err(error);
            }
        };
        Ok(Some(ReceiveInput {
            ticket,
            lease,
            scope,
            header,
            frame,
            known: known.is_some(),
            accepted: known.is_some_and(|index| {
                let slot = &self.engine.streams.slots[index];
                slot.accepted() && slot.prefix
            }),
            bound: bound.is_some(),
            rekey: None,
            rekey_authentication: None,
            digest_context: (self.engine.hash, self.engine.profile, 1 - self.engine.role),
            stream_digest: None,
        }))
    }
    pub(crate) fn finish_receive_input(
        &mut self,
        input: ReceiveInput,
        wire: &[u8],
        opened: Result<usize>,
    ) -> Result<ReceiveDisposition> {
        let ReceiveInput {
            ticket,
            lease,
            scope,
            header,
            frame,
            known,
            accepted,
            bound,
            rekey,
            rekey_authentication: _authentication,
            digest_context: _,
            stream_digest,
        } = input;
        // A permanent direction fence may win while AEAD is outside the
        // gate. Its late completion cannot deliver or reopen the direction.
        if !bound && frame == 8 && accepted && matches!(opened, Ok(_) | Err(CryptoError::State)) {
            self.check()?;
            match self.reject_closed_data(scope, wire, header, true) {
                Ok(true) => return Ok(ReceiveDisposition::Discarded { scope }),
                Ok(false) => {}
                Err(cause) => {
                    self.engine.fail();
                    return Err(cause);
                }
            }
        }
        let plain = &lease.bytes;
        let mut authenticated = false;
        let mut semantic_failure = false;
        let result = opened.and_then(|n| {
            if let Some((expected, marker)) = rekey {
                return self
                    .engine
                    .commit_rekey(&ticket, wire, &plain[..n], expected, marker);
            }
            self.engine
                .commit_open(&ticket, frame, &plain[..n], |engine, kind, body| {
                    authenticated = true;
                    let result =
                        engine.validate_stream_input(scope, header, kind, body, stream_digest);
                    semantic_failure = result.as_ref().err().is_some_and(|cause| {
                        matches!(
                            cause,
                            CryptoError::Authentication
                                | CryptoError::Capacity
                                | CryptoError::Configuration
                                | CryptoError::Sequence
                        )
                    });
                    result
                })?;
            self.apply_input(scope, header, frame, &plain[..n], stream_digest)
        });
        if let Err(error) = &result {
            self.engine.disable_open(&ticket);
            let known = known.then(|| self.engine.streams.index(scope)).flatten();
            if frame == 8
                && (bound || accepted && authenticated && semantic_failure)
                && known.is_some_and(|i| {
                    self.engine.streams.slots[i].accepted() && self.engine.streams.slots[i].prefix
                })
                && !matches!(error, CryptoError::Authorization(_) | CryptoError::Deadline)
            {
                let index = known.expect("known accepted scope");
                self.isolate_input_error(index, *error)?;
                if !bound {
                    self.check()?;
                    return Ok(ReceiveDisposition::Isolated { scope });
                }
            } else {
                self.engine.fail();
            }
        }
        if result.is_ok() && !self.engine.closed {
            self.check()?;
            let now = self.engine.account.security_time()?;
            if rekey.is_some() && self.engine.rekey.busy() {
                self.engine
                    .streams
                    .controls
                    .interrupt(ProbeOutcome::RekeyInProgress, Some(now));
            }
            self.engine.streams.controls.activity(now)?;
        }
        result.map(|()| ReceiveDisposition::Applied)
    }
    fn apply_input(
        &mut self,
        scope: u64,
        header: Tuple,
        frame: u8,
        body: &[u8],
        digest: Option<[u8; 32]>,
    ) -> Result<()> {
        let now = self.engine.account.security_time()?.monotonic_sample;
        let role = usize::from(self.engine.role);
        let peer = 1 - role;
        if matches!(frame, 12..=15) {
            return self.apply_control(header, frame, body);
        }
        if frame == 7 {
            let v = decode(
                body,
                "OPEN_STREAM",
                self.engine.max_frame,
                Context::default(),
            )?;
            let digest = v.b("OPEN_STREAM", "open_digest")?;
            if let Some(i) = self.engine.streams.index(scope) {
                let s = &mut self.engine.streams.slots[i];
                s.prefix = true;
                s.open_epoch = header.epoch;
                s.open_digest = digest;
                s.open_digest_ready = true;
                s.directions[peer].current = Tuple {
                    epoch: header.epoch,
                    next: 1,
                    offset: 0,
                };
                s.directions[peer].last = s.directions[peer].current;
                return Ok(());
            }
            let kind = v.field("OPEN_STREAM", "kind")?.text()?;
            let metadata = v.field("OPEN_STREAM", "metadata")?.bytes()?;
            let peer_limit = v.u("OPEN_STREAM", "initial_receive_limit")?;
            let state = &mut self.engine.streams;
            let class = state.class(kind, peer as u8).unwrap_or(Class::Business);
            state.count_lifetime(peer as u8, class)?;
            let full = state
                .slots
                .iter()
                .filter(|s| s.phase == Phase::Pending && s.forced_rejection.is_none())
                .count()
                >= INGRESS
                || metadata.len() > 512 * 1024 - state.ingress_bytes;
            let token = if full {
                state.take_token(true)?
            } else {
                Token::None
            };
            let mut slot = state.slot(SlotSeed {
                scope,
                opener: peer as u8,
                kind,
                metadata: if full { &[] } else { metadata },
                local_window: 0,
                peer_window: peer_limit,
                epoch: header.epoch,
                token,
                bootstrap: false,
            })?;
            slot.open_digest = digest;
            slot.open_digest_ready = true;
            slot.prefix = true;
            slot.directions[peer].current.next = 1;
            slot.directions[peer].last = slot.directions[peer].current;
            if full {
                slot.forced_rejection = Some(Rejection::Resource)
            }
            if state.draining {
                slot.forced_rejection = Some(Rejection::Draining);
            }
            state.ingress_bytes += slot.metadata.len();
            slot.barrier_refs = self.engine.incoming_barrier_refs(scope);
            self.engine.streams.slots.push(slot);
            if self.engine.candidate.is_some() {
                self.engine.charge_keys(2)?;
                for direction in 0..2 {
                    let candidate = self.engine.candidate.as_ref().ok_or(CryptoError::State)?;
                    let key = self.engine.record_material(
                        &candidate.root,
                        self.engine.epoch + 1,
                        scope,
                        direction,
                    )?;
                    self.engine
                        .candidate
                        .as_mut()
                        .ok_or(CryptoError::State)?
                        .keys
                        .push(RecordKey {
                            scope,
                            direction,
                            key,
                            order: self
                                .engine
                                .keys
                                .iter()
                                .find(|key| key.scope == scope && key.direction == direction)
                                .ok_or(CryptoError::State)?
                                .order
                                .clone(),
                            next: 0,
                            disabled: false,
                            usage: Usage::default(),
                        });
                }
            }
            return Ok(());
        }
        if frame == 8 {
            let v = decode(
                body,
                "STREAM_DATA",
                self.engine.max_frame,
                Context::default(),
            )?;
            let data = v.field("STREAM_DATA", "data")?.bytes()?;
            let fin = v.field("STREAM_DATA", "fin")?.boolean()?;
            let i = self.engine.streams.index(scope).ok_or(CryptoError::State)?;
            let s = &mut self.engine.streams.slots[i];
            let d = &mut s.directions[peer];
            d.current = Tuple {
                epoch: header.epoch,
                next: header.next + 1,
                offset: d.current.offset + data.len() as u64,
            };
            d.last = d.current;
            d.ack = d.current.offset;
            s.credit_dirty = true;
            if d.stop {
                d.released += data.len() as u64;
                self.engine.streams.promised -= data.len() as u64;
            } else {
                if s.queue.is_empty() && !data.is_empty() {
                    s.receive_progress = Some(now);
                }
                s.queue.extend(data);
            }
            if fin {
                d.terminal = Some(d.current);
                d.fin = !d.stop;
                s.view
                    .end
                    .store(if d.fin { 1 } else { 2 }, Ordering::Release);
                d.begin(now, false)?;
                let final_offset = d.current.offset;
                self.engine.streams.trim_promise(i, final_offset)?;
            }
            return Ok(());
        }
        let name = control_schema(body)?;
        let v = decode(body, name, self.engine.max_frame, Context::default())?;
        if name == "STREAM_ACK_RETIRE_BATCH" || name == "STREAM_ACK_RETIRE_ACK" {
            return self.apply_retirement(v, name, digest, now);
        }
        let target = v.u(name, "stream_id")?;
        let Some(i) = self.engine.streams.index(target) else {
            return Ok(());
        };
        if self.engine.streams.slots[i].phase == Phase::Held {
            return Ok(());
        }
        if name == "OPEN_ACCEPT" {
            if self.engine.streams.slots[i].phase != Phase::Opening {
                return Ok(());
            }
            let decision = open_decision(v)?;
            self.engine.streams.slots[i].outcome = Some(decision);
            if matches!(decision, OpenDecision::Reject(_)) {
                return self.rejected(i);
            }
            let s = &mut self.engine.streams.slots[i];
            s.phase = Phase::Accepted;
            s.opening_deadline = None;
            s.directions[role].limit = v.u(name, "initial_receive_limit")?;
            s.directions[role].committed_limit = s.directions[role].limit;
            self.engine.streams.controls.highest_accepted[role] =
                self.engine.streams.controls.highest_accepted[role].max(s.scope);
            if s.cancel {
                self.reset_index(i, false)?;
            }
            return Ok(());
        }
        match name {
            "STREAM_ACK_CREDIT" => {
                let d = &mut self.engine.streams.slots[i].directions[role];
                let ack = v.u(name, "ack_offset")?;
                let limit = v.u(name, "receive_limit")?;
                if ack <= d.ack && limit <= d.limit {
                    return Ok(());
                }
                d.ack = ack;
                if !d.stop && d.terminal.is_none() {
                    d.limit = limit;
                    d.committed_limit = limit;
                }
                if self.engine.streams.slots[i].send_progress.is_some() {
                    self.engine.streams.slots[i].send_progress = Some(now);
                }
                self.engine.streams.slots[i]
                    .view
                    .authenticated
                    .store(ack, Ordering::Release);
            }
            "STREAM_ACK_STOP" => {
                let d = &mut self.engine.streams.slots[i].directions[role];
                d.stop = true;
                d.stopped_requested = true;
                d.stopped_sent = false;
                if d.terminal.is_none() {
                    d.terminal = Some(d.current)
                }
                if !d.fin {
                    d.begin(now, false)?;
                }
            }
            "STREAM_ACK_STOPPED" => {
                let final_tuple = Tuple {
                    epoch: v.u(name, "final_epoch")? as u32,
                    next: v.u(name, "final_next_sequence")?,
                    offset: v.u(name, "final_offset")?,
                };
                let d = &mut self.engine.streams.slots[i].directions[peer];
                d.terminal = Some(final_tuple);
                if !d.stop || d.fin {
                    self.engine.streams.slots[i]
                        .view
                        .end
                        .store(2, Ordering::Release);
                    let d = &mut self.engine.streams.slots[i].directions[peer];
                    d.stop = true;
                    d.fin = false;
                    d.begin(now, false)?;
                    self.engine.streams.release_queue(i);
                }
                self.engine.streams.trim_promise(i, final_tuple.offset)?;
            }
            "STREAM_ACK_DRAINED" => {
                let proof = DrainProof {
                    terminal: tuple_value(v.field(name, "terminal_tuple")?)?,
                    observed: tuple_value(v.field(name, "observed_tuple")?)?,
                    aborted: v.u(name, "outcome")? == 1,
                };
                if proof.aborted {
                    self.engine.streams.slots[i]
                        .view
                        .send_aborted
                        .store(true, Ordering::Release);
                }
                let d = &mut self.engine.streams.slots[i].directions[role];
                d.proof = Some(proof);
                d.deadline = None;
                if !proof.aborted {
                    d.ack = d.ack.max(proof.terminal.offset)
                }
                let send_end = if d.fin && !proof.aborted { 1 } else { 2 };
                let authenticated = d.ack;
                self.engine.streams.slots[i]
                    .view
                    .send_end
                    .store(send_end, Ordering::Release);
                self.engine.streams.slots[i]
                    .view
                    .authenticated
                    .store(authenticated, Ordering::Release);
                self.engine.streams.recent(i, now);
                self.retire_keys();
            }
            _ => return Err(CryptoError::Authentication),
        }
        Ok(())
    }
    fn apply_retirement(
        &mut self,
        v: Value<'_>,
        name: &str,
        digest: Option<[u8; 32]>,
        now: Instant,
    ) -> Result<()> {
        let seq = v.u(name, "batch_seq")?;
        if name == "STREAM_ACK_RETIRE_ACK" {
            if seq <= self.engine.streams.last_out {
                return Ok(());
            }
            let batch = self
                .engine
                .streams
                .outgoing
                .take()
                .ok_or(CryptoError::State)?;
            self.engine.streams.last_out = batch.sequence;
            self.engine.streams.last_out_digest = batch.digest;
            self.make_stable(&batch.ids)?;
            return Ok(());
        }
        if seq < self.engine.streams.last_in {
            return Ok(());
        }
        if seq == self.engine.streams.last_in {
            self.engine.streams.repeat_ack = true;
            return Ok(());
        }
        if self.engine.streams.incoming.is_some() {
            return Ok(());
        }
        let mut ids = Vec::new();
        ids.try_reserve_exact(BATCH)
            .map_err(|_| CryptoError::Capacity)?;
        for id in v.field(name, "scope_ids")?.children()? {
            let scope = id?.uint()?;
            let i = self.engine.streams.index(scope).ok_or(CryptoError::State)?;
            self.engine.streams.slots[i].batch_refs += 1;
            ids.push(scope)
        }
        self.engine.streams.incoming = Some(BatchState {
            sequence: seq,
            digest: digest.ok_or(CryptoError::Authentication)?,
            digest_ready: true,
            ids,
            deadline: now + Duration::from_secs(90),
            submitted: true,
        });
        Ok(())
    }
    fn make_stable(&mut self, ids: &[u64]) -> Result<()> {
        // Preflight the entire authenticated retirement commit before
        // recording any historical input entitlement or releasing a slot.
        for scope in ids {
            let index = self
                .engine
                .streams
                .index(*scope)
                .ok_or(CryptoError::State)?;
            let slot = &self.engine.streams.slots[index];
            if slot.phase != Phase::Recent
                || !slot.prefix
                || !slot.open_digest_ready
                || !slot.directions.iter().all(Direction::complete)
                || slot.batch_refs == 0
            {
                return Err(CryptoError::State);
            }
        }
        for scope in ids {
            let (byte, bit) = State::bit(*scope)?;
            self.engine.streams.authenticated_stable[byte] |= bit;
            let i = self
                .engine
                .streams
                .index(*scope)
                .ok_or(CryptoError::State)?;
            let s = &mut self.engine.streams.slots[i];
            s.phase = Phase::Held;
            s.batch_refs -= 1;
        }
        self.engine.streams.collect();
        self.retire_keys();
        Ok(())
    }
}
impl ReliableSession {
    fn basic_control(&self, variant: u64, scope: u64, direction: u8) -> Result<Vec<u8>> {
        let mut out = map(3, 128)?;
        for (k, v) in [(0, variant), (1, scope), (2, u64::from(direction))] {
            uint(&mut out, k);
            uint(&mut out, v)
        }
        Ok(out)
    }
    fn update_quarantine(&mut self) -> Result<()> {
        let now = self.engine.account.security_time()?.monotonic_sample;
        let peer = usize::from(1 - self.engine.role);
        for i in 0..self.engine.streams.slots.len() {
            for direction in 0..2 {
                let d = &mut self.engine.streams.slots[i].directions[direction];
                if !d.complete() && d.normal_deadline.is_some_and(|deadline| now >= deadline) {
                    d.begin(now, true)?;
                    if direction == peer {
                        d.stop = true;
                        d.fin = false;
                        d.disabled = true;
                        self.engine.streams.slots[i]
                            .view
                            .receive_disabled
                            .store(true, Ordering::Release);
                        self.engine.streams.slots[i]
                            .view
                            .end
                            .store(2, Ordering::Release);
                        self.engine.streams.release_queue(i);
                    }
                }
            }
        }
        let count = self
            .engine
            .streams
            .slots
            .iter()
            .flat_map(|s| &s.directions)
            .filter(|d| d.quarantined && !d.complete())
            .count();
        if count > 32 {
            return Err(CryptoError::Capacity);
        }
        for key in &mut self.engine.keys {
            if self.engine.streams.index(key.scope).is_some_and(|i| {
                self.engine.streams.slots[i].directions[usize::from(key.direction)].disabled
            }) {
                key.disabled = true;
            }
        }
        if let Some(candidate) = &mut self.engine.candidate {
            for key in &mut candidate.keys {
                if self.engine.streams.index(key.scope).is_some_and(|i| {
                    self.engine.streams.slots[i].directions[usize::from(key.direction)].disabled
                }) {
                    key.disabled = true;
                }
            }
        }
        Ok(())
    }
    fn poll_terminal(&mut self, publisher: &mut dyn RecordPublisher) -> Result<bool> {
        let role = usize::from(self.engine.role);
        let peer = 1 - role;
        for i in 0..self.engine.streams.slots.len() {
            if !self.engine.streams.slots[i].accepted() {
                continue;
            }
            let scope = self.engine.streams.slots[i].scope;
            let send = self.engine.streams.slots[i].directions[role];
            let receive = self.engine.streams.slots[i].directions[peer];
            if send.fin_requested && send.terminal.is_none() && !send.stop && !self.engine.frozen {
                let handle = self.engine.streams.handle(scope);
                self.write(&handle, &[], true, publisher)?;
                return Ok(true);
            }
            if receive.stop && !receive.stop_sent && receive.terminal.is_none() {
                let body = self.basic_control(2, scope, peer as u8)?;
                self.engine.streams.slots[i].directions[peer].stop_sent = true;
                self.send(0, 9, &body, true, publisher)?;
                return Ok(true);
            }
            if let Some(final_tuple) = send.terminal
                && (!send.fin || send.stopped_requested)
                && !send.stopped_sent
            {
                let mut body = self.basic_control(3, scope, role as u8)?;
                body[0] = 0xa6;
                for (k, v) in [
                    (3, u64::from(final_tuple.epoch)),
                    (4, final_tuple.next),
                    (5, final_tuple.offset),
                ] {
                    uint(&mut body, k);
                    uint(&mut body, v)
                }
                self.engine.streams.slots[i].directions[role].stopped_sent = true;
                self.send(0, 9, &body, true, publisher)?;
                return Ok(true);
            }
            if let Some(final_tuple) = receive.terminal
                && !receive.drain_sent
            {
                let observed = receive.in_epoch(final_tuple.epoch)?;
                let aborted =
                    observed != final_tuple || receive.disabled || (receive.stop && !receive.fin);
                if observed != final_tuple && !receive.quarantined && !receive.disabled {
                    continue;
                }
                if aborted
                    && (!self.engine.streams.slots[i].prefix
                        || !self.engine.streams.slots[i].accepted())
                {
                    continue;
                }
                let proof = DrainProof {
                    terminal: final_tuple,
                    observed,
                    aborted,
                };
                let mut body = self.basic_control(4, scope, peer as u8)?;
                body[0] = 0xa6;
                uint(&mut body, 3);
                tuple(&mut body, final_tuple);
                uint(&mut body, 4);
                uint(&mut body, u64::from(aborted));
                uint(&mut body, 5);
                tuple(&mut body, observed);
                if aborted {
                    self.engine.streams.slots[i]
                        .view
                        .receive_disabled
                        .store(true, Ordering::Release);
                }
                let d = &mut self.engine.streams.slots[i].directions[peer];
                d.proof = Some(proof);
                d.drain_sent = true;
                d.deadline = None;
                if aborted {
                    d.disabled = true;
                    d.committed_limit = d.released;
                    self.engine.streams.promised -= d.limit - d.released;
                    d.limit = d.released;
                }
                self.engine
                    .streams
                    .recent(i, self.engine.account.security_time()?.monotonic_sample);
                self.retire_keys();
                self.send(0, 9, &body, true, publisher)?;
                if !aborted {
                    self.engine.streams.slots[i]
                        .view
                        .normal_drained
                        .store(true, Ordering::Release);
                }
                self.engine.streams.discard_backing(i);
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn poll_credit(&mut self, publisher: &mut dyn RecordPublisher) -> Result<bool> {
        let peer = usize::from(1 - self.engine.role);
        for i in 0..self.engine.streams.slots.len() {
            let s = &self.engine.streams.slots[i];
            let d = s.directions[peer];
            if !s.credit_dirty || !s.accepted() || d.stop || d.terminal.is_some() {
                continue;
            }
            let mut body = self.basic_control(0, s.scope, peer as u8)?;
            body[0] = 0xa5;
            uint(&mut body, 3);
            uint(&mut body, d.ack);
            uint(&mut body, 4);
            uint(&mut body, d.limit);
            self.engine.streams.slots[i].credit_dirty = false;
            self.send(0, 9, &body, false, publisher)?;
            self.engine.streams.slots[i].directions[peer].committed_limit = d.limit;
            return Ok(true);
        }
        Ok(false)
    }
    fn retire_ack_body(sequence: u64, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let mut body = map(3, 64)?;
        uint(&mut body, 0);
        uint(&mut body, 6);
        uint(&mut body, 1);
        uint(&mut body, sequence);
        uint(&mut body, 2);
        bytes(&mut body, digest);
        Ok(body)
    }
    fn poll_retirement(&mut self, publisher: &mut dyn RecordPublisher) -> Result<bool> {
        if self.engine.streams.repeat_ack {
            let body = Self::retire_ack_body(
                self.engine.streams.last_in,
                &self.engine.streams.last_in_digest,
            )?;
            self.engine.streams.repeat_ack = false;
            self.send(0, 9, &body, false, publisher)?;
            return Ok(true);
        }
        if let Some(batch) = &self.engine.streams.incoming {
            if batch.ids.iter().any(|id| {
                self.engine
                    .streams
                    .index(*id)
                    .is_some_and(|i| self.engine.streams.slots[i].unpublished != 0)
            }) {
                return Ok(false);
            }
            let body = Self::retire_ack_body(batch.sequence, &batch.digest)?;
            let batch = self
                .engine
                .streams
                .incoming
                .take()
                .ok_or(CryptoError::State)?;
            // Actual synchronous publication retains this local batch until the
            // publisher exits. No second batch can borrow the still-live tail.
            self.send(0, 9, &body, false, publisher)?;
            self.engine.streams.last_in = batch.sequence;
            self.engine.streams.last_in_digest = batch.digest;
            self.make_stable(&batch.ids)?;
            return Ok(true);
        }
        if self.engine.streams.outgoing.is_some() {
            return Ok(false);
        }
        let now = self.engine.account.security_time()?.monotonic_sample;
        let opening = self
            .engine
            .streams
            .slots
            .iter()
            .any(|s| s.phase == Phase::Opening);
        let mut ids = Vec::new();
        ids.try_reserve_exact(BATCH)
            .map_err(|_| CryptoError::Capacity)?;
        for slot in &self.engine.streams.slots {
            if slot.phase == Phase::Recent
                && slot.opener == self.engine.role
                && slot.unpublished == 0
                && (opening
                    || slot
                        .recent_at
                        .is_some_and(|t| now.duration_since(t) >= Duration::from_millis(50)))
            {
                ids.push(slot.scope);
                if ids.len() == BATCH {
                    break;
                }
            }
        }
        if ids.is_empty() {
            return Ok(false);
        }
        ids.sort_unstable();
        let sequence = self
            .engine
            .streams
            .last_out
            .checked_add(1)
            .ok_or(CryptoError::Capacity)?;
        let mut body = map(3, 32 + 9 * ids.len())?;
        uint(&mut body, 0);
        uint(&mut body, 5);
        uint(&mut body, 1);
        uint(&mut body, sequence);
        uint(&mut body, 2);
        codec::encode_head(&mut body, 4, ids.len() as u64);
        for id in &ids {
            uint(&mut body, *id)
        }
        if body.len() + 36 > self.engine.max_frame {
            return Err(CryptoError::Capacity);
        }
        let digest = if self.engine.deferred_crypto {
            [0; 32]
        } else {
            retirement_digest(
                &self.engine.hash,
                self.engine.profile,
                self.engine.role,
                &body,
            )
        };
        for scope in &ids {
            let i = self
                .engine
                .streams
                .index(*scope)
                .ok_or(CryptoError::State)?;
            self.engine.streams.slots[i].batch_refs += 1;
        }
        self.engine.streams.outgoing = Some(BatchState {
            sequence,
            digest,
            digest_ready: !self.engine.deferred_crypto,
            ids,
            deadline: now + Duration::from_secs(90),
            submitted: true,
        });
        self.send(0, 9, &body, false, publisher)?;
        Ok(true)
    }
    /// One bounded maintenance quantum. The carrier scheduler polls again on
    /// actual input, application release and the retained original deadlines.
    pub(crate) fn poll(&mut self, publisher: &mut dyn RecordPublisher) -> Result<bool> {
        let result = (|| {
            self.check()?;
            self.observe_liveness_provider(publisher);
            let progress = self.poll_lifecycle_deadlines()?;
            if self.engine.closed {
                return Ok(true);
            }
            self.poll_slow_consumers()?;
            self.update_quarantine()?;
            if self.poll_terminal(publisher)? {
                return Ok(true);
            }
            if let Some((scope, reason)) = self
                .engine
                .streams
                .slots
                .iter()
                .find_map(|s| s.forced_rejection.map(|r| (s.scope, r)))
            {
                self.decide_open(
                    &self.engine.streams.handle(scope),
                    OpenDecision::Reject(reason),
                    publisher,
                )?;
                return Ok(true);
            }
            if self.engine.poll_rekey(publisher)? {
                if self.engine.rekey.busy() {
                    self.engine.streams.controls.interrupt(
                        ProbeOutcome::RekeyInProgress,
                        Some(self.engine.account.security_time()?),
                    );
                }
                return Ok(true);
            }
            if self.poll_session_control(publisher)? {
                return Ok(true);
            }
            if self.poll_retirement(publisher)? {
                return Ok(true);
            }
            Ok(self.poll_credit(publisher)? || progress)
        })();
        if result.is_err() {
            self.engine.fail()
        }
        result
    }
    pub(crate) fn rekey(&mut self, publisher: &mut dyn RecordPublisher) -> Result<bool> {
        self.check()?;
        self.engine.streams.controls.interrupt(
            ProbeOutcome::RekeyInProgress,
            Some(self.engine.account.security_time()?),
        );
        self.engine.request_rekey(publisher)
    }
    pub(crate) fn phase(&self, handle: &StreamHandle) -> Result<StreamPhase> {
        self.engine.check()?;
        if handle.owner != self.engine.streams.owner {
            return Err(CryptoError::State);
        }
        let Some(i) = self.engine.streams.index(handle.scope) else {
            return if self.engine.streams.used(handle.scope)? {
                Ok(StreamPhase::Stable)
            } else {
                Err(CryptoError::State)
            };
        };
        Ok(match self.engine.streams.slots[i].phase {
            Phase::Opening => StreamPhase::Opening,
            Phase::Pending => StreamPhase::Pending,
            Phase::Accepted => StreamPhase::Accepted,
            Phase::Recent => StreamPhase::Recent,
            Phase::Held => StreamPhase::Stable,
        })
    }
    pub(crate) fn management_retired(&self, handle: &StreamHandle) -> Result<bool> {
        self.engine.check()?;
        if handle.owner != self.engine.streams.owner {
            return Err(CryptoError::State);
        }
        // Stable public state can still retain a barrier or retirement-batch
        // proof. A replacement M waits until that actual slot is collected.
        Ok(self.engine.streams.index(handle.scope).is_none()
            && self.engine.streams.used(handle.scope)?)
    }
    pub(crate) fn management_allocations_exhausted(&self) -> bool {
        self.engine
            .streams
            .check_lifetime(0, Class::Management)
            .is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_v4::tests::record_pair_for_limits;
    #[derive(Default)]
    struct Writer(VecDeque<Vec<u8>>);
    impl RecordPublisher for Writer {
        fn publish(&mut self, wire: &[u8]) -> Result<()> {
            self.0.push_back(wire.to_vec());
            Ok(())
        }
    }
    fn deliver(writer: &mut Writer, receiver: &mut ReliableSession) {
        while let Some(wire) = writer.0.pop_front() {
            let scope = u64::from_be_bytes(wire[12..20].try_into().unwrap());
            receiver.receive(scope, &wire).unwrap();
        }
    }
    fn pump(client: &mut ReliableSession, server: &mut ReliableSession) {
        let mut c = Writer::default();
        let mut s = Writer::default();
        for _ in 0..40 {
            // Tests that inspect terminal tuples control timed retirement
            // explicitly. Parallel scheduler delays must not retire them.
            for session in [&mut *client, &mut *server] {
                for slot in &mut session.engine.streams.slots {
                    slot.recent_at = None;
                }
            }
            let cp = client.poll(&mut c).unwrap();
            deliver(&mut c, server);
            let sp = server.poll(&mut s).unwrap();
            deliver(&mut s, client);
            if !cp && !sp {
                return;
            }
        }
        panic!("maintenance did not quiesce");
    }
    fn accepted(
        client: &mut ReliableSession,
        server: &mut ReliableSession,
        window: u64,
    ) -> (StreamHandle, StreamHandle) {
        let mut c = Writer::default();
        let mut s = Writer::default();
        let handle = client
            .open_stream("example.echo", b"", window, &mut c)
            .unwrap();
        assert_eq!(client.phase(&handle).unwrap(), StreamPhase::Opening);
        deliver(&mut c, server);
        let remote = server.pending_open().unwrap().unwrap();
        assert_eq!(
            server.pending_metadata(&remote).unwrap(),
            ("example.echo", &b""[..])
        );
        server
            .decide_open(
                &remote,
                OpenDecision::Accept {
                    receive_window: window,
                },
                &mut s,
            )
            .unwrap();
        deliver(&mut s, client);
        (handle, remote)
    }
    #[test]
    fn accepted_stream_credit_fin_and_rekey_use_actual_owner_frontiers() {
        for profile in [Profile::X25519, Profile::P256] {
            let (_owner, client, server) = record_pair_for_limits(profile);
            let mut client: crate::crypto_v4::ReliableSession = client.into_session().unwrap();
            let mut server = server.into_session().unwrap();
            let (ch, sh) = accepted(&mut client, &mut server, 4);
            let mut c = Writer::default();
            let mut s = Writer::default();
            client.write(&ch, b"four", false, &mut c).unwrap();
            deliver(&mut c, &mut server);
            let mut out = [0; 4];
            assert_eq!(server.read(&sh, &mut out).unwrap(), ReadState::Data(4));
            assert_eq!(&out, b"four");
            server.grant(&sh, 8).unwrap();
            assert_eq!(
                server.engine.streams.slots[0].directions[0].committed_limit,
                4
            );
            assert!(client.write(&ch, b"next", false, &mut c).is_err());
            pump(&mut client, &mut server);
            assert_eq!(
                server.engine.streams.slots[0].directions[0].committed_limit,
                8
            );
            client.rekey(&mut c).unwrap();
            deliver(&mut c, &mut server);
            pump(&mut client, &mut server);
            assert_eq!(client.engine.epoch, 1);
            assert_eq!(server.engine.epoch, 1);
            client.write(&ch, b"next", true, &mut c).unwrap();
            deliver(&mut c, &mut server);
            server.write(&sh, b"done", true, &mut s).unwrap();
            deliver(&mut s, &mut client);
            pump(&mut client, &mut server);
            assert_eq!(client.phase(&ch).unwrap(), StreamPhase::Recent);
            assert_eq!(server.phase(&sh).unwrap(), StreamPhase::Recent);
            assert_eq!(server.read(&sh, &mut out).unwrap(), ReadState::Data(4));
            assert_eq!(&out, b"next");
            assert_eq!(server.read(&sh, &mut out).unwrap(), ReadState::Eof);
            assert_eq!(client.read(&ch, &mut out).unwrap(), ReadState::Data(4));
            assert_eq!(&out, b"done");
            assert_eq!(client.read(&ch, &mut out).unwrap(), ReadState::Eof);
            assert_eq!(client.engine.streams.promised, 0);
            assert_eq!(server.engine.streams.promised, 0);
        }
    }
    #[test]
    fn shared_discard_exact_boundaries_and_unauthenticated_consumption() {
        let now = Instant::now();
        let mut records = SharedDiscard::default();
        for _ in 0..16 {
            records.reject(now, 44).unwrap();
        }
        assert_eq!(records.reject(now, 44), Err(CryptoError::Capacity));
        assert_eq!((records.records, records.bytes), (16, 16 * 44));
        let mut bytes = SharedDiscard::default();
        bytes.reject(now, 44).unwrap();
        bytes.reject(now, 65_536 - 44).unwrap();
        assert_eq!(bytes.reject(now, 44), Err(CryptoError::Capacity));
        assert_eq!((bytes.records, bytes.bytes), (2, 65_536));
        let mut deadline = SharedDiscard::default();
        deadline.reject(now, 44).unwrap();
        deadline
            .reject(now + Duration::from_secs(10) - Duration::from_nanos(1), 44)
            .unwrap();
        assert_eq!(
            deadline.reject(now + Duration::from_secs(10), 44),
            Err(CryptoError::Deadline)
        );
        assert_eq!(deadline.deadline, Some(now + Duration::from_secs(10)));

        for profile in [Profile::X25519, Profile::P256] {
            let (_owner, client, server) = record_pair_for_limits(profile);
            let mut client = client.into_session().unwrap();
            let mut server = server.into_session().unwrap();
            let (handle, remote) = accepted(&mut client, &mut server, 8);
            assert!(server.make_stable(&[remote.scope()]).is_err());
            assert!(
                !server
                    .engine
                    .streams
                    .authenticated_stable(remote.scope())
                    .unwrap()
            );
            // A consumed local ID with no authenticated OPEN/retirement cannot
            // turn an unknown outer scope into a permissible discard.
            let scope: u64 = 101;
            server.engine.streams.set_used(scope).unwrap();
            assert!(server.engine.streams.used(scope).unwrap());
            assert!(!server.engine.streams.authenticated_stable(scope).unwrap());
            let mut wire = vec![0; 44];
            wire[..4].copy_from_slice(&36_u32.to_be_bytes());
            wire[4] = 8;
            wire[12..20].copy_from_slice(&scope.to_be_bytes());
            assert!(server.receive(scope, &wire).is_err());
            assert!(server.engine.closed);
            assert_eq!(server.engine.streams.shared_discard.records, 0);
            drop(handle);
        }
    }

    #[test]
    fn rejected_open_keeps_original_epoch_proof_across_rekey_and_retires() {
        let (_owner, client, server) = record_pair_for_limits(Profile::P256);
        let mut client: crate::crypto_v4::ReliableSession = client.into_session().unwrap();
        let mut server = server.into_session().unwrap();
        let mut c = Writer::default();
        let mut s = Writer::default();
        let ch = client
            .open_stream("example.denied", &[], 4, &mut c)
            .unwrap();
        deliver(&mut c, &mut server);
        let sh = server.pending_open().unwrap().unwrap();
        client.rekey(&mut c).unwrap();
        deliver(&mut c, &mut server);
        pump(&mut client, &mut server);
        assert_eq!(client.engine.epoch, 1);
        server
            .decide_open(&sh, OpenDecision::Reject(Rejection::Application), &mut s)
            .unwrap();
        deliver(&mut s, &mut client);
        for session in [&client, &server] {
            let slot = &session.engine.streams.slots[0];
            assert_eq!(slot.phase, Phase::Recent);
            assert_eq!(
                slot.directions[0].proof.unwrap().terminal,
                Tuple {
                    epoch: 0,
                    next: 1,
                    offset: 0
                }
            );
            assert_eq!(
                slot.directions[1].proof.unwrap().terminal,
                Tuple {
                    epoch: 0,
                    next: 0,
                    offset: 0
                }
            );
        }
        // A waiting original OPEN triggers immediate retirement without a timer reset.
        let _new = client.open_stream("example.next", &[], 0, &mut c).unwrap();
        deliver(&mut c, &mut server);
        pump(&mut client, &mut server);
        assert_eq!(client.phase(&ch).unwrap(), StreamPhase::Stable);
        assert_eq!(server.phase(&sh).unwrap(), StreamPhase::Stable);
        assert!(client.engine.streams.used(ch.scope()).unwrap());
        assert!(
            server
                .engine
                .streams
                .barrier(ch.scope(), 1, 0, true)
                .is_err()
        );
    }
    #[test]
    fn bad_bound_record_aborts_locally_without_reusing_key_then_rekeys() {
        let (_owner, client, server) = record_pair_for_limits(Profile::X25519);
        let mut client: crate::crypto_v4::ReliableSession = client.into_session().unwrap();
        let mut server = server.into_session().unwrap();
        let (bad, remote) = accepted(&mut client, &mut server, 8);
        let (healthy, healthy_remote) = accepted(&mut client, &mut server, 8);
        let mut c = Writer::default();
        client.write(&bad, b"lost", false, &mut c).unwrap();
        let mut damaged = c.0.pop_front().unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(server.receive_bound(&remote, &damaged).is_err());
        let attempts = server.engine.session_usage.opens;
        server.receive_bound(&remote, &damaged).unwrap();
        assert_eq!(server.engine.session_usage.opens, attempts);
        let i = server.engine.streams.index(bad.scope()).unwrap();
        assert_eq!(server.engine.streams.slots[i].directions[0].current.next, 1);
        assert_eq!(server.engine.streams.slots[i].directions[0].ack, 0);
        assert_eq!(
            server.read(&remote, &mut [0; 8]).unwrap(),
            ReadState::Aborted
        );
        pump(&mut client, &mut server);
        assert_eq!(client.phase(&bad).unwrap(), StreamPhase::Recent);
        let proof = server.engine.streams.slots[i].directions[0].proof.unwrap();
        assert!(proof.aborted);
        assert_eq!(proof.terminal.next, 2);
        assert_eq!(proof.observed.next, 1);
        assert_eq!(proof.observed.offset, 0);
        client.rekey(&mut c).unwrap();
        deliver(&mut c, &mut server);
        pump(&mut client, &mut server);
        assert_eq!(client.engine.epoch, 1);
        assert_eq!(server.engine.epoch, 1);
        client.write(&healthy, b"alive", false, &mut c).unwrap();
        deliver(&mut c, &mut server);
        let mut out = [0; 8];
        assert_eq!(
            server.read(&healthy_remote, &mut out).unwrap(),
            ReadState::Data(5)
        );
        assert_eq!(&out[..5], b"alive");
    }
    #[test]
    fn future_credit_is_not_accepted_before_publication() {
        let (_owner, client, server) = record_pair_for_limits(Profile::P256);
        let mut client: crate::crypto_v4::ReliableSession = client.into_session().unwrap();
        let mut server = server.into_session().unwrap();
        let (ch, sh) = accepted(&mut client, &mut server, 4);
        server.grant(&sh, 8).unwrap();
        // A malicious peer guesses the reserved but unpublished receive window.
        client.engine.streams.slots[0].directions[0].limit = 8;
        let mut c = Writer::default();
        client.write(&ch, b"12345678", false, &mut c).unwrap();
        let wire = c.0.pop_front().unwrap();
        let mut input = server
            .prepare_receive_input(
                ch.scope(),
                &wire,
                None,
                server.engine.streams.input_pool.acquire(false).unwrap(),
            )
            .unwrap()
            .unwrap();
        let opened = input.execute(&wire);
        assert_eq!(
            server.finish_receive_input(input, &wire, opened).unwrap(),
            ReceiveDisposition::Isolated { scope: ch.scope() }
        );
        assert!(!server.engine.closed);
        assert!(
            server.engine.streams.slots[0].directions[0]
                .first_error
                .is_some()
        );
        assert_eq!(
            server.engine.streams.slots[0].directions[0].current.offset,
            0
        );
        assert_eq!(server.engine.streams.slots[0].directions[0].ack, 0);
    }
    #[test]
    fn interrupting_stopped_after_fin_discards_unread_bytes() {
        let (_owner, client, server) = record_pair_for_limits(Profile::P256);
        let mut client: crate::crypto_v4::ReliableSession = client.into_session().unwrap();
        let mut server = server.into_session().unwrap();
        let (ch, sh) = accepted(&mut client, &mut server, 4);
        let mut c = Writer::default();
        client.write(&ch, b"tail", true, &mut c).unwrap();
        deliver(&mut c, &mut server);
        let final_tuple = client.engine.streams.slots[0].directions[0]
            .terminal
            .unwrap();
        let mut body = client.basic_control(3, ch.scope(), 0).unwrap();
        body[0] = 0xa6;
        for (key, value) in [
            (3, u64::from(final_tuple.epoch)),
            (4, final_tuple.next),
            (5, final_tuple.offset),
        ] {
            uint(&mut body, key);
            uint(&mut body, value);
        }
        client.send(0, 9, &body, true, &mut c).unwrap();
        deliver(&mut c, &mut server);
        pump(&mut client, &mut server);
        let mut out = [0; 4];
        assert_eq!(server.read(&sh, &mut out).unwrap(), ReadState::Aborted);
        let i = client.engine.streams.index(ch.scope()).unwrap();
        assert!(
            client.engine.streams.slots[i].directions[0]
                .proof
                .unwrap()
                .aborted
        );
    }

    #[test]
    fn retirement_retains_frozen_proofs_until_original_rekey_references_exit() {
        for profile in [Profile::X25519, Profile::P256] {
            let (_owner, client, server) = record_pair_for_limits(profile);
            let mut client = client.into_session().unwrap();
            let mut server = server.into_session().unwrap();
            let (ch, sh) = accepted(&mut client, &mut server, 4);
            let mut c = Writer::default();
            let mut s = Writer::default();
            client.write(&ch, b"", true, &mut c).unwrap();
            server.write(&sh, b"", true, &mut s).unwrap();
            deliver(&mut c, &mut server);
            deliver(&mut s, &mut client);
            client.rekey(&mut c).unwrap();
            deliver(&mut c, &mut server);
            assert_eq!(server.engine.streams.slots[0].unpublished, 1);
            assert!(server.poll_terminal(&mut s).unwrap());
            deliver(&mut s, &mut client);
            assert!(client.poll_terminal(&mut c).unwrap());
            deliver(&mut c, &mut server);
            assert_eq!(client.phase(&ch).unwrap(), StreamPhase::Recent);
            client.engine.streams.slots[0].recent_at =
                Some(Instant::now() - Duration::from_secs(1));
            assert!(client.poll_retirement(&mut c).unwrap());
            deliver(&mut c, &mut server);
            assert!(!server.poll_retirement(&mut s).unwrap());
            assert!(server.poll(&mut s).unwrap()); // REPLY publication releases its original fence.
            assert_eq!(server.engine.streams.slots[0].unpublished, 0);
            assert!(server.poll_retirement(&mut s).unwrap());
            deliver(&mut s, &mut client);
            for session in [&client, &server] {
                let slot = &session.engine.streams.slots[0];
                assert_eq!(slot.phase, Phase::Held);
                assert_eq!(slot.barrier_refs, 2);
                assert!(slot.directions.iter().all(Direction::complete));
                assert!(
                    session
                        .engine
                        .streams
                        .barrier(ch.scope(), 0, 2, true)
                        .is_err()
                );
            }
            pump(&mut client, &mut server);
            assert!(client.engine.streams.slots.is_empty());
            assert!(server.engine.streams.slots.is_empty());
            assert_eq!(client.read(&ch, &mut [0; 1]).unwrap(), ReadState::Eof);
            assert_eq!(server.read(&sh, &mut [0; 1]).unwrap(), ReadState::Eof);
            assert_eq!(client.engine.epoch, 1);
            assert_eq!(server.engine.epoch, 1);
        }
    }
    #[test]
    fn reset_waits_for_original_open_outcome_and_damaged_fin_reuses_terminal_tuple() {
        let (_owner, client, server) = record_pair_for_limits(Profile::X25519);
        let mut client = client.into_session().unwrap();
        let mut server = server.into_session().unwrap();
        let mut c = Writer::default();
        let mut s = Writer::default();
        let pending = client
            .open_stream("example.cancel", &[], 4, &mut c)
            .unwrap();
        client.reset(&pending).unwrap();
        assert!(!client.poll(&mut s).unwrap());
        deliver(&mut c, &mut server);
        let remote = server.pending_open().unwrap().unwrap();
        server
            .decide_open(&remote, OpenDecision::Accept { receive_window: 4 }, &mut s)
            .unwrap();
        deliver(&mut s, &mut client);
        pump(&mut client, &mut server);
        assert_eq!(client.phase(&pending).unwrap(), StreamPhase::Recent);
        let (ch, sh) = accepted(&mut client, &mut server, 4);
        client.write(&ch, b"fin", true, &mut c).unwrap();
        let mut fin = c.0.pop_front().unwrap();
        *fin.last_mut().unwrap() ^= 1;
        assert!(server.receive_bound(&sh, &fin).is_err());
        pump(&mut client, &mut server);
        assert_eq!(client.phase(&ch).unwrap(), StreamPhase::Recent);
        assert_eq!(server.read(&sh, &mut [0; 4]).unwrap(), ReadState::Aborted);
        let i = client.engine.streams.index(ch.scope()).unwrap();
        assert_eq!(
            client.engine.streams.slots[i].directions[0]
                .proof
                .unwrap()
                .terminal
                .offset,
            3
        );
    }
    #[test]
    fn duplicate_outcomes_are_exact_and_do_not_switch_rejection_to_acceptance() {
        for decision in [
            OpenDecision::Accept { receive_window: 4 },
            OpenDecision::Reject(Rejection::Metadata),
        ] {
            let (_owner, client, server) = record_pair_for_limits(Profile::P256);
            let mut client = client.into_session().unwrap();
            let mut server = server.into_session().unwrap();
            let mut c = Writer::default();
            let mut s = Writer::default();
            let ch = client
                .open_stream("example.outcome", &[], 4, &mut c)
                .unwrap();
            deliver(&mut c, &mut server);
            let sh = server.pending_open().unwrap().unwrap();
            server.decide_open(&sh, decision, &mut s).unwrap();
            deliver(&mut s, &mut client);
            let repeat = server.outcome_body(0, decision).unwrap();
            server.send(0, 9, &repeat, true, &mut s).unwrap();
            deliver(&mut s, &mut client);
            let conflict = server
                .outcome_body(0, OpenDecision::Accept { receive_window: 8 })
                .unwrap();
            server.send(0, 9, &conflict, true, &mut s).unwrap();
            assert!(client.receive(0, &s.0.pop_front().unwrap()).is_err());
            assert!(client.phase(&ch).is_err());
        }
    }
    #[tokio::test]
    async fn original_environment_revoke_and_quarantine_deadline_close_owned_state() {
        let (owner, client, server) = record_pair_for_limits(Profile::P256);
        let mut client = client.into_session().unwrap();
        let mut server = server.into_session().unwrap();
        let (ch, _) = accepted(&mut client, &mut server, 4);
        client.reset(&ch).unwrap();
        let original = client.engine.streams.slots[0].directions[1]
            .deadline
            .unwrap();
        client.engine.streams.slots[0].directions[1].normal_deadline =
            Some(Instant::now() - Duration::from_millis(1));
        client.update_quarantine().unwrap();
        let d = client.engine.streams.slots[0].directions[1];
        assert!(d.quarantined && d.disabled);
        assert!(d.deadline.unwrap() <= original);
        client.engine.streams.slots[0].directions[1].deadline =
            Some(Instant::now() - Duration::from_millis(1));
        assert!(client.poll(&mut Writer::default()).is_err());
        assert!(client.engine.streams.closed);
        owner.environment.close().await.unwrap();
        assert!(server.poll(&mut Writer::default()).is_err());
        assert!(server.engine.streams.closed);
    }
    #[test]
    fn transport_only_session_cannot_fabricate_bootstrap_owner() {
        let (_owner, client, _) = record_pair_for_limits(Profile::P256);
        let mut session = client.into_session().unwrap();
        assert!(
            session
                .materialize_bootstrap(&mut Writer::default())
                .is_err()
        );
    }
}
