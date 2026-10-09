//! One original unreliable scope. Reliable ordering and barriers never consume
//! its replay state; physical native send tails retain the original prepayment.
use super::*;
use crate::transport::{UnreliableMessageError, UnreliableReceiveBlock, UnreliableSendOutcome};
use bytes::Bytes;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

pub(crate) const SCOPE: u64 = 0x8000_0000_0000_0001;
const MAXIMUM: usize = 1024;
const PAYLOAD: usize = 949;
const POSITIONS: usize = 64;

pub(crate) struct DatagramBacking {
    sends: Arc<Semaphore>,
    receiving: AtomicBool,
    crypto: Arc<Semaphore>,
    _charge: Option<ResourceCharge>,
}
pub(crate) struct DatagramLease {
    _backing: Arc<DatagramBacking>,
    _permit: OwnedSemaphorePermit,
}
pub(crate) struct ReceiveLease(Arc<DatagramBacking>);
impl Drop for ReceiveLease {
    fn drop(&mut self) {
        self.0.receiving.store(false, Ordering::Release);
    }
}
struct CryptoLease {
    _backing: Arc<DatagramBacking>,
    _permit: OwnedSemaphorePermit,
}
pub(crate) struct DatagramSeal {
    work: RecordWork,
    pub(crate) wire: Zeroizing<Vec<u8>>,
    expires_ms: u64,
    _original: CryptoLease,
}
impl DatagramSeal {
    pub(crate) fn check(&self) -> Result<()> {
        self.work.check()
    }
    pub(crate) fn expired(&self) -> Result<bool> {
        Ok(self.work.account.security_time()?.upper_ms >= self.expires_ms)
    }
    pub(crate) fn epoch(&self) -> u32 {
        u32::from_be_bytes(
            self.wire[8..12]
                .try_into()
                .expect("original datagram epoch"),
        )
    }
    pub(crate) fn execute(&mut self) -> Result<()> {
        if self.expired()? {
            return Err(CryptoError::Deadline);
        }
        self.work.seal(&mut self.wire)?;
        if self.expired()? {
            self.wire.zeroize();
            return Err(CryptoError::Deadline);
        }
        Ok(())
    }
    pub(crate) fn take_wire(&mut self) -> Vec<u8> {
        std::mem::take(&mut *self.wire)
    }
}
pub(crate) struct DatagramOpen {
    work: RecordWork,
    plain: Zeroizing<[u8; MAXIMUM]>,
    epoch: u32,
    sequence: u64,
    delta: Usage,
    _original: CryptoLease,
}
impl DatagramOpen {
    pub(crate) fn execute(&mut self, wire: &[u8]) -> Result<usize> {
        self.work.open(wire, self.plain.as_mut())
    }
}
impl DatagramBacking {
    fn claim_crypto(self: &Arc<Self>) -> Option<CryptoLease> {
        Some(CryptoLease {
            _backing: self.clone(),
            _permit: self.crypto.clone().try_acquire_owned().ok()?,
        })
    }
    pub(crate) fn send(self: &Arc<Self>) -> Option<DatagramLease> {
        Some(DatagramLease {
            _backing: self.clone(),
            _permit: self.sends.clone().try_acquire_owned().ok()?,
        })
    }
    pub(crate) fn receive(
        self: &Arc<Self>,
    ) -> std::result::Result<ReceiveLease, UnreliableMessageError> {
        self.receiving
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        Ok(ReceiveLease(self.clone()))
    }
}
#[derive(Default)]
struct Replay {
    empty: bool,
    highest: u64,
    bits: [u64; 4],
}
impl Replay {
    fn new() -> Self {
        Self {
            empty: true,
            ..Self::default()
        }
    }
    fn admits(&self, sequence: u64) -> bool {
        if self.empty || sequence > self.highest {
            return true;
        }
        let difference = self.highest - sequence;
        difference < 256 && self.bits[(difference / 64) as usize] & (1u64 << (difference % 64)) == 0
    }
    fn mark(&mut self, sequence: u64) {
        if self.empty {
            self.empty = false;
            self.highest = sequence;
            self.bits = [1, 0, 0, 0];
            return;
        }
        if sequence > self.highest {
            let delta = (sequence - self.highest).min(256) as usize;
            let old = self.bits;
            self.bits = [0; 4];
            // Fixed work for every distance, including a jump to u64::MAX.
            for bit in 0..256 - delta {
                if old[bit / 64] & (1u64 << (bit % 64)) != 0 {
                    let shifted = bit + delta;
                    self.bits[shifted / 64] |= 1u64 << (shifted % 64);
                }
            }
            self.highest = sequence;
            self.bits[0] |= 1;
        } else {
            let difference = (self.highest - sequence) as usize;
            self.bits[difference / 64] |= 1u64 << (difference % 64);
        }
    }
}
struct Message {
    epoch: u32,
    size: usize,
    bytes: [u8; PAYLOAD],
}
pub(super) struct State {
    pub(super) enabled: bool,
    pub(super) backing: Arc<DatagramBacking>,
    replay: Replay,
    messages: Vec<Message>,
    first: usize,
    count: usize,
    failures: u32,
    pause: Option<Instant>,
    receive_disabled: bool,
    key_blocked: bool,
    pub(super) attempts: Usage,
    pub(super) good: Usage,
}
impl State {
    pub(super) fn preparation_limits(enabled: bool) -> ResourceLimits {
        if enabled {
            ResourceLimits {
                sdk_bytes: (std::mem::size_of::<Self>()
                    + POSITIONS * (std::mem::size_of::<Message>() + MAXIMUM + 512)
                    + 4 * MAXIMUM
                    + 4096) as u64,
                provider_bytes: (POSITIONS * MAXIMUM) as u64,
                items: (POSITIONS * 2 + 8) as u64,
                work_slots: 2,
                tasks: 65,
                timers: 1,
                ..ResourceLimits::default()
            }
        } else {
            ResourceLimits::default()
        }
    }
    pub(super) fn prepare_prepaid(
        account: &ResourceAccount,
        enabled: bool,
        charge: Option<ResourceCharge>,
    ) -> Result<Self> {
        if enabled != charge.is_some()
            || charge
                .as_ref()
                .is_some_and(|charge| !charge.matches(account, Self::preparation_limits(true)))
        {
            return Err(CryptoError::Configuration);
        }
        let mut messages = Vec::new();
        messages
            .try_reserve_exact(if enabled { POSITIONS } else { 0 })
            .map_err(|_| CryptoError::Capacity)?;
        for _ in 0..(if enabled { POSITIONS } else { 0 }) {
            messages.push(Message {
                epoch: 0,
                size: 0,
                bytes: [0; PAYLOAD],
            });
        }
        Ok(Self {
            enabled: false,
            backing: Arc::new(DatagramBacking {
                sends: Arc::new(Semaphore::new(if enabled { POSITIONS } else { 0 })),
                receiving: AtomicBool::new(false),
                crypto: Arc::new(Semaphore::new(if enabled { 2 } else { 0 })),
                _charge: charge,
            }),
            replay: Replay::new(),
            messages,
            first: 0,
            count: 0,
            failures: 0,
            pause: None,
            receive_disabled: false,
            key_blocked: false,
            attempts: Usage::default(),
            good: Usage::default(),
        })
    }
    fn clear_queue(&mut self) {
        for message in &mut self.messages {
            message.bytes.zeroize();
            message.size = 0;
        }
        self.first = 0;
        self.count = 0;
    }
    pub(super) fn close(&mut self) {
        self.enabled = false;
        self.backing.sends.close();
        self.clear_queue();
    }
    pub(super) fn install_epoch(&mut self) {
        self.replay = Replay::new();
        self.key_blocked = false;
        self.attempts = Usage::default();
        self.good = Usage::default();
        // Already queued old-generation results cannot become new-generation
        // Receive authority. The Session failure/pause facts are never reset.
        self.clear_queue();
    }
    fn guard(&mut self) -> std::result::Result<(), UnreliableMessageError> {
        if self.receive_disabled {
            return Err(UnreliableMessageError::ReceiveDisabled);
        }
        if let Some(until) = self.pause {
            if until > Instant::now() {
                return Err(UnreliableMessageError::TemporarilyBlocked {
                    reason: UnreliableReceiveBlock::InvalidInputBudget,
                    retry_after_ms: Some(
                        until
                            .saturating_duration_since(Instant::now())
                            .as_millis()
                            .max(1)
                            .min(u64::MAX as u128) as u64,
                    ),
                });
            }
            self.pause = None;
        }
        if self.key_blocked {
            return Err(UnreliableMessageError::TemporarilyBlocked {
                reason: UnreliableReceiveBlock::KeyOpenBudget,
                retry_after_ms: None,
            });
        }
        Ok(())
    }
    fn failed_authentication(&mut self) {
        self.failures += 1;
        if self.failures >= 32 {
            self.receive_disabled = true;
            self.pause = None;
            self.clear_queue();
        } else if self.failures.is_multiple_of(8) {
            self.pause = Some(Instant::now() + Duration::from_millis(1000));
            self.clear_queue();
        }
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.close();
    }
}
fn uint(output: &mut [u8], at: &mut usize, major: u8, value: u64) {
    let (additional, width) = if value < 24 {
        (value as u8, 0)
    } else if value <= u8::MAX as u64 {
        (24, 1)
    } else if value <= u16::MAX as u64 {
        (25, 2)
    } else if value <= u32::MAX as u64 {
        (26, 4)
    } else {
        (27, 8)
    };
    output[*at] = (major << 5) | additional;
    *at += 1;
    if width != 0 {
        output[*at..*at + width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
        *at += width;
    }
}
impl RecordEngine {
    pub(crate) fn datagram_available(&self) -> bool {
        self.ready && !self.closed && self.datagrams.enabled
    }
    pub(crate) fn datagram_backing(&self) -> Option<Arc<DatagramBacking>> {
        self.datagram_available()
            .then(|| self.datagrams.backing.clone())
    }
    pub(crate) fn datagram_maximum(native: usize) -> usize {
        native.min(MAXIMUM).saturating_sub(75).min(PAYLOAD)
    }
    pub(crate) fn datagram_info(
        &mut self,
        native: usize,
    ) -> std::result::Result<crate::transport::UnreliableMessagesInfo, UnreliableMessageError> {
        if !self.datagram_available() {
            return Err(UnreliableMessageError::Unavailable);
        }
        self.check()
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        Ok(crate::transport::UnreliableMessagesInfo {
            epoch: self.epoch,
            max_message_bytes: Self::datagram_maximum(native),
            receive_failure: self.datagrams.guard().err(),
        })
    }
    pub(crate) fn datagram_guard(&mut self) -> std::result::Result<(), UnreliableMessageError> {
        if !self.datagram_available() {
            return Err(UnreliableMessageError::Unavailable);
        }
        self.check()
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        self.datagrams.guard()
    }
    pub(crate) fn prepare_datagram(
        &mut self,
        payload: &[u8],
        native: usize,
        expires_ms: u64,
    ) -> std::result::Result<
        std::result::Result<DatagramSeal, UnreliableSendOutcome>,
        UnreliableMessageError,
    > {
        if !self.datagram_available() {
            return Err(UnreliableMessageError::Unavailable);
        }
        self.check()
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        if self
            .account
            .security_time()
            .map_err(|_| UnreliableMessageError::OperationFailed)?
            .upper_ms
            >= expires_ms
        {
            return Ok(Err(UnreliableSendOutcome::DroppedExpired));
        }
        if self.frozen {
            return Ok(Err(UnreliableSendOutcome::DroppedBudget));
        }
        if payload.len() > Self::datagram_maximum(native) {
            return Err(UnreliableMessageError::TooLarge);
        }
        let Some(original) = self.datagrams.backing.claim_crypto() else {
            return Ok(Err(UnreliableSendOutcome::DroppedBudget));
        };
        let index = self
            .slot_for(false, SCOPE, self.role)
            .map_err(|_| UnreliableMessageError::Unavailable)?;
        let sequence = self.keys[index].next;
        let Some(next) = sequence.checked_add(1) else {
            return Ok(Err(UnreliableSendOutcome::DroppedBudget));
        };
        let mut plain = Zeroizing::new([0u8; MAXIMUM]);
        let mut size = 0;
        plain[size] = 0xa4;
        size += 1;
        for (field, value) in [(0, self.epoch as u64), (1, sequence), (2, SCOPE)] {
            uint(plain.as_mut(), &mut size, 0, field);
            uint(plain.as_mut(), &mut size, 0, value);
        }
        uint(plain.as_mut(), &mut size, 0, 3);
        uint(plain.as_mut(), &mut size, 2, payload.len() as u64);
        plain[size..size + payload.len()].copy_from_slice(payload);
        size += payload.len();
        let length = size + 44;
        let mut output = Zeroizing::new(vec![0u8; length]);
        output[..4].copy_from_slice(&((length - 8) as u32).to_be_bytes());
        output[4] = 10;
        output[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        output[12..20].copy_from_slice(&SCOPE.to_be_bytes());
        output[20..28].copy_from_slice(&sequence.to_be_bytes());
        let aad = self
            .aad(&output[..8], &output[8..28], self.role)
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        if self
            .charge(false, index, true, aad.len(), size, false)
            .is_err()
        {
            return Ok(Err(UnreliableSendOutcome::DroppedBudget));
        }
        self.keys[index].next = next;
        self.check()
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        output[28..28 + size].copy_from_slice(&plain[..size]);
        let work = self
            .record_work(false, index, &aad, self.epoch, sequence)
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        Ok(Ok(DatagramSeal {
            work,
            wire: output,
            expires_ms,
            _original: original,
        }))
    }
    pub(crate) fn prepare_datagram_open(
        &mut self,
        wire: &[u8],
    ) -> std::result::Result<Option<DatagramOpen>, UnreliableMessageError> {
        self.datagram_guard()?;
        if wire.len() < 44
            || wire.len() > MAXIMUM
            || wire[4..8] != [10, 0, 0, 0]
            || u32::from_be_bytes(wire[..4].try_into().expect("bounded header")) as usize
                != wire.len() - 8
            || wire[12..20] != SCOPE.to_be_bytes()
        {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::CurrentDatagramDrops);
            return Ok(None);
        }
        let wire_epoch = u32::from_be_bytes(wire[8..12].try_into().expect("bounded epoch"));
        if wire_epoch < self.epoch {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::OldDatagramDrops);
            return Ok(None);
        }
        if wire_epoch > self.epoch {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::FutureDatagramDrops);
            return Ok(None);
        }
        let sequence = u64::from_be_bytes(wire[20..28].try_into().expect("bounded sequence"));
        if !self.datagrams.replay.admits(sequence) {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::OldDatagramDrops);
            return Ok(None);
        }
        let Some(original) = self.datagrams.backing.claim_crypto() else {
            return Ok(None);
        };
        let index = self
            .slot_for(false, SCOPE, 1 - self.role)
            .map_err(|_| UnreliableMessageError::Unavailable)?;
        let aad = self
            .aad(&wire[..8], &wire[8..28], 1 - self.role)
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        let size = wire.len() - 44;
        let delta = Usage {
            opens: 1,
            blocks: (aad.len() as u64).div_ceil(16) + (size as u64).div_ceil(16) + 1,
            bytes: size as u64 + 16,
            ..Usage::default()
        };
        let (key_limit, _, _) = self.limits();
        if !self.keys[index]
            .usage
            .add(delta)
            .map_err(|_| UnreliableMessageError::OperationFailed)?
            .fits(key_limit)
        {
            self.datagrams.key_blocked = true;
            self.datagrams.clear_queue();
            return self.datagrams.guard().map(|()| None);
        }
        self.charge(false, index, false, aad.len(), size, true)
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        self.datagrams.attempts = self
            .datagrams
            .attempts
            .add(delta)
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        let work = self
            .record_work(false, index, &aad, self.epoch, sequence)
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        Ok(Some(DatagramOpen {
            work,
            plain: Zeroizing::new([0; MAXIMUM]),
            epoch: self.epoch,
            sequence,
            delta,
            _original: original,
        }))
    }
    pub(crate) fn finish_datagram_open(
        &mut self,
        job: DatagramOpen,
        opened: Result<usize>,
    ) -> std::result::Result<(), UnreliableMessageError> {
        self.datagram_guard()?;
        if job.epoch != self.epoch {
            return Ok(());
        }
        job.work
            .check()
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        let size = match opened {
            Ok(size) => size,
            Err(CryptoError::Authentication) => {
                self.datagrams.failed_authentication();
                self.account.diagnostic_count(
                    crate::diagnostics_v4::DiagnosticCounter::CurrentDatagramDrops,
                );
                return Ok(());
            }
            Err(_) => return Err(UnreliableMessageError::OperationFailed),
        };
        let sequence = job.sequence;
        let Ok(value) = crate::codec_v4::decode_context(
            &job.plain[..size],
            "DATAGRAM",
            crate::codec_v4::Limits {
                bytes: MAXIMUM,
                nodes: 32,
            },
            None,
            crate::codec_v4::Context::default(),
        ) else {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::CurrentDatagramDrops);
            return Ok(());
        };
        let valid = (|| -> crate::codec_v4::Result<&[u8]> {
            if value.u("DATAGRAM", "epoch")? != self.epoch as u64
                || value.u("DATAGRAM", "sequence")? != sequence
                || value.u("DATAGRAM", "scope")? != SCOPE
            {
                return Err("datagram_binding");
            }
            value.field("DATAGRAM", "data")?.bytes()
        })();
        let Ok(payload) = valid else {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::CurrentDatagramDrops);
            return Ok(());
        };
        if payload.len() > PAYLOAD {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::CurrentDatagramDrops);
            return Ok(());
        }
        self.check()
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        self.datagrams.guard()?;
        let now = self
            .account
            .security_time()
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        self.streams
            .controls
            .activity(now)
            .map_err(|_| UnreliableMessageError::OperationFailed)?;
        let sequence = job.sequence;
        let delta = job.delta;
        let account = self.account.clone();
        account
            .with_security(|| -> Result<()> {
                if !self.datagram_available() || !self.datagrams.replay.admits(sequence) {
                    return Ok(());
                }
                self.datagrams.replay.mark(sequence);
                self.datagrams.good = self.datagrams.good.add(delta)?;
                // A full queue still consumes this unique replay acceptance.
                if self.datagrams.count == POSITIONS {
                    account.diagnostic_count(
                        crate::diagnostics_v4::DiagnosticCounter::CurrentDatagramDrops,
                    );
                }
                if self.datagrams.count < POSITIONS {
                    let at = (self.datagrams.first + self.datagrams.count) % POSITIONS;
                    let message = &mut self.datagrams.messages[at];
                    message.epoch = self.epoch;
                    message.size = payload.len();
                    message.bytes[..payload.len()].copy_from_slice(payload);
                    self.datagrams.count += 1;
                }
                Ok(())
            })
            .map_err(|_| UnreliableMessageError::OperationFailed)?
            .map_err(|_| UnreliableMessageError::OperationFailed)
    }
    pub(crate) fn take_datagram(
        &mut self,
    ) -> std::result::Result<Option<Bytes>, UnreliableMessageError> {
        self.datagram_guard()?;
        let account = self.account.clone();
        account
            .with_security(|| {
                if self.datagrams.count == 0 {
                    return None;
                }
                let message = &mut self.datagrams.messages[self.datagrams.first];
                let result = (message.epoch == self.epoch)
                    .then(|| Bytes::copy_from_slice(&message.bytes[..message.size]));
                message.bytes.zeroize();
                message.size = 0;
                self.datagrams.first = (self.datagrams.first + 1) % POSITIONS;
                self.datagrams.count -= 1;
                result
            })
            .map_err(|_| UnreliableMessageError::OperationFailed)
    }
    pub(super) fn datagram_soft_epoch_usage(&self) -> Usage {
        Usage {
            opens: self.epoch_usage.opens - self.datagrams.attempts.opens
                + self.datagrams.good.opens,
            blocks: self.epoch_usage.blocks - self.datagrams.attempts.blocks
                + self.datagrams.good.blocks,
            bytes: self.epoch_usage.bytes - self.datagrams.attempts.bytes
                + self.datagrams.good.bytes,
            seals: self.epoch_usage.seals,
        }
    }
    pub(super) fn datagram_soft_key_usage(&self, key: &RecordKey) -> Usage {
        if key.scope == SCOPE && key.direction != self.role {
            self.datagrams.good
        } else {
            key.usage
        }
    }
}
