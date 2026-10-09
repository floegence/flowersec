//! Reliable records and the original, exclusive rekey crypto owner. The Session
//! supplies admitted scopes; an unauthenticated header never creates a key.
use super::{Binding, CryptoError, Profile, RecordPublisher, Result, domain, expand};
use crate::environment_v4::{ResourceAccount, ResourceCharge, ResourceLimits, TrustedTimeSample};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use zeroize::{Zeroize, Zeroizing};
#[path = "crypto_v4_datagrams.rs"]
mod datagrams;
#[path = "crypto_v4_rekey.rs"]
mod rekey;
#[path = "crypto_v4_streams.rs"]
mod streams;
pub(crate) use datagrams::DatagramLease;
pub(crate) use streams::ProbePublication;
pub use streams::{
    DrainOperation, DrainOutcome, DrainResult, Metadata, OpenRequest, ProbeOutcome, ProbeResult,
    RawStreamMetadataContract, RawStreamMetadataField, RawStreamMetadataType, Session, Stream,
    UnreliableMessages,
};
#[cfg(test)]
pub(crate) use streams::{
    MaintenanceReceiveProbe, TerminalPublicationProbe, install_maintenance_receive_probe,
    install_terminal_publication_probe,
};
pub(crate) use streams::{
    NativeStreamBinding, ReceiveDisposition, ReliableSession, ResumeMessageClaim, SessionLink,
    SessionReceiver, SessionTransport, StreamPreparation, StreamPublicationAdmission, StreamView,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Usage {
    seals: u64,
    opens: u64,
    blocks: u64,
    bytes: u64,
}
impl Usage {
    fn add(self, other: Self) -> Result<Self> {
        Ok(Self {
            seals: self
                .seals
                .checked_add(other.seals)
                .ok_or(CryptoError::Capacity)?,
            opens: self
                .opens
                .checked_add(other.opens)
                .ok_or(CryptoError::Capacity)?,
            blocks: self
                .blocks
                .checked_add(other.blocks)
                .ok_or(CryptoError::Capacity)?,
            bytes: self
                .bytes
                .checked_add(other.bytes)
                .ok_or(CryptoError::Capacity)?,
        })
    }
    fn fits(self, limit: Self) -> bool {
        self.seals <= limit.seals
            && self.opens <= limit.opens
            && self.blocks <= limit.blocks
            && self.bytes <= limit.bytes
    }
}
/// One original reliable direction orders its own immutable publication tickets.
struct RecordOrder {
    state: std::sync::Mutex<(u64, u64)>,
}
impl RecordOrder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new((0, 0)),
        })
    }
    fn claim(self: &Arc<Self>, lifetime: Arc<CryptoLifetime>) -> Result<RecordPublication> {
        let mut state = self
            .state
            .lock()
            .expect("reliable direction publication ticket");
        let ticket = state.0;
        state.0 = state.0.checked_add(1).ok_or(CryptoError::Sequence)?;
        Ok(RecordPublication {
            order: self.clone(),
            lifetime,
            ticket,
        })
    }
}
pub(crate) struct RecordPublication {
    order: Arc<RecordOrder>,
    lifetime: Arc<CryptoLifetime>,
    ticket: u64,
}
impl RecordPublication {
    pub(crate) fn wait(&self) -> Result<()> {
        let mut waiting = self
            .lifetime
            .waiting
            .lock()
            .expect("original publication wake owner");
        loop {
            if self.lifetime.stopped.load(Ordering::Acquire) {
                return Err(CryptoError::State);
            }
            if self
                .order
                .state
                .lock()
                .expect("reliable direction publication turn")
                .1
                == self.ticket
            {
                return Ok(());
            }
            waiting = self
                .lifetime
                .changed
                .wait(waiting)
                .expect("reliable direction publication wait");
        }
    }
}
impl Drop for RecordPublication {
    fn drop(&mut self) {
        let failed = {
            let mut state = self
                .order
                .state
                .lock()
                .expect("original publication completion");
            if state.1 == self.ticket {
                state.1 = state.1.saturating_add(1);
                false
            } else {
                true
            }
        };
        if failed {
            self.lifetime.stop();
        } else {
            self.lifetime.wake();
        }
    }
}
/// The original admission remains charged through the actual crypto exit.
pub(crate) struct CryptoLifetime {
    stopped: AtomicBool,
    waiting: std::sync::Mutex<()>,
    changed: std::sync::Condvar,
    active: AtomicUsize,
    deadline: std::sync::Mutex<Option<tokio::time::Instant>>,
    _charge: std::sync::Mutex<Option<ResourceCharge>>,
    #[cfg(test)]
    test_hold: std::sync::Mutex<Option<Arc<RecordCryptoProbe>>>,
}
#[cfg(test)]
struct RecordCryptoProbe {
    scope: u64,
    frame: u8,
    seal: bool,
    digest: bool,
    state: std::sync::Mutex<(bool, bool)>,
    changed: std::sync::Condvar,
}
#[cfg(test)]
pub(crate) struct RecordCryptoHold(Arc<RecordCryptoProbe>);
#[cfg(test)]
impl RecordCryptoHold {
    pub(crate) fn wait_entered(&self) -> bool {
        let state = self.0.state.lock().unwrap();
        let (state, _) = self
            .0
            .changed
            .wait_timeout_while(state, std::time::Duration::from_secs(3), |state| !state.0)
            .unwrap();
        state.0
    }
    pub(crate) fn release(&self) {
        let mut state = self.0.state.lock().unwrap();
        state.1 = true;
        self.0.changed.notify_all();
    }
}
#[cfg(test)]
impl Drop for RecordCryptoHold {
    fn drop(&mut self) {
        self.release();
    }
}
impl CryptoLifetime {
    fn wake(&self) {
        let _waiting = self.waiting.lock().expect("original crypto wake");
        self.changed.notify_all();
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.wake();
    }
    fn tighten_deadline(&self, deadline: Option<tokio::time::Instant>) {
        if let Some(deadline) = deadline {
            let mut current = self.deadline.lock().expect("original crypto hard deadline");
            *current = Some(deadline);
        }
    }
    fn release(&self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 && self.stopped.load(Ordering::Acquire) {
            self._charge
                .lock()
                .expect("original crypto admission return")
                .take();
        }
    }
    pub(crate) fn pending(&self) -> usize {
        let active = self.active.load(Ordering::Acquire);
        if self.stopped.load(Ordering::Acquire) {
            active
        } else {
            active.saturating_sub(1)
        }
    }
}
pub(crate) struct CryptoTail(Arc<CryptoLifetime>);
impl Drop for CryptoTail {
    fn drop(&mut self) {
        self.0.release();
    }
}
pub(crate) struct RecordWork {
    lifetime: Arc<CryptoLifetime>,
    account: ResourceAccount,
    born: TrustedTimeSample,
    profile: Profile,
    deadline: Option<tokio::time::Instant>,
    key: Option<Arc<RecordMaterial>>,
    aad: [u8; 128],
    aad_len: usize,
    nonce: [u8; 12],
    publication: Option<RecordPublication>,
    rekey: Option<rekey::SealPatch>,
    stream: Option<streams::StreamSealPatch>,
    receive_view: Option<Arc<StreamView>>,
    send_view: Option<Arc<StreamView>>,
}
pub(crate) struct RecordSealCompletion {
    rekey: Option<rekey::SealCompletion>,
    stream: Option<streams::StreamSealCompletion>,
}
impl RecordSealCompletion {
    pub(crate) fn needs_commit(&self) -> bool {
        self.rekey.is_some() || self.stream.is_some()
    }
}
impl RecordWork {
    #[cfg(test)]
    pub(super) fn test_hold(&self, record: &[u8], seal: bool, digest: bool) {
        let probe = self.lifetime.test_hold.lock().unwrap().clone();
        let Some(probe) = probe else {
            return;
        };
        if record.get(4) != Some(&probe.frame)
            || record.get(12..20) != Some(probe.scope.to_be_bytes().as_slice())
            || seal != probe.seal
            || digest != probe.digest
        {
            return;
        }
        let mut state = probe.state.lock().unwrap();
        state.0 = true;
        probe.changed.notify_all();
        while !state.1 {
            state = probe.changed.wait(state).unwrap();
        }
    }
    pub(crate) fn send_view(&self) -> Option<Arc<StreamView>> {
        self.send_view.clone()
    }
    pub(crate) fn aborted(&self) -> bool {
        self.send_view
            .as_ref()
            .is_some_and(|view| view.send_aborted.load(Ordering::Acquire))
    }
    pub(crate) fn physical_tail(&self) -> CryptoTail {
        self.lifetime.active.fetch_add(1, Ordering::AcqRel);
        CryptoTail(self.lifetime.clone())
    }
    pub(crate) fn take_publication(&mut self) -> Option<RecordPublication> {
        self.publication.take()
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.aborted() {
            return Err(CryptoError::State);
        }
        if self
            .receive_view
            .as_ref()
            .is_some_and(|view| view.receive_disabled.load(Ordering::Acquire))
        {
            return Err(CryptoError::State);
        }
        if self.lifetime.stopped.load(Ordering::Acquire) {
            return Err(CryptoError::State);
        }
        let now = self.account.security_time()?;
        let deadline = self
            .deadline
            .into_iter()
            .chain(
                *self
                    .lifetime
                    .deadline
                    .lock()
                    .expect("original crypto hard deadline"),
            )
            .min();
        if deadline.is_some_and(|deadline| now.monotonic_sample >= deadline) {
            return Err(CryptoError::Deadline);
        }
        if now.clock_incarnation != self.born.clock_incarnation
            || now
                .upper_ms
                .checked_sub(self.born.lower_ms)
                .is_none_or(|age| age >= 86_400_000)
        {
            return Err(CryptoError::Deadline);
        }
        Ok(())
    }
    fn cipher(&self) -> Result<LessSafeKey> {
        let algorithm = match self.profile {
            Profile::X25519 => &aead::CHACHA20_POLY1305,
            Profile::P256 => &aead::AES_256_GCM,
        };
        Ok(LessSafeKey::new(
            UnboundKey::new(
                algorithm,
                self.key
                    .as_ref()
                    .ok_or(CryptoError::State)?
                    .material()?
                    .as_ref(),
            )
            .map_err(|_| CryptoError::Key)?,
        ))
    }
    pub(crate) fn seal_with_completion(
        &mut self,
        record: &mut [u8],
    ) -> Result<RecordSealCompletion> {
        self.check()?;
        let end = record
            .len()
            .checked_sub(16)
            .filter(|end| *end >= 28)
            .ok_or(CryptoError::State)?;
        let stream = self
            .stream
            .take()
            .map(|patch| patch.execute(&mut record[28..end]))
            .transpose()?;
        #[cfg(test)]
        if stream.is_some() {
            self.test_hold(record, true, true);
        }
        let completion = if let Some(patch) = self.rekey.take() {
            let end = record
                .len()
                .checked_sub(16)
                .filter(|end| *end >= 28)
                .ok_or(CryptoError::State)?;
            patch.execute(&mut record[28..end])?
        } else {
            None
        };
        self.seal(record)?;
        Ok(RecordSealCompletion {
            rekey: completion,
            stream,
        })
    }
    pub(crate) fn seal(&self, record: &mut [u8]) -> Result<()> {
        let result = (|| {
            self.check()?;
            let end = record
                .len()
                .checked_sub(16)
                .filter(|end| *end >= 28)
                .ok_or(CryptoError::State)?;
            let tag = self
                .cipher()?
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(self.nonce),
                    Aad::from(&self.aad[..self.aad_len]),
                    &mut record[28..end],
                )
                .map_err(|_| CryptoError::Authentication)?;
            record[end..].copy_from_slice(tag.as_ref());
            #[cfg(test)]
            self.test_hold(record, true, false);
            self.check()
        })();
        if result.is_err() {
            record.zeroize();
        }
        result
    }
    fn open(&self, wire: &[u8], plain: &mut [u8]) -> Result<usize> {
        let result = (|| {
            self.check()?;
            let size = wire
                .len()
                .checked_sub(28)
                .ok_or(CryptoError::Authentication)?;
            if size < 16 || plain.len() < size {
                return Err(CryptoError::Capacity);
            }
            plain[..size].copy_from_slice(&wire[28..]);
            let n = self
                .cipher()?
                .open_in_place(
                    Nonce::assume_unique_for_key(self.nonce),
                    Aad::from(&self.aad[..self.aad_len]),
                    &mut plain[..size],
                )
                .map_err(|_| CryptoError::Authentication)?
                .len();
            #[cfg(test)]
            self.test_hold(wire, false, false);
            self.check()?;
            plain[n..size].zeroize();
            Ok(n)
        })();
        if result.is_err() {
            plain.zeroize();
        }
        result
    }
}
impl Drop for RecordWork {
    fn drop(&mut self) {
        self.rekey.take();
        self.key.take();
        self.publication.take();
        self.lifetime.release();
    }
}
pub(crate) struct RecordOpen {
    work: RecordWork,
    epoch: u32,
    scope: u64,
    next: u64,
}
impl RecordOpen {
    #[cfg(test)]
    pub(super) fn test_hold(&self, wire: &[u8]) {
        self.work.test_hold(wire, false, true);
    }
    pub(crate) fn execute(&self, wire: &[u8], plain: &mut [u8]) -> Result<usize> {
        self.work.open(wire, plain)
    }
}
enum RecordMaterialState {
    Ready(Zeroizing<[u8; 32]>),
    Pending {
        root: Zeroizing<[u8; 32]>,
        info: [u8; 192],
        size: usize,
    },
}
struct RecordMaterial {
    state: std::sync::Mutex<RecordMaterialState>,
}
impl RecordMaterial {
    fn ready(key: Zeroizing<[u8; 32]>) -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(RecordMaterialState::Ready(key)),
        })
    }
    fn material(&self) -> Result<Zeroizing<[u8; 32]>> {
        // Only this exact key's owner can wait here. No public Session or
        // Environment lock is held through a first-use derivation.
        let mut state = self.state.lock().expect("original record key material");
        if let RecordMaterialState::Pending { root, info, size } = &*state {
            let key = expand(root, &info[..*size])?;
            *state = RecordMaterialState::Ready(key);
        }
        match &*state {
            RecordMaterialState::Ready(key) => Ok(Zeroizing::new(**key)),
            _ => Err(CryptoError::State),
        }
    }
}
struct RecordKey {
    scope: u64,
    direction: u8,
    key: Arc<RecordMaterial>,
    order: Arc<RecordOrder>,
    next: u64,
    disabled: bool,
    usage: Usage,
}
struct Candidate {
    root: Zeroizing<[u8; 32]>,
    born: TrustedTimeSample,
    keys: Vec<RecordKey>,
    usage: Usage,
    armed: bool,
    sent: bool,
    received: bool,
}
pub(crate) struct RecordEngine {
    account: ResourceAccount,
    crypto: Arc<CryptoLifetime>,
    profile: Profile,
    role: u8,
    root: Zeroizing<[u8; 32]>,
    hash: [u8; 32],
    context: [u8; 32],
    authenticated_identities: [[u8; 32]; 2],
    service_authorities: [[u8; 32]; 2],
    application_profile: u8,
    resume_policy: Option<crate::checkpoint_v4::ResumeSessionPolicy>,
    born: TrustedTimeSample,
    epoch: u32,
    max_frame: usize,
    max_keys: usize,
    keys: Vec<RecordKey>,
    epoch_usage: Usage,
    session_usage: Usage,
    key_derivations: u64,
    ready: bool,
    closed: bool,
    frozen: bool,
    deferred_crypto: bool,
    candidate: Option<Candidate>,
    spare_keys: Vec<RecordKey>,
    rekey: rekey::CoordinatorStorage,
    streams: streams::State,
    datagrams: datagrams::State,
    // Declared last: return the engine admission only after every owned field.
    _engine_tail: CryptoTail,
}
impl fmt::Debug for RecordEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordEngine { <redacted> }")
    }
}
/// Fixed key tables, decoder/output buffers, rekey state and reliable stream
/// geometry retained before irreversible consumption. It carries no key or
/// authentication authority and can be adopted only by its original account.
pub(super) struct RecordReservation {
    account: ResourceAccount,
    shape: super::RecordShape,
    role: super::Role,
    charge: ResourceCharge,
    max_keys: usize,
    keys: Vec<RecordKey>,
    spare_keys: Vec<RecordKey>,
    rekey: rekey::CoordinatorStorage,
    streams: streams::State,
    datagrams: datagrams::State,
}
impl RecordReservation {
    fn record_limits(shape: &super::RecordShape) -> Result<ResourceLimits> {
        if !(36..=1_048_576).contains(&shape.max_frame) || shape.max_streams > 1035 {
            return Err(CryptoError::Configuration);
        }
        let max_keys = (shape.max_streams + 2 + 128) * 2;
        let geometry = rekey::Geometry::new(shape)?;
        Ok(ResourceLimits {
            sdk_bytes: (2
                * max_keys
                * (std::mem::size_of::<RecordKey>()
                    + std::mem::size_of::<RecordOrder>()
                    + std::mem::size_of::<RecordMaterial>()
                    + 64)
                + std::mem::size_of::<RecordEngine>()
                + std::mem::size_of::<rekey::Coordinator>()
                + geometry.bytes
                + 320) as u64,
            items: (2 * max_keys + 5) as u64,
            timers: 1,
            work_slots: 2,
            tasks: 1,
            ..ResourceLimits::default()
        })
    }
    pub(super) fn preparation_limits(
        shape: &super::RecordShape,
        automatic: bool,
    ) -> Result<ResourceLimits> {
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            Self::record_limits(shape)?,
            streams::State::preparation_limits(shape, automatic)?,
        )?;
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            limits,
            datagrams::State::preparation_limits(shape.datagrams),
        )?)
    }
    pub(super) fn owns(&self, account: &ResourceAccount) -> bool {
        self.account.same_owner(account)
    }
    pub(super) fn new(
        account: ResourceAccount,
        shape: super::RecordShape,
        role: super::Role,
    ) -> Result<Self> {
        let charge = account.reserve(Self::preparation_limits(
            &shape,
            account.automatic_liveness().is_some(),
        )?)?;
        Self::new_prepaid(account, shape, role, charge)
    }
    pub(super) fn new_prepaid(
        account: ResourceAccount,
        shape: super::RecordShape,
        role: super::Role,
        mut backing: ResourceCharge,
    ) -> Result<Self> {
        let automatic = account.automatic_liveness().is_some();
        if !backing.matches(&account, Self::preparation_limits(&shape, automatic)?) {
            return Err(CryptoError::Configuration);
        }
        if !(36..=1_048_576).contains(&shape.max_frame) || shape.max_streams > 1035 {
            return Err(CryptoError::Configuration);
        }
        let max_keys = (shape.max_streams + 2 + 128) * 2;
        let geometry = rekey::Geometry::new(&shape)?;
        let credit = rekey::Credit::new(
            shape.rekey_envelope,
            shape.service_ms,
            account.security_time_profile(),
        )?;
        // The admitted idle policy must cover the original rekey preparation,
        // provider/barrier and confirmation service window, before any spend.
        let silence = shape.rekey_envelope[1]
            .checked_add(shape.rekey_envelope[2])
            .and_then(|n| n.checked_add(45_000))
            .ok_or(CryptoError::Configuration)?;
        if shape.idle_duration_ms != 0 && shape.idle_duration_ms < silence {
            return Err(CryptoError::Configuration);
        }
        // Both generations, full legal barriers, phase messages, decoder/MAC
        // scratch and output coexist under this original admission reservation.
        let charge = backing.split(Self::record_limits(&shape)?)?;
        let stream_charge =
            backing.split(streams::State::preparation_limits(&shape, automatic)?)?;
        let datagram_charge = if shape.datagrams {
            Some(backing.split(datagrams::State::preparation_limits(true))?)
        } else {
            None
        };
        let mut keys = Vec::new();
        let mut spare_keys = Vec::new();
        keys.try_reserve_exact(max_keys)
            .map_err(|_| CryptoError::Capacity)?;
        spare_keys
            .try_reserve_exact(max_keys)
            .map_err(|_| CryptoError::Capacity)?;
        let rekey = rekey::CoordinatorStorage::new(geometry, credit)?;
        let streams =
            streams::State::prepare_prepaid(account.clone(), &shape, role, stream_charge)?;
        let datagrams =
            datagrams::State::prepare_prepaid(&account, shape.datagrams, datagram_charge)?;
        Ok(Self {
            account,
            shape,
            role,
            charge,
            max_keys,
            keys,
            spare_keys,
            rekey,
            streams,
            datagrams,
        })
    }
}
impl RecordEngine {
    #[cfg(test)]
    pub(crate) fn hold_record_crypto(
        &self,
        scope: u64,
        frame: u8,
        seal: bool,
        digest: bool,
    ) -> RecordCryptoHold {
        let probe = Arc::new(RecordCryptoProbe {
            scope,
            frame,
            seal,
            digest,
            state: std::sync::Mutex::new((false, false)),
            changed: std::sync::Condvar::new(),
        });
        *self.crypto.test_hold.lock().unwrap() = Some(probe.clone());
        RecordCryptoHold(probe)
    }
    pub(crate) fn finish_record_seal(&mut self, completion: RecordSealCompletion) -> Result<()> {
        self.check()?;
        if let Some(rekey) = completion.rekey {
            self.finish_rekey_seal(rekey)?;
        }
        if let Some(stream) = completion.stream {
            self.finish_stream_seal(stream)?;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn prepare(
        account: ResourceAccount,
        binding: &Binding,
        hash: [u8; 32],
        born: TrustedTimeSample,
        root: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let reservation = RecordReservation::new(account, binding.shape, binding.role)?;
        Self::prepare_reserved(reservation, binding, hash, born, root)
    }
    pub(super) fn prepare_reserved(
        reservation: RecordReservation,
        binding: &Binding,
        hash: [u8; 32],
        born: TrustedTimeSample,
        root: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        if reservation.shape != binding.shape || reservation.role != binding.role {
            return Err(CryptoError::Configuration);
        }
        let RecordReservation {
            account,
            charge,
            max_keys,
            keys,
            spare_keys,
            rekey,
            streams,
            datagrams,
            ..
        } = reservation;
        let crypto = Arc::new(CryptoLifetime {
            stopped: AtomicBool::new(false),
            waiting: std::sync::Mutex::new(()),
            changed: std::sync::Condvar::new(),
            active: AtomicUsize::new(1),
            deadline: std::sync::Mutex::new(None),
            _charge: std::sync::Mutex::new(Some(charge)),
            #[cfg(test)]
            test_hold: std::sync::Mutex::new(None),
        });
        let mut engine = Self {
            account,
            crypto: crypto.clone(),
            profile: binding.profile,
            role: binding.role.index() as u8,
            root,
            hash,
            context: binding.context,
            authenticated_identities: binding.certificates,
            service_authorities: binding.service_authorities,
            application_profile: binding.shape.application_profile,
            resume_policy: binding.resume,
            born,
            epoch: 0,
            max_frame: binding.shape.max_frame,
            max_keys,
            keys,
            epoch_usage: Usage::default(),
            session_usage: Usage::default(),
            key_derivations: 0,
            ready: false,
            closed: false,
            frozen: false,
            deferred_crypto: false,
            candidate: None,
            spare_keys,
            rekey,
            streams,
            datagrams,
            _engine_tail: CryptoTail(crypto),
        };
        engine.datagrams.enabled = binding.features & 1 != 0;
        engine.install(0)?;
        if engine.datagrams.enabled {
            engine.install(datagrams::SCOPE)?;
        }
        if binding.shape.application_profile != 0 {
            engine.install(1)?;
        }
        engine.check()?;
        Ok(engine)
    }
    pub(super) fn start(&mut self, now: TrustedTimeSample) -> Result<()> {
        if self.ready {
            return Err(CryptoError::State);
        }
        self.streams.controls.activate(now)?;
        self.ready = true;
        Ok(())
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.closed || self.crypto.stopped.load(Ordering::Acquire) {
            return Err(CryptoError::State);
        }
        let now = self.account.security_time()?;
        self.check_age(self.born, now)?;
        if let Some(candidate) = &self.candidate {
            self.check_age(candidate.born, now)?;
        }
        if let Err(error) = self.rekey.check_deadline(now) {
            self.rekey.record_timeout(&self.account);
            return Err(error);
        }
        self.streams.check_deadlines(now)
    }
    fn check_age(&self, born: TrustedTimeSample, now: TrustedTimeSample) -> Result<()> {
        if now.clock_incarnation != born.clock_incarnation
            || now
                .upper_ms
                .checked_sub(born.lower_ms)
                .is_none_or(|age| age >= 86_400_000)
        {
            return Err(CryptoError::Deadline);
        }
        Ok(())
    }
    fn fail(&mut self) {
        self.closed = true;
        self.ready = false;
        self.frozen = true;
        self.root.zeroize();
        self.keys.clear();
        self.spare_keys.clear();
        self.candidate = None;
        self.rekey.clear();
        self.streams.close();
        self.datagrams.close();
    }
    pub(super) fn derive_ready_key(&self, info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        self.check()?;
        expand(&self.root, info)
    }
    fn record_key(
        &self,
        root: &[u8; 32],
        epoch: u32,
        scope: u64,
        direction: u8,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut info = domain(
            b"flowersec/v4/record-key\0",
            &[self.profile.name().as_bytes(), &self.hash],
        )?;
        info.extend_from_slice(&epoch.to_be_bytes());
        info.push(direction);
        info.extend_from_slice(&scope.to_be_bytes());
        expand(root, &info)
    }
    fn record_material(
        &self,
        root: &[u8; 32],
        epoch: u32,
        scope: u64,
        direction: u8,
    ) -> Result<Arc<RecordMaterial>> {
        if !self.deferred_crypto {
            return Ok(RecordMaterial::ready(
                self.record_key(root, epoch, scope, direction)?,
            ));
        }
        let mut encoded = domain(
            b"flowersec/v4/record-key\0",
            &[self.profile.name().as_bytes(), &self.hash],
        )?;
        encoded.extend_from_slice(&epoch.to_be_bytes());
        encoded.push(direction);
        encoded.extend_from_slice(&scope.to_be_bytes());
        if encoded.len() > 192 {
            return Err(CryptoError::Capacity);
        }
        let mut info = [0; 192];
        info[..encoded.len()].copy_from_slice(&encoded);
        Ok(Arc::new(RecordMaterial {
            state: std::sync::Mutex::new(RecordMaterialState::Pending {
                root: Zeroizing::new(*root),
                info,
                size: encoded.len(),
            }),
        }))
    }
    fn charge_keys(&mut self, count: usize) -> Result<()> {
        self.key_derivations = self
            .key_derivations
            .checked_add(count as u64)
            .filter(|n| *n <= 1 << 28)
            .ok_or(CryptoError::Capacity)?;
        Ok(())
    }
    fn install(&mut self, scope: u64) -> Result<()> {
        self.check()?;
        if self.keys.iter().any(|k| k.scope == scope) {
            return Err(CryptoError::State);
        }
        if self.keys.len() + 2 > self.max_keys {
            return Err(CryptoError::Capacity);
        }
        self.charge_keys(2)?;
        for direction in 0..2 {
            let key = self.record_material(&self.root, self.epoch, scope, direction)?;
            self.keys.push(RecordKey {
                scope,
                direction,
                key,
                order: RecordOrder::new(),
                next: 0,
                disabled: false,
                usage: Usage::default(),
            });
        }
        Ok(())
    }
    /// Only the Session's admitted live direction owner may install a scope.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Native v4 scope assembly is not yet wired")
    )]
    pub(crate) fn install_reliable_scope(&mut self, scope: u64) -> Result<()> {
        if !self.ready
            || self.frozen
            || scope == 0
            || scope > 4_194_335
            || (scope & 1 == 0 && scope / 2 > 2_097_152)
        {
            return Err(CryptoError::State);
        }
        self.install(scope)
    }
    fn keys_for(&self, future: bool) -> Result<&[RecordKey]> {
        if future {
            Ok(&self.candidate.as_ref().ok_or(CryptoError::State)?.keys)
        } else {
            Ok(&self.keys)
        }
    }
    fn keys_for_mut(&mut self, future: bool) -> Result<&mut [RecordKey]> {
        if future {
            Ok(&mut self.candidate.as_mut().ok_or(CryptoError::State)?.keys)
        } else {
            Ok(&mut self.keys)
        }
    }
    fn slot_for(&self, future: bool, scope: u64, direction: u8) -> Result<usize> {
        self.keys_for(future)?
            .iter()
            .position(|k| k.scope == scope && k.direction == direction && !k.disabled)
            .ok_or(CryptoError::State)
    }
    fn frame_class(frame_type: u8, scope: u64) -> Result<()> {
        if match frame_type {
            7 | 8 => scope != 0,
            6 | 9 | 11..=15 => scope == 0,
            _ => false,
        } {
            Ok(())
        } else {
            Err(CryptoError::Configuration)
        }
    }
    fn aad(&self, envelope: &[u8], header: &[u8], direction: u8) -> Result<Vec<u8>> {
        let mut aad = Vec::new();
        aad.try_reserve_exact(128)
            .map_err(|_| CryptoError::Capacity)?;
        aad.extend_from_slice(b"flowersec/v4/record-aad\0");
        aad.extend_from_slice(envelope);
        aad.extend_from_slice(header);
        aad.extend_from_slice(&(self.profile.name().len() as u32).to_be_bytes());
        aad.extend_from_slice(self.profile.name().as_bytes());
        aad.push(direction);
        Ok(aad)
    }
    fn limits(&self) -> (Usage, Usage, Usage) {
        let shift = u32::from(self.profile == Profile::X25519);
        (
            Usage {
                seals: 1 << 20,
                opens: 1 << 20,
                blocks: 1 << (31 + shift),
                bytes: 1 << 36,
            },
            Usage {
                seals: 1 << (30 + shift),
                opens: 1 << (30 + shift),
                blocks: 1 << (41 + shift),
                bytes: 1 << (45 + shift),
            },
            Usage {
                seals: 1 << (35 + shift),
                opens: 1 << (35 + shift),
                blocks: 1 << (51 + shift),
                bytes: 1 << (55 + shift),
            },
        )
    }
    fn charge(
        &mut self,
        future: bool,
        index: usize,
        seal: bool,
        aad: usize,
        payload: usize,
        protected: bool,
    ) -> Result<()> {
        let delta = Usage {
            seals: u64::from(seal),
            opens: u64::from(!seal),
            blocks: (aad as u64).div_ceil(16) + (payload as u64).div_ceil(16) + 1,
            bytes: payload as u64 + 16,
        };
        let (key_limit, epoch_limit, session_limit) = self.limits();
        let keys = self.keys_for(future)?;
        let key = keys[index].usage.add(delta)?;
        let epoch = if future {
            self.candidate.as_ref().ok_or(CryptoError::State)?.usage
        } else {
            self.epoch_usage
        }
        .add(delta)?;
        let session = self.session_usage.add(delta)?;
        if !key.fits(key_limit) || !epoch.fits(epoch_limit) || !session.fits(session_limit) {
            return Err(CryptoError::Capacity);
        }
        // Ordinary output cannot borrow the schema-derived phase/STOP tail.
        // Received authenticated obligations retain their full hard allowance.
        if seal && !protected {
            let margin = self.rekey.geometry.margin;
            let key_margin = if keys[index].scope == 0 {
                margin
            } else {
                Usage::default()
            };
            if !key.add(key_margin)?.fits(key_limit)
                || !epoch.add(margin)?.fits(epoch_limit)
                || !session.add(margin)?.fits(session_limit)
            {
                return Err(CryptoError::Capacity);
            }
        }
        self.keys_for_mut(future)?[index].usage = key;
        if future {
            self.candidate.as_mut().ok_or(CryptoError::State)?.usage = epoch;
        } else {
            self.epoch_usage = epoch;
        }
        self.session_usage = session;
        Ok(())
    }
    fn prepare_seal(
        &mut self,
        scope: u64,
        frame_type: u8,
        payload: &[u8],
        out: &mut [u8],
        marker: bool,
        protected: bool,
    ) -> Result<(usize, RecordWork)> {
        let result = (|| {
            self.check()?;
            if !self.ready || (scope != 0 && self.frozen) {
                return Err(CryptoError::State);
            }
            Self::frame_class(frame_type, scope)?;
            let future = marker || self.candidate.as_ref().is_some_and(|c| c.sent);
            let epoch = self.epoch + u32::from(future);
            let length = payload.len().checked_add(36).ok_or(CryptoError::Capacity)?;
            if length > self.max_frame || out.len() < length + 8 {
                return Err(CryptoError::Capacity);
            }
            let index = self.slot_for(future, scope, self.role)?;
            let sequence = self.keys_for(future)?[index].next;
            // The first candidate maintenance ticket belongs exclusively to
            // COMMIT/ACK. Ordinary controls may still use the legal old gate.
            if future && scope == 0 && sequence == 0 && !marker {
                return Err(CryptoError::State);
            }
            if marker && (scope != 0 || frame_type != 6 || sequence != 0) {
                return Err(CryptoError::State);
            }
            let next = sequence.checked_add(1).ok_or(CryptoError::Sequence)?;
            out[..4].copy_from_slice(&(length as u32).to_be_bytes());
            out[4..8].copy_from_slice(&[frame_type, 0, 0, 0]);
            out[8..12].copy_from_slice(&epoch.to_be_bytes());
            out[12..20].copy_from_slice(&scope.to_be_bytes());
            out[20..28].copy_from_slice(&sequence.to_be_bytes());
            let aad = self.aad(&out[..8], &out[8..28], self.role)?;
            self.charge(future, index, true, aad.len(), payload.len(), protected)?;
            self.keys_for_mut(future)?[index].next = next;
            self.check()?;
            out[28..28 + payload.len()].copy_from_slice(payload);
            let mut work = self.record_work(future, index, &aad, epoch, sequence)?;
            work.publication = Some(
                self.keys_for(future)?[index]
                    .order
                    .claim(self.crypto.clone())?,
            );
            if frame_type == 6 {
                work.rekey = self.prepare_rekey_seal(payload)?;
            }
            if self.deferred_crypto
                && (frame_type == 7
                    || (frame_type == 9 && scope == 0 && payload.get(..3) == Some(&[0xa3, 0, 5])))
            {
                work.stream = Some(streams::StreamSealPatch {
                    hash: self.hash,
                    profile: self.profile,
                    role: self.role,
                    scope,
                    epoch,
                    frame: frame_type,
                });
            }
            Ok((length + 8, work))
        })();
        if result.is_err() {
            out.zeroize();
        }
        result
    }
    fn record_work(
        &self,
        future: bool,
        index: usize,
        aad: &[u8],
        epoch: u32,
        sequence: u64,
    ) -> Result<RecordWork> {
        if aad.len() > 128 {
            return Err(CryptoError::Capacity);
        }
        let mut fixed_aad = [0; 128];
        fixed_aad[..aad.len()].copy_from_slice(aad);
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&epoch.to_be_bytes());
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        let born = if future {
            self.candidate.as_ref().ok_or(CryptoError::State)?.born
        } else {
            self.born
        };
        let key = self.keys_for(future)?[index].key.clone();
        let deadline = self
            .rekey
            .work_deadline()
            .into_iter()
            .chain(self.streams.crypto_deadline(
                self.keys_for(future)?[index].scope,
                self.keys_for(future)?[index].direction,
            ))
            .min();
        let receive_view = (self.keys_for(future)?[index].direction != self.role)
            .then(|| {
                self.streams
                    .record_view(self.keys_for(future).ok()?[index].scope)
            })
            .flatten();
        let send_view = (self.keys_for(future)?[index].direction == self.role)
            .then(|| {
                self.streams
                    .record_view(self.keys_for(future).ok()?[index].scope)
            })
            .flatten();
        self.crypto.active.fetch_add(1, Ordering::AcqRel);
        Ok(RecordWork {
            lifetime: self.crypto.clone(),
            account: self.account.clone(),
            born,
            profile: self.profile,
            deadline,
            key: Some(key),
            aad: fixed_aad,
            aad_len: aad.len(),
            nonce,
            publication: None,
            rekey: None,
            stream: None,
            receive_view,
            send_view,
        })
    }
    #[cfg(test)]
    fn seal(
        &mut self,
        scope: u64,
        frame_type: u8,
        payload: &[u8],
        out: &mut [u8],
        marker: bool,
        protected: bool,
    ) -> Result<usize> {
        let (n, work) = self.prepare_seal(scope, frame_type, payload, out, marker, protected)?;
        work.seal(&mut out[..n])?;
        self.check()?;
        Ok(n)
    }
    #[cfg(test)]
    pub(crate) fn seal_reliable(
        &mut self,
        scope: u64,
        frame_type: u8,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        self.seal(scope, frame_type, payload, out, false, false)
    }
    /// The original publisher owns the sole output order. Reversible admission
    /// refusals preserve the owner; a failed irreversible ticket never retries.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Native v4 ordered publisher is not yet wired")
    )]
    pub(crate) fn publish_reliable(
        &mut self,
        scope: u64,
        frame_type: u8,
        payload: &[u8],
        out: &mut [u8],
        publisher: &mut dyn RecordPublisher,
    ) -> Result<()> {
        if frame_type == 6 || (scope != 0 && self.frozen) {
            out.zeroize();
            return Err(CryptoError::State);
        }
        let future = self.candidate.as_ref().is_some_and(|c| c.sent);
        let before = self
            .slot_for(future, scope, self.role)
            .ok()
            .and_then(|i| self.keys_for(future).ok().map(|keys| keys[i].next));
        let (n, work) = match self.prepare_seal(scope, frame_type, payload, out, false, false) {
            Ok(n) => n,
            Err(error) => {
                let after = self
                    .slot_for(future, scope, self.role)
                    .ok()
                    .and_then(|i| self.keys_for(future).ok().map(|keys| keys[i].next));
                if before != after
                    || !matches!(
                        error,
                        CryptoError::State | CryptoError::Capacity | CryptoError::Configuration
                    )
                {
                    self.fail();
                }
                return Err(error);
            }
        };
        let result = publisher
            .publish_seal(work, &mut out[..n])
            .and_then(|()| self.check());
        out.zeroize();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn receive_generation(&self, scope: u64, wire: &[u8], marker: bool) -> Result<bool> {
        if wire.len() < 44 {
            return Err(CryptoError::Authentication);
        }
        let epoch = u32::from_be_bytes(
            wire[8..12]
                .try_into()
                .map_err(|_| CryptoError::Authentication)?,
        );
        if epoch == self.epoch {
            if marker || self.candidate.as_ref().is_some_and(|c| c.received) {
                return Err(CryptoError::Sequence);
            }
            return Ok(false);
        }
        let c = self.candidate.as_ref().ok_or(CryptoError::Sequence)?;
        if epoch != self.epoch + 1 {
            return Err(CryptoError::Sequence);
        }
        if marker {
            if !c.armed || c.received || scope != 0 || wire[4] != 6 || wire[20..28] != [0; 8] {
                return Err(CryptoError::State);
            }
        } else if scope == 0 {
            if !c.received {
                return Err(CryptoError::State);
            }
        } else if !c.sent {
            return Err(CryptoError::State);
        }
        Ok(true)
    }
    fn prepare_open(&mut self, scope: u64, wire: &[u8], marker: bool) -> Result<RecordOpen> {
        let future = self.receive_generation(scope, wire, marker)?;
        let direction = 1 - self.role;
        let index = self.slot_for(future, scope, direction)?;
        let result = (|| {
            self.check()?;
            if !self.ready {
                return Err(CryptoError::State);
            }
            if wire.len() - 8 > self.max_frame {
                return Err(CryptoError::Capacity);
            }
            let length = u32::from_be_bytes(
                wire[..4]
                    .try_into()
                    .map_err(|_| CryptoError::Authentication)?,
            ) as usize;
            if length != wire.len() - 8
                || wire[5..8] != [0, 0, 0]
                || wire[12..20] != scope.to_be_bytes()
            {
                return Err(CryptoError::Authentication);
            }
            Self::frame_class(wire[4], scope)?;
            let sequence = u64::from_be_bytes(
                wire[20..28]
                    .try_into()
                    .map_err(|_| CryptoError::Authentication)?,
            );
            if sequence != self.keys_for(future)?[index].next {
                return Err(CryptoError::Sequence);
            }
            let next = sequence.checked_add(1).ok_or(CryptoError::Sequence)?;
            let epoch = u32::from_be_bytes(
                wire[8..12]
                    .try_into()
                    .map_err(|_| CryptoError::Authentication)?,
            );
            let aad = self.aad(&wire[..8], &wire[8..28], direction)?;
            self.charge(future, index, false, aad.len(), wire.len() - 44, true)?;
            self.check()?;
            Ok(RecordOpen {
                work: self.record_work(future, index, &aad, epoch, sequence)?,
                epoch,
                scope,
                next,
            })
        })();
        if result.is_err() {
            self.keys_for_mut(future)?[index].disabled = true;
        }
        result
    }
    fn commit_open(
        &mut self,
        ticket: &RecordOpen,
        frame: u8,
        plain: &[u8],
        validate: impl FnOnce(&Self, u8, &[u8]) -> Result<()>,
    ) -> Result<()> {
        ticket.work.check()?;
        self.check()?;
        let future = ticket.epoch == self.epoch.checked_add(1).ok_or(CryptoError::Sequence)?;
        if !future && ticket.epoch != self.epoch {
            return Err(CryptoError::Sequence);
        }
        let index = self.slot_for(future, ticket.scope, 1 - self.role)?;
        if self.keys_for(future)?[index].next != ticket.next - 1 {
            return Err(CryptoError::Sequence);
        }
        validate(self, frame, plain)?;
        self.check()?;
        let account = self.account.clone();
        account.with_security(|| {
            self.keys_for_mut(future)
                .map(|keys| keys[index].next = ticket.next)
        })??;
        Ok(())
    }
    fn disable_open(&mut self, ticket: &RecordOpen) {
        let future = ticket.epoch == self.epoch.saturating_add(1);
        if let Ok(index) = self.slot_for(future, ticket.scope, 1 - self.role)
            && let Ok(keys) = self.keys_for_mut(future)
        {
            keys[index].disabled = true;
        }
    }
    fn open(
        &mut self,
        scope: u64,
        wire: &[u8],
        out: &mut [u8],
        marker: bool,
        validate: impl FnOnce(&Self, u8, &[u8]) -> Result<()>,
    ) -> Result<usize> {
        let ticket = self.prepare_open(scope, wire, marker)?;
        let result = ticket.execute(wire, out).and_then(|n| {
            self.commit_open(&ticket, wire[4], &out[..n], validate)?;
            Ok(n)
        });
        if result.is_err() {
            self.disable_open(&ticket);
            out.zeroize();
        }
        result
    }
    /// Future application plaintext is private until application_input_ready.
    /// The original receiver retains it in its existing charged output slot.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Native v4 record input owner is not yet wired")
    )]
    pub(crate) fn open_reliable(
        &mut self,
        scope: u64,
        wire: &[u8],
        out: &mut [u8],
        validate: impl FnOnce(u8, &[u8]) -> Result<()>,
    ) -> Result<usize> {
        if wire.get(4) == Some(&6) {
            return Err(CryptoError::State);
        }
        let result = self.open(scope, wire, out, false, |_, frame, plain| {
            validate(frame, plain)
        });
        if let Err(error) = &result {
            out.zeroize();
            if scope == 0 || matches!(error, CryptoError::Authorization(_) | CryptoError::Deadline)
            {
                self.fail();
            }
        }
        result
    }
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Native v4 delivery owner is not yet wired")
    )]
    pub(crate) fn application_input_ready(&self, epoch: u32) -> Result<()> {
        self.check()?;
        if epoch != self.epoch {
            return Err(CryptoError::State);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_bad_tag_and_semantic_failure_keep_attempt_charges_and_frontiers() {
        let (_fixture, mut sender, mut receiver) =
            crate::crypto_v4::tests::record_pair_for_limits(Profile::P256);
        for scope in [1, 3] {
            sender.install_reliable_scope(scope).unwrap();
            receiver.install_reliable_scope(scope).unwrap();
        }
        let mut wire = [0; 128];
        let mut plain = [0; 128];
        let n = sender.seal_reliable(1, 8, b"bad tag", &mut wire).unwrap();
        wire[n - 1] ^= 1;
        assert!(
            receiver
                .open_reliable(1, &wire[..n], &mut plain, |_, _| Ok(()))
                .is_err()
        );
        assert_eq!(receiver.epoch_usage.opens, 1);
        assert_eq!(receiver.session_usage.opens, 1);
        assert_eq!(
            receiver
                .keys
                .iter()
                .find(|key| key.scope == 1 && key.direction == 0)
                .unwrap()
                .next,
            0
        );
        let before = receiver.session_usage;
        assert!(
            receiver
                .open_reliable(1, &wire[..n], &mut plain, |_, _| Ok(()))
                .is_err()
        );
        assert_eq!(receiver.session_usage, before);
        let n = sender
            .seal_reliable(3, 8, b"bad protocol", &mut wire)
            .unwrap();
        assert!(
            receiver
                .open_reliable(3, &wire[..n], &mut plain, |_, _| Err(
                    CryptoError::Authentication
                ))
                .is_err()
        );
        assert_eq!(receiver.session_usage.opens, 2);
        assert_eq!(
            receiver
                .keys
                .iter()
                .find(|key| key.scope == 3 && key.direction == 0)
                .unwrap()
                .next,
            0
        );
    }
    #[test]
    fn exhausted_usage_and_expired_original_root_refuse_before_aead() {
        let (_fixture, mut sender, _) =
            crate::crypto_v4::tests::record_pair_for_limits(Profile::X25519);
        let mut wire = [0; 128];
        sender.keys[0].usage.seals = 1 << 20;
        let usage = sender.session_usage;
        assert_eq!(
            sender.seal_reliable(0, 14, b"", &mut wire),
            Err(CryptoError::Capacity)
        );
        assert_eq!(sender.session_usage, usage);
        sender.keys[0].usage.seals = 0;
        sender.born.lower_ms = 0;
        // Original birth is not reset by scope installation or READY handoff.
        sender.born.clock_incarnation = sender.born.clock_incarnation.wrapping_add(1);
        assert_eq!(
            sender.seal_reliable(0, 14, b"", &mut wire),
            Err(CryptoError::Deadline)
        );
        assert_eq!(sender.session_usage, usage);
    }
}
