//! Reliable records and the original, exclusive rekey crypto owner. The Session
//! supplies admitted scopes; an unauthenticated header never creates a key.
use super::{Binding, CryptoError, Profile, RecordPublisher, Result, domain, expand};
use crate::environment_v4::{ResourceAccount, ResourceCharge, ResourceLimits, TrustedTimeSample};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use std::fmt;
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
    NativeStreamBinding, ReliableSession, ResumeMessageClaim, SessionLink, SessionReceiver,
    SessionTransport, StreamPreparation, StreamPublicationAdmission, StreamView,
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
struct RecordKey {
    scope: u64,
    direction: u8,
    key: Zeroizing<[u8; 32]>,
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
    _charge: ResourceCharge,
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
    candidate: Option<Candidate>,
    spare_keys: Vec<RecordKey>,
    rekey: rekey::Coordinator,
    streams: streams::State,
    datagrams: datagrams::State,
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
    rekey: rekey::Coordinator,
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
            sdk_bytes: (2 * max_keys * std::mem::size_of::<RecordKey>()
                + std::mem::size_of::<RecordEngine>()
                + geometry.bytes
                + 256) as u64,
            items: (2 * max_keys + 4) as u64,
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
        let rekey = rekey::Coordinator::new(geometry, credit)?;
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
        let mut engine = Self {
            account,
            _charge: charge,
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
            candidate: None,
            spare_keys,
            rekey,
            streams,
            datagrams,
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
        if self.closed {
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
            let key = self.record_key(&self.root, self.epoch, scope, direction)?;
            self.keys.push(RecordKey {
                scope,
                direction,
                key,
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
    fn cipher(&self, future: bool, index: usize) -> Result<LessSafeKey> {
        let algorithm = match self.profile {
            Profile::X25519 => &aead::CHACHA20_POLY1305,
            Profile::P256 => &aead::AES_256_GCM,
        };
        Ok(LessSafeKey::new(
            UnboundKey::new(algorithm, self.keys_for(future)?[index].key.as_ref())
                .map_err(|_| CryptoError::Key)?,
        ))
    }
    fn seal(
        &mut self,
        scope: u64,
        frame_type: u8,
        payload: &[u8],
        out: &mut [u8],
        marker: bool,
        protected: bool,
    ) -> Result<usize> {
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
            let mut nonce = [0; 12];
            nonce[..4].copy_from_slice(&epoch.to_be_bytes());
            nonce[4..].copy_from_slice(&sequence.to_be_bytes());
            let tag = self
                .cipher(future, index)?
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut out[28..28 + payload.len()],
                )
                .map_err(|_| CryptoError::Authentication)?;
            out[28 + payload.len()..length + 8].copy_from_slice(tag.as_ref());
            self.check()?;
            Ok(length + 8)
        })();
        if result.is_err() {
            out.zeroize();
        }
        result
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
        let n = match self.seal(scope, frame_type, payload, out, false, false) {
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
        let result = publisher.publish(&out[..n]).and_then(|()| self.check());
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
    fn open(
        &mut self,
        scope: u64,
        wire: &[u8],
        out: &mut [u8],
        marker: bool,
        validate: impl FnOnce(&Self, u8, &[u8]) -> Result<()>,
    ) -> Result<usize> {
        let future = self.receive_generation(scope, wire, marker)?;
        let direction = 1 - self.role;
        let index = self.slot_for(future, scope, direction)?;
        let result = (|| {
            self.check()?;
            if !self.ready {
                return Err(CryptoError::State);
            }
            if wire.len() - 8 > self.max_frame || out.len() < wire.len() - 28 {
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
            let aad = self.aad(&wire[..8], &wire[8..28], direction)?;
            let size = wire.len() - 28;
            let payload = size - 16;
            self.charge(future, index, false, aad.len(), payload, true)?;
            self.check()?;
            out[..size].copy_from_slice(&wire[28..]);
            let mut nonce = [0; 12];
            nonce[..4].copy_from_slice(&wire[8..12]);
            nonce[4..].copy_from_slice(&sequence.to_be_bytes());
            let plain = self
                .cipher(future, index)?
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut out[..size],
                )
                .map_err(|_| CryptoError::Authentication)?;
            if plain.len() != payload {
                return Err(CryptoError::Authentication);
            }
            validate(self, wire[4], plain)?;
            self.check()?;
            // Frontier publication shares the original revocation/close gate.
            let account = self.account.clone();
            account.with_security(|| {
                self.keys_for_mut(future)
                    .map(|keys| keys[index].next = next)
            })??;
            out[payload..size].zeroize();
            Ok(payload)
        })();
        if result.is_err() {
            self.keys_for_mut(future)?[index].disabled = true;
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
