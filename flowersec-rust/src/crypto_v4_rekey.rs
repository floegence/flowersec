//! Single-flight reliable rekey. Bounded original jobs own DH/KDF and phase
//! authentication outside Session gates; only claim/commit transitions hold state.
use super::*;
use crate::crypto_v4::{decode, keys::SoftwareDh, mac};
use crate::{
    codec_v4::{self as codec, Context, Value},
    environment_v4::TrustedTimeProfile,
};
use hkdf::Hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::time::Instant;

pub(super) struct Geometry {
    pub(super) bytes: usize,
    pub(super) margin: Usage,
    phase_bytes: usize,
    scopes: usize,
}
impl Geometry {
    pub(super) fn new(shape: &super::super::RecordShape) -> Result<Self> {
        // Canonical REPLY fixed fields plus maximum uint64 barrier entries.
        // Two complete messages and REQUEST coexist in the 64 KiB normal lane.
        let phase_bytes = 268 + 21 * shape.max_streams;
        if phase_bytes + 36 > shape.max_frame || 2 * phase_bytes + 3 > 65_536 {
            return Err(CryptoError::Configuration);
        }
        // Each active scope can contribute STOP/STOPPED/DRAINED in each
        // direction, plus two retirement flights, liveness and the four phases.
        // 4 KiB is the maximum critical item; rekey messages use their full cap.
        let calls = 6 * shape.max_streams as u64 + 32;
        let bytes = calls * 4096 + 2 * phase_bytes as u64;
        let margin = Usage {
            seals: calls,
            opens: calls,
            blocks: bytes.div_ceil(16) + calls * 9,
            bytes: bytes + calls * 16,
        };
        Ok(Self {
            bytes: 6 * phase_bytes
                + 3 * shape.max_streams * std::mem::size_of::<Entry>()
                + 32_768
                + 3 * std::mem::size_of::<RekeyCrypto>()
                + 3 * std::mem::size_of::<RekeyAuthentication>()
                + std::mem::size_of::<RoundSeed>(),
            margin,
            phase_bytes,
            scopes: shape.max_streams,
        })
    }
}
pub(super) struct Credit {
    burst: u64,
    period: u64,
    start_budget: u64,
    base: u64,
    anchor: Option<TrustedTimeSample>,
    profile: TrustedTimeProfile,
    maximum_rounds: u64,
    rounds: u64,
}
impl Credit {
    pub(super) fn new(
        envelope: [u64; 3],
        service: u64,
        profile: TrustedTimeProfile,
    ) -> Result<Self> {
        let [burst, period, start_budget] = envelope;
        if period
            .checked_add(start_budget)
            .and_then(|n| n.checked_add(45_000))
            .is_none_or(|n| n >= 86_400_000)
        {
            return Err(CryptoError::Configuration);
        }
        if burst == 0
            || burst >= 65_536
            || period == 0
            || period > u32::MAX as u64
            || start_budget == 0
            || start_budget > u32::MAX as u64
            || service == 0
            || profile.rate_denominator == 0
            || profile.rate_numerator >= profile.rate_denominator
        {
            return Err(CryptoError::Configuration);
        }
        let d = u128::from(profile.rate_denominator);
        let n = u128::from(profile.rate_numerator);
        let eta = u128::from(profile.quantization_ms);
        let e = eta
            .checked_mul(2)
            .and_then(|x| x.checked_mul(d))
            .ok_or(CryptoError::Capacity)?
            .div_ceil(d - n)
            .checked_add(1)
            .ok_or(CryptoError::Capacity)?;
        let cost = u128::from(burst)
            .checked_mul(e)
            .ok_or(CryptoError::Capacity)?;
        let gap = u128::from(period)
            .checked_sub(cost)
            .filter(|x| *x > 0)
            .ok_or(CryptoError::Configuration)?;
        // Exact rational Nmax. No floating point or rounded intermediate a.
        let capacity = u128::from(burst) * u128::from(period);
        let numerator = capacity
            .checked_mul(d - n)
            .and_then(|x| {
                u128::from(burst)
                    .checked_mul(d + n)
                    .and_then(|x| x.checked_mul(u128::from(service)))
                    .and_then(|y| x.checked_add(y))
            })
            .ok_or(CryptoError::Capacity)?;
        let denominator = gap.checked_mul(d - n).ok_or(CryptoError::Capacity)?;
        let maximum_rounds =
            u64::try_from(numerator / denominator).map_err(|_| CryptoError::Capacity)?;
        if maximum_rounds == 0 || maximum_rounds >= 65_536 {
            return Err(CryptoError::Configuration);
        }
        Ok(Self {
            burst,
            period,
            start_budget,
            base: u64::try_from(capacity).map_err(|_| CryptoError::Capacity)?,
            anchor: None,
            profile,
            maximum_rounds,
            rounds: 0,
        })
    }
    fn available(&self, now: TrustedTimeSample, server: bool) -> Result<u64> {
        let capacity = self.burst * self.period;
        let Some(anchor) = self.anchor else {
            return Ok(self.base);
        };
        if now.clock_incarnation != anchor.clock_incarnation {
            return Err(CryptoError::Deadline);
        }
        let delta = now
            .monotonic_sample
            .checked_duration_since(anchor.monotonic_sample)
            .ok_or(CryptoError::Deadline)?;
        let millis = u64::try_from(delta.as_millis()).map_err(|_| CryptoError::Capacity)?;
        let d = u128::from(self.profile.rate_denominator);
        let n = u128::from(self.profile.rate_numerator);
        let elapsed = if server {
            let ceil = millis
                .checked_add(u64::from(!delta.subsec_nanos().is_multiple_of(1_000_000)))
                .ok_or(CryptoError::Capacity)?;
            u128::from(
                ceil.checked_add(self.profile.quantization_ms)
                    .ok_or(CryptoError::Capacity)?,
            )
            .checked_mul(d)
            .ok_or(CryptoError::Capacity)?
            .div_ceil(d - n)
        } else {
            u128::from(millis.saturating_sub(self.profile.quantization_ms))
                .checked_mul(d)
                .ok_or(CryptoError::Capacity)?
                / (d + n)
        };
        if elapsed >= u128::from(self.period) {
            return Ok(capacity);
        }
        Ok(self
            .base
            .checked_add(self.burst * elapsed as u64)
            .ok_or(CryptoError::Capacity)?
            .min(capacity))
    }
    fn charge(&mut self, now: TrustedTimeSample, server: bool) -> Result<u64> {
        if self.rounds >= self.maximum_rounds {
            return Err(CryptoError::Capacity);
        }
        let post = self
            .available(now, server)?
            .checked_sub(self.period)
            .ok_or(CryptoError::Capacity)?;
        self.rounds += 1;
        Ok(post)
    }
    fn complete(&mut self, post: u64, now: TrustedTimeSample) {
        self.base = post;
        self.anchor = Some(now);
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    scope: u64,
    next: u64,
}
struct Round {
    id: [u8; 16],
    secret: Zeroizing<[u8; 32]>,
    confirm_keys: [Zeroizing<[u8; 32]>; 4],
    ephemeral: Option<SoftwareDh>,
    init: Vec<u8>,
    reply: Vec<u8>,
    outgoing: Vec<Entry>,
    incoming: Vec<Entry>,
    transcript: [u8; 32],
    init_digest: [u8; 32],
    post_credit: u64,
    stage: u8,
}
pub(super) struct Coordinator {
    pub(super) geometry: Geometry,
    credit: Credit,
    round: Option<Round>,
    seed: Option<RoundSeed>,
    crypto: Option<RekeyCrypto>,
    crypto_pending: bool,
    pending_incoming: Vec<Entry>,
    intent: Option<Instant>,
    requested: bool,
    timeout_reported: std::sync::atomic::AtomicBool,
    deadline: Option<Instant>,
    output: Vec<u8>,
    init: Vec<u8>,
    reply: Vec<u8>,
    outgoing: Vec<Entry>,
    incoming: Vec<Entry>,
}
// The original reservation owns this fixed slot before admission is consumed.
// Keep the coordinator's crypto jobs out of each enclosing async stack frame;
// transferring the reservation into the engine transfers this same allocation.
pub(super) struct CoordinatorStorage(Vec<Coordinator>);
impl CoordinatorStorage {
    pub(super) fn new(geometry: Geometry, credit: Credit) -> Result<Self> {
        let mut slot = Vec::new();
        slot.try_reserve_exact(1)
            .map_err(|_| CryptoError::Capacity)?;
        slot.push(Coordinator::new(geometry, credit)?);
        Ok(Self(slot))
    }
}
impl std::ops::Deref for CoordinatorStorage {
    type Target = Coordinator;
    fn deref(&self) -> &Self::Target {
        &self.0[0]
    }
}
impl std::ops::DerefMut for CoordinatorStorage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[0]
    }
}
fn buffer(cap: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(cap)
        .map_err(|_| CryptoError::Capacity)?;
    Ok(v)
}
impl Coordinator {
    pub(super) fn new(geometry: Geometry, credit: Credit) -> Result<Self> {
        let mut output = buffer(geometry.phase_bytes + 44)?;
        output.resize(geometry.phase_bytes + 44, 0);
        let init = buffer(geometry.phase_bytes)?;
        let reply = buffer(geometry.phase_bytes)?;
        let mut outgoing = Vec::new();
        let mut incoming = Vec::new();
        outgoing
            .try_reserve_exact(geometry.scopes)
            .map_err(|_| CryptoError::Capacity)?;
        incoming
            .try_reserve_exact(geometry.scopes)
            .map_err(|_| CryptoError::Capacity)?;
        let mut pending_incoming = Vec::new();
        pending_incoming
            .try_reserve_exact(geometry.scopes)
            .map_err(|_| CryptoError::Capacity)?;
        Ok(Self {
            geometry,
            credit,
            round: None,
            seed: None,
            crypto: None,
            crypto_pending: false,
            pending_incoming,
            intent: None,
            requested: false,
            timeout_reported: std::sync::atomic::AtomicBool::new(false),
            deadline: None,
            output,
            init,
            reply,
            outgoing,
            incoming,
        })
    }
    pub(super) fn work_deadline(&self) -> Option<Instant> {
        self.deadline.or(self.intent)
    }
    pub(super) fn check_deadline(&self, now: TrustedTimeSample) -> Result<()> {
        if self.deadline.is_some_and(|d| now.monotonic_sample >= d)
            || self.round.is_none() && self.intent.is_some_and(|d| now.monotonic_sample >= d)
        {
            return Err(CryptoError::Deadline);
        }
        Ok(())
    }
    pub(super) fn record_timeout(&self, account: &crate::environment_v4::ResourceAccount) {
        if !self
            .timeout_reported
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            account.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::RekeyTimeouts);
        }
    }
    pub(super) fn busy(&self) -> bool {
        self.intent.is_some() || self.round.is_some() || self.crypto_pending
    }
    pub(super) fn clear(&mut self) {
        self.round = None;
        self.seed = None;
        self.crypto = None;
        self.crypto_pending = false;
        self.pending_incoming.clear();
        self.output.zeroize();
        self.init.zeroize();
        self.reply.zeroize();
        self.outgoing.clear();
        self.incoming.clear();
    }
    fn deadline_after(now: Instant, millis: u64) -> Result<Instant> {
        now.checked_add(Duration::from_millis(millis))
            .ok_or(CryptoError::Capacity)
    }
    fn finish(&mut self, now: TrustedTimeSample) -> Result<()> {
        let round = self.round.take().ok_or(CryptoError::State)?;
        self.credit.complete(round.post_credit, now);
        self.init = round.init;
        self.reply = round.reply;
        self.outgoing = round.outgoing;
        self.incoming = round.incoming;
        self.init.clear();
        self.reply.clear();
        self.outgoing.clear();
        self.incoming.clear();
        self.intent = None;
        self.requested = false;
        self.deadline = None;
        Ok(())
    }
}
fn lp(out: &mut Vec<u8>, part: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u32::try_from(part.len())
            .map_err(|_| CryptoError::Capacity)?
            .to_be_bytes(),
    );
    out.extend_from_slice(part);
    Ok(())
}
fn uint(out: &mut Vec<u8>, n: u64) {
    codec::encode_head(out, 0, n);
}
fn data(out: &mut Vec<u8>, bytes: &[u8]) {
    codec::encode_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
fn barrier(out: &mut Vec<u8>, entries: &[Entry]) {
    codec::encode_head(out, 4, entries.len() as u64);
    for e in entries {
        codec::encode_head(out, 5, 2);
        uint(out, 0);
        uint(out, e.scope);
        uint(out, 1);
        uint(out, e.next);
    }
}
pub(crate) struct SealPatch {
    hash: [u8; 32],
    context: [u8; 32],
    profile: Profile,
    epoch: u32,
    id: [u8; 16],
    phase: u8,
    key: Zeroizing<[u8; 32]>,
    init: Option<Vec<u8>>,
}
pub(crate) struct SealCompletion {
    epoch: u32,
    id: [u8; 16],
    init: Vec<u8>,
    digest: [u8; 32],
}
impl SealPatch {
    pub(crate) fn execute(mut self, body: &mut [u8]) -> Result<Option<SealCompletion>> {
        let name = RecordEngine::schema(self.phase)?;
        let value = decode(body, name, body.len(), Context::default())?;
        let mac_id = if self.phase == 2 { 6 } else { 5 };
        let original_tag = value.field(name, "confirmation_mac")?.bytes()?;
        if original_tag.len() != 32 {
            return Err(CryptoError::Authentication);
        }
        let offset = original_tag.as_ptr() as usize - body.as_ptr() as usize;
        let mut unsigned = buffer(body.len())?;
        codec::encode_head(&mut unsigned, 5, (value.len()? - 1) as u64);
        let mut fields = value.children()?;
        while let Some(id) = fields.next() {
            let id = id?;
            let value = fields.next().ok_or(CryptoError::Authentication)??;
            if id.uint()? != mac_id {
                unsigned.extend_from_slice(id.raw());
                unsigned.extend_from_slice(value.raw());
            }
        }
        let mut msg = domain(
            b"flowersec/v4/rekey-confirm-mac\0",
            &[self.profile.name().as_bytes(), &self.hash, &self.context],
        )?;
        msg.extend_from_slice(&self.epoch.to_be_bytes());
        msg.extend_from_slice(&(self.epoch + 1).to_be_bytes());
        msg.extend_from_slice(&[self.phase, (self.phase + 1) % 2]);
        lp(&mut msg, &unsigned)?;
        let tag = mac(&self.key, &msg);
        body[offset..offset + 32].copy_from_slice(&tag);
        let Some(mut init) = self.init.take() else {
            return Ok(None);
        };
        init.clear();
        init.extend_from_slice(body);
        let mut input = domain(
            b"flowersec/v4/rekey-init-digest\0",
            &[&self.hash, self.profile.name().as_bytes()],
        )?;
        input.extend_from_slice(&self.epoch.to_be_bytes());
        lp(&mut input, body)?;
        Ok(Some(SealCompletion {
            epoch: self.epoch,
            id: self.id,
            init,
            digest: Sha256::digest(&input).into(),
        }))
    }
}
struct RoundSeed {
    started: Instant,
    deadline: Instant,
    id: [u8; 16],
    secret: Zeroizing<[u8; 32]>,
    ephemeral: SoftwareDh,
    confirm_keys: [Zeroizing<[u8; 32]>; 4],
}
struct RekeyContext {
    guard: RecordWork,
    root: Zeroizing<[u8; 32]>,
    profile: Profile,
    hash: [u8; 32],
    context: [u8; 32],
    epoch: u32,
    phase_bytes: usize,
}
impl RekeyContext {
    fn domain(&self, label: &[u8]) -> Result<Vec<u8>> {
        let mut v = domain(
            label,
            &[self.profile.name().as_bytes(), &self.hash, &self.context],
        )?;
        v.extend_from_slice(&self.epoch.to_be_bytes());
        Ok(v)
    }
    fn confirm_key(
        &self,
        base: &[u8; 32],
        id: &[u8; 16],
        phase: u8,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut info = self.domain(b"flowersec/v4/rekey-confirm-key\0")?;
        info.extend_from_slice(&(self.epoch + 1).to_be_bytes());
        lp(&mut info, id)?;
        info.extend_from_slice(&[phase, (phase + 1) % 2]);
        expand(base, &info)
    }
    fn seed(&self, id: [u8; 16]) -> Result<RoundSeed> {
        self.guard.check()?;
        let started = self.guard.account.security_time()?.monotonic_sample;
        let secret = expand(&self.root, &self.domain(b"flowersec/v4/rekey-secret\0")?)?;
        let ephemeral = SoftwareDh::ephemeral(self.profile)?;
        let mut confirm_keys = std::array::from_fn(|_| Zeroizing::new([0; 32]));
        for phase in 1..=2 {
            confirm_keys[usize::from(phase - 1)] = self.confirm_key(&secret, &id, phase)?;
        }
        self.guard.check()?;
        Ok(RoundSeed {
            started,
            deadline: self
                .guard
                .deadline
                .into_iter()
                .chain(Some(Coordinator::deadline_after(started, 5000)?))
                .min()
                .ok_or(CryptoError::Deadline)?,
            id,
            secret,
            ephemeral,
            confirm_keys,
        })
    }
    fn transcript(&self, label: &[u8], init: &[u8], reply: Option<&[u8]>) -> Result<[u8; 32]> {
        let mut v = domain(label, &[&self.hash, self.profile.name().as_bytes()])?;
        v.extend_from_slice(&self.epoch.to_be_bytes());
        lp(&mut v, init)?;
        if let Some(reply) = reply {
            lp(&mut v, reply)?;
        }
        Ok(Sha256::digest(&v).into())
    }
    fn phase_mac(&self, key: &[u8; 32], phase: u8, unsigned: &[u8]) -> Result<[u8; 32]> {
        let mut msg = self.domain(b"flowersec/v4/rekey-confirm-mac\0")?;
        msg.extend_from_slice(&(self.epoch + 1).to_be_bytes());
        msg.extend_from_slice(&[phase, (phase + 1) % 2]);
        lp(&mut msg, unsigned)?;
        Ok(mac(key, &msg))
    }
    fn reply(&self, round: &Round) -> Result<Vec<u8>> {
        let mut out = buffer(self.phase_bytes)?;
        codec::encode_head(&mut out, 5, 6);
        uint(&mut out, 0);
        uint(&mut out, 2);
        uint(&mut out, 1);
        data(&mut out, &round.id);
        uint(&mut out, 2);
        uint(&mut out, u64::from(self.epoch + 1));
        uint(&mut out, 3);
        data(&mut out, &round.init_digest);
        uint(&mut out, 4);
        data(
            &mut out,
            round.ephemeral.as_ref().ok_or(CryptoError::State)?.public(),
        );
        uint(&mut out, 5);
        barrier(&mut out, &round.outgoing);
        let tag = self.phase_mac(&round.confirm_keys[1], 2, &out)?;
        out[0] += 1;
        uint(&mut out, 6);
        data(&mut out, &tag);
        if out.len() > self.phase_bytes {
            return Err(CryptoError::Capacity);
        }
        Ok(out)
    }
}
pub(crate) struct RekeyAuthentication {
    context: RekeyContext,
    phase: u8,
    marker: bool,
    base: Zeroizing<[u8; 32]>,
}
impl RekeyAuthentication {
    pub(crate) fn verify(&self, body: &[u8]) -> Result<()> {
        self.context.guard.check()?;
        let phase = if self.phase == 0 || !self.marker && body == [0xa1, 0, 0] {
            0
        } else {
            self.phase
        };
        if phase == 0 {
            return Ok(());
        }
        let name = RecordEngine::schema(phase)?;
        let value = decode(body, name, self.context.phase_bytes, Context::default())?;
        let id = value.b(name, "rekey_id")?;
        let secret = if phase == 1 {
            expand(
                &self.context.root,
                &self.context.domain(b"flowersec/v4/rekey-secret\0")?,
            )?
        } else {
            Zeroizing::new(*self.base)
        };
        let key = self.context.confirm_key(&secret, &id, phase)?;
        let mac_id = if phase == 2 { 6 } else { 5 };
        let mut unsigned = buffer(body.len())?;
        codec::encode_head(&mut unsigned, 5, (value.len()? - 1) as u64);
        let mut fields = value.children()?;
        while let Some(id) = fields.next() {
            let id = id?;
            let value = fields.next().ok_or(CryptoError::Authentication)??;
            if id.uint()? != mac_id {
                unsigned.extend_from_slice(id.raw());
                unsigned.extend_from_slice(value.raw());
            }
        }
        let tag = self.context.phase_mac(&key, phase, &unsigned)?;
        if !bool::from(tag.ct_eq(&value.b::<32>(name, "confirmation_mac")?)) {
            return Err(CryptoError::Authentication);
        }
        if phase <= 2 {
            crate::crypto_v4::keys::check_public(
                self.context.profile,
                value
                    .field(
                        name,
                        if phase == 1 {
                            "client_ephemeral"
                        } else {
                            "server_ephemeral"
                        },
                    )?
                    .bytes()?,
            )?;
        }
        self.context.guard.check()
    }
}
pub(crate) struct RekeyCrypto {
    kind: RekeyCryptoKind,
}
enum RekeyCryptoKind {
    Seed {
        context: RekeyContext,
    },
    Candidate {
        context: RekeyContext,
        round: Round,
        peer: [u8; 65],
        peer_len: usize,
        keys: Vec<RecordKey>,
        seed: bool,
    },
    Fill {
        context: RekeyContext,
        round: Round,
        candidate: Candidate,
        start: usize,
    },
}
pub(crate) struct RekeyCompletion {
    kind: RekeyCompletionKind,
    _guard: RecordWork,
}
#[expect(
    clippy::large_enum_variant,
    reason = "The single-flight completion keeps its original rekey state inline without allocating another heap owner."
)]
enum RekeyCompletionKind {
    Seed(RoundSeed),
    Candidate(Round, Candidate),
}
impl RekeyCrypto {
    pub(crate) fn execute(self) -> Result<RekeyCompletion> {
        match self.kind {
            RekeyCryptoKind::Fill {
                context,
                round,
                mut candidate,
                start,
            } => {
                for key in &mut candidate.keys[start..] {
                    context.guard.check()?;
                    let mut info = domain(
                        b"flowersec/v4/record-key\0",
                        &[context.profile.name().as_bytes(), &context.hash],
                    )?;
                    info.extend_from_slice(&(context.epoch + 1).to_be_bytes());
                    info.push(key.direction);
                    info.extend_from_slice(&key.scope.to_be_bytes());
                    key.key = RecordMaterial::ready(expand(&candidate.root, &info)?);
                }
                context.guard.check()?;
                Ok(RekeyCompletion {
                    kind: RekeyCompletionKind::Candidate(round, candidate),
                    _guard: context.guard,
                })
            }
            RekeyCryptoKind::Seed { context } => {
                context.guard.check()?;
                let mut id = [0; 16];
                SystemRandom::new()
                    .fill(&mut id)
                    .map_err(|_| CryptoError::Key)?;
                Ok(RekeyCompletion {
                    kind: RekeyCompletionKind::Seed(context.seed(id)?),
                    _guard: context.guard,
                })
            }
            RekeyCryptoKind::Candidate {
                context,
                mut round,
                peer,
                peer_len,
                mut keys,
                seed,
            } => {
                context.guard.check()?;
                if seed {
                    let seed = context.seed(round.id)?;
                    round.secret = seed.secret;
                    round.confirm_keys = seed.confirm_keys;
                    round.ephemeral = Some(seed.ephemeral);
                    round.init_digest = context.transcript(
                        b"flowersec/v4/rekey-init-digest\0",
                        &round.init,
                        None,
                    )?;
                    round.reply = context.reply(&round)?;
                }
                round.transcript = context.transcript(
                    b"flowersec/v4/rekey-transcript\0",
                    &round.init,
                    Some(&round.reply),
                )?;
                let shared = round
                    .ephemeral
                    .take()
                    .ok_or(CryptoError::State)?
                    .shared(&peer[..peer_len])?;
                let born = context.guard.account.security_time()?;
                let (mut extracted, _) =
                    Hkdf::<Sha256>::extract(Some(round.secret.as_ref()), shared.as_ref());
                let mut prk = Zeroizing::new(<[u8; 32]>::from(extracted));
                extracted.as_mut_slice().zeroize();
                let mut info = context.domain(b"flowersec/v4/rekey-root\0")?;
                info.extend_from_slice(&(context.epoch + 1).to_be_bytes());
                lp(&mut info, &round.id)?;
                lp(&mut info, &round.transcript)?;
                let root = expand(&prk, &info)?;
                prk.zeroize();
                for key in &mut keys {
                    context.guard.check()?;
                    let mut info = domain(
                        b"flowersec/v4/record-key\0",
                        &[context.profile.name().as_bytes(), &context.hash],
                    )?;
                    info.extend_from_slice(&(context.epoch + 1).to_be_bytes());
                    info.push(key.direction);
                    info.extend_from_slice(&key.scope.to_be_bytes());
                    key.key = RecordMaterial::ready(expand(&root, &info)?);
                }
                for phase in 3..=4 {
                    round.confirm_keys[usize::from(phase - 1)] =
                        context.confirm_key(&root, &round.id, phase)?;
                }
                context.guard.check()?;
                Ok(RekeyCompletion {
                    kind: RekeyCompletionKind::Candidate(
                        round,
                        Candidate {
                            root,
                            born,
                            keys,
                            usage: Usage::default(),
                            armed: false,
                            sent: false,
                            received: false,
                        },
                    ),
                    _guard: context.guard,
                })
            }
        }
    }
}
impl RecordEngine {
    pub(super) fn prepare_rekey_seal(&mut self, payload: &[u8]) -> Result<Option<SealPatch>> {
        if !self.deferred_crypto {
            return Ok(None);
        }
        let phase = payload.get(2).copied().ok_or(CryptoError::Authentication)?;
        if phase == 0 || phase == 2 {
            return Ok(None);
        }
        if !(1..=4).contains(&phase) {
            return Err(CryptoError::Authentication);
        }
        let round = self.rekey.round.as_mut().ok_or(CryptoError::State)?;
        Ok(Some(SealPatch {
            hash: self.hash,
            context: self.context,
            profile: self.profile,
            epoch: self.epoch,
            id: round.id,
            phase,
            key: Zeroizing::new(*round.confirm_keys[usize::from(phase - 1)]),
            init: (phase == 1).then(|| std::mem::take(&mut round.init)),
        }))
    }
    pub(crate) fn finish_rekey_seal(&mut self, completion: SealCompletion) -> Result<()> {
        self.check()?;
        let round = self.rekey.round.as_mut().ok_or(CryptoError::State)?;
        if completion.epoch != self.epoch || completion.id != round.id || round.stage != 1 {
            return Err(CryptoError::State);
        }
        round.init = completion.init;
        round.init_digest = completion.digest;
        Ok(())
    }
    fn rekey_context(&self) -> Result<RekeyContext> {
        let index = self.slot_for(false, 0, self.role)?;
        Ok(RekeyContext {
            guard: self.record_work(false, index, &[], self.epoch, 0)?,
            root: Zeroizing::new(*self.root),
            profile: self.profile,
            hash: self.hash,
            context: self.context,
            epoch: self.epoch,
            phase_bytes: self.rekey.geometry.phase_bytes,
        })
    }
    pub(super) fn rekey_authentication(
        &self,
        phase: u8,
        marker: bool,
    ) -> Result<RekeyAuthentication> {
        let base = if phase < 2 {
            Zeroizing::new([0; 32])
        } else if phase < 3 {
            Zeroizing::new(*self.rekey.round.as_ref().ok_or(CryptoError::State)?.secret)
        } else {
            Zeroizing::new(*self.candidate.as_ref().ok_or(CryptoError::State)?.root)
        };
        Ok(RekeyAuthentication {
            context: self.rekey_context()?,
            phase,
            marker,
            base,
        })
    }
    fn queue_candidate(&mut self, round: Round, peer: &[u8], seed: bool) -> Result<()> {
        if self.rekey.crypto_pending || peer.len() > 65 {
            return Err(CryptoError::State);
        }
        self.rekey.pending_incoming.clear();
        self.rekey
            .pending_incoming
            .extend_from_slice(&round.incoming);
        self.charge_keys(self.keys.len())?;
        let mut keys = std::mem::take(&mut self.spare_keys);
        for old in &self.keys {
            if old.disabled && old.scope != datagrams::SCOPE {
                if self.streams.exists(old.scope) {
                    continue;
                }
                return Err(CryptoError::State);
            }
            if self.streams.terminal(old.scope, old.direction) {
                continue;
            }
            keys.push(RecordKey {
                scope: old.scope,
                direction: old.direction,
                key: RecordMaterial::ready(Zeroizing::new([0; 32])),
                order: old.order.clone(),
                next: 0,
                disabled: false,
                usage: Usage::default(),
            });
        }
        let mut fixed_peer = [0; 65];
        fixed_peer[..peer.len()].copy_from_slice(peer);
        let mut context = self.rekey_context()?;
        if seed {
            let now = self.account.security_time()?;
            context.guard.deadline = context
                .guard
                .deadline
                .into_iter()
                .chain(Some(Coordinator::deadline_after(
                    now.monotonic_sample,
                    5000,
                )?))
                .min();
        }
        self.rekey.crypto = Some(RekeyCrypto {
            kind: RekeyCryptoKind::Candidate {
                context,
                round,
                peer: fixed_peer,
                peer_len: peer.len(),
                keys,
                seed,
            },
        });
        self.rekey.crypto_pending = true;
        Ok(())
    }
    pub(crate) fn take_rekey_crypto(&mut self) -> Option<RekeyCrypto> {
        self.rekey.crypto.take()
    }
    pub(crate) fn finish_rekey_crypto(&mut self, completion: RekeyCompletion) -> Result<()> {
        completion._guard.check()?;
        self.check()?;
        if !self.rekey.crypto_pending {
            return Err(CryptoError::State);
        }
        match completion.kind {
            RekeyCompletionKind::Seed(seed) => self.rekey.seed = Some(seed),
            RekeyCompletionKind::Candidate(round, mut candidate) => {
                // A direction may authenticate its terminal proof while this
                // owned computation runs. Never reinstall its retired key.
                candidate.keys.retain(|key| {
                    self.keys.iter().any(|old| {
                        old.scope == key.scope
                            && old.direction == key.direction
                            && (old.scope == datagrams::SCOPE
                                || !old.disabled
                                    && !self.streams.terminal(old.scope, old.direction))
                    })
                });
                let start = candidate.keys.len();
                for old in &self.keys {
                    if old.disabled
                        || self.streams.terminal(old.scope, old.direction)
                        || candidate
                            .keys
                            .iter()
                            .any(|key| key.scope == old.scope && key.direction == old.direction)
                    {
                        continue;
                    }
                    if candidate.keys.len() >= self.max_keys {
                        return Err(CryptoError::Capacity);
                    }
                    candidate.keys.push(RecordKey {
                        scope: old.scope,
                        direction: old.direction,
                        key: RecordMaterial::ready(Zeroizing::new([0; 32])),
                        order: old.order.clone(),
                        next: 0,
                        disabled: false,
                        usage: Usage::default(),
                    });
                }
                if candidate.keys.len() != start {
                    self.charge_keys(candidate.keys.len() - start)?;
                    self.rekey.crypto = Some(RekeyCrypto {
                        kind: RekeyCryptoKind::Fill {
                            context: self.rekey_context()?,
                            round,
                            candidate,
                            start,
                        },
                    });
                    return Ok(());
                }
                self.rekey.round = Some(round);
                self.candidate = Some(candidate);
            }
        }
        self.rekey.crypto_pending = false;
        self.rekey.pending_incoming.clear();
        Ok(())
    }
    fn rekey_domain(&self, label: &[u8]) -> Result<Vec<u8>> {
        let mut v = domain(
            label,
            &[self.profile.name().as_bytes(), &self.hash, &self.context],
        )?;
        v.extend_from_slice(&self.epoch.to_be_bytes());
        Ok(v)
    }
    fn rekey_secret(&self) -> Result<Zeroizing<[u8; 32]>> {
        expand(
            &self.root,
            &self.rekey_domain(b"flowersec/v4/rekey-secret\0")?,
        )
    }
    fn phase_mac(&self, round: &Round, phase: u8, unsigned: &[u8]) -> Result<[u8; 32]> {
        let mut info = self.rekey_domain(b"flowersec/v4/rekey-confirm-key\0")?;
        info.extend_from_slice(&(self.epoch + 1).to_be_bytes());
        lp(&mut info, &round.id)?;
        info.extend_from_slice(&[phase, (phase + 1) % 2]);
        let base = if phase < 3 {
            &round.secret
        } else {
            &self.candidate.as_ref().ok_or(CryptoError::State)?.root
        };
        let key = if self.deferred_crypto {
            Zeroizing::new(*round.confirm_keys[usize::from(phase - 1)])
        } else {
            expand(base, &info)?
        };
        let mut msg = self.rekey_domain(b"flowersec/v4/rekey-confirm-mac\0")?;
        msg.extend_from_slice(&(self.epoch + 1).to_be_bytes());
        msg.extend_from_slice(&[phase, (phase + 1) % 2]);
        lp(&mut msg, unsigned)?;
        Ok(mac(&key, &msg))
    }
    fn phase_map(&self, round: &Round, phase: u8, frontier: u64) -> Result<Vec<u8>> {
        let mut out = buffer(self.rekey.geometry.phase_bytes)?;
        codec::encode_head(&mut out, 5, if phase == 2 { 6 } else { 5 });
        uint(&mut out, 0);
        uint(&mut out, u64::from(phase));
        uint(&mut out, 1);
        data(&mut out, &round.id);
        uint(&mut out, 2);
        uint(&mut out, u64::from(self.epoch + 1));
        uint(&mut out, 3);
        match phase {
            1 => {
                data(
                    &mut out,
                    round.ephemeral.as_ref().ok_or(CryptoError::State)?.public(),
                );
                uint(&mut out, 4);
                barrier(&mut out, &round.outgoing);
            }
            2 => {
                data(&mut out, &round.init_digest);
                uint(&mut out, 4);
                data(
                    &mut out,
                    round.ephemeral.as_ref().ok_or(CryptoError::State)?.public(),
                );
                uint(&mut out, 5);
                barrier(&mut out, &round.outgoing);
            }
            3 | 4 => {
                data(&mut out, &round.transcript);
                uint(&mut out, 4);
                uint(&mut out, frontier);
            }
            _ => return Err(CryptoError::State),
        }
        let tag = if self.deferred_crypto {
            [0; 32]
        } else {
            self.phase_mac(round, phase, &out)?
        };
        out[0] += 1;
        uint(&mut out, if phase == 2 { 6 } else { 5 });
        data(&mut out, &tag);
        if out.len() > self.rekey.geometry.phase_bytes || (phase >= 3 && out.len() > 107) {
            return Err(CryptoError::Capacity);
        }
        Ok(out)
    }
    fn schema(phase: u8) -> Result<&'static str> {
        match phase {
            0 => Ok("REKEY_REQUEST"),
            1 => Ok("REKEY_INIT"),
            2 => Ok("REKEY_REPLY"),
            3 => Ok("REKEY_COMMIT"),
            4 => Ok("REKEY_ACK"),
            _ => Err(CryptoError::State),
        }
    }
    fn parse_phase<'a>(&self, raw: &'a [u8], phase: u8) -> Result<Value<'a>> {
        decode(
            raw,
            Self::schema(phase)?,
            self.rekey.geometry.phase_bytes,
            Context::default(),
        )
    }
    fn verify_phase(&self, round: &Round, raw: &[u8], phase: u8) -> Result<()> {
        let v = self.parse_phase(raw, phase)?;
        let name = Self::schema(phase)?;
        if v.b::<16>(name, "rekey_id")? != round.id
            || v.u(name, "next_epoch")? != u64::from(self.epoch + 1)
        {
            return Err(CryptoError::Authentication);
        }
        let mac_id = if phase == 2 { 6 } else { 5 };
        let mut unsigned = buffer(raw.len())?;
        codec::encode_head(&mut unsigned, 5, (v.len()? - 1) as u64);
        let mut fields = v.children()?;
        while let Some(id) = fields.next() {
            let id = id?;
            let value = fields.next().ok_or(CryptoError::Authentication)??;
            if id.uint()? != mac_id {
                unsigned.extend_from_slice(id.raw());
                unsigned.extend_from_slice(value.raw());
            }
        }
        let tag = self.phase_mac(round, phase, &unsigned)?;
        if !bool::from(tag.ct_eq(&v.b::<32>(name, "confirmation_mac")?)) {
            return Err(CryptoError::Authentication);
        }
        Ok(())
    }
    fn transcript(&self, label: &[u8], init: &[u8], reply: Option<&[u8]>) -> Result<[u8; 32]> {
        let mut v = domain(label, &[&self.hash, self.profile.name().as_bytes()])?;
        v.extend_from_slice(&self.epoch.to_be_bytes());
        lp(&mut v, init)?;
        if let Some(reply) = reply {
            lp(&mut v, reply)?;
        }
        Ok(Sha256::digest(&v).into())
    }
    fn snapshot(&mut self, out: &mut Vec<Entry>) -> Result<()> {
        out.clear();
        for (scope, next) in self.streams.snapshot(self.epoch) {
            out.push(Entry { scope, next });
        }

        for key in &self.keys {
            if key.scope != 0
                && key.scope != datagrams::SCOPE
                && key.direction == self.role
                && !self.streams.exists(key.scope)
            {
                // A failed direction needs the Session's authenticated abort
                // proof. This crypto owner cannot manufacture that proof.
                if key.disabled {
                    return Err(CryptoError::State);
                }
                out.push(Entry {
                    scope: key.scope,
                    next: key.next,
                });
            }
        }
        if out.len() > self.rekey.geometry.scopes {
            return Err(CryptoError::Capacity);
        }
        out.sort_unstable_by_key(|e| e.scope);
        for entry in out.iter() {
            self.streams.hold(entry.scope, true)?;
        }
        Ok(())
    }
    fn read_barrier(&self, v: Value<'_>, phase: u8, out: &mut Vec<Entry>) -> Result<()> {
        let name = Self::schema(phase)?;
        let entries = v.field(
            name,
            if phase == 1 {
                "client_barrier"
            } else {
                "server_barrier"
            },
        )?;
        if entries.len()? > self.rekey.geometry.scopes {
            return Err(CryptoError::Capacity);
        }
        out.clear();
        let mut previous = 0;
        for entry in entries.children()? {
            let entry = entry?;
            let scope = entry.u("RekeyBarrierEntry", "scope_id")?;
            let next = entry.u("RekeyBarrierEntry", "next_sequence")?;
            if scope <= previous || scope > 4_194_335 || (scope & 1 == 0 && scope / 2 > 2_097_152) {
                return Err(CryptoError::Authentication);
            }
            previous = scope;
            if self
                .streams
                .barrier(scope, self.epoch, next, true)?
                .is_some()
            {
                out.push(Entry { scope, next });
                continue;
            }
            if let Some(key) = self
                .keys
                .iter()
                .find(|k| k.scope == scope && k.direction == 1 - self.role)
            {
                if key.disabled || next < key.next {
                    return Err(CryptoError::Authentication);
                }
            } else {
                // Awaiting OPEN consumes only this bounded dependency. It
                // creates no scope/key. The Session must later admit the real
                // OPEN through its original owner before this can drain.
                let peer_parity = if self.role == 0 { 0 } else { 1 };
                if (scope == 1 && self.streams.has_bootstrap())
                    || scope % 2 != peer_parity
                    || next != 1
                {
                    return Err(CryptoError::Authentication);
                }
            }
            out.push(Entry { scope, next });
        }
        Ok(())
    }
    fn drained(&self, entries: &[Entry]) -> Result<bool> {
        for entry in entries {
            if let Some(ready) = self
                .streams
                .barrier(entry.scope, self.epoch, entry.next, false)?
            {
                if !ready {
                    return Ok(false);
                }
                continue;
            }
            let Some(key) = self
                .keys
                .iter()
                .find(|k| k.scope == entry.scope && k.direction == 1 - self.role)
            else {
                return Ok(false);
            };
            if key.disabled || key.next > entry.next {
                return Err(CryptoError::Authentication);
            }
            if key.next != entry.next {
                return Ok(false);
            }
        }
        Ok(true)
    }
    #[cfg(test)]
    pub(crate) fn rekey_diagnostic(&self) -> String {
        format!(
            "role={} epoch={} closed={} frozen={} intent={} stage={:?} drained={:?}",
            self.role,
            self.epoch,
            self.closed,
            self.frozen,
            self.rekey.intent.is_some(),
            self.rekey.round.as_ref().map(|round| round.stage),
            self.rekey
                .round
                .as_ref()
                .map(|round| self.drained(&round.incoming)),
        )
    }
    fn new_round(
        &mut self,
        now: TrustedTimeSample,
        id: [u8; 16],
        post_credit: u64,
    ) -> Result<Round> {
        if self.epoch >= 65_535 || self.rekey.round.is_some() || self.candidate.is_some() {
            return Err(CryptoError::State);
        }
        let seed = if self.deferred_crypto {
            self.rekey
                .seed
                .take()
                .filter(|seed| seed.id == id)
                .ok_or(CryptoError::State)?
        } else {
            self.rekey_context()?.seed(id)?
        };
        let started = seed.started.min(now.monotonic_sample);
        if now.monotonic_sample >= seed.deadline {
            return Err(CryptoError::Deadline);
        }
        let mut round = Round {
            id,
            secret: seed.secret,
            confirm_keys: seed.confirm_keys,
            ephemeral: Some(seed.ephemeral),
            init: std::mem::take(&mut self.rekey.init),
            reply: std::mem::take(&mut self.rekey.reply),
            outgoing: std::mem::take(&mut self.rekey.outgoing),
            incoming: std::mem::take(&mut self.rekey.incoming),
            transcript: [0; 32],
            init_digest: [0; 32],
            post_credit,
            stage: 1,
        };
        if self.account.security_time()?.monotonic_sample
            >= Coordinator::deadline_after(started, 5000)?
        {
            return Err(CryptoError::Deadline);
        }
        self.snapshot(&mut round.outgoing)?;
        Ok(round)
    }
    fn stage_candidate(&mut self, round: &mut Round, peer: &[u8]) -> Result<()> {
        round.transcript = self.transcript(
            b"flowersec/v4/rekey-transcript\0",
            &round.init,
            Some(&round.reply),
        )?;
        let shared = round
            .ephemeral
            .take()
            .ok_or(CryptoError::State)?
            .shared(peer)?;
        let born = self.account.security_time()?;
        let (mut extracted, _) =
            Hkdf::<Sha256>::extract(Some(round.secret.as_ref()), shared.as_ref());
        let mut prk = Zeroizing::new(<[u8; 32]>::from(extracted));
        extracted.as_mut_slice().zeroize();
        let mut info = self.rekey_domain(b"flowersec/v4/rekey-root\0")?;
        info.extend_from_slice(&(self.epoch + 1).to_be_bytes());
        lp(&mut info, &round.id)?;
        lp(&mut info, &round.transcript)?;
        let root = expand(&prk, &info)?;
        prk.zeroize();
        self.charge_keys(self.keys.len())?;
        let mut keys = std::mem::take(&mut self.spare_keys);
        for old in &self.keys {
            if old.disabled && old.scope != datagrams::SCOPE {
                if self.streams.exists(old.scope) {
                    continue;
                }
                return Err(CryptoError::State);
            }
            if self.streams.terminal(old.scope, old.direction) {
                continue;
            }
            let key = self.record_material(&root, self.epoch + 1, old.scope, old.direction)?;
            keys.push(RecordKey {
                scope: old.scope,
                direction: old.direction,
                key,
                order: old.order.clone(),
                next: 0,
                disabled: false,
                usage: Usage::default(),
            });
        }
        self.candidate = Some(Candidate {
            root,
            born,
            keys,
            usage: Usage::default(),
            armed: false,
            sent: false,
            received: false,
        });
        self.check()
    }
    fn finish_round(&mut self, now: TrustedTimeSample) -> Result<()> {
        let candidate = self.candidate.take().ok_or(CryptoError::State)?;
        if !candidate.sent || !candidate.received {
            return Err(CryptoError::State);
        }
        // Authenticated barriers settle the old generation. Any original
        // crypto/provider tail retains its exact key Arc and physical charge;
        // removing this table cannot destroy or refund that retained material.
        let mut old = std::mem::replace(&mut self.keys, candidate.keys);
        old.clear();
        self.spare_keys = old;
        self.root = candidate.root;
        self.born = candidate.born;
        self.epoch += 1;
        self.epoch_usage = candidate.usage;
        let round = self.rekey.round.as_ref().ok_or(CryptoError::State)?;
        for entry in round.outgoing.iter().chain(round.incoming.iter()) {
            self.streams.release(entry.scope);
        }
        self.streams.install_epoch(self.epoch);
        self.datagrams.install_epoch();
        self.rekey.finish(now)?;
        self.streams.controls.rekey_complete(now);
        self.frozen = false;
        *self
            .crypto
            .deadline
            .lock()
            .expect("completed original rekey deadline") = None;
        Ok(())
    }
    fn send_phase(
        &mut self,
        body: &[u8],
        marker: bool,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<()> {
        publisher.prepare_publication(
            body.len().checked_add(44).ok_or(CryptoError::Capacity)?,
            self.rekey.geometry.scopes + 1,
        )?;
        let mut out = std::mem::take(&mut self.rekey.output);
        let result = (|| {
            let (n, work) = self.prepare_seal(0, 6, body, &mut out, marker, true)?;
            publisher.publish_seal(work, &mut out[..n])?;
            self.check()?;
            self.streams
                .controls
                .activity(self.account.security_time()?)
        })();
        out.as_mut_slice().zeroize();
        self.rekey.output = out;
        result
    }
    fn safety_due(&self) -> Result<bool> {
        let now = self.account.security_time()?;
        let wait = self
            .rekey
            .credit
            .period
            .checked_add(self.rekey.credit.start_budget)
            .and_then(|n| n.checked_add(45_000))
            .ok_or(CryptoError::Capacity)?;
        if wait >= 86_400_000 {
            return Err(CryptoError::Configuration);
        }
        if now
            .upper_ms
            .checked_sub(self.born.lower_ms)
            .is_none_or(|age| age >= 86_400_000 - wait)
        {
            return Ok(true);
        }
        let (key_limit, epoch_limit, session_limit) = self.limits();
        // Half-budget scheduling leaves a complete admitted credit wait and
        // all schema-derived protected work. Output admission enforces the tail.
        let half = |u: Usage| Usage {
            seals: u.seals / 2,
            opens: u.opens / 2,
            blocks: u.blocks / 2,
            bytes: u.bytes / 2,
        };
        if !self.datagram_soft_epoch_usage().fits(half(epoch_limit))
            || !self
                .session_usage
                .add(self.rekey.geometry.margin)?
                .fits(session_limit)
            || self.key_derivations + self.max_keys as u64 >= 1 << 28
        {
            return Ok(true);
        }
        Ok(self
            .keys
            .iter()
            .any(|k| !self.datagram_soft_key_usage(k).fits(half(key_limit))))
    }
    fn remember_intent(&mut self, now: TrustedTimeSample) -> Result<()> {
        if self.rekey.intent.is_none() && self.rekey.round.is_none() {
            self.account
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::RekeyStarts);
            self.rekey
                .timeout_reported
                .store(false, std::sync::atomic::Ordering::Release);
            // A legitimate request gets the next credit opportunity plus the
            // signed start budget; repeats never refresh this original bound.
            self.streams
                .controls
                .interrupt(ProbeOutcome::RekeyInProgress, Some(now));
            self.rekey.intent = Some(Coordinator::deadline_after(
                now.monotonic_sample,
                self.rekey
                    .credit
                    .period
                    .checked_add(self.rekey.credit.start_budget)
                    .ok_or(CryptoError::Capacity)?,
            )?);
        }
        Ok(())
    }
    /// Joins the sole cause. This private core does not allocate manual waiters.
    pub(crate) fn request_rekey(&mut self, publisher: &mut dyn RecordPublisher) -> Result<bool> {
        let result = (|| {
            self.check()?;
            let now = self.account.security_time()?;
            self.remember_intent(now)?;
            self.progress_rekey(publisher)
        })();
        if result.is_err() {
            self.fail()
        }
        result
    }
    /// Called by the bounded maintenance scheduler after input/frontier changes
    /// and on its original watchdog. No new timers or detached work are created.
    pub(crate) fn poll_rekey(&mut self, publisher: &mut dyn RecordPublisher) -> Result<bool> {
        let result = (|| {
            self.check()?;
            if self.rekey.round.is_none() && self.safety_due()? {
                let now = self.account.security_time()?;
                self.remember_intent(now)?;
            }
            self.progress_rekey(publisher)
        })();
        if result.is_err() {
            self.fail()
        }
        result
    }
    fn progress_rekey(&mut self, publisher: &mut dyn RecordPublisher) -> Result<bool> {
        if !self.ready {
            return Err(CryptoError::State);
        }
        if self.rekey.crypto_pending {
            return Ok(false);
        }
        if self.rekey.round.is_none() {
            if self.rekey.intent.is_none() {
                return Ok(false);
            }
            if self.role == 1 {
                if self.rekey.requested {
                    return Ok(false);
                }
                self.rekey.requested = true;
                self.send_phase(&[0xa1, 0, 0], false, publisher)?;
                return Ok(true);
            }
            let now = self.account.security_time()?;
            if self.rekey.credit.available(now, false)? < self.rekey.credit.period {
                return Ok(false);
            }
            let id = if self.deferred_crypto {
                if let Some(seed) = &self.rekey.seed {
                    seed.id
                } else {
                    let mut context = self.rekey_context()?;
                    context.guard.deadline = context
                        .guard
                        .deadline
                        .into_iter()
                        .chain(Some(Coordinator::deadline_after(
                            now.monotonic_sample,
                            5000,
                        )?))
                        .min();
                    self.rekey.crypto = Some(RekeyCrypto {
                        kind: RekeyCryptoKind::Seed { context },
                    });
                    self.rekey.crypto_pending = true;
                    return Ok(true);
                }
            } else {
                let mut id = [0; 16];
                SystemRandom::new()
                    .fill(&mut id)
                    .map_err(|_| CryptoError::Key)?;
                id
            };
            let mut round = self.new_round(now, id, 0)?;
            // Freeze, snapshot and unique INIT ownership share exclusive &mut.
            // No crypto or I/O takes place under the Environment security lock.
            self.account.with_security(|| ())?;
            self.frozen = true;
            let ticket = self.account.security_time()?;
            round.post_credit = self.rekey.credit.charge(ticket, false)?;
            self.rekey.deadline = Some(Coordinator::deadline_after(
                ticket.monotonic_sample,
                10_000,
            )?);
            self.crypto.tighten_deadline(self.rekey.deadline);
            let init = self.phase_map(&round, 1, 0)?;
            round.init.extend_from_slice(&init);
            round.init_digest = if self.deferred_crypto {
                [0; 32]
            } else {
                self.transcript(b"flowersec/v4/rekey-init-digest\0", &init, None)?
            };
            self.rekey.round = Some(round);
            self.send_phase(&init, false, publisher)?;
            for entry in &self
                .rekey
                .round
                .as_ref()
                .ok_or(CryptoError::State)?
                .outgoing
            {
                if publisher.is_deferred() {
                    publisher.defer_publication(crate::crypto_v4::DeferredPublication::published(
                        entry.scope,
                    ));
                } else {
                    self.streams.published(entry.scope);
                }
            }
            return Ok(true);
        }
        let round = self.rekey.round.as_ref().ok_or(CryptoError::State)?;
        let phase = match (self.role, round.stage) {
            (1, 1) => 2,
            (0, 2) => 3,
            (1, 3) => 4,
            _ => return Ok(false),
        };
        if phase != 4 && !self.drained(&round.incoming)? {
            return Ok(false);
        }
        let frontier = self.keys[self.slot_for(false, 0, self.role)?].next;
        let body = if phase == 2 {
            round.reply.clone()
        } else {
            self.phase_map(round, phase, frontier)?
        };
        if phase == 2 {
            self.candidate.as_mut().ok_or(CryptoError::State)?.armed = true;
            self.rekey.round.as_mut().ok_or(CryptoError::State)?.stage = 2;
        } else {
            self.candidate.as_mut().ok_or(CryptoError::State)?.armed = true;
            self.rekey.round.as_mut().ok_or(CryptoError::State)?.stage = phase;
        }
        // The original exclusive publisher cannot overtake any prior old write.
        // Marker seq0 is sealed once and failure is terminal, never retry/reseal.
        if phase >= 3 {
            let now = self.account.security_time()?;
            if phase == 3 {
                self.rekey.deadline =
                    Some(Coordinator::deadline_after(now.monotonic_sample, 30_000)?);
                self.crypto.tighten_deadline(self.rekey.deadline);
            }
            publisher
                .prepare_publication(body.len().checked_add(44).ok_or(CryptoError::Capacity)?, 1)?;
            let mut out = std::mem::take(&mut self.rekey.output);
            let result: Result<()> = (|| {
                let (n, work) = self.prepare_seal(0, 6, &body, &mut out, true, true)?;
                self.candidate.as_mut().ok_or(CryptoError::State)?.sent = true;
                if phase == 4 {
                    self.finish_round(now)?;
                }
                publisher.publish_seal(work, &mut out[..n])?;
                if publisher.is_deferred() {
                    publisher.defer_publication(if phase == 4 {
                        crate::crypto_v4::DeferredPublication::rekey_success()
                    } else {
                        crate::crypto_v4::DeferredPublication::handoff(None)
                    });
                } else {
                    if phase == 4 {
                        self.account.diagnostic_count(
                            crate::diagnostics_v4::DiagnosticCounter::RekeySuccesses,
                        );
                    }
                    self.check()?;
                    self.streams
                        .controls
                        .activity(self.account.security_time()?)?;
                }
                Ok(())
            })();
            out.as_mut_slice().zeroize();
            self.rekey.output = out;
            result?;
        } else {
            self.send_phase(&body, false, publisher)?;
            if phase == 2 {
                for entry in &self
                    .rekey
                    .round
                    .as_ref()
                    .ok_or(CryptoError::State)?
                    .outgoing
                {
                    if publisher.is_deferred() {
                        publisher.defer_publication(
                            crate::crypto_v4::DeferredPublication::published(entry.scope),
                        );
                    } else {
                        self.streams.published(entry.scope);
                    }
                }
            }
        }
        Ok(true)
    }
    pub(super) fn incoming_barrier_refs(&self, scope: u64) -> u8 {
        self.rekey.round.as_ref().map_or_else(
            || {
                self.rekey
                    .pending_incoming
                    .iter()
                    .filter(|e| e.scope == scope)
                    .count() as u8
            },
            |r| r.incoming.iter().filter(|e| e.scope == scope).count() as u8,
        )
    }
    pub(super) fn expected_phase(&self, wire: &[u8]) -> Result<u8> {
        if wire.len() < 44 || wire[4] != 6 {
            return Err(CryptoError::Authentication);
        }
        match (self.role, self.rekey.round.as_ref().map(|r| r.stage)) {
            (0, None) => Ok(0),
            (1, None) => Ok(1),
            (0, Some(1)) => Ok(2),
            (0, Some(2)) => Ok(0),
            (1, Some(2)) => Ok(3),
            (0, Some(3)) => Ok(4),
            _ => Err(CryptoError::State),
        }
    }
    fn validate_rekey(&self, body: &[u8], phase: u8) -> Result<()> {
        let v = self.parse_phase(body, phase)?;
        if phase != 0 {
            let name = Self::schema(phase)?;
            if v.u(name, "next_epoch")? != u64::from(self.epoch + 1)
                || phase >= 2
                    && v.b::<16>(name, "rekey_id")?
                        != self.rekey.round.as_ref().ok_or(CryptoError::State)?.id
            {
                return Err(CryptoError::Authentication);
            }
        }
        if phase == 0 {
            return Ok(());
        }
        if phase == 1 {
            let temporary = Round {
                id: v.b("REKEY_INIT", "rekey_id")?,
                secret: if self.deferred_crypto {
                    Zeroizing::new([0; 32])
                } else {
                    self.rekey_secret()?
                },
                confirm_keys: std::array::from_fn(|_| Zeroizing::new([0; 32])),
                ephemeral: None,
                init: body.to_vec(),
                reply: Vec::new(),
                outgoing: Vec::new(),
                incoming: Vec::new(),
                transcript: [0; 32],
                init_digest: [0; 32],
                post_credit: 0,
                stage: 0,
            };
            if !self.deferred_crypto {
                self.verify_phase(&temporary, body, 1)?;
            }
            if !self.deferred_crypto {
                crate::crypto_v4::keys::check_public(
                    self.profile,
                    v.field("REKEY_INIT", "client_ephemeral")?.bytes()?,
                )?;
            }
            let mut barrier = Vec::with_capacity(self.rekey.geometry.scopes);
            self.read_barrier(v, 1, &mut barrier)?;
            if self
                .rekey
                .credit
                .available(self.account.security_time()?, true)?
                < self.rekey.credit.period
            {
                return Err(CryptoError::Capacity);
            }
            return Ok(());
        }
        let round = self.rekey.round.as_ref().ok_or(CryptoError::State)?;
        if !self.deferred_crypto {
            self.verify_phase(round, body, phase)?;
        }
        let name = Self::schema(phase)?;
        if phase == 2 {
            if v.b::<32>(name, "init_digest")? != round.init_digest {
                return Err(CryptoError::Authentication);
            }
            if !self.deferred_crypto {
                crate::crypto_v4::keys::check_public(
                    self.profile,
                    v.field(name, "server_ephemeral")?.bytes()?,
                )?;
            }
            let mut barrier = Vec::with_capacity(self.rekey.geometry.scopes);
            self.read_barrier(v, 2, &mut barrier)?;
        } else {
            let received = self.keys[self.slot_for(false, 0, 1 - self.role)?].next;
            if v.b::<32>(name, "transcript_digest")? != round.transcript
                || v.u(name, "old_maintenance_next_sequence")? != received
            {
                return Err(CryptoError::Authentication);
            }
        }
        Ok(())
    }
    /// A barrier may precede its peer's original OPEN on a different native
    /// stream. Only its retained authenticated dependency admits this bounded
    /// key installation; the actual sequence-zero OPEN must still authenticate.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Native v4 pending OPEN owner is not yet wired")
    )]
    pub(crate) fn open_awaited_peer_scope(
        &mut self,
        scope: u64,
        wire: &[u8],
        plain: &mut [u8],
        validate: impl FnOnce(u8, &[u8]) -> Result<()>,
    ) -> Result<usize> {
        let result = (|| {
            self.check()?;
            let round = self.rekey.round.as_ref().ok_or(CryptoError::State)?;
            if !self.frozen
                || !round
                    .incoming
                    .iter()
                    .any(|e| e.scope == scope && e.next == 1)
                || self.keys.iter().any(|k| k.scope == scope)
                || wire.len() < 44
                || wire[4] != 7
                || wire[8..12] != self.epoch.to_be_bytes()
                || wire[20..28] != [0; 8]
            {
                return Err(CryptoError::State);
            }
            self.install(scope)?;
            let n = self.open(scope, wire, plain, false, |_, frame, body| {
                validate(frame, body)
            })?;
            if self.candidate.is_some() {
                self.charge_keys(2)?;
                for direction in 0..2 {
                    let candidate = self.candidate.as_ref().ok_or(CryptoError::State)?;
                    if candidate.keys.len() + 1 > self.max_keys {
                        return Err(CryptoError::Capacity);
                    }
                    let key =
                        self.record_material(&candidate.root, self.epoch + 1, scope, direction)?;
                    self.candidate
                        .as_mut()
                        .ok_or(CryptoError::State)?
                        .keys
                        .push(RecordKey {
                            scope,
                            direction,
                            key,
                            order: self
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
            Ok(n)
        })();
        if result.is_err() {
            plain.zeroize();
            self.fail()
        }
        result
    }
    /// This sole entry authenticates the current or preinstalled marker key;
    /// callers cannot assert a phase, completed barrier, or key-install success.
    #[cfg(test)]
    pub(crate) fn receive_rekey(&mut self, wire: &[u8], plain: &mut [u8]) -> Result<()> {
        let expected = self.expected_phase(wire)?;
        let marker = expected >= 3 && wire[8..12] == (self.epoch + 1).to_be_bytes();
        let ticket = self.prepare_open(0, wire, marker)?;
        let result = ticket
            .execute(wire, plain)
            .and_then(|n| self.commit_rekey(&ticket, wire, &plain[..n], expected, marker));
        plain.zeroize();
        if result.is_err() {
            self.disable_open(&ticket);
            self.fail();
        }
        result
    }
    pub(super) fn commit_rekey(
        &mut self,
        ticket: &RecordOpen,
        wire: &[u8],
        body: &[u8],
        expected: u8,
        marker: bool,
    ) -> Result<()> {
        let phase = if self.role == 0 && !marker && body == [0xa1, 0, 0] {
            0
        } else {
            expected
        };
        self.commit_open(ticket, wire[4], body, |engine, _, body| {
            engine.validate_rekey(body, phase)
        })?;
        let now = self.account.security_time()?;
        if phase == 0 {
            self.remember_intent(now)?;
            return Ok(());
        }
        if phase == 1 {
            if !self.rekey.busy() {
                self.account
                    .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::RekeyStarts);
                self.rekey
                    .timeout_reported
                    .store(false, std::sync::atomic::Ordering::Release);
            }
            let value = self.parse_phase(body, 1)?;
            let id = value.b("REKEY_INIT", "rekey_id")?;
            let post = self.rekey.credit.charge(now, true)?;
            self.frozen = true;
            self.rekey.deadline = Some(Coordinator::deadline_after(now.monotonic_sample, 10_000)?);
            self.crypto.tighten_deadline(self.rekey.deadline);
            if self.deferred_crypto {
                let mut outgoing = std::mem::take(&mut self.rekey.outgoing);
                self.snapshot(&mut outgoing)?;
                let mut incoming = std::mem::take(&mut self.rekey.incoming);
                self.read_barrier(value, 1, &mut incoming)?;
                for entry in &incoming {
                    self.streams.hold(entry.scope, false)?;
                }
                let mut init = std::mem::take(&mut self.rekey.init);
                init.extend_from_slice(body);
                let round = Round {
                    id,
                    secret: Zeroizing::new([0; 32]),
                    confirm_keys: std::array::from_fn(|_| Zeroizing::new([0; 32])),
                    ephemeral: None,
                    init,
                    reply: std::mem::take(&mut self.rekey.reply),
                    outgoing,
                    incoming,
                    transcript: [0; 32],
                    init_digest: [0; 32],
                    post_credit: post,
                    stage: 1,
                };
                self.queue_candidate(
                    round,
                    value.field("REKEY_INIT", "client_ephemeral")?.bytes()?,
                    true,
                )?;
                return self.check();
            }
            let mut round = self.new_round(now, id, post)?;
            round.init.extend_from_slice(body);
            round.init_digest = self.transcript(b"flowersec/v4/rekey-init-digest\0", body, None)?;
            self.read_barrier(value, 1, &mut round.incoming)?;
            for entry in &round.incoming {
                self.streams.hold(entry.scope, false)?;
            }
            let reply = self.phase_map(&round, 2, 0)?;
            round.reply.extend_from_slice(&reply);
            self.stage_candidate(
                &mut round,
                value.field("REKEY_INIT", "client_ephemeral")?.bytes()?,
            )?;
            self.rekey.round = Some(round);
        } else if phase == 2 {
            let value = self.parse_phase(body, 2)?;
            let mut round = self.rekey.round.take().ok_or(CryptoError::State)?;
            self.read_barrier(value, 2, &mut round.incoming)?;
            for entry in &round.incoming {
                self.streams.hold(entry.scope, false)?;
            }
            round.reply.extend_from_slice(body);
            round.stage = 2;
            if self.deferred_crypto {
                self.queue_candidate(
                    round,
                    value.field("REKEY_REPLY", "server_ephemeral")?.bytes()?,
                    false,
                )?;
            } else {
                self.stage_candidate(
                    &mut round,
                    value.field("REKEY_REPLY", "server_ephemeral")?.bytes()?,
                )?;
                self.rekey.round = Some(round);
            }
        } else {
            self.candidate.as_mut().ok_or(CryptoError::State)?.received = true;
            self.rekey.round.as_mut().ok_or(CryptoError::State)?.stage = phase;
            if phase == 3 {
                self.rekey.deadline =
                    Some(Coordinator::deadline_after(now.monotonic_sample, 30_000)?);
                self.crypto.tighten_deadline(self.rekey.deadline);
            } else {
                self.finish_round(now)?;
                self.account
                    .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::RekeySuccesses);
            }
        }
        self.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_v4::tests::record_pair_for_limits;
    #[derive(Default)]
    struct Writer {
        records: Vec<Vec<u8>>,
        reject: bool,
    }
    impl RecordPublisher for Writer {
        fn publish(&mut self, record: &[u8]) -> Result<()> {
            self.records.push(record.to_vec());
            if self.reject {
                Err(CryptoError::State)
            } else {
                Ok(())
            }
        }
    }
    fn take(writer: &mut Writer) -> Vec<u8> {
        assert_eq!(writer.records.len(), 1);
        writer.records.remove(0)
    }
    fn receive(engine: &mut RecordEngine, wire: &[u8]) {
        let expected = engine.expected_phase(wire);
        let result = engine.receive_rekey(wire, &mut vec![0; wire.len()]);
        assert!(result.is_ok(), "phase {expected:?}: {result:?}");
    }
    fn epoch(wire: &[u8]) -> u32 {
        u32::from_be_bytes(wire[8..12].try_into().unwrap())
    }
    fn complete(client: &mut RecordEngine, server: &mut RecordEngine) {
        let mut c = Writer::default();
        let mut s = Writer::default();
        assert!(client.request_rekey(&mut c).unwrap());
        let init = take(&mut c);
        assert_eq!(epoch(&init), client.epoch);
        receive(server, &init);
        assert!(server.poll_rekey(&mut s).unwrap());
        receive(client, &take(&mut s));
        assert!(client.poll_rekey(&mut c).unwrap());
        let commit = take(&mut c);
        assert_eq!(epoch(&commit), client.epoch + 1);
        assert_eq!(&commit[20..28], &[0; 8]);
        receive(server, &commit);
        assert!(server.poll_rekey(&mut s).unwrap());
        receive(client, &take(&mut s));
    }
    #[test]
    fn both_profiles_rekey_preserves_session_ledger_and_releases_frozen_application() {
        for profile in [Profile::X25519, Profile::P256] {
            let (_owner, mut client, mut server) = record_pair_for_limits(profile);
            client.install_reliable_scope(1).unwrap();
            server.install_reliable_scope(1).unwrap();
            let mut wire = [0; 256];
            let mut plain = [0; 256];
            let n = client.seal_reliable(1, 8, b"old", &mut wire).unwrap();
            server
                .open_reliable(1, &wire[..n], &mut plain, |_, _| Ok(()))
                .unwrap();
            let total = client.session_usage;
            let keys = client.key_derivations;
            complete(&mut client, &mut server);
            assert_eq!(client.epoch, 1);
            assert_eq!(server.epoch, 1);
            assert!(!client.frozen);
            assert!(!server.frozen);
            assert!(client.session_usage.seals > total.seals);
            assert!(client.key_derivations > keys);
            assert!(
                client.rekey.credit.base < client.rekey.credit.burst * client.rekey.credit.period
            );
            assert_eq!(client.keys[client.slot_for(false, 0, 0).unwrap()].next, 1);
            assert_eq!(server.keys[server.slot_for(false, 0, 1).unwrap()].next, 1);
            let n = client.seal_reliable(1, 8, b"new", &mut wire).unwrap();
            assert_eq!(&wire[20..28], &[0; 8]);
            let n = server
                .open_reliable(1, &wire[..n], &mut plain, |_, _| Ok(()))
                .unwrap();
            assert_eq!(&plain[..n], b"new");
        }
    }
    #[test]
    fn pending_open_drain_and_new_control_cutover_use_original_frontiers() {
        let (_owner, mut client, mut server) = record_pair_for_limits(Profile::P256);
        client.install_reliable_scope(3).unwrap();
        let mut wire = [0; 512];
        let mut plain = [0; 512];
        let open_len = client.seal_reliable(3, 7, b"real OPEN", &mut wire).unwrap();
        let old_open = wire[..open_len].to_vec();
        let mut c = Writer::default();
        let mut s = Writer::default();
        client.request_rekey(&mut c).unwrap();
        receive(&mut server, &take(&mut c));
        assert!(!server.poll_rekey(&mut s).unwrap());
        assert!(server.install_reliable_scope(5).is_err());
        assert!(client.seal_reliable(3, 8, b"frozen", &mut wire).is_err());
        let n = server
            .open_awaited_peer_scope(3, &old_open, &mut plain, |kind, payload| {
                assert_eq!(kind, 7);
                assert_eq!(payload, b"real OPEN");
                Ok(())
            })
            .unwrap();
        assert_eq!(n, 9);
        server.poll_rekey(&mut s).unwrap();
        receive(&mut client, &take(&mut s));
        client.poll_rekey(&mut c).unwrap();
        receive(&mut server, &take(&mut c));
        // c2s ordinary control switches immediately after COMMIT, while server
        // s2c stays old until its ACK. Both are covered by exact old frontiers.
        client
            .publish_reliable(0, 15, b"new control", &mut wire, &mut c)
            .unwrap();
        let control = take(&mut c);
        assert_eq!(epoch(&control), 1);
        server
            .open_reliable(0, &control, &mut plain, |_, _| Ok(()))
            .unwrap();
        server
            .publish_reliable(0, 15, b"old control", &mut wire, &mut s)
            .unwrap();
        let control = take(&mut s);
        assert_eq!(epoch(&control), 0);
        client
            .open_reliable(0, &control, &mut plain, |_, _| Ok(()))
            .unwrap();
        server.poll_rekey(&mut s).unwrap();
        let ack = take(&mut s);
        let n = server
            .seal_reliable(3, 8, b"future private", &mut wire)
            .unwrap();
        let n = client
            .open_reliable(3, &wire[..n], &mut plain, |_, _| Ok(()))
            .unwrap();
        assert_eq!(&plain[..n], b"future private");
        assert!(client.application_input_ready(1).is_err());
        receive(&mut client, &ack);
        client.application_input_ready(1).unwrap();
    }
    #[test]
    fn deleted_old_maintenance_suffix_cannot_be_hidden_by_valid_new_marker() {
        let (_owner, mut client, mut server) = record_pair_for_limits(Profile::X25519);
        let mut c = Writer::default();
        let mut s = Writer::default();
        client.request_rekey(&mut c).unwrap();
        receive(&mut server, &take(&mut c));
        server.poll_rekey(&mut s).unwrap();
        receive(&mut client, &take(&mut s));
        client
            .publish_reliable(0, 15, b"deleted tail", &mut [0; 256], &mut c)
            .unwrap();
        let _deleted = take(&mut c);
        client.poll_rekey(&mut c).unwrap();
        let marker = take(&mut c);
        assert!(server.receive_rekey(&marker, &mut [0; 512]).is_err());
        assert!(server.closed);
        assert!(server.root.iter().all(|b| *b == 0));
        assert!(server.candidate.is_none());
    }
    #[test]
    fn duplicate_requests_do_not_refresh_deadline_and_publication_failure_is_terminal() {
        let (_owner, mut client, mut server) = record_pair_for_limits(Profile::X25519);
        let mut s = Writer::default();
        server.request_rekey(&mut s).unwrap();
        receive(&mut client, &take(&mut s));
        let original = client.rekey.intent;
        server.send_phase(&[0xa1, 0, 0], false, &mut s).unwrap();
        receive(&mut client, &take(&mut s));
        assert_eq!(client.rekey.intent, original);
        let mut c = Writer {
            reject: true,
            ..Writer::default()
        };
        assert!(client.poll_rekey(&mut c).is_err());
        assert!(client.closed);
        assert!(client.keys.is_empty());
    }
    #[test]
    fn fixed_phase_deadline_and_original_authorization_destroy_pending_keys() {
        let (_owner, mut client, mut server) = record_pair_for_limits(Profile::P256);
        let mut c = Writer::default();
        let mut s = Writer::default();
        client.request_rekey(&mut c).unwrap();
        receive(&mut server, &take(&mut c));
        server.poll_rekey(&mut s).unwrap();
        receive(&mut client, &take(&mut s));
        client.rekey.deadline = Some(Instant::now());
        assert_eq!(client.poll_rekey(&mut c), Err(CryptoError::Deadline));
        assert!(client.candidate.is_none());
        server.account.revoke();
        assert!(server.poll_rekey(&mut s).is_err());
        assert!(server.root.iter().all(|b| *b == 0));
    }
    fn hex(v: &serde_json::Value) -> Vec<u8> {
        crate::codec_v4::tests::hex(v.as_str().unwrap())
    }
    fn fixed<const N: usize>(v: &serde_json::Value) -> [u8; N] {
        hex(v).try_into().unwrap()
    }
    fn entries(v: &serde_json::Value) -> Vec<Entry> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|v| Entry {
                scope: v["scope_id"].as_str().unwrap().parse().unwrap(),
                next: v["next_sequence"].as_str().unwrap().parse().unwrap(),
            })
            .collect()
    }
    #[test]
    fn production_phase_mac_transcript_dh_root_and_markers_match_all_shared_rounds() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/transport_v4/rekey.json")).unwrap();
        for v in corpus["rounds"].as_array().unwrap() {
            let profile = Profile::parse(v["context"]["profile"].as_str().unwrap()).unwrap();
            let (_owner, mut client, mut server) = record_pair_for_limits(profile);
            for engine in [&mut client, &mut server] {
                engine.root = Zeroizing::new(fixed(&v["old_root_hex"]));
                engine.hash = fixed(&v["context"]["handshake_hash_hex"]);
                engine.context = fixed(&v["context"]["context_digest_hex"]);
                engine.epoch = v["context"]["epoch"].as_u64().unwrap() as u32;
                engine.keys.clear();
                engine.install(0).unwrap();
            }
            let now = client.account.security_time().unwrap();
            let id = fixed(&v["input"]["rekey_id_hex"]);
            let mut c = client.new_round(now, id, 0).unwrap();
            let mut s = server.new_round(now, id, 0).unwrap();
            c.ephemeral = Some(
                SoftwareDh::fixture(profile, fixed(&v["input"]["client_private_hex"])).unwrap(),
            );
            s.ephemeral = Some(
                SoftwareDh::fixture(profile, fixed(&v["input"]["server_private_hex"])).unwrap(),
            );
            c.outgoing = entries(&v["input"]["client_barrier"]);
            s.outgoing = entries(&v["input"]["server_barrier"]);
            assert_eq!(c.secret.as_slice(), hex(&v["secret_hex"]));
            let init = client.phase_map(&c, 1, 0).unwrap();
            assert_eq!(init, hex(&v["phases"][0]["message_hex"]));
            client.verify_phase(&c, &init, 1).unwrap();
            let mut wire = vec![0; 1024];
            let index = client.slot_for(false, 0, 0).unwrap();
            client.keys[index].next = v["phases"][0]["record"]["sequence"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let size = client.seal(0, 6, &init, &mut wire, false, true).unwrap();
            assert_eq!(&wire[..size], hex(&v["phases"][0]["record"]["wire_hex"]));
            c.init = init.clone();
            s.init = init;
            c.init_digest = client
                .transcript(b"flowersec/v4/rekey-init-digest\0", &c.init, None)
                .unwrap();
            s.init_digest = c.init_digest;
            assert_eq!(c.init_digest.as_slice(), hex(&v["init_digest_hex"]));
            let reply = server.phase_map(&s, 2, 0).unwrap();
            assert_eq!(reply, hex(&v["phases"][1]["message_hex"]));
            server.verify_phase(&s, &reply, 2).unwrap();
            let index = server.slot_for(false, 0, 1).unwrap();
            server.keys[index].next = v["phases"][1]["record"]["sequence"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let size = server.seal(0, 6, &reply, &mut wire, false, true).unwrap();
            assert_eq!(&wire[..size], hex(&v["phases"][1]["record"]["wire_hex"]));
            c.reply = reply.clone();
            s.reply = reply;
            let cp = c.ephemeral.as_ref().unwrap().public().to_vec();
            let sp = s.ephemeral.as_ref().unwrap().public().to_vec();
            client.stage_candidate(&mut c, &sp).unwrap();
            server.stage_candidate(&mut s, &cp).unwrap();
            assert_eq!(c.transcript.as_slice(), hex(&v["transcript_hex"]));
            assert_eq!(s.transcript, c.transcript);
            assert_eq!(
                client.candidate.as_ref().unwrap().root.as_slice(),
                hex(&v["new_root_hex"])
            );
            assert_eq!(
                server.candidate.as_ref().unwrap().root.as_slice(),
                hex(&v["new_root_hex"])
            );
            for (engine, round, phase, field) in [
                (&mut client, &c, 3, "client_old_sequence"),
                (&mut server, &s, 4, "server_old_sequence"),
            ] {
                let _ = field;
                let frontier =
                    v["phases"][phase as usize - 1]["expected"]["old_maintenance_next_sequence"]
                        .as_str()
                        .unwrap()
                        .parse()
                        .unwrap();
                let body = engine.phase_map(round, phase, frontier).unwrap();
                assert_eq!(body, hex(&v["phases"][phase as usize - 1]["message_hex"]));
                engine.verify_phase(round, &body, phase).unwrap();
                let size = engine.seal(0, 6, &body, &mut wire, true, true).unwrap();
                assert_eq!(
                    &wire[..size],
                    hex(&v["phases"][phase as usize - 1]["record"]["wire_hex"])
                );
                let mut changed = body.clone();
                let last = changed.len() - 1;
                changed[last] ^= 1;
                assert!(engine.verify_phase(round, &changed, phase).is_err());
            }
        }
    }
    #[test]
    fn signed_service_capacity_matches_shared_integer_boundary_corpus() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v4/rekey_credit.json"
        ))
        .unwrap();
        for vector in corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["operation"] == "service")
        {
            let input = &vector["input"];
            let number = |name: &str| input[name].as_str().unwrap().parse::<u64>().unwrap();
            let service = number("session_not_after_ms").saturating_sub(number("issued_at_ms"));
            let profile = TrustedTimeProfile {
                rate_numerator: number("rate_numerator"),
                rate_denominator: number("rate_denominator"),
                quantization_ms: number("quantization_ms"),
                ..TrustedTimeProfile::default()
            };
            let result = Credit::new(
                [
                    number("burst_rounds"),
                    number("refill_period_ms"),
                    number("request_start_budget_ms"),
                ],
                service,
                profile,
            );
            if !vector["expected_error"].is_null() {
                assert!(result.is_err(), "{}", vector["id"]);
            } else {
                let credit = result.unwrap();
                assert_eq!(
                    credit.maximum_rounds,
                    vector["expected"]["max_rounds"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap(),
                    "{}",
                    vector["id"]
                );
                assert_eq!(
                    credit.base,
                    vector["expected"]["capacity_credit"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                );
            }
        }
    }
    #[test]
    fn protected_maintenance_tail_and_unknown_future_epoch_are_not_spendable() {
        let (_owner, mut client, mut server) = record_pair_for_limits(Profile::X25519);
        let index = client.slot_for(false, 0, 0).unwrap();
        client.keys[index].usage.seals = (1 << 20) - client.rekey.geometry.margin.seals;
        let total = client.session_usage;
        assert_eq!(
            client.seal_reliable(0, 15, b"ordinary", &mut [0; 256]),
            Err(CryptoError::Capacity)
        );
        assert_eq!(client.session_usage, total);
        let mut writer = Writer::default();
        assert!(client.request_rekey(&mut writer).unwrap());
        let mut wire = take(&mut writer);
        wire[8..12].copy_from_slice(&1234u32.to_be_bytes());
        let before = server.session_usage;
        assert!(server.receive_rekey(&wire, &mut [0; 512]).is_err());
        assert_eq!(server.session_usage, before);
    }
    #[test]
    fn exact_credit_keeps_partial_balance_and_excludes_round_duration() {
        let profile = TrustedTimeProfile {
            rate_numerator: 1,
            rate_denominator: 10_000,
            quantization_ms: 2,
            ..TrustedTimeProfile::default()
        };
        let mut c = Credit::new([2, 30_000, 5000], 86_400_000, profile).unwrap();
        let (_owner, client, _server) = record_pair_for_limits(Profile::X25519);
        let now = client.account.security_time().unwrap();
        let post = c.charge(now, false).unwrap();
        assert_eq!(post, 30_000);
        let mut ack = now;
        ack.monotonic_sample += Duration::from_secs(20);
        c.complete(post, ack);
        let mut next = ack;
        next.monotonic_sample += Duration::from_secs(10);
        let available = c.available(next, false).unwrap();
        assert_eq!(available, 49_994);
        assert_eq!(c.available(next, false).unwrap(), available);
        assert_eq!(c.base, 30_000);
        let post = c.charge(next, false).unwrap();
        assert_eq!(post, 19_994);
        next.monotonic_sample += Duration::from_secs(25);
        c.complete(post, next);
        assert_eq!(c.available(next, false).unwrap(), 19_994);
        assert!(Credit::new([2, 12, 5000], 100_000, profile).is_err());
    }
}
