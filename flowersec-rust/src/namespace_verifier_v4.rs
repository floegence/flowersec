//! Namespace verification belongs to the original Environment and independent
//! trust root. No public assertion can mint a verified update.

use super::{
    CredentialKind, Denial, Head, NamespaceAnchor, NamespaceKey, PendingNamespaceCandidate,
    VerifiedNamespaceHead, VerifiedNamespaceUpdate,
};
use crate::{
    codec_v4::{self as codec, Limits, StateLimits, Value},
    environment_v4::{
        EnvironmentCharge, EnvironmentError, EnvironmentRoot, ResourceLimits, TrustedTimeProfile,
        TrustedTimeSample,
    },
};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

const TRUST_BYTES: usize = 262_144;
const RESPONSE_BYTES: usize = 270_336;
const MAX_HISTORY: usize = 8;

#[path = "credential_verifier_v4.rs"]
pub(crate) mod credential;

#[derive(Clone, Debug)]
pub struct NamespaceTrustRoot {
    pub tenant: String,
    pub authority: String,
    pub key_id: [u8; 16],
    pub public_key: [u8; 32],
    pub max_lifetime_ms: u64,
}
#[derive(Debug)]
pub(crate) struct NamespaceVerifier {
    environment: Arc<EnvironmentRoot>,
    root: NamespaceTrustRoot,
    owner: Arc<AtomicBool>,
    key: NamespaceKey,
    state_bytes: usize,
    node_cap: usize,
    history: Vec<Box<[u8]>>,
    signature_input: Vec<u8>,
    nonce: [u8; 32],
    bootstrap_deadline: Instant,
    bootstrap_end: u64,
    bootstrap_incarnation: u64,
    bootstrap_response: Option<Box<[u8]>>,
    bootstrap_lower_bound: u64,
    bootstrap_material_end: Option<u64>,
    bootstrap_material_deadline: Option<Instant>,
    bootstrap_head_deadline: Option<Instant>,
    bootstrap_failure: Option<EnvironmentError>,
    bootstrap_was_pending: bool,
    bootstrap_fetch_started: bool,
    pending_refresh: Option<(VerifiedNamespaceUpdate, Instant, u64)>,
    pending_trust: Option<Box<[u8]>>,
    retired_refresh_through: Option<u64>,
    bootstrapped: bool,
    previous: Vec<u8>,
    _charge: EnvironmentCharge,
}
#[derive(Debug)]
struct NamespaceTimeCheck {
    now: TrustedTimeSample,
    lower_bound: u64,
    cap: u64,
}
impl NamespaceTimeCheck {
    fn new(now: TrustedTimeSample) -> Self {
        Self {
            now,
            lower_bound: 0,
            cap: u64::MAX,
        }
    }
    fn issuance(&mut self, start: u64, end: u64) -> Result<(), EnvironmentError> {
        if start >= end {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        if self.now.upper_ms >= end {
            return Err(EnvironmentError::MaterialExpired);
        }
        if start > self.now.upper_ms {
            return Err(EnvironmentError::FutureTimestamp);
        }
        self.lower_bound = self.lower_bound.max(start);
        self.cap = self.cap.min(end);
        Ok(())
    }
    fn require_lower(&mut self, bound: u64) {
        self.lower_bound = self.lower_bound.max(bound);
    }
    fn pending(&self) -> bool {
        self.now.lower_ms < self.lower_bound
    }
}
fn invalid(_: codec::Error) -> EnvironmentError {
    EnvironmentError::AuthorizationDenied
}
fn raw_copy(input: &[u8]) -> Result<Box<[u8]>, EnvironmentError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(input.len())
        .map_err(|_| EnvironmentError::Capacity)?;
    copy.extend_from_slice(input);
    Ok(copy.into_boxed_slice())
}
fn key(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}
fn interval(now: TrustedTimeSample, start: u64, end: u64) -> Result<(), EnvironmentError> {
    if start >= end || now.upper_ms >= end {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    if now.lower_ms < start {
        return Err(EnvironmentError::TimePending);
    }
    Ok(())
}
fn decode<'a>(
    input: &'a [u8],
    name: &str,
    bytes: usize,
    nodes: usize,
    state: Option<StateLimits>,
) -> Result<Value<'a>, EnvironmentError> {
    codec::decode(input, name, Limits { bytes, nodes }, state).map_err(invalid)
}
impl NamespaceVerifier {
    pub(crate) fn new(
        environment: Arc<EnvironmentRoot>,
        root: NamespaceTrustRoot,
        state_bytes: usize,
        node_cap: usize,
    ) -> Result<Self, EnvironmentError> {
        let valid_id = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:/@-".contains(&b))
        };
        if !valid_id(&root.tenant)
            || !valid_id(&root.authority)
            || root.key_id == [0; 16]
            || root.public_key == [0; 32]
            || root.max_lifetime_ms == 0
            || state_bytes == 0
            || state_bytes > 1 << 24
            || node_cap == 0
            || node_cap > 1 << 20
        {
            return Err(EnvironmentError::Configuration);
        }
        // Reserve one additional bounded trust document for a fully
        // authenticated TrustConfig whose time lower bound is still pending.
        // It must remain available as the exact authorization context for the
        // retained H2 pair, without entering mature history early.
        let bytes = ((MAX_HISTORY + 1) * TRUST_BYTES
            + 2 * RESPONSE_BYTES
            + 128
            + state_bytes
            + std::mem::size_of::<Self>()) as u64;
        let charge = environment.reserve_environment(ResourceLimits {
            sdk_bytes: bytes,
            items: (MAX_HISTORY + 4) as u64,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let now = environment.sample()?;
        let bootstrap_end = now
            .lower_ms
            .checked_add(90_000)
            .ok_or(EnvironmentError::TimeUnavailable)?;
        let local_deadline = Instant::now()
            .checked_add(Duration::from_secs(89))
            .ok_or(EnvironmentError::TimeUnavailable)?;
        let bootstrap_deadline = local_deadline.min(Self::project_original_deadline(
            environment.security_time_profile(),
            now,
            bootstrap_end,
        )?);
        let mut nonce = [0; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
            .map_err(|_| EnvironmentError::TimeUnavailable)?;
        let mut signature_input = Vec::new();
        signature_input
            .try_reserve_exact(RESPONSE_BYTES + 128)
            .map_err(|_| EnvironmentError::Capacity)?;
        let mut previous = Vec::new();
        previous
            .try_reserve_exact(state_bytes)
            .map_err(|_| EnvironmentError::Capacity)?;
        let mut history = Vec::new();
        history
            .try_reserve_exact(MAX_HISTORY)
            .map_err(|_| EnvironmentError::Capacity)?;
        let key = NamespaceKey {
            tenant: key(&root.tenant),
            authority: key(&root.authority),
        };
        let owner = Arc::new(AtomicBool::new(false));
        environment.claim_namespace_verifier(key, &owner)?;
        Ok(Self {
            environment,
            root,
            owner,
            key,
            state_bytes,
            node_cap,
            history,
            signature_input,
            nonce,
            bootstrap_deadline,
            bootstrap_end,
            bootstrap_incarnation: now.clock_incarnation,
            bootstrap_response: None,
            bootstrap_lower_bound: 0,
            bootstrap_material_end: None,
            bootstrap_material_deadline: None,
            bootstrap_head_deadline: None,
            bootstrap_failure: None,
            bootstrap_was_pending: false,
            bootstrap_fetch_started: false,
            pending_refresh: None,
            pending_trust: None,
            retired_refresh_through: None,
            bootstrapped: false,
            previous,
            _charge: charge,
        })
    }
    pub(crate) fn bootstrap_nonce(&self) -> [u8; 32] {
        self.nonce
    }
    fn check(&self) -> Result<TrustedTimeSample, EnvironmentError> {
        if self.owner.load(Ordering::Acquire) {
            return Err(EnvironmentError::Closed);
        }
        let now = self.environment.sample()?;
        if now.clock_incarnation != self.bootstrap_incarnation {
            self.owner.store(true, Ordering::Release);
            return Err(EnvironmentError::TimeUnavailable);
        }
        Ok(now)
    }

    fn check_mut(&mut self) -> Result<TrustedTimeSample, EnvironmentError> {
        let result = self.check();
        if self.owner.load(Ordering::Acquire) {
            self.retire_pending_refresh();
        }
        result
    }

    /// Drop a retained H2 candidate exactly once when its namespace reaches a
    /// terminal state. Recording its sequence fences a later replay while
    /// dropping the update (and its EnvironmentCharge) returns every extra
    /// byte/item/work reservation immediately.
    fn retire_pending_refresh(&mut self) {
        if let Some((original, _, _)) = self.pending_refresh.take() {
            self.retired_refresh_through = Some(
                self.retired_refresh_through
                    .unwrap_or(0)
                    .max(original.head.sequence),
            );
        }
        self.pending_trust = None;
    }
    pub(crate) fn cancel_bootstrap_wait(&mut self) {
        if self.bootstrapped {
            self.retire_pending_refresh();
            return;
        }
        // Preserve the original nonce, pinned bytes and earliest deadlines as
        // terminal evidence. Only this namespace ends; the Environment survives.
        self.owner.store(true, Ordering::Release);
        self.retire_pending_refresh();
        let _ = self.environment.terminate_namespace(self.key);
    }
    fn bootstrap_deadline_failure(&self) -> EnvironmentError {
        if self.bootstrap_was_pending {
            EnvironmentError::TimeNotProven
        } else {
            EnvironmentError::BootstrapDeadline
        }
    }
    fn check_bootstrap_bounds(&mut self, now: TrustedTimeSample) -> Result<(), EnvironmentError> {
        if let Some(failure) = self.bootstrap_failure {
            return Err(failure);
        }
        let failure = if self
            .bootstrap_material_end
            .is_some_and(|cap| now.upper_ms >= cap)
            || self
                .bootstrap_material_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Some(EnvironmentError::MaterialExpired)
        } else if now.upper_ms >= self.bootstrap_end || Instant::now() >= self.bootstrap_deadline {
            Some(self.bootstrap_deadline_failure())
        } else {
            None
        };
        if let Some(failure) = failure {
            self.bootstrap_failure = Some(failure);
            return Err(failure);
        }
        Ok(())
    }
    pub(crate) fn bootstrap_wait_owner(
        &mut self,
        fetching: bool,
    ) -> Result<(Arc<EnvironmentRoot>, EnvironmentCharge), EnvironmentError> {
        if let Some(failure) = self.bootstrap_failure {
            return Err(failure);
        }
        let now = self.check_mut()?;
        if self.bootstrapped || fetching && self.bootstrap_fetch_started {
            return Err(EnvironmentError::Closed);
        }
        self.check_bootstrap_bounds(now)?;
        // The fetch result pair can coexist with the pinned original pair and
        // full-verification temporaries. A callback moves this custody into any
        // physical worker that may outlive dropping its observing future.
        let charge = self.environment.reserve_environment(ResourceLimits {
            sdk_bytes: ((if fetching {
                RESPONSE_BYTES + self.state_bytes
            } else {
                0
            }) + std::mem::size_of::<EnvironmentCharge>()
                + 2 * std::mem::size_of::<usize>()
                + std::mem::size_of::<crate::NamespaceBootstrapRequest>())
                as u64,
            items: 1,
            tasks: u64::from(fetching),
            work_slots: u64::from(fetching),
            timers: 1,
            ..ResourceLimits::default()
        })?;
        self.bootstrap_fetch_started |= fetching;
        Ok((self.environment.clone(), charge))
    }
    pub(crate) fn bootstrap_acquisition_deadline(&mut self) -> Result<Instant, EnvironmentError> {
        let now = self.check_mut()?;
        self.check_bootstrap_bounds(now)?;
        Ok(self
            .bootstrap_material_deadline
            .map_or(self.bootstrap_deadline, |deadline| {
                deadline.min(self.bootstrap_deadline)
            }))
    }
    fn project_deadline(
        &self,
        now: TrustedTimeSample,
        cap: u64,
    ) -> Result<Instant, EnvironmentError> {
        Self::project_original_deadline(self.environment.security_time_profile(), now, cap)
    }
    fn project_original_deadline(
        profile: TrustedTimeProfile,
        now: TrustedTimeSample,
        cap: u64,
    ) -> Result<Instant, EnvironmentError> {
        let remaining = cap
            .checked_sub(now.upper_ms)
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let duration = u128::from(
            remaining
                .saturating_sub(profile.quantization_ms)
                .saturating_sub(1),
        ) * u128::from(profile.rate_denominator - profile.rate_numerator)
            / u128::from(profile.rate_denominator);
        let duration = u64::try_from(duration).map_err(|_| EnvironmentError::TimeUnavailable)?;
        now.monotonic_sample
            .checked_add(Duration::from_millis(duration))
            .ok_or(EnvironmentError::TimeUnavailable)
    }
    pub(crate) fn bootstrap_wake(&mut self) -> Result<Instant, EnvironmentError> {
        let now = self.check_mut()?;
        self.check_bootstrap_bounds(now)?;
        let profile = self.environment.security_time_profile();
        let denominator = u128::from(profile.rate_denominator);
        let product = u128::from(self.bootstrap_lower_bound.saturating_sub(now.lower_ms))
            .checked_mul(denominator + u128::from(profile.rate_numerator))
            .ok_or(EnvironmentError::TimeUnavailable)?;
        let delta = product
            .div_ceil(denominator)
            .checked_add(u128::from(profile.quantization_ms))
            .ok_or(EnvironmentError::TimeUnavailable)?;
        let delta = u64::try_from(delta).map_err(|_| EnvironmentError::TimeUnavailable)?;
        let wake = now
            .monotonic_sample
            .checked_add(Duration::from_millis(delta))
            .ok_or(EnvironmentError::TimeUnavailable)?;
        Ok(wake.min(self.bootstrap_deadline).min(
            self.bootstrap_material_deadline
                .unwrap_or(self.bootstrap_deadline),
        ))
    }
    /// The original nonce-bound authority response authenticates startup
    /// freshness. A cached TrustConfig/Head pair alone cannot bootstrap.
    pub(crate) fn bootstrap(
        &mut self,
        response: &[u8],
        state: &[u8],
    ) -> Result<(), EnvironmentError> {
        if let Some(failure) = self.bootstrap_failure {
            return Err(failure);
        }
        let now = self.check_mut()?;
        if self.bootstrapped {
            return Err(EnvironmentError::Closed);
        }
        self.check_bootstrap_bounds(now)?;
        if self
            .bootstrap_response
            .as_ref()
            .is_some_and(|original| original.as_ref() != response || self.previous != state)
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let response_bytes = response;
        let mut timing = NamespaceTimeCheck::new(now);
        let response = decode(
            response,
            "TrustBootstrapResponse",
            RESPONSE_BYTES,
            self.node_cap,
            None,
        )?;
        codec::verify_signature(
            "TrustBootstrapResponse",
            response,
            &self.root.public_key,
            &mut self.signature_input,
        )
        .map_err(invalid)?;
        self.check_root(response, "TrustBootstrapResponse")?;
        if response
            .b::<32>("TrustBootstrapResponse", "request_nonce")
            .map_err(invalid)?
            != self.nonce
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        timing.issuance(
            response
                .u("TrustBootstrapResponse", "issued_at_ms")
                .map_err(invalid)?,
            response
                .u("TrustBootstrapResponse", "not_after_ms")
                .map_err(invalid)?,
        )?;
        let trust = response
            .field("TrustBootstrapResponse", "trust_config")
            .and_then(Value::bytes)
            .map_err(invalid)?;
        let head = response
            .field("TrustBootstrapResponse", "freshness_head")
            .and_then(Value::bytes)
            .map_err(invalid)?;
        self.update_trust(trust, &mut timing)?;
        // Bootstrap may still be proving the first TrustConfig's local time
        // lower bound. Verify the signed Head/State against that fully
        // authenticated, but not-yet-published, TrustConfig instead of
        // requiring history to be non-empty.
        let (update, head_deadline) =
            self.verify_pair(Some(trust), head, state, &mut timing, false)?;
        let head_deadline = self
            .bootstrap_head_deadline
            .map_or(head_deadline, |original| original.min(head_deadline));
        self.bootstrap_head_deadline = Some(head_deadline);
        self.bootstrap_material_end = Some(
            self.bootstrap_material_end
                .unwrap_or(u64::MAX)
                .min(timing.cap),
        );
        self.bootstrap_was_pending |= timing.pending();
        let material_deadline = self.project_deadline(now, timing.cap)?;
        let material_deadline = self
            .bootstrap_material_deadline
            .map_or(material_deadline, |original| {
                original.min(material_deadline)
            });
        self.bootstrap_material_deadline = Some(material_deadline);
        let checked_now = self.check_mut()?;
        self.check_bootstrap_bounds(checked_now)?;
        let result = self.environment.install_verified_namespace(
            &update,
            &self.owner,
            timing.pending(),
            timing.cap,
            material_deadline,
            head_deadline,
            Some((self.bootstrap_deadline, self.bootstrap_deadline_failure())),
            None,
        );
        if result == Err(EnvironmentError::TimePending) {
            if self.bootstrap_response.is_none() {
                self.bootstrap_response = Some(raw_copy(response_bytes)?);
                self.previous.extend_from_slice(state);
            }
            self.bootstrap_lower_bound = self.bootstrap_lower_bound.max(timing.lower_bound);
        }
        if let Err(
            failure @ (EnvironmentError::TimeNotProven
            | EnvironmentError::BootstrapDeadline
            | EnvironmentError::MaterialExpired),
        ) = result
        {
            self.bootstrap_failure = Some(failure);
        }
        result?;
        self.bootstrap_response = None;
        self.bootstrap_head_deadline = None;
        self.previous.clear();
        self.previous.extend_from_slice(state);
        self.bootstrapped = true;
        self.nonce.fill(0);
        Ok(())
    }
    pub(crate) fn refresh(
        &mut self,
        trust: Option<&[u8]>,
        head: &[u8],
        state: &[u8],
    ) -> Result<(), EnvironmentError> {
        let now = self.check_mut()?;
        if !self.bootstrapped {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let pending_expired = self
            .pending_refresh
            .as_ref()
            .is_some_and(|(_, deadline, cap)| now.upper_ms >= *cap || Instant::now() >= *deadline);
        if pending_expired {
            // Retain the terminal sequence while releasing the expired
            // candidate and its authenticated trust context. Active H1 and
            // mature denial history stay intact; a later anchor cannot revive
            // this original H2.
            self.retire_pending_refresh();
        }
        let mut timing = NamespaceTimeCheck::new(now);
        let pending_candidate = self
            .pending_refresh
            .as_ref()
            .is_some_and(|(original, _, _)| {
                original.head_bytes.as_ref() == head && original.state_bytes.as_ref() == state
            });
        let pending_trust = pending_candidate
            .then(|| self.pending_trust.clone())
            .flatten();
        if let Some(trust) = trust
            && let Err(error) = self.update_trust(trust, &mut timing)
        {
            if self.owner.load(Ordering::Acquire) {
                self.retire_pending_refresh();
            }
            return Err(error);
        }
        // A pending candidate carries the exact TrustConfig that authenticated
        // its original Head/State bytes.  Once that document's issuance lower
        // bound is proven, publish the same authenticated bytes before the
        // candidate can complete.  This makes the mature trust revision (and
        // its independent issuer/signer retirements) visible to all later
        // credential checks even when the caller has no reason to retransmit
        // the TrustConfig.  update_trust also enforces the monotonic revision
        // fence, so an old retained candidate cannot roll a newer history back.
        if pending_candidate && let Some(pending_trust) = pending_trust.as_deref() {
            // A newer independently authenticated TrustConfig may already be
            // serving while this original candidate was pending.  Keep that
            // higher revision as the serving authority; the candidate still
            // verifies against its own retained bytes below, and the current
            // history remains the independent rejection gate.
            if !self.pending_trust_is_older(pending_trust)?
                && let Err(error) = self.update_trust(pending_trust, &mut timing)
            {
                // A retained candidate that cannot be published is no longer
                // a valid completion path. Release its charge and replay
                // fence while leaving active State and denial evidence intact.
                self.retire_pending_refresh();
                return Err(error);
            }
        }
        let pair_trust = if pending_candidate {
            pending_trust
        } else if let Some(trust) = trust {
            Some(raw_copy(trust)?)
        } else {
            self.history.last().cloned()
        };
        if pending_candidate && pair_trust.is_none() {
            self.retire_pending_refresh();
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let pending_proof = self
            .pending_refresh
            .as_ref()
            .and_then(|(original, deadline, _)| {
                (original.head_bytes.as_ref() == head && original.state_bytes.as_ref() == state)
                    .then(|| PendingNamespaceCandidate::from_update(original, *deadline))
            });
        let (update, deadline) = match self.verify_pair(
            pair_trust.as_deref(),
            head,
            state,
            &mut timing,
            pending_candidate,
        ) {
            Ok(value) => value,
            Err(error) => {
                if pending_candidate && !timing.pending() {
                    // Once the retained TrustConfig/Head pair is mature, an
                    // authentication failure (including its signer being
                    // independently revoked) permanently invalidates this
                    // candidate.  Release its pin immediately while keeping
                    // the active pair and denial history in the registry.
                    self.retire_pending_refresh();
                } else if self.owner.load(Ordering::Acquire) {
                    self.retire_pending_refresh();
                }
                return Err(error);
            }
        };
        // H2 is verified against the exact TrustConfig that authenticated its
        // original bytes, while any independently supplied mature TrustConfig
        // still governs whether that candidate may complete.
        if pending_candidate
            && !timing.pending()
            && let Some(current) = self.history.last().map(|value| value.as_ref())
            && let Err(error) = self.check_current_trust(current, update.head)
        {
            // The candidate's own signer may be revoked while the active Head
            // remains valid.  Retire this candidate immediately so its pin
            // cannot block future progress; the active pair and all denial
            // evidence already published in the registry are preserved.
            self.retire_pending_refresh();
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Err(EnvironmentError::MaterialExpired);
        }
        if !pending_candidate && self.pending_refresh.is_some() {
            // A retained H2 owns the only completion pin. The independently
            // authenticated newer Head has already advanced observed denial
            // evidence (and its complete State was verified), but cannot
            // install a second active pair until H2 is completed or retired.
            if !timing.pending()
                && let Err(error) = self
                    .environment
                    .observe_verified_namespace_denials(&update, &self.owner)
            {
                if self.owner.load(Ordering::Acquire) {
                    self.retire_pending_refresh();
                }
                return Err(error);
            }
            return Err(EnvironmentError::TimePending);
        }
        let result = self.environment.install_verified_namespace(
            &update,
            &self.owner,
            timing.pending(),
            timing.cap,
            deadline,
            deadline,
            None,
            pending_proof,
        );
        if pending_candidate && result == Err(EnvironmentError::AuthorizationDenied) {
            // The retained candidate has become stale after a newer active
            // pair. Retire it so a fresh old network replay cannot retry the
            // bypass path, while failures before this gate still preserve it.
            self.retire_pending_refresh();
        }
        if result == Err(EnvironmentError::TimePending) {
            // Keep the first candidate's bytes and earliest deadline pinned. A
            // later independently authenticated Head may still advance the
            // observed high-water mark while this candidate is pending.
            if self.pending_refresh.is_none() {
                // Copy the authorization context before publishing either
                // half of the retained candidate. A capacity failure must
                // leave no refresh/trust pair that cannot be retried.
                let original_trust = raw_copy(
                    pair_trust
                        .as_deref()
                        .ok_or(EnvironmentError::AuthorizationDenied)?,
                )?;
                self.pending_trust = Some(original_trust);
                self.pending_refresh = Some((update, deadline, timing.cap));
            }
        } else {
            // An independently newer complete Head may replace the active
            // pair while the original pending candidate remains immutable and
            // finishable by its exact bytes/deadline path.
            if pending_candidate || self.pending_refresh.is_none() {
                self.retire_pending_refresh();
            }
        }
        // `previous` is the continuity baseline for the next admission. Move
        // it only after the registry has accepted this complete pair; a
        // pending or stale candidate must leave the currently active State as
        // the baseline. This is deliberately based on the install result,
        // rather than on candidate identity or the pending flag.
        if result.is_ok() {
            self.previous.clear();
            self.previous.extend_from_slice(state);
        }
        result?;
        Ok(())
    }
    fn check_root(&self, value: Value<'_>, schema: &str) -> Result<(), EnvironmentError> {
        if value
            .field(schema, "tenant_id")
            .and_then(Value::text)
            .map_err(invalid)?
            != self.root.tenant
            || value
                .field(schema, "revocation_authority_id")
                .and_then(Value::text)
                .map_err(invalid)?
                != self.root.authority
            || value.b::<16>(schema, "signing_key_id").map_err(invalid)? != self.root.key_id
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        Ok(())
    }
    fn check_current_trust(&self, bytes: &[u8], head: Head) -> Result<(), EnvironmentError> {
        let trust = decode(bytes, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
        self.check_root(trust, "TrustConfig")?;
        if trust
            .field("TrustConfig", "rejected_head_signers")
            .and_then(Value::children)
            .map_err(invalid)?
            .any(|entry| entry.and_then(Value::bytes) == Ok(head.signer.as_slice()))
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        Ok(())
    }
    fn pending_trust_is_older(&self, bytes: &[u8]) -> Result<bool, EnvironmentError> {
        let Some(current) = self.history.last() else {
            return Ok(false);
        };
        let pending = decode(bytes, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
        let current = decode(current, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
        if pending
            .u("TrustConfig", "authority_generation")
            .map_err(invalid)?
            != current
                .u("TrustConfig", "authority_generation")
                .map_err(invalid)?
        {
            return Ok(false);
        }
        Ok(pending.u("TrustConfig", "revision").map_err(invalid)?
            < current.u("TrustConfig", "revision").map_err(invalid)?)
    }
    fn update_trust(
        &mut self,
        bytes: &[u8],
        timing: &mut NamespaceTimeCheck,
    ) -> Result<(), EnvironmentError> {
        if self.history.last().is_some_and(|old| old.as_ref() == bytes) {
            let old = decode(bytes, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            return timing.issuance(
                old.u("TrustConfig", "issued_at_ms").map_err(invalid)?,
                old.u("TrustConfig", "not_after_ms").map_err(invalid)?,
            );
        }
        if self.history.len() == MAX_HISTORY {
            return Err(EnvironmentError::Capacity);
        }
        let trust = decode(bytes, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
        codec::verify_signature(
            "TrustConfig",
            trust,
            &self.root.public_key,
            &mut self.signature_input,
        )
        .map_err(invalid)?;
        self.check_root(trust, "TrustConfig")?;
        let issued = trust.u("TrustConfig", "issued_at_ms").map_err(invalid)?;
        let end = trust.u("TrustConfig", "not_after_ms").map_err(invalid)?;
        timing.issuance(issued, end)?;
        // A trust document whose issuance lower bound is not yet proven may be
        // fully authenticated and checked, but it cannot mutate the serving
        // history or denial gates until that bound is reached.
        let trust_time_pending = timing.pending();
        if end - issued > self.root.max_lifetime_ms {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let capacity = trust.field("TrustConfig", "capacity").map_err(invalid)?;
        let generation = trust
            .u("TrustConfig", "authority_generation")
            .map_err(invalid)?;
        if generation == 0 {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        self.capacity_limits(capacity)?;
        if let Some(previous) = self.history.last() {
            let old = decode(previous, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            if generation
                != old
                    .u("TrustConfig", "authority_generation")
                    .map_err(invalid)?
            {
                if trust_time_pending {
                    return Ok(());
                }
                self.owner.store(true, Ordering::Release);
                let _ = self.environment.terminate_namespace(self.key);
                return Err(EnvironmentError::AuthorizationDenied);
            }
            if trust.u("TrustConfig", "revision").map_err(invalid)?
                <= old.u("TrustConfig", "revision").map_err(invalid)?
                || issued < old.u("TrustConfig", "issued_at_ms").map_err(invalid)?
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            for field in ["capacity", "publication"] {
                if trust.field("TrustConfig", field).map_err(invalid)?.raw()
                    != old.field("TrustConfig", field).map_err(invalid)?.raw()
                {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
            }
            self.check_trust_history(trust)?;
        }
        let capacity_digest =
            codec::digest("namespace_capacity_digest", capacity).map_err(invalid)?;
        self.check_issuer_history(trust)?;
        for (field, schema) in [
            ("issuer_authorizations", "CredentialIssuerAuthorization"),
            ("head_delegations", "HeadSignerDelegation"),
            ("activation_delegations", "ConnectionActivationDelegation"),
        ] {
            for entry in trust
                .field("TrustConfig", field)
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                self.check_namespace(entry, schema, capacity_digest, generation)?;
                if schema == "HeadSignerDelegation" {
                    self.check_publication(
                        entry,
                        schema,
                        trust.field("TrustConfig", "publication").map_err(invalid)?,
                    )?;
                }
            }
        }
        let total = self
            .history
            .iter()
            .try_fold(bytes.len() as u64, |n, b| n.checked_add(b.len() as u64))
            .ok_or(EnvironmentError::Capacity)?;
        if total
            > capacity
                .u("NamespaceCapacity", "max_trust_proof_bytes")
                .map_err(invalid)?
        {
            return Err(EnvironmentError::Capacity);
        }
        let mut entries = 0u64;
        for original in self
            .history
            .iter()
            .map(|b| b.as_ref())
            .chain(std::iter::once(bytes))
        {
            let original = decode(original, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            for field in [
                "credential_policies",
                "issuer_authorizations",
                "head_delegations",
                "activation_delegations",
                "once_authorities",
            ] {
                entries = entries
                    .checked_add(
                        original
                            .field("TrustConfig", field)
                            .and_then(Value::len)
                            .map_err(invalid)? as u64,
                    )
                    .ok_or(EnvironmentError::Capacity)?;
            }
        }
        if entries
            > capacity
                .u("NamespaceCapacity", "max_trust_proof_entries")
                .map_err(invalid)?
        {
            return Err(EnvironmentError::Capacity);
        }
        // Independent rejection takes effect before a replacement Head exists.
        let mut rejected = [None; 64];
        for (i, id) in trust
            .field("TrustConfig", "rejected_head_signers")
            .and_then(Value::children)
            .map_err(invalid)?
            .enumerate()
        {
            rejected[i] = Some(
                id.and_then(Value::bytes)
                    .map_err(invalid)?
                    .try_into()
                    .map_err(|_| EnvironmentError::AuthorizationDenied)?,
            );
        }
        if trust_time_pending {
            return Ok(());
        }
        self.environment
            .reject_namespace_signers(self.key, &rejected)?;
        let mut retired = [None; 64];
        for (i, id) in trust
            .field("TrustConfig", "retired_issuers")
            .and_then(Value::children)
            .map_err(invalid)?
            .enumerate()
        {
            retired[i] = Some(
                id.and_then(Value::bytes)
                    .map_err(invalid)?
                    .try_into()
                    .map_err(|_| EnvironmentError::AuthorizationDenied)?,
            );
        }
        self.environment
            .reject_namespace_issuers(self.key, &retired)?;
        self.history.push(raw_copy(bytes)?);
        Ok(())
    }
    fn check_trust_history(&self, next: Value<'_>) -> Result<(), EnvironmentError> {
        for original in &self.history {
            let old = decode(original, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            for (field, schema, id) in [
                (
                    "issuer_authorizations",
                    "CredentialIssuerAuthorization",
                    "authorization_id",
                ),
                ("head_delegations", "HeadSignerDelegation", "signer_key_id"),
                (
                    "activation_delegations",
                    "ConnectionActivationDelegation",
                    "signing_key_id",
                ),
                (
                    "credential_policies",
                    "CredentialRevocationPolicy",
                    "revocation_policy_id",
                ),
                (
                    "once_authorities",
                    "OnceAuthorityRef",
                    "artifact_issuer_key_id",
                ),
            ] {
                for entry in old
                    .field("TrustConfig", field)
                    .and_then(Value::children)
                    .map_err(invalid)?
                {
                    let entry = entry.map_err(invalid)?;
                    for replacement in next
                        .field("TrustConfig", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                    {
                        let replacement = replacement.map_err(invalid)?;
                        if entry.field(schema, id).map_err(invalid)?.raw()
                            == replacement.field(schema, id).map_err(invalid)?.raw()
                            && (schema != "CredentialRevocationPolicy"
                                || entry
                                    .u(schema, "revocation_policy_revision")
                                    .map_err(invalid)?
                                    == replacement
                                        .u(schema, "revocation_policy_revision")
                                        .map_err(invalid)?)
                            && entry.raw() != replacement.raw()
                        {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    }
                }
            }
            for field in ["retired_issuers", "rejected_head_signers"] {
                for id in old
                    .field("TrustConfig", field)
                    .and_then(Value::children)
                    .map_err(invalid)?
                {
                    let id = id.map_err(invalid)?;
                    if !next
                        .field("TrustConfig", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                        .any(|v| v.is_ok_and(|v| v.raw() == id.raw()))
                    {
                        return Err(EnvironmentError::AuthorizationDenied);
                    }
                }
            }
        }
        Ok(())
    }
    fn check_issuer_history(&self, next: Value<'_>) -> Result<(), EnvironmentError> {
        const GROUPS: [(&str, &str, &str); 2] = [
            (
                "issuer_authorizations",
                "CredentialIssuerAuthorization",
                "issuer_public_key",
            ),
            (
                "activation_delegations",
                "ConnectionActivationDelegation",
                "signer_public_key",
            ),
        ];
        let mut originals = [None; MAX_HISTORY + 1];
        for (i, raw) in self.history.iter().enumerate() {
            originals[i] = Some(decode(
                raw,
                "TrustConfig",
                TRUST_BYTES,
                self.node_cap,
                None,
            )?);
        }
        originals[self.history.len()] = Some(next);
        let previous = if self.previous.is_empty() {
            None
        } else {
            Some(decode(
                &self.previous,
                "RevocationState",
                self.state_bytes,
                self.node_cap,
                Some(
                    self.capacity_limits(next.field("TrustConfig", "capacity").map_err(invalid)?)?,
                ),
            )?)
        };
        for (field, schema, public_field) in GROUPS {
            for entry in next
                .field("TrustConfig", field)
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                let issuer = entry.b::<16>(schema, "issuer_key_id").map_err(invalid)?;
                let public = entry.b::<32>(schema, public_field).map_err(invalid)?;
                if !codec::valid_ed25519_key(&public) {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                let mut already_known = false;
                let mut retired = false;
                for original in originals[..self.history.len()].iter().flatten() {
                    retired |= original
                        .field("TrustConfig", "retired_issuers")
                        .and_then(Value::children)
                        .map_err(invalid)?
                        .any(|v| v.and_then(Value::bytes) == Ok(issuer.as_slice()));
                    for existing in original
                        .field("TrustConfig", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                    {
                        already_known |= existing.map_err(invalid)?.raw() == entry.raw();
                    }
                }
                if !already_known && retired {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                // One issuer revocation identity cannot acquire another public
                // key through a distinct permission or signing-key identifier.
                for original in originals.iter().flatten() {
                    for (other_field, other_schema, other_public) in GROUPS {
                        for other in original
                            .field("TrustConfig", other_field)
                            .and_then(Value::children)
                            .map_err(invalid)?
                        {
                            let other = other.map_err(invalid)?;
                            if other
                                .b::<16>(other_schema, "issuer_key_id")
                                .map_err(invalid)?
                                == issuer
                                && other.b::<32>(other_schema, other_public).map_err(invalid)?
                                    != public
                            {
                                return Err(EnvironmentError::AuthorizationDenied);
                            }
                        }
                    }
                }
                if !already_known
                    && let Some(state) = previous
                    && state
                        .field("RevocationState", "revoked_issuers")
                        .and_then(Value::children)
                        .map_err(invalid)?
                        .any(|v| {
                            v.is_ok_and(|v| {
                                v.b::<16>("RevokedIssuerEntry", "issuer_key_id") == Ok(issuer)
                            })
                        })
                {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
            }
        }
        Ok(())
    }
    fn check_namespace(
        &self,
        value: Value<'_>,
        schema: &str,
        capacity: [u8; 32],
        generation: u64,
    ) -> Result<(), EnvironmentError> {
        if value
            .field(schema, "tenant_id")
            .and_then(Value::text)
            .map_err(invalid)?
            != self.root.tenant
            || value
                .field(schema, "revocation_authority_id")
                .and_then(Value::text)
                .map_err(invalid)?
                != self.root.authority
            || value
                .b::<32>(schema, "namespace_capacity_digest")
                .map_err(invalid)?
                != capacity
            || value.u(schema, "authority_generation").map_err(invalid)? != generation
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        Ok(())
    }
    fn check_publication(
        &self,
        value: Value<'_>,
        schema: &str,
        publication: Value<'_>,
    ) -> Result<(), EnvironmentError> {
        for field in ["publication_policy_id", "publication_policy_revision"] {
            if value.field(schema, field).map_err(invalid)?.raw()
                != publication
                    .field("PublicationPolicy", field)
                    .map_err(invalid)?
                    .raw()
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        Ok(())
    }
    fn capacity_limits(&self, capacity: Value<'_>) -> Result<StateLimits, EnvironmentError> {
        let u = |name| capacity.u("NamespaceCapacity", name).map_err(invalid);
        let limits = StateLimits {
            bytes: u("max_state_encoded_bytes")?,
            issuers: u("max_revoked_issuers")?,
            certificates: u("max_revoked_certificates")?,
            leases: u("max_revoked_leases")?,
            segments: u("max_cohort_policy_segments")?,
        };
        if limits.bytes > self.state_bytes as u64
            || u("max_head_encoded_bytes")? > super::MAX_HEAD_BYTES as u64
        {
            return Err(EnvironmentError::Capacity);
        }
        Ok(limits)
    }
    fn verify_pair(
        &mut self,
        trust_bytes: Option<&[u8]>,
        head_bytes: &[u8],
        state_bytes: &[u8],
        timing: &mut NamespaceTimeCheck,
        pending_candidate: bool,
    ) -> Result<(VerifiedNamespaceUpdate, Instant), EnvironmentError> {
        let trust = decode(
            trust_bytes
                .or_else(|| self.history.last().map(|value| value.as_ref()))
                .ok_or(EnvironmentError::AuthorizationDenied)?,
            "TrustConfig",
            TRUST_BYTES,
            self.node_cap,
            None,
        )?;
        let capacity = trust.field("TrustConfig", "capacity").map_err(invalid)?;
        let limits = self.capacity_limits(capacity)?;
        let publication = trust.field("TrustConfig", "publication").map_err(invalid)?;
        let capacity_digest =
            codec::digest("namespace_capacity_digest", capacity).map_err(invalid)?;
        let generation = trust
            .u("TrustConfig", "authority_generation")
            .map_err(invalid)?;
        let head = decode(head_bytes, "FreshnessHead", 795, self.node_cap, None)?;
        self.check_namespace(head, "FreshnessHead", capacity_digest, generation)?;
        self.check_publication(head, "FreshnessHead", publication)?;
        if head_bytes.len() as u64
            > capacity
                .u("NamespaceCapacity", "max_head_encoded_bytes")
                .map_err(invalid)?
            || head
                .u("FreshnessHead", "state_encoded_bytes")
                .map_err(invalid)?
                > limits.bytes
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let signer = head
            .b::<16>("FreshnessHead", "signing_key_id")
            .map_err(invalid)?;
        let signer_rejected = trust
            .field("TrustConfig", "rejected_head_signers")
            .and_then(Value::children)
            .map_err(invalid)?
            .any(|v| v.and_then(Value::bytes) == Ok(signer.as_slice()));
        let delegation = trust
            .field("TrustConfig", "head_delegations")
            .and_then(Value::children)
            .map_err(invalid)?
            .find_map(|v| {
                v.ok()
                    .filter(|v| v.b::<16>("HeadSignerDelegation", "signer_key_id") == Ok(signer))
            })
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        if codec::digest("head_signer_delegation_digest", delegation).map_err(invalid)?
            != head
                .b::<32>("FreshnessHead", "signer_delegation_digest")
                .map_err(invalid)?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let signer_key = delegation
            .b::<32>("HeadSignerDelegation", "signer_public_key")
            .map_err(invalid)?;
        codec::verify_signature(
            "FreshnessHead",
            head,
            &signer_key,
            &mut self.signature_input,
        )
        .map_err(invalid)?;
        let issued = head.u("FreshnessHead", "this_update_ms").map_err(invalid)?;
        let next = head.u("FreshnessHead", "next_update_ms").map_err(invalid)?;
        let delegation_issued = delegation
            .u("HeadSignerDelegation", "issued_at_ms")
            .map_err(invalid)?;
        let delegation_end = delegation
            .u("HeadSignerDelegation", "not_after_ms")
            .map_err(invalid)?;
        let trust_end = trust.u("TrustConfig", "not_after_ms").map_err(invalid)?;
        let end = next.min(delegation_end).min(trust_end);
        timing.issuance(
            issued
                .max(delegation_issued)
                .max(trust.u("TrustConfig", "issued_at_ms").map_err(invalid)?),
            end,
        )?;
        // A TrustConfig may itself still be proving its issuance lower bound.
        // Its signer-revocation list is authenticated, but must not reject a
        // retained candidate before that TrustConfig becomes mature.  The
        // mature retry re-runs this check after publishing the exact pending
        // TrustConfig and retires any now-invalid candidate immediately.
        if signer_rejected && !timing.pending() {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        if issued < delegation_issued
            || issued >= delegation_end
            || next - issued
                > publication
                    .u("PublicationPolicy", "max_head_validity_ms")
                    .map_err(invalid)?
            || delegation_end - delegation_issued
                > publication
                    .u("PublicationPolicy", "max_signer_lifetime_ms")
                    .map_err(invalid)?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let floors = [
            head.field("FreshnessHead", "credential_revocation_floors")
                .and_then(|v| v.at(0))
                .and_then(Value::uint)
                .map_err(invalid)?,
            head.field("FreshnessHead", "credential_revocation_floors")
                .and_then(|v| v.at(1))
                .and_then(Value::uint)
                .map_err(invalid)?,
        ];
        let origin = capacity
            .u("NamespaceCapacity", "cohort_time_origin_ms")
            .map_err(invalid)?;
        let duration = capacity
            .u("NamespaceCapacity", "cohort_duration_ms")
            .map_err(invalid)?;
        for (class, impact) in ["max_certificate_impact_ms", "max_connection_impact_ms"]
            .iter()
            .enumerate()
        {
            if floors[class] > 0 {
                let impact = capacity.u("NamespaceCapacity", impact).map_err(invalid)?;
                timing.require_lower(
                    floors[class]
                        .checked_mul(duration)
                        .and_then(|n| n.checked_add(origin))
                        .and_then(|n| n.checked_add(impact))
                        .ok_or(EnvironmentError::AuthorizationDenied)?,
                );
            }
        }
        let anchor = NamespaceAnchor {
            key: self.key,
            generation,
            capacity_digest,
        };
        let verified_head = Head {
            generation,
            sequence: head.u("FreshnessHead", "head_sequence").map_err(invalid)?,
            digest: codec::digest("freshness_head_digest", head).map_err(invalid)?,
            state_digest: head.b("FreshnessHead", "state_digest").map_err(invalid)?,
            floors,
            this_update_ms: issued,
            next_update_ms: end,
            signer,
            signer_lifetime_ms: delegation_end - delegation_issued,
        };
        let mut deadline = self.project_deadline(timing.now, verified_head.next_update_ms)?;
        if self.bootstrapped {
            if self
                .retired_refresh_through
                .is_some_and(|retired| verified_head.sequence <= retired)
            {
                return Err(EnvironmentError::MaterialExpired);
            }
            if let Some((original, original_deadline, _)) = &self.pending_refresh
                && original.head_bytes.as_ref() == head_bytes
                && original.state_bytes.as_ref() == state_bytes
            {
                deadline = deadline.min(*original_deadline);
            }
            // Mature Head floors are independent denial evidence. Observe an
            // authenticated H4 before State installation, while the active
            // pair and any retained H2 candidate remain unchanged until the
            // complete State passes below.
            if !pending_candidate {
                match self.environment.observe_verified_namespace_head(
                    &VerifiedNamespaceHead {
                        anchor,
                        head: verified_head,
                        owner: self.owner.clone(),
                    },
                    &self.owner,
                    timing.pending(),
                    timing.cap,
                    deadline,
                ) {
                    Ok(original) => deadline = original,
                    Err(EnvironmentError::TimePending) => (),
                    Err(failure) => return Err(failure),
                }
            }
        }
        let state = decode(
            state_bytes,
            "RevocationState",
            self.state_bytes,
            self.node_cap,
            Some(limits),
        )?;
        if state_bytes.len() as u64
            != head
                .u("FreshnessHead", "state_encoded_bytes")
                .map_err(invalid)?
            || codec::digest("revocation_state_digest", state).map_err(invalid)?
                != head
                    .b::<32>("FreshnessHead", "state_digest")
                    .map_err(invalid)?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        for field in [
            "schema_revision",
            "tenant_id",
            "revocation_authority_id",
            "namespace_capacity_digest",
            "authority_generation",
            "credential_revocation_floors",
            "publication_policy_id",
            "publication_policy_revision",
        ] {
            if state
                .field("RevocationState", field)
                .map_err(invalid)?
                .raw()
                != head.field("FreshnessHead", field).map_err(invalid)?.raw()
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        self.check_state(state, trust, capacity, floors, limits)?;
        let charge = self.environment.reserve_environment(ResourceLimits {
            sdk_bytes: (head_bytes.len()
                + state_bytes.len()
                + super::MAX_DENIALS * std::mem::size_of::<Denial>()) as u64,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let mut denials = Vec::new();
        denials
            .try_reserve_exact(super::MAX_DENIALS)
            .map_err(|_| EnvironmentError::Capacity)?;
        for (field, schema, kind) in [
            ("revoked_issuers", "RevokedIssuerEntry", None),
            (
                "revoked_certificates",
                "RevokedCertificateEntry",
                Some(CredentialKind::Certificate),
            ),
            (
                "revoked_leases",
                "RevokedLeaseEntry",
                Some(CredentialKind::Connection),
            ),
        ] {
            for entry in state
                .field("RevocationState", field)
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                denials.push(match kind {
                    None => Denial::Issuer(entry.b(schema, "issuer_key_id").map_err(invalid)?),
                    Some(CredentialKind::Certificate) => Denial::Credential(
                        CredentialKind::Certificate,
                        entry.b(schema, "certificate_digest").map_err(invalid)?,
                    ),
                    Some(CredentialKind::Connection) => Denial::Lease(
                        entry.b(schema, "issuer_key_id").map_err(invalid)?,
                        entry.b(schema, "lease_id").map_err(invalid)?,
                    ),
                });
            }
        }
        // Keep the original bytes in the update after all bounded State and
        // denial checks. An invalid State never becomes active, while any
        // mature Head observation above remains independent evidence.
        let head_copy = raw_copy(head_bytes)?;
        let state_copy = raw_copy(state_bytes)?;
        Ok((
            VerifiedNamespaceUpdate {
                anchor,
                head: verified_head,
                head_bytes: head_copy,
                state_bytes: state_copy,
                denials: denials.into_boxed_slice(),
                owner: Some(self.owner.clone()),
                _charge: Some(charge),
            },
            deadline,
        ))
    }
    fn check_state(
        &self,
        state: Value<'_>,
        trust: Value<'_>,
        capacity: Value<'_>,
        floors: [u64; 2],
        limits: StateLimits,
    ) -> Result<(), EnvironmentError> {
        let origin = capacity
            .u("NamespaceCapacity", "cohort_time_origin_ms")
            .map_err(invalid)?;
        let duration = capacity
            .u("NamespaceCapacity", "cohort_duration_ms")
            .map_err(invalid)?;
        let impacts = [
            capacity
                .u("NamespaceCapacity", "max_certificate_impact_ms")
                .map_err(invalid)?,
            capacity
                .u("NamespaceCapacity", "max_connection_impact_ms")
                .map_err(invalid)?,
        ];
        let end = |cohort: u64| {
            cohort
                .checked_add(1)
                .and_then(|n| n.checked_mul(duration))
                .and_then(|n| n.checked_add(origin))
                .ok_or(EnvironmentError::AuthorizationDenied)
        };
        let segments = state
            .field("RevocationState", "cohort_policy_segments")
            .map_err(invalid)?;
        // The complete signed State bounds this loop. Reject overlap independently
        // in each class; an absent class does not participate in that interval.
        for (i, entry) in segments.children().map_err(invalid)?.enumerate() {
            let entry = entry.map_err(invalid)?;
            let first = entry
                .u("CohortPolicySegment", "first_cohort")
                .map_err(invalid)?;
            let last = entry
                .u("CohortPolicySegment", "last_cohort")
                .map_err(invalid)?;
            for (class, field) in ["certificate_impact_ms", "connection_impact_ms"]
                .iter()
                .enumerate()
            {
                if let Some(impact) = entry
                    .optional("CohortPolicySegment", field)
                    .map_err(invalid)?
                {
                    let impact = impact.uint().map_err(invalid)?;
                    if impact > impacts[class] || end(last)?.checked_add(impact).is_none() {
                        return Err(EnvironmentError::AuthorizationDenied);
                    }
                    for before in segments.children().map_err(invalid)?.take(i) {
                        let before = before.map_err(invalid)?;
                        if before
                            .optional("CohortPolicySegment", field)
                            .map_err(invalid)?
                            .is_some()
                            && first
                                <= before
                                    .u("CohortPolicySegment", "last_cohort")
                                    .map_err(invalid)?
                            && last
                                >= before
                                    .u("CohortPolicySegment", "first_cohort")
                                    .map_err(invalid)?
                        {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    }
                }
            }
        }
        for (field, schema, time, class) in [
            (
                "revoked_certificates",
                "RevokedCertificateEntry",
                "expires_at_ms",
                0,
            ),
            (
                "revoked_leases",
                "RevokedLeaseEntry",
                "latest_impact_not_after_ms",
                1,
            ),
        ] {
            for entry in state
                .field("RevocationState", field)
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                if entry.u(schema, time).map_err(invalid)?
                    > end(entry.u(schema, "cohort").map_err(invalid)?)?
                        .checked_add(impacts[class])
                        .ok_or(EnvironmentError::AuthorizationDenied)?
                {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
            }
        }
        // Every revoked issuer must carry all independently retained original
        // issuance/delegation impacts, including earlier TrustConfig revisions.
        for entry in state
            .field("RevocationState", "revoked_issuers")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let entry = entry.map_err(invalid)?;
            let issuer = entry
                .b::<16>("RevokedIssuerEntry", "issuer_key_id")
                .map_err(invalid)?;
            let evidence = entry
                .field("RevokedIssuerEntry", "authorizations")
                .map_err(invalid)?;
            for impact in evidence.children().map_err(invalid)? {
                let impact = impact.map_err(invalid)?;
                if !self.original_impact_matches(issuer, impact, trust)? {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
            }
            let mut configs = Vec::with_capacity(self.history.len() + 1);
            for original in &self.history {
                configs.push(decode(
                    original,
                    "TrustConfig",
                    TRUST_BYTES,
                    self.node_cap,
                    None,
                )?);
            }
            configs.push(trust);
            for config in configs {
                for (field, schema, domain) in [
                    (
                        "issuer_authorizations",
                        "CredentialIssuerAuthorization",
                        "credential_issuer_authorization_digest",
                    ),
                    (
                        "activation_delegations",
                        "ConnectionActivationDelegation",
                        "connection_activation_delegation_digest",
                    ),
                ] {
                    for authorization in config
                        .field("TrustConfig", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                    {
                        let authorization = authorization.map_err(invalid)?;
                        if authorization
                            .b::<16>(schema, "issuer_key_id")
                            .map_err(invalid)?
                            != issuer
                        {
                            continue;
                        }
                        let digest = codec::digest(domain, authorization).map_err(invalid)?;
                        if !evidence.children().map_err(invalid)?.any(|v| {
                            v.is_ok_and(|v| {
                                v.b::<32>("IssuerAuthorizationImpact", "authorization_digest")
                                    == Ok(digest)
                            })
                        }) {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    }
                }
            }
        }
        if !self.previous.is_empty() {
            let old = decode(
                &self.previous,
                "RevocationState",
                self.state_bytes,
                self.node_cap,
                Some(limits),
            )?;
            for (field, schema, id, class) in [
                (
                    "revoked_certificates",
                    "RevokedCertificateEntry",
                    "certificate_digest",
                    Some(0),
                ),
                ("revoked_leases", "RevokedLeaseEntry", "lease_id", Some(1)),
                (
                    "revoked_issuers",
                    "RevokedIssuerEntry",
                    "issuer_key_id",
                    None,
                ),
            ] {
                for entry in old
                    .field("RevocationState", field)
                    .and_then(Value::children)
                    .map_err(invalid)?
                {
                    let entry = entry.map_err(invalid)?;
                    let mut retained = None;
                    for next in state
                        .field("RevocationState", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                    {
                        let next = next.map_err(invalid)?;
                        if next.field(schema, id).map_err(invalid)?.raw()
                            == entry.field(schema, id).map_err(invalid)?.raw()
                            && (schema != "RevokedLeaseEntry"
                                || next.field(schema, "issuer_key_id").map_err(invalid)?.raw()
                                    == entry.field(schema, "issuer_key_id").map_err(invalid)?.raw())
                        {
                            retained = Some(next);
                            break;
                        }
                    }
                    if let Some(retained) = retained {
                        if schema == "RevokedIssuerEntry" {
                            for impact in entry
                                .field(schema, "authorizations")
                                .and_then(Value::children)
                                .map_err(invalid)?
                            {
                                let impact = impact.map_err(invalid)?;
                                if !retained
                                    .field(schema, "authorizations")
                                    .and_then(Value::children)
                                    .map_err(invalid)?
                                    .any(|v| v.is_ok_and(|v| v.raw() == impact.raw()))
                                {
                                    return Err(EnvironmentError::AuthorizationDenied);
                                }
                            }
                        } else if schema == "RevokedLeaseEntry" {
                            for field in ["cohort", "artifact_digest"] {
                                if entry.field(schema, field).map_err(invalid)?.raw()
                                    != retained.field(schema, field).map_err(invalid)?.raw()
                                {
                                    return Err(EnvironmentError::AuthorizationDenied);
                                }
                            }
                            if retained
                                .u(schema, "latest_impact_not_after_ms")
                                .map_err(invalid)?
                                < entry
                                    .u(schema, "latest_impact_not_after_ms")
                                    .map_err(invalid)?
                            {
                                return Err(EnvironmentError::AuthorizationDenied);
                            }
                        } else if entry.raw() != retained.raw() {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    } else if let Some(class) = class {
                        if entry.u(schema, "cohort").map_err(invalid)? >= floors[class] {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    } else {
                        let issuer = entry.field(schema, "issuer_key_id").map_err(invalid)?;
                        if !trust
                            .field("TrustConfig", "retired_issuers")
                            .and_then(Value::children)
                            .map_err(invalid)?
                            .any(|v| v.is_ok_and(|v| v.raw() == issuer.raw()))
                        {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                        for impact in entry
                            .field(schema, "authorizations")
                            .and_then(Value::children)
                            .map_err(invalid)?
                        {
                            let impact = impact
                                .map_err(invalid)?
                                .field("IssuerAuthorizationImpact", "max_affected_cohorts")
                                .map_err(invalid)?;
                            for (class, floor) in floors.iter().enumerate() {
                                let cohort = impact.at(class).map_err(invalid)?;
                                if !cohort.is_null() && cohort.uint().map_err(invalid)? >= *floor {
                                    return Err(EnvironmentError::AuthorizationDenied);
                                }
                            }
                        }
                    }
                }
            }
            for old in old
                .field("RevocationState", "cohort_policy_segments")
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let old = old.map_err(invalid)?;
                if segments
                    .children()
                    .map_err(invalid)?
                    .any(|v| v.is_ok_and(|v| v.raw() == old.raw()))
                {
                    continue;
                }
                for (class, field) in ["certificate_impact_ms", "connection_impact_ms"]
                    .iter()
                    .enumerate()
                {
                    if old
                        .optional("CohortPolicySegment", field)
                        .map_err(invalid)?
                        .is_some()
                        && old
                            .u("CohortPolicySegment", "last_cohort")
                            .map_err(invalid)?
                            >= floors[class]
                    {
                        return Err(EnvironmentError::AuthorizationDenied);
                    }
                }
            }
        }
        Ok(())
    }
    fn original_impact_matches(
        &self,
        issuer: [u8; 16],
        impact: Value<'_>,
        current: Value<'_>,
    ) -> Result<bool, EnvironmentError> {
        let digest = impact
            .b::<32>("IssuerAuthorizationImpact", "authorization_digest")
            .map_err(invalid)?;
        let matches = |config: Value<'_>| -> Result<bool, EnvironmentError> {
            for (field, schema, domain) in [
                (
                    "issuer_authorizations",
                    "CredentialIssuerAuthorization",
                    "credential_issuer_authorization_digest",
                ),
                (
                    "activation_delegations",
                    "ConnectionActivationDelegation",
                    "connection_activation_delegation_digest",
                ),
            ] {
                for entry in config
                    .field("TrustConfig", field)
                    .and_then(Value::children)
                    .map_err(invalid)?
                {
                    let entry = entry.map_err(invalid)?;
                    if entry.b::<16>(schema, "issuer_key_id").map_err(invalid)? != issuer
                        || codec::digest(domain, entry).map_err(invalid)? != digest
                    {
                        continue;
                    }
                    for field in [
                        "max_affected_cohorts",
                        "signing_not_before_ms",
                        "signing_not_after_ms",
                    ] {
                        if entry.field(schema, field).map_err(invalid)?.raw()
                            != impact
                                .field("IssuerAuthorizationImpact", field)
                                .map_err(invalid)?
                                .raw()
                        {
                            return Ok(false);
                        }
                    }
                    return Ok(true);
                }
            }
            Ok(false)
        };
        for original in &self.history {
            if matches(decode(
                original,
                "TrustConfig",
                TRUST_BYTES,
                self.node_cap,
                None,
            )?)? {
                return Ok(true);
            }
        }
        if matches(current)? {
            return Ok(true);
        }
        Ok(false)
    }
}
impl Drop for NamespaceVerifier {
    fn drop(&mut self) {
        self.owner.store(true, Ordering::Release);
        self.retire_pending_refresh();
        let _ = self.environment.terminate_namespace(self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec_v4::tests::{array, b, encode_map, sign, t, u};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    fn digest(name: &str, raw: &[u8], schema: &str) -> [u8; 32] {
        codec::digest(
            name,
            decode(
                raw,
                schema,
                1 << 20,
                1 << 20,
                Some(StateLimits {
                    bytes: 1 << 20,
                    issuers: 64,
                    certificates: 64,
                    leases: 64,
                    segments: 64,
                }),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn fixture(
        nonce: [u8; 32],
        sequence: u64,
        revoked: bool,
    ) -> (NamespaceTrustRoot, Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signer = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        let capacity = encode_map(&[
            (0, t("tenant")),
            (1, t("authority")),
            (2, t("cap-1")),
            (3, u(4096)),
            (4, u(8)),
            (5, u(8)),
            (6, u(8)),
            (7, u(8)),
            (8, u(795)),
            (9, u(1 << 20)),
            (10, u(1024)),
            (11, u(0)),
            (12, u(100)),
            (13, u(1000)),
            (14, u(1000)),
        ]);
        let cap = digest("namespace_capacity_digest", &capacity, "NamespaceCapacity");
        let publication = encode_map(&[
            (0, t("publication")),
            (1, u(1)),
            (2, u(10_000)),
            (3, u(20_000)),
        ]);
        let delegation = encode_map(&[
            (0, t(crate::codec_v4::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, b(&cap)),
            (4, u(1)),
            (5, b(&[2; 16])),
            (6, b(&[3; 16])),
            (7, b(signer.public_key().as_ref())),
            (8, u(0)),
            (9, t("publication")),
            (10, u(1)),
            (11, u(1)),
            (12, u(1)),
            (13, u(20_000)),
        ]);
        let trust = sign(
            "TrustConfig",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, u(1)),
                (4, u(1)),
                (5, u(1)),
                (6, u(30_000)),
                (7, capacity),
                (8, publication),
                (9, array(&[])),
                (10, array(&[])),
                (11, array(std::slice::from_ref(&delegation))),
                (12, array(&[])),
                (13, array(&[])),
                (14, array(&[])),
                (15, array(&[])),
                (16, b(&[1; 16])),
            ],
            &root,
        );
        let segments = array(&[encode_map(&[
            (0, u(0)),
            (1, u(100)),
            (2, u(1000)),
            (3, u(1000)),
        ])]);
        let revoked = if revoked {
            array(&[encode_map(&[(0, b(&[8; 32])), (1, u(8)), (2, u(1800))])])
        } else {
            array(&[])
        };
        let state = encode_map(&[
            (0, t(crate::codec_v4::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, b(&cap)),
            (4, u(1)),
            (5, array(&[u(0), u(0)])),
            (6, t("publication")),
            (7, u(1)),
            (8, array(&[])),
            (9, revoked),
            (10, array(&[])),
            (11, segments),
        ]);
        let head = sign(
            "FreshnessHead",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, b(&cap)),
                (4, u(1)),
                (5, array(&[u(0), u(0)])),
                (6, t("publication")),
                (7, u(1)),
                (8, u(sequence)),
                (9, u(900)),
                (10, u(10_000)),
                (
                    11,
                    b(&digest(
                        "revocation_state_digest",
                        &state,
                        "RevocationState",
                    )),
                ),
                (12, u(state.len() as u64)),
                (13, b(&[3; 16])),
                (
                    14,
                    b(&digest(
                        "head_signer_delegation_digest",
                        &delegation,
                        "HeadSignerDelegation",
                    )),
                ),
            ],
            &signer,
        );
        let response = sign(
            "TrustBootstrapResponse",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, b(&nonce)),
                (4, u(900)),
                (5, u(5_000)),
                (6, b(&trust)),
                (7, b(&head)),
                (8, b(&[1; 16])),
            ],
            &root,
        );
        (
            NamespaceTrustRoot {
                tenant: "tenant".into(),
                authority: "authority".into(),
                key_id: [1; 16],
                public_key: root.public_key().as_ref().try_into().unwrap(),
                max_lifetime_ms: 40_000,
            },
            response,
            head,
            state,
        )
    }
    #[test]
    fn authenticated_bootstrap_and_refresh_drive_the_original_namespace_gate() {
        use crate::environment_v4::tests::{bounds, environment};
        let environment = environment();
        let (root, _, _, _) = fixture([0; 32], 1, false);
        let mut verifier = NamespaceVerifier::new(environment.clone(), root, 4096, 16384).unwrap();
        let (_, response, head, state) = fixture(verifier.bootstrap_nonce(), 1, false);
        verifier.bootstrap(&response, &state).unwrap();
        let account = environment.admit(key("tenant"), bounds()).unwrap();
        account
            .bind_namespaces(&[super::super::NamespaceBinding {
                namespace: verifier.key,
                generation: 1,
                kind: CredentialKind::Certificate,
                cohort: 8,
                issuer: [4; 16],
                credential: [8; 32],
                lease: None,
                max_staleness_ms: 10_000,
                max_head_signer_lifetime_ms: 20_000,
            }])
            .unwrap();
        account.check().unwrap();
        assert_eq!(
            verifier.bootstrap(&response, &state),
            Err(EnvironmentError::Closed)
        );
        let mut forged = head.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(
            verifier.refresh(None, &forged, &state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        account.check().unwrap();
        let (_, _, next, state2) = fixture([0; 32], 2, true);
        verifier.refresh(None, &next, &state2).unwrap();
        assert_eq!(account.check(), Err(EnvironmentError::Closed));
        let (_, _, missing, state3) = fixture([0; 32], 3, false);
        assert_eq!(
            verifier.refresh(None, &missing, &state3),
            Err(EnvironmentError::AuthorizationDenied)
        );
    }

    #[test]
    fn mature_pending_trust_is_published_without_retransmission_and_retirement_is_visible() {
        use crate::environment_v4::tests::bounds;

        let clock = crate::environment_v4::tests::TestClock::new(1_000, 1_500);
        let environment =
            crate::TransportEnvironment::with_options(crate::TransportEnvironmentOptions {
                clock: Some(clock.clone()),
                time_profile: crate::environment_v4::TrustedTimeProfile {
                    rate_numerator: 0,
                    quantization_ms: 0,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        let (root, _, _, _) = fixture([0; 32], 1, false);
        let namespace = environment.namespace(root, 4096, 16384).unwrap();
        let (_, response, head, state) = fixture(namespace.bootstrap_nonce(), 1, false);
        namespace.bootstrap(&response, &state).unwrap();

        let account = environment.root().admit(key("tenant"), bounds()).unwrap();
        account
            .bind_namespaces(&[super::super::NamespaceBinding {
                namespace: super::super::NamespaceKey {
                    tenant: key("tenant"),
                    authority: key("authority"),
                },
                generation: 1,
                kind: CredentialKind::Certificate,
                cohort: 8,
                issuer: [4; 16],
                credential: [8; 32],
                lease: None,
                max_staleness_ms: 10_000,
                max_head_signer_lifetime_ms: 20_000,
            }])
            .unwrap();
        account.check().unwrap();

        let trust = decode(
            &response,
            "TrustBootstrapResponse",
            RESPONSE_BYTES,
            16384,
            None,
        )
        .unwrap()
        .field("TrustBootstrapResponse", "trust_config")
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();
        // T2 becomes valid at 1_300ms and independently retires the active
        // credential issuer.  Its bytes are retained by the first pending
        // refresh and are deliberately omitted from the mature retry.
        let trust2 = revise(
            &trust,
            "TrustConfig",
            &[(4, u(2)), (5, u(1_300)), (14, array(&[b(&[4; 16])]))],
            Some(7),
        );
        let head2 = revise(&head, "FreshnessHead", &[(8, u(2)), (9, u(1_300))], Some(9));
        assert_eq!(
            namespace.refresh(Some(&trust2), &head2, &state),
            Err(EnvironmentError::TimePending)
        );

        {
            let mut sample = clock.value.lock().unwrap();
            sample.lower_ms = 1_300;
            sample.upper_ms = 1_500;
            sample.monotonic_sample = tokio::time::Instant::now();
        }
        namespace.refresh(None, &head2, &state).unwrap();
        assert_eq!(account.check(), Err(EnvironmentError::Closed));
    }

    #[test]
    fn mature_revocation_of_pending_signer_retires_only_the_candidate_pin() {
        use crate::environment_v4::tests::bounds;

        let clock = crate::environment_v4::tests::TestClock::new(1_000, 1_500);
        let environment =
            crate::TransportEnvironment::with_options(crate::TransportEnvironmentOptions {
                clock: Some(clock.clone()),
                time_profile: crate::environment_v4::TrustedTimeProfile {
                    rate_numerator: 0,
                    quantization_ms: 0,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        let (root, _, _, _) = fixture([0; 32], 1, false);
        let namespace = environment.namespace(root, 4096, 16384).unwrap();
        let (_, response, head, state) = fixture(namespace.bootstrap_nonce(), 1, false);
        namespace.bootstrap(&response, &state).unwrap();

        let account = environment.root().admit(key("tenant"), bounds()).unwrap();
        account
            .bind_namespaces(&[super::super::NamespaceBinding {
                namespace: super::super::NamespaceKey {
                    tenant: key("tenant"),
                    authority: key("authority"),
                },
                generation: 1,
                kind: CredentialKind::Certificate,
                cohort: 8,
                issuer: [4; 16],
                credential: [8; 32],
                lease: None,
                max_staleness_ms: 10_000,
                max_head_signer_lifetime_ms: 20_000,
            }])
            .unwrap();
        account.check().unwrap();

        let trust = decode(
            &response,
            "TrustBootstrapResponse",
            RESPONSE_BYTES,
            16384,
            None,
        )
        .unwrap()
        .field("TrustBootstrapResponse", "trust_config")
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();
        let trust_value = decode(&trust, "TrustConfig", TRUST_BYTES, 16384, None).unwrap();
        let delegation_a = trust_value
            .field("TrustConfig", "head_delegations")
            .unwrap()
            .at(0)
            .unwrap()
            .raw()
            .to_vec();
        let signer_b = Ed25519KeyPair::from_seed_unchecked(&[10; 32]).unwrap();
        let delegation_b = revise(
            &delegation_a,
            "HeadSignerDelegation",
            &[
                (5, b(&[4; 16])),
                (6, b(&[4; 16])),
                (7, b(signer_b.public_key().as_ref())),
            ],
            None,
        );
        // T2 initially authorizes B, but its independently authenticated
        // rejection is not effective until T2's issuance lower bound is
        // proven.  H2 therefore remains retained as the exact candidate.
        let trust2 = revise(
            &trust,
            "TrustConfig",
            &[
                (4, u(2)),
                (5, u(1_300)),
                (11, array(&[delegation_a, delegation_b.clone()])),
                (15, array(&[b(&[4; 16])])),
            ],
            Some(7),
        );
        let head2 = revise(
            &head,
            "FreshnessHead",
            &[
                (8, u(2)),
                (9, u(1_300)),
                (13, b(&[4; 16])),
                (
                    14,
                    b(&digest(
                        "head_signer_delegation_digest",
                        &delegation_b,
                        "HeadSignerDelegation",
                    )),
                ),
            ],
            Some(10),
        );
        assert_eq!(
            namespace.refresh(Some(&trust2), &head2, &state),
            Err(EnvironmentError::TimePending)
        );

        {
            let mut sample = clock.value.lock().unwrap();
            sample.lower_ms = 1_400;
            sample.upper_ms = 1_500;
            sample.monotonic_sample = tokio::time::Instant::now();
        }
        assert_eq!(
            namespace.refresh(None, &head2, &state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        // A remains active and B's failed candidate no longer pins the slot;
        // an independently signed A head can advance immediately afterward.
        account.check().unwrap();
        let head3 = revise(&head, "FreshnessHead", &[(8, u(3)), (9, u(1_400))], Some(9));
        namespace.refresh(None, &head3, &state).unwrap();
        account.check().unwrap();
    }

    #[test]
    fn older_pending_trust_does_not_roll_back_a_newer_published_revision() {
        let clock = crate::environment_v4::tests::TestClock::new(1_000, 1_500);
        let environment =
            crate::TransportEnvironment::with_options(crate::TransportEnvironmentOptions {
                clock: Some(clock.clone()),
                time_profile: crate::environment_v4::TrustedTimeProfile {
                    rate_numerator: 0,
                    quantization_ms: 0,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        let (root, _, _, _) = fixture([0; 32], 1, false);
        let mut verifier =
            NamespaceVerifier::new(environment.root().clone(), root, 4096, 16384).unwrap();
        let (_, response, head, state) = fixture(verifier.bootstrap_nonce(), 1, false);
        verifier.bootstrap(&response, &state).unwrap();
        let trust = decode(
            &response,
            "TrustBootstrapResponse",
            RESPONSE_BYTES,
            16384,
            None,
        )
        .unwrap()
        .field("TrustBootstrapResponse", "trust_config")
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();
        let trust2 = revise(&trust, "TrustConfig", &[(4, u(2)), (5, u(1_300))], Some(7));
        let head2 = revise(&head, "FreshnessHead", &[(8, u(2)), (9, u(1_300))], Some(9));
        assert_eq!(
            verifier.refresh(Some(&trust2), &head2, &state),
            Err(EnvironmentError::TimePending)
        );

        // A newer T3 is independently published while H2 remains pinned.
        let trust3 = revise(&trust, "TrustConfig", &[(4, u(3)), (5, u(1_000))], Some(7));
        let head3 = revise(&head, "FreshnessHead", &[(8, u(3)), (9, u(1_000))], Some(9));
        assert_eq!(
            verifier.refresh(Some(&trust3), &head3, &state),
            Err(EnvironmentError::TimePending)
        );
        assert_eq!(verifier.history.len(), 2);
        assert_eq!(verifier.history.last().unwrap().as_ref(), trust3.as_slice());

        {
            let mut sample = clock.value.lock().unwrap();
            sample.lower_ms = 1_400;
            sample.upper_ms = 1_500;
            sample.monotonic_sample = tokio::time::Instant::now();
        }
        // H2 is still verified against its original T2 bytes, but publishing
        // T2 is skipped because T3 is already the higher serving revision.
        verifier.refresh(None, &head2, &state).unwrap();
        assert_eq!(verifier.history.len(), 2);
        assert_eq!(verifier.history.last().unwrap().as_ref(), trust3.as_slice());
    }
    #[test]
    fn bootstrap_nonce_and_full_state_binding_are_required() {
        use crate::environment_v4::tests::environment;
        let environment = environment();
        let (root, _, _, _) = fixture([0; 32], 1, false);
        let mut verifier =
            NamespaceVerifier::new(environment.clone(), root.clone(), 4096, 16384).unwrap();
        assert_eq!(
            NamespaceVerifier::new(environment, root, 4096, 16384).unwrap_err(),
            EnvironmentError::AuthorizationDenied
        );
        let (_, wrong, _, state) = fixture([0; 32], 1, false);
        assert_eq!(
            verifier.bootstrap(&wrong, &state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let (_, response, _, state) = fixture(verifier.bootstrap_nonce(), 1, false);
        let mut wrong_state = state.clone();
        let last = wrong_state.len() - 1;
        wrong_state[last] ^= 1;
        assert_eq!(
            verifier.bootstrap(&response, &wrong_state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        verifier.bootstrap(&response, &state).unwrap();
    }

    fn revise(raw: &[u8], schema: &str, changes: &[(u64, Vec<u8>)], seed: Option<u8>) -> Vec<u8> {
        let value = decode(
            raw,
            schema,
            1 << 20,
            1 << 20,
            Some(StateLimits {
                bytes: 4096,
                issuers: 8,
                certificates: 8,
                leases: 8,
                segments: 8,
            }),
        )
        .unwrap();
        let mut children = value.children().unwrap();
        let mut fields = Vec::new();
        while let Some(id) = children.next() {
            let id = id.unwrap().uint().unwrap();
            let original = children.next().unwrap().unwrap();
            fields.push((
                id,
                changes
                    .iter()
                    .find(|(field, _)| *field == id)
                    .map_or_else(|| original.raw().to_vec(), |(_, value)| value.clone()),
            ));
        }
        if seed.is_some() {
            fields.pop();
        }
        for (id, value) in changes {
            if !fields.iter().any(|(field, _)| field == id) {
                fields.push((*id, value.clone()));
            }
        }
        fields.sort_by_key(|(id, _)| *id);
        match seed {
            Some(seed) => sign(
                schema,
                &fields,
                &Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap(),
            ),
            None => encode_map(&fields),
        }
    }
    // Keep provider and task type boundaries explicit. These are test-owned
    // boxes; SDK custody, cancellation and real I/O still use production APIs.
    type BootstrapFetch = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(Vec<u8>, Vec<u8>), EnvironmentError>> + Send>,
    >;
    type BootstrapAttempt<'a> = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), EnvironmentError>> + Send + 'a>,
    >;

    fn bootstrap_environment(
        upper_ms: u64,
    ) -> (
        crate::TransportEnvironment,
        Arc<crate::environment_v4::tests::TestClock>,
    ) {
        let clock = crate::environment_v4::tests::TestClock::new(1000, upper_ms);
        let environment =
            crate::TransportEnvironment::with_options(crate::TransportEnvironmentOptions {
                clock: Some(clock.clone()),
                time_profile: crate::environment_v4::TrustedTimeProfile {
                    rate_numerator: 0,
                    quantization_ms: 0,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        (environment, clock)
    }
    fn bootstrap_verifier(
        environment: &crate::TransportEnvironment,
        window_ms: u64,
    ) -> NamespaceVerifier {
        let (root, _, _, _) = fixture([0; 32], 1, false);
        let mut verifier =
            NamespaceVerifier::new(environment.root().clone(), root, 4096, 16384).unwrap();
        // Supply the test's original local deadline before any fetch or proof.
        // Retries and later anchors still exercise the real immutable cap.
        verifier.bootstrap_deadline = Instant::now() + Duration::from_millis(window_ms);
        verifier
    }
    fn pending_bootstrap_pair(nonce: [u8; 32], cap: u64) -> (Vec<u8>, Vec<u8>) {
        let (_, response, head, state) = fixture(nonce, 1, false);
        let state = revise(
            &state,
            "RevocationState",
            &[(5, array(&[u(1), u(1)]))],
            None,
        );
        let head = history_head(&head, &state, 1, 1);
        let response = revise(
            &response,
            "TrustBootstrapResponse",
            &[(5, u(cap)), (7, b(&head))],
            Some(7),
        );
        (response, state)
    }

    #[test]
    fn pending_bootstrap_preserves_original_nonce_bytes_and_rejects_independent_invalidity() {
        let (environment, _) = bootstrap_environment(1500);
        let mut verifier = bootstrap_verifier(&environment, 5000);
        let nonce = verifier.bootstrap_nonce();
        let (_, response, head, state) = fixture(nonce, 1, false);
        let pending = revise(
            &response,
            "TrustBootstrapResponse",
            &[(4, u(1300))],
            Some(7),
        );
        assert_eq!(
            verifier.bootstrap(&pending, &[0xa0]),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let forged = revise(&head, "FreshnessHead", &[], Some(13));
        let wrong_signer = revise(
            &pending,
            "TrustBootstrapResponse",
            &[(7, b(&forged))],
            Some(7),
        );
        assert_eq!(
            verifier.bootstrap(&wrong_signer, &state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let future = revise(
            &response,
            "TrustBootstrapResponse",
            &[(4, u(2000))],
            Some(7),
        );
        assert_eq!(
            verifier.bootstrap(&future, &state),
            Err(EnvironmentError::FutureTimestamp)
        );
        assert!(verifier.bootstrap_response.is_none());
        for _ in 0..2 {
            assert_eq!(
                verifier.bootstrap(&pending, &state),
                Err(EnvironmentError::TimePending)
            );
            assert_eq!(verifier.bootstrap_nonce(), nonce);
            assert_eq!(
                verifier.bootstrap_response.as_deref(),
                Some(pending.as_slice())
            );
            assert_eq!(verifier.previous, state);
        }
        assert_eq!(
            verifier.bootstrap(&response, &state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        assert!(!verifier.bootstrapped);
    }

    #[tokio::test]
    async fn bootstrap_from_fetches_once_and_proves_the_original_signed_pair() {
        use std::sync::atomic::AtomicUsize;
        let (environment, _) = bootstrap_environment(1500);
        let namespace = crate::Namespace::new(bootstrap_verifier(&environment, 5000));
        let nonce = namespace.bootstrap_nonce();
        let (_, response, head, state) = fixture(nonce, 1, false);
        let response = revise(
            &response,
            "TrustBootstrapResponse",
            &[(4, u(1300))],
            Some(7),
        );
        let calls = AtomicUsize::new(0);
        let start = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(2),
            namespace.bootstrap_from(|original| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(original.nonce(), nonce);
                async move { Ok::<_, EnvironmentError>((response, state.clone())) }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(start.elapsed() >= Duration::from_millis(250));
        assert_eq!(namespace.bootstrap_nonce(), [0; 32]);
        let (_, _, _, state) = fixture(nonce, 1, false);
        namespace.refresh(None, &head, &state).unwrap();
    }

    #[tokio::test]
    async fn pending_bootstrap_local_deadline_does_not_become_signed_material_expiry() {
        let (environment, _) = bootstrap_environment(1010);
        let verifier = bootstrap_verifier(&environment, 40);
        let (response, state) = pending_bootstrap_pair(verifier.bootstrap_nonce(), 5000);
        let namespace = crate::Namespace::new(verifier);
        assert_eq!(
            namespace.bootstrap(&response, &state),
            Err(EnvironmentError::TimePending)
        );
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(2),
                namespace.bootstrap_when_ready(&response, &state)
            )
            .await
            .unwrap(),
            Err(EnvironmentError::TimeNotProven)
        );
        assert_eq!(
            namespace.bootstrap(&response, &state),
            Err(EnvironmentError::TimeNotProven)
        );
    }

    #[tokio::test]
    async fn pending_material_and_local_deadlines_cannot_extend_on_retry_or_new_anchor() {
        for material_first in [false, true] {
            let (environment, clock) = bootstrap_environment(1010);
            let mut verifier =
                bootstrap_verifier(&environment, if material_first { 5000 } else { 40 });
            let original_local = verifier.bootstrap_deadline;
            let (response, state) = pending_bootstrap_pair(
                verifier.bootstrap_nonce(),
                if material_first { 1060 } else { 5000 },
            );
            assert_eq!(
                verifier.bootstrap(&response, &state),
                Err(EnvironmentError::TimePending)
            );
            let original_material = verifier.bootstrap_material_deadline.unwrap();
            // Keep the same original monotonic sample and narrow the interval.
            // This would extend both projections if the first caps were lost.
            clock.value.lock().unwrap().upper_ms = 1001;
            assert_eq!(
                verifier.bootstrap(&response, &state),
                Err(EnvironmentError::TimePending)
            );
            assert_eq!(verifier.bootstrap_deadline, original_local);
            assert!(verifier.bootstrap_material_deadline.unwrap() <= original_material);
            tokio::time::sleep_until(
                original_local.min(original_material) + Duration::from_millis(2),
            )
            .await;
            let expected = if material_first {
                EnvironmentError::MaterialExpired
            } else {
                EnvironmentError::TimeNotProven
            };
            for _ in 0..2 {
                assert_eq!(verifier.bootstrap(&response, &state), Err(expected));
            }
        }
    }

    #[tokio::test]
    async fn dropping_a_polled_pending_future_permanently_ends_original_bootstrap() {
        let (environment, _) = bootstrap_environment(1010);
        let verifier = bootstrap_verifier(&environment, 5000);
        let nonce = verifier.bootstrap_nonce();
        let (response, state) = pending_bootstrap_pair(nonce, 5000);
        let namespace = crate::Namespace::new(verifier);
        // An unpolled future has not begun an attempt and owns no timer.
        drop(namespace.bootstrap_when_ready(&response, &state));
        let baseline = environment.resource_usage();
        let mut waiting: BootstrapAttempt<'_> =
            Box::pin(namespace.bootstrap_when_ready(&response, &state));
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(waiting.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert_eq!(environment.resource_usage().timers, baseline.timers + 1);
        drop(waiting);
        assert_eq!(environment.resource_usage(), baseline);
        assert_eq!(namespace.bootstrap_nonce(), nonce);
        assert_eq!(
            namespace.bootstrap(&response, &state),
            Err(EnvironmentError::Closed)
        );
        assert_eq!(
            namespace.bootstrap_when_ready(&response, &state).await,
            Err(EnvironmentError::Closed)
        );
        assert!(!environment.is_closed());
    }

    #[tokio::test]
    async fn bootstrap_from_close_deadline_and_drop_close_the_actual_pending_socket() {
        use tokio::io::AsyncReadExt;
        for mode in ["close", "deadline", "drop"] {
            let (environment, _) = bootstrap_environment(1010);
            let verifier =
                bootstrap_verifier(&environment, if mode == "deadline" { 200 } else { 5000 });
            let nonce = verifier.bootstrap_nonce();
            let namespace = Arc::new(crate::Namespace::new(verifier));
            let baseline = environment.resource_usage();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (started, ready) = tokio::sync::oneshot::channel();
            let original_namespace = namespace.clone();
            let attempt: BootstrapAttempt<'static> = Box::pin(async move {
                original_namespace
                    .bootstrap_from(|original| -> BootstrapFetch {
                        Box::pin(async move {
                            assert_eq!(original.nonce(), nonce);
                            let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
                            started.send(()).unwrap();
                            let mut byte = [0];
                            let _ = socket.read(&mut byte).await.unwrap();
                            drop(original);
                            Err::<(Vec<u8>, Vec<u8>), _>(EnvironmentError::AuthorizationDenied)
                        })
                    })
                    .await
            });
            let mut task = tokio::spawn(attempt);
            let (mut peer, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
            ready.await.unwrap();
            assert_eq!(environment.resource_usage().tasks, baseline.tasks + 1);
            if mode == "drop" {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else if mode == "close" {
                // Poll the real public Close while the actual socket is pending.
                let close = environment.close();
                tokio::pin!(close);
                tokio::select! {
                    result = &mut task => assert_eq!(result.unwrap(), Err(EnvironmentError::Closed)),
                    result = &mut close => panic!("cleanup completed with namespace and socket still owned: {result:?}"),
                    () = tokio::time::sleep(Duration::from_secs(2)) => panic!("Close did not stop original I/O"),
                }
            } else {
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), task)
                        .await
                        .unwrap()
                        .unwrap(),
                    Err(EnvironmentError::BootstrapDeadline)
                );
            }
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            assert_eq!(environment.resource_usage(), baseline);
            let (_, response, _, state) = fixture(nonce, 1, false);
            assert_eq!(
                namespace.bootstrap(&response, &state),
                Err(if mode == "deadline" {
                    EnvironmentError::BootstrapDeadline
                } else {
                    EnvironmentError::Closed
                })
            );
            drop(namespace);
            assert!(environment.close().await.unwrap().complete);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_observer_keeps_worker_custody_until_physical_cleanup_finishes() {
        let (environment, _) = bootstrap_environment(1010);
        let namespace = Arc::new(crate::Namespace::new(bootstrap_verifier(
            &environment,
            5000,
        )));
        let baseline = environment.resource_usage();
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let original_namespace = namespace.clone();
        let attempt: BootstrapAttempt<'static> = Box::pin(async move {
            original_namespace
                .bootstrap_from(|original| -> BootstrapFetch {
                    Box::pin(async move {
                        // The curl adapter uses this same ownership arrangement: its
                        // bounded blocking worker owns custody through child wait and
                        // file cleanup, even if the observer is dropped earlier.
                        let (result, _physical_tail) = tokio::task::spawn_blocking(move || {
                            started.send(()).unwrap();
                            blocked.recv_timeout(Duration::from_secs(2)).unwrap();
                            (
                                Err::<(Vec<u8>, Vec<u8>), _>(EnvironmentError::AuthorizationDenied),
                                original,
                            )
                        })
                        .await
                        .unwrap();
                        result
                    })
                })
                .await
        });
        let observer = tokio::spawn(attempt);
        ready.await.unwrap();
        observer.abort();
        assert!(observer.await.unwrap_err().is_cancelled());
        assert_eq!(environment.resource_usage().tasks, baseline.tasks + 1);
        assert_eq!(environment.resource_usage().timers, baseline.timers + 1);
        assert_eq!(
            namespace.bootstrap_from(|_| async { unreachable!() }).await,
            Err::<(), _>(EnvironmentError::Closed)
        );
        drop(namespace);
        environment.root().close();
        assert!(!environment.cleanup_status().complete);
        release.send(()).unwrap();
        let cleanup = tokio::time::timeout(Duration::from_secs(2), environment.wait_cleanup())
            .await
            .unwrap();
        assert!(cleanup.complete);
        assert!(!cleanup.cleanup_incomplete);
        assert_eq!(environment.resource_usage().tasks, 0);
        assert_eq!(environment.resource_usage().timers, 0);
    }

    fn history_head(original: &[u8], state: &[u8], sequence: u64, floor: u64) -> Vec<u8> {
        revise(
            original,
            "FreshnessHead",
            &[
                (5, array(&[u(floor), u(floor)])),
                (8, u(sequence)),
                (
                    11,
                    b(&digest("revocation_state_digest", state, "RevocationState")),
                ),
                (12, u(state.len() as u64)),
            ],
            Some(9),
        )
    }
    fn policy_segment(
        first: u64,
        last: u64,
        certificate: Option<u64>,
        connection: Option<u64>,
    ) -> Vec<u8> {
        let mut fields = vec![(0, u(first)), (1, u(last))];
        if let Some(value) = certificate {
            fields.push((2, u(value)));
        }
        if let Some(value) = connection {
            fields.push((3, u(value)));
        }
        encode_map(&fields)
    }
    struct PublicHistory {
        environment: crate::TransportEnvironment,
        clock: Arc<crate::environment_v4::tests::TestClock>,
        namespace: Arc<crate::Namespace>,
        trust: Vec<u8>,
        head: Vec<u8>,
        state: Vec<u8>,
        authorizations: Vec<Vec<u8>>,
    }
    impl PublicHistory {
        fn new() -> Self {
            let clock = crate::environment_v4::tests::TestClock::new(1000, 1010);
            let environment =
                crate::TransportEnvironment::with_options(crate::TransportEnvironmentOptions {
                    clock: Some(clock.clone()),
                    ..Default::default()
                })
                .unwrap();
            let (root, _, _, _) = fixture([0; 32], 1, false);
            let namespace = environment.namespace(root, 4096, 16384).unwrap();
            let (_, response, head, state) = fixture(namespace.bootstrap_nonce(), 1, false);
            let response_value = decode(
                &response,
                "TrustBootstrapResponse",
                RESPONSE_BYTES,
                16384,
                None,
            )
            .unwrap();
            let original_trust = response_value
                .field("TrustBootstrapResponse", "trust_config")
                .unwrap()
                .bytes()
                .unwrap();
            let state_value = decode(
                &state,
                "RevocationState",
                4096,
                16384,
                Some(StateLimits {
                    bytes: 4096,
                    issuers: 8,
                    certificates: 8,
                    leases: 8,
                    segments: 8,
                }),
            )
            .unwrap();
            let cap = state_value
                .b::<32>("RevocationState", "namespace_capacity_digest")
                .unwrap();
            let issuer = Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap();
            let authorizations = [0u64, 1]
                .into_iter()
                .map(|kind| {
                    let mut fields = vec![
                        (0, b(&[20 + kind as u8; 16])),
                        (1, t("tenant")),
                        (2, t("authority")),
                        (3, b(&cap)),
                        (4, u(1)),
                        (5, u(kind)),
                        (6, b(&[4; 16])),
                        (7, b(issuer.public_key().as_ref())),
                        (8, t("service")),
                        (9, u(1)),
                        (10, u(1000)),
                        (11, u(0)),
                        (12, u(8)),
                        (13, u(1900)),
                    ];
                    if kind == 0 {
                        fields.push((14, t("client")));
                    }
                    fields.push((15, t("fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1")));
                    if kind == 0 {
                        fields.push((16, u(0)));
                    }
                    fields.push((
                        24,
                        if kind == 0 {
                            array(&[u(8), vec![0xf6]])
                        } else {
                            array(&[vec![0xf6], u(8)])
                        },
                    ));
                    encode_map(&fields)
                })
                .collect::<Vec<_>>();
            let trust = revise(
                original_trust,
                "TrustConfig",
                &[(10, array(&authorizations))],
                Some(7),
            );
            let state = revise(
                &state,
                "RevocationState",
                &[(11, array(&[policy_segment(0, 8, Some(1000), Some(1000))]))],
                None,
            );
            let head = history_head(&head, &state, 1, 0);
            let response = revise(
                &response,
                "TrustBootstrapResponse",
                &[(6, b(&trust)), (7, b(&head))],
                Some(7),
            );
            namespace.bootstrap(&response, &state).unwrap();
            Self {
                environment,
                clock,
                namespace,
                trust,
                head,
                state,
                authorizations,
            }
        }
        fn refresh(&self, state: &[u8], sequence: u64, floor: u64) -> Result<(), EnvironmentError> {
            self.namespace.refresh(
                None,
                &history_head(&self.head, state, sequence, floor),
                state,
            )
        }
        fn advance_past_original_impact(&self) {
            // Keep the original trusted anchor. Replacing its wall interval
            // with a later disjoint sample would contradict retained evidence.
            let elapsed = self.clock.value.lock().unwrap().monotonic_sample.elapsed();
            if let Some(remaining) = Duration::from_secs(2).checked_sub(elapsed) {
                std::thread::sleep(remaining);
            }
        }
        fn issuer_entry(&self, authorizations: &[Vec<u8>]) -> Vec<u8> {
            let mut evidence = authorizations
                .iter()
                .map(|authorization| {
                    let value = decode(
                        authorization,
                        "CredentialIssuerAuthorization",
                        2048,
                        16384,
                        None,
                    )
                    .unwrap();
                    let digest = digest(
                        "credential_issuer_authorization_digest",
                        authorization,
                        "CredentialIssuerAuthorization",
                    );
                    (
                        digest,
                        encode_map(&[
                            (0, b(&digest)),
                            (
                                1,
                                value
                                    .field("CredentialIssuerAuthorization", "max_affected_cohorts")
                                    .unwrap()
                                    .raw()
                                    .to_vec(),
                            ),
                            (2, u(1)),
                            (3, u(1000)),
                        ]),
                    )
                })
                .collect::<Vec<_>>();
            evidence.sort_by_key(|(digest, _)| *digest);
            encode_map(&[
                (0, b(&[4; 16])),
                (
                    1,
                    array(
                        &evidence
                            .into_iter()
                            .map(|(_, value)| value)
                            .collect::<Vec<_>>(),
                    ),
                ),
            ])
        }
    }
    #[test]
    fn public_namespace_preserves_revoked_lease_identity_and_policy_until_safe_floor() {
        let history = PublicHistory::new();
        let lease = encode_map(&[
            (0, b(&[4; 16])),
            (1, b(&[5; 16])),
            (2, b(&[6; 32])),
            (3, u(8)),
            (4, u(1800)),
        ]);
        let state = revise(
            &history.state,
            "RevocationState",
            &[(10, array(std::slice::from_ref(&lease)))],
            None,
        );
        history.refresh(&state, 2, 0).unwrap();
        for (sequence, changes) in [
            (3, vec![(2, b(&[7; 32]))]),
            (4, vec![(3, u(7))]),
            (5, vec![(4, u(1700))]),
        ] {
            let changed = revise(&lease, "RevokedLeaseEntry", &changes, None);
            let invalid = revise(&state, "RevocationState", &[(10, array(&[changed]))], None);
            assert_eq!(
                history.refresh(&invalid, sequence, 0),
                Err(EnvironmentError::AuthorizationDenied)
            );
        }
        assert_eq!(
            history.refresh(&history.state, 3, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let longer = revise(&lease, "RevokedLeaseEntry", &[(4, u(1850))], None);
        let retained = revise(&state, "RevocationState", &[(10, array(&[longer]))], None);
        history.refresh(&retained, 6, 0).unwrap();
        let removed_policy = revise(&retained, "RevocationState", &[(11, array(&[]))], None);
        assert_eq!(
            history.refresh(&removed_policy, 7, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let collected = revise(
            &history.state,
            "RevocationState",
            &[(5, array(&[u(9), u(9)])), (11, array(&[]))],
            None,
        );
        assert_eq!(
            history.refresh(&collected, 8, 9),
            Err(EnvironmentError::TimePending)
        );
        history.advance_past_original_impact();
        history.refresh(&collected, 8, 9).unwrap();
        drop(history.namespace);
        drop(history.environment);
    }
    #[test]
    fn public_namespace_requires_complete_original_issuer_history_after_trust_replacement() {
        let history = PublicHistory::new();
        // Removing a permission from the latest trust document does not erase
        // its independently retained impact from earlier signed revisions.
        let replacement = revise(
            &history.trust,
            "TrustConfig",
            &[(4, u(2)), (10, array(&history.authorizations[1..]))],
            Some(7),
        );
        history
            .namespace
            .refresh(
                Some(&replacement),
                &history_head(&history.head, &history.state, 2, 0),
                &history.state,
            )
            .unwrap();
        let incomplete = revise(
            &history.state,
            "RevocationState",
            &[(
                8,
                array(&[history.issuer_entry(&history.authorizations[1..])]),
            )],
            None,
        );
        assert_eq!(
            history.refresh(&incomplete, 3, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let evidence = history.issuer_entry(&history.authorizations);
        let revoked = revise(
            &history.state,
            "RevocationState",
            &[(8, array(std::slice::from_ref(&evidence)))],
            None,
        );
        history.refresh(&revoked, 4, 0).unwrap();
        assert_eq!(
            history.refresh(&incomplete, 5, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        assert_eq!(
            history.refresh(&history.state, 6, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let new_permission = revise(
            &history.authorizations[1],
            "CredentialIssuerAuthorization",
            &[(0, b(&[22; 16]))],
            None,
        );
        let resurrected = revise(
            &replacement,
            "TrustConfig",
            &[(4, u(3)), (10, array(&[new_permission]))],
            Some(7),
        );
        assert_eq!(
            history.namespace.refresh(
                Some(&resurrected),
                &history_head(&history.head, &revoked, 7, 0),
                &revoked
            ),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let retired = revise(
            &replacement,
            "TrustConfig",
            &[(4, u(3)), (10, array(&[])), (14, array(&[b(&[4; 16])]))],
            Some(7),
        );
        history
            .namespace
            .refresh(
                Some(&retired),
                &history_head(&history.head, &revoked, 8, 0),
                &revoked,
            )
            .unwrap();
        assert_eq!(
            history.refresh(&history.state, 9, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        history.advance_past_original_impact();
        let collected = revise(
            &history.state,
            "RevocationState",
            &[(5, array(&[u(9), u(9)])), (11, array(&[]))],
            None,
        );
        history.refresh(&collected, 10, 9).unwrap();
        let unretired = revise(
            &retired,
            "TrustConfig",
            &[(4, u(4)), (14, array(&[]))],
            Some(7),
        );
        assert_eq!(
            history.namespace.refresh(
                Some(&unretired),
                &history_head(&history.head, &collected, 11, 9),
                &collected
            ),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let reused = revise(
            &retired,
            "TrustConfig",
            &[(4, u(4)), (10, array(&history.authorizations))],
            Some(7),
        );
        // Identical old evidence may be retained, but a retired identity cannot
        // gain new signing permission even under a new authorization ID.
        history
            .namespace
            .refresh(
                Some(&reused),
                &history_head(&history.head, &collected, 12, 9),
                &collected,
            )
            .unwrap();
        let new_permission = revise(
            &history.authorizations[1],
            "CredentialIssuerAuthorization",
            &[(0, b(&[23; 16]))],
            None,
        );
        let expanded = revise(
            &reused,
            "TrustConfig",
            &[(4, u(5)), (10, array(&[new_permission]))],
            Some(7),
        );
        assert_eq!(
            history.namespace.refresh(
                Some(&expanded),
                &history_head(&history.head, &collected, 13, 9),
                &collected
            ),
            Err(EnvironmentError::AuthorizationDenied)
        );
    }
    #[test]
    fn public_namespace_rejects_overlapping_policy_and_issuer_identity_rewrites() {
        let history = PublicHistory::new();
        let mut overlapping_segments = vec![
            policy_segment(0, 8, Some(1000), Some(1000)),
            policy_segment(8, 9, Some(900), None),
        ];
        overlapping_segments.sort();
        let overlap = revise(
            &history.state,
            "RevocationState",
            &[(11, array(&overlapping_segments))],
            None,
        );
        assert_eq!(
            history.refresh(&overlap, 2, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let inflated = revise(
            &history.state,
            "RevocationState",
            &[(11, array(&[policy_segment(0, 8, Some(1001), Some(1000))]))],
            None,
        );
        assert_eq!(
            history.refresh(&inflated, 3, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let too_late = encode_map(&[
            (0, b(&[4; 16])),
            (1, b(&[5; 16])),
            (2, b(&[6; 32])),
            (3, u(8)),
            (4, u(1901)),
        ]);
        let invalid_lease = revise(
            &history.state,
            "RevocationState",
            &[(10, array(&[too_late]))],
            None,
        );
        assert_eq!(
            history.refresh(&invalid_lease, 4, 0),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let changed = revise(
            &history.authorizations[1],
            "CredentialIssuerAuthorization",
            &[(10, u(999))],
            None,
        );
        let changed_trust = revise(
            &history.trust,
            "TrustConfig",
            &[
                (4, u(2)),
                (10, array(&[history.authorizations[0].clone(), changed])),
            ],
            Some(7),
        );
        assert_eq!(
            history
                .namespace
                .refresh(Some(&changed_trust), &history.head, &history.state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let another_key = Ed25519KeyPair::from_seed_unchecked(&[12; 32]).unwrap();
        let changed = revise(
            &history.authorizations[1],
            "CredentialIssuerAuthorization",
            &[(0, b(&[22; 16])), (7, b(another_key.public_key().as_ref()))],
            None,
        );
        let changed_trust = revise(
            &history.trust,
            "TrustConfig",
            &[(4, u(2)), (10, array(&[changed]))],
            Some(7),
        );
        assert_eq!(
            history
                .namespace
                .refresh(Some(&changed_trust), &history.head, &history.state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        history.refresh(&history.state, 5, 0).unwrap();
    }
}
