//! Bounded namespace continuity and subscriber gates under the Environment lock.
//! This module accepts only the private full-verifier result type. It does not
//! turn a digest, caller assertion, or newer sequence into verified State.

use crate::environment_v4::{EnvironmentCharge, EnvironmentError, TrustedTimeSample};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

#[path = "namespace_verifier_v4.rs"]
pub(crate) mod verifier;

const MAX_DENIALS: usize = 256;
const MAX_HEAD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceKey {
    pub(crate) tenant: [u8; 32],
    pub(crate) authority: [u8; 32],
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct NamespaceAnchor {
    pub(crate) key: NamespaceKey,
    pub(crate) generation: u64,
    pub(crate) capacity_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialKind {
    Certificate,
    Connection,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceBinding {
    pub(crate) namespace: NamespaceKey,
    pub(crate) generation: u64,
    pub(crate) kind: CredentialKind,
    pub(crate) cohort: u64,
    pub(crate) issuer: [u8; 16],
    pub(crate) credential: [u8; 32],
    pub(crate) lease: Option<([u8; 16], [u8; 16])>,
    pub(crate) max_staleness_ms: u64,
    pub(crate) max_head_signer_lifetime_ms: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Denial {
    Issuer([u8; 16]),
    Credential(CredentialKind, [u8; 32]),
    Lease([u8; 16], [u8; 16]),
}
#[derive(Clone, Copy, Debug)]
struct Head {
    generation: u64,
    sequence: u64,
    digest: [u8; 32],
    state_digest: [u8; 32],
    floors: [u64; 2],
    this_update_ms: u64,
    next_update_ms: u64,
    signer: [u8; 16],
    signer_lifetime_ms: u64,
}

/// This result has no public or crate-visible constructor. A production full
/// verifier must produce it after authenticating the exact State/Head pair,
/// original trust/delegation, capacity and complete continuity proof. Until
/// that assembly exists the production namespace gate stays unavailable.
#[derive(Debug)]
pub(crate) struct VerifiedNamespaceUpdate {
    anchor: NamespaceAnchor,
    head: Head,
    head_bytes: Box<[u8]>,
    state_bytes: Box<[u8]>,
    denials: Box<[Denial]>,
    owner: Option<Arc<AtomicBool>>,
    _charge: Option<EnvironmentCharge>,
}
#[derive(Debug)]
struct Subscriber {
    generation: u64,
    binding: Option<NamespaceBinding>,
    closed: Weak<AtomicBool>,
    wake: Option<Arc<Notify>>,
}
#[derive(Debug)]
struct NamespaceSlot {
    anchor: Option<NamespaceAnchor>,
    pending_key: Option<NamespaceKey>,
    verifier: Option<Arc<AtomicBool>>,
    terminal: bool,
    observed: Option<Head>,
    active: Option<Head>,
    // Two complete preallocated workspaces: the active pair remains intact
    // until the candidate is fully copied and committed under the same gate.
    states: [Vec<u8>; 2],
    active_buffer: usize,
    head_bytes: Vec<u8>,
    denials: Vec<Denial>,
    subscribers: Vec<Subscriber>,
}
#[derive(Debug)]
pub(crate) struct NamespaceRegistry {
    slots: Vec<NamespaceSlot>,
    state_bytes: usize,
    closed: bool,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct SubscriptionId {
    namespace: usize,
    index: usize,
    generation: u64,
}
impl NamespaceRegistry {
    pub(crate) fn backing_bytes(
        entries: u16,
        subscribers: u16,
        state_bytes: u32,
    ) -> Result<u64, EnvironmentError> {
        if entries == 0 || subscribers == 0 || state_bytes == 0 {
            return Err(EnvironmentError::Configuration);
        }
        let per_entry = std::mem::size_of::<NamespaceSlot>() as u64
            + 2 * u64::from(state_bytes)
            + MAX_HEAD_BYTES as u64
            + MAX_DENIALS as u64 * std::mem::size_of::<Denial>() as u64
            + u64::from(subscribers)
                * (std::mem::size_of::<Subscriber>()
                    + std::mem::size_of::<Notify>()
                    + 2 * std::mem::size_of::<usize>()) as u64;
        per_entry
            .checked_mul(u64::from(entries))
            .ok_or(EnvironmentError::Configuration)
    }
    pub(crate) fn new(
        entries: u16,
        subscribers: u16,
        state_bytes: u32,
    ) -> Result<Self, EnvironmentError> {
        Self::backing_bytes(entries, subscribers, state_bytes)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(usize::from(entries))
            .map_err(|_| EnvironmentError::Capacity)?;
        for _ in 0..entries {
            let mut states = [Vec::new(), Vec::new()];
            for buffer in &mut states {
                buffer
                    .try_reserve_exact(state_bytes as usize)
                    .map_err(|_| EnvironmentError::Capacity)?;
            }
            let mut head_bytes = Vec::new();
            head_bytes
                .try_reserve_exact(MAX_HEAD_BYTES)
                .map_err(|_| EnvironmentError::Capacity)?;
            let mut denials = Vec::new();
            denials
                .try_reserve_exact(MAX_DENIALS)
                .map_err(|_| EnvironmentError::Capacity)?;
            let mut listeners = Vec::new();
            listeners
                .try_reserve_exact(usize::from(subscribers))
                .map_err(|_| EnvironmentError::Capacity)?;
            listeners.resize_with(usize::from(subscribers), || Subscriber {
                generation: 0,
                binding: None,
                closed: Weak::new(),
                wake: None,
            });
            slots.push(NamespaceSlot {
                anchor: None,
                pending_key: None,
                verifier: None,
                terminal: false,
                observed: None,
                active: None,
                states,
                active_buffer: 0,
                head_bytes,
                denials,
                subscribers: listeners,
            });
        }
        Ok(Self {
            slots,
            state_bytes: state_bytes as usize,
            closed: false,
        })
    }
    pub(crate) fn claim_verifier(
        &mut self,
        key: NamespaceKey,
        owner: &Arc<AtomicBool>,
    ) -> Result<(), EnvironmentError> {
        if self.closed {
            return Err(EnvironmentError::Closed);
        }
        if self
            .slots
            .iter()
            .any(|slot| slot.pending_key == Some(key) || slot.anchor.is_some_and(|a| a.key == key))
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.anchor.is_none() && s.pending_key.is_none())
            .ok_or(EnvironmentError::Capacity)?;
        slot.pending_key = Some(key);
        slot.verifier = Some(owner.clone());
        Ok(())
    }
    pub(crate) fn install_verified(
        &mut self,
        update: &VerifiedNamespaceUpdate,
        owner: &Arc<AtomicBool>,
        now: TrustedTimeSample,
    ) -> Result<(), EnvironmentError> {
        if update
            .owner
            .as_ref()
            .is_none_or(|original| !Arc::ptr_eq(original, owner))
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.pending_key == Some(update.anchor.key))
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        if slot.terminal
            || slot
                .verifier
                .as_ref()
                .is_none_or(|original| !Arc::ptr_eq(original, owner))
            || owner.load(Ordering::Acquire)
        {
            return Err(EnvironmentError::Closed);
        }
        if slot.anchor.is_none() {
            slot.anchor = Some(update.anchor);
        }
        self.install(update, now)
    }
    pub(crate) fn reject_signers(
        &mut self,
        key: NamespaceKey,
        rejected: &[Option<[u8; 16]>; 64],
    ) -> Result<(), EnvironmentError> {
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.pending_key == Some(key) || s.anchor.is_some_and(|a| a.key == key))
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        if slot
            .active
            .is_some_and(|head| rejected.iter().flatten().any(|id| *id == head.signer))
        {
            slot.seal();
        }
        Ok(())
    }
    pub(crate) fn reject_issuers(
        &mut self,
        key: NamespaceKey,
        rejected: &[Option<[u8; 16]>; 64],
        now: TrustedTimeSample,
    ) -> Result<(), EnvironmentError> {
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.pending_key == Some(key) || s.anchor.is_some_and(|a| a.key == key))
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        for issuer in rejected.iter().flatten() {
            let denial = Denial::Issuer(*issuer);
            if slot.denials.contains(&denial) {
                continue;
            }
            if slot.denials.len() == MAX_DENIALS {
                slot.seal();
                return Err(EnvironmentError::Capacity);
            }
            slot.denials.push(denial);
        }
        if slot.active.is_some() {
            slot.notify(now);
        }
        Ok(())
    }
    pub(crate) fn register(&mut self, anchor: NamespaceAnchor) -> Result<(), EnvironmentError> {
        if self.closed {
            return Err(EnvironmentError::Closed);
        }
        if anchor.generation == 0
            || anchor.key.tenant == [0; 32]
            || anchor.key.authority == [0; 32]
            || anchor.capacity_digest == [0; 32]
        {
            return Err(EnvironmentError::Configuration);
        }
        if let Some(slot) = self
            .slots
            .iter()
            .find(|s| s.anchor.is_some_and(|a| a.key == anchor.key))
        {
            let old = slot.anchor.expect("namespace anchor");
            return if !slot.terminal
                && old.generation == anchor.generation
                && old.capacity_digest == anchor.capacity_digest
            {
                Ok(())
            } else {
                Err(EnvironmentError::AuthorizationDenied)
            };
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.anchor.is_none() && s.pending_key.is_none())
            .ok_or(EnvironmentError::Capacity)?;
        slot.anchor = Some(anchor);
        Ok(())
    }
    pub(crate) fn close(&mut self) {
        self.closed = true;
        for slot in &mut self.slots {
            slot.seal();
        }
    }
    pub(crate) fn terminate(&mut self, key: NamespaceKey) -> Result<(), EnvironmentError> {
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.pending_key == Some(key) || s.anchor.is_some_and(|a| a.key == key))
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        slot.seal();
        Ok(())
    }
    pub(crate) fn install(
        &mut self,
        update: &VerifiedNamespaceUpdate,
        now: TrustedTimeSample,
    ) -> Result<(), EnvironmentError> {
        if self.closed {
            return Err(EnvironmentError::Closed);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.anchor.is_some_and(|a| a.key == update.anchor.key))
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let anchor = slot.anchor.expect("registered namespace");
        let head = update.head;
        if slot.terminal
            || anchor.generation != head.generation
            || anchor.generation != update.anchor.generation
            || anchor.capacity_digest != update.anchor.capacity_digest
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        if head.sequence == 0
            || head.this_update_ms >= head.next_update_ms
            || now.upper_ms >= head.next_update_ms
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        if now.lower_ms < head.this_update_ms {
            return Err(EnvironmentError::TimePending);
        }
        if update.state_bytes.is_empty()
            || update.state_bytes.len() > self.state_bytes
            || update.head_bytes.is_empty()
            || update.head_bytes.len() > MAX_HEAD_BYTES
            || update.denials.len() > MAX_DENIALS
        {
            return Err(EnvironmentError::Capacity);
        }
        if let Some(observed) = slot.observed {
            if head.sequence < observed.sequence {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            if head.sequence == observed.sequence {
                if head.digest != observed.digest || head.state_digest != observed.state_digest {
                    slot.seal();
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                return Ok(());
            }
            if head.this_update_ms < observed.this_update_ms
                || head.floors[0] < observed.floors[0]
                || head.floors[1] < observed.floors[1]
            {
                slot.seal();
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        // Retain all independent denial evidence. Removing it requires the
        // separate proven history-retirement workflow; capacity never evicts it.
        let additional = update
            .denials
            .iter()
            .filter(|d| !slot.denials.contains(d))
            .count();
        if additional > MAX_DENIALS - slot.denials.len() {
            slot.seal();
            return Err(EnvironmentError::Capacity);
        }
        for denial in update.denials.iter() {
            if !slot.denials.contains(denial) {
                slot.denials.push(*denial);
            }
        }
        // A refresh that arrives after a subscriber's original freshness gate
        // expired cannot reopen that subscriber, even when it admits new work.
        if slot.active.is_some() {
            slot.notify(now);
        }
        let buffer = 1 - slot.active_buffer;
        slot.states[buffer].clear();
        slot.states[buffer].extend_from_slice(&update.state_bytes);
        slot.head_bytes.clear();
        slot.head_bytes.extend_from_slice(&update.head_bytes);
        slot.observed = Some(head);
        slot.active = Some(head);
        slot.active_buffer = buffer;
        slot.states[1 - buffer].clear();
        slot.notify(now);
        Ok(())
    }
    pub(crate) fn subscribe(
        &mut self,
        binding: NamespaceBinding,
        closed: &Arc<AtomicBool>,
        now: TrustedTimeSample,
    ) -> Result<(SubscriptionId, Arc<Notify>), EnvironmentError> {
        if self.closed {
            return Err(EnvironmentError::Closed);
        }
        let index = self
            .slots
            .iter()
            .position(|s| s.anchor.is_some_and(|a| a.key == binding.namespace))
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let slot = &mut self.slots[index];
        slot.check(binding, now)?;
        let i = slot
            .subscribers
            .iter()
            .position(|s| s.binding.is_none() && s.generation < u64::MAX)
            .ok_or(EnvironmentError::Capacity)?;
        let generation = slot.subscribers[i].generation + 1;
        let wake = Arc::new(Notify::new());
        slot.subscribers[i] = Subscriber {
            generation,
            binding: Some(binding),
            closed: Arc::downgrade(closed),
            wake: Some(wake.clone()),
        };
        Ok((
            SubscriptionId {
                namespace: index,
                index: i,
                generation,
            },
            wake,
        ))
    }
    pub(crate) fn check(
        &mut self,
        id: SubscriptionId,
        now: TrustedTimeSample,
    ) -> Result<(), EnvironmentError> {
        if self.closed {
            return Err(EnvironmentError::Closed);
        }
        let slot = self
            .slots
            .get_mut(id.namespace)
            .ok_or(EnvironmentError::Closed)?;
        let subscriber = slot
            .subscribers
            .get(id.index)
            .ok_or(EnvironmentError::Closed)?;
        if subscriber.generation != id.generation {
            return Err(EnvironmentError::Closed);
        }
        if subscriber
            .closed
            .upgrade()
            .is_none_or(|closed| closed.load(Ordering::Acquire))
        {
            return Err(EnvironmentError::Closed);
        }
        let result = slot.check(subscriber.binding.ok_or(EnvironmentError::Closed)?, now);
        if result == Err(EnvironmentError::AuthorizationDenied) {
            if let Some(closed) = subscriber.closed.upgrade() {
                closed.store(true, Ordering::Release);
            }
            if let Some(wake) = &subscriber.wake {
                wake.notify_one();
            }
        }
        result
    }
    pub(crate) fn release(&mut self, id: SubscriptionId) {
        if let Some(slot) = self
            .slots
            .get_mut(id.namespace)
            .and_then(|s| s.subscribers.get_mut(id.index))
            && slot.generation == id.generation
        {
            slot.binding = None;
            slot.closed = Weak::new();
            slot.wake = None;
        }
    }
}
impl NamespaceSlot {
    fn seal(&mut self) {
        self.terminal = true;
        if let Some(owner) = &self.verifier {
            owner.store(true, Ordering::Release);
        }
        for subscriber in &self.subscribers {
            if let Some(closed) = subscriber.closed.upgrade() {
                closed.store(true, Ordering::Release);
            }
            if let Some(wake) = &subscriber.wake {
                wake.notify_one();
            }
        }
    }
    fn check(
        &self,
        binding: NamespaceBinding,
        now: TrustedTimeSample,
    ) -> Result<(), EnvironmentError> {
        let anchor = self.anchor.ok_or(EnvironmentError::AuthorizationDenied)?;
        let active = self.active.ok_or(EnvironmentError::TimeUnavailable)?;
        if self.terminal
            || anchor.generation != binding.generation
            || binding.max_staleness_ms == 0
            || binding.max_head_signer_lifetime_ms == 0
            || active.signer_lifetime_ms > binding.max_head_signer_lifetime_ms
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let head = self.observed.ok_or(EnvironmentError::TimeUnavailable)?;
        let class = match binding.kind {
            CredentialKind::Certificate => 0,
            CredentialKind::Connection => 1,
        };
        if binding.cohort < head.floors[class]
            || self.denials.contains(&Denial::Issuer(binding.issuer))
            || self
                .denials
                .contains(&Denial::Credential(binding.kind, binding.credential))
            || binding
                .lease
                .is_some_and(|(issuer, lease)| self.denials.contains(&Denial::Lease(issuer, lease)))
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let freshness = active
            .this_update_ms
            .checked_add(binding.max_staleness_ms)
            .ok_or(EnvironmentError::AuthorizationDenied)?
            .min(active.next_update_ms);
        if now.upper_ms >= freshness {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        if now.lower_ms < active.this_update_ms {
            return Err(EnvironmentError::TimePending);
        }
        Ok(())
    }
    fn notify(&self, now: TrustedTimeSample) {
        for subscriber in &self.subscribers {
            if let Some(binding) = subscriber.binding {
                if self.check(binding, now) == Err(EnvironmentError::AuthorizationDenied)
                    && let Some(closed) = subscriber.closed.upgrade()
                {
                    closed.store(true, Ordering::Release);
                }
                if let Some(wake) = &subscriber.wake {
                    wake.notify_one();
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::time::Instant;

    pub(crate) fn anchor() -> NamespaceAnchor {
        NamespaceAnchor {
            key: NamespaceKey {
                tenant: [1; 32],
                authority: [2; 32],
            },
            generation: 1,
            capacity_digest: [3; 32],
        }
    }
    pub(crate) fn binding() -> NamespaceBinding {
        NamespaceBinding {
            namespace: anchor().key,
            generation: 1,
            kind: CredentialKind::Certificate,
            cohort: 8,
            issuer: [4; 16],
            credential: [5; 32],
            lease: None,
            max_staleness_ms: 10_000,
            max_head_signer_lifetime_ms: 20_000,
        }
    }
    pub(crate) fn update(sequence: u64) -> VerifiedNamespaceUpdate {
        VerifiedNamespaceUpdate {
            anchor: anchor(),
            head: Head {
                generation: 1,
                sequence,
                digest: [sequence as u8; 32],
                state_digest: [6; 32],
                floors: [1, 1],
                this_update_ms: 900,
                next_update_ms: 20_000,
                signer: [7; 16],
                signer_lifetime_ms: 20_000,
            },
            head_bytes: Box::new([0xa0]),
            state_bytes: Box::new([0xa0]),
            denials: Box::new([]),
            owner: None,
            _charge: None,
        }
    }
    fn now(time: u64) -> TrustedTimeSample {
        TrustedTimeSample {
            lower_ms: time,
            upper_ms: time,
            monotonic_sample: Instant::now(),
            clock_incarnation: 1,
            anchor_age_upper_ms: 0,
        }
    }
    fn registry(subscribers: u16) -> NamespaceRegistry {
        let mut registry = NamespaceRegistry::new(1, subscribers, 1024).unwrap();
        registry.register(anchor()).unwrap();
        registry.install(&update(1), now(1_000)).unwrap();
        registry
    }

    #[test]
    fn high_water_rejects_rollback_and_equivocation_without_replacing_history() {
        let mut registry = registry(1);
        registry.install(&update(3), now(1_000)).unwrap();
        assert_eq!(
            registry.install(&update(2), now(1_000)),
            Err(EnvironmentError::AuthorizationDenied)
        );
        assert_eq!(registry.slots[0].observed.unwrap().sequence, 3);
        let closed = Arc::new(AtomicBool::new(false));
        let (_, wake) = registry.subscribe(binding(), &closed, now(1_000)).unwrap();
        let mut fork = update(3);
        fork.head.digest = [9; 32];
        assert_eq!(
            registry.install(&fork, now(1_000)),
            Err(EnvironmentError::AuthorizationDenied)
        );
        assert!(closed.load(Ordering::Acquire));
        assert!(wake.notified().now_or_never().is_some());
        assert_eq!(
            registry.register(anchor()),
            Err(EnvironmentError::AuthorizationDenied)
        );
        assert_eq!(
            registry.install(&update(4), now(1_000)),
            Err(EnvironmentError::AuthorizationDenied)
        );
    }

    #[test]
    fn floor_and_denial_apply_to_subscribers_under_the_install_gate() {
        let mut registry = registry(2);
        let closed = Arc::new(AtomicBool::new(false));
        registry.subscribe(binding(), &closed, now(1_000)).unwrap();
        let unaffected = Arc::new(AtomicBool::new(false));
        let other = NamespaceBinding {
            kind: CredentialKind::Connection,
            ..binding()
        };
        let (other_id, _) = registry.subscribe(other, &unaffected, now(1_000)).unwrap();
        let mut next = update(2);
        next.head.floors = [9, 1];
        registry.install(&next, now(1_000)).unwrap();
        assert!(closed.load(Ordering::Acquire));
        assert!(!unaffected.load(Ordering::Acquire));
        let mut denied = update(3);
        denied.head.floors = [9, 1];
        denied.denials = Box::new([Denial::Issuer([4; 16])]);
        registry.install(&denied, now(1_000)).unwrap();
        assert!(unaffected.load(Ordering::Acquire));
        assert_eq!(
            registry.check(other_id, now(1_000)),
            Err(EnvironmentError::Closed)
        );
        let mut later = update(4);
        later.head.floors = [9, 1];
        registry.install(&later, now(1_000)).unwrap();
        assert!(registry.slots[0].denials.contains(&Denial::Issuer([4; 16])));
    }

    #[test]
    fn subscriber_slots_are_bounded_and_old_handles_cannot_release_new_owners() {
        let mut registry = registry(1);
        let first = Arc::new(AtomicBool::new(false));
        let (old, _) = registry.subscribe(binding(), &first, now(1_000)).unwrap();
        assert_eq!(
            registry
                .subscribe(binding(), &first, now(1_000))
                .unwrap_err(),
            EnvironmentError::Capacity
        );
        registry.release(old);
        let replacement = Arc::new(AtomicBool::new(false));
        let (current, _) = registry
            .subscribe(binding(), &replacement, now(1_000))
            .unwrap();
        registry.release(old);
        registry.check(current, now(1_000)).unwrap();
        registry.terminate(anchor().key).unwrap();
        assert!(replacement.load(Ordering::Acquire));
    }

    #[test]
    fn late_freshness_refresh_cannot_reopen_an_expired_subscriber() {
        let mut registry = registry(1);
        let closed = Arc::new(AtomicBool::new(false));
        let (id, _) = registry
            .subscribe(
                NamespaceBinding {
                    max_staleness_ms: 200,
                    ..binding()
                },
                &closed,
                now(1_000),
            )
            .unwrap();
        let mut next = update(2);
        next.head.this_update_ms = 1_100;
        registry.install(&next, now(1_100)).unwrap();
        assert!(closed.load(Ordering::Acquire));
        assert_eq!(
            registry.check(id, now(1_100)),
            Err(EnvironmentError::Closed)
        );
        registry.release(id);
        registry
            .subscribe(binding(), &Arc::new(AtomicBool::new(false)), now(1_100))
            .unwrap();
    }

    use futures_util::FutureExt;
}
