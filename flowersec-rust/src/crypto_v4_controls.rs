//! Bounded control operations on the original reliable Session gate.
use super::*;
use crate::environment_v4::{AutomaticLivenessPolicy, TrustedTimeProfile};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

const PROBES: usize = 8;
const PROBE_BUDGET: Duration = Duration::from_secs(10);
const DRAIN_BUDGET: Duration = Duration::from_secs(30);
const CONSUMER_BUDGET: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeOutcome {
    Pending,
    Responsive,
    Canceled,
    DeadlineExceeded,
    RekeyInProgress,
    TimeUnavailable,
    LocalStall,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeResult {
    pub outcome: ProbeOutcome,
    pub submitted: bool,
    pub complete: bool,
    pub elapsed: Option<Duration>,
}
pub(super) struct Probe {
    pub(super) nonce: [u8; 16],
    started: TrustedTimeSample,
    duration_ms: u64,
    finished_at: Mutex<Option<TrustedTimeSample>>,
    account: ResourceAccount,
    profile: TrustedTimeProfile,
    automatic: bool,
    released: AtomicBool,
    pub(super) result: Mutex<ProbeResult>,
    _charge: Option<ResourceCharge>,
    _automatic_charge: Option<Arc<ResourceCharge>>,
}
impl Probe {
    fn observe(&self, now: Option<TrustedTimeSample>) {
        if self.raw().outcome != ProbeOutcome::Pending {
            return;
        }
        let Some(now) = now else {
            self.finish(ProbeOutcome::TimeUnavailable, None);
            return;
        };
        if now.clock_incarnation != self.started.clock_incarnation {
            self.finish(ProbeOutcome::TimeUnavailable, None);
            return;
        }
        match now
            .monotonic_sample
            .checked_duration_since(self.started.monotonic_sample)
            .and_then(|delta| self.profile.elapsed(delta).ok())
        {
            Some((_, upper)) if upper >= self.duration_ms => {
                self.finish(ProbeOutcome::DeadlineExceeded, Some(now));
            }
            None => {
                self.finish(ProbeOutcome::TimeUnavailable, None);
            }
            _ => {}
        }
    }
    fn raw(&self) -> ProbeResult {
        *self.result.lock().expect("v4 probe result")
    }
    pub(super) fn snapshot(&self) -> ProbeResult {
        self.observe(self.account.security_time().ok());
        self.raw()
    }
    fn finish(&self, outcome: ProbeOutcome, now: Option<TrustedTimeSample>) -> bool {
        let mut result = self.result.lock().expect("v4 probe result");
        if result.outcome != ProbeOutcome::Pending {
            return false;
        }
        result.outcome = outcome;
        *self.finished_at.lock().expect("v4 probe terminal mark") = now;
        result.elapsed = now
            .filter(|n| n.clock_incarnation == self.started.clock_incarnation)
            .and_then(|n| {
                n.monotonic_sample
                    .checked_duration_since(self.started.monotonic_sample)
            });
        true
    }
    // Dropping a waiter never needs the drive lock held by an actual synchronous
    // provider publication. The original slot is collected only after it exits.
    pub(super) fn release(&self) {
        self.finish(ProbeOutcome::Canceled, self.account.security_time().ok());
        self.released.store(true, Ordering::Release);
    }
}
struct ProbeSlot {
    owner: Arc<Probe>,
    epoch: Option<u32>,
    handoff: Option<TrustedTimeSample>,
    eligible: bool,
    stall_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainOutcome {
    Pending,
    Drained,
    DeadlineAborted,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainResult {
    pub outcome: DrainOutcome,
}
pub(super) struct Drain {
    deadline: Mutex<Instant>,
    result: Mutex<DrainResult>,
    _charge: ResourceCharge,
}
impl Drain {
    pub(super) fn deadline(&self) -> Instant {
        *self.deadline.lock().expect("v4 drain deadline")
    }
    pub(super) fn limit_deadline(&self, deadline: Instant) {
        let mut current = self.deadline.lock().expect("v4 drain deadline");
        *current = (*current).min(deadline);
    }
    pub(super) fn snapshot(&self) -> DrainResult {
        *self.result.lock().expect("v4 drain result")
    }
    pub(super) fn finish(&self, outcome: DrainOutcome) {
        let mut result = self.result.lock().expect("v4 drain result");
        if result.outcome == DrainOutcome::Pending {
            result.outcome = outcome;
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct GoAway {
    pub(super) ceiling: u64,
    reason: u64,
}
pub(in super::super) struct State {
    idle_duration_ms: u64,
    idle_anchor: Option<TrustedTimeSample>,
    idle_terminal: AtomicU8,
    time_profile: TrustedTimeProfile,
    automatic: Option<AutomaticLivenessPolicy>,
    automatic_charge: Option<Arc<ResourceCharge>>,
    automatic_next: Option<TrustedTimeSample>,
    automatic_misses: u32,
    counter: u128,
    probes: [Option<ProbeSlot>; PROBES],
    pongs: [Option<[u8; 16]>; PROBES],
    pub(super) highest_accepted: [u64; 2],
    pub(super) peer_goaway: Option<GoAway>,
    local_goaway: Option<GoAway>,
    goaway_sent: bool,
    pub(super) drain: Option<Arc<Drain>>,
}
impl State {
    pub(super) fn new(idle_duration_ms: u64, account: &ResourceAccount) -> Result<Self> {
        let time_profile = account.security_time_profile();
        let automatic = account.automatic_liveness();
        let automatic_charge = if automatic.is_some() {
            Some(Arc::new(account.reserve(ResourceLimits {
                sdk_bytes: 1024,
                items: 1,
                timers: 1,
                work_slots: 1,
                tasks: 1,
                sessions: 0,
                ..ResourceLimits::default()
            })?))
        } else {
            None
        };
        if idle_duration_ms != 0 && idle_duration_ms <= time_profile.elapsed(Duration::ZERO)?.1 {
            return Err(CryptoError::Configuration);
        }
        Ok(Self {
            idle_duration_ms,
            idle_anchor: None,
            idle_terminal: AtomicU8::new(0),
            time_profile,
            automatic,
            automatic_charge,
            automatic_next: None,
            automatic_misses: 0,
            counter: 0,
            probes: std::array::from_fn(|_| None),
            pongs: [None; PROBES],
            highest_accepted: [0; 2],
            peer_goaway: None,
            local_goaway: None,
            goaway_sent: false,
            drain: None,
        })
    }
    pub(in super::super) fn activate(&mut self, now: TrustedTimeSample) -> Result<()> {
        if self.idle_anchor.is_some() || self.idle_terminal.load(Ordering::Acquire) != 0 {
            return Err(CryptoError::State);
        }
        if self.idle_duration_ms != 0 {
            self.idle_anchor = Some(now);
        }
        if self.automatic.is_some() {
            self.automatic_next = Some(now);
        }
        Ok(())
    }
    pub(in super::super) fn activity(&mut self, now: TrustedTimeSample) -> Result<()> {
        self.check_idle(now)?;
        if self.idle_duration_ms != 0 {
            if self.idle_anchor.is_none() {
                return Err(CryptoError::State);
            }
            self.idle_anchor = Some(now);
        }
        Ok(())
    }
    pub(super) fn check_idle(&self, now: TrustedTimeSample) -> Result<()> {
        match self.idle_terminal.load(Ordering::Acquire) {
            1 => return Err(CryptoError::Deadline),
            2 => return Err(crate::environment_v4::EnvironmentError::TimeUnavailable.into()),
            _ => {}
        }
        let Some(anchor) = self.idle_anchor else {
            return Ok(());
        };
        // Compare the full signed uint64 millisecond duration with outward
        // elapsed bounds. Never project it into a platform Instant deadline.
        let result = (|| {
            if now.clock_incarnation != anchor.clock_incarnation {
                return Err(crate::environment_v4::EnvironmentError::TimeUnavailable.into());
            }
            let delta = now
                .monotonic_sample
                .checked_duration_since(anchor.monotonic_sample)
                .ok_or(crate::environment_v4::EnvironmentError::TimeUnavailable)?;
            if self.time_profile.elapsed(delta)?.1 >= self.idle_duration_ms {
                return Err(CryptoError::Deadline);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.idle_terminal.store(
                if error == CryptoError::Deadline { 1 } else { 2 },
                Ordering::Release,
            );
        }
        result
    }
    pub(in super::super) fn local_stall(&mut self, now: Option<TrustedTimeSample>) {
        if self.automatic.is_some()
            && let Some(slot) = &mut self.probes[PROBES - 1]
        {
            slot.eligible = false;
            slot.owner.finish(ProbeOutcome::LocalStall, now);
        }
    }
    pub(in super::super) fn rekey_complete(&mut self, now: TrustedTimeSample) {
        self.automatic_misses = 0;
        self.automatic_next = self.automatic.map(|_| now);
        if self.automatic.is_some() {
            self.probes[PROBES - 1] = None;
        }
    }
    fn automatic_outcome(&mut self, now: TrustedTimeSample) -> Result<()> {
        let Some(policy) = self.automatic else {
            return Ok(());
        };
        let Some(slot) = &self.probes[PROBES - 1] else {
            return Ok(());
        };
        let outcome = slot.owner.raw().outcome;
        let finished = *slot
            .owner
            .finished_at
            .lock()
            .expect("v4 probe terminal mark");
        if outcome == ProbeOutcome::Pending {
            return Ok(());
        }
        if outcome == ProbeOutcome::Responsive {
            self.automatic_misses = 0;
        } else if outcome == ProbeOutcome::DeadlineExceeded
            && slot.eligible
            && let (Some(handoff), Some(finished)) = (slot.handoff, finished)
            && handoff.clock_incarnation == finished.clock_incarnation
            && let Some(delta) = finished
                .monotonic_sample
                .checked_duration_since(handoff.monotonic_sample)
            && self
                .time_profile
                .elapsed(delta)
                .is_ok_and(|(lower, _)| lower >= policy.response_ms)
        {
            self.automatic_misses += 1;
        }
        self.probes[PROBES - 1] = None;
        self.automatic_next = Some(now);
        if self.automatic_misses >= policy.miss_threshold {
            return Err(CryptoError::LivenessPathUnresponsive);
        }
        Ok(())
    }
    fn collect_released(&mut self) {
        for slot in &mut self.probes {
            if slot
                .as_ref()
                .is_some_and(|s| !s.owner.automatic && s.owner.released.load(Ordering::Acquire))
            {
                *slot = None;
            }
        }
    }
    pub(in super::super) fn interrupt(
        &mut self,
        cause: ProbeOutcome,
        now: Option<TrustedTimeSample>,
    ) -> bool {
        let mut changed = false;
        for p in self.probes.iter_mut().flatten() {
            p.eligible = false;
            changed |= p.owner.finish(cause, now);
        }
        changed
    }
    pub(super) fn close(&mut self) {
        self.interrupt(ProbeOutcome::Closed, None);
        self.pongs.fill(None);
        if let Some(drain) = &self.drain {
            drain.finish(DrainOutcome::Failed);
        }
    }
}
impl RecordEngine {
    pub(super) fn validate_control(
        &self,
        scope: u64,
        _header: Tuple,
        frame: u8,
        body: &[u8],
    ) -> Result<()> {
        if scope != 0 {
            return Err(CryptoError::Authentication);
        }
        let name = match frame {
            12 => "CLOSE",
            13 => "GOAWAY",
            14 => "PING",
            15 => "PONG",
            _ => return Err(CryptoError::Authentication),
        };
        let value = decode(body, name, self.max_frame, Context::default())?;
        if frame == 12 {
            let target = value.u(name, "target_scope")?;
            if target != 0 {
                let slot = self
                    .streams
                    .index(target)
                    .map(|i| &self.streams.slots[i])
                    .ok_or(CryptoError::Authentication)?;
                if !slot.accepted() || !slot.prefix {
                    return Err(CryptoError::Authentication);
                }
            }
        } else if frame == 13 {
            let tuple = GoAway {
                ceiling: value.u(name, "accept_ceiling")?,
                reason: value.u(name, "reason")?,
            };
            if tuple.ceiling < self.streams.controls.highest_accepted[usize::from(self.role)]
                || self
                    .streams
                    .controls
                    .peer_goaway
                    .is_some_and(|old| old != tuple)
            {
                return Err(CryptoError::Authentication);
            }
        }
        Ok(())
    }
}
impl ReliableSession {
    pub(super) fn start_probe(&mut self, timeout: Duration) -> Result<Arc<Probe>> {
        self.begin_probe(timeout.min(PROBE_BUDGET).as_millis() as u64, false)
    }
    fn begin_probe(&mut self, duration_ms: u64, automatic: bool) -> Result<Arc<Probe>> {
        self.check()?;
        let now = self.engine.account.security_time()?;
        let busy = self.engine.rekey.busy() || self.engine.frozen;
        let controls = &mut self.engine.streams.controls;
        controls.collect_released();
        let ordinary = if controls.automatic.is_some() {
            PROBES - 1
        } else {
            PROBES
        };
        let index = if automatic {
            if controls.automatic.is_none() || controls.probes[PROBES - 1].is_some() {
                return Err(CryptoError::Capacity);
            }
            PROBES - 1
        } else {
            controls.probes[..ordinary]
                .iter()
                .position(Option::is_none)
                .ok_or(CryptoError::Capacity)?
        };
        let charge = if automatic {
            None
        } else {
            match self.engine.account.reserve(ResourceLimits {
                sdk_bytes: 1024,
                items: 1,
                timers: 1,
                work_slots: 1,
                tasks: 1,
                sessions: 0,
                ..ResourceLimits::default()
            }) {
                Ok(charge) => Some(charge),
                Err(error) => {
                    controls.local_stall(Some(now));
                    return Err(error.into());
                }
            }
        };
        let nonce = if busy {
            [0; 16]
        } else {
            controls.counter = controls
                .counter
                .checked_add(1)
                .ok_or(CryptoError::Capacity)?;
            controls.counter.to_be_bytes()
        };
        let owner = Arc::new(Probe {
            nonce,
            started: now,
            duration_ms,
            finished_at: Mutex::new(None),
            account: self.engine.account.clone(),
            profile: controls.time_profile,
            automatic,
            released: AtomicBool::new(false),
            result: Mutex::new(ProbeResult {
                outcome: if busy {
                    ProbeOutcome::RekeyInProgress
                } else {
                    ProbeOutcome::Pending
                },
                submitted: false,
                complete: false,
                elapsed: Some(Duration::ZERO),
            }),
            _charge: charge,
            _automatic_charge: if automatic {
                controls.automatic_charge.clone()
            } else {
                None
            },
        });
        if !busy {
            controls.probes[index] = Some(ProbeSlot {
                owner: owner.clone(),
                epoch: None,
                handoff: None,
                eligible: false,
                stall_generation: 0,
            });
        }
        Ok(owner)
    }
    #[cfg(test)]
    pub(super) fn release_probe(&mut self, probe: &Arc<Probe>) {
        probe.release();
        self.engine.streams.controls.collect_released();
    }
    pub(crate) fn local_liveness_stall(&mut self) {
        self.engine
            .streams
            .controls
            .local_stall(self.engine.account.security_time().ok());
    }
    pub(crate) fn observe_liveness_provider(&mut self, publisher: &dyn RecordPublisher) {
        let controls = &mut self.engine.streams.controls;
        if controls.automatic.is_some()
            && controls.probes[PROBES - 1].as_ref().is_some_and(|slot| {
                publisher.liveness_stalled()
                    || slot.epoch.is_some()
                        && slot.stall_generation != publisher.liveness_stall_generation()
            })
        {
            controls.local_stall(self.engine.account.security_time().ok());
        }
    }
    fn poll_automatic_probe(&mut self, publisher: &dyn RecordPublisher) -> Result<()> {
        let now = self.engine.account.security_time()?;
        self.observe_liveness_provider(publisher);
        let controls = &mut self.engine.streams.controls;
        controls.automatic_outcome(now)?;
        if self.engine.rekey.busy() || self.engine.frozen || publisher.liveness_stalled() {
            return Ok(());
        }
        if let (Some(policy), Some(next)) = (controls.automatic, controls.automatic_next)
            && controls.probes[PROBES - 1].is_none()
            && next.clock_incarnation == now.clock_incarnation
            && let Some(delta) = now
                .monotonic_sample
                .checked_duration_since(next.monotonic_sample)
            && controls.time_profile.elapsed(delta)?.0 >= policy.interval_ms
        {
            match self.begin_probe(policy.submission_ms + policy.response_ms, true) {
                Err(CryptoError::Capacity) => {
                    self.engine.streams.controls.automatic_next = Some(now)
                }
                Err(error) => return Err(error),
                _ => {}
            }
        }
        Ok(())
    }
    pub(super) fn start_drain(&mut self, timeout: Duration) -> Result<Arc<Drain>> {
        self.start_drain_bounded(timeout, None)
    }
    pub(super) fn start_drain_bounded(
        &mut self,
        timeout: Duration,
        group_deadline: Option<Instant>,
    ) -> Result<Arc<Drain>> {
        if let Some(drain) = &self.engine.streams.controls.drain {
            if let Some(deadline) = group_deadline {
                drain.limit_deadline(deadline);
            }
            return Ok(drain.clone());
        }
        self.check()?;
        let now = self.engine.account.security_time()?.monotonic_sample;
        let charge = self.engine.account.reserve(ResourceLimits {
            sdk_bytes: 256,
            items: 1,
            timers: 1,
            work_slots: 1,
            tasks: 0,
            sessions: 0,
            ..ResourceLimits::default()
        })?;
        let deadline = now
            .checked_add(timeout.min(DRAIN_BUDGET))
            .ok_or(CryptoError::Capacity)?;
        let drain = Arc::new(Drain {
            deadline: Mutex::new(group_deadline.map_or(deadline, |group| group.min(deadline))),
            result: Mutex::new(DrainResult {
                outcome: DrainOutcome::Pending,
            }),
            _charge: charge,
        });
        // All fallible preparation precedes this admission boundary. The
        // original drive gate excludes a core poll until application dispatch
        // is sealed, so an ordinary callback can never enter after a zero-work
        // drain observation. Callbacks that won first remain counted.
        if let Some(application) = &self.application {
            application.seal();
        }
        let state = &mut self.engine.streams;
        state.draining = true;
        state.controls.local_goaway = Some(GoAway {
            ceiling: state.controls.highest_accepted[usize::from(1 - self.engine.role)],
            reason: 0,
        });
        state.controls.drain = Some(drain.clone());
        for slot in &mut state.slots {
            if slot.phase == Phase::Pending {
                slot.forced_rejection = Some(Rejection::Draining);
            }
        }
        Ok(drain)
    }
    pub(super) fn apply_control(&mut self, header: Tuple, frame: u8, body: &[u8]) -> Result<()> {
        let now = self.engine.account.security_time()?;
        match frame {
            12 => {
                let value = decode(body, "CLOSE", self.engine.max_frame, Context::default())?;
                let target = value.u("CLOSE", "target_scope")?;
                if target == 0 {
                    if value.u("CLOSE", "reason")? == 0
                        && self.communication_drained()
                        && let Some(drain) = &self.engine.streams.controls.drain
                    {
                        drain.finish(DrainOutcome::Drained);
                    }
                    self.engine.fail();
                } else {
                    let i = self
                        .engine
                        .streams
                        .index(target)
                        .ok_or(CryptoError::Authentication)?;
                    self.reset_index(i, false)?;
                }
            }
            13 => {
                let value = decode(body, "GOAWAY", self.engine.max_frame, Context::default())?;
                self.engine.streams.controls.peer_goaway = Some(GoAway {
                    ceiling: value.u("GOAWAY", "accept_ceiling")?,
                    reason: value.u("GOAWAY", "reason")?,
                });
            }
            14 => {
                let nonce = decode(body, "PING", self.engine.max_frame, Context::default())?
                    .b("PING", "nonce")?;
                let slot = self
                    .engine
                    .streams
                    .controls
                    .pongs
                    .iter_mut()
                    .find(|n| n.is_none())
                    .ok_or(CryptoError::Capacity)?;
                *slot = Some(nonce);
            }
            15 => {
                let nonce = decode(body, "PONG", self.engine.max_frame, Context::default())?
                    .b::<16>("PONG", "nonce")?;
                for slot in self.engine.streams.controls.probes.iter().flatten() {
                    if slot.owner.nonce == nonce && slot.epoch == Some(header.epoch) {
                        slot.owner.observe(Some(now));
                        slot.owner.finish(ProbeOutcome::Responsive, Some(now));
                        break;
                    }
                }
            }
            _ => return Err(CryptoError::Authentication),
        }
        Ok(())
    }
    fn communication_drained(&self) -> bool {
        self.application
            .as_ref()
            .is_none_or(|application| application.ordinary_count().load(Ordering::Acquire) == 0)
            && self.engine.streams.slots.iter().all(|s| {
                !matches!(s.phase, Phase::Opening | Phase::Pending | Phase::Accepted)
                    && s.queue.is_empty()
            })
    }
    pub(super) fn poll_lifecycle_deadlines(&mut self) -> Result<bool> {
        let now = self.engine.account.security_time()?;
        let mut changed = false;
        for slot in self.engine.streams.controls.probes.iter().flatten() {
            let before = slot.owner.raw().outcome;
            slot.owner.observe(Some(now));
            changed |= slot.owner.raw().outcome != before;
        }
        self.engine.streams.controls.collect_released();
        if let Some(drain) = &self.engine.streams.controls.drain
            && now.monotonic_sample >= drain.deadline()
        {
            drain.finish(DrainOutcome::DeadlineAborted);
            self.engine.fail();
            return Ok(true);
        }
        Ok(changed)
    }
    pub(super) fn poll_session_control(
        &mut self,
        publisher: &mut dyn RecordPublisher,
    ) -> Result<bool> {
        if let Some(goaway) = self.engine.streams.controls.local_goaway {
            if !self.engine.streams.controls.goaway_sent {
                let mut body = map(2, 32)?;
                for (key, value) in [(0, goaway.ceiling), (1, goaway.reason)] {
                    uint(&mut body, key);
                    uint(&mut body, value);
                }
                self.send(0, 13, &body, false, publisher)?;
                self.engine.streams.controls.goaway_sent = true;
                return Ok(true);
            }
            if self.communication_drained() && !self.engine.rekey.busy() {
                let body = [0xa2, 0, 0, 1, 0];
                // The result describes real communication proof. Provider cleanup
                // remains an independent observable fact if CLOSE publication fails.
                self.engine
                    .streams
                    .controls
                    .drain
                    .as_ref()
                    .ok_or(CryptoError::State)?
                    .finish(DrainOutcome::Drained);
                self.send(0, 12, &body, false, publisher)?;
                self.engine.fail();
                return Ok(true);
            }
        }
        if let Some(index) = self
            .engine
            .streams
            .controls
            .pongs
            .iter()
            .position(Option::is_some)
        {
            let nonce = self.engine.streams.controls.pongs[index]
                .take()
                .ok_or(CryptoError::State)?;
            let mut body = map(1, 20)?;
            uint(&mut body, 0);
            bytes(&mut body, &nonce);
            self.send(0, 15, &body, false, publisher)?;
            return Ok(true);
        }
        if self.engine.rekey.busy() || self.engine.frozen {
            return Ok(self.engine.streams.controls.interrupt(
                ProbeOutcome::RekeyInProgress,
                Some(self.engine.account.security_time()?),
            ));
        }
        self.poll_automatic_probe(publisher)?;
        let pending = self.engine.streams.controls.probes.iter().position(|s| {
            s.as_ref().is_some_and(|p| {
                p.epoch.is_none() && p.owner.snapshot().outcome == ProbeOutcome::Pending
            })
        });
        let Some(index) = pending else {
            return Ok(false);
        };
        let probe = self.engine.streams.controls.probes[index]
            .as_ref()
            .ok_or(CryptoError::State)?
            .owner
            .clone();
        let mut body = map(1, 20)?;
        uint(&mut body, 0);
        bytes(&mut body, &probe.nonce);
        if !probe.automatic {
            self.local_liveness_stall();
        }
        let stall_generation = publisher.liveness_stall_generation();
        let mut out = std::mem::take(&mut self.engine.streams.output);
        let result = (|| {
            probe.observe(self.engine.account.security_time().ok());
            if probe.raw().outcome != ProbeOutcome::Pending {
                return Ok(());
            }
            // The small ticket gate orders cancellation/result observation
            // with sealing; release it before the actual blocking provider call.
            let size = {
                let mut progress = probe.result.lock().expect("v4 probe result");
                if progress.outcome != ProbeOutcome::Pending {
                    return Ok(());
                }
                let epoch = self.current_epoch();
                let future = self.engine.candidate.as_ref().is_some_and(|c| c.sent);
                let key = self.engine.slot_for(future, 0, self.engine.role)?;
                let before = self.engine.keys_for(future)?[key].next;
                let sealed = self.engine.seal(0, 14, &body, &mut out, false, false);
                if self.engine.keys_for(future)?[key].next != before {
                    progress.submitted = true;
                    self.engine.streams.controls.probes[index]
                        .as_mut()
                        .ok_or(CryptoError::State)?
                        .epoch = Some(epoch);
                }
                sealed?
            };
            publisher.publish(&out[..size])?;
            let now = self.engine.account.security_time()?;
            {
                let mut result = probe.result.lock().expect("v4 probe result");
                if result.outcome == ProbeOutcome::Pending {
                    result.complete = true;
                }
            }
            probe.observe(Some(now));
            if probe.automatic {
                let submission_ms = self
                    .engine
                    .streams
                    .controls
                    .automatic
                    .unwrap()
                    .submission_ms;
                let slot = self.engine.streams.controls.probes[index]
                    .as_mut()
                    .ok_or(CryptoError::State)?;
                slot.handoff = Some(now);
                slot.stall_generation = stall_generation;
                slot.eligible = probe.raw().outcome == ProbeOutcome::Pending
                    && !publisher.liveness_stalled()
                    && publisher.liveness_stall_generation() == stall_generation
                    && now.clock_incarnation == probe.started.clock_incarnation
                    && now
                        .monotonic_sample
                        .checked_duration_since(probe.started.monotonic_sample)
                        .and_then(|delta| probe.profile.elapsed(delta).ok())
                        .is_some_and(|(_, upper)| upper <= submission_ms);
            }
            self.check()?;
            self.engine.streams.controls.activity(now)
        })();
        out.as_mut_slice().zeroize();
        self.engine.streams.output = out;
        result?;
        Ok(true)
    }
    pub(super) fn poll_slow_consumers(&mut self) -> Result<()> {
        let now = self.engine.account.security_time()?.monotonic_sample;
        let role = usize::from(self.engine.role);
        for i in 0..self.engine.streams.slots.len() {
            let slot = &mut self.engine.streams.slots[i];
            if slot
                .receive_progress
                .is_some_and(|p| now.saturating_duration_since(p) >= CONSUMER_BUDGET)
            {
                let d = &mut slot.directions[1 - role];
                d.stop = true;
                d.fin = false;
                if !d.complete() {
                    d.begin(now, false)?;
                }
                slot.view.end.store(2, Ordering::Release);
                self.engine.streams.release_queue(i);
            }
            let slot = &mut self.engine.streams.slots[i];
            if slot
                .send_progress
                .is_some_and(|p| now.saturating_duration_since(p) >= CONSUMER_BUDGET)
            {
                slot.send_progress = None;
                let d = &mut slot.directions[role];
                d.stop = true;
                if d.terminal.is_none() {
                    d.terminal = Some(d.current);
                }
                d.begin(now, false)?;
            }
        }
        Ok(())
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
    fn deliver(writer: &mut Writer, peer: &mut ReliableSession) {
        while let Some(wire) = writer.0.pop_front() {
            peer.receive(u64::from_be_bytes(wire[12..20].try_into().unwrap()), &wire)
                .unwrap();
        }
    }
    fn stream(
        client: &mut ReliableSession,
        server: &mut ReliableSession,
        window: u64,
    ) -> (StreamHandle, StreamHandle) {
        let mut c = Writer::default();
        let mut s = Writer::default();
        let ch = client
            .open_stream("example.control", b"", window, &mut c)
            .unwrap();
        deliver(&mut c, server);
        let sh = server.pending_open().unwrap().unwrap();
        server
            .decide_open(
                &sh,
                OpenDecision::Accept {
                    receive_window: window,
                },
                &mut s,
            )
            .unwrap();
        deliver(&mut s, client);
        (ch, sh)
    }
    fn pump(client: &mut ReliableSession, server: &mut ReliableSession) {
        let mut c = Writer::default();
        let mut s = Writer::default();
        for _ in 0..40 {
            let a = client.poll(&mut c).unwrap();
            deliver(&mut c, server);
            let b = server.poll(&mut s).unwrap();
            deliver(&mut s, client);
            if !a && !b {
                return;
            }
        }
        panic!("control scheduler did not quiesce");
    }
    #[test]
    fn independent_probes_use_original_publication_counter_and_matching_epoch() {
        for profile in [Profile::X25519, Profile::P256] {
            let (_fixture, c, s) = record_pair_for_limits(profile);
            let mut c = c.into_session().unwrap();
            let mut s = s.into_session().unwrap();
            let one = c.start_probe(PROBE_BUDGET).unwrap();
            let two = c.start_probe(PROBE_BUDGET).unwrap();
            assert_eq!(one.nonce, 1u128.to_be_bytes());
            assert_eq!(two.nonce, 2u128.to_be_bytes());
            assert!(!one.snapshot().submitted);
            let mut output = Writer::default();
            c.poll(&mut output).unwrap();
            assert!(one.snapshot().submitted);
            assert!(!two.snapshot().submitted);
            deliver(&mut output, &mut s);
            pump(&mut c, &mut s);
            for p in [&one, &two] {
                assert_eq!(p.snapshot().outcome, ProbeOutcome::Responsive);
                assert!(p.snapshot().submitted && p.snapshot().elapsed.is_some());
                c.release_probe(p);
            }
            c.rekey(&mut output).unwrap();
            deliver(&mut output, &mut s);
            pump(&mut c, &mut s);
            let three = c.start_probe(PROBE_BUDGET).unwrap();
            assert_eq!(three.nonce, 3u128.to_be_bytes());
            pump(&mut c, &mut s);
            assert_eq!(three.snapshot().outcome, ProbeOutcome::Responsive);
            assert_eq!(
                c.engine.streams.controls.probes[0].as_ref().unwrap().epoch,
                Some(1)
            );
        }
    }
    #[test]
    fn cancel_timeout_capacity_and_late_pong_never_reuse_or_close() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        let mut owners = Vec::new();
        for _ in 0..PROBES {
            owners.push(c.start_probe(PROBE_BUDGET).unwrap());
        }
        assert!(matches!(
            c.start_probe(PROBE_BUDGET),
            Err(CryptoError::Capacity)
        ));
        let mut output = Writer::default();
        c.poll(&mut output).unwrap();
        deliver(&mut output, &mut s);
        c.release_probe(&owners[0]);
        assert_eq!(owners[0].snapshot().outcome, ProbeOutcome::Canceled);
        assert!(owners[0].snapshot().submitted);
        for owner in &owners[1..] {
            c.release_probe(owner);
            assert!(!owner.snapshot().submitted);
        }
        let expired = c.start_probe(Duration::ZERO).unwrap();
        c.poll(&mut output).unwrap();
        assert_eq!(expired.snapshot().outcome, ProbeOutcome::DeadlineExceeded);
        assert!(!expired.snapshot().submitted);
        c.release_probe(&expired);
        let next = c.start_probe(PROBE_BUDGET).unwrap();
        assert_eq!(next.nonce, 10u128.to_be_bytes());
        s.poll(&mut output).unwrap();
        deliver(&mut output, &mut c);
        assert_eq!(next.snapshot().outcome, ProbeOutcome::Pending);
        pump(&mut c, &mut s);
        assert_eq!(next.snapshot().outcome, ProbeOutcome::Responsive);
        assert!(!c.engine.closed);
    }
    #[test]
    fn rekey_interrupts_probes_but_pong_keeps_original_maintenance_gate() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::P256);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        let a = c.start_probe(PROBE_BUDGET).unwrap();
        let b = c.start_probe(PROBE_BUDGET).unwrap();
        let mut output = Writer::default();
        c.poll(&mut output).unwrap();
        deliver(&mut output, &mut s);
        c.rekey(&mut output).unwrap();
        deliver(&mut output, &mut s);
        assert_eq!(a.snapshot().outcome, ProbeOutcome::RekeyInProgress);
        assert!(a.snapshot().submitted);
        assert!(!b.snapshot().submitted);
        assert!(s.engine.frozen);
        assert!(s.poll_session_control(&mut output).unwrap());
        assert_eq!(output.0.front().unwrap()[4], 15);
        assert_eq!(&output.0.front().unwrap()[8..12], &0u32.to_be_bytes());
        deliver(&mut output, &mut c);
        pump(&mut c, &mut s);
        assert_eq!(c.engine.epoch, 1);
        assert_eq!(a.snapshot().outcome, ProbeOutcome::RekeyInProgress);
    }
    #[test]
    fn submitted_probe_deadline_is_local_and_nonce_exhaustion_is_bounded() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        let probe = c.start_probe(PROBE_BUDGET).unwrap();
        let mut output = Writer::default();
        c.poll(&mut output).unwrap();
        deliver(&mut output, &mut s);
        // The owner has no other observer in this test; shorten its original
        // fixture deadline after real publication to exercise the expiry gate.
        let slot = c.engine.streams.controls.probes[0].as_mut().unwrap();
        drop(probe);
        Arc::get_mut(&mut slot.owner).unwrap().duration_ms = 0;
        let probe = slot.owner.clone();
        c.poll_lifecycle_deadlines().unwrap();
        assert_eq!(probe.snapshot().outcome, ProbeOutcome::DeadlineExceeded);
        assert!(probe.snapshot().submitted);
        pump(&mut c, &mut s);
        assert_eq!(probe.snapshot().outcome, ProbeOutcome::DeadlineExceeded);
        assert!(!c.engine.closed);
        c.release_probe(&probe);
        c.engine.streams.controls.counter = u128::MAX;
        assert!(matches!(
            c.start_probe(PROBE_BUDGET),
            Err(CryptoError::Capacity)
        ));
        assert!(!c.engine.closed);
    }
    #[test]
    fn goaway_keeps_highest_accepted_history_and_explicit_open_outcomes() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        let (ch, _) = stream(&mut c, &mut s, 0);
        c.reset(&ch).unwrap();
        pump(&mut c, &mut s);
        let mut output = Writer::default();
        let pending = c
            .open_stream("example.pending", b"", 0, &mut output)
            .unwrap();
        deliver(&mut output, &mut s);
        let drain = s.start_drain(DRAIN_BUDGET).unwrap();
        assert_eq!(
            s.engine.streams.controls.local_goaway.unwrap().ceiling,
            ch.scope()
        );
        assert!(Arc::ptr_eq(
            &drain,
            &s.start_drain(Duration::from_secs(1)).unwrap()
        ));
        assert!(s.poll_session_control(&mut output).unwrap());
        deliver(&mut output, &mut c);
        assert_eq!(c.phase(&pending).unwrap(), StreamPhase::Opening);
        assert!(
            c.open_stream("example.closed", b"", 0, &mut output)
                .is_err()
        );
        let rejected = s.pending_open().unwrap();
        assert!(rejected.is_none());
        s.poll(&mut output).unwrap();
        deliver(&mut output, &mut c);
        assert_eq!(c.phase(&pending).unwrap(), StreamPhase::Recent);
        let tuple = c.engine.streams.controls.peer_goaway.unwrap();
        let mut body = map(2, 32).unwrap();
        for (k, v) in [(0, tuple.ceiling), (1, tuple.reason)] {
            uint(&mut body, k);
            uint(&mut body, v);
        }
        s.send(0, 13, &body, false, &mut output).unwrap();
        deliver(&mut output, &mut c);
        body = map(2, 32).unwrap();
        for (k, v) in [(0, tuple.ceiling + 2), (1, tuple.reason)] {
            uint(&mut body, k);
            uint(&mut body, v);
        }
        s.send(0, 13, &body, false, &mut output).unwrap();
        assert!(c.receive(0, &output.0.pop_front().unwrap()).is_err());
    }
    #[test]
    fn drain_waits_for_real_terminal_proof_and_unread_bytes() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::P256);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        let (ch, sh) = stream(&mut c, &mut s, 16);
        let mut output = Writer::default();
        c.write(&ch, b"unread", true, &mut output).unwrap();
        deliver(&mut output, &mut s);
        s.write(&sh, b"", true, &mut output).unwrap();
        deliver(&mut output, &mut c);
        pump(&mut c, &mut s);
        let drain = s.start_drain(DRAIN_BUDGET).unwrap();
        s.poll_session_control(&mut output).unwrap();
        deliver(&mut output, &mut c);
        assert!(!s.communication_drained());
        assert!(!s.poll_session_control(&mut output).unwrap());
        let mut data = [0; 16];
        assert_eq!(s.read(&sh, &mut data).unwrap(), ReadState::Data(6));
        assert!(s.poll_session_control(&mut output).unwrap());
        assert_eq!(drain.snapshot().outcome, DrainOutcome::Drained);
        assert!(s.engine.closed);
        assert_eq!(output.0.back().unwrap()[4], 12);
    }
    #[test]
    fn drain_deadline_never_forges_drained_and_security_failure_is_distinct() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        stream(&mut c, &mut s, 0);
        let drain = c.start_drain(Duration::ZERO).unwrap();
        assert!(matches!(
            c.poll(&mut Writer::default()),
            Err(CryptoError::Deadline)
        ));
        assert_eq!(drain.snapshot().outcome, DrainOutcome::DeadlineAborted);
        assert!(c.engine.closed);
        let drain = s.start_drain(DRAIN_BUDGET).unwrap();
        s.engine.fail();
        assert_eq!(drain.snapshot().outcome, DrainOutcome::Failed);
    }
    #[test]
    fn slow_receive_preserves_reverse_direction_and_idle_zero_credit_stream() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        let (ch, sh) = stream(&mut c, &mut s, 16);
        let (_, idle) = stream(&mut c, &mut s, 0);
        let mut output = Writer::default();
        c.write(&ch, b"slow", false, &mut output).unwrap();
        deliver(&mut output, &mut s);
        let i = s.engine.streams.resolve(&sh).unwrap();
        s.engine.streams.slots[i].receive_progress = Some(Instant::now() - CONSUMER_BUDGET);
        s.poll_slow_consumers().unwrap();
        assert_eq!(s.read(&sh, &mut [0; 4]).unwrap(), ReadState::Aborted);
        assert!(s.engine.streams.slots[i].directions[0].stop);
        assert!(!s.engine.streams.slots[i].directions[1].stop);
        assert!(s.engine.streams.slots[i].queue.is_empty());
        let idle = s.engine.streams.resolve(&idle).unwrap();
        assert!(
            s.engine.streams.slots[idle]
                .directions
                .iter()
                .all(|d| !d.stop)
        );
        pump(&mut c, &mut s);
        s.write(&sh, b"reverse", false, &mut output).unwrap();
        deliver(&mut output, &mut c);
        assert_eq!(c.read(&ch, &mut [0; 16]).unwrap(), ReadState::Data(7));
    }
    #[test]
    fn slow_unread_fin_drops_only_application_storage_not_wire_proof() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        let (ch, sh) = stream(&mut c, &mut s, 16);
        let mut output = Writer::default();
        c.write(&ch, b"tail", true, &mut output).unwrap();
        deliver(&mut output, &mut s);
        pump(&mut c, &mut s);
        let i = s.engine.streams.resolve(&sh).unwrap();
        let proof = s.engine.streams.slots[i].directions[0].proof;
        assert!(proof.is_some());
        s.engine.streams.slots[i].receive_progress = Some(Instant::now() - CONSUMER_BUDGET);
        s.poll_slow_consumers().unwrap();
        assert_eq!(s.engine.streams.slots[i].directions[0].proof, proof);
        assert_eq!(s.read(&sh, &mut [0; 16]).unwrap(), ReadState::Aborted);
        assert!(!s.engine.closed);
    }
    #[test]
    fn idle_gate_is_disabled_at_zero_and_never_revives_overdue_session() {
        let (_fixture, c, s) = record_pair_for_limits(Profile::P256);
        let mut c = c.into_session().unwrap();
        let mut s = s.into_session().unwrap();
        let now = c.engine.account.security_time().unwrap();
        c.engine.streams.controls.idle_duration_ms = 0;
        c.engine.streams.controls.idle_anchor = None;
        c.engine.streams.controls.activity(now).unwrap();
        assert!(c.engine.streams.controls.idle_anchor.is_none());
        c.engine.streams.controls.idle_duration_ms = 1000;
        c.engine.streams.controls.activate(now).unwrap();
        let before = c.engine.streams.controls.idle_anchor.unwrap();
        let probe = c.start_probe(PROBE_BUDGET).unwrap();
        assert_eq!(
            c.engine
                .streams
                .controls
                .idle_anchor
                .unwrap()
                .monotonic_sample,
            before.monotonic_sample
        );
        pump(&mut c, &mut s);
        assert_eq!(probe.snapshot().outcome, ProbeOutcome::Responsive);
        assert!(
            c.engine
                .streams
                .controls
                .idle_anchor
                .unwrap()
                .monotonic_sample
                >= before.monotonic_sample
        );
        c.engine.streams.controls.idle_anchor = Some(TrustedTimeSample {
            monotonic_sample: now.monotonic_sample - Duration::from_secs(1),
            ..now
        });
        assert!(c.engine.streams.controls.activity(now).is_err());
        assert!(c.poll(&mut Writer::default()).is_err());
        assert!(c.engine.closed);
    }
}
