//! Actual current WSS, raw QUIC and WebTransport relay hosting. Physical directions are independent
//! of logical endpoint roles. Each original publication owns two HOP claims,
//! bounded opaque forwarding, cancellation and the actual provider join tails.
use super::relay_publication::{OriginalRelayPoolPublication, RelayParentRegistration};
use super::*;
use crate::api_v4::CleanupStatus;
use crate::pool_v4::relay::{OriginalRelayClaim, SQLiteRelayLedger};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Notify, mpsc};

#[derive(Debug)]
pub enum WssRelayLegOptions {
    Dialer(WssConnectOptions),
    Listener(ReverseTunnelProviderOptions),
}
#[derive(Debug)]
pub struct WssRelayHostOptions {
    pub client_leg: WssRelayLegOptions,
    pub server_leg: WssRelayLegOptions,
    pub maximum_pairs: usize,
    pub cancellation: CancellationToken,
}
#[derive(Debug)]
struct PhysicalLeg {
    options: WssConnectOptions,
    listener: Option<Arc<reverse::SharedRelayListener>>,
    _charge: EnvironmentCharge,
}
struct Slot {
    generation: u64,
    cancellation: CancellationToken,
    started: bool,
    prepared: [bool; 2],
    paired: bool,
    forwarded: bool,
    datagram_forwarded: bool,
    done: bool,
    retired: bool,
    result: Option<ConnectResult<()>>,
}
struct Gate {
    closed: bool,
    listener_roles: [usize; 2],
    generation: u64,
    slots: Vec<Option<Slot>>,
    cleanup_until: Option<Instant>,
}
struct Owner {
    root: Arc<EnvironmentRoot>,
    keys: IdentityKeys,
    ledger: Arc<SQLiteRelayLedger>,
    legs: [PhysicalLeg; 2],
    relay: [u8; 16],
    gate: Mutex<Gate>,
    changed: Arc<Notify>,
    cancellation: CancellationToken,
    delivery_active: AtomicBool,
    observers: AtomicUsize,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WssRelayHostOwner { <opaque> }")
    }
}
#[derive(Debug)]
pub struct WssRelayHost {
    owner: Arc<Owner>,
}
#[derive(Debug)]
pub struct WssRelayPublication {
    owner: Arc<Owner>,
    index: usize,
    generation: u64,
}
impl Owner {
    fn close(&self) {
        let mut gate = self.gate.lock().expect("relay close gate");
        gate.closed = true;
        gate.cleanup_until
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        for slot in gate.slots.iter().flatten() {
            slot.cancellation.cancel();
        }
        for leg in &self.legs {
            if let Some(listener) = &leg.listener {
                listener.close();
            }
        }
        self.changed.notify_waiters();
    }
    fn cleanup(&self) -> CleanupStatus {
        let gate = self.gate.lock().expect("relay cleanup gate");
        let pending = gate
            .slots
            .iter()
            .flatten()
            .filter(|slot| !slot.done)
            .count() as u64
            + self
                .legs
                .iter()
                .filter(|leg| {
                    leg.listener
                        .as_ref()
                        .is_some_and(|listener| !listener.cleanup_complete())
                })
                .count() as u64;
        CleanupStatus {
            complete: pending == 0,
            cleanup_incomplete: false,
            pending_callbacks: pending,
        }
    }
    fn check(&self, index: usize, generation: u64) -> ConnectResult<()> {
        if self.root.is_closed() || self.cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        let gate = self.gate.lock().expect("relay original publication guard");
        if gate.closed
            || gate
                .slots
                .get(index)
                .and_then(Option::as_ref)
                .is_none_or(|slot| {
                    slot.generation != generation || slot.cancellation.is_cancelled() || slot.done
                })
        {
            return Err(ConnectError::Canceled);
        }
        Ok(())
    }
}
/// Original pre-TxB backing. Listener ingress retains its independent physical
/// budgets; outgoing carriers remain the same sockets through Grant pairing.
pub(super) struct OriginalRelayPreparation {
    pub(super) accounts: [ResourceAccount; 2],
    policies: Vec<wss::Policy>,
    native_pair: Option<Arc<super::native_relay_pair::Pair>>,
    charges: Vec<ResourceCharge>,
    hop_charges: Vec<ResourceCharge>,
    outgoing: [Option<OriginalPreparedCarrier>; 2],
    deadline: Instant,
}
struct OriginalPreparedCarrier {
    provider: direct_carrier::Provider,
    incoming: mpsc::Receiver<Vec<u8>>,
    _guard: direct_carrier::Guard,
}
impl OriginalRelayPreparation {
    pub(super) fn check(&self) -> ConnectResult<()> {
        if Instant::now() >= self.deadline {
            return Err(ConnectError::Deadline);
        }
        for account in &self.accounts {
            account.check()?;
        }
        for carrier in self.outgoing.iter().flatten() {
            carrier.provider.check()?;
        }
        Ok(())
    }
    pub(super) fn close(&self) {
        for carrier in self.outgoing.iter().flatten() {
            carrier.provider.close();
        }
        if let Some(pair) = &self.native_pair {
            pair.close();
        }
    }
    pub(super) async fn wait_cleanup(&self) {
        self.close();
        for carrier in self.outgoing.iter().flatten() {
            wait_provider(&carrier.provider).await;
        }
        if let Some(pair) = &self.native_pair {
            pair.wait_cleanup().await;
        }
    }
}
impl Drop for OriginalRelayPreparation {
    fn drop(&mut self) {
        self.close();
    }
}
impl WssRelayHost {
    pub(crate) fn new(
        root: Arc<EnvironmentRoot>,
        keys: IdentityKeys,
        ledger: Arc<SQLiteRelayLedger>,
        options: WssRelayHostOptions,
    ) -> ConnectResult<Self> {
        Self::new_with_socket(root, keys, ledger, options, None)
    }
    pub(crate) fn new_with_listener(
        root: Arc<EnvironmentRoot>,
        keys: IdentityKeys,
        ledger: Arc<SQLiteRelayLedger>,
        options: WssRelayHostOptions,
        listener: std::net::TcpListener,
    ) -> ConnectResult<Self> {
        Self::new_with_socket(
            root,
            keys,
            ledger,
            options,
            Some(reverse::PreboundSocket::Tcp(listener)),
        )
    }
    pub(crate) fn new_with_udp_socket(
        root: Arc<EnvironmentRoot>,
        keys: IdentityKeys,
        ledger: Arc<SQLiteRelayLedger>,
        options: WssRelayHostOptions,
        socket: std::net::UdpSocket,
    ) -> ConnectResult<Self> {
        Self::new_with_socket(
            root,
            keys,
            ledger,
            options,
            Some(reverse::PreboundSocket::Udp(socket)),
        )
    }
    fn new_with_socket(
        root: Arc<EnvironmentRoot>,
        keys: IdentityKeys,
        ledger: Arc<SQLiteRelayLedger>,
        options: WssRelayHostOptions,
        prebound_listener: Option<reverse::PreboundSocket>,
    ) -> ConnectResult<Self> {
        if !keys.belongs_to(&root)
            || !ledger.belongs_to(&root)
            || options.cancellation.is_cancelled()
            || !(1..=64).contains(&options.maximum_pairs)
            || !tokio::runtime::Handle::try_current().is_ok_and(|handle| {
                handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            })
        {
            return Err(ConnectError::Configuration);
        }
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: 32768 + options.maximum_pairs as u64 * 2048,
            items: options.maximum_pairs as u64 + 17,
            work_slots: options.maximum_pairs as u64 * 2 + 16,
            tasks: options.maximum_pairs as u64 * 2,
            timers: options.maximum_pairs as u64 + 16,
            ..ResourceLimits::default()
        })?;
        let maximum_pairs = options.maximum_pairs;
        let mut prebound_listener = prebound_listener;
        let mut capture = |leg| -> ConnectResult<PhysicalLeg> {
            let (options, listener) = match leg {
                WssRelayLegOptions::Dialer(options) => (options, None),
                WssRelayLegOptions::Listener(options) => {
                    let (listener, options) = reverse::Capture::new_with_socket(
                        root.clone(),
                        options,
                        prebound_listener.take(),
                    )?;
                    let listener = reverse::SharedRelayListener::new(
                        listener,
                        options.clone(),
                        maximum_pairs,
                        false,
                    )?;
                    (options, Some(listener))
                }
            };
            if options.binding_mode != BindingMode::AuthenticatedContext
                || options.timeout.is_zero()
                || options.timeout > Duration::from_secs(30)
                || options.publication_timeout.is_zero()
                || options.publication_timeout > Duration::from_secs(5)
                || !(1..=64).contains(&options.queue_messages)
                || !(16384..=262144).contains(&options.prepare_bytes)
            {
                return Err(ConnectError::Configuration);
            }
            let bytes = options
                .ca_certificates_der
                .iter()
                .try_fold(0u64, |bytes, certificate| {
                    if certificate.is_empty() || certificate.capacity() > 65536 {
                        return None;
                    }
                    bytes.checked_add(certificate.capacity() as u64)
                })
                .ok_or(ConnectError::Configuration)?;
            if options.ca_certificates_der.capacity() > 16 {
                return Err(ConnectError::Configuration);
            }
            let charge = root.reserve_environment(ResourceLimits {
                sdk_bytes: bytes + 8192,
                items: 17,
                work_slots: 1,
                ..ResourceLimits::default()
            })?;
            Ok(PhysicalLeg {
                options,
                listener,
                _charge: charge,
            })
        };
        let legs = [capture(options.client_leg)?, capture(options.server_leg)?];
        if prebound_listener.is_some() {
            return Err(ConnectError::Configuration);
        }
        let changed = Arc::new(Notify::new());
        for leg in &legs {
            if let Some(listener) = &leg.listener {
                listener.observe_cleanup(changed.clone())?;
            }
        }
        let mut relay = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut relay)
            .map_err(|_| ConnectError::Authorization)?;
        if relay == [0; 16] {
            return Err(ConnectError::Authorization);
        }
        Ok(Self {
            owner: Arc::new(Owner {
                root,
                keys,
                ledger,
                legs,
                relay,
                gate: Mutex::new(Gate {
                    closed: false,
                    listener_roles: [0, 1],
                    generation: 0,
                    slots: (0..options.maximum_pairs).map(|_| None).collect(),
                    cleanup_until: None,
                }),
                changed,
                cancellation: options.cancellation,
                delivery_active: AtomicBool::new(false),
                observers: AtomicUsize::new(0),
                _charge: charge,
            }),
        })
    }
    pub fn close(&self) {
        self.owner.close();
    }
    pub(super) fn original_delivery_root(&self) -> Arc<EnvironmentRoot> {
        self.owner.root.clone()
    }
    pub(super) fn original_delivery_ledger(&self) -> Arc<SQLiteRelayLedger> {
        self.owner.ledger.clone()
    }
    pub(super) fn claim_original_delivery(&self) -> ConnectResult<()> {
        self.owner
            .delivery_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ConnectError::Configuration)?;
        Ok(())
    }
    pub(super) fn release_original_delivery(&self) {
        self.owner.delivery_active.store(false, Ordering::Release);
    }
    pub(super) fn original_delivery_closed(&self) -> bool {
        self.owner.cancellation.is_cancelled()
            || self
                .owner
                .gate
                .lock()
                .expect("original relay delivery lifecycle")
                .closed
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.owner.cleanup()
    }
    pub async fn wait_cleanup(&self) -> ConnectResult<CleanupStatus> {
        self.owner
            .observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = Observer(self.owner.clone());
        let until = *self
            .owner
            .gate
            .lock()
            .expect("relay fixed cleanup deadline")
            .cleanup_until
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(until) => {
                let mut status = self.cleanup_status(); status.cleanup_incomplete = !status.complete; return Ok(status);
            }}
        }
    }
    pub async fn wait_listener_ready(
        &self,
        role: u8,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<std::net::SocketAddr> {
        if role > 1 || timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(ConnectError::Configuration);
        }
        let until = Instant::now()
            .checked_add(timeout)
            .ok_or(ConnectError::Configuration)?;
        self.owner
            .observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = Observer(self.owner.clone());
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if cancellation.is_cancelled() {
                return Err(ConnectError::Canceled);
            }
            if Instant::now() >= until {
                return Err(ConnectError::Deadline);
            }
            let listener = {
                let gate = self
                    .owner
                    .gate
                    .lock()
                    .expect("original relay listener observation");
                if gate.closed
                    || self.owner.root.is_closed()
                    || self.owner.cancellation.is_cancelled()
                {
                    return Err(ConnectError::Canceled);
                }
                let listener = self.owner.legs[gate.listener_roles[role as usize]]
                    .listener
                    .as_ref()
                    .ok_or(ConnectError::Configuration)?;
                if listener.physical_binding_ready()? {
                    return Ok(listener.local_address());
                }
                listener.clone()
            };
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
            ready = listener.wait_ready(until.saturating_duration_since(Instant::now()), cancellation) => { ready?; },
            _ = tokio::time::sleep_until(until) => return Err(ConnectError::Deadline) }
        }
    }
    /// Bind one independently installed relay ingress before live TxB. This
    /// installs no Grant, account, parent registration or HOP claim. The exact
    /// original live publication must later match this frozen physical policy.
    /// Observe the bind with `wait_listener_ready` before reporting readiness.
    pub fn prepare_live_listener(
        &self,
        role: u8,
        carrier: crate::LiveAuthorityCarrier,
        host: String,
    ) -> ConnectResult<()> {
        let mut gate = self
            .owner
            .gate
            .lock()
            .expect("installed live relay preparation");
        if gate.closed || self.owner.root.is_closed() || self.owner.cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        let listener = self
            .owner
            .legs
            .get(role as usize)
            .and_then(|leg| leg.listener.as_ref())
            .ok_or(ConnectError::Configuration)?;
        let carrier = match carrier {
            crate::LiveAuthorityCarrier::RawQuic => 0,
            crate::LiveAuthorityCarrier::WebSocket => 1,
            crate::LiveAuthorityCarrier::WebTransport => 2,
        };
        let other_role = 1usize - role as usize;
        if let Some(other) = self.owner.legs[other_role].listener.as_ref()
            && other.same_installation(listener)
            && other.installed_as(carrier, &host)
        {
            gate.listener_roles[role as usize] = other_role;
            self.owner.changed.notify_waiters();
            return Ok(());
        }
        listener.start_installed(carrier, host)
    }
    pub(super) fn live_leg_is_listener(&self, role: usize) -> ConnectResult<bool> {
        self.owner
            .legs
            .get(role)
            .map(|leg| leg.listener.is_some())
            .ok_or(ConnectError::Configuration)
    }
    pub(super) fn check_live_listener_preparation(&self) -> ConnectResult<()> {
        let gate = self
            .owner
            .gate
            .lock()
            .expect("original live relay listener observation");
        if gate.closed || self.owner.root.is_closed() || self.owner.cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        for role in 0..2 {
            if self.owner.legs[role].listener.is_some() {
                let listener = self.owner.legs[gate.listener_roles[role]]
                    .listener
                    .as_ref()
                    .ok_or(ConnectError::Configuration)?;
                if !listener.physical_binding_ready()? {
                    return Err(ConnectError::Carrier);
                }
            }
        }
        Ok(())
    }
    pub(super) async fn prepare_original_live(
        &self,
        accounts: [ResourceAccount; 2],
        candidate: &[u8],
        artifact: [u8; 32],
        limits: crate::namespace_v4::verifier::credential::tunnel::TunnelLimits,
        cancellation: CancellationToken,
    ) -> ConnectResult<OriginalRelayPreparation> {
        let deadline = Instant::now()
            .checked_add(
                self.owner.legs[0]
                    .options
                    .timeout
                    .min(self.owner.legs[1].options.timeout),
            )
            .ok_or(ConnectError::Configuration)?;
        let mut preparation = OriginalRelayPreparation {
            accounts,
            policies: Vec::with_capacity(2),
            native_pair: None,
            charges: Vec::with_capacity(2),
            hop_charges: Vec::with_capacity(2),
            outgoing: [None, None],
            deadline,
        };
        for role in 0..2 {
            let physical = &self.owner.legs[role];
            let account = &preparation.accounts[role];
            account.check()?;
            if !account.belongs_to(&self.owner.root) {
                return Err(ConnectError::Configuration);
            }
            let queue = physical.options.queue_messages as u64;
            if queue > limits.max_queue_items
                || queue
                    .checked_mul(limits.max_envelope_bytes)
                    .is_none_or(|bytes| bytes > limits.max_queue_bytes)
            {
                return Err(ConnectError::Capacity);
            }
            preparation
                .policies
                .push(wss::Policy::new_live_relay_preparation(
                    candidate,
                    role as u8,
                    limits,
                    artifact,
                    account,
                    &physical.options,
                    physical.listener.is_some(),
                )?);
            preparation
                .hop_charges
                .push(account.reserve(ResourceLimits {
                    sdk_bytes: 57344,
                    items: 6,
                    work_slots: 3,
                    ..ResourceLimits::default()
                })?);
            preparation.charges.push(
                account.reserve(ResourceLimits {
                    sdk_bytes: limits
                        .max_envelope_bytes
                        .checked_mul(queue + 2)
                        .and_then(|bytes| bytes.checked_add(8192))
                        .ok_or(ConnectError::Capacity)?,
                    items: queue + 4,
                    work_slots: 2,
                    tasks: 2,
                    timers: 2,
                    ..ResourceLimits::default()
                })?,
            );
        }
        preparation.native_pair = super::native_relay_pair::Pair::new(
            &preparation.accounts,
            [limits; 2],
            &preparation.policies,
            self.owner.legs[0]
                .options
                .publication_timeout
                .min(self.owner.legs[1].options.publication_timeout),
            [
                self.owner.legs[0].options.queue_messages,
                self.owner.legs[1].options.queue_messages,
            ],
        )?;
        // Reserve all provider and forwarding positions before the first dial.
        for role in 0..2 {
            let physical = &self.owner.legs[role];
            let policy = &mut preparation.policies[role];
            if let Some(pair) = &preparation.native_pair {
                policy.max_streams = pair.mapping_capacity().div_ceil(2);
                policy.max_credit = pair.queue_bytes();
            }
            let vector = if let Some(listener) = &physical.listener {
                listener.preparation_limits(policy, &preparation.accounts[role])?
            } else {
                policy.preparation_limits(&physical.options)?
            };
            policy.fund_relay(&preparation.accounts[role], vector)?;
            if physical.listener.is_some() {
                let carrier = match policy.carrier {
                    0 => crate::LiveAuthorityCarrier::RawQuic,
                    1 => crate::LiveAuthorityCarrier::WebSocket,
                    2 => crate::LiveAuthorityCarrier::WebTransport,
                    _ => return Err(ConnectError::Configuration),
                };
                self.prepare_live_listener(role as u8, carrier, policy.host.clone())?;
            }
        }
        let preparation_ref = &preparation;
        let cancellation_ref = &cancellation;
        let prepare = |role: usize| async move {
            let preparation = preparation_ref;
            let cancellation = cancellation_ref;
            if self.owner.legs[role].listener.is_some() {
                let physical_role = self
                    .owner
                    .gate
                    .lock()
                    .expect("original live preparation mapping")
                    .listener_roles[role];
                let listener = self.owner.legs[physical_role]
                    .listener
                    .as_ref()
                    .ok_or(ConnectError::Configuration)?;
                listener
                    .wait_ready(self.owner.legs[role].options.timeout, cancellation)
                    .await?;
                return Ok(None);
            }
            let (provider, incoming) = direct_carrier::Provider::prepare(
                preparation.accounts[role].clone(),
                preparation.policies[role].clone(),
                self.owner.legs[role].options.clone(),
                deadline,
                cancellation.clone(),
            )
            .await?;
            let guard = direct_carrier::Guard(Some(provider.clone()));
            let result = provider.complete_preparation().and_then(|()| {
                provider.bind_relay_limits(
                    preparation.policies[role]
                        .max_streams
                        .checked_mul(2)
                        .ok_or(ConnectError::Capacity)?,
                    0,
                    preparation.policies[role].live_maximum,
                )
            });
            if let Err(failure) = result {
                provider.close();
                wait_provider(&provider).await;
                return Err(failure);
            }
            Ok(Some(OriginalPreparedCarrier {
                provider,
                incoming,
                _guard: guard,
            }))
        };
        let (left, right) = tokio::join!(prepare(0), prepare(1));
        match (left, right) {
            (Ok(left), Ok(right)) => preparation.outgoing = [left, right],
            (left, right) => {
                let failure = left
                    .as_ref()
                    .err()
                    .copied()
                    .or_else(|| right.as_ref().err().copied())
                    .unwrap_or(ConnectError::Carrier);
                preparation.outgoing = [left.ok().flatten(), right.ok().flatten()];
                preparation.wait_cleanup().await;
                return Err(failure);
            }
        }
        let final_check = preparation
            .accounts
            .iter()
            .try_for_each(|account| account.check().map_err(ConnectError::from));
        if let Err(failure) = final_check {
            preparation.wait_cleanup().await;
            return Err(failure);
        }
        if cancellation.is_cancelled() {
            preparation.wait_cleanup().await;
            return Err(ConnectError::Canceled);
        }
        Ok(preparation)
    }
    #[expect(
        clippy::result_large_err,
        reason = "Failure returns the original preparation owner for physical cleanup without allocating on the failure path."
    )]
    pub(super) fn publish_prepared_live(
        &self,
        publication: OriginalRelayPoolPublication,
        preparation: OriginalRelayPreparation,
    ) -> std::result::Result<WssRelayPublication, (ConnectError, OriginalRelayPreparation)> {
        if publication.source != codec::ActivationSource::LiveAuthority
            || (0..2).any(|role| {
                !publication.facts.accounts[role].same_owner(&preparation.accounts[role])
            })
        {
            return Err((ConnectError::Configuration, preparation));
        }
        let input = PublicationInput::PreparedLive {
            publication,
            preparation,
        };
        match self.reserve_publication(&input, false) {
            Ok((index, generation, cancellation)) => {
                Ok(self.launch_publication(input, index, generation, cancellation))
            }
            Err(failure) => {
                let PublicationInput::PreparedLive { preparation, .. } = input else {
                    unreachable!()
                };
                Err((failure, preparation))
            }
        }
    }
    /// The non-cloneable publication is captured by the original issuer before
    /// this entry point. A failure cannot replace it with another parent after
    /// either original HOP claim was submitted or bytes were forwarded.
    pub fn publish_pool(
        &self,
        publication: OriginalRelayPoolPublication,
    ) -> ConnectResult<WssRelayPublication> {
        if publication.source != codec::ActivationSource::PreauthorizedPool {
            return Err(ConnectError::Configuration);
        }
        self.publish_original(PublicationInput::Pool(publication), true)
    }
    /// Consume only the retained original live TxB publication. Pool material
    /// cannot enter this path, and failed publication cannot be reopened.
    pub fn publish_live(
        &self,
        publication: OriginalRelayPoolPublication,
    ) -> ConnectResult<WssRelayPublication> {
        if publication.source != codec::ActivationSource::LiveAuthority {
            return Err(ConnectError::Configuration);
        }
        self.publish_original(PublicationInput::Pool(publication), true)
    }
    /// Consume the original registered continuation. Public rows and tokens
    /// cannot construct this handle, and failed publication cannot be retried.
    pub fn publish_registered(
        &self,
        registration: RelayParentRegistration,
    ) -> ConnectResult<WssRelayPublication> {
        registration.original.check()?;
        if !registration.original.belongs_to_ledger(&self.owner.ledger) {
            return Err(ConnectError::Configuration);
        }
        self.publish_original(PublicationInput::Registered(registration), true)
    }
    /// Capture one original publication and prepare its physical listeners.
    /// Outgoing native legs and all HOP claims remain suspended until the same
    /// process-local publication handle starts its original forwarding task.
    pub fn prepare_pool(
        &self,
        publication: OriginalRelayPoolPublication,
    ) -> ConnectResult<WssRelayPublication> {
        if publication.source != codec::ActivationSource::PreauthorizedPool {
            return Err(ConnectError::Configuration);
        }
        self.publish_original(PublicationInput::Pool(publication), false)
    }
    /// Retain the exact live publication behind its original start barrier.
    /// Native listener preparation may precede TxB through the installed
    /// ingress entry point; HOP authentication still requires this publication.
    pub fn prepare_live(
        &self,
        publication: OriginalRelayPoolPublication,
    ) -> ConnectResult<WssRelayPublication> {
        if publication.source != codec::ActivationSource::LiveAuthority {
            return Err(ConnectError::Configuration);
        }
        self.publish_original(PublicationInput::Pool(publication), false)
    }
    pub fn prepare_registered(
        &self,
        registration: RelayParentRegistration,
    ) -> ConnectResult<WssRelayPublication> {
        registration.original.check()?;
        if !registration.original.belongs_to_ledger(&self.owner.ledger) {
            return Err(ConnectError::Configuration);
        }
        self.publish_original(PublicationInput::Registered(registration), false)
    }
    fn publish_original(
        &self,
        publication: PublicationInput,
        started: bool,
    ) -> ConnectResult<WssRelayPublication> {
        let (index, generation, cancellation) = self.reserve_publication(&publication, started)?;
        Ok(self.launch_publication(publication, index, generation, cancellation))
    }
    fn reserve_publication(
        &self,
        publication: &PublicationInput,
        started: bool,
    ) -> ConnectResult<(usize, u64, CancellationToken)> {
        if !tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        }) {
            return Err(ConnectError::Configuration);
        }
        let (index, generation, cancellation) = {
            let mut gate = self.owner.gate.lock().expect("relay publication slot");
            if gate.closed || self.owner.root.is_closed() || self.owner.cancellation.is_cancelled()
            {
                return Err(ConnectError::Canceled);
            }
            let index = gate
                .slots
                .iter()
                .position(|slot| slot.is_none())
                .ok_or(ConnectError::Capacity)?;
            let generation = gate
                .generation
                .checked_add(1)
                .ok_or(ConnectError::Capacity)?;
            gate.generation = generation;
            let cancellation = match &publication {
                PublicationInput::Pool(_) | PublicationInput::PreparedLive { .. } => {
                    CancellationToken::new()
                }
                PublicationInput::Registered(registration) => registration.cancellation.clone(),
            };
            gate.slots[index] = Some(Slot {
                generation,
                cancellation: cancellation.clone(),
                started,
                prepared: [false; 2],
                paired: false,
                forwarded: false,
                datagram_forwarded: false,
                done: false,
                retired: false,
                result: None,
            });
            (index, generation, cancellation)
        };
        Ok((index, generation, cancellation))
    }
    fn launch_publication(
        &self,
        publication: PublicationInput,
        index: usize,
        generation: u64,
        cancellation: CancellationToken,
    ) -> WssRelayPublication {
        let owner = self.owner.clone();
        tokio::spawn(async move {
            let original =
                run_original(&owner, index, generation, publication, cancellation.clone());
            tokio::pin!(original);
            let result = loop {
                tokio::select! {
                    result = &mut original => break result,
                    _ = owner.cancellation.cancelled() => { cancellation.cancel(); break original.await; },
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {
                        if owner.root.is_closed() { cancellation.cancel(); break original.await; }
                    },
                }
            };
            let mut gate = owner.gate.lock().expect("relay original task exit");
            if let Some(slot) = gate.slots[index]
                .as_mut()
                .filter(|slot| slot.generation == generation)
            {
                slot.result = Some(result);
                slot.done = true;
                if slot.retired {
                    gate.slots[index] = None;
                }
            }
            owner.changed.notify_waiters();
        });
        WssRelayPublication {
            owner: self.owner.clone(),
            index,
            generation,
        }
    }
}
impl Drop for WssRelayHost {
    fn drop(&mut self) {
        self.close();
    }
}
struct Observer(Arc<Owner>);
impl Drop for Observer {
    fn drop(&mut self) {
        self.0.observers.fetch_sub(1, Ordering::AcqRel);
    }
}
impl WssRelayPublication {
    /// Observations of the original HOP pair and physical forwarding task.
    /// These values never grant claim, retry, admission or publication rights.
    pub fn forwarding_progress(&self) -> ConnectResult<(bool, bool, bool)> {
        let gate = self
            .owner
            .gate
            .lock()
            .expect("original relay forwarding observation");
        let slot = gate.slots[self.index]
            .as_ref()
            .filter(|slot| slot.generation == self.generation)
            .ok_or(ConnectError::Canceled)?;
        Ok((slot.paired, slot.forwarded, slot.datagram_forwarded))
    }
    /// Release the original preparation barrier once. This handle cannot be
    /// reconstructed from Grants, durable rows or a driver acknowledgement.
    pub fn start(&self) -> ConnectResult<()> {
        self.owner.check(self.index, self.generation)?;
        let mut gate = self
            .owner
            .gate
            .lock()
            .expect("original relay start barrier");
        if gate.closed || self.owner.root.is_closed() || self.owner.cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        let slot = gate.slots[self.index]
            .as_mut()
            .filter(|slot| {
                slot.generation == self.generation
                    && !slot.done
                    && !slot.cancellation.is_cancelled()
            })
            .ok_or(ConnectError::Canceled)?;
        if slot.started {
            return Err(ConnectError::Configuration);
        }
        slot.started = true;
        self.owner.changed.notify_waiters();
        Ok(())
    }

    pub(super) async fn wait_original_preparation(
        &self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<()> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(ConnectError::Configuration);
        }
        let until = Instant::now()
            .checked_add(timeout)
            .ok_or(ConnectError::Configuration)?;
        self.owner
            .observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = Observer(self.owner.clone());
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if cancellation.is_cancelled() {
                return Err(ConnectError::Canceled);
            }
            if Instant::now() >= until {
                return Err(ConnectError::Deadline);
            }
            self.owner.check(self.index, self.generation)?;
            {
                let gate = self
                    .owner
                    .gate
                    .lock()
                    .expect("original relay provider preparation");
                let slot = gate.slots[self.index]
                    .as_ref()
                    .filter(|slot| slot.generation == self.generation)
                    .ok_or(ConnectError::Canceled)?;
                if let Some(result) = slot.result {
                    return result.and(Err(ConnectError::Carrier));
                }
                let mut ready = true;
                for role in 0..2 {
                    // Logical roles may share one independently installed
                    // physical listener, including reverse startup order.
                    // Observe the current mapping on every wakeup rather than
                    // waiting on an unused second listener forever.
                    let physical = &self.owner.legs[gate.listener_roles[role]];
                    ready &= if let Some(listener) = &physical.listener {
                        listener.physical_binding_ready()?
                    } else {
                        slot.prepared[role]
                    };
                }
                if ready {
                    return Ok(());
                }
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(until) => return Err(ConnectError::Deadline) }
        }
    }
    pub(super) fn original_result(&self) -> Option<ConnectResult<()>> {
        self.owner
            .gate
            .lock()
            .expect("original relay publication observation")
            .slots[self.index]
            .as_ref()
            .filter(|slot| slot.generation == self.generation)
            .and_then(|slot| slot.result)
    }
    pub fn close(&self) {
        let gate = self
            .owner
            .gate
            .lock()
            .expect("original relay publication close");
        if let Some(slot) = gate.slots[self.index]
            .as_ref()
            .filter(|slot| slot.generation == self.generation)
        {
            slot.cancellation.cancel();
        }
        self.owner.changed.notify_waiters();
    }
    pub(super) async fn wait_original_exit(&self) -> ConnectResult<()> {
        // The dedicated original-delivery registry already prepays and bounds
        // this internal watcher. It must not compete for external observers.
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(result) = self.original_result() {
                return result;
            }
            changed.await;
        }
    }
    pub async fn wait_completion(&self) -> ConnectResult<()> {
        self.owner
            .observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = Observer(self.owner.clone());
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let gate = self
                    .owner
                    .gate
                    .lock()
                    .expect("original relay publication result");
                let slot = gate.slots[self.index]
                    .as_ref()
                    .filter(|slot| slot.generation == self.generation)
                    .ok_or(ConnectError::Canceled)?;
                if let Some(result) = slot.result {
                    return result;
                }
            }
            changed.await;
        }
    }
}
impl Drop for WssRelayPublication {
    fn drop(&mut self) {
        self.close();
        let mut gate = self
            .owner
            .gate
            .lock()
            .expect("original relay publication retire");
        if let Some(slot) = gate.slots[self.index]
            .as_mut()
            .filter(|slot| slot.generation == self.generation)
        {
            slot.retired = true;
            if slot.done {
                gate.slots[self.index] = None;
            }
        }
    }
}
struct Prepared {
    provider: direct_carrier::Provider,
    incoming: mpsc::Receiver<Vec<u8>>,
    claim: OriginalRelayClaim,
    _guard: direct_carrier::Guard,
}

fn check_original_claim(
    claim: &OriginalRelayClaim,
    provider: &direct_carrier::Provider,
) -> ConnectResult<()> {
    claim.check().map_err(|failure| {
        // The claim is bound to this physical carrier's cancellation token.
        // A real socket exit revokes possession; preserve that carrier failure
        // instead of reporting it as an unavailable persistent ledger owner.
        if failure.code == crate::PoolStoreFailure::OwnerUnavailable
            && provider.cancellation().is_cancelled()
        {
            ConnectError::Carrier
        } else {
            failure.into()
        }
    })
}
async fn wait_original_start(
    owner: &Arc<Owner>,
    index: usize,
    generation: u64,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> ConnectResult<()> {
    loop {
        let changed = owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        owner.check(index, generation)?;
        {
            let gate = owner
                .gate
                .lock()
                .expect("original relay preparation barrier");
            if gate.slots[index]
                .as_ref()
                .filter(|slot| slot.generation == generation)
                .ok_or(ConnectError::Canceled)?
                .started
            {
                return Ok(());
            }
        }
        tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
        _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline) }
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Relay forwarding binds both original legs and their separate resource, deadline and cancellation owners."
)]
async fn prepare_leg(
    owner: &Arc<Owner>,
    index: usize,
    registration: &RelayParentRegistration,
    role: u8,
    generation: u64,
    deadline: Instant,
    policy: wss::Policy,
    cancellation: CancellationToken,
    hop_charge: ResourceCharge,
    original_prepared: Option<OriginalPreparedCarrier>,
) -> ConnectResult<Prepared> {
    let physical = &owner.legs[role as usize];
    let setup = (|| {
        let account = registration.original.account(role)?;
        let mappings = policy
            .max_streams
            .checked_mul(2)
            .ok_or(ConnectError::Capacity)?;
        Ok::<_, ConnectError>((account, mappings))
    })();
    let (account, mappings) = match setup {
        Ok(setup) => setup,
        Err(failure) => {
            if let Some(original) = &original_prepared {
                original.provider.close();
                wait_provider(&original.provider).await;
            }
            return Err(failure);
        }
    };
    let maximum = policy.live_maximum;
    let physical_role = owner
        .gate
        .lock()
        .expect("original prepared relay listener role")
        .listener_roles[role as usize];
    let mut shared_listener = owner.legs[physical_role].listener.as_ref();
    if role == 1
        && let (Some(a), Some(b)) = (&owner.legs[0].listener, &physical.listener)
    {
        let grant = decode(
            &registration.endpoints[0].grant,
            "Grant",
            9302,
            Context::default(),
        )?;
        let first_carrier = grant
            .field("Grant", "route_descriptor")?
            .field("Route", "client_leg")?
            .u("Leg", "carrier")? as u8;
        if a.same_address(b) && first_carrier == policy.carrier {
            if !a.same_installation(b) {
                return Err(ConnectError::Configuration);
            }
            let mut gate = owner
                .gate
                .lock()
                .expect("shared original relay listener role");
            let original_role = gate.listener_roles[0];
            shared_listener = owner.legs[original_role].listener.as_ref();
            gate.listener_roles[role as usize] = original_role;
            owner.changed.notify_waiters();
        }
    }
    let already_prepared = original_prepared.is_some();
    let (provider, mut incoming, first_hello, guard) = if let Some(original) = original_prepared {
        (original.provider, original.incoming, None, original._guard)
    } else if let Some(listener) = shared_listener {
        let accepted = listener
            .prepare(
                account,
                &registration.endpoints[role as usize].grant,
                policy,
                deadline,
                cancellation.clone(),
            )
            .await?;
        (
            accepted.provider,
            accepted.incoming,
            accepted.first_hello,
            accepted.guard,
        )
    } else {
        wait_original_start(owner, index, generation, deadline, &cancellation).await?;
        let (provider, incoming) = direct_carrier::Provider::prepare(
            account,
            policy,
            physical.options.clone(),
            deadline,
            cancellation.clone(),
        )
        .await?;
        let guard = direct_carrier::Guard(Some(provider.clone()));
        (provider, incoming, None, guard)
    };
    let prepared = async {
        provider.bind_relay_limits(mappings, 0, maximum)?;
        if !already_prepared && owner.legs[role as usize].listener.is_none() {
            provider.complete_preparation()?;
        }
        owner.check(index, generation)?;
        {
            let mut gate = owner
                .gate
                .lock()
                .expect("original relay native Prepare exit");
            let slot = gate.slots[index]
                .as_mut()
                .filter(|slot| slot.generation == generation)
                .ok_or(ConnectError::Canceled)?;
            slot.prepared[role as usize] = true;
        }
        owner.changed.notify_waiters();
        wait_original_start(owner, index, generation, deadline, &cancellation).await?;
        let mut hop = super::relay_hop::RelayHop::new(
            registration,
            role,
            &provider,
            &owner.keys,
            owner.relay,
            generation,
            hop_charge,
        )?;
        let claim = hop
            .authenticate(
                registration,
                role,
                &provider,
                &mut incoming,
                &owner.keys,
                deadline,
                &cancellation,
                first_hello,
            )
            .await?;
        Ok::<_, ConnectError>(claim)
    }
    .await;
    let claim = match prepared {
        Ok(prepared) => prepared,
        Err(failure) => {
            provider.close();
            wait_provider(&provider).await;
            return Err(failure);
        }
    };
    Ok(Prepared {
        provider,
        incoming,
        claim,
        _guard: guard,
    })
}
#[expect(
    clippy::large_enum_variant,
    reason = "Publication transfers original pool material and prepared cleanup ownership as one inline value."
)]
enum PublicationInput {
    Pool(OriginalRelayPoolPublication),
    Registered(RelayParentRegistration),
    PreparedLive {
        publication: OriginalRelayPoolPublication,
        preparation: OriginalRelayPreparation,
    },
}
impl PublicationInput {
    fn endpoints(&self) -> &[super::relay_publication::RelayEndpoint; 2] {
        match self {
            Self::Pool(publication) | Self::PreparedLive { publication, .. } => {
                &publication.endpoints
            }
            Self::Registered(registration) => &registration.endpoints,
        }
    }
    fn accounts(&self) -> &[ResourceAccount; 2] {
        match self {
            Self::Pool(publication) | Self::PreparedLive { publication, .. } => {
                &publication.facts.accounts
            }
            Self::Registered(registration) => registration.original.accounts(),
        }
    }
    fn register(
        self,
        ledger: Arc<SQLiteRelayLedger>,
        cancellation: CancellationToken,
    ) -> ConnectResult<RelayParentRegistration> {
        match self {
            Self::Pool(publication) => publication.register(ledger, cancellation),
            Self::PreparedLive { .. } => Err(ConnectError::Configuration),
            Self::Registered(registration) => {
                registration.original.check()?;
                Ok(registration)
            }
        }
    }
}
async fn run_original(
    owner: &Arc<Owner>,
    index: usize,
    generation: u64,
    publication: PublicationInput,
    cancellation: CancellationToken,
) -> ConnectResult<()> {
    let (publication, mut preparation) = match publication {
        PublicationInput::PreparedLive {
            publication,
            preparation,
        } => (PublicationInput::Pool(publication), Some(preparation)),
        publication => (publication, None),
    };
    let result = run_original_inner(
        owner,
        index,
        generation,
        publication,
        &mut preparation,
        cancellation,
    )
    .await;
    if let Some(preparation) = preparation {
        preparation.wait_cleanup().await;
    }
    result
}
async fn run_original_inner(
    owner: &Arc<Owner>,
    index: usize,
    generation: u64,
    publication: PublicationInput,
    preparation: &mut Option<OriginalRelayPreparation>,
    cancellation: CancellationToken,
) -> ConnectResult<()> {
    owner.check(index, generation)?;
    // Both forwarding budgets and resident queue bytes are prepaid before
    // either native Prepare or irreversible HOP claim can run.
    let mut charges = Vec::with_capacity(2);
    let mut policies = Vec::with_capacity(2);
    let mut hop_charges = Vec::with_capacity(2);
    if preparation.is_none() {
        for role in 0..2 {
            let limits = publication.endpoints()[role].hop.limits;
            let queue = owner.legs[role].options.queue_messages as u64;
            if queue > limits.max_queue_items
                || queue
                    .checked_mul(limits.max_envelope_bytes)
                    .is_none_or(|bytes| bytes > limits.max_queue_bytes)
            {
                return Err(ConnectError::Capacity);
            }
            let account = &publication.accounts()[role];
            if !account.belongs_to(&owner.root) {
                return Err(ConnectError::Configuration);
            }
            let physical = &owner.legs[role];
            let policy = wss::Policy::new_relay(
                &publication.endpoints()[role],
                account,
                &physical.options,
                physical.listener.is_some(),
            )?;
            policies.push(policy);
            hop_charges.push(account.reserve(ResourceLimits {
                sdk_bytes: 57344,
                items: 6,
                work_slots: 3,
                ..ResourceLimits::default()
            })?);
            charges.push(
                account.reserve(ResourceLimits {
                    sdk_bytes: limits
                        .max_envelope_bytes
                        .checked_mul(queue + 2)
                        .ok_or(ConnectError::Capacity)?
                        + 8192,
                    items: queue + 4,
                    work_slots: 2,
                    tasks: 2,
                    timers: 2,
                    ..ResourceLimits::default()
                })?,
            );
        }
    }
    let native_pair = if let Some(preparation) = preparation.as_mut() {
        charges = std::mem::take(&mut preparation.charges);
        policies = std::mem::take(&mut preparation.policies);
        hop_charges = std::mem::take(&mut preparation.hop_charges);
        preparation.native_pair.take()
    } else {
        super::native_relay_pair::Pair::new(
            publication.accounts(),
            [
                publication.endpoints()[0].hop.limits,
                publication.endpoints()[1].hop.limits,
            ],
            &policies,
            owner.legs[0]
                .options
                .publication_timeout
                .min(owner.legs[1].options.publication_timeout),
            [
                owner.legs[0].options.queue_messages,
                owner.legs[1].options.queue_messages,
            ],
        )?
    };
    if preparation.is_none() {
        for (role, policy) in policies.iter_mut().enumerate() {
            if let Some(pair) = &native_pair {
                policy.max_streams = pair.mapping_capacity().div_ceil(2);
                policy.max_credit = pair.queue_bytes();
            }
            let physical = &owner.legs[role];
            let prepayment = if let Some(listener) = &physical.listener {
                listener.preparation_limits(policy, &publication.accounts()[role])?
            } else {
                policy.preparation_limits(&physical.options)?
            };
            policy.fund_relay(&publication.accounts()[role], prepayment)?;
        }
    }
    let registration = publication.register(owner.ledger.clone(), cancellation.clone())?;
    let deadline = preparation
        .as_ref()
        .map(|preparation| preparation.deadline)
        .unwrap_or(
            Instant::now()
                .checked_add(
                    owner.legs[0]
                        .options
                        .timeout
                        .min(owner.legs[1].options.timeout),
                )
                .ok_or(ConnectError::Configuration)?,
        );
    let a_original = preparation
        .as_mut()
        .and_then(|preparation| preparation.outgoing[0].take());
    let b_original = preparation
        .as_mut()
        .and_then(|preparation| preparation.outgoing[1].take());
    // Joining these exact two futures retains a successful prepared leg while
    // the other exits, including any actual native cancellation/join tail.
    let mut policies = policies.into_iter();
    let a_policy = policies.next().ok_or(ConnectError::Configuration)?;
    let b_policy = policies.next().ok_or(ConnectError::Configuration)?;
    let mut hop_charges = hop_charges.into_iter();
    let a_hop = hop_charges.next().ok_or(ConnectError::Configuration)?;
    let b_hop = hop_charges.next().ok_or(ConnectError::Configuration)?;
    let both = tokio::join!(
        prepare_leg(
            owner,
            index,
            &registration,
            0,
            generation,
            deadline,
            a_policy,
            cancellation.clone(),
            a_hop,
            a_original
        ),
        prepare_leg(
            owner,
            index,
            &registration,
            1,
            generation,
            deadline,
            b_policy,
            cancellation.clone(),
            b_hop,
            b_original
        )
    );
    let (mut a, mut b) = match both {
        (Ok(a), Ok(b)) => (a, b),
        (left, right) => {
            let failure = left
                .as_ref()
                .err()
                .copied()
                .or_else(|| right.as_ref().err().copied())
                .unwrap_or(ConnectError::Carrier);
            if let Ok(leg) = left {
                leg.provider.close();
                wait_provider(&leg.provider).await;
            }
            if let Ok(leg) = right {
                leg.provider.close();
                wait_provider(&leg.provider).await;
            }
            if let Some(pair) = &native_pair {
                pair.wait_cleanup().await;
            }
            return Err(failure);
        }
    };
    {
        let mut gate = owner
            .gate
            .lock()
            .expect("original relay authenticated pairing");
        let slot = gate.slots[index]
            .as_mut()
            .filter(|slot| slot.generation == generation)
            .ok_or(ConnectError::Canceled)?;
        slot.paired = true;
    }
    owner.changed.notify_waiters();
    let result = forward(
        owner,
        index,
        generation,
        &registration,
        &mut a,
        &mut b,
        deadline,
        &cancellation,
        native_pair.as_ref(),
    )
    .await;
    if let Some(pair) = &native_pair {
        pair.close();
    }
    a.provider.close();
    b.provider.close();
    if let Some(pair) = &native_pair {
        pair.wait_cleanup().await;
        let mut gate = owner
            .gate
            .lock()
            .expect("original relay datagram forwarding observation");
        if let Some(slot) = gate.slots[index]
            .as_mut()
            .filter(|slot| slot.generation == generation)
        {
            slot.datagram_forwarded = pair.datagram_forwarded();
        }
    }
    tokio::join!(wait_provider(&a.provider), wait_provider(&b.provider));
    drop(a);
    drop(b);
    drop(charges);
    result
}
async fn wait_provider(provider: &direct_carrier::Provider) {
    while !provider.cleanup().complete {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Relay forwarding binds both original legs and their separate resource, deadline and cancellation owners."
)]
async fn forward(
    owner: &Arc<Owner>,
    index: usize,
    generation: u64,
    registration: &RelayParentRegistration,
    a: &mut Prepared,
    b: &mut Prepared,
    deadline: Instant,
    cancellation: &CancellationToken,
    native_pair: Option<&Arc<super::native_relay_pair::Pair>>,
) -> ConnectResult<()> {
    if a.claim.role() != 0
        || b.claim.role() != 1
        || a.claim.carrier() != a.provider.identity()
        || b.claim.carrier() != b.provider.identity()
    {
        return Err(ConnectError::Configuration);
    }
    let mut progress = [0usize; 2];
    let sequence = [[1u8, 2, 4, 5], [1u8, 3, 4, 5]];
    loop {
        owner.check(index, generation)?;
        registration.original.check()?;
        check_original_claim(&a.claim, &a.provider)?;
        check_original_claim(&b.claim, &b.provider)?;
        let wire = tokio::select! {
            _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = owner.cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep(Duration::from_millis(10)) => { if progress != [4,4] && Instant::now() >= deadline {
                return Err(ConnectError::Deadline); } continue; },
            wire = a.provider.receive_prepared(&mut a.incoming) => (0, wire?),
            wire = b.provider.receive_prepared(&mut b.incoming) => (1, wire?),
        };
        let (role, wire) = wire;
        if wire.len() < 8
            || u32::from_be_bytes(wire[..4].try_into().map_err(|_| ConnectError::Protocol)?)
                as usize
                + 8
                != wire.len()
            || wire[5..8] != [0; 3]
            || !(1..=15).contains(&wire[4])
        {
            return Err(ConnectError::Protocol);
        }
        if progress != [4, 4] && Instant::now() >= deadline {
            return Err(ConnectError::Deadline);
        }
        if progress[role] < 4 {
            if wire[4] != sequence[role][progress[role]] {
                return Err(ConnectError::Protocol);
            }
            progress[role] += 1;
        } else if progress != [4, 4] || wire[4] < 6 || wire.len() < 44 {
            return Err(ConnectError::Protocol);
        }
        owner.check(index, generation)?;
        check_original_claim(&a.claim, &a.provider)?;
        check_original_claim(&b.claim, &b.provider)?;
        if role == 0 {
            b.provider.send(wire).await?;
        } else {
            a.provider.send(wire).await?;
        }
        if progress == [4, 4] {
            {
                let mut gate = owner.gate.lock().expect("original relay READY forwarding");
                let slot = gate.slots[index]
                    .as_mut()
                    .filter(|slot| slot.generation == generation)
                    .ok_or(ConnectError::Canceled)?;
                slot.forwarded = true;
            }
            owner.changed.notify_waiters();
            a.provider.activate();
            b.provider.activate();
            if let Some(pair) = native_pair {
                let providers = [a.provider.clone(), b.provider.clone()];
                let a_claim = &a.claim;
                let b_claim = &b.claim;
                let result = pair
                    .run(&mut a.incoming, &mut b.incoming, providers, || {
                        if cancellation.is_cancelled() {
                            return Err(ConnectError::Canceled);
                        }
                        owner.check(index, generation)?;
                        registration.original.check()?;
                        check_original_claim(a_claim, &a.provider)?;
                        check_original_claim(b_claim, &b.provider)
                    })
                    .await;
                return result;
            }
        }
    }
}
