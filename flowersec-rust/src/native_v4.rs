//! Current native stream assembly. Maintenance and each authenticated application
//! scope retain separate original QUIC stream objects and physical cleanup tails.
use super::*;
use crate::api_v4::CleanupStatus;
use flowersec_native_transport::{
    Cancellation as NativeCancellation, CandidatePreparationBudget, PathProfile, PreparationBudget,
    PreparationBudgetError, PreparationLimits, RawQuicClientConfig, RawQuicError, RawQuicLimits,
    RawQuicSession, RawQuicStream, WebTransportConfig, WebTransportSession,
};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::task::TaskTracker;

#[derive(Debug)]
struct Clock(ResourceAccount);
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        self.0.security_time().ok().map(|time| {
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_millis(time.upper_ms))
        })
    }
}
pub(super) fn budget_error(error: PreparationBudgetError) -> ConnectError {
    match error {
        PreparationBudgetError::Exhausted => ConnectError::Capacity,
        PreparationBudgetError::Invalid => ConnectError::Configuration,
        PreparationBudgetError::Closed => ConnectError::Canceled,
    }
}
pub(super) fn preparation_error(error: RawQuicError, fallback: ConnectError) -> ConnectError {
    match error {
        RawQuicError::PreparationBudget(error) => budget_error(error),
        RawQuicError::Canceled => ConnectError::Canceled,
        RawQuicError::Timeout => ConnectError::Deadline,
        _ => fallback,
    }
}
/// One fixed SDK Prepare owns all native address, UDP/TLS and H3 work. This
/// capability survives cancellation with the original physical native owners.
pub(super) fn preparation_limits(bytes: usize) -> ConnectResult<PreparationLimits> {
    if !(16384..=262144).contains(&bytes) {
        return Err(ConnectError::Configuration);
    }
    Ok(PreparationLimits {
        preauth_input_bytes: bytes as u64,
        address_attempts: 1,
        work_units: bytes as u64,
    })
}
pub(super) fn original_preparation_budget(
    bytes: usize,
) -> ConnectResult<CandidatePreparationBudget> {
    let limits = preparation_limits(bytes)?;
    let owner = PreparationBudget::new();
    owner.configure(limits).map_err(budget_error)?;
    owner.begin_candidate(limits).map_err(budget_error)
}
#[derive(Clone, Debug)]
pub(super) enum Connection {
    Raw(RawQuicSession),
    WebTransport(WebTransportSession),
}
impl Connection {
    pub(super) fn raw(&self) -> &RawQuicSession {
        match self {
            Self::Raw(native) => native,
            Self::WebTransport(native) => native.raw(),
        }
    }
    pub(super) async fn open_stream(
        &self,
        cancellation: &NativeCancellation,
    ) -> std::result::Result<RawQuicStream, RawQuicError> {
        match self {
            Self::Raw(native) => native.open_stream(cancellation).await,
            Self::WebTransport(native) => native.open_stream(cancellation).await,
        }
    }
    pub(super) async fn accept_stream(
        &self,
        cancellation: &NativeCancellation,
    ) -> std::result::Result<RawQuicStream, RawQuicError> {
        match self {
            Self::Raw(native) => native.accept_stream(cancellation).await,
            Self::WebTransport(native) => native.accept_stream(cancellation).await,
        }
    }
    pub(super) fn capacity(&self) -> usize {
        match self {
            Self::Raw(native) => native.inbound_bidirectional_stream_capacity() as usize,
            Self::WebTransport(native) => native.inbound_bidirectional_stream_capacity() as usize,
        }
    }
    pub(super) fn datagram_maximum(&self) -> Option<usize> {
        match self {
            Self::Raw(native) => native.max_datagram_size(),
            Self::WebTransport(native) => native.max_datagram_size(),
        }
    }
    pub(super) fn submit_datagram(
        &self,
        wire: Vec<u8>,
    ) -> Option<flowersec_native_transport::DatagramSubmission> {
        match self {
            Self::Raw(native) => native.submit_datagram_current(wire),
            Self::WebTransport(native) => native.submit_datagram(wire),
        }
    }
    pub(super) async fn receive_datagram(
        &self,
        maximum: usize,
        cancellation: &NativeCancellation,
    ) -> std::result::Result<Vec<u8>, RawQuicError> {
        match self {
            Self::Raw(native) => native.receive_datagram_bounded(maximum, cancellation).await,
            Self::WebTransport(native) => native.receive_datagram(maximum, cancellation).await,
        }
    }
    pub(super) fn abort(&self) {
        match self {
            Self::Raw(native) => native.abort(),
            Self::WebTransport(native) => native.abort(),
        }
    }
    pub(super) async fn wait_termination(&self) {
        match self {
            Self::Raw(native) => native.wait_termination().await,
            Self::WebTransport(native) => native.wait_termination().await,
        }
    }
}
#[derive(Clone)]
enum Security {
    Account(ResourceAccount),
    Environment(Arc<EnvironmentRoot>),
}
type Charge = PreparationCharge;
enum FrameFailure {
    Boundary,
    Truncated,
    Native(RawQuicError),
}
enum WriteFailure {
    Canceled,
    Deadline,
    Native(RawQuicError),
}
impl WriteFailure {
    fn normal(&self) -> bool {
        matches!(self, Self::Native(RawQuicError::NormalDrained))
    }
    fn projection(self) -> ConnectError {
        match self {
            Self::Canceled => ConnectError::Canceled,
            Self::Deadline => ConnectError::Deadline,
            Self::Native(_) => ConnectError::Carrier,
        }
    }
}
struct Publication {
    wire: Vec<u8>,
    reply: oneshot::Sender<ConnectResult<()>>,
}
struct Position {
    commands: mpsc::Sender<Publication>,
    pending: AtomicUsize,
    physical_done: AtomicBool,
    binding: OnceLock<NativeStreamBinding>,
    _charge: Arc<ResourceCharge>,
}
struct IngressPosition {
    provider: Arc<Provider>,
    charge: Option<Arc<ResourceCharge>>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for IngressPosition {
    fn drop(&mut self) {
        self.charge.take();
        self.permit.take();
        self.provider.changed.notify_waiters();
    }
}
pub(super) struct Provider {
    security: Mutex<Security>,
    charge: Mutex<Option<Charge>>,
    bootstrap_charge: Mutex<Option<ResourceCharge>>,
    management_charge: Mutex<Option<Arc<ResourceCharge>>>,
    management_scope: AtomicU64,
    ingress_charge: Mutex<Option<Arc<ResourceCharge>>>,
    native: Mutex<Option<Connection>>,
    maintenance: Mutex<Option<RawQuicStream>>,
    cancellation: CancellationToken,
    parent: CancellationToken,
    native_cancellation: NativeCancellation,
    deadline: Instant,
    publication_timeout: Duration,
    maximum: usize,
    live_maximum: AtomicUsize,
    capacity: AtomicUsize,
    live: AtomicBool,
    done: AtomicBool,
    receivers: AtomicUsize,
    maintenance_pending: AtomicUsize,
    commands: mpsc::Sender<Publication>,
    streams: Mutex<BTreeMap<u64, Arc<Position>>>,
    receiver: OnceLock<SessionReceiver>,
    changed: tokio::sync::Notify,
    workers: TaskTracker,
    input_slots: OnceLock<Arc<tokio::sync::Semaphore>>,
    id: [u8; 16],
    listener_cleanup: OnceLock<Arc<AtomicBool>>,
    connect_diagnostic: OnceLock<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
    connect_physical: Mutex<Option<crate::diagnostics_v4::DiagnosticPhysicalTail>>,
    connect_preparation: Mutex<Option<direct_carrier::PreparationTail>>,
    cleanup_changed: tokio::sync::Notify,
    relay_cleanup: OnceLock<Arc<AtomicBool>>,
    preparation_tail: Mutex<Option<direct_carrier::PreparationTail>>,
    relay_budget: Mutex<Option<Arc<wss::RelayBudget>>>,
    relay_mode: AtomicBool,
    relay_unassigned: AtomicBool,
    relay_assigned: tokio::sync::Notify,
    validity: (u64, u64),
    artifact: Mutex<Option<[u8; 32]>>,
    exporter: Mutex<Option<[u8; 32]>>,
    data_slot: Arc<AtomicU64>,
    failed_scope: AtomicU64,
    failed_normal: AtomicBool,
    stall_generation: AtomicU64,
    read_stalled: AtomicBool,
}
impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeV4Provider { <opaque> }")
    }
}

/// Wait for the one-shot classification of an initially unassigned ingress.
/// The notification is armed before the state check so `notify_waiters()`
/// cannot fall between the check and the await.
async fn wait_for_relay_assignment(
    relay_unassigned: &AtomicBool,
    relay_assigned: &tokio::sync::Notify,
    cancellation: &CancellationToken,
    parent: &CancellationToken,
) -> bool {
    loop {
        let assigned = relay_assigned.notified();
        tokio::pin!(assigned);
        assigned.as_mut().enable();
        if !relay_unassigned.load(Ordering::Acquire) {
            return true;
        }
        tokio::select! {
            _ = cancellation.cancelled() => return false,
            _ = parent.cancelled() => return false,
            _ = assigned => {},
        }
    }
}
struct PreparationGuard {
    native: Option<Connection>,
    maintenance: Option<RawQuicStream>,
    charge: Option<Charge>,
    tls: Option<Charge>,
    preparation_tail: Option<direct_carrier::PreparationTail>,
}
impl PreparationGuard {
    fn new(native: Connection, charge: Charge, tls: Charge) -> Self {
        Self {
            native: Some(native),
            maintenance: None,
            charge: Some(charge),
            tls: Some(tls),
            preparation_tail: None,
        }
    }
}
impl Drop for PreparationGuard {
    fn drop(&mut self) {
        let Some(native) = self.native.take() else {
            return;
        };
        if let Some(tail) = &self.preparation_tail {
            tail.start_cleanup();
        }
        native.abort();
        let maintenance = self.maintenance.take();
        let charge = self.charge.take();
        let tls = self.tls.take();
        let preparation_tail = self.preparation_tail.take();
        // A failed preparation retains its original prepayment while actual
        // native tasks and direction observers exit. Cancellation is not exit.
        tokio::spawn(async move {
            if let Some(maintenance) = maintenance {
                maintenance.cancel_current();
                maintenance.wait_termination_current().await;
            }
            native.wait_termination().await;
            drop(native);
            drop(tls);
            drop(charge);
            drop(preparation_tail);
        });
    }
}
struct DialCancellation {
    cancellation: Option<NativeCancellation>,
    cleanup: Option<Arc<ConnectCleanup>>,
}
impl Drop for DialCancellation {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            if let Some(cleanup) = &self.cleanup {
                cleanup.start();
            }
            cancellation.cancel();
        }
    }
}
struct PreparedConnection {
    native: Option<Connection>,
    charge: Option<ResourceCharge>,
    tls: Option<ResourceCharge>,
    preparation_tail: Option<direct_carrier::PreparationTail>,
}
impl Drop for PreparedConnection {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            let guard = PreparationGuard {
                native: Some(native),
                maintenance: None,
                charge: self.charge.take().map(Charge::Account),
                tls: self.tls.take().map(Charge::Account),
                preparation_tail: self.preparation_tail.take(),
            };
            drop(guard);
        }
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Native assembly receives the original connection, negotiated limits and separately reserved lifecycle owners."
)]
async fn dial_owned(
    local: SocketAddr,
    remote: SocketAddr,
    config: RawQuicClientConfig,
    policy: &wss::Policy,
    deadline: Instant,
    caller: &CancellationToken,
    cancellation: &NativeCancellation,
    charge: ResourceCharge,
    tls: ResourceCharge,
    preparation_tail: Option<direct_carrier::PreparationTail>,
) -> ConnectResult<PreparedConnection> {
    let cleanup = preparation_tail
        .as_ref()
        .and_then(|tail| tail.cleanup_owner());
    let (completed, wait) = oneshot::channel();
    let native_cancellation = cancellation.clone();
    let host = policy.host.clone();
    let path = policy.path.clone();
    let carrier = policy.carrier;
    let capacity = policy.max_streams * 2 + 12;
    tokio::spawn(async move {
        let result = if carrier == 2 {
            WebTransportSession::connect_native_h3(
                remote,
                config,
                WebTransportConfig {
                    server_name: host,
                    path,
                    tuples: vec!["native_h3".to_owned()],
                    allowed_origins: Vec::new(),
                    allow_absent_origin: true,
                    header_bytes: 16384,
                    control_bytes: 65536,
                    handshake_timeout: deadline.saturating_duration_since(Instant::now()),
                },
                capacity as u32,
                &native_cancellation,
            )
            .await
            .map(Connection::WebTransport)
        } else {
            RawQuicSession::dial_from(local, remote, host, config, &native_cancellation)
                .await
                .map(Connection::Raw)
        };
        let result = result.map(|native| PreparedConnection {
            native: Some(native),
            charge: Some(charge),
            tls: Some(tls),
            preparation_tail,
        });
        // If observation was withdrawn, dropping this original result owns
        // cancellation and cleanup. A new caller can never adopt it.
        let _ = completed.send(result);
    });
    let mut guard = DialCancellation {
        cancellation: Some(cancellation.clone()),
        cleanup,
    };
    let result = tokio::select! {
        _=caller.cancelled()=>return Err(ConnectError::Canceled),
        _=tokio::time::sleep_until(deadline)=>return Err(ConnectError::Deadline),
        result=wait=>result.map_err(|_|ConnectError::Carrier)?.map_err(|failure|match failure{
            RawQuicError::PreparationBudget(error)=>budget_error(error),
            RawQuicError::Canceled=>ConnectError::Canceled,RawQuicError::Timeout=>ConnectError::Deadline,_=>ConnectError::Carrier,
        }),
    };
    if result.is_ok() {
        guard.cancellation = None;
    }
    result
}
impl Provider {
    pub(super) async fn prepare(
        account: ResourceAccount,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        Self::prepare_original(account, policy, options, deadline, caller, None).await
    }
    pub(super) async fn prepare_observed(
        account: ResourceAccount,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        tail: direct_carrier::PreparationTail,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        Self::prepare_original(account, policy, options, deadline, caller, Some(tail)).await
    }
    async fn prepare_original(
        account: ResourceAccount,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        preparation_tail: Option<direct_carrier::PreparationTail>,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        if !matches!(policy.carrier, 0 | 2) {
            return Err(ConnectError::Configuration);
        }
        let capacity = policy
            .max_streams
            .checked_mul(2)
            .and_then(|n| n.checked_add(11))
            .ok_or(ConnectError::Capacity)?;
        let application_window = policy
            .max_credit
            .checked_add(
                (capacity as u64)
                    .checked_mul(policy.live_maximum as u64)
                    .ok_or(ConnectError::Capacity)?,
            )
            .ok_or(ConnectError::Capacity)?;
        let maintenance_window = policy.maximum as u64;
        let connection_window = application_window
            .checked_add(maintenance_window)
            .and_then(|n| n.checked_add(if policy.carrier == 2 { 65536 } else { 0 }))
            .ok_or(ConnectError::Capacity)?;
        let mut limits = RawQuicLimits::for_session(
            u32::try_from(capacity + if policy.carrier == 2 { 2 } else { 1 })
                .map_err(|_| ConnectError::Capacity)?,
            deadline.saturating_duration_since(Instant::now()),
        )
        .map_err(|_| ConnectError::Configuration)?;
        limits.stream_receive_window = maintenance_window;
        limits.connection_receive_window = connection_window;
        limits.validate().map_err(|_| ConnectError::Capacity)?;
        let required_native = connection_window
            .checked_add(options.prepare_bytes as u64)
            .and_then(|n| n.checked_add(196608))
            .and_then(|n| n.checked_add((capacity as u64 + 2).checked_mul(16384)?))
            .ok_or(ConnectError::Capacity)?;
        if options.native_runtime_bytes < required_native {
            return Err(ConnectError::Capacity);
        }
        let mut charge = policy.take_preparation(&account, policy.preparation_limits(&options)?)?;
        let tls_charge = charge.split(ResourceLimits {
            tls_handshakes: 1,
            ..ResourceLimits::default()
        })?;
        let clock: Arc<dyn rustls::time_provider::TimeProvider> = Arc::new(Clock(account.clone()));
        let profile = if policy.carrier == 2 {
            PathProfile::WebTransportV4
        } else if policy.path_kind == 1 {
            PathProfile::TunnelV4
        } else {
            PathProfile::DirectV4
        };
        let config = match &policy.pins {
            None => RawQuicClientConfig::new_ca_with_time_provider(
                profile,
                policy.ca.clone(),
                limits,
                clock,
            ),
            Some(pins) => RawQuicClientConfig::new_pin_with_time_provider(
                profile,
                pins.iter().map(|pin| pin.digest).collect(),
                limits,
                clock,
            ),
        }
        .map_err(|error| preparation_error(error, ConnectError::Tls))?
        .with_preparation_budget(match &policy.preparation_budget {
            Some(budget) => budget.clone(),
            None => original_preparation_budget(options.prepare_bytes)?,
        })
        .map_err(|error| preparation_error(error, ConnectError::Configuration))?;
        let native_cancellation = NativeCancellation::new();
        let remote = SocketAddr::new(options.remote_address, policy.port);
        let local = SocketAddr::new(
            if remote.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        );
        let mut prepared = dial_owned(
            local,
            remote,
            config,
            &policy,
            deadline,
            &caller,
            &native_cancellation,
            charge,
            tls_charge,
            preparation_tail,
        )
        .await?;
        let native = prepared.native.take().ok_or(ConnectError::Carrier)?;
        let mut guard = PreparationGuard::new(
            native.clone(),
            Charge::Account(prepared.charge.take().ok_or(ConnectError::Capacity)?),
            Charge::Account(prepared.tls.take().ok_or(ConnectError::Capacity)?),
        );
        guard.preparation_tail = prepared.preparation_tail.take();
        let leaf = native
            .raw()
            .peer_leaf_der()
            .map_err(|error| preparation_error(error, ConnectError::Tls))?;
        let time = account.security_time()?;
        let validity = wss::interval(&leaf, time).map_err(|_| ConnectError::Tls)?;
        if let Some(pins) = &policy.pins {
            wss::pin_profile(&leaf).map_err(|_| ConnectError::Tls)?;
            let digest: [u8; 32] = Sha256::digest(&leaf).into();
            if !pins.iter().any(|pin| {
                pin.digest == digest
                    && pin.start >= validity.0
                    && pin.end <= validity.1
                    && time.lower_ms >= pin.start
                    && time.upper_ms < pin.end
            }) {
                return Err(ConnectError::Tls);
            }
        }
        let exporter: [u8; 32] = native
            .raw()
            .export_keying_material(32, b"EXPORTER-flowersec-v4", &policy.artifact)
            .map_err(|error| preparation_error(error, ConnectError::Tls))?
            .try_into()
            .map_err(|_| ConnectError::Tls)?;
        // Prepare creates only the empty dedicated maintenance stream. The first
        // Flowersec byte still comes from the retained post-spend continuation.
        let maintenance = tokio::select! {
            _ = caller.cancelled() => return Err(ConnectError::Canceled),
            result = tokio::time::timeout_at(deadline, native.open_stream(&native_cancellation)) =>
                result.map_err(|_|ConnectError::Deadline)?.map_err(|error| preparation_error(error, ConnectError::Carrier))?,
        };
        guard.maintenance = Some(maintenance.clone());
        drop(guard.tls.take());
        let id = Self::new_identity()?;
        let original_charge = guard.charge.take().ok_or(ConnectError::Configuration)?;
        let (provider, input) = Self::start(
            id,
            Security::Account(account),
            original_charge,
            native,
            Some(maintenance),
            native_cancellation,
            deadline,
            options.publication_timeout,
            policy.maximum,
            policy.live_maximum,
            capacity,
            validity,
            Some((policy.artifact, exporter)),
            options.queue_messages,
            caller,
            policy.relay_budget.clone(),
            false,
            guard.preparation_tail.take(),
        );
        guard.native = None;
        guard.maintenance = None;
        if let Err(failure) = provider.check() {
            provider.close();
            drop(input);
            // The original provider worker retains its charge and observation
            // tail through physical exit while the caller receives the failure.
            return Err(failure);
        }
        Ok((provider, input))
    }
    fn new_identity() -> ConnectResult<[u8; 16]> {
        let mut id = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
            .map_err(|_| ConnectError::Carrier)?;
        if id == [0; 16] {
            return Err(ConnectError::Carrier);
        }
        Ok(id)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Native assembly receives the original connection, negotiated limits and separately reserved lifecycle owners."
    )]
    fn start(
        id: [u8; 16],
        security: Security,
        charge: Charge,
        native: Connection,
        maintenance: Option<RawQuicStream>,
        native_cancellation: NativeCancellation,
        deadline: Instant,
        publication_timeout: Duration,
        maximum: usize,
        live_maximum: usize,
        capacity: usize,
        validity: (u64, u64),
        binding: Option<([u8; 32], [u8; 32])>,
        queue_messages: usize,
        parent: CancellationToken,
        relay_budget: Option<Arc<wss::RelayBudget>>,
        relay_unassigned: bool,
        preparation_tail: Option<direct_carrier::PreparationTail>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        // All fallible work ran while the original preparation guard owned
        // the native objects and charge. This is one synchronous custody move.
        let (commands, writing) = mpsc::channel(1);
        let (incoming, input) = mpsc::channel(queue_messages);
        let provider = Arc::new(Self {
            security: Mutex::new(security),
            charge: Mutex::new(Some(charge)),
            bootstrap_charge: Mutex::new(None),
            management_charge: Mutex::new(None),
            management_scope: AtomicU64::new(0),
            ingress_charge: Mutex::new(None),
            native: Mutex::new(Some(native)),
            maintenance: Mutex::new(maintenance),
            cancellation: CancellationToken::new(),
            parent,
            native_cancellation,
            deadline,
            publication_timeout,
            maximum,
            live_maximum: AtomicUsize::new(live_maximum),
            capacity: AtomicUsize::new(capacity),
            live: AtomicBool::new(false),
            done: AtomicBool::new(false),
            receivers: AtomicUsize::new(0),
            relay_mode: AtomicBool::new(relay_budget.is_some() || relay_unassigned),
            relay_budget: Mutex::new(relay_budget),
            relay_unassigned: AtomicBool::new(relay_unassigned),
            relay_assigned: tokio::sync::Notify::new(),
            maintenance_pending: AtomicUsize::new(0),
            commands,
            streams: Mutex::new(BTreeMap::new()),
            receiver: OnceLock::new(),
            changed: tokio::sync::Notify::new(),
            workers: TaskTracker::new(),
            input_slots: OnceLock::new(),
            listener_cleanup: OnceLock::new(),
            connect_diagnostic: OnceLock::new(),
            connect_physical: Mutex::new(None),
            connect_preparation: Mutex::new(None),
            cleanup_changed: tokio::sync::Notify::new(),
            relay_cleanup: OnceLock::new(),
            preparation_tail: Mutex::new(preparation_tail),
            id,
            validity,
            artifact: Mutex::new(binding.map(|binding| binding.0)),
            exporter: Mutex::new(binding.map(|binding| binding.1)),
            data_slot: Arc::new(AtomicU64::new(0)),
            failed_scope: AtomicU64::new(0),
            failed_normal: AtomicBool::new(false),
            stall_generation: AtomicU64::new(0),
            read_stalled: AtomicBool::new(false),
        });
        let owner = provider.clone();
        tokio::spawn(async move {
            owner
                .workers
                .spawn(owner.clone().write_maintenance(writing));
            owner
                .workers
                .spawn(owner.clone().read_maintenance(incoming));
            owner.workers.spawn(owner.clone().accept_applications());
            owner.workers.spawn(owner.clone().read_datagrams());
            loop {
                tokio::select! {_=owner.cancellation.cancelled()=>break,_=owner.parent.cancelled()=>break,
                _=tokio::time::sleep(Duration::from_millis(10))=>if owner.check().is_err(){break;} }
            }
            owner.close();
            owner.workers.close();
            owner.workers.wait().await;
            if let Ok(native) = owner.native() {
                native.wait_termination().await;
            }
            if let Ok(maintenance) = owner.maintenance() {
                maintenance.cancel_current();
                maintenance.wait_termination_current().await;
            }
            owner
                .maintenance
                .lock()
                .expect("native maintenance owner")
                .take();
            owner.native.lock().expect("native connection owner").take();
            owner
                .streams
                .lock()
                .expect("native stream directory")
                .clear();
            owner
                .bootstrap_charge
                .lock()
                .expect("native bootstrap backing")
                .take();
            owner
                .management_charge
                .lock()
                .expect("native management backing")
                .take();
            owner
                .ingress_charge
                .lock()
                .expect("native ingress backing")
                .take();
            if let Some(mut exporter) = owner.exporter.lock().expect("native TLS binding").take() {
                exporter.zeroize();
            }
            loop {
                let released = {
                    let mut charge = owner.charge.lock().expect("native resource charge");
                    if owner.receivers.load(Ordering::Acquire) != 0
                        || owner.maintenance_pending.load(Ordering::Acquire) != 0
                        || owner
                            .listener_cleanup
                            .get()
                            .is_some_and(|done| !done.load(Ordering::Acquire))
                        || owner
                            .relay_cleanup
                            .get()
                            .is_some_and(|done| !done.load(Ordering::Acquire))
                    {
                        false
                    } else {
                        charge.take();
                        true
                    }
                };
                if released {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let preparation_tail = {
                let mut tail = owner
                    .preparation_tail
                    .lock()
                    .expect("native failed preparation retirement");
                owner.done.store(true, Ordering::Release);
                tail.take()
            };
            owner.cleanup();
            owner.cleanup_changed.notify_waiters();
            owner.changed.notify_waiters();
            drop(preparation_tail);
        });
        (provider, input)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Native assembly receives the original connection, negotiated limits and separately reserved lifecycle owners."
    )]
    pub(super) async fn accept_observed(
        root: Arc<EnvironmentRoot>,
        native: Connection,
        policy: serve::SocketPolicy,
        deadline: Instant,
        caller: CancellationToken,
        charges: (PreparationCharge, PreparationCharge),
        preparation_tail: Option<direct_carrier::PreparationTail>,
        retain: impl FnOnce(Arc<Self>),
        authorize: impl FnOnce(serve::ServeRequestContext) -> wss::RequestAuthorizationFuture,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        let (charge, tls_charge) = charges;
        let mut guard = PreparationGuard::new(native.clone(), charge, tls_charge);
        guard.preparation_tail = preparation_tail;
        let request = match &native {
            Connection::WebTransport(native) => Some(
                native
                    .request()
                    .map_err(|error| preparation_error(error, ConnectError::Carrier))?,
            ),
            Connection::Raw(_) => None,
        };
        let context = serve::ServeRequestContext {
            method: if request.is_some() { "CONNECT" } else { "QUIC" }.to_owned(),
            target: request
                .as_ref()
                .map(|request| request.path.clone())
                .unwrap_or_default(),
            authority: request
                .as_ref()
                .map(|request| request.authority.clone())
                .unwrap_or_else(|| policy.authority.clone()),
            origin: request.as_ref().and_then(|request| request.origin.clone()),
            headers: Vec::new(),
            local_address: native
                .raw()
                .local_address()
                .map_err(|_| ConnectError::Carrier)?,
            remote_address: native.raw().peer_address(),
            cancellation: caller.clone(),
        };
        let authorization = tokio::select! {_=caller.cancelled()=>return Err(ConnectError::Canceled),
        result=tokio::time::timeout_at(deadline,authorize(context))=>result.map_err(|_|ConnectError::Deadline)?.map_err(|_|ConnectError::Authorization)?};
        if !authorization.allowed {
            return Err(ConnectError::Authorization);
        }
        let cancellation = NativeCancellation::new();
        // TLS and the prepaid native position complete physical preparation.
        // The original reader accepts maintenance later: a reverse endpoint
        // must authorize before its dialer may publish the first stream byte.
        drop(guard.tls.take());
        let capacity = native
            .capacity()
            .checked_sub(1)
            .ok_or(ConnectError::Capacity)?;
        let id = Self::new_identity()?;
        let (provider, input) = Self::start(
            id,
            Security::Environment(root),
            guard.charge.take().ok_or(ConnectError::Configuration)?,
            native,
            None,
            cancellation,
            deadline,
            policy.publication_timeout,
            policy.maximum,
            policy.maximum,
            capacity,
            policy.validity,
            None,
            policy.queue_messages,
            caller,
            policy.relay_budget.clone(),
            policy.relay_unassigned,
            guard.preparation_tail.take(),
        );
        retain(provider.clone());
        guard.native = None;
        guard.maintenance = None;
        provider.check()?;
        Ok((provider, input))
    }
    fn native(&self) -> ConnectResult<Connection> {
        self.native
            .lock()
            .expect("native connection owner")
            .as_ref()
            .cloned()
            .ok_or(ConnectError::Carrier)
    }
    fn maintenance(&self) -> ConnectResult<RawQuicStream> {
        self.maintenance
            .lock()
            .expect("native maintenance owner")
            .as_ref()
            .cloned()
            .ok_or(ConnectError::Carrier)
    }
    async fn wait_maintenance(&self) -> ConnectResult<RawQuicStream> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.check()?;
            if let Ok(stream) = self.maintenance() {
                return Ok(stream);
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => return Err(ConnectError::Canceled),
                _ = self.parent.cancelled() => return Err(ConnectError::Canceled),
                _ = tokio::time::sleep_until(self.deadline) => return Err(ConnectError::Deadline),
                _ = changed => {},
            }
        }
    }
    async fn accept_maintenance(&self) -> ConnectResult<()> {
        if self.maintenance().is_ok() {
            return Ok(());
        }
        self.check()?;
        let native = self.native()?;
        let stream = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = self.parent.cancelled() => return Err(ConnectError::Canceled),
            result = tokio::time::timeout_at(self.deadline, native.accept_stream(&self.native_cancellation)) =>
                result.map_err(|_| ConnectError::Deadline)?.map_err(|error| preparation_error(error, ConnectError::Carrier))?,
        };
        let installed = {
            let mut maintenance = self
                .maintenance
                .lock()
                .expect("native maintenance acceptance");
            if self.cancellation.is_cancelled()
                || self.parent.is_cancelled()
                || Instant::now() >= self.deadline
            {
                false
            } else {
                *maintenance = Some(stream.clone());
                true
            }
        };
        if !installed {
            stream.cancel_current();
            stream.wait_termination_current().await;
            return Err(ConnectError::Canceled);
        }
        self.changed.notify_waiters();
        Ok(())
    }
    fn account(&self) -> ConnectResult<ResourceAccount> {
        match &*self.security.lock().expect("native security owner") {
            Security::Account(account) => Ok(account.clone()),
            Security::Environment(_) => Err(ConnectError::Configuration),
        }
    }
    pub(super) fn attach(&self, account: ResourceAccount) -> ConnectResult<()> {
        let mut security = self.security.lock().expect("native security owner");
        let Security::Environment(root) = &*security else {
            return Err(ConnectError::Configuration);
        };
        if !account.belongs_to(root) {
            return Err(ConnectError::Configuration);
        }
        let mut charge = self.charge.lock().expect("native resource charge");
        match charge.as_mut() {
            Some(Charge::Environment(held)) => {
                let attached = held.attach(&account)?;
                *charge = Some(Charge::Account(attached));
            }
            Some(Charge::Account(held)) if held.belongs_to(&account) => {}
            _ => return Err(ConnectError::Configuration),
        }
        *security = Security::Account(account);
        Ok(())
    }
    pub(super) fn assign_endpoint(
        &self,
        account: ResourceAccount,
        prepaid: ResourceCharge,
    ) -> ConnectResult<()> {
        if !self.relay_unassigned.load(Ordering::Acquire)
            || self.live.load(Ordering::Acquire)
            || self
                .relay_budget
                .lock()
                .expect("endpoint ingress budget")
                .is_some()
        {
            return Err(ConnectError::Configuration);
        }
        {
            let mut security = self
                .security
                .lock()
                .expect("original endpoint ingress security");
            let Security::Environment(root) = &*security else {
                return Err(ConnectError::Configuration);
            };
            if !account.belongs_to(root) {
                return Err(ConnectError::Configuration);
            }
            let mut charge = self
                .charge
                .lock()
                .expect("original endpoint ingress backing");
            let Some(Charge::Environment(held)) = charge.as_mut() else {
                return Err(ConnectError::Configuration);
            };
            let attached = held.attach_prepaid(&account, prepaid)?;
            *charge = Some(Charge::Account(attached));
            *security = Security::Account(account);
        }
        self.relay_mode.store(false, Ordering::Release);
        self.relay_unassigned.store(false, Ordering::Release);
        self.relay_assigned.notify_waiters();
        self.check()
    }
    pub(super) fn bind_relay_limits(&self, mappings: usize, maximum: usize) -> ConnectResult<()> {
        if !self.relay_mode.load(Ordering::Acquire)
            || self.live.load(Ordering::Acquire)
            || mappings
                .checked_add(3)
                .is_none_or(|required| required > self.capacity.load(Ordering::Acquire))
        {
            return Err(ConnectError::Capacity);
        }
        self.bind_frame_limit(maximum)
    }
    pub(super) fn bind_contract(
        &self,
        max_streams: usize,
        max_credit: u64,
        maximum: usize,
    ) -> ConnectResult<()> {
        let capacity = max_streams
            .checked_mul(2)
            .and_then(|n| n.checked_add(11))
            .ok_or(ConnectError::Capacity)?;
        let window = max_credit
            .checked_add(
                (capacity as u64)
                    .checked_mul(maximum as u64)
                    .ok_or(ConnectError::Capacity)?,
            )
            .and_then(|n| n.checked_add(self.maximum as u64 + 65536))
            .ok_or(ConnectError::Capacity)?;
        if self.live.load(Ordering::Acquire)
            || capacity > self.capacity.load(Ordering::Acquire)
            || window > 16 << 20
        {
            return Err(ConnectError::Capacity);
        }
        self.capacity.store(capacity, Ordering::Release);
        self.bind_frame_limit(maximum)
    }
    pub(super) fn check(&self) -> ConnectResult<()> {
        if let Ok(native) = self.native()
            && let Some(budget) = native.raw().preparation_budget()
        {
            budget.check().map_err(budget_error)?;
        }
        if self.cancellation.is_cancelled() || self.done.load(Ordering::Acquire) {
            return Err(ConnectError::Carrier);
        }
        if !self.live.load(Ordering::Acquire) && Instant::now() >= self.deadline {
            return Err(ConnectError::Deadline);
        }
        let security = self.security.lock().expect("native security owner").clone();
        let now = match security {
            Security::Account(account) => account.security_time()?,
            Security::Environment(root) => {
                if root.is_closed() {
                    return Err(ConnectError::Canceled);
                }
                root.sample()?
            }
        };
        if now.lower_ms < self.validity.0 || now.upper_ms >= self.validity.1 {
            return Err(ConnectError::Tls);
        }
        Ok(())
    }
    pub(super) fn bind_frame_limit(&self, maximum: usize) -> ConnectResult<()> {
        if self.live.load(Ordering::Acquire) || maximum < 8 || maximum > self.maximum {
            return Err(ConnectError::Configuration);
        }
        self.live_maximum.store(maximum, Ordering::Release);
        Ok(())
    }
    pub(super) fn binding(
        &self,
        mode: BindingMode,
        artifact: [u8; 32],
    ) -> ConnectResult<Option<Zeroizing<[u8; 32]>>> {
        self.check()?;
        let mut original = self.artifact.lock().expect("native artifact binding");
        if original.is_some_and(|original| original != artifact) {
            return Err(ConnectError::Authorization);
        }
        if original.is_none() {
            let value = self
                .native()?
                .raw()
                .export_keying_material(32, b"EXPORTER-flowersec-v4", &artifact)
                .map_err(|error| preparation_error(error, ConnectError::Tls))?;
            let value: [u8; 32] = value.try_into().map_err(|_| ConnectError::Tls)?;
            *self.exporter.lock().expect("native TLS binding") = Some(value);
            *original = Some(artifact);
        }
        if mode == BindingMode::AuthenticatedContext {
            return Ok(None);
        }
        self.exporter
            .lock()
            .expect("native TLS binding")
            .as_ref()
            .copied()
            .map(Zeroizing::new)
            .map(Some)
            .ok_or(ConnectError::Tls)
    }
    fn relay_budget(&self) -> Option<Arc<wss::RelayBudget>> {
        self.relay_budget
            .lock()
            .expect("native relay meter")
            .clone()
    }
    pub(super) fn relay_connection(&self) -> ConnectResult<Connection> {
        if !self.relay_mode.load(Ordering::Acquire) || !self.live.load(Ordering::Acquire) {
            return Err(ConnectError::Configuration);
        }
        self.check()?;
        self.native()
    }
    pub(super) async fn assign_relay(
        &self,
        account: ResourceAccount,
        budget: Arc<wss::RelayBudget>,
        first_bytes: usize,
        prepaid: ResourceCharge,
    ) -> ConnectResult<()> {
        if !self.relay_unassigned.load(Ordering::Acquire) || self.live.load(Ordering::Acquire) {
            return Err(ConnectError::Configuration);
        }
        budget.reserve(first_bytes, &self.cancellation).await?;
        {
            let mut security = self
                .security
                .lock()
                .expect("native original ingress security");
            let Security::Environment(root) = &*security else {
                return Err(ConnectError::Configuration);
            };
            if !account.belongs_to(root) {
                return Err(ConnectError::Configuration);
            }
            let mut charge = self.charge.lock().expect("native original ingress backing");
            let Some(Charge::Environment(held)) = charge.as_mut() else {
                return Err(ConnectError::Configuration);
            };
            let attached = held.attach_prepaid(&account, prepaid)?;
            *charge = Some(Charge::Account(attached));
            *security = Security::Account(account);
        }
        {
            let mut installed = self
                .relay_budget
                .lock()
                .expect("native original relay meter installation");
            if installed.is_some() {
                return Err(ConnectError::Configuration);
            }
            *installed = Some(budget);
        }
        self.relay_unassigned.store(false, Ordering::Release);
        self.relay_assigned.notify_waiters();
        self.check()
    }
    pub(super) fn bind_receiver(&self, receiver: SessionReceiver) -> ConnectResult<()> {
        self.receiver
            .set(receiver)
            .map_err(|_| ConnectError::Protocol)
    }
    pub(super) fn complete_preparation(&self) -> ConnectResult<()> {
        self.check()?;
        self.native()?
            .raw()
            .complete_preparation()
            .map_err(|error| preparation_error(error, ConnectError::Carrier))
    }
    pub(super) fn activate(&self) {
        if self.receiver.get().is_none() && !self.relay_mode.load(Ordering::Acquire) {
            self.close();
            return;
        }
        let _ = self.input_slots.set(Arc::new(tokio::sync::Semaphore::new(
            self.capacity.load(Ordering::Acquire).min(128),
        )));
        if let Some(mut exporter) = self.exporter.lock().expect("native TLS binding").take() {
            exporter.zeroize();
        }
        self.live.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    pub(super) fn datagram_maximum(&self) -> Option<usize> {
        self.native().ok()?.datagram_maximum()
    }
    pub(super) fn identity(&self) -> [u8; 16] {
        self.id
    }
    pub(super) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    pub(super) fn close(&self) {
        if let Some(tail) = self
            .preparation_tail
            .lock()
            .expect("native preparation cleanup origin")
            .as_ref()
        {
            tail.start_cleanup();
        }
        if let Some(tail) = self
            .connect_preparation
            .lock()
            .expect("native accepted cleanup origin")
            .as_ref()
        {
            tail.start_cleanup();
        }
        {
            // Serialize sealing with the original reader's maintenance handoff.
            let _maintenance = self.maintenance.lock().expect("native maintenance close");
            self.cancellation.cancel();
            self.native_cancellation.cancel();
        }
        if let Ok(native) = self.native() {
            native.abort();
        }
        self.changed.notify_waiters();
    }
    pub(super) fn cleanup(&self) -> CleanupStatus {
        let pending = self.maintenance_pending.load(Ordering::Acquire)
            + self.receivers.load(Ordering::Acquire)
            + self
                .streams
                .lock()
                .expect("native stream directory")
                .values()
                .filter(|p| !p.physical_done.load(Ordering::Acquire))
                .count()
            + usize::from(
                self.listener_cleanup
                    .get()
                    .is_some_and(|done| !done.load(Ordering::Acquire)),
            )
            + usize::from(
                self.relay_cleanup
                    .get()
                    .is_some_and(|done| !done.load(Ordering::Acquire)),
            );
        let complete = self.done.load(Ordering::Acquire) && pending == 0;
        if complete {
            // Release mutex guards before dropping physical tails. A tail can
            // own the cleanup controller, whose Session drop may re-enter
            // provider.close()/cleanup().
            let diagnostic_tail = self
                .connect_physical
                .lock()
                .expect("Connect diagnostic physical owner")
                .take();
            let preparation_tail = self
                .connect_preparation
                .lock()
                .expect("Connect preparation physical owner")
                .take();
            drop(diagnostic_tail);
            drop(preparation_tail);
        }
        CleanupStatus {
            complete,
            cleanup_incomplete: false,
            pending_callbacks: pending as u64,
        }
    }
    pub(super) fn retain_connect_diagnostic(
        self: &Arc<Self>,
        diagnostic: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    ) {
        let _ = self.connect_diagnostic.set(diagnostic.clone());
        let mut physical = self
            .connect_physical
            .lock()
            .expect("Connect diagnostic physical owner");
        if physical.is_none() {
            *physical = Some(diagnostic.retain_physical());
        }
        drop(physical);
        self.cleanup();
    }
    pub(super) fn retain_relay_cleanup(&self, done: Arc<AtomicBool>) -> ConnectResult<()> {
        let charge = self
            .charge
            .lock()
            .expect("original relay physical resource owner");
        if charge.is_none() || self.cancellation.is_cancelled() {
            return Err(ConnectError::Carrier);
        }
        self.relay_cleanup
            .set(done)
            .map_err(|_| ConnectError::Configuration)
    }
    pub(super) fn retain_listener_cleanup(&self, done: Arc<AtomicBool>) -> ConnectResult<()> {
        let charge = self.charge.lock().expect("native listener cleanup owner");
        if charge.is_none() || self.cancellation.is_cancelled() {
            return Err(ConnectError::Carrier);
        }
        self.listener_cleanup
            .set(done)
            .map_err(|_| ConnectError::Configuration)
    }
    pub(super) fn receiver(self: &Arc<Self>) -> ConnectResult<ReceiverGuard> {
        let charge = self.charge.lock().expect("native receiver owner");
        if charge.is_none() || self.cancellation.is_cancelled() {
            return Err(ConnectError::Carrier);
        }
        self.receivers.fetch_add(1, Ordering::AcqRel);
        Ok(ReceiverGuard(self.clone()))
    }
    async fn write_maintenance(self: Arc<Self>, mut commands: mpsc::Receiver<Publication>) {
        while let Some(command) =
            tokio::select! { _=self.cancellation.cancelled()=>None, value=commands.recv()=>value }
        {
            let result = match self.wait_maintenance().await {
                Ok(stream) => self.write(&stream, &command.wire).await,
                Err(failure) => Err(failure),
            };
            self.maintenance_pending.store(0, Ordering::Release);
            let failed = result.is_err();
            let _ = command.reply.send(result);
            if failed {
                break;
            }
        }
        self.maintenance_pending.store(0, Ordering::Release);
        self.close();
    }
    async fn wait_for_relay_assignment(&self) -> bool {
        wait_for_relay_assignment(
            &self.relay_unassigned,
            &self.relay_assigned,
            &self.cancellation,
            &self.parent,
        )
        .await
    }
    async fn wait_for_endpoint_role(&self) -> bool {
        self.wait_for_relay_assignment().await && !self.relay_mode.load(Ordering::Acquire)
    }
    async fn wait_until_live(&self) -> bool {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.live.load(Ordering::Acquire) {
                return true;
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => return false,
                _ = self.parent.cancelled() => return false,
                _ = changed => {},
            }
        }
    }
    async fn read_datagrams(self: Arc<Self>) {
        if !self.wait_for_endpoint_role().await || !self.wait_until_live().await {
            return;
        }
        let Ok(native) = self.native() else {
            return;
        };
        loop {
            let wire = match native
                .receive_datagram(1024, &self.native_cancellation)
                .await
            {
                Ok(wire) => wire,
                Err(_) => return,
            };
            if self.check().is_err() {
                return;
            }
            if let Some(receiver) = self.receiver.get() {
                receiver.receive_datagram(&wire);
            }
            // Bounded discard/crypto work shares a finite reader service turn.
            tokio::task::yield_now().await;
        }
    }
    async fn read_maintenance(self: Arc<Self>, incoming: mpsc::Sender<Vec<u8>>) {
        // This existing worker is the sole maintenance acceptor. Its original
        // task and connection backing remain charged until the native exit.
        if self.accept_maintenance().await.is_err() {
            self.close();
            return;
        }
        loop {
            let wire = match match self.maintenance() {
                Ok(stream) => self.read_frame(&stream).await,
                Err(_) => Err(FrameFailure::Boundary),
            } {
                Ok(Some(wire)) => wire,
                _ => break,
            };
            if self.live.load(Ordering::Acquire)
                && (!matches!(wire[4], 6 | 9 | 11..=15)
                    || wire.len() < 44
                    || wire[12..20] != [0; 8])
            {
                break;
            }
            let unassigned = self.relay_unassigned.load(Ordering::Acquire);
            if unassigned && wire.len() > 10354 {
                break;
            }
            if let Some(budget) = self.relay_budget()
                && budget
                    .reserve(wire.len(), &self.cancellation)
                    .await
                    .is_err()
            {
                break;
            }
            if incoming.try_send(wire.clone()).is_err() {
                self.read_stalled.store(true, Ordering::Release);
                if self
                    .stall_generation
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                    .is_err()
                {
                    break;
                }
                let sent = tokio::select! { _=self.cancellation.cancelled()=>false,result=incoming.send(wire)=>result.is_ok() };
                self.read_stalled.store(false, Ordering::Release);
                if !sent {
                    break;
                }
            }
            if unassigned && !self.wait_for_relay_assignment().await {
                break;
            }
        }
        self.close();
    }
    async fn write_outcome(
        &self,
        stream: &RawQuicStream,
        wire: &[u8],
    ) -> std::result::Result<(), WriteFailure> {
        tokio::select! {_=self.cancellation.cancelled()=>Err(WriteFailure::Canceled),
        result=tokio::time::timeout(self.publication_timeout,stream.write_all_current(wire))=>
            match result{Ok(Ok(()))=>Ok(()),Ok(Err(failure))=>Err(WriteFailure::Native(failure)),Err(_)=>Err(WriteFailure::Deadline)}}
    }
    async fn write(&self, stream: &RawQuicStream, wire: &[u8]) -> ConnectResult<()> {
        if let Some(budget) = self.relay_budget() {
            budget.reserve(wire.len(), &self.cancellation).await?;
        }
        self.write_outcome(stream, wire)
            .await
            .map_err(WriteFailure::projection)
    }
    async fn read_frame(
        &self,
        stream: &RawQuicStream,
    ) -> std::result::Result<Option<Vec<u8>>, FrameFailure> {
        let mut header = [0; 8];
        let mut used = 0;
        while used < 8 {
            match stream
                .read_current(8 - used, &self.native_cancellation)
                .await
            {
                Ok(Some(bytes)) => {
                    header[used..used + bytes.len()].copy_from_slice(&bytes);
                    used += bytes.len();
                }
                Ok(None) if used == 0 => return Ok(None),
                Ok(None) => return Err(FrameFailure::Truncated),
                Err(failure) => return Err(FrameFailure::Native(failure)),
            }
        }
        let length = u32::from_be_bytes(header[..4].try_into().map_err(|_| FrameFailure::Boundary)?)
            as usize;
        let maximum = if self.live.load(Ordering::Acquire) {
            self.live_maximum.load(Ordering::Acquire)
        } else {
            self.maximum
        };
        if header[5..8] != [0; 3] || length > maximum.saturating_sub(8) {
            return Err(FrameFailure::Boundary);
        }
        let mut wire = Vec::with_capacity(length + 8);
        wire.extend_from_slice(&header);
        while wire.len() < length + 8 {
            let remaining = (length + 8 - wire.len()).min(65536);
            match stream
                .read_current(remaining, &self.native_cancellation)
                .await
            {
                Ok(Some(bytes)) => wire.extend_from_slice(&bytes),
                Ok(None) => return Err(FrameFailure::Truncated),
                Err(failure) => return Err(FrameFailure::Native(failure)),
            }
        }
        Ok(Some(wire))
    }
    pub(super) fn position_preparation_limits(maximum: usize) -> ConnectResult<ResourceLimits> {
        Ok(ResourceLimits {
            sdk_bytes: (maximum as u64)
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(2048))
                .ok_or(ConnectError::Capacity)?,
            items: 4,
            tasks: 4,
            work_slots: 4,
            timers: 3,
            native_handles: 1,
            ..ResourceLimits::default()
        })
    }
    fn ingress_preparation_limits(maximum: usize) -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: maximum as u64 + 2048,
            items: 1,
            tasks: 1,
            work_slots: 1,
            timers: 1,
            native_handles: 1,
            ..ResourceLimits::default()
        }
    }
    pub(super) fn application_preparation_limits(
        maximum: usize,
        profile: u8,
    ) -> ConnectResult<ResourceLimits> {
        let mut limits = Self::ingress_preparation_limits(maximum);
        for _ in 0..(usize::from(profile != 0) + usize::from(profile == 2)) {
            limits = candidate_add_limits(limits, Self::position_preparation_limits(maximum)?)?;
        }
        Ok(limits)
    }
    pub(super) fn fund_application(
        &self,
        account: &ResourceAccount,
        maximum: usize,
        profile: u8,
        mut charge: ResourceCharge,
    ) -> ConnectResult<()> {
        if !self.account()?.same_owner(account)
            || !charge.matches(
                account,
                Self::application_preparation_limits(maximum, profile)?,
            )
        {
            return Err(ConnectError::Configuration);
        }
        let directory = self.streams.lock().expect("native stream directory");
        let mut slot = self
            .bootstrap_charge
            .lock()
            .expect("native bootstrap backing");
        let mut management = self
            .management_charge
            .lock()
            .expect("native management backing");
        let mut ingress = self.ingress_charge.lock().expect("native ingress backing");
        if slot.is_some()
            || management.is_some()
            || ingress.is_some()
            || !directory.is_empty()
            || self.live.load(Ordering::Acquire)
        {
            return Err(ConnectError::Configuration);
        }
        let position_limits = Self::position_preparation_limits(maximum)?;
        let bootstrap = (profile != 0)
            .then(|| charge.split(position_limits))
            .transpose()?;
        let protected = (profile == 2)
            .then(|| charge.split(position_limits))
            .transpose()?;
        *slot = bootstrap;
        *management = protected.map(Arc::new);
        *ingress = Some(Arc::new(charge));
        Ok(())
    }
    fn input_charge(&self) -> ConnectResult<Arc<ResourceCharge>> {
        let backing = self.ingress_charge.lock().expect("native ingress backing");
        let charge = backing.as_ref().ok_or(ConnectError::Configuration)?;
        if Arc::strong_count(charge) == 1 {
            return Ok(charge.clone());
        }
        // One original input position remains available without ordinary
        // admission. Additional concurrent prefixes use the ordinary account.
        Ok(Arc::new(self.account()?.reserve(
            Self::ingress_preparation_limits(self.live_maximum.load(Ordering::Acquire)),
        )?))
    }
    fn prepare_management(&self, scope: u64) -> ConnectResult<()> {
        let directory = self.streams.lock().expect("native stream directory");
        let backing = self
            .management_charge
            .lock()
            .expect("native management backing");
        let charge = backing.as_ref().ok_or(ConnectError::Configuration)?;
        if Arc::strong_count(charge) != 1 || directory.contains_key(&scope) {
            return Err(ConnectError::Capacity);
        }
        self.management_scope.store(scope, Ordering::Release);
        Ok(())
    }
    fn reserve_position(
        &self,
        scope: u64,
        binding: Option<NativeStreamBinding>,
    ) -> ConnectResult<(Arc<Position>, mpsc::Receiver<Publication>)> {
        let mut directory = self.streams.lock().expect("native stream directory");
        let management = binding
            .as_ref()
            .is_some_and(NativeStreamBinding::is_management)
            || self.management_scope.load(Ordering::Acquire) == scope;
        let management_backing = self
            .management_charge
            .lock()
            .expect("native management backing");
        let protected = usize::from(
            !management
                && management_backing.is_some()
                && !directory.contains_key(&self.management_scope.load(Ordering::Acquire)),
        );
        if directory.contains_key(&scope)
            || directory.len()
                >= self
                    .capacity
                    .load(Ordering::Acquire)
                    .saturating_sub(protected)
        {
            return Err(ConnectError::Capacity);
        }
        let account = self.account()?;
        let limits = Self::position_preparation_limits(self.live_maximum.load(Ordering::Acquire))?;
        let prepaid = if scope == 1 {
            self.bootstrap_charge
                .lock()
                .expect("native bootstrap backing")
                .take()
        } else {
            None
        };
        let charge = if management {
            let charge = management_backing
                .as_ref()
                .ok_or(ConnectError::Configuration)?;
            if Arc::strong_count(charge) != 1 || !charge.matches(&account, limits) {
                return Err(ConnectError::Capacity);
            }
            self.management_scope.store(scope, Ordering::Release);
            charge.clone()
        } else if let Some(charge) = prepaid {
            if !charge.matches(&account, limits) {
                return Err(ConnectError::Configuration);
            }
            Arc::new(charge)
        } else {
            Arc::new(account.reserve(limits)?)
        };
        let (commands, incoming) = mpsc::channel(1);
        let position = Arc::new(Position {
            commands,
            pending: AtomicUsize::new(0),
            physical_done: AtomicBool::new(false),
            binding: OnceLock::new(),
            _charge: charge,
        });
        if let Some(binding) = binding {
            let _ = position.binding.set(binding);
        }
        directory.insert(scope, position.clone());
        Ok((position, incoming))
    }
    fn submit(
        self: &Arc<Self>,
        wire: Vec<u8>,
    ) -> ConnectResult<oneshot::Receiver<ConnectResult<()>>> {
        self.check()?;
        let live = self.live.load(Ordering::Acquire);
        let maximum = if live {
            self.live_maximum.load(Ordering::Acquire)
        } else {
            self.maximum
        };
        if wire.len() < 8 || wire.len() > maximum {
            return Err(ConnectError::Protocol);
        }
        if live && self.relay_mode.load(Ordering::Acquire) && !matches!(wire[4], 6 | 9 | 11..=15) {
            return Err(ConnectError::Protocol);
        }
        let (reply, wait) = oneshot::channel();
        if !live || matches!(wire[4], 6 | 9 | 11..=15) {
            if self.live.load(Ordering::Acquire) && (wire.len() < 44 || wire[12..20] != [0; 8]) {
                return Err(ConnectError::Protocol);
            }
            self.maintenance_pending
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ConnectError::Capacity)?;
            if self.commands.try_send(Publication { wire, reply }).is_err() {
                self.maintenance_pending.store(0, Ordering::Release);
                return Err(ConnectError::Carrier);
            }
        } else {
            if wire.len() < 44
                || !matches!(wire[4], 7 | 8)
                || wire.len() > self.live_maximum.load(Ordering::Acquire)
            {
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
            let existing = self
                .streams
                .lock()
                .expect("native stream directory")
                .get(&scope)
                .cloned();
            let position = match existing {
                Some(position) if wire[4] == 8 => position,
                None if wire[4] == 7 => {
                    let (position, input) = self.reserve_position(scope, None)?;
                    let worker = self.clone();
                    let original = position.clone();
                    self.workers.spawn(async move {
                        match match worker.native() {
                            Ok(native) => native.open_stream(&worker.native_cancellation).await,
                            Err(_) => Err(RawQuicError::Closed),
                        } {
                            Ok(stream) => {
                                worker
                                    .clone()
                                    .drive_application(scope, original, stream, input, None)
                                    .await
                            }
                            Err(_) => {
                                original.physical_done.store(true, Ordering::Release);
                                worker.close();
                            }
                        }
                    });
                    position
                }
                _ => return Err(ConnectError::Protocol),
            };
            position
                .pending
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ConnectError::Capacity)?;
            if position
                .commands
                .try_send(Publication { wire, reply })
                .is_err()
            {
                position.pending.store(0, Ordering::Release);
                return Err(ConnectError::Carrier);
            }
        }
        Ok(wait)
    }
    pub(super) async fn send(self: &Arc<Self>, wire: Vec<u8>) -> ConnectResult<()> {
        self.submit(wire)?
            .await
            .map_err(|_| ConnectError::Carrier)??;
        self.check()
    }
    async fn accept_applications(self: Arc<Self>) {
        if !self.wait_for_endpoint_role().await || !self.wait_until_live().await {
            return;
        }
        loop {
            let Some(slots) = self.input_slots.get() else {
                self.close();
                return;
            };
            let permit = tokio::select! {_=self.cancellation.cancelled()=>return,result=slots.clone().acquire_owned()=>match result{Ok(permit)=>permit,Err(_)=>return}};
            // Ordinary saturation waits for the original prepaid input to
            // return. It cannot close a healthy Session or consume M backing.
            let charge = loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                match self.input_charge() {
                    Ok(charge) => break charge,
                    Err(ConnectError::Capacity) => {
                        tokio::select! {
                            _ = self.cancellation.cancelled() => return,
                            _ = changed => {},
                        }
                    }
                    Err(_) => {
                        self.close();
                        return;
                    }
                }
            };
            let ingress = IngressPosition {
                provider: self.clone(),
                charge: Some(charge),
                permit: Some(permit),
            };
            let stream = match match self.native() {
                Ok(native) => native.accept_stream(&self.native_cancellation).await,
                Err(_) => Err(RawQuicError::Closed),
            } {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let worker = self.clone();
            self.workers.spawn(async move {
                let first = match tokio::time::timeout(
                    worker.publication_timeout,
                    worker.read_frame(&stream),
                )
                .await
                {
                    Ok(Ok(Some(wire))) if wire.len() >= 44 && wire[4] == 7 => wire,
                    _ => {
                        stream.cancel_current();
                        worker.close();
                        stream.wait_termination_current().await;
                        return;
                    }
                };
                let Some(receiver) = worker.receiver.get() else {
                    worker.close();
                    stream.cancel_current();
                    stream.wait_termination_current().await;
                    return;
                };
                let admitted = receiver.native_prefix(&first, |binding| {
                    worker
                        .reserve_position(binding.scope(), Some(binding.clone()))
                        .ok()
                        .map(|(position, input)| (binding, position, input))
                });
                let (binding, position, input) = match admitted {
                    Ok(Some(admitted)) => admitted,
                    Ok(None) => {
                        let _ = stream.reset_write_current().await;
                        let _ = stream.stop_sending_current(false).await;
                        stream.cancel_current();
                        stream.wait_termination_current().await;
                        return;
                    }
                    Err(_) => {
                        worker.close();
                        stream.cancel_current();
                        stream.wait_termination_current().await;
                        return;
                    }
                };
                let scope = binding.scope();
                // The authenticated position now owns its complete reader
                // vector. Return only the original unbound ingress position.
                drop(first);
                drop(ingress);
                worker
                    .drive_application(scope, position, stream, input, Some(binding))
                    .await;
            });
        }
    }
    async fn drive_application(
        self: Arc<Self>,
        scope: u64,
        position: Arc<Position>,
        stream: RawQuicStream,
        commands: mpsc::Receiver<Publication>,
        incoming_binding: Option<NativeStreamBinding>,
    ) {
        self.drive_application_body(scope, &position, &stream, commands, incoming_binding)
            .await;
        stream.cancel_current();
        stream.wait_termination_current().await;
        position.pending.store(0, Ordering::Release);
        position.physical_done.store(true, Ordering::Release);
        self.streams
            .lock()
            .expect("native stream directory")
            .remove(&scope);
    }
    async fn drive_application_body(
        &self,
        scope: u64,
        position: &Position,
        stream: &RawQuicStream,
        mut commands: mpsc::Receiver<Publication>,
        incoming_binding: Option<NativeStreamBinding>,
    ) {
        let binding = match incoming_binding {
            Some(binding) => binding,
            None => {
                let first = match tokio::select! {_=self.cancellation.cancelled()=>None,command=commands.recv()=>command}
                {
                    Some(first) => first,
                    None => {
                        stream.cancel_current();
                        return;
                    }
                };
                let result = self.write(stream, &first.wire).await;
                position.pending.store(0, Ordering::Release);
                let failed = result.is_err();
                let _ = first.reply.send(result);
                if failed {
                    self.close();
                    stream.cancel_current();
                    stream.wait_termination_current().await;
                    position.physical_done.store(true, Ordering::Release);
                    return;
                }
                loop {
                    if self.cancellation.is_cancelled() {
                        stream.cancel_current();
                        return;
                    }
                    if let Some(binding) = position.binding.get() {
                        break binding.clone();
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        };
        let writing = async {
            loop {
                tokio::select! {
                    _=self.cancellation.cancelled()=>return,
                    command=commands.recv()=>match command {
                        Some(command)=>{
                            let outcome=self.write_outcome(stream,&command.wire).await;
                            let normal=outcome.as_ref().err().is_some_and(WriteFailure::normal);
                            let failed=outcome.is_err();
                            if failed{self.failed_normal.store(normal,Ordering::Release);self.failed_scope.store(scope,Ordering::Release);}
                            position.pending.store(0,Ordering::Release);
                            let _=command.reply.send(outcome.map_err(WriteFailure::projection));
                            if failed{binding.native_hint(true,normal);return;}
                        },None=>return,
                    },
                    _=tokio::time::sleep(Duration::from_millis(2))=>{
                        let facts=match binding.projection(){Ok(facts)=>facts,Err(_)=>return};
                        if facts.reset_write {let _=stream.reset_write_current().await;return;}
                        if facts.close_write {let _=stream.close_write_current().await;return;}
                    }
                }
            }
        };
        let reading = async {
            loop {
                let facts = match binding.projection() {
                    Ok(facts) => facts,
                    Err(_) => return,
                };
                if facts.stop_read {
                    let _ = stream.stop_sending_current(facts.normal_read).await;
                    return;
                }
                if !facts.accepted {
                    tokio::select! {_=self.cancellation.cancelled()=>return,_=tokio::time::sleep(Duration::from_millis(2))=>{}};
                    continue;
                }
                match self.read_frame(stream).await {
                    Ok(Some(wire)) => {
                        if binding.receive(&wire).is_err() {
                            binding.reset();
                            return;
                        }
                    }
                    // Native termination is a direction fact. Authenticated
                    // maintenance still decides rejection/FIN/STOPPED/DRAINED.
                    Ok(None) => {
                        binding.native_hint(false, true);
                        return;
                    }
                    Err(FrameFailure::Native(RawQuicError::NormalDrained)) => {
                        binding.native_hint(false, true);
                        return;
                    }
                    Err(_) => {
                        binding.native_hint(false, false);
                        return;
                    }
                }
            }
        };
        let actions = async {
            loop {
                tokio::select! {_=self.cancellation.cancelled()=>return,_=tokio::time::sleep(Duration::from_millis(2))=>{}}
                let facts = match binding.projection() {
                    Ok(facts) => facts,
                    Err(_) => return,
                };
                if facts.stop_read {
                    let _ = stream.stop_sending_current(facts.normal_read).await;
                }
                if facts.reset_write {
                    let _ = stream.reset_write_current().await;
                } else if facts.close_write {
                    let _ = stream.close_write_current().await;
                }
                if facts.retired {
                    return;
                }
            }
        };
        let sending = async {
            tokio::select! {
                _=self.cancellation.cancelled()=>{},
                failure=stream.wait_write_failure()=>match failure {
                    Some(flowersec_native_transport::NativeDirectionFailure::NormalDrained)=>binding.native_hint(true,true),
                    Some(flowersec_native_transport::NativeDirectionFailure::DirectionReset)=>binding.native_hint(true,false),
                    None=>{},
                },
            }
        };
        tokio::join!(writing, reading, actions, sending);
    }
}
pub(super) struct ReceiverGuard(Arc<Provider>);
impl Drop for ReceiverGuard {
    fn drop(&mut self) {
        self.0.receivers.fetch_sub(1, Ordering::AcqRel);
        self.0.cleanup_changed.notify_waiters();
    }
}
pub(super) struct Transport {
    provider: Arc<Provider>,
    _keys: IdentityKeys,
    _namespaces: Vec<Arc<Namespace>>,
}
impl Transport {
    pub(super) fn new(
        provider: Arc<Provider>,
        keys: IdentityKeys,
        namespaces: Vec<Arc<Namespace>>,
    ) -> Self {
        Self {
            provider,
            _keys: keys,
            _namespaces: namespaces,
        }
    }
}
impl RecordPublisher for Transport {
    fn prepare_management_stream(&mut self, scope: u64) -> Result<()> {
        self.provider
            .prepare_management(scope)
            .map_err(|_| CryptoError::Capacity)
    }
    fn try_claim_data(&mut self, scope: u64, maximum: usize) -> Result<DataPublicationClaim> {
        self.provider.check().map_err(|_| CryptoError::State)?;
        if scope == 0 || maximum > self.provider.live_maximum.load(Ordering::Acquire) {
            return Err(CryptoError::Capacity);
        }
        self.provider
            .data_slot
            .compare_exchange(0, scope, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CryptoError::Capacity)?;
        let slot = self.provider.data_slot.clone();
        Ok(DataPublicationClaim::new(move || {
            slot.store(0, Ordering::Release);
        }))
    }
    fn data_publication_permitted(&self, scope: u64) -> bool {
        let claimed = self.provider.data_slot.load(Ordering::Acquire);
        claimed == 0 || claimed == scope
    }
    fn liveness_stall_generation(&self) -> u64 {
        self.provider.stall_generation.load(Ordering::Acquire)
    }
    fn liveness_stalled(&self) -> bool {
        self.provider.read_stalled.load(Ordering::Acquire)
    }
    fn failed_stream_publication(&self, scope: u64) -> Option<bool> {
        (scope != 0 && self.provider.failed_scope.load(Ordering::Acquire) == scope)
            .then(|| self.provider.failed_normal.load(Ordering::Acquire))
    }
    fn publish(&mut self, wire: &[u8]) -> Result<()> {
        self.provider.failed_scope.store(0, Ordering::Release);
        let wait = self
            .provider
            .submit(wire.to_vec())
            .map_err(|_| CryptoError::State)?;
        let receive = || {
            wait.blocking_recv()
                .map_err(|_| CryptoError::State)?
                .map_err(|_| CryptoError::State)
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(receive)
            }
            Ok(_) => Err(CryptoError::Configuration),
            Err(_) => receive(),
        }
    }
}
impl SessionTransport for Transport {
    fn close_signal(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let provider = self.provider.clone();
        Some(Arc::new(move || provider.close()))
    }
    fn cleanup_signal(&self) -> Option<Arc<dyn Fn() -> CleanupStatus + Send + Sync>> {
        let provider = self.provider.clone();
        Some(Arc::new(move || provider.cleanup()))
    }
    fn datagram_maximum(&self) -> Option<usize> {
        self.provider.native().ok()?.datagram_maximum()
    }
    fn publish_datagram(
        &mut self,
        wire: Vec<u8>,
        original: DatagramLease,
    ) -> crate::transport::UnreliableSendOutcome {
        use crate::transport::UnreliableSendOutcome;
        if self.provider.check().is_err() {
            return UnreliableSendOutcome::DroppedCarrier;
        }
        let Some(submission) = self
            .provider
            .native()
            .ok()
            .and_then(|native| native.submit_datagram(wire))
        else {
            return UnreliableSendOutcome::DroppedCarrier;
        };
        self.provider.workers.spawn(async move {
            submission.completion().await;
            drop(original);
        });
        UnreliableSendOutcome::Accepted
    }
    fn capture_native_bindings(&mut self, session: &mut ReliableSession) -> Result<()> {
        let Some(receiver) = self.provider.receiver.get() else {
            return Ok(());
        };
        let directory = self
            .provider
            .streams
            .lock()
            .expect("native stream directory");
        for (scope, position) in directory.iter() {
            if position.binding.get().is_none() {
                let original = session.capture_native_binding(*scope)?;
                position
                    .binding
                    .set(receiver.original_native_binding(original))
                    .map_err(|_| CryptoError::State)?;
            }
        }
        Ok(())
    }
    fn close(&mut self) {
        self.provider.close();
    }
    fn cleanup_status(&self) -> CleanupStatus {
        self.provider.cleanup()
    }
    fn stream_cleanup_status(&self, scope: u64) -> CleanupStatus {
        let directory = self
            .provider
            .streams
            .lock()
            .expect("native stream directory");
        let complete = directory
            .get(&scope)
            .is_none_or(|position| position.physical_done.load(Ordering::Acquire));
        CleanupStatus {
            complete,
            cleanup_incomplete: false,
            pending_callbacks: u64::from(!complete),
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.provider.close();
    }
}

#[cfg(test)]
#[path = "native_v4_role_tests.rs"]
mod role_tests;
