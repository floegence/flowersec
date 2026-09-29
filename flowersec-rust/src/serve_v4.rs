//! Original native WSS listener, durable accepted establishment and publication
//! gate. Every socket enters the gate before TLS or application work starts.
use super::*;
use crate::{api_v4::CleanupStatus, pool_v4::admission::SQLiteAdmissionAuthority};
use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::{
    net::TcpListener,
    sync::{Notify, mpsc},
};
#[path = "serve_v4_drain.rs"]
mod drain;
use drain::DrainState;
#[path = "serve_v4_application.rs"]
mod application;
pub use crate::application_lifetime_v4::ApplicationLimits;
use crate::application_lifetime_v4::{ApplicationLifetime, CallbackKind};
use application::Invocation;
pub use application::{
    ApplicationAuthorization, ApplicationAuthorizationLease, ApplicationBinding,
    AuthenticatedRequestContext, AuthorizeApplicationResult, HandlerPlan, HandlerPlanOptions,
    RawStreamHandler, RawStreamRegistration, RequestAuthorization, ServeCallbacks, ServeError,
    ServeFailure, ServeReleaseContext, ServeRequestContext, SessionAcceptance, StreamAuthorization,
    StreamDispatch,
};
pub use drain::{ServeDrainOperation, ServeDrainResult};
const MAX_OBSERVERS: usize = 16;
fn serve_charge(max_connections: usize) -> ResourceLimits {
    ResourceLimits {
        sdk_bytes: 327680 + max_connections as u64 * 4096 + MAX_OBSERVERS as u64 * 256,
        provider_bytes: 262144,
        items: max_connections as u64 * 3 + 1 + MAX_OBSERVERS as u64,
        tasks: 1 + MAX_OBSERVERS as u64,
        timers: 1,
        native_handles: 1,
        work_slots: 1 + MAX_OBSERVERS as u64,
        ..ResourceLimits::default()
    }
}

/// Bounded trusted material lookup. The HELLO is unauthenticated lookup input;
/// the SDK independently verifies every returned credential and actual binding.
#[async_trait]
pub trait AcceptedMaterialSource: fmt::Debug + Send + Sync + 'static {
    async fn resolve(
        &self,
        client_hello: &[u8],
        cancellation: CancellationToken,
    ) -> ConnectResult<PoolCredentialBytes>;
}
/// Secret TLS provisioning bytes are never logged or retained in diagnostics.
pub struct WssServerIdentity {
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
}
impl fmt::Debug for WssServerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("V4WssServerIdentity { <redacted> }")
    }
}
impl Drop for WssServerIdentity {
    fn drop(&mut self) {
        self.private_key_der.zeroize();
    }
}
#[derive(Clone, Debug)]
pub struct WssServeOptions {
    pub callbacks: Arc<dyn ServeCallbacks>,
    pub application_limits: ApplicationLimits,
    pub cancellation: CancellationToken,
    pub binding_mode: BindingMode,
    pub listen_address: std::net::SocketAddr,
    pub host: String,
    pub origin: Option<String>,
    pub max_connections: usize,
    pub max_frame_bytes: usize,
    pub handshake_timeout: Duration,
    pub publication_timeout: Duration,
    pub queue_messages: usize,
    pub prepare_bytes: usize,
    pub native_runtime_bytes: u64,
}
#[derive(Clone)]
pub(super) struct SocketPolicy {
    pub(super) binding_mode: BindingMode,
    pub(super) tls: Arc<rustls::ServerConfig>,
    pub(super) host: String,
    pub(super) authority: String,
    pub(super) allow_absent_origin: bool,
    pub(super) origins: Vec<String>,
    pub(super) validity: (u64, u64),
    pub(super) maximum: usize,
    pub(super) publication_timeout: Duration,
    pub(super) queue_messages: usize,
    pub(super) prepare_bytes: usize,
}
struct Slot {
    generation: u64,
    cancel: CancellationToken,
    session: Option<Session>,
    provider: Option<Arc<wss::Provider>>,
    pending: bool,
    drain: Option<DrainOperation>,
    drain_done: bool,
    drain_starting: bool,
    tail_done: bool,
    invocation: Option<Arc<Invocation>>,
}
struct Gate {
    closed: bool,
    drain: Option<DrainState>,
    slots: Vec<Option<Slot>>,
    generation: u64,
}
struct ServeOwner {
    root: Arc<EnvironmentRoot>,
    gate: Mutex<Gate>,
    changed: Notify,
    stop: CancellationToken,
    pump_done: AtomicBool,
    charge: Mutex<Option<EnvironmentCharge>>,
    cleanup_deadline: Mutex<Option<Instant>>,
    observers: AtomicUsize,
}
impl fmt::Debug for ServeOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServeOwner { <opaque> }")
    }
}
/// One listener and all Sessions published by it. Cloned application Session
/// handles remain children of this original owner until physical cleanup ends.
#[derive(Debug)]
pub struct ServeHandle {
    owner: Arc<ServeOwner>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<Session>>,
    address: std::net::SocketAddr,
}
impl ServeHandle {
    pub fn local_address(&self) -> std::net::SocketAddr {
        self.address
    }
    pub async fn accept(&self) -> Option<Session> {
        self.incoming.lock().await.recv().await
    }
    pub fn close(&self) {
        self.owner.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.owner.cleanup()
    }
    pub async fn wait_cleanup(&self) -> ConnectResult<CleanupStatus> {
        let status = self.cleanup_status();
        if status.complete || status.cleanup_incomplete {
            return Ok(status);
        }
        let Some(_wait) = self.owner.observe()? else {
            return Ok(self.cleanup_status());
        };
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete || status.cleanup_incomplete {
                return Ok(status);
            }
            notified.await;
        }
    }
}
impl Drop for ServeHandle {
    fn drop(&mut self) {
        self.owner.close();
    }
}
impl ServeOwner {
    fn close(&self) {
        self.close_with_cause(crate::transport::SessionError::Closed);
    }
    fn close_with_cause(&self, cause: crate::transport::SessionError) {
        let sessions = {
            let mut gate = self.gate.lock().expect("Serve publication gate");
            gate.closed = true;
            let drain = gate.drain.get_or_insert_with(|| {
                let mut drain = DrainState::closed();
                drain.error = Some(cause);
                drain
            });
            if drain.outcome == DrainOutcome::Pending {
                drain.outcome = DrainOutcome::Failed;
                drain.error.get_or_insert(cause);
            }
            let mut sessions = Vec::with_capacity(gate.slots.len());
            for slot in gate.slots.iter().flatten() {
                slot.cancel.cancel();
                if let Some(session) = &slot.session {
                    sessions.push(session.clone());
                }
            }
            sessions
        };
        self.stop.cancel();
        let mut deadline = self
            .cleanup_deadline
            .lock()
            .expect("Serve cleanup deadline");
        if deadline.is_none() {
            *deadline = Instant::now().checked_add(Duration::from_secs(5));
        }
        drop(deadline);
        for session in sessions {
            session.close();
        }
        let invocations: Vec<_> = self
            .gate
            .lock()
            .expect("Serve publication gate")
            .slots
            .iter()
            .flatten()
            .filter_map(|slot| slot.invocation.clone())
            .collect();
        for invocation in invocations {
            invocation.revoke();
        }
        self.changed.notify_waiters();
    }
    fn ingress_stopped(&self) {
        if !self.gate.lock().expect("Serve publication gate").closed {
            self.close_with_cause(crate::transport::SessionError::OperationFailed);
        }
    }
    fn check(&self, index: usize, generation: u64) -> ConnectResult<()> {
        if self.root.is_closed() {
            return Err(ConnectError::Canceled);
        }
        let gate = self.gate.lock().expect("Serve publication gate");
        if gate.closed
            || !gate.slots[index].as_ref().is_some_and(|s| {
                s.generation == generation && s.pending && !s.cancel.is_cancelled()
            })
        {
            return Err(ConnectError::Canceled);
        }
        Ok(())
    }
    fn finish(&self, index: usize, generation: u64) {
        let mut gate = self.gate.lock().expect("Serve publication gate");
        if let Some(slot) = gate.slots[index].as_mut()
            && slot.generation == generation
        {
            slot.tail_done = true;
            if let Some(invocation) = &slot.invocation
                && !invocation.complete.load(Ordering::Acquire)
            {
                invocation.failed_cleanup.store(true, Ordering::Release);
            }
        }
        drop(gate);
        self.close_finished_child(index, generation);
        self.observe_child(index, generation);
        self.collect_finished();
        self.finish_drain();
        self.changed.notify_waiters();
    }
    fn cleanup(&self) -> CleanupStatus {
        if self.root.is_closed() {
            self.close();
        }
        let gate = self.gate.lock().expect("Serve publication gate");
        let pending = gate.slots.iter().flatten().count();
        let application_incomplete = gate.slots.iter().flatten().any(|s| {
            s.invocation
                .as_ref()
                .is_some_and(|i| i.failed_cleanup.load(Ordering::Acquire))
        });
        let complete = gate.closed && pending == 0 && self.pump_done.load(Ordering::Acquire);
        drop(gate);
        if complete {
            let mut charge = self.charge.lock().expect("Serve charge");
            if self.observers.load(Ordering::Acquire) == 0 {
                charge.take();
            }
        }
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete
                && (application_incomplete
                    || self
                        .cleanup_deadline
                        .lock()
                        .expect("Serve cleanup deadline")
                        .is_some_and(|d| Instant::now() >= d)),
            pending_callbacks: pending as u64,
        }
    }
}
struct PendingTail {
    owner: Arc<ServeOwner>,
    index: usize,
    generation: u64,
}
impl Drop for PendingTail {
    fn drop(&mut self) {
        self.owner.finish(self.index, self.generation);
    }
}
struct PumpTail(Arc<ServeOwner>);
impl Drop for PumpTail {
    fn drop(&mut self) {
        let closed = self.0.gate.lock().expect("Serve publication gate").closed;
        if !closed {
            self.0.close();
        }
        self.0.pump_done.store(true, Ordering::Release);
        self.0.cleanup();
        self.0.changed.notify_waiters();
    }
}
struct Configuration {
    keys: IdentityKeys,
    namespaces: Vec<Arc<Namespace>>,
    source: Arc<dyn AcceptedMaterialSource>,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: WssServeOptions,
    socket: SocketPolicy,
    certificate: Vec<u8>,
}
pub(crate) async fn serve(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    source: Arc<dyn AcceptedMaterialSource>,
    admission: Arc<SQLiteAdmissionAuthority>,
    identity: WssServerIdentity,
    options: WssServeOptions,
) -> ConnectResult<ServeHandle> {
    options.application_limits.charge()?;
    if options.cancellation.is_cancelled() {
        return Err(ConnectError::Canceled);
    }
    if !Arc::ptr_eq(&root, &keys.owner.environment)
        || !admission.belongs_to(&root)
        || namespaces.is_empty()
        || namespaces.len() > 3
        || !(1..=64).contains(&options.max_connections)
        || !(65536..=1048576).contains(&options.max_frame_bytes)
        || options.handshake_timeout.is_zero()
        || options.handshake_timeout > Duration::from_secs(30)
        || options.publication_timeout.is_zero()
        || options.publication_timeout > Duration::from_secs(5)
        || !(1..=64).contains(&options.queue_messages)
        || !(16384..=262144).contains(&options.prepare_bytes)
        || options.native_runtime_bytes
            < ((options.max_frame_bytes + 8) * 2 + options.prepare_bytes + 196608) as u64
        || options.native_runtime_bytes < 1 << 20
        || options.host.is_empty()
        || options.host.len() > 253
        || identity.certificate_chain_der.is_empty()
        || identity.certificate_chain_der.len() > 16
        || identity
            .certificate_chain_der
            .iter()
            .map(Vec::len)
            .sum::<usize>()
            > 262144
        || identity.private_key_der.len() > 16384
        || !tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        return Err(ConnectError::Configuration);
    }
    // Derive the only accepted origin from trusted listener configuration.
    if options.origin.as_ref().is_some_and(|o| {
        o.len() > 2048
            || o.parse::<tokio_tungstenite::tungstenite::http::HeaderValue>()
                .is_err()
    }) {
        return Err(ConnectError::Configuration);
    }
    let charge = root.reserve_environment(serve_charge(options.max_connections))?;
    let certificate = identity.certificate_chain_der[0].clone();
    let validity = wss::interval(&certificate, root.sample()?).map_err(|_| ConnectError::Tls)?;
    let key = PrivateKeyDer::try_from(identity.private_key_der.clone())
        .map_err(|_| ConnectError::Configuration)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| ConnectError::Configuration)?
    .with_no_client_auth()
    .with_single_cert(
        identity
            .certificate_chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect(),
        key,
    )
    .map_err(|_| ConnectError::Tls)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let listener = TcpListener::bind(options.listen_address)
        .await
        .map_err(|_| ConnectError::Carrier)?;
    let address = listener.local_addr().map_err(|_| ConnectError::Carrier)?;
    let authority = if options.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", options.host, address.port())
    } else {
        format!("{}:{}", options.host, address.port())
    };
    let socket = SocketPolicy {
        binding_mode: options.binding_mode,
        tls: Arc::new(tls),
        host: options.host.clone(),
        authority,
        allow_absent_origin: options.origin.is_none(),
        origins: options.origin.clone().into_iter().collect(),
        validity,
        maximum: options.max_frame_bytes + 8,
        publication_timeout: options.publication_timeout,
        queue_messages: options.queue_messages,
        prepare_bytes: options.prepare_bytes,
    };
    let owner = Arc::new(ServeOwner {
        root,
        gate: Mutex::new(Gate {
            closed: false,
            drain: None,
            slots: (0..options.max_connections).map(|_| None).collect(),
            generation: 0,
        }),
        changed: Notify::new(),
        stop: CancellationToken::new(),
        pump_done: AtomicBool::new(false),
        charge: Mutex::new(Some(charge)),
        cleanup_deadline: Mutex::new(None),
        observers: AtomicUsize::new(0),
    });
    let (published, incoming) = mpsc::channel(options.max_connections);
    let config = Arc::new(Configuration {
        keys,
        namespaces,
        source,
        admission,
        options,
        socket,
        certificate,
    });
    tokio::spawn(pump(owner.clone(), config, listener, published));
    Ok(ServeHandle {
        owner,
        incoming: tokio::sync::Mutex::new(incoming),
        address,
    })
}
async fn pump(
    owner: Arc<ServeOwner>,
    config: Arc<Configuration>,
    listener: TcpListener,
    published: mpsc::Sender<Session>,
) {
    let _tail = PumpTail(owner.clone());
    loop {
        owner.collect_finished();
        if owner.root.is_closed() {
            owner.close();
            break;
        }
        if config.options.cancellation.is_cancelled() {
            owner.close();
            break;
        }
        if owner.stop.is_cancelled() {
            break;
        }
        let free = {
            let gate = owner.gate.lock().expect("Serve publication gate");
            gate.slots.iter().position(Option::is_none)
        };
        let Some(index) = free else {
            tokio::select! { _=owner.stop.cancelled()=>{},_=owner.changed.notified()=>{},_=tokio::time::sleep(Duration::from_millis(10))=>{} };
            continue;
        };
        let maximum = config.socket.maximum;
        let reserve =
            || -> ConnectResult<(EnvironmentCharge, EnvironmentCharge, EnvironmentCharge)> {
                let charge = owner.root.reserve_environment(ResourceLimits {
                    sdk_bytes: (maximum * (config.options.queue_messages + 4)) as u64 + 819200,
                    provider_bytes: config.options.native_runtime_bytes
                        + config.options.prepare_bytes as u64
                        + 524288,
                    items: (config.options.queue_messages + 16) as u64,
                    work_slots: 8,
                    tasks: 6,
                    timers: 3,
                    connections: 1,
                    native_handles: 8,
                    ..ResourceLimits::default()
                })?;
                let tls = owner.root.reserve_environment(ResourceLimits {
                    tls_handshakes: 1,
                    ..ResourceLimits::default()
                })?;
                let application = owner.root.reserve_environment(ResourceLimits {
                    sdk_bytes: 32768 + config.options.application_limits.control_callback_bytes * 2,
                    items: 8,
                    tasks: 2,
                    work_slots: 2,
                    timers: 1,
                    ..ResourceLimits::default()
                })?;
                Ok((charge, tls, application))
            };
        let Ok((charge, tls_charge, application_charge)) = reserve() else {
            tokio::select! { _=owner.stop.cancelled()=>{},_=tokio::time::sleep(Duration::from_millis(10))=>{} };
            continue;
        };
        let cancel = CancellationToken::new();
        let invocation = Invocation::new(cancel.clone(), application_charge);
        let generation = {
            let mut gate = owner.gate.lock().expect("Serve publication gate");
            if gate.closed {
                break;
            }
            let Some(generation) = gate.generation.checked_add(1) else {
                drop(gate);
                owner.close();
                break;
            };
            gate.generation = generation;
            gate.slots[index] = Some(Slot {
                generation,
                cancel: cancel.clone(),
                session: None,
                provider: None,
                pending: true,
                drain: None,
                drain_done: false,
                drain_starting: false,
                tail_done: false,
                invocation: None,
            });
            generation
        };
        let tail = PendingTail {
            owner: owner.clone(),
            index,
            generation,
        };
        let accepted = loop {
            tokio::select! { _=config.options.cancellation.cancelled()=>{owner.close();break None},_=cancel.cancelled()=>break None,_=owner.stop.cancelled()=>break None,result=listener.accept()=>break result.ok(), _=tokio::time::sleep(Duration::from_millis(10))=>{owner.collect_finished();if owner.root.is_closed(){owner.close();break None;}} }
        };
        let Some((tcp, _)) = accepted else {
            drop(tail);
            break;
        };
        if owner.check(index, generation).is_err() {
            drop(tail);
            break;
        }
        let Ok(tcp) = tcp.into_std() else {
            drop(tail);
            continue;
        };
        owner.gate.lock().expect("Serve publication gate").slots[index]
            .as_mut()
            .expect("original ingress")
            .invocation = Some(invocation.clone());
        let owner = owner.clone();
        let config = config.clone();
        let published = published.clone();
        tokio::spawn(async move {
            let _tail = tail;
            let deadline = Instant::now() + config.options.handshake_timeout;
            let accepted = wss::Provider::accept(
                owner.root.clone(),
                tcp,
                config.socket.clone(),
                deadline,
                cancel.clone(),
                (charge, tls_charge),
                wss::AcceptHooks {
                    retain: |provider| {
                        let mut gate = owner.gate.lock().expect("Serve publication gate");
                        let slot = gate.slots[index].as_mut().expect("original ingress");
                        assert_eq!(slot.generation, generation);
                        slot.provider = Some(provider);
                    },
                    authorize: |request| {
                        let callbacks = config.options.callbacks.clone();
                        let owner = owner.clone();
                        Box::pin(async move {
                            owner.check(index, generation).map_err(ServeError::from)?;
                            application::callback(callbacks.authorize_request(request)).await
                        }) as wss::RequestAuthorizationFuture
                    },
                },
            )
            .await;
            let Ok((provider, mut incoming)) = accepted else {
                invocation
                    .finish(&config.options.callbacks, application::complete())
                    .await;
                invocation.retire();
                return;
            };
            let mut guard = ConnectGuard(Some(provider.clone()));
            let result = {
                let establishment = establish(
                    &owner,
                    &config,
                    (index, generation),
                    &provider,
                    &mut incoming,
                    deadline,
                    &invocation,
                );
                tokio::pin!(establishment);
                tokio::select! {
                    result = &mut establishment => result,
                    _ = cancel.cancelled() => { invocation.revoke(); provider.close(); establishment.await },
                    _ = tokio::time::sleep_until(deadline) => { invocation.revoke(); provider.close(); establishment.await },
                }
            };
            // A READY owner that failed attachment/publication is still an
            // original private child with a real maintenance worker.
            let mut child = owner.gate.lock().expect("Serve publication gate").slots[index]
                .as_ref()
                .and_then(|slot| slot.session.clone());
            if let Ok(ReadySession {
                session,
                received,
                application,
                handlers,
                authentication,
                publication,
            }) = result
            {
                let queue = published.clone().try_reserve_owned().ok();
                // This short gate orders the sole host publication against
                // first Drain/Close. It never traverses a Session lock.
                let accepted = {
                    let mut gate = owner.gate.lock().expect("Serve publication gate");
                    let closed = gate.closed;
                    if gate.slots[index]
                        .as_ref()
                        .is_some_and(|s| s.generation == generation && s.pending)
                    {
                        let slot = gate.slots[index].as_mut().expect("original ingress");
                        slot.session = Some(session.clone());
                        let accepted = !closed
                            && !cancel.is_cancelled()
                            && !owner.root.is_closed()
                            && queue.is_some();
                        slot.pending = !accepted;
                        accepted
                    } else {
                        false
                    }
                };
                if accepted {
                    invocation.published();
                    let receiver = session.receiver();
                    let tail = provider.receiver();
                    tokio::spawn(async move {
                        let _charge = received;
                        let _tail = tail;
                        while let Some(wire) = incoming.recv().await {
                            if receiver.receive(&wire).is_err() {
                                receiver.close();
                                return;
                            }
                        }
                        receiver.close();
                    });
                    guard.0 = None;
                    handlers.dispatch(session.clone(), authentication.binding(), application);
                    let result = application::callback(
                        config
                            .options
                            .callbacks
                            .on_session(session.clone(), authentication.clone()),
                    )
                    .await;
                    match result {
                        Ok(SessionAcceptance::Queue) => {
                            queue
                                .expect("prepaid publication position")
                                .send(session.clone());
                        }
                        Ok(SessionAcceptance::Retained) => {}
                        _ => session.close(),
                    }
                } else {
                    session.close();
                }
                drop(publication);
                child = Some(session);
            }
            drop(guard);
            if let Some(session) = &child {
                session.wait_termination().await;
            }
            invocation.revoke();
            provider.close();
            let cleanup_deadline = Instant::now() + Duration::from_secs(5);
            let core = loop {
                let status = child
                    .as_ref()
                    .map_or_else(|| provider.cleanup(), |s| s.core_cleanup_status());
                if status.complete || status.cleanup_incomplete {
                    break status;
                }
                if Instant::now() >= cleanup_deadline {
                    break CleanupStatus {
                        complete: false,
                        cleanup_incomplete: true,
                        pending_callbacks: status.pending_callbacks,
                    };
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            invocation.finish(&config.options.callbacks, core).await;
            if let Some(session) = child {
                loop {
                    if owner.root.is_closed() {
                        session.close();
                    }
                    if session.cleanup_status().complete {
                        break;
                    }
                    tokio::select! { _=owner.changed.notified()=>{},_=tokio::time::sleep(Duration::from_millis(10))=>{} }
                }
            }
            while !provider.cleanup().complete {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            invocation.retire();
        });
    }
    // Stop the listener before waiting for the existing children. The same
    // prepaid pump drives their bounded aggregate; Drain creates no wait task
    // per Session and never closes a healthy sibling on another child's error.
    drop(listener);
    drop(published);
    owner.ingress_stopped();
    loop {
        owner.poll_drain();
        if owner
            .gate
            .lock()
            .expect("Serve publication gate")
            .slots
            .iter()
            .all(Option::is_none)
        {
            break;
        }
        tokio::select! { _ = owner.changed.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
    }
}
fn check_hello(
    admission: &CredentialAdmission,
    artifact: Value<'_>,
    hello: Value<'_>,
    binding_mode: BindingMode,
) -> ConnectResult<()> {
    for (name, value) in [
        ("artifact_digest", admission.artifact_digest.as_slice()),
        ("candidate_id", admission.candidate_id.as_slice()),
        ("route_digest", admission.route_digest.as_slice()),
        ("attempt_id", admission.attempt_id.as_slice()),
    ] {
        expect_bytes(hello, "ClientHello", name, value)?;
    }
    same(
        hello,
        "ClientHello",
        "crypto_profile_id",
        artifact,
        "Artifact",
        "crypto_profile_id",
    )?;
    same(
        hello,
        "ClientHello",
        "client_nonce",
        artifact,
        "Artifact",
        "session_nonce",
    )?;
    if hello.u("ClientHello", "supported_binding_modes")? & (1 << binding_mode.wire()) == 0 {
        return Err(ConnectError::Protocol);
    }
    Ok(())
}
fn check_route(config: &Configuration, artifact: Value<'_>) -> ConnectResult<()> {
    let leg = artifact
        .field("Artifact", "candidates")?
        .at(0)?
        .field("Candidate", "direct_leg")?;
    if leg.u("Leg", "access_class")? != 0
        || leg.u("Leg", "carrier")? != 1
        || leg.field("Leg", "host")?.text()? != config.socket.host
        || leg.u("Leg", "port")?
            != config
                .socket
                .authority
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u64>().ok())
                .ok_or(ConnectError::Configuration)?
        || leg.field("Leg", "path")?.text()? != "/flowersec/v4/direct"
        || leg.field("Leg", "alpn")?.text()? != "http/1.1"
        || leg.field("Leg", "subprotocol")?.text()? != "flowersec.direct.v4"
        || artifact
            .field("Artifact", "session_contract")?
            .u("SessionContract", "max_frame")?
            > config.options.max_frame_bytes as u64
    {
        return Err(ConnectError::Authorization);
    }
    if let Some(policy) = leg.optional("Leg", "origin_policy")? {
        match &config.options.origin {
            None if !policy.field("OriginPolicy", "allow_absent")?.boolean()? => {
                return Err(ConnectError::Authorization);
            }
            Some(origin)
                if !policy
                    .field("OriginPolicy", "origins")?
                    .children()?
                    .any(|o| o.is_ok_and(|v| v.text() == Ok(origin))) =>
            {
                return Err(ConnectError::Authorization);
            }
            _ => {}
        }
    } else if config.options.origin.is_some() {
        return Err(ConnectError::Authorization);
    }
    let tls = leg.field("Leg", "tls_policy")?;
    if tls.u("TLSPolicy", "mode")? == 1 {
        wss::pin_profile(&config.certificate).map_err(|_| ConnectError::Tls)?;
        let digest: [u8; 32] = Sha256::digest(&config.certificate).into();
        let now = config.keys.owner.environment.sample()?;
        if !tls.field("TLSPolicy", "pins")?.children()?.any(|p| {
            p.is_ok_and(|p| {
                p.b::<32>("TLSPin", "leaf_der_sha256") == Ok(digest)
                    && p.u("TLSPin", "not_before_ms")
                        .is_ok_and(|v| v >= config.socket.validity.0 && now.lower_ms >= v)
                    && p.u("TLSPin", "not_after_ms")
                        .is_ok_and(|v| v <= config.socket.validity.1 && now.upper_ms < v)
            })
        }) {
            return Err(ConnectError::Tls);
        }
    }
    Ok(())
}
struct ReadySession {
    session: Session,
    received: ResourceCharge,
    application: Arc<ApplicationLifetime>,
    handlers: HandlerPlan,
    authentication: AuthenticatedRequestContext,
    publication: crate::application_lifetime_v4::Callback,
}
async fn establish(
    owner: &Arc<ServeOwner>,
    config: &Configuration,
    ingress: (usize, u64),
    provider: &Arc<wss::Provider>,
    incoming: &mut mpsc::Receiver<Vec<u8>>,
    deadline: Instant,
    invocation: &Arc<Invocation>,
) -> ConnectResult<ReadySession> {
    let cancel = invocation.cancel.clone();
    let (index, generation) = ingress;
    let hello_wire = incoming.recv().await.ok_or(ConnectError::Carrier)?;
    let hello = payload(&hello_wire, 1, 16384)?;
    let ch = decode(hello, "ClientHello", 16384, Context::default())?;
    owner.check(index, generation)?;
    let credential_bytes = application::callback(async {
        config
            .source
            .resolve(hello, cancel.clone())
            .await
            .map_err(ServeError::from)
    })
    .await
    .map_err(|_| ConnectError::Authorization)?;
    owner.check(index, generation)?;
    let material = PoolConnectionMaterial::for_role(
        owner.root.clone(),
        config.namespaces.clone(),
        config.keys.clone(),
        credential_bytes,
        Role::Server,
    )?;
    let artifact = decode(
        &material.bytes.artifact,
        "Artifact",
        65536,
        Context::default(),
    )?;
    let binding_mode = config.options.binding_mode;
    check_hello(&material.admission, artifact, ch, binding_mode)?;
    check_route(config, artifact)?;
    let exporter = provider.binding(binding_mode, material.admission.artifact_digest)?;
    provider.bind_frame_limit(
        artifact
            .field("Artifact", "session_contract")?
            .u("SessionContract", "max_frame")? as usize
            + 8,
    )?;
    provider.attach(material.admission.account.clone())?;
    let account = material.admission.account.clone();
    let mut server_nonce = [0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut server_nonce)
        .map_err(|_| ConnectError::Protocol)?;
    let server_hello = encode(13, |out| {
        for (id, name) in [
            "protocol_id",
            "profile_revision",
            "crypto_profile_id",
            "artifact_digest",
            "candidate_id",
            "route_digest",
            "attempt_id",
            "client_nonce",
        ]
        .into_iter()
        .enumerate()
        {
            u(out, id as u64);
            out.extend_from_slice(
                ch.field("ClientHello", name)
                    .expect("validated hello")
                    .raw(),
            );
        }
        u(out, 8);
        b(out, &server_nonce);
        u(out, 9);
        u(out, 0);
        u(out, 10);
        u(out, 0);
        u(out, 11);
        u(out, binding_mode.wire());
        u(out, 12);
        b(out, &[]);
    });
    provider.send(envelope(1, &server_hello)).await?;
    let transcript: [u8; 32] = Sha256::digest(domain(
        b"flowersec/v4/hello-transcript\0",
        &[hello, &server_hello],
    )?)
    .into();
    let nonce = artifact.b::<32>("Artifact", "session_nonce")?;
    let a = &material.admission;
    let context = encode(13, |out| {
        for key in 0..13 {
            u(out, key);
            match key {
                0 => t(out, "4"),
                1 => t(out, config.keys.profile()),
                2 | 3 | 9 => u(out, 0),
                4 => b(out, &a.artifact_digest),
                5 => b(out, &a.route_digest),
                6 => b(out, &a.attempt_id),
                7 => b(out, &nonce),
                8 => b(out, &transcript),
                10 => u(out, binding_mode.wire()),
                11 => u(out, u64::from(binding_mode == BindingMode::DirectExporter)),
                12 => b(out, exporter.as_ref().map_or(&[], |v| v.as_slice())),
                _ => unreachable!(),
            }
        }
    });
    let context_digest = codec::digest(
        "transport_context_digest",
        decode(&context, "TransportContext", 4096, Context::default())?,
    )?;
    let fsb_wire = incoming.recv().await.ok_or(ConnectError::Carrier)?;
    let fsb = payload(&fsb_wire, 2, 65536)?;
    let f = decode(
        fsb,
        "FSB4",
        65536,
        Context::with_activation_source(codec::ActivationSource::PreauthorizedPool),
    )?;
    for name in ["tenant_id", "issuer_key_id", "lease_id", "session_nonce"] {
        same(f, "FSB4", name, artifact, "Artifact", name)?;
    }
    for (name, value) in [
        ("artifact_digest", a.artifact_digest.as_slice()),
        ("candidate_id", a.candidate_id.as_slice()),
        ("route_digest", a.route_digest.as_slice()),
        ("attempt_id", a.attempt_id.as_slice()),
        ("hello_transcript_digest", &transcript),
        ("transport_context_digest", &context_digest),
    ] {
        expect_bytes(f, "FSB4", name, value)?;
    }
    if f.u("FSB4", "binding_mode")? != binding_mode.wire()
        || f.u("FSB4", "selected_features")? != 0
        || bytes(f, "FSB4", "activation_authorization")? != material.bytes.activation
        || bytes(f, "FSB4", "client_certificate")? != material.bytes.client_certificate
    {
        return Err(ConnectError::Authorization);
    }
    let client = decode(
        &material.bytes.client_certificate,
        "IdentityCertificate",
        8192,
        Context::default(),
    )?;
    codec::verify_signature(
        "FSB4",
        f,
        &client.b::<32>("IdentityCertificate", "ed25519_public_key")?,
        &mut Vec::with_capacity(65664),
    )?;
    let application = ApplicationLifetime::with_cancellation(
        account.clone(),
        config.options.application_limits,
        cancel.clone(),
    )?;
    let authentication = invocation.authenticated(
        ApplicationBinding {
            artifact: a.artifact_digest,
            client_identity: a.certificate_digests[0],
            server_identity: a.certificate_digests[1],
            route: a.route_digest,
            attempt: a.attempt_id,
            candidate: a.candidate_id,
        },
        application.clone(),
    );
    let control = application.enter(CallbackKind::Control)?;
    let handlers = application::callback(
        config
            .options
            .callbacks
            .resolve_handlers(authentication.clone()),
    )
    .await
    .map_err(|_| ConnectError::Authorization)?;
    let handlers = handlers
        .capture(&owner.root)
        .map_err(|_| ConnectError::Authorization)?;
    owner.check(index, generation)?;
    account.check()?;
    provider.check()?;
    invocation.authorizing();
    let authorized = application::callback(
        config
            .options
            .callbacks
            .authorize_application(authentication.clone(), handlers),
    )
    .await;
    let handlers = match authorized {
        Ok(AuthorizeApplicationResult::Authorized { handlers }) => {
            if !invocation.authorized(ApplicationAuthorization::Authorized) {
                return Err(ConnectError::Authorization);
            }
            handlers
                .capture(&owner.root)
                .map_err(|_| ConnectError::Authorization)?
        }
        Ok(AuthorizeApplicationResult::Rejected) => {
            invocation.authorized(ApplicationAuthorization::Rejected);
            return Err(ConnectError::Authorization);
        }
        _ => {
            invocation.authorized(ApplicationAuthorization::Unknown);
            return Err(ConnectError::Authorization);
        }
    };
    drop(control);
    handlers
        .validate_limits(config.options.application_limits)
        .map_err(|_| ConnectError::Capacity)?;
    owner.check(index, generation)?;
    account.check()?;
    provider.check()?;
    let binding = codec::digest("admission_binding", f)?;
    let reservation = HandshakePreflight::new(
        account.clone(),
        RecordShape::from_artifact(artifact)?,
        Role::Server,
    )?;
    let session_charge = account.reserve(ResourceLimits {
        sdk_bytes: 4096,
        items: 1,
        timers: 2,
        work_slots: 1,
        tasks: 1,
        ..ResourceLimits::default()
    })?;
    let received = account.reserve(ResourceLimits {
        sdk_bytes: 1024,
        items: 1,
        work_slots: 1,
        tasks: 1,
        ..ResourceLimits::default()
    })?;
    owner.check(index, generation)?;
    provider.check()?;
    let durable = config.admission.admit(
        a,
        &material.bytes.artifact,
        binding,
        PoolSpendOwner::new(provider.identity(), generation, deadline, cancel)?
            .bind_carrier(provider.cancellation()),
    )?;
    durable.check()?;
    owner.check(index, generation)?;
    let fields = |out: &mut Vec<u8>| {
        for key in 0..13 {
            u(out, key);
            match key {
                0 | 1 | 7 => u(out, 0),
                2 => u(out, durable.epoch),
                3 => b(out, &durable.reservation),
                4 => b(out, &binding),
                5 => b(out, &a.route_digest),
                6 => b(out, &transcript),
                8 => u(out, binding_mode.wire()),
                9 => b(out, &context_digest),
                10 => b(out, &a.certificate_digests[0]),
                11 => b(out, &a.certificate_digests[1]),
                12 => b(out, &material.bytes.server_certificate),
                _ => unreachable!(),
            }
        }
    };
    let signature = config.keys.inner.sign(&domain(
        b"flowersec/v4/fsa4/signature\0",
        &[&encode(13, fields)],
    )?)?;
    let fsa = encode(14, |out| {
        fields(out);
        u(out, 13);
        b(out, &signature);
    });
    durable.check()?;
    owner.check(index, generation)?;
    let mut handshake = Handshake::new_reserved(
        material.admission,
        Role::Server,
        config.keys.inner.clone(),
        HandshakeInput {
            artifact: &material.bytes.artifact,
            client_hello: hello,
            server_hello: &server_hello,
            transport_context: &context,
            fsb,
            fsa: &fsa,
        },
        Some(reservation),
    )?;
    durable.check()?;
    owner.check(index, generation)?;
    provider.send(envelope(3, &fsa)).await?;
    let noise = incoming.recv().await.ok_or(ConnectError::Carrier)?;
    durable.check()?;
    owner.check(index, generation)?;
    handshake.read_noise(payload(&noise, 4, 81)?)?;
    let mut noise = [0; 81];
    durable.check()?;
    owner.check(index, generation)?;
    let count = handshake.write_noise(&mut noise)?;
    provider.send(envelope(4, &noise[..count])).await?;
    noise.zeroize();
    let peer = incoming.recv().await.ok_or(ConnectError::Carrier)?;
    durable.check()?;
    owner.check(index, generation)?;
    handshake.verify_ready(payload(&peer, 5, 103)?)?;
    let mut ready = ReadySubmission(None);
    durable.check()?;
    owner.check(index, generation)?;
    handshake.submit_ready(&mut ready)?;
    provider
        .send(envelope(5, &ready.0.take().ok_or(ConnectError::Protocol)?))
        .await?;
    durable.check()?;
    owner.check(index, generation)?;
    provider.check()?;
    let records = handshake.into_records()?;
    provider.activate();
    let publication = application.enter(CallbackKind::Control)?;
    let session = Session::adopt(
        &owner.root,
        records,
        Box::new(wss::Transport::new(
            provider.clone(),
            material.keys,
            material.namespaces,
        )),
        Some(session_charge),
    )
    .map_err(|_| ConnectError::Protocol)?;
    let closed = {
        let mut gate = owner.gate.lock().expect("Serve publication gate");
        let closed = gate.closed;
        let slot = gate.slots[index].as_mut().expect("original private child");
        assert_eq!(slot.generation, generation);
        slot.session = Some(session.clone());
        closed
    };
    if closed {
        session.close();
    }
    if session.attach_application(application.clone()).is_err() {
        session.close();
        return Err(ConnectError::Authorization);
    }
    handlers.bind(&session);
    Ok(ReadySession {
        session,
        received,
        application,
        handlers,
        authentication,
        publication,
    })
}

#[cfg(test)]
#[path = "serve_v4_application_tests.rs"]
mod application_tests;
#[cfg(test)]
#[path = "serve_v4_tests.rs"]
mod tests;
