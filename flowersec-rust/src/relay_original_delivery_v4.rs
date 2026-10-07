//! Dedicated fixed mTLS original relay delivery. The authenticated invocation
//! may install one public projection and consume its volatile continuation.
//! There is no query, lookup, adoption, reopen, retry or Artifact transport.
use super::relay_publication::{
    OriginalRelayPoolPublication, RelayParentRegistration, capture_remote_live, capture_remote_pool,
};
use super::serve::WssServerIdentity;
use super::serve::live_source::remote::{decode_envelope, encode_envelope};
use super::*;
use crate::{
    api_v4::CleanupStatus,
    control_https_v4::{ControlHTTPS, ControlHTTPSConfiguration, ControlHTTPSFailure},
    pool_v4::relay::SQLiteRelayBinding,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::Notify;

#[path = "relay_live_control_v4.rs"]
mod live;
pub use live::{RelayLiveControlDeployment, RelayLivePreparationLimits};
struct ControlResponse {
    bytes: Vec<u8>,
    acknowledgement: Option<live::Acknowledgement>,
}
impl From<Vec<u8>> for ControlResponse {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            acknowledgement: None,
        }
    }
}

const REGISTER: &str = "/relay/original/register";
const REGISTER_LIVE: &str = "/relay/original/register-live";
const START: &str = "/relay/original/start";
const MAX_REQUEST: usize = 65536;

/// Installed independently of publication, HOP HELLO and data listeners. One
/// exact original issuer identity may publish only this fixed relay mapping.
#[derive(Clone, Debug)]
pub struct RelayOriginalIssuer {
    pub leaf_digest: [u8; 32],
    pub binding: SQLiteRelayBinding,
    pub namespaces: Vec<Arc<Namespace>>,
}
#[derive(Clone, Debug)]
pub struct RelayOriginalDeliveryOptions {
    pub listen_address: SocketAddr,
    pub authority: String,
    pub client_roots_der: Vec<Vec<u8>>,
    pub issuers: Vec<RelayOriginalIssuer>,
    pub maximum_publications: usize,
    pub maximum_connections: usize,
    pub timeout: Duration,
    pub provider_runtime_bytes: u64,
    pub cancellation: CancellationToken,
}
struct Pending {
    token: [u8; 32],
    peer: [u8; 32],
    cutoff: u64,
    registration: RelayParentRegistration,
}
struct StartGuard {
    publication: Arc<WssRelayPublication>,
    confirmed: bool,
}
impl Drop for StartGuard {
    fn drop(&mut self) {
        if !self.confirmed {
            self.publication.close();
        }
    }
}
struct Running {
    token: [u8; 32],
    publication: Arc<WssRelayPublication>,
}
#[expect(
    clippy::large_enum_variant,
    reason = "Each bounded delivery registry slot retains its original pending registration inline."
)]
enum Entry {
    Pending(Pending),
    Running(Running),
}
struct Owner {
    root: Arc<EnvironmentRoot>,
    host: Arc<WssRelayHost>,
    options: RelayOriginalDeliveryOptions,
    registry: Mutex<Vec<Option<Entry>>>,
    live: Option<Arc<live::LiveControl>>,
    stop: CancellationToken,
    workers: AtomicUsize,
    observers: AtomicUsize,
    changed: Notify,
    cleanup_until: Mutex<Option<Instant>>,
    validity: (u64, u64),
    _position: Position,
    _charge: EnvironmentCharge,
}
struct Position(Arc<WssRelayHost>);
impl Drop for Position {
    fn drop(&mut self) {
        self.0.release_original_delivery();
    }
}
struct Worker(Arc<Owner>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.workers.fetch_sub(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}
struct Observer(Arc<Owner>);
impl Drop for Observer {
    fn drop(&mut self) {
        self.0.observers.fetch_sub(1, Ordering::AcqRel);
    }
}
impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalRelayDeliveryOwner { <opaque> }")
    }
}
/// Aggregate observations of this handle's independently installed original
/// live publications. Counts carry no claim, retry or reconstruction rights.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayLiveForwardingProgress {
    /// Independently installed original public projections.
    pub installed: u64,
    /// Original publications accepted after verification of both Grants.
    pub published: u64,
    /// Publications whose two original HOP owners authenticated and paired.
    pub paired: u64,
    /// Publications that forwarded both endpoint READY records.
    pub ready_forwarded: u64,
    /// Publications that forwarded original datagrams in both directions.
    pub datagram_forwarded: u64,
    /// Installations with no remaining preparation or forwarding physical tail.
    pub completed: u64,
    /// Installations withdrawn, rejected or terminated with a forwarding error.
    pub failed: u64,
}
#[derive(Debug)]
pub struct RelayOriginalDeliveryHandle {
    owner: Arc<Owner>,
    address: SocketAddr,
}
impl RelayOriginalDeliveryHandle {
    pub fn local_address(&self) -> SocketAddr {
        self.address
    }
    /// Read milestones from the retained original forwarding objects, including
    /// completed publications whose physical tails have already terminated.
    pub fn live_forwarding_progress(&self) -> ConnectResult<RelayLiveForwardingProgress> {
        self.owner
            .live
            .as_ref()
            .ok_or(ConnectError::Configuration)?
            .forwarding_progress()
    }
    /// Observe all installed live publications through actual native exit. An
    /// interrupted observer does not cancel, retry or recreate a publication.
    pub async fn wait_live_completion(
        &self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<RelayLiveForwardingProgress> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(ConnectError::Configuration);
        }
        let deadline = Instant::now()
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
            let progress = self.live_forwarding_progress()?;
            if progress.completed == progress.installed {
                return Ok(progress);
            }
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
                _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline),
            }
        }
    }
    pub fn close(&self) {
        self.owner.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let pending = self.owner.workers.load(Ordering::Acquire) as u64;
        CleanupStatus {
            complete: pending == 0,
            cleanup_incomplete: pending != 0,
            pending_callbacks: pending,
        }
    }
    pub async fn wait_cleanup(&self) -> ConnectResult<CleanupStatus> {
        if self.cleanup_status().complete {
            return Ok(self.cleanup_status());
        }
        self.owner
            .observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = Observer(self.owner.clone());
        let until = *self
            .owner
            .cleanup_until
            .lock()
            .expect("original relay delivery cleanup deadline")
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(until) => return Ok(self.cleanup_status()) }
        }
    }
}
impl Drop for RelayOriginalDeliveryHandle {
    fn drop(&mut self) {
        self.close();
    }
}
#[derive(Debug)]
struct Clock(Arc<EnvironmentRoot>);
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        self.0.sample().ok().map(|sample| {
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_millis(sample.upper_ms))
        })
    }
}
impl Owner {
    fn check(&self) -> ConnectResult<()> {
        if self.stop.is_cancelled()
            || self.options.cancellation.is_cancelled()
            || self.root.is_closed()
            || self.host.original_delivery_closed()
        {
            return Err(ConnectError::Canceled);
        }
        let now = self.root.sample()?;
        if now.lower_ms < self.validity.0 || now.upper_ms >= self.validity.1 {
            return Err(ConnectError::Tls);
        }
        Ok(())
    }
    fn close(&self) {
        self.stop.cancel();
        if let Some(live) = &self.live {
            live.close();
        }
        self.cleanup_until
            .lock()
            .expect("original relay delivery close deadline")
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        let mut registry = self.registry.lock().expect("original relay delivery close");
        for entry in registry.iter_mut() {
            match entry.as_ref() {
                Some(Entry::Pending(_)) => {
                    entry.take();
                }
                Some(Entry::Running(running)) => running.publication.close(),
                None => {}
            }
        }
        self.changed.notify_waiters();
    }
    fn register(
        &self,
        peer: [u8; 32],
        wire: &[u8],
        source: codec::ActivationSource,
    ) -> ConnectResult<Vec<u8>> {
        self.check()?;
        let issuer = self
            .options
            .issuers
            .iter()
            .find(|issuer| issuer.leaf_digest == peer)
            .ok_or(ConnectError::Authorization)?;
        // Hold a finite original registry position before decoding/verifying or
        // submitting the protected transaction. No detached retry can claim it.
        let mut registry = self
            .registry
            .lock()
            .expect("original relay registration position");
        let index = registry
            .iter()
            .position(Option::is_none)
            .ok_or(ConnectError::Capacity)?;
        let ledger = self.host.original_delivery_ledger();
        let publication = match source {
            codec::ActivationSource::PreauthorizedPool => capture_remote_pool(
                self.root.clone(),
                issuer.namespaces.clone(),
                &issuer.binding,
                wire,
            )?,
            codec::ActivationSource::LiveAuthority => capture_remote_live(
                self.root.clone(),
                issuer.namespaces.clone(),
                &issuer.binding,
                wire,
                ledger.parent_authority_id(),
            )?,
        };
        let cutoff = publication.facts.initiation_end;
        let mut token = [0; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut token)
            .map_err(|_| ConnectError::Capacity)?;
        if token == [0; 32]
            || registry.iter().flatten().any(|entry| match entry {
                Entry::Pending(pending) => pending.token == token,
                Entry::Running(running) => running.token == token,
            })
        {
            return Err(ConnectError::Capacity);
        }
        let registration = publication.register(
            self.host.original_delivery_ledger(),
            self.stop.child_token(),
        )?;
        self.check()?;
        if self.root.sample()?.upper_ms >= cutoff {
            return Err(ConnectError::Authorization);
        }
        registry[index] = Some(Entry::Pending(Pending {
            token,
            peer,
            cutoff,
            registration,
        }));
        Ok(encode_envelope(b"relay-original-registered-1", &[&token]))
    }
    async fn start(self: &Arc<Self>, peer: [u8; 32], wire: &[u8]) -> ConnectResult<Vec<u8>> {
        self.check()?;
        let fields = decode_envelope(wire, b"relay-original-start-1", 1)?;
        let token: [u8; 32] = fields[0]
            .try_into()
            .map_err(|_| ConnectError::Configuration)?;
        let (index, pending) = {
            let mut registry = self
                .registry
                .lock()
                .expect("original relay continuation consume");
            let index = registry
                .iter()
                .position(|entry| {
                    matches!(entry, Some(Entry::Pending(pending))
                if pending.token == token && pending.peer == peer)
                })
                .ok_or(ConnectError::Authorization)?;
            let Some(Entry::Pending(pending)) = registry[index].take() else {
                return Err(ConnectError::Authorization);
            };
            // This same lock keeps the slot reserved until host ownership has
            // been installed. Missing ACK never restores the pending entry.
            if self.root.sample()?.upper_ms >= pending.cutoff {
                return Err(ConnectError::Authorization);
            }
            let publication = Arc::new(self.host.publish_registered(pending.registration)?);
            registry[index] = Some(Entry::Running(Running {
                token,
                publication: publication.clone(),
            }));
            (index, publication)
        };
        self.workers.fetch_add(1, Ordering::AcqRel);
        let owner = self.clone();
        let publication = pending.clone();
        tokio::spawn(async move {
            let _worker = Worker(owner.clone());
            // Completion means the original providers and their join tails
            // have exited. Cancellation closes the handle but awaits that same
            // task, rather than refunding a detached replacement position.
            let completion = publication.wait_original_exit();
            tokio::pin!(completion);
            tokio::select! { _ = &mut completion => {}, _ = owner.stop.cancelled() => { publication.close(); let _ = completion.await; } }
            let mut registry = owner
                .registry
                .lock()
                .expect("original relay continuation exit");
            if matches!(&registry[index], Some(Entry::Running(running)) if running.token == token) {
                registry[index].take();
            }
            owner.changed.notify_waiters();
        });
        // A listener must physically exist before the authority exposes the
        // client material. This observation grants no HOP possession or READY.
        let mut guard = StartGuard {
            publication: pending.clone(),
            confirmed: false,
        };
        pending
            .wait_original_preparation(self.options.timeout, &self.stop)
            .await?;
        self.check()?;
        if pending.original_result().is_some() {
            return Err(ConnectError::Carrier);
        }
        guard.confirmed = true;
        Ok(encode_envelope(b"relay-original-started-1", &[&token]))
    }
}
impl WssRelayHost {
    pub async fn serve_original_delivery(
        self: &Arc<Self>,
        identity: WssServerIdentity,
        options: RelayOriginalDeliveryOptions,
    ) -> ConnectResult<RelayOriginalDeliveryHandle> {
        self.serve_original_delivery_inner(identity, options, None, Vec::new())
            .await
    }
    /// Serve original mTLS delivery on a socket already bound by its deployment
    /// owner. The socket address must match the installed authority endpoint.
    pub async fn serve_original_delivery_on_listener(
        self: &Arc<Self>,
        identity: WssServerIdentity,
        options: RelayOriginalDeliveryOptions,
        listener: std::net::TcpListener,
    ) -> ConnectResult<RelayOriginalDeliveryHandle> {
        self.serve_original_delivery_inner(identity, options, Some(listener), Vec::new())
            .await
    }
    /// Install bounded public live issuance projections and their three exact
    /// mTLS control roles before exposing the original control listener.
    pub async fn serve_original_live_control(
        self: &Arc<Self>,
        identity: WssServerIdentity,
        options: RelayOriginalDeliveryOptions,
        deployments: Vec<RelayLiveControlDeployment>,
    ) -> ConnectResult<RelayOriginalDeliveryHandle> {
        self.serve_original_delivery_inner(identity, options, None, deployments)
            .await
    }
    pub async fn serve_original_live_control_on_listener(
        self: &Arc<Self>,
        identity: WssServerIdentity,
        options: RelayOriginalDeliveryOptions,
        deployments: Vec<RelayLiveControlDeployment>,
        listener: std::net::TcpListener,
    ) -> ConnectResult<RelayOriginalDeliveryHandle> {
        self.serve_original_delivery_inner(identity, options, Some(listener), deployments)
            .await
    }
    async fn serve_original_delivery_inner(
        self: &Arc<Self>,
        identity: WssServerIdentity,
        options: RelayOriginalDeliveryOptions,
        prebound: Option<std::net::TcpListener>,
        deployments: Vec<RelayLiveControlDeployment>,
    ) -> ConnectResult<RelayOriginalDeliveryHandle> {
        if options.authority.is_empty()
            || options.authority.len() > 512
            || options.authority.capacity() > 512
            || options
                .authority
                .bytes()
                .any(|byte| byte <= 32 || byte >= 127 || matches!(byte, b'/' | b'@' | b'#' | b'?'))
            || options.client_roots_der.is_empty()
            || options.client_roots_der.len() > 16
            || options.client_roots_der.capacity() > 16
            || options
                .client_roots_der
                .iter()
                .any(|root| root.is_empty() || root.len() > 65536 || root.capacity() > 65536)
            || options.issuers.is_empty()
            || options.issuers.len() > 16
            || options.issuers.capacity() > 16
            || options.issuers.iter().enumerate().any(|(index, issuer)| {
                issuer.leaf_digest == [0; 32]
                    || options.issuers[..index]
                        .iter()
                        .any(|old| old.leaf_digest == issuer.leaf_digest)
                    || issuer.namespaces.is_empty()
                    || issuer.namespaces.len() > 8
                    || issuer.namespaces.capacity() > 8
            })
            || !(1..=16).contains(&options.maximum_publications)
            || !(1..=16).contains(&options.maximum_connections)
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
            || options.provider_runtime_bytes < 1 << 20
            || options.provider_runtime_bytes > 1 << 30
            || identity.certificate_chain_der.is_empty()
            || identity.certificate_chain_der.len() > 16
            || identity.certificate_chain_der.capacity() > 16
            || identity.certificate_chain_der.iter().any(|certificate| {
                certificate.is_empty()
                    || certificate.len() > 65536
                    || certificate.capacity() > 65536
            })
            || identity.private_key_der.is_empty()
            || identity.private_key_der.len() > 8192
            || identity.private_key_der.capacity() > 8192
        {
            return Err(ConnectError::Configuration);
        }
        if !tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        }) {
            return Err(ConnectError::Configuration);
        }
        let ledger = self.original_delivery_ledger();
        if options.issuers.iter().any(|issuer| {
            !ledger.accepts_binding(&issuer.binding)
                || [
                    &issuer.binding.tenant,
                    &issuer.binding.server_admission_authority,
                    &issuer.binding.service,
                    &issuer.binding.relay_audience,
                ]
                .iter()
                .any(|field| field.capacity() > 128)
        }) {
            return Err(ConnectError::Configuration);
        }
        self.claim_original_delivery()?;
        let position = Position(self.clone());
        let root = self.original_delivery_root();
        let maximum = options.maximum_publications;
        let ordinary_publications = maximum.saturating_sub(deployments.len());
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: 3145728 + maximum as u64 * 512,
            provider_bytes: 262144,
            items: maximum as u64 + 20,
            tasks: maximum as u64 + 1,
            native_handles: 1,
            work_slots: 17,
            timers: 32,
            ..ResourceLimits::default()
        })?;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in &options.client_roots_der {
            roots
                .add(rustls::pki_types::CertificateDer::from(certificate.clone()))
                .map_err(|_| ConnectError::Configuration)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .map_err(|_| ConnectError::Configuration)?;
        let chain = identity
            .certificate_chain_der
            .iter()
            .cloned()
            .map(rustls::pki_types::CertificateDer::from)
            .collect();
        let key = rustls::pki_types::PrivateKeyDer::try_from(identity.private_key_der.to_vec())
            .map_err(|_| ConnectError::Configuration)?;
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ConnectError::Configuration)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .map_err(|_| ConnectError::Configuration)?;
        tls.time_provider = Arc::new(Clock(root.clone()));
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.max_fragment_size = Some(16384);
        tls.send_tls13_tickets = 0;
        tls.max_early_data_size = 0;
        let validity = validate_certificates(&root, &identity.certificate_chain_der)?;
        let listener = match prebound {
            Some(listener) => {
                if listener.local_addr().map_err(|_| ConnectError::Carrier)?
                    != options.listen_address
                {
                    return Err(ConnectError::Configuration);
                }
                listener
                    .set_nonblocking(true)
                    .map_err(|_| ConnectError::Carrier)?;
                tokio::net::TcpListener::from_std(listener).map_err(|_| ConnectError::Carrier)?
            }
            None => tokio::net::TcpListener::bind(options.listen_address)
                .await
                .map_err(|_| ConnectError::Carrier)?,
        };
        let address = listener.local_addr().map_err(|_| ConnectError::Carrier)?;
        let stop = CancellationToken::new();
        let live = live::LiveControl::new(
            root.clone(),
            self.clone(),
            &options,
            deployments,
            stop.child_token(),
        )?;
        let owner = Arc::new(Owner {
            root,
            host: self.clone(),
            options,
            live,
            registry: Mutex::new((0..ordinary_publications).map(|_| None).collect()),
            stop,
            workers: AtomicUsize::new(1),
            observers: AtomicUsize::new(0),
            changed: Notify::new(),
            cleanup_until: Mutex::new(None),
            validity,
            _position: position,
            _charge: charge,
        });
        owner.check()?;
        if let Some(live) = &owner.live {
            live.start_workers(&owner);
        }
        tokio::spawn(pump(owner.clone(), listener, Arc::new(tls)));
        Ok(RelayOriginalDeliveryHandle { owner, address })
    }
}
async fn pump(
    owner: Arc<Owner>,
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
) {
    let _worker = Worker(owner.clone());
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        if owner.check().is_err() {
            owner.close();
            break;
        }
        // Retire unconsumed original publications at their signed cutoff. No
        // receiver response extends or reconstructs this original authority.
        {
            let now = owner.root.sample();
            let mut registry = owner
                .registry
                .lock()
                .expect("original relay pending cutoff");
            for entry in registry.iter_mut() {
                if matches!(entry, Some(Entry::Pending(pending))
              if now.as_ref().is_ok_and(|now| now.upper_ms >= pending.cutoff))
                {
                    entry.take();
                }
            }
        }
        if active.load(Ordering::Acquire) >= owner.options.maximum_connections {
            tokio::select! { _ = owner.stop.cancelled() => {}, _ = owner.changed.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
            continue;
        }
        let charge = match owner.root.reserve_environment(ResourceLimits {
            sdk_bytes: 3 * MAX_REQUEST as u64 + 524288,
            provider_bytes: owner.options.provider_runtime_bytes,
            items: 8,
            tasks: 1,
            timers: 1,
            native_handles: 1,
            connections: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        }) {
            Ok(charge) => charge,
            Err(_) => {
                owner.close();
                break;
            }
        };
        let socket = tokio::select! {
            socket = listener.accept() => socket,
            _ = owner.stop.cancelled() => break,
            _ = owner.options.cancellation.cancelled() => { owner.close(); break; },
            _ = wait_owner_close(&owner) => { owner.close(); break; },
            _ = tokio::time::sleep(Duration::from_millis(10)) => continue,
        };
        let Ok((socket, _)) = socket else {
            owner.close();
            break;
        };
        owner.workers.fetch_add(1, Ordering::AcqRel);
        active.fetch_add(1, Ordering::AcqRel);
        let current = owner.clone();
        let active = active.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _worker = Worker(current.clone());
            let _charge = charge;
            let until = Instant::now() + current.options.timeout;
            tokio::select! { _ = connection(current.clone(), socket, tls) => {}, _ = current.stop.cancelled() => {},
            _ = current.options.cancellation.cancelled() => {}, _ = wait_owner_close(&current) => {}, _ = tokio::time::sleep_until(until) => {} }
            active.fetch_sub(1, Ordering::AcqRel);
            current.changed.notify_waiters();
        });
    }
}
async fn wait_owner_close(owner: &Owner) {
    loop {
        let changed = owner.root.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if owner.root.is_closed() || owner.host.original_delivery_closed() {
            return;
        }
        tokio::select! { _ = changed => {}, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
    }
}
fn validate_certificates(
    root: &EnvironmentRoot,
    certificates: &[Vec<u8>],
) -> ConnectResult<(u64, u64)> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    if certificates.is_empty()
        || certificates.len() > 16
        || certificates.iter().map(Vec::len).sum::<usize>() > 131072
    {
        return Err(ConnectError::Tls);
    }
    let now = root.sample()?;
    let mut validity = (0, u64::MAX);
    for certificate in certificates {
        let (remaining, certificate) =
            X509Certificate::from_der(certificate).map_err(|_| ConnectError::Tls)?;
        let start = u64::try_from(certificate.validity().not_before.timestamp())
            .ok()
            .and_then(|value| value.checked_mul(1000))
            .ok_or(ConnectError::Tls)?;
        let end = u64::try_from(certificate.validity().not_after.timestamp())
            .ok()
            .and_then(|value| value.checked_mul(1000))
            .ok_or(ConnectError::Tls)?;
        if !remaining.is_empty() || now.lower_ms < start || now.upper_ms >= end {
            return Err(ConnectError::Tls);
        }
        validity.0 = validity.0.max(start);
        validity.1 = validity.1.min(end);
    }
    Ok(validity)
}
async fn connection(
    owner: Arc<Owner>,
    socket: tokio::net::TcpStream,
    tls: Arc<rustls::ServerConfig>,
) -> ConnectResult<()> {
    let mut stream = tokio_rustls::TlsAcceptor::from(tls)
        .accept(socket)
        .await
        .map_err(|_| ConnectError::Tls)?;
    stream.get_mut().1.set_buffer_limit(Some(65536));
    let native = &stream.get_ref().1;
    if native.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || native.alpn_protocol() != Some(b"http/1.1")
    {
        return Err(ConnectError::Tls);
    }
    let certificates = native.peer_certificates().ok_or(ConnectError::Tls)?;
    if certificates.is_empty()
        || certificates.len() > 16
        || certificates
            .iter()
            .map(|certificate| certificate.len())
            .sum::<usize>()
            > 131072
    {
        return Err(ConnectError::Tls);
    }
    let validity = validate_certificates(
        &owner.root,
        &certificates
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect::<Vec<_>>(),
    )?;
    let peer: [u8; 32] = Sha256::digest(certificates[0].as_ref()).into();
    if !owner
        .options
        .issuers
        .iter()
        .any(|issuer| issuer.leaf_digest == peer)
        && !owner
            .live
            .as_ref()
            .is_some_and(|live| live.accepts_peer(peer))
    {
        return Err(ConnectError::Authorization);
    }
    let final_owner = owner.clone();
    let once = Arc::new(AtomicBool::new(false));
    let acknowledgement = Arc::new(Mutex::new(None::<live::Acknowledgement>));
    let written = acknowledgement.clone();
    let service = hyper::service::service_fn(move |request| {
        let owner = owner.clone();
        let once = once.clone();
        let acknowledgement = acknowledgement.clone();
        async move {
            let result = if once.swap(true, Ordering::AcqRel) {
                Err(ConnectError::Authorization)
            } else {
                receive(owner, peer, validity, request).await
            };
            let (status, bytes) = match result {
                Ok(response) => {
                    *acknowledgement.lock().expect("original relay response ACK") =
                        response.acknowledgement;
                    (http::StatusCode::OK, response.bytes)
                }
                Err(_) => (http::StatusCode::FORBIDDEN, vec![0xf6]),
            };
            let response = http::Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, "application/cbor")
                .header(http::header::CONTENT_LENGTH, bytes.len().to_string())
                .header(http::header::CACHE_CONTROL, "no-store")
                .header(http::header::CONNECTION, "close")
                .body(Full::new(Bytes::from(bytes)))
                .expect("fixed original relay delivery response");
            Ok::<_, Infallible>(response)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .max_buf_size(16384)
        .max_headers(32)
        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
        .await
        .map_err(|_| ConnectError::Carrier)?;
    // The sole response and TLS shutdown have been flushed by this original
    // connection. A dropped/error connection drops its ACK guard and retires
    // the projection. Local write completion never claims remote receipt.
    final_owner.check()?;
    let now = final_owner.root.sample()?;
    if now.lower_ms < validity.0 || now.upper_ms >= validity.1 {
        return Err(ConnectError::Tls);
    }
    let acknowledgement = written.lock().expect("original relay written ACK").take();
    if let Some(acknowledgement) = acknowledgement {
        acknowledgement.written()?;
    }
    Ok(())
}
async fn receive(
    owner: Arc<Owner>,
    peer: [u8; 32],
    validity: (u64, u64),
    request: http::Request<hyper::body::Incoming>,
) -> ConnectResult<ControlResponse> {
    owner.check()?;
    let path = request.uri().path();
    let headers = request.headers();
    if request.method() != http::Method::POST
        || request.version() != http::Version::HTTP_11
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().query().is_some()
        || !matches!(
            path,
            REGISTER
                | REGISTER_LIVE
                | START
                | live::READY
                | live::PREPARE
                | live::SERVER
                | live::CLIENT
        )
        || headers.get_all(http::header::HOST).iter().count() != 1
        || headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            != Some(owner.options.authority.as_str())
        || headers.get_all(http::header::CONTENT_TYPE).iter().count() != 1
        || headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some("application/cbor")
        || headers.get_all(http::header::CONTENT_LENGTH).iter().count() != 1
        || headers.contains_key(http::header::TRANSFER_ENCODING)
        || headers.contains_key(http::header::CONTENT_ENCODING)
        || headers.contains_key(http::header::EXPECT)
    {
        return Err(ConnectError::Configuration);
    }
    let length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(ConnectError::Configuration)?;
    let maximum = match path {
        REGISTER | REGISTER_LIVE => MAX_REQUEST,
        live::READY | live::PREPARE => 1024,
        live::SERVER | live::CLIENT => 24576,
        _ => 128,
    };
    if length == 0 || length > maximum {
        return Err(ConnectError::Capacity);
    }
    let path = path.to_owned();
    let mut body = request.into_body();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ConnectError::Capacity)?;
    while let Some(frame) = body.frame().await {
        let data = frame
            .map_err(|_| ConnectError::Carrier)?
            .into_data()
            .map_err(|_| ConnectError::Configuration)?;
        if bytes
            .len()
            .checked_add(data.len())
            .is_none_or(|total| total > length)
        {
            return Err(ConnectError::Capacity);
        }
        bytes.extend_from_slice(&data);
    }
    if bytes.len() != length {
        return Err(ConnectError::Configuration);
    }
    let now = owner.root.sample()?;
    if now.lower_ms < validity.0 || now.upper_ms >= validity.1 {
        return Err(ConnectError::Tls);
    }
    let result = match path.as_str() {
        REGISTER => owner
            .register(peer, &bytes, codec::ActivationSource::PreauthorizedPool)
            .map(Into::into),
        REGISTER_LIVE => owner
            .register(peer, &bytes, codec::ActivationSource::LiveAuthority)
            .map(Into::into),
        START => owner.start(peer, &bytes).await.map(Into::into),
        _ => match &owner.live {
            Some(live) => {
                live.receive(peer, &path, &bytes)
                    .await
                    .map(|(bytes, acknowledgement)| ControlResponse {
                        bytes,
                        acknowledgement: Some(acknowledgement),
                    })
            }
            None => Err(ConnectError::Authorization),
        },
    };
    let now = owner.root.sample()?;
    if now.lower_ms < validity.0 || now.upper_ms >= validity.1 {
        return Err(ConnectError::Tls);
    }
    result
}

/// Fixed original issuer-side mTLS client. It accepts only the sealed original
/// pool publication, never arbitrary public rows or driver configuration.
pub struct OriginalRelayDelivery {
    root: Arc<EnvironmentRoot>,
    transport: ControlHTTPS,
}
impl fmt::Debug for OriginalRelayDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalRelayDelivery { <opaque> }")
    }
}
pub struct RemoteRelayPublication {
    delivery: Arc<OriginalRelayDelivery>,
    token: [u8; 32],
    cutoff: u64,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for RemoteRelayPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteRelayPublication { <opaque> }")
    }
}
impl TransportEnvironment {
    pub fn original_relay_delivery(
        &self,
        configuration: ControlHTTPSConfiguration,
    ) -> std::result::Result<Arc<OriginalRelayDelivery>, ControlHTTPSFailure> {
        if !configuration.base_path.is_empty() {
            return Err(ControlHTTPSFailure::Configuration);
        }
        Ok(Arc::new(OriginalRelayDelivery {
            root: self.root().clone(),
            transport: ControlHTTPS::new(self.root().clone(), configuration)?,
        }))
    }
}
impl OriginalRelayDelivery {
    pub async fn register_pool_original(
        self: &Arc<Self>,
        publication: OriginalRelayPoolPublication,
        cancellation: &CancellationToken,
    ) -> std::result::Result<RemoteRelayPublication, ControlHTTPSFailure> {
        self.register_original(
            publication,
            codec::ActivationSource::PreauthorizedPool,
            cancellation,
        )
        .await
    }
    /// Consume the confirmed original live TxB publication on its dedicated
    /// mTLS route. A pool projection cannot enter this receiver or vice versa.
    pub async fn register_live_original(
        self: &Arc<Self>,
        publication: OriginalRelayPoolPublication,
        cancellation: &CancellationToken,
    ) -> std::result::Result<RemoteRelayPublication, ControlHTTPSFailure> {
        self.register_original(
            publication,
            codec::ActivationSource::LiveAuthority,
            cancellation,
        )
        .await
    }
    async fn register_original(
        self: &Arc<Self>,
        publication: OriginalRelayPoolPublication,
        source: codec::ActivationSource,
        cancellation: &CancellationToken,
    ) -> std::result::Result<RemoteRelayPublication, ControlHTTPSFailure> {
        if publication.source != source {
            return Err(ControlHTTPSFailure::Configuration);
        }
        if publication
            .facts
            .accounts
            .iter()
            .any(|account| !account.belongs_to(&self.root))
        {
            return Err(ControlHTTPSFailure::Configuration);
        }
        for account in &publication.facts.accounts {
            account.check().map_err(|_| ControlHTTPSFailure::Rejected)?;
        }
        let cutoff = publication.facts.initiation_end;
        if self
            .root
            .sample()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?
            .upper_ms
            >= cutoff
        {
            return Err(ControlHTTPSFailure::Deadline);
        }
        let charge = self
            .root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 3 * MAX_REQUEST as u64 + 4096,
                items: 4,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| ControlHTTPSFailure::Capacity)?;
        let response = self
            .transport
            .post_original_delivery(
                match source {
                    codec::ActivationSource::PreauthorizedPool => REGISTER,
                    codec::ActivationSource::LiveAuthority => REGISTER_LIVE,
                },
                &publication.facts.public_record,
                128,
                cancellation,
            )
            .await?;
        let fields = decode_envelope(&response, b"relay-original-registered-1", 1)
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        let token: [u8; 32] = fields[0]
            .try_into()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        if token == [0; 32] {
            return Err(ControlHTTPSFailure::Unavailable);
        }
        if cancellation.is_cancelled() || self.root.is_closed() {
            return Err(ControlHTTPSFailure::Canceled);
        }
        if self
            .root
            .sample()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?
            .upper_ms
            >= cutoff
        {
            return Err(ControlHTTPSFailure::Deadline);
        }
        Ok(RemoteRelayPublication {
            delivery: self.clone(),
            token,
            cutoff,
            _charge: charge,
        })
    }
}
impl RemoteRelayPublication {
    /// Consume only from the same original issuance continuation. Any uncertain
    /// result yields no client delivery and never retries the original request.
    pub async fn start_original(
        self,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(), ControlHTTPSFailure> {
        if self
            .delivery
            .root
            .sample()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?
            .upper_ms
            >= self.cutoff
        {
            return Err(ControlHTTPSFailure::Deadline);
        }
        let request = encode_envelope(b"relay-original-start-1", &[&self.token]);
        let response = self
            .delivery
            .transport
            .post_original_delivery(START, &request, 128, cancellation)
            .await?;
        let fields = decode_envelope(&response, b"relay-original-started-1", 1)
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        if fields[0] != self.token.as_slice() {
            return Err(ControlHTTPSFailure::Unavailable);
        }
        if cancellation.is_cancelled() || self.delivery.root.is_closed() {
            return Err(ControlHTTPSFailure::Canceled);
        }
        if self
            .delivery
            .root
            .sample()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?
            .upper_ms
            >= self.cutoff
        {
            return Err(ControlHTTPSFailure::Deadline);
        }
        Ok(())
    }
}
