//! Fixed mTLS delivery between the original authority invocation and the
//! accepted server. Volatile publication capabilities have no reopen or query
//! operation and never substitute for the durable admission ledger.
use super::*;
use crate::control_https_v4::{ControlHTTPS, ControlHTTPSConfiguration, ControlHTTPSFailure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Notify, mpsc};
use zeroize::Zeroizing;

const REGISTER: &str = "/live/server/register";
const REGISTER_TUNNEL: &str = "/live/server/register-tunnel";
const PUBLISH: &str = "/live/server/publish";
const PUBLISH_TUNNEL: &str = "/live/server/publish-tunnel";
const MAX_REQUEST: usize = 106496;

/// Trusted deployment configuration. Client roots and exact leaf digests must
/// identify the original issuance authority, independently of data listeners.
#[derive(Clone, Debug)]
pub struct LiveServerDeliveryOptions {
    pub listen_address: SocketAddr,
    pub authority: String,
    pub client_roots_der: Vec<Vec<u8>>,
    pub authority_leaf_digests: Vec<[u8; 32]>,
    pub maximum_connections: usize,
    pub timeout: Duration,
    pub provider_runtime_bytes: u64,
    pub cancellation: CancellationToken,
}
#[expect(
    clippy::large_enum_variant,
    reason = "Publication slots retain original tunnel material inline within their reserved delivery storage."
)]
enum PublicationHandle {
    Direct(OriginalLiveServerPublication),
    Tunnel(OriginalLiveTunnelServerPublication),
    Announcing,
}
struct Publication {
    token: [u8; 32],
    peer: [u8; 32],
    cutoff: u64,
    handle: PublicationHandle,
}
struct OriginalTunnelReadiness {
    listener: Option<Arc<super::super::tunnel::OriginalListenerReadiness>>,
    carrier: Option<WssConnectOptions>,
    control: Arc<crate::LiveTunnelAuthorityControl>,
    _charge: EnvironmentCharge,
}
struct ReadinessGuard {
    owner: Arc<DeliveryOwner>,
    index: usize,
    token: [u8; 32],
    confirmed: bool,
}
impl Drop for ReadinessGuard {
    fn drop(&mut self) {
        if self.confirmed {
            return;
        }
        let mut entries = self
            .owner
            .publications
            .lock()
            .expect("original B readiness retirement");
        if entries[self.index].as_ref().is_some_and(|entry| {
            entry.token == self.token && matches!(&entry.handle, PublicationHandle::Announcing)
        }) {
            entries[self.index].take();
        }
        self.owner.changed.notify_waiters();
    }
}
struct DeliveryOwner {
    source: Arc<OriginalLiveAcceptedSource>,
    options: LiveServerDeliveryOptions,
    publications: Mutex<Vec<Option<Publication>>>,
    readiness: std::sync::OnceLock<OriginalTunnelReadiness>,
    tunnel_sender: mpsc::Sender<OriginalLiveTunnelServerMaterial>,
    stop: CancellationToken,
    workers: AtomicUsize,
    observers: AtomicUsize,
    changed: Notify,
    cleanup_deadline: Mutex<Option<Instant>>,
    validity: (u64, u64),
    _position: DeliveryPosition,
    _charge: EnvironmentCharge,
}
struct DeliveryPosition(Arc<OriginalLiveAcceptedSource>);
impl Drop for DeliveryPosition {
    fn drop(&mut self) {
        self.0.delivery_active.store(false, Ordering::Release);
    }
}
impl fmt::Debug for DeliveryOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalLiveDeliveryOwner { <opaque> }")
    }
}
/// Closing ingress retires all pending original publications. Physical native
/// tasks retain their reservation until exit; wait_cleanup is bounded.
pub struct LiveServerDeliveryHandle {
    owner: Arc<DeliveryOwner>,
    address: SocketAddr,
    tunnel_receiver: tokio::sync::Mutex<mpsc::Receiver<OriginalLiveTunnelServerMaterial>>,
}
impl fmt::Debug for LiveServerDeliveryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveServerDeliveryHandle")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}
impl LiveServerDeliveryHandle {
    pub fn local_address(&self) -> SocketAddr {
        self.address
    }
    /// Install original B listener readiness before any live registration.
    /// The delivery owner retains only this already installed physical owner
    /// and fixed control configuration. No peer request can replace them.
    pub fn configure_original_tunnel_listener_readiness(
        &self,
        listener: &LiveReverseTunnelListener,
        control: Arc<crate::LiveTunnelAuthorityControl>,
    ) -> ConnectResult<()> {
        self.owner.check()?;
        if !control.belongs_to(&self.owner.source.root) {
            return Err(ConnectError::Configuration);
        }
        let charge = self.owner.source.root.reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let readiness = listener.original_readiness()?;
        if !readiness.belongs_to(&self.owner.source.root) {
            return Err(ConnectError::Configuration);
        }
        let state = self
            .owner
            .source
            .state
            .lock()
            .expect("original B readiness installation");
        if state.closed || state.records.iter().any(Option::is_some) {
            return Err(ConnectError::Configuration);
        }
        self.owner
            .readiness
            .set(OriginalTunnelReadiness {
                listener: Some(Arc::new(readiness)),
                carrier: None,
                control,
                _charge: charge,
            })
            .map_err(|_| ConnectError::Configuration)
    }
    /// Install the forward B provider before any registration. Registration
    /// ACK waits for native Prepare on the original verified Account; no
    /// request can replace this fixed provider or activation signing key.
    pub fn configure_original_tunnel_carrier_preparation(
        &self,
        provider: WssConnectOptions,
        control: Arc<crate::LiveTunnelAuthorityControl>,
    ) -> ConnectResult<()> {
        self.owner.check()?;
        if !control.belongs_to(&self.owner.source.root) {
            return Err(ConnectError::Configuration);
        }
        let charge = self.owner.source.root.reserve_environment(ResourceLimits {
            sdk_bytes: 32768,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let state = self
            .owner
            .source
            .state
            .lock()
            .expect("original B carrier installation");
        if state.closed || state.records.iter().any(Option::is_some) {
            return Err(ConnectError::Configuration);
        }
        self.owner
            .readiness
            .set(OriginalTunnelReadiness {
                listener: None,
                carrier: Some(provider),
                control,
                _charge: charge,
            })
            .map_err(|_| ConnectError::Configuration)
    }
    /// Receive the next one-shot server-leg material delivered through the
    /// original mTLS publication. This consumes the queued capability; it is
    /// not a lookup and cannot reopen or retry a publication.
    pub async fn next_tunnel_publication(
        &self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<OriginalLiveTunnelServerMaterial> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) || cancellation.is_cancelled() {
            return Err(if cancellation.is_cancelled() {
                ConnectError::Canceled
            } else {
                ConnectError::Configuration
            });
        }
        self.owner.check()?;
        // One queue consumer owns its original bounded wait. Parallel callers
        // cannot allocate an unbounded mutex waiter chain or evade cancellation
        // while another invocation retains the receiver.
        let mut receiver = self
            .tunnel_receiver
            .try_lock()
            .map_err(|_| ConnectError::Capacity)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ConnectError::Configuration)?;
        let item = tokio::select! {
            biased;
            _ = self.owner.stop.cancelled() => return Err(ConnectError::Canceled),
            _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline),
            value = receiver.recv() => value.ok_or(ConnectError::Canceled)?,
        };
        self.owner.check()?;
        if cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        if Instant::now() >= deadline {
            return Err(ConnectError::Deadline);
        }
        Ok(item)
    }
    pub fn close(&self) {
        self.owner.close();
        // Closing ingress also drops any queued one-shot tunnel material. A
        // consumer waiting in `next_tunnel_publication` observes the owner
        // cancellation; a consumer that already owns the receiver releases
        // the queue item on return.
        if let Ok(mut receiver) = self.tunnel_receiver.try_lock() {
            while receiver.try_recv().is_ok() {}
        }
    }
    pub fn cleanup_status(&self) -> crate::api_v4::CleanupStatus {
        let pending = self.owner.workers.load(Ordering::Acquire) as u64
            + self.owner.source.pending_preparations() as u64;
        crate::api_v4::CleanupStatus {
            complete: pending == 0,
            cleanup_incomplete: pending != 0,
            pending_callbacks: pending,
        }
    }
    pub async fn wait_cleanup(&self) -> ConnectResult<crate::api_v4::CleanupStatus> {
        let status = self.cleanup_status();
        if status.complete {
            return Ok(status);
        }
        self.owner
            .observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = CleanupObserver(self.owner.clone());
        let until = self
            .owner
            .cleanup_deadline
            .lock()
            .expect("original delivery cleanup deadline")
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(5));
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let preparation = self.owner.source.preparation_cleanup_notify().notified();
            tokio::pin!(preparation);
            preparation.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = preparation => {},
            _ = tokio::time::sleep_until(until) => return Ok(self.cleanup_status()) }
        }
    }
}
impl Drop for LiveServerDeliveryHandle {
    fn drop(&mut self) {
        self.close();
    }
}
struct CleanupObserver(Arc<DeliveryOwner>);
impl Drop for CleanupObserver {
    fn drop(&mut self) {
        self.0.observers.fetch_sub(1, Ordering::AcqRel);
    }
}
#[derive(Debug)]
pub(crate) struct DeliveryClock(pub(crate) Arc<EnvironmentRoot>);
impl rustls::time_provider::TimeProvider for DeliveryClock {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        self.0.sample().ok().map(|now| {
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_millis(now.upper_ms))
        })
    }
}
impl DeliveryOwner {
    fn close(&self) {
        self.stop.cancel();
        self.cleanup_deadline
            .lock()
            .expect("original delivery cleanup deadline")
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        self.publications
            .lock()
            .expect("original delivery close")
            .iter_mut()
            .for_each(|entry| {
                entry.take();
            });
        self.source.close();
        self.changed.notify_waiters();
    }
    fn check(&self) -> ConnectResult<()> {
        if self.stop.is_cancelled()
            || self.options.cancellation.is_cancelled()
            || self.source.root.is_closed()
        {
            Err(ConnectError::Canceled)
        } else {
            let now = self.source.root.sample()?;
            if now.lower_ms < self.validity.0 || now.upper_ms >= self.validity.1 {
                Err(ConnectError::Tls)
            } else {
                Ok(())
            }
        }
    }
    async fn announce_original_registration(
        self: &Arc<Self>,
        peer: [u8; 32],
        response: &[u8],
    ) -> ConnectResult<()> {
        let Some(readiness) = self.readiness.get() else {
            return Ok(());
        };
        self.check()?;
        // This token was just created by this original request in dispatch.
        // It selects the already retained capability only inside this handler;
        // no lookup or caller-supplied token can invoke this operation.
        let fields = decode_envelope(response, b"live-server-registration-1", 1)?;
        let token: [u8; 32] = fields[0].try_into().map_err(|_| ConnectError::Protocol)?;
        let (index, handle) = {
            let mut entries = self
                .publications
                .lock()
                .expect("original B readiness capture");
            let index = entries
                .iter()
                .position(|entry| {
                    entry
                        .as_ref()
                        .is_some_and(|entry| entry.token == token && entry.peer == peer)
                })
                .ok_or(ConnectError::Authorization)?;
            let entry = entries[index].as_mut().ok_or(ConnectError::Authorization)?;
            if self.source.root.sample()?.upper_ms >= entry.cutoff {
                return Err(ConnectError::Authorization);
            }
            let handle = match std::mem::replace(&mut entry.handle, PublicationHandle::Announcing) {
                PublicationHandle::Tunnel(handle) => handle,
                other => {
                    entry.handle = other;
                    return Err(ConnectError::Authorization);
                }
            };
            (index, handle)
        };
        let mut guard = ReadinessGuard {
            owner: self.clone(),
            index,
            token,
            confirmed: false,
        };
        let handle = if let Some(listener) = &readiness.listener {
            handle
                .announce_original_readiness(
                    listener,
                    &readiness.control,
                    self.options.timeout,
                    &self.stop,
                )
                .await?
        } else {
            handle
                .prepare_original_carrier(
                    readiness
                        .carrier
                        .as_ref()
                        .ok_or(ConnectError::Configuration)?
                        .clone(),
                    &self.stop,
                )
                .await?
        };
        self.check()?;
        let mut entries = self
            .publications
            .lock()
            .expect("original B readiness confirmation");
        let entry = entries[index]
            .as_mut()
            .filter(|entry| {
                entry.token == token
                    && entry.peer == peer
                    && matches!(&entry.handle, PublicationHandle::Announcing)
            })
            .ok_or(ConnectError::Authorization)?;
        if self.source.root.sample()?.upper_ms >= entry.cutoff {
            return Err(ConnectError::Authorization);
        }
        entry.handle = PublicationHandle::Tunnel(handle);
        guard.confirmed = true;
        Ok(())
    }
    fn dispatch(&self, path: &str, peer: [u8; 32], bytes: &[u8]) -> ConnectResult<Vec<u8>> {
        self.check()?;
        if path == REGISTER || path == REGISTER_TUNNEL {
            let tunnel = path == REGISTER_TUNNEL;
            let fields = if tunnel {
                decode_envelope(bytes, b"live-server-register-tunnel-1", 6)?
            } else {
                decode_envelope(bytes, b"live-server-register-1", 3)?
            };
            if fields[0].len() > 65536 || fields[1].len() > 8192 || fields[2].len() > 8192 {
                return Err(ConnectError::Configuration);
            }
            let artifact = decode(fields[0], "Artifact", 65536, Context::default())?;
            let cutoff = artifact.u("Artifact", "initiation_not_after_ms")?;
            let path_kind = artifact
                .field("Artifact", "candidates")?
                .at(0)?
                .u("Candidate", "path_kind")?;
            if path_kind > 1 || tunnel != (path_kind == 1) {
                return Err(ConnectError::Configuration);
            }
            let mut token = [0; 32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut token)
                .map_err(|_| ConnectError::Capacity)?;
            let mut entries = self
                .publications
                .lock()
                .expect("original remote registration");
            self.check()?;
            let now = self.source.root.sample()?.upper_ms;
            for entry in entries.iter_mut() {
                if entry.as_ref().is_some_and(|entry| now >= entry.cutoff) {
                    entry.take();
                }
            }
            if entries.iter().flatten().any(|entry| entry.token == token) {
                return Err(ConnectError::Capacity);
            }
            let slot = entries
                .iter_mut()
                .find(|entry| entry.is_none())
                .ok_or(ConnectError::Capacity)?;
            let connection = PoolCredentialBytes {
                artifact: fields[0].to_vec(),
                client_certificate: fields[1].to_vec(),
                server_certificate: fields[2].to_vec(),
                activation: Vec::new(),
            };
            let handle = if tunnel {
                if fields[3].len() > 8192
                    || fields[4].is_empty()
                    || fields[4].len() > 128
                    || fields[5].is_empty()
                    || fields[5].len() > 128
                {
                    return Err(ConnectError::Configuration);
                }
                PublicationHandle::Tunnel(
                    self.source.register_tunnel_original_with_signer(
                        connection,
                        fields[3].to_vec(),
                        std::str::from_utf8(fields[4])
                            .map_err(|_| ConnectError::Configuration)?
                            .to_owned(),
                        std::str::from_utf8(fields[5])
                            .map_err(|_| ConnectError::Configuration)?
                            .to_owned(),
                        self.readiness
                            .get()
                            .map(|readiness| readiness.control.activation_signing_key_id()),
                    )?,
                )
            } else {
                PublicationHandle::Direct(self.source.register_original(connection)?)
            };
            *slot = Some(Publication {
                token,
                peer,
                cutoff,
                handle,
            });
            Ok(encode_envelope(b"live-server-registration-1", &[&token]))
        } else if path == PUBLISH || path == PUBLISH_TUNNEL {
            let tunnel = path == PUBLISH_TUNNEL;
            let fields = if tunnel {
                decode_envelope(bytes, b"live-server-publish-tunnel-1", 3)?
            } else {
                decode_envelope(bytes, b"live-server-publish-1", 2)?
            };
            let token: [u8; 32] = fields[0]
                .try_into()
                .map_err(|_| ConnectError::Configuration)?;
            if fields[1].len() > 4096
                || (tunnel && (fields[2].is_empty() || fields[2].len() > 9302))
            {
                return Err(ConnectError::Configuration);
            }
            let permit = if tunnel {
                Some(
                    self.tunnel_sender
                        .try_reserve()
                        .map_err(|_| ConnectError::Capacity)?,
                )
            } else {
                None
            };
            let tunnel_charge = if tunnel {
                Some(self.source.root.reserve_environment(ResourceLimits {
                    sdk_bytes: 120_000,
                    items: 1,
                    work_slots: 0,
                    ..ResourceLimits::default()
                })?)
            } else {
                None
            };
            let publication = {
                let mut entries = self
                    .publications
                    .lock()
                    .expect("original remote publication capture");
                self.check()?;
                let index = entries
                    .iter()
                    .position(|entry| {
                        entry
                            .as_ref()
                            .is_some_and(|entry| entry.token == token && entry.peer == peer)
                    })
                    .ok_or(ConnectError::Authorization)?;
                entries[index].take().ok_or(ConnectError::Authorization)?
            };
            if self.source.root.sample()?.upper_ms >= publication.cutoff {
                return Err(ConnectError::Authorization);
            }
            // Capture consumes the only volatile publication position before
            // invoking the shared current verifier. Failure cannot be retried.
            match (publication.handle, tunnel) {
                (PublicationHandle::Direct(handle), false) => {
                    handle.publish_original(fields[1].to_vec(), &self.stop)?
                }
                (PublicationHandle::Tunnel(handle), true) => {
                    let mut material = handle.publish_tunnel(
                        fields[1].to_vec(),
                        fields[2].to_vec(),
                        &self.stop,
                    )?;
                    material.retain_delivery_charge(tunnel_charge.ok_or(ConnectError::Capacity)?);
                    permit.ok_or(ConnectError::Capacity)?.send(material);
                }
                _ => return Err(ConnectError::Authorization),
            }
            self.check()?;
            Ok(encode_envelope(b"live-server-published-1", &[&token]))
        } else {
            Err(ConnectError::Configuration)
        }
    }
}
struct Worker(Arc<DeliveryOwner>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.workers.fetch_sub(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}
impl OriginalLiveAcceptedSource {
    /// Bind the dedicated server-local mTLS recipient before issuing material.
    /// Its finite volatile registry is owned by this original source instance.
    pub async fn serve_original_delivery(
        self: &Arc<Self>,
        identity: super::super::WssServerIdentity,
        options: LiveServerDeliveryOptions,
    ) -> ConnectResult<LiveServerDeliveryHandle> {
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
                .any(|root| root.len() > 65536 || root.capacity() > 65536)
            || options.authority_leaf_digests.is_empty()
            || options.authority_leaf_digests.len() > 16
            || options.authority_leaf_digests.capacity() > 16
            || options
                .authority_leaf_digests
                .iter()
                .enumerate()
                .any(|(index, digest)| {
                    *digest == [0; 32] || options.authority_leaf_digests[..index].contains(digest)
                })
            || !(1..=16).contains(&options.maximum_connections)
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
            || options.provider_runtime_bytes < 1 << 20
            || identity.certificate_chain_der.is_empty()
            || identity.certificate_chain_der.len() > 16
            || identity.certificate_chain_der.capacity() > 16
            || identity
                .certificate_chain_der
                .iter()
                .any(|certificate| certificate.len() > 65536 || certificate.capacity() > 65536)
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
        self.delivery_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ConnectError::Configuration)?;
        let position = DeliveryPosition(self.clone());
        let maximum = self
            .state
            .lock()
            .expect("original delivery geometry")
            .records
            .len();
        let charge = self.root.reserve_environment(ResourceLimits {
            sdk_bytes: 3_145_728 + maximum as u64 * 512,
            provider_bytes: 262144,
            items: maximum as u64 + 20,
            tasks: 1,
            native_handles: 1,
            work_slots: 17,
            ..ResourceLimits::default()
        })?;
        let (tls, validity) =
            installed_control_tls(&self.root, &identity, &options.client_roots_der)?;
        let listener = tokio::net::TcpListener::bind(options.listen_address)
            .await
            .map_err(|_| ConnectError::Carrier)?;
        let address = listener.local_addr().map_err(|_| ConnectError::Carrier)?;
        let (tunnel_sender, tunnel_receiver) = mpsc::channel(maximum);
        let owner = Arc::new(DeliveryOwner {
            source: self.clone(),
            options,
            publications: Mutex::new((0..maximum).map(|_| None).collect()),
            readiness: std::sync::OnceLock::new(),
            tunnel_sender,
            stop: CancellationToken::new(),
            workers: AtomicUsize::new(1),
            observers: AtomicUsize::new(0),
            changed: Notify::new(),
            cleanup_deadline: Mutex::new(None),
            validity,
            _position: position,
            _charge: charge,
        });
        owner.check()?;
        tokio::spawn(pump(owner.clone(), listener, Arc::new(tls)));
        Ok(LiveServerDeliveryHandle {
            owner,
            address,
            tunnel_receiver: tokio::sync::Mutex::new(tunnel_receiver),
        })
    }
}
// Shared TLS policy for dedicated authenticated control receivers. A receiver
// supplies its independently installed trust and exact peer mapping separately.
pub(crate) fn installed_control_tls(
    root: &Arc<EnvironmentRoot>,
    identity: &super::super::WssServerIdentity,
    client_roots_der: &[Vec<u8>],
) -> ConnectResult<(rustls::ServerConfig, (u64, u64))> {
    let mut roots = rustls::RootCertStore::empty();
    for root in client_roots_der {
        roots
            .add(rustls::pki_types::CertificateDer::from(root.clone()))
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
    let key = rustls::pki_types::PrivateKeyDer::try_from(identity.private_key_der.clone())
        .map_err(|_| ConnectError::Configuration)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ConnectError::Configuration)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| ConnectError::Configuration)?;
    tls.time_provider = Arc::new(DeliveryClock(root.clone()));
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.max_fragment_size = Some(16384);
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    let validity = validate_certificates(root, &identity.certificate_chain_der)?;
    Ok((tls, validity))
}
async fn pump(
    owner: Arc<DeliveryOwner>,
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
) {
    let _worker = Worker(owner.clone());
    loop {
        if owner.check().is_err() {
            owner.close();
            break;
        }
        if owner.workers.load(Ordering::Acquire) > owner.options.maximum_connections {
            tokio::select! { _ = owner.stop.cancelled() => {}, _ = owner.changed.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
            continue;
        }
        // Reserve before accept/TLS. The original worker owns this charge
        // through every error, cancellation and native task exit.
        let charge = match owner.source.root.reserve_environment(ResourceLimits {
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
            _ = wait_environment_close(&owner.source.root) => { owner.close(); break; },
        };
        let Ok((socket, _)) = socket else {
            owner.close();
            break;
        };
        owner.workers.fetch_add(1, Ordering::AcqRel);
        let current = owner.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _worker = Worker(current.clone());
            let _charge = charge;
            let until = Instant::now() + current.options.timeout;
            tokio::select! {
                _ = connection(current.clone(), socket, tls) => {},
                _ = current.stop.cancelled() => {},
                _ = current.options.cancellation.cancelled() => {},
                _ = wait_environment_close(&current.source.root) => {},
                _ = tokio::time::sleep_until(until) => {},
            }
        });
    }
}
async fn wait_environment_close(root: &EnvironmentRoot) {
    loop {
        let changed = root.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if root.is_closed() {
            return;
        }
        changed.await;
    }
}
pub(crate) fn validate_certificates(
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
    owner: Arc<DeliveryOwner>,
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
        || certificates.iter().map(|value| value.len()).sum::<usize>() > 131072
    {
        return Err(ConnectError::Tls);
    }
    let validity = validate_certificates(
        &owner.source.root,
        &certificates
            .iter()
            .map(|value| value.as_ref().to_vec())
            .collect::<Vec<_>>(),
    )?;
    let peer: [u8; 32] = Sha256::digest(certificates[0].as_ref()).into();
    if !owner.options.authority_leaf_digests.contains(&peer) {
        return Err(ConnectError::Authorization);
    }
    let once = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let service = hyper::service::service_fn(move |request| {
        let owner = owner.clone();
        let once = once.clone();
        async move {
            let result = if once.swap(true, Ordering::AcqRel) {
                Err(ConnectError::Authorization)
            } else {
                receive(owner, peer, validity, request).await
            };
            let (status, bytes) = match result {
                Ok(bytes) => (http::StatusCode::OK, bytes),
                Err(_) => (http::StatusCode::FORBIDDEN, vec![0xf6]),
            };
            let response = http::Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, "application/cbor")
                .header(http::header::CONTENT_LENGTH, bytes.len().to_string())
                .header(http::header::CACHE_CONTROL, "no-store")
                .header(http::header::CONNECTION, "close")
                .body(Full::new(Bytes::from(bytes)))
                .expect("fixed original delivery response");
            Ok::<_, Infallible>(response)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .max_buf_size(16384)
        .max_headers(32)
        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
        .await
        .map_err(|_| ConnectError::Carrier)
}
async fn receive(
    owner: Arc<DeliveryOwner>,
    peer: [u8; 32],
    validity: (u64, u64),
    request: http::Request<hyper::body::Incoming>,
) -> ConnectResult<Vec<u8>> {
    owner.check()?;
    let path = request.uri().path();
    let headers = request.headers();
    if request.method() != http::Method::POST
        || request.version() != http::Version::HTTP_11
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().query().is_some()
        || !matches!(path, REGISTER | REGISTER_TUNNEL | PUBLISH | PUBLISH_TUNNEL)
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
    let maximum = if matches!(path, REGISTER | REGISTER_TUNNEL) {
        MAX_REQUEST
    } else {
        8192 + 9302
    };
    if length == 0 || length > maximum {
        return Err(ConnectError::Capacity);
    }
    let path = match path {
        REGISTER => REGISTER,
        REGISTER_TUNNEL => REGISTER_TUNNEL,
        PUBLISH => PUBLISH,
        PUBLISH_TUNNEL => PUBLISH_TUNNEL,
        _ => return Err(ConnectError::Configuration),
    };
    let mut body = request.into_body();
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ConnectError::Capacity)?;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ConnectError::Carrier)?;
        let data = frame.into_data().map_err(|_| ConnectError::Configuration)?;
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
    let now = owner.source.root.sample()?;
    if now.lower_ms < validity.0 || now.upper_ms >= validity.1 {
        return Err(ConnectError::Tls);
    }
    let response = owner.dispatch(path, peer, &bytes)?;
    if path == REGISTER_TUNNEL {
        owner
            .announce_original_registration(peer, &response)
            .await?;
    }
    owner.check()?;
    let now = owner.source.root.sample()?;
    if now.lower_ms < validity.0 || now.upper_ms >= validity.1 {
        return Err(ConnectError::Tls);
    }
    Ok(response)
}

/// SDK-owned fixed mTLS control client used by the authority before TxB.
/// The returned capability stays in the original authority invocation.
pub struct OriginalLiveServerDelivery {
    root: Arc<EnvironmentRoot>,
    transport: ControlHTTPS,
    relay_transport: Option<ControlHTTPS>,
}
impl fmt::Debug for OriginalLiveServerDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalLiveServerDelivery { <opaque> }")
    }
}
pub struct RemoteLiveServerPublication {
    delivery: Arc<OriginalLiveServerDelivery>,
    token: Zeroizing<[u8; 32]>,
    cutoff: u64,
    _charge: Arc<crate::control_https_v4::ControlHTTPSCustody>,
}
pub struct RemoteLiveTunnelServerPublication {
    delivery: Arc<OriginalLiveServerDelivery>,
    token: Zeroizing<[u8; 32]>,
    cutoff: u64,
    _charge: Arc<crate::control_https_v4::ControlHTTPSCustody>,
}
impl fmt::Debug for RemoteLiveServerPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteLiveServerPublication { <opaque> }")
    }
}
impl fmt::Debug for RemoteLiveTunnelServerPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteLiveTunnelServerPublication { <opaque> }")
    }
}
impl TransportEnvironment {
    pub fn original_live_server_delivery(
        &self,
        configuration: ControlHTTPSConfiguration,
    ) -> std::result::Result<Arc<OriginalLiveServerDelivery>, ControlHTTPSFailure> {
        // Recipient routes are fixed at the root; no caller-supplied base path
        // or reply can move a retained capability to another endpoint.
        if !configuration.base_path.is_empty() {
            return Err(ControlHTTPSFailure::Configuration);
        }
        Ok(Arc::new(OriginalLiveServerDelivery {
            root: self.root().clone(),
            transport: ControlHTTPS::new(self.root().clone(), configuration)?,
            relay_transport: None,
        }))
    }
    /// Configure original live tunnel publication with its independently fixed
    /// RelayHost mTLS control recipient. Both transports are built before TxB;
    /// tunnel registration fails before TxB when this recipient is absent.
    pub fn original_live_tunnel_server_delivery(
        &self,
        configuration: ControlHTTPSConfiguration,
        relay_host: ControlHTTPSConfiguration,
    ) -> std::result::Result<Arc<OriginalLiveServerDelivery>, ControlHTTPSFailure> {
        if !configuration.base_path.is_empty() || !relay_host.base_path.is_empty() {
            return Err(ControlHTTPSFailure::Configuration);
        }
        Ok(Arc::new(OriginalLiveServerDelivery {
            root: self.root().clone(),
            transport: ControlHTTPS::new(self.root().clone(), configuration)?,
            relay_transport: Some(ControlHTTPS::new(self.root().clone(), relay_host)?),
        }))
    }
}
impl OriginalLiveServerDelivery {
    fn check_original(
        &self,
        cutoff: u64,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(), ControlHTTPSFailure> {
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
        Ok(())
    }
    /// Registration must finish before the original TxB begins. An unavailable
    /// reply has no retry/reopen path and yields no publication capability.
    pub async fn register_original(
        self: &Arc<Self>,
        bytes: PoolCredentialBytes,
        cancellation: &CancellationToken,
    ) -> std::result::Result<RemoteLiveServerPublication, ControlHTTPSFailure> {
        if !bytes.activation.is_empty()
            || bytes.artifact.len() > 65536
            || bytes.artifact.capacity() > 65536
            || bytes.client_certificate.len() > 8192
            || bytes.client_certificate.capacity() > 8192
            || bytes.server_certificate.len() > 8192
            || bytes.server_certificate.capacity() > 8192
        {
            return Err(ControlHTTPSFailure::Configuration);
        }
        let artifact = decode(&bytes.artifact, "Artifact", 65536, Context::default())
            .map_err(|_| ControlHTTPSFailure::Configuration)?;
        let cutoff = artifact
            .u("Artifact", "initiation_not_after_ms")
            .map_err(|_| ControlHTTPSFailure::Configuration)?;
        let now = self
            .root
            .sample()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        if now.upper_ms >= cutoff {
            return Err(ControlHTTPSFailure::Deadline);
        }
        let charge = crate::control_https_v4::ControlHTTPSCustody::new_environment(
            self.root
                .reserve_environment(ResourceLimits {
                    sdk_bytes: 4 * MAX_REQUEST as u64 + 4096,
                    items: 4,
                    work_slots: 1,
                    ..ResourceLimits::default()
                })
                .map_err(|_| ControlHTTPSFailure::Capacity)?,
        );
        let request = Zeroizing::new(encode_envelope(
            b"live-server-register-1",
            &[
                &bytes.artifact,
                &bytes.client_certificate,
                &bytes.server_certificate,
            ],
        ));
        let guard = || self.check_original(cutoff, cancellation);
        let response = self
            .transport
            .post_owned(
                REGISTER,
                &request,
                128,
                cancellation,
                true,
                &guard,
                charge.clone(),
            )
            .await?;
        let fields = decode_envelope(&response, b"live-server-registration-1", 1)
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        let token = fields[0]
            .try_into()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
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
        Ok(RemoteLiveServerPublication {
            delivery: self.clone(),
            token: Zeroizing::new(token),
            cutoff,
            _charge: charge,
        })
    }
    /// Register one fixed tunnel server leg before TxB. The relay identity,
    /// service, audience, Artifact, route, and recipient are retained together;
    /// only the original TxB proof and server Grant may complete publication.
    pub async fn register_tunnel_original(
        self: &Arc<Self>,
        bytes: PoolCredentialBytes,
        relay_certificate: Vec<u8>,
        service: String,
        audience: String,
        cancellation: &CancellationToken,
    ) -> std::result::Result<RemoteLiveTunnelServerPublication, ControlHTTPSFailure> {
        if self.relay_transport.is_none()
            || !bytes.activation.is_empty()
            || bytes.artifact.len() > 65536
            || bytes.artifact.capacity() > 65536
            || bytes.client_certificate.len() > 8192
            || bytes.client_certificate.capacity() > 8192
            || bytes.server_certificate.len() > 8192
            || bytes.server_certificate.capacity() > 8192
            || relay_certificate.is_empty()
            || relay_certificate.len() > 8192
            || relay_certificate.capacity() > 8192
            || service.is_empty()
            || service.len() > 128
            || service.capacity() > 256
            || audience.is_empty()
            || audience.len() > 128
            || audience.capacity() > 256
        {
            return Err(ControlHTTPSFailure::Configuration);
        }
        let artifact = decode(&bytes.artifact, "Artifact", 65536, Context::default())
            .map_err(|_| ControlHTTPSFailure::Configuration)?;
        if artifact
            .field("Artifact", "candidates")
            .and_then(|candidates| candidates.len())
            .map_err(|_| ControlHTTPSFailure::Configuration)?
            != 1
            || artifact
                .field("Artifact", "candidates")
                .and_then(|candidates| candidates.at(0))
                .and_then(|candidate| candidate.u("Candidate", "path_kind"))
                .map_err(|_| ControlHTTPSFailure::Configuration)?
                != 1
        {
            return Err(ControlHTTPSFailure::Configuration);
        }
        let cutoff = artifact
            .u("Artifact", "initiation_not_after_ms")
            .map_err(|_| ControlHTTPSFailure::Configuration)?;
        if self
            .root
            .sample()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?
            .upper_ms
            >= cutoff
        {
            return Err(ControlHTTPSFailure::Deadline);
        }
        let charge = crate::control_https_v4::ControlHTTPSCustody::new_environment(
            self.root
                .reserve_environment(ResourceLimits {
                    sdk_bytes: 4 * MAX_REQUEST as u64 + 4096,
                    items: 4,
                    work_slots: 1,
                    ..ResourceLimits::default()
                })
                .map_err(|_| ControlHTTPSFailure::Capacity)?,
        );
        let request = Zeroizing::new(encode_envelope(
            b"live-server-register-tunnel-1",
            &[
                &bytes.artifact,
                &bytes.client_certificate,
                &bytes.server_certificate,
                &relay_certificate,
                service.as_bytes(),
                audience.as_bytes(),
            ],
        ));
        let guard = || self.check_original(cutoff, cancellation);
        let response = self
            .transport
            .post_owned(
                REGISTER_TUNNEL,
                &request,
                128,
                cancellation,
                true,
                &guard,
                charge.clone(),
            )
            .await?;
        let fields = decode_envelope(&response, b"live-server-registration-1", 1)
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        let token = fields[0]
            .try_into()
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
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
        Ok(RemoteLiveTunnelServerPublication {
            delivery: self.clone(),
            token: Zeroizing::new(token),
            cutoff,
            _charge: charge,
        })
    }
}
impl RemoteLiveServerPublication {
    /// Consume once from the original confirmed TxB continuation, before
    /// returning authorization to the client. Any missing ACK is unknown;
    /// it must never cause another publication or an authorization reply.
    pub async fn publish_original(
        self,
        proof: Vec<u8>,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(), ControlHTTPSFailure> {
        if proof.is_empty() || proof.len() > 4096 || proof.capacity() > 4096 {
            return Err(ControlHTTPSFailure::Configuration);
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
        let request = Zeroizing::new(encode_envelope(
            b"live-server-publish-1",
            &[self.token.as_ref(), &proof],
        ));
        let guard = || self.delivery.check_original(self.cutoff, cancellation);
        let response = self
            .delivery
            .transport
            .post_owned(
                PUBLISH,
                &request,
                128,
                cancellation,
                true,
                &guard,
                self._charge.clone(),
            )
            .await?;
        let fields = decode_envelope(&response, b"live-server-published-1", 1)
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        if fields[0] != self.token.as_ref() {
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
impl RemoteLiveTunnelServerPublication {
    /// Publish only from the same original confirmed TxB continuation. An
    /// uncertain response consumes this capability and never authorizes retry.
    pub async fn publish_tunnel_original(
        self,
        relay_request_bytes: Vec<u8>,
        activation: Vec<u8>,
        server_grant: Vec<u8>,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(), ControlHTTPSFailure> {
        let relay_request_bytes = Zeroizing::new(relay_request_bytes);
        let activation = Zeroizing::new(activation);
        let server_grant = Zeroizing::new(server_grant);
        if relay_request_bytes.is_empty()
            || relay_request_bytes.len() > 8192
            || relay_request_bytes.capacity() > 8192
            || activation.is_empty()
            || activation.len() > 4096
            || activation.capacity() > 4096
            || server_grant.is_empty()
            || server_grant.len() > 9302
            || server_grant.capacity() > 9302
        {
            return Err(ControlHTTPSFailure::Configuration);
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
        let relay = self
            .delivery
            .relay_transport
            .as_ref()
            .ok_or(ControlHTTPSFailure::Configuration)?;
        // Install this exact server leg at the prepared RelayHost before the
        // original publication can be acknowledged. An uncertain result is
        // terminal: this capability is consumed and cannot retry either leg.
        let relay_request = Zeroizing::new(encode_envelope(
            b"tunnel-relay-server-grant-1",
            &[&relay_request_bytes, &activation, &server_grant],
        ));
        let guard = || self.delivery.check_original(self.cutoff, cancellation);
        let relay_response = relay
            .post_owned(
                "/tunnel/relay-server-grant",
                &relay_request,
                1,
                cancellation,
                true,
                &guard,
                self._charge.clone(),
            )
            .await?;
        if relay_response.as_slice() != [0xf5] {
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
        let request = Zeroizing::new(encode_envelope(
            b"live-server-publish-tunnel-1",
            &[self.token.as_ref(), &activation, &server_grant],
        ));
        let response = self
            .delivery
            .transport
            .post_owned(
                PUBLISH_TUNNEL,
                &request,
                128,
                cancellation,
                true,
                &guard,
                self._charge.clone(),
            )
            .await?;
        let fields = decode_envelope(&response, b"live-server-published-1", 1)
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        if fields[0] != self.token.as_ref() {
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
// This reference control protocol has a closed, exact canonical CBOR envelope.
// It is outside the authenticated wire schema and has no permissive map parser.
pub(crate) fn encode_envelope(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        tag.len() + fields.iter().map(|field| field.len() + 9).sum::<usize>() + 16,
    );
    codec::encode_head(&mut output, 4, (fields.len() + 1) as u64);
    codec::encode_head(&mut output, 3, tag.len() as u64);
    output.extend_from_slice(tag);
    for field in fields {
        codec::encode_head(&mut output, 2, field.len() as u64);
        output.extend_from_slice(field);
    }
    output
}
pub(crate) fn decode_envelope<'a>(
    raw: &'a [u8],
    tag: &[u8],
    count: usize,
) -> ConnectResult<Vec<&'a [u8]>> {
    fn head(raw: &[u8], offset: &mut usize, major: u8) -> ConnectResult<usize> {
        let first = *raw.get(*offset).ok_or(ConnectError::Configuration)?;
        *offset += 1;
        if first >> 5 != major {
            return Err(ConnectError::Configuration);
        }
        let extra = first & 31;
        let value = if extra < 24 {
            u64::from(extra)
        } else {
            if extra > 27 {
                return Err(ConnectError::Configuration);
            }
            let width = 1usize << (extra - 24);
            let end = offset
                .checked_add(width)
                .ok_or(ConnectError::Configuration)?;
            let bytes = raw.get(*offset..end).ok_or(ConnectError::Configuration)?;
            *offset = end;
            let value = bytes
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
            if value < [24, 256, 65536, 4294967296][usize::from(extra - 24)] {
                return Err(ConnectError::Configuration);
            }
            value
        };
        usize::try_from(value).map_err(|_| ConnectError::Configuration)
    }
    fn take<'a>(raw: &'a [u8], offset: &mut usize, major: u8) -> ConnectResult<&'a [u8]> {
        let length = head(raw, offset, major)?;
        let end = offset
            .checked_add(length)
            .ok_or(ConnectError::Configuration)?;
        let value = raw.get(*offset..end).ok_or(ConnectError::Configuration)?;
        *offset = end;
        Ok(value)
    }
    if raw.len() > MAX_REQUEST || count > 16 {
        return Err(ConnectError::Capacity);
    }
    let mut offset = 0;
    if head(raw, &mut offset, 4)? != count + 1 || take(raw, &mut offset, 3)? != tag {
        return Err(ConnectError::Configuration);
    }
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let field = take(raw, &mut offset, 2)?;
        if field.is_empty() {
            return Err(ConnectError::Configuration);
        }
        fields.push(field);
    }
    if offset != raw.len() {
        return Err(ConnectError::Configuration);
    }
    Ok(fields)
}
