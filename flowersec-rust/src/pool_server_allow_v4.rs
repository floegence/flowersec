//! Original pool B Allow intake. The finite index belongs to one Serve; no
//! lookup, reconstructed spend record or replacement listener can recreate it.
use super::super::live_source::remote::{installed_control_tls, validate_certificates};
use super::*;
use crate::codec_v4::{Limits, decode_control_array};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, net::SocketAddr, sync::Weak};
use zeroize::Zeroizing;

const MAX_REQUEST: usize = 66560;

/// Independently installed A-to-B control identity and destination. Every
/// fixed pool slot in this Serve is authorized for this exact coordinator.
#[derive(Debug)]
pub struct PoolServerAllowOptions {
    pub listen_address: SocketAddr,
    pub authority: String,
    pub client_roots_der: Vec<Vec<u8>>,
    pub coordinator_leaf_digest: [u8; 32],
    pub timeout: Duration,
    pub provider_runtime_bytes: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct PoolServerAllowBinding {
    pub recipient: [u8; 16],
    pub incarnation: [u8; 16],
}
struct Execution {
    phase: u8, // 0: awaiting Allow, 1: original dispatch, 2: terminal.
    cutoff: Option<u64>,
    deadline: Option<Instant>,
}
struct Entry {
    expected: Zeroizing<Vec<u8>>,
    account: ResourceAccount,
    cutoff: u64,
    deadline: Instant,
    execution: Mutex<Execution>,
}
pub(super) struct PoolAllow {
    root: Arc<EnvironmentRoot>,
    owner: Weak<ServeOwner>,
    binding: PoolServerAllowBinding,
    entries: Vec<Entry>,
    installed: AtomicBool,
    physical: AtomicUsize,
    changed: Notify,
    cancellation: CancellationToken,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for PoolAllow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalPoolAllow { <opaque> }")
    }
}
impl PoolAllow {
    pub(super) fn new(
        owner: &Arc<ServeOwner>,
        materials: &[(
            PoolConnectionMaterial,
            EnvironmentCharge,
            Option<super::super::live_source::OriginalLiveServerPreparation>,
        )],
        cancellation: CancellationToken,
    ) -> ConnectResult<Arc<Self>> {
        let charge = owner.root.reserve_environment(ResourceLimits {
            sdk_bytes: 4096 + materials.len() as u64 * 14336,
            items: materials.len() as u64 + 1,
            timers: materials.len() as u64,
            work_slots: materials.len() as u64,
            ..ResourceLimits::default()
        })?;
        let mut binding = PoolServerAllowBinding {
            recipient: [0; 16],
            incarnation: [0; 16],
        };
        for bytes in [&mut binding.recipient, &mut binding.incarnation] {
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), bytes)
                .map_err(|_| ConnectError::Configuration)?;
            if *bytes == [0; 16] {
                return Err(ConnectError::Configuration);
            }
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(materials.len());
        for (material, _, _) in materials {
            let admission = &material.admission;
            let facts = admission
                .tunnel
                .as_ref()
                .ok_or(ConnectError::Configuration)?;
            let credentials = material
                .tunnel_credentials
                .as_ref()
                .ok_or(ConnectError::Configuration)?;
            if facts.endpoint_role != 1 {
                return Err(ConnectError::Configuration);
            }
            let parent = decode(
                &material.bytes.artifact,
                "Artifact",
                65536,
                Context::default(),
            )?;
            let grant = decode(&credentials.grant, "Grant", 9302, Context::default())?;
            let cutoff = admission
                .initiation_not_after_ms
                .min(parent.u("Artifact", "session_not_after_ms")?)
                .min(grant.u("Grant", "not_after_ms")?);
            let now = owner.root.sample()?;
            if now.upper_ms >= cutoff {
                return Err(ConnectError::Deadline);
            }
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(cutoff - now.upper_ms))
                .ok_or(ConnectError::Configuration)?;
            let mut expected = Zeroizing::new(Vec::with_capacity(12288));
            codec::encode_head(&mut expected, 4, 14);
            t(&mut expected, "tunnel-server-allow-1");
            t(
                &mut expected,
                parent.field("Artifact", "tenant_id")?.text()?,
            );
            t(&mut expected, parent.field("Artifact", "audience")?.text()?);
            for value in [
                admission.artifact_digest.as_slice(),
                facts.grant_digest.as_slice(),
                facts.relay_identity_digest.as_slice(),
                admission.attempt_id.as_slice(),
                facts.pairing_id.as_slice(),
                facts.leg_id.as_slice(),
                binding.recipient.as_slice(),
                binding.incarnation.as_slice(),
            ] {
                b(&mut expected, value);
            }
            codec::encode_head(&mut expected, 4, 3);
            u(
                &mut expected,
                u64::from(
                    admission
                        .pool
                        .as_ref()
                        .ok_or(ConnectError::Configuration)?
                        .candidate_index,
                ),
            );
            b(&mut expected, &admission.candidate_id);
            b(&mut expected, &admission.route_digest);
            u(&mut expected, cutoff);
            b(&mut expected, &credentials.grant);
            // Duplicate keys never obtain a second physical dispatch slot.
            let request = decode_request(&expected)?;
            if entries.iter().any(|entry| {
                decode_request(&entry.expected)
                    .is_ok_and(|old| old.at(4).ok() == request.at(4).ok())
            }) {
                return Err(ConnectError::Configuration);
            }
            entries.push(Entry {
                expected,
                account: admission.account.clone(),
                cutoff,
                deadline,
                execution: Mutex::new(Execution {
                    phase: 0,
                    cutoff: None,
                    deadline: None,
                }),
            });
        }
        Ok(Arc::new(Self {
            root: owner.root.clone(),
            owner: Arc::downgrade(owner),
            binding,
            entries,
            installed: AtomicBool::new(false),
            physical: AtomicUsize::new(0),
            changed: Notify::new(),
            cancellation,
            _charge: charge,
        }))
    }
    fn check(&self) -> ConnectResult<Arc<ServeOwner>> {
        let owner = self.owner.upgrade().ok_or(ConnectError::Canceled)?;
        if self.root.is_closed() || owner.stop.is_cancelled() || self.cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        Ok(owner)
    }
    pub(super) fn physical_pending(&self) -> u64 {
        self.physical.load(Ordering::Acquire) as u64
    }
    pub(super) async fn wait(
        &self,
        index: usize,
        cancel: &CancellationToken,
    ) -> ConnectResult<Instant> {
        let entry = self.entries.get(index).ok_or(ConnectError::Configuration)?;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let owner = self.check()?;
            entry.account.check()?;
            if cancel.is_cancelled() {
                return Err(ConnectError::Canceled);
            }
            if Instant::now() >= entry.deadline || self.root.sample()?.upper_ms >= entry.cutoff {
                return Err(ConnectError::Deadline);
            }
            {
                let execution = entry.execution.lock().expect("original Allow execution");
                match execution.phase {
                    1 => {
                        let deadline = execution.deadline.ok_or(ConnectError::Configuration)?;
                        if self.root.sample()?.upper_ms
                            >= execution.cutoff.ok_or(ConnectError::Configuration)?
                            || Instant::now() >= deadline
                        {
                            return Err(ConnectError::Deadline);
                        }
                        return Ok(deadline);
                    }
                    2 => return Err(ConnectError::Canceled),
                    _ => {}
                }
            }
            tokio::select! {
                _ = changed => {}, _ = cancel.cancelled() => return Err(ConnectError::Canceled),
                _ = owner.stop.cancelled() => return Err(ConnectError::Canceled),
                _ = self.cancellation.cancelled() => return Err(ConnectError::Canceled),
                _ = tokio::time::sleep_until(entry.deadline) => return Err(ConnectError::Deadline),
            }
        }
    }
    pub(super) fn check_dispatch(&self, index: usize) -> ConnectResult<()> {
        self.check()?;
        let entry = &self.entries[index];
        entry.account.check()?;
        let execution = entry.execution.lock().expect("original Allow dispatch");
        if execution.phase != 1
            || Instant::now() >= execution.deadline.ok_or(ConnectError::Configuration)?
            || self.root.sample()?.upper_ms
                >= execution.cutoff.ok_or(ConnectError::Configuration)?
        {
            return Err(ConnectError::Authorization);
        }
        Ok(())
    }
    pub(super) fn retire(&self, index: usize) {
        self.entries[index]
            .execution
            .lock()
            .expect("original Allow terminal")
            .phase = 2;
        self.changed.notify_waiters();
    }
    fn receive(&self, bytes: &[u8]) -> ConnectResult<()> {
        self.check()?;
        let request = decode_request(bytes)?;
        let requested_cutoff = request.at(12)?.uint()?;
        let now = self.root.sample()?;
        for entry in &self.entries {
            let expected = decode_request(&entry.expected)?;
            if (0..14)
                .filter(|index| *index != 12)
                .any(|index| request.at(index).ok() != expected.at(index).ok())
            {
                continue;
            }
            entry.account.check()?;
            if requested_cutoff > entry.cutoff
                || now.upper_ms >= requested_cutoff
                || Instant::now() >= entry.deadline
            {
                return Err(ConnectError::Deadline);
            }
            let mut execution = entry.execution.lock().expect("original Allow once index");
            self.check()?;
            if execution.phase == 2
                || execution
                    .cutoff
                    .is_some_and(|cutoff| cutoff != requested_cutoff)
            {
                return Err(ConnectError::Authorization);
            }
            // The exact slot and once responsibility exist before waking any
            // provider preparation. Repeated valid arrivals join this slot.
            if execution.phase == 0 {
                execution.deadline = Some(
                    entry.deadline.min(
                        Instant::now()
                            .checked_add(Duration::from_millis(requested_cutoff - now.upper_ms))
                            .ok_or(ConnectError::Configuration)?,
                    ),
                );
            }
            if execution
                .deadline
                .is_none_or(|deadline| Instant::now() >= deadline)
            {
                return Err(ConnectError::Deadline);
            }
            execution.cutoff = Some(requested_cutoff);
            execution.phase = 1;
            drop(execution);
            self.changed.notify_waiters();
            return Ok(());
        }
        Err(ConnectError::Authorization)
    }
    pub(super) async fn install(
        self: &Arc<Self>,
        identity: WssServerIdentity,
        options: PoolServerAllowOptions,
    ) -> ConnectResult<PoolServerAllowBinding> {
        let owner = self.check()?;
        if options.listen_address.port() == 0
            || options.authority.is_empty()
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
                .any(|cert| cert.is_empty() || cert.len() > 65536 || cert.capacity() > 65536)
            || options.coordinator_leaf_digest == [0; 32]
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(2)
            || !(1048576..=1073741824).contains(&options.provider_runtime_bytes)
            || identity.certificate_chain_der.is_empty()
            || identity.certificate_chain_der.len() > 16
            || identity.certificate_chain_der.capacity() > 16
            || identity
                .certificate_chain_der
                .iter()
                .any(|cert| cert.is_empty() || cert.len() > 65536 || cert.capacity() > 65536)
            || identity.private_key_der.is_empty()
            || identity.private_key_der.len() > 8192
            || identity.private_key_der.capacity() > 8192
        {
            return Err(ConnectError::Configuration);
        }
        {
            let gate = owner.gate.lock().expect("original Allow installation gate");
            if gate.closed || owner.root.is_closed() || self.cancellation.is_cancelled() {
                return Err(ConnectError::Canceled);
            }
            self.installed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ConnectError::Configuration)?;
            self.physical.store(1, Ordering::Release);
        }
        let tail = ReceiverTail {
            registry: self.clone(),
            owner: owner.clone(),
        };
        // One serial TLS/HTTP worker bounds native buffers, body, parser, timer
        // and callback work before accept. The worker drops this charge last.
        let configuration_bytes = options
            .client_roots_der
            .iter()
            .map(Vec::capacity)
            .sum::<usize>()
            + identity
                .certificate_chain_der
                .iter()
                .map(Vec::capacity)
                .sum::<usize>()
            + identity.private_key_der.capacity()
            + options.authority.capacity();
        let charge = self.root.reserve_environment(ResourceLimits {
            sdk_bytes: 4194304 + configuration_bytes as u64 * 3,
            provider_bytes: options.provider_runtime_bytes,
            items: 24,
            tasks: 1,
            timers: 1,
            native_handles: 2,
            connections: 1,
            tls_handshakes: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let (tls, validity) =
            installed_control_tls(&self.root, &identity, &options.client_roots_der)?;
        let listener = tokio::net::TcpListener::bind(options.listen_address)
            .await
            .map_err(|_| ConnectError::Carrier)?;
        self.check()?;
        let current = self.clone();
        tokio::spawn(async move {
            let _tail = tail;
            let _charge = charge;
            let tls = Arc::new(tls);
            loop {
                if current.check().is_err() {
                    break;
                }
                let accepted = tokio::select! {
                    value = listener.accept() => value,
                    _ = owner.stop.cancelled() => break,
                    _ = current.cancellation.cancelled() => break,
                };
                let Ok((socket, _)) = accepted else {
                    owner.close();
                    break;
                };
                let until = Instant::now() + options.timeout;
                tokio::select! {
                    _ = connection(current.clone(), socket, tls.clone(), &options, validity) => {},
                    _ = owner.stop.cancelled() => break,
                    _ = current.cancellation.cancelled() => break,
                    _ = tokio::time::sleep_until(until) => {},
                }
            }
            drop(listener);
            drop(tls);
            drop(options);
            drop(_charge);
            drop(_tail);
        });
        Ok(self.binding)
    }
}
struct ReceiverTail {
    registry: Arc<PoolAllow>,
    owner: Arc<ServeOwner>,
}
impl Drop for ReceiverTail {
    fn drop(&mut self) {
        self.registry.physical.store(0, Ordering::Release);
        self.owner.changed.notify_waiters();
    }
}
fn decode_request(bytes: &[u8]) -> ConnectResult<codec::Value<'_>> {
    let value = decode_control_array(
        bytes,
        Limits {
            bytes: MAX_REQUEST,
            nodes: 18,
        },
    )?;
    if value.len()? != 14 || value.at(0)?.text()? != "tunnel-server-allow-1" {
        return Err(ConnectError::Configuration);
    }
    Ok(value)
}
async fn connection(
    registry: Arc<PoolAllow>,
    socket: tokio::net::TcpStream,
    tls: Arc<rustls::ServerConfig>,
    options: &PoolServerAllowOptions,
    server_validity: (u64, u64),
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
        || certificates.iter().map(|cert| cert.len()).sum::<usize>() > 131072
    {
        return Err(ConnectError::Tls);
    }
    if <[u8; 32]>::from(Sha256::digest(certificates[0].as_ref())) != options.coordinator_leaf_digest
    {
        return Err(ConnectError::Authorization);
    }
    let validity = validate_certificates(
        &registry.root,
        &certificates
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect::<Vec<_>>(),
    )?;
    let once = AtomicBool::new(false);
    let service = hyper::service::service_fn(|request| {
        let registry = registry.clone();
        let once = &once;
        async move {
            let result = if once.swap(true, Ordering::AcqRel) {
                Err(ConnectError::Authorization)
            } else {
                receive_http(
                    registry,
                    request,
                    &options.authority,
                    (
                        validity.0.max(server_validity.0),
                        validity.1.min(server_validity.1),
                    ),
                )
                .await
            };
            let (status, body) = if result.is_ok() {
                (http::StatusCode::OK, 0xf5)
            } else {
                (http::StatusCode::FORBIDDEN, 0xf6)
            };
            Ok::<_, Infallible>(
                http::Response::builder()
                    .status(status)
                    .header("content-type", "application/cbor")
                    .header("content-length", "1")
                    .header("cache-control", "no-store")
                    .header("connection", "close")
                    .body(Full::new(Bytes::from(vec![body])))
                    .expect("fixed Allow response"),
            )
        }
    });
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .max_buf_size(16384)
        .max_headers(16)
        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
        .await
        .map_err(|_| ConnectError::Carrier)
}
async fn receive_http(
    registry: Arc<PoolAllow>,
    request: http::Request<hyper::body::Incoming>,
    authority: &str,
    validity: (u64, u64),
) -> ConnectResult<()> {
    registry.check()?;
    let headers = request.headers();
    if request.method() != http::Method::POST
        || request.version() != http::Version::HTTP_11
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().query().is_some()
        || request.uri().path() != "/tunnel/server-allow"
        || ["host", "content-type", "content-length"]
            .iter()
            .any(|name| headers.get_all(*name).iter().count() != 1)
        || headers.get("host").and_then(|value| value.to_str().ok()) != Some(authority)
        || headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            != Some("application/cbor")
        || ["transfer-encoding", "content-encoding", "expect"]
            .iter()
            .any(|name| headers.contains_key(*name))
    {
        return Err(ConnectError::Configuration);
    }
    let length_text = headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .ok_or(ConnectError::Configuration)?;
    let length = length_text
        .parse::<usize>()
        .map_err(|_| ConnectError::Configuration)?;
    if length == 0 || length > MAX_REQUEST || length.to_string() != length_text {
        return Err(ConnectError::Capacity);
    }
    let mut body = request.into_body();
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
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
    let now = registry.root.sample()?;
    if now.lower_ms < validity.0 || now.upper_ms >= validity.1 {
        return Err(ConnectError::Tls);
    }
    registry.receive(&bytes)
}
