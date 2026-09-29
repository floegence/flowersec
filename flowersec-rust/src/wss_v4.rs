//! One bounded native TLS/WebSocket worker per original prepared carrier.
use super::*;
use crate::api_v4::CleanupStatus;
use futures_util::{SinkExt, StreamExt};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::{
        Resumption, WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
use x509_parser::{
    extensions::ParsedExtension,
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY},
    prelude::{FromDer, X509Certificate, X509Version},
};
pub(super) type RequestAuthorizationFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<
                    super::serve::RequestAuthorization,
                    super::serve::ServeError,
                >,
            > + Send,
    >,
>;
pub(super) struct AcceptHooks<R, A> {
    pub(super) retain: R,
    pub(super) authorize: A,
}
#[derive(Clone, Debug)]
struct PinPolicy {
    digest: [u8; 32],
    start: u64,
    end: u64,
}
#[derive(Clone, Debug)]
pub(super) struct Policy {
    artifact: [u8; 32],
    binding_mode: BindingMode,
    host: String,
    port: u16,
    path: String,
    subprotocol: String,
    origin: Option<String>,
    pins: Option<Vec<PinPolicy>>,
    maximum: usize,
    live_maximum: usize,
    ca: Vec<Vec<u8>>,
}
impl Policy {
    pub(super) fn new(
        material: &PoolConnectionMaterial,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        if options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
            || options.publication_timeout.is_zero()
            || options.publication_timeout > Duration::from_secs(5)
            || !(1..=64).contains(&options.queue_messages)
            || !(16_384..=262_144).contains(&options.prepare_bytes)
            || options.native_runtime_bytes < 1 << 20
        {
            return Err(ConnectError::Configuration);
        }
        let artifact = decode(
            &material.bytes.artifact,
            "Artifact",
            65536,
            Context::default(),
        )?;
        let candidate = artifact.field("Artifact", "candidates")?.at(0)?;
        let leg = candidate.field("Candidate", "direct_leg")?;
        if candidate.u("Candidate", "path_kind")? != 0
            || leg.u("Leg", "access_class")? != 0
            || leg.u("Leg", "carrier")? != 1
            || leg.field("Leg", "alpn")?.text()? != "http/1.1"
            || leg.field("Leg", "path")?.text()? != "/flowersec/v4/direct"
            || leg.field("Leg", "subprotocol")?.text()? != "flowersec.direct.v4"
        {
            return Err(ConnectError::Configuration);
        }
        let host = leg.field("Leg", "host")?.text()?.to_owned();
        if host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip != options.remote_address)
        {
            return Err(ConnectError::Configuration);
        }
        let origin = options.origin.clone();
        if let Some(policy) = leg.optional("Leg", "origin_policy")? {
            match &origin {
                None => {
                    if !policy.field("OriginPolicy", "allow_absent")?.boolean()? {
                        return Err(ConnectError::Configuration);
                    }
                }
                Some(value) => {
                    if !policy
                        .field("OriginPolicy", "origins")?
                        .children()?
                        .any(|v| v.is_ok_and(|v| v.text() == Ok(value.as_str())))
                    {
                        return Err(ConnectError::Configuration);
                    }
                }
            }
        } else if origin.is_some() {
            return Err(ConnectError::Configuration);
        }
        let activation = decode(
            &material.bytes.activation,
            "ActivationAuthorization",
            4096,
            Context::with_activation_source(codec::ActivationSource::PreauthorizedPool),
        )?;
        let budget = activation
            .field("ActivationAuthorization", "candidate_selection")?
            .field("PoolSelectionRef", "attempt_budget")?;
        let per = budget.field("PoolAttemptBudget", "per_candidate")?;
        if per.u("CandidateAttemptBudget", "preauth_bytes")? < options.prepare_bytes as u64
            || budget.u("PoolAttemptBudget", "total_preauth_bytes")? < options.prepare_bytes as u64
        {
            return Err(ConnectError::Configuration);
        }
        let tls = leg.field("Leg", "tls_policy")?;
        let pins = if tls.u("TLSPolicy", "mode")? == 0 {
            if options.ca_certificates_der.is_empty()
                || options.ca_certificates_der.len() > 64
                || options
                    .ca_certificates_der
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>()
                    > 262144
            {
                return Err(ConnectError::Configuration);
            }
            None
        } else {
            let mut pins = Vec::new();
            for p in tls.field("TLSPolicy", "pins")?.children()? {
                let p = p?;
                pins.push(PinPolicy {
                    digest: p.b("TLSPin", "leaf_der_sha256")?,
                    start: p.u("TLSPin", "not_before_ms")?,
                    end: p.u("TLSPin", "not_after_ms")?,
                });
            }
            let now = material.admission.account.security_time()?;
            pins.retain(|p| now.lower_ms >= p.start && now.upper_ms < p.end);
            if pins.is_empty() {
                return Err(ConnectError::Tls);
            }
            Some(pins)
        };
        let maximum = artifact
            .field("Artifact", "session_contract")?
            .u("SessionContract", "max_frame")? as usize
            + 8;
        if options.native_runtime_bytes
            < (maximum.max(65544) * 2 + options.prepare_bytes + 196608) as u64
        {
            return Err(ConnectError::Capacity);
        }
        Ok(Self {
            artifact: material.admission.artifact_digest,
            binding_mode: options.binding_mode,
            host,
            port: leg.u("Leg", "port")? as u16,
            path: leg.field("Leg", "path")?.text()?.to_owned(),
            subprotocol: leg.field("Leg", "subprotocol")?.text()?.to_owned(),
            origin,
            pins,
            maximum: maximum.max(65544),
            live_maximum: maximum,
            ca: options.ca_certificates_der.clone(),
        })
    }
}
#[derive(Debug)]
struct Clock(ResourceAccount);
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        self.0
            .security_time()
            .ok()
            .map(|n| UnixTime::since_unix_epoch(Duration::from_millis(n.upper_ms)))
    }
}
#[derive(Debug)]
struct Verifier {
    account: ResourceAccount,
    ca: Option<Arc<WebPkiServerVerifier>>,
    pins: Option<Vec<PinPolicy>>,
    supported: WebPkiSupportedAlgorithms,
    validity: Arc<Mutex<Option<(u64, u64)>>>,
}
fn tls_error() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}
pub(super) fn interval(
    der: &[u8],
    now: crate::environment_v4::TrustedTimeSample,
) -> std::result::Result<(u64, u64), rustls::Error> {
    let (remaining, cert) = X509Certificate::from_der(der).map_err(|_| tls_error())?;
    let start = u64::try_from(cert.validity().not_before.timestamp())
        .ok()
        .and_then(|n| n.checked_mul(1000))
        .ok_or_else(tls_error)?;
    let end = u64::try_from(cert.validity().not_after.timestamp())
        .ok()
        .and_then(|n| n.checked_mul(1000))
        .ok_or_else(tls_error)?;
    if !remaining.is_empty() || now.lower_ms < start || now.upper_ms >= end {
        return Err(tls_error());
    }
    Ok((start, end))
}
pub(super) fn pin_profile(der: &[u8]) -> std::result::Result<(), rustls::Error> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| tls_error())?;
    let key = cert.public_key();
    if cert.version() != X509Version::V3
        || key.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY
        || !key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .is_some_and(|oid| oid == OID_EC_P256)
        || cert
            .validity()
            .not_after
            .timestamp()
            .checked_sub(cert.validity().not_before.timestamp())
            .is_none_or(|d| d <= 0 || d > 1_209_600)
    {
        return Err(tls_error());
    }
    let mut seen = std::collections::HashSet::new();
    for extension in cert.extensions() {
        if !seen.insert(extension.oid.clone()) {
            return Err(tls_error());
        }
        match extension.parsed_extension() {
            ParsedExtension::KeyUsage(k) if !k.digital_signature() => return Err(tls_error()),
            ParsedExtension::ExtendedKeyUsage(k) if !k.server_auth && !k.any => {
                return Err(tls_error());
            }
            ParsedExtension::KeyUsage(_)
            | ParsedExtension::ExtendedKeyUsage(_)
            | ParsedExtension::BasicConstraints(_)
            | ParsedExtension::SubjectAlternativeName(_) => {}
            _ if extension.critical => return Err(tls_error()),
            _ => {}
        }
    }
    Ok(())
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if chain.len() > 15 || leaf.len() + chain.iter().map(|c| c.len()).sum::<usize>() > 262144 {
            return Err(tls_error());
        }
        let now = self.account.security_time().map_err(|_| tls_error())?;
        let (mut from, mut until) = interval(leaf.as_ref(), now)?;
        if let Some(ca) = &self.ca {
            ca.verify_server_cert(
                leaf,
                chain,
                name,
                ocsp,
                UnixTime::since_unix_epoch(Duration::from_millis(now.lower_ms)),
            )?;
            ca.verify_server_cert(
                leaf,
                chain,
                name,
                ocsp,
                UnixTime::since_unix_epoch(Duration::from_millis(now.upper_ms)),
            )?;
            for cert in chain {
                let (a, b) = interval(cert.as_ref(), now)?;
                from = from.max(a);
                until = until.min(b);
            }
        } else {
            pin_profile(leaf.as_ref())?;
            let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
            let pin = self
                .pins
                .as_ref()
                .and_then(|pins| {
                    pins.iter().find(|p| {
                        p.digest == digest
                            && p.start >= from
                            && p.end <= until
                            && now.lower_ms >= p.start
                            && now.upper_ms < p.end
                    })
                })
                .ok_or_else(tls_error)?;
            from = pin.start;
            until = pin.end;
        }
        *self.validity.lock().expect("TLS validity") = Some((from, until));
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls_error())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, signature, &self.supported)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
struct Meter {
    remaining: AtomicUsize,
    enabled: AtomicBool,
}
struct LimitedIo {
    tcp: TcpStream,
    meter: Arc<Meter>,
}
impl Meter {
    fn take(&self, count: usize) -> io::Result<()> {
        if self.enabled.load(Ordering::Acquire)
            && self
                .remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    n.checked_sub(count)
                })
                .is_err()
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}
impl AsyncRead for LimitedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let allowed = if self.meter.enabled.load(Ordering::Acquire) {
            out.remaining()
                .min(self.meter.remaining.load(Ordering::Acquire))
        } else {
            out.remaining()
        };
        if allowed == 0 && out.remaining() != 0 {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        let mut limited = ReadBuf::new(&mut out.initialize_unfilled()[..allowed]);
        match Pin::new(&mut self.tcp).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let count = limited.filled().len();
                self.meter.take(count)?;
                out.advance(count);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl AsyncWrite for LimitedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let allowed = if self.meter.enabled.load(Ordering::Acquire) {
            data.len().min(self.meter.remaining.load(Ordering::Acquire))
        } else {
            data.len()
        };
        if allowed == 0 && !data.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        match Pin::new(&mut self.tcp).poll_write(cx, &data[..allowed]) {
            Poll::Ready(Ok(n)) => Poll::Ready(self.meter.take(n).map(|()| n)),
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}
struct SendCommand {
    wire: Vec<u8>,
    reply: oneshot::Sender<ConnectResult<()>>,
}
#[derive(Clone)]
enum Security {
    Account(ResourceAccount),
    Environment(Arc<EnvironmentRoot>),
}
enum ProviderCharge {
    Account(ResourceCharge),
    Environment(EnvironmentCharge),
}
struct BoundExporter {
    artifact: [u8; 32],
    value: Zeroizing<[u8; 32]>,
}
pub(crate) struct Provider {
    security: Mutex<Security>,
    id: [u8; 16],
    cancel: CancellationToken,
    commands: mpsc::Sender<SendCommand>,
    pending: AtomicUsize,
    read_stall: AtomicBool,
    stall_generation: AtomicU64,
    receivers: AtomicUsize,
    done: AtomicBool,
    live: AtomicBool,
    validity: Arc<Mutex<Option<(u64, u64)>>>,
    deadline: Instant,
    publication_timeout: Duration,
    maximum: usize,
    live_maximum: AtomicUsize,
    charge: Mutex<Option<ProviderCharge>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    exporter: Mutex<Option<BoundExporter>>,
    first_hello: Mutex<Option<Vec<u8>>>,
}
impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WssProvider { <opaque> }")
    }
}
impl Provider {
    pub(super) async fn prepare(
        account: ResourceAccount,
        policy: Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        let mut charge = account.reserve(ResourceLimits {
            sdk_bytes: (policy.maximum * (options.queue_messages + 4)) as u64 + 16_384,
            provider_bytes: options
                .native_runtime_bytes
                .checked_add(options.prepare_bytes as u64)
                .and_then(|n| n.checked_add(524_288))
                .ok_or(ConnectError::Capacity)?,
            items: (options.queue_messages + 8) as u64,
            work_slots: 4,
            tasks: 4,
            timers: 2,
            connections: 1,
            tls_handshakes: 1,
            native_handles: 8,
            ..ResourceLimits::default()
        })?;
        let tls_charge = charge.split(ResourceLimits {
            tls_handshakes: 1,
            ..ResourceLimits::default()
        })?;
        let (commands, rx) = mpsc::channel(1);
        let (incoming, input) = mpsc::channel(options.queue_messages);
        let (prepared, ready) = oneshot::channel();
        let mut id = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
            .map_err(|_| ConnectError::Carrier)?;
        let provider = Arc::new(Self {
            security: Mutex::new(Security::Account(account)),
            id,
            cancel: CancellationToken::new(),
            commands,
            pending: AtomicUsize::new(0),
            read_stall: AtomicBool::new(false),
            stall_generation: AtomicU64::new(0),
            receivers: AtomicUsize::new(0),
            done: AtomicBool::new(false),
            live: AtomicBool::new(false),
            validity: Arc::new(Mutex::new(None)),
            deadline,
            publication_timeout: options.publication_timeout,
            maximum: policy.maximum,
            live_maximum: AtomicUsize::new(policy.live_maximum),
            charge: Mutex::new(Some(ProviderCharge::Account(charge))),
            thread: Mutex::new(None),
            exporter: Mutex::new(None),
            first_hello: Mutex::new(None),
        });
        let mut guard = ConnectGuard(Some(provider.clone()));
        let worker = provider.clone();
        let thread = std::thread::Builder::new()
            .name("flowersec-v4-wss".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let _tail = WorkerTail(worker.clone());
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    runtime.block_on(
                        worker.drive(policy, options, rx, incoming, prepared, tls_charge),
                    );
                }
            })
            .map_err(|_| ConnectError::Capacity)?;
        *provider.thread.lock().expect("WSS thread") = Some(thread);
        let result = tokio::select! {_ = caller.cancelled()=>Err(ConnectError::Canceled),_ = tokio::time::sleep_until(deadline)=>Err(ConnectError::Deadline),result=ready=>result.map_err(|_|ConnectError::Carrier)?};
        result?;
        provider.check()?;
        guard.0 = None;
        Ok((provider, input))
    }
    fn account(&self) -> ConnectResult<ResourceAccount> {
        match &*self.security.lock().expect("WSS security owner") {
            Security::Account(account) => Ok(account.clone()),
            Security::Environment(_) => Err(ConnectError::Configuration),
        }
    }
    pub(super) fn attach(&self, account: ResourceAccount) -> ConnectResult<()> {
        let mut security = self.security.lock().expect("WSS security owner");
        let Security::Environment(root) = &*security else {
            return Err(ConnectError::Configuration);
        };
        if !account.belongs_to(root) {
            return Err(ConnectError::Configuration);
        }
        let mut charge = self.charge.lock().expect("WSS charge");
        let Some(ProviderCharge::Environment(held)) = charge.as_mut() else {
            return Err(ConnectError::Configuration);
        };
        let attached = held.attach(&account)?;
        *charge = Some(ProviderCharge::Account(attached));
        *security = Security::Account(account);
        Ok(())
    }
    pub(super) async fn accept(
        root: Arc<EnvironmentRoot>,
        tcp: std::net::TcpStream,
        policy: super::serve::SocketPolicy,
        deadline: Instant,
        caller: CancellationToken,
        charges: (EnvironmentCharge, EnvironmentCharge),
        hooks: AcceptHooks<
            impl FnOnce(Arc<Self>),
            impl FnOnce(super::serve::ServeRequestContext) -> RequestAuthorizationFuture,
        >,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        let AcceptHooks { retain, authorize } = hooks;
        let (charge, tls_charge) = charges;
        let (commands, rx) = mpsc::channel(1);
        let (incoming, input) = mpsc::channel(policy.queue_messages);
        let (prepared, ready) = oneshot::channel();
        let (request_sender, request_receiver) = oneshot::channel();
        let (decision_sender, decision_receiver) = std::sync::mpsc::sync_channel(1);
        let request_cancel = caller.clone();
        let mut id = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
            .map_err(|_| ConnectError::Carrier)?;
        let provider = Arc::new(Self {
            security: Mutex::new(Security::Environment(root)),
            id,
            cancel: CancellationToken::new(),
            commands,
            pending: AtomicUsize::new(0),
            read_stall: AtomicBool::new(false),
            stall_generation: AtomicU64::new(0),
            receivers: AtomicUsize::new(0),
            done: AtomicBool::new(false),
            live: AtomicBool::new(false),
            validity: Arc::new(Mutex::new(Some(policy.validity))),
            deadline,
            publication_timeout: policy.publication_timeout,
            maximum: policy.maximum,
            live_maximum: AtomicUsize::new(policy.maximum),
            charge: Mutex::new(Some(ProviderCharge::Environment(charge))),
            thread: Mutex::new(None),
            exporter: Mutex::new(None),
            first_hello: Mutex::new(None),
        });
        retain(provider.clone());
        let mut guard = ConnectGuard(Some(provider.clone()));
        let worker = provider.clone();
        let thread = std::thread::Builder::new()
            .name("flowersec-v4-wss-accept".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let _tail = WorkerTail(worker.clone());
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    runtime.block_on(async {
                        let established = tokio::select! {
                            _ = worker.cancel.cancelled() => Err(ConnectError::Canceled),
                            _ = tokio::time::sleep_until(deadline) => Err(ConnectError::Deadline),
                            result = worker.accept_socket(tcp, &policy, request_sender, decision_receiver, request_cancel) => result,
                        };
                        drop(tls_charge);
                        match established {
                            Ok(socket) => {
                                if prepared.send(Ok(())).is_ok() {
                                    worker.drive_socket(socket, rx, incoming).await;
                                }
                            }
                            Err(error) => {
                                let _ = prepared.send(Err(error));
                            }
                        }
                    });
                }
            })
            .map_err(|_| {
                provider.done.store(true, Ordering::Release);
                ConnectError::Capacity
            })?;
        *provider.thread.lock().expect("WSS thread") = Some(thread);
        let mut ready = ready;
        let result = tokio::select! {
            _ = caller.cancelled() => Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(deadline) => Err(ConnectError::Deadline),
            result = &mut ready => result.unwrap_or(Err(ConnectError::Carrier)),
            request = request_receiver => {
                let mut native_result = None;
                if let Ok(request) = request
                    && !caller.is_cancelled() && Instant::now() < deadline && provider.check().is_ok()
                {
                    // The callback runs on the original accepted task, outside
                    // the native worker. Cancellation closes the native path
                    // but cannot discard this future or its original charge.
                    let authorizing = authorize(request);
                    tokio::pin!(authorizing);
                    let allowed = tokio::select! {
                        result = &mut authorizing => result.is_ok_and(|r| r.allowed),
                        _ = caller.cancelled() => { provider.close(); let _ = authorizing.await; false },
                        _ = tokio::time::sleep_until(deadline) => { caller.cancel(); provider.close(); let _ = authorizing.await; false },
                        result = &mut ready => {
                            caller.cancel(); provider.close();
                            native_result = Some(result.unwrap_or(Err(ConnectError::Carrier)));
                            let _ = authorizing.await;
                            false
                        },
                    } && !caller.is_cancelled() && Instant::now() < deadline;
                    let _ = decision_sender.send(allowed);
                } else {
                    caller.cancel();
                    provider.close();
                }
                match native_result { Some(result) => result, None => ready.await.unwrap_or(Err(ConnectError::Carrier)) }
            }
        };
        if let Err(error) = result.and_then(|()| provider.check()) {
            provider.close();
            while !provider.cleanup().complete {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            return Err(error);
        }
        guard.0 = None;
        Ok((provider, input))
    }
    #[expect(
        clippy::result_large_err,
        reason = "Tungstenite fixes the HTTP error response type"
    )]
    async fn accept_socket(
        &self,
        tcp: std::net::TcpStream,
        policy: &super::serve::SocketPolicy,
        request_sender: oneshot::Sender<super::serve::ServeRequestContext>,
        decision_receiver: std::sync::mpsc::Receiver<bool>,
        caller: CancellationToken,
    ) -> ConnectResult<tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<LimitedIo>>>
    {
        self.check()?;
        let local_address = tcp.local_addr().map_err(|_| ConnectError::Carrier)?;
        let remote_address = tcp.peer_addr().map_err(|_| ConnectError::Carrier)?;
        let tcp = TcpStream::from_std(tcp).map_err(|_| ConnectError::Carrier)?;
        tcp.set_nodelay(true).map_err(|_| ConnectError::Carrier)?;
        let meter = Arc::new(Meter {
            remaining: AtomicUsize::new(policy.prepare_bytes),
            enabled: AtomicBool::new(true),
        });
        let tls = tokio_rustls::TlsAcceptor::from(policy.tls.clone())
            .accept(LimitedIo {
                tcp,
                meter: meter.clone(),
            })
            .await
            .map_err(|_| ConnectError::Tls)?;
        if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || tls.get_ref().1.alpn_protocol() != Some(b"http/1.1")
            || (policy.host.parse::<IpAddr>().is_err()
                && tls.get_ref().1.server_name() != Some(policy.host.as_str()))
        {
            return Err(ConnectError::Tls);
        }
        let config = WebSocketConfig::default()
            .read_buffer_size(16384)
            .write_buffer_size(0)
            .max_write_buffer_size(policy.maximum + 1024)
            .max_message_size(Some(policy.maximum))
            .max_frame_size(Some(policy.maximum));
        let mut socket = tokio_tungstenite::accept_hdr_async_with_config(tls, move |request: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
            let headers = request.headers();
            let origin = headers.get("origin").and_then(|v| v.to_str().ok());
            let valid_origin = match origin { None => policy.allow_absent_origin && !headers.contains_key("origin"), Some(origin) => policy.origins.iter().any(|v| v == origin) };
            if request.method() != "GET" || request.version() != http::Version::HTTP_11
                || headers.len() > 32 || headers.iter().map(|(k,v)| k.as_str().len() + v.as_bytes().len()).sum::<usize>() > 16384
                || headers.contains_key("content-length") || headers.contains_key("transfer-encoding")
                || request.uri().path_and_query().map(|v| v.as_str()) != Some("/flowersec/v4/direct")
                || headers.get_all("host").iter().count()!=1 || headers.get("host").and_then(|v|v.to_str().ok()) != Some(policy.authority.as_str())
                || headers.get_all("sec-websocket-protocol").iter().count()!=1 || headers.get("sec-websocket-protocol").and_then(|v|v.to_str().ok()) != Some("flowersec.direct.v4")
                || headers.get_all("origin").iter().count()>1 || headers.contains_key("sec-websocket-extensions") || !valid_origin {
                return Err(tokio_tungstenite::tungstenite::http::Response::builder().status(403).body(None).expect("fixed refusal"));
            }
            let context = super::serve::ServeRequestContext {
                method: "GET".into(), target: "/flowersec/v4/direct".into(), authority: policy.authority.clone(),
                origin: origin.map(str::to_owned), headers: headers.iter().map(|(k,v)| (k.as_str().to_owned(), v.as_bytes().to_vec())).collect(),
                local_address, remote_address, cancellation: caller.clone(),
            };
            let sent = request_sender.send(context).is_ok();
            let allowed = sent && loop {
                if caller.is_cancelled() || self.cancel.is_cancelled() || self.check().is_err() || Instant::now() >= self.deadline { break false; }
                match decision_receiver.recv_timeout(Duration::from_millis(10)) {
                    Ok(allowed) => break allowed,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
                    Err(_) => break false,
                }
            };
            if !allowed {
                return Err(tokio_tungstenite::tungstenite::http::Response::builder().status(403).body(None).expect("fixed refusal"));
            }
            response.headers_mut().insert("sec-websocket-protocol", "flowersec.direct.v4".parse().expect("fixed subprotocol"));
            Ok(response)
        }, Some(config)).await.map_err(|_|ConnectError::Carrier)?;
        meter.enabled.store(false, Ordering::Release);
        if policy.binding_mode == BindingMode::DirectExporter {
            // Retain the first original HELLO under the existing preauth
            // position before splitting TLS ownership. It is forwarded once
            // to the same accepted material lookup, never read a second time.
            let Message::Binary(wire) = socket
                .next()
                .await
                .ok_or(ConnectError::Carrier)?
                .map_err(|_| ConnectError::Carrier)?
            else {
                return Err(ConnectError::Protocol);
            };
            let hello = decode(
                payload(&wire, 1, 16384)?,
                "ClientHello",
                16384,
                Context::default(),
            )?;
            let artifact = hello.b::<32>("ClientHello", "artifact_digest")?;
            let tls = socket.get_ref().get_ref().1;
            if tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                return Err(ConnectError::Tls);
            }
            let value = tls
                .export_keying_material([0u8; 32], b"EXPORTER-flowersec-v4", Some(&artifact))
                .map_err(|_| ConnectError::Tls)?;
            self.install_exporter(artifact, value)?;
            *self.first_hello.lock().expect("original HELLO") = Some(wire.to_vec());
        }
        self.check()?;
        Ok(socket)
    }
    fn install_exporter(&self, artifact: [u8; 32], value: [u8; 32]) -> ConnectResult<()> {
        let value = Zeroizing::new(value);
        self.check()?;
        let mut exporter = self.exporter.lock().expect("original TLS binding");
        if exporter.is_some() || artifact == [0; 32] {
            return Err(ConnectError::Configuration);
        }
        *exporter = Some(BoundExporter { artifact, value });
        Ok(())
    }
    pub(super) fn binding(
        &self,
        mode: BindingMode,
        artifact: [u8; 32],
    ) -> ConnectResult<Option<Zeroizing<[u8; 32]>>> {
        self.check()?;
        if mode == BindingMode::AuthenticatedContext {
            return Ok(None);
        }
        let bound = self.exporter.lock().expect("original TLS binding");
        let bound = bound.as_ref().ok_or(ConnectError::Tls)?;
        if bound.artifact != artifact {
            return Err(ConnectError::Authorization);
        }
        Ok(Some(Zeroizing::new(*bound.value)))
    }
    pub(super) fn receiver(self: &Arc<Self>) -> ReceiverGuard {
        self.receivers.fetch_add(1, Ordering::AcqRel);
        ReceiverGuard(self.clone())
    }
    pub(super) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub(super) fn identity(&self) -> [u8; 16] {
        self.id
    }
    pub(super) fn check(&self) -> ConnectResult<()> {
        if self.cancel.is_cancelled() || self.done.load(Ordering::Acquire) {
            return Err(ConnectError::Carrier);
        }
        if !self.live.load(Ordering::Acquire) && Instant::now() >= self.deadline {
            return Err(ConnectError::Deadline);
        }
        let security = self.security.lock().expect("WSS security owner").clone();
        let now = match &security {
            Security::Account(account) => account.security_time()?,
            Security::Environment(root) => {
                if root.is_closed() {
                    return Err(ConnectError::Canceled);
                }
                root.sample()?
            }
        };
        if let Some((start, end)) = *self.validity.lock().expect("TLS validity")
            && (now.lower_ms < start || now.upper_ms >= end)
        {
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
    pub(super) fn activate(&self) {
        self.exporter.lock().expect("original TLS binding").take();
        self.live.store(true, Ordering::Release);
    }
    fn submit(&self, wire: Vec<u8>) -> ConnectResult<oneshot::Receiver<ConnectResult<()>>> {
        self.check()?;
        let maximum = if self.live.load(Ordering::Acquire) {
            self.live_maximum.load(Ordering::Acquire)
        } else {
            self.maximum
        };
        if wire.len() > maximum
            || self
                .pending
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(ConnectError::Capacity);
        }
        let (reply, wait) = oneshot::channel();
        if self.commands.try_send(SendCommand { wire, reply }).is_err() {
            self.pending.store(0, Ordering::Release);
            return Err(ConnectError::Carrier);
        }
        Ok(wait)
    }
    pub(super) async fn send(&self, wire: Vec<u8>) -> ConnectResult<()> {
        let wait = self.submit(wire)?;
        wait.await.map_err(|_| ConnectError::Carrier)??;
        self.check()
    }
    pub(crate) fn close(&self) {
        self.cancel.cancel();
    }
    pub(super) fn cleanup(&self) -> CleanupStatus {
        let mut thread = self.thread.lock().expect("WSS thread");
        let complete = self.done.load(Ordering::Acquire)
            && self.receivers.load(Ordering::Acquire) == 0
            && thread
                .as_ref()
                .is_none_or(std::thread::JoinHandle::is_finished);
        if complete && let Some(thread) = thread.take() {
            let _ = thread.join();
            if let Some(ProviderCharge::Account(charge)) =
                self.charge.lock().expect("WSS charge").take()
            {
                drop(charge);
            }
        }
        CleanupStatus {
            complete,
            cleanup_incomplete: false,
            pending_callbacks: (self.pending.load(Ordering::Acquire)
                + self.receivers.load(Ordering::Acquire)) as u64,
        }
    }
    async fn establish(
        &self,
        policy: &Policy,
        options: &WssConnectOptions,
    ) -> ConnectResult<tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<LimitedIo>>>
    {
        self.check()?;
        let account = self.account()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca = if policy.pins.is_none() {
            let mut roots = rustls::RootCertStore::empty();
            for der in &policy.ca {
                roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|_| ConnectError::Configuration)?;
            }
            Some(
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|_| ConnectError::Configuration)?,
            )
        } else {
            None
        };
        let verifier = Arc::new(Verifier {
            account: account.clone(),
            ca,
            pins: policy.pins.clone(),
            supported: provider.signature_verification_algorithms,
            validity: self.validity.clone(),
        });
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ConnectError::Configuration)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.time_provider = Arc::new(Clock(account));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        let remote = SocketAddr::new(options.remote_address, policy.port);
        let tcp = TcpStream::connect(remote)
            .await
            .map_err(|_| ConnectError::Carrier)?;
        if tcp.peer_addr().map_err(|_| ConnectError::Carrier)? != remote {
            return Err(ConnectError::Carrier);
        }
        tcp.set_nodelay(true).map_err(|_| ConnectError::Carrier)?;
        let meter = Arc::new(Meter {
            remaining: AtomicUsize::new(options.prepare_bytes),
            enabled: AtomicBool::new(true),
        });
        let io = LimitedIo {
            tcp,
            meter: meter.clone(),
        };
        let name =
            ServerName::try_from(policy.host.clone()).map_err(|_| ConnectError::Configuration)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, io)
            .await
            .map_err(|_| ConnectError::Tls)?;
        if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || tls.get_ref().1.alpn_protocol() != Some(b"http/1.1")
        {
            return Err(ConnectError::Tls);
        }
        self.check()?;
        let host = if policy.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", policy.host)
        } else {
            policy.host.clone()
        };
        let mut request = format!("wss://{}:{}{}", host, policy.port, policy.path)
            .into_client_request()
            .map_err(|_| ConnectError::Configuration)?;
        request.headers_mut().insert(
            "sec-websocket-protocol",
            policy
                .subprotocol
                .parse()
                .map_err(|_| ConnectError::Configuration)?,
        );
        if let Some(origin) = &policy.origin {
            request.headers_mut().insert(
                "origin",
                origin.parse().map_err(|_| ConnectError::Configuration)?,
            );
        }
        let config = WebSocketConfig::default()
            .read_buffer_size(16384)
            .write_buffer_size(0)
            .max_write_buffer_size(policy.maximum + 1024)
            .max_message_size(Some(policy.maximum))
            .max_frame_size(Some(policy.maximum));
        let (websocket, response) = client_async_with_config(request, tls, Some(config))
            .await
            .map_err(|_| ConnectError::Carrier)?;
        if response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            != Some(policy.subprotocol.as_str())
            || response.headers().contains_key("sec-websocket-extensions")
        {
            return Err(ConnectError::Carrier);
        }
        meter.enabled.store(false, Ordering::Release);
        if policy.binding_mode == BindingMode::DirectExporter {
            let tls = websocket.get_ref().get_ref().1;
            if tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                return Err(ConnectError::Tls);
            }
            // rustls consumes the complete label without adding a prefix.
            let value = tls
                .export_keying_material([0u8; 32], b"EXPORTER-flowersec-v4", Some(&policy.artifact))
                .map_err(|_| ConnectError::Tls)?;
            self.install_exporter(policy.artifact, value)?;
        }
        self.check()?;
        Ok(websocket)
    }
    async fn drive(
        &self,
        policy: Policy,
        options: WssConnectOptions,
        commands: mpsc::Receiver<SendCommand>,
        incoming: mpsc::Sender<Vec<u8>>,
        prepared: oneshot::Sender<ConnectResult<()>>,
        tls_charge: ResourceCharge,
    ) {
        let websocket = {
            let establishing = self.establish(&policy, &options);
            tokio::pin!(establishing);
            loop {
                tokio::select! {_ = self.cancel.cancelled()=>{let _=prepared.send(Err(ConnectError::Canceled));return;},_ = tokio::time::sleep(Duration::from_millis(10))=>{if let Err(e)=self.check(){let _=prepared.send(Err(e));return;}},result=&mut establishing=>match result{Ok(w)=>break w,Err(e)=>{let _=prepared.send(Err(e));return;}}}
            }
        };
        // The exact preparation future exited; this handshake position can
        // return independently of the still-owned socket/runtime tail.
        drop(tls_charge);
        if prepared.send(Ok(())).is_err() {
            return;
        }
        self.drive_socket(websocket, commands, incoming).await;
    }
    async fn drive_socket<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        websocket: tokio_tungstenite::WebSocketStream<S>,
        mut commands: mpsc::Receiver<SendCommand>,
        incoming: mpsc::Sender<Vec<u8>>,
    ) {
        let first = self.first_hello.lock().expect("original HELLO").take();
        if let Some(wire) = first
            && incoming.try_send(wire).is_err()
        {
            return;
        }
        let (mut sink, mut stream) = websocket.split();
        let writing = async {
            while let Some(command) = commands.recv().await {
                let result = match self.check() {
                    Err(e) => Err(e),
                    Ok(()) => match tokio::time::timeout(
                        self.publication_timeout,
                        sink.send(Message::Binary(command.wire.into())),
                    )
                    .await
                    {
                        Ok(Ok(())) => self.check(),
                        Ok(Err(_)) => Err(ConnectError::Carrier),
                        Err(_) => Err(ConnectError::Deadline),
                    },
                };
                self.pending.store(0, Ordering::Release);
                let failed = result.is_err();
                let _ = command.reply.send(result);
                if failed {
                    break;
                }
            }
        };
        let reading = async {
            while let Some(message) = stream.next().await {
                match message {
                    Ok(Message::Binary(bytes)) => {
                        let maximum = if self.live.load(Ordering::Acquire) {
                            self.live_maximum.load(Ordering::Acquire)
                        } else {
                            self.maximum
                        };
                        if bytes.len() > maximum || self.check().is_err() {
                            break;
                        }
                        match incoming.try_send(bytes.to_vec()) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                            Err(mpsc::error::TrySendError::Full(bytes)) => {
                                // Sticky generation survives a stall that ends
                                // before the original Session can reacquire its gate.
                                self.read_stall.store(true, Ordering::Release);
                                if self
                                    .stall_generation
                                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                                        n.checked_add(1)
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                                let result = incoming.send(bytes).await;
                                self.read_stall.store(false, Ordering::Release);
                                if result.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    _ => break,
                }
            }
        };
        tokio::select! {_ = self.cancel.cancelled()=>{},_ = writing=>{},_ = reading=>{},_ = async{loop{tokio::time::sleep(Duration::from_millis(10)).await;if self.check().is_err(){break;}}}=>{}}
    }
}
struct WorkerTail(Arc<Provider>);
impl Drop for WorkerTail {
    fn drop(&mut self) {
        self.0.cancel.cancel();
        self.0.exporter.lock().expect("original TLS binding").take();
        if let Some(mut wire) = self.0.first_hello.lock().expect("original HELLO").take() {
            wire.zeroize();
        }
        self.0.pending.store(0, Ordering::Release);
        self.0.done.store(true, Ordering::Release);
    }
}
pub(super) struct ReceiverGuard(Arc<Provider>);
impl Drop for ReceiverGuard {
    fn drop(&mut self) {
        self.0.receivers.fetch_sub(1, Ordering::AcqRel);
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
    fn liveness_stall_generation(&self) -> u64 {
        self.provider.stall_generation.load(Ordering::Acquire)
    }
    fn liveness_stalled(&self) -> bool {
        self.provider.read_stall.load(Ordering::Acquire)
    }
    fn publish(&mut self, wire: &[u8]) -> Result<()> {
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
            Ok(_) => {
                self.provider.close();
                Err(CryptoError::Configuration)
            }
            Err(_) => receive(),
        }
    }
}
impl SessionTransport for Transport {
    fn close(&mut self) {
        self.provider.close();
    }
    fn cleanup_status(&self) -> CleanupStatus {
        self.provider.cleanup()
    }
    fn stream_cleanup_status(&self, _: u64) -> CleanupStatus {
        CleanupStatus {
            complete: self.provider.pending.load(Ordering::Acquire) == 0,
            cleanup_incomplete: false,
            pending_callbacks: self.provider.pending.load(Ordering::Acquire) as u64,
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.provider.close();
    }
}
