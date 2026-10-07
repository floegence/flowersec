//! Fixed native mTLS control transport. Routing, roots and client credentials
//! are deployment inputs; a reply cannot redirect, refresh trust or select keys.
use crate::environment_v4::{EnvironmentRoot, ResourceLimits};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::{
        Resumption, WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpStream, task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct ControlHTTPSConfiguration {
    pub host: String,
    pub port: u16,
    pub remote_address: IpAddr,
    pub base_path: String,
    pub roots_der: Vec<Vec<u8>>,
    pub client_chain_der: Vec<Vec<u8>>,
    pub client_key_pkcs8: Zeroizing<Vec<u8>>,
    pub timeout: Duration,
    pub provider_runtime_bytes: u64,
}
impl fmt::Debug for ControlHTTPSConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlHTTPSConfiguration { <opaque> }")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ControlHTTPSFailure {
    #[error("control_configuration_invalid")]
    Configuration,
    #[error("control_configuration_capacity")]
    Capacity,
    #[error("control_canceled")]
    Canceled,
    #[error("control_deadline_exceeded")]
    Deadline,
    #[error("control_unavailable")]
    Unavailable,
    #[error("control_authority_rejected")]
    Rejected,
}
pub(crate) struct ControlHTTPS {
    root: Arc<EnvironmentRoot>,
    configuration: ControlHTTPSConfiguration,
    tls: Arc<rustls::ClientConfig>,
    busy: Arc<AtomicBool>,
    _charge: Arc<crate::environment_v4::EnvironmentCharge>,
}
impl fmt::Debug for ControlHTTPS {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlHTTPS { <opaque> }")
    }
}
#[derive(Debug)]
struct Clock(Arc<EnvironmentRoot>);
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        self.0
            .sample()
            .ok()
            .map(|now| UnixTime::since_unix_epoch(Duration::from_millis(now.upper_ms)))
    }
}
#[derive(Debug)]
struct Verifier {
    root: Arc<EnvironmentRoot>,
    inner: Arc<WebPkiServerVerifier>,
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let invalid = || {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        };
        if chain.len() > 16
            || leaf.len() > 65536
            || ocsp.len() > 8192
            || chain
                .iter()
                .map(|certificate| certificate.len())
                .sum::<usize>()
                > 131072
        {
            return Err(invalid());
        }
        let now = self.root.sample().map_err(|_| invalid())?;
        for certificate in std::iter::once(leaf).chain(chain) {
            use x509_parser::prelude::{FromDer, X509Certificate};
            let (remaining, parsed) =
                X509Certificate::from_der(certificate.as_ref()).map_err(|_| invalid())?;
            let start = u64::try_from(parsed.validity().not_before.timestamp())
                .ok()
                .and_then(|value| value.checked_mul(1000))
                .ok_or_else(invalid)?;
            let end = u64::try_from(parsed.validity().not_after.timestamp())
                .ok()
                .and_then(|value| value.checked_mul(1000))
                .ok_or_else(invalid)?;
            if !remaining.is_empty() || now.lower_ms < start || now.upper_ms >= end {
                return Err(invalid());
            }
        }
        self.inner.verify_server_cert(
            leaf,
            chain,
            name,
            ocsp,
            UnixTime::since_unix_epoch(Duration::from_millis(now.lower_ms)),
        )?;
        self.inner.verify_server_cert(
            leaf,
            chain,
            name,
            ocsp,
            UnixTime::since_unix_epoch(Duration::from_millis(now.upper_ms)),
        )?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.3 required".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
struct ControlPosition(Arc<AtomicBool>);
impl Drop for ControlPosition {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
/// Original Account and optional registration retirement retained by the
/// physical HTTP driver and every remaining request-body view.
pub(crate) struct ControlHTTPSCustody {
    charge: Option<crate::environment_v4::ResourceCharge>,
    environment_charge: Option<crate::environment_v4::EnvironmentCharge>,
    cleanup: Option<Box<dyn FnOnce() + Send + Sync>>,
}
impl ControlHTTPSCustody {
    pub(crate) fn new(charge: crate::environment_v4::ResourceCharge) -> Arc<Self> {
        Arc::new(Self {
            charge: Some(charge),
            environment_charge: None,
            cleanup: None,
        })
    }
    /// Issuer custody is rooted before endpoint admission; its original
    /// invocation prepayment still belongs to the actual writer lifetime.
    pub(crate) fn new_environment(charge: crate::environment_v4::EnvironmentCharge) -> Arc<Self> {
        Arc::new(Self {
            charge: None,
            environment_charge: Some(charge),
            cleanup: None,
        })
    }
    pub(crate) fn with_cleanup(
        charge: crate::environment_v4::ResourceCharge,
        cleanup: impl FnOnce() + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            charge: Some(charge),
            environment_charge: None,
            cleanup: Some(Box::new(cleanup)),
        })
    }
}
impl Drop for ControlHTTPSCustody {
    fn drop(&mut self) {
        self.charge.take();
        self.environment_charge.take();
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}
// Copies handed to the HTTP writer keep their original prepayment until the
// last body view is released, and clear credential bytes at that boundary.
struct ExchangeReservation {
    _account: Option<crate::environment_v4::ResourceCharge>,
    _environment: Option<crate::environment_v4::EnvironmentCharge>,
}
impl ExchangeReservation {
    fn reserve(
        root: &Arc<EnvironmentRoot>,
        custody: Option<&ControlHTTPSCustody>,
        value: ResourceLimits,
    ) -> Result<Arc<Self>, ControlHTTPSFailure> {
        if let Some(charge) = custody.and_then(|custody| custody.charge.as_ref()) {
            Ok(Arc::new(Self {
                _account: Some(
                    charge
                        .reserve_related(root, value)
                        .map_err(|_| ControlHTTPSFailure::Capacity)?,
                ),
                _environment: None,
            }))
        } else {
            Ok(Arc::new(Self {
                _account: None,
                _environment: Some(
                    root.reserve_environment(value)
                        .map_err(|_| ControlHTTPSFailure::Capacity)?,
                ),
            }))
        }
    }
}
struct RequestBody {
    bytes: Zeroizing<Vec<u8>>,
    _reservation: Arc<ExchangeReservation>,
    _transport: Arc<crate::environment_v4::EnvironmentCharge>,
    _position: Arc<ControlPosition>,
    _custody: Option<Arc<ControlHTTPSCustody>>,
}
impl AsRef<[u8]> for RequestBody {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
struct Driver(Option<JoinHandle<()>>);
impl Drop for Driver {
    fn drop(&mut self) {
        if let Some(driver) = &self.0 {
            driver.abort();
        }
    }
}
impl Driver {
    async fn close(mut self) {
        if let Some(driver) = self.0.take() {
            driver.abort();
            let _ = driver.await;
        }
    }
}
/// Native HTTP publication backing reserved by the original Connect before
/// pool consumption. Moving it into one exchange cannot authorize a replay.
pub(crate) struct ControlHTTPSPrepayment {
    reservation: Arc<ExchangeReservation>,
    position: Arc<ControlPosition>,
    request_bytes: usize,
    maximum_response: usize,
}
impl ControlHTTPS {
    pub(crate) fn new(
        root: Arc<EnvironmentRoot>,
        configuration: ControlHTTPSConfiguration,
    ) -> Result<Self, ControlHTTPSFailure> {
        let c = &configuration;
        if c.host.is_empty()
            || c.host.len() > 253
            || c.host.capacity() > 512
            || c.port == 0
            || !c
                .host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".:-".contains(&byte))
            || c.base_path.len() > 1024
            || c.base_path.capacity() > 2048
            || !c.base_path.is_empty()
                && (!c.base_path.starts_with('/')
                    || c.base_path.ends_with('/')
                    || c.base_path.contains("//")
                    || c.base_path.contains("..")
                    || !c
                        .base_path
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"/-_".contains(&byte)))
            || c.roots_der.is_empty()
            || c.roots_der.len() > 32
            || c.roots_der.capacity() > 32
            || c.client_chain_der.is_empty()
            || c.client_chain_der.len() > 16
            || c.client_chain_der.capacity() > 16
            || c.client_key_pkcs8.is_empty()
            || c.client_key_pkcs8.len() > 16384
            || c.client_key_pkcs8.capacity() > 32768
            || c.timeout.is_zero()
            || c.timeout > Duration::from_secs(30)
            || c.provider_runtime_bytes < 1048576
        {
            return Err(ControlHTTPSFailure::Configuration);
        }
        ServerName::try_from(c.host.clone()).map_err(|_| ControlHTTPSFailure::Configuration)?;
        let certificate_bytes = c
            .roots_der
            .iter()
            .chain(&c.client_chain_der)
            .try_fold(0u64, |sum, certificate| {
                if certificate.is_empty()
                    || certificate.len() > 65536
                    || certificate.capacity() > 65536
                {
                    return None;
                }
                sum.checked_add(certificate.capacity() as u64)
            })
            .filter(|bytes| *bytes <= 524288)
            .ok_or(ControlHTTPSFailure::Capacity)?;
        let charge = root
            .reserve_environment(ResourceLimits {
                sdk_bytes: certificate_bytes * 2 + 32768,
                provider_bytes: c.provider_runtime_bytes,
                items: 4,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| ControlHTTPSFailure::Capacity)?;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in &c.roots_der {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|_| ControlHTTPSFailure::Configuration)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|_| ControlHTTPSFailure::Configuration)?;
        let verifier = Arc::new(Verifier {
            root: root.clone(),
            inner,
        });
        let chain = c
            .client_chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        let key = PrivatePkcs8KeyDer::from(c.client_key_pkcs8.to_vec()).into();
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ControlHTTPSFailure::Configuration)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(chain, key)
            .map_err(|_| ControlHTTPSFailure::Configuration)?;
        tls.time_provider = Arc::new(Clock(root.clone()));
        tls.resumption = Resumption::disabled();
        tls.enable_early_data = false;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.max_fragment_size = Some(16384);
        Ok(Self {
            root,
            configuration,
            tls: Arc::new(tls),
            busy: Arc::new(AtomicBool::new(false)),
            _charge: Arc::new(charge),
        })
    }
    pub(crate) async fn post(
        &self,
        path: &'static str,
        request: &[u8],
        maximum_response: usize,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<Vec<u8>>, ControlHTTPSFailure> {
        self.post_bounded(
            path,
            request,
            maximum_response,
            cancellation,
            false,
            "application/cbor",
            None,
            None,
            None,
        )
        .await
    }
    pub(crate) async fn post_original_delivery(
        &self,
        path: &'static str,
        request: &[u8],
        maximum_response: usize,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<Vec<u8>>, ControlHTTPSFailure> {
        self.post_bounded(
            path,
            request,
            maximum_response,
            cancellation,
            true,
            "application/cbor",
            None,
            None,
            None,
        )
        .await
    }
    /// Retain the original Account through the actual CBOR writer and final
    /// body view, and recheck its fence immediately before request handoff.
    #[expect(
        clippy::too_many_arguments,
        reason = "A bounded exchange retains original delivery custody and guard with its request, deadline and response limit."
    )]
    pub(crate) async fn post_owned(
        &self,
        path: &'static str,
        request: &[u8],
        maximum_response: usize,
        cancellation: &CancellationToken,
        original_delivery: bool,
        guard: &(dyn Fn() -> Result<(), ControlHTTPSFailure> + Sync),
        custody: Arc<ControlHTTPSCustody>,
    ) -> Result<Zeroizing<Vec<u8>>, ControlHTTPSFailure> {
        self.post_bounded(
            path,
            request,
            maximum_response,
            cancellation,
            original_delivery,
            "application/cbor",
            Some(guard),
            Some(custody),
            None,
        )
        .await
    }
    pub(crate) async fn post_registered_live(
        &self,
        request: &[u8],
        maximum_response: usize,
        cancellation: &CancellationToken,
        guard: &(dyn Fn() -> Result<(), ControlHTTPSFailure> + Sync),
        custody: Arc<ControlHTTPSCustody>,
    ) -> Result<Zeroizing<Vec<u8>>, ControlHTTPSFailure> {
        if self.configuration.base_path != "/flowersec/control/live" {
            return Err(ControlHTTPSFailure::Configuration);
        }
        self.post_bounded(
            "",
            request,
            maximum_response,
            cancellation,
            false,
            "application/json",
            Some(guard),
            Some(custody),
            None,
        )
        .await
    }
    pub(crate) async fn post_registered_pool(
        &self,
        request: &[u8],
        maximum_response: usize,
        cancellation: &CancellationToken,
        guard: &(dyn Fn() -> Result<(), ControlHTTPSFailure> + Sync),
        custody: Arc<ControlHTTPSCustody>,
    ) -> Result<Zeroizing<Vec<u8>>, ControlHTTPSFailure> {
        if self.configuration.base_path != "/flowersec/control/tunnel" {
            return Err(ControlHTTPSFailure::Configuration);
        }
        self.post_bounded(
            "",
            request,
            maximum_response,
            cancellation,
            false,
            "application/json",
            Some(guard),
            Some(custody),
            None,
        )
        .await
    }
    pub(crate) fn prepare_original_delivery(
        &self,
        request_bytes: usize,
        maximum_response: usize,
        custody: Option<&ControlHTTPSCustody>,
    ) -> Result<ControlHTTPSPrepayment, ControlHTTPSFailure> {
        if request_bytes == 0
            || request_bytes > 262144
            || maximum_response == 0
            || maximum_response > 262144
        {
            return Err(ControlHTTPSFailure::Configuration);
        }
        if self.root.is_closed() {
            return Err(ControlHTTPSFailure::Unavailable);
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ControlHTTPSFailure::Capacity)?;
        let position = Arc::new(ControlPosition(self.busy.clone()));
        let reservation = ExchangeReservation::reserve(
            &self.root,
            custody,
            ResourceLimits {
                sdk_bytes: (request_bytes * 2 + maximum_response + 32768) as u64,
                provider_bytes: self.configuration.provider_runtime_bytes,
                native_handles: 1,
                tls_handshakes: 1,
                tasks: 2,
                timers: 1,
                items: 4,
                work_slots: 1,
                ..ResourceLimits::default()
            },
        )?;
        Ok(ControlHTTPSPrepayment {
            reservation,
            position,
            request_bytes,
            maximum_response,
        })
    }
    pub(crate) async fn post_prepaid_original_delivery(
        &self,
        request: &[u8],
        cancellation: &CancellationToken,
        guard: &(dyn Fn() -> Result<(), ControlHTTPSFailure> + Sync),
        custody: Arc<ControlHTTPSCustody>,
        prepayment: ControlHTTPSPrepayment,
    ) -> Result<Zeroizing<Vec<u8>>, ControlHTTPSFailure> {
        self.post_bounded(
            "/tunnel/server-allow",
            request,
            1,
            cancellation,
            true,
            "application/cbor",
            Some(guard),
            Some(custody),
            Some(prepayment),
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "A bounded exchange retains original delivery custody and guard with its request, deadline and response limit."
    )]
    async fn post_bounded(
        &self,
        path: &'static str,
        request: &[u8],
        maximum_response: usize,
        cancellation: &CancellationToken,
        original_delivery: bool,
        content_type: &'static str,
        guard: Option<&(dyn Fn() -> Result<(), ControlHTTPSFailure> + Sync)>,
        custody: Option<Arc<ControlHTTPSCustody>>,
        prepaid: Option<ControlHTTPSPrepayment>,
    ) -> Result<Zeroizing<Vec<u8>>, ControlHTTPSFailure> {
        let registered_live = path.is_empty()
            && content_type == "application/json"
            && matches!(
                self.configuration.base_path.as_str(),
                "/flowersec/control/live" | "/flowersec/control/tunnel"
            );
        let tunnel_control = matches!(
            path,
            "/tunnel/relay-ready" | "/tunnel/relay-prepare" | "/tunnel/relay-activate-client"
        );
        let allowed = registered_live
            || if original_delivery {
                matches!(
                    path,
                    "/live/server/register"
                        | "/live/server/register-tunnel"
                        | "/live/server/publish"
                        | "/live/server/publish-tunnel"
                        | "/relay/original/register"
                        | "/relay/original/register-live"
                        | "/relay/original/start"
                        | "/tunnel/relay-server-grant"
                        | "/tunnel/server-allow"
                )
            } else {
                tunnel_control
                    || matches!(
                        path,
                        "/issue/direct"
                            | "/issue/artifact"
                            | "/issue/tunnel"
                            | "/live/authorize"
                            | "/pool/top-up"
                            | "/pool/ack"
                    )
            };
        let maximum_request = if registered_live {
            262144
        } else if original_delivery {
            106496
        } else if tunnel_control {
            73728
        } else {
            8192
        };
        if !allowed
            || request.is_empty()
            || request.len() > maximum_request
            || maximum_response == 0
            || maximum_response > if registered_live { 262144 } else { 73728 }
        {
            return Err(ControlHTTPSFailure::Configuration);
        }
        if cancellation.is_cancelled() {
            return Err(ControlHTTPSFailure::Canceled);
        }
        if self.root.is_closed() {
            return Err(ControlHTTPSFailure::Unavailable);
        }
        if let Some(guard) = guard {
            guard()?;
        }
        let prepayment = match prepaid {
            Some(prepayment)
                if prepayment.request_bytes == request.len()
                    && prepayment.maximum_response == maximum_response
                    && Arc::ptr_eq(&prepayment.position.0, &self.busy) =>
            {
                prepayment
            }
            Some(_) => return Err(ControlHTTPSFailure::Configuration),
            None => {
                self.prepare_original_delivery(request.len(), maximum_response, custody.as_deref())?
            }
        };
        let ControlHTTPSPrepayment {
            reservation,
            position,
            ..
        } = prepayment;
        let until = Instant::now()
            .checked_add(self.configuration.timeout)
            .ok_or(ControlHTTPSFailure::Configuration)?;
        let exchange = self.exchange(
            path,
            request,
            maximum_response,
            reservation,
            position,
            content_type,
            guard,
            custody,
        );
        tokio::pin!(exchange);
        tokio::select! { result = exchange => result, _ = cancellation.cancelled() => Err(ControlHTTPSFailure::Canceled),
        _ = self.wait_root_close() => Err(ControlHTTPSFailure::Unavailable),
        _ = tokio::time::sleep_until(until) => Err(ControlHTTPSFailure::Deadline) }
    }
    async fn wait_root_close(&self) {
        loop {
            let changed = self.root.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.root.is_closed() {
                return;
            }
            changed.await;
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "A bounded exchange retains original delivery custody and guard with its request, deadline and response limit."
    )]
    async fn exchange(
        &self,
        path: &str,
        request: &[u8],
        maximum_response: usize,
        reservation: Arc<ExchangeReservation>,
        position: Arc<ControlPosition>,
        content_type: &'static str,
        guard: Option<&(dyn Fn() -> Result<(), ControlHTTPSFailure> + Sync)>,
        custody: Option<Arc<ControlHTTPSCustody>>,
    ) -> Result<Zeroizing<Vec<u8>>, ControlHTTPSFailure> {
        let socket = TcpStream::connect(SocketAddr::new(
            self.configuration.remote_address,
            self.configuration.port,
        ))
        .await
        .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        let name = ServerName::try_from(self.configuration.host.clone())
            .map_err(|_| ControlHTTPSFailure::Configuration)?;
        let mut tls = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, socket)
            .await
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        tls.get_mut().1.set_buffer_limit(Some(65536));
        if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || tls.get_ref().1.alpn_protocol() != Some(b"http/1.1")
        {
            return Err(ControlHTTPSFailure::Unavailable);
        }
        let io = hyper_util::rt::TokioIo::new(tls);
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(16384)
            .handshake(io)
            .await
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        let driver_reservation = reservation.clone();
        let driver_position = position.clone();
        let driver_custody = custody.clone();
        let driver_transport = self._charge.clone();
        let driver = Driver(Some(tokio::spawn(async move {
            let _reservation = driver_reservation;
            let _position = driver_position;
            let _custody = driver_custody;
            let _transport = driver_transport;
            let _ = connection.await;
        })));
        let authority = if self.configuration.host.contains(':') {
            format!("[{}]:{}", self.configuration.host, self.configuration.port)
        } else {
            format!("{}:{}", self.configuration.host, self.configuration.port)
        };
        let body = Full::new(Bytes::from_owner(RequestBody {
            bytes: Zeroizing::new(request.to_vec()),
            _reservation: reservation.clone(),
            _transport: self._charge.clone(),
            _position: position.clone(),
            _custody: custody,
        }));
        let uri = format!("{}{}", self.configuration.base_path, path);
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(http::header::HOST, authority)
            .header(http::header::CONTENT_TYPE, content_type)
            .header(http::header::CONTENT_LENGTH, request.len().to_string())
            .header(http::header::CACHE_CONTROL, "no-store")
            .header(http::header::CONNECTION, "close")
            .body(body)
            .map_err(|_| ControlHTTPSFailure::Configuration)?;
        // TLS construction can await while the original publication is
        // fenced or its immutable cutoff expires. Recheck the same owner
        // immediately before handing any application request to the writer.
        if let Some(guard) = guard {
            guard()?;
        }
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| ControlHTTPSFailure::Unavailable)?;
        let result = async {
            if response.status() != http::StatusCode::OK {
                return Err(ControlHTTPSFailure::Rejected);
            }
            let headers = response.headers();
            if headers.contains_key(http::header::CONTENT_ENCODING)
                || headers.contains_key(http::header::TRANSFER_ENCODING)
                || headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    != Some(content_type)
                || headers.get_all(http::header::CONTENT_LENGTH).iter().count() != 1
            {
                return Err(ControlHTTPSFailure::Unavailable);
            }
            let length: usize = headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
                .ok_or(ControlHTTPSFailure::Unavailable)?;
            if length == 0 || length > maximum_response {
                return Err(ControlHTTPSFailure::Capacity);
            }
            let mut bytes = Zeroizing::new(Vec::new());
            bytes
                .try_reserve_exact(length)
                .map_err(|_| ControlHTTPSFailure::Capacity)?;
            let mut body = response.into_body();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| ControlHTTPSFailure::Unavailable)?;
                if let Ok(data) = frame.into_data() {
                    if bytes
                        .len()
                        .checked_add(data.len())
                        .is_none_or(|total| total > length)
                    {
                        return Err(ControlHTTPSFailure::Capacity);
                    }
                    bytes.extend_from_slice(&data);
                } else {
                    return Err(ControlHTTPSFailure::Unavailable);
                }
            }
            if bytes.len() != length {
                return Err(ControlHTTPSFailure::Unavailable);
            }
            if self.root.is_closed() {
                return Err(ControlHTTPSFailure::Unavailable);
            }
            if let Some(guard) = guard {
                guard()?;
            }
            Ok(bytes)
        }
        .await;
        drop(sender);
        driver.close().await;
        drop(reservation);
        drop(position);
        result
    }
}
