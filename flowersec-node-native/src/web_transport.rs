//! N-API bridge to the original dedicated H3 lifecycle. Shared stream classes
//! keep their actual receive/write borrows, failure observers and receipts.
use crate::raw_quic::{
    NativePreparationLimits, OperationTask, RawQuicAddress, RawQuicDatagramOperation,
    RawQuicStreamOperation, RawQuicSubmission, RawQuicTLS, current_limits, native_error,
    preparation_limits, raw_address, resolve_prepared, spawn_native, stable_error, take_task,
};
use flowersec_native_transport::{
    Cancellation, CandidatePreparationBudget, PathProfile, RawQuicClientConfig, RawQuicError,
    WebTransportConfig, WebTransportListener, WebTransportSession,
};
use napi::{
    Env, Result,
    bindgen_prelude::{Buffer, ExternalRef, PromiseRaw, Uint8Array, within_runtime_if_available},
};
use napi_derive::napi;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
#[napi(object)]
pub struct WebTransportBindOptions {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub path: String,
    pub connect_path: String,
    pub certificate_chain_der: Vec<Uint8Array>,
    pub private_key_der: Uint8Array,
    pub inbound_bidirectional_stream_capacity: u32,
    pub read_buffer_bytes: u32,
    pub datagram_queue_bytes: u32,
    pub handshake_timeout_ms: u32,
    pub pending_connections: u32,
    pub tuples: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub allow_absent_origin: bool,
    pub header_bytes: u32,
    pub control_bytes: u32,
    pub preparation_budget: Option<ExternalRef<CandidatePreparationBudget>>,
    pub incoming_preparation_capacity: Option<NativePreparationLimits>,
}
#[napi(object)]
pub struct WebTransportConnectOptions {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub path: String,
    pub connect_path: String,
    pub tls_mode: String,
    pub trust_roots_der: Option<Vec<Uint8Array>>,
    pub active_leaf_der_sha256: Option<Vec<Uint8Array>>,
    pub inbound_bidirectional_stream_capacity: u32,
    pub read_buffer_bytes: u32,
    pub datagram_queue_bytes: u32,
    pub handshake_timeout_ms: u32,
    pub tuple: String,
    pub header_bytes: u32,
    pub control_bytes: u32,
    pub preparation_budget: Option<ExternalRef<CandidatePreparationBudget>>,
}
#[napi(object)]
pub struct WebTransportRequest {
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub origin: Option<String>,
    pub tuple: String,
    pub protocol: String,
    pub session_flow_control: bool,
    pub stream_prefixes: String,
    pub datagram_context: String,
}
fn check_path(path: &str, connect_path: &str) -> Result<()> {
    if !matches!(
        (path, connect_path),
        ("direct", "/flowersec/webtransport/v4/direct")
            | ("tunnel", "/flowersec/webtransport/v4/tunnel")
    ) {
        return Err(stable_error("invalid_path"));
    }
    Ok(())
}
#[napi(js_name = "bindWebTransport")]
pub fn bind_web_transport(
    env: Env,
    options: WebTransportBindOptions,
) -> Result<PromiseRaw<'static, WebTransportListenerBinding>> {
    check_path(&options.path, &options.connect_path)?;
    let address = SocketAddr::new(
        options
            .host
            .parse::<IpAddr>()
            .map_err(|_| stable_error("invalid_bind_address"))?,
        options.port,
    );
    let limits = current_limits(
        options.inbound_bidirectional_stream_capacity,
        options.handshake_timeout_ms,
        options.read_buffer_bytes,
        options.datagram_queue_bytes,
        options.pending_connections,
    )?;
    if options.certificate_chain_der.is_empty()
        || options.certificate_chain_der.len() > 16
        || options
            .certificate_chain_der
            .iter()
            .any(|certificate| certificate.is_empty() || certificate.len() > 65536)
        || options.private_key_der.is_empty()
        || options.private_key_der.len() > 65536
    {
        return Err(stable_error("invalid_server_identity"));
    }
    let config = WebTransportConfig {
        server_name: options.server_name,
        path: options.connect_path,
        tuples: options.tuples,
        allowed_origins: options.allowed_origins,
        allow_absent_origin: options.allow_absent_origin,
        header_bytes: options.header_bytes as usize,
        control_bytes: options.control_bytes as usize,
        handshake_timeout: Duration::from_millis(u64::from(options.handshake_timeout_ms)),
    };
    config.validate().map_err(native_error)?;
    let certificates = options
        .certificate_chain_der
        .into_iter()
        .map(|bytes| bytes.to_vec())
        .collect();
    let key = options.private_key_der.to_vec();
    let listener = within_runtime_if_available(|| {
        let listener = match (
            options.preparation_budget.as_ref(),
            options.incoming_preparation_capacity,
        ) {
            (Some(_), Some(_)) => return Err(stable_error("invalid_preparation_budget")),
            (Some(budget), None) => WebTransportListener::bind_with_preparation_budget(
                address,
                certificates,
                key,
                limits,
                config,
                (**budget).clone(),
            ),
            (None, Some(capacity)) => {
                WebTransportListener::bind_with_incoming_preparation_capacity(
                    address,
                    certificates,
                    key,
                    limits,
                    config,
                    preparation_limits(capacity),
                )
            }
            (None, None) => WebTransportListener::bind(address, certificates, key, limits, config),
        };
        listener.map_err(native_error)
    })?;
    PromiseRaw::resolve(
        &env,
        WebTransportListenerBinding {
            listener: Arc::new(listener),
            read_max: options.read_buffer_bytes,
        },
    )
}
#[napi(js_name = "connectWebTransport")]
pub fn connect_web_transport(
    mut options: WebTransportConnectOptions,
) -> Result<WebTransportConnectOperation> {
    check_path(&options.path, &options.connect_path)?;
    if options.tuple != "native_h3"
        || options.host.is_empty()
        || options.host.len() > 253
        || options.host.contains('\0')
        || options.port == 0
        || options.server_name.is_empty()
        || options.server_name.len() > 253
        || options.server_name.contains('\0')
        || !(1024..=65536).contains(&options.header_bytes)
        || !(16384..=1048576).contains(&options.control_bytes)
    {
        return Err(stable_error("invalid_endpoint"));
    }
    let limits = current_limits(
        options.inbound_bidirectional_stream_capacity,
        options.handshake_timeout_ms,
        options.read_buffer_bytes,
        options.datagram_queue_bytes,
        128,
    )?;
    match options.tls_mode.as_str() {
        "ca" if options.active_leaf_der_sha256.is_none() => {
            let roots = options
                .trust_roots_der
                .as_ref()
                .ok_or_else(|| stable_error("invalid_tls_policy"))?;
            if roots.is_empty()
                || roots.len() > 64
                || roots
                    .iter()
                    .any(|bytes| bytes.is_empty() || bytes.len() > 65536)
                || roots.iter().map(|bytes| bytes.len()).sum::<usize>() > 1048576
            {
                return Err(stable_error("invalid_tls_policy"));
            }
        }
        "pin" if options.trust_roots_der.is_none() => {
            let pins = options
                .active_leaf_der_sha256
                .as_ref()
                .ok_or_else(|| stable_error("invalid_tls_policy"))?;
            if pins.is_empty() || pins.len() > 4 || pins.iter().any(|bytes| bytes.len() != 32) {
                return Err(stable_error("invalid_tls_policy"));
            }
        }
        _ => return Err(stable_error("invalid_tls_policy")),
    }
    let tls = match options.tls_mode.as_str() {
        "ca" => RawQuicClientConfig::new_ca(
            PathProfile::WebTransportV4,
            options
                .trust_roots_der
                .take()
                .unwrap()
                .into_iter()
                .map(|bytes| bytes.to_vec())
                .collect(),
            limits,
        ),
        "pin" => {
            let pins = options
                .active_leaf_der_sha256
                .take()
                .unwrap()
                .into_iter()
                .map(|bytes| {
                    let mut pin = [0; 32];
                    pin.copy_from_slice(bytes.as_ref());
                    pin
                })
                .collect();
            RawQuicClientConfig::new_pin(PathProfile::WebTransportV4, pins, limits)
        }
        _ => return Err(stable_error("invalid_tls_policy")),
    }
    .map_err(native_error)?;
    let tls = match options.preparation_budget.take() {
        Some(budget) => tls
            .with_preparation_budget((*budget).clone())
            .map_err(native_error)?,
        None => tls,
    };
    let mut config = WebTransportConfig {
        server_name: options.server_name,
        path: options.connect_path,
        tuples: vec!["native_h3".into()],
        allowed_origins: vec![],
        allow_absent_origin: true,
        header_bytes: options.header_bytes as usize,
        control_bytes: options.control_bytes as usize,
        handshake_timeout: Duration::from_millis(u64::from(options.handshake_timeout_ms)),
    };
    config.validate().map_err(native_error)?;
    let cancellation = Cancellation::new();
    let original = cancellation.clone();
    let capacity = options.inbound_bidirectional_stream_capacity;
    let host = options.host;
    let port = options.port;
    let task = spawn_native(async move {
        let preparing = napi::tokio::time::Instant::now();
        let remote = resolve_prepared(
            host,
            port,
            tls.preparation_budget().cloned(),
            &original,
            Some(config.handshake_timeout),
        )
        .await?
        .into_iter()
        .next()
        .ok_or(RawQuicError::NoUsableAddress)?;
        config.handshake_timeout = config
            .handshake_timeout
            .checked_sub(preparing.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RawQuicError::Timeout)?;
        WebTransportSession::connect_native_h3(remote, tls, config, capacity, &original).await
    });
    Ok(WebTransportConnectOperation {
        cancellation,
        task: Mutex::new(Some(task)),
        read_max: options.read_buffer_bytes,
    })
}
#[napi(js_name = "WebTransportConnectOperation")]
pub struct WebTransportConnectOperation {
    cancellation: Cancellation,
    task: OperationTask<WebTransportSession>,
    read_max: u32,
}
impl Drop for WebTransportConnectOperation {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
#[napi]
impl WebTransportConnectOperation {
    #[napi]
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<WebTransportSessionBinding> {
        let session = take_task(&self.task)?
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)?;
        Ok(WebTransportSessionBinding {
            session,
            read_max: self.read_max,
        })
    }
}
#[napi(js_name = "WebTransportListener")]
pub struct WebTransportListenerBinding {
    listener: Arc<WebTransportListener>,
    read_max: u32,
}
impl Drop for WebTransportListenerBinding {
    fn drop(&mut self) {
        self.listener.abort();
    }
}
#[napi]
impl WebTransportListenerBinding {
    #[napi]
    pub fn address(&self) -> Result<RawQuicAddress> {
        self.listener
            .local_address()
            .map(raw_address)
            .map_err(native_error)
    }
    #[napi]
    pub fn accept(&self) -> WebTransportConnectOperation {
        let cancellation = Cancellation::new();
        let original = cancellation.clone();
        let listener = self.listener.clone();
        let task = spawn_native(async move { listener.accept(&original).await });
        WebTransportConnectOperation {
            cancellation,
            task: Mutex::new(Some(task)),
            read_max: self.read_max,
        }
    }
    #[napi(js_name = "stopAcceptingCurrent")]
    pub fn stop_accepting_current(&self) {
        self.listener.stop_accepting_current();
    }
    #[napi]
    pub fn abort(&self) {
        self.listener.abort();
    }
    #[napi]
    pub async fn close(&self) {
        self.listener.close().await;
    }
    #[napi(js_name = "waitTermination")]
    pub async fn wait_termination(&self) {
        self.listener.wait_termination().await;
    }
}
#[napi(js_name = "WebTransportSession")]
pub struct WebTransportSessionBinding {
    session: WebTransportSession,
    read_max: u32,
}
impl Drop for WebTransportSessionBinding {
    fn drop(&mut self) {
        self.session.abort();
    }
}
#[napi]
impl WebTransportSessionBinding {
    #[napi(js_name = "completePreparation")]
    pub fn complete_preparation(&self) -> Result<()> {
        self.session
            .raw()
            .complete_preparation()
            .map_err(native_error)
    }
    #[napi(getter)]
    pub fn kind(&self) -> &'static str {
        "webtransport"
    }
    #[napi(getter)]
    pub fn path(&self) -> &'static str {
        self.session.path()
    }
    #[napi(getter, js_name = "wireVersion")]
    pub fn wire_version(&self) -> u32 {
        4
    }
    #[napi(getter, js_name = "inboundBidirectionalStreamCapacity")]
    pub fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.session.inbound_bidirectional_stream_capacity()
    }
    #[napi]
    pub fn request(&self) -> Result<WebTransportRequest> {
        let request = self.session.request().map_err(native_error)?;
        Ok(WebTransportRequest {
            scheme: request.scheme,
            authority: request.authority,
            path: request.path,
            origin: request.origin,
            tuple: request.tuple,
            protocol: request.protocol,
            session_flow_control: false,
            stream_prefixes: "rfc_webtransport".into(),
            datagram_context: "rfc_h3_quarter_stream_id".into(),
        })
    }
    #[napi]
    pub fn tls(&self) -> Result<RawQuicTLS> {
        Ok(RawQuicTLS {
            version: "TLSv1.3".into(),
            alpn: self.session.raw().profile().alpn().into(),
            early_data_accepted: false,
            dedicated_connection: true,
            peer_leaf_der: self
                .session
                .raw()
                .peer_leaf_der()
                .map_err(native_error)?
                .into(),
            certificate_verified: self.session.raw().certificate_verified(),
        })
    }
    #[napi(js_name = "exportKeyingMaterial")]
    pub fn export_keying_material(
        &self,
        length: u32,
        label: String,
        context: Uint8Array,
    ) -> Result<Buffer> {
        self.session
            .raw()
            .export_keying_material(length as usize, label.as_bytes(), context.as_ref())
            .map(Buffer::from)
            .map_err(native_error)
    }
    #[napi(js_name = "localAddress")]
    pub fn local_address(&self) -> Result<RawQuicAddress> {
        self.session
            .raw()
            .local_address()
            .map(raw_address)
            .map_err(native_error)
    }
    #[napi(js_name = "peerAddress")]
    pub fn peer_address(&self) -> RawQuicAddress {
        raw_address(self.session.raw().peer_address())
    }
    #[napi(js_name = "maxDatagramBytes")]
    pub fn max_datagram_bytes(&self) -> u32 {
        self.session
            .max_datagram_size()
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0)
    }
    #[napi(js_name = "openStream")]
    pub fn open_stream(&self) -> RawQuicStreamOperation {
        self.stream_operation(true)
    }
    #[napi(js_name = "acceptStream")]
    pub fn accept_stream(&self) -> RawQuicStreamOperation {
        self.stream_operation(false)
    }
    #[napi(js_name = "receiveDatagram")]
    pub fn receive_datagram(&self, maximum: u32) -> Result<RawQuicDatagramOperation> {
        if maximum == 0 || maximum > 65535 {
            return Err(stable_error("invalid_read_size"));
        }
        let session = self.session.clone();
        let cancellation = Cancellation::new();
        let original = cancellation.clone();
        let task =
            spawn_native(
                async move { session.receive_datagram(maximum as usize, &original).await },
            );
        Ok(RawQuicDatagramOperation {
            cancellation,
            task: Mutex::new(Some(task)),
        })
    }
    #[napi(js_name = "submitDatagram")]
    pub fn submit_datagram(&self, payload: Uint8Array) -> Option<RawQuicSubmission> {
        if payload.is_empty() || payload.len() > 65535 {
            return None;
        }
        let submission = self.session.submit_datagram(payload.to_vec())?;
        let task = spawn_native(async move {
            submission.completion().await;
            Ok(())
        });
        Some(RawQuicSubmission {
            task: Mutex::new(Some(task)),
        })
    }
    #[napi]
    pub fn abort(&self) {
        self.session.abort();
    }
    #[napi]
    pub async fn close(&self) {
        self.session.close().await;
    }
    #[napi(js_name = "waitTermination")]
    pub async fn wait_termination(&self) {
        self.session.wait_termination().await;
    }
}
impl WebTransportSessionBinding {
    fn stream_operation(&self, open: bool) -> RawQuicStreamOperation {
        let session = self.session.clone();
        let cancellation = Cancellation::new();
        let original = cancellation.clone();
        let task = spawn_native(async move {
            if open {
                session.open_stream(&original).await
            } else {
                session.accept_stream(&original).await
            }
        });
        RawQuicStreamOperation {
            cancellation,
            task: Mutex::new(Some(task)),
            read_max: self.read_max,
        }
    }
}
