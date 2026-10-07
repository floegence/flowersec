use flowersec_native_transport::{
    ApplicationClose, Cancellation, CandidatePreparationBudget, NativeDirectionFailure,
    PathProfile, PreparationBudget, PreparationBudgetError, PreparationLimits, PreparationUsage,
    RawQuicClientConfig, RawQuicError, RawQuicLimits, RawQuicListener, RawQuicServerConfig,
    RawQuicSession, RawQuicStream,
};
use napi::{
    Env, Error, Result, Status,
    bindgen_prelude::{
        Buffer, External, ExternalRef, PromiseRaw, Uint8Array, within_runtime_if_available,
    },
};
use napi_derive::napi;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const DEFAULT_CLOSE_CODE: u64 = 0x0000_f500;
const MAX_READ_BYTES: u32 = 16_384;
const MAX_SUBMISSION_BYTES: usize = 16_777_224;
pub(crate) type OperationTask<T> =
    Mutex<Option<napi::tokio::task::JoinHandle<std::result::Result<T, RawQuicError>>>>;

#[napi(object)]
pub struct RawQuicConnectOptions {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub path: String,
    pub tls_mode: String,
    pub trust_roots_der: Option<Vec<Uint8Array>>,
    pub active_leaf_der_sha256: Option<Vec<Uint8Array>>,
    pub inbound_bidirectional_stream_capacity: u32,
    pub read_buffer_bytes: u32,
    pub datagram_queue_bytes: u32,
    pub handshake_timeout_ms: u32,
    pub preparation_budget: Option<ExternalRef<CandidatePreparationBudget>>,
}
#[napi(object)]
pub struct RawQuicBindOptions {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub certificate_chain_der: Vec<Uint8Array>,
    pub private_key_der: Uint8Array,
    pub inbound_bidirectional_stream_capacity: u32,
    pub read_buffer_bytes: u32,
    pub datagram_queue_bytes: u32,
    pub handshake_timeout_ms: u32,
    pub pending_connections: u32,
    pub preparation_budget: Option<ExternalRef<CandidatePreparationBudget>>,
    pub incoming_preparation_capacity: Option<NativePreparationLimits>,
}
#[napi(object)]
pub struct NativePreparationLimits {
    pub preauth_input_bytes: u32,
    pub address_attempts: u32,
    pub work_units: u32,
}
#[napi(object)]
pub struct NativePreparationUsage {
    pub preauth_input_bytes: u32,
    pub address_attempts: u32,
    pub work_units: u32,
}
pub(crate) fn preparation_limits(value: NativePreparationLimits) -> PreparationLimits {
    PreparationLimits {
        preauth_input_bytes: u64::from(value.preauth_input_bytes),
        address_attempts: value.address_attempts,
        work_units: u64::from(value.work_units),
    }
}
fn preparation_error(error: PreparationBudgetError) -> Error {
    stable_error(match error {
        PreparationBudgetError::Invalid => "invalid_preparation_budget",
        PreparationBudgetError::Exhausted => "preparation_budget_exhausted",
        PreparationBudgetError::Closed => "preparation_budget_closed",
    })
}
fn preparation_usage(value: PreparationUsage) -> Result<NativePreparationUsage> {
    Ok(NativePreparationUsage {
        preauth_input_bytes: u32::try_from(value.preauth_input_bytes)
            .map_err(|_| stable_error("invalid_preparation_budget"))?,
        address_attempts: value.address_attempts,
        work_units: u32::try_from(value.work_units)
            .map_err(|_| stable_error("invalid_preparation_budget"))?,
    })
}
#[napi(js_name = "NativePreparationBudget")]
pub struct NativePreparationBudgetBinding {
    owner: PreparationBudget,
}
#[napi]
impl NativePreparationBudgetBinding {
    #[napi]
    pub fn configure(&self, limits: NativePreparationLimits) -> Result<()> {
        self.owner
            .configure(preparation_limits(limits))
            .map_err(preparation_error)
    }
    #[napi(js_name = "beginCandidate")]
    pub fn begin_candidate(
        &self,
        limits: NativePreparationLimits,
    ) -> Result<External<CandidatePreparationBudget>> {
        self.owner
            .begin_candidate(preparation_limits(limits))
            .map(External::new)
            .map_err(preparation_error)
    }
    #[napi]
    pub fn usage(&self) -> Result<NativePreparationUsage> {
        preparation_usage(self.owner.usage())
    }
    #[napi]
    pub fn close(&self) {
        self.owner.close();
    }
}
#[napi(js_name = "createPreparationBudget")]
pub fn create_preparation_budget() -> NativePreparationBudgetBinding {
    NativePreparationBudgetBinding {
        owner: PreparationBudget::new(),
    }
}

#[napi(object)]
pub struct RawQuicAddress {
    pub host: String,
    pub port: u16,
}
#[napi(object)]
pub struct RawQuicTLS {
    pub version: String,
    pub alpn: String,
    pub early_data_accepted: bool,
    pub dedicated_connection: bool,
    #[napi(js_name = "peerLeafDER")]
    pub peer_leaf_der: Uint8Array,
    pub certificate_verified: bool,
}

/// Cancellation retires the actual resolver job before releasing the original
/// preparation owner. Dropping Tokio lookup_host would detach its blocking tail.
pub(crate) async fn resolve_prepared(
    host: String,
    port: u16,
    budget: Option<CandidatePreparationBudget>,
    cancellation: &Cancellation,
    timeout: Option<Duration>,
) -> std::result::Result<Vec<SocketAddr>, RawQuicError> {
    if let Some(budget) = &budget {
        budget.debit_work(1)?;
    }
    let mut resolution = napi::tokio::task::spawn_blocking(move || {
        let _original_owner = budget;
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.take(64).collect())
            .map_err(|_| RawQuicError::NoUsableAddress)
    });
    let expired = async {
        match timeout {
            Some(timeout) => napi::tokio::time::sleep(timeout).await,
            None => std::future::pending::<()>().await,
        }
    };
    let failure = napi::tokio::select! {
        biased;
        _ = cancellation.cancelled() => RawQuicError::Canceled,
        _ = expired => RawQuicError::Timeout,
        result = &mut resolution => return result.map_err(|_| RawQuicError::NoUsableAddress)?,
    };
    let _ = resolution.await;
    Err(failure)
}
#[napi(js_name = "connectRawQuic")]
pub fn connect_raw_quic(options: RawQuicConnectOptions) -> Result<RawQuicConnectOperation> {
    if options.host.is_empty()
        || options.host.len() > 253
        || options.host.contains('\0')
        || options.port == 0
        || options.server_name.is_empty()
        || options.server_name.len() > 253
        || options.server_name.contains('\0')
    {
        return Err(stable_error("invalid_endpoint"));
    }
    let profile = profile(&options.path)?;
    let limits = current_limits(
        options.inbound_bidirectional_stream_capacity,
        options.handshake_timeout_ms,
        options.read_buffer_bytes,
        options.datagram_queue_bytes,
        128,
    )?;
    let config = match options.tls_mode.as_str() {
        "ca" => {
            if options.active_leaf_der_sha256.is_some() {
                return Err(stable_error("invalid_tls_policy"));
            }
            let roots = options
                .trust_roots_der
                .ok_or_else(|| stable_error("invalid_tls_policy"))?;
            if roots.is_empty()
                || roots.len() > 64
                || roots
                    .iter()
                    .any(|root| root.is_empty() || root.len() > 65536)
                || roots.iter().map(|root| root.len()).sum::<usize>() > 1048576
            {
                return Err(stable_error("invalid_tls_policy"));
            }
            RawQuicClientConfig::new_ca(
                profile,
                roots.into_iter().map(|root| root.to_vec()).collect(),
                limits,
            )
        }
        "pin" => {
            if options.trust_roots_der.is_some() {
                return Err(stable_error("invalid_tls_policy"));
            }
            let pins = options
                .active_leaf_der_sha256
                .ok_or_else(|| stable_error("invalid_tls_policy"))?;
            if pins.is_empty() || pins.len() > 4 {
                return Err(stable_error("invalid_tls_policy"));
            }
            let pins = pins
                .into_iter()
                .map(|pin| {
                    pin.as_ref()
                        .try_into()
                        .map_err(|_| stable_error("invalid_tls_policy"))
                })
                .collect::<Result<Vec<[u8; 32]>>>()?;
            RawQuicClientConfig::new_pin(profile, pins, limits)
        }
        _ => return Err(stable_error("invalid_tls_policy")),
    }
    .map_err(native_error)?;
    let config = match options.preparation_budget.as_ref() {
        Some(budget) => config
            .with_preparation_budget((**budget).clone())
            .map_err(native_error)?,
        None => config,
    };
    // All configuration and TLS arrays above are copied before a task exists.
    let host = options.host;
    let port = options.port;
    let server_name = options.server_name;
    let cancellation = Cancellation::new();
    let task_cancellation = cancellation.clone();
    let task = spawn_native(async move {
        let addresses = resolve_prepared(
            host,
            port,
            config.preparation_budget().cloned(),
            &task_cancellation,
            None,
        )
        .await?;
        RawQuicSession::dial(addresses, server_name, config, &task_cancellation).await
    });
    Ok(RawQuicConnectOperation {
        cancellation,
        task: Mutex::new(Some(task)),
        read_max: options.read_buffer_bytes,
    })
}

#[napi(js_name = "bindRawQuic")]
pub fn bind_raw_quic(
    env: Env,
    options: RawQuicBindOptions,
) -> Result<PromiseRaw<'static, RawQuicListenerBinding>> {
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
    let profile = profile(&options.path)?;
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
    let certificates = options
        .certificate_chain_der
        .into_iter()
        .map(|certificate| certificate.to_vec())
        .collect();
    let key = options.private_key_der.to_vec();
    let config =
        RawQuicServerConfig::new(profile, certificates, key, limits).map_err(native_error)?;
    let config = match options.preparation_budget.as_ref() {
        Some(budget) => config
            .with_preparation_budget((**budget).clone())
            .map_err(native_error)?,
        None => config,
    };
    let config = match options.incoming_preparation_capacity {
        Some(capacity) => config
            .with_incoming_preparation_capacity(preparation_limits(capacity))
            .map_err(native_error)?,
        None => config,
    };
    let read_max = options.read_buffer_bytes;
    // Bind completes using the owned config before returning its Promise.
    // No asynchronous task borrows configuration or TLS bytes.
    let listener = within_runtime_if_available(|| RawQuicListener::bind(address, config))
        .map_err(native_error)?;
    PromiseRaw::resolve(
        &env,
        RawQuicListenerBinding {
            listener: Arc::new(listener),
            read_max,
        },
    )
}

#[napi(js_name = "RawQuicConnectOperation")]
pub struct RawQuicConnectOperation {
    cancellation: Cancellation,
    task: OperationTask<RawQuicSession>,
    read_max: u32,
}
impl Drop for RawQuicConnectOperation {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
#[napi]
impl RawQuicConnectOperation {
    #[napi]
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<RawQuicSessionBinding> {
        let session = take_task(&self.task)?
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)?;
        Ok(RawQuicSessionBinding {
            session,
            read_max: self.read_max,
        })
    }
}
#[napi(js_name = "RawQuicListener")]
pub struct RawQuicListenerBinding {
    listener: Arc<RawQuicListener>,
    read_max: u32,
}
impl Drop for RawQuicListenerBinding {
    fn drop(&mut self) {
        self.listener.abort();
    }
}
#[napi]
impl RawQuicListenerBinding {
    #[napi]
    pub fn address(&self) -> Result<RawQuicAddress> {
        self.listener
            .local_address()
            .map(raw_address)
            .map_err(native_error)
    }
    #[napi]
    pub fn accept(&self) -> RawQuicAcceptOperation {
        let listener = self.listener.clone();
        let cancellation = Cancellation::new();
        let task_cancellation = cancellation.clone();
        let task = spawn_native(async move { listener.accept(&task_cancellation).await });
        RawQuicAcceptOperation {
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
#[napi(js_name = "RawQuicAcceptOperation")]
pub struct RawQuicAcceptOperation {
    cancellation: Cancellation,
    task: OperationTask<RawQuicSession>,
    read_max: u32,
}
impl Drop for RawQuicAcceptOperation {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
#[napi]
impl RawQuicAcceptOperation {
    #[napi]
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<RawQuicSessionBinding> {
        let session = take_task(&self.task)?
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)?;
        Ok(RawQuicSessionBinding {
            session,
            read_max: self.read_max,
        })
    }
}
#[napi(js_name = "RawQuicSession")]
pub struct RawQuicSessionBinding {
    session: RawQuicSession,
    read_max: u32,
}
impl Drop for RawQuicSessionBinding {
    fn drop(&mut self) {
        self.session.abort();
    }
}
#[napi]
impl RawQuicSessionBinding {
    #[napi(js_name = "completePreparation")]
    pub fn complete_preparation(&self) -> Result<()> {
        self.session.complete_preparation().map_err(native_error)
    }
    #[napi(getter)]
    pub fn kind(&self) -> &'static str {
        "raw_quic"
    }
    #[napi(getter)]
    pub fn path(&self) -> &'static str {
        match self.session.profile() {
            PathProfile::DirectV4 => "direct",
            PathProfile::TunnelV4 => "tunnel",
            PathProfile::WebTransportV4 => "webtransport",
        }
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
    pub fn tls(&self) -> Result<RawQuicTLS> {
        Ok(RawQuicTLS {
            version: "TLSv1.3".into(),
            alpn: self.session.profile().alpn().into(),
            early_data_accepted: false,
            dedicated_connection: true,
            peer_leaf_der: self.session.peer_leaf_der().map_err(native_error)?.into(),
            certificate_verified: self.session.certificate_verified(),
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
            .export_keying_material(length as usize, label.as_bytes(), context.as_ref())
            .map(Buffer::from)
            .map_err(native_error)
    }
    #[napi(js_name = "maxDatagramBytes")]
    pub fn max_datagram_bytes(&self) -> u32 {
        self.session
            .max_datagram_size()
            .and_then(|maximum| u32::try_from(maximum).ok())
            .unwrap_or(0)
    }
    #[napi(js_name = "openStream")]
    pub fn open_stream(&self) -> RawQuicStreamOperation {
        stream_operation(self.session.clone(), self.read_max, true)
    }
    #[napi(js_name = "acceptStream")]
    pub fn accept_stream(&self) -> RawQuicStreamOperation {
        stream_operation(self.session.clone(), self.read_max, false)
    }
    #[napi(js_name = "receiveDatagram")]
    pub fn receive_datagram(&self, max_bytes: u32) -> Result<RawQuicDatagramOperation> {
        if max_bytes == 0 || max_bytes > 65535 {
            return Err(stable_error("invalid_read_size"));
        }
        let session = self.session.clone();
        let cancellation = Cancellation::new();
        let task_cancellation = cancellation.clone();
        let task = spawn_native(async move {
            session
                .receive_datagram_bounded(max_bytes as usize, &task_cancellation)
                .await
        });
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
        let submission = self.session.submit_datagram_current(payload.to_vec())?;
        let task = spawn_native(async move {
            submission.completion().await;
            Ok(())
        });
        Some(RawQuicSubmission {
            task: Mutex::new(Some(task)),
        })
    }
    #[napi(js_name = "waitTermination")]
    pub async fn wait_termination(&self) {
        self.session.wait_termination().await;
    }
    #[napi]
    pub async fn close(&self) -> Result<()> {
        self.session
            .close(ApplicationClose {
                code: DEFAULT_CLOSE_CODE,
                reason: String::new(),
            })
            .map_err(native_error)?;
        self.session.wait_termination().await;
        Ok(())
    }
    #[napi]
    pub fn abort(&self) {
        self.session.abort();
    }
    #[napi(js_name = "localAddress")]
    pub fn local_address(&self) -> Result<RawQuicAddress> {
        self.session
            .local_address()
            .map(raw_address)
            .map_err(native_error)
    }
    #[napi(js_name = "peerAddress")]
    pub fn peer_address(&self) -> RawQuicAddress {
        raw_address(self.session.peer_address())
    }
}
#[napi(js_name = "RawQuicStreamOperation")]
pub struct RawQuicStreamOperation {
    pub(crate) cancellation: Cancellation,
    pub(crate) task: OperationTask<RawQuicStream>,
    pub(crate) read_max: u32,
}
impl Drop for RawQuicStreamOperation {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
#[napi]
impl RawQuicStreamOperation {
    #[napi]
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<RawQuicStreamBinding> {
        let stream = take_task(&self.task)?
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)?;
        Ok(RawQuicStreamBinding {
            owner: Arc::new(StreamOwner {
                stream,
                runtime: napi::tokio::runtime::Handle::current(),
                read_max: self.read_max,
                reading: AtomicBool::new(false),
                writing: AtomicBool::new(false),
                changed: napi::tokio::sync::Notify::new(),
            }),
        })
    }
}
#[napi(js_name = "RawQuicDatagramOperation")]
pub struct RawQuicDatagramOperation {
    pub(crate) cancellation: Cancellation,
    pub(crate) task: OperationTask<Vec<u8>>,
}
impl Drop for RawQuicDatagramOperation {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
#[napi]
impl RawQuicDatagramOperation {
    #[napi]
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<Buffer> {
        take_task(&self.task)?
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map(Buffer::from)
            .map_err(native_error)
    }
}
#[napi(js_name = "RawQuicReadOperation")]
pub struct RawQuicReadOperation {
    cancellation: Cancellation,
    task: OperationTask<Option<Vec<u8>>>,
}
impl Drop for RawQuicReadOperation {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
#[napi]
impl RawQuicReadOperation {
    #[napi]
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<Option<Buffer>> {
        take_task(&self.task)?
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map(|payload| payload.map(Buffer::from))
            .map_err(native_error)
    }
}
#[napi(js_name = "RawQuicSubmission")]
pub struct RawQuicSubmission {
    pub(crate) task: OperationTask<()>,
}
#[napi]
impl RawQuicSubmission {
    // There is deliberately no cancellation method on an admitted byte owner.
    #[napi]
    pub async fn completion(&self) -> Result<()> {
        take_task(&self.task)?
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)
    }
}
struct StreamOwner {
    stream: RawQuicStream,
    // Finalizers may run after N-API has removed its global runtime. Keep the
    // original handle so late drops never try to reenter that destroyed slot.
    runtime: napi::tokio::runtime::Handle,
    read_max: u32,
    reading: AtomicBool,
    writing: AtomicBool,
    changed: napi::tokio::sync::Notify,
}
struct StreamBorrow {
    owner: Arc<StreamOwner>,
    read: bool,
    bytes: Option<Vec<u8>>,
}
impl Drop for StreamBorrow {
    fn drop(&mut self) {
        if let Some(mut bytes) = self.bytes.take() {
            bytes.fill(0);
            drop(bytes);
        }
        if self.read {
            self.owner.reading.store(false, Ordering::Release);
        } else {
            self.owner.writing.store(false, Ordering::Release);
        }
        self.owner.changed.notify_waiters();
    }
}
#[napi(js_name = "RawQuicStream")]
pub struct RawQuicStreamBinding {
    owner: Arc<StreamOwner>,
}
impl Drop for RawQuicStreamBinding {
    fn drop(&mut self) {
        reset_stream(self.owner.stream.clone(), &self.owner.runtime);
    }
}
#[napi]
impl RawQuicStreamBinding {
    #[napi]
    pub fn read(&self, max_bytes: u32) -> Result<RawQuicReadOperation> {
        if max_bytes == 0 || max_bytes > self.owner.read_max {
            return Err(stable_error("invalid_read_size"));
        }
        if self.owner.reading.swap(true, Ordering::AcqRel) {
            return Err(stable_error("busy"));
        }
        let owner = self.owner.clone();
        let cancellation = Cancellation::new();
        let task_cancellation = cancellation.clone();
        let task = spawn_native(async move {
            let _borrow = StreamBorrow {
                owner: owner.clone(),
                read: true,
                bytes: None,
            };
            owner
                .stream
                .read_current(max_bytes as usize, &task_cancellation)
                .await
        });
        Ok(RawQuicReadOperation {
            cancellation,
            task: Mutex::new(Some(task)),
        })
    }
    #[napi]
    pub fn submit(&self, payload: Uint8Array) -> Result<Option<RawQuicSubmission>> {
        if payload.is_empty() || payload.len() > MAX_SUBMISSION_BYTES {
            return Err(stable_error("invalid_write_size"));
        }
        if self.owner.writing.swap(true, Ordering::AcqRel) {
            return Ok(None);
        }
        let bytes = payload.to_vec();
        let owner = self.owner.clone();
        let task = spawn_native(async move {
            let borrow = StreamBorrow {
                owner: owner.clone(),
                read: false,
                bytes: Some(bytes),
            };
            owner
                .stream
                .write_all_current(borrow.bytes.as_deref().expect("original admitted bytes"))
                .await
        });
        Ok(Some(RawQuicSubmission {
            task: Mutex::new(Some(task)),
        }))
    }
    #[napi(js_name = "closeWrite")]
    pub async fn close_write(&self) -> Result<()> {
        self.owner
            .stream
            .close_write_current()
            .await
            .map_err(native_error)
    }
    #[napi(js_name = "stopSending")]
    pub async fn stop_sending(&self, reason: Option<String>) -> Result<()> {
        if reason
            .as_deref()
            .is_some_and(|reason| reason != "normal_drained")
        {
            return Err(stable_error("invalid_stop_reason"));
        }
        self.owner
            .stream
            .stop_sending_current(reason.is_some())
            .await
            .map_err(native_error)
    }
    #[napi(js_name = "resetWrite")]
    pub async fn reset_write(&self) -> Result<()> {
        self.owner
            .stream
            .reset_write_current()
            .await
            .map_err(native_error)
    }
    #[napi(js_name = "waitWriteFailure")]
    pub async fn wait_write_failure(&self) -> Option<String> {
        self.owner
            .stream
            .wait_write_failure()
            .await
            .map(|reason| match reason {
                NativeDirectionFailure::NormalDrained => "normal_drained".into(),
                NativeDirectionFailure::DirectionReset => "direction_reset".into(),
            })
    }
    #[napi(js_name = "waitTermination")]
    pub async fn wait_termination(&self) {
        self.owner.stream.wait_termination_current().await;
        loop {
            let changed = self.owner.changed.notified();
            napi::tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.owner.reading.load(Ordering::Acquire)
                && !self.owner.writing.load(Ordering::Acquire)
            {
                return;
            }
            changed.await;
        }
    }
    #[napi]
    pub fn abort(&self) {
        reset_stream(self.owner.stream.clone(), &self.owner.runtime);
    }
}
fn stream_operation(session: RawQuicSession, read_max: u32, open: bool) -> RawQuicStreamOperation {
    let cancellation = Cancellation::new();
    let task_cancellation = cancellation.clone();
    let task = spawn_native(async move {
        if open {
            session.open_stream(&task_cancellation).await
        } else {
            session.accept_stream(&task_cancellation).await
        }
    });
    RawQuicStreamOperation {
        cancellation,
        task: Mutex::new(Some(task)),
        read_max,
    }
}
fn reset_stream(stream: RawQuicStream, runtime: &napi::tokio::runtime::Handle) {
    stream.cancel_current();
    drop(runtime.spawn(async move {
        let (write, read) = napi::tokio::join!(
            stream.reset_write_current(),
            stream.stop_sending_current(false)
        );
        write?;
        read?;
        Ok::<(), RawQuicError>(())
    }));
}
fn profile(value: &str) -> Result<PathProfile> {
    match value {
        "direct" => Ok(PathProfile::DirectV4),
        "tunnel" => Ok(PathProfile::TunnelV4),
        _ => Err(stable_error("invalid_path")),
    }
}
fn limits(capacity: u32, handshake_timeout_ms: u32) -> Result<RawQuicLimits> {
    if handshake_timeout_ms == 0 {
        return Err(stable_error("invalid_limits"));
    }
    RawQuicLimits::for_session(
        capacity,
        Duration::from_millis(u64::from(handshake_timeout_ms)),
    )
    .map_err(native_error)
}
pub(crate) fn current_limits(
    capacity: u32,
    timeout: u32,
    read_max: u32,
    datagram_queue: u32,
    pending: u32,
) -> Result<RawQuicLimits> {
    if read_max == 0 || read_max > MAX_READ_BYTES || datagram_queue != 65536 {
        return Err(stable_error("invalid_limits"));
    }
    let mut limits = limits(capacity, timeout)?;
    limits.datagram_queue_bytes = datagram_queue as usize;
    limits.datagram_send_queue_bytes = datagram_queue as usize;
    limits.pending_connections = pending;
    limits.stream_receive_window = u64::from(read_max);
    limits.connection_receive_window =
        (u64::from(read_max) * u64::from(capacity)).clamp(u64::from(read_max), 16 << 20);
    limits.validate().map_err(native_error)?;
    Ok(limits)
}
pub(crate) fn raw_address(address: SocketAddr) -> RawQuicAddress {
    RawQuicAddress {
        host: address.ip().to_string(),
        port: address.port(),
    }
}
pub(crate) fn take_task<T>(
    task: &Mutex<Option<napi::tokio::task::JoinHandle<T>>>,
) -> Result<napi::tokio::task::JoinHandle<T>> {
    task.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .ok_or_else(|| stable_error("operation_already_consumed"))
}
pub(crate) fn spawn_native<T, F>(
    future: F,
) -> napi::tokio::task::JoinHandle<std::result::Result<T, RawQuicError>>
where
    T: Send + 'static,
    F: Future<Output = std::result::Result<T, RawQuicError>> + Send + 'static,
{
    within_runtime_if_available(|| napi::tokio::spawn(future))
}
pub(crate) fn native_error(error: RawQuicError) -> Error {
    let code = match error {
        RawQuicError::PreparationBudget(error) => return preparation_error(error),
        RawQuicError::InvalidLimits => "invalid_limits",
        RawQuicError::InvalidTrust => "invalid_trust_roots",
        RawQuicError::InvalidServerIdentity => "invalid_server_identity",
        RawQuicError::InvalidTls => "invalid_tls_policy",
        RawQuicError::Endpoint(_) => "endpoint_failed",
        RawQuicError::ListenerClosed => "listener_closed",
        RawQuicError::Canceled => "canceled",
        RawQuicError::NoUsableAddress => "name_resolution_failed",
        RawQuicError::Connect => "connect_failed",
        RawQuicError::Handshake => "handshake_failed",
        RawQuicError::Timeout => "handshake_timeout",
        RawQuicError::PinMismatch => "pin_mismatch",
        RawQuicError::PinCertificateInvalid => "pin_certificate_invalid",
        RawQuicError::InvalidNegotiatedAlpn => "invalid_alpn",
        RawQuicError::Stream => "stream_failed",
        RawQuicError::DatagramUnavailable => "datagram_unavailable",
        RawQuicError::Closed => "closed",
        RawQuicError::MigrationUnavailable => "migration_unavailable",
        RawQuicError::Migration(_) => "migration_failed",
        RawQuicError::InvalidApplicationClose => "invalid_close",
        RawQuicError::InvalidReadSize => "invalid_read_size",
        RawQuicError::NormalDrained => "normal_drained",
        RawQuicError::DirectionReset => "direction_reset",
        RawQuicError::WebTransportProtocol => "webtransport_protocol",
        RawQuicError::WebTransportPartialResetUnavailable => {
            "webtransport_partial_reset_unavailable"
        }
    };
    stable_error(code)
}
#[cfg(test)]
fn stream_io_error(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::ConnectionReset => stable_error("reset"),
        std::io::ErrorKind::Interrupted => stable_error("canceled"),
        _ => stable_error("stream_failed"),
    }
}
pub(crate) fn stable_error(code: &str) -> Error {
    Error::new(Status::GenericFailure, code.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{limits, stream_io_error};
    use std::io;

    #[test]
    fn handshake_timeout_preserves_the_public_connector_range() {
        assert!(limits(66, 120_000).is_ok());
    }

    #[test]
    fn stream_reset_uses_the_stable_reset_code() {
        assert_eq!(
            stream_io_error(io::Error::new(io::ErrorKind::ConnectionReset, "peer reset")).reason,
            "reset",
        );
        assert_eq!(
            stream_io_error(io::Error::new(io::ErrorKind::BrokenPipe, "connection lost")).reason,
            "stream_failed",
        );
    }
}
