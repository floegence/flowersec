use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use flowersec_native_transport::{
    ApplicationClose, Cancellation, DatagramSendOutcome, PathProfile, RawQuicClientConfig,
    RawQuicError, RawQuicLimits, RawQuicListener, RawQuicServerConfig, RawQuicSession,
    RawQuicStream,
};
use napi::{
    Error, Result, Status,
    bindgen_prelude::{Buffer, Uint8Array, within_runtime_if_available},
};
use napi_derive::napi;

const DEFAULT_READ_BYTES: usize = 64 * 1024;
const DEFAULT_CLOSE_CODE: u64 = 0x0000_f500;
type OperationTask<T> =
    Mutex<Option<napi::tokio::task::JoinHandle<std::result::Result<T, RawQuicError>>>>;

#[napi(object)]
pub struct RawQuicConnectOptions {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub path: String,
    pub trust_roots_der: Vec<Uint8Array>,
    pub inbound_bidirectional_stream_capacity: u32,
    pub handshake_timeout_ms: u32,
}

#[napi(object)]
pub struct RawQuicBindOptions {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub certificate_chain_der: Vec<Uint8Array>,
    pub private_key_der: Uint8Array,
    pub inbound_bidirectional_stream_capacity: u32,
    pub handshake_timeout_ms: Option<u32>,
}

#[napi(object)]
pub struct RawQuicAddress {
    pub host: String,
    pub port: u16,
}

#[napi(js_name = "connectRawQuic")]
pub fn connect_raw_quic(options: RawQuicConnectOptions) -> Result<RawQuicConnectOperation> {
    let cancellation = Cancellation::new();
    let task_cancellation = cancellation.clone();
    let profile = profile(&options.path)?;
    let limits = limits(
        options.inbound_bidirectional_stream_capacity,
        options.handshake_timeout_ms,
    )?;
    let config = RawQuicClientConfig::new(
        profile,
        options
            .trust_roots_der
            .into_iter()
            .map(|root| root.to_vec())
            .collect(),
        limits,
    )
    .map_err(native_error)?;
    let task = spawn_native(async move {
        let addresses = napi::tokio::select! {
            biased;
            _ = task_cancellation.cancelled() => return Err(RawQuicError::Canceled),
            result = napi::tokio::net::lookup_host((options.host.as_str(), options.port)) => {
                result.map_err(|_| RawQuicError::NoUsableAddress)?.collect::<Vec<_>>()
            }
        };
        RawQuicSession::dial(addresses, options.server_name, config, &task_cancellation).await
    });
    Ok(RawQuicConnectOperation {
        cancellation,
        task: Mutex::new(Some(task)),
    })
}

#[napi(js_name = "bindRawQuic")]
pub async fn bind_raw_quic(options: RawQuicBindOptions) -> Result<RawQuicListenerBinding> {
    let address = SocketAddr::new(
        options
            .host
            .parse::<IpAddr>()
            .map_err(|_| stable_error("invalid_bind_address"))?,
        options.port,
    );
    let limits = limits(
        options.inbound_bidirectional_stream_capacity,
        options.handshake_timeout_ms.unwrap_or(10_000),
    )?;
    let config = RawQuicServerConfig::new(
        profile(&options.path)?,
        options
            .certificate_chain_der
            .into_iter()
            .map(|certificate| certificate.to_vec())
            .collect(),
        options.private_key_der.to_vec(),
        limits,
    )
    .map_err(native_error)?;
    let listener = RawQuicListener::bind(address, config).map_err(native_error)?;
    Ok(RawQuicListenerBinding {
        listener: Arc::new(listener),
    })
}

#[napi(js_name = "RawQuicConnectOperation")]
pub struct RawQuicConnectOperation {
    cancellation: Cancellation,
    task: OperationTask<RawQuicSession>,
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
        let task = take_task(&self.task)?;
        let session = task
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)?;
        Ok(RawQuicSessionBinding { session })
    }
}

#[napi(js_name = "RawQuicListener")]
pub struct RawQuicListenerBinding {
    listener: Arc<RawQuicListener>,
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
        let address = self.listener.local_address().map_err(native_error)?;
        Ok(raw_address(address))
    }

    #[napi(js_name = "accept")]
    pub fn accept(&self) -> RawQuicAcceptOperation {
        let listener = self.listener.clone();
        let cancellation = Cancellation::new();
        let task_cancellation = cancellation.clone();
        let task = spawn_native(async move { listener.accept(&task_cancellation).await });
        RawQuicAcceptOperation {
            cancellation,
            task: Mutex::new(Some(task)),
        }
    }

    #[napi]
    pub fn abort(&self) {
        self.listener.abort();
    }

    #[napi]
    pub async fn close(&self) {
        self.listener.close().await;
    }
}

#[napi(js_name = "RawQuicAcceptOperation")]
pub struct RawQuicAcceptOperation {
    cancellation: Cancellation,
    task: OperationTask<RawQuicSession>,
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
        let task = take_task(&self.task)?;
        let session = task
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)?;
        Ok(RawQuicSessionBinding { session })
    }
}

#[napi(js_name = "RawQuicSession")]
pub struct RawQuicSessionBinding {
    session: RawQuicSession,
}

impl Drop for RawQuicSessionBinding {
    fn drop(&mut self) {
        self.session.abort();
    }
}

#[napi]
impl RawQuicSessionBinding {
    #[napi(getter)]
    pub fn kind(&self) -> &'static str {
        "raw_quic"
    }

    #[napi(getter)]
    pub fn path(&self) -> &'static str {
        match self.session.profile() {
            PathProfile::Direct => "direct",
            PathProfile::Tunnel => "tunnel",
        }
    }

    #[napi(getter, js_name = "inboundBidirectionalStreamCapacity")]
    pub fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.session.inbound_bidirectional_stream_capacity()
    }

    #[napi(getter, js_name = "maxDatagramSize")]
    pub fn max_datagram_size(&self) -> Option<u32> {
        self.session
            .max_datagram_size()
            .and_then(|maximum| u32::try_from(maximum).ok())
    }

    #[napi(js_name = "openStream")]
    pub fn open_stream(&self) -> RawQuicStreamOperation {
        stream_operation(self.session.clone(), true)
    }

    #[napi(js_name = "acceptStream")]
    pub fn accept_stream(&self) -> RawQuicStreamOperation {
        stream_operation(self.session.clone(), false)
    }

    #[napi(js_name = "receiveDatagram")]
    pub fn receive_datagram(&self) -> RawQuicDatagramOperation {
        let session = self.session.clone();
        let cancellation = Cancellation::new();
        let task_cancellation = cancellation.clone();
        let task = spawn_native(async move { session.receive_datagram(&task_cancellation).await });
        RawQuicDatagramOperation {
            cancellation,
            task: Mutex::new(Some(task)),
        }
    }

    #[napi(js_name = "sendDatagram")]
    pub fn send_datagram(&self, payload: Uint8Array) -> &'static str {
        match self.session.send_datagram(payload.to_vec()) {
            DatagramSendOutcome::Accepted => "accepted",
            DatagramSendOutcome::DroppedBudget => "dropped_budget",
            DatagramSendOutcome::DroppedCarrier => "dropped_carrier",
            DatagramSendOutcome::TooLarge => "too_large",
            DatagramSendOutcome::Unavailable => "unavailable",
        }
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
            .map_err(native_error)
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
    cancellation: Cancellation,
    task: OperationTask<RawQuicStream>,
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
        let task = take_task(&self.task)?;
        let stream = task
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)?;
        Ok(RawQuicStreamBinding { stream })
    }
}

#[napi(js_name = "RawQuicDatagramOperation")]
pub struct RawQuicDatagramOperation {
    cancellation: Cancellation,
    task: OperationTask<Vec<u8>>,
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
        let task = take_task(&self.task)?;
        let payload = task
            .await
            .map_err(|_| stable_error("operation_failed"))?
            .map_err(native_error)?;
        Ok(payload.into())
    }
}

#[napi(js_name = "RawQuicStream")]
pub struct RawQuicStreamBinding {
    stream: RawQuicStream,
}

#[napi]
impl RawQuicStreamBinding {
    #[napi]
    pub async fn read(&self) -> Result<Option<Buffer>> {
        self.stream
            .read(DEFAULT_READ_BYTES, &Cancellation::new())
            .await
            .map(|payload| payload.map(Into::into))
            .map_err(native_error)
    }

    #[napi]
    pub async fn write(&self, payload: Uint8Array) -> Result<u32> {
        let written = self
            .stream
            .write(payload.to_vec(), &Cancellation::new())
            .await
            .map_err(native_error)?;
        u32::try_from(written).map_err(|_| stable_error("operation_failed"))
    }

    #[napi(js_name = "closeWrite")]
    pub async fn close_write(&self) -> Result<()> {
        self.stream
            .close_write(&Cancellation::new())
            .await
            .map_err(native_error)
    }

    #[napi(js_name = "stopSending")]
    pub async fn stop_sending(&self) -> Result<()> {
        self.stream.stop_sending().await.map_err(native_error)
    }

    #[napi]
    pub async fn reset(&self) -> Result<()> {
        self.stream.reset().await.map_err(native_error)
    }

    #[napi]
    pub fn abort(&self) {
        reset_stream(self.stream.clone());
    }
}

fn stream_operation(session: RawQuicSession, open: bool) -> RawQuicStreamOperation {
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
    }
}

fn reset_stream(stream: RawQuicStream) {
    stream.abort();
    drop(spawn_native(async move {
        stream.reset().await?;
        Ok(())
    }));
}

fn profile(value: &str) -> Result<PathProfile> {
    match value {
        "direct" => Ok(PathProfile::Direct),
        "tunnel" => Ok(PathProfile::Tunnel),
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

fn raw_address(address: SocketAddr) -> RawQuicAddress {
    RawQuicAddress {
        host: address.ip().to_string(),
        port: address.port(),
    }
}

fn take_task<T>(
    task: &Mutex<Option<napi::tokio::task::JoinHandle<T>>>,
) -> Result<napi::tokio::task::JoinHandle<T>> {
    task.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .ok_or_else(|| stable_error("operation_already_consumed"))
}

fn spawn_native<T, F>(
    future: F,
) -> napi::tokio::task::JoinHandle<std::result::Result<T, RawQuicError>>
where
    T: Send + 'static,
    F: Future<Output = std::result::Result<T, RawQuicError>> + Send + 'static,
{
    within_runtime_if_available(|| napi::tokio::spawn(future))
}

fn native_error(error: RawQuicError) -> Error {
    let code = match error {
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
        RawQuicError::InvalidNegotiatedAlpn => "invalid_alpn",
        RawQuicError::Stream => "stream_failed",
        RawQuicError::DatagramUnavailable => "datagram_unavailable",
        RawQuicError::Closed => "closed",
        RawQuicError::MigrationUnavailable => "migration_unavailable",
        RawQuicError::Migration(_) => "migration_failed",
        RawQuicError::InvalidApplicationClose => "invalid_close",
        RawQuicError::InvalidReadSize => "invalid_read_size",
    };
    stable_error(code)
}

fn stable_error(code: &str) -> Error {
    Error::new(Status::GenericFailure, code.to_owned())
}

#[cfg(test)]
mod tests {
    use super::limits;

    #[test]
    fn handshake_timeout_preserves_the_public_connector_range() {
        assert!(limits(66, 120_000).is_ok());
    }
}
