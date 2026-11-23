use crate::raw_quic::RawQuicAddress;
use flowersec_native_transport::{
    Cancellation,
    webtransport::{
        self as wt, Carrier, ClientTrust, DialFailure, Listener, MessageError, Stream,
        WebTransportListenerPolicy,
    },
};
use napi::{
    Error, Result,
    bindgen_prelude::{Buffer, Uint8Array, within_runtime_if_available},
    tokio,
};
use napi_derive::napi;
use std::{
    future::Future,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    time::Duration,
};

fn failure(code: &'static str) -> Error {
    Error::from_reason(code)
}
fn wire_path(path: &str) -> Result<&'static str> {
    match path {
        "direct" => Ok(wt::DIRECT),
        "tunnel" => Ok(wt::TUNNEL),
        _ => Err(failure("invalid_path")),
    }
}
struct Operation<T> {
    cancel: Cancellation,
    task: Mutex<Option<tokio::task::JoinHandle<Result<T>>>>,
}
impl<T: Send + 'static> Operation<T> {
    fn new(future: impl Future<Output = Result<T>> + Send + 'static) -> Self {
        let cancel = Cancellation::new();
        let stop = cancel.clone();
        let task = within_runtime_if_available(|| {
            tokio::spawn(async move {
                tokio::select! { biased; _ = stop.cancelled() => Err(failure("canceled")), result = future => result }
            })
        });
        Self {
            cancel,
            task: Mutex::new(Some(task)),
        }
    }
    async fn result(&self) -> Result<T> {
        let task = self
            .task
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take()
            .ok_or_else(|| failure("operation_already_consumed"))?;
        task.await.map_err(|_| failure("operation_failed"))?
    }
}
impl<T> Drop for Operation<T> {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[napi(object)]
pub struct WebTransportConnectOptions {
    #[napi(skip_typescript)]
    pub profile: Option<String>,
    pub url: String,
    pub path: String,
    pub origin: String,
    pub tls_mode: String,
    pub trust_roots_der: Option<Vec<Uint8Array>>,
    pub active_leaf_der_sha256: Option<Vec<Uint8Array>>,
    pub inbound_bidirectional_stream_capacity: u32,
    pub handshake_timeout_ms: u32,
}
#[napi(js_name = "connectWebTransport")]
pub fn connect(options: WebTransportConnectOptions) -> Result<WebTransportSessionOperation> {
    reject_profile(options.profile.as_deref())?;
    let path = wire_path(&options.path)?;
    if !options.url.ends_with(path) || !(1..=120_000).contains(&options.handshake_timeout_ms) {
        return Err(failure("invalid_limits"));
    }
    let trust = match (
        options.tls_mode.as_str(),
        options.trust_roots_der,
        options.active_leaf_der_sha256,
    ) {
        ("ca", Some(roots), None) if !roots.is_empty() => {
            ClientTrust::Ca(roots.into_iter().map(|value| value.to_vec()).collect())
        }
        ("pin", None, Some(pins)) if !pins.is_empty() && pins.len() <= 4 => ClientTrust::Pin(
            pins.into_iter()
                .map(|value| {
                    value
                        .as_ref()
                        .try_into()
                        .map_err(|_| failure("invalid_tls_policy"))
                })
                .collect::<Result<_>>()?,
        ),
        _ => return Err(failure("invalid_tls_policy")),
    };
    Ok(WebTransportSessionOperation(Operation::new(async move {
        let carrier = tokio::time::timeout(
            Duration::from_millis(options.handshake_timeout_ms.into()),
            wt::dial(
                &options.url,
                &options.origin,
                trust,
                options.inbound_bidirectional_stream_capacity,
            ),
        )
        .await
        .map_err(|_| failure("handshake_timeout"))?
        .map_err(|err| {
            failure(match err {
                DialFailure::InvalidArtifact => "invalid_limits",
                DialFailure::Security => "handshake_failed",
                DialFailure::Connection => "connect_failed",
            })
        })?;
        Ok(WebTransportSession {
            carrier,
            path: options.path,
        })
    })))
}
#[napi(object)]
pub struct WebTransportBindOptions {
    #[napi(skip_typescript)]
    pub profile: Option<String>,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub authority_host: String,
    pub allowed_origins: Vec<String>,
    pub certificate_chain_der: Vec<Uint8Array>,
    pub private_key_der: Uint8Array,
    pub inbound_bidirectional_stream_capacity: u32,
    pub handshake_timeout_ms: Option<u32>,
}
#[napi(js_name = "bindWebTransport")]
pub async fn bind(options: WebTransportBindOptions) -> Result<WebTransportListener> {
    reject_profile(options.profile.as_deref())?;
    let bind = SocketAddr::new(
        options
            .host
            .parse()
            .map_err(|_| failure("invalid_bind_address"))?,
        options.port,
    );
    let path = wire_path(&options.path)?;
    let policy = WebTransportListenerPolicy::new(options.authority_host, options.allowed_origins)
        .map_err(|_| failure("invalid_origin_policy"))?;
    let timeout = options.handshake_timeout_ms.unwrap_or(10_000);
    if !(1..=120_000).contains(&timeout) {
        return Err(failure("invalid_limits"));
    }
    let socket = UdpSocket::bind(bind).map_err(|_| failure("endpoint_failed"))?;
    let address = socket
        .local_addr()
        .map_err(|_| failure("endpoint_failed"))?;
    let listener = Listener::new(
        socket,
        address,
        options
            .certificate_chain_der
            .into_iter()
            .map(|value| value.to_vec())
            .collect(),
        options.private_key_der.to_vec(),
        policy,
        path,
        options.inbound_bidirectional_stream_capacity,
        Duration::from_millis(timeout.into()),
    )
    .map_err(|_| failure("endpoint_failed"))?;
    Ok(WebTransportListener {
        listener: Arc::new(listener),
        path: options.path,
    })
}
fn reject_profile(profile: Option<&str>) -> Result<()> {
    if profile.is_some() {
        return Err(failure(
            "WebTransport profile was removed; omit profile for draft02 or use raw QUIC",
        ));
    }
    Ok(())
}
#[napi]
pub struct WebTransportListener {
    listener: Arc<Listener>,
    path: String,
}
impl Drop for WebTransportListener {
    fn drop(&mut self) {
        self.listener.abort();
    }
}
#[napi]
impl WebTransportListener {
    #[napi]
    pub fn address(&self) -> Result<RawQuicAddress> {
        let address = self
            .listener
            .local_address()
            .map_err(|_| failure("listener_closed"))?;
        Ok(RawQuicAddress {
            host: address.ip().to_string(),
            port: address.port(),
        })
    }
    #[napi]
    pub fn accept(&self) -> WebTransportSessionOperation {
        let listener = self.listener.clone();
        let path = self.path.clone();
        WebTransportSessionOperation(Operation::new(async move {
            let (carrier, _) = listener
                .accept()
                .await
                .map_err(|_| failure("listener_closed"))?;
            Ok(WebTransportSession { carrier, path })
        }))
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
#[napi]
pub struct WebTransportSessionOperation(Operation<WebTransportSession>);
#[napi]
impl WebTransportSessionOperation {
    #[napi]
    pub fn cancel(&self) {
        self.0.cancel.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<WebTransportSession> {
        self.0.result().await
    }
}
#[napi]
pub struct WebTransportSession {
    carrier: Arc<Carrier>,
    path: String,
}
impl Drop for WebTransportSession {
    fn drop(&mut self) {
        self.carrier.abort();
    }
}
#[napi]
impl WebTransportSession {
    #[napi(getter)]
    pub fn kind(&self) -> &'static str {
        "webtransport"
    }
    #[napi(getter)]
    pub fn path(&self) -> String {
        self.path.clone()
    }
    #[napi(getter)]
    pub fn wire_version(&self) -> u32 {
        5
    }
    #[napi(getter)]
    pub fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.carrier.inbound_bidirectional_stream_capacity()
    }
    #[napi(getter)]
    pub fn max_datagram_size(&self) -> Option<u32> {
        self.carrier
            .unreliable_message_max_size()
            .and_then(|size| size.try_into().ok())
    }
    #[napi]
    pub fn open_stream(&self) -> WebTransportStreamOperation {
        self.stream(true)
    }
    #[napi]
    pub fn accept_stream(&self) -> WebTransportStreamOperation {
        self.stream(false)
    }
    #[napi]
    pub fn receive_datagram(&self) -> WebTransportDatagramOperation {
        let carrier = self.carrier.clone();
        WebTransportDatagramOperation(Operation::new(async move {
            carrier
                .receive_unreliable_message()
                .await
                .map(|value| value.to_vec().into())
                .map_err(|_| failure("closed"))
        }))
    }
    #[napi]
    pub async fn send_datagram(&self, data: Uint8Array) -> Result<&'static str> {
        if self
            .carrier
            .unreliable_message_max_size()
            .is_none_or(|max| data.len() > max)
        {
            return Ok(if self.carrier.unreliable_message_max_size().is_none() {
                "unavailable"
            } else {
                "too_large"
            });
        }
        match self
            .carrier
            .send_unreliable_message(data.to_vec().into())
            .await
        {
            Ok(()) => Ok("accepted"),
            Err(MessageError::TooLarge) => Ok("too_large"),
            Err(MessageError::Dropped) => Ok("dropped_budget"),
            Err(MessageError::Unavailable) => Ok("unavailable"),
            Err(MessageError::Closed) => Err(failure("closed")),
        }
    }
    #[napi]
    pub async fn close(&self, code: Option<u32>, reason: Option<String>) -> Result<()> {
        let result = match (code, reason) {
            (None, None) => self.carrier.close().await,
            (code, reason) => {
                self.carrier
                    .close_with_reason(code.unwrap_or(0), reason.as_deref().unwrap_or(""))
                    .await
            }
        };
        result.map_err(|error| match error.kind() {
            std::io::ErrorKind::InvalidInput => failure("invalid_close"),
            _ => failure("closed"),
        })
    }
    #[napi]
    pub async fn wait_termination(&self) {
        self.carrier.wait_shutdown().await;
    }
    #[napi(js_name = "waitRemoteSessionClose")]
    pub async fn wait_remote_session_close(&self) -> bool {
        self.carrier.wait_termination().await;
        crate::is_remote_session_close(self.carrier.peer_application_close())
    }
    #[napi]
    pub fn abort(&self) {
        self.carrier.abort();
    }
}
impl WebTransportSession {
    fn stream(&self, open: bool) -> WebTransportStreamOperation {
        let carrier = self.carrier.clone();
        WebTransportStreamOperation(Operation::new(async move {
            let stream = if open {
                carrier.open_stream().await
            } else {
                carrier.accept_stream().await
            }
            .map_err(|_| failure("closed"))?;
            Ok(WebTransportStream {
                stream,
                pending: Mutex::new(Cancellation::new()),
            })
        }))
    }
}
#[napi]
pub struct WebTransportStreamOperation(Operation<WebTransportStream>);
#[napi]
impl WebTransportStreamOperation {
    #[napi]
    pub fn cancel(&self) {
        self.0.cancel.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<WebTransportStream> {
        self.0.result().await
    }
}
#[napi]
pub struct WebTransportDatagramOperation(Operation<Buffer>);
#[napi]
impl WebTransportDatagramOperation {
    #[napi]
    pub fn cancel(&self) {
        self.0.cancel.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<Buffer> {
        self.0.result().await
    }
}
#[napi]
pub struct WebTransportStream {
    stream: Arc<Stream>,
    pending: Mutex<Cancellation>,
}
impl WebTransportStream {
    fn token(&self) -> Cancellation {
        self.pending
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }
}
#[napi]
impl WebTransportStream {
    #[napi]
    pub async fn read(&self) -> Result<Option<Buffer>> {
        let mut data = vec![0; 65536];
        let token = self.token();
        let read = tokio::select! {biased; _ = token.cancelled() => return Err(failure("canceled")), result = self.stream.read(&mut data) => result.map_err(|_|failure("reset"))? };
        data.truncate(read);
        Ok((read != 0).then(|| data.into()))
    }
    #[napi]
    pub async fn write(&self, data: Uint8Array) -> Result<u32> {
        let token = self.token();
        tokio::select! {biased; _ = token.cancelled() => Err(failure("canceled")), result = self.stream.write(data.as_ref()) => result.map_err(|_|failure("reset")).and_then(|size| size.try_into().map_err(|_|failure("invalid_limits"))) }
    }
    #[napi]
    pub async fn close_write(&self) -> Result<()> {
        self.stream
            .close_write()
            .await
            .map_err(|_| failure("reset"))
    }
    #[napi]
    pub async fn stop_sending(&self) -> Result<()> {
        self.stream
            .stop_sending()
            .await
            .map_err(|_| failure("reset"))
    }
    #[napi]
    pub async fn reset(&self) -> Result<()> {
        self.stream.reset().await.map_err(|_| failure("reset"))
    }
    #[napi]
    pub fn cancel_pending(&self) {
        let mut token = self.pending.lock().unwrap_or_else(|err| err.into_inner());
        token.cancel();
        *token = Cancellation::new();
    }
    #[napi]
    pub fn abort(&self) {
        let stream = self.stream.clone();
        self.cancel_pending();
        within_runtime_if_available(|| {
            tokio::spawn(async move {
                let _ = stream.reset().await;
            })
        });
    }
}
