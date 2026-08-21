//! Version-neutral native WebSocket transport mechanics.

use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};

use async_trait::async_trait;
use futures_util::{SinkExt as _, StreamExt as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, oneshot},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config, client_async_with_config,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        handshake::server::{ErrorResponse, Request, Response},
        http::{HeaderValue, StatusCode},
        protocol::WebSocketConfig,
    },
};
use tokio_util::{compat::TokioAsyncReadCompatExt, sync::CancellationToken};

use crate::transport_v2::{CarrierKind, CarrierSessionV2, CarrierStreamV2};
use crate::transport_v3::{CarrierKind as CarrierKindV3, CarrierSessionV3, CarrierStreamV3};

const MAX_BINARY_MESSAGE_BYTES: usize = 256 * 1024 + 12;
const MAX_QUEUED_MESSAGES: usize = 64;
const YAMUX_BYTE_BUFFER_BYTES: usize = 512 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebSocketError {
    #[error("invalid WebSocket configuration")]
    InvalidConfiguration,
    #[error("WebSocket bind failed")]
    Bind(#[source] io::Error),
    #[error("WebSocket connection failed")]
    Connect,
    #[error("WebSocket TLS failed")]
    Tls(#[source] io::Error),
    #[error("WebSocket listener closed")]
    Closed,
}

pub(crate) struct WebSocketListener {
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    allowed_origins: Arc<HashSet<String>>,
    capacity: u32,
    path: &'static str,
    subprotocol: &'static str,
}

impl fmt::Debug for WebSocketListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebSocketListener { <opaque> }")
    }
}

impl WebSocketListener {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind(
        address: SocketAddr,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        allowed_origins: Vec<String>,
        capacity: u32,
        path: &'static str,
        subprotocol: &'static str,
        require_tls: bool,
        disable_resumption: bool,
    ) -> Result<Self, WebSocketError> {
        if !(3..=130).contains(&capacity)
            || allowed_origins.is_empty()
            || allowed_origins.iter().any(|origin| !valid_origin(origin))
        {
            return Err(WebSocketError::InvalidConfiguration);
        }
        let tls = server_tls(certificate_chain_der, private_key_der, disable_resumption)?;
        if tls.is_none() && (require_tls || !address.ip().is_loopback()) {
            return Err(WebSocketError::InvalidConfiguration);
        }
        let listener = std::net::TcpListener::bind(address).map_err(WebSocketError::Bind)?;
        listener
            .set_nonblocking(true)
            .map_err(WebSocketError::Bind)?;
        let listener = TcpListener::from_std(listener).map_err(WebSocketError::Bind)?;
        Ok(Self {
            listener,
            tls,
            allowed_origins: Arc::new(allowed_origins.into_iter().collect()),
            capacity,
            path,
            subprotocol,
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) async fn accept_with_peer(
        &self,
    ) -> Result<(Arc<WebSocketCarrier>, SocketAddr), WebSocketError> {
        loop {
            let (stream, peer) = self
                .listener
                .accept()
                .await
                .map_err(|_| WebSocketError::Closed)?;
            if self.tls.is_none()
                && (!peer.ip().is_loopback()
                    || !stream
                        .local_addr()
                        .map(|address| address.ip().is_loopback())
                        .unwrap_or(false))
            {
                continue;
            }
            let accepted = if let Some(tls) = &self.tls {
                match tls.accept(stream).await {
                    Ok(stream) => {
                        accept_server_websocket(
                            stream,
                            self.path,
                            self.subprotocol,
                            self.allowed_origins.clone(),
                        )
                        .await
                    }
                    Err(_) => continue,
                }
            } else {
                accept_server_websocket(
                    stream,
                    self.path,
                    self.subprotocol,
                    self.allowed_origins.clone(),
                )
                .await
            };
            if let Ok(io) = accepted {
                return Ok((WebSocketCarrier::pending(io, false, self.capacity), peer));
            }
        }
    }
}

fn server_tls(
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_der: Vec<u8>,
    disable_resumption: bool,
) -> Result<Option<TlsAcceptor>, WebSocketError> {
    Ok(
        server_tls_config(certificate_chain_der, private_key_der, disable_resumption)?
            .map(|config| TlsAcceptor::from(Arc::new(config))),
    )
}

fn server_tls_config(
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_der: Vec<u8>,
    disable_resumption: bool,
) -> Result<Option<rustls::ServerConfig>, WebSocketError> {
    if certificate_chain_der.is_empty() && private_key_der.is_empty() {
        return Ok(None);
    }
    if certificate_chain_der.is_empty() || private_key_der.is_empty() {
        return Err(WebSocketError::InvalidConfiguration);
    }
    let key = PrivateKeyDer::try_from(private_key_der)
        .map_err(|_| WebSocketError::InvalidConfiguration)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| WebSocketError::InvalidConfiguration)?
        .with_no_client_auth()
        .with_single_cert(
            certificate_chain_der
                .into_iter()
                .map(CertificateDer::from)
                .collect(),
            key,
        )
        .map_err(|_| WebSocketError::InvalidConfiguration)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    if disable_resumption {
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
    }
    Ok(Some(config))
}

async fn accept_server_websocket<S>(
    stream: S,
    path: &'static str,
    subprotocol: &'static str,
    allowed_origins: Arc<HashSet<String>>,
) -> Result<WebSocketIo, WebSocketError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let callback = move |request: &Request, mut response: Response| {
        let protocol_matches = request
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(',').any(|item| item.trim() == subprotocol));
        let origin_allowed = request
            .headers()
            .get("origin")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|origin| allowed_origins.contains(origin));
        if request.uri().path() != path || !protocol_matches || !origin_allowed {
            let mut rejected = ErrorResponse::new(Some("request rejected".to_owned()));
            *rejected.status_mut() = StatusCode::FORBIDDEN;
            return Err(rejected);
        }
        response.headers_mut().insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(subprotocol),
        );
        Ok(response)
    };
    let websocket = accept_hdr_async_with_config(stream, callback, Some(websocket_config()))
        .await
        .map_err(|_| WebSocketError::Connect)?;
    Ok(spawn_websocket_pump(websocket))
}

pub(crate) async fn dial_with_trust_roots(
    url: &str,
    subprotocol: &'static str,
    origin: &str,
    trust_roots_der: Vec<Vec<u8>>,
    capacity: u32,
) -> Result<Arc<WebSocketCarrier>, WebSocketError> {
    if !valid_origin(origin) || !(3..=130).contains(&capacity) {
        return Err(WebSocketError::InvalidConfiguration);
    }
    let parsed = url::Url::parse(url).map_err(|_| WebSocketError::InvalidConfiguration)?;
    if !matches!(parsed.scheme(), "ws" | "wss") {
        return Err(WebSocketError::InvalidConfiguration);
    }
    let host = parsed
        .host_str()
        .ok_or(WebSocketError::InvalidConfiguration)?;
    let port = parsed
        .port_or_known_default()
        .ok_or(WebSocketError::InvalidConfiguration)?;
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|_| WebSocketError::Connect)?;
    if parsed.scheme() == "ws"
        && (!loopback_host(host)
            || !stream
                .peer_addr()
                .map(|address| address.ip().is_loopback())
                .unwrap_or(false)
            || !stream
                .local_addr()
                .map(|address| address.ip().is_loopback())
                .unwrap_or(false))
    {
        return Err(WebSocketError::InvalidConfiguration);
    }
    let mut request = url
        .into_client_request()
        .map_err(|_| WebSocketError::InvalidConfiguration)?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(subprotocol),
    );
    request.headers_mut().insert(
        "origin",
        HeaderValue::from_str(origin).map_err(|_| WebSocketError::InvalidConfiguration)?,
    );
    let carrier = if parsed.scheme() == "wss" {
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| WebSocketError::InvalidConfiguration)?;
        let tls = TlsConnector::from(client_tls(trust_roots_der)?)
            .connect(server_name, stream)
            .await
            .map_err(|_| WebSocketError::Connect)?;
        establish_client_websocket(request, tls, subprotocol, capacity).await
    } else {
        establish_client_websocket(request, stream, subprotocol, capacity).await
    }?;
    Ok(carrier)
}

pub(crate) async fn dial_strict_tls(
    url: &str,
    expected_path: &'static str,
    subprotocol: &'static str,
    origin: &str,
    tls_config: Arc<rustls::ClientConfig>,
    capacity: u32,
) -> Result<Arc<WebSocketCarrier>, WebSocketError> {
    if !valid_origin(origin) || !(3..=130).contains(&capacity) {
        return Err(WebSocketError::InvalidConfiguration);
    }
    let parsed = url::Url::parse(url).map_err(|_| WebSocketError::InvalidConfiguration)?;
    if parsed.as_str() != url
        || parsed.scheme() != "wss"
        || parsed.path() != expected_path
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(WebSocketError::InvalidConfiguration);
    }
    let host = parsed
        .host_str()
        .ok_or(WebSocketError::InvalidConfiguration)?;
    let port = parsed
        .port_or_known_default()
        .ok_or(WebSocketError::InvalidConfiguration)?;
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|_| WebSocketError::Connect)?;
    let mut request = url
        .into_client_request()
        .map_err(|_| WebSocketError::InvalidConfiguration)?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(subprotocol),
    );
    request.headers_mut().insert(
        "origin",
        HeaderValue::from_str(origin).map_err(|_| WebSocketError::InvalidConfiguration)?,
    );
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| WebSocketError::InvalidConfiguration)?;
    let tls = TlsConnector::from(tls_config)
        .connect(server_name, stream)
        .await
        .map_err(WebSocketError::Tls)?;
    let carrier = establish_client_websocket(request, tls, subprotocol, capacity).await?;
    Ok(carrier)
}

async fn establish_client_websocket<S>(
    request: tokio_tungstenite::tungstenite::handshake::client::Request,
    stream: S,
    subprotocol: &'static str,
    capacity: u32,
) -> Result<Arc<WebSocketCarrier>, WebSocketError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (websocket, response) = client_async_with_config(request, stream, Some(websocket_config()))
        .await
        .map_err(|_| WebSocketError::Connect)?;
    if response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        != Some(subprotocol)
    {
        return Err(WebSocketError::Connect);
    }
    Ok(WebSocketCarrier::pending(
        spawn_websocket_pump(websocket),
        true,
        capacity,
    ))
}

pub(crate) fn client_tls(
    trust_roots_der: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ClientConfig>, WebSocketError> {
    if trust_roots_der.is_empty() {
        return Err(WebSocketError::InvalidConfiguration);
    }
    let mut roots = rustls::RootCertStore::empty();
    for root in trust_roots_der {
        roots
            .add(CertificateDer::from(root))
            .map_err(|_| WebSocketError::InvalidConfiguration)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| WebSocketError::InvalidConfiguration)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn websocket_config() -> WebSocketConfig {
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_BINARY_MESSAGE_BYTES);
    config.max_frame_size = Some(MAX_BINARY_MESSAGE_BYTES);
    config
}

fn valid_origin(origin: &str) -> bool {
    url::Url::parse(origin).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

enum OutgoingMessage {
    Binary(Vec<u8>, oneshot::Sender<io::Result<()>>),
    Barrier(oneshot::Sender<io::Result<()>>),
    Close(oneshot::Sender<io::Result<()>>),
}

struct WebSocketIo {
    incoming: Mutex<Option<mpsc::Receiver<io::Result<Vec<u8>>>>>,
    outgoing: mpsc::Sender<OutgoingMessage>,
    cancellation: CancellationToken,
}

impl fmt::Debug for WebSocketIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebSocketIo { <opaque> }")
    }
}

fn spawn_websocket_pump<S>(websocket: WebSocketStream<S>) -> WebSocketIo
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = websocket.split();
    let (incoming_tx, incoming_rx) = mpsc::channel(MAX_QUEUED_MESSAGES);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel(MAX_QUEUED_MESSAGES);
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = task_cancellation.cancelled() => break,
                outgoing = outgoing_rx.recv() => match outgoing {
                    Some(OutgoingMessage::Binary(payload, delivered)) => {
                        match sink.send(Message::Binary(payload.into())).await {
                            Ok(()) => { let _ = delivered.send(Ok(())); }
                            Err(error) => {
                                let _ = delivered.send(Err(io::Error::other(error.to_string())));
                                break;
                            }
                        }
                    }
                    Some(OutgoingMessage::Barrier(delivered)) => {
                        let _ = delivered.send(Ok(()));
                    }
                    Some(OutgoingMessage::Close(delivered)) => {
                        let result = sink.send(Message::Close(None)).await
                            .map_err(|error| io::Error::other(error.to_string()));
                        let _ = delivered.send(result);
                        break;
                    }
                    None => {
                        break;
                    }
                },
                incoming = stream.next() => match incoming {
                    Some(Ok(Message::Binary(payload))) => {
                        if incoming_tx.send(Ok(payload.to_vec())).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if sink.send(Message::Pong(payload)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {
                        let _ = incoming_tx.send(Err(io::Error::new(io::ErrorKind::InvalidData, "non-binary WebSocket message"))).await;
                        break;
                    }
                    Some(Err(error)) => {
                        let _ = incoming_tx.send(Err(io::Error::other(error))).await;
                        break;
                    }
                }
            }
        }
    });
    WebSocketIo {
        incoming: Mutex::new(Some(incoming_rx)),
        outgoing: outgoing_tx,
        cancellation,
    }
}

pub(crate) struct WebSocketCarrier {
    state: Arc<WebSocketCarrierState>,
}

struct WebSocketCarrierState {
    io: Mutex<Option<WebSocketIo>>,
    mux: Mutex<Option<Arc<WebSocketMuxSession>>>,
    cancellation: CancellationToken,
    admission_client: bool,
    multiplexer_client: AtomicBool,
    capacity: u32,
    admission_taken: AtomicBool,
    closed: AtomicBool,
}

impl fmt::Debug for WebSocketCarrier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebSocketCarrier { <opaque> }")
    }
}

impl WebSocketCarrier {
    fn pending(io: WebSocketIo, client: bool, capacity: u32) -> Arc<Self> {
        let cancellation = io.cancellation.clone();
        Arc::new(Self {
            state: Arc::new(WebSocketCarrierState {
                io: Mutex::new(Some(io)),
                mux: Mutex::new(None),
                cancellation,
                admission_client: client,
                multiplexer_client: AtomicBool::new(client),
                capacity,
                admission_taken: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            }),
        })
    }

    async fn mux(&self) -> io::Result<Arc<WebSocketMuxSession>> {
        let mut mux = self.state.mux.lock().await;
        if let Some(active) = mux.as_ref() {
            return Ok(active.clone());
        }
        if !self.state.admission_taken.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WebSocket admission has not completed",
            ));
        }
        let io =
            self.state.io.lock().await.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "WebSocket is closed")
            })?;
        let active = WebSocketMuxSession::start(
            io,
            self.state.multiplexer_client.load(Ordering::Acquire),
            self.state.capacity,
        )
        .await?;
        *mux = Some(active.clone());
        Ok(active)
    }

    fn admission_stream(&self) -> io::Result<Arc<WebSocketAdmissionStream>> {
        if self
            .state
            .admission_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "WebSocket admission stream already used",
            ));
        }
        Ok(Arc::new(WebSocketAdmissionStream {
            state: self.state.clone(),
            inbound: Mutex::new(AdmissionInbound::Waiting),
            outbound: StdMutex::new(Some(Vec::new())),
        }))
    }
}

#[async_trait]
impl CarrierSessionV2 for WebSocketCarrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Wss
    }

    fn set_multiplexer_client(&self, client: bool) -> io::Result<()> {
        let mux = self.state.mux.try_lock().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "WebSocket carrier is activating")
        })?;
        if mux.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "WebSocket multiplexer is already active",
            ));
        }
        self.state
            .multiplexer_client
            .store(client, Ordering::Release);
        Ok(())
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.state.capacity
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        if self.state.admission_client && !self.state.admission_taken.load(Ordering::Acquire) {
            self.admission_stream()
                .map(|stream| stream as Arc<dyn CarrierStreamV2>)
        } else {
            self.mux()
                .await?
                .open_stream()
                .await
                .map(|stream| stream as Arc<dyn CarrierStreamV2>)
        }
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        if !self.state.admission_client && !self.state.admission_taken.load(Ordering::Acquire) {
            self.admission_stream()
                .map(|stream| stream as Arc<dyn CarrierStreamV2>)
        } else {
            self.mux()
                .await?
                .accept_stream()
                .await
                .map(|stream| stream as Arc<dyn CarrierStreamV2>)
        }
    }

    async fn close(&self) -> io::Result<()> {
        if self.state.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let _cancel_on_exit = CancelCarrierOnDrop(self.state.cancellation.clone());
        if let Some(mux) = self.state.mux.lock().await.as_ref() {
            mux.close().await?;
        }
        if let Some(io) = self.state.io.lock().await.as_ref() {
            send_websocket_close(&io.outgoing).await?;
            io.cancellation.cancel();
        }
        Ok(())
    }

    fn abort(&self) {
        self.state.closed.store(true, Ordering::Release);
        self.state.cancellation.cancel();
    }
}

struct CancelCarrierOnDrop(CancellationToken);

impl Drop for CancelCarrierOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[async_trait]
impl CarrierSessionV3 for WebSocketCarrier {
    fn kind(&self) -> CarrierKindV3 {
        CarrierKindV3::Wss
    }

    fn set_multiplexer_client(&self, client: bool) -> io::Result<()> {
        CarrierSessionV2::set_multiplexer_client(self, client)
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.state.capacity
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        if self.state.admission_client && !self.state.admission_taken.load(Ordering::Acquire) {
            self.admission_stream()
                .map(|stream| stream as Arc<dyn CarrierStreamV3>)
        } else {
            self.mux()
                .await?
                .open_stream()
                .await
                .map(|stream| stream as Arc<dyn CarrierStreamV3>)
        }
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        if !self.state.admission_client && !self.state.admission_taken.load(Ordering::Acquire) {
            self.admission_stream()
                .map(|stream| stream as Arc<dyn CarrierStreamV3>)
        } else {
            self.mux()
                .await?
                .accept_stream()
                .await
                .map(|stream| stream as Arc<dyn CarrierStreamV3>)
        }
    }

    async fn close(&self) -> io::Result<()> {
        CarrierSessionV2::close(self).await
    }

    fn abort(&self) {
        CarrierSessionV2::abort(self);
    }
}

enum AdmissionInbound {
    Waiting,
    Reading { payload: Vec<u8>, offset: usize },
    Complete,
}

struct WebSocketAdmissionStream {
    state: Arc<WebSocketCarrierState>,
    inbound: Mutex<AdmissionInbound>,
    outbound: StdMutex<Option<Vec<u8>>>,
}

impl fmt::Debug for WebSocketAdmissionStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebSocketAdmissionStream { <opaque> }")
    }
}

#[async_trait]
impl CarrierStreamV2 for WebSocketAdmissionStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        if payload.is_empty() {
            return Ok(0);
        }
        let mut inbound = self.inbound.lock().await;
        if matches!(*inbound, AdmissionInbound::Waiting) {
            let mut io_guard = self.state.io.lock().await;
            let io = io_guard.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "WebSocket is closed")
            })?;
            let receiver = io.incoming.get_mut().as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "WebSocket is active")
            })?;
            let message = receiver.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "WebSocket closed")
            })??;
            *inbound = AdmissionInbound::Reading {
                payload: message,
                offset: 0,
            };
        }
        match &mut *inbound {
            AdmissionInbound::Reading {
                payload: message,
                offset,
            } => {
                let count = payload.len().min(message.len().saturating_sub(*offset));
                payload[..count].copy_from_slice(&message[*offset..*offset + count]);
                *offset += count;
                if *offset == message.len() {
                    *inbound = AdmissionInbound::Complete;
                }
                Ok(count)
            }
            AdmissionInbound::Complete => Ok(0),
            AdmissionInbound::Waiting => unreachable!(),
        }
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        let mut outbound = self
            .outbound
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let buffer = outbound
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "admission write closed"))?;
        if buffer.len().saturating_add(payload.len()) > 32 * 1024 + 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "admission message exceeds limit",
            ));
        }
        buffer.extend_from_slice(payload);
        Ok(payload.len())
    }

    async fn close_write(&self) -> io::Result<()> {
        let outbound = self
            .outbound
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(outbound) = outbound else {
            return Ok(());
        };
        let io = self.state.io.lock().await;
        let io = io
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "WebSocket is closed"))?;
        send_websocket_binary(&io.outgoing, outbound).await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        CarrierStreamV2::reset(self).await
    }

    async fn reset(&self) -> io::Result<()> {
        if let Some(io) = self.state.io.lock().await.as_ref() {
            io.cancellation.cancel();
        }
        Ok(())
    }

    async fn close(&self) -> io::Result<()> {
        CarrierStreamV2::close_write(self).await
    }
}

#[async_trait]
impl CarrierStreamV3 for WebSocketAdmissionStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        CarrierStreamV2::read(self, payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        CarrierStreamV2::write(self, payload).await
    }

    async fn close_write(&self) -> io::Result<()> {
        CarrierStreamV2::close_write(self).await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        CarrierStreamV2::stop_sending(self).await
    }

    async fn reset(&self) -> io::Result<()> {
        CarrierStreamV2::reset(self).await
    }

    async fn close(&self) -> io::Result<()> {
        CarrierStreamV2::close(self).await
    }
}

enum MuxCommand {
    Open(oneshot::Sender<io::Result<yamux::Stream>>),
    Flush(oneshot::Sender<io::Result<()>>),
    Close(oneshot::Sender<io::Result<()>>),
}

struct WebSocketMuxSession {
    commands: mpsc::Sender<MuxCommand>,
    incoming: Mutex<mpsc::Receiver<io::Result<yamux::Stream>>>,
    outgoing: mpsc::Sender<OutgoingMessage>,
    outbound_flush: mpsc::Sender<oneshot::Sender<io::Result<()>>>,
    outbound_done: Mutex<Option<oneshot::Receiver<io::Result<()>>>>,
    cancellation: CancellationToken,
}

impl WebSocketMuxSession {
    async fn start(io: WebSocketIo, client: bool, capacity: u32) -> io::Result<Arc<Self>> {
        let incoming_messages = io.incoming.lock().await.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::AlreadyExists, "WebSocket already active")
        })?;
        let (yamux_side, bridge_side) = tokio::io::duplex(YAMUX_BYTE_BUFFER_BYTES);
        let (outbound_done, outbound_flush) = spawn_binary_bridge(
            bridge_side,
            incoming_messages,
            io.outgoing.clone(),
            io.cancellation.clone(),
        );
        let mut config = yamux::Config::default();
        config
            .set_max_num_streams(capacity as usize)
            .set_max_connection_receive_window(Some(
                capacity as usize * yamux::DEFAULT_CREDIT as usize,
            ))
            .set_split_send_size(64 * 1024)
            .set_read_after_close(true);
        let connection = yamux::Connection::new(
            yamux_side.compat(),
            config,
            if client {
                yamux::Mode::Client
            } else {
                yamux::Mode::Server
            },
        );
        let (commands_tx, commands_rx) = mpsc::channel(capacity as usize + 2);
        let (incoming_tx, incoming_rx) = mpsc::channel(capacity as usize);
        let cancellation = io.cancellation.clone();
        tokio::spawn(run_yamux(
            connection,
            commands_rx,
            incoming_tx,
            cancellation.clone(),
        ));
        Ok(Arc::new(Self {
            commands: commands_tx,
            incoming: Mutex::new(incoming_rx),
            outgoing: io.outgoing,
            outbound_flush,
            outbound_done: Mutex::new(Some(outbound_done)),
            cancellation,
        }))
    }

    async fn open_stream(&self) -> io::Result<Arc<YamuxCarrierStream>> {
        let (sender, receiver) = oneshot::channel();
        self.commands
            .send(MuxCommand::Open(sender))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "WebSocket carrier closed"))?;
        let stream = receiver.await.map_err(|_| {
            io::Error::new(io::ErrorKind::NotConnected, "WebSocket carrier closed")
        })??;
        Ok(Arc::new(YamuxCarrierStream::new(
            stream,
            self.commands.clone(),
            self.outbound_flush.clone(),
        )))
    }

    async fn accept_stream(&self) -> io::Result<Arc<YamuxCarrierStream>> {
        let stream = self.incoming.lock().await.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "WebSocket carrier closed")
        })??;
        Ok(Arc::new(YamuxCarrierStream::new(
            stream,
            self.commands.clone(),
            self.outbound_flush.clone(),
        )))
    }

    async fn close(&self) -> io::Result<()> {
        let (delivered, delivery) = oneshot::channel();
        if self
            .commands
            .send(MuxCommand::Close(delivered))
            .await
            .is_err()
        {
            self.cancellation.cancel();
            return Ok(());
        }
        if delivery.await.ok().and_then(Result::ok).is_none() {
            self.cancellation.cancel();
            return Ok(());
        }
        if let Some(outbound_done) = self.outbound_done.lock().await.take() {
            if outbound_done.await.ok().and_then(Result::ok).is_none() {
                self.cancellation.cancel();
                return Ok(());
            }
        }
        let _ = send_websocket_close(&self.outgoing).await;
        self.cancellation.cancel();
        Ok(())
    }
}

async fn run_yamux<T>(
    mut connection: yamux::Connection<T>,
    mut commands: mpsc::Receiver<MuxCommand>,
    incoming: mpsc::Sender<io::Result<yamux::Stream>>,
    cancellation: CancellationToken,
) where
    T: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin,
{
    enum Event {
        Command(MuxCommand),
        Inbound(Option<yamux::Result<yamux::Stream>>),
        Canceled,
    }
    loop {
        let event = futures_util::future::poll_fn(|context| {
            if cancellation.is_cancelled() {
                return Poll::Ready(Event::Canceled);
            }
            if let Poll::Ready(command) = Pin::new(&mut commands).poll_recv(context) {
                return Poll::Ready(match command {
                    Some(command) => Event::Command(command),
                    None => Event::Canceled,
                });
            }
            connection.poll_next_inbound(context).map(Event::Inbound)
        })
        .await;
        match event {
            Event::Command(MuxCommand::Open(sender)) => {
                let result =
                    futures_util::future::poll_fn(|context| connection.poll_new_outbound(context))
                        .await
                        .map_err(io::Error::other);
                let _ = sender.send(result);
            }
            Event::Command(MuxCommand::Flush(delivered)) => {
                let result = futures_util::future::poll_fn(|context| {
                    loop {
                        match connection.poll_next_inbound(context) {
                            Poll::Pending => return Poll::Ready(Ok(())),
                            Poll::Ready(Some(Ok(stream))) => {
                                if incoming.try_send(Ok(stream)).is_err() {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::WouldBlock,
                                        "WebSocket inbound stream queue is full",
                                    )));
                                }
                            }
                            Poll::Ready(Some(Err(error))) => {
                                return Poll::Ready(Err(io::Error::other(error)));
                            }
                            Poll::Ready(None) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::NotConnected,
                                    "WebSocket carrier closed",
                                )));
                            }
                        }
                    }
                })
                .await;
                let _ = delivered.send(result);
            }
            Event::Command(MuxCommand::Close(delivered)) => {
                let result =
                    futures_util::future::poll_fn(|context| connection.poll_close(context))
                        .await
                        .map_err(io::Error::other);
                let _ = delivered.send(result);
                break;
            }
            Event::Canceled => {
                break;
            }
            Event::Inbound(Some(Ok(stream))) => {
                if incoming.send(Ok(stream)).await.is_err() {
                    break;
                }
            }
            Event::Inbound(Some(Err(error))) => {
                let _ = incoming.send(Err(io::Error::other(error))).await;
                break;
            }
            Event::Inbound(None) => break,
        }
    }
    cancellation.cancel();
}

fn spawn_binary_bridge(
    stream: tokio::io::DuplexStream,
    mut incoming: mpsc::Receiver<io::Result<Vec<u8>>>,
    outgoing: mpsc::Sender<OutgoingMessage>,
    cancellation: CancellationToken,
) -> (
    oneshot::Receiver<io::Result<()>>,
    mpsc::Sender<oneshot::Sender<io::Result<()>>>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let read_cancellation = cancellation.clone();
    tokio::spawn(async move {
        while !read_cancellation.is_cancelled() {
            let message = tokio::select! {
                _ = read_cancellation.cancelled() => break,
                message = incoming.recv() => message,
            };
            match message {
                Some(Ok(payload)) if writer.write_all(&payload).await.is_ok() => {}
                _ => break,
            }
        }
        let _ = writer.shutdown().await;
    });
    let (flush_tx, mut flush_rx) = mpsc::channel::<oneshot::Sender<io::Result<()>>>(1);
    let (outbound_done, outbound_delivery) = oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 64 * 1024];
        let result = loop {
            let read = tokio::select! {
                biased;
                _ = cancellation.cancelled() => break Err(io::Error::new(io::ErrorKind::Interrupted, "WebSocket carrier closed")),
                read = reader.read(&mut buffer) => read,
                flush = flush_rx.recv() => {
                    let Some(flush) = flush else {
                        break Err(io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket flush channel closed"));
                    };
                    let result = send_websocket_barrier(&outgoing).await;
                    let failed = result.is_err();
                    let _ = flush.send(result);
                    if failed {
                        break Err(io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket delivery barrier failed"));
                    }
                    continue;
                }
            };
            match read {
                Ok(0) => break Ok(()),
                Err(error) => break Err(error),
                Ok(count) => {
                    if let Err(error) =
                        send_websocket_binary(&outgoing, buffer[..count].to_vec()).await
                    {
                        break Err(error);
                    }
                }
            }
        };
        let _ = outbound_done.send(result);
    });
    (outbound_delivery, flush_tx)
}

async fn send_websocket_binary(
    outgoing: &mpsc::Sender<OutgoingMessage>,
    payload: Vec<u8>,
) -> io::Result<()> {
    let (delivered, delivery) = oneshot::channel();
    outgoing
        .send(OutgoingMessage::Binary(payload, delivered))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket is closed"))?;
    delivery
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket is closed"))?
}

async fn send_websocket_close(outgoing: &mpsc::Sender<OutgoingMessage>) -> io::Result<()> {
    let (delivered, delivery) = oneshot::channel();
    outgoing
        .send(OutgoingMessage::Close(delivered))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket is closed"))?;
    delivery
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket is closed"))?
}

async fn send_websocket_barrier(outgoing: &mpsc::Sender<OutgoingMessage>) -> io::Result<()> {
    let (delivered, delivery) = oneshot::channel();
    outgoing
        .send(OutgoingMessage::Barrier(delivered))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket is closed"))?;
    delivery
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket is closed"))?
}

struct YamuxCarrierStream {
    reader: Mutex<Option<futures_util::io::ReadHalf<yamux::Stream>>>,
    writer: Mutex<Option<futures_util::io::WriteHalf<yamux::Stream>>>,
    canceled: CancellationToken,
    mux_commands: mpsc::Sender<MuxCommand>,
    outbound_flush: mpsc::Sender<oneshot::Sender<io::Result<()>>>,
}

impl YamuxCarrierStream {
    fn new(
        stream: yamux::Stream,
        mux_commands: mpsc::Sender<MuxCommand>,
        outbound_flush: mpsc::Sender<oneshot::Sender<io::Result<()>>>,
    ) -> Self {
        let (reader, writer) = futures_util::io::AsyncReadExt::split(stream);
        Self {
            reader: Mutex::new(Some(reader)),
            writer: Mutex::new(Some(writer)),
            canceled: CancellationToken::new(),
            mux_commands,
            outbound_flush,
        }
    }
}

impl fmt::Debug for YamuxCarrierStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("YamuxCarrierStream { <opaque> }")
    }
}

#[async_trait]
impl CarrierStreamV2 for YamuxCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        tokio::select! {
            biased;
            _ = self.canceled.cancelled() => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Yamux stream reset",
            )),
            result = async {
                let mut reader = self.reader.lock().await;
                let reader = reader.as_mut().ok_or_else(|| io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Yamux stream reset",
                ))?;
                futures_util::io::AsyncReadExt::read(reader, payload).await
            } => result,
        }
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        tokio::select! {
            biased;
            _ = self.canceled.cancelled() => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Yamux stream reset",
            )),
            result = async {
                let mut writer = self.writer.lock().await;
                let writer = writer
                    .as_mut()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"))?;
                futures_util::io::AsyncWriteExt::write(writer, payload).await
            } => result,
        }
    }

    async fn close_write(&self) -> io::Result<()> {
        tokio::select! {
            biased;
            _ = self.canceled.cancelled() => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Yamux stream reset",
            )),
            result = async {
                let mut writer = self.writer.lock().await;
                if let Some(writer) = writer.as_mut() {
                    futures_util::io::AsyncWriteExt::close(writer).await?;
                }
                Ok(())
            } => result,
        }
    }

    async fn close_write_delivered(&self) -> io::Result<()> {
        CarrierStreamV2::close_write(self).await?;
        let (mux_flushed, mux_delivery) = oneshot::channel();
        self.mux_commands
            .send(MuxCommand::Flush(mux_flushed))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket carrier closed"))?;
        mux_delivery
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket carrier closed"))??;
        let (outbound_flushed, outbound_delivery) = oneshot::channel();
        self.outbound_flush
            .send(outbound_flushed)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket carrier closed"))?;
        outbound_delivery
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket carrier closed"))?
    }

    async fn stop_sending(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Yamux cannot stop only one receive direction",
        ))
    }

    async fn reset(&self) -> io::Result<()> {
        self.canceled.cancel();
        let mut reader_guard = self.reader.lock().await;
        let mut writer_guard = self.writer.lock().await;
        let reader = reader_guard.take();
        let writer = writer_guard.take();
        drop(writer_guard);
        drop(reader_guard);
        if let (Some(reader), Some(writer)) = (reader, writer) {
            drop(reader.reunite(writer));
        }
        Ok(())
    }

    async fn close(&self) -> io::Result<()> {
        CarrierStreamV2::reset(self).await
    }
}

#[async_trait]
impl CarrierStreamV3 for YamuxCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        CarrierStreamV2::read(self, payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        CarrierStreamV2::write(self, payload).await
    }

    async fn close_write(&self) -> io::Result<()> {
        CarrierStreamV2::close_write(self).await
    }

    async fn close_write_delivered(&self) -> io::Result<()> {
        CarrierStreamV2::close_write_delivered(self).await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        CarrierStreamV2::stop_sending(self).await
    }

    async fn reset(&self) -> io::Result<()> {
        CarrierStreamV2::reset(self).await
    }

    async fn close(&self) -> io::Result<()> {
        CarrierStreamV2::close(self).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        sync::atomic::Ordering,
        task::{Context, Poll},
    };

    use cert_test_builder::{CertificateParams, KeyPair};
    use futures_util::{SinkExt, io::AsyncRead, io::AsyncWrite};
    use tokio::io::{AsyncReadExt, duplex};
    use tokio::sync::{Mutex, mpsc};
    use tokio_tungstenite::{accept_async, client_async, tungstenite::Message};
    use tokio_util::sync::CancellationToken;

    use super::{
        CarrierSessionV2, OutgoingMessage, WebSocketCarrier, WebSocketIo, run_yamux,
        server_tls_config, spawn_binary_bridge, spawn_websocket_pump,
    };

    struct PendingIo;

    impl AsyncRead for PendingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[test]
    fn v3_server_tls_disables_early_data_and_session_tickets() {
        let key = KeyPair::generate().expect("generate test server key");
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .expect("create test certificate parameters")
            .self_signed(&key)
            .expect("sign test certificate");
        let config = server_tls_config(vec![certificate.der().to_vec()], key.serialize_der(), true)
            .expect("build v3 WebSocket TLS configuration")
            .expect("v3 WebSocket TLS configuration is present");

        assert_eq!(config.max_early_data_size, 0);
        assert_eq!(config.send_tls13_tickets, 0);
    }

    #[tokio::test]
    async fn graceful_websocket_close_drains_queued_binary_into_mux() {
        let (client_transport, server_transport) = duplex(64 * 1024);
        let accepting = tokio::spawn(async move {
            accept_async(server_transport)
                .await
                .expect("accept test WebSocket")
        });
        let (mut client, _) = client_async("ws://localhost/", client_transport)
            .await
            .expect("connect test WebSocket");
        let server = accepting.await.expect("join WebSocket accept");
        let io = spawn_websocket_pump(server);
        let incoming = io
            .incoming
            .lock()
            .await
            .take()
            .expect("take WebSocket incoming queue");

        let payload = b"queued before graceful close".to_vec();
        client
            .send(Message::Binary(payload.clone().into()))
            .await
            .expect("send queued binary message");
        client
            .send(Message::Close(None))
            .await
            .expect("send graceful close");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !incoming.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("WebSocket pump did not close its incoming queue");

        let (mut mux_side, bridge_side) = duplex(64 * 1024);
        let (_outbound_done, _outbound_flush) = spawn_binary_bridge(
            bridge_side,
            incoming,
            io.outgoing.clone(),
            io.cancellation.clone(),
        );
        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            mux_side.read_to_end(&mut received),
        )
        .await
        .expect("binary bridge did not finish draining")
        .expect("read drained binary payload");

        assert_eq!(received, payload);
        assert!(
            !io.cancellation.is_cancelled(),
            "graceful inbound EOF must be consumed by the mux before cancellation"
        );
        io.cancellation.cancel();
    }

    fn pending_test_carrier() -> (
        std::sync::Arc<WebSocketCarrier>,
        CancellationToken,
        mpsc::Receiver<OutgoingMessage>,
    ) {
        let (_incoming_tx, incoming_rx) = mpsc::channel(1);
        let (outgoing, outgoing_rx) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        let carrier = WebSocketCarrier::pending(
            WebSocketIo {
                incoming: Mutex::new(Some(incoming_rx)),
                outgoing,
                cancellation: cancellation.clone(),
            },
            true,
            3,
        );
        (carrier, cancellation, outgoing_rx)
    }

    #[tokio::test]
    async fn canceled_carrier_close_aborts_the_transport() {
        let (carrier, cancellation, mut outgoing) = pending_test_carrier();
        let mut closing = Box::pin(CarrierSessionV2::close(carrier.as_ref()));
        let message = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::select! {
                result = &mut closing => panic!("carrier close unexpectedly finished: {result:?}"),
                message = outgoing.recv() => message,
            }
        })
        .await
        .expect("carrier close did not request WebSocket shutdown")
        .expect("carrier close channel ended");
        assert!(matches!(message, OutgoingMessage::Close(_)));
        assert!(!cancellation.is_cancelled());

        drop(closing);
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn abort_cancels_after_close_ownership_was_claimed() {
        let (carrier, cancellation, _outgoing) = pending_test_carrier();
        carrier.state.closed.store(true, Ordering::Release);

        CarrierSessionV2::abort(carrier.as_ref());

        assert!(cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn canceled_yamux_driver_does_not_wait_for_graceful_io() {
        let connection =
            yamux::Connection::new(PendingIo, yamux::Config::default(), yamux::Mode::Client);
        let (_commands_tx, commands_rx) = mpsc::channel(1);
        let (incoming_tx, _incoming_rx) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            run_yamux(connection, commands_rx, incoming_tx, cancellation),
        )
        .await
        .expect("hard-canceled Yamux driver waited for graceful I/O");
    }
}
