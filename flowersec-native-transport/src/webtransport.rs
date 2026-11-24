//! One explicitly negotiated WebTransport session per dedicated HTTP/3 connection.
use crate::ApplicationClose;
use bytes::{Buf, Bytes};
use quinn::{Connection, Endpoint, ReadError, ReadExactError, RecvStream, SendStream, VarInt};
use quinn_proto::coding::Codec;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, io,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use url::Url;
pub enum ClientTrust {
    Ca(Vec<Vec<u8>>),
    Pin(Vec<[u8; 32]>),
}
impl fmt::Debug for ClientTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientTrust { <redacted> }")
    }
}
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum DialFailure {
    #[error("invalid WebTransport configuration")]
    InvalidArtifact,
    #[error("WebTransport TLS authentication failed")]
    Security,
    #[error("WebTransport connection failed")]
    Connection,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MessageError {
    #[error("unavailable")]
    Unavailable,
    #[error("too large")]
    TooLarge,
    #[error("send budget exhausted")]
    Dropped,
    #[error("closed")]
    Closed,
}

pub const DIRECT: &str = "/flowersec/webtransport/v5/direct";
pub const TUNNEL: &str = "/flowersec/webtransport/v5/tunnel";
const DRAFT: u64 = 0x2b603742;
const MAX_HEADERS: usize = 16 * 1024;
const MAX_SETTINGS: usize = 512;
const RESET: u64 = 0x52e4a40fa8db + 0xf502 + 0xf502 / 0x1e;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid WebTransport negotiation",
    )
}
fn io_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

pub fn valid_origin(origin: &str) -> bool {
    origin.len() <= 4096
        && Url::parse(origin).is_ok_and(|url| {
            matches!(url.scheme(), "https" | "http") && url.origin().ascii_serialization() == origin
        })
}

/// The exact HTTP authority host (without port) and permitted browser origins.
#[derive(Clone)]
pub struct WebTransportListenerPolicy {
    host: String,
    origins: Vec<String>,
}
impl fmt::Debug for WebTransportListenerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebTransportListenerPolicy { <redacted> }")
    }
}
impl WebTransportListenerPolicy {
    pub fn new(host: impl Into<String>, origins: Vec<String>) -> io::Result<Self> {
        let host = host.into();
        if host.len() > 253
            || !url::Host::parse(&host).is_ok_and(|parsed| parsed.to_string() == host)
            || origins.is_empty()
            || origins.len() > 64
            || origins.iter().any(|origin| !valid_origin(origin))
            || origins.iter().collect::<BTreeSet<_>>().len() != origins.len()
        {
            return Err(invalid());
        }
        Ok(Self { host, origins })
    }
}

fn transport(capacity: u32, listener: bool) -> io::Result<Arc<quinn::TransportConfig>> {
    if !(3..=130).contains(&capacity) {
        return Err(invalid());
    }
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams((capacity + u32::from(listener)).into())
        .max_concurrent_uni_streams(3u32.into())
        .receive_window((1u32 << 20).into())
        .stream_receive_window((512u32 << 10).into())
        .send_window(1 << 20)
        .datagram_receive_buffer_size(Some(256 << 10))
        .datagram_send_buffer_size(256 << 10)
        .max_idle_timeout(Some(Duration::from_secs(60).try_into().map_err(io_error)?))
        .keep_alive_interval(Some(Duration::from_secs(20)));
    Ok(Arc::new(transport))
}

pub struct Listener {
    endpoint: Endpoint,
    pending: crate::HandshakeQueue<io::Result<(Arc<Carrier>, SocketAddr)>>,
    config: Arc<HandshakeConfig>,
}

struct HandshakeConfig {
    policy: WebTransportListenerPolicy,
    authority: String,
    path: &'static str,
    capacity: u32,
    timeout: Duration,
}
impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebTransportListener { <redacted> }")
    }
}
impl Listener {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket: UdpSocket,
        bind: SocketAddr,
        chain: Vec<Vec<u8>>,
        key: Vec<u8>,
        policy: WebTransportListenerPolicy,
        path: &'static str,
        capacity: u32,
        timeout: Duration,
    ) -> io::Result<Self> {
        let actual = socket.local_addr()?;
        if actual != bind || timeout.is_zero() || !matches!(path, DIRECT | TUNNEL) {
            return Err(invalid());
        }
        let authority = if actual.port() == 443 {
            policy.host.clone()
        } else {
            format!("{}:{}", policy.host, actual.port())
        };
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io_error)?
        .with_no_client_auth()
        .with_single_cert(
            chain.into_iter().map(CertificateDer::from).collect(),
            PrivateKeyDer::try_from(key).map_err(|_| invalid())?,
        )
        .map_err(io_error)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.max_early_data_size = 0;
        tls.send_tls13_tickets = 0;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(io_error)?,
        ));
        config.transport_config(transport(capacity, true)?);
        config
            .max_incoming(128)
            .incoming_buffer_size(64 << 10)
            .incoming_buffer_size_total(1 << 20);
        let runtime = quinn::default_runtime().ok_or_else(invalid)?;
        let endpoint = Endpoint::new(
            Default::default(),
            Some(config),
            socket,
            Arc::new(crate::raw_quic::ListenerRuntime(runtime)),
        )?;
        Ok(Self {
            endpoint,
            pending: crate::HandshakeQueue::new(),
            config: Arc::new(HandshakeConfig {
                policy,
                authority,
                path,
                capacity,
                timeout,
            }),
        })
    }
    pub fn local_address(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
    pub fn ingress_url(&self) -> String {
        format!("https://{}{}", self.config.authority, self.config.path)
    }
    pub fn abort(&self) {
        self.endpoint.close(0u32.into(), b"");
    }
    pub async fn close(&self) {
        self.abort();
        self.pending.shutdown().await;
        self.endpoint.wait_idle().await;
    }
    pub async fn accept(&self) -> io::Result<(Arc<Carrier>, SocketAddr)> {
        loop {
            let result = self
                .pending
                .accept(&self.endpoint, |incoming| {
                    self.config
                        .clone()
                        .handshake(incoming, self.endpoint.clone())
                })
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
            if let Ok(accepted) = result {
                return Ok(accepted);
            }
        }
    }
}

impl HandshakeConfig {
    async fn handshake(
        self: Arc<Self>,
        incoming: quinn::Incoming,
        endpoint: Endpoint,
    ) -> io::Result<(Arc<Carrier>, SocketAddr)> {
        tokio::time::timeout(self.timeout, async {
            let accepted_driver = TaskTracker::new();
            let connecting = crate::raw_quic::ACCEPTED_DRIVER
                .sync_scope(accepted_driver.clone(), || incoming.accept())
                .map_err(io_error)?;
            accepted_driver.close();
            let conn = connecting.await.map_err(io_error)?;
            let remote = conn.remote_address();
            let mut guard = Pending::new(conn.clone());
            let controls = controls(&conn, false).await?;
            let (mut send, mut recv) = conn.accept_bi().await.map_err(io_error)?;
            if u64::from(VarInt::from(send.id())) != 0 {
                return Err(invalid());
            }
            let headers = read_headers(&mut recv).await?;
            let valid =
                |key: &str, value: &str| headers.get(key).is_some_and(|actual| actual == value);
            if !valid(":method", "CONNECT")
                || !valid(":scheme", "https")
                || !valid(":protocol", "webtransport")
                || !valid(":path", self.path)
                || !valid(":authority", &self.authority)
                || !valid("sec-webtransport-http3-draft02", "1")
                || !headers
                    .get("origin")
                    .is_some_and(|origin| self.policy.origins.contains(origin))
                || headers.keys().any(|key| {
                    key.starts_with(':')
                        && !matches!(
                            key.as_str(),
                            ":method" | ":scheme" | ":protocol" | ":path" | ":authority"
                        )
                })
            {
                return Err(invalid());
            }
            write_headers(
                &mut send,
                &[
                    (":status", "200"),
                    ("sec-webtransport-http3-draft", "draft02"),
                ],
            )
            .await?;
            let session = Carrier::new(
                conn,
                endpoint,
                Some(accepted_driver),
                self.capacity,
                controls,
                send,
                recv,
            );
            guard.disarm();
            Ok::<_, io::Error>((session, remote))
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}

struct Pending(Option<Connection>);
impl Pending {
    fn new(conn: Connection) -> Self {
        Self(Some(conn))
    }
    fn disarm(&mut self) {
        self.0.take();
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            conn.close(0x101u32.into(), b"");
        }
    }
}

pub async fn dial(
    raw: &str,
    origin: &str,
    trust: ClientTrust,
    capacity: u32,
) -> Result<Arc<Carrier>, DialFailure> {
    use DialFailure as Failure;
    let url = Url::parse(raw).map_err(|_| Failure::InvalidArtifact)?;
    if url.scheme() != "https"
        || !matches!(url.path(), DIRECT | TUNNEL)
        || !valid_origin(origin)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || raw != url.as_str()
    {
        return Err(Failure::InvalidArtifact);
    }
    let host = url
        .host_str()
        .ok_or(Failure::InvalidArtifact)?
        .trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .ok_or(Failure::InvalidArtifact)?;
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let tls = match trust {
        ClientTrust::Ca(roots) => crate::RawQuicClientConfig::ca_tls(roots, b"h3"),
        ClientTrust::Pin(pins) => {
            crate::RawQuicClientConfig::pin_tls(pins, b"h3").map(|(tls, _)| tls)
        }
    }
    .map_err(|_| Failure::InvalidArtifact)?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| Failure::Security)?,
    ));
    config.transport_config(transport(capacity, false).map_err(|_| Failure::InvalidArtifact)?);
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| Failure::Connection)?;
    for peer in addresses.take(16) {
        let local = if peer.is_ipv4() {
            SocketAddr::from(([0; 4], 0))
        } else {
            SocketAddr::from(([0; 16], 0))
        };
        let endpoint = Endpoint::client(local).map_err(|_| Failure::Connection)?;
        let conn = match endpoint
            .connect_with(config.clone(), peer, host)
            .map_err(|_| Failure::InvalidArtifact)?
            .await
        {
            Ok(conn) => conn,
            Err(quinn::ConnectionError::TransportError(error))
                if (0x100..0x200).contains(&u64::from(error.code)) =>
            {
                return Err(Failure::Security);
            }
            Err(quinn::ConnectionError::ConnectionClosed(close))
                if (0x100..0x200).contains(&u64::from(close.error_code)) =>
            {
                return Err(Failure::Security);
            }
            Err(_) => continue,
        };
        let mut guard = Pending::new(conn.clone());
        let controls = controls(&conn, true)
            .await
            .map_err(|_| Failure::Connection)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|_| Failure::Connection)?;
        let request = [
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", authority),
            (":path", url.path()),
            (":protocol", "webtransport"),
            ("origin", origin),
            ("sec-webtransport-http3-draft02", "1"),
        ];
        write_headers(&mut send, &request)
            .await
            .map_err(|_| Failure::Connection)?;
        let headers = read_headers(&mut recv)
            .await
            .map_err(|_| Failure::Connection)?;
        if headers.get(":status").map(String::as_str) != Some("200")
            || headers
                .keys()
                .any(|name| name.starts_with(':') && name != ":status")
            || headers
                .get("sec-webtransport-http3-draft")
                .is_some_and(|value| value != "draft02")
        {
            return Err(Failure::Connection);
        }
        let session = Carrier::new(conn, endpoint, None, capacity, controls, send, recv);
        guard.disarm();
        return Ok(session);
    }
    Err(Failure::Connection)
}

fn put(bytes: &mut Vec<u8>, value: u64) {
    let value = VarInt::from_u64(value).expect("bounded HTTP/3 value");
    value.encode(bytes);
}
async fn read_int(stream: &mut RecvStream) -> io::Result<u64> {
    read_varint(stream).await.map_err(io_error)
}
async fn read_varint(stream: &mut RecvStream) -> Result<u64, ReadExactError> {
    let mut bytes = [0; 8];
    stream.read_exact(&mut bytes[..1]).await?;
    let length = 1usize << (bytes[0] >> 6);
    stream.read_exact(&mut bytes[1..length]).await?;
    Ok(VarInt::decode(&mut &bytes[..length])
        .expect("complete QUIC varint")
        .into_inner())
}
async fn write_headers(send: &mut SendStream, headers: &[(&str, &str)]) -> io::Result<()> {
    let fields: Vec<_> = headers
        .iter()
        .map(|(name, value)| qpack::HeaderField::new(name.as_bytes(), value.as_bytes()))
        .collect();
    let mut block = Vec::new();
    qpack::encode_stateless(&mut block, &fields).map_err(|_| invalid())?;
    if block.len() > MAX_HEADERS {
        return Err(invalid());
    }
    let mut frame = Vec::new();
    put(&mut frame, 1);
    put(&mut frame, block.len() as u64);
    frame.extend(block);
    send.write_all(&frame).await.map_err(io_error)
}
async fn read_headers(recv: &mut RecvStream) -> io::Result<BTreeMap<String, String>> {
    if read_int(recv).await? != 1 {
        return Err(invalid());
    }
    let size = read_int(recv).await?;
    if size == 0 || size > MAX_HEADERS as u64 {
        return Err(invalid());
    }
    let mut block = vec![0; size as usize];
    recv.read_exact(&mut block).await.map_err(io_error)?;
    let mut bytes = &block[..];
    let decoded = qpack::decode_stateless(&mut bytes, MAX_HEADERS as u64).map_err(|_| invalid())?;
    if decoded.dyn_ref || !bytes.is_empty() || decoded.fields.len() > 64 {
        return Err(invalid());
    }
    let mut result = BTreeMap::new();
    let mut regular = false;
    for field in decoded.fields {
        let name = String::from_utf8(field.name.to_vec()).map_err(|_| invalid())?;
        let value = String::from_utf8(field.value.to_vec()).map_err(|_| invalid())?;
        if name.is_empty()
            || name.bytes().any(|ch| ch.is_ascii_uppercase())
            || name.starts_with(':') && regular
            || http::HeaderName::from_bytes(name.strip_prefix(':').unwrap_or(&name).as_bytes())
                .is_err()
            || http::HeaderValue::from_str(&value).is_err()
            || matches!(
                name.as_str(),
                "connection"
                    | "upgrade"
                    | "transfer-encoding"
                    | "capsule-protocol"
                    | "wt-protocol"
                    | "wt-available-protocols"
            )
        {
            return Err(invalid());
        }
        regular |= !name.starts_with(':');
        if result.insert(name, value).is_some() {
            return Err(invalid());
        }
    }
    Ok(result)
}

struct Controls {
    outgoing: SendStream,
    incoming: RecvStream,
    qpack: Vec<(u64, RecvStream)>,
}
async fn controls(conn: &Connection, client: bool) -> io::Result<Controls> {
    let mut outgoing = conn.open_uni().await.map_err(io_error)?;
    let mut settings = Vec::new();
    for (key, value) in [(0x33, 1), (DRAFT, 1)] {
        put(&mut settings, key);
        put(&mut settings, value);
    }
    if !client {
        put(&mut settings, 8);
        put(&mut settings, 1);
    }
    let mut frame = vec![0, 4];
    put(&mut frame, settings.len() as u64);
    frame.extend(settings);
    outgoing.write_all(&frame).await.map_err(io_error)?;
    let mut qpack = Vec::new();
    let mut incoming = loop {
        let mut stream = conn.accept_uni().await.map_err(io_error)?;
        match read_int(&mut stream).await? {
            0 => break stream,
            kind @ (2 | 3) if !qpack.iter().any(|(seen, _)| *seen == kind) => {
                qpack.push((kind, stream))
            }
            _ => return Err(invalid()),
        }
    };
    if read_int(&mut incoming).await? != 4 {
        return Err(invalid());
    }
    let size = read_int(&mut incoming).await?;
    if size > MAX_SETTINGS as u64 {
        return Err(invalid());
    }
    let mut payload = vec![0; size as usize];
    incoming.read_exact(&mut payload).await.map_err(io_error)?;
    let mut rest = &payload[..];
    let mut values = BTreeMap::new();
    while !rest.is_empty() {
        let key = VarInt::decode(&mut rest)
            .map_err(|_| invalid())?
            .into_inner();
        let value = VarInt::decode(&mut rest)
            .map_err(|_| invalid())?
            .into_inner();
        if matches!(key, 2..=5)
            || values.len() >= 64
            || matches!(key, 0x33 | 8 | DRAFT) && value > 1
            || values.insert(key, value).is_some()
        {
            return Err(invalid());
        }
    }
    if values.get(&0x33) != Some(&1)
        || values.get(&DRAFT) != Some(&1)
        || client && values.get(&8) != Some(&1)
        || conn.max_datagram_size().is_none()
    {
        return Err(invalid());
    }
    Ok(Controls {
        outgoing,
        incoming,
        qpack,
    })
}

async fn bounded_frame_size(recv: &mut RecvStream, remaining: &mut usize) -> io::Result<usize> {
    let size = usize::try_from(read_int(recv).await?).map_err(|_| invalid())?;
    *remaining = remaining
        .checked_sub(16)
        .and_then(|n| n.checked_sub(size))
        .ok_or_else(invalid)?;
    Ok(size)
}

async fn read_capsules(recv: &mut RecvStream) -> io::Result<ApplicationClose> {
    let mut pending = Vec::new();
    let mut remaining = MAX_HEADERS;
    loop {
        if read_int(recv).await? != 0 {
            return Err(invalid());
        }
        let size = bounded_frame_size(recv, &mut remaining).await?;
        let start = pending.len();
        pending.resize(start + size, 0);
        recv.read_exact(&mut pending[start..])
            .await
            .map_err(io_error)?;
        let mut bytes = pending.as_slice();
        while !bytes.is_empty() {
            let mut next = bytes;
            let Ok(kind) = VarInt::decode(&mut next) else {
                break;
            };
            let Ok(length) = VarInt::decode(&mut next) else {
                break;
            };
            let length = usize::try_from(length.into_inner()).map_err(|_| invalid())?;
            if length > 1028 {
                return Err(invalid());
            }
            if next.len() < length {
                break;
            }
            match (kind.into_inner(), length) {
                (0x2843, 4..) => {
                    return Ok(ApplicationClose {
                        code: u64::from(u32::from_be_bytes(next[..4].try_into().unwrap())),
                        reason: std::str::from_utf8(&next[4..length])
                            .map_err(|_| invalid())?
                            .to_owned(),
                    });
                }
                (0x78ae, 0) => {}
                (reserved, _) if reserved % 0x29 == 0x17 => {} // RFC 9297 reserved capsule type
                _ => return Err(invalid()),
            }
            bytes = &next[length..];
        }
        pending.drain(..pending.len() - bytes.len());
    }
}

async fn monitor_control(recv: &mut RecvStream) -> io::Result<()> {
    let mut remaining = MAX_HEADERS;
    let mut scratch = [0; 512];
    loop {
        let kind = read_int(recv).await?;
        // RFC 9114 reserved frames can follow SETTINGS on the critical control stream.
        if kind < 0x21 || !(kind - 0x21).is_multiple_of(0x1f) {
            return Err(invalid());
        }
        let mut size = bounded_frame_size(recv, &mut remaining).await?;
        while size > 0 {
            let count = size.min(scratch.len());
            recv.read_exact(&mut scratch[..count])
                .await
                .map_err(io_error)?;
            size -= count;
        }
    }
}

pub struct Carrier {
    connect_send: Mutex<CloseSend>,
    conn: Connection,
    endpoint: Endpoint,
    accepted_driver: Option<TaskTracker>,
    capacity: u32,
    tasks: TaskTracker,
    peer_close: Arc<OnceLock<ApplicationClose>>,
    datagram_send: std::sync::Mutex<()>,
}
struct CloseSend {
    stream: SendStream,
    result: Option<Result<(), io::ErrorKind>>,
}
impl fmt::Debug for Carrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebTransport { <opaque> }")
    }
}
impl Carrier {
    fn new(
        conn: Connection,
        endpoint: Endpoint,
        accepted_driver: Option<TaskTracker>,
        capacity: u32,
        controls: Controls,
        send: SendStream,
        mut recv: RecvStream,
    ) -> Arc<Self> {
        let tasks = TaskTracker::new();
        let monitor = conn.clone();
        let peer_close = Arc::new(OnceLock::new());
        let reported = peer_close.clone();
        tasks.spawn(async move {
            let Controls {outgoing, mut incoming, mut qpack, ..} = controls;
            let _held = outgoing;
            let monitor_uni = async {
                loop {let mut next = monitor.accept_uni().await.map_err(io_error)?; match read_int(&mut next).await? {
                    kind @ (2|3) if !qpack.iter().any(|(seen,_)| *seen == kind) => qpack.push((kind,next)),
                    0x54 if read_int(&mut next).await? == 0 => {let _ = next.stop(VarInt::from_u64(RESET).unwrap());},
                    _ => return Err::<(),_>(invalid()),
                }}
            };
            tokio::select! {
                biased;
                result = read_capsules(&mut recv) => { if let Ok(close) = result { let _ = reported.set(close); } },
                _ = monitor.closed() => {}, _ = monitor_control(&mut incoming) => {}, _ = monitor_uni => {}
            }
            monitor.close(0x100u32.into(),b"");
        });
        tasks.close();
        Arc::new(Self {
            connect_send: Mutex::new(CloseSend {
                stream: send,
                result: None,
            }),
            conn,
            endpoint,
            accepted_driver,
            capacity,
            tasks,
            peer_close,
            datagram_send: std::sync::Mutex::new(()),
        })
    }
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.abort();
    }
}
impl Carrier {
    pub fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.capacity
    }
    #[cfg(feature = "__flowersec_internal_test_support")]
    #[doc(hidden)]
    pub async fn reset_during_stream_header_for_test(&self) -> io::Result<()> {
        let (mut send, _recv) = self.conn.open_bi().await.map_err(io_error)?;
        send.write_all(&[0x40, 0x41]).await.map_err(io_error)?;
        send.reset(VarInt::from_u64(RESET).unwrap())
            .map_err(io_error)
    }
    pub async fn open_stream(&self) -> io::Result<Arc<Stream>> {
        let (mut send, recv) = self.conn.open_bi().await.map_err(io_error)?;
        let prefix = &[0x40, 0x41, 0];
        send.write_all(prefix).await.map_err(io_error)?;
        Ok(Stream::new(send, recv))
    }
    pub async fn accept_stream(&self) -> io::Result<Arc<Stream>> {
        loop {
            let (mut send, mut recv) = self.conn.accept_bi().await.map_err(io_error)?;
            let prefix = async {
                Ok(read_varint(&mut recv).await? == 0x41 && read_varint(&mut recv).await? == 0)
            }
            .await;
            match prefix {
                Ok(true) => return Ok(Stream::new(send, recv)),
                Ok(false) => {
                    self.abort();
                    return Err(invalid());
                }
                Err(ReadExactError::ReadError(ReadError::Reset(_))) => {
                    let _ = send.reset(VarInt::from_u64(RESET).unwrap());
                }
                Err(error) => return Err(io_error(error)),
            }
        }
    }
    pub fn unreliable_message_max_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()?.checked_sub(1)
    }
    pub async fn send_unreliable_message(&self, payload: Bytes) -> Result<(), MessageError> {
        if payload.len()
            > self
                .unreliable_message_max_size()
                .ok_or(MessageError::Unavailable)?
        {
            return Err(MessageError::TooLarge);
        }
        let _permit = self.datagram_send.lock().unwrap_or_else(|p| p.into_inner());
        if self.conn.datagram_send_buffer_space() < payload.len() + 1 {
            return Err(MessageError::Dropped);
        }
        let mut bytes = Vec::with_capacity(payload.len() + 1);
        bytes.push(0);
        bytes.extend_from_slice(&payload);
        self.conn
            .send_datagram(bytes.into())
            .map_err(|error| match error {
                quinn::SendDatagramError::TooLarge => MessageError::TooLarge,
                quinn::SendDatagramError::ConnectionLost(_) => MessageError::Closed,
                _ => MessageError::Unavailable,
            })
    }
    pub async fn receive_unreliable_message(&self) -> Result<Bytes, MessageError> {
        loop {
            let mut bytes = self
                .conn
                .read_datagram()
                .await
                .map_err(|_| MessageError::Closed)?;
            if VarInt::decode(&mut bytes).is_ok_and(|id| id.into_inner() == 0)
                && bytes.has_remaining()
            {
                return Ok(bytes);
            }
            tokio::task::yield_now().await;
        }
    }
    pub async fn close(&self) -> io::Result<()> {
        self.abort();
        self.wait_shutdown().await;
        Ok(())
    }
    pub async fn close_with_reason(&self, code: u32, reason: &str) -> io::Result<()> {
        if reason.len() > 1024 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let result = {
            let mut sender = self.connect_send.lock().await;
            if let Some(previous) = sender.result {
                return previous.map_err(io::Error::from);
            }
            sender.result = Some(Err(io::ErrorKind::Interrupted));
            let connect = &mut sender.stream;
            let mut capsule = Vec::new();
            put(&mut capsule, 0x2843);
            put(&mut capsule, (4 + reason.len()) as u64);
            capsule.extend_from_slice(&code.to_be_bytes());
            capsule.extend_from_slice(reason.as_bytes());
            let mut frame = vec![0];
            put(&mut frame, capsule.len() as u64);
            frame.extend_from_slice(&capsule);
            let result = tokio::time::timeout(Duration::from_millis(500), async {
                connect.write_all(&frame).await.map_err(io_error)?;
                connect.finish().map_err(io_error)?;
                match connect.stopped().await.map_err(io_error)? {
                    None => Ok(()),
                    Some(_) => Err(io::ErrorKind::ConnectionReset.into()),
                }
            })
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
            sender.result = Some(result.as_ref().map(|_| ()).map_err(io::Error::kind));
            result
        };
        self.abort();
        self.wait_shutdown().await;
        result
    }
    pub fn abort(&self) {
        self.conn.close(0x100u32.into(), b"");
    }
    pub async fn wait_termination(&self) {
        self.tasks.wait().await;
    }
    pub fn peer_application_close(&self) -> Option<ApplicationClose> {
        self.peer_close.get().cloned()
    }
    pub async fn wait_shutdown(&self) {
        self.wait_termination().await;
        if let Some(driver) = &self.accepted_driver {
            driver.wait().await;
        } else {
            self.endpoint.wait_idle().await;
        }
    }
}

pub struct Stream {
    send: Mutex<SendStream>,
    recv: Mutex<RecvStream>,
    stop: CancellationToken,
    reset: CancellationToken,
}
impl Stream {
    fn new(send: SendStream, recv: RecvStream) -> Arc<Self> {
        Arc::new(Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            stop: CancellationToken::new(),
            reset: CancellationToken::new(),
        })
    }
}
impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebTransportStream { <opaque> }")
    }
}
impl Stream {
    pub async fn read_chunk(&self, maximum: usize) -> io::Result<Option<Bytes>> {
        let mut recv = self.recv.lock().await;
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => Err(io::ErrorKind::ConnectionReset.into()),
            result = recv.read_chunk(maximum, true) => result.map(|chunk| chunk.map(|chunk| chunk.bytes)).map_err(io_error),
        }
    }

    pub async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        let mut recv = self.recv.lock().await;
        tokio::select! {biased; _=self.stop.cancelled()=>Err(io::ErrorKind::ConnectionReset.into()), result=recv.read(payload)=>result.map(|n|n.unwrap_or(0)).map_err(io_error)}
    }
    pub async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        let mut send = self.send.lock().await;
        tokio::select! {biased;_=self.reset.cancelled()=>Err(io::ErrorKind::ConnectionReset.into()),result=send.write(payload)=>result.map_err(io_error)}
    }
    pub async fn close_write(&self) -> io::Result<()> {
        self.send.lock().await.finish().map_err(io_error)
    }
    pub async fn close_write_delivered(&self) -> io::Result<()> {
        let stopped = {
            let mut send = self.send.lock().await;
            send.finish().map_err(io_error)?;
            send.stopped()
        };
        match stopped.await.map_err(io_error)? {
            None => Ok(()),
            Some(_) => Err(io::ErrorKind::ConnectionReset.into()),
        }
    }
    pub async fn stop_sending(&self) -> io::Result<()> {
        self.stop.cancel();
        let _ = self
            .recv
            .lock()
            .await
            .stop(VarInt::from_u64(RESET).unwrap());
        Ok(())
    }
    pub async fn reset(&self) -> io::Result<()> {
        self.reset.cancel();
        self.stop.cancel();
        let _ = self
            .send
            .lock()
            .await
            .reset(VarInt::from_u64(RESET).unwrap());
        self.stop_sending().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn draft02_pair() -> (Arc<Listener>, Arc<Carrier>, Arc<Carrier>) {
        let identity =
            cert_test_builder::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let root = identity.cert.der().to_vec();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let origin = "https://app.example";
        let listener = Arc::new(
            Listener::new(
                socket,
                address,
                vec![root.clone()],
                identity.signing_key.serialize_der(),
                WebTransportListenerPolicy::new("127.0.0.1", vec![origin.into()]).unwrap(),
                DIRECT,
                3,
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        let server = tokio::spawn({
            let listener = listener.clone();
            async move { listener.accept().await.unwrap().0 }
        });
        let url = listener.ingress_url();
        let client = dial(&url, origin, ClientTrust::Ca(vec![root]), 3)
            .await
            .unwrap();
        (listener, client, server.await.unwrap())
    }

    #[tokio::test]
    async fn draft02_stream_cancellation_isolated_in_both_directions() {
        let run = async {
            let (listener, client, server) = draft02_pair().await;
            for (sender, receiver) in [(&client, &server), (&server, &client)] {
                let active = sender.open_stream().await.unwrap();
                let reading = receiver.accept_stream().await.unwrap();
                assert_eq!(active.write(b"a").await.unwrap(), 1);
                sender.open_stream().await.unwrap().reset().await.unwrap();
                assert_eq!(active.write(b"b").await.unwrap(), 1);
                active.close_write().await.unwrap();
                let mut byte = [0];
                for expected in b"ab" {
                    assert_eq!(reading.read(&mut byte).await.unwrap(), 1);
                    assert_eq!(byte[0], *expected);
                }
                assert_eq!(reading.read(&mut byte).await.unwrap(), 0);
                let next = sender.open_stream().await.unwrap();
                assert_eq!(next.write(b"x").await.unwrap(), 1);
                next.close_write().await.unwrap();
                let received = receiver.accept_stream().await.unwrap();
                let mut byte = [0];
                assert_eq!(received.read(&mut byte).await.unwrap(), 1);
                assert_eq!(byte, *b"x");
                assert_eq!(received.read(&mut byte).await.unwrap(), 0);
            }
            let (left, right) = tokio::join!(client.close(), server.close());
            left.unwrap();
            right.unwrap();
            listener.close().await;
        };
        tokio::time::timeout(Duration::from_secs(8), run)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn draft02_fragmented_grease_preserves_close_capsules() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let (listener, client, server) = draft02_pair().await;
            let mut grease = Vec::new();
            put(&mut grease, 0x17 + 0x29 * 100);
            grease.extend_from_slice(&[2, 0xab, 0xcd]);
            let mut frames = vec![0, 1, grease[0], 0, (grease.len() - 1) as u8];
            frames.extend_from_slice(&grease[1..]);
            client
                .connect_send
                .lock()
                .await
                .stream
                .write_all(&frames)
                .await
                .unwrap();
            let _ = client.close_with_reason(17, "done").await;
            server.wait_termination().await;
            let close = server.peer_application_close().unwrap();
            assert_eq!((close.code, close.reason.as_str()), (17, "done"));
            listener.close().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn draft02_rejects_unexpected_frames_and_oversized_grease() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let (listener, client, server) = draft02_pair().await;
            for (control, fields, trailing) in [
                (true, vec![0x40, 1, 42, 4, 0], 0),
                (true, vec![0x21, MAX_HEADERS as u64, 55], 55),
                (false, vec![4, 0], 0),
                (false, vec![0, 3, 0x17, 1029, 55], 55),
            ] {
                let mut payload = Vec::new();
                for field in fields {
                    put(&mut payload, field);
                }
                let (mut send, _recv) = client.conn.open_bi().await.unwrap();
                send.write_all(&payload).await.unwrap();
                send.finish().unwrap();
                let (_send, mut recv) = server.conn.accept_bi().await.unwrap();
                let error = if control {
                    monitor_control(&mut recv).await.unwrap_err()
                } else {
                    read_capsules(&mut recv).await.unwrap_err()
                };
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(read_int(&mut recv).await.unwrap(), trailing);
            }
            client.abort();
            listener.close().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn explicit_close_preserves_capsule_write_failure_after_local_abort() {
        let identity =
            cert_test_builder::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let root = identity.cert.der().to_vec();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let origin = "https://app.example";
        let policy = WebTransportListenerPolicy::new("127.0.0.1", vec![origin.into()]).unwrap();
        let listener = Listener::new(
            socket,
            address,
            vec![root.clone()],
            identity.signing_key.serialize_der(),
            policy,
            TUNNEL,
            3,
            Duration::from_secs(2),
        )
        .unwrap();
        let url = listener.ingress_url();
        let (client, server) = tokio::join!(
            dial(&url, origin, ClientTrust::Ca(vec![root]), 3,),
            listener.accept()
        );
        let client = client.unwrap();
        let (server, _) = server.unwrap();
        client.abort();
        client.wait_termination().await;
        let (left, right) = tokio::join!(
            client.close_with_reason(1, "session closed"),
            client.close_with_reason(1, "session closed")
        );
        let first = left.unwrap_err().kind();
        assert_eq!(right.unwrap_err().kind(), first);
        assert_eq!(
            client
                .close_with_reason(1, "session closed")
                .await
                .unwrap_err()
                .kind(),
            first
        );
        server.wait_termination().await;
        assert!(server.peer_application_close().is_none());
        listener.close().await;
    }

    #[tokio::test]
    async fn incompatible_connect_authority_path_and_native_h3_never_reach_acceptance() {
        let identity =
            cert_test_builder::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let root = identity.cert.der().to_vec();
        let key = identity.signing_key.serialize_der();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let listener = Arc::new(
            Listener::new(
                socket,
                address,
                vec![root.clone()],
                key,
                WebTransportListenerPolicy::new("localhost", vec!["https://app.example".into()])
                    .unwrap(),
                DIRECT,
                3,
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        let task = tokio::spawn({
            let listener = listener.clone();
            async move { listener.accept().await }
        });
        let expected = format!("localhost:{}", address.port());
        for (path, authority, protocol, draft) in [
            (TUNNEL, expected.as_str(), "webtransport", true),
            (DIRECT, "another.example", "webtransport", true),
            (DIRECT, expected.as_str(), "webtransport-h3", false),
        ] {
            let mut config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(
                    crate::RawQuicClientConfig::ca_tls(vec![root.clone()], b"h3").unwrap(),
                )
                .unwrap(),
            ));
            config.transport_config(transport(3, false).unwrap());
            let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let conn = endpoint
                .connect_with(config, address, "localhost")
                .unwrap()
                .await
                .unwrap();
            let _controls = controls(&conn, true).await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            let mut headers = vec![
                (":method", "CONNECT"),
                (":scheme", "https"),
                (":authority", authority),
                (":path", path),
                (":protocol", protocol),
                ("origin", "https://app.example"),
            ];
            if draft {
                headers.push(("sec-webtransport-http3-draft02", "1"));
            }
            write_headers(&mut send, &headers).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(3), read_headers(&mut recv))
                    .await
                    .unwrap()
                    .is_err()
            );
            assert!(!task.is_finished());
        }
        listener.close().await;
        assert!(task.await.unwrap().is_err());
    }
}
