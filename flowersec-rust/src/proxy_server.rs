use std::{
    collections::HashSet,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{Notify, Semaphore},
    time::Instant,
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{WebSocketStream, client_async_with_config, tungstenite};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    HandlerRegistrationError, IncomingStream, SessionError, StreamHandler, StreamHandlerRegistrar,
    session_handlers::register_stream_handlers, transport::ByteStream, websocket_transport,
};

const HTTP_KIND: &str = "flowersec-proxy/http1";
const WEBSOCKET_KIND: &str = "flowersec-proxy/ws";
const WIRE_VERSION: u8 = 1;
pub(crate) const DEFAULT_MAX_JSON: usize = 1 << 20;
pub(crate) const DEFAULT_MAX_CHUNK: usize = 256 * 1024;
pub(crate) const DEFAULT_MAX_BODY: usize = 64 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_WEBSOCKET_FRAME: usize = 1 << 20;
pub(crate) const DEFAULT_MAX_CONCURRENT: usize = 64;
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(300);
const WEBSOCKET_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);

const FORBIDDEN_HEADERS: &[&str] = &[
    "authorization",
    "connection",
    "host",
    "keep-alive",
    "proxy-authorization",
    "set-cookie",
    "transfer-encoding",
    "upgrade",
];
const REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "if-match",
    "if-none-match",
    "range",
];
const RESPONSE_HEADERS: &[&str] = &[
    "accept-ranges",
    "cache-control",
    "content-disposition",
    "content-language",
    "content-range",
    "content-type",
    "etag",
    "expires",
    "last-modified",
    "location",
];

pub type ProxyErrorReporter = Arc<dyn Fn(ProxyServerError) + Send + Sync + 'static>;

/// Bounded server-side browser proxy configuration.
pub struct ProxyServerOptions {
    pub upstream: Url,
    pub upstream_origin: Url,
    /// Explicit DER trust roots for HTTPS and WSS upstreams.
    pub upstream_trust_roots_der: Vec<Vec<u8>>,
    pub allowed_upstream_hosts: Vec<String>,
    pub allowed_origins: Vec<Url>,
    pub max_concurrent_streams: usize,
    pub max_json_frame_bytes: usize,
    pub max_chunk_bytes: usize,
    pub max_body_bytes: usize,
    pub max_websocket_frame_bytes: usize,
    pub default_http_request_timeout: Duration,
    pub max_http_request_timeout: Duration,
    pub extra_request_headers: Vec<String>,
    pub extra_response_headers: Vec<String>,
    pub blocked_response_headers: Vec<String>,
    pub extra_websocket_headers: Vec<String>,
    pub forbidden_cookie_names: Vec<String>,
    pub forbidden_cookie_name_prefixes: Vec<String>,
    pub on_error: Option<ProxyErrorReporter>,
}

impl fmt::Debug for ProxyServerOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyServerOptions { <opaque> }")
    }
}

impl ProxyServerOptions {
    /// Creates a proxy configuration with bounded SDK defaults.
    pub fn new(upstream: Url, upstream_origin: Url) -> Self {
        Self {
            upstream,
            upstream_origin,
            upstream_trust_roots_der: Vec::new(),
            allowed_upstream_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            max_concurrent_streams: 0,
            max_json_frame_bytes: 0,
            max_chunk_bytes: 0,
            max_body_bytes: 0,
            max_websocket_frame_bytes: 0,
            default_http_request_timeout: Duration::ZERO,
            max_http_request_timeout: Duration::ZERO,
            extra_request_headers: Vec::new(),
            extra_response_headers: Vec::new(),
            blocked_response_headers: Vec::new(),
            extra_websocket_headers: Vec::new(),
            forbidden_cookie_names: Vec::new(),
            forbidden_cookie_name_prefixes: Vec::new(),
            on_error: None,
        }
    }
}

/// Stable server-side proxy failure without upstream or peer details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProxyServerError {
    #[error("invalid Flowersec proxy server options")]
    InvalidOptions,
    #[error("Flowersec proxy handlers are already registered")]
    AlreadyRegistered,
    #[error("Flowersec proxy server is closed")]
    Closed,
    #[error("Flowersec proxy operation failed")]
    OperationFailed,
}

#[derive(Debug)]
struct Config {
    upstream: Url,
    upstream_origin: String,
    upstream_trust_roots_der: Vec<Vec<u8>>,
    allowed_origins: HashSet<String>,
    max_json: usize,
    max_chunk: usize,
    max_body: usize,
    max_websocket_frame: usize,
    websocket_establish_timeout: Duration,
    default_timeout: Duration,
    max_timeout: Duration,
    request_headers: HashSet<String>,
    response_headers: HashSet<String>,
    blocked_response_headers: HashSet<String>,
    websocket_headers: HashSet<String>,
    forbidden_cookies: HashSet<String>,
    forbidden_cookie_prefixes: Vec<String>,
}

struct Inner {
    config: Config,
    permits: Arc<Semaphore>,
    closed: CancellationToken,
    active: AtomicUsize,
    completion: Notify,
    on_error: Option<ProxyErrorReporter>,
}

impl fmt::Debug for Inner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyServerInner { <opaque> }")
    }
}

/// Application-session proxy protocol owner. It has no carrier or tunnel API.
#[derive(Clone)]
pub struct ProxyServer {
    inner: Arc<Inner>,
}

impl ProxyServer {
    pub fn new(options: ProxyServerOptions) -> Result<Self, ProxyServerError> {
        let (config, max_concurrent, on_error) = compile_options(options)?;
        if config.upstream.scheme() == "https" {
            websocket_transport::client_tls(config.upstream_trust_roots_der.clone())
                .map_err(|_| ProxyServerError::InvalidOptions)?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                permits: Arc::new(Semaphore::new(max_concurrent)),
                closed: CancellationToken::new(),
                active: AtomicUsize::new(0),
                completion: Notify::new(),
                on_error,
            }),
        })
    }

    /// Atomically installs the HTTP and WebSocket handlers on a carrier-neutral registry.
    pub fn register_stream_handlers<R>(&self, handlers: &mut R) -> Result<(), ProxyServerError>
    where
        R: StreamHandlerRegistrar,
    {
        self.register_into(handlers)
    }

    fn register_into<R>(&self, handlers: &mut R) -> Result<(), ProxyServerError>
    where
        R: StreamHandlerRegistrar,
    {
        if self.inner.closed.is_cancelled() {
            return Err(ProxyServerError::Closed);
        }
        let http: Arc<dyn StreamHandler> = Arc::new(ProxyHandler {
            inner: self.inner.clone(),
            protocol: Protocol::Http,
        });
        let websocket: Arc<dyn StreamHandler> = Arc::new(ProxyHandler {
            inner: self.inner.clone(),
            protocol: Protocol::WebSocket,
        });
        register_stream_handlers(
            handlers,
            vec![
                (HTTP_KIND.to_owned(), http),
                (WEBSOCKET_KIND.to_owned(), websocket),
            ],
        )
        .map_err(|error| match error {
            HandlerRegistrationError::AlreadyRegistered => ProxyServerError::AlreadyRegistered,
            HandlerRegistrationError::Invalid => ProxyServerError::OperationFailed,
        })
    }

    /// Cancels active operations, waits for their cleanup, and rejects future dispatch.
    pub async fn close(&self) {
        self.inner.closed.cancel();
        loop {
            let completion = self.inner.completion.notified();
            tokio::pin!(completion);
            completion.as_mut().enable();
            if self.inner.active.load(Ordering::Acquire) == 0 {
                return;
            }
            completion.await;
        }
    }
}

impl fmt::Debug for ProxyServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyServer { <opaque> }")
    }
}

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Http,
    WebSocket,
}

#[derive(Debug)]
struct ProxyHandler {
    inner: Arc<Inner>,
    protocol: Protocol,
}

struct ActiveOperation {
    inner: Arc<Inner>,
}

impl ActiveOperation {
    fn enter(inner: Arc<Inner>) -> Result<Self, SessionError> {
        if inner.closed.is_cancelled() {
            return Err(SessionError::Closed);
        }
        inner.active.fetch_add(1, Ordering::AcqRel);
        let operation = Self { inner };
        if operation.inner.closed.is_cancelled() {
            return Err(SessionError::Closed);
        }
        Ok(operation)
    }
}

impl Drop for ActiveOperation {
    fn drop(&mut self) {
        if self.inner.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.completion.notify_waiters();
        }
    }
}

#[async_trait]
impl StreamHandler for ProxyHandler {
    async fn handle(
        &self,
        incoming: &IncomingStream,
        cancellation: CancellationToken,
    ) -> Result<(), SessionError> {
        let _active = ActiveOperation::enter(self.inner.clone())?;
        let permit = self
            .inner
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| SessionError::ResourceExhausted)?;
        if self.inner.closed.is_cancelled() {
            return Err(SessionError::Closed);
        }
        let operation = cancellation.child_token();
        let closed = self.inner.closed.clone();
        let operation_for_close = operation.clone();
        let close_task = tokio::spawn(async move {
            closed.cancelled().await;
            operation_for_close.cancel();
        });
        let result = match self.protocol {
            Protocol::Http => serve_http(&self.inner, incoming.stream(), operation.clone()).await,
            Protocol::WebSocket => {
                serve_websocket(&self.inner, incoming.stream(), operation.clone()).await
            }
        };
        close_task.abort();
        drop(permit);
        if let Err(error) = result {
            report(&self.inner, error);
            return Err(SessionError::OperationFailed);
        }
        Ok(())
    }
}

fn report(inner: &Inner, error: ProxyServerError) {
    if let Some(reporter) = &inner.on_error {
        let reporter = reporter.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| reporter(error)));
    }
}

fn compile_options(
    options: ProxyServerOptions,
) -> Result<(Config, usize, Option<ProxyErrorReporter>), ProxyServerError> {
    validate_base_url(&options.upstream, true)?;
    validate_base_url(&options.upstream_origin, false)?;
    if options.upstream.scheme() == "https"
        && (options.upstream_trust_roots_der.is_empty()
            || options.upstream_trust_roots_der.iter().any(Vec::is_empty))
    {
        return Err(ProxyServerError::InvalidOptions);
    }
    let host = options
        .upstream
        .host_str()
        .ok_or(ProxyServerError::InvalidOptions)?
        .to_ascii_lowercase();
    let allowed_hosts = if options.allowed_upstream_hosts.is_empty() {
        vec!["127.0.0.1".to_owned(), "::1".to_owned()]
    } else {
        options.allowed_upstream_hosts
    };
    if !allowed_hosts
        .iter()
        .any(|candidate| candidate.trim().eq_ignore_ascii_case(&host))
    {
        return Err(ProxyServerError::InvalidOptions);
    }
    let max_concurrent = fallback(options.max_concurrent_streams, DEFAULT_MAX_CONCURRENT)?;
    let max_json = fallback(options.max_json_frame_bytes, DEFAULT_MAX_JSON)?;
    let max_chunk = fallback(options.max_chunk_bytes, DEFAULT_MAX_CHUNK)?;
    let max_body = fallback(options.max_body_bytes, DEFAULT_MAX_BODY)?;
    let max_websocket_frame = fallback(
        options.max_websocket_frame_bytes,
        DEFAULT_MAX_WEBSOCKET_FRAME,
    )?;
    if max_concurrent > Semaphore::MAX_PERMITS
        || max_json > u32::MAX as usize
        || max_chunk > u32::MAX as usize
        || max_websocket_frame > u32::MAX as usize
    {
        return Err(ProxyServerError::InvalidOptions);
    }
    let default_timeout = duration_fallback(options.default_http_request_timeout, DEFAULT_TIMEOUT);
    let max_timeout = duration_fallback(options.max_http_request_timeout, MAX_TIMEOUT);
    if default_timeout > max_timeout || max_timeout.is_zero() {
        return Err(ProxyServerError::InvalidOptions);
    }
    let allowed_origins = if options.allowed_origins.is_empty() {
        HashSet::from([options.upstream_origin.origin().ascii_serialization()])
    } else {
        options
            .allowed_origins
            .iter()
            .map(|origin| {
                validate_external_origin(origin.as_str())
                    .map(|origin| origin.origin().ascii_serialization())
                    .ok_or(ProxyServerError::InvalidOptions)
            })
            .collect::<Result<HashSet<_>, _>>()?
    };
    Ok((
        Config {
            upstream: options.upstream,
            upstream_origin: options.upstream_origin.origin().ascii_serialization(),
            upstream_trust_roots_der: options.upstream_trust_roots_der,
            allowed_origins,
            max_json,
            max_chunk,
            max_body,
            max_websocket_frame,
            websocket_establish_timeout: WEBSOCKET_ESTABLISH_TIMEOUT,
            default_timeout,
            max_timeout,
            request_headers: normalize_header_set(options.extra_request_headers)?,
            response_headers: normalize_header_set(options.extra_response_headers)?,
            blocked_response_headers: normalize_header_set(options.blocked_response_headers)?,
            websocket_headers: normalize_header_set(options.extra_websocket_headers)?,
            forbidden_cookies: normalize_names(options.forbidden_cookie_names)?,
            forbidden_cookie_prefixes: normalize_prefixes(options.forbidden_cookie_name_prefixes)?,
        },
        max_concurrent,
        options.on_error,
    ))
}

fn validate_base_url(value: &Url, require_port: bool) -> Result<(), ProxyServerError> {
    if !matches!(value.scheme(), "http" | "https")
        || value.host_str().is_none()
        || (require_port && value.port().is_none())
        || value.username() != ""
        || value.password().is_some()
        || !matches!(value.path(), "" | "/")
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err(ProxyServerError::InvalidOptions);
    }
    Ok(())
}

fn fallback(value: usize, default: usize) -> Result<usize, ProxyServerError> {
    let value = if value == 0 { default } else { value };
    (value > 0)
        .then_some(value)
        .ok_or(ProxyServerError::InvalidOptions)
}

fn duration_fallback(value: Duration, default: Duration) -> Duration {
    if value.is_zero() { default } else { value }
}

fn normalize_names(values: Vec<String>) -> Result<HashSet<String>, ProxyServerError> {
    values
        .into_iter()
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            (!value.is_empty())
                .then_some(value)
                .ok_or(ProxyServerError::InvalidOptions)
        })
        .collect()
}

fn normalize_prefixes(values: Vec<String>) -> Result<Vec<String>, ProxyServerError> {
    values
        .into_iter()
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            (!value.is_empty())
                .then_some(value)
                .ok_or(ProxyServerError::InvalidOptions)
        })
        .collect()
}

fn normalize_header_set(values: Vec<String>) -> Result<HashSet<String>, ProxyServerError> {
    values
        .into_iter()
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            if !valid_header_name(&value) || FORBIDDEN_HEADERS.contains(&value.as_str()) {
                return Err(ProxyServerError::InvalidOptions);
            }
            Ok(value)
        })
        .collect()
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRequestMeta {
    v: u8,
    request_id: String,
    method: String,
    path: String,
    headers: Vec<Header>,
    #[serde(default)]
    external_origin: String,
    #[serde(default)]
    timeout_ms: u64,
}

#[derive(Debug, Serialize)]
struct WireError<'a> {
    code: &'a str,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct HttpResponseMeta<'a> {
    v: u8,
    request_id: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    headers: Vec<HeaderOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<WireError<'a>>,
}

#[derive(Debug, Serialize)]
struct HeaderOutput {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebSocketOpen {
    v: u8,
    conn_id: String,
    path: String,
    headers: Vec<Header>,
}

#[derive(Debug, Serialize)]
struct WebSocketResponse<'a> {
    v: u8,
    conn_id: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    protocol: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<WireError<'a>>,
}

struct ProxyReader<'a> {
    stream: &'a dyn ByteStream,
    buffered: BytesMut,
}

impl<'a> ProxyReader<'a> {
    fn new(stream: &'a dyn ByteStream) -> Self {
        Self {
            stream,
            buffered: BytesMut::new(),
        }
    }

    async fn exact(
        &mut self,
        length: usize,
        cancellation: &CancellationToken,
    ) -> Result<Bytes, ProxyServerError> {
        while self.buffered.len() < length {
            let next = tokio::select! {
                _ = cancellation.cancelled() => return Err(ProxyServerError::Closed),
                next = self.stream.read() => next,
            }
            .map_err(|_| ProxyServerError::OperationFailed)?
            .ok_or(ProxyServerError::OperationFailed)?;
            self.buffered.extend_from_slice(&next);
        }
        Ok(self.buffered.split_to(length).freeze())
    }
}

async fn read_json<T: DeserializeOwned>(
    reader: &mut ProxyReader<'_>,
    maximum: usize,
    cancellation: &CancellationToken,
) -> Result<T, ProxyServerError> {
    let mut header = reader.exact(4, cancellation).await?;
    let length = header.get_u32() as usize;
    if length > maximum {
        return Err(ProxyServerError::OperationFailed);
    }
    serde_json::from_slice(&reader.exact(length, cancellation).await?)
        .map_err(|_| ProxyServerError::OperationFailed)
}

async fn write_all(
    stream: &dyn ByteStream,
    mut payload: Bytes,
    cancellation: &CancellationToken,
) -> Result<(), ProxyServerError> {
    while !payload.is_empty() {
        let count = tokio::select! {
            _ = cancellation.cancelled() => return Err(ProxyServerError::Closed),
            count = stream.write(payload.clone()) => count,
        }
        .map_err(|_| ProxyServerError::OperationFailed)?;
        if count == 0 || count > payload.len() {
            return Err(ProxyServerError::OperationFailed);
        }
        payload.advance(count);
    }
    Ok(())
}

async fn write_json(
    stream: &dyn ByteStream,
    value: &impl Serialize,
    cancellation: &CancellationToken,
) -> Result<(), ProxyServerError> {
    let payload = serde_json::to_vec(value).map_err(|_| ProxyServerError::OperationFailed)?;
    let length = u32::try_from(payload.len()).map_err(|_| ProxyServerError::OperationFailed)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    write_all(stream, Bytes::from(frame), cancellation).await
}

async fn read_body(
    reader: &mut ProxyReader<'_>,
    config: &Config,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, ProxyServerError> {
    let mut body = Vec::new();
    loop {
        let mut header = reader.exact(4, cancellation).await?;
        let length = header.get_u32() as usize;
        if length == 0 {
            return Ok(body);
        }
        if length > config.max_chunk || body.len().saturating_add(length) > config.max_body {
            return Err(ProxyServerError::OperationFailed);
        }
        body.extend_from_slice(&reader.exact(length, cancellation).await?);
    }
}

async fn write_chunk(
    stream: &dyn ByteStream,
    payload: &[u8],
    cancellation: &CancellationToken,
) -> Result<(), ProxyServerError> {
    let length = u32::try_from(payload.len()).map_err(|_| ProxyServerError::OperationFailed)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    write_all(stream, Bytes::from(frame), cancellation).await
}

async fn serve_http(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
) -> Result<(), ProxyServerError> {
    let started = Instant::now();
    tokio::time::timeout_at(
        started + inner.config.max_timeout,
        serve_http_request(inner, stream, cancellation, started),
    )
    .await
    .map_err(|_| ProxyServerError::OperationFailed)?
}

async fn serve_http_request(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
    started: Instant,
) -> Result<(), ProxyServerError> {
    let mut reader = ProxyReader::new(stream);
    let meta: HttpRequestMeta =
        match read_json(&mut reader, inner.config.max_json, &cancellation).await {
            Ok(meta) => meta,
            Err(_) => {
                write_http_error(stream, "unknown", "invalid_request_meta", &cancellation).await;
                return Ok(());
            }
        };
    let request_id = meta.request_id.trim();
    let method = meta.method.trim().to_ascii_uppercase();
    let Some(path) = normalize_path(&meta.path) else {
        write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
        return Ok(());
    };
    let Ok(method) = Method::from_bytes(method.as_bytes()) else {
        write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
        return Ok(());
    };
    if meta.v != WIRE_VERSION || request_id.is_empty() {
        write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
        return Ok(());
    }
    let external_origin = if meta.external_origin.is_empty() {
        None
    } else {
        let origin = validate_external_origin(&meta.external_origin);
        if origin.as_ref().is_none_or(|origin| {
            !inner
                .config
                .allowed_origins
                .contains(&origin.origin().ascii_serialization())
        }) {
            write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
            return Ok(());
        }
        origin
    };
    let timeout = if meta.timeout_ms == 0 {
        inner.config.default_timeout
    } else {
        Duration::from_millis(meta.timeout_ms).min(inner.config.max_timeout)
    };
    let deadline = started + timeout;
    tokio::time::timeout_at(deadline, async {
        let body = match read_body(&mut reader, &inner.config, &cancellation).await {
            Ok(body) => body,
            Err(_) => {
                write_http_error(stream, request_id, "request_body_invalid", &cancellation).await;
                return Ok(());
            }
        };
        let target = inner
            .config
            .upstream
            .join(&path)
            .map_err(|_| ProxyServerError::OperationFailed)?;
        let uri = if target.query().is_some() {
            format!("{}?{}", target.path(), target.query().unwrap_or_default())
        } else {
            target.path().to_owned()
        };
        let uri: Uri = uri.parse().map_err(|_| ProxyServerError::OperationFailed)?;
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Full::new(Bytes::from(body.clone())))
            .map_err(|_| ProxyServerError::OperationFailed)?;
        let connect_host = target
            .host_str()
            .ok_or(ProxyServerError::OperationFailed)?
            .to_owned();
        let port = target
            .port_or_known_default()
            .ok_or(ProxyServerError::OperationFailed)?;
        let authority = target[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
        request.headers_mut().insert(
            header::HOST,
            authority
                .parse()
                .map_err(|_| ProxyServerError::OperationFailed)?,
        );
        let request_headers = filter_request_headers(&meta.headers, &inner.config);
        if let Some(origin) = &external_origin {
            let expected = origin.origin().ascii_serialization();
            if request_headers.iter().any(|header| {
                header.name == "origin"
                    && validate_external_origin(&header.value)
                        .is_none_or(|value| value.origin().ascii_serialization() != expected)
            }) {
                write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
                return Ok(());
            }
        }
        for header in request_headers {
            let name = header::HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| ProxyServerError::OperationFailed)?;
            let value = header::HeaderValue::from_str(&header.value)
                .map_err(|_| ProxyServerError::OperationFailed)?;
            request.headers_mut().append(name, value);
        }
        if let Some(origin) = external_origin {
            request.headers_mut().insert(
                "x-forwarded-proto",
                origin
                    .scheme()
                    .parse()
                    .map_err(|_| ProxyServerError::OperationFailed)?,
            );
        }
        let (response, connection_task) =
            match send_http_request(inner, request, connect_host, port, deadline, &cancellation)
                .await
            {
                Ok(response) => response,
                Err(HttpRequestFailure::Closed) => return Err(ProxyServerError::Closed),
                Err(HttpRequestFailure::Timeout) => {
                    write_http_error(stream, request_id, "timeout", &cancellation).await;
                    return Ok(());
                }
                Err(HttpRequestFailure::Dial) => {
                    write_http_error(stream, request_id, "upstream_dial_failed", &cancellation)
                        .await;
                    return Ok(());
                }
                Err(HttpRequestFailure::Request) => {
                    write_http_error(stream, request_id, "upstream_request_failed", &cancellation)
                        .await;
                    return Ok(());
                }
            };
        let (parts, mut body) = response.into_parts();
        if parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > inner.config.max_body as u64)
        {
            connection_task.abort();
            write_http_error(stream, request_id, "response_body_too_large", &cancellation).await;
            return Ok(());
        }
        let status = parts.status.as_u16();
        let headers = filter_response_headers(&parts.headers, &inner.config);
        let result = async {
            write_json(
                stream,
                &HttpResponseMeta {
                    v: WIRE_VERSION,
                    request_id,
                    ok: true,
                    status: Some(status),
                    headers,
                    error: None,
                },
                &cancellation,
            )
            .await?;
            let mut total = 0usize;
            while let Some(frame) = tokio::select! {
                _ = cancellation.cancelled() => return Err(ProxyServerError::Closed),
                frame = tokio::time::timeout_at(deadline, body.frame()) => frame
                    .map_err(|_| ProxyServerError::OperationFailed)?,
            } {
                let frame = frame.map_err(|_| ProxyServerError::OperationFailed)?;
                let Some(chunk) = frame.data_ref() else {
                    continue;
                };
                total = total
                    .checked_add(chunk.len())
                    .ok_or(ProxyServerError::OperationFailed)?;
                if total > inner.config.max_body {
                    return Err(ProxyServerError::OperationFailed);
                }
                for payload in chunk.chunks(inner.config.max_chunk) {
                    write_chunk(stream, payload, &cancellation).await?;
                }
            }
            write_all(stream, Bytes::from_static(&[0, 0, 0, 0]), &cancellation).await
        }
        .await;
        connection_task.abort();
        result
    })
    .await
    .map_err(|_| ProxyServerError::OperationFailed)?
}

#[derive(Clone, Copy, Debug)]
enum HttpRequestFailure {
    Closed,
    Timeout,
    Dial,
    Request,
}

enum HttpIo {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for HttpIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for HttpIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, buffer),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }
}

async fn send_http_request(
    inner: &Inner,
    request: Request<Full<Bytes>>,
    host: String,
    port: u16,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<
    (
        hyper::Response<Incoming>,
        tokio_util::task::AbortOnDropHandle<()>,
    ),
    HttpRequestFailure,
> {
    let tcp = tokio::select! {
        _ = cancellation.cancelled() => return Err(HttpRequestFailure::Closed),
        result = tokio::time::timeout_at(deadline, TcpStream::connect((host.as_str(), port))) => match result {
            Err(_) => return Err(HttpRequestFailure::Timeout),
            Ok(Err(_)) => return Err(HttpRequestFailure::Dial),
            Ok(Ok(tcp)) => tcp,
        },
    };
    let io = if inner.config.upstream.scheme() == "https" {
        let server_name = ServerName::try_from(host).map_err(|_| HttpRequestFailure::Dial)?;
        let tls = TlsConnector::from(
            websocket_transport::client_tls(inner.config.upstream_trust_roots_der.clone())
                .map_err(|_| HttpRequestFailure::Dial)?,
        );
        let connected = tokio::select! {
            _ = cancellation.cancelled() => return Err(HttpRequestFailure::Closed),
            result = tokio::time::timeout_at(deadline, tls.connect(server_name, tcp)) => match result {
                Err(_) => return Err(HttpRequestFailure::Timeout),
                Ok(Err(_)) => return Err(HttpRequestFailure::Dial),
                Ok(Ok(connected)) => connected,
            },
        };
        HttpIo::Tls(Box::new(connected))
    } else {
        HttpIo::Plain(tcp)
    };
    let (mut sender, connection) = tokio::select! {
        _ = cancellation.cancelled() => return Err(HttpRequestFailure::Closed),
        result = tokio::time::timeout_at(deadline, http1::handshake(TokioIo::new(io))) => match result {
            Err(_) => return Err(HttpRequestFailure::Timeout),
            Ok(Err(_)) => return Err(HttpRequestFailure::Request),
            Ok(Ok(parts)) => parts,
        },
    };
    let connection_task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = tokio::select! {
        _ = cancellation.cancelled() => {
            connection_task.abort();
            return Err(HttpRequestFailure::Closed);
        },
        result = tokio::time::timeout_at(deadline, sender.send_request(request)) => match result {
            Err(_) => {
                connection_task.abort();
                return Err(HttpRequestFailure::Timeout);
            },
            Ok(Err(_)) => {
                connection_task.abort();
                return Err(HttpRequestFailure::Request);
            },
            Ok(Ok(response)) => response,
        },
    };
    Ok((response, connection_task))
}

async fn write_http_error(
    stream: &dyn ByteStream,
    request_id: &str,
    code: &str,
    cancellation: &CancellationToken,
) {
    let request_id = if request_id.trim().is_empty() {
        "unknown"
    } else {
        request_id.trim()
    };
    let _ = write_json(
        stream,
        &HttpResponseMeta {
            v: WIRE_VERSION,
            request_id,
            ok: false,
            status: None,
            headers: Vec::new(),
            error: Some(WireError {
                code,
                message: "proxy operation failed",
            }),
        },
        cancellation,
    )
    .await;
    let _ = write_all(stream, Bytes::from_static(&[0, 0, 0, 0]), cancellation).await;
}

async fn serve_websocket(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
) -> Result<(), ProxyServerError> {
    serve_websocket_with_establishment_timeout(
        inner,
        stream,
        cancellation,
        inner.config.websocket_establish_timeout,
    )
    .await
}

async fn serve_websocket_with_establishment_timeout(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
    establishment_timeout: Duration,
) -> Result<(), ProxyServerError> {
    let mut reader = ProxyReader::new(stream);
    let open: WebSocketOpen = match read_json(&mut reader, inner.config.max_json, &cancellation)
        .await
    {
        Ok(open) => open,
        Err(_) => {
            write_websocket_error(stream, "unknown", "invalid_ws_open_meta", &cancellation).await;
            return Ok(());
        }
    };
    let conn_id = open.conn_id.trim();
    let Some(path) = normalize_path(&open.path) else {
        write_websocket_error(stream, conn_id, "invalid_ws_open_meta", &cancellation).await;
        return Ok(());
    };
    if open.v != WIRE_VERSION || conn_id.is_empty() {
        write_websocket_error(stream, conn_id, "invalid_ws_open_meta", &cancellation).await;
        return Ok(());
    }
    let mut target = inner.config.upstream.clone();
    target
        .set_scheme(if target.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| ProxyServerError::OperationFailed)?;
    let target = target
        .join(&path)
        .map_err(|_| ProxyServerError::OperationFailed)?;
    let mut request = target
        .as_str()
        .into_client_request()
        .map_err(|_| ProxyServerError::OperationFailed)?;
    for header in filter_websocket_headers(&open.headers, &inner.config) {
        let name: tungstenite::http::HeaderName = header
            .name
            .parse()
            .map_err(|_| ProxyServerError::OperationFailed)?;
        let value: tungstenite::http::HeaderValue = header
            .value
            .parse()
            .map_err(|_| ProxyServerError::OperationFailed)?;
        request.headers_mut().append(name, value);
    }
    request.headers_mut().insert(
        "origin",
        inner
            .config
            .upstream_origin
            .parse()
            .map_err(|_| ProxyServerError::OperationFailed)?,
    );
    let websocket_config = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(inner.config.max_websocket_frame))
        .max_frame_size(Some(inner.config.max_websocket_frame));
    let host = target
        .host_str()
        .ok_or(ProxyServerError::OperationFailed)?
        .to_owned();
    let port = target
        .port_or_known_default()
        .ok_or(ProxyServerError::OperationFailed)?;
    let establishment_deadline = Instant::now() + establishment_timeout;
    let tcp = await_websocket_establishment(
        establishment_deadline,
        &cancellation,
        TcpStream::connect((host.as_str(), port)),
    )
    .await?
    .map_err(|_| ProxyServerError::OperationFailed)?;
    if target.scheme() == "wss" {
        let server_name =
            ServerName::try_from(host).map_err(|_| ProxyServerError::OperationFailed)?;
        let tls = TlsConnector::from(
            websocket_transport::client_tls(inner.config.upstream_trust_roots_der.clone())
                .map_err(|_| ProxyServerError::OperationFailed)?,
        );
        let tls = await_websocket_establishment(
            establishment_deadline,
            &cancellation,
            tls.connect(server_name, tcp),
        )
        .await?
        .map_err(|_| ProxyServerError::OperationFailed)?;
        let connected = await_websocket_establishment(
            establishment_deadline,
            &cancellation,
            client_async_with_config(request, tls, Some(websocket_config)),
        )
        .await?;
        return relay_connected_websocket(inner, stream, reader, cancellation, conn_id, connected)
            .await;
    }
    let connected = await_websocket_establishment(
        establishment_deadline,
        &cancellation,
        client_async_with_config(request, tcp, Some(websocket_config)),
    )
    .await?;
    relay_connected_websocket(inner, stream, reader, cancellation, conn_id, connected).await
}

async fn await_websocket_establishment<F, T>(
    deadline: Instant,
    cancellation: &CancellationToken,
    future: F,
) -> Result<T, ProxyServerError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProxyServerError::Closed),
        result = tokio::time::timeout_at(deadline, future) => {
            result.map_err(|_| ProxyServerError::OperationFailed)
        }
    }
}

async fn relay_connected_websocket<S>(
    inner: &Inner,
    stream: &dyn ByteStream,
    mut reader: ProxyReader<'_>,
    cancellation: CancellationToken,
    conn_id: &str,
    connected: Result<
        (WebSocketStream<S>, tungstenite::handshake::client::Response),
        tungstenite::Error,
    >,
) -> Result<(), ProxyServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (websocket, response) = match connected {
        Ok(connected) => connected,
        Err(tungstenite::Error::Http(response)) => {
            let code = if response.status() == StatusCode::REQUEST_TIMEOUT {
                "timeout"
            } else {
                "upstream_ws_rejected"
            };
            write_websocket_error(stream, conn_id, code, &cancellation).await;
            return Ok(());
        }
        Err(_) => {
            write_websocket_error(stream, conn_id, "upstream_ws_dial_failed", &cancellation).await;
            return Ok(());
        }
    };
    let protocol = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    write_json(
        stream,
        &WebSocketResponse {
            v: WIRE_VERSION,
            conn_id,
            ok: true,
            protocol: &protocol,
            error: None,
        },
        &cancellation,
    )
    .await?;
    let (sink, mut source) = websocket.split();
    let sink = Arc::new(tokio::sync::Mutex::new(sink));
    let mut downstream_close_sent = false;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            upstream_message = source.next() => {
                let Some(message) = upstream_message else { break; };
                let message = message.map_err(|_| ProxyServerError::OperationFailed)?;
                let (operation, payload) = match message {
                    tungstenite::Message::Text(value) => (1, Bytes::from(value.to_string())),
                    tungstenite::Message::Binary(value) => (2, value),
                    tungstenite::Message::Close(value) => (8, encode_websocket_close(value)),
                    tungstenite::Message::Ping(value) => (9, value),
                    tungstenite::Message::Pong(value) => (10, value),
                    tungstenite::Message::Frame(_) => continue,
                };
                write_websocket_frame(
                    stream,
                    operation,
                    payload,
                    inner.config.max_websocket_frame,
                    &cancellation,
                )
                .await?;
                if operation == 8 {
                    // An upstream close is terminal after it has been relayed. If the
                    // downstream initiated close first, this is its acknowledgement.
                    break;
                }
            }
            downstream_frame = read_websocket_frame(
                &mut reader,
                inner.config.max_websocket_frame,
                &cancellation,
            ), if !downstream_close_sent => {
                let (operation, payload) = downstream_frame?;
                let message = match operation {
                    1 => tungstenite::Message::Text(
                        String::from_utf8(payload.to_vec())
                            .map_err(|_| ProxyServerError::OperationFailed)?
                            .into(),
                    ),
                    2 => tungstenite::Message::Binary(payload),
                    8 => tungstenite::Message::Close(decode_websocket_close(&payload)?),
                    9 => tungstenite::Message::Ping(payload),
                    10 => tungstenite::Message::Pong(payload),
                    _ => return Err(ProxyServerError::OperationFailed),
                };
                sink.lock()
                    .await
                    .send(message)
                    .await
                    .map_err(|_| ProxyServerError::OperationFailed)?;
                if operation == 8 {
                    // Keep the carrier stream alive until upstream acknowledges the
                    // close. This preserves normal FIN semantics for the peer.
                    downstream_close_sent = true;
                }
            }
        }
    }
    let _ = sink.lock().await.close().await;
    Ok(())
}

async fn write_websocket_error(
    stream: &dyn ByteStream,
    conn_id: &str,
    code: &str,
    cancellation: &CancellationToken,
) {
    let conn_id = if conn_id.trim().is_empty() {
        "unknown"
    } else {
        conn_id.trim()
    };
    let _ = write_json(
        stream,
        &WebSocketResponse {
            v: WIRE_VERSION,
            conn_id,
            ok: false,
            protocol: "",
            error: Some(WireError {
                code,
                message: "proxy operation failed",
            }),
        },
        cancellation,
    )
    .await;
}

async fn read_websocket_frame(
    reader: &mut ProxyReader<'_>,
    maximum: usize,
    cancellation: &CancellationToken,
) -> Result<(u8, Bytes), ProxyServerError> {
    let mut header = reader.exact(5, cancellation).await?;
    let operation = header.get_u8();
    let length = header.get_u32() as usize;
    if length > maximum || !matches!(operation, 1 | 2 | 8 | 9 | 10) {
        return Err(ProxyServerError::OperationFailed);
    }
    Ok((operation, reader.exact(length, cancellation).await?))
}

async fn write_websocket_frame(
    stream: &dyn ByteStream,
    operation: u8,
    payload: Bytes,
    maximum: usize,
    cancellation: &CancellationToken,
) -> Result<(), ProxyServerError> {
    if payload.len() > maximum {
        return Err(ProxyServerError::OperationFailed);
    }
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(operation);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    write_all(stream, Bytes::from(frame), cancellation).await
}

fn encode_websocket_close(close: Option<tungstenite::protocol::CloseFrame>) -> Bytes {
    let Some(close) = close else {
        return Bytes::new();
    };
    let reason = close.reason.as_bytes();
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&u16::from(close.code).to_be_bytes());
    payload.extend_from_slice(reason);
    Bytes::from(payload)
}

fn decode_websocket_close(
    payload: &[u8],
) -> Result<Option<tungstenite::protocol::CloseFrame>, ProxyServerError> {
    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() == 1 {
        return Err(ProxyServerError::OperationFailed);
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]).into();
    let reason = std::str::from_utf8(&payload[2..])
        .map_err(|_| ProxyServerError::OperationFailed)?
        .to_owned()
        .into();
    Ok(Some(tungstenite::protocol::CloseFrame { code, reason }))
}

fn normalize_path(raw: &str) -> Option<String> {
    if raw.trim() != raw
        || !raw.starts_with('/')
        || raw.starts_with("//")
        || raw.contains("://")
        || raw.contains('#')
        || raw.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return None;
    }
    let (raw_path, raw_query) = raw
        .split_once('?')
        .map_or((raw, None), |(path, query)| (path, Some(query)));
    let path = normalize_percent_escapes(raw_path, true)?.replace('\\', "/");
    if path.starts_with("//") {
        return None;
    }
    let path = clean_proxy_path(&path);
    let query = match raw_query {
        Some(query) => Some(normalize_percent_escapes(query, false)?),
        None => None,
    };
    let mut canonical = path;
    if let Some(query) = query {
        canonical.push('?');
        canonical.push_str(&query);
    }
    Some(canonical)
}

fn normalize_percent_escapes(raw: &str, reject_encoded_separators: bool) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] != b'%' {
            normalized.push(bytes[offset]);
            offset += 1;
            continue;
        }
        let high = decode_hex(*bytes.get(offset + 1)?)?;
        let low = decode_hex(*bytes.get(offset + 2)?)?;
        let value = high << 4 | low;
        if reject_encoded_separators && matches!(value, b'/' | b'\\') {
            return None;
        }
        if value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~') {
            normalized.push(value);
        } else {
            normalized.push(b'%');
            normalized.push(HEX[(value >> 4) as usize]);
            normalized.push(HEX[(value & 0x0f) as usize]);
        }
        offset += 3;
    }
    String::from_utf8(normalized).ok()
}

fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn clean_proxy_path(path: &str) -> String {
    let keep_trailing_slash = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    let mut canonical = String::from("/");
    canonical.push_str(&segments.join("/"));
    if keep_trailing_slash && canonical != "/" {
        canonical.push('/');
    }
    canonical
}

fn validate_external_origin(raw: &str) -> Option<Url> {
    let parsed = Url::parse(raw).ok()?;
    (matches!(parsed.scheme(), "http" | "https")
        && parsed.host_str().is_some()
        && matches!(parsed.path(), "" | "/")
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none())
    .then_some(parsed)
}

fn filter_request_headers(headers: &[Header], config: &Config) -> Vec<HeaderOutput> {
    let mut result = filter_headers(
        headers,
        REQUEST_HEADERS,
        &config.request_headers,
        &HashSet::new(),
    );
    for header in &mut result {
        if header.name == "cookie" {
            header.value = filter_cookies(&header.value, config);
        }
    }
    result.retain(|header| !header.value.is_empty());
    result.retain(|header| header.name != "x-forwarded-proto");
    result
}

fn filter_response_headers(headers: &HeaderMap, config: &Config) -> Vec<HeaderOutput> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            let allowed = RESPONSE_HEADERS.contains(&name.as_str())
                || config.response_headers.contains(&name);
            let value = value.to_str().ok()?;
            (allowed
                && !FORBIDDEN_HEADERS.contains(&name.as_str())
                && !config.blocked_response_headers.contains(&name)
                && !value.contains(['\r', '\n']))
            .then(|| HeaderOutput {
                name,
                value: value.to_owned(),
            })
        })
        .collect()
}

fn filter_websocket_headers(headers: &[Header], config: &Config) -> Vec<HeaderOutput> {
    filter_headers(
        headers,
        &["sec-websocket-protocol"],
        &config.websocket_headers,
        &HashSet::new(),
    )
}

fn filter_headers(
    headers: &[Header],
    base: &[&str],
    extra: &HashSet<String>,
    blocked: &HashSet<String>,
) -> Vec<HeaderOutput> {
    headers
        .iter()
        .filter_map(|header| {
            let name = header.name.trim().to_ascii_lowercase();
            let allowed = base.contains(&name.as_str()) || extra.contains(&name);
            (allowed
                && valid_header_name(&name)
                && !FORBIDDEN_HEADERS.contains(&name.as_str())
                && !blocked.contains(&name)
                && !header.value.contains(['\r', '\n']))
            .then(|| HeaderOutput {
                name,
                value: header.value.clone(),
            })
        })
        .collect()
}

fn filter_cookies(raw: &str, config: &Config) -> String {
    raw.split(';')
        .filter_map(|part| {
            let part = part.trim();
            let (name, _) = part.split_once('=')?;
            let name = name.trim().to_ascii_lowercase();
            (!config.forbidden_cookies.contains(&name)
                && !config
                    .forbidden_cookie_prefixes
                    .iter()
                    .any(|prefix| name.starts_with(prefix)))
            .then_some(part)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::pending,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Notify,
    };

    use super::*;

    const TEST_CERT_DER_B64: &str = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";

    #[derive(Debug)]
    struct TestStream {
        reads: Mutex<VecDeque<Bytes>>,
        writes: Mutex<Vec<u8>>,
        reset: AtomicBool,
        wait: Notify,
    }

    impl TestStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                reads: Mutex::new(VecDeque::from([Bytes::from(input)])),
                writes: Mutex::new(Vec::new()),
                reset: AtomicBool::new(false),
                wait: Notify::new(),
            }
        }

        fn output(&self) -> Vec<u8> {
            self.writes.lock().expect("writes lock").clone()
        }
    }

    #[async_trait]
    impl ByteStream for Arc<TestStream> {
        fn internal_test_id(&self) -> u64 {
            1
        }
        fn kind(&self) -> &str {
            HTTP_KIND
        }
        fn terminal_error(&self) -> Option<SessionError> {
            None
        }
        async fn read(&self) -> Result<Option<Bytes>, SessionError> {
            if let Some(bytes) = self.reads.lock().expect("reads lock").pop_front() {
                return Ok(Some(bytes));
            }
            self.wait.notified().await;
            Ok(None)
        }
        async fn write(&self, payload: Bytes) -> Result<usize, SessionError> {
            self.writes
                .lock()
                .expect("writes lock")
                .extend_from_slice(&payload);
            Ok(payload.len())
        }
        async fn close_write(&self) -> Result<(), SessionError> {
            Ok(())
        }
        async fn reset(&self) -> Result<(), SessionError> {
            self.reset.store(true, Ordering::SeqCst);
            Ok(())
        }
        async fn close(&self) -> Result<(), SessionError> {
            self.wait.notify_waiters();
            Ok(())
        }
    }

    fn frame_json(value: serde_json::Value) -> Vec<u8> {
        let payload = serde_json::to_vec(&value).expect("serialize frame");
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(&payload);
        framed
    }

    fn response_meta(output: &[u8]) -> serde_json::Value {
        let length = u32::from_be_bytes(output[..4].try_into().expect("response length")) as usize;
        serde_json::from_slice(&output[4..4 + length]).expect("response metadata")
    }

    #[derive(Debug)]
    struct NoopHandler;

    #[async_trait]
    impl StreamHandler for NoopHandler {
        async fn handle(
            &self,
            _stream: &IncomingStream,
            _cancellation: CancellationToken,
        ) -> Result<(), SessionError> {
            Ok(())
        }
    }

    fn test_options(upstream: Url) -> ProxyServerOptions {
        ProxyServerOptions {
            upstream,
            upstream_origin: "http://127.0.0.1:8080".parse().expect("origin"),
            upstream_trust_roots_der: Vec::new(),
            allowed_upstream_hosts: vec!["127.0.0.1".into()],
            allowed_origins: vec!["https://app.example".parse().expect("allowed origin")],
            max_concurrent_streams: 2,
            max_json_frame_bytes: 4096,
            max_chunk_bytes: 1024,
            max_body_bytes: 4096,
            max_websocket_frame_bytes: 1024,
            default_http_request_timeout: Duration::from_secs(2),
            max_http_request_timeout: Duration::from_secs(3),
            extra_request_headers: vec!["cookie".into(), "x-request-id".into()],
            extra_response_headers: vec!["x-visible".into()],
            blocked_response_headers: vec!["location".into()],
            extra_websocket_headers: vec!["x-request-id".into()],
            forbidden_cookie_names: vec!["session".into()],
            forbidden_cookie_name_prefixes: vec!["private_".into()],
            on_error: None,
        }
    }

    #[tokio::test]
    async fn http_intake_deadline_covers_incomplete_metadata_and_bodies() {
        for stage in ["metadata", "GET", "POST"] {
            let mut options = test_options("http://127.0.0.1:1".parse().unwrap());
            options.default_http_request_timeout = Duration::from_millis(20);
            options.max_http_request_timeout = Duration::from_millis(40);
            let server = ProxyServer::new(options).unwrap();
            let input = if stage == "metadata" {
                Vec::new()
            } else {
                frame_json(serde_json::json!({
                    "v": 1, "request_id": "stalled", "method": stage,
                    "path": "/", "headers": [], "timeout_ms": 20
                }))
            };
            let stream = Arc::new(TestStream::new(input));
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                serve_http(&server.inner, &stream, CancellationToken::new()),
            )
            .await
            .expect("incomplete proxy request ignored deadline");
            assert!(result.is_err(), "incomplete {stage} was accepted");
            server.close().await;
        }
    }

    #[test]
    fn canonical_proxy_path_closes_policy_bypasses_before_upstream_use() {
        for (raw, expected) in [
            ("/safe/../admin?mode=raw", "/admin?mode=raw"),
            ("/safe/./../admin", "/admin"),
            ("/safe/%2e%2e/admin?mode=encoded", "/admin?mode=encoded"),
            ("/safe\\..\\admin?mode=backslash", "/admin?mode=backslash"),
            ("/%61dmin", "/admin"),
            ("/safe//child?mode=double", "/safe/child?mode=double"),
            ("/public/../api//items?q=%7euser", "/api/items?q=~user"),
            ("/api?q=%2f%5c", "/api?q=%2F%5C"),
            ("/api/a%20b?q=%2f", "/api/a%20b?q=%2F"),
        ] {
            assert_eq!(
                normalize_path(raw).unwrap_or_else(|| panic!("rejected {raw}")),
                expected,
                "{raw}"
            );
        }

        for raw in [
            "/%2fadmin",
            "/%2Fadmin",
            "/%5cadmin",
            "/%5Cadmin",
            "/safe/%2f/admin",
            "/\\evil.example/admin",
            "/invalid%",
            "/invalid%2",
            "/invalid%zz",
            "/admin#fragment",
        ] {
            assert!(normalize_path(raw).is_none(), "accepted unsafe path {raw}");
        }
    }

    #[tokio::test]
    async fn http_proxy_enforces_origin_host_cookie_header_and_body_policy() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let address = listener.local_addr().expect("upstream address");
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let count = socket.read(&mut buffer).await.expect("read request");
                assert_ne!(count, 0, "request ended before headers");
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n")
                    && request.ends_with(b"hello")
                {
                    break;
                }
            }
            let text = String::from_utf8(request)
                .expect("request utf8")
                .to_ascii_lowercase();
            assert!(
                text.starts_with("post /api/items?q=~user http/1.1\r\n"),
                "{text}"
            );
            assert!(text.contains(&format!("host: {address}\r\n")), "{text}");
            assert!(text.contains("x-forwarded-proto: https\r\n"), "{text}");
            assert!(text.contains("cookie: public=ok\r\n"), "{text}");
            assert!(text.contains("x-request-id: visible\r\n"), "{text}");
            assert!(!text.contains("authorization:"), "{text}");
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\nLocation: /hidden\r\nX-Visible: yes\r\nSet-Cookie: secret=no\r\nConnection: close\r\n\r\nworld").await.expect("write response");
        });

        let server = ProxyServer::new(test_options(
            format!("http://{address}").parse().expect("upstream URL"),
        ))
        .expect("proxy server");
        let stream = Arc::new(TestStream::new({
            let mut input = frame_json(serde_json::json!({
                "v": 1, "request_id": "request-1", "method": "POST",
                "path": "/public/../api//items?q=%7euser",
                "headers": [
                    {"name":"cookie", "value":"session=bad; private_key=no; public=ok"},
                    {"name":"authorization", "value":"Bearer secret"},
                    {"name":"x-request-id", "value":"visible"}
                ],
                "external_origin": "https://app.example", "timeout_ms": 1000
            }));
            input.extend_from_slice(&5u32.to_be_bytes());
            input.extend_from_slice(b"hello");
            input.extend_from_slice(&0u32.to_be_bytes());
            input
        }));
        serve_http(&server.inner, &stream, CancellationToken::new())
            .await
            .expect("serve HTTP");
        upstream.await.expect("upstream task");

        let output = stream.output();
        let length = u32::from_be_bytes(output[..4].try_into().expect("response length")) as usize;
        let meta: serde_json::Value =
            serde_json::from_slice(&output[4..4 + length]).expect("response meta");
        assert_eq!(meta["status"], 200);
        assert_eq!(
            meta["headers"],
            serde_json::json!([
                {"name":"content-type", "value":"text/plain"},
                {"name":"x-visible", "value":"yes"}
            ])
        );
        assert_eq!(
            &output[4 + length..],
            &[0, 0, 0, 5, b'w', b'o', b'r', b'l', b'd', 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn websocket_proxy_relays_frames_and_closes_after_upstream_close() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let address = listener.local_addr().expect("upstream address");
        let upstream = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept websocket");
            let mut websocket = tokio_tungstenite::accept_hdr_async(
                socket,
                |request: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    assert_eq!(
                        request
                            .uri()
                            .path_and_query()
                            .expect("canonical WebSocket target")
                            .as_str(),
                        "/api/items?q=~user"
                    );
                    assert_eq!(
                        request.headers().get("origin").expect("origin"),
                        "http://127.0.0.1:8080"
                    );
                    assert_eq!(
                        request.headers().get("x-request-id").expect("request ID"),
                        "visible"
                    );
                    assert!(request.headers().get("authorization").is_none());
                    assert_eq!(
                        request
                            .headers()
                            .get("sec-websocket-protocol")
                            .expect("protocol"),
                        "chat"
                    );
                    response.headers_mut().insert(
                        "sec-websocket-protocol",
                        "chat".parse().expect("protocol header"),
                    );
                    Ok(response)
                },
            )
            .await
            .expect("upgrade websocket");
            assert_eq!(
                websocket
                    .next()
                    .await
                    .expect("client frame")
                    .expect("valid frame"),
                tungstenite::Message::Binary(Bytes::from_static(b"hello"))
            );
            websocket
                .send(tungstenite::Message::Binary(Bytes::from_static(b"world")))
                .await
                .expect("echo frame");
            websocket
                .close(Some(tungstenite::protocol::CloseFrame {
                    code: tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: "done".into(),
                }))
                .await
                .expect("close websocket");
        });

        let server = ProxyServer::new(test_options(
            format!("http://{address}").parse().expect("upstream URL"),
        ))
        .expect("proxy server");
        let stream = Arc::new(TestStream::new({
            let mut input = frame_json(serde_json::json!({
                "v": 1, "conn_id": "socket-1",
                "path": "/public/../api//items?q=%7euser",
                "headers": [
                    {"name":"sec-websocket-protocol", "value":"chat"},
                    {"name":"x-request-id", "value":"visible"},
                    {"name":"authorization", "value":"Bearer secret"}
                ]
            }));
            input.push(2);
            input.extend_from_slice(&5u32.to_be_bytes());
            input.extend_from_slice(b"hello");
            input
        }));
        tokio::time::timeout(
            Duration::from_secs(2),
            serve_websocket(&server.inner, &stream, CancellationToken::new()),
        )
        .await
        .expect("websocket proxy converged")
        .expect("serve websocket");
        upstream.await.expect("upstream task");

        let output = stream.output();
        let length = u32::from_be_bytes(output[..4].try_into().expect("response length")) as usize;
        let meta: serde_json::Value =
            serde_json::from_slice(&output[4..4 + length]).expect("response meta");
        assert_eq!(
            meta,
            serde_json::json!({
                "v": 1, "conn_id": "socket-1", "ok": true, "protocol": "chat"
            })
        );
        let frames = &output[4 + length..];
        assert_eq!(frames[0], 2);
        assert_eq!(
            u32::from_be_bytes(frames[1..5].try_into().expect("frame length")),
            5
        );
        assert_eq!(&frames[5..10], b"world");
        assert_eq!(frames[10], 8);
        assert_eq!(
            &frames[15..],
            &[0x03, 0xe8, b'd', b'o', b'n', b'e'],
            "close code and reason are preserved"
        );
    }

    #[tokio::test]
    async fn websocket_frame_limit_and_close_cancel_release_resources() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let address = listener.local_addr().expect("upstream address");
        let upstream = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept websocket");
            let _websocket = tokio_tungstenite::accept_async(socket)
                .await
                .expect("upgrade websocket");
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let mut options = test_options(format!("http://{address}").parse().expect("upstream URL"));
        options.max_websocket_frame_bytes = 4;
        let server = ProxyServer::new(options).expect("proxy server");
        let stream = Arc::new(TestStream::new({
            let mut input = frame_json(serde_json::json!({
                "v": 1, "conn_id": "socket-limit", "path": "/socket", "headers": []
            }));
            input.push(2);
            input.extend_from_slice(&5u32.to_be_bytes());
            input.extend_from_slice(b"hello");
            input
        }));
        let handler = ProxyHandler {
            inner: server.inner.clone(),
            protocol: Protocol::WebSocket,
        };
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            handler.handle(
                &IncomingStream::new(
                    WEBSOCKET_KIND,
                    crate::StreamMetadata::empty(),
                    Box::new(stream.clone()),
                ),
                CancellationToken::new(),
            ),
        )
        .await
        .expect("bounded frame rejection");
        assert_eq!(result, Err(SessionError::OperationFailed));
        assert_eq!(server.inner.permits.available_permits(), 2);
        server.close().await;
        assert_eq!(
            handler
                .handle(
                    &IncomingStream::new(
                        WEBSOCKET_KIND,
                        crate::StreamMetadata::empty(),
                        Box::new(stream)
                    ),
                    CancellationToken::new(),
                )
                .await,
            Err(SessionError::Closed)
        );
        upstream.abort();
    }

    #[tokio::test]
    async fn websocket_tcp_stage_and_shared_establishment_budget_are_bounded() {
        let cancellation = CancellationToken::new();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(40);
        await_websocket_establishment(deadline, &cancellation, async {
            tokio::time::sleep(Duration::from_millis(25)).await;
        })
        .await
        .expect("first establishment stage");
        assert_eq!(
            await_websocket_establishment(deadline, &cancellation, pending::<()>()).await,
            Err(ProxyServerError::OperationFailed)
        );
        assert!(
            started.elapsed() < Duration::from_millis(70),
            "establishment stages reset the shared deadline"
        );
    }

    #[tokio::test]
    async fn websocket_tls_blackhole_is_bounded_by_the_establishment_deadline() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS blackhole");
        let address = listener.local_addr().expect("TLS blackhole address");
        let upstream = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.expect("accept TLS connection");
            pending::<()>().await;
        });
        let mut options = test_options(
            format!("https://localhost:{}", address.port())
                .parse()
                .expect("WSS upstream URL"),
        );
        options.allowed_upstream_hosts = vec!["localhost".into()];
        options.upstream_trust_roots_der = vec![STANDARD.decode(TEST_CERT_DER_B64).unwrap()];
        let server = ProxyServer::new(options).expect("proxy server");
        let stream = Arc::new(TestStream::new(frame_json(serde_json::json!({
            "v": 1, "conn_id": "tls-blackhole", "path": "/socket", "headers": []
        }))));

        let started = Instant::now();
        assert_eq!(
            serve_websocket_with_establishment_timeout(
                &server.inner,
                &stream,
                CancellationToken::new(),
                Duration::from_millis(30),
            )
            .await,
            Err(ProxyServerError::OperationFailed)
        );
        assert!(started.elapsed() < Duration::from_millis(150));
        upstream.abort();
    }

    #[tokio::test]
    async fn websocket_upgrade_blackholes_release_handler_permits() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Upgrade blackhole");
        let address = listener.local_addr().expect("Upgrade blackhole address");
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let upstream = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.expect("accept Upgrade connection");
                accepted_tx.send(()).expect("record accepted connection");
                tokio::spawn(async move {
                    let _socket = socket;
                    pending::<()>().await;
                });
            }
        });
        let mut options = test_options(
            format!("http://{address}")
                .parse()
                .expect("WebSocket upstream URL"),
        );
        options.max_concurrent_streams = 1;
        let mut server = ProxyServer::new(options).expect("proxy server");
        Arc::get_mut(&mut server.inner)
            .expect("unshared test server")
            .config
            .websocket_establish_timeout = Duration::from_millis(30);
        let handler = ProxyHandler {
            inner: server.inner.clone(),
            protocol: Protocol::WebSocket,
        };

        for conn_id in ["upgrade-blackhole-1", "upgrade-blackhole-2"] {
            let stream = Arc::new(TestStream::new(frame_json(serde_json::json!({
                "v": 1, "conn_id": conn_id, "path": "/socket", "headers": []
            }))));
            let result = tokio::time::timeout(
                Duration::from_millis(200),
                handler.handle(
                    &IncomingStream::new(
                        WEBSOCKET_KIND,
                        crate::StreamMetadata::empty(),
                        Box::new(stream),
                    ),
                    CancellationToken::new(),
                ),
            )
            .await
            .expect("Upgrade blackhole converged");
            assert_eq!(result, Err(SessionError::OperationFailed));
            accepted_rx
                .recv()
                .await
                .expect("connection reached upstream");
            assert_eq!(server.inner.permits.available_permits(), 1);
        }
        server.close().await;
        upstream.abort();
    }

    #[test]
    fn options_and_registration_fail_closed_without_partial_installation() {
        let invalid = ProxyServerOptions::new(
            "http://user:secret@127.0.0.1:8080".parse().expect("URL"),
            "http://127.0.0.1:8080".parse().expect("origin"),
        );
        assert!(!format!("{invalid:?}").contains("secret"));
        assert!(matches!(
            ProxyServer::new(invalid),
            Err(ProxyServerError::InvalidOptions)
        ));

        let mut invalid_limit = ProxyServerOptions::new(
            "http://127.0.0.1:8080".parse().expect("URL"),
            "http://127.0.0.1:8080".parse().expect("origin"),
        );
        invalid_limit.max_concurrent_streams = Semaphore::MAX_PERMITS + 1;
        assert!(matches!(
            ProxyServer::new(invalid_limit),
            Err(ProxyServerError::InvalidOptions)
        ));

        let https_without_roots = ProxyServerOptions::new(
            "https://127.0.0.1:8443".parse().expect("URL"),
            "https://127.0.0.1:8443".parse().expect("origin"),
        );
        assert!(matches!(
            ProxyServer::new(https_without_roots),
            Err(ProxyServerError::InvalidOptions)
        ));

        let server = ProxyServer::new(ProxyServerOptions::new(
            "http://127.0.0.1:8080".parse().expect("URL"),
            "http://127.0.0.1:8080".parse().expect("origin"),
        ))
        .expect("proxy server");
        let mut handlers = crate::SessionHandlers::new(crate::SessionHandlerOptions::default())
            .expect("session handlers");
        handlers
            .handle_stream(WEBSOCKET_KIND, NoopHandler)
            .expect("occupy websocket handler");
        assert_eq!(
            server.register_stream_handlers(&mut handlers),
            Err(ProxyServerError::AlreadyRegistered)
        );
        handlers
            .handle_stream(HTTP_KIND, NoopHandler)
            .expect("HTTP handler was not partially installed");
    }

    #[test]
    fn websocket_close_wire_round_trip_rejects_malformed_payloads() {
        let close = decode_websocket_close(&[0x03, 0xe8, b'd', b'o', b'n', b'e'])
            .expect("decode close")
            .expect("close frame");
        assert_eq!(u16::from(close.code), 1000);
        assert_eq!(close.reason, "done");
        assert_eq!(
            encode_websocket_close(Some(close)),
            Bytes::from_static(&[0x03, 0xe8, b'd', b'o', b'n', b'e'])
        );
        assert!(decode_websocket_close(&[0]).is_err());
        assert!(decode_websocket_close(&[0x03, 0xe8, 0xff]).is_err());
    }

    #[tokio::test]
    async fn http_proxy_rejects_unknown_metadata_and_oversized_request_body() {
        let mut options = ProxyServerOptions::new(
            "http://127.0.0.1:8080".parse().expect("URL"),
            "http://127.0.0.1:8080".parse().expect("origin"),
        );
        options.max_body_bytes = 4;
        options.max_chunk_bytes = 8;
        let server = ProxyServer::new(options).expect("proxy server");

        let unknown = Arc::new(TestStream::new(frame_json(serde_json::json!({
            "v": 1, "request_id": "unknown", "method": "GET", "path": "/",
            "headers": [], "unexpected": "rejected"
        }))));
        serve_http(&server.inner, &unknown, CancellationToken::new())
            .await
            .expect("structured rejection");
        assert_eq!(
            response_meta(&unknown.output())["error"]["code"],
            "invalid_request_meta"
        );

        let oversized = Arc::new(TestStream::new({
            let mut input = frame_json(serde_json::json!({
                "v": 1, "request_id": "large", "method": "POST", "path": "/",
                "headers": []
            }));
            input.extend_from_slice(&5u32.to_be_bytes());
            input.extend_from_slice(b"large");
            input
        }));
        serve_http(&server.inner, &oversized, CancellationToken::new())
            .await
            .expect("structured rejection");
        assert_eq!(
            response_meta(&oversized.output())["error"]["code"],
            "request_body_invalid"
        );

        let mut origin_options = ProxyServerOptions::new(
            "http://127.0.0.1:8080".parse().expect("URL"),
            "http://127.0.0.1:8080".parse().expect("origin"),
        );
        origin_options.allowed_origins =
            vec!["https://app.example".parse().expect("allowed origin")];
        origin_options.extra_request_headers = vec!["origin".into()];
        let origin_server = ProxyServer::new(origin_options).expect("proxy server");
        let conflicting_origin = Arc::new(TestStream::new({
            let mut input = frame_json(serde_json::json!({
                "v": 1, "request_id": "origin", "method": "GET", "path": "/",
                "headers": [{"name":"origin", "value":"https://evil.example"}],
                "external_origin": "https://app.example"
            }));
            input.extend_from_slice(&0u32.to_be_bytes());
            input
        }));
        serve_http(
            &origin_server.inner,
            &conflicting_origin,
            CancellationToken::new(),
        )
        .await
        .expect("structured rejection");
        assert_eq!(
            response_meta(&conflicting_origin.output())["error"]["code"],
            "invalid_request_meta"
        );
    }

    #[tokio::test]
    async fn close_cancels_active_http_request_and_releases_permit() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let address = listener.local_addr().expect("upstream address");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await.expect("read request");
            let _ = accepted_tx.send(());
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let server = ProxyServer::new(test_options(
            format!("http://{address}").parse().expect("upstream URL"),
        ))
        .expect("proxy server");
        let stream = Arc::new(TestStream::new({
            let mut input = frame_json(serde_json::json!({
                "v": 1, "request_id": "cancel", "method": "GET", "path": "/wait",
                "headers": []
            }));
            input.extend_from_slice(&0u32.to_be_bytes());
            input
        }));
        let handler = ProxyHandler {
            inner: server.inner.clone(),
            protocol: Protocol::Http,
        };
        let operation = tokio::spawn(async move {
            handler
                .handle(
                    &IncomingStream::new(
                        HTTP_KIND,
                        crate::StreamMetadata::empty(),
                        Box::new(stream),
                    ),
                    CancellationToken::new(),
                )
                .await
        });
        accepted_rx.await.expect("request reached upstream");
        server.close().await;
        assert!(operation.is_finished());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), operation)
                .await
                .expect("operation canceled")
                .expect("handler task"),
            Err(SessionError::OperationFailed)
        );
        assert_eq!(server.inner.permits.available_permits(), 2);
        let rejected = ProxyHandler {
            inner: server.inner.clone(),
            protocol: Protocol::Http,
        }
        .handle(
            &IncomingStream::new(
                HTTP_KIND,
                crate::StreamMetadata::empty(),
                Box::new(Arc::new(TestStream::new(Vec::new()))),
            ),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(rejected, Err(SessionError::Closed));
        upstream.abort();
    }
}
