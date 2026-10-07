use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
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
use http_body_util::BodyExt;
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, Semaphore, watch},
    time::Instant,
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{WebSocketStream, client_async_with_config, tungstenite};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    SessionError,
    proxy_network::{ProxyNativeOwnership, ProxyNetworkPolicy, ProxySocket},
    transport::ByteStream,
};

const HTTP_KIND: &str = "flowersec-proxy/http1";
const CREDENTIAL_CONTROL_PATH: &str = "/.flowersec/upstream-credentials";
const WEBSOCKET_KIND: &str = "flowersec-proxy/ws";
const WIRE_VERSION: u8 = 2;
pub(crate) const DEFAULT_MAX_METADATA: usize = 1 << 20;
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
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "set-cookie",
    "te",
    "trailer",
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
    "content-encoding",
    "content-language",
    "content-length",
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
    /// Numeric addresses or canonical CIDRs; required for DNS upstreams.
    pub allowed_upstream_addresses: Vec<String>,
    pub allowed_origins: Vec<Url>,
    pub max_concurrent_streams: usize,
    pub max_concurrent_http_streams: usize,
    pub max_concurrent_event_streams: usize,
    pub event_stream_idle_timeout: Duration,
    pub max_metadata_bytes: usize,
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
    pub credentials: Option<crate::ProxyCredentialPolicy>,
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
            allowed_upstream_addresses: Vec::new(),
            allowed_origins: Vec::new(),
            max_concurrent_streams: 0,
            max_concurrent_http_streams: 0,
            max_concurrent_event_streams: 0,
            event_stream_idle_timeout: Duration::ZERO,
            max_metadata_bytes: 0,
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
            credentials: None,
            on_error: None,
        }
    }
}

/// Stable server-side proxy failure without upstream or peer details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProxyServerError {
    #[error("invalid Flowersec proxy server options")]
    InvalidOptions,
    #[error("Flowersec proxy server is closed")]
    Closed,
    #[error("Flowersec proxy operation failed")]
    OperationFailed,
}

#[derive(Debug)]
struct Config {
    upstream: Url,
    network: ProxyNetworkPolicy,
    upstream_origin: String,
    upstream_trust_roots_der: Vec<Vec<u8>>,
    allowed_origins: HashSet<String>,
    max_metadata: usize,
    max_chunk: usize,
    max_body: usize,
    max_http: usize,
    max_events: usize,
    event_idle_timeout: Duration,
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
    credentials: Option<Arc<crate::proxy_credentials_v4::CredentialRuntime>>,
    config: Config,
    permits: Arc<Semaphore>,
    http_permits: Arc<Semaphore>,
    event_permits: Arc<Semaphore>,
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
        let mut options = options;
        let credential_policy = options.credentials.take();
        let (config, max_concurrent, on_error) = compile_options(options)?;
        let credentials = credential_policy
            .filter(|policy| policy.mode != crate::ProxyCredentialMode::None)
            .map(|policy| {
                crate::proxy_credentials_v4::CredentialRuntime::new(policy, &config.upstream)
            })
            .transpose()
            .map_err(|_| ProxyServerError::InvalidOptions)?;
        if config.upstream.scheme() == "https" {
            crate::proxy_network::client_tls(config.upstream_trust_roots_der.clone())
                .map_err(|_| ProxyServerError::InvalidOptions)?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                http_permits: Arc::new(Semaphore::new(config.max_http)),
                event_permits: Arc::new(Semaphore::new(config.max_events)),
                config,
                credentials,
                permits: Arc::new(Semaphore::new(max_concurrent)),
                closed: CancellationToken::new(),
                active: AtomicUsize::new(0),
                completion: Notify::new(),
                on_error,
            }),
        })
    }

    /// Current raw-stream registrations for a frozen HandlerPlan. HTTP/WS
    /// authorization, request framing and upstream policy stay in this owner.
    pub fn stream_registrations(
        &self,
    ) -> Result<Vec<crate::RawStreamRegistration>, ProxyServerError> {
        if self.inner.closed.is_cancelled() {
            return Err(ProxyServerError::Closed);
        }
        let registrations = vec![
            crate::RawStreamRegistration {
                kind: HTTP_KIND.to_owned(),
                metadata: None,
                handler: Arc::new(CurrentProxyHandler(ProxyHandler {
                    inner: self.inner.clone(),
                    protocol: Protocol::Http,
                })),
            },
            crate::RawStreamRegistration {
                kind: WEBSOCKET_KIND.to_owned(),
                metadata: None,
                handler: Arc::new(CurrentProxyHandler(ProxyHandler {
                    inner: self.inner.clone(),
                    protocol: Protocol::WebSocket,
                })),
            },
        ];
        Ok(registrations)
    }

    pub async fn bind_upstream_credentials(
        &self,
        authentication: crate::ApplicationBinding,
        surface_owner: [u8; 16],
        content_origin: &str,
    ) -> Result<crate::ProxyCookieSession, crate::ProxyCredentialError> {
        self.inner
            .credentials
            .as_ref()
            .ok_or(crate::ProxyCredentialError::ScopeUnavailable)?
            .bind(authentication, surface_owner, content_origin)
            .await
    }
    /// Reports this server's original invalidation fact. Host/Service Worker
    /// fences remain separate facts owned by their actual publishers.
    pub async fn clear_upstream_credentials(
        &self,
        authentication: crate::ApplicationBinding,
        surface_owner: [u8; 16],
        session: &crate::ProxyCookieSession,
    ) -> Result<crate::ProxyCredentialClearResult, crate::ProxyCredentialError> {
        let attachment = session.attachment()?;
        self.inner
            .credentials
            .as_ref()
            .ok_or(crate::ProxyCredentialError::ScopeUnavailable)?
            .clear(authentication, surface_owner, &attachment)
            .await
    }
    /// Cancels active operations, waits for their cleanup, and rejects future dispatch.
    pub async fn close(&self) {
        self.inner.closed.cancel();
        if let Some(credentials) = &self.inner.credentials {
            credentials.close();
        }
        loop {
            let completion = self.inner.completion.notified();
            tokio::pin!(completion);
            completion.as_mut().enable();
            if self.inner.active.load(Ordering::Acquire) == 0 {
                self.inner.config.network.close().await;
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

impl ProxyHandler {
    async fn serve_stream(
        &self,
        stream: &dyn ByteStream,
        cancellation: CancellationToken,
        ownership: Option<Arc<ProxyNativeOwnership>>,
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
            Protocol::Http => {
                serve_http_owned(&self.inner, stream, operation.clone(), ownership.clone()).await
            }
            Protocol::WebSocket => {
                serve_websocket_owned(&self.inner, stream, operation.clone(), ownership.clone())
                    .await
            }
        };
        close_task.abort();
        let _ = close_task.await;
        drop(permit);
        if let Err(error) = result {
            report(&self.inner, error);
            return Err(SessionError::OperationFailed);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CurrentProxyHandler(ProxyHandler);
impl CurrentProxyHandler {
    fn accepts_metadata(&self, metadata: &crate::Metadata) -> bool {
        if metadata.encoded().is_empty() {
            return true;
        }
        let contract = crate::RawStreamMetadataContract {
            contract_id: "flowersec.proxy.open".into(),
            namespace: "application/json".into(),
            version: 1,
            codec: "application/json".into(),
            fields: vec![
                crate::RawStreamMetadataField {
                    name: "protocol".into(),
                    value_type: crate::RawStreamMetadataType::String,
                    required: true,
                },
                crate::RawStreamMetadataField {
                    name: "version".into(),
                    value_type: crate::RawStreamMetadataType::Number,
                    required: true,
                },
            ],
            max_encoded_bytes: 256,
            max_decoded_bytes: 128,
        };
        let Ok(values) = metadata.project_raw(&contract) else {
            return false;
        };
        let protocol = match self.0.protocol {
            Protocol::Http => "flowersec.proxy.http",
            Protocol::WebSocket => "flowersec.proxy.websocket",
        };
        values.get("protocol").and_then(serde_json::Value::as_str) == Some(protocol)
            && values.get("version").and_then(serde_json::Value::as_u64)
                == Some(u64::from(WIRE_VERSION))
    }

    fn resources(&self) -> Result<crate::environment_v4::ResourceLimits, crate::ServeError> {
        let config = &self.0.inner.config;
        let body = match self.0.protocol {
            Protocol::Http => config.max_body,
            Protocol::WebSocket => config.max_websocket_frame,
        } as u64;
        let bytes = body
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(config.max_metadata as u64 * 4))
            .and_then(|bytes| bytes.checked_add(config.max_chunk as u64 * 4 + 524288))
            .ok_or_else(|| crate::ServeError::new(crate::ServeFailure::Capacity))?;
        Ok(crate::environment_v4::ResourceLimits {
            sdk_bytes: bytes,
            provider_bytes: 2 << 20,
            items: 16,
            tasks: 3,
            timers: 3,
            native_handles: 1,
            work_slots: 3,
            ..Default::default()
        })
    }
    fn failure(error: SessionError) -> crate::ServeError {
        crate::ServeError::new(match error {
            SessionError::Closed => crate::ServeFailure::Closed,
            SessionError::Canceled => crate::ServeFailure::Canceled,
            SessionError::ResourceExhausted => crate::ServeFailure::Capacity,
            _ => crate::ServeFailure::Rejected,
        })
    }
}
#[async_trait]
impl crate::RawStreamHandler for CurrentProxyHandler {
    async fn authorize(
        &self,
        _authentication: crate::ApplicationBinding,
        metadata: crate::Metadata,
        cancellation: CancellationToken,
    ) -> Result<crate::StreamAuthorization, crate::ServeError> {
        if cancellation.is_cancelled() || self.0.inner.closed.is_cancelled() {
            return Err(crate::ServeError::new(crate::ServeFailure::Closed));
        }
        if !self.accepts_metadata(&metadata) {
            return Ok(crate::StreamAuthorization::Reject);
        }
        Ok(crate::StreamAuthorization::Accept {
            receive_window: 16384,
        })
    }
    async fn handle_open_with_context(
        &self,
        request: crate::OpenRequest,
        authentication: crate::ApplicationBinding,
        cancellation: CancellationToken,
        context: crate::ApplicationInvocationContext,
    ) -> Result<(), crate::ServeError> {
        context
            .check_cancellation()
            .map_err(|_| crate::ServeError::new(crate::ServeFailure::Canceled))?;
        let metadata = request.metadata().clone();
        if !matches!(
            self.authorize(authentication, metadata, cancellation.clone())
                .await?,
            crate::StreamAuthorization::Accept { .. }
        ) {
            let _ = request.reject();
            return Ok(());
        }
        // All actual buffers, native work and its Session cleanup descriptor
        // are admitted before accepting this original pending OPEN.
        let charge = Arc::new(
            request
                .account()
                .reserve(self.resources()?)
                .map_err(|_| crate::ServeError::new(crate::ServeFailure::Capacity))?,
        );
        let tail = Arc::new(
            request
                .session()
                .application_tail()
                .map_err(Self::failure)?,
        );
        let ownership = Arc::new(ProxyNativeOwnership {
            authentication: Some(authentication),
            _charge: charge,
            _tail: tail,
        });
        let stream = request.accept(16384).map_err(Self::failure)?;
        let result = self
            .0
            .serve_stream(&stream, cancellation, Some(ownership))
            .await
            .map_err(Self::failure);
        if result.is_err() || stream.finish().await.is_err() {
            let _ = stream.reset().await;
        }
        result
    }
    async fn handle(
        &self,
        stream: crate::Stream,
        metadata: crate::Metadata,
        cancellation: CancellationToken,
    ) -> Result<(), crate::ServeError> {
        if !self.accepts_metadata(&metadata) {
            return Err(crate::ServeError::new(crate::ServeFailure::Rejected));
        }
        let charge = Arc::new(
            stream
                .account()
                .reserve(self.resources()?)
                .map_err(|_| crate::ServeError::new(crate::ServeFailure::Capacity))?,
        );
        let tail = Arc::new(stream.application_tail().map_err(Self::failure)?);
        self.0
            .serve_stream(
                &stream,
                cancellation,
                Some(Arc::new(ProxyNativeOwnership {
                    authentication: None,
                    _charge: charge,
                    _tail: tail,
                })),
            )
            .await
            .map_err(Self::failure)
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
        .trim_start_matches('[')
        .trim_end_matches(']')
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
    let max_http = fallback(options.max_concurrent_http_streams, max_concurrent.min(24))?;
    let max_events = fallback(
        options.max_concurrent_event_streams,
        (max_http.saturating_mul(2) / 3).clamp(1, 16),
    )?;
    if max_http > max_concurrent || max_events > max_http {
        return Err(ProxyServerError::InvalidOptions);
    }
    let event_idle_timeout =
        duration_fallback(options.event_stream_idle_timeout, Duration::from_secs(45));
    if Instant::now().checked_add(event_idle_timeout).is_none() {
        return Err(ProxyServerError::InvalidOptions);
    }
    let network = ProxyNetworkPolicy::compile(
        &options.upstream,
        &options.allowed_upstream_addresses,
        max_concurrent,
    )?;
    let max_metadata = fallback(options.max_metadata_bytes, DEFAULT_MAX_METADATA)?;
    let max_chunk = fallback(options.max_chunk_bytes, DEFAULT_MAX_CHUNK)?;
    let max_body = fallback(options.max_body_bytes, DEFAULT_MAX_BODY)?;
    let max_websocket_frame = fallback(
        options.max_websocket_frame_bytes,
        DEFAULT_MAX_WEBSOCKET_FRAME,
    )?;
    if max_concurrent > Semaphore::MAX_PERMITS
        || max_metadata > u32::MAX as usize
        || max_chunk > u32::MAX as usize
        || max_websocket_frame > u32::MAX as usize
    {
        return Err(ProxyServerError::InvalidOptions);
    }
    let default_timeout = duration_fallback(options.default_http_request_timeout, DEFAULT_TIMEOUT);
    let max_timeout = duration_fallback(options.max_http_request_timeout, MAX_TIMEOUT);
    if default_timeout > max_timeout
        || max_timeout.is_zero()
        || Instant::now().checked_add(max_timeout).is_none()
    {
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
            network,
            upstream_origin: options.upstream_origin.origin().ascii_serialization(),
            upstream_trust_roots_der: options.upstream_trust_roots_der,
            allowed_origins,
            max_metadata,
            max_chunk,
            max_body,
            max_http,
            max_events,
            event_idle_timeout,
            max_websocket_frame,
            websocket_establish_timeout: WEBSOCKET_ESTABLISH_TIMEOUT,
            default_timeout,
            max_timeout,
            request_headers: normalize_header_set(options.extra_request_headers)?,
            response_headers: normalize_response_header_set(options.extra_response_headers)?,
            blocked_response_headers: normalize_response_header_set(
                options.blocked_response_headers,
            )?,
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

fn normalize_response_header_set(values: Vec<String>) -> Result<HashSet<String>, ProxyServerError> {
    values
        .into_iter()
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            if !valid_header_name(&value)
                || value != "set-cookie" && FORBIDDEN_HEADERS.contains(&value.as_str())
            {
                return Err(ProxyServerError::InvalidOptions);
            }
            Ok(value)
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
    #[serde(default)]
    credential_context: String,
    #[serde(default = "default_credentials")]
    credentials: String,
    #[serde(default)]
    request_origin: String,
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

#[derive(Debug, Serialize, Deserialize)]
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
    #[serde(default)]
    credential_context: String,
    #[serde(default = "default_credentials")]
    credentials: String,
    #[serde(default)]
    request_origin: String,
}
fn default_credentials() -> String {
    "same-origin".to_owned()
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

trait ProxyDecode {
    const SCHEMA: &'static str;
}
impl ProxyDecode for HttpRequestMeta {
    const SCHEMA: &'static str = "ProxyHTTPRequest";
}
impl ProxyDecode for WebSocketOpen {
    const SCHEMA: &'static str = "ProxyWebSocketOpen";
}
trait ProxyEncode {
    fn schema(&self) -> &'static str;
}
impl ProxyEncode for HttpResponseMeta<'_> {
    fn schema(&self) -> &'static str {
        "ProxyHTTPResponse"
    }
}
impl ProxyEncode for WebSocketResponse<'_> {
    fn schema(&self) -> &'static str {
        "ProxyWebSocketResponse"
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyEnd {
    v: u8,
    trailers: Vec<HeaderOutput>,
}
impl ProxyEncode for BodyEnd {
    fn schema(&self) -> &'static str {
        "ProxyBodyEnd"
    }
}
impl ProxyDecode for BodyEnd {
    const SCHEMA: &'static str = "ProxyBodyEnd";
}
async fn write_body_end(
    stream: &dyn ByteStream,
    trailers: Vec<HeaderOutput>,
    cancellation: &CancellationToken,
) -> Result<(), ProxyServerError> {
    write_all(stream, Bytes::from_static(&[0, 0, 0, 0]), cancellation).await?;
    write_metadata(
        stream,
        &BodyEnd {
            v: WIRE_VERSION,
            trailers,
        },
        cancellation,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Proxy forwarding retains original socket ownership and credential binding with the request context."
)]
async fn credential_request(
    inner: &Inner,
    ownership: Option<&Arc<ProxyNativeOwnership>>,
    association: &str,
    credentials: &str,
    origin: &str,
    path: &str,
    headers: &[Header],
    websocket: bool,
) -> Result<Option<Arc<crate::proxy_credentials_v4::CredentialRequest>>, crate::ProxyCredentialError>
{
    let Some(runtime) = &inner.credentials else {
        if !association.is_empty() {
            return Err(crate::ProxyCredentialError::ScopeUnavailable);
        }
        return Ok(None);
    };
    let fields = headers
        .iter()
        .map(|header| (header.name.clone(), header.value.clone()))
        .collect::<Vec<_>>();
    runtime
        .request(
            ownership.and_then(|owner| owner.authentication),
            association,
            credentials,
            origin,
            path,
            &fields,
            websocket,
        )
        .await
        .map(|request| Some(Arc::new(request)))
}
struct CredentialCancellation(Option<tokio::task::JoinHandle<()>>);
impl CredentialCancellation {
    fn new(
        credential: &Option<Arc<crate::proxy_credentials_v4::CredentialRequest>>,
        original: &CancellationToken,
    ) -> Self {
        Self(credential.as_ref().map(|credential| {
            let stop = credential.cancellation();
            let original = original.clone();
            tokio::spawn(async move {
                stop.cancelled().await;
                original.cancel();
            })
        }))
    }
}
impl Drop for CredentialCancellation {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            worker.abort();
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialControlRequest {
    v: u8,
    operation_id: String,
    action: u8,
    surface_owner: String,
    #[serde(default)]
    credential_context: Option<String>,
    #[serde(default)]
    content_origin: Option<String>,
}
#[derive(Debug, Serialize)]
struct CredentialControlResponse<'a> {
    v: u8,
    operation_id: &'a str,
    action: u8,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_invalidated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<WireError<'a>>,
}
fn surface_id(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut id = [0; 16];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        id[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (id != [0; 16]).then_some(id)
}
async fn serve_credential_control(
    inner: &Inner,
    stream: &dyn ByteStream,
    request_id: &str,
    body: &[u8],
    ownership: Option<&Arc<ProxyNativeOwnership>>,
    cancellation: &CancellationToken,
) -> Result<(), ProxyServerError> {
    let control: CredentialControlRequest =
        match crate::proxy_wire::decode("ProxyCredentialControlRequest", body) {
            Ok(control) => control,
            Err(_) => {
                write_http_error(
                    stream,
                    request_id,
                    "credential_control_invalid",
                    cancellation,
                )
                .await;
                return Ok(());
            }
        };
    let surface = surface_id(&control.surface_owner);
    if control.v != WIRE_VERSION
        || surface.is_none()
        || surface_id(&control.operation_id).is_none()
        || !(1..=3).contains(&control.action)
        || (control.action == 1
            && (control.content_origin.is_none() || control.credential_context.is_some()))
        || (control.action != 1
            && (control.credential_context.is_none() || control.content_origin.is_some()))
    {
        write_http_error(
            stream,
            request_id,
            "credential_control_invalid",
            cancellation,
        )
        .await;
        return Ok(());
    }
    let outcome = match (
        inner.credentials.as_ref(),
        ownership.and_then(|owner| owner.authentication),
    ) {
        (Some(runtime), Some(authentication)) => {
            runtime
                .control(
                    authentication,
                    surface.expect("validated surface"),
                    &control.operation_id,
                    control.action,
                    control.credential_context.as_deref().unwrap_or(""),
                    control.content_origin.as_deref().unwrap_or(""),
                )
                .await
        }
        _ => Err(crate::ProxyCredentialError::ScopeUnavailable),
    };
    let response = match outcome {
        Ok(outcome) => CredentialControlResponse {
            v: WIRE_VERSION,
            operation_id: &control.operation_id,
            action: control.action,
            ok: outcome.error.is_none(),
            credential_context: outcome.context,
            server_invalidated: outcome.invalidated.then_some(true),
            error: outcome.error.map(|error| WireError {
                code: match error {
                    crate::ProxyCredentialError::UpdateFailed => "credential_update_failed",
                    _ => "credential_scope_unavailable",
                },
                message: "proxy operation failed",
            }),
        },
        Err(error) => CredentialControlResponse {
            v: WIRE_VERSION,
            operation_id: &control.operation_id,
            action: control.action,
            ok: false,
            credential_context: None,
            server_invalidated: None,
            error: Some(WireError {
                code: match error {
                    crate::ProxyCredentialError::OperationConflict => {
                        "credential_operation_conflict"
                    }
                    crate::ProxyCredentialError::UpdateFailed => "credential_update_failed",
                    _ => "credential_scope_unavailable",
                },
                message: "proxy operation failed",
            }),
        },
    };
    let bytes = crate::proxy_wire::encode("ProxyCredentialControlResponse", &response)
        .map_err(|_| ProxyServerError::OperationFailed)?;
    write_metadata(
        stream,
        &HttpResponseMeta {
            v: WIRE_VERSION,
            request_id,
            ok: true,
            status: Some(200),
            headers: vec![
                HeaderOutput {
                    name: "content-type".to_owned(),
                    value: "application/cbor".to_owned(),
                },
                HeaderOutput {
                    name: "cache-control".to_owned(),
                    value: "no-store, no-transform".to_owned(),
                },
            ],
            error: None,
        },
        cancellation,
    )
    .await?;
    write_all(
        stream,
        Bytes::from((bytes.len() as u32).to_be_bytes().to_vec()),
        cancellation,
    )
    .await?;
    write_all(stream, Bytes::from(bytes), cancellation).await?;
    write_body_end(stream, Vec::new(), cancellation).await
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

async fn read_metadata<T: DeserializeOwned + ProxyDecode>(
    reader: &mut ProxyReader<'_>,
    maximum: usize,
    cancellation: &CancellationToken,
) -> Result<T, ProxyServerError> {
    let mut header = reader.exact(4, cancellation).await?;
    let length = header.get_u32() as usize;
    if length > maximum {
        return Err(ProxyServerError::OperationFailed);
    }
    crate::proxy_wire::decode(T::SCHEMA, &reader.exact(length, cancellation).await?)
        .map_err(|_| ProxyServerError::OperationFailed)
}

async fn write_all(
    stream: &dyn ByteStream,
    mut payload: Bytes,
    cancellation: &CancellationToken,
) -> Result<(), ProxyServerError> {
    while !payload.is_empty() {
        let count = tokio::select! {
            biased;
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

async fn write_metadata(
    stream: &dyn ByteStream,
    value: &(impl Serialize + ProxyEncode),
    cancellation: &CancellationToken,
) -> Result<(), ProxyServerError> {
    let payload = crate::proxy_wire::encode(value.schema(), value)
        .map_err(|_| ProxyServerError::OperationFailed)?;
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
) -> Result<(Vec<u8>, Vec<HeaderOutput>), ProxyServerError> {
    let mut body = Vec::new();
    loop {
        let mut header = reader.exact(4, cancellation).await?;
        let length = header.get_u32() as usize;
        if length == 0 {
            let end: BodyEnd = read_metadata(reader, config.max_metadata, cancellation).await?;
            return Ok((body, end.trailers));
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

#[cfg(test)]
async fn serve_http(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
) -> Result<(), ProxyServerError> {
    serve_http_owned(inner, stream, cancellation, None).await
}
async fn serve_http_owned(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
    ownership: Option<Arc<ProxyNativeOwnership>>,
) -> Result<(), ProxyServerError> {
    let started = Instant::now();
    let (deadline, mut updates) = watch::channel(started + inner.config.max_timeout);
    let request = serve_http_request(
        inner,
        stream,
        cancellation.clone(),
        started,
        &deadline,
        ownership,
    );
    tokio::pin!(request);
    loop {
        let current = *updates.borrow_and_update();
        if Instant::now() >= current {
            return Err(ProxyServerError::OperationFailed);
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(ProxyServerError::Closed),
            result = &mut request => return result,
            _ = updates.changed() => {},
            _ = tokio::time::sleep_until(current) => return Err(ProxyServerError::OperationFailed),
        }
    }
}

async fn serve_http_request(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
    started: Instant,
    deadline_updates: &watch::Sender<Instant>,
    ownership: Option<Arc<ProxyNativeOwnership>>,
) -> Result<(), ProxyServerError> {
    let mut reader = ProxyReader::new(stream);
    let meta: HttpRequestMeta =
        match read_metadata(&mut reader, inner.config.max_metadata, &cancellation).await {
            Ok(meta) => meta,
            Err(_) => {
                write_http_error(stream, "unknown", "invalid_request_meta", &cancellation).await;
                return Ok(());
            }
        };
    let request_id = meta.request_id.trim();
    let Some(path) = normalize_path(&meta.path) else {
        write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
        return Ok(());
    };
    let Ok(method) = Method::from_bytes(meta.method.as_bytes()) else {
        write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
        return Ok(());
    };
    if meta.v != WIRE_VERSION || request_id.is_empty() || method == Method::CONNECT {
        write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
        return Ok(());
    }
    let credential = if path == CREDENTIAL_CONTROL_PATH {
        None
    } else {
        match credential_request(
            inner,
            ownership.as_ref(),
            &meta.credential_context,
            &meta.credentials,
            &meta.request_origin,
            &path,
            &meta.headers,
            false,
        )
        .await
        {
            Ok(credential) => credential,
            Err(_) => {
                write_http_error(
                    stream,
                    request_id,
                    "credential_scope_unavailable",
                    &cancellation,
                )
                .await;
                return Ok(());
            }
        }
    };
    let _credential_stop = CredentialCancellation::new(&credential, &cancellation);
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
    deadline_updates.send_replace(deadline);
    if Instant::now() >= deadline {
        return Err(ProxyServerError::OperationFailed);
    }
    {
        let facts = match validate_structured_headers(&meta.headers) {
            Ok(facts) => facts,
            Err(_) => {
                write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
                return Ok(());
            }
        };
        // The structured body is already delimited. Transfer codings belong
        // to the prior ingress parser and cannot be interpreted a second time
        // by this native HTTP adapter.
        if facts.transfer_encoding {
            write_http_error(stream, request_id, "invalid_request_meta", &cancellation).await;
            return Ok(());
        }
        let Ok(_http_permit) = inner.http_permits.clone().try_acquire_owned() else {
            write_http_error(stream, request_id, "resource_exhausted", &cancellation).await;
            return Ok(());
        };
        let event_requested = meta.headers.iter().any(|field| {
            field.name.eq_ignore_ascii_case("accept")
                && field.value.split(',').any(accepts_event_stream)
        });
        let mut event_permit = if event_requested {
            match inner.event_permits.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    write_http_error(stream, request_id, "resource_exhausted", &cancellation).await;
                    return Ok(());
                }
            }
        } else {
            None
        };
        let (body, input_trailers) = match read_body(&mut reader, &inner.config, &cancellation)
            .await
        {
            Ok(body) => body,
            Err(_) => {
                write_http_error(stream, request_id, "request_body_invalid", &cancellation).await;
                return Ok(());
            }
        };
        if facts
            .content_length
            .is_some_and(|length| length != body.len() as u64)
        {
            write_http_error(stream, request_id, "request_body_invalid", &cancellation).await;
            return Ok(());
        }
        let trailers = match request_trailers(input_trailers, &inner.config, &facts) {
            Ok(trailers) => trailers,
            Err(_) => {
                write_http_error(stream, request_id, "request_body_invalid", &cancellation).await;
                return Ok(());
            }
        };
        if !reader.buffered.is_empty() {
            write_http_error(stream, request_id, "request_body_invalid", &cancellation).await;
            return Ok(());
        }
        if path == CREDENTIAL_CONTROL_PATH {
            if method != Method::POST || body.len() > 8192 || trailers.is_some() {
                write_http_error(
                    stream,
                    request_id,
                    "credential_control_invalid",
                    &cancellation,
                )
                .await;
                return Ok(());
            }
            return serve_credential_control(
                inner,
                stream,
                request_id,
                &body,
                ownership.as_ref(),
                &cancellation,
            )
            .await;
        }
        let work = async {
            let is_head = method == Method::HEAD;
            // Authority is fixed by configuration; submit the validated origin-form
            // target directly so URL resolution cannot rewrite an authorized route.
            let target = &inner.config.upstream;
            let uri: Uri = path
                .parse()
                .map_err(|_| ProxyServerError::OperationFailed)?;
            let mut request = Request::builder()
                .method(method)
                .uri(uri)
                .body(ProxyRequestBody {
                    data: Some(Bytes::from(body)),
                    trailers,
                })
                .map_err(|_| ProxyServerError::OperationFailed)?;
            if let Some(trailers) = &request.body().trailers {
                let names = trailers
                    .keys()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let value = header::HeaderValue::from_str(&names)
                    .map_err(|_| ProxyServerError::OperationFailed)?;
                request.headers_mut().insert(header::TRAILER, value);
            }
            let authority = target[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
            request.headers_mut().insert(
                header::HOST,
                authority
                    .parse()
                    .map_err(|_| ProxyServerError::OperationFailed)?,
            );
            let mut request_headers = filter_request_headers(&meta.headers, &inner.config, &facts);
            if credential.is_some() {
                request_headers
                    .retain(|field| field.name != "cookie" && field.name != "authorization");
            }
            if let Some(origin) = &external_origin {
                let expected = origin.origin().ascii_serialization();
                if request_headers.iter().any(|header| {
                    header.name == "origin"
                        && validate_external_origin(&header.value)
                            .is_none_or(|value| value.origin().ascii_serialization() != expected)
                }) {
                    write_http_error(stream, request_id, "invalid_request_meta", &cancellation)
                        .await;
                    return Ok(());
                }
            }
            for header in request_headers {
                let name = header::HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|_| ProxyServerError::OperationFailed)?;
                let value = header::HeaderValue::from_bytes(&header_value_bytes(&header.value)?)
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
            if let Some(credential) = &credential {
                credential.check().map_err(|_| ProxyServerError::Closed)?;
                for (name, value) in &credential.headers {
                    let name = header::HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| ProxyServerError::OperationFailed)?;
                    let value = header::HeaderValue::from_bytes(value.as_bytes())
                        .map_err(|_| ProxyServerError::OperationFailed)?;
                    request.headers_mut().append(name, value);
                }
            }
            let (response, connection_task) =
                match send_http_request(inner, request, deadline, &cancellation, ownership.clone())
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
                        write_http_error(
                            stream,
                            request_id,
                            "upstream_request_failed",
                            &cancellation,
                        )
                        .await;
                        return Ok(());
                    }
                };
            let (parts, mut body) = response.into_parts();
            let response_facts = match validate_native_headers(&parts.headers) {
                Ok(facts) if !parts.status.is_informational() => facts,
                _ => {
                    connection_task.abort();
                    write_http_error(stream, request_id, "upstream_request_failed", &cancellation)
                        .await;
                    return Ok(());
                }
            };
            let no_body = is_head || matches!(parts.status.as_u16(), 204 | 205 | 304);
            let persistent = event_requested
                && !no_body
                && parts
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(is_event_stream);
            if persistent {
                renew_event_deadline(deadline_updates, inner.config.event_idle_timeout)?;
            } else {
                drop(event_permit.take());
            }
            if !is_head
                && matches!(parts.status.as_u16(), 204 | 205)
                && response_facts
                    .content_length
                    .is_some_and(|length| length != 0)
            {
                connection_task.abort();
                write_http_error(stream, request_id, "upstream_request_failed", &cancellation)
                    .await;
                return Ok(());
            }
            if !no_body
                && !persistent
                && response_facts
                    .content_length
                    .is_some_and(|length| length > inner.config.max_body as u64)
            {
                connection_task.abort();
                write_http_error(stream, request_id, "response_body_too_large", &cancellation)
                    .await;
                return Ok(());
            }
            let status = parts.status.as_u16();
            // Coded bytes must never outlive their representation label. A hop
            // nomination or local filter cannot turn them into identity content.
            if parts.headers.contains_key(header::CONTENT_ENCODING)
                && (response_facts.connection.contains("content-encoding")
                    || inner
                        .config
                        .blocked_response_headers
                        .contains("content-encoding"))
            {
                connection_task.abort();
                write_http_error(stream, request_id, "upstream_request_failed", &cancellation)
                    .await;
                return Ok(());
            }
            if let Some(credential) = &credential
                && credential.receive_cookies(&parts.headers, &path).is_err()
            {
                connection_task.abort();
                write_http_error(
                    stream,
                    request_id,
                    "credential_update_failed",
                    &cancellation,
                )
                .await;
                return Ok(());
            }
            let mut headers =
                filter_response_headers(&parts.headers, &inner.config, &response_facts);
            if credential.is_some() {
                headers.retain(|field| {
                    field.name != "cache-control"
                        && (!credential
                            .as_ref()
                            .is_some_and(|credential| credential.managed())
                            || field.name != "set-cookie")
                });
                headers.push(HeaderOutput {
                    name: "cache-control".to_owned(),
                    value: "no-store, no-transform".to_owned(),
                });
            }
            let result = async {
                write_metadata(
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
                let mut remaining = if no_body {
                    None
                } else {
                    response_facts.content_length
                };
                let mut terminal_fields = Vec::new();
                while let Some(frame) = tokio::select! {
                    _ = cancellation.cancelled() => return Err(ProxyServerError::Closed),
                    frame = body.frame() => frame,
                } {
                    let frame = frame.map_err(|_| ProxyServerError::OperationFailed)?;
                    let Some(chunk) = frame.data_ref() else {
                        if let Some(trailers) = frame.trailers_ref() {
                            // Preserve the native terminal as a separate bounded map.
                            validate_native_trailers(trailers, &response_facts)?;
                            terminal_fields.extend(filter_response_headers(
                                trailers,
                                &inner.config,
                                &response_facts,
                            ));
                        }
                        continue;
                    };
                    if no_body && !chunk.is_empty() {
                        return Err(ProxyServerError::OperationFailed);
                    }
                    if let Some(left) = &mut remaining {
                        *left = left
                            .checked_sub(chunk.len() as u64)
                            .ok_or(ProxyServerError::OperationFailed)?;
                    }
                    if !persistent {
                        total = total
                            .checked_add(chunk.len())
                            .ok_or(ProxyServerError::OperationFailed)?;
                        if total > inner.config.max_body {
                            return Err(ProxyServerError::OperationFailed);
                        }
                    } else if !chunk.is_empty() {
                        renew_event_deadline(deadline_updates, inner.config.event_idle_timeout)?;
                    }
                    for payload in chunk.chunks(inner.config.max_chunk) {
                        if Instant::now() >= *deadline_updates.borrow() {
                            return Err(ProxyServerError::OperationFailed);
                        }
                        write_chunk(stream, payload, &cancellation).await?;
                        if persistent {
                            renew_event_deadline(
                                deadline_updates,
                                inner.config.event_idle_timeout,
                            )?;
                        }
                    }
                }
                if remaining.is_some_and(|left| left != 0) {
                    return Err(ProxyServerError::OperationFailed);
                }
                write_body_end(stream, terminal_fields, &cancellation).await
            }
            .await;
            connection_task.abort();
            result
        };
        tokio::pin!(work);
        // A write FIN is valid after the terminal. A reset or additional bytes
        // cancel the original upstream even if an event response is idle.
        tokio::select! {
            biased;
            result = &mut work => result,
            next = stream.read() => match next {
                Ok(None) => work.await,
                _ => Err(ProxyServerError::OperationFailed),
            },
        }
    }
}

fn renew_event_deadline(
    deadline: &watch::Sender<Instant>,
    idle: Duration,
) -> Result<(), ProxyServerError> {
    let now = Instant::now();
    if now >= *deadline.borrow() {
        return Err(ProxyServerError::OperationFailed);
    }
    deadline.send_replace(now + idle);
    Ok(())
}

fn is_event_stream(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}
fn accepts_event_stream(value: &str) -> bool {
    is_event_stream(value)
        && !value.split(';').skip(1).any(|parameter| {
            parameter
                .trim()
                .split_once('=')
                .is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("q")
                        && value.trim().parse::<f32>().map_or(true, |value| {
                            !value.is_finite() || value <= 0.0 || value > 1.0
                        })
                })
        })
}

#[derive(Clone, Copy, Debug)]
enum HttpRequestFailure {
    Closed,
    Timeout,
    Dial,
    Request,
}

enum HttpIo {
    Plain(ProxySocket),
    Tls(Box<tokio_rustls::client::TlsStream<ProxySocket>>),
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

// The native HTTP encoder receives data and trailers as distinct frames. A
// trailer-bearing body has no exact size hint, so HTTP/1 generates chunked
// framing even for an empty body; input Content-Length is only an assertion.
struct ProxyRequestBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Body for ProxyRequestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(data) = self.data.take().filter(|data| !data.is_empty()) {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        Poll::Ready(
            self.trailers
                .take()
                .map(|trailers| Ok(Frame::trailers(trailers))),
        )
    }

    fn is_end_stream(&self) -> bool {
        self.data.as_ref().is_none_or(Bytes::is_empty) && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        if self.trailers.is_some() {
            SizeHint::default()
        } else {
            SizeHint::with_exact(self.data.as_ref().map_or(0, |data| data.len() as u64))
        }
    }
}

async fn send_http_request(
    inner: &Inner,
    request: Request<ProxyRequestBody>,
    deadline: Instant,
    cancellation: &CancellationToken,
    ownership: Option<Arc<ProxyNativeOwnership>>,
) -> Result<
    (
        hyper::Response<Incoming>,
        tokio_util::task::AbortOnDropHandle<()>,
    ),
    HttpRequestFailure,
> {
    let tcp = inner
        .config
        .network
        .connect_owned(deadline, cancellation, ownership)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::Interrupted => HttpRequestFailure::Closed,
            std::io::ErrorKind::TimedOut => HttpRequestFailure::Timeout,
            _ => HttpRequestFailure::Dial,
        })?;
    let io = if inner.config.upstream.scheme() == "https" {
        let server_name = ServerName::try_from(inner.config.network.host.clone())
            .map_err(|_| HttpRequestFailure::Dial)?;
        let tls = TlsConnector::from(
            crate::proxy_network::client_tls(inner.config.upstream_trust_roots_der.clone())
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
    let _ = write_metadata(
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
    let _ = write_body_end(stream, Vec::new(), cancellation).await;
}

#[cfg(test)]
async fn serve_websocket(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
) -> Result<(), ProxyServerError> {
    serve_websocket_owned(inner, stream, cancellation, None).await
}
async fn serve_websocket_owned(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
    ownership: Option<Arc<ProxyNativeOwnership>>,
) -> Result<(), ProxyServerError> {
    serve_websocket_owned_with_establishment_timeout(
        inner,
        stream,
        cancellation,
        inner.config.websocket_establish_timeout,
        ownership,
    )
    .await
}

#[cfg(test)]
async fn serve_websocket_with_establishment_timeout(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
    establishment_timeout: Duration,
) -> Result<(), ProxyServerError> {
    serve_websocket_owned_with_establishment_timeout(
        inner,
        stream,
        cancellation,
        establishment_timeout,
        None,
    )
    .await
}
async fn serve_websocket_owned_with_establishment_timeout(
    inner: &Inner,
    stream: &dyn ByteStream,
    cancellation: CancellationToken,
    establishment_timeout: Duration,
    ownership: Option<Arc<ProxyNativeOwnership>>,
) -> Result<(), ProxyServerError> {
    let mut reader = ProxyReader::new(stream);
    let open: WebSocketOpen =
        match read_metadata(&mut reader, inner.config.max_metadata, &cancellation).await {
            Ok(open) => open,
            Err(_) => {
                write_websocket_error(stream, "unknown", "invalid_ws_open_meta", &cancellation)
                    .await;
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
    let facts = match validate_structured_headers(&open.headers) {
        Ok(facts)
            if facts.content_length.is_none_or(|length| length == 0)
                && !facts.transfer_encoding =>
        {
            facts
        }
        _ => {
            write_websocket_error(stream, conn_id, "invalid_ws_open_meta", &cancellation).await;
            return Ok(());
        }
    };
    let credential = match credential_request(
        inner,
        ownership.as_ref(),
        &open.credential_context,
        &open.credentials,
        &open.request_origin,
        &path,
        &open.headers,
        true,
    )
    .await
    {
        Ok(credential) => credential,
        Err(_) => {
            write_websocket_error(
                stream,
                conn_id,
                "credential_scope_unavailable",
                &cancellation,
            )
            .await;
            return Ok(());
        }
    };
    let _credential_stop = CredentialCancellation::new(&credential, &cancellation);
    let mut target = inner.config.upstream.clone();
    target
        .set_scheme(if target.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| ProxyServerError::OperationFailed)?;
    let request_target = format!("{}{}", &target[..url::Position::BeforePath], path);
    let mut request = request_target
        .into_client_request()
        .map_err(|_| ProxyServerError::OperationFailed)?;
    for header in filter_websocket_headers(&open.headers, &inner.config, &facts) {
        let name: tungstenite::http::HeaderName = header
            .name
            .parse()
            .map_err(|_| ProxyServerError::OperationFailed)?;
        let value = tungstenite::http::HeaderValue::from_bytes(&header_value_bytes(&header.value)?)
            .map_err(|_| ProxyServerError::OperationFailed)?;
        request.headers_mut().append(name, value);
    }
    if let Some(credential) = &credential {
        credential.check().map_err(|_| ProxyServerError::Closed)?;
        for (name, value) in &credential.headers {
            request.headers_mut().append(
                header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| ProxyServerError::OperationFailed)?,
                header::HeaderValue::from_bytes(value.as_bytes())
                    .map_err(|_| ProxyServerError::OperationFailed)?,
            );
        }
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
    let establishment_deadline = Instant::now() + establishment_timeout;
    let tcp = await_websocket_establishment(
        establishment_deadline,
        &cancellation,
        inner
            .config
            .network
            .connect_owned(establishment_deadline, &cancellation, ownership),
    )
    .await?
    .map_err(|_| ProxyServerError::OperationFailed)?;
    if target.scheme() == "wss" {
        let server_name = ServerName::try_from(inner.config.network.host.clone())
            .map_err(|_| ProxyServerError::OperationFailed)?;
        let tls = TlsConnector::from(
            crate::proxy_network::client_tls(inner.config.upstream_trust_roots_der.clone())
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
        return relay_connected_websocket(
            inner,
            stream,
            reader,
            cancellation,
            conn_id,
            connected,
            credential,
            &path,
        )
        .await;
    }
    let connected = await_websocket_establishment(
        establishment_deadline,
        &cancellation,
        client_async_with_config(request, tcp, Some(websocket_config)),
    )
    .await?;
    relay_connected_websocket(
        inner,
        stream,
        reader,
        cancellation,
        conn_id,
        connected,
        credential,
        &path,
    )
    .await
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

#[expect(
    clippy::too_many_arguments,
    reason = "Proxy forwarding retains original socket ownership and credential binding with the request context."
)]
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
    credential: Option<Arc<crate::proxy_credentials_v4::CredentialRequest>>,
    path: &str,
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
    if let Some(credential) = &credential
        && credential
            .receive_cookies(response.headers(), path)
            .is_err()
    {
        write_websocket_error(stream, conn_id, "credential_update_failed", &cancellation).await;
        return Ok(());
    }
    let protocol = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    write_metadata(
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
    let mut websocket = Some(websocket);
    let relay = async {
        let mut downstream_close_sent = false;
        let mut upstream_close_received = false;
        loop {
            // Keep this exact read across upstream messages: a partial frame
            // may already have consumed its header from the original reader.
            let downstream_frame =
                read_websocket_frame(&mut reader, inner.config.max_websocket_frame, &cancellation);
            tokio::pin!(downstream_frame);
            let (operation, payload) = loop {
                tokio::select! {
                upstream_message = async { websocket.as_mut().expect("original native WebSocket").next().await }, if !upstream_close_received => {
                    let message = upstream_message.ok_or(ProxyServerError::OperationFailed)?;
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
                        upstream_close_received = true;
                        // Tungstenite queued the native Close reply while reading.
                        // Flush it once; sending another Close is invalid here.
                        websocket.as_mut().expect("original native WebSocket").flush().await
                            .map_err(|_| ProxyServerError::OperationFailed)?;
                        drop(websocket.take());
                        if downstream_close_sent {
                            return Ok(());
                        }
                    }
                }
                frame = &mut downstream_frame, if !downstream_close_sent => break frame?,
                }
            };
            if upstream_close_received {
                // The native socket has completed its Close exchange. Retain
                // this original reader until the downstream actually replies;
                // earlier in-flight data cannot be sent on the closed socket.
                if operation == 8 {
                    decode_websocket_close(&payload)?;
                    return Ok(());
                }
                continue;
            }
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
            websocket
                .as_mut()
                .expect("original native WebSocket")
                .send(message)
                .await
                .map_err(|_| ProxyServerError::OperationFailed)?;
            if operation == 8 {
                // Keep the carrier stream alive until upstream acknowledges the
                // close. This preserves normal FIN semantics for the peer.
                downstream_close_sent = true;
            }
        }
    };
    // Cancellation drops the original I/O futures and native socket together;
    // no detached relay can outlive the caller's operation ownership.
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProxyServerError::Closed),
        result = relay => result,
    }
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
    let _ = write_metadata(
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

// This is an origin-form transport boundary, not a subtree routing policy.
// Preserve legal encoded bytes so authorization and upstream serialization agree.
fn normalize_path(raw: &str) -> Option<String> {
    if !raw.starts_with('/')
        || raw.contains(['\\', '#'])
        || raw.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f)
    {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] == b'%' {
            decode_hex(*bytes.get(offset + 1)?)?;
            decode_hex(*bytes.get(offset + 2)?)?;
            offset += 3;
        } else {
            offset += 1;
        }
    }
    let parsed: Uri = raw.parse().ok()?;
    if parsed.scheme().is_some()
        || parsed.authority().is_some()
        || parsed.path_and_query()?.as_str() != raw
    {
        return None;
    }
    Some(raw.to_owned())
}

fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
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

// The current string boundary uses an exact Latin-1/ByteString projection.
// Native field bytes are never interpreted as UTF-8, normalized or discarded.
fn header_value_bytes(value: &str) -> Result<Vec<u8>, ProxyServerError> {
    value
        .chars()
        .map(|character| {
            u8::try_from(character as u32)
                .ok()
                .filter(|byte| valid_field_octet(*byte))
                .ok_or(ProxyServerError::OperationFailed)
        })
        .collect()
}

fn valid_field_octet(byte: u8) -> bool {
    byte == b'\t' || (byte >= b' ' && byte != 0x7f)
}

fn trim_field_ows(value: &[u8]) -> &[u8] {
    value.trim_ascii_start().trim_ascii_end()
}

#[derive(Default)]
struct HeaderFacts {
    content_length: Option<u64>,
    transfer_encoding: bool,
    connection: HashSet<String>,
    singletons: HashMap<&'static str, Vec<u8>>,
}

impl HeaderFacts {
    fn observe(&mut self, name: &str, value: &[u8]) -> Result<(), ProxyServerError> {
        if !valid_header_name(name) || !value.iter().copied().all(valid_field_octet) {
            return Err(ProxyServerError::OperationFailed);
        }
        let name = name.to_ascii_lowercase();
        match name.as_str() {
            "content-length" => {
                for item in value.split(|byte| *byte == b',') {
                    let item = trim_field_ows(item);
                    if item.is_empty() || !item.iter().all(u8::is_ascii_digit) {
                        return Err(ProxyServerError::OperationFailed);
                    }
                    let length = item
                        .iter()
                        .try_fold(0u64, |length, digit| {
                            length.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
                        })
                        .ok_or(ProxyServerError::OperationFailed)?;
                    if self
                        .content_length
                        .is_some_and(|previous| previous != length)
                    {
                        return Err(ProxyServerError::OperationFailed);
                    }
                    self.content_length = Some(length);
                }
            }
            "transfer-encoding" => {
                // Only the transfer coding actually removed by this HTTP/1
                // adapter can describe its content-coded representation.
                if self.transfer_encoding || !trim_field_ows(value).eq_ignore_ascii_case(b"chunked")
                {
                    return Err(ProxyServerError::OperationFailed);
                }
                self.transfer_encoding = true;
            }
            "connection" => {
                for item in value.split(|byte| *byte == b',') {
                    let item = std::str::from_utf8(trim_field_ows(item))
                        .map_err(|_| ProxyServerError::OperationFailed)?;
                    if !valid_header_name(item) {
                        return Err(ProxyServerError::OperationFailed);
                    }
                    self.connection.insert(item.to_ascii_lowercase());
                }
            }
            _ => {}
        }
        const SINGLETONS: &[&str] = &[
            "host",
            "origin",
            "authorization",
            "proxy-authorization",
            "content-type",
            "content-range",
            "etag",
            "last-modified",
            "location",
        ];
        if let Some(&singleton) = SINGLETONS.iter().find(|singleton| **singleton == name) {
            let value = trim_field_ows(value);
            if let Some(previous) = self.singletons.get(singleton) {
                if previous != value {
                    return Err(ProxyServerError::OperationFailed);
                }
            } else {
                self.singletons.insert(singleton, value.to_vec());
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Self, ProxyServerError> {
        if self.transfer_encoding && self.content_length.is_some() {
            return Err(ProxyServerError::OperationFailed);
        }
        self.singletons.clear();
        Ok(self)
    }
}

fn validate_structured_headers(headers: &[Header]) -> Result<HeaderFacts, ProxyServerError> {
    let mut facts = HeaderFacts::default();
    for header in headers {
        facts.observe(&header.name, &header_value_bytes(&header.value)?)?;
    }
    facts.finish()
}

fn validate_native_headers(headers: &HeaderMap) -> Result<HeaderFacts, ProxyServerError> {
    let mut facts = HeaderFacts::default();
    for (name, value) in headers {
        facts.observe(name.as_str(), value.as_bytes())?;
    }
    facts.finish()
}

fn validate_native_trailers(
    headers: &HeaderMap,
    initial: &HeaderFacts,
) -> Result<(), ProxyServerError> {
    let facts = validate_native_headers(headers)?;
    if !facts.connection.is_empty()
        || headers.keys().any(|name| {
            FORBIDDEN_HEADERS.contains(&name.as_str())
                || matches!(
                    name.as_str(),
                    "content-length"
                        | "trailer"
                        | "content-encoding"
                        | "content-range"
                        | "content-type"
                        | "cookie"
                        | "origin"
                        | "location"
                        | "www-authenticate"
                )
        })
        || headers
            .keys()
            .any(|name| initial.connection.contains(name.as_str()))
    {
        return Err(ProxyServerError::OperationFailed);
    }
    Ok(())
}

fn request_trailers(
    fields: Vec<HeaderOutput>,
    config: &Config,
    original: &HeaderFacts,
) -> Result<Option<HeaderMap>, ProxyServerError> {
    let mut native = HeaderMap::new();
    for field in fields {
        let name = header::HeaderName::from_bytes(field.name.as_bytes())
            .map_err(|_| ProxyServerError::OperationFailed)?;
        let value = header::HeaderValue::from_bytes(&header_value_bytes(&field.value)?)
            .map_err(|_| ProxyServerError::OperationFailed)?;
        native.append(name, value);
    }
    validate_native_trailers(&native, original)?;
    let allowed: Vec<_> = native
        .keys()
        .filter(|name| {
            !REQUEST_HEADERS.contains(&name.as_str())
                && !config.request_headers.contains(name.as_str())
        })
        .cloned()
        .collect();
    for name in allowed {
        native.remove(name);
    }
    Ok((!native.is_empty()).then_some(native))
}

fn filter_request_headers(
    headers: &[Header],
    config: &Config,
    facts: &HeaderFacts,
) -> Vec<HeaderOutput> {
    let mut result = filter_headers(
        headers,
        REQUEST_HEADERS,
        &config.request_headers,
        &facts.connection,
    );
    for header in &mut result {
        if header.name == "cookie" {
            header.value = filter_cookies(&header.value, config);
        }
    }
    result.retain(|header| !header.value.is_empty());
    result.retain(|header| header.name != "x-forwarded-proto" && header.name != "authorization");
    // The original CL remains an assertion in facts, while the native HTTP
    // adapter chooses fresh framing from the actual admitted body.
    result.retain(|header| header.name != "content-length");
    result
}

fn filter_response_headers(
    headers: &HeaderMap,
    config: &Config,
    facts: &HeaderFacts,
) -> Vec<HeaderOutput> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            let allowed = RESPONSE_HEADERS.contains(&name.as_str())
                || config.response_headers.contains(&name);
            (allowed
                && (name == "set-cookie" || !FORBIDDEN_HEADERS.contains(&name.as_str()))
                && !config.blocked_response_headers.contains(&name)
                && !facts.connection.contains(&name))
            .then(|| HeaderOutput {
                name,
                value: value
                    .as_bytes()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect(),
            })
        })
        .collect()
}

fn filter_websocket_headers(
    headers: &[Header],
    config: &Config,
    facts: &HeaderFacts,
) -> Vec<HeaderOutput> {
    filter_headers(
        headers,
        &["sec-websocket-protocol"],
        &config.websocket_headers,
        &facts.connection,
    )
    .into_iter()
    .filter(|header| {
        header.name != "content-length" && header.name != "cookie" && header.name != "authorization"
    })
    .collect()
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
            let name = header.name.to_ascii_lowercase();
            let allowed = base.contains(&name.as_str()) || extra.contains(&name);
            (allowed
                && valid_header_name(&name)
                && !FORBIDDEN_HEADERS.contains(&name.as_str())
                && !blocked.contains(&name))
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
            let part = part.trim_matches([' ', '\t']);
            let (name, _) = part.split_once('=')?;
            let name = name.trim_matches([' ', '\t']).to_ascii_lowercase();
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
    include!("proxy_credentials_v4_tests.rs");

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
        closed: AtomicBool,
        wait: Notify,
    }

    impl TestStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                reads: Mutex::new(VecDeque::from([Bytes::from(input)])),
                writes: Mutex::new(Vec::new()),
                reset: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                wait: Notify::new(),
            }
        }

        fn output(&self) -> Vec<u8> {
            self.writes.lock().expect("writes lock").clone()
        }

        fn push_input(&self, bytes: Bytes) {
            self.reads.lock().expect("reads lock").push_back(bytes);
            self.wait.notify_waiters();
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
            loop {
                let wake = self.wait.notified();
                tokio::pin!(wake);
                wake.as_mut().enable();
                if self.reset.load(Ordering::Acquire) {
                    return Err(SessionError::StreamReset);
                }
                if let Some(bytes) = self.reads.lock().expect("reads lock").pop_front() {
                    return Ok(Some(bytes));
                }
                if self.closed.load(Ordering::Acquire) {
                    return Ok(None);
                }
                wake.await;
            }
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
            self.wait.notify_waiters();
            Ok(())
        }
        async fn close(&self) -> Result<(), SessionError> {
            self.closed.store(true, Ordering::Release);
            self.wait.notify_waiters();
            Ok(())
        }
    }

    fn frame_metadata(mut value: serde_json::Value) -> Vec<u8> {
        let schema = if value.get("trailers").is_some() {
            "ProxyBodyEnd"
        } else if value.get("conn_id").is_some() {
            "ProxyWebSocketOpen"
        } else {
            "ProxyHTTPRequest"
        };
        let unknown = value
            .as_object_mut()
            .unwrap()
            .remove("unexpected")
            .is_some();
        let mut payload = crate::proxy_wire::encode(schema, &value).expect("encode metadata");
        if unknown {
            payload[0] += 1;
            payload.extend_from_slice(&[23, 0]);
        }
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(&payload);
        framed
    }

    fn body_end_frame() -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0];
        bytes.extend_from_slice(&frame_metadata(serde_json::json!({"v":2,"trailers":[]})));
        bytes
    }

    fn response_meta(output: &[u8]) -> serde_json::Value {
        let length = u32::from_be_bytes(output[..4].try_into().expect("response length")) as usize;
        crate::proxy_wire::decode_value("ProxyHTTPResponse", &output[4..4 + length])
            .or_else(|_| {
                crate::proxy_wire::decode_value("ProxyWebSocketResponse", &output[4..4 + length])
            })
            .expect("response metadata")
    }

    fn test_options(upstream: Url) -> ProxyServerOptions {
        ProxyServerOptions {
            upstream,
            upstream_origin: "http://127.0.0.1:8080".parse().expect("origin"),
            upstream_trust_roots_der: Vec::new(),
            allowed_upstream_hosts: vec!["127.0.0.1".into()],
            allowed_upstream_addresses: Vec::new(),
            allowed_origins: vec!["https://app.example".parse().expect("allowed origin")],
            max_concurrent_streams: 2,
            max_concurrent_http_streams: 0,
            max_concurrent_event_streams: 0,
            event_stream_idle_timeout: Duration::ZERO,
            max_metadata_bytes: 4096,
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
            credentials: None,
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
                frame_metadata(serde_json::json!({
                    "v": 2, "request_id": "stalled", "method": stage,
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

    fn event_request() -> Vec<u8> {
        let mut input = frame_metadata(serde_json::json!({
            "v":2, "request_id":"events", "method":"GET", "path":"/events",
            "headers":[{"name":"accept","value":"text/event-stream"}]
        }));
        input.extend_from_slice(&body_end_frame());
        input
    }

    #[tokio::test]
    async fn event_reset_cancels_native_work_without_waiting_for_idle_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = socket.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buffer[..n]);
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
            ready.send(()).unwrap();
            match socket.read(&mut buffer).await {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("native socket survived reset: {result:?}"),
            }
        });
        let server =
            ProxyServer::new(test_options(format!("http://{address}").parse().unwrap())).unwrap();
        let stream = Arc::new(TestStream::new(event_request()));
        let worker = stream.clone();
        let inner = server.inner.clone();
        let running =
            tokio::spawn(
                async move { serve_http(&inner, &worker, CancellationToken::new()).await },
            );
        waiting.await.unwrap();
        stream.reset().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), running)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), upstream)
            .await
            .unwrap()
            .unwrap();
        server.close().await;
    }

    #[tokio::test]
    async fn http_rejects_buffered_data_after_original_body_terminal_before_dial() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server =
            ProxyServer::new(test_options(format!("http://{address}").parse().unwrap())).unwrap();
        let mut input = event_request();
        input.push(1);
        let stream = Arc::new(TestStream::new(input));
        serve_http(&server.inner, &stream, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            response_meta(&stream.output())["error"]["code"],
            "request_body_invalid"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(5), listener.accept())
                .await
                .is_err()
        );
        server.close().await;
    }

    #[tokio::test]
    async fn event_stream_outlives_finite_limits_with_original_length_integrity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = socket.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buffer[..n]);
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: 104\r\nConnection: close, content-length\r\n\r\n").await.unwrap();
            for _ in 0..8 {
                socket.write_all(b"data: alive\n\n").await.unwrap();
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        });
        let mut options = test_options(format!("http://{address}").parse().unwrap());
        options.max_body_bytes = 16;
        options.default_http_request_timeout = Duration::from_millis(100);
        options.max_http_request_timeout = Duration::from_millis(100);
        options.event_stream_idle_timeout = Duration::from_secs(1);
        let server = ProxyServer::new(options).unwrap();
        let stream = Arc::new(TestStream::new(event_request()));
        serve_http(&server.inner, &stream, CancellationToken::new())
            .await
            .unwrap();
        let output = stream.output();
        assert_eq!(response_meta(&output)["ok"], true);
        let mut at = 4 + u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
        let mut total = 0;
        loop {
            let n = u32::from_be_bytes(output[at..at + 4].try_into().unwrap()) as usize;
            at += 4;
            if n == 0 {
                break;
            }
            total += n;
            at += n;
        }
        assert_eq!(total, 104);
        let n = u32::from_be_bytes(output[at..at + 4].try_into().unwrap()) as usize;
        assert!(
            crate::proxy_wire::decode_value("ProxyBodyEnd", &output[at + 4..at + 4 + n]).is_ok()
        );
        upstream.await.unwrap();
        server.close().await;
    }

    #[tokio::test]
    async fn event_capacity_preserves_finite_requests_and_idle_closes_native_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = socket.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buffer[..n]);
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
            ready.send(()).unwrap();
            let (mut finite, _) = listener.accept().await.unwrap();
            request.clear();
            while !request.ends_with(b"\r\n\r\n") {
                let n = finite.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buffer[..n]);
            }
            finite
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            assert_eq!(socket.read(&mut buffer).await.unwrap(), 0);
        });
        let mut options = test_options(format!("http://{address}").parse().unwrap());
        options.event_stream_idle_timeout = Duration::from_millis(250);
        options.max_concurrent_http_streams = 2;
        options.max_concurrent_event_streams = 1;
        let server = ProxyServer::new(options).unwrap();
        let stream = Arc::new(TestStream::new(event_request()));
        let inner = server.inner.clone();
        let running_stream = stream.clone();
        let running = tokio::spawn(async move {
            serve_http(&inner, &running_stream, CancellationToken::new()).await
        });
        waiting.await.unwrap();
        let rejected = Arc::new(TestStream::new(event_request()));
        serve_http(&server.inner, &rejected, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            response_meta(&rejected.output())["error"]["code"],
            "resource_exhausted"
        );
        let mut input = frame_metadata(
            serde_json::json!({"v":2,"request_id":"finite","method":"GET","path":"/","headers":[]}),
        );
        input.extend_from_slice(&body_end_frame());
        let finite = Arc::new(TestStream::new(input));
        serve_http(&server.inner, &finite, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(response_meta(&finite.output())["ok"], true);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), running)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(2), upstream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server.inner.event_permits.available_permits(), 1);
        assert_eq!(server.inner.http_permits.available_permits(), 2);
        server.close().await;
    }

    #[test]
    fn canonical_proxy_path_closes_policy_bypasses_before_upstream_use() {
        for raw in [
            "/safe/../admin?mode=raw",
            "/safe/./../admin",
            "/safe/%2e%2e/admin?mode=encoded",
            "/%61dmin",
            "/safe//child?mode=double",
            "/public/../api//items?q=%7euser",
            "/api?q=%2f%5c&x=+&x=%41",
            "/objects/a%2Fb/literal%25/a;b/%ff",
            "/api/a%20b?q=%2f",
            "/?",
            "/",
        ] {
            assert_eq!(normalize_path(raw).as_deref(), Some(raw), "{raw}");
        }
        for raw in [
            "/\\evil.example/admin",
            "/safe\\..\\admin",
            "/invalid%",
            "/invalid%2",
            "/invalid%zz",
            "/admin#fragment",
            "/a b",
            "/é",
        ] {
            assert!(normalize_path(raw).is_none(), "accepted unsafe path {raw}");
        }
    }

    #[test]
    fn structured_header_facts_reject_malformed_framing_and_preserve_equal_lengths() {
        let equal = vec![
            Header {
                name: "Content-Length".into(),
                value: "0005, 5".into(),
            },
            Header {
                name: "content-length".into(),
                value: "5".into(),
            },
            Header {
                name: "Connection".into(),
                value: "x-secret, content-length".into(),
            },
            Header {
                name: "X-Secret".into(),
                value: "é".into(),
            },
        ];
        let facts = validate_structured_headers(&equal).expect("equal content lengths");
        assert_eq!(facts.content_length, Some(5));
        assert!(facts.connection.contains("x-secret"));
        assert!(facts.connection.contains("content-length"));
        assert_eq!(header_value_bytes("é").unwrap(), vec![0xe9]);
        assert!(header_value_bytes("€").is_err());
        for headers in [
            vec![Header {
                name: "content-length".into(),
                value: "4,5".into(),
            }],
            vec![Header {
                name: "content-length".into(),
                value: "+5".into(),
            }],
            vec![Header {
                name: "content-length".into(),
                value: "18446744073709551616".into(),
            }],
            vec![Header {
                name: "transfer-encoding".into(),
                value: "gzip".into(),
            }],
            vec![Header {
                name: "connection".into(),
                value: "bad token".into(),
            }],
            vec![Header {
                name: "x-test".into(),
                value: "line\nfeed".into(),
            }],
        ] {
            assert!(validate_structured_headers(&headers).is_err());
        }
        assert!(
            validate_structured_headers(&[
                Header {
                    name: "transfer-encoding".into(),
                    value: "chunked".into()
                },
                Header {
                    name: "content-length".into(),
                    value: "5".into()
                },
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn http_proxy_delivers_native_request_and_response_trailers() {
        for body in ["", "hello"] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind upstream");
            let address = listener.local_addr().expect("address");
            let upstream = tokio::spawn(async move {
                let (mut socket, _) =
                    tokio::time::timeout(Duration::from_secs(3), listener.accept())
                        .await
                        .expect("request deadline")
                        .expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.ends_with(b"x-check: two\r\n\r\n") {
                    let n = socket.read(&mut buffer).await.expect("request bytes");
                    assert_ne!(n, 0);
                    request.extend_from_slice(&buffer[..n]);
                }
                let text = String::from_utf8(request).expect("ASCII request");
                assert!(
                    text.starts_with("POST //fixed/path? HTTP/1.1\r\n"),
                    "{text}"
                );
                assert!(
                    text.contains(&format!("host: localhost:{}\r\n", address.port())),
                    "{text}"
                );
                assert!(text.contains("transfer-encoding: chunked\r\n"), "{text}");
                assert!(text.contains("trailer: x-check\r\n"), "{text}");
                assert!(text.contains("x-check: one\r\nx-check: two\r\n"), "{text}");
                assert!(!text.contains("content-length:"), "{text}");
                socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Check\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\nX-Check: first\r\nX-Check: last\r\n\r\n").await.expect("response");
            });
            let mut options = test_options(
                format!("http://localhost:{}", address.port())
                    .parse()
                    .expect("URL"),
            );
            options.allowed_upstream_hosts = vec!["localhost".into()];
            options.allowed_upstream_addresses = vec!["127.0.0.1".into(), "::1".into()];
            options.extra_request_headers.push("x-check".into());
            options.extra_response_headers.push("x-check".into());
            let server = ProxyServer::new(options).expect("proxy");
            let mut input = frame_metadata(
                serde_json::json!({ "v":2, "request_id":"trailers", "method":"POST", "path":"//fixed/path?", "headers":[{"name":"content-length","value":body.len().to_string()}] }),
            );
            if !body.is_empty() {
                input.extend_from_slice(&(body.len() as u32).to_be_bytes());
                input.extend_from_slice(body.as_bytes());
            }
            input.extend_from_slice(&[0, 0, 0, 0]);
            input.extend_from_slice(&frame_metadata(serde_json::json!({"v":2,"trailers":[{"name":"x-check","value":"one"},{"name":"x-check","value":"two"}]})));
            let stream = Arc::new(TestStream::new(input));
            serve_http(&server.inner, &stream, CancellationToken::new())
                .await
                .expect("proxy HTTP");
            let output = stream.output();
            assert_eq!(response_meta(&output)["ok"], true);
            upstream.await.expect("upstream task");
            let mut at = 4 + u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
            loop {
                let n = u32::from_be_bytes(output[at..at + 4].try_into().unwrap()) as usize;
                at += 4;
                if n == 0 {
                    break;
                }
                at += n;
            }
            let n = u32::from_be_bytes(output[at..at + 4].try_into().unwrap()) as usize;
            let terminal =
                crate::proxy_wire::decode_value("ProxyBodyEnd", &output[at + 4..at + 4 + n])
                    .expect("terminal");
            assert_eq!(
                terminal["trailers"],
                serde_json::json!([{"name":"x-check","value":"first"},{"name":"x-check","value":"last"}])
            );
            server.close().await;
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
            assert!(
                request
                    .windows(b"x-visible: \xe9\r\n".len())
                    .any(|part| part == b"x-visible: \xe9\r\n")
            );
            assert!(
                request
                    .windows(b"x-visible: \xff\r\n".len())
                    .any(|part| part == b"x-visible: \xff\r\n")
            );
            let text = request
                .iter()
                .map(|byte| char::from(*byte))
                .collect::<String>()
                .to_ascii_lowercase();
            assert!(
                text.starts_with("post /public/../api//items?q=%7euser http/1.1\r\n"),
                "{text}"
            );
            assert!(text.contains(&format!("host: {address}\r\n")), "{text}");
            assert!(text.contains("x-forwarded-proto: https\r\n"), "{text}");
            assert!(text.contains("cookie: public=ok\r\n"), "{text}");
            assert!(text.contains("x-request-id: visible\r\n"), "{text}");
            assert!(!text.contains("authorization:"), "{text}");
            assert!(!text.contains("x-remove:"), "{text}");
            assert!(text.contains("content-length: 5\r\n"), "{text}");
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\nLocation: /hidden\r\nX-Visible: \xe9\r\nX-Visible: \xff\r\nETag: private\r\nSet-Cookie: secret=no\r\nConnection: close, etag\r\n\r\nworld").await.expect("write response");
        });

        let mut options = test_options(format!("http://{address}").parse().expect("upstream URL"));
        options
            .extra_request_headers
            .extend(["x-visible".into(), "x-remove".into()]);
        let server = ProxyServer::new(options).expect("proxy server");
        let stream = Arc::new(TestStream::new({
            let mut input = frame_metadata(serde_json::json!({
                "v": 2, "request_id": "request-1", "method": "POST",
                "path": "/public/../api//items?q=%7euser",
                "headers": [
                    {"name":"cookie", "value":"session=bad; private_key=no; public=ok"},
                    {"name":"authorization", "value":"Bearer secret"},
                    {"name":"x-request-id", "value":"visible"},
                    {"name":"content-length", "value":"0005, 5"},
                    {"name":"content-length", "value":"5"},
                    {"name":"connection", "value":"content-length, x-remove, x-forwarded-proto"},
                    {"name":"x-remove", "value":"hidden"},
                    {"name":"x-visible", "value":"é"},
                    {"name":"x-visible", "value":"ÿ"}
                ],
                "external_origin": "https://app.example", "timeout_ms": 1000
            }));
            input.extend_from_slice(&5u32.to_be_bytes());
            input.extend_from_slice(b"hello");
            input.extend_from_slice(&body_end_frame());
            input
        }));
        serve_http(&server.inner, &stream, CancellationToken::new())
            .await
            .expect("serve HTTP");
        upstream.await.expect("upstream task");

        let output = stream.output();
        let length = u32::from_be_bytes(output[..4].try_into().expect("response length")) as usize;
        let meta: serde_json::Value = response_meta(&output);
        assert_eq!(meta["status"], 200);
        assert_eq!(
            meta["headers"],
            serde_json::json!([
                {"name":"content-length", "value":"5"},
                {"name":"content-type", "value":"text/plain"},
                {"name":"x-visible", "value":"é"},
                {"name":"x-visible", "value":"ÿ"}
            ])
        );
        assert_eq!(
            &output[4 + length..],
            [
                &[0, 0, 0, 5, b'w', b'o', b'r', b'l', b'd'][..],
                &body_end_frame()
            ]
            .concat()
        );
    }

    #[tokio::test]
    #[expect(
        clippy::result_large_err,
        reason = "The WebSocket handshake callback returns the provider-owned HTTP error response unchanged."
    )]
    async fn websocket_proxy_relays_frames_and_joins_actual_downstream_close() {
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
                        "/public/../api//items?q=%7euser"
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
            assert!(matches!(
                websocket
                    .next()
                    .await
                    .expect("proxy native Close reply")
                    .expect("valid Close"),
                tungstenite::Message::Close(_)
            ));
            let mut byte = [0];
            assert_eq!(
                websocket
                    .get_mut()
                    .read(&mut byte)
                    .await
                    .expect("native EOF"),
                0,
                "The native socket ends before the delayed downstream Close"
            );
        });

        let server = ProxyServer::new(test_options(
            format!("http://{address}").parse().expect("upstream URL"),
        ))
        .expect("proxy server");
        let stream = Arc::new(TestStream::new({
            let mut input = frame_metadata(serde_json::json!({
                "v": 2, "conn_id": "socket-1",
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
            // Keep a partially read downstream Close across upstream data and
            // Close frames. Its actual body arrives only after our slow read.
            input.push(8);
            input.extend_from_slice(&6u32.to_be_bytes());
            input
        }));
        let serving = serve_websocket(&server.inner, &stream, CancellationToken::new());
        tokio::pin!(serving);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut serving)
                .await
                .is_err(),
            "Proxy must retain its original reader until the downstream Close arrives"
        );
        tokio::time::timeout(Duration::from_secs(2), upstream)
            .await
            .expect("native Close reply was flushed before waiting for downstream")
            .expect("upstream task");

        let output = stream.output();
        let length = u32::from_be_bytes(output[..4].try_into().expect("response length")) as usize;
        let meta: serde_json::Value = response_meta(&output);
        assert_eq!(
            meta,
            serde_json::json!({
                "v": 2, "conn_id": "socket-1", "ok": true, "protocol": "chat"
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
        stream.push_input(Bytes::from_static(&[0x03, 0xe8, b'd', b'o', b'n', b'e']));
        tokio::time::timeout(Duration::from_secs(2), &mut serving)
            .await
            .expect("websocket proxy converged after the real downstream Close")
            .expect("serve websocket");
    }

    #[tokio::test]
    async fn websocket_proxy_rejects_upstream_eof_without_close() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let address = listener.local_addr().expect("upstream address");
        let upstream = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept websocket");
            let websocket = tokio_tungstenite::accept_async(socket)
                .await
                .expect("upgrade websocket");
            drop(websocket);
        });
        let server =
            ProxyServer::new(test_options(format!("http://{address}").parse().unwrap())).unwrap();
        let stream = Arc::new(TestStream::new(frame_metadata(serde_json::json!({
            "v": 2, "conn_id": "abrupt-close", "path": "/socket", "headers": []
        }))));
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                serve_websocket(&server.inner, &stream, CancellationToken::new())
            )
            .await
            .expect("abrupt upstream termination is bounded"),
            Err(ProxyServerError::OperationFailed)
        ));
        upstream.await.expect("upstream task");
    }

    #[test]
    fn current_proxy_metadata_matches_the_registered_protocol() {
        let server =
            ProxyServer::new(test_options("http://127.0.0.1:8080".parse().unwrap())).unwrap();
        let metadata = |namespace: &str,
                        envelope_version,
                        protocol: serde_json::Value,
                        version: serde_json::Value| {
            crate::Metadata::new(
                namespace,
                envelope_version,
                &std::collections::BTreeMap::from([
                    (
                        "protocol".into(),
                        Bytes::from(serde_json::to_vec(&protocol).unwrap()),
                    ),
                    (
                        "version".into(),
                        Bytes::from(serde_json::to_vec(&version).unwrap()),
                    ),
                ]),
            )
            .unwrap()
        };
        for (kind, expected, other) in [
            (
                Protocol::Http,
                "flowersec.proxy.http",
                "flowersec.proxy.websocket",
            ),
            (
                Protocol::WebSocket,
                "flowersec.proxy.websocket",
                "flowersec.proxy.http",
            ),
        ] {
            let handler = CurrentProxyHandler(ProxyHandler {
                inner: server.inner.clone(),
                protocol: kind,
            });
            assert!(handler.accepts_metadata(&crate::Metadata::empty()));
            assert!(handler.accepts_metadata(&metadata(
                "application/json",
                1,
                expected.into(),
                2.into()
            )));
            for rejected in [
                metadata("application/json", 1, other.into(), 2.into()),
                metadata("application/json", 1, "denied".into(), 2.into()),
                metadata("application/json", 1, expected.into(), 3.into()),
                metadata("application/json", 1, expected.into(), "2".into()),
                metadata("application/json", 1, 2.into(), 2.into()),
                metadata("application/json", 2, expected.into(), 2.into()),
                metadata("example/json", 1, expected.into(), 2.into()),
            ] {
                assert!(!handler.accepts_metadata(&rejected));
            }
            let valid = metadata("application/json", 1, expected.into(), 2.into());
            let mut fields = valid.byte_values();
            fields.insert("extra".into(), Bytes::from_static(b"true"));
            assert!(
                !handler.accepts_metadata(
                    &crate::Metadata::new("application/json", 1, &fields).unwrap()
                )
            );
            fields.remove("extra");
            fields.remove("version");
            assert!(
                !handler.accepts_metadata(
                    &crate::Metadata::new("application/json", 1, &fields).unwrap()
                )
            );
            fields.insert("version".into(), Bytes::from_static(b"invalid JSON"));
            assert!(
                !handler.accepts_metadata(
                    &crate::Metadata::new("application/json", 1, &fields).unwrap()
                )
            );
        }
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
            let mut input = frame_metadata(serde_json::json!({
                "v": 2, "conn_id": "socket-limit", "path": "/socket", "headers": []
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
            handler.serve_stream(&stream, CancellationToken::new(), None),
        )
        .await
        .expect("bounded frame rejection");
        assert_eq!(result, Err(SessionError::OperationFailed));
        assert_eq!(server.inner.permits.available_permits(), 2);
        server.close().await;
        assert_eq!(
            handler
                .serve_stream(&stream, CancellationToken::new(), None)
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
        options.allowed_upstream_addresses = vec!["127.0.0.1".into(), "::1".into()];
        options.upstream_trust_roots_der = vec![STANDARD.decode(TEST_CERT_DER_B64).unwrap()];
        let server = ProxyServer::new(options).expect("proxy server");
        let stream = Arc::new(TestStream::new(frame_metadata(serde_json::json!({
            "v": 2, "conn_id": "tls-blackhole", "path": "/socket", "headers": []
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
            let stream = Arc::new(TestStream::new(frame_metadata(serde_json::json!({
                "v": 2, "conn_id": conn_id, "path": "/socket", "headers": []
            }))));
            let result = tokio::time::timeout(
                Duration::from_millis(200),
                handler.serve_stream(&stream, CancellationToken::new(), None),
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
    fn options_and_raw_stream_plan_fail_closed_without_duplicates() {
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
        let registrations = server.stream_registrations().expect("current raw streams");
        assert_eq!(registrations.len(), 2);
        assert_eq!(registrations[0].kind, HTTP_KIND);
        assert_eq!(registrations[1].kind, WEBSOCKET_KIND);
        let environment = crate::TransportEnvironment::new();
        let plan = environment
            .handler_plan(crate::HandlerPlanOptions {
                streams: crate::StreamDispatch::Registered(registrations.clone()),
                application_bytes: 65536,
            })
            .expect("current handler plan");
        plan.close();
        let mut duplicate = registrations;
        duplicate.push(duplicate[0].clone());
        assert!(
            environment
                .handler_plan(crate::HandlerPlanOptions {
                    streams: crate::StreamDispatch::Registered(duplicate),
                    application_bytes: 65536,
                })
                .is_err()
        );
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

        let unknown = Arc::new(TestStream::new(frame_metadata(serde_json::json!({
            "v": 2, "request_id": "unknown", "method": "GET", "path": "/",
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
            let mut input = frame_metadata(serde_json::json!({
                "v": 2, "request_id": "large", "method": "POST", "path": "/",
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
            let mut input = frame_metadata(serde_json::json!({
                "v": 2, "request_id": "origin", "method": "GET", "path": "/",
                "headers": [{"name":"origin", "value":"https://evil.example"}],
                "external_origin": "https://app.example"
            }));
            input.extend_from_slice(&body_end_frame());
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
            let mut input = frame_metadata(serde_json::json!({
                "v": 2, "request_id": "cancel", "method": "GET", "path": "/wait",
                "headers": []
            }));
            input.extend_from_slice(&body_end_frame());
            input
        }));
        let handler = ProxyHandler {
            inner: server.inner.clone(),
            protocol: Protocol::Http,
        };
        let operation = tokio::spawn(async move {
            handler
                .serve_stream(&stream, CancellationToken::new(), None)
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
        let stream = Arc::new(TestStream::new(Vec::new()));
        let rejected = ProxyHandler {
            inner: server.inner.clone(),
            protocol: Protocol::Http,
        }
        .serve_stream(&stream, CancellationToken::new(), None)
        .await;
        assert_eq!(rejected, Err(SessionError::Closed));
        upstream.abort();
    }
}
