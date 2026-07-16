//! Stable Flowersec HTTP and WebSocket proxy stream contracts.

use crate::{
    Client,
    endpoint::Session,
    streamio::{self, StreamIoError},
    yamux::{YamuxError, YamuxStream},
};
use futures_util::{SinkExt as _, StreamExt as _};
use rand::{RngCore as _, rngs::OsRng};
use reqwest::{
    Method, Url,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio_tungstenite::tungstenite::{
    Message,
    client::IntoClientRequest as _,
    protocol::{CloseFrame, frame::coding::CloseCode},
};

pub const PROTOCOL_VERSION: u32 = 1;
pub const HTTP1_KIND: &str = "flowersec-proxy/http1";
pub const WEBSOCKET_KIND: &str = "flowersec-proxy/ws";

const DEFAULT_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "cache-control",
    "content-type",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "origin",
    "pragma",
    "range",
    "x-requested-with",
];
const DEFAULT_RESPONSE_HEADERS: &[&str] = &[
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-security-policy",
    "content-security-policy-report-only",
    "content-type",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "etag",
    "expires",
    "last-modified",
    "location",
    "permissions-policy",
    "pragma",
    "referrer-policy",
    "set-cookie",
    "vary",
    "www-authenticate",
    "x-content-type-options",
    "x-frame-options",
];
const DEFAULT_WS_HEADERS: &[&str] = &["sec-websocket-protocol"];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestMeta {
    pub v: u32,
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseMeta {
    pub v: u32,
    pub request_id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RemoteError>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketOpenMeta {
    pub v: u32,
    pub conn_id: String,
    pub path: String,
    pub headers: Vec<Header>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketOpenResponse {
    pub v: u32,
    pub conn_id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RemoteError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<Header>,
    pub external_origin: Option<String>,
    pub timeout: Option<Duration>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: "GET".to_owned(),
            path: path.into(),
            headers: Vec::new(),
            external_origin: None,
            timeout: None,
            body: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WebSocketOp {
    Text = 1,
    Binary = 2,
    Close = 8,
    Ping = 9,
    Pong = 10,
}

impl TryFrom<u8> for WebSocketOp {
    type Error = ProxyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Text),
            2 => Ok(Self::Binary),
            8 => Ok(Self::Close),
            9 => Ok(Self::Ping),
            10 => Ok(Self::Pong),
            _ => Err(ProxyError::InvalidWebSocketOp(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketFrame {
    pub op: WebSocketOp,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ContractOptions {
    pub max_json_frame_bytes: usize,
    pub max_chunk_bytes: usize,
    pub max_body_bytes: usize,
    pub max_ws_frame_bytes: usize,
    pub default_http_request_timeout: Option<Duration>,
    pub extra_request_headers: Vec<String>,
    pub extra_response_headers: Vec<String>,
    pub blocked_response_headers: Vec<String>,
    pub extra_ws_headers: Vec<String>,
    pub forbidden_cookie_names: Vec<String>,
    pub forbidden_cookie_name_prefixes: Vec<String>,
}

impl Default for ContractOptions {
    fn default() -> Self {
        Self {
            max_json_frame_bytes: crate::defaults::MAX_JSON_FRAME_BYTES,
            max_chunk_bytes: crate::defaults::PROXY_MAX_CHUNK_BYTES,
            max_body_bytes: crate::defaults::PROXY_MAX_BODY_BYTES,
            max_ws_frame_bytes: crate::defaults::PROXY_MAX_WS_FRAME_BYTES,
            default_http_request_timeout: None,
            extra_request_headers: Vec::new(),
            extra_response_headers: Vec::new(),
            blocked_response_headers: Vec::new(),
            extra_ws_headers: Vec::new(),
            forbidden_cookie_names: Vec::new(),
            forbidden_cookie_name_prefixes: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub upstream: String,
    pub upstream_origin: String,
    pub allowed_upstream_hosts: Vec<String>,
    pub contract: ContractOptions,
    pub default_timeout: Option<Duration>,
    pub max_timeout: Option<Duration>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid proxy configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid proxy path")]
    InvalidPath,
    #[error("invalid proxy metadata: {0}")]
    InvalidMeta(&'static str),
    #[error("proxy frame exceeds configured limit")]
    FrameTooLarge,
    #[error("proxy body exceeds configured limit")]
    BodyTooLarge,
    #[error("invalid WebSocket operation {0}")]
    InvalidWebSocketOp(u8),
    #[error("proxy peer returned {code}: {message}")]
    Remote { code: String, message: String },
    #[error("proxy stream failed: {0}")]
    Stream(#[from] StreamIoError),
    #[error("proxy Yamux stream failed: {0}")]
    Yamux(#[from] YamuxError),
    #[error("proxy HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("proxy WebSocket failed: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("proxy endpoint session failed: {0}")]
    Endpoint(#[from] crate::FlowersecError),
    #[error("proxy task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error("proxy operation failed: {operation}; stream cleanup failed: {close}")]
    Cleanup {
        operation: Box<ProxyError>,
        close: YamuxError,
    },
}

#[derive(Clone, Debug)]
struct HeaderPolicy {
    request: HashSet<String>,
    response: HashSet<String>,
    blocked_response: HashSet<String>,
    websocket: HashSet<String>,
    forbidden_cookie_names: HashSet<String>,
    forbidden_cookie_prefixes: Vec<String>,
}

impl HeaderPolicy {
    fn compile(options: &ContractOptions) -> Result<Self, ProxyError> {
        let mut request = normalized_header_set(DEFAULT_REQUEST_HEADERS.iter().copied())?;
        request.extend(normalized_header_set(
            options.extra_request_headers.iter().map(String::as_str),
        )?);
        let mut response = normalized_header_set(DEFAULT_RESPONSE_HEADERS.iter().copied())?;
        response.extend(normalized_header_set(
            options.extra_response_headers.iter().map(String::as_str),
        )?);
        let blocked_response =
            normalized_header_set(options.blocked_response_headers.iter().map(String::as_str))?;
        let mut websocket = normalized_header_set(DEFAULT_WS_HEADERS.iter().copied())?;
        websocket.extend(normalized_header_set(
            options.extra_ws_headers.iter().map(String::as_str),
        )?);
        let forbidden_cookie_names = normalized_nonempty_set(&options.forbidden_cookie_names)?;
        let forbidden_cookie_prefixes = options
            .forbidden_cookie_name_prefixes
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .map(|value| {
                if value.is_empty() {
                    Err(ProxyError::InvalidConfig(
                        "empty forbidden cookie prefix".to_owned(),
                    ))
                } else {
                    Ok(value)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            request,
            response,
            blocked_response,
            websocket,
            forbidden_cookie_names,
            forbidden_cookie_prefixes,
        })
    }

    pub fn filter_request(&self, headers: &[Header]) -> Vec<Header> {
        self.filter(headers, HeaderDirection::Request)
    }

    pub fn filter_response(&self, headers: &[Header]) -> Vec<Header> {
        self.filter(headers, HeaderDirection::Response)
    }

    pub fn filter_websocket(&self, headers: &[Header]) -> Vec<Header> {
        self.filter(headers, HeaderDirection::WebSocket)
    }

    fn filter(&self, headers: &[Header], direction: HeaderDirection) -> Vec<Header> {
        let mut output = Vec::new();
        for header in headers {
            let name = header.name.trim().to_ascii_lowercase();
            if !valid_header_name(&name) || !safe_header_value(&header.value) {
                continue;
            }
            let allowed = match direction {
                HeaderDirection::Request => {
                    name == "cookie"
                        || (name != "host"
                            && name != "authorization"
                            && self.request.contains(&name))
                }
                HeaderDirection::Response => {
                    self.response.contains(&name) && !self.blocked_response.contains(&name)
                }
                HeaderDirection::WebSocket => name == "cookie" || self.websocket.contains(&name),
            };
            if !allowed || hop_by_hop(&name) {
                continue;
            }
            let value = if name == "cookie" {
                self.filter_cookie_header(&header.value)
            } else {
                Some(header.value.clone())
            };
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                output.push(Header { name, value });
            }
        }
        output
    }

    fn filter_cookie_header(&self, value: &str) -> Option<String> {
        let cookies = value
            .split(';')
            .filter_map(|part| {
                let part = part.trim();
                let (name, _) = part.split_once('=')?;
                let normalized = name.trim().to_ascii_lowercase();
                if normalized.is_empty()
                    || self.forbidden_cookie_names.contains(&normalized)
                    || self
                        .forbidden_cookie_prefixes
                        .iter()
                        .any(|prefix| normalized.starts_with(prefix))
                {
                    None
                } else {
                    Some(part.to_owned())
                }
            })
            .collect::<Vec<_>>();
        (!cookies.is_empty()).then(|| cookies.join("; "))
    }
}

#[derive(Clone, Copy, Debug)]
enum HeaderDirection {
    Request,
    Response,
    WebSocket,
}

#[derive(Clone, Debug)]
struct CompiledContract {
    options: ContractOptions,
    headers: HeaderPolicy,
}

impl CompiledContract {
    fn new(options: ContractOptions) -> Result<Self, ProxyError> {
        if options.max_json_frame_bytes == 0
            || options.max_chunk_bytes == 0
            || options.max_body_bytes == 0
            || options.max_ws_frame_bytes == 0
        {
            return Err(ProxyError::InvalidConfig(
                "proxy limits must be positive".to_owned(),
            ));
        }
        let headers = HeaderPolicy::compile(&options)?;
        Ok(Self { options, headers })
    }
}

#[derive(Clone, Debug)]
pub struct ProxyClient {
    client: Arc<Client>,
    contract: Arc<CompiledContract>,
}

impl ProxyClient {
    pub fn new(client: Arc<Client>, options: ContractOptions) -> Result<Self, ProxyError> {
        Ok(Self {
            client,
            contract: Arc::new(CompiledContract::new(options)?),
        })
    }

    pub async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ProxyError> {
        validate_path(&request.path)?;
        if request.method.trim().is_empty() {
            return Err(ProxyError::InvalidMeta("missing method"));
        }
        if request.body.len() > self.contract.options.max_body_bytes {
            return Err(ProxyError::BodyTooLarge);
        }
        let stream = self.client.open_stream(HTTP1_KIND).await?;
        let result = async {
            let request_id = opaque_id();
            let timeout_ms = request
                .timeout
                .or(self.contract.options.default_http_request_timeout)
                .map(duration_millis_i64)
                .transpose()?;
            let meta = HttpRequestMeta {
                v: PROTOCOL_VERSION,
                request_id: request_id.clone(),
                method: request.method.trim().to_owned(),
                path: request.path,
                headers: self.contract.headers.filter_request(&request.headers),
                external_origin: request.external_origin,
                timeout_ms,
            };
            streamio::write_json(&stream, &meta).await?;
            write_body(&stream, &request.body, &self.contract).await?;
            let response: HttpResponseMeta =
                streamio::read_json(&stream, self.contract.options.max_json_frame_bytes).await?;
            validate_http_response(&response, &request_id)?;
            if !response.ok {
                let error = response
                    .error
                    .ok_or(ProxyError::InvalidMeta("missing error"))?;
                return Err(ProxyError::Remote {
                    code: error.code,
                    message: error.message,
                });
            }
            let body = read_body(&stream, &self.contract).await?;
            Ok(HttpResponse {
                status: response
                    .status
                    .ok_or(ProxyError::InvalidMeta("missing status"))?,
                headers: self.contract.headers.filter_response(&response.headers),
                body,
            })
        }
        .await;
        let close = stream.close().await;
        match (result, close) {
            (Ok(response), Ok(())) => Ok(response),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(ProxyError::Yamux(error)),
            (Err(operation), Err(close)) => Err(ProxyError::Cleanup {
                operation: Box::new(operation),
                close,
            }),
        }
    }

    pub async fn open_websocket(
        &self,
        path: impl Into<String>,
        headers: Vec<Header>,
    ) -> Result<ProxyWebSocket, ProxyError> {
        let path = path.into();
        validate_path(&path)?;
        let stream = self.client.open_stream(WEBSOCKET_KIND).await?;
        let conn_id = opaque_id();
        let requested_protocols = protocols(&headers);
        streamio::write_json(
            &stream,
            &WebSocketOpenMeta {
                v: PROTOCOL_VERSION,
                conn_id: conn_id.clone(),
                path,
                headers: self.contract.headers.filter_websocket(&headers),
            },
        )
        .await?;
        let response: WebSocketOpenResponse =
            streamio::read_json(&stream, self.contract.options.max_json_frame_bytes).await?;
        validate_ws_response(&response, &conn_id)?;
        if !response.ok {
            let error = response
                .error
                .ok_or(ProxyError::InvalidMeta("missing error"))?;
            return Err(ProxyError::Remote {
                code: error.code,
                message: error.message,
            });
        }
        if let Some(protocol) = response
            .protocol
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            if !requested_protocols.iter().any(|value| value == protocol) {
                return Err(ProxyError::InvalidMeta("WebSocket subprotocol mismatch"));
            }
        }
        Ok(ProxyWebSocket {
            stream,
            protocol: response.protocol.filter(|value| !value.is_empty()),
            max_frame_bytes: self.contract.options.max_ws_frame_bytes,
        })
    }
}

#[derive(Debug)]
pub struct ProxyWebSocket {
    stream: YamuxStream,
    protocol: Option<String>,
    max_frame_bytes: usize,
}

impl ProxyWebSocket {
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    pub async fn send(&self, frame: WebSocketFrame) -> Result<(), ProxyError> {
        write_ws_frame(&self.stream, frame, self.max_frame_bytes).await
    }

    pub async fn receive(&self) -> Result<WebSocketFrame, ProxyError> {
        read_ws_frame(&self.stream, self.max_frame_bytes).await
    }

    pub async fn close(&self, code: Option<u16>, reason: &str) -> Result<(), ProxyError> {
        let payload = close_payload(code, reason)?;
        self.send(WebSocketFrame {
            op: WebSocketOp::Close,
            payload,
        })
        .await?;
        self.stream.close().await?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct CompiledServer {
    contract: Arc<CompiledContract>,
    upstream: Url,
    upstream_origin: String,
    default_timeout: Option<Duration>,
    max_timeout: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct ProxyServer {
    config: Arc<CompiledServer>,
    http: reqwest::Client,
}

impl ProxyServer {
    pub fn new(options: ServerOptions) -> Result<Self, ProxyError> {
        let contract = Arc::new(CompiledContract::new(options.contract)?);
        let upstream = validate_upstream(&options.upstream, &options.allowed_upstream_hosts)?;
        let upstream_origin = validate_origin(&options.upstream_origin)?.to_string();
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(ProxyError::Http)?;
        Ok(Self {
            config: Arc::new(CompiledServer {
                contract,
                upstream,
                upstream_origin,
                default_timeout: options
                    .default_timeout
                    .or(Some(crate::defaults::PROXY_DEFAULT_TIMEOUT)),
                max_timeout: options
                    .max_timeout
                    .or(Some(crate::defaults::PROXY_MAX_TIMEOUT)),
            }),
            http,
        })
    }

    pub async fn serve(&self, session: &Session) -> Result<(), ProxyError> {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                outcome = tasks.join_next(), if !tasks.is_empty() => {
                    match outcome {
                        Some(Ok(result)) => result?,
                        Some(Err(error)) => return Err(ProxyError::Task(error)),
                        None => return Err(ProxyError::InvalidConfig("proxy supervisor ended unexpectedly".to_owned())),
                    }
                }
                accepted = session.accept_stream() => {
                    let (kind, stream) = accepted?;
                    let server = self.clone();
                    tasks.spawn(async move {
                        let result = server.serve_stream(&kind, stream.clone()).await;
                        match result {
                            Ok(()) => Ok(()),
                            Err(operation) => match stream.reset().await {
                                Ok(()) => Err(operation),
                                Err(close) => Err(ProxyError::Cleanup {
                                    operation: Box::new(operation),
                                    close,
                                }),
                            },
                        }
                    });
                }
            }
        }
    }

    pub async fn serve_stream(&self, kind: &str, stream: YamuxStream) -> Result<(), ProxyError> {
        match kind {
            HTTP1_KIND => self.serve_http(stream).await,
            WEBSOCKET_KIND => self.serve_websocket(stream).await,
            _ => {
                stream.reset().await?;
                Ok(())
            }
        }
    }

    async fn serve_http(&self, stream: YamuxStream) -> Result<(), ProxyError> {
        let meta = streamio::read_json::<HttpRequestMeta>(
            &stream,
            self.config.contract.options.max_json_frame_bytes,
        )
        .await;
        let mut meta = match meta {
            Ok(meta) => meta,
            Err(error) => {
                write_http_error(
                    &stream,
                    "unknown",
                    "invalid_request_meta",
                    &error.to_string(),
                )
                .await?;
                return Ok(());
            }
        };
        if let Err(error) = validate_http_request(&mut meta) {
            write_http_error(
                &stream,
                &meta.request_id,
                "invalid_request_meta",
                &error.to_string(),
            )
            .await?;
            return Ok(());
        }
        let body = match read_body(&stream, &self.config.contract).await {
            Ok(body) => body,
            Err(error) => {
                let code = if matches!(error, ProxyError::BodyTooLarge | ProxyError::FrameTooLarge)
                {
                    "request_body_too_large"
                } else {
                    "request_body_invalid"
                };
                write_http_error(&stream, &meta.request_id, code, &error.to_string()).await?;
                return Ok(());
            }
        };
        let method = match Method::from_bytes(meta.method.as_bytes()) {
            Ok(method) => method,
            Err(error) => {
                write_http_error(
                    &stream,
                    &meta.request_id,
                    "invalid_request_meta",
                    &error.to_string(),
                )
                .await?;
                return Ok(());
            }
        };
        let url = join_upstream(&self.config.upstream, &meta.path)?;
        let mut headers =
            to_header_map(&self.config.contract.headers.filter_request(&meta.headers));
        if let Err(error) = apply_external_origin(&mut headers, meta.external_origin.as_deref()) {
            write_http_error(
                &stream,
                &meta.request_id,
                "invalid_request_meta",
                &error.to_string(),
            )
            .await?;
            return Ok(());
        }
        let timeout = match resolve_timeout(
            meta.timeout_ms,
            self.config.default_timeout,
            self.config.max_timeout,
        ) {
            Ok(timeout) => timeout,
            Err(error) => {
                write_http_error(
                    &stream,
                    &meta.request_id,
                    "invalid_request_meta",
                    &error.to_string(),
                )
                .await?;
                return Ok(());
            }
        };
        let mut request = self.http.request(method, url).headers(headers);
        if !matches!(meta.method.as_str(), "GET" | "HEAD") {
            request = request.body(body);
        }
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                let code = classify_http_error(&error);
                write_http_error(&stream, &meta.request_id, code, &error.to_string()).await?;
                return Ok(());
            }
        };
        if response
            .content_length()
            .is_some_and(|length| length > self.config.contract.options.max_body_bytes as u64)
        {
            write_http_error(
                &stream,
                &meta.request_id,
                "response_body_too_large",
                "upstream response exceeds max_body_bytes",
            )
            .await?;
            return Ok(());
        }
        let status = response.status().as_u16();
        let response_headers = self
            .config
            .contract
            .headers
            .filter_response(&from_header_map(response.headers()));
        let body =
            match read_response_body(response, self.config.contract.options.max_body_bytes).await {
                Ok(body) => body,
                Err(ProxyError::BodyTooLarge) => {
                    write_http_error(
                        &stream,
                        &meta.request_id,
                        "response_body_too_large",
                        "upstream response exceeds max_body_bytes",
                    )
                    .await?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
        streamio::write_json(
            &stream,
            &HttpResponseMeta {
                v: PROTOCOL_VERSION,
                request_id: meta.request_id,
                ok: true,
                status: Some(status),
                headers: response_headers,
                error: None,
            },
        )
        .await?;
        write_body(&stream, &body, &self.config.contract).await?;
        stream.close().await?;
        Ok(())
    }

    async fn serve_websocket(&self, stream: YamuxStream) -> Result<(), ProxyError> {
        let meta = streamio::read_json::<WebSocketOpenMeta>(
            &stream,
            self.config.contract.options.max_json_frame_bytes,
        )
        .await;
        let mut meta = match meta {
            Ok(meta) => meta,
            Err(error) => {
                write_ws_error(
                    &stream,
                    "unknown",
                    "invalid_ws_open_meta",
                    &error.to_string(),
                )
                .await?;
                return Ok(());
            }
        };
        if let Err(error) = validate_ws_request(&mut meta) {
            write_ws_error(
                &stream,
                &meta.conn_id,
                "invalid_ws_open_meta",
                &error.to_string(),
            )
            .await?;
            return Ok(());
        }
        let mut url = join_upstream(&self.config.upstream, &meta.path)?;
        let ws_scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => {
                return Err(ProxyError::InvalidConfig(
                    "invalid upstream scheme".to_owned(),
                ));
            }
        };
        url.set_scheme(ws_scheme)
            .map_err(|_| ProxyError::InvalidConfig("invalid WebSocket scheme".to_owned()))?;
        let mut request = url.as_str().into_client_request()?;
        for header in self.config.contract.headers.filter_websocket(&meta.headers) {
            let name = tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(
                header.name.as_bytes(),
            )
            .map_err(|_| ProxyError::InvalidMeta("invalid header name"))?;
            let value = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&header.value)
                .map_err(|_| ProxyError::InvalidMeta("invalid header value"))?;
            request.headers_mut().append(name, value);
        }
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::ORIGIN,
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(
                &self.config.upstream_origin,
            )
            .map_err(|_| ProxyError::InvalidConfig("invalid upstream origin".to_owned()))?,
        );
        let (websocket, response) = match tokio_tungstenite::connect_async(request).await {
            Ok(result) => result,
            Err(error) => {
                let code = if matches!(error, tokio_tungstenite::tungstenite::Error::Http(_)) {
                    "upstream_ws_rejected"
                } else {
                    "upstream_ws_dial_failed"
                };
                write_ws_error(&stream, &meta.conn_id, code, &error.to_string()).await?;
                return Ok(());
            }
        };
        let protocol = response
            .headers()
            .get(tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        streamio::write_json(
            &stream,
            &WebSocketOpenResponse {
                v: PROTOCOL_VERSION,
                conn_id: meta.conn_id,
                ok: true,
                protocol,
                error: None,
            },
        )
        .await?;
        let (mut upstream_write, mut upstream_read) = websocket.split();
        let inbound = stream.clone();
        let max_frame = self.config.contract.options.max_ws_frame_bytes;
        let to_upstream = async move {
            loop {
                let frame = read_ws_frame(&inbound, max_frame).await?;
                let is_close = frame.op == WebSocketOp::Close;
                upstream_write.send(frame_to_message(frame)?).await?;
                if is_close {
                    return Ok::<(), ProxyError>(());
                }
            }
        };
        let outbound = stream.clone();
        let from_upstream = async move {
            while let Some(message) = upstream_read.next().await {
                let frame = message_to_frame(message?)?;
                let Some(frame) = frame else { continue };
                let is_close = frame.op == WebSocketOp::Close;
                write_ws_frame(&outbound, frame, max_frame).await?;
                if is_close {
                    return Ok::<(), ProxyError>(());
                }
            }
            Ok(())
        };
        tokio::select! {
            result = to_upstream => result?,
            result = from_upstream => result?,
        }
        stream.close().await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BrowserOriginPolicy {
    allowed: HashSet<String>,
}

impl BrowserOriginPolicy {
    pub fn new(origins: impl IntoIterator<Item = String>) -> Result<Self, ProxyError> {
        let allowed = origins
            .into_iter()
            .map(|origin| validate_origin(&origin).map(|origin| origin.to_string()))
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Self { allowed })
    }

    pub fn allows(&self, origin: &str) -> bool {
        validate_origin(origin)
            .map(|origin| self.allowed.contains(origin.as_str()))
            .unwrap_or(false)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredCookie {
    name: String,
    value: String,
    path: String,
}

#[derive(Clone, Debug, Default)]
pub struct CookieJar {
    cookies: HashMap<(String, String), StoredCookie>,
}

impl CookieJar {
    pub fn capture(&mut self, request_path: &str, headers: &[Header]) {
        let default_path = default_cookie_path(request_path);
        for header in headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("set-cookie"))
        {
            let mut parts = header.value.split(';');
            let Some((name, value)) = parts.next().and_then(|part| part.trim().split_once('='))
            else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let mut path = default_path.clone();
            let mut delete = value.is_empty();
            for attribute in parts {
                let (attribute_name, attribute_value) = attribute
                    .trim()
                    .split_once('=')
                    .unwrap_or((attribute.trim(), ""));
                if attribute_name.eq_ignore_ascii_case("path") && attribute_value.starts_with('/') {
                    path = attribute_value.to_owned();
                }
                if attribute_name.eq_ignore_ascii_case("max-age")
                    && attribute_value
                        .trim()
                        .parse::<i64>()
                        .is_ok_and(|value| value <= 0)
                {
                    delete = true;
                }
            }
            let key = (name.to_owned(), path.clone());
            if delete {
                self.cookies.remove(&key);
            } else {
                self.cookies.insert(
                    key,
                    StoredCookie {
                        name: name.to_owned(),
                        value: value.to_owned(),
                        path,
                    },
                );
            }
        }
    }

    pub fn request_header(&self, request_path: &str) -> Option<Header> {
        let mut cookies = self
            .cookies
            .values()
            .filter(|cookie| cookie_path_matches(&cookie.path, request_path))
            .collect::<Vec<_>>();
        cookies.sort_by(|left, right| right.path.len().cmp(&left.path.len()));
        (!cookies.is_empty()).then(|| Header {
            name: "cookie".to_owned(),
            value: cookies
                .into_iter()
                .map(|cookie| format!("{}={}", cookie.name, cookie.value))
                .collect::<Vec<_>>()
                .join("; "),
        })
    }
}

async fn write_body(
    stream: &YamuxStream,
    body: &[u8],
    contract: &CompiledContract,
) -> Result<(), ProxyError> {
    if body.len() > contract.options.max_body_bytes {
        return Err(ProxyError::BodyTooLarge);
    }
    for chunk in body.chunks(contract.options.max_chunk_bytes) {
        streamio::write_chunk(stream, chunk).await?;
    }
    streamio::write_chunk(stream, &[]).await?;
    Ok(())
}

async fn read_body(
    stream: &YamuxStream,
    contract: &CompiledContract,
) -> Result<Vec<u8>, ProxyError> {
    let mut body = Vec::new();
    loop {
        let chunk = streamio::read_chunk(stream, contract.options.max_chunk_bytes)
            .await
            .map_err(|error| match error {
                StreamIoError::TooLarge => ProxyError::FrameTooLarge,
                other => ProxyError::Stream(other),
            })?;
        if chunk.is_empty() {
            return Ok(body);
        }
        if body.len().saturating_add(chunk.len()) > contract.options.max_body_bytes {
            return Err(ProxyError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
}

async fn write_ws_frame(
    stream: &YamuxStream,
    frame: WebSocketFrame,
    max_frame_bytes: usize,
) -> Result<(), ProxyError> {
    if frame.payload.len() > max_frame_bytes || frame.payload.len() > u32::MAX as usize {
        return Err(ProxyError::FrameTooLarge);
    }
    let mut wire = Vec::with_capacity(5 + frame.payload.len());
    wire.push(frame.op as u8);
    wire.extend_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    wire.extend_from_slice(&frame.payload);
    stream.write(&wire).await?;
    Ok(())
}

async fn read_ws_frame(
    stream: &YamuxStream,
    max_frame_bytes: usize,
) -> Result<WebSocketFrame, ProxyError> {
    let header = stream.read_exact(5).await?;
    let op = WebSocketOp::try_from(header[0])?;
    let length = u32::from_be_bytes(header[1..5].try_into().expect("fixed header")) as usize;
    if length > max_frame_bytes {
        return Err(ProxyError::FrameTooLarge);
    }
    Ok(WebSocketFrame {
        op,
        payload: stream.read_exact(length).await?,
    })
}

async fn write_http_error(
    stream: &YamuxStream,
    request_id: &str,
    code: &str,
    message: &str,
) -> Result<(), ProxyError> {
    streamio::write_json(
        stream,
        &HttpResponseMeta {
            v: PROTOCOL_VERSION,
            request_id: nonempty_id(request_id),
            ok: false,
            status: None,
            headers: Vec::new(),
            error: Some(RemoteError {
                code: code.to_owned(),
                message: message.to_owned(),
            }),
        },
    )
    .await?;
    streamio::write_chunk(stream, &[]).await?;
    Ok(())
}

async fn write_ws_error(
    stream: &YamuxStream,
    conn_id: &str,
    code: &str,
    message: &str,
) -> Result<(), ProxyError> {
    streamio::write_json(
        stream,
        &WebSocketOpenResponse {
            v: PROTOCOL_VERSION,
            conn_id: nonempty_id(conn_id),
            ok: false,
            protocol: None,
            error: Some(RemoteError {
                code: code.to_owned(),
                message: message.to_owned(),
            }),
        },
    )
    .await?;
    Ok(())
}

fn validate_http_request(meta: &mut HttpRequestMeta) -> Result<(), ProxyError> {
    if meta.v != PROTOCOL_VERSION {
        return Err(ProxyError::InvalidMeta("unsupported version"));
    }
    meta.request_id = meta.request_id.trim().to_owned();
    meta.method = meta.method.trim().to_ascii_uppercase();
    if meta.request_id.is_empty() || meta.method.is_empty() {
        return Err(ProxyError::InvalidMeta("missing request fields"));
    }
    validate_path(&meta.path)
}

fn validate_http_response(meta: &HttpResponseMeta, request_id: &str) -> Result<(), ProxyError> {
    if meta.v != PROTOCOL_VERSION || meta.request_id != request_id {
        return Err(ProxyError::InvalidMeta("response correlation mismatch"));
    }
    if meta.ok {
        let status = meta
            .status
            .ok_or(ProxyError::InvalidMeta("missing status"))?;
        if !(100..=999).contains(&status) {
            return Err(ProxyError::InvalidMeta("invalid status"));
        }
    } else if meta
        .error
        .as_ref()
        .is_none_or(|error| error.code.trim().is_empty())
    {
        return Err(ProxyError::InvalidMeta("missing error"));
    }
    Ok(())
}

fn validate_ws_request(meta: &mut WebSocketOpenMeta) -> Result<(), ProxyError> {
    if meta.v != PROTOCOL_VERSION {
        return Err(ProxyError::InvalidMeta("unsupported version"));
    }
    meta.conn_id = meta.conn_id.trim().to_owned();
    if meta.conn_id.is_empty() {
        return Err(ProxyError::InvalidMeta("missing conn_id"));
    }
    validate_path(&meta.path)
}

fn validate_ws_response(response: &WebSocketOpenResponse, conn_id: &str) -> Result<(), ProxyError> {
    if response.v != PROTOCOL_VERSION || response.conn_id != conn_id {
        return Err(ProxyError::InvalidMeta("WebSocket correlation mismatch"));
    }
    if !response.ok
        && response
            .error
            .as_ref()
            .is_none_or(|error| error.code.trim().is_empty())
    {
        return Err(ProxyError::InvalidMeta("missing error"));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ProxyError> {
    let path = path.trim();
    if path.is_empty()
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ProxyError::InvalidPath);
    }
    let parsed = Url::parse(&format!("http://flowersec.invalid{path}"))
        .map_err(|_| ProxyError::InvalidPath)?;
    if parsed.fragment().is_some() {
        return Err(ProxyError::InvalidPath);
    }
    Ok(())
}

fn validate_upstream(raw: &str, allowed_hosts: &[String]) -> Result<Url, ProxyError> {
    let upstream = Url::parse(raw.trim())
        .map_err(|error| ProxyError::InvalidConfig(format!("invalid upstream: {error}")))?;
    if !matches!(upstream.scheme(), "http" | "https")
        || upstream.host_str().is_none()
        || upstream.port().is_none()
        || !matches!(upstream.path(), "" | "/")
        || upstream.query().is_some()
        || upstream.fragment().is_some()
        || !upstream.username().is_empty()
        || upstream.password().is_some()
    {
        return Err(ProxyError::InvalidConfig(
            "upstream must be an http(s) origin with an explicit port".to_owned(),
        ));
    }
    let host = upstream
        .host_str()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let allowed = if allowed_hosts.is_empty() {
        HashSet::from(["127.0.0.1".to_owned()])
    } else {
        normalized_nonempty_set(allowed_hosts)?
    };
    if !allowed.contains(&host) {
        return Err(ProxyError::InvalidConfig(format!(
            "upstream host {host:?} is not allowed"
        )));
    }
    Ok(upstream)
}

fn validate_origin(raw: &str) -> Result<Url, ProxyError> {
    let mut origin = Url::parse(raw.trim())
        .map_err(|error| ProxyError::InvalidConfig(format!("invalid origin: {error}")))?;
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !matches!(origin.path(), "" | "/")
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err(ProxyError::InvalidConfig(
            "origin must be an http(s) origin".to_owned(),
        ));
    }
    origin.set_path("");
    Ok(origin)
}

fn join_upstream(upstream: &Url, path: &str) -> Result<Url, ProxyError> {
    validate_path(path)?;
    let parsed = Url::parse(&format!("http://flowersec.invalid{path}"))
        .map_err(|_| ProxyError::InvalidPath)?;
    let mut result = upstream.clone();
    result.set_path(parsed.path());
    result.set_query(parsed.query());
    result.set_fragment(None);
    Ok(result)
}

fn resolve_timeout(
    timeout_ms: Option<i64>,
    default_timeout: Option<Duration>,
    max_timeout: Option<Duration>,
) -> Result<Option<Duration>, ProxyError> {
    let timeout_ms = timeout_ms.unwrap_or_default();
    if timeout_ms < 0 {
        return Err(ProxyError::InvalidMeta("timeout_ms must be non-negative"));
    }
    let timeout = if timeout_ms == 0 {
        default_timeout
    } else {
        Some(Duration::from_millis(timeout_ms as u64))
    };
    Ok(match (timeout, max_timeout) {
        (Some(timeout), Some(maximum)) => Some(timeout.min(maximum)),
        (timeout, _) => timeout,
    })
}

fn apply_external_origin(
    headers: &mut HeaderMap,
    external_origin: Option<&str>,
) -> Result<(), ProxyError> {
    let Some(external_origin) = external_origin
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let origin = validate_origin(external_origin)?;
    if let Some(browser_origin) = headers.get(reqwest::header::ORIGIN) {
        let browser_origin = browser_origin
            .to_str()
            .map_err(|_| ProxyError::InvalidMeta("invalid origin header"))?;
        if validate_origin(browser_origin)?.origin() != origin.origin() {
            return Err(ProxyError::InvalidMeta(
                "external_origin conflicts with origin header",
            ));
        }
    }
    headers.insert(
        reqwest::header::HOST,
        HeaderValue::from_str(origin.host_str().unwrap_or_default())
            .map_err(|_| ProxyError::InvalidMeta("invalid external origin host"))?,
    );
    if !headers.contains_key("x-forwarded-proto") {
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_str(origin.scheme())
                .map_err(|_| ProxyError::InvalidMeta("invalid external origin scheme"))?,
        );
    }
    Ok(())
}

async fn read_response_body(
    response: reqwest::Response,
    max_body_bytes: usize,
) -> Result<Vec<u8>, ProxyError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > max_body_bytes {
            return Err(ProxyError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn classify_http_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "upstream_dial_failed"
    } else {
        "upstream_request_failed"
    }
}

fn to_header_map(headers: &[Header]) -> HeaderMap {
    let mut output = HeaderMap::new();
    for header in headers {
        let Ok(name) = HeaderName::from_bytes(header.name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&header.value) else {
            continue;
        };
        output.append(name, value);
    }
    output
}

fn from_header_map(headers: &HeaderMap) -> Vec<Header> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| Header {
                name: name.as_str().to_owned(),
                value: value.to_owned(),
            })
        })
        .collect()
}

fn protocols(headers: &[Header]) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("sec-websocket-protocol"))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn frame_to_message(frame: WebSocketFrame) -> Result<Message, ProxyError> {
    Ok(match frame.op {
        WebSocketOp::Text => Message::Text(
            String::from_utf8(frame.payload)
                .map_err(|_| ProxyError::InvalidMeta("WebSocket text is not UTF-8"))?
                .into(),
        ),
        WebSocketOp::Binary => Message::Binary(frame.payload.into()),
        WebSocketOp::Ping => Message::Ping(frame.payload.into()),
        WebSocketOp::Pong => Message::Pong(frame.payload.into()),
        WebSocketOp::Close => Message::Close(parse_close_payload(&frame.payload)?),
    })
}

fn message_to_frame(message: Message) -> Result<Option<WebSocketFrame>, ProxyError> {
    Ok(match message {
        Message::Text(text) => Some(WebSocketFrame {
            op: WebSocketOp::Text,
            payload: text.as_str().as_bytes().to_vec(),
        }),
        Message::Binary(payload) => Some(WebSocketFrame {
            op: WebSocketOp::Binary,
            payload: payload.to_vec(),
        }),
        Message::Ping(payload) => Some(WebSocketFrame {
            op: WebSocketOp::Ping,
            payload: payload.to_vec(),
        }),
        Message::Pong(payload) => Some(WebSocketFrame {
            op: WebSocketOp::Pong,
            payload: payload.to_vec(),
        }),
        Message::Close(frame) => Some(WebSocketFrame {
            op: WebSocketOp::Close,
            payload: match frame {
                Some(frame) => close_payload(Some(frame.code.into()), &frame.reason)?,
                None => Vec::new(),
            },
        }),
        Message::Frame(_) => None,
    })
}

fn parse_close_payload(payload: &[u8]) -> Result<Option<CloseFrame>, ProxyError> {
    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() < 2 {
        return Err(ProxyError::InvalidMeta("invalid WebSocket close payload"));
    }
    let code = u16::from_be_bytes(payload[..2].try_into().expect("fixed close code"));
    let reason = std::str::from_utf8(&payload[2..])
        .map_err(|_| ProxyError::InvalidMeta("invalid WebSocket close reason"))?;
    Ok(Some(CloseFrame {
        code: CloseCode::from(code),
        reason: reason.to_owned().into(),
    }))
}

fn close_payload(code: Option<u16>, reason: &str) -> Result<Vec<u8>, ProxyError> {
    if code.is_none() && reason.is_empty() {
        return Ok(Vec::new());
    }
    let code = code.ok_or(ProxyError::InvalidMeta(
        "WebSocket close reason requires a code",
    ))?;
    let mut output = Vec::with_capacity(2 + reason.len());
    output.extend_from_slice(&code.to_be_bytes());
    output.extend_from_slice(reason.as_bytes());
    Ok(output)
}

fn normalized_header_set<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<HashSet<String>, ProxyError> {
    values
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| {
            if valid_header_name(&value) {
                Ok(value)
            } else {
                Err(ProxyError::InvalidConfig("invalid header name".to_owned()))
            }
        })
        .collect()
}

fn normalized_nonempty_set(values: &[String]) -> Result<HashSet<String>, ProxyError> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| {
            if value.is_empty() {
                Err(ProxyError::InvalidConfig("empty value".to_owned()))
            } else {
                Ok(value)
            }
        })
        .collect()
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
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

fn safe_header_value(value: &str) -> bool {
    !value.contains(['\r', '\n'])
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
            | "content-length"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-extensions"
    )
}

fn duration_millis_i64(duration: Duration) -> Result<i64, ProxyError> {
    i64::try_from(duration.as_millis())
        .map_err(|_| ProxyError::InvalidConfig("timeout is too large".to_owned()))
}

fn opaque_id() -> String {
    let mut bytes = [0_u8; 18];
    OsRng.fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

fn nonempty_id(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "unknown".to_owned()
    } else {
        value.to_owned()
    }
}

fn default_cookie_path(request_path: &str) -> String {
    let path = request_path.split('?').next().unwrap_or("/");
    if !path.starts_with('/') || path == "/" {
        return "/".to_owned();
    }
    match path.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(index) => path[..index].to_owned(),
    }
}

fn cookie_path_matches(cookie_path: &str, request_path: &str) -> bool {
    let request_path = request_path.split('?').next().unwrap_or("/");
    request_path == cookie_path
        || (request_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/')
                || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_defaults_to_loopback_only() {
        assert!(validate_upstream("http://127.0.0.1:8080", &[]).is_ok());
        assert!(validate_upstream("http://localhost:8080", &[]).is_err());
        assert!(validate_upstream("http://10.0.0.1:8080", &[]).is_err());
        assert!(validate_upstream("http://127.0.0.1", &[]).is_err());
        assert!(validate_upstream("file:///tmp/socket", &[]).is_err());
    }

    #[test]
    fn paths_reject_absolute_and_ambiguous_forms() {
        assert!(validate_path("/hello?x=1").is_ok());
        assert!(validate_path("https://evil.example/").is_err());
        assert!(validate_path("//evil.example/path").is_err());
        assert!(validate_path("/bad path").is_err());
    }

    #[test]
    fn header_policy_filters_credentials_hop_by_hop_and_cookies() {
        let policy = HeaderPolicy::compile(&ContractOptions {
            forbidden_cookie_names: vec!["secret".to_owned()],
            forbidden_cookie_name_prefixes: vec!["x-".to_owned()],
            ..ContractOptions::default()
        })
        .expect("policy");
        let filtered = policy.filter_request(&[
            Header {
                name: "accept".to_owned(),
                value: "text/html".to_owned(),
            },
            Header {
                name: "authorization".to_owned(),
                value: "Bearer token".to_owned(),
            },
            Header {
                name: "connection".to_owned(),
                value: "close".to_owned(),
            },
            Header {
                name: "cookie".to_owned(),
                value: "a=1; secret=2; x-debug=3; b=4".to_owned(),
            },
        ]);
        assert_eq!(
            filtered,
            vec![
                Header {
                    name: "accept".to_owned(),
                    value: "text/html".to_owned(),
                },
                Header {
                    name: "cookie".to_owned(),
                    value: "a=1; b=4".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn cookie_jar_preserves_same_name_paths_and_orders_longest_first() {
        let mut jar = CookieJar::default();
        jar.capture(
            "/admin/login",
            &[
                Header {
                    name: "set-cookie".to_owned(),
                    value: "session=admin; Path=/admin".to_owned(),
                },
                Header {
                    name: "set-cookie".to_owned(),
                    value: "session=root; Path=/".to_owned(),
                },
            ],
        );
        assert_eq!(
            jar.request_header("/admin/users").expect("cookie").value,
            "session=admin; session=root"
        );
        assert_eq!(
            jar.request_header("/administrator").expect("cookie").value,
            "session=root"
        );
    }

    #[test]
    fn browser_origin_policy_requires_exact_origins() {
        let policy = BrowserOriginPolicy::new(vec!["https://app.example.com".to_owned()])
            .expect("origin policy");
        assert!(policy.allows("https://app.example.com"));
        assert!(!policy.allows("https://evil.example.com"));
        assert!(!policy.allows("https://app.example.com/path"));
    }

    #[test]
    fn websocket_close_payload_round_trips() {
        let payload = close_payload(Some(1000), "done").expect("encode");
        let frame = parse_close_payload(&payload)
            .expect("decode")
            .expect("close frame");
        assert_eq!(u16::from(frame.code), 1000);
        assert_eq!(frame.reason, "done");
    }
}
