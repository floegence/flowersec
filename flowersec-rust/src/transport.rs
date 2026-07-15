use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_tungstenite::{MaybeTlsStream, connect_async, tungstenite::client::IntoClientRequest};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketMessageKind {
    Text,
    Binary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketMessage {
    pub kind: WebSocketMessageKind,
    pub payload: Bytes,
}

#[async_trait]
pub trait WebSocketTransport: Send + Sync + 'static {
    async fn receive(&self) -> std::io::Result<Option<WebSocketMessage>>;
    async fn send(&self, message: WebSocketMessage) -> std::io::Result<()>;
    async fn close(&self) -> std::io::Result<()>;
}

pub struct TungsteniteTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    reader: Mutex<SplitStream<WebSocketStream<S>>>,
    writer: Mutex<SplitSink<WebSocketStream<S>, Message>>,
}

impl<S> std::fmt::Debug for TungsteniteTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TungsteniteTransport(..)")
    }
}

impl<S> TungsteniteTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(stream: WebSocketStream<S>) -> Self {
        let (writer, reader) = stream.split();
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait]
impl<S> WebSocketTransport for TungsteniteTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn receive(&self) -> std::io::Result<Option<WebSocketMessage>> {
        loop {
            let message = self
                .reader
                .lock()
                .await
                .next()
                .await
                .transpose()
                .map_err(io_error)?;
            match message {
                Some(Message::Binary(payload)) => {
                    return Ok(Some(WebSocketMessage {
                        kind: WebSocketMessageKind::Binary,
                        payload,
                    }));
                }
                Some(Message::Text(payload)) => {
                    return Ok(Some(WebSocketMessage {
                        kind: WebSocketMessageKind::Text,
                        payload: Bytes::copy_from_slice(payload.as_bytes()),
                    }));
                }
                Some(Message::Close(_)) | None => return Ok(None),
                Some(Message::Ping(payload)) => {
                    self.writer
                        .lock()
                        .await
                        .send(Message::Pong(payload))
                        .await
                        .map_err(io_error)?;
                }
                Some(Message::Pong(_)) | Some(Message::Frame(_)) => {}
            }
        }
    }

    async fn send(&self, message: WebSocketMessage) -> std::io::Result<()> {
        let message = match message.kind {
            WebSocketMessageKind::Binary => Message::Binary(message.payload),
            WebSocketMessageKind::Text => Message::Text(
                String::from_utf8(message.payload.to_vec())
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
                    .into(),
            ),
        };
        self.writer
            .lock()
            .await
            .send(message)
            .await
            .map_err(io_error)
    }

    async fn close(&self) -> std::io::Result<()> {
        self.writer.lock().await.close().await.map_err(io_error)
    }
}

fn io_error(error: tokio_tungstenite::tungstenite::Error) -> std::io::Error {
    std::io::Error::other(error)
}

pub(crate) type NativeWebSocketTransport =
    TungsteniteTransport<MaybeTlsStream<tokio::net::TcpStream>>;

pub(crate) async fn connect_native(
    url: &Url,
    origin: Option<&str>,
    timeout: std::time::Duration,
) -> std::io::Result<Arc<NativeWebSocketTransport>> {
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    if let Some(origin) = origin {
        request.headers_mut().insert(
            http::header::ORIGIN,
            http::HeaderValue::from_str(origin)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?,
        );
    }
    let (stream, _) = tokio::time::timeout(timeout, connect_async(request))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "WebSocket connect timed out")
        })?
        .map_err(io_error)?;
    Ok(Arc::new(TungsteniteTransport::new(stream)))
}
