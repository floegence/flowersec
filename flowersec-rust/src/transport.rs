use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, accept_async_with_config, connect_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
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
    pub fn new(stream: WebSocketStream<S>) -> std::io::Result<Self> {
        validate_websocket_config(stream.get_config())?;
        let (writer, reader) = stream.split();
        Ok(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        })
    }

    pub async fn accept(stream: S) -> std::io::Result<Self> {
        Self::accept_with_timeout(stream, crate::defaults::HANDSHAKE_TIMEOUT).await
    }

    pub async fn accept_with_timeout(
        stream: S,
        timeout: std::time::Duration,
    ) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(
            timeout,
            accept_async_with_config(stream, Some(websocket_config())),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "WebSocket accept timed out")
        })?
        .map_err(io_error)?;
        Self::new(stream)
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

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(crate::defaults::MAX_RECORD_BYTES))
        .max_frame_size(Some(crate::defaults::MAX_RECORD_BYTES))
}

fn validate_websocket_config(config: &WebSocketConfig) -> std::io::Result<()> {
    let limit = crate::defaults::MAX_RECORD_BYTES;
    let message_limited = config.max_message_size.is_some_and(|value| value <= limit);
    let frame_limited = config.max_frame_size.is_some_and(|value| value <= limit);
    if message_limited && frame_limited {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "WebSocket stream must enforce Flowersec message and frame limits",
    ))
}

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
    let (stream, _) = tokio::time::timeout(
        timeout,
        connect_async_with_config(request, Some(websocket_config()), false),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "WebSocket connect timed out"))?
    .map_err(io_error)?;
    Ok(Arc::new(TungsteniteTransport::new(stream)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{Error, protocol::Role},
    };

    #[test]
    fn native_config_uses_the_encrypted_record_limit() {
        let config = websocket_config();
        assert_eq!(
            config.max_message_size,
            Some(crate::defaults::MAX_RECORD_BYTES)
        );
        assert_eq!(
            config.max_frame_size,
            Some(crate::defaults::MAX_RECORD_BYTES)
        );
    }

    #[tokio::test]
    async fn server_accept_rejects_an_oversized_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let transport = TungsteniteTransport::accept(tcp)
                .await
                .expect("accept WebSocket");
            transport
                .receive()
                .await
                .expect_err("oversized server message must fail")
        });

        let (mut client, _) = connect_async(format!("ws://{address}"))
            .await
            .expect("connect WebSocket");
        let _ = client
            .send(Message::Binary(
                vec![0x41; crate::defaults::MAX_RECORD_BYTES + 1].into(),
            ))
            .await;
        let error = server.await.expect("server task");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn server_accept_times_out_an_incomplete_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("listener address");
        let client = tokio::spawn(tokio::net::TcpStream::connect(address));
        let (tcp, _) = listener.accept().await.expect("accept TCP");

        let error = TungsteniteTransport::accept_with_timeout(tcp, std::time::Duration::ZERO)
            .await
            .expect_err("incomplete WebSocket upgrade must time out");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(client.await.expect("client task").expect("connect client"));
    }

    #[tokio::test]
    async fn new_rejects_a_stream_without_flowersec_limits() {
        let (client, _server) = tokio::io::duplex(1024);
        let websocket = WebSocketStream::from_raw_socket(client, Role::Client, None).await;

        let error = TungsteniteTransport::new(websocket)
            .expect_err("unbounded WebSocket stream must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn native_config_rejects_an_oversized_frame() {
        let payload = vec![0x41; crate::defaults::MAX_RECORD_BYTES + 1];
        assert_capacity_error(vec![server_frame(true, 0x2, &payload)]).await;
    }

    #[tokio::test]
    async fn native_config_rejects_an_oversized_fragmented_message() {
        let payload = vec![0x42; 600 * 1024];
        assert_capacity_error(vec![
            server_frame(false, 0x2, &payload),
            server_frame(true, 0x0, &payload),
        ])
        .await;
    }

    async fn assert_capacity_error(frames: Vec<Vec<u8>>) {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut websocket =
            WebSocketStream::from_raw_socket(client, Role::Client, Some(websocket_config())).await;
        let writer = tokio::spawn(async move {
            for frame in frames {
                if server.write_all(&frame).await.is_err() {
                    return;
                }
            }
        });

        let error = websocket
            .next()
            .await
            .expect("WebSocket yielded a result")
            .expect_err("oversized WebSocket input must fail");
        assert!(
            matches!(error, Error::Capacity(_)),
            "unexpected error: {error}"
        );
        drop(websocket);
        writer.await.expect("join frame writer");
    }

    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(payload.len() + 10);
        frame.push(if fin { 0x80 | opcode } else { opcode });
        match payload.len() {
            length @ 0..=125 => frame.push(length as u8),
            length @ 126..=65_535 => {
                frame.push(126);
                frame.extend_from_slice(&(length as u16).to_be_bytes());
            }
            length => {
                frame.push(127);
                frame.extend_from_slice(&(length as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(payload);
        frame
    }
}
