use crate::{
    defaults,
    generated::flowersec::rpc::v1::StreamHello,
    streamio::{self, StreamIoError},
    yamux::{YamuxError, YamuxSession, YamuxStream},
};
use std::{future::Future, pin::Pin};
use tokio::sync::Mutex;

pub const VERSION: u32 = 1;
pub const RPC_KIND: &str = "rpc";

#[derive(Debug, thiserror::Error)]
pub(crate) enum AcceptError {
    #[error("failed to accept Yamux stream: {0}")]
    Yamux(#[source] YamuxError),
    #[error("failed to read stream hello: {0}")]
    Hello(#[source] StreamIoError),
}

type AcceptResult = Result<(String, YamuxStream), AcceptError>;
type AcceptFuture = Pin<Box<dyn Future<Output = AcceptResult> + Send>>;

pub(crate) struct Acceptor {
    session: YamuxSession,
    pending: Mutex<Option<AcceptFuture>>,
}

impl std::fmt::Debug for Acceptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Acceptor").finish_non_exhaustive()
    }
}

impl Acceptor {
    pub(crate) fn new(session: YamuxSession) -> Self {
        Self {
            session,
            pending: Mutex::new(None),
        }
    }

    pub(crate) async fn accept(&self) -> AcceptResult {
        let mut pending = self.pending.lock().await;
        if pending.is_none() {
            let session = self.session.clone();
            *pending = Some(Box::pin(async move {
                let stream = session.accept_stream().await.map_err(AcceptError::Yamux)?;
                let kind = read(&stream, defaults::MAX_STREAM_HELLO_BYTES)
                    .await
                    .map_err(AcceptError::Hello)?;
                Ok((kind, stream))
            }));
        }
        let result = pending
            .as_mut()
            .expect("pending accept is initialized")
            .await;
        *pending = None;
        result
    }
}

pub async fn write(stream: &YamuxStream, kind: &str) -> Result<(), StreamIoError> {
    if kind.trim().is_empty() {
        return Err(StreamIoError::Json(serde_json::Error::io(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "stream kind is empty"),
        )));
    }
    streamio::write_json(
        stream,
        &StreamHello {
            kind: kind.to_owned(),
            v: VERSION,
        },
    )
    .await
}

pub async fn read(stream: &YamuxStream, max_bytes: usize) -> Result<String, StreamIoError> {
    let hello: StreamHello = streamio::read_json(
        stream,
        if max_bytes == 0 {
            defaults::MAX_STREAM_HELLO_BYTES
        } else {
            max_bytes
        },
    )
    .await?;
    if hello.v != VERSION || hello.kind.trim().is_empty() {
        return Err(StreamIoError::Json(serde_json::Error::io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid stream hello"),
        )));
    }
    Ok(hello.kind)
}
