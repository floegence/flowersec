//! Carrier-neutral accepted-session handler registration.

use std::{collections::HashMap, fmt, sync::Arc};

use async_trait::async_trait;
use tokio::{sync::Semaphore, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    session_v2::RpcHandlerV2,
    transport_v2::{IncomingStream, RpcError, Session, SessionError},
};

const DEFAULT_MAX_CONCURRENT_STREAMS: usize = 64;
const MAX_CONCURRENT_STREAMS: usize = 128;

/// Bounded dispatch options for one accepted session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionHandlerOptions {
    pub max_concurrent_streams: usize,
}

/// Stable registration failure for invalid or duplicate handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HandlerRegistrationError {
    #[error("invalid Flowersec session handler")]
    Invalid,
    #[error("Flowersec session handler is already registered")]
    AlreadyRegistered,
}

/// Handles one bounded JSON RPC request or notification.
#[async_trait]
pub trait RpcHandler: Send + Sync + 'static {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError>;

    async fn notify(&self, type_id: u32, request: serde_json::Value) -> Result<(), RpcError>;
}

/// Handles one inbound RPC notification without producing a response.
#[async_trait]
pub trait NotificationHandler: Send + Sync + 'static {
    async fn handle_notification(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<(), RpcError>;
}

/// Handles one authenticated application stream without carrier access.
#[async_trait]
pub trait StreamHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        stream: &IncomingStream,
        cancellation: CancellationToken,
    ) -> Result<(), SessionError>;
}

/// Immutable handler set consumed by [`crate::Acceptor::accept_with_handlers`].
pub struct SessionHandlers {
    max_concurrent_streams: usize,
    rpc: HashMap<u32, Arc<dyn RpcHandler>>,
    notifications: HashMap<u32, Arc<dyn NotificationHandler>>,
    streams: HashMap<String, Arc<dyn StreamHandler>>,
}

impl SessionHandlers {
    pub fn new(options: SessionHandlerOptions) -> Result<Self, HandlerRegistrationError> {
        let max_concurrent_streams = if options.max_concurrent_streams == 0 {
            DEFAULT_MAX_CONCURRENT_STREAMS
        } else {
            options.max_concurrent_streams
        };
        if !(1..=MAX_CONCURRENT_STREAMS).contains(&max_concurrent_streams) {
            return Err(HandlerRegistrationError::Invalid);
        }
        Ok(Self {
            max_concurrent_streams,
            rpc: HashMap::new(),
            notifications: HashMap::new(),
            streams: HashMap::new(),
        })
    }

    pub fn handle_rpc<H>(
        &mut self,
        type_id: u32,
        handler: H,
    ) -> Result<(), HandlerRegistrationError>
    where
        H: RpcHandler,
    {
        if type_id == 0 || self.notifications.contains_key(&type_id) {
            return Err(HandlerRegistrationError::Invalid);
        }
        if self.rpc.insert(type_id, Arc::new(handler)).is_some() {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
        Ok(())
    }

    pub fn handle_stream<K, H>(
        &mut self,
        kind: K,
        handler: H,
    ) -> Result<(), HandlerRegistrationError>
    where
        K: Into<String>,
        H: StreamHandler,
    {
        let kind = kind.into();
        if kind.is_empty() || kind.len() > 255 || kind == "flowersec.rpc.v2" {
            return Err(HandlerRegistrationError::Invalid);
        }
        if self.streams.insert(kind, Arc::new(handler)).is_some() {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
        Ok(())
    }

    pub(crate) fn handle_streams(
        &mut self,
        handlers: impl IntoIterator<Item = (String, Arc<dyn StreamHandler>)>,
    ) -> Result<(), HandlerRegistrationError> {
        let handlers: Vec<_> = handlers.into_iter().collect();
        for (kind, _) in &handlers {
            if kind.is_empty()
                || kind.len() > 255
                || kind == "flowersec.rpc.v2"
                || self.streams.contains_key(kind)
            {
                return Err(if self.streams.contains_key(kind) {
                    HandlerRegistrationError::AlreadyRegistered
                } else {
                    HandlerRegistrationError::Invalid
                });
            }
        }
        if handlers
            .iter()
            .enumerate()
            .any(|(index, (kind, _))| handlers[..index].iter().any(|(seen, _)| seen == kind))
        {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
        self.streams.extend(handlers);
        Ok(())
    }

    pub fn handle_notification<H>(
        &mut self,
        type_id: u32,
        handler: H,
    ) -> Result<(), HandlerRegistrationError>
    where
        H: NotificationHandler,
    {
        if type_id == 0 || self.rpc.contains_key(&type_id) {
            return Err(HandlerRegistrationError::Invalid);
        }
        if self
            .notifications
            .insert(type_id, Arc::new(handler))
            .is_some()
        {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
        Ok(())
    }

    pub(crate) fn rpc_handler(&self) -> Arc<dyn RpcHandlerV2> {
        Arc::new(RpcHandlers {
            handlers: self.rpc.clone(),
            notifications: self.notifications.clone(),
        })
    }
}

impl fmt::Debug for SessionHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionHandlers { <opaque> }")
    }
}

struct RpcHandlers {
    handlers: HashMap<u32, Arc<dyn RpcHandler>>,
    notifications: HashMap<u32, Arc<dyn NotificationHandler>>,
}

impl fmt::Debug for RpcHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpcHandlers { <opaque> }")
    }
}

#[async_trait]
impl RpcHandlerV2 for RpcHandlers {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let handler = self.handlers.get(&type_id).ok_or_else(|| {
            RpcError::new(404, Some("handler not found".into())).expect("valid RPC error")
        })?;
        handler.call(type_id, request).await
    }

    async fn notify(&self, type_id: u32, request: serde_json::Value) -> Result<(), RpcError> {
        if let Some(handler) = self.notifications.get(&type_id) {
            return handler.handle_notification(type_id, request).await;
        }
        if let Some(handler) = self.handlers.get(&type_id) {
            handler.notify(type_id, request).await
        } else {
            Ok(())
        }
    }
}

/// One accepted public session paired with its frozen handlers.
pub struct AcceptedSession {
    session: Arc<dyn Session>,
    handlers: Arc<SessionHandlers>,
}

impl AcceptedSession {
    pub(crate) fn new(session: Arc<dyn Session>, handlers: SessionHandlers) -> Self {
        Self {
            session,
            handlers: Arc::new(handlers),
        }
    }

    pub fn session(&self) -> &dyn Session {
        self.session.as_ref()
    }

    pub async fn serve(&self, cancellation: CancellationToken) -> Result<(), SessionError> {
        let permits = Arc::new(Semaphore::new(self.handlers.max_concurrent_streams));
        let mut tasks = JoinSet::new();
        let result = loop {
            let incoming = tokio::select! {
                _ = cancellation.cancelled() => break Err(SessionError::Canceled),
                accepted = self.session.accept_stream() => accepted,
            }?;
            let Some(handler) = self.handlers.streams.get(incoming.kind()).cloned() else {
                let _ = incoming.stream().reset().await;
                continue;
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                let _ = incoming.stream().reset().await;
                continue;
            };
            let handler_cancellation = cancellation.child_token();
            tasks.spawn(async move {
                let _permit = permit;
                let succeeded = handler
                    .handle(&incoming, handler_cancellation)
                    .await
                    .is_ok();
                if !succeeded {
                    let _ = incoming.stream().reset().await;
                } else {
                    let _ = incoming.stream().close_write().await;
                }
            });
        };
        let _ = self.session.close().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}

impl fmt::Debug for AcceptedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcceptedSession { <opaque> }")
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;

    #[derive(Debug)]
    struct NoopStreamHandler;

    #[async_trait]
    impl StreamHandler for NoopStreamHandler {
        async fn handle(
            &self,
            _stream: &IncomingStream,
            _cancellation: CancellationToken,
        ) -> Result<(), SessionError> {
            Ok(())
        }
    }

    #[derive(serde::Deserialize)]
    struct StreamKindVectors {
        stream_kinds: Vec<StreamKindVector>,
        duplicate_kind: String,
    }

    #[derive(serde::Deserialize)]
    struct StreamKindVector {
        id: String,
        unit: String,
        repeat: usize,
        suffix: String,
        valid: bool,
    }

    #[test]
    fn enforces_shared_utf8_stream_kind_contract() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/transport_v2/session_handler_vectors.json");
        let vectors: StreamKindVectors =
            serde_json::from_slice(&fs::read(path).expect("read session handler vectors"))
                .expect("decode session handler vectors");
        for vector in vectors.stream_kinds {
            let mut handlers =
                SessionHandlers::new(SessionHandlerOptions::default()).expect("create handlers");
            let kind = format!("{}{}", vector.unit.repeat(vector.repeat), vector.suffix);
            let result = handlers.handle_stream(kind, NoopStreamHandler);
            assert_eq!(
                result.is_ok(),
                vector.valid,
                "stream kind vector {}",
                vector.id
            );
            if !vector.valid {
                assert_eq!(result, Err(HandlerRegistrationError::Invalid));
            }
        }

        let mut handlers =
            SessionHandlers::new(SessionHandlerOptions::default()).expect("create handlers");
        handlers
            .handle_stream(vectors.duplicate_kind.clone(), NoopStreamHandler)
            .expect("register stream handler");
        assert_eq!(
            handlers.handle_stream(vectors.duplicate_kind, NoopStreamHandler),
            Err(HandlerRegistrationError::AlreadyRegistered)
        );
    }
}
