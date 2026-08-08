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
pub trait RpcHandler: fmt::Debug + Send + Sync + 'static {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError>;

    async fn notify(&self, type_id: u32, request: serde_json::Value) -> Result<(), RpcError>;
}

/// Handles one authenticated application stream without carrier access.
#[async_trait]
pub trait StreamHandler: fmt::Debug + Send + Sync + 'static {
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
            streams: HashMap::new(),
        })
    }

    pub fn handle_rpc(
        &mut self,
        type_id: u32,
        handler: Arc<dyn RpcHandler>,
    ) -> Result<(), HandlerRegistrationError> {
        if type_id == 0 {
            return Err(HandlerRegistrationError::Invalid);
        }
        if self.rpc.insert(type_id, handler).is_some() {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
        Ok(())
    }

    pub fn handle_stream<K: Into<String>>(
        &mut self,
        kind: K,
        handler: Arc<dyn StreamHandler>,
    ) -> Result<(), HandlerRegistrationError> {
        let kind = kind.into();
        if kind.is_empty() || kind.len() > 255 || kind == "flowersec.rpc.v2" {
            return Err(HandlerRegistrationError::Invalid);
        }
        if self.streams.insert(kind, handler).is_some() {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
        Ok(())
    }

    pub(crate) fn rpc_handler(&self) -> Arc<dyn RpcHandlerV2> {
        Arc::new(RpcHandlers {
            handlers: self.rpc.clone(),
        })
    }
}

impl fmt::Debug for SessionHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionHandlers { <opaque> }")
    }
}

#[derive(Debug)]
struct RpcHandlers {
    handlers: HashMap<u32, Arc<dyn RpcHandler>>,
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

    pub async fn serve(self, cancellation: CancellationToken) -> Result<(), SessionError> {
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
                let _ = handler.handle(&incoming, handler_cancellation).await;
                let _ = incoming.stream().close().await;
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
