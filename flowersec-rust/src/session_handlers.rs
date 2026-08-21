//! Carrier-neutral stream dispatch and role-specific RPC handler registration.

use std::{collections::HashMap, fmt, panic::AssertUnwindSafe, sync::Arc};

use async_trait::async_trait;
use futures_util::FutureExt;
use tokio::{sync::Semaphore, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    protocol_v2::valid_open_kind,
    session_v2::RpcHandlerV2,
    session_v3::RpcHandlerV3,
    transport_v2::{IncomingStream, RpcError, Session, SessionError},
};

const DEFAULT_MAX_CONCURRENT_STREAMS: usize = 64;
const MAX_CONCURRENT_STREAMS: usize = 128;

/// Bounded dispatch options for one accepted session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionHandlerOptions {
    pub max_concurrent_streams: usize,
}

/// Bounded dispatch options for application streams on any established session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamHandlerOptions {
    pub max_concurrent_streams: usize,
}

/// Stable registration failure for invalid or duplicate handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HandlerRegistrationError {
    #[error("invalid Flowersec handler registration")]
    Invalid,
    #[error("Flowersec handler is already registered")]
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

mod sealed {
    use std::sync::Arc;

    use super::{HandlerRegistrationError, StreamHandler};

    pub trait Sealed {
        fn register_stream_handlers(
            &mut self,
            handlers: Vec<(String, Arc<dyn StreamHandler>)>,
        ) -> Result<(), HandlerRegistrationError>;
    }
}

/// Sealed application-stream registration boundary for SDK-owned servers.
pub trait StreamHandlerRegistrar: sealed::Sealed {}

/// Carrier-neutral application-stream registry and dispatcher.
pub struct StreamHandlers {
    max_concurrent_streams: usize,
    streams: HashMap<String, Arc<dyn StreamHandler>>,
    snapshot: Option<Arc<StreamHandlerSnapshot>>,
}

impl StreamHandlers {
    pub fn new(options: StreamHandlerOptions) -> Result<Self, HandlerRegistrationError> {
        let max_concurrent_streams = effective_stream_limit(options.max_concurrent_streams)?;
        Ok(Self {
            max_concurrent_streams,
            streams: HashMap::new(),
            snapshot: None,
        })
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
        sealed::Sealed::register_stream_handlers(self, vec![(kind.into(), Arc::new(handler))])
    }

    /// Serves application streams until cancellation or session termination.
    /// The registry is frozen on first use.
    pub async fn serve(
        &mut self,
        session: &dyn Session,
        cancellation: CancellationToken,
    ) -> Result<(), SessionError> {
        let snapshot = self.snapshot();
        serve_stream_snapshot(session, snapshot.as_ref(), cancellation).await
    }

    fn snapshot(&mut self) -> Arc<StreamHandlerSnapshot> {
        if let Some(snapshot) = &self.snapshot {
            return snapshot.clone();
        }
        let snapshot = Arc::new(StreamHandlerSnapshot {
            streams: self.streams.clone(),
            max_concurrent_streams: self.max_concurrent_streams,
        });
        self.snapshot = Some(snapshot.clone());
        snapshot
    }
}

impl sealed::Sealed for StreamHandlers {
    fn register_stream_handlers(
        &mut self,
        handlers: Vec<(String, Arc<dyn StreamHandler>)>,
    ) -> Result<(), HandlerRegistrationError> {
        if self.snapshot.is_some() {
            return Err(HandlerRegistrationError::Invalid);
        }
        validate_stream_registrations(&self.streams, &handlers)?;
        self.streams.extend(handlers);
        Ok(())
    }
}

impl StreamHandlerRegistrar for StreamHandlers {}

impl Default for StreamHandlers {
    fn default() -> Self {
        Self::new(StreamHandlerOptions::default()).expect("valid Flowersec defaults")
    }
}

impl fmt::Debug for StreamHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamHandlers { <opaque> }")
    }
}

fn effective_stream_limit(value: usize) -> Result<usize, HandlerRegistrationError> {
    let value = if value == 0 {
        DEFAULT_MAX_CONCURRENT_STREAMS
    } else {
        value
    };
    if !(1..=MAX_CONCURRENT_STREAMS).contains(&value) {
        return Err(HandlerRegistrationError::Invalid);
    }
    Ok(value)
}

fn validate_stream_registrations(
    existing: &HashMap<String, Arc<dyn StreamHandler>>,
    handlers: &[(String, Arc<dyn StreamHandler>)],
) -> Result<(), HandlerRegistrationError> {
    if handlers.is_empty() {
        return Err(HandlerRegistrationError::Invalid);
    }
    for (index, (kind, _)) in handlers.iter().enumerate() {
        if !valid_open_kind(kind)
            || matches!(kind.as_str(), "flowersec.rpc.v2" | "flowersec.rpc.v3")
        {
            return Err(HandlerRegistrationError::Invalid);
        }
        if existing.contains_key(kind) || handlers[..index].iter().any(|(seen, _)| seen == kind) {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
    }
    Ok(())
}

/// Reusable inbound RPC and notification definitions for client sessions.
///
/// The builder is consumed by [`crate::ConnectorOptions::with_rpc_handlers`].
/// It intentionally has no application-stream registration API; accepted
/// server sessions use [`SessionHandlers`] for that role.
///
/// ```compile_fail
/// use flowersec::RpcHandlers;
///
/// let mut handlers = RpcHandlers::new();
/// handlers.handle_stream("application.stream", |_stream, _cancellation| async { Ok(()) });
/// ```
pub struct RpcHandlers {
    requests: HashMap<u32, Arc<dyn RpcHandler>>,
    notifications: HashMap<u32, Arc<dyn NotificationHandler>>,
}

impl RpcHandlers {
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
            notifications: HashMap::new(),
        }
    }

    pub fn handle_rpc<H>(
        &mut self,
        type_id: u32,
        handler: H,
    ) -> Result<(), HandlerRegistrationError>
    where
        H: RpcHandler,
    {
        if type_id == 0 {
            return Err(HandlerRegistrationError::Invalid);
        }
        if self.requests.contains_key(&type_id) || self.notifications.contains_key(&type_id) {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
        self.requests.insert(type_id, Arc::new(handler));
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
        if type_id == 0 {
            return Err(HandlerRegistrationError::Invalid);
        }
        if self.requests.contains_key(&type_id) || self.notifications.contains_key(&type_id) {
            return Err(HandlerRegistrationError::AlreadyRegistered);
        }
        self.notifications.insert(type_id, Arc::new(handler));
        Ok(())
    }

    pub(crate) fn into_snapshot(self) -> Arc<RpcHandlerSnapshot> {
        Arc::new(RpcHandlerSnapshot {
            requests: self.requests,
            notifications: self.notifications,
        })
    }
}

impl Default for RpcHandlers {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RpcHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpcHandlers { <opaque> }")
    }
}

#[derive(Clone)]
pub(crate) struct RpcHandlerSnapshot {
    requests: HashMap<u32, Arc<dyn RpcHandler>>,
    notifications: HashMap<u32, Arc<dyn NotificationHandler>>,
}

pub(crate) fn rpc_router(snapshot: Arc<RpcHandlerSnapshot>) -> Arc<dyn RpcHandlerV2> {
    Arc::new(RpcRouterAdapter::new(snapshot))
}

pub(crate) fn rpc_router_v3(snapshot: Arc<RpcHandlerSnapshot>) -> Arc<dyn RpcHandlerV3> {
    Arc::new(RpcRouterAdapter::new(snapshot))
}

struct RpcRouterAdapter {
    snapshot: Arc<RpcHandlerSnapshot>,
}

impl RpcRouterAdapter {
    fn new(snapshot: Arc<RpcHandlerSnapshot>) -> Self {
        Self { snapshot }
    }
}

impl fmt::Debug for RpcRouterAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpcRouterAdapter { <opaque> }")
    }
}

#[async_trait]
impl RpcHandlerV2 for RpcRouterAdapter {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let handler = self.snapshot.requests.get(&type_id).ok_or_else(|| {
            RpcError::new(404, Some("handler not found".into())).expect("valid RPC error")
        })?;
        handler.call(type_id, request).await
    }

    async fn notify(&self, type_id: u32, request: serde_json::Value) -> Result<(), RpcError> {
        if let Some(handler) = self.snapshot.notifications.get(&type_id) {
            return handler.handle_notification(type_id, request).await;
        }
        if let Some(handler) = self.snapshot.requests.get(&type_id) {
            handler.notify(type_id, request).await
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl RpcHandlerV3 for RpcRouterAdapter {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let handler = self.snapshot.requests.get(&type_id).ok_or_else(|| {
            RpcError::new(404, Some("handler not found".into())).expect("valid RPC error")
        })?;
        handler.call(type_id, request).await
    }

    async fn notify(&self, type_id: u32, request: serde_json::Value) -> Result<(), RpcError> {
        if let Some(handler) = self.snapshot.notifications.get(&type_id) {
            return handler.handle_notification(type_id, request).await;
        }
        if let Some(handler) = self.snapshot.requests.get(&type_id) {
            handler.notify(type_id, request).await
        } else {
            Ok(())
        }
    }
}

/// Immutable handler set consumed by [`crate::Acceptor::accept_with_handlers`].
pub struct SessionHandlers {
    rpc: RpcHandlers,
    streams: StreamHandlers,
}

impl SessionHandlers {
    pub fn new(options: SessionHandlerOptions) -> Result<Self, HandlerRegistrationError> {
        Ok(Self {
            rpc: RpcHandlers::new(),
            streams: StreamHandlers::new(StreamHandlerOptions {
                max_concurrent_streams: options.max_concurrent_streams,
            })?,
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
        self.rpc.handle_rpc(type_id, handler)
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
        self.streams.handle_stream(kind, handler)
    }

    pub fn handle_notification<H>(
        &mut self,
        type_id: u32,
        handler: H,
    ) -> Result<(), HandlerRegistrationError>
    where
        H: NotificationHandler,
    {
        self.rpc.handle_notification(type_id, handler)
    }

    pub(crate) fn into_snapshot(mut self) -> Arc<SessionHandlerSnapshot> {
        Arc::new(SessionHandlerSnapshot {
            rpc: self.rpc.into_snapshot(),
            streams: self.streams.snapshot(),
        })
    }
}

impl fmt::Debug for SessionHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionHandlers { <opaque> }")
    }
}

impl sealed::Sealed for SessionHandlers {
    fn register_stream_handlers(
        &mut self,
        handlers: Vec<(String, Arc<dyn StreamHandler>)>,
    ) -> Result<(), HandlerRegistrationError> {
        sealed::Sealed::register_stream_handlers(&mut self.streams, handlers)
    }
}

impl StreamHandlerRegistrar for SessionHandlers {}

pub(crate) fn register_stream_handlers<R: StreamHandlerRegistrar>(
    registrar: &mut R,
    handlers: Vec<(String, Arc<dyn StreamHandler>)>,
) -> Result<(), HandlerRegistrationError> {
    sealed::Sealed::register_stream_handlers(registrar, handlers)
}

struct StreamHandlerSnapshot {
    streams: HashMap<String, Arc<dyn StreamHandler>>,
    max_concurrent_streams: usize,
}

pub(crate) struct SessionHandlerSnapshot {
    pub(crate) rpc: Arc<RpcHandlerSnapshot>,
    streams: Arc<StreamHandlerSnapshot>,
}

/// One accepted public session paired with its frozen handlers.
pub struct AcceptedSession {
    session: Arc<dyn Session>,
    handlers: Arc<SessionHandlerSnapshot>,
}

impl AcceptedSession {
    pub(crate) fn new(session: Arc<dyn Session>, handlers: Arc<SessionHandlerSnapshot>) -> Self {
        Self { session, handlers }
    }

    pub fn session(&self) -> &dyn Session {
        self.session.as_ref()
    }

    pub async fn serve(&self, cancellation: CancellationToken) -> Result<(), SessionError> {
        serve_stream_snapshot(
            self.session.as_ref(),
            self.handlers.streams.as_ref(),
            cancellation,
        )
        .await
    }
}

async fn serve_stream_snapshot(
    session: &dyn Session,
    handlers: &StreamHandlerSnapshot,
    cancellation: CancellationToken,
) -> Result<(), SessionError> {
    let permits = Arc::new(Semaphore::new(handlers.max_concurrent_streams));
    let mut tasks = JoinSet::new();
    let handler_shutdown = cancellation.child_token();
    let result = loop {
        while tasks.try_join_next().is_some() {}
        let incoming = tokio::select! {
            _ = cancellation.cancelled() => break Err(SessionError::Canceled),
            accepted = session.accept_stream() => accepted,
        };
        let incoming = match incoming {
            Ok(incoming) => incoming,
            Err(error) => break Err(error),
        };
        let Some(handler) = handlers.streams.get(incoming.kind()).cloned() else {
            let _ = incoming.stream().reset().await;
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            let _ = incoming.stream().reset().await;
            continue;
        };
        let handler_cancellation = handler_shutdown.child_token();
        let cleanup_shutdown = handler_shutdown.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let succeeded =
                AssertUnwindSafe(handler.handle(&incoming, handler_cancellation.clone()))
                    .catch_unwind()
                    .await
                    .is_ok_and(|result| result.is_ok());
            if !succeeded {
                tokio::select! {
                    biased;
                    _ = cleanup_shutdown.cancelled() => {},
                    _ = incoming.stream().reset() => {},
                }
                return;
            }
            let close_result = tokio::select! {
                biased;
                _ = cleanup_shutdown.cancelled() => return,
                result = incoming.stream().close_write() => result,
            };
            if close_result.is_err() {
                tokio::select! {
                    biased;
                    _ = cleanup_shutdown.cancelled() => {},
                    _ = incoming.stream().reset() => {},
                }
            }
        });
    };
    handler_shutdown.cancel();
    let _ = session.close().await;
    while tasks.join_next().await.is_some() {}
    result
}

impl fmt::Debug for AcceptedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcceptedSession { <opaque> }")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        future::pending,
        path::PathBuf,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::Duration,
    };

    use bytes::Bytes;
    use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

    use super::*;
    use crate::transport_v2::{
        ByteStream, NotificationSubscription, RpcCallError, RpcPeer, SessionTermination,
        StreamMetadata,
    };

    #[derive(Debug)]
    struct NoopStreamHandler;

    #[derive(Debug)]
    struct ValueRpcHandler(&'static str);

    #[async_trait]
    impl RpcHandler for ValueRpcHandler {
        async fn call(
            &self,
            _type_id: u32,
            _request: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            Ok(serde_json::Value::String(self.0.into()))
        }

        async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct NoopNotificationHandler;

    #[async_trait]
    impl NotificationHandler for NoopNotificationHandler {
        async fn handle_notification(
            &self,
            _type_id: u32,
            _request: serde_json::Value,
        ) -> Result<(), RpcError> {
            Ok(())
        }
    }

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

    #[derive(Debug)]
    struct StreamTestRpcPeer;

    #[async_trait]
    impl RpcPeer for StreamTestRpcPeer {
        async fn call(
            &self,
            _type_id: u32,
            _request: serde_json::Value,
        ) -> Result<serde_json::Value, RpcCallError> {
            Err(RpcCallError::Session(SessionError::OperationFailed))
        }

        async fn notify(
            &self,
            _type_id: u32,
            _request: serde_json::Value,
        ) -> Result<(), SessionError> {
            Err(SessionError::OperationFailed)
        }

        fn subscribe_notification(
            &self,
            _type_id: u32,
            _handler: Arc<dyn Fn(serde_json::Value) + Send + Sync>,
        ) -> Result<NotificationSubscription, SessionError> {
            Err(SessionError::OperationFailed)
        }
    }

    struct StreamTestSession {
        rpc: StreamTestRpcPeer,
        incoming: AsyncMutex<mpsc::UnboundedReceiver<Result<IncomingStream, SessionError>>>,
        sender: mpsc::UnboundedSender<Result<IncomingStream, SessionError>>,
        close_count: Arc<AtomicUsize>,
    }

    impl StreamTestSession {
        fn new() -> Self {
            let (sender, incoming) = mpsc::unbounded_channel();
            Self {
                rpc: StreamTestRpcPeer,
                incoming: AsyncMutex::new(incoming),
                sender,
                close_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn enqueue(&self, incoming: Result<IncomingStream, SessionError>) {
            self.sender
                .send(incoming)
                .expect("stream test session is open");
        }
    }

    impl fmt::Debug for StreamTestSession {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("StreamTestSession")
        }
    }

    #[async_trait]
    impl Session for StreamTestSession {
        fn rpc(&self) -> &dyn RpcPeer {
            &self.rpc
        }

        async fn open_stream(
            &self,
            _kind: &str,
            _metadata: StreamMetadata,
        ) -> Result<Box<dyn ByteStream>, SessionError> {
            Err(SessionError::OperationFailed)
        }

        async fn accept_stream(&self) -> Result<IncomingStream, SessionError> {
            self.incoming
                .lock()
                .await
                .recv()
                .await
                .unwrap_or(Err(SessionError::Closed))
        }

        async fn rekey(&self) -> Result<(), SessionError> {
            Ok(())
        }

        async fn probe_liveness(&self) -> Result<Duration, SessionError> {
            Ok(Duration::ZERO)
        }

        async fn wait_termination(&self) -> SessionTermination {
            SessionTermination {
                error: SessionError::Closed,
            }
        }

        async fn close(&self) -> Result<(), SessionError> {
            self.close_count.fetch_add(1, Ordering::SeqCst);
            let _ = self.sender.send(Err(SessionError::Closed));
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct StreamTestState {
        close_write_count: AtomicUsize,
        reset_count: AtomicUsize,
    }

    #[derive(Debug)]
    struct StreamTestByteStream {
        kind: String,
        state: Arc<StreamTestState>,
        fail_close_write: bool,
        block_close_write: bool,
        block_reset: bool,
    }

    #[async_trait]
    impl ByteStream for StreamTestByteStream {
        fn internal_test_id(&self) -> u64 {
            1
        }

        fn kind(&self) -> &str {
            &self.kind
        }

        fn terminal_error(&self) -> Option<SessionError> {
            None
        }

        async fn read(&self) -> Result<Option<Bytes>, SessionError> {
            Ok(None)
        }

        async fn write(&self, payload: Bytes) -> Result<usize, SessionError> {
            Ok(payload.len())
        }

        async fn close_write(&self) -> Result<(), SessionError> {
            self.state.close_write_count.fetch_add(1, Ordering::SeqCst);
            if self.block_close_write {
                pending::<()>().await;
            }
            if self.fail_close_write {
                Err(SessionError::OperationFailed)
            } else {
                Ok(())
            }
        }

        async fn reset(&self) -> Result<(), SessionError> {
            self.state.reset_count.fetch_add(1, Ordering::SeqCst);
            if self.block_reset {
                pending::<()>().await;
            }
            Ok(())
        }

        async fn close(&self) -> Result<(), SessionError> {
            self.reset().await
        }
    }

    fn stream_test_incoming(
        kind: &str,
        state: Arc<StreamTestState>,
        fail_close_write: bool,
    ) -> IncomingStream {
        IncomingStream::new(
            kind,
            StreamMetadata::empty(),
            Box::new(StreamTestByteStream {
                kind: kind.to_owned(),
                state,
                fail_close_write,
                block_close_write: false,
                block_reset: false,
            }),
        )
    }

    fn stream_test_incoming_with_blocking_cleanup(
        kind: &str,
        state: Arc<StreamTestState>,
        fail_close_write: bool,
        block_close_write: bool,
        block_reset: bool,
    ) -> IncomingStream {
        IncomingStream::new(
            kind,
            StreamMetadata::empty(),
            Box::new(StreamTestByteStream {
                kind: kind.to_owned(),
                state,
                fail_close_write,
                block_close_write,
                block_reset,
            }),
        )
    }

    #[derive(Clone, Copy, Debug)]
    enum StreamTestBehavior {
        Success,
        Failure,
        Panic,
        WaitForCancellation,
        WaitForCancellationThenFailure,
        SelfCancelSuccess,
        SelfCancelFailure,
    }

    #[derive(Debug)]
    struct StreamTestHandler {
        behavior: StreamTestBehavior,
        started: Arc<Notify>,
        completed: Arc<AtomicBool>,
    }

    impl StreamTestHandler {
        fn new(behavior: StreamTestBehavior) -> Self {
            Self {
                behavior,
                started: Arc::new(Notify::new()),
                completed: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    #[derive(Debug)]
    struct WaitForSessionCloseHandler {
        close_count: Arc<AtomicUsize>,
        completed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl StreamHandler for WaitForSessionCloseHandler {
        async fn handle(
            &self,
            _stream: &IncomingStream,
            cancellation: CancellationToken,
        ) -> Result<(), SessionError> {
            cancellation.cancelled().await;
            while self.close_count.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            self.completed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl StreamHandler for StreamTestHandler {
        async fn handle(
            &self,
            _stream: &IncomingStream,
            cancellation: CancellationToken,
        ) -> Result<(), SessionError> {
            self.started.notify_one();
            let result = match self.behavior {
                StreamTestBehavior::Success => Ok(()),
                StreamTestBehavior::Failure => Err(SessionError::OperationFailed),
                StreamTestBehavior::Panic => panic!("stream test handler panic"),
                StreamTestBehavior::WaitForCancellation => {
                    cancellation.cancelled().await;
                    Ok(())
                }
                StreamTestBehavior::WaitForCancellationThenFailure => {
                    cancellation.cancelled().await;
                    Err(SessionError::OperationFailed)
                }
                StreamTestBehavior::SelfCancelSuccess => {
                    cancellation.cancel();
                    Ok(())
                }
                StreamTestBehavior::SelfCancelFailure => {
                    cancellation.cancel();
                    Err(SessionError::OperationFailed)
                }
            };
            self.completed.store(true, Ordering::SeqCst);
            result
        }
    }

    #[tokio::test]
    async fn stream_handlers_isolate_failures_and_continue_dispatch() {
        let session = StreamTestSession::new();
        let success = Arc::new(StreamTestState::default());
        let failure = Arc::new(StreamTestState::default());
        let panicked = Arc::new(StreamTestState::default());
        let close_failure = Arc::new(StreamTestState::default());
        let self_canceled_success = Arc::new(StreamTestState::default());
        let self_canceled_failure = Arc::new(StreamTestState::default());
        let unknown = Arc::new(StreamTestState::default());
        session.enqueue(Ok(stream_test_incoming("success", success.clone(), false)));
        session.enqueue(Ok(stream_test_incoming("failure", failure.clone(), false)));
        session.enqueue(Ok(stream_test_incoming("panic", panicked.clone(), false)));
        session.enqueue(Ok(stream_test_incoming(
            "close-failure",
            close_failure.clone(),
            true,
        )));
        session.enqueue(Ok(stream_test_incoming(
            "self-canceled-success",
            self_canceled_success.clone(),
            false,
        )));
        session.enqueue(Ok(stream_test_incoming(
            "self-canceled-failure",
            self_canceled_failure.clone(),
            false,
        )));
        session.enqueue(Ok(stream_test_incoming("unknown", unknown.clone(), false)));

        let mut handlers = StreamHandlers::default();
        handlers
            .handle_stream(
                "success",
                StreamTestHandler::new(StreamTestBehavior::Success),
            )
            .expect("register success handler");
        handlers
            .handle_stream(
                "failure",
                StreamTestHandler::new(StreamTestBehavior::Failure),
            )
            .expect("register failure handler");
        handlers
            .handle_stream("panic", StreamTestHandler::new(StreamTestBehavior::Panic))
            .expect("register panic handler");
        handlers
            .handle_stream(
                "close-failure",
                StreamTestHandler::new(StreamTestBehavior::Success),
            )
            .expect("register close failure handler");
        handlers
            .handle_stream(
                "self-canceled-success",
                StreamTestHandler::new(StreamTestBehavior::SelfCancelSuccess),
            )
            .expect("register self-canceling success handler");
        handlers
            .handle_stream(
                "self-canceled-failure",
                StreamTestHandler::new(StreamTestBehavior::SelfCancelFailure),
            )
            .expect("register self-canceling failure handler");

        let serving = handlers.serve(&session, CancellationToken::new());
        let terminating = async {
            while success.close_write_count.load(Ordering::SeqCst) == 0
                || failure.reset_count.load(Ordering::SeqCst) == 0
                || panicked.reset_count.load(Ordering::SeqCst) == 0
                || close_failure.reset_count.load(Ordering::SeqCst) == 0
                || self_canceled_success
                    .close_write_count
                    .load(Ordering::SeqCst)
                    == 0
                || self_canceled_failure.reset_count.load(Ordering::SeqCst) == 0
                || unknown.reset_count.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
            session.enqueue(Err(SessionError::Closed));
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(serving, terminating)
        })
        .await
        .expect("stream serving cleanup timed out");
        assert_eq!(result, Err(SessionError::Closed));
        assert_eq!(session.close_count.load(Ordering::SeqCst), 1);
        assert_eq!(success.close_write_count.load(Ordering::SeqCst), 1);
        assert_eq!(success.reset_count.load(Ordering::SeqCst), 0);
        assert_eq!(failure.close_write_count.load(Ordering::SeqCst), 0);
        assert_eq!(failure.reset_count.load(Ordering::SeqCst), 1);
        assert_eq!(panicked.close_write_count.load(Ordering::SeqCst), 0);
        assert_eq!(panicked.reset_count.load(Ordering::SeqCst), 1);
        assert_eq!(close_failure.close_write_count.load(Ordering::SeqCst), 1);
        assert_eq!(close_failure.reset_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            self_canceled_success
                .close_write_count
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(self_canceled_success.reset_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            self_canceled_failure
                .close_write_count
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(self_canceled_failure.reset_count.load(Ordering::SeqCst), 1);
        assert_eq!(unknown.reset_count.load(Ordering::SeqCst), 1);
    }

    async fn assert_pending_cleanup_yields_to_shutdown(
        behavior: StreamTestBehavior,
        fail_close_write: bool,
        block_close_write: bool,
        block_reset: bool,
        wait_for_reset: bool,
    ) {
        let session = StreamTestSession::new();
        let active = Arc::new(StreamTestState::default());
        session.enqueue(Ok(stream_test_incoming_with_blocking_cleanup(
            "held",
            active.clone(),
            fail_close_write,
            block_close_write,
            block_reset,
        )));

        let mut handlers = StreamHandlers::default();
        handlers
            .handle_stream("held", StreamTestHandler::new(behavior))
            .expect("register cleanup handler");
        let cancellation = CancellationToken::new();
        let serving = handlers.serve(&session, cancellation.clone());
        let canceling = async {
            loop {
                let count = if wait_for_reset {
                    active.reset_count.load(Ordering::SeqCst)
                } else {
                    active.close_write_count.load(Ordering::SeqCst)
                };
                if count > 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            cancellation.cancel();
        };

        let (result, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(serving, canceling)
        })
        .await
        .expect("pending stream cleanup did not yield to shutdown");
        assert_eq!(result, Err(SessionError::Canceled));
        assert_eq!(session.close_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pending_close_write_yields_to_shutdown() {
        assert_pending_cleanup_yields_to_shutdown(
            StreamTestBehavior::Success,
            false,
            true,
            false,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn pending_failure_reset_yields_to_shutdown() {
        assert_pending_cleanup_yields_to_shutdown(
            StreamTestBehavior::Failure,
            false,
            false,
            true,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn pending_close_failure_reset_yields_to_shutdown() {
        assert_pending_cleanup_yields_to_shutdown(
            StreamTestBehavior::Success,
            true,
            false,
            true,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn stream_handlers_close_session_before_waiting_for_handlers() {
        let session = StreamTestSession::new();
        let active = Arc::new(StreamTestState::default());
        session.enqueue(Ok(stream_test_incoming("held", active.clone(), false)));
        session.enqueue(Err(SessionError::Closed));

        let completed = Arc::new(AtomicBool::new(false));
        let mut handlers = StreamHandlers::default();
        handlers
            .handle_stream(
                "held",
                WaitForSessionCloseHandler {
                    close_count: session.close_count.clone(),
                    completed: completed.clone(),
                },
            )
            .expect("register close-order handler");

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            handlers.serve(&session, CancellationToken::new()),
        )
        .await
        .expect("session close waited for an active handler");
        assert_eq!(result, Err(SessionError::Closed));
        assert!(completed.load(Ordering::SeqCst));
        assert_eq!(session.close_count.load(Ordering::SeqCst), 1);
        assert_eq!(active.close_write_count.load(Ordering::SeqCst), 0);
        assert_eq!(active.reset_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stream_handlers_cancel_and_wait_for_active_handlers_on_session_termination() {
        let session = StreamTestSession::new();
        let active = Arc::new(StreamTestState::default());
        session.enqueue(Ok(stream_test_incoming("held", active.clone(), false)));
        session.enqueue(Err(SessionError::Closed));

        let handler = StreamTestHandler::new(StreamTestBehavior::WaitForCancellation);
        let completed = handler.completed.clone();
        let mut handlers = StreamHandlers::default();
        handlers
            .handle_stream("held", handler)
            .expect("register blocking handler");

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            handlers.serve(&session, CancellationToken::new()),
        )
        .await
        .expect("session termination cleanup timed out");
        assert_eq!(result, Err(SessionError::Closed));
        assert!(completed.load(Ordering::SeqCst));
        assert_eq!(session.close_count.load(Ordering::SeqCst), 1);
        assert_eq!(active.close_write_count.load(Ordering::SeqCst), 0);
        assert_eq!(active.reset_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stream_handlers_enforce_concurrency_and_wait_for_canceled_handlers() {
        let session = StreamTestSession::new();
        let active = Arc::new(StreamTestState::default());
        let excess = Arc::new(StreamTestState::default());
        session.enqueue(Ok(stream_test_incoming("held", active.clone(), false)));
        session.enqueue(Ok(stream_test_incoming("held", excess.clone(), false)));

        let handler = StreamTestHandler::new(StreamTestBehavior::WaitForCancellationThenFailure);
        let started = handler.started.clone();
        let completed = handler.completed.clone();
        let mut handlers = StreamHandlers::new(StreamHandlerOptions {
            max_concurrent_streams: 1,
        })
        .expect("create bounded stream handlers");
        handlers
            .handle_stream("held", handler)
            .expect("register blocking handler");
        let cancellation = CancellationToken::new();
        let serving = handlers.serve(&session, cancellation.clone());
        let canceling = async {
            started.notified().await;
            while excess.reset_count.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            cancellation.cancel();
        };

        let (result, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(serving, canceling)
        })
        .await
        .expect("canceled stream serving cleanup timed out");
        assert_eq!(result, Err(SessionError::Canceled));
        assert!(completed.load(Ordering::SeqCst));
        assert_eq!(session.close_count.load(Ordering::SeqCst), 1);
        assert_eq!(active.close_write_count.load(Ordering::SeqCst), 0);
        assert_eq!(active.reset_count.load(Ordering::SeqCst), 0);
        assert_eq!(excess.reset_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rpc_handlers_enforce_shared_namespace_and_create_fresh_routers() {
        let mut handlers = RpcHandlers::new();
        assert_eq!(
            handlers.handle_rpc(0, ValueRpcHandler("invalid")),
            Err(HandlerRegistrationError::Invalid)
        );
        handlers
            .handle_rpc(1, ValueRpcHandler("original"))
            .expect("register minimum type ID");
        handlers
            .handle_notification(u32::MAX, NoopNotificationHandler)
            .expect("register maximum type ID");
        assert_eq!(
            handlers.handle_rpc(1, ValueRpcHandler("replacement")),
            Err(HandlerRegistrationError::AlreadyRegistered)
        );
        assert_eq!(
            handlers.handle_notification(1, NoopNotificationHandler),
            Err(HandlerRegistrationError::AlreadyRegistered)
        );
        assert_eq!(format!("{handlers:?}"), "RpcHandlers { <opaque> }");
        assert_eq!(
            HandlerRegistrationError::AlreadyRegistered.to_string(),
            "Flowersec handler is already registered"
        );

        let snapshot = handlers.into_snapshot();
        let first = rpc_router(snapshot.clone());
        let second = rpc_router(snapshot);
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(
            first.call(1, serde_json::Value::Null).await,
            Ok(serde_json::Value::String("original".into()))
        );
    }

    #[derive(serde::Deserialize)]
    struct StreamKindVectors {
        stream_kinds: Vec<StreamKindVector>,
        duplicate_kind: String,
        rpc_type_ids: Vec<RpcTypeIdVector>,
        duplicate_type_id: u32,
    }

    #[derive(serde::Deserialize)]
    struct StreamKindVector {
        id: String,
        unit: String,
        repeat: usize,
        suffix: String,
        valid: bool,
    }

    #[derive(serde::Deserialize)]
    struct RpcTypeIdVector {
        id: String,
        value: u32,
        valid: bool,
    }

    #[test]
    fn enforces_shared_utf8_stream_kind_contract() {
        for version in ["v2", "v3"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
                "../testdata/transport_{version}/session_handler_vectors.json"
            ));
            let vectors: StreamKindVectors =
                serde_json::from_slice(&fs::read(path).expect("read session handler vectors"))
                    .expect("decode session handler vectors");
            for vector in vectors.stream_kinds {
                let mut handlers = SessionHandlers::new(SessionHandlerOptions::default())
                    .expect("create handlers");
                let kind = format!("{}{}", vector.unit.repeat(vector.repeat), vector.suffix);
                let result = handlers.handle_stream(kind.clone(), NoopStreamHandler);
                assert_eq!(
                    result.is_ok(),
                    vector.valid,
                    "{version} stream kind vector {}",
                    vector.id
                );
                if !vector.valid {
                    assert_eq!(result, Err(HandlerRegistrationError::Invalid));
                }
                let mut portable = StreamHandlers::default();
                let portable_result = portable.handle_stream(kind, NoopStreamHandler);
                assert_eq!(
                    portable_result.is_ok(),
                    vector.valid,
                    "{version} portable stream kind vector {}",
                    vector.id
                );
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

            for vector in vectors.rpc_type_ids {
                let mut handlers = RpcHandlers::new();
                let result = handlers.handle_rpc(vector.value, ValueRpcHandler("fixture"));
                assert_eq!(
                    result.is_ok(),
                    vector.valid,
                    "{version} RPC type ID vector {}",
                    vector.id
                );
            }
            let mut handlers = RpcHandlers::new();
            handlers
                .handle_rpc(vectors.duplicate_type_id, ValueRpcHandler("original"))
                .expect("register fixture duplicate type ID");
            assert_eq!(
                handlers.handle_notification(vectors.duplicate_type_id, NoopNotificationHandler),
                Err(HandlerRegistrationError::AlreadyRegistered)
            );
        }
    }
}
