use crate::generated::flowersec::rpc::v1::{RpcEnvelope, RpcError as WireRpcError};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, Semaphore, mpsc, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{defaults, streamio, yamux::YamuxStream};

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("RPC transport failed: {0}")]
    Transport(String),
    #[error("RPC call failed with code {code}: {message}")]
    Call { code: u32, message: String },
    #[error("RPC payload is invalid: {0}")]
    InvalidPayload(#[from] serde_json::Error),
    #[error("RPC stream closed")]
    Closed,
    #[error("RPC call timed out")]
    Timeout,
    #[error("RPC call was canceled")]
    Canceled,
    #[error("RPC request capacity is exhausted")]
    ResourceExhausted,
}

#[derive(Clone, Debug, Default)]
pub struct RpcCallOptions {
    pub timeout: Option<Duration>,
    pub cancellation: Option<CancellationToken>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcClientLimits {
    pub max_concurrent_requests: usize,
    pub max_queued_requests: usize,
}

type NotifyFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type NotifyHandler = dyn Fn(Value) -> NotifyFuture + Send + Sync;
type NotifyHandlers = HashMap<u32, HashMap<u64, Arc<NotifyHandler>>>;

pub struct RpcSubscription {
    cancel: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl std::fmt::Debug for RpcSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RpcSubscription(..)")
    }
}

impl RpcSubscription {
    pub fn cancel(mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
    }
}

impl Drop for RpcSubscription {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
    }
}

impl Default for RpcClientLimits {
    fn default() -> Self {
        Self {
            max_concurrent_requests: defaults::RPC_MAX_CONCURRENT_REQUESTS,
            max_queued_requests: defaults::RPC_MAX_QUEUED_REQUESTS,
        }
    }
}

#[async_trait::async_trait]
pub trait RpcTransport: Send + Sync + 'static {
    async fn call(&self, envelope: RpcEnvelope) -> Result<RpcEnvelope, RpcError>;
    async fn call_with_options(
        &self,
        envelope: RpcEnvelope,
        options: RpcCallOptions,
    ) -> Result<RpcEnvelope, RpcError>;
    async fn notify(&self, envelope: RpcEnvelope) -> Result<(), RpcError>;
    fn subscribe(&self, type_id: u32, handler: Arc<NotifyHandler>) -> RpcSubscription;
}

#[derive(Clone)]
pub struct RpcClient {
    transport: Arc<dyn RpcTransport>,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RpcClient(..)")
    }
}

impl RpcClient {
    pub fn new(transport: Arc<dyn RpcTransport>) -> Self {
        Self { transport }
    }

    pub fn from_stream(stream: YamuxStream) -> Self {
        Self::from_stream_with_limits(stream, RpcClientLimits::default())
    }

    pub fn from_stream_with_limits(stream: YamuxStream, limits: RpcClientLimits) -> Self {
        Self::new(StreamRpcTransport::start(stream, limits))
    }

    pub async fn call_typed<Request, Response>(
        &self,
        type_id: u32,
        request: &Request,
    ) -> Result<Response, RpcError>
    where
        Request: Serialize + Sync,
        Response: DeserializeOwned,
    {
        self.call_typed_with_options(type_id, request, RpcCallOptions::default())
            .await
    }

    pub async fn call_typed_with_options<Request, Response>(
        &self,
        type_id: u32,
        request: &Request,
        options: RpcCallOptions,
    ) -> Result<Response, RpcError>
    where
        Request: Serialize + Sync,
        Response: DeserializeOwned,
    {
        let response = self
            .transport
            .call_with_options(
                RpcEnvelope {
                    type_id,
                    request_id: 1,
                    response_to: 0,
                    payload: serde_json::to_value(request)?,
                    error: None,
                },
                options,
            )
            .await?;
        if let Some(error) = response.error {
            return Err(RpcError::Call {
                code: error.code,
                message: error.message.unwrap_or_default(),
            });
        }
        Ok(serde_json::from_value(response.payload)?)
    }

    pub async fn notify_typed<Message>(
        &self,
        type_id: u32,
        message: &Message,
    ) -> Result<(), RpcError>
    where
        Message: Serialize + Sync,
    {
        self.transport
            .notify(RpcEnvelope {
                type_id,
                request_id: 0,
                response_to: 0,
                payload: serde_json::to_value(message)?,
                error: None,
            })
            .await
    }

    pub fn on_notify_typed<Message, F, Fut>(&self, type_id: u32, handler: F) -> RpcSubscription
    where
        Message: DeserializeOwned + Send + 'static,
        F: Fn(Message) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.transport.subscribe(
            type_id,
            Arc::new(move |payload| {
                let decoded = serde_json::from_value(payload);
                let future = match decoded {
                    Ok(message) => Some(handler(message)),
                    Err(_) => None,
                };
                Box::pin(async move {
                    if let Some(future) = future {
                        future.await;
                    }
                })
            }),
        )
    }
}

struct StreamRpcTransport {
    stream: YamuxStream,
    next_request_id: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<RpcEnvelope, RpcError>>>>,
    write_serial: Mutex<()>,
    admission: Arc<Semaphore>,
    concurrent: Arc<Semaphore>,
    next_subscription_id: AtomicU64,
    notification_handlers: Arc<StdMutex<NotifyHandlers>>,
}

impl std::fmt::Debug for StreamRpcTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StreamRpcTransport(..)")
    }
}

impl StreamRpcTransport {
    fn start(stream: YamuxStream, limits: RpcClientLimits) -> Arc<Self> {
        let max_concurrent_requests = limits.max_concurrent_requests.max(1);
        let total_capacity = max_concurrent_requests.saturating_add(limits.max_queued_requests);
        let transport = Arc::new(Self {
            stream,
            next_request_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            write_serial: Mutex::new(()),
            admission: Arc::new(Semaphore::new(total_capacity)),
            concurrent: Arc::new(Semaphore::new(max_concurrent_requests)),
            next_subscription_id: AtomicU64::new(1),
            notification_handlers: Arc::new(StdMutex::new(HashMap::new())),
        });
        tokio::spawn(read_responses(transport.clone()));
        transport
    }

    async fn write(&self, envelope: &RpcEnvelope) -> Result<(), RpcError> {
        let _serial = self.write_serial.lock().await;
        streamio::write_json(&self.stream, envelope)
            .await
            .map_err(|error| RpcError::Transport(error.to_string()))
    }
}

#[async_trait::async_trait]
impl RpcTransport for StreamRpcTransport {
    async fn call(&self, envelope: RpcEnvelope) -> Result<RpcEnvelope, RpcError> {
        self.call_with_options(envelope, RpcCallOptions::default())
            .await
    }

    async fn call_with_options(
        &self,
        mut envelope: RpcEnvelope,
        options: RpcCallOptions,
    ) -> Result<RpcEnvelope, RpcError> {
        let _admission = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| RpcError::ResourceExhausted)?;
        let deadline = options.timeout.map(|timeout| Instant::now() + timeout);
        let cancellation = options.cancellation.unwrap_or_default();
        let _concurrent = controlled(
            self.concurrent.clone().acquire_owned(),
            &cancellation,
            deadline,
        )
        .await?
        .map_err(|_| RpcError::Closed)?;
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        if request_id == 0 || request_id == u64::MAX {
            return Err(RpcError::Closed);
        }
        envelope.request_id = request_id;
        envelope.response_to = 0;
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(request_id, sender);
        if let Err(error) = self.write(&envelope).await {
            self.pending.lock().await.remove(&request_id);
            return Err(error);
        }
        let result = controlled(receiver, &cancellation, deadline).await;
        match result {
            Ok(response) => response.map_err(|_| RpcError::Closed)?,
            Err(error) => {
                self.pending.lock().await.remove(&request_id);
                Err(error)
            }
        }
    }

    async fn notify(&self, mut envelope: RpcEnvelope) -> Result<(), RpcError> {
        envelope.request_id = 0;
        envelope.response_to = 0;
        self.write(&envelope).await
    }

    fn subscribe(&self, type_id: u32, handler: Arc<NotifyHandler>) -> RpcSubscription {
        let id = self
            .next_subscription_id
            .fetch_add(1, Ordering::Relaxed)
            .max(1);
        let handlers = self.notification_handlers.clone();
        handlers
            .lock()
            .expect("RPC notification handler lock poisoned")
            .entry(type_id)
            .or_default()
            .insert(id, handler);
        RpcSubscription {
            cancel: Some(Box::new(move || {
                let mut handlers = handlers
                    .lock()
                    .expect("RPC notification handler lock poisoned");
                if let Some(by_id) = handlers.get_mut(&type_id) {
                    by_id.remove(&id);
                    if by_id.is_empty() {
                        handlers.remove(&type_id);
                    }
                }
            })),
        }
    }
}

async fn controlled<F, T>(
    future: F,
    cancellation: &CancellationToken,
    deadline: Option<Instant>,
) -> Result<T, RpcError>
where
    F: std::future::Future<Output = T>,
{
    match deadline {
        Some(deadline) => {
            tokio::select! {
                _ = cancellation.cancelled() => Err(RpcError::Canceled),
                _ = tokio::time::sleep_until(deadline) => Err(RpcError::Timeout),
                output = future => Ok(output),
            }
        }
        None => {
            tokio::select! {
                _ = cancellation.cancelled() => Err(RpcError::Canceled),
                output = future => Ok(output),
            }
        }
    }
}

async fn read_responses(transport: Arc<StreamRpcTransport>) {
    loop {
        let result =
            streamio::read_json::<RpcEnvelope>(&transport.stream, defaults::MAX_JSON_FRAME_BYTES)
                .await;
        let envelope = match result {
            Ok(envelope) => envelope,
            Err(error) => {
                let mut pending = transport.pending.lock().await;
                for (_, sender) in pending.drain() {
                    let _ = sender.send(Err(RpcError::Transport(error.to_string())));
                }
                return;
            }
        };
        if envelope.response_to == 0 {
            if envelope.request_id == 0 {
                let handlers = transport
                    .notification_handlers
                    .lock()
                    .expect("RPC notification handler lock poisoned")
                    .get(&envelope.type_id)
                    .map(|handlers| handlers.values().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                for handler in handlers {
                    let payload = envelope.payload.clone();
                    tokio::spawn(handler(payload));
                }
            }
            continue;
        }
        if let Some(sender) = transport.pending.lock().await.remove(&envelope.response_to) {
            let _ = sender.send(Ok(envelope));
        }
    }
}

pub type RpcHandlerResult = Result<Value, WireRpcError>;

#[derive(Clone, Default)]
pub struct Router {
    handlers: Arc<tokio::sync::RwLock<std::collections::HashMap<u32, Arc<dyn Handler>>>>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Router(..)")
    }
}

#[async_trait::async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, payload: Value) -> RpcHandlerResult;
}

#[async_trait::async_trait]
impl<F, Fut> Handler for F
where
    F: Fn(Value) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = RpcHandlerResult> + Send,
{
    async fn handle(&self, payload: Value) -> RpcHandlerResult {
        self(payload).await
    }
}

impl Router {
    pub async fn register(&self, type_id: u32, handler: impl Handler) {
        self.handlers
            .write()
            .await
            .insert(type_id, Arc::new(handler));
    }

    pub async fn dispatch(&self, type_id: u32, payload: Value) -> RpcHandlerResult {
        let handler = self.handlers.read().await.get(&type_id).cloned();
        match handler {
            Some(handler) => handler.handle(payload).await,
            None => Err(WireRpcError {
                code: 404,
                message: Some("handler not found".to_owned()),
            }),
        }
    }
}

#[derive(Debug)]
pub struct Server {
    router: Router,
    pub max_concurrent_requests: usize,
    pub max_queued_requests: usize,
    pub max_queued_notifications: usize,
    active_stream: Mutex<Option<YamuxStream>>,
    write_serial: Arc<Mutex<()>>,
}

impl Server {
    pub fn new(router: Router) -> Self {
        Self {
            router,
            max_concurrent_requests: crate::defaults::RPC_MAX_CONCURRENT_REQUESTS,
            max_queued_requests: crate::defaults::RPC_MAX_QUEUED_REQUESTS,
            max_queued_notifications: crate::defaults::RPC_MAX_QUEUED_NOTIFICATIONS,
            active_stream: Mutex::new(None),
            write_serial: Arc::new(Mutex::new(())),
        }
    }

    pub async fn notify_typed<Message>(
        &self,
        type_id: u32,
        message: &Message,
    ) -> Result<(), RpcError>
    where
        Message: Serialize + Sync,
    {
        self.notify(RpcEnvelope {
            type_id,
            request_id: 0,
            response_to: 0,
            payload: serde_json::to_value(message)?,
            error: None,
        })
        .await
    }

    pub async fn notify(&self, mut envelope: RpcEnvelope) -> Result<(), RpcError> {
        envelope.request_id = 0;
        envelope.response_to = 0;
        let stream = self
            .active_stream
            .lock()
            .await
            .clone()
            .ok_or(RpcError::Closed)?;
        let _write = self.write_serial.lock().await;
        streamio::write_json(&stream, &envelope)
            .await
            .map_err(|error| RpcError::Transport(error.to_string()))
    }

    pub async fn handle(&self, envelope: RpcEnvelope) -> RpcEnvelope {
        let response_to = envelope.request_id;
        match self
            .router
            .dispatch(envelope.type_id, envelope.payload)
            .await
        {
            Ok(payload) => RpcEnvelope {
                type_id: envelope.type_id,
                request_id: 0,
                response_to,
                payload,
                error: None,
            },
            Err(error) => RpcEnvelope {
                type_id: envelope.type_id,
                request_id: 0,
                response_to,
                payload: Value::Null,
                error: Some(error),
            },
        }
    }

    pub async fn serve(self: Arc<Self>, stream: YamuxStream) -> Result<(), RpcError> {
        {
            let mut active = self.active_stream.lock().await;
            if active.is_some() {
                return Err(RpcError::ResourceExhausted);
            }
            *active = Some(stream.clone());
        }
        let result = self.clone().serve_active(stream).await;
        *self.active_stream.lock().await = None;
        result
    }

    async fn serve_active(self: Arc<Self>, stream: YamuxStream) -> Result<(), RpcError> {
        if self.max_concurrent_requests == 0
            || self.max_queued_requests == 0
            || self.max_queued_notifications == 0
        {
            return Err(RpcError::ResourceExhausted);
        }
        let (request_tx, request_rx) = mpsc::channel(self.max_queued_requests);
        let (notification_tx, notification_rx) =
            mpsc::channel::<RpcEnvelope>(self.max_queued_notifications);
        let request_rx = Arc::new(Mutex::new(request_rx));
        let notification_rx = Arc::new(Mutex::new(notification_rx));
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_requests));

        for _ in 0..self.max_concurrent_requests {
            let server = self.clone();
            let receiver = request_rx.clone();
            let stream = stream.clone();
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                loop {
                    let envelope = receiver.lock().await.recv().await;
                    let Some(envelope) = envelope else { return };
                    let permit = match semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    let response = server.handle(envelope).await;
                    let _permit = permit;
                    let _write = server.write_serial.lock().await;
                    if streamio::write_json(&stream, &response).await.is_err() {
                        return;
                    }
                }
            });
        }

        for _ in 0..self.max_concurrent_requests {
            let server = self.clone();
            let receiver = notification_rx.clone();
            tokio::spawn(async move {
                loop {
                    let envelope = receiver.lock().await.recv().await;
                    let Some(envelope) = envelope else { return };
                    let _ = server
                        .router
                        .dispatch(envelope.type_id, envelope.payload)
                        .await;
                }
            });
        }

        loop {
            let envelope: RpcEnvelope =
                streamio::read_json(&stream, defaults::MAX_JSON_FRAME_BYTES)
                    .await
                    .map_err(|error| RpcError::Transport(error.to_string()))?;
            if envelope.response_to != 0 {
                continue;
            }
            if envelope.request_id == 0 {
                let _ = notification_tx.try_send(envelope);
                continue;
            }
            match request_tx.try_send(envelope) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(envelope)) => {
                    let response = RpcEnvelope {
                        type_id: envelope.type_id,
                        request_id: 0,
                        response_to: envelope.request_id,
                        payload: Value::Null,
                        error: Some(WireRpcError {
                            code: 429,
                            message: Some("server overloaded".to_owned()),
                        }),
                    };
                    let _write = self.write_serial.lock().await;
                    streamio::write_json(&stream, &response)
                        .await
                        .map_err(|error| RpcError::Transport(error.to_string()))?;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(RpcError::Closed),
            }
        }
    }
}
