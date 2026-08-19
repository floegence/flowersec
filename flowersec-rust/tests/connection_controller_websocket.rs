use std::{
    fmt,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use flowersec::v2::{
    Acceptor, Artifact, ArtifactLease, ArtifactSource, ArtifactSourceError, ConnectionController,
    ConnectionControllerOptions, ConnectionState, DirectIssueOptions, EndpointSet, Issuer,
    SessionOptions, WebSocketAcceptorOptions,
};
use flowersec::{
    AcceptedSession, ConnectorOptions, HandlerRegistrationError, NotificationHandler, RpcError,
    RpcHandler, RpcHandlers, Session, SessionHandlerOptions, SessionHandlers,
};
use tokio::sync::{Notify, oneshot};
use tokio_util::sync::CancellationToken;

const CLIENT_RPC: u32 = 901;
const CLIENT_NOTIFICATION: u32 = 902;
const PENDING_SERVER_RPC: u32 = 903;

struct EchoHandler {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl RpcHandler for EchoHandler {
    async fn call(
        &self,
        _type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let generation = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(serde_json::json!({"generation": generation, "request": request}))
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        Ok(())
    }
}

struct CountingNotification {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl NotificationHandler for CountingNotification {
    async fn handle_notification(
        &self,
        _type_id: u32,
        _request: serde_json::Value,
    ) -> Result<(), RpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct PendingHandler {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait]
impl RpcHandler for PendingHandler {
    async fn call(
        &self,
        _type_id: u32,
        _request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        self.started.notify_waiters();
        self.release.notified().await;
        Ok(serde_json::json!({"late": true}))
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        Ok(())
    }
}

struct ServerGeneration {
    session: oneshot::Receiver<Arc<AcceptedSession>>,
    pending_started: Arc<Notify>,
    pending_release: Arc<Notify>,
}

#[derive(Default)]
struct RestartSource {
    generations: Mutex<Vec<Option<ServerGeneration>>>,
}

impl fmt::Debug for RestartSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RestartSource { <opaque> }")
    }
}

#[async_trait]
impl ArtifactSource for RestartSource {
    async fn acquire(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ArtifactLease, ArtifactSourceError> {
        let acceptor = Arc::new(
            Acceptor::bind_websocket(WebSocketAcceptorOptions {
                bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                certificate_chain_der: Vec::new(),
                private_key_der: Vec::new(),
                allowed_origins: vec!["https://native-client.test".into()],
                max_inbound_streams: 8,
                accept_timeout: Duration::from_secs(5),
            })
            .map_err(|_| ArtifactSourceError::terminal())?,
        );
        let address = acceptor
            .local_address()
            .map_err(|_| ArtifactSourceError::terminal())?;
        let mut session_options = SessionOptions::new("rust-controller-handlers");
        session_options.max_inbound_streams = 8;
        let issued = Issuer::new()
            .issue_direct(DirectIssueOptions {
                session: session_options,
                endpoints: EndpointSet::new([format!("ws://{address}")])
                    .map_err(|_| ArtifactSourceError::terminal())?,
                rendezvous_group_id: "rust-controller-handlers-group".into(),
                listener_audience: "rust-controller-handlers-listener".into(),
                upstream_address: "127.0.0.1:23998".into(),
            })
            .map_err(|_| ArtifactSourceError::terminal())?;
        let server_artifact =
            Artifact::parse(issued.artifact_json()).map_err(|_| ArtifactSourceError::terminal())?;
        let client_artifact =
            Artifact::parse(issued.artifact_json()).map_err(|_| ArtifactSourceError::terminal())?;
        let pending_started = Arc::new(Notify::new());
        let pending_release = Arc::new(Notify::new());
        let mut handlers = SessionHandlers::new(SessionHandlerOptions::default())
            .map_err(|_: HandlerRegistrationError| ArtifactSourceError::terminal())?;
        handlers
            .handle_rpc(
                PENDING_SERVER_RPC,
                PendingHandler {
                    started: pending_started.clone(),
                    release: pending_release.clone(),
                },
            )
            .map_err(|_| ArtifactSourceError::terminal())?;
        let (session_tx, session_rx) = oneshot::channel();
        let server_cancellation = cancellation.child_token();
        tokio::spawn(async move {
            if let Ok(accepted) = acceptor
                .accept_with_handlers(&server_artifact, handlers, server_cancellation)
                .await
            {
                let accepted = Arc::new(accepted);
                let _ = session_tx.send(accepted.clone());
                accepted.session().wait_termination().await;
            }
        });
        self.generations
            .lock()
            .expect("generation lock")
            .push(Some(ServerGeneration {
                session: session_rx,
                pending_started,
                pending_release,
            }));
        Ok(ArtifactLease::new(client_artifact, || async { Ok(()) }))
    }
}

impl RestartSource {
    async fn take_generation(&self, index: usize) -> ServerGeneration {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(generation) = self
                    .generations
                    .lock()
                    .expect("generation lock")
                    .get_mut(index)
                    .and_then(Option::take)
                {
                    return generation;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("source creates generation")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controller_reuses_rpc_definitions_with_generation_local_websocket_routers() {
    let rpc_calls = Arc::new(AtomicUsize::new(0));
    let notifications = Arc::new(AtomicUsize::new(0));
    let mut rpc_handlers = RpcHandlers::new();
    rpc_handlers
        .handle_rpc(
            CLIENT_RPC,
            EchoHandler {
                calls: rpc_calls.clone(),
            },
        )
        .unwrap();
    rpc_handlers
        .handle_notification(
            CLIENT_NOTIFICATION,
            CountingNotification {
                calls: notifications.clone(),
            },
        )
        .unwrap();
    let connector = ConnectorOptions::new()
        .with_websocket_origin("https://native-client.test")
        .unwrap()
        .with_connect_timeout(Duration::from_secs(5))
        .unwrap()
        .with_close_flush_timeout(Duration::from_millis(100))
        .unwrap()
        .with_rpc_handlers(rpc_handlers);
    let source = Arc::new(RestartSource::default());
    let controller =
        ConnectionController::new(source.clone(), ConnectionControllerOptions::new(connector));
    controller.start();

    let first_client = wait_for_session(&controller, None).await;
    let first_generation = source.take_generation(0).await;
    let first_server = first_generation
        .session
        .await
        .expect("first server session");
    assert_eq!(
        first_server
            .session()
            .rpc()
            .call(CLIENT_RPC, serde_json::json!({"phase": "first"}))
            .await
            .unwrap(),
        serde_json::json!({"generation": 1, "request": {"phase": "first"}})
    );
    first_server
        .session()
        .rpc()
        .notify(CLIENT_NOTIFICATION, serde_json::json!({"phase": "first"}))
        .await
        .unwrap();
    wait_for_count(&notifications, 1).await;

    let pending = first_client
        .rpc()
        .call(PENDING_SERVER_RPC, serde_json::Value::Null);
    tokio::pin!(pending);
    tokio::select! {
        _ = first_generation.pending_started.notified() => {}
        result = &mut pending => panic!("pending RPC completed early: {result:?}"),
    }
    let _ = first_client.close().await;
    assert!(
        pending.await.is_err(),
        "old pending RPC unexpectedly succeeded"
    );

    let second_client = wait_for_session(&controller, Some(&first_client)).await;
    assert!(!Arc::ptr_eq(&first_client, &second_client));
    let second_generation = source.take_generation(1).await;
    let second_server = second_generation
        .session
        .await
        .expect("second server session");
    assert_eq!(
        second_server
            .session()
            .rpc()
            .call(CLIENT_RPC, serde_json::json!({"phase": "second"}))
            .await
            .unwrap(),
        serde_json::json!({"generation": 2, "request": {"phase": "second"}})
    );
    second_server
        .session()
        .rpc()
        .notify(CLIENT_NOTIFICATION, serde_json::json!({"phase": "second"}))
        .await
        .unwrap();
    wait_for_count(&notifications, 2).await;
    assert_eq!(rpc_calls.load(Ordering::SeqCst), 2);

    first_generation.pending_release.notify_waiters();
    controller.close().await;
    second_generation.pending_release.notify_waiters();
    let _ = second_server.session().close().await;
}

async fn wait_for_session(
    controller: &ConnectionController,
    previous: Option<&Arc<dyn Session>>,
) -> Arc<dyn Session> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = controller.snapshot();
            if snapshot.state == ConnectionState::Connected
                && let Some(session) = snapshot.current_session
                && previous.is_none_or(|old| !Arc::ptr_eq(old, &session))
            {
                return session;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("controller publishes session")
}

async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while counter.load(Ordering::SeqCst) != expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("handler invocation count");
}
