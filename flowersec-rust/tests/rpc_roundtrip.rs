use async_trait::async_trait;
use flowersec::{
    generated::flowersec::rpc::v1::RpcEnvelope,
    rpc::{Router, RpcCallOptions, RpcClient, RpcClientLimits, RpcError, Server},
    streamhello, streamio,
    yamux::{ByteDuplex, Mode, YamuxError, YamuxLimits, YamuxSession},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Deserialize, Serialize)]
struct EchoRequest {
    value: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EchoResponse {
    value: String,
}

#[tokio::test]
async fn typed_rpc_round_trip_over_stream_hello_and_yamux() {
    let (client_connection, server_connection) = duplex_pair();
    let client_session = YamuxSession::new(client_connection, Mode::Client, YamuxLimits::default())
        .expect("client session");
    let server_session = YamuxSession::new(server_connection, Mode::Server, YamuxLimits::default())
        .expect("server session");

    let client_stream = client_session.open_stream().await.expect("open RPC stream");
    streamhello::write(&client_stream, streamhello::RPC_KIND)
        .await
        .expect("write stream hello");
    let server_stream = server_session
        .accept_stream()
        .await
        .expect("accept RPC stream");
    assert_eq!(
        streamhello::read(&server_stream, 0)
            .await
            .expect("read stream hello"),
        streamhello::RPC_KIND
    );

    let router = Router::default();
    router
        .register(7, |payload: Value| async move {
            Ok(json!({ "value": payload["value"].as_str().unwrap_or_default() }))
        })
        .await;
    router
        .register(8, |payload: Value| async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(payload)
        })
        .await;
    let notification_stream = server_stream.clone();
    let server = Arc::new(Server::new(router));
    let server_task = tokio::spawn(server.serve(server_stream));

    let client = RpcClient::from_stream_with_limits(
        client_stream,
        RpcClientLimits {
            max_concurrent_requests: 1,
            max_queued_requests: 0,
        },
    );
    let (notification_tx, mut notification_rx) = mpsc::channel(1);
    let _subscription = client.on_notify_typed::<EchoRequest, _, _>(9, move |message| {
        let notification_tx = notification_tx.clone();
        async move {
            let _ = notification_tx.send(message.value).await;
        }
    });
    streamio::write_json(
        &notification_stream,
        &RpcEnvelope {
            type_id: 9,
            request_id: 0,
            response_to: 0,
            payload: json!({ "value": "notification" }),
            error: None,
        },
    )
    .await
    .expect("write notification");
    assert_eq!(
        notification_rx.recv().await.as_deref(),
        Some("notification")
    );
    let response: EchoResponse = client
        .call_typed(
            7,
            &EchoRequest {
                value: "flowersec".to_owned(),
            },
        )
        .await
        .expect("RPC call");
    assert_eq!(
        response,
        EchoResponse {
            value: "flowersec".to_owned()
        }
    );

    let timeout = client
        .call_typed_with_options::<_, EchoResponse>(
            8,
            &EchoRequest {
                value: "timeout".to_owned(),
            },
            RpcCallOptions {
                timeout: Some(Duration::from_millis(5)),
                cancellation: None,
            },
        )
        .await
        .expect_err("timeout");
    assert!(matches!(timeout, RpcError::Timeout));

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let canceled = client
        .call_typed_with_options::<_, EchoResponse>(
            8,
            &EchoRequest {
                value: "canceled".to_owned(),
            },
            RpcCallOptions {
                timeout: None,
                cancellation: Some(cancellation),
            },
        )
        .await
        .expect_err("canceled");
    assert!(matches!(canceled, RpcError::Canceled));

    let first_client = client.clone();
    let first = tokio::spawn(async move {
        first_client
            .call_typed::<_, EchoResponse>(
                8,
                &EchoRequest {
                    value: "first".to_owned(),
                },
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(5)).await;
    let exhausted = client
        .call_typed::<_, EchoResponse>(
            8,
            &EchoRequest {
                value: "second".to_owned(),
            },
        )
        .await
        .expect_err("client capacity");
    assert!(matches!(exhausted, RpcError::ResourceExhausted));
    assert_eq!(
        first.await.expect("first task").expect("first response"),
        EchoResponse {
            value: "first".to_owned()
        }
    );

    client_session.close().await.expect("close client session");
    server_session.close().await.expect("close server session");
    server_task.abort();
}

#[derive(Debug)]
struct MemoryDuplex {
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

#[async_trait]
impl ByteDuplex for MemoryDuplex {
    async fn read(&self) -> Result<Vec<u8>, YamuxError> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(YamuxError::Closed)
    }

    async fn write(&self, bytes: &[u8]) -> Result<(), YamuxError> {
        self.outgoing
            .send(bytes.to_vec())
            .await
            .map_err(|_| YamuxError::Closed)
    }

    async fn close(&self) -> Result<(), YamuxError> {
        Ok(())
    }
}

fn duplex_pair() -> (Arc<MemoryDuplex>, Arc<MemoryDuplex>) {
    let (client_tx, server_rx) = mpsc::channel(64);
    let (server_tx, client_rx) = mpsc::channel(64);
    (
        Arc::new(MemoryDuplex {
            incoming: Mutex::new(client_rx),
            outgoing: client_tx,
        }),
        Arc::new(MemoryDuplex {
            incoming: Mutex::new(server_rx),
            outgoing: server_tx,
        }),
    )
}
