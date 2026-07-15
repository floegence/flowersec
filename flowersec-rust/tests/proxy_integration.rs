use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    client::{ConnectOptions, connect_direct},
    e2ee::{Secret32, ServerHandshakeOptions, Suite},
    endpoint::{DirectAcceptOptions, accept_direct},
    generated::flowersec::direct::v1::{DirectConnectInfo, Suite as DirectSuite},
    proxy::{
        ContractOptions, Header, HttpRequest, ProxyClient, ProxyServer, ServerOptions,
        WebSocketFrame, WebSocketOp,
    },
    rpc::{Router, Server as RpcServer},
    streamhello,
    transport::TungsteniteTransport,
    transport_security::TransportSecurityPolicy,
};
use futures_util::{SinkExt as _, StreamExt as _};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    sync::oneshot,
};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn rust_proxy_http_and_websocket_round_trip_over_direct_session() {
    let http_listener = TcpListener::bind("127.0.0.1:0").await.expect("HTTP bind");
    let http_address = http_listener.local_addr().expect("HTTP address");
    let (http_request_tx, http_request_rx) = oneshot::channel();
    let http_task = tokio::spawn(async move {
        let (mut socket, _) = http_listener.accept().await.expect("HTTP accept");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = socket.read(&mut chunk).await.expect("HTTP read");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = http_request_tx.send(String::from_utf8_lossy(&request).into_owned());
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Not-Allowed: secret\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            )
            .await
            .expect("HTTP response");
    });

    let ws_listener = TcpListener::bind("127.0.0.1:0").await.expect("WS bind");
    let ws_address = ws_listener.local_addr().expect("WS address");
    let ws_task = tokio::spawn(async move {
        let (tcp, _) = ws_listener.accept().await.expect("WS accept");
        let mut websocket = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("WS handshake");
        while let Some(message) = websocket.next().await {
            let Ok(message) = message else { return };
            match message {
                Message::Text(text) => websocket.send(Message::Text(text)).await.expect("WS echo"),
                Message::Binary(bytes) => websocket
                    .send(Message::Binary(bytes))
                    .await
                    .expect("WS echo"),
                Message::Close(frame) => {
                    let _ = websocket.send(Message::Close(frame)).await;
                    return;
                }
                Message::Ping(bytes) => {
                    websocket.send(Message::Pong(bytes)).await.expect("WS pong")
                }
                Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    });

    let flowersec_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Flowersec bind");
    let flowersec_address = flowersec_listener.local_addr().expect("Flowersec address");
    let psk = [0x52_u8; 32];
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64
        + 60;
    let endpoint_task = tokio::spawn(async move {
        let (tcp, _) = flowersec_listener.accept().await.expect("Flowersec accept");
        let websocket = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("Flowersec WebSocket");
        let mut handshake = ServerHandshakeOptions::new(
            Secret32::new(psk),
            Suite::X25519HkdfSha256Aes256Gcm,
            expires,
        );
        handshake.channel_id = Some("rust-proxy-integration".to_owned());
        let session = accept_direct(
            Arc::new(TungsteniteTransport::new(websocket)),
            DirectAcceptOptions::new(handshake),
        )
        .await
        .expect("accept direct");

        let (rpc_kind, rpc_stream) = session.accept_stream().await.expect("accept RPC");
        assert_eq!(rpc_kind, streamhello::RPC_KIND);
        tokio::spawn(Arc::new(RpcServer::new(Router::default())).serve(rpc_stream));

        let proxy = ProxyServer::new(ServerOptions {
            upstream: format!("http://{http_address}"),
            upstream_origin: format!("http://{http_address}"),
            allowed_upstream_hosts: Vec::new(),
            contract: ContractOptions::default(),
            default_timeout: None,
            max_timeout: None,
        })
        .expect("HTTP proxy server");
        let (http_kind, http_stream) = session.accept_stream().await.expect("accept HTTP proxy");
        proxy
            .serve_stream(&http_kind, http_stream)
            .await
            .expect("serve HTTP proxy");

        let proxy = ProxyServer::new(ServerOptions {
            upstream: format!("http://{ws_address}"),
            upstream_origin: "http://127.0.0.1:5173".to_owned(),
            allowed_upstream_hosts: Vec::new(),
            contract: ContractOptions::default(),
            default_timeout: None,
            max_timeout: None,
        })
        .expect("WS proxy server");
        let (ws_kind, ws_stream) = session.accept_stream().await.expect("accept WS proxy");
        let _ = proxy.serve_stream(&ws_kind, ws_stream).await;
    });

    let client = Arc::new(
        connect_direct(
            DirectConnectInfo {
                ws_url: format!("ws://{flowersec_address}/flowersec"),
                channel_id: "rust-proxy-integration".to_owned(),
                e2ee_psk_b64u: URL_SAFE_NO_PAD.encode(psk),
                channel_init_expire_at_unix_s: expires,
                default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
            },
            ConnectOptions {
                transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..ConnectOptions::default()
            },
        )
        .await
        .expect("connect direct"),
    );
    let proxy = ProxyClient::new(client.clone(), ContractOptions::default()).expect("proxy client");
    let mut request = HttpRequest::get("/hello?value=1");
    request.headers = vec![
        Header {
            name: "accept".to_owned(),
            value: "text/plain".to_owned(),
        },
        Header {
            name: "authorization".to_owned(),
            value: "Bearer secret".to_owned(),
        },
    ];
    let response = proxy.request(request).await.expect("HTTP proxy response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello");
    assert!(
        response
            .headers
            .iter()
            .any(|header| header.name == "content-type")
    );
    assert!(
        response
            .headers
            .iter()
            .all(|header| header.name != "x-not-allowed")
    );
    let upstream_request = http_request_rx.await.expect("upstream request");
    assert!(upstream_request.starts_with("GET /hello?value=1 HTTP/1.1"));
    assert!(
        !upstream_request
            .to_ascii_lowercase()
            .contains("authorization:")
    );

    let websocket = proxy
        .open_websocket("/socket", Vec::new())
        .await
        .expect("open proxied WS");
    websocket
        .send(WebSocketFrame {
            op: WebSocketOp::Text,
            payload: b"hello websocket".to_vec(),
        })
        .await
        .expect("send proxied WS frame");
    let echoed = websocket.receive().await.expect("receive proxied WS frame");
    assert_eq!(echoed.op, WebSocketOp::Text);
    assert_eq!(echoed.payload, b"hello websocket");
    websocket.close(Some(1000), "done").await.expect("close WS");
    client.close().await.expect("close Flowersec client");

    http_task.await.expect("HTTP task");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), ws_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), endpoint_task).await;
}
