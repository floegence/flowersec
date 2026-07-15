use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    client::{ConnectOptions, connect_direct},
    e2ee::{Secret32, ServerHandshakeOptions, Suite},
    endpoint::{DirectAcceptOptions, accept_direct},
    generated::flowersec::direct::v1::{DirectConnectInfo, Suite as DirectSuite},
    rpc::Router,
    transport::TungsteniteTransport,
    transport_security::TransportSecurityPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

#[derive(Debug, Serialize)]
struct PingRequest {
    value: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct PingResponse {
    value: String,
}

#[tokio::test]
async fn high_level_direct_client_and_endpoint_interoperate() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let psk = [0x31_u8; 32];
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64
        + 60;

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let websocket = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("accept WebSocket");
        let mut handshake = ServerHandshakeOptions::new(
            Secret32::new(psk),
            Suite::X25519HkdfSha256Aes256Gcm,
            expires,
        );
        handshake.channel_id = Some("rust-direct-integration".to_owned());
        let session = accept_direct(
            Arc::new(TungsteniteTransport::new(websocket)),
            DirectAcceptOptions::new(handshake),
        )
        .await
        .expect("accept Flowersec direct");
        let router = Router::default();
        router
            .register(99, |payload: Value| async move {
                Ok(json!({ "value": payload["value"].as_str().unwrap_or_default() }))
            })
            .await;
        session.serve_rpc(router).await.expect("serve RPC");
    });

    let options = ConnectOptions {
        transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
        ..ConnectOptions::default()
    };
    let client = connect_direct(
        DirectConnectInfo {
            ws_url: format!("ws://{address}/flowersec"),
            channel_id: "rust-direct-integration".to_owned(),
            e2ee_psk_b64u: URL_SAFE_NO_PAD.encode(psk),
            channel_init_expire_at_unix_s: expires,
            default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
        },
        options,
    )
    .await
    .expect("connect direct");

    let response: PingResponse = client
        .rpc()
        .call_typed(
            99,
            &PingRequest {
                value: "ok".to_owned(),
            },
        )
        .await
        .expect("RPC response");
    assert_eq!(
        response,
        PingResponse {
            value: "ok".to_owned()
        }
    );
    client.close().await.expect("close client");
    server_task.abort();
}
