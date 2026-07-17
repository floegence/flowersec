use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    ErrorCode, FlowersecError, Stage,
    client::{ConnectOptions, connect_direct},
    e2ee::{Secret32, ServerHandshakeOptions, Suite},
    endpoint::{DirectAcceptOptions, accept_direct},
    generated::flowersec::direct::v1::{DirectConnectInfo, Suite as DirectSuite},
    rpc::Router,
    transport::TungsteniteTransport,
    transport_security::TransportSecurityPolicy,
    yamux::YamuxError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
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
    let missing_kind = client
        .open_stream(" \t ")
        .await
        .expect_err("blank stream kind must fail before opening a stream");
    assert_eq!(missing_kind.stage, Stage::Rpc);
    assert_eq!(missing_kind.code.as_str(), ErrorCode::MISSING_STREAM_KIND);
    client.close().await.expect("close client");
    server_task.abort();
}

#[tokio::test]
async fn secure_outbound_exhaustion_surfaces_as_high_level_resource_error() {
    for (limit, current) in [(8, 12), (12, 36)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local address");
        let psk = [0x32_u8; 32];
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs() as i64
            + 60;
        let channel_id = format!("rust-outbound-exhaustion-{limit}");
        let server_channel_id = channel_id.clone();

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
            handshake.channel_id = Some(server_channel_id);
            accept_direct(
                Arc::new(TungsteniteTransport::new(websocket)),
                DirectAcceptOptions::new(handshake),
            )
            .await
            .expect("accept Flowersec direct")
        });

        let options = ConnectOptions {
            transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
            max_outbound_buffered_bytes: limit,
            ..ConnectOptions::default()
        };
        let error = connect_direct(
            DirectConnectInfo {
                ws_url: format!("ws://{address}/flowersec"),
                channel_id,
                e2ee_psk_b64u: URL_SAFE_NO_PAD.encode(psk),
                channel_init_expire_at_unix_s: expires,
                default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
            },
            options,
        )
        .await
        .expect_err("initial Yamux write must exceed the secure outbound budget");

        assert_eq!(error.stage, Stage::Rpc);
        assert_eq!(error.code.as_str(), ErrorCode::RESOURCE_EXHAUSTED);
        let source = yamux_source(&error).expect("preserve typed Yamux source");
        assert!(matches!(
            source,
            YamuxError::ResourceExhausted {
                resource: "secure_channel_pending_write_bytes",
                current: actual,
                limit: actual_limit,
            } if *actual == current && *actual_limit == limit
        ));

        server_task.abort();
        let _ = tokio::time::timeout(Duration::from_secs(1), server_task).await;
    }
}

fn yamux_source(error: &FlowersecError) -> Option<&YamuxError> {
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        if let Some(yamux) = error.downcast_ref::<YamuxError>() {
            return Some(yamux);
        }
        source = error.source();
    }
    None
}
