use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    ErrorCode, FlowersecError, Path, Stage,
    client::{ConnectOptions, connect_direct},
    e2ee::{Secret32, Suite},
    endpoint::{
        DirectCredentialResolver, DirectHandshakeCredential, DirectHandshakeInit, EndpointOptions,
        accept_direct_resolved,
    },
    generated::flowersec::direct::v1::{DirectConnectInfo, Suite as DirectSuite},
    rpc::{Router, Server as RpcServer},
    streamhello,
    transport::TungsteniteTransport,
    transport_security::TransportSecurityPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

#[derive(Debug, Serialize)]
struct PingRequest {
    value: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct PingResponse {
    value: String,
}

#[derive(Debug, Deserialize)]
struct ServerNotify {
    value: String,
}

#[derive(Clone)]
struct Resolver {
    psk: [u8; 32],
    expires: i64,
    observed: Arc<Mutex<Vec<DirectHandshakeInit>>>,
    commits: Arc<AtomicUsize>,
    fail_commit: bool,
}

#[async_trait]
impl DirectCredentialResolver for Resolver {
    async fn resolve(
        &self,
        init: DirectHandshakeInit,
    ) -> Result<DirectHandshakeCredential, FlowersecError> {
        self.observed.lock().unwrap().push(init);
        let commits = self.commits.clone();
        let fail_commit = self.fail_commit;
        Ok(DirectHandshakeCredential {
            psk: Secret32::new(self.psk),
            init_expires_at_unix_s: self.expires,
            commit_authenticated: Some(Arc::new(move || {
                let commits = commits.clone();
                Box::pin(async move {
                    commits.fetch_add(1, Ordering::SeqCst);
                    if fail_commit {
                        Err(FlowersecError::new(
                            Path::Direct,
                            Stage::Handshake,
                            ErrorCode::CREDENTIAL_COMMIT_FAILED,
                            "commit rejected",
                        ))
                    } else {
                        Ok(())
                    }
                })
            })),
        })
    }
}

#[tokio::test]
async fn resolved_endpoint_commits_after_authentication_and_supports_bidirectional_sessions() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let psk = [0x73_u8; 32];
    let expires = unix_now() + 60;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let commits = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver {
        psk,
        expires,
        observed: observed.clone(),
        commits: commits.clone(),
        fail_commit: false,
    };

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let websocket = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("accept WebSocket");
        let session = accept_direct_resolved(
            Arc::new(TungsteniteTransport::new(websocket)),
            &resolver,
            EndpointOptions::default(),
        )
        .await
        .expect("accept resolved direct session");
        assert_eq!(session.path(), Path::Direct);
        assert_eq!(resolver.commits.load(Ordering::SeqCst), 1);

        let (rpc_kind, rpc_stream) = session.accept_stream().await.expect("accept RPC stream");
        assert_eq!(rpc_kind, streamhello::RPC_KIND);
        let router = Router::default();
        let server = Arc::new(RpcServer::new(router.clone()));
        router
            .register(41, {
                let server = Arc::downgrade(&server);
                move |payload: Value| {
                    let server = server.clone();
                    async move {
                        if let Some(server) = server.upgrade() {
                            server
                                .notify_typed(42, &json!({ "value": "server-notify" }))
                                .await
                                .expect("send server notification");
                        }
                        Ok(json!({ "value": payload["value"] }))
                    }
                }
            })
            .await;
        let rpc_task = tokio::spawn(server.serve(rpc_stream));

        session
            .probe_liveness(Duration::from_secs(2))
            .await
            .expect("endpoint liveness probe");
        let push = session
            .open_stream("server-push")
            .await
            .expect("open push stream");
        push.write(b"from-server")
            .await
            .expect("write push payload");
        push.close().await.expect("close push stream");

        let (kind, echo) = session.accept_stream().await.expect("accept echo stream");
        assert_eq!(kind, "client-echo");
        let payload = echo.read_exact(11).await.expect("read echo payload");
        echo.write(&payload).await.expect("write echo payload");
        echo.close().await.expect("close echo stream");

        session.terminated().await;
        rpc_task.abort();
    });

    let client = connect_direct(direct_info(address, psk, expires), connect_options())
        .await
        .expect("connect direct client");
    assert_eq!(client.path(), Path::Direct);
    client
        .probe_liveness(Duration::from_secs(2))
        .await
        .expect("client liveness probe");

    let (kind, push) = client.accept_stream().await.expect("accept server push");
    assert_eq!(kind, "server-push");
    assert_eq!(
        push.read_exact(11).await.expect("read push"),
        b"from-server"
    );

    let echo = client.open_stream("client-echo").await.expect("open echo");
    echo.write(b"from-client").await.expect("write echo");
    assert_eq!(
        echo.read_exact(11).await.expect("read echo"),
        b"from-client"
    );
    echo.close().await.expect("close echo");

    let (notify_tx, notify_rx) = tokio::sync::oneshot::channel();
    let notify_tx = Arc::new(Mutex::new(Some(notify_tx)));
    let _subscription = client
        .rpc()
        .on_notify_typed::<ServerNotify, _, _>(42, move |message| {
            let notify_tx = notify_tx.clone();
            async move {
                if let Some(sender) = notify_tx.lock().unwrap().take() {
                    let _ = sender.send(message.value);
                }
            }
        });
    let response: PingResponse = client
        .rpc()
        .call_typed(
            41,
            &PingRequest {
                value: "resolved".to_owned(),
            },
        )
        .await
        .expect("typed RPC");
    assert_eq!(
        response,
        PingResponse {
            value: "resolved".to_owned()
        }
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), notify_rx)
            .await
            .expect("server notification timeout")
            .expect("server notification sender"),
        "server-notify"
    );

    client.close().await.expect("close client");
    server_task.await.expect("server task");
    let inits = observed.lock().unwrap();
    assert_eq!(inits.len(), 1);
    assert_eq!(inits[0].channel_id, "rust-resolved-endpoint");
    assert_eq!(inits[0].version, 1);
    assert_eq!(inits[0].suite, Suite::X25519HkdfSha256Aes256Gcm);
    assert_eq!(commits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn resolved_endpoint_closes_session_when_authenticated_commit_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let psk = [0x74_u8; 32];
    let expires = unix_now() + 60;
    let commits = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver {
        psk,
        expires,
        observed: Arc::new(Mutex::new(Vec::new())),
        commits: commits.clone(),
        fail_commit: true,
    };

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let websocket = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("accept WebSocket");
        accept_direct_resolved(
            Arc::new(TungsteniteTransport::new(websocket)),
            &resolver,
            EndpointOptions::default(),
        )
        .await
        .expect_err("commit failure must reject the endpoint session")
    });

    let client = connect_direct(direct_info(address, psk, expires), connect_options())
        .await
        .expect("handshake completes before credential commit");
    let server_error = server_task.await.expect("server task");
    assert_eq!(
        server_error.code.as_str(),
        ErrorCode::CREDENTIAL_COMMIT_FAILED
    );
    assert_eq!(commits.load(Ordering::SeqCst), 1);
    tokio::time::timeout(Duration::from_secs(2), client.terminated())
        .await
        .expect("failed commit closes the client session");
}

fn direct_info(address: std::net::SocketAddr, psk: [u8; 32], expires: i64) -> DirectConnectInfo {
    DirectConnectInfo {
        ws_url: format!("ws://{address}/flowersec"),
        channel_id: "rust-resolved-endpoint".to_owned(),
        e2ee_psk_b64u: URL_SAFE_NO_PAD.encode(psk),
        channel_init_expire_at_unix_s: expires,
        default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
    }
}

fn connect_options() -> ConnectOptions {
    ConnectOptions {
        transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
        ..ConnectOptions::default()
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64
}
