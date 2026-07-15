use flowersec::{
    Client, ConnectOptions, Path, connect_direct, connect_tunnel,
    generated::flowersec::{controlplane::v1::ChannelInitGrant, direct::v1::DirectConnectInfo},
    proxy::{ContractOptions, HttpRequest, ProxyClient, WebSocketFrame, WebSocketOp},
    transport_security::TransportSecurityPolicy,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;

#[derive(Debug, Deserialize)]
struct HarnessReady {
    v: u32,
    event: String,
    direct_info: DirectConnectInfo,
}

#[derive(Debug, Deserialize)]
struct GoReady {
    grant_client: ChannelInitGrant,
    grant_server: ChannelInitGrant,
}

#[derive(Debug, Serialize)]
struct PingRequest {}

#[derive(Debug, Deserialize)]
struct PingResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct HelloNotify {
    hello: String,
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn rust_client_interoperates_with_typescript_endpoint() {
    if std::env::var_os("FLOWERSEC_PAIRWISE_INTEROP").is_none() {
        return;
    }
    let mut harness = start_typescript_harness(None);
    let stdout = harness.0.stdout.take().expect("TypeScript harness stdout");
    let mut reader = BufReader::new(stdout);
    let mut ready_line = String::new();
    reader.read_line(&mut ready_line).expect("read ready line");
    let ready: HarnessReady = serde_json::from_str(&ready_line).expect("decode ready line");
    assert_eq!(ready.v, 1);
    assert_eq!(ready.event, "ready");

    let client = connect_direct(
        ready.direct_info,
        ConnectOptions {
            origin: Some("https://app.example.com".to_owned()),
            transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
            ..ConnectOptions::default()
        },
    )
    .await
    .expect("connect TypeScript endpoint");
    exercise_client(client, Path::Direct).await;

    let mut go = start_go_harness();
    let mut go_reader = BufReader::new(go.0.stdout.take().expect("Go harness stdout"));
    ready_line.clear();
    go_reader
        .read_line(&mut ready_line)
        .expect("read Go harness ready line");
    let grants: GoReady = serde_json::from_str(&ready_line).expect("decode Go harness ready line");
    let mut tunnel_harness = start_typescript_harness(Some(&grants.grant_server));
    let mut tunnel_reader = BufReader::new(
        tunnel_harness
            .0
            .stdout
            .take()
            .expect("TypeScript tunnel harness stdout"),
    );
    ready_line.clear();
    tunnel_reader
        .read_line(&mut ready_line)
        .expect("read TypeScript attaching line");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&ready_line).unwrap()["event"],
        "attaching"
    );
    let tunnel = connect_tunnel(
        grants.grant_client,
        ConnectOptions {
            origin: Some("https://app.redeven.com".to_owned()),
            transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
            ..ConnectOptions::default()
        },
    )
    .await
    .expect("connect TypeScript tunnel endpoint");
    exercise_client(tunnel, Path::Tunnel).await;
}

fn start_typescript_harness(server_grant: Option<&ChannelInitGrant>) -> ChildGuard {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("Rust crate below repository root");
    let mut command = Command::new("node");
    command.arg("scripts/interop-endpoint-harness.mjs");
    if let Some(server_grant) = server_grant {
        command
            .arg("--tunnel-grant-json")
            .arg(serde_json::to_string(server_grant).expect("server grant JSON"));
    }
    let child = command
        .current_dir(repo_root.join("flowersec-ts"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start TypeScript endpoint harness");
    ChildGuard(child)
}

fn start_go_harness() -> ChildGuard {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("Rust crate below repository root");
    ChildGuard(
        Command::new("go")
            .args([
                "run",
                "./internal/cmd/flowersec-e2e-harness",
                "-external-server",
            ])
            .current_dir(repo_root.join("flowersec-go"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start Go tunnel harness"),
    )
}

async fn exercise_client(client: Client, expected_path: Path) {
    assert_eq!(client.path(), expected_path);
    let client = Arc::new(client);
    let (notify_tx, notify_rx) = oneshot::channel();
    let notify_tx = Arc::new(Mutex::new(Some(notify_tx)));
    let _subscription = client
        .rpc()
        .on_notify_typed::<HelloNotify, _, _>(2, move |message| {
            let notify_tx = notify_tx.clone();
            async move {
                if let Some(sender) = notify_tx.lock().unwrap().take() {
                    let _ = sender.send(message.hello);
                }
            }
        });
    let response: PingResponse = client
        .rpc()
        .call_typed(1, &PingRequest {})
        .await
        .expect("TypeScript RPC");
    assert!(response.ok);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), notify_rx)
            .await
            .expect("notification timeout")
            .expect("notification sender"),
        "world"
    );

    let echo = client.open_stream("echo").await.expect("open echo");
    echo.write(b"rust-typescript-stream")
        .await
        .expect("write echo");
    assert_eq!(
        echo.read_exact(22).await.expect("read echo"),
        b"rust-typescript-stream"
    );
    echo.close().await.expect("close echo");
    client
        .probe_liveness(Duration::from_secs(2))
        .await
        .expect("TypeScript liveness ACK");

    let proxy = ProxyClient::new(client.clone(), ContractOptions::default()).expect("proxy client");
    let http = proxy
        .request(HttpRequest::get("/http"))
        .await
        .expect("TypeScript HTTP proxy");
    assert_eq!(http.status, 200);
    assert_eq!(http.body, b"flowersec-typescript-proxy-ok");
    let websocket = proxy
        .open_websocket("/ws", Vec::new())
        .await
        .expect("proxy WS");
    websocket
        .send(WebSocketFrame {
            op: WebSocketOp::Text,
            payload: b"rust-typescript-websocket".to_vec(),
        })
        .await
        .expect("send WS frame");
    assert_eq!(
        websocket.receive().await.expect("receive WS frame"),
        WebSocketFrame {
            op: WebSocketOp::Text,
            payload: b"rust-typescript-websocket".to_vec(),
        }
    );
    websocket.close(Some(1000), "done").await.expect("close WS");
    client.close().await.expect("close client");
}
