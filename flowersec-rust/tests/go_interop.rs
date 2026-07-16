use flowersec::{
    Client, ConnectOptions, Path, connect, connect_direct,
    controlplane::client::{ConnectArtifactRequestConfig, request_connect_artifact},
    generated::flowersec::direct::v1::DirectConnectInfo,
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
    direct_info: DirectConnectInfo,
    controlplane_base_url: String,
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
async fn rust_client_interoperates_with_go_direct_tunnel_rpc_stream_liveness_and_proxy() {
    let mut harness = start_go_harness();
    let stdout = harness
        .0
        .stdout
        .take()
        .expect("Go harness stdout must be piped");
    let mut reader = BufReader::new(stdout);
    let mut ready_line = String::new();
    reader
        .read_line(&mut ready_line)
        .expect("read Go harness ready envelope");
    let ready: HarnessReady =
        serde_json::from_str(&ready_line).expect("decode Go harness ready envelope");

    let direct = connect_direct(ready.direct_info, connect_options())
        .await
        .expect("Rust direct client connects to Go endpoint");
    exercise_client(direct, Path::Direct).await;

    let mut request = ConnectArtifactRequestConfig::new("go-interop-endpoint");
    request.base_url = ready.controlplane_base_url;
    request.trace_id = Some("trace-rust-go-interop".to_owned());
    let artifact = request_connect_artifact(request)
        .await
        .expect("Rust fetches a Go-issued ConnectArtifact");
    assert_eq!(
        artifact
            .correlation()
            .and_then(|correlation| correlation.trace_id.as_deref()),
        Some("trace-rust-go-interop")
    );
    let tunnel = connect(artifact, connect_options())
        .await
        .expect("Rust tunnel client connects to Go endpoint");
    exercise_client(tunnel, Path::Tunnel).await;
}

fn start_go_harness() -> ChildGuard {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Rust crate must live below the repository root")
        .to_owned();
    let child = Command::new("go")
        .args(["run", "./internal/cmd/flowersec-e2e-harness"])
        .current_dir(repo_root.join("flowersec-go"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start Go E2E harness");
    ChildGuard(child)
}

fn connect_options() -> ConnectOptions {
    ConnectOptions {
        origin: Some("https://interop.flowersec.test".to_owned()),
        transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
        ..ConnectOptions::default()
    }
}

async fn exercise_client(client: Client, expected_path: Path) {
    assert_eq!(client.path(), expected_path);
    let client = Arc::new(client);

    let (notify_tx, notify_rx) = oneshot::channel();
    let notify_tx = Arc::new(Mutex::new(Some(notify_tx)));
    let subscription = client
        .rpc()
        .on_notify_typed::<HelloNotify, _, _>(2, move |message| {
            let notify_tx = notify_tx.clone();
            async move {
                if let Some(sender) = notify_tx.lock().expect("notification lock").take() {
                    let _ = sender.send(message.hello);
                }
            }
        });
    let response: PingResponse = client
        .rpc()
        .call_typed(1, &PingRequest {})
        .await
        .expect("typed RPC request succeeds");
    assert!(response.ok);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), notify_rx)
            .await
            .expect("Go notification arrives")
            .expect("Go notification sender remains active"),
        "world"
    );
    drop(subscription);

    let echo = client.open_stream("echo").await.expect("open echo stream");
    echo.write(b"rust-go-stream")
        .await
        .expect("write echo stream");
    assert_eq!(
        echo.read_exact(b"rust-go-stream".len())
            .await
            .expect("read echo stream"),
        b"rust-go-stream"
    );
    echo.close().await.expect("close echo stream");

    client
        .probe_liveness(Duration::from_secs(2))
        .await
        .expect("Go endpoint acknowledges Yamux liveness probe");

    let proxy = ProxyClient::new(client.clone(), ContractOptions::default())
        .expect("construct Rust proxy client");
    let response = proxy
        .request(HttpRequest::get("/http"))
        .await
        .expect("Rust HTTP proxy request reaches Go upstream");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"flowersec-go-proxy-ok");

    let websocket = proxy
        .open_websocket("/ws", Vec::new())
        .await
        .expect("Rust WebSocket proxy reaches Go upstream");
    websocket
        .send(WebSocketFrame {
            op: WebSocketOp::Text,
            payload: b"rust-go-websocket".to_vec(),
        })
        .await
        .expect("send proxied WebSocket frame");
    assert_eq!(
        websocket
            .receive()
            .await
            .expect("receive proxied WebSocket frame"),
        WebSocketFrame {
            op: WebSocketOp::Text,
            payload: b"rust-go-websocket".to_vec(),
        }
    );
    websocket
        .close(Some(1000), "done")
        .await
        .expect("close proxied WebSocket");

    client.close().await.expect("close Rust client");
}
