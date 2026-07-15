use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    ConnectOptions, Path, connect_direct, connect_tunnel,
    generated::flowersec::controlplane::v1::ChannelInitGrant,
    generated::flowersec::direct::v1::{DirectConnectInfo, Suite as DirectSuite},
    proxy::{ContractOptions, HttpRequest, ProxyClient, WebSocketFrame, WebSocketOp},
    transport_security::TransportSecurityPolicy,
};
use futures_util::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[derive(Deserialize)]
struct GoReady {
    grant_client: ChannelInitGrant,
    grant_server: ChannelInitGrant,
    upstream_url: String,
}

#[derive(Serialize)]
struct PingRequest {}

#[derive(Deserialize)]
struct PingResponse {
    ok: bool,
}

#[derive(Deserialize)]
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

struct DirectHarnessGuard {
    _child: ChildGuard,
    bridge: JoinHandle<()>,
}

impl Drop for DirectHarnessGuard {
    fn drop(&mut self) {
        self.bridge.abort();
    }
}

#[tokio::test]
async fn rust_client_interoperates_with_swift_direct_and_tunnel_endpoints() {
    if std::env::var_os("FLOWERSEC_SWIFT_INTEROP").is_none() {
        return;
    }
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root")
        .to_owned();
    let mut go = ChildGuard(
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
    );
    let mut go_reader = BufReader::new(go.0.stdout.take().expect("Go stdout"));
    let mut line = String::new();
    go_reader.read_line(&mut line).expect("Go ready line");
    let ready: GoReady = serde_json::from_str(&line).expect("decode Go ready line");

    let (direct_harness, direct_info) =
        start_swift_direct_harness(&repo_root, &ready.upstream_url).await;
    let direct = Arc::new(
        connect_direct(
            direct_info,
            ConnectOptions {
                origin: Some("https://app.example.com".to_owned()),
                transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..ConnectOptions::default()
            },
        )
        .await
        .expect("connect Swift direct endpoint"),
    );
    exercise_client(direct, Path::Direct).await;
    drop(direct_harness);

    let server_grant = serde_json::to_string(&ready.grant_server).expect("server grant JSON");
    let mut swift = ChildGuard(
        Command::new("swift")
            .args([
                "run",
                "--package-path",
                repo_root.to_str().expect("repository path"),
                "FlowersecInteropHarness",
                "--tunnel-grant-json",
                &server_grant,
                "--upstream-url",
                &ready.upstream_url,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start Swift endpoint harness"),
    );
    let mut swift_reader = BufReader::new(swift.0.stdout.take().expect("Swift stdout"));
    line.clear();
    swift_reader
        .read_line(&mut line)
        .expect("Swift attaching line");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap()["event"],
        "attaching"
    );

    let tunnel = Arc::new(
        connect_tunnel(
            ready.grant_client,
            ConnectOptions {
                origin: Some("https://app.redeven.com".to_owned()),
                transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..ConnectOptions::default()
            },
        )
        .await
        .expect("connect Swift endpoint"),
    );
    exercise_client(tunnel, Path::Tunnel).await;
}

async fn start_swift_direct_harness(
    repo_root: &std::path::Path,
    upstream_url: &str,
) -> (DirectHarnessGuard, DirectConnectInfo) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind direct bridge");
    let address = listener.local_addr().expect("direct bridge address");
    let channel_id = "swift-rust-direct".to_owned();
    let psk = [0x5a_u8; 32];
    let psk_b64u = URL_SAFE_NO_PAD.encode(psk);
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64
        + 300;
    let credential = serde_json::json!({
        "channel_id": channel_id.clone(),
        "suite": DirectSuite::X25519HkdfSha256Aes256Gcm as u16,
        "e2ee_psk_b64u": psk_b64u.clone(),
        "init_expires_at_unix_s": expires_at,
    });
    let mut child = ChildGuard(
        Command::new("swift")
            .args([
                "run",
                "--package-path",
                repo_root.to_str().expect("repository path"),
                "FlowersecInteropHarness",
                "--direct-credential-json",
                &credential.to_string(),
                "--upstream-url",
                upstream_url,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start Swift direct endpoint harness"),
    );
    let child_stdin = child.0.stdin.take().expect("Swift stdin");
    let mut child_stdout = BufReader::new(child.0.stdout.take().expect("Swift stdout"));
    let mut line = String::new();
    child_stdout
        .read_line(&mut line)
        .expect("Swift direct ready line");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap()["event"],
        "ready"
    );
    let bridge = tokio::spawn(run_direct_bridge(listener, child_stdin, child_stdout));
    let direct_info = DirectConnectInfo {
        ws_url: format!("ws://{address}/direct"),
        channel_id,
        e2ee_psk_b64u: psk_b64u,
        channel_init_expire_at_unix_s: expires_at,
        default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
    };
    (
        DirectHarnessGuard {
            _child: child,
            bridge,
        },
        direct_info,
    )
}

async fn run_direct_bridge(
    listener: TcpListener,
    mut child_stdin: ChildStdin,
    mut child_stdout: BufReader<ChildStdout>,
) {
    let (socket, _) = listener.accept().await.expect("accept Rust client");
    let mut websocket = accept_async(socket).await.expect("accept WebSocket");
    let (swift_tx, mut swift_rx) = mpsc::channel::<Vec<u8>>(32);
    std::thread::spawn(move || {
        loop {
            let mut header = [0_u8; 4];
            if child_stdout.read_exact(&mut header).is_err() {
                break;
            }
            let length = u32::from_be_bytes(header) as usize;
            if length > 16 * 1024 * 1024 {
                break;
            }
            let mut payload = vec![0_u8; length];
            if child_stdout.read_exact(&mut payload).is_err()
                || swift_tx.blocking_send(payload).is_err()
            {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            message = websocket.next() => {
                match message {
                    Some(Ok(Message::Binary(payload))) => {
                        let length = u32::try_from(payload.len()).expect("WebSocket frame length");
                        if child_stdin.write_all(&length.to_be_bytes()).is_err()
                            || child_stdin.write_all(&payload).is_err()
                            || child_stdin.flush().is_err()
                        {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if websocket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
            payload = swift_rx.recv() => {
                let Some(payload) = payload else { break };
                if websocket.send(Message::Binary(payload.into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn exercise_client(client: Arc<flowersec::Client>, expected_path: Path) {
    assert_eq!(client.path(), expected_path);
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
        .expect("Swift RPC");
    assert!(response.ok);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), notify_rx)
            .await
            .expect("notification timeout")
            .expect("notification sender"),
        "world"
    );
    let echo = client.open_stream("echo").await.expect("open echo");
    echo.write(b"interop-stream-v1").await.expect("write echo");
    assert_eq!(
        echo.read_exact(17).await.expect("read echo"),
        b"interop-stream-v1"
    );
    echo.close().await.expect("close echo");
    client
        .probe_liveness(Duration::from_secs(2))
        .await
        .expect("Swift liveness ACK");

    let proxy = ProxyClient::new(client.clone(), ContractOptions::default()).expect("proxy");
    let http = proxy
        .request(HttpRequest::get("/http"))
        .await
        .expect("Swift HTTP proxy");
    assert_eq!(http.status, 200);
    assert_eq!(http.body, b"flowersec-go-proxy-ok");
    let websocket = proxy
        .open_websocket("/ws", Vec::new())
        .await
        .expect("proxy WS");
    websocket
        .send(WebSocketFrame {
            op: WebSocketOp::Text,
            payload: b"rust-swift-websocket".to_vec(),
        })
        .await
        .expect("send WS");
    assert_eq!(
        websocket.receive().await.expect("receive WS"),
        WebSocketFrame {
            op: WebSocketOp::Text,
            payload: b"rust-swift-websocket".to_vec(),
        }
    );
    websocket.close(Some(1000), "done").await.expect("close WS");
    client.close().await.expect("close client");
}
