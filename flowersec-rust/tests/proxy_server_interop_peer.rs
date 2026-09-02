use std::{
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flowersec::{
    Acceptor, Artifact, ProxyServer, ProxyServerOptions, SessionHandlerOptions, SessionHandlers,
    WebSocketAcceptorOptions,
};
use serde::Deserialize;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use url::Url;

const ORIGIN: &str = "https://app.example";
const TEST_CERT_DER_B64: &str = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";
const TEST_KEY_DER_B64: &str = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6";

#[derive(Deserialize)]
struct IssuerResponse {
    artifact_json: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawned by the Browser TypeScript ProxyServer interoperability matrix"]
async fn browser_typescript_proxy_runtime_uses_rust_proxy_server() {
    let upstream = std::env::var("FLOWERSEC_PROXY_UPSTREAM").expect("proxy upstream environment");
    let upstream: Url = upstream.parse().expect("valid proxy upstream URL");
    let certificate = STANDARD
        .decode(TEST_CERT_DER_B64)
        .expect("test certificate DER");
    let acceptor = Arc::new(
        Acceptor::bind_websocket(WebSocketAcceptorOptions {
            bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            certificate_chain_der: vec![certificate.clone()],
            private_key_der: STANDARD.decode(TEST_KEY_DER_B64).expect("test key DER"),
            allowed_origins: vec![ORIGIN.into()],
            max_inbound_streams: 16,
            accept_timeout: Duration::from_secs(10),
        })
        .expect("bind TLS WebSocket listener"),
    );
    let address = acceptor.local_address().expect("listener address");
    let artifact_json = issue_artifact(format!(
        "wss://localhost:{}/flowersec/v3/direct",
        address.port()
    ));
    let artifact = Artifact::parse(&artifact_json).expect("server artifact");

    let mut options = ProxyServerOptions::new(upstream.clone(), upstream);
    options.allowed_upstream_hosts = vec!["127.0.0.1".into()];
    options.allowed_origins = vec![ORIGIN.parse().expect("allowed origin")];
    options.max_concurrent_streams = 4;
    options.max_json_frame_bytes = 4096;
    options.max_chunk_bytes = 8;
    options.max_body_bytes = 8;
    options.max_websocket_frame_bytes = 32;
    options.default_http_request_timeout = Duration::from_secs(5);
    options.max_http_request_timeout = Duration::from_secs(5);
    options.extra_request_headers = vec!["cookie".into(), "origin".into(), "x-request-id".into()];
    options.extra_response_headers = vec!["x-visible".into()];
    options.blocked_response_headers = vec!["location".into()];
    options.extra_websocket_headers = vec!["x-request-id".into()];
    options.forbidden_cookie_names = vec!["secret".into()];
    options.forbidden_cookie_name_prefixes = vec!["private_".into()];
    let proxy = ProxyServer::new(options).expect("create proxy server");
    let mut handlers =
        SessionHandlers::new(SessionHandlerOptions::default()).expect("create session handlers");
    proxy
        .register_stream_handlers(&mut handlers)
        .expect("register proxy handlers");

    println!(
        "{}",
        json!({
            "runtime": "rust",
            "artifact_json": artifact_json,
            "origin": ORIGIN,
            "trust_pem": certificate_pem(&certificate),
        })
    );
    io::stdout().flush().expect("flush endpoint");

    let cancellation = CancellationToken::new();
    let accepted = acceptor
        .accept_with_handlers(&artifact, handlers, cancellation.clone())
        .await
        .expect("accept Browser TypeScript session");
    let _ = accepted.serve(cancellation.clone()).await;
    cancellation.cancel();
    proxy.close().await;
}

fn issue_artifact(endpoint: String) -> String {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root")
        .to_path_buf();
    let mut child = Command::new("go")
        .args(["run", "./internal/cmd/parity-artifact-issuer"])
        .current_dir(repository_root.join("flowersec-go"))
        .env("FLOWERSEC_SERVER_PARITY_PEER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn parity artifact issuer");
    serde_json::to_writer(
        child.stdin.as_mut().expect("issuer stdin"),
        &json!({ "mode": "direct", "endpoint": endpoint }),
    )
    .expect("write issuer request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for artifact issuer");
    assert!(
        output.status.success(),
        "artifact issuer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<IssuerResponse>(&output.stdout)
        .expect("decode artifact issuer response")
        .artifact_json
}

fn certificate_pem(certificate: &[u8]) -> String {
    let encoded = STANDARD.encode(certificate);
    let lines = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n")
}
