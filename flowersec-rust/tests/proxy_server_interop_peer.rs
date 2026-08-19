use std::{
    io::{self, Write},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use flowersec::v2::{
    Acceptor, Artifact, DirectIssueOptions, EndpointSet, Issuer, SessionOptions,
    WebSocketAcceptorOptions,
};
use flowersec::{ProxyServer, ProxyServerOptions, SessionHandlerOptions, SessionHandlers};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use url::Url;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawned by the Browser TypeScript ProxyServer interoperability matrix"]
async fn browser_typescript_proxy_runtime_uses_rust_proxy_server() {
    let upstream = std::env::var("FLOWERSEC_PROXY_UPSTREAM").expect("proxy upstream environment");
    let upstream: Url = upstream.parse().expect("valid proxy upstream URL");
    let acceptor = Arc::new(
        Acceptor::bind_websocket(WebSocketAcceptorOptions {
            bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            certificate_chain_der: Vec::new(),
            private_key_der: Vec::new(),
            allowed_origins: vec!["https://app.example".into()],
            max_inbound_streams: 8,
            accept_timeout: Duration::from_secs(10),
        })
        .expect("bind loopback WebSocket listener"),
    );
    let address = acceptor.local_address().expect("listener address");
    let mut session_options = SessionOptions::new("browser-proxy-rust");
    session_options.max_inbound_streams = 8;
    let issued = Issuer::new()
        .issue_direct(DirectIssueOptions {
            session: session_options,
            endpoints: EndpointSet::new([format!("ws://{address}")]).expect("endpoint set"),
            rendezvous_group_id: "browser-proxy-rust".into(),
            listener_audience: "browser-proxy-matrix".into(),
            upstream_address: address.to_string(),
        })
        .expect("issue direct artifact");
    let artifact = Artifact::parse(issued.artifact_json()).expect("server artifact");

    let mut options = ProxyServerOptions::new(upstream.clone(), upstream);
    options.allowed_upstream_hosts = vec!["127.0.0.1".into()];
    options.allowed_origins = vec!["https://app.example".parse().expect("allowed origin")];
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
        .register(&mut handlers)
        .expect("register proxy handlers");

    println!(
        "{}",
        json!({
            "runtime": "rust",
            "artifact_json": String::from_utf8(issued.artifact_json()).expect("artifact JSON"),
            "origin": "https://app.example"
        })
    );
    io::stdout().flush().expect("flush endpoint");

    let cancellation = CancellationToken::new();
    let accepted = acceptor
        .accept_with_handlers(&artifact, handlers, cancellation.clone())
        .await
        .expect("accept Browser TypeScript Session");
    let _ = accepted.serve(cancellation.clone()).await;
    cancellation.cancel();
    proxy.close().await;
}
