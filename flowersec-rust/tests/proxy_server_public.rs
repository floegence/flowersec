use std::{sync::Arc, time::Duration};

use flowersec::{
    ProxyServer, ProxyServerError, ProxyServerOptions, SessionHandlerOptions, SessionHandlers,
    StreamHandlerOptions, StreamHandlers,
};

#[tokio::test]
async fn proxy_server_public_api_is_application_session_only() {
    let options = ProxyServerOptions {
        upstream: "http://127.0.0.1:8080".parse().expect("valid upstream"),
        upstream_origin: "http://127.0.0.1:8080"
            .parse()
            .expect("valid upstream origin"),
        upstream_trust_roots_der: Vec::new(),
        allowed_upstream_hosts: vec!["127.0.0.1".into()],
        allowed_origins: vec!["https://app.example".parse().expect("valid origin")],
        max_concurrent_streams: 4,
        max_json_frame_bytes: 1024,
        max_chunk_bytes: 1024,
        max_body_bytes: 4096,
        max_websocket_frame_bytes: 1024,
        default_http_request_timeout: Duration::from_secs(1),
        max_http_request_timeout: Duration::from_secs(2),
        extra_request_headers: vec!["x-request-id".into()],
        extra_response_headers: vec!["x-request-id".into()],
        blocked_response_headers: vec!["location".into()],
        extra_websocket_headers: vec!["x-request-id".into()],
        forbidden_cookie_names: vec!["session".into()],
        forbidden_cookie_name_prefixes: vec!["private_".into()],
        on_error: Some(Arc::new(|_error| {})),
    };
    let server = ProxyServer::new(options).expect("create proxy server");
    let mut handlers =
        SessionHandlers::new(SessionHandlerOptions::default()).expect("create handlers");
    server
        .register(&mut handlers)
        .expect("register proxy handlers");
    assert_eq!(
        server.register(&mut handlers),
        Err(ProxyServerError::AlreadyRegistered)
    );
    let mut streams =
        StreamHandlers::new(StreamHandlerOptions::default()).expect("create stream handlers");
    server
        .register_stream_handlers(&mut streams)
        .expect("register proxy handlers into role-neutral registrar");
    assert_eq!(
        server.register_stream_handlers(&mut streams),
        Err(ProxyServerError::AlreadyRegistered)
    );
    server.close().await;
    server.close().await;
}
