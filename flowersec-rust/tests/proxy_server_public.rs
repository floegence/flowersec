use std::{sync::Arc, time::Duration};

use flowersec::{
    HandlerPlanOptions, ProxyServer, ProxyServerOptions, StreamDispatch, TransportEnvironment,
};

#[tokio::test]
async fn proxy_server_exposes_only_current_raw_stream_registrations() {
    let options = ProxyServerOptions {
        upstream: "http://127.0.0.1:8080".parse().expect("valid upstream"),
        upstream_origin: "http://127.0.0.1:8080"
            .parse()
            .expect("valid upstream origin"),
        upstream_trust_roots_der: Vec::new(),
        allowed_upstream_hosts: vec!["127.0.0.1".into()],
        allowed_upstream_addresses: Vec::new(),
        allowed_origins: vec!["https://app.example".parse().expect("valid origin")],
        max_concurrent_streams: 4,
        max_concurrent_http_streams: 0,
        max_concurrent_event_streams: 0,
        event_stream_idle_timeout: Duration::ZERO,
        max_metadata_bytes: 1024,
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
        credentials: None,
        on_error: Some(Arc::new(|_error| {})),
    };
    let server = ProxyServer::new(options).expect("create proxy server");
    let registrations = server
        .stream_registrations()
        .expect("current registrations");
    assert_eq!(registrations.len(), 2);
    assert_eq!(registrations[0].kind, "flowersec-proxy/http1");
    assert_eq!(registrations[1].kind, "flowersec-proxy/ws");

    let environment = TransportEnvironment::new();
    let plan = environment
        .handler_plan(HandlerPlanOptions {
            streams: StreamDispatch::Registered(registrations.clone()),
            application_bytes: 65536,
        })
        .expect("freeze current proxy handlers");
    plan.close();

    let mut duplicates = registrations;
    duplicates.push(duplicates[0].clone());
    assert!(
        environment
            .handler_plan(HandlerPlanOptions {
                streams: StreamDispatch::Registered(duplicates),
                application_bytes: 65536,
            })
            .is_err()
    );

    server.close().await;
    server.close().await;
}
