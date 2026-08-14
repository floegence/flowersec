use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use flowersec::{
    Acceptor, Artifact, ArtifactLease, ConnectErrorCode, ConnectorOptions, DirectIssueOptions,
    EndpointSet, Issuer, SessionOptions, StreamMetadata, WebSocketAcceptorOptions, connect,
};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_websocket_direct_runs_the_shared_session_core() {
    let acceptor = Arc::new(
        Acceptor::bind_websocket(WebSocketAcceptorOptions {
            bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            certificate_chain_der: Vec::new(),
            private_key_der: Vec::new(),
            allowed_origins: vec!["https://native-client.test".into()],
            max_inbound_streams: 8,
            accept_timeout: Duration::from_secs(5),
        })
        .expect("bind loopback WebSocket listener"),
    );
    let address = acceptor.local_address().expect("listener address");
    let mut session_options = SessionOptions::new("rust-websocket-direct");
    session_options.max_inbound_streams = 8;
    let issued = Issuer::new()
        .issue_direct(DirectIssueOptions {
            session: session_options,
            endpoints: EndpointSet::new([format!("ws://{address}")]).unwrap(),
            rendezvous_group_id: "rust-websocket-group".into(),
            listener_audience: "rust-websocket-listener".into(),
            upstream_address: "127.0.0.1:23998".into(),
        })
        .expect("issue direct artifact");
    let server_artifact = Artifact::parse(issued.artifact_json()).expect("server artifact");
    let cancellation = CancellationToken::new();
    let server_cancellation = cancellation.clone();
    let server = tokio::spawn({
        let acceptor = acceptor.clone();
        async move {
            let session = acceptor
                .accept(&server_artifact, server_cancellation)
                .await
                .expect("accept WebSocket Session");
            let incoming = session
                .accept_stream()
                .await
                .expect("accept request stream");
            assert_eq!(incoming.kind(), "websocket.direct");
            assert_eq!(
                incoming.stream().read().await.expect("read request"),
                Some(Bytes::from_static(b"request"))
            );
            assert_eq!(
                incoming.stream().read().await.expect("read request FIN"),
                None
            );
            incoming
                .stream()
                .write(Bytes::from_static(b"response"))
                .await
                .expect("write response");
            incoming
                .stream()
                .close_write()
                .await
                .expect("finish response");
            session
        }
    });

    let client_artifact = Artifact::parse(issued.artifact_json()).expect("client artifact");
    let lease = ArtifactLease::new(client_artifact, || async { Ok(()) });
    let connector = ConnectorOptions::new()
        .with_websocket_origin("https://native-client.test")
        .unwrap()
        .with_connect_timeout(Duration::from_secs(5))
        .unwrap();
    let client = connect(lease, connector)
        .await
        .expect("connect WebSocket Session");
    assert!(client.unreliable_messages().is_err());
    let stream = client
        .open_stream("websocket.direct", StreamMetadata::empty())
        .await
        .expect("open request stream");
    stream
        .write(Bytes::from_static(b"request"))
        .await
        .expect("write request");
    stream.close_write().await.expect("finish request");
    assert_eq!(
        stream.read().await.expect("read response"),
        Some(Bytes::from_static(b"response"))
    );
    assert_eq!(stream.read().await.expect("read response FIN"), None);

    let server = server.await.expect("join server");
    let (client_close, server_close) = tokio::join!(client.close(), server.close());
    client_close.expect("close client");
    server_close.expect("close server");
    cancellation.cancel();
}

#[tokio::test]
async fn secure_or_mixed_candidates_without_roots_fail_before_spend() {
    for (name, endpoints) in [
        ("wss", vec!["wss://localhost:443"]),
        ("raw-quic", vec!["quic://127.0.0.1:443"]),
        (
            "mixed",
            vec!["ws://127.0.0.1:23998", "quic://127.0.0.1:443"],
        ),
    ] {
        let issued = Issuer::new()
            .issue_direct(DirectIssueOptions {
                session: SessionOptions::new(format!("rust-rootless-{name}")),
                endpoints: EndpointSet::new(endpoints).expect("canonical endpoint set"),
                rendezvous_group_id: format!("rust-rootless-{name}-group"),
                listener_audience: "rust-rootless-listener".into(),
                upstream_address: "127.0.0.1:23998".into(),
            })
            .expect("issue secure artifact");
        let artifact = Artifact::parse(issued.artifact_json()).expect("parse secure artifact");
        let spends = Arc::new(AtomicUsize::new(0));
        let observed = spends.clone();
        let lease = ArtifactLease::new(artifact, move || {
            let observed = observed.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
        let options = ConnectorOptions::new()
            .with_websocket_origin("https://native-client.test")
            .expect("valid WebSocket origin");

        let error = connect(lease, options)
            .await
            .expect_err("TLS candidates require explicit roots");
        assert_eq!(error.code(), ConnectErrorCode::InvalidInput, "{name}");
        assert_eq!(spends.load(Ordering::SeqCst), 0, "{name} spend count");
    }
}

#[test]
fn explicit_roots_reject_invalid_values() {
    assert_eq!(
        ConnectorOptions::new()
            .with_trust_roots_der(Vec::new())
            .expect_err("empty root set must fail")
            .code(),
        ConnectErrorCode::InvalidInput,
    );
    assert_eq!(
        ConnectorOptions::new()
            .with_trust_roots_der(vec![Vec::new()])
            .expect_err("empty root must fail")
            .code(),
        ConnectErrorCode::InvalidInput,
    );
    assert_eq!(
        ConnectorOptions::new()
            .with_trust_roots_der(vec![vec![1]])
            .expect_err("malformed DER root must fail")
            .code(),
        ConnectErrorCode::InvalidInput,
    );
}
