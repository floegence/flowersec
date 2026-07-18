use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    Client,
    client::{ConnectOptions, connect_direct},
    e2ee::{Secret32, ServerHandshakeOptions, Suite},
    endpoint::{DirectAcceptOptions, accept_direct},
    generated::flowersec::direct::v1::{DirectConnectInfo, Suite as DirectSuite},
    proxy::{
        ContractOptions, HTTP1_KIND, HttpRequestMeta, HttpResponseMeta, PROTOCOL_VERSION,
        ProxyServer, ServerOptions,
    },
    rpc::{Router, Server as RpcServer},
    streamhello, streamio,
    transport::TungsteniteTransport,
    transport_security::TransportSecurityPolicy,
    yamux::YamuxError,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

#[tokio::test]
async fn proxy_server_streams_request_and_response_before_end_frames() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let (request_chunk_tx, request_chunk_rx) = oneshot::channel();
    let (release_response_tail_tx, release_response_tail_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.expect("accept upstream request");
        let mut wire = Vec::new();
        read_through_headers(&mut socket, &mut wire).await;
        let first = read_http_chunk(&mut socket, &mut wire).await;
        request_chunk_tx
            .send(first)
            .expect("report first request chunk");
        assert!(read_http_chunk(&mut socket, &mut wire).await.is_empty());

        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n",
            )
            .await
            .expect("write response head and first chunk");
        release_response_tail_rx
            .await
            .expect("release response tail");
        socket
            .write_all(b"6\r\n world\r\n0\r\n\r\n")
            .await
            .expect("write response tail");
    });

    let (client, endpoint_task) = connect_proxy_server(
        upstream_address,
        ServerOptions {
            upstream: format!("http://{upstream_address}"),
            upstream_origin: format!("http://{upstream_address}"),
            allowed_upstream_hosts: Vec::new(),
            contract: ContractOptions::default(),
            default_timeout: None,
            max_timeout: None,
            max_concurrent_streams: 64,
        },
    )
    .await;

    let stream = client
        .open_stream(HTTP1_KIND)
        .await
        .expect("open proxy stream");
    streamio::write_json(
        &stream,
        &HttpRequestMeta {
            v: PROTOCOL_VERSION,
            request_id: "streaming-request".to_owned(),
            method: "POST".to_owned(),
            path: "/stream".to_owned(),
            headers: Vec::new(),
            external_origin: None,
            timeout_ms: None,
        },
    )
    .await
    .expect("write request metadata");
    streamio::write_chunk(&stream, b"first")
        .await
        .expect("write first request chunk");
    let first_request_chunk = tokio::time::timeout(Duration::from_secs(2), request_chunk_rx)
        .await
        .expect("first request chunk must arrive before terminator")
        .expect("first request chunk signal");
    assert_eq!(first_request_chunk, b"first");
    streamio::write_chunk(&stream, &[])
        .await
        .expect("write request terminator");

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        streamio::read_json::<HttpResponseMeta>(&stream, 1024 * 1024),
    )
    .await
    .expect("response metadata must arrive before upstream tail")
    .expect("read response metadata");
    assert!(response.ok);
    assert_eq!(response.status, Some(200));
    let first_response_chunk =
        tokio::time::timeout(Duration::from_secs(2), streamio::read_chunk(&stream, 1024))
            .await
            .expect("first response chunk must arrive before upstream tail")
            .expect("read first response chunk");
    assert_eq!(first_response_chunk, b"hello");

    release_response_tail_tx
        .send(())
        .expect("release response tail");
    assert_eq!(
        streamio::read_chunk(&stream, 1024)
            .await
            .expect("read response tail"),
        b" world"
    );
    assert!(
        streamio::read_chunk(&stream, 1024)
            .await
            .expect("read response terminator")
            .is_empty()
    );

    client.close().await.expect("close client");
    upstream_task.await.expect("upstream task");
    endpoint_task.abort();
}

#[tokio::test]
async fn proxy_server_resets_saturated_stream_and_releases_permit() {
    let flowersec_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Flowersec endpoint");
    let flowersec_address = flowersec_listener.local_addr().expect("endpoint address");
    let (psk, expires) = credentials();
    let (first_accepted_tx, first_accepted_rx) = oneshot::channel();
    let (finish_endpoint_tx, finish_endpoint_rx) = oneshot::channel();
    let endpoint_task = tokio::spawn(async move {
        let session = accept_session(&flowersec_listener, psk, expires).await;
        accept_rpc_bootstrap(&session).await;
        let server = ProxyServer::new(ServerOptions {
            upstream: "http://127.0.0.1:1".to_owned(),
            upstream_origin: "http://127.0.0.1:1".to_owned(),
            allowed_upstream_hosts: Vec::new(),
            contract: ContractOptions::default(),
            default_timeout: None,
            max_timeout: None,
            max_concurrent_streams: 1,
        })
        .expect("proxy server");

        let (first_kind, first_stream) = session.accept_stream().await.expect("accept first");
        let first_server = server.clone();
        let first_task =
            tokio::spawn(async move { first_server.serve_stream(&first_kind, first_stream).await });
        tokio::task::yield_now().await;
        first_accepted_tx.send(()).expect("report first stream");

        let (second_kind, second_stream) = session.accept_stream().await.expect("accept second");
        server
            .serve_stream(&second_kind, second_stream)
            .await
            .expect("reject saturated stream");

        first_task.await.expect("first stream task").ok();
        let (third_kind, third_stream) = session.accept_stream().await.expect("accept third");
        server
            .serve_stream(&third_kind, third_stream)
            .await
            .expect("serve after permit release");
        finish_endpoint_rx.await.expect("finish endpoint");
    });
    let client = connect_client(flowersec_address, psk, expires).await;

    let first = client.open_stream(HTTP1_KIND).await.expect("open first");
    first_accepted_rx.await.expect("first stream accepted");
    let second = client.open_stream(HTTP1_KIND).await.expect("open second");
    let second_read = tokio::time::timeout(Duration::from_secs(2), second.read_exact(1))
        .await
        .expect("saturated stream must be reset immediately");
    assert!(matches!(second_read, Err(YamuxError::Reset)));

    first.reset().await.expect("reset first stream");
    let third = client.open_stream(HTTP1_KIND).await.expect("open third");
    streamio::write_json(
        &third,
        &HttpRequestMeta {
            v: PROTOCOL_VERSION + 1,
            request_id: "after-release".to_owned(),
            method: "GET".to_owned(),
            path: "/".to_owned(),
            headers: Vec::new(),
            external_origin: None,
            timeout_ms: None,
        },
    )
    .await
    .expect("write invalid metadata");
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        streamio::read_json::<HttpResponseMeta>(&third, 1024 * 1024),
    )
    .await
    .expect("permit must be reusable")
    .expect("read structured error");
    assert_eq!(
        response.error.expect("structured error").code,
        "invalid_request_meta"
    );

    finish_endpoint_tx.send(()).expect("finish endpoint");
    client.close().await.expect("close client");
    endpoint_task.await.expect("endpoint task");
}

#[tokio::test]
async fn unknown_length_response_overflow_resets_after_success_metadata() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let (release_overflow_tx, release_overflow_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.expect("accept upstream request");
        let mut wire = Vec::new();
        read_through_headers(&mut socket, &mut wire).await;
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n",
            )
            .await
            .expect("write allowed response chunk");
        release_overflow_rx.await.expect("release overflow chunk");
        socket
            .write_all(b"1\r\n!\r\n0\r\n\r\n")
            .await
            .expect("write overflowing response chunk");
    });
    let contract = ContractOptions {
        max_body_bytes: 5,
        ..ContractOptions::default()
    };
    let (client, endpoint_task) = connect_proxy_server(
        upstream_address,
        ServerOptions {
            upstream: format!("http://{upstream_address}"),
            upstream_origin: format!("http://{upstream_address}"),
            allowed_upstream_hosts: Vec::new(),
            contract,
            default_timeout: None,
            max_timeout: None,
            max_concurrent_streams: 64,
        },
    )
    .await;

    let stream = client
        .open_stream(HTTP1_KIND)
        .await
        .expect("open proxy stream");
    write_request_meta(&stream, "unknown-overflow", "GET").await;
    streamio::write_chunk(&stream, &[])
        .await
        .expect("write request terminator");
    let response: HttpResponseMeta = streamio::read_json(&stream, 1024 * 1024)
        .await
        .expect("read success metadata");
    assert!(response.ok);
    assert_eq!(
        streamio::read_chunk(&stream, 1024)
            .await
            .expect("read allowed chunk"),
        b"hello"
    );
    release_overflow_tx.send(()).expect("release overflow");
    let next_frame =
        tokio::time::timeout(Duration::from_secs(2), streamio::read_chunk(&stream, 1024))
            .await
            .expect("overflow must terminate the stream");
    assert!(matches!(
        next_frame,
        Err(flowersec::streamio::StreamIoError::Yamux(YamuxError::Reset))
    ));

    client.close().await.expect("close client");
    upstream_task.await.expect("upstream task");
    endpoint_task.abort();
}

#[tokio::test]
async fn known_length_response_overflow_returns_structured_error_before_success_metadata() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.expect("accept upstream request");
        let mut wire = Vec::new();
        read_through_headers(&mut socket, &mut wire).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntoolong")
            .await
            .expect("write oversized response");
    });
    let contract = ContractOptions {
        max_body_bytes: 5,
        ..ContractOptions::default()
    };
    let (client, endpoint_task) = connect_proxy_server(
        upstream_address,
        server_options(upstream_address, contract, 64),
    )
    .await;

    let stream = client
        .open_stream(HTTP1_KIND)
        .await
        .expect("open proxy stream");
    write_request_meta(&stream, "known-overflow", "GET").await;
    streamio::write_chunk(&stream, &[])
        .await
        .expect("write request terminator");
    let response: HttpResponseMeta = streamio::read_json(&stream, 1024 * 1024)
        .await
        .expect("read structured error");
    assert!(!response.ok);
    assert_eq!(
        response.error.expect("response error").code,
        "response_body_too_large"
    );

    client.close().await.expect("close client");
    upstream_task.await.expect("upstream task");
    endpoint_task.abort();
}

#[tokio::test]
async fn request_body_overflow_cancels_upstream_and_returns_structured_error() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let (upstream_closed_tx, upstream_closed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.expect("accept upstream request");
        while socket.read_u8().await.is_ok() {}
        upstream_closed_tx
            .send(())
            .expect("report canceled upstream request");
    });
    let contract = ContractOptions {
        max_body_bytes: 5,
        ..ContractOptions::default()
    };
    let (client, endpoint_task) = connect_proxy_server(
        upstream_address,
        server_options(upstream_address, contract, 64),
    )
    .await;

    let stream = client
        .open_stream(HTTP1_KIND)
        .await
        .expect("open proxy stream");
    write_request_meta(&stream, "request-overflow", "POST").await;
    streamio::write_chunk(&stream, b"hello")
        .await
        .expect("write allowed request chunk");
    streamio::write_chunk(&stream, b"!")
        .await
        .expect("write overflowing request chunk");
    let response: HttpResponseMeta = streamio::read_json(&stream, 1024 * 1024)
        .await
        .expect("read structured request error");
    assert!(!response.ok);
    assert_eq!(
        response.error.expect("request error").code,
        "request_body_too_large"
    );
    tokio::time::timeout(Duration::from_secs(2), upstream_closed_rx)
        .await
        .expect("overflow must cancel upstream")
        .expect("upstream cancellation signal");

    client.close().await.expect("close client");
    upstream_task.await.expect("upstream task");
    endpoint_task.abort();
}

#[tokio::test]
async fn upstream_early_response_does_not_wait_for_request_terminator() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let (first_chunk_tx, first_chunk_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.expect("accept upstream request");
        let mut wire = Vec::new();
        read_through_headers(&mut socket, &mut wire).await;
        first_chunk_tx
            .send(read_http_chunk(&mut socket, &mut wire).await)
            .expect("report first request chunk");
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nearly")
            .await
            .expect("write early response");
    });
    let (client, endpoint_task) = connect_proxy_server(
        upstream_address,
        server_options(upstream_address, ContractOptions::default(), 64),
    )
    .await;

    let stream = client
        .open_stream(HTTP1_KIND)
        .await
        .expect("open proxy stream");
    write_request_meta(&stream, "early-response", "POST").await;
    streamio::write_chunk(&stream, b"partial")
        .await
        .expect("write partial request body");
    assert_eq!(
        first_chunk_rx.await.expect("first request chunk signal"),
        b"partial"
    );
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        streamio::read_json::<HttpResponseMeta>(&stream, 1024 * 1024),
    )
    .await
    .expect("early response metadata must not wait for request terminator")
    .expect("read early response metadata");
    assert!(response.ok);
    assert_eq!(
        streamio::read_chunk(&stream, 1024)
            .await
            .expect("read early response body"),
        b"early"
    );
    assert!(
        streamio::read_chunk(&stream, 1024)
            .await
            .expect("read early response terminator")
            .is_empty()
    );

    client.close().await.expect("close client");
    upstream_task.await.expect("upstream task");
    endpoint_task.abort();
}

#[tokio::test]
async fn oversized_request_frame_cancels_upstream_and_returns_structured_error() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.expect("accept upstream request");
        while socket.read_u8().await.is_ok() {}
    });
    let contract = ContractOptions {
        max_chunk_bytes: 4,
        ..ContractOptions::default()
    };
    let (client, endpoint_task) = connect_proxy_server(
        upstream_address,
        server_options(upstream_address, contract, 64),
    )
    .await;

    let stream = client
        .open_stream(HTTP1_KIND)
        .await
        .expect("open proxy stream");
    write_request_meta(&stream, "oversized-frame", "POST").await;
    streamio::write_chunk(&stream, b"12345")
        .await
        .expect("write oversized request frame");
    let response: HttpResponseMeta = streamio::read_json(&stream, 1024 * 1024)
        .await
        .expect("read structured framing error");
    assert!(!response.ok);
    assert_eq!(
        response.error.expect("framing error").code,
        "request_body_too_large"
    );

    client.close().await.expect("close client");
    upstream_task.await.expect("upstream task");
    endpoint_task.abort();
}

#[tokio::test]
async fn client_reset_cancels_active_upstream_request() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let (first_chunk_tx, first_chunk_rx) = oneshot::channel();
    let (upstream_closed_tx, upstream_closed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.expect("accept upstream request");
        let mut wire = Vec::new();
        read_through_headers(&mut socket, &mut wire).await;
        first_chunk_tx
            .send(read_http_chunk(&mut socket, &mut wire).await)
            .expect("report first request chunk");
        while socket.read_u8().await.is_ok() {}
        upstream_closed_tx
            .send(())
            .expect("report upstream cancellation");
    });
    let (client, endpoint_task) = connect_proxy_server(
        upstream_address,
        server_options(upstream_address, ContractOptions::default(), 64),
    )
    .await;

    let stream = client
        .open_stream(HTTP1_KIND)
        .await
        .expect("open proxy stream");
    write_request_meta(&stream, "client-reset", "POST").await;
    streamio::write_chunk(&stream, b"partial")
        .await
        .expect("write partial request body");
    assert_eq!(
        first_chunk_rx.await.expect("first request chunk signal"),
        b"partial"
    );
    stream.reset().await.expect("reset proxy stream");
    tokio::time::timeout(Duration::from_secs(2), upstream_closed_rx)
        .await
        .expect("reset must cancel upstream")
        .expect("upstream cancellation signal");

    client.close().await.expect("close client");
    upstream_task.await.expect("upstream task");
    endpoint_task.abort();
}

async fn connect_proxy_server(
    upstream_address: std::net::SocketAddr,
    options: ServerOptions,
) -> (Arc<Client>, tokio::task::JoinHandle<()>) {
    let flowersec_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Flowersec endpoint");
    let flowersec_address = flowersec_listener.local_addr().expect("endpoint address");
    let (psk, expires) = credentials();
    assert_eq!(
        options.upstream,
        format!("http://{upstream_address}"),
        "test options must target the upstream listener"
    );
    let endpoint_task = tokio::spawn(async move {
        let session = accept_session(&flowersec_listener, psk, expires).await;
        accept_rpc_bootstrap(&session).await;
        ProxyServer::new(options)
            .expect("proxy server")
            .serve(&session)
            .await
            .expect("serve proxy session");
    });
    (
        connect_client(flowersec_address, psk, expires).await,
        endpoint_task,
    )
}

fn server_options(
    upstream_address: std::net::SocketAddr,
    contract: ContractOptions,
    max_concurrent_streams: usize,
) -> ServerOptions {
    ServerOptions {
        upstream: format!("http://{upstream_address}"),
        upstream_origin: format!("http://{upstream_address}"),
        allowed_upstream_hosts: Vec::new(),
        contract,
        default_timeout: None,
        max_timeout: None,
        max_concurrent_streams,
    }
}

fn credentials() -> ([u8; 32], i64) {
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64
        + 60;
    ([0x6d; 32], expires)
}

async fn accept_session(
    listener: &TcpListener,
    psk: [u8; 32],
    expires: i64,
) -> flowersec::endpoint::Session {
    let (tcp, _) = listener.accept().await.expect("accept Flowersec endpoint");
    let transport = TungsteniteTransport::accept(tcp)
        .await
        .expect("accept Flowersec WebSocket");
    let handshake = ServerHandshakeOptions::new(
        Secret32::new(psk),
        Suite::X25519HkdfSha256Aes256Gcm,
        expires,
    );
    accept_direct(Arc::new(transport), DirectAcceptOptions::new(handshake))
        .await
        .expect("accept direct session")
}

async fn accept_rpc_bootstrap(session: &flowersec::endpoint::Session) {
    let (kind, stream) = session.accept_stream().await.expect("accept RPC bootstrap");
    assert_eq!(kind, streamhello::RPC_KIND);
    tokio::spawn(Arc::new(RpcServer::new(Router::default())).serve(stream));
}

async fn connect_client(address: std::net::SocketAddr, psk: [u8; 32], expires: i64) -> Arc<Client> {
    Arc::new(
        connect_direct(
            DirectConnectInfo {
                ws_url: format!("ws://{address}/flowersec"),
                channel_id: "rust-proxy-streaming".to_owned(),
                e2ee_psk_b64u: URL_SAFE_NO_PAD.encode(psk),
                channel_init_expire_at_unix_s: expires,
                default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
            },
            ConnectOptions {
                transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..ConnectOptions::default()
            },
        )
        .await
        .expect("connect direct client"),
    )
}

async fn write_request_meta(
    stream: &flowersec::yamux::YamuxStream,
    request_id: &str,
    method: &str,
) {
    streamio::write_json(
        stream,
        &HttpRequestMeta {
            v: PROTOCOL_VERSION,
            request_id: request_id.to_owned(),
            method: method.to_owned(),
            path: "/stream".to_owned(),
            headers: Vec::new(),
            external_origin: None,
            timeout_ms: None,
        },
    )
    .await
    .expect("write request metadata");
}

async fn read_through_headers(socket: &mut TcpStream, wire: &mut Vec<u8>) {
    while !wire.windows(4).any(|window| window == b"\r\n\r\n") {
        read_more(socket, wire).await;
    }
    let end = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator")
        + 4;
    wire.drain(..end);
}

async fn read_http_chunk(socket: &mut TcpStream, wire: &mut Vec<u8>) -> Vec<u8> {
    while !wire.windows(2).any(|window| window == b"\r\n") {
        read_more(socket, wire).await;
    }
    let line_end = wire
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("chunk header");
    let length = usize::from_str_radix(
        std::str::from_utf8(&wire[..line_end])
            .expect("ASCII chunk header")
            .split(';')
            .next()
            .expect("chunk length"),
        16,
    )
    .expect("hex chunk length");
    let frame_length = line_end + 2 + length + 2;
    while wire.len() < frame_length {
        read_more(socket, wire).await;
    }
    let payload = wire[line_end + 2..line_end + 2 + length].to_vec();
    wire.drain(..frame_length);
    payload
}

async fn read_more(socket: &mut TcpStream, wire: &mut Vec<u8>) {
    let mut buffer = [0_u8; 4096];
    let read = socket.read(&mut buffer).await.expect("read HTTP wire");
    assert_ne!(read, 0, "HTTP connection closed unexpectedly");
    wire.extend_from_slice(&buffer[..read]);
}
