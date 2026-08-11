use std::{net::SocketAddr, sync::Arc, time::Duration};

use flowersec_native_transport::{
    Cancellation, DatagramSendOutcome, PathProfile, RawQuicClientConfig, RawQuicError,
    RawQuicLimits, RawQuicListener, RawQuicServerConfig, RawQuicSession,
};

const CERTIFICATE: &str = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";
const PRIVATE_KEY: &str = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6";

#[test]
fn raw_quic_requires_explicit_roots_and_tls_identity() {
    assert!(matches!(
        RawQuicClientConfig::new(PathProfile::Direct, vec![], limits()),
        Err(RawQuicError::InvalidTrust)
    ));
    assert!(matches!(
        RawQuicServerConfig::new(PathProfile::Direct, vec![], vec![], limits()),
        Err(RawQuicError::InvalidServerIdentity)
    ));
}

#[tokio::test]
async fn raw_quic_runs_stream_datagram_and_bounded_shutdown() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::Direct))
            .expect("bind raw QUIC listener"),
    );
    let address = listener.local_address().expect("listener address");
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move {
            listener
                .accept(&Cancellation::new())
                .await
                .expect("accept raw QUIC")
        })
    };
    let client = RawQuicSession::dial(
        vec![address],
        "localhost".into(),
        client_config(PathProfile::Direct),
        &Cancellation::new(),
    )
    .await
    .expect("connect raw QUIC");
    let server = accepting.await.expect("server task");

    assert_eq!(client.profile(), PathProfile::Direct);
    assert_eq!(server.profile(), PathProfile::Direct);
    assert_eq!(client.inbound_bidirectional_stream_capacity(), 10);

    let client_stream = client
        .open_stream(&Cancellation::new())
        .await
        .expect("open stream");
    assert_eq!(
        client_stream
            .write(b"native-driver".to_vec(), &Cancellation::new())
            .await
            .expect("write stream"),
        13,
    );
    let server_stream = tokio::time::timeout(
        Duration::from_secs(1),
        server.accept_stream(&Cancellation::new()),
    )
    .await
    .expect("accept stream deadline")
    .expect("accept stream");
    client_stream
        .close_write(&Cancellation::new())
        .await
        .expect("finish stream");
    assert_eq!(
        server_stream
            .read(64, &Cancellation::new())
            .await
            .expect("read stream")
            .expect("stream data"),
        b"native-driver",
    );
    assert_eq!(
        server_stream
            .read(64, &Cancellation::new())
            .await
            .expect("read FIN"),
        None,
    );

    assert_eq!(
        client.send_datagram(b"unreliable".to_vec()),
        DatagramSendOutcome::Accepted,
    );
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            server.receive_datagram(&Cancellation::new()),
        )
        .await
        .expect("datagram deadline")
        .expect("receive datagram"),
        b"unreliable",
    );

    client.abort();
    tokio::time::timeout(Duration::from_secs(1), server.wait_termination())
        .await
        .expect("peer termination barrier");
    tokio::time::timeout(Duration::from_secs(1), listener.close())
        .await
        .expect("listener cleanup barrier");
}

#[tokio::test]
async fn cancellation_settles_pending_accept_without_closing_listener() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::Tunnel))
            .expect("bind raw QUIC listener"),
    );
    let cancellation = Cancellation::new();
    let pending = {
        let listener = listener.clone();
        let cancellation = cancellation.clone();
        tokio::spawn(async move { listener.accept(&cancellation).await })
    };
    cancellation.cancel();
    assert!(matches!(
        pending.await.expect("accept task"),
        Err(RawQuicError::Canceled)
    ));
    assert!(listener.local_address().is_ok());
    tokio::time::timeout(Duration::from_secs(1), listener.close())
        .await
        .expect("listener cleanup barrier");
}

#[tokio::test]
async fn canceled_close_write_can_retry_and_deliver_fin() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::Direct))
            .expect("bind raw QUIC listener"),
    );
    let address = listener.local_address().expect("listener address");
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move {
            listener
                .accept(&Cancellation::new())
                .await
                .expect("accept raw QUIC")
        })
    };
    let client = RawQuicSession::dial(
        vec![address],
        "localhost".into(),
        client_config(PathProfile::Direct),
        &Cancellation::new(),
    )
    .await
    .expect("connect raw QUIC");
    let server = accepting.await.expect("server task");
    let client_stream = client
        .open_stream(&Cancellation::new())
        .await
        .expect("open stream");
    client_stream
        .write(vec![7], &Cancellation::new())
        .await
        .expect("write stream");
    let server_stream = server
        .accept_stream(&Cancellation::new())
        .await
        .expect("accept stream");

    let canceled = Cancellation::new();
    canceled.cancel();
    assert!(matches!(
        client_stream.close_write(&canceled).await,
        Err(RawQuicError::Canceled)
    ));
    client_stream
        .close_write(&Cancellation::new())
        .await
        .expect("retry FIN");
    assert_eq!(
        server_stream
            .read(1, &Cancellation::new())
            .await
            .expect("read payload"),
        Some(vec![7]),
    );
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            server_stream.read(1, &Cancellation::new()),
        )
        .await
        .expect("FIN deadline")
        .expect("read FIN"),
        None,
    );

    client.abort();
    listener.close().await;
}

#[tokio::test]
async fn migration_is_client_owned_and_preserves_the_connection() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::Direct))
            .expect("bind raw QUIC listener"),
    );
    let address = listener.local_address().expect("listener address");
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move {
            listener
                .accept(&Cancellation::new())
                .await
                .expect("accept raw QUIC")
        })
    };
    let client = RawQuicSession::dial(
        vec![address],
        "localhost".into(),
        client_config(PathProfile::Direct),
        &Cancellation::new(),
    )
    .await
    .expect("connect raw QUIC");
    let server = accepting.await.expect("server task");

    assert!(matches!(
        server.migrate_local_address(loopback()),
        Err(RawQuicError::MigrationUnavailable)
    ));
    let before = client.local_address().expect("client address");
    let rebound = client
        .migrate_local_address(loopback())
        .expect("client migration");
    assert_ne!(rebound.port(), before.port());

    let stream = client
        .open_stream(&Cancellation::new())
        .await
        .expect("open after migration");
    stream
        .write(vec![9], &Cancellation::new())
        .await
        .expect("write after migration");
    let peer = tokio::time::timeout(
        Duration::from_secs(1),
        server.accept_stream(&Cancellation::new()),
    )
    .await
    .expect("migration validation deadline")
    .expect("accept after migration");
    assert_eq!(
        peer.read(1, &Cancellation::new())
            .await
            .expect("read after migration"),
        Some(vec![9]),
    );

    client.abort();
    listener.close().await;
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback")
}

fn limits() -> RawQuicLimits {
    RawQuicLimits::for_session(10, Duration::from_secs(2)).expect("limits")
}

fn client_config(profile: PathProfile) -> RawQuicClientConfig {
    RawQuicClientConfig::new(profile, vec![decode_base64(CERTIFICATE)], limits())
        .expect("client config")
}

fn server_config(profile: PathProfile) -> RawQuicServerConfig {
    RawQuicServerConfig::new(
        profile,
        vec![decode_base64(CERTIFICATE)],
        decode_base64(PRIVATE_KEY),
        limits(),
    )
    .expect("server config")
}

fn decode_base64(input: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1_u32 << bits) - 1;
        }
    }
    output
}
