use std::{net::SocketAddr, sync::Arc, time::Duration};

use cert_test_builder::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use flowersec_native_transport::{
    Cancellation, DatagramSendOutcome, PathProfile, ProtocolVersion, RawQuicClientConfig,
    RawQuicError, RawQuicLimits, RawQuicListener, RawQuicServerConfig, RawQuicSession,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};

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

#[tokio::test]
async fn v3_raw_quic_enforces_ca_pin_and_versioned_alpn() {
    let (root, ca_identity) = private_ca_identity();
    let ca_client =
        RawQuicClientConfig::new_v3_ca(PathProfile::Direct, vec![root.as_ref().to_vec()], limits())
            .expect("v3 CA client config");
    let ca_server = RawQuicServerConfig::new_v3(
        PathProfile::Direct,
        ca_identity.chain_der(),
        ca_identity.key_der(),
        limits(),
    )
    .expect("v3 CA server config");
    let (client, server) = connect_pair(ca_client, ca_server)
        .await
        .expect("v3 CA connection");
    assert_eq!(client.protocol_version(), ProtocolVersion::V3);
    assert_eq!(server.protocol_version(), ProtocolVersion::V3);
    client.abort();
    server.abort();

    let pinned_identity = self_signed_identity();
    let pin: [u8; 32] = Sha256::digest(pinned_identity.leaf.as_ref()).into();
    let pin_client = RawQuicClientConfig::new_v3_pin(PathProfile::Direct, vec![pin], limits())
        .expect("v3 pin client config");
    let pin_server = RawQuicServerConfig::new_v3(
        PathProfile::Direct,
        pinned_identity.chain_der(),
        pinned_identity.key_der(),
        limits(),
    )
    .expect("v3 pin server config");
    let (client, server) = connect_pair(pin_client, pin_server)
        .await
        .expect("v3 pin connection");
    client.abort();
    server.abort();

    let mismatched_identity = self_signed_identity();
    let mismatch_client =
        RawQuicClientConfig::new_v3_pin(PathProfile::Direct, vec![[0xA5; 32]], limits())
            .expect("v3 mismatch client config");
    let mismatch_server = RawQuicServerConfig::new_v3(
        PathProfile::Direct,
        mismatched_identity.chain_der(),
        mismatched_identity.key_der(),
        limits(),
    )
    .expect("v3 mismatch server config");
    assert!(matches!(
        connect_pair(mismatch_client, mismatch_server).await,
        Err(RawQuicError::PinMismatch)
    ));

    let v2_identity = self_signed_identity();
    let v2_server = RawQuicServerConfig::new(
        PathProfile::Direct,
        v2_identity.chain_der(),
        v2_identity.key_der(),
        limits(),
    )
    .expect("v2 server config");
    let v2_server_pin: [u8; 32] = Sha256::digest(v2_identity.leaf.as_ref()).into();
    let v3_client =
        RawQuicClientConfig::new_v3_pin(PathProfile::Direct, vec![v2_server_pin], limits())
            .expect("v3 client config");
    let mismatch = connect_pair(v3_client, v2_server).await;
    assert!(
        matches!(mismatch, Err(RawQuicError::Handshake)),
        "v2/v3 ALPN mismatch returned {mismatch:?}"
    );
}

struct TestIdentityV3 {
    chain: Vec<CertificateDer<'static>>,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl TestIdentityV3 {
    fn chain_der(&self) -> Vec<Vec<u8>> {
        self.chain
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect()
    }

    fn key_der(&self) -> Vec<u8> {
        self.key.secret_der().to_vec()
    }
}

async fn connect_pair(
    client_config: RawQuicClientConfig,
    server_config: RawQuicServerConfig,
) -> Result<(RawQuicSession, RawQuicSession), RawQuicError> {
    let listener = Arc::new(RawQuicListener::bind(loopback(), server_config)?);
    let address = listener.local_address()?;
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept(&Cancellation::new()).await })
    };
    let client = RawQuicSession::dial(
        vec![address],
        "localhost".into(),
        client_config,
        &Cancellation::new(),
    )
    .await;
    let server = accepting.await.expect("server accept task");
    listener.close().await;
    match (client, server) {
        (Ok(client), Ok(server)) => Ok((client, server)),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

fn validity() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (now - TimeDuration::minutes(1), now + TimeDuration::hours(1))
}

fn self_signed_identity() -> TestIdentityV3 {
    let (not_before, not_after) = validity();
    let key = KeyPair::generate().expect("P-256 key");
    let mut params = CertificateParams::new(vec!["localhost".into()]).expect("certificate params");
    params.not_before = not_before;
    params.not_after = not_after;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let certificate = params.self_signed(&key).expect("self-signed certificate");
    let leaf = certificate.der().clone();
    TestIdentityV3 {
        chain: vec![leaf.clone()],
        leaf,
        key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    }
}

fn private_ca_identity() -> (CertificateDer<'static>, TestIdentityV3) {
    let (not_before, not_after) = validity();
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).expect("leaf params");
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;
    leaf_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_certificate: Certificate = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");
    let root = ca.der().clone();
    let leaf = leaf_certificate.der().clone();
    (
        root.clone(),
        TestIdentityV3 {
            chain: vec![leaf.clone(), root],
            leaf,
            key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        },
    )
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
