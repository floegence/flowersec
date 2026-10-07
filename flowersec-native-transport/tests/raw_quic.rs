use std::{net::SocketAddr, sync::Arc, time::Duration};

use flowersec_native_transport::{
    Cancellation, DatagramSendOutcome, PathProfile, PreparationBudget, PreparationLimits,
    RawQuicClientConfig, RawQuicError, RawQuicLimits, RawQuicListener, RawQuicServerConfig,
    RawQuicSession,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};

const CERTIFICATE: &str = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";
const PRIVATE_KEY: &str = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6";

#[test]
fn raw_quic_requires_explicit_roots_and_tls_identity() {
    assert!(matches!(
        RawQuicClientConfig::new_ca(PathProfile::DirectV4, vec![], limits()),
        Err(RawQuicError::InvalidTrust)
    ));
    assert!(matches!(
        RawQuicServerConfig::new(PathProfile::DirectV4, vec![], vec![], limits()),
        Err(RawQuicError::InvalidServerIdentity)
    ));
}

#[tokio::test]
async fn raw_quic_runs_stream_datagram_and_bounded_shutdown() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::DirectV4))
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
        client_config(PathProfile::DirectV4),
        &Cancellation::new(),
    )
    .await
    .expect("connect raw QUIC");
    let server = accepting.await.expect("server task");

    assert_eq!(client.profile(), PathProfile::DirectV4);
    assert_eq!(server.profile(), PathProfile::DirectV4);
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
async fn dial_from_retirement_releases_dedicated_port_while_listener_survives() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::DirectV4))
            .expect("bind raw QUIC listener"),
    );
    let address = listener.local_address().expect("listener address");
    let probe = std::net::UdpSocket::bind(loopback()).expect("reserve client port");
    let client_address = probe.local_addr().expect("client port");
    drop(probe);

    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept(&Cancellation::new()).await })
    };
    let client = RawQuicSession::dial_from(
        client_address,
        address,
        "localhost".into(),
        client_config(PathProfile::DirectV4),
        &Cancellation::new(),
    )
    .await
    .expect("dial from fixed client port");
    let server = accepting
        .await
        .expect("server accept task")
        .expect("server session");

    // Retained RawQuicSession handles keep metadata and the connection
    // capability alive, but wait_termination must retire the dedicated dial
    // endpoint and release its UDP socket.
    let retained = client.clone();
    client.abort();
    tokio::time::timeout(Duration::from_secs(2), retained.wait_termination())
        .await
        .expect("dedicated endpoint retirement");
    let rebound = std::net::UdpSocket::bind(client_address)
        .expect("dial endpoint released while session handle is retained");
    drop(rebound);

    // The accepted listener owns a shared endpoint. A new dial can reuse the
    // exact client port while the listener and accepted sibling remain alive.
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept(&Cancellation::new()).await })
    };
    let sibling = RawQuicSession::dial_from(
        client_address,
        address,
        "localhost".into(),
        client_config(PathProfile::DirectV4),
        &Cancellation::new(),
    )
    .await
    .expect("reuse retired dial port");
    let sibling_server = accepting
        .await
        .expect("sibling accept task")
        .expect("sibling session");
    let stream = sibling
        .open_stream(&Cancellation::new())
        .await
        .expect("open sibling stream");
    stream
        .write(vec![0x5a], &Cancellation::new())
        .await
        .expect("write sibling stream");
    let peer = sibling_server
        .accept_stream(&Cancellation::new())
        .await
        .expect("accept sibling stream");
    assert_eq!(
        peer.read(1, &Cancellation::new())
            .await
            .expect("read sibling"),
        Some(vec![0x5a])
    );

    sibling.abort();
    tokio::time::timeout(Duration::from_secs(2), sibling.wait_termination())
        .await
        .expect("sibling dial endpoint retirement");
    server.abort();
    listener.close().await;
}

#[tokio::test]
async fn canceled_dial_from_releases_dedicated_endpoint_before_return() {
    let probe = std::net::UdpSocket::bind(loopback()).expect("reserve canceled client port");
    let client_address = probe.local_addr().expect("canceled client port");
    drop(probe);
    let cancellation = Cancellation::new();
    let task = tokio::spawn({
        let cancellation = cancellation.clone();
        async move {
            RawQuicSession::dial_from(
                client_address,
                SocketAddr::new("127.0.0.1".parse().unwrap(), 9),
                "localhost".into(),
                client_config(PathProfile::DirectV4),
                &cancellation,
            )
            .await
        }
    });
    cancellation.cancel();
    assert!(matches!(
        task.await.expect("canceled dial task"),
        Err(RawQuicError::Canceled | RawQuicError::Connect)
    ));
    std::net::UdpSocket::bind(client_address)
        .expect("canceled dial endpoint released before return");
}

#[tokio::test]
async fn listener_close_releases_udp_port_while_listener_is_retained() {
    let listener =
        RawQuicListener::bind(loopback(), server_config(PathProfile::DirectV4)).expect("listener");
    let address = listener.local_address().expect("listener address");
    tokio::time::timeout(Duration::from_secs(2), listener.close())
        .await
        .expect("close deadline");
    let rebound = std::net::UdpSocket::bind(address)
        .expect("closed listener must release its UDP port without dropping the public handle");
    listener.close().await;
    assert_eq!(
        listener.local_address().expect("closed listener address"),
        address
    );
    assert_eq!(rebound.local_addr().unwrap(), address);
}

#[tokio::test]
async fn listener_close_releases_udp_port_while_sessions_and_streams_are_retained() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::TunnelV4)).expect("listener"),
    );
    let address = listener.local_address().expect("listener address");
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move {
            listener
                .accept(&Cancellation::new())
                .await
                .expect("accepted session")
        })
    };
    let client = RawQuicSession::dial(
        vec![address],
        "localhost".into(),
        client_config(PathProfile::TunnelV4),
        &Cancellation::new(),
    )
    .await
    .expect("client");
    let server = accepting.await.expect("accept task");
    let outgoing = client
        .open_stream(&Cancellation::new())
        .await
        .expect("outgoing stream");
    outgoing
        .write(vec![1], &Cancellation::new())
        .await
        .expect("stream write");
    let incoming = server
        .accept_stream(&Cancellation::new())
        .await
        .expect("incoming stream");
    assert_eq!(
        incoming.read(1, &Cancellation::new()).await.unwrap(),
        Some(vec![1])
    );
    let pending_read = {
        let incoming = incoming.clone();
        tokio::spawn(async move { incoming.read(1, &Cancellation::new()).await })
    };
    tokio::time::timeout(Duration::from_secs(2), listener.close())
        .await
        .expect("close joins physical drivers");
    let rebound = std::net::UdpSocket::bind(address)
        .expect("closed sessions and streams must not retain the listener UDP port");
    tokio::time::timeout(Duration::from_secs(2), async {
        server.wait_termination().await;
        client.wait_termination().await;
        incoming.wait_termination_current().await;
        outgoing.wait_termination_current().await;
        assert!(pending_read.await.expect("pending reader").is_err());
    })
    .await
    .expect("all original session and stream owners terminate");
    listener.close().await;
    assert_eq!(
        server.local_address().expect("closed session address"),
        address
    );
    assert_eq!(
        listener.local_address().expect("retained listener address"),
        address
    );
    assert_eq!(rebound.local_addr().unwrap(), address);
}

#[tokio::test]
async fn candidate_listener_accepts_one_connection_and_drains_after_sealing() {
    let capacity = PreparationLimits {
        preauth_input_bytes: 65_536,
        address_attempts: 1,
        work_units: 1024,
    };
    let budget = PreparationBudget::with_capacity(capacity).unwrap();
    let candidate = budget.begin_candidate(capacity).unwrap();
    let listener = RawQuicListener::bind(
        loopback(),
        server_config(PathProfile::TunnelV4)
            .with_preparation_budget(candidate.clone())
            .unwrap(),
    )
    .unwrap();
    let address = listener.local_address().unwrap();
    let cancel = Cancellation::new();
    let (first, second, client) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            listener.accept(&cancel),
            listener.accept(&cancel),
            RawQuicSession::dial(
                vec![address],
                "localhost".into(),
                client_config(PathProfile::TunnelV4),
                &cancel,
            )
        )
    })
    .await
    .expect("both original accepts settle within the handshake deadline");
    let client = client.expect("first candidate connection completes TLS");
    let server = match (first, second) {
        (Ok(server), Err(RawQuicError::ListenerClosed))
        | (Err(RawQuicError::ListenerClosed), Ok(server)) => server,
        _ => panic!("a candidate listener must admit exactly one connection"),
    };
    assert_eq!(candidate.usage().address_attempts, 1);
    assert!(candidate.usage().preauth_input_bytes > 0);
    server.complete_preparation().unwrap();
    let prepared = budget.usage();
    assert!(matches!(
        listener.accept(&cancel).await,
        Err(RawQuicError::ListenerClosed)
    ));

    let outgoing = client.open_stream(&cancel).await.unwrap();
    outgoing.write(b"drain".to_vec(), &cancel).await.unwrap();
    outgoing.close_write(&cancel).await.unwrap();
    let incoming = server.accept_stream(&cancel).await.unwrap();
    assert_eq!(
        incoming.read(5, &cancel).await.unwrap(),
        Some(b"drain".to_vec())
    );
    assert_eq!(incoming.read(1, &cancel).await.unwrap(), None);
    assert_eq!(budget.usage(), prepared);
    client.abort();
    tokio::time::timeout(Duration::from_secs(2), async {
        server.wait_termination().await;
        client.wait_termination().await;
        incoming.wait_termination_current().await;
        outgoing.wait_termination_current().await;
        listener.wait_termination().await;
    })
    .await
    .expect("the original listener and stream drivers join after drain");
    let rebound = std::net::UdpSocket::bind(address)
        .expect("retained candidate handles do not retain the original UDP port");
    assert_eq!(rebound.local_addr().unwrap(), address);
}

#[tokio::test]
async fn stopping_admission_keeps_accepted_sessions_alive_until_they_drain() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::DirectV4)).expect("listener"),
    );
    let address = listener.local_address().expect("listener address");
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move {
            listener
                .accept(&Cancellation::new())
                .await
                .expect("accepted session")
        })
    };
    let client = RawQuicSession::dial(
        vec![address],
        "localhost".into(),
        client_config(PathProfile::DirectV4),
        &Cancellation::new(),
    )
    .await
    .expect("client");
    let server = accepting.await.expect("accept task");
    listener.stop_accepting_current();
    let retired = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.wait_termination().await })
    };
    assert!(matches!(
        listener.accept(&Cancellation::new()).await,
        Err(RawQuicError::ListenerClosed)
    ));
    let outgoing = client
        .open_stream(&Cancellation::new())
        .await
        .expect("open after admission stopped");
    outgoing
        .write(vec![8], &Cancellation::new())
        .await
        .expect("write after admission stopped");
    let incoming = server
        .accept_stream(&Cancellation::new())
        .await
        .expect("accepted session remains usable");
    assert_eq!(
        incoming.read(1, &Cancellation::new()).await.unwrap(),
        Some(vec![8])
    );
    assert!(
        !retired.is_finished(),
        "active session must keep its original listener alive"
    );
    server.abort();
    tokio::time::timeout(Duration::from_secs(2), retired)
        .await
        .expect("listener retirement deadline")
        .expect("retirement task");
    let rebound = std::net::UdpSocket::bind(address)
        .expect("drained listener port is released with all handles retained");
    assert_eq!(
        server.local_address().unwrap(),
        rebound.local_addr().unwrap()
    );
}

#[tokio::test]
async fn listener_close_joins_pending_accept_without_waiting_for_handle_drop() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::DirectV4)).expect("listener"),
    );
    let address = listener.local_address().expect("listener address");
    let pending = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept(&Cancellation::new()).await })
    };
    listener.close().await;
    assert!(matches!(
        pending.await.expect("pending accept"),
        Err(RawQuicError::ListenerClosed)
    ));
    let rebound = std::net::UdpSocket::bind(address)
        .expect("pending accept does not retain closed listener port");
    listener.close().await;
    assert_eq!(
        listener.local_address().unwrap(),
        rebound.local_addr().unwrap()
    );
}

#[tokio::test]
async fn cancellation_settles_pending_accept_without_closing_listener() {
    let listener = Arc::new(
        RawQuicListener::bind(loopback(), server_config(PathProfile::TunnelV4))
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
        RawQuicListener::bind(loopback(), server_config(PathProfile::DirectV4))
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
        client_config(PathProfile::DirectV4),
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
        RawQuicListener::bind(loopback(), server_config(PathProfile::DirectV4))
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
        client_config(PathProfile::DirectV4),
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
async fn raw_quic_enforces_ca_and_pin_tls_profiles() {
    for profile in [PathProfile::DirectV4, PathProfile::TunnelV4] {
        let (root, ca_identity) = private_ca_identity();
        let ca_client =
            RawQuicClientConfig::new_ca(profile, vec![root.as_ref().to_vec()], limits())
                .expect("wire 4 CA client config");
        let ca_server = RawQuicServerConfig::new(
            profile,
            ca_identity.chain_der(),
            ca_identity.key_der(),
            limits(),
        )
        .expect("wire 4 CA server config");
        let (client, server) = connect_pair(ca_client, ca_server)
            .await
            .expect("wire 4 CA connection");
        client.abort();
        server.abort();

        let pinned_identity = self_signed_identity();
        let pin: [u8; 32] = Sha256::digest(pinned_identity.leaf.as_ref()).into();
        let pin_client = RawQuicClientConfig::new_pin(profile, vec![[0xA5; 32], pin], limits())
            .expect("wire 4 pin client config");
        let pin_server = RawQuicServerConfig::new(
            profile,
            pinned_identity.chain_der(),
            pinned_identity.key_der(),
            limits(),
        )
        .expect("wire 4 pin server config");
        let (client, server) = connect_pair(pin_client, pin_server)
            .await
            .expect("wire 4 pin connection");
        client.abort();
        server.abort();

        let mismatched_identity = self_signed_identity();
        let mismatch_client = RawQuicClientConfig::new_pin(profile, vec![[0xA5; 32]], limits())
            .expect("wire 4 mismatch client config");
        let mismatch_server = RawQuicServerConfig::new(
            profile,
            mismatched_identity.chain_der(),
            mismatched_identity.key_der(),
            limits(),
        )
        .expect("wire 4 mismatch server config");
        assert!(matches!(
            connect_pair(mismatch_client, mismatch_server).await,
            Err(RawQuicError::PinMismatch)
        ));
    }
}

#[tokio::test]
async fn raw_quic_rejects_every_pinned_certificate_profile_variant() {
    let now = OffsetDateTime::now_utc();
    for (name, algorithm, not_before, not_after) in [
        (
            "non-p256",
            &PKCS_ECDSA_P384_SHA384,
            now - TimeDuration::minutes(1),
            now + TimeDuration::hours(1),
        ),
        (
            "overlong",
            &PKCS_ECDSA_P256_SHA256,
            now - TimeDuration::minutes(1),
            now + TimeDuration::days(15),
        ),
        (
            "not-yet-valid",
            &PKCS_ECDSA_P256_SHA256,
            now + TimeDuration::hours(1),
            now + TimeDuration::hours(2),
        ),
        (
            "expired",
            &PKCS_ECDSA_P256_SHA256,
            now - TimeDuration::hours(2),
            now - TimeDuration::hours(1),
        ),
    ] {
        let key = KeyPair::generate_for(algorithm).expect("profile key");
        let mut params = CertificateParams::new(vec!["localhost".into()]).expect("params");
        params.not_before = not_before;
        params.not_after = not_after;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let certificate = params.self_signed(&key).expect("certificate");
        let leaf = certificate.der().clone();
        let identity = TestIdentity {
            chain: vec![leaf.clone()],
            leaf: leaf.clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        };
        assert_pin_profile_rejected(name, &identity).await;
    }
}

#[tokio::test]
async fn raw_quic_rejects_invalid_pinned_certificate_extensions() {
    for name in [
        "key-usage-without-digital-signature",
        "extended-key-usage-without-server-auth",
    ] {
        let key = KeyPair::generate().expect("P-256 key");
        let mut params = CertificateParams::new(vec!["localhost".into()]).expect("params");
        (params.not_before, params.not_after) = validity();
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        match name {
            "key-usage-without-digital-signature" => {
                params.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
            }
            "extended-key-usage-without-server-auth" => {
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            }
            _ => unreachable!(),
        }
        let certificate = params.self_signed(&key).expect("certificate");
        let leaf = certificate.der().clone();
        let identity = TestIdentity {
            chain: vec![leaf.clone()],
            leaf,
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        };
        assert_pin_profile_rejected(name, &identity).await;
    }
}

async fn assert_pin_profile_rejected(name: &str, identity: &TestIdentity) {
    let pin: [u8; 32] = Sha256::digest(identity.leaf.as_ref()).into();
    for profile in [PathProfile::DirectV4, PathProfile::TunnelV4] {
        let client =
            RawQuicClientConfig::new_pin(profile, vec![pin], limits()).expect("pin client");
        let server =
            RawQuicServerConfig::new(profile, identity.chain_der(), identity.key_der(), limits())
                .unwrap_or_else(|error| panic!("server identity {name}: {error:?}"));
        assert!(
            matches!(
                connect_pair(client, server).await,
                Err(RawQuicError::PinCertificateInvalid)
            ),
            "certificate {name} was not rejected before a {profile:?} session became ready"
        );
    }
}

struct TestIdentity {
    chain: Vec<CertificateDer<'static>>,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl TestIdentity {
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

fn self_signed_identity() -> TestIdentity {
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
    TestIdentity {
        chain: vec![leaf.clone()],
        leaf,
        key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    }
}

fn private_ca_identity() -> (CertificateDer<'static>, TestIdentity) {
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
        TestIdentity {
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
    RawQuicClientConfig::new_ca(profile, vec![decode_base64(CERTIFICATE)], limits())
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
