use super::*;

// These obsolete ALPNs are negative peer inputs, never supported profiles.
const OBSOLETE_ALPNS: [(PathProfile, &[u8]); 2] = [
    (PathProfile::DirectV4, b"flowersec-direct/3"),
    (PathProfile::TunnelV4, b"flowersec-tunnel/3"),
];

#[tokio::test]
async fn current_server_rejects_obsolete_raw_quic_alpns() {
    for (profile, obsolete) in OBSOLETE_ALPNS {
        assert_eq!(PathProfile::from_alpn(obsolete), None);
        assert_alpn_rejected(profile, Some(obsolete), None).await;
    }
}

#[tokio::test]
async fn current_client_rejects_obsolete_raw_quic_alpns() {
    for (profile, obsolete) in OBSOLETE_ALPNS {
        assert_alpn_rejected(profile, None, Some(obsolete)).await;
    }
}

async fn assert_alpn_rejected(
    profile: PathProfile,
    client_alpn: Option<&[u8]>,
    server_alpn: Option<&[u8]>,
) {
    let identity =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("test certificate");
    let certificate = identity.cert.der().clone();
    let limits = RawQuicLimits::for_session(2, Duration::from_secs(2)).expect("limits");
    let mut server = RawQuicServerConfig::new(
        profile,
        vec![certificate.as_ref().to_vec()],
        identity.signing_key.serialize_der(),
        limits,
    )
    .expect("current server config");
    if let Some(alpn) = server_alpn {
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivateKeyDer::try_from(identity.signing_key.serialize_der()).expect("key"),
        )
        .expect("test server TLS");
        tls.alpn_protocols = vec![alpn.to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("test QUIC server TLS");
        server.inner = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server.inner.transport_config(Arc::new(
            transport_config(limits, false).expect("test server transport"),
        ));
    }
    let client = if let Some(alpn) = client_alpn {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("test trust root");
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![alpn.to_vec()];
        RawQuicClientConfig::from_tls(profile, limits, tls, None).expect("test client config")
    } else {
        RawQuicClientConfig::new_ca(profile, vec![certificate.as_ref().to_vec()], limits)
            .expect("current client config")
    };
    let listener = RawQuicListener::bind("127.0.0.1:0".parse().unwrap(), server).expect("listener");
    let address = listener.local_address().expect("listener address");
    let client_cancellation = Cancellation::new();
    let server_cancellation = Cancellation::new();
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            RawQuicSession::dial(
                vec![address],
                "localhost".into(),
                client,
                &client_cancellation,
            ),
            listener.accept(&server_cancellation),
        )
    })
    .await;
    tokio::time::timeout(Duration::from_secs(1), listener.close())
        .await
        .expect("rejected handshake cleanup");
    let (client_result, server_result) = result.expect("ALPN rejection deadline");
    assert!(
        matches!(client_result, Err(RawQuicError::Handshake)),
        "client must reject unsupported ALPN for {profile:?}: {client_result:?}"
    );
    assert!(
        matches!(server_result, Err(RawQuicError::Handshake)),
        "server must reject unsupported ALPN for {profile:?}: {server_result:?}"
    );
}

#[test]
fn pin_verifier_rejects_critical_duplicate_and_malformed_extensions() {
    use rcgen::{
        CertificateParams, CustomExtension, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    };
    use time::{Duration as TimeDuration, OffsetDateTime};

    // Rustls rejects these identities while configuring a server, so exercise
    // the native verifier directly with the correctly pinned peer DER.
    for name in [
        "unknown-critical-extension",
        "duplicate-key-usage",
        "malformed-key-usage",
        "malformed-extended-key-usage",
    ] {
        let key = KeyPair::generate().expect("P-256 key");
        let mut params = CertificateParams::new(vec!["localhost".into()]).expect("params");
        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::minutes(1);
        params.not_after = now + TimeDuration::hours(1);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        match name {
            "unknown-critical-extension" => {
                let mut extension = CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]);
                extension.set_criticality(true);
                params.custom_extensions.push(extension);
            }
            "duplicate-key-usage" => {
                params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[2, 5, 29, 15],
                        vec![3, 2, 7, 0x80],
                    ));
            }
            "malformed-key-usage" => {
                params.key_usages.clear();
                params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[2, 5, 29, 15],
                        vec![5, 0],
                    ));
            }
            "malformed-extended-key-usage" => {
                params.extended_key_usages.clear();
                params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[2, 5, 29, 37],
                        vec![5, 0],
                    ));
            }
            _ => unreachable!(),
        }
        let certificate = params.self_signed(&key).expect("certificate");
        let leaf = certificate.der();
        let failure = Arc::new(AtomicU8::new(PIN_FAILURE_NONE));
        let verifier = PinnedServerVerifier {
            active_leaf_der_sha256: vec![Sha256::digest(leaf.as_ref()).into()],
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            failure: failure.clone(),
        };
        assert!(
            verifier
                .verify_server_cert(
                    leaf,
                    &[],
                    &ServerName::try_from("localhost").unwrap(),
                    &[],
                    UnixTime::since_unix_epoch(Duration::from_secs(now.unix_timestamp() as u64)),
                )
                .is_err(),
            "certificate {name} must be rejected"
        );
        assert_eq!(
            failure.load(Ordering::Acquire),
            PIN_FAILURE_PROFILE,
            "certificate {name}"
        );
    }
}

#[tokio::test]
async fn endpoint_shutdown_releases_current_and_previous_migration_sockets() {
    let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("endpoint");
    let previous_address = endpoint.local_addr().unwrap();
    let migrated = std::net::UdpSocket::bind("127.0.0.1:0").expect("migration socket");
    let current_address = migrated.local_addr().unwrap();
    endpoint.rebind(migrated).expect("migrate");
    tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle_and_shutdown())
        .await
        .expect("endpoint retirement deadline");
    let previous = std::net::UdpSocket::bind(previous_address).expect("previous socket released");
    let current = std::net::UdpSocket::bind(current_address).expect("current socket released");
    assert_eq!(endpoint.local_addr().unwrap(), current_address);
    assert_eq!(previous.local_addr().unwrap(), previous_address);
    assert_eq!(current.local_addr().unwrap(), current_address);
    assert!(
        endpoint
            .rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .is_err(),
        "retired endpoint cannot migrate"
    );
}
