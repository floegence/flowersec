use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cert_test_builder::{
    CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
};
use flowersec::{
    Artifact, ArtifactLease, ConnectErrorCode, ConnectorOptions, RetryDisposition, connect,
};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    version::TLS13,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::{io::AsyncReadExt as _, net::TcpListener, task::JoinHandle};
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy, Debug)]
enum InvalidProfile {
    NonP256,
    OverlongLifetime,
    NotYetValid,
    Expired,
}

struct TestIdentity {
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

#[derive(Debug)]
struct ServerObservation {
    tls_completed: bool,
    application_bytes: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_wss_pin_rejects_hash_matched_invalid_profiles_before_spend_or_fsb3() {
    for profile in [
        InvalidProfile::NonP256,
        InvalidProfile::OverlongLifetime,
        InvalidProfile::NotYetValid,
        InvalidProfile::Expired,
    ] {
        let identity = identity(profile);
        let pin = URL_SAFE_NO_PAD.encode(Sha256::digest(identity.leaf.as_ref()));
        let (address, server) = start_wss_server(identity).await;
        let artifact = artifact(address, pin);
        let spends = Arc::new(AtomicUsize::new(0));
        let retires = Arc::new(AtomicUsize::new(0));
        let spend_counter = spends.clone();
        let retire_counter = retires.clone();
        let lease = ArtifactLease::new_with_retire(
            artifact,
            move || async move {
                spend_counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            move || async move {
                retire_counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        let options = ConnectorOptions::new()
            .with_websocket_origin("https://app.example")
            .unwrap()
            .with_connect_timeout(StdDuration::from_secs(2))
            .unwrap();

        let error = connect(lease, options).await.unwrap_err();
        let observation = tokio::time::timeout(StdDuration::from_secs(10), server)
            .await
            .unwrap_or_else(|_| panic!("{profile:?} server did not observe the TLS result"))
            .expect("profile server task panicked");

        assert_eq!(
            error.code(),
            ConnectErrorCode::TransportSecurityFailed,
            "{profile:?}"
        );
        assert_eq!(
            error.retry_disposition(),
            RetryDisposition::Terminal,
            "{profile:?}"
        );
        assert_eq!(spends.load(Ordering::SeqCst), 0, "{profile:?}");
        assert_eq!(retires.load(Ordering::SeqCst), 1, "{profile:?}");
        assert!(!observation.tls_completed, "{profile:?}");
        assert!(observation.application_bytes.is_empty(), "{profile:?}");
    }
}

fn identity(profile: InvalidProfile) -> TestIdentity {
    let now = OffsetDateTime::now_utc();
    let (not_before, not_after) = match profile {
        InvalidProfile::NonP256 => (now - Duration::minutes(1), now + Duration::hours(1)),
        InvalidProfile::OverlongLifetime => (now - Duration::days(1), now + Duration::days(14)),
        InvalidProfile::NotYetValid => (now + Duration::hours(1), now + Duration::hours(2)),
        InvalidProfile::Expired => (now - Duration::hours(2), now - Duration::hours(1)),
    };
    let key = match profile {
        InvalidProfile::NonP256 => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
        _ => KeyPair::generate().unwrap(),
    };
    let mut params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    params.not_before = not_before;
    params.not_after = not_after;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let certificate = params.self_signed(&key).unwrap();
    TestIdentity {
        leaf: certificate.der().clone(),
        key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    }
}

async fn start_wss_server(identity: TestIdentity) -> (SocketAddr, JoinHandle<ServerObservation>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let provider = Arc::new(ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![identity.leaf], identity.key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return ServerObservation {
                tls_completed: false,
                application_bytes: Vec::new(),
            };
        };
        let mut application_bytes = vec![0; 4096];
        let read = tokio::time::timeout(
            StdDuration::from_millis(500),
            tls.read(&mut application_bytes),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(0);
        application_bytes.truncate(read);
        ServerObservation {
            tls_completed: true,
            application_bytes,
        }
    });
    (address, task)
}

fn artifact(address: SocketAddr, pin: String) -> Artifact {
    let projection = json!({
        "allowed_suites": [1],
        "channel_id": "channel",
        "default_suite": 1,
        "establish_timeout_seconds": 30,
        "idle_timeout_seconds": 0,
        "max_inbound_streams": 1,
        "profile": "flowersec/3",
        "rekey_completion_timeout_seconds": 30,
        "rekey_prepare_timeout_seconds": 10,
        "selected_features": 0
    });
    let contract = URL_SAFE_NO_PAD.encode(hash_lp(
        b"flowersec-v3-session-contract\0",
        &canonical_json(&projection),
    ));
    let value = json!({
        "correlation": {"tags": [], "v": 3},
        "path": {
            "candidates": [{
                "carrier": "websocket",
                "id": "wss-invalid-profile",
                "tls": {"mode": "pin", "pins": [{
                    "algorithm": "sha-256",
                    "not_after_unix_s": unix_seconds() + 600,
                    "value_b64u": pin
                }]},
                "url": format!("wss://127.0.0.1:{}/flowersec/v3/direct", address.port()),
                "wire_profile": "flowersec-direct/3"
            }],
            "kind": "direct",
            "listener_audience": "listener",
            "rendezvous_group_id": "group",
            "routing_token": "token"
        },
        "profile": "flowersec/3",
        "scoped": [],
        "session": {
            "allowed_suites": [1],
            "channel_id": "channel",
            "contract_hash_b64u": contract,
            "default_suite": 1,
            "e2ee_psk_b64u": URL_SAFE_NO_PAD.encode([7_u8; 32]),
            "establish_timeout_seconds": 30,
            "idle_timeout_seconds": 0,
            "init_expire_at_unix_s": unix_seconds() + 600,
            "max_inbound_streams": 1,
            "rekey_completion_timeout_seconds": 30,
            "rekey_prepare_timeout_seconds": 10,
            "selected_features": 0
        },
        "v": 3
    });
    Artifact::parse(canonical_json(&value)).unwrap()
}

fn canonical_json(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn hash_lp(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(domain.len() + 4 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    preimage.extend_from_slice(canonical);
    Sha256::digest(preimage).into()
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
