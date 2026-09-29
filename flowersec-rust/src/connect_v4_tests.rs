//! Real TLS/WSS integration against a cryptographic peer harness. This peer
//! deliberately does not claim to implement a production admission ledger.
use super::*;
use crate::{
    api_v4::CleanupStatus,
    codec_v4::{
        ActivationSource,
        tests::{b, encode_map, t, u},
    },
    namespace_v4::verifier::credential::tests::Fixture,
    pool_v4::tests::StoreFixture,
    transport::ByteStream,
};
use bytes::Bytes;
use cert_test_builder::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::server::{Request, Response},
    },
};
type Socket = WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

pub(super) fn tls_provisioning() -> (serve::WssServerIdentity, Vec<u8>, [u8; 32]) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.not_before = time::OffsetDateTime::UNIX_EPOCH;
    ca_params.not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(100);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["example.com".into()]).unwrap();
    params.not_before = time::OffsetDateTime::UNIX_EPOCH;
    params.not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(100);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params.signed_by(&key, &issuer).unwrap();
    let digest = Sha256::digest(certificate.der().as_ref()).into();
    (
        serve::WssServerIdentity {
            certificate_chain_der: vec![certificate.der().to_vec()],
            private_key_der: key.serialize_der(),
        },
        ca.der().to_vec(),
        digest,
    )
}
fn tls_identity() -> (Arc<rustls::ServerConfig>, Vec<u8>, [u8; 32]) {
    let (identity, ca, digest) = tls_provisioning();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        identity
            .certificate_chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect(),
        PrivatePkcs8KeyDer::from(identity.private_key_der.clone()).into(),
    )
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (Arc::new(config), ca, digest)
}

struct Setup {
    environment: TransportEnvironment,
    material: PoolConnectionMaterial,
    pool: StoreFixture,
    options: WssConnectOptions,
    server: Peer,
}
struct Peer {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    admission: CredentialAdmission,
    keys: Arc<LocalKeys>,
    artifact: Vec<u8>,
    certificate: Vec<u8>,
}
async fn setup(profile: Profile, pin: bool, bad_pin: bool) -> Setup {
    setup_with_credit(profile, pin, bad_pin, None).await
}
async fn setup_with_credit(
    profile: Profile,
    pin: bool,
    bad_pin: bool,
    credit: Option<u64>,
) -> Setup {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (tls, ca, digest) = tls_identity();
    let server_keys = LocalKeys::generate(profile).unwrap();
    let ed = server_keys.ed_public();
    let mut fixture = Fixture::with_identity(
        ActivationSource::PreauthorizedPool,
        profile.name(),
        Some([
            (server_keys.dh_public(), &ed),
            (server_keys.dh_public(), &ed),
        ]),
    );
    let keys = fixture.environment.identity_keys(profile.name()).unwrap();
    fixture.set_client_keys(&keys);
    fixture.set_wss_route(
        listener.local_addr().unwrap().port(),
        pin.then_some(if bad_pin { [0x55; 32] } else { digest }),
    );
    if let Some(credit) = credit {
        fixture.set_max_credit(credit);
    }
    let pool = StoreFixture::new(&fixture);
    let admission = fixture.reserve().unwrap();
    let artifact = fixture.artifact.clone();
    let certificate = fixture.server.clone();
    let namespaces = vec![Arc::new(Namespace::new(fixture.verifier))];
    let environment = fixture.environment;
    let material = environment
        .pool_connection_material(
            namespaces,
            keys,
            PoolCredentialBytes {
                artifact: fixture.artifact,
                client_certificate: fixture.client,
                server_certificate: fixture.server,
                activation: fixture.activation,
            },
        )
        .unwrap();
    Setup {
        environment,
        material,
        pool,
        options: WssConnectOptions {
            binding_mode: BindingMode::AuthenticatedContext,
            remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
            origin: None,
            ca_certificates_der: if pin { vec![] } else { vec![ca] },
            timeout: Duration::from_secs(10),
            publication_timeout: Duration::from_secs(2),
            queue_messages: 2,
            prepare_bytes: 65536,
            native_runtime_bytes: 1 << 20,
        },
        server: Peer {
            listener,
            tls,
            admission,
            keys: server_keys,
            artifact,
            certificate,
        },
    }
}
async fn receive(socket: &mut Socket, kind: u8) -> Vec<u8> {
    let wire = socket.next().await.unwrap().unwrap().into_data();
    payload(&wire, kind, 65536).unwrap().to_vec()
}
async fn send(socket: &mut Socket, kind: u8, body: &[u8]) {
    socket
        .send(Message::Binary(envelope(kind, body).into()))
        .await
        .unwrap();
}
impl Peer {
    #[expect(
        clippy::result_large_err,
        reason = "Tungstenite fixes the HTTP error response type"
    )]
    async fn socket(&self) -> std::result::Result<Socket, ()> {
        let (tcp, _) = self.listener.accept().await.map_err(|_| ())?;
        let tls = tokio_rustls::TlsAcceptor::from(self.tls.clone())
            .accept(tcp)
            .await
            .map_err(|_| ())?;
        tokio_tungstenite::accept_hdr_async(tls, |request: &Request, mut response: Response| {
            assert_eq!(request.uri().path(), "/flowersec/v4/direct");
            assert!(
                request.headers()["host"]
                    .to_str()
                    .unwrap()
                    .starts_with("example.com:")
            );
            assert_eq!(
                request.headers()["sec-websocket-protocol"],
                "flowersec.direct.v4"
            );
            response.headers_mut().insert(
                "sec-websocket-protocol",
                "flowersec.direct.v4".parse().unwrap(),
            );
            Ok(response)
        })
        .await
        .map_err(|_| ())
    }
    async fn handshake(self) -> (Socket, RecordEngine) {
        let mut socket = self.socket().await.unwrap();
        let hello = receive(&mut socket, 1).await;
        let ch = decode(&hello, "ClientHello", 16384, Context::default()).unwrap();
        let mut fields = Vec::new();
        for (id, name) in [
            "protocol_id",
            "profile_revision",
            "crypto_profile_id",
            "artifact_digest",
            "candidate_id",
            "route_digest",
            "attempt_id",
            "client_nonce",
        ]
        .into_iter()
        .enumerate()
        {
            fields.push((
                id as u64,
                ch.field("ClientHello", name).unwrap().raw().to_vec(),
            ));
        }
        fields.extend([
            (8, b(&[91; 32])),
            (9, u(0)),
            (10, u(0)),
            (11, u(1)),
            (12, b(&[])),
        ]);
        let sh = encode_map(&fields);
        send(&mut socket, 1, &sh).await;
        let transcript: [u8; 32] =
            Sha256::digest(domain(b"flowersec/v4/hello-transcript\0", &[&hello, &sh]).unwrap())
                .into();
        let nonce = ch.b::<32>("ClientHello", "client_nonce").unwrap();
        let a = &self.admission;
        let context = encode_map(&[
            (0, t("4")),
            (1, t(self.profile())),
            (2, u(0)),
            (3, u(0)),
            (4, b(&a.artifact_digest)),
            (5, b(&a.route_digest)),
            (6, b(&a.attempt_id)),
            (7, b(&nonce)),
            (8, b(&transcript)),
            (9, u(0)),
            (10, u(1)),
            (11, u(0)),
            (12, b(&[])),
        ]);
        let context_digest = codec::digest(
            "transport_context_digest",
            decode(&context, "TransportContext", 4096, Context::default()).unwrap(),
        )
        .unwrap();
        let fsb = receive(&mut socket, 2).await;
        let binding = codec::digest(
            "admission_binding",
            decode(
                &fsb,
                "FSB4",
                65536,
                Context::with_activation_source(ActivationSource::PreauthorizedPool),
            )
            .unwrap(),
        )
        .unwrap();
        let mut fields = vec![
            (0, u(0)),
            (1, u(0)),
            (2, u(1)),
            (3, b(&[92; 32])),
            (4, b(&binding)),
            (5, b(&a.route_digest)),
            (6, b(&transcript)),
            (7, u(0)),
            (8, u(1)),
            (9, b(&context_digest)),
            (10, b(&a.certificate_digests[0])),
            (11, b(&a.certificate_digests[1])),
            (12, b(&self.certificate)),
        ];
        let signature = self
            .keys
            .sign(&domain(b"flowersec/v4/fsa4/signature\0", &[&encode_map(&fields)]).unwrap())
            .unwrap();
        fields.push((13, b(&signature)));
        let fsa = encode_map(&fields);
        send(&mut socket, 3, &fsa).await;
        let mut handshake = Handshake::new(
            self.admission,
            Role::Server,
            self.keys,
            HandshakeInput {
                artifact: &self.artifact,
                client_hello: &hello,
                server_hello: &sh,
                transport_context: &context,
                fsb: &fsb,
                fsa: &fsa,
            },
        )
        .unwrap();
        handshake
            .read_noise(&receive(&mut socket, 4).await)
            .unwrap();
        let mut noise = [0; 81];
        let count = handshake.write_noise(&mut noise).unwrap();
        send(&mut socket, 4, &noise[..count]).await;
        handshake
            .verify_ready(&receive(&mut socket, 5).await)
            .unwrap();
        let mut ready = ReadySubmission(None);
        handshake.submit_ready(&mut ready).unwrap();
        send(&mut socket, 5, &ready.0.unwrap()).await;
        (socket, handshake.into_records().unwrap())
    }
    fn profile(&self) -> &str {
        decode(&self.artifact, "Artifact", 65536, Context::default())
            .unwrap()
            .field("Artifact", "crypto_profile_id")
            .unwrap()
            .text()
            .unwrap()
    }
}
struct Published {
    wire: Vec<u8>,
    done: oneshot::Sender<()>,
}
struct TestTransport {
    output: mpsc::Sender<Published>,
    cancel: CancellationToken,
    done: Arc<AtomicBool>,
}
impl RecordPublisher for TestTransport {
    fn publish(&mut self, wire: &[u8]) -> Result<()> {
        let (done, wait) = oneshot::channel();
        self.output
            .try_send(Published {
                wire: wire.to_vec(),
                done,
            })
            .map_err(|_| CryptoError::State)?;
        tokio::task::block_in_place(|| wait.blocking_recv()).map_err(|_| CryptoError::State)
    }
}
impl SessionTransport for TestTransport {
    fn close(&mut self) {
        self.cancel.cancel();
    }
    fn cleanup_status(&self) -> CleanupStatus {
        CleanupStatus {
            complete: self.done.load(Ordering::Acquire),
            cleanup_incomplete: false,
            pending_callbacks: 0,
        }
    }
    fn stream_cleanup_status(&self, _: u64) -> CleanupStatus {
        CleanupStatus {
            complete: true,
            cleanup_incomplete: false,
            pending_callbacks: 0,
        }
    }
}
fn peer_session(
    environment: &TransportEnvironment,
    socket: Socket,
    engine: RecordEngine,
) -> (Session, tokio::task::JoinHandle<()>) {
    let (output, mut input) = mpsc::channel::<Published>(1);
    let cancel = CancellationToken::new();
    let done = Arc::new(AtomicBool::new(false));
    let session = environment
        .adopt_ready_session(
            engine,
            Box::new(TestTransport {
                output,
                cancel: cancel.clone(),
                done: done.clone(),
            }),
        )
        .unwrap();
    let receiver = session.receiver();
    let task = tokio::spawn(async move {
        let (mut sink, mut stream) = socket.split();
        let write_cancel = cancel.clone();
        let writer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _=write_cancel.cancelled()=>break,
                    message=input.recv()=>match message {
                        Some(Published{wire,done})=>{
                            let sent = tokio::select! {
                                _ = write_cancel.cancelled() => break,
                                result = sink.send(Message::Binary(wire.into())) => result,
                            };
                            if sent.is_err(){break;}
                            let _=done.send(());
                        },
                        None=>break,
                    }
                }
            }
            write_cancel.cancel();
        });
        loop {
            tokio::select! {
                _=cancel.cancelled()=>break,
                message=stream.next()=>match message {
                    Some(Ok(Message::Binary(wire)))=>{
                        if tokio::task::block_in_place(||receiver.receive(&wire)).is_err(){break;}
                    },
                    _=>break,
                },
            }
        }
        cancel.cancel();
        let _ = writer.await;
        receiver.close();
        done.store(true, Ordering::Release);
    });
    (session, task)
}
async fn wss_phase<T>(
    profile: Profile,
    stage: &std::cell::Cell<(&str, Instant)>,
    client: &Session,
    server: &Session,
    budget: Duration,
    operation: impl std::future::Future<Output = T>,
) -> T {
    tokio::time::timeout(budget, operation)
        .await
        .unwrap_or_else(|_| {
            let (name, started) = stage.get();
            panic!(
                "WSS {profile:?} timed out during {name} after {:?}; client: {}; server: {}",
                started.elapsed(),
                client.rekey_diagnostic(),
                server.rekey_diagnostic(),
            )
        })
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_wss_pool_connect_dual_ready_stream_rekey_probe_and_cleanup() {
    for (profile, pin) in [(Profile::X25519, true), (Profile::P256, false)] {
        let Setup {
            environment,
            material,
            pool,
            options,
            server,
        } = setup(profile, pin, false).await;
        let provider_baseline = environment.resource_usage();
        let (peer, client) = tokio::join!(
            server.handshake(),
            environment.connect_pool_wss(
                material,
                pool.store.clone(),
                options,
                CancellationToken::new()
            )
        );
        let client = client.unwrap();
        let active = environment.resource_usage();
        assert_eq!(active.connections, provider_baseline.connections + 1);
        assert_eq!(active.tls_handshakes, provider_baseline.tls_handshakes);
        assert_eq!(active.native_handles, provider_baseline.native_handles + 8);
        assert!(active.provider_bytes > provider_baseline.provider_bytes);
        assert_eq!(active.disk_bytes, provider_baseline.disk_bytes);
        assert_eq!(pool.rows(), 1);
        let (server, task) = peer_session(&environment, peer.0, peer.1);
        let stage = std::cell::Cell::new(("probe", Instant::now()));
        let mark = |name| stage.set((name, Instant::now()));
        let opening = async {
            assert_eq!(
                client
                    .probe_liveness(Duration::from_secs(2))
                    .await
                    .unwrap()
                    .outcome,
                ProbeOutcome::Responsive
            );
            mark("open stream");
            let (outgoing, incoming) = tokio::join!(
                client.open_stream("example.wss", Metadata::empty(), 128),
                async { server.next_open().await.unwrap().accept(128).unwrap() }
            );
            let outgoing = outgoing.unwrap();
            mark("write request");
            outgoing
                .write(Bytes::from_static(b"native WSS data"))
                .await
                .unwrap();
            mark("read request");
            assert_eq!(
                incoming.read().await.unwrap().unwrap(),
                Bytes::from_static(b"native WSS data")
            );
            (outgoing, incoming)
        };
        let (outgoing, incoming) = wss_phase(
            profile,
            &stage,
            &client,
            &server,
            Duration::from_secs(15),
            opening,
        )
        .await;
        mark("rekey");
        // The original INIT/REPLY and COMMIT/ACK phases allow 10s and 30s.
        // Preceding I/O must not consume this round's test observation window.
        wss_phase(
            profile,
            &stage,
            &client,
            &server,
            Duration::from_secs(45),
            client.rekey(),
        )
        .await
        .unwrap();
        let completion = async {
            mark("write response");
            incoming
                .write(Bytes::from_static(b"new epoch reply"))
                .await
                .unwrap();
            mark("read response");
            assert_eq!(
                outgoing.read().await.unwrap().unwrap(),
                Bytes::from_static(b"new epoch reply")
            );
            mark("close request write");
            outgoing.close_write().await.unwrap();
            mark("read request EOF");
            assert!(incoming.read().await.unwrap().is_none());
            mark("close response write");
            incoming.close_write().await.unwrap();
            mark("read response EOF");
            assert!(outgoing.read().await.unwrap().is_none());
            mark("finish stream");
            outgoing.finish().await.unwrap();
            mark("drain");
            let drain = client.drain(Duration::from_secs(2)).unwrap();
            assert_eq!(drain.wait().await.unwrap().outcome, DrainOutcome::Drained);
            mark("client cleanup");
            assert!(client.wait_cleanup().await.complete);
            server.close();
            mark("server provider join");
            task.await.unwrap();
            mark("server cleanup");
            assert!(server.wait_cleanup().await.complete);
            let cleaned = environment.resource_usage();
            assert_eq!(cleaned.connections, provider_baseline.connections);
            assert_eq!(cleaned.native_handles, provider_baseline.native_handles);
            assert_eq!(cleaned.provider_bytes, provider_baseline.provider_bytes);
            assert_eq!(cleaned.disk_bytes, provider_baseline.disk_bytes);
        };
        wss_phase(
            profile,
            &stage,
            &client,
            &server,
            Duration::from_secs(15),
            completion,
        )
        .await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_actual_tls_pin_fails_before_pool_spend() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, true).await;
    let peer = tokio::spawn(async move {
        assert!(server.socket().await.is_err());
    });
    assert_eq!(
        environment
            .connect_pool_wss(
                material,
                pool.store.clone(),
                options,
                CancellationToken::new()
            )
            .await
            .unwrap_err(),
        ConnectError::Tls
    );
    assert_eq!(pool.rows(), 0);
    peer.await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_after_client_hello_preserves_consumed_classification() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, false).await;
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let peer = tokio::spawn(async move {
        let mut socket = server.socket().await.unwrap();
        let _ = receive(&mut socket, 1).await;
        stop.cancel();
        while socket.next().await.is_some() {}
    });
    assert_eq!(
        environment
            .connect_pool_wss(material, pool.store.clone(), options, cancel)
            .await
            .unwrap_err(),
        ConnectError::Spent(PostSpendFailure::Canceled)
    );
    assert_eq!(pool.rows(), 1);
    peer.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_record_geometry_is_reserved_before_irreversible_spend() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup_with_credit(Profile::X25519, true, false, Some(4 << 20)).await;
    let peer = tokio::spawn(async move {
        let mut socket = server.socket().await.unwrap();
        // No credential-bearing ClientHello may be published when the complete
        // reliable/rekey reservation cannot fit the original Session account.
        assert!(!matches!(socket.next().await, Some(Ok(Message::Binary(_)))));
    });
    assert_eq!(
        environment
            .connect_pool_wss(
                material,
                pool.store.clone(),
                options,
                CancellationToken::new()
            )
            .await
            .unwrap_err(),
        ConnectError::Capacity
    );
    assert_eq!(pool.rows(), 0);
    peer.await.unwrap();
}
