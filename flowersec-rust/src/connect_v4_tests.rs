//! Real TLS/WSS integration against a cryptographic peer harness. This peer
//! deliberately does not claim to implement a production admission ledger.
use super::*;
use crate::{
    ContractAcceptance, FixedContractQuery, MessageCodec, MessageDefinition, MethodDefinition,
    MethodDefinitionOptions, NotificationServiceRegistration, ResponseLimitPolicy,
    ServiceBindingOptions, ServiceContract, ServiceDefinition, ServiceMethod, ServiceSemantics,
    ServiceShape,
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
    sync::{Semaphore, mpsc, oneshot},
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
    setup_with_application(profile, pin, bad_pin, credit, false).await
}
async fn setup_with_application(
    profile: Profile,
    pin: bool,
    bad_pin: bool,
    credit: Option<u64>,
    execution: bool,
) -> Setup {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (tls, ca, digest) = tls_identity();
    let server_keys = LocalKeys::generate(profile).unwrap();
    let ed = server_keys.ed_public();
    let mut fixture = Fixture::with_identity_and_execution(
        ActivationSource::PreauthorizedPool,
        profile.name(),
        Some([
            (server_keys.dh_public(), &ed),
            (server_keys.dh_public(), &ed),
        ]),
        execution,
    );
    if execution {
        fixture.enable_execution_recovery();
    }
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
        let socket = self.socket().await.unwrap();
        self.handshake_socket(socket).await
    }
    async fn handshake_socket(self, mut socket: Socket) -> (Socket, RecordEngine) {
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
        let artifact = decode(&self.artifact, "Artifact", 65536, Context::default()).unwrap();
        let offered_features = crate::checkpoint_v4::application_features(artifact).unwrap();
        let selected_features = offered_features & ch.u("ClientHello", "offered_features").unwrap();
        fields.extend([
            (8, b(&[91; 32])),
            (9, u(offered_features)),
            (10, u(selected_features)),
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
            (9, u(selected_features)),
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
                Context::with_activation_source(self.admission.source),
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
            (7, u(selected_features)),
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
    tap: Option<mpsc::Sender<Vec<u8>>>,
    cancel: CancellationToken,
    done: Arc<AtomicBool>,
}
impl RecordPublisher for TestTransport {
    fn publish(&mut self, wire: &[u8]) -> Result<()> {
        if let Some(tap) = &self.tap {
            let _ = tap.try_send(wire.to_vec());
        }
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
                tap: None,
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
struct TappedPeer {
    session: Session,
    inject: mpsc::Sender<Vec<u8>>,
    published: mpsc::Receiver<Vec<u8>>,
    committed: mpsc::Receiver<()>,
    publication_gate: Arc<Semaphore>,
    publication_pending: Arc<std::sync::Mutex<Option<(u8, u64)>>>,
    task: tokio::task::JoinHandle<()>,
}
fn tapped_peer_session(
    environment: &TransportEnvironment,
    socket: Socket,
    engine: RecordEngine,
) -> TappedPeer {
    let (output, mut input) = mpsc::channel::<Published>(2);
    let (tap, published) = mpsc::channel::<Vec<u8>>(2);
    let (inject, mut injected) = mpsc::channel::<Vec<u8>>(2);
    let (committed, committed_rx) = mpsc::channel::<()>(2);
    let cancel = CancellationToken::new();
    let done = Arc::new(AtomicBool::new(false));
    let publication_gate = Arc::new(Semaphore::new(0));
    let publication_pending = Arc::new(std::sync::Mutex::new(None));
    let session = environment
        .adopt_ready_session(
            engine,
            Box::new(TestTransport {
                output,
                tap: Some(tap),
                cancel: cancel.clone(),
                done: done.clone(),
            }),
        )
        .unwrap();
    let receiver = session.receiver();
    let writer_gate = publication_gate.clone();
    let writer_pending = publication_pending.clone();
    let task = tokio::spawn(async move {
        let (mut sink, mut stream) = socket.split();
        let write_cancel = cancel.clone();
        let writer = tokio::spawn(async move {
            let mut pending = None;
            loop {
                if pending.is_some() {
                    tokio::select! {
                        _ = write_cancel.cancelled() => break,
                        permit = writer_gate.clone().acquire_owned() => {
                            let permit = match permit {
                                Ok(permit) => permit,
                                Err(_) => break,
                            };
                            let Published { wire: _, done } =
                                pending.take().expect("pending publication");
                            *writer_pending.lock().expect("peer publication diagnostic") = None;
                            std::mem::forget(permit);
                            let _ = done.send(());
                            if committed.send(()).await.is_err() {
                                break;
                            }
                        }
                    }
                    continue;
                }
                tokio::select! {
                    _ = write_cancel.cancelled() => break,
                    message = input.recv() => match message {
                        Some(publication) => {
                            let scope = u64::from_be_bytes(
                                publication.wire[12..20].try_into().expect("published record scope"),
                            );
                            *writer_pending.lock().expect("peer publication diagnostic") =
                                Some((publication.wire[4], scope));
                            pending = Some(publication);
                        },
                        None => break,
                    },
                    injected = injected.recv() => match injected {
                        Some(wire) => {
                            if sink.send(Message::Binary(wire.into())).await.is_err() { break; }
                        }
                        None => break,
                    },
                }
            }
            *writer_pending.lock().expect("peer publication diagnostic") = None;
            write_cancel.cancel();
        });
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                message = stream.next() => match message {
                    Some(Ok(Message::Binary(wire))) => {
                        if tokio::task::block_in_place(|| receiver.receive(&wire)).is_err() { break; }
                    }
                    _ => break,
                },
            }
        }
        let _ = writer.await;
        done.store(true, Ordering::Release);
    });
    TappedPeer {
        session,
        inject,
        published,
        committed: committed_rx,
        publication_gate,
        publication_pending,
        task,
    }
}
impl TappedPeer {
    fn release_publication(&self) {
        self.publication_gate.add_permits(1);
    }
    fn publication_diagnostic(&self) -> String {
        format!(
            "pending_frame_scope={:?}, inject_available={}, gate_permits={}",
            *self
                .publication_pending
                .lock()
                .expect("peer publication diagnostic"),
            self.inject.capacity(),
            self.publication_gate.available_permits(),
        )
    }
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
async fn real_wss_connect_reader_retains_tail_during_terminal_publication() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, false).await;
    let baseline = environment.resource_usage();
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
    let mut peer = tapped_peer_session(&environment, peer.0, peer.1);

    // Generate the two authenticated maintenance records before the client
    // publishes CLOSE. The writer commits each real Session publication while
    // retaining the wire, then sends each retained wire exactly once during
    // the terminal publication window.
    let first_generation = tokio::spawn({
        let session = peer.session.clone();
        async move { session.probe_liveness(Duration::from_secs(2)).await }
    });
    let first_wire = tokio::time::timeout(Duration::from_secs(2), peer.published.recv())
        .await
        .expect("first peer maintenance publication")
        .expect("first peer maintenance wire");
    peer.release_publication();
    tokio::time::timeout(Duration::from_secs(2), peer.committed.recv())
        .await
        .expect("first peer publication commit")
        .expect("first peer publication commit event");
    first_generation.abort();

    let second_generation = tokio::spawn({
        let session = peer.session.clone();
        async move { session.probe_liveness(Duration::from_secs(2)).await }
    });
    let second_wire = tokio::time::timeout(Duration::from_secs(2), peer.published.recv())
        .await
        .expect("second peer maintenance publication")
        .expect("second peer maintenance wire");
    peer.release_publication();
    tokio::time::timeout(Duration::from_secs(2), peer.committed.recv())
        .await
        .expect("second peer publication commit")
        .expect("second peer publication commit event");
    second_generation.abort();

    let probe = TerminalPublicationProbe::new();
    let _probe_guard = install_terminal_publication_probe(&client, probe.clone());
    let receive_probe = MaintenanceReceiveProbe::new(2);
    let _receive_probe_guard = install_maintenance_receive_probe(&client, receive_probe.clone());
    let drain = client.drain(Duration::from_secs(2)).unwrap();
    let drain_wait = tokio::spawn(async move { drain.wait().await });
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking({
                let probe = probe.clone();
                move || probe.wait_entered()
            }),
        )
        .await
        .expect("terminal publication entered")
        .expect("terminal publication probe task"),
        "terminal publication probe released before entry"
    );
    assert!(client.termination_cause().is_none());
    assert!(!client.cleanup_status().complete);

    peer.inject
        .send(first_wire)
        .await
        .expect("inject first generated maintenance wire");
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking({
            let receive_probe = receive_probe.clone();
            move || receive_probe.wait_for(1)
        }),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "first maintenance frame reached reader: {}",
            peer.publication_diagnostic()
        )
    })
    .expect("first maintenance receive probe task");
    assert!(client.termination_cause().is_none());
    assert!(!client.cleanup_status().complete);

    peer.inject
        .send(second_wire)
        .await
        .expect("inject second generated maintenance wire");
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking({
            let receive_probe = receive_probe.clone();
            move || receive_probe.wait_for(2)
        }),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "second maintenance frame reached reader: {}",
            peer.publication_diagnostic()
        )
    })
    .expect("second maintenance receive probe task");
    assert!(client.termination_cause().is_none());
    assert!(!client.cleanup_status().complete);
    assert_eq!(
        environment.resource_usage().connections,
        baseline.connections + 1
    );

    // The reader retention assertion is complete. Release the terminal
    // publisher before waiting for cleanup.
    probe.release();
    let drain_result = tokio::time::timeout(Duration::from_secs(5), drain_wait)
        .await
        .expect("drain completion")
        .expect("drain task")
        .expect("drain result");
    assert_eq!(drain_result.outcome, DrainOutcome::Drained);
    assert!(client.wait_cleanup().await.complete);
    peer.session.close();
    peer.task.await.expect("peer task");
    assert_eq!(
        environment.resource_usage().connections,
        baseline.connections
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_wss_connect_drop_last_session_releases_owner_and_carrier() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, false).await;
    let baseline = environment.resource_usage();
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
    let client_owner = client.owner_lifetime_probe_for_test();
    assert!(client_owner.is_alive());
    let (server_session, peer_task) = peer_session(&environment, peer.0, peer.1);
    let server_owner = server_session.owner_lifetime_probe_for_test();
    assert!(server_owner.is_alive());

    // This is the complete application surface: no handler plan, streams, or
    // explicit close. Dropping the last client Session must release its weak
    // reader owner and close the actual WSS carrier.
    drop(client);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !client_owner.is_alive() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client owner is released without the cleanup deadline");
    assert!(!client_owner.is_alive());
    tokio::time::timeout(Duration::from_secs(3), peer_task)
        .await
        .expect("peer carrier exits after last Session drop")
        .expect("peer carrier task");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let usage = environment.resource_usage();
            if usage.connections == baseline.connections
                && usage.native_handles == baseline.native_handles
                && usage.provider_bytes == baseline.provider_bytes
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client carrier cleanup reaches its resource baseline");
    assert_eq!(
        environment.resource_usage().connections,
        baseline.connections
    );
    assert_eq!(
        environment.resource_usage().native_handles,
        baseline.native_handles
    );
    assert_eq!(
        environment.resource_usage().provider_bytes,
        baseline.provider_bytes
    );
    drop(server_session);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !server_owner.is_alive() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server owner is released without an explicit close or cleanup deadline");
    assert!(!server_owner.is_alive());
    // Pool spend permanently transfers its prepaid controller charge, so the
    // setup snapshot is not a full post-spend accounting baseline. Carrier
    // cleanup is asserted above on the dimensions owned by this test.
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
async fn production_pool_connect_keeps_the_exact_post_commit_failure_and_spend_fact() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, false).await;
    let expected = crate::PoolSpendObservation {
        state: crate::PoolSpendState::CommitKnown,
        artifact_digest: material.admission.artifact_digest,
        activation_digest: material.admission.activation_digest,
        attempt_id: material.admission.attempt_id,
    };
    let cancel = CancellationToken::new();
    // Two original continuity fences precede COMMIT; the third is its actual
    // post-commit fence. Cancel there, before the returned activation is checked.
    pool.proof.cancel_after_checks(3, cancel.clone());
    let peer = tokio::spawn(async move {
        if let Ok(mut socket) = server.socket().await {
            while socket.next().await.is_some() {}
        }
    });
    let error = environment
        .connect_pool_wss(material, pool.store.clone(), options, cancel)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ConnectError::Pool(crate::PoolStoreError {
            code: crate::PoolStoreFailure::OwnerUnavailable,
            write_state: crate::PoolWriteState::Committed,
            format: None,
        })
    ));
    assert_eq!(pool.store.spend_observation(), Some(expected));
    assert_eq!(pool.rows(), 1);
    let facts = error.connection_facts();
    assert_eq!(facts.phase, crate::ConnectionPhase::SpentNotAdmitted);
    assert_eq!(facts.spend_state, crate::ConnectionSpendState::Spent);
    assert_eq!(
        facts.admission_state,
        crate::ConnectionAdmissionState::NotStarted
    );
    assert_eq!(
        facts.network_ready,
        crate::ConnectionNetworkReady::NotStarted
    );
    assert_eq!(
        facts.source_profile,
        Some(crate::ConnectionSourceProfile::PreauthorizedPool)
    );
    peer.await.unwrap();
    let _ = environment.close().await;
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
    // Full record geometry is reserved before native carrier preparation, so
    // capacity rejection must not even establish a credential-bearing socket.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server.listener.accept())
            .await
            .is_err()
    );
}

fn ordinary_pool_source(
    environment: &TransportEnvironment,
    material: PoolConnectionMaterial,
    store: Arc<crate::pool_v4::SQLitePoolStore>,
    provider: WssConnectOptions,
) -> crate::ConnectionMaterialSource {
    let PoolConnectionMaterial {
        admission,
        bytes,
        keys,
        namespaces,
        _charge,
        ..
    } = material;
    drop(admission);
    drop(_charge);
    crate::LocalDirectMaterialSource::preauthorized_pool(
        environment,
        crate::PreauthorizedPoolSourceConfiguration {
            namespaces,
            identity: keys,
            credentials: vec![bytes],
            spend_ledger: store,
            provider,
            application_profile: crate::ApplicationProfile::Transport,
        },
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_source_connect_and_acquired_material_share_original_native_pool_flow() {
    async fn phase<T>(
        profile: Profile,
        name: &str,
        future: std::pin::Pin<Box<impl std::future::Future<Output = T>>>,
    ) -> T {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap_or_else(|_| panic!("original source {profile:?}: {name} exceeded 10 seconds"))
    }
    for (profile, pin, acquire_before_close) in
        [(Profile::X25519, true, false), (Profile::P256, false, true)]
    {
        let Setup {
            environment,
            material,
            pool,
            options,
            server,
        } = setup(profile, pin, false).await;
        let mismatched = PoolCredentialBytes {
            artifact: material.bytes.artifact.clone(),
            client_certificate: material.bytes.client_certificate.clone(),
            server_certificate: material.bytes.server_certificate.clone(),
            activation: material.bytes.activation.clone(),
        };
        let wrong_identity = environment.identity_keys(profile.name()).unwrap();
        let source = ordinary_pool_source(&environment, material, pool.store.clone(), options);
        assert_eq!(
            source
                .replace_pool_generation(vec![mismatched], wrong_identity)
                .unwrap_err(),
            crate::MaterialSourceError::MaterialUnavailable
        );
        let unsupported = crate::ConnectionRequest {
            requirements: crate::ConnectionRequirements {
                independent_reliable_read_progress: true,
                ..crate::ConnectionRequirements::default()
            },
            ..crate::ConnectionRequest::default()
        };
        assert_eq!(
            source
                .acquire(&environment, &unsupported, &CancellationToken::new())
                .unwrap_err(),
            crate::MaterialSourceError::RequiredGuaranteeUnavailable
        );
        let wrong_profile = crate::ConnectionRequest {
            requirements: crate::ConnectionRequirements {
                application_profile: Some("execution".into()),
                ..crate::ConnectionRequirements::default()
            },
            ..crate::ConnectionRequest::default()
        };
        assert_eq!(
            source
                .acquire(&environment, &wrong_profile, &CancellationToken::new())
                .unwrap_err(),
            crate::MaterialSourceError::ConnectionRequirementUnavailable
        );
        assert_eq!(pool.rows(), 0);
        let foreign_environment = TransportEnvironment::default();
        let foreign_plan = foreign_environment
            .handler_plan(crate::HandlerPlanOptions {
                streams: crate::StreamDispatch::Manual,
                application_bytes: 65536,
            })
            .unwrap();
        let refusal = environment
            .connect(
                &source,
                crate::ConnectionRequest {
                    handlers: Some((
                        foreign_plan,
                        crate::ApplicationLimits {
                            ordinary_callbacks: 1,
                            ordinary_callback_bytes: 256,
                            control_callback_bytes: 256,
                        },
                    )),
                    ..crate::ConnectionRequest::default()
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            refusal,
            crate::ConnectionError::Connect(crate::TransportConnectError::Authorization)
        ));
        assert_eq!(pool.rows(), 0);
        let _ = foreign_environment.close().await;
        let request = crate::ConnectionRequest {
            requirements: crate::ConnectionRequirements {
                local_consumer_tls13_verification: true,
                ..crate::ConnectionRequirements::default()
            },
            ..crate::ConnectionRequest::default()
        };
        let (peer, client) = phase(
            profile,
            "handshake and Connect",
            Box::pin(async {
                if acquire_before_close {
                    let material = source
                        .acquire(&environment, &request, &CancellationToken::new())
                        .unwrap();
                    source.close();
                    assert_eq!(
                        source
                            .acquire(&environment, &request, &CancellationToken::new())
                            .unwrap_err(),
                        crate::MaterialSourceError::SourceUnavailable
                    );
                    tokio::join!(
                        server.handshake(),
                        environment.connect_material(material, CancellationToken::new())
                    )
                } else {
                    tokio::join!(
                        server.handshake(),
                        environment.connect(&source, request, CancellationToken::new())
                    )
                }
            }),
        )
        .await;
        let client = client.unwrap();
        assert_eq!(pool.rows(), 1);
        source.close();
        let (server, task) = peer_session(&environment, peer.0, peer.1);
        assert_eq!(
            source
                .acquire(
                    &environment,
                    &crate::ConnectionRequest::default(),
                    &CancellationToken::new()
                )
                .unwrap_err(),
            crate::MaterialSourceError::SourceUnavailable
        );
        let (opened, accepted) = phase(
            profile,
            "OPEN and accept",
            Box::pin(async {
                tokio::join!(
                    client.open_stream("example.source", Metadata::empty(), 65536),
                    async { server.next_open().await.unwrap().accept(65536).unwrap() }
                )
            }),
        )
        .await;
        let opened = opened.unwrap();
        phase(
            profile,
            "payload and dual FIN",
            Box::pin(async {
                opened
                    .write(Bytes::from_static(b"source-owned-pair"))
                    .await
                    .unwrap();
                assert_eq!(
                    accepted.read().await.unwrap().unwrap().as_ref(),
                    b"source-owned-pair"
                );
                opened.close_write().await.unwrap();
                assert!(accepted.read().await.unwrap().is_none());
                accepted.close_write().await.unwrap();
                assert!(opened.read().await.unwrap().is_none());
                let (first, second) = tokio::join!(opened.finish(), accepted.finish());
                first.unwrap();
                second.unwrap();
            }),
        )
        .await;
        client.probe_liveness(Duration::from_secs(1)).await.unwrap();
        client.close();
        server.close();
        phase(profile, "peer task exit", Box::pin(task))
            .await
            .unwrap();
        drop(source);
        let _ = phase(
            profile,
            "Environment cleanup",
            Box::pin(environment.close()),
        )
        .await;
    }
}

#[derive(Debug)]
struct NativeCandidateInitializer {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl crate::CandidateSessionInitializer for NativeCandidateInitializer {
    async fn initialize(
        &self,
        session: crate::Session,
        _: CancellationToken,
    ) -> std::result::Result<(), crate::MaterialControllerError> {
        assert!(session.termination_cause().is_none());
        self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        Ok(())
    }
}
fn native_controller_options(
    source: crate::ConnectionMaterialSource,
    ownership: crate::MaterialSourceOwnership,
    parent: CancellationToken,
    initialize_session: Option<Arc<dyn crate::CandidateSessionInitializer>>,
) -> crate::MaterialControllerOptions {
    crate::MaterialControllerOptions {
        sources: vec![crate::ControllerMaterialSource { source, ownership }],
        managed_services: Vec::new(),
        request: crate::ConnectionRequest::default(),
        parent,
        initialize_session,
        max_attempts_per_outage: 1,
        retry_after: Duration::from_millis(20),
        candidate_timeout: Duration::from_secs(3),
        retain_replaced_for: Duration::from_millis(10),
        drain_timeout: Duration::from_secs(1),
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn material_controller_publishes_only_initialized_native_ready_candidate() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::P256, false, false).await;
    let environment = Arc::new(environment);
    let source = ordinary_pool_source(&environment, material, pool.store.clone(), options);
    let initializer = Arc::new(NativeCandidateInitializer {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let parent = CancellationToken::new();
    let peer = tokio::spawn({
        let environment = environment.clone();
        async move {
            let peer = server.handshake().await;
            peer_session(&environment, peer.0, peer.1)
        }
    });
    let controller = crate::MaterialConnectionController::new(
        environment.clone(),
        native_controller_options(
            source.clone(),
            crate::MaterialSourceOwnership::Borrowed,
            parent,
            Some(initializer.clone()),
        ),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), initializer.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert_eq!(
        controller.progress().state,
        crate::MaterialControllerState::Initializing
    );
    assert!(controller.current().is_none());
    assert_eq!(
        controller.capture_session().unwrap_err(),
        crate::MaterialControllerError::NotReady
    );
    let facts = controller.progress().connection_facts.unwrap();
    assert_eq!(facts.network_ready, crate::ConnectionNetworkReady::Ready);
    assert_eq!(facts.spend_state, crate::ConnectionSpendState::Spent);
    assert_eq!(
        facts.application_publish,
        crate::ConnectionApplicationPublish::NotStarted
    );
    assert_eq!(pool.rows(), 1);
    let canceled = CancellationToken::new();
    canceled.cancel();
    assert_eq!(
        controller.wait_current(0, &canceled).await.unwrap_err(),
        crate::MaterialControllerError::Canceled
    );
    initializer.release.add_permits(1);
    let snapshot = tokio::time::timeout(
        Duration::from_secs(3),
        controller.wait_current(0, &CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(snapshot.generation, 1);
    assert_eq!(snapshot.source_index, 0);
    assert!(
        controller
            .capture_session()
            .unwrap()
            .same_original(&snapshot.session)
    );
    assert_eq!(
        controller
            .progress()
            .connection_facts
            .unwrap()
            .application_publish,
        crate::ConnectionApplicationPublish::Published
    );
    let refused = controller
        .replace_session_with_options(
            crate::MaterialSessionReplaceOptions {
                retirement: crate::MaterialSessionRetirement::Retain { retain_until_ms: 0 },
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refused,
        crate::MaterialControllerError::RetirementUnavailable
    );
    assert_eq!(controller.current().unwrap().generation, 1);
    assert_eq!(pool.rows(), 1);
    assert_eq!(
        initializer.calls.load(std::sync::atomic::Ordering::Acquire),
        1
    );
    let (server, task) = peer.await.unwrap();
    let (opened, accepted) = tokio::join!(
        snapshot
            .session
            .open_stream("example.controller", Metadata::empty(), 65536),
        async { server.next_open().await.unwrap().accept(65536).unwrap() }
    );
    let opened = opened.unwrap();
    opened
        .write(Bytes::from_static(b"captured-current"))
        .await
        .unwrap();
    assert_eq!(
        accepted.read().await.unwrap().unwrap().as_ref(),
        b"captured-current"
    );
    opened.close_write().await.unwrap();
    assert!(accepted.read().await.unwrap().is_none());
    accepted.close_write().await.unwrap();
    assert!(opened.read().await.unwrap().is_none());
    let (first, second) = tokio::join!(opened.finish(), accepted.finish());
    first.unwrap();
    second.unwrap();
    controller.close();
    assert!(!source.is_closed());
    server.close();
    task.await.unwrap();
    assert!(controller.wait_cleanup().await.complete);
    drop(snapshot);
    drop(controller);
    source.close();
    drop(source);
    drop(initializer);
    drop(pool);
    let _ = environment.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_parent_close_retains_actual_initializer_exit_and_closes_owned_source() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, false).await;
    let environment = Arc::new(environment);
    let source = ordinary_pool_source(&environment, material, pool.store.clone(), options);
    let initializer = Arc::new(NativeCandidateInitializer {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let parent = CancellationToken::new();
    let peer = tokio::spawn({
        let environment = environment.clone();
        async move {
            let peer = server.handshake().await;
            peer_session(&environment, peer.0, peer.1)
        }
    });
    let controller = crate::MaterialConnectionController::new(
        environment.clone(),
        native_controller_options(
            source.clone(),
            crate::MaterialSourceOwnership::Owned,
            parent.clone(),
            Some(initializer.clone()),
        ),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), initializer.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    parent.cancel();
    assert!(controller.current().is_none());
    assert!(!controller.cleanup_status().complete);
    initializer.release.add_permits(1);
    let (server, task) = peer.await.unwrap();
    server.close();
    task.await.unwrap();
    assert!(controller.wait_cleanup().await.complete);
    assert!(source.is_closed());
    assert_eq!(pool.rows(), 1);
    assert_eq!(
        initializer.calls.load(std::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(controller.progress().generation, 0);
    drop(controller);
    drop(initializer);
    drop(source);
    drop(pool);
    let _ = environment.close().await;
}

#[path = "connect_v4_live_tests.rs"]
mod live_authority;

#[path = "connect_v4_cleanup_tests.rs"]
mod cleanup_tests;

#[derive(Debug)]
struct ControllerNotificationLockOrderCodec {
    definition: MessageDefinition,
}
impl MessageCodec<u8> for ControllerNotificationLockOrderCodec {
    fn definition(&self) -> &MessageDefinition {
        &self.definition
    }
    fn encode(
        &self,
        value: &u8,
        destination: &mut [u8],
    ) -> std::result::Result<usize, crate::ServiceError> {
        destination[0] = *value;
        Ok(1)
    }
    fn decode(&self, source: &[u8]) -> std::result::Result<u8, crate::ServiceError> {
        Ok(source[0])
    }
}

fn controller_notification_lock_order_service(
    environment: &TransportEnvironment,
) -> (
    ServiceContract,
    ServiceDefinition,
    ServiceBindingOptions,
    NotificationServiceRegistration,
    Arc<ControllerNotificationLockOrderCodec>,
    FixedContractQuery,
) {
    let contract = ServiceContract::capture(
        environment,
        &encode_map(&[
            (0, t("example/lock-order")),
            (1, u(42)),
            (2, u(2)),
            (5, u(0)),
            (6, t("bytes.v1")),
            (7, t("none.v1")),
            (8, u(0)),
            (9, u(0)),
            (10, u(0)),
            (11, u(10000)),
            (21, vec![0xf4]),
            (23, u(128)),
            (27, vec![0x80]),
        ]),
    )
    .unwrap();
    let message = MessageDefinition::new([9; 32], "bytes.v1".into(), 128).unwrap();
    let method = MethodDefinition::new(MethodDefinitionOptions {
        type_id: 42,
        shape: ServiceShape::Notify,
        semantics: ServiceSemantics::Observation,
        request: message.clone(),
        response: None,
        response_revision: "none.v1".into(),
        request_max_bytes: 128,
        min_response_limit_bytes: 0,
        max_response_bytes: 0,
        require_durable: false,
        checkpoint_format: None,
        restart_flush_deadline_ms: None,
        streaming: None,
        content: None,
        errors: Vec::new(),
    })
    .unwrap();
    let definition = ServiceDefinition::new(
        "example/lock-order".into(),
        vec![ServiceMethod {
            name: "Observe".into(),
            export_name: "observe".into(),
            method: method.clone(),
        }],
    )
    .unwrap();
    let binding = ServiceBindingOptions {
        method,
        acceptance: ContractAcceptance::exact(),
        response_limit: ResponseLimitPolicy::FollowContractMaximum,
        execution_reference_identity: None,
        streaming: None,
        resume: None,
    };
    let registration = NotificationServiceRegistration {
        contract: contract.clone(),
        request: message.clone(),
        query_allowed: true,
        offer: None,
        execution: None,
        caller: None,
        handler: None,
    };
    let codec = Arc::new(ControllerNotificationLockOrderCodec {
        definition: message,
    });
    let query = FixedContractQuery {
        type_id: 1,
        contract_digest: [1; 32],
    };
    (contract, definition, binding, registration, codec, query)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_controller_notification_lock_order_three_way_regression() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup_with_application(Profile::P256, false, false, None, true).await;
    let environment = Arc::new(environment);
    let PoolConnectionMaterial {
        admission,
        bytes,
        keys,
        namespaces,
        _charge,
        ..
    } = material;
    drop(admission);
    drop(_charge);
    let source = crate::LocalDirectMaterialSource::preauthorized_pool(
        &environment,
        crate::PreauthorizedPoolSourceConfiguration {
            namespaces,
            identity: keys,
            credentials: vec![bytes],
            spend_ledger: pool.store.clone(),
            provider: options,
            application_profile: crate::ApplicationProfile::Execution,
        },
    )
    .unwrap();
    let (contract, _definition, _binding, registration, codec, query) =
        controller_notification_lock_order_service(&environment);
    let handler_plan = environment
        .handler_plan(crate::HandlerPlanOptions {
            streams: crate::StreamDispatch::Manual,
            application_bytes: 65536,
        })
        .unwrap()
        .with_services(crate::ServicePlan {
            query,
            unary: Vec::new(),
            notifications: vec![registration],
            streaming: Vec::new(),
            resume: Vec::new(),
            result_read: None,
            management: None,
        })
        .unwrap();
    let initializer = Arc::new(NativeCandidateInitializer {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let peer_task = tokio::spawn({
        let environment = environment.clone();
        async move {
            let peer = server.handshake().await;
            peer_session(&environment, peer.0, peer.1)
        }
    });
    let parent = CancellationToken::new();
    let mut controller_options = native_controller_options(
        source.clone(),
        crate::MaterialSourceOwnership::Borrowed,
        parent,
        Some(initializer.clone()),
    );
    controller_options.request.handlers = Some((
        handler_plan,
        crate::ApplicationLimits {
            ordinary_callbacks: 1,
            ordinary_callback_bytes: 65536,
            control_callback_bytes: 65536,
        },
    ));
    let controller =
        crate::MaterialConnectionController::new(environment.clone(), controller_options).unwrap();
    tokio::time::timeout(Duration::from_secs(5), initializer.entered.acquire())
        .await
        .unwrap_or_else(|error| {
            panic!(
                "candidate initializer: {error}; progress: {:?}",
                controller.progress()
            )
        })
        .unwrap()
        .forget();

    initializer.release.add_permits(1);
    let current = tokio::time::timeout(
        Duration::from_secs(3),
        controller.wait_current(0, &CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(current.generation, 1);

    for admit in [false, true] {
        let probe = crate::NotificationLockOrderProbe::new();
        let _probe_guard = crate::install_notification_lock_order_probe(probe.clone());
        let root = crate::new_test_notification_root(&controller, contract.clone(), codec.clone());
        let root_task = crate::start_test_notification_root(root.clone());
        probe.wait_entered(crate::NotificationLockOrderStage::LateAttachment);
        let old_root = root.clone();
        let old_input = tokio::task::spawn_blocking(move || {
            crate::exercise_test_old_input_rejection(&old_root, admit)
        });
        probe.wait_entered(crate::NotificationLockOrderStage::OldInputRejection);
        let publishing_root = root.clone();
        let publication = tokio::task::spawn_blocking(move || {
            crate::exercise_test_notification_publication(&publishing_root)
        });
        probe.wait_entered(crate::NotificationLockOrderStage::Publication);

        // Root state, callback entry and Controller state are now each held by
        // a different original path. Rejection must drop its entry gate before
        // recording the gap so publication and late attachment can both finish.
        probe.release(crate::NotificationLockOrderStage::OldInputRejection);
        probe.release(crate::NotificationLockOrderStage::Publication);
        probe.release(crate::NotificationLockOrderStage::LateAttachment);
        tokio::time::timeout(Duration::from_secs(2), async {
            old_input.await.unwrap();
            publication.await.unwrap();
            while !crate::test_notification_root_attached(&root) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(controller.current().unwrap().generation, 1);
        crate::close_test_notification_root(&root);
        tokio::time::timeout(Duration::from_secs(2), root_task)
            .await
            .unwrap()
            .unwrap();
    }

    controller.close();
    let (server, task) = peer_task.await.unwrap();
    server.close();
    task.await.unwrap();
    assert!(controller.wait_cleanup().await.complete);
    source.close();
    drop(source);
    drop(pool);
    let _ = environment.close().await;
}

#[path = "controller_public_lifecycle_v4_tests.rs"]
mod controller_public_lifecycle;
