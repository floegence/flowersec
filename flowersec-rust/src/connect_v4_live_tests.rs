//! The SDK uses actual TLS 1.3 mutual authentication for both authority calls
//! and its original WSS provider for Prepare and READY. The bounded authority
//! fixture signs only the original request and never supplies a Session owner.
use super::*;
use crate::{
    ControlHTTPSConfiguration, LiveAuthoritySourceConfiguration,
    codec_v4::tests::{array, encode_map, hex, sign},
    codec_v4::{self as codec, Context, Limits},
};
use http_body_util::{BodyExt, Full};
use ring::signature::Ed25519KeyPair;
use std::sync::atomic::AtomicUsize;
use zeroize::Zeroizing;

#[derive(Debug)]
struct AuthorityTime;
impl rustls::time_provider::TimeProvider for AuthorityTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(1),
        ))
    }
}
fn control_tls(port: u16) -> (Arc<rustls::ServerConfig>, ControlHTTPSConfiguration) {
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
    let leaf = |name: &str, purpose| {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.not_before = time::OffsetDateTime::UNIX_EPOCH;
        params.not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(100);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![purpose];
        (
            params.signed_by(&key, &issuer).unwrap(),
            key.serialize_der(),
        )
    };
    let (server, server_key) = leaf("example.com", ExtendedKeyUsagePurpose::ServerAuth);
    let (client, client_key) = leaf(
        "control-client.example",
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server.der().to_vec())],
            PrivatePkcs8KeyDer::from(server_key).into(),
        )
        .unwrap();
    tls.time_provider = Arc::new(AuthorityTime);
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    (
        Arc::new(tls),
        ControlHTTPSConfiguration {
            host: "example.com".into(),
            port,
            remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
            base_path: String::new(),
            roots_der: vec![ca.der().to_vec()],
            client_chain_der: vec![client.der().to_vec()],
            client_key_pkcs8: Zeroizing::new(client_key),
            timeout: Duration::from_secs(2),
            provider_runtime_bytes: 1 << 20,
        },
    )
}
fn corpus(id: &str) -> Vec<u8> {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
    hex(corpus["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["id"] == id)
        .unwrap()["hex"]
        .as_str()
        .unwrap())
}
fn replace_map(
    raw: &[u8],
    schema: &str,
    changes: &[(u64, Vec<u8>)],
    signer_seed: Option<u8>,
) -> Vec<u8> {
    let value = codec::decode(
        raw,
        schema,
        Limits {
            bytes: 65536,
            nodes: 16384,
        },
        None,
    )
    .unwrap();
    let mut children = value.children().unwrap();
    let mut fields = Vec::new();
    while let Some(id) = children.next() {
        let id = id.unwrap().uint().unwrap();
        let value = children.next().unwrap().unwrap();
        if signer_seed.is_some() && schema == "Artifact" && id == 27 {
            continue;
        }
        fields.push((
            id,
            changes
                .iter()
                .find(|(change, _)| *change == id)
                .map_or_else(|| value.raw().to_vec(), |(_, wire)| wire.clone()),
        ));
    }
    for (id, wire) in changes {
        if !fields.iter().any(|(existing, _)| existing == id) {
            fields.push((*id, wire.clone()));
        }
    }
    fields.sort_by_key(|(id, _)| *id);
    signer_seed.map_or_else(
        || encode_map(&fields),
        |seed| {
            sign(
                schema,
                &fields,
                &Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap(),
            )
        },
    )
}
fn tunnelize_live_fixture(mut fixture: Fixture) -> Fixture {
    let original_artifact = codec::decode(
        &fixture.artifact,
        "Artifact",
        Limits {
            bytes: 65536,
            nodes: 16384,
        },
        None,
    )
    .unwrap();
    let original_refs = original_artifact
        .field("Artifact", "candidates")
        .unwrap()
        .at(0)
        .unwrap()
        .field("Candidate", "revocation_namespace_refs")
        .unwrap()
        .raw()
        .to_vec();
    let candidate_seed = corpus("candidate_tunnel_fields");
    let candidate = replace_map(
        &candidate_seed,
        "Candidate",
        &[(0, b(&[20; 16])), (6, original_refs)],
        None,
    );
    fixture.artifact = replace_map(
        &fixture.artifact,
        "Artifact",
        &[(12, array(std::slice::from_ref(&candidate)))],
        Some(12),
    );
    let artifact = codec::decode(
        &fixture.artifact,
        "Artifact",
        Limits {
            bytes: 65536,
            nodes: 16384,
        },
        None,
    )
    .unwrap();
    let artifact_digest = codec::digest("artifact_digest", artifact).unwrap();
    let candidate_value = codec::decode(
        &candidate,
        "Candidate",
        Limits {
            bytes: 65536,
            nodes: 16384,
        },
        None,
    )
    .unwrap();
    let route = crate::namespace_v4::verifier::credential::relay_public::preparation_route_digest(
        &candidate,
    )
    .unwrap();
    fixture.activation = sign(
        "ActivationAuthorization",
        &[
            (0, u(1)),
            (1, t("spend")),
            (2, t("activate-1")),
            (3, t("tenant")),
            (4, b(&[5; 16])),
            (5, b(&[22; 16])),
            (6, b(&artifact_digest)),
            (7, b(&[20; 16])),
            (8, b(&route)),
            (9, b(&[25; 16])),
            (
                10,
                b(&artifact
                    .b::<32>("Artifact", "client_identity_digest")
                    .unwrap()),
            ),
            (
                11,
                b(&artifact
                    .b::<32>("Artifact", "server_identity_digest")
                    .unwrap()),
            ),
            (12, t("service")),
            (13, u(950)),
            (14, u(10_000)),
            (15, u(30_000)),
        ],
        &Ed25519KeyPair::from_seed_unchecked(&[13; 32]).unwrap(),
    );
    assert_eq!(candidate_value.u("Candidate", "path_kind").unwrap(), 1);
    fixture
}

fn activation_for_attempt(original: &[u8], attempt: [u8; 16]) -> Vec<u8> {
    let document = codec::decode_context(
        original,
        "ActivationAuthorization",
        codec::Limits {
            bytes: 4096,
            nodes: 256,
        },
        None,
        Context::with_activation_source(ActivationSource::LiveAuthority),
    )
    .unwrap();
    let mut children = document.children().unwrap();
    let mut fields = Vec::new();
    while let Some(id) = children.next() {
        let id = id.unwrap().uint().unwrap();
        let value = children.next().unwrap().unwrap();
        if id == 16 {
            continue;
        }
        fields.push((
            id,
            if id == 9 {
                b(&attempt)
            } else {
                value.raw().to_vec()
            },
        ));
    }
    sign(
        "ActivationAuthorization",
        &fields,
        &Ed25519KeyPair::from_seed_unchecked(&[13; 32]).unwrap(),
    )
}
struct LiveAuthority {
    environment: Arc<TransportEnvironment>,
    namespace: Arc<Namespace>,
    artifact: Vec<u8>,
    client: Vec<u8>,
    server: Vec<u8>,
    original_activation: Vec<u8>,
    prepared: Arc<AtomicBool>,
    txa: AtomicUsize,
    txb: AtomicUsize,
    admission: Mutex<Option<oneshot::Sender<CredentialAdmission>>>,
    publication: Mutex<Option<serve::OriginalLiveServerPublication>>,
    lose_confirmation: bool,
}
impl LiveAuthority {
    fn authorize(&self, request: &[u8]) -> Vec<u8> {
        assert!(
            self.prepared.load(Ordering::Acquire),
            "TxB must follow the original native Prepare"
        );
        assert_eq!(
            self.txb.fetch_add(1, Ordering::AcqRel),
            0,
            "one original TxB only"
        );
        let artifact = decode(&self.artifact, "Artifact", 65536, Context::default()).unwrap();
        let mut prefix = vec![0x8d];
        for text in [
            "live-authorization-1",
            "tenant",
            "service",
            artifact
                .field("Artifact", "crypto_profile_id")
                .unwrap()
                .text()
                .unwrap(),
        ] {
            prefix.extend_from_slice(&t(text));
        }
        prefix.extend_from_slice(&b(&artifact.b::<16>("Artifact", "issuer_key_id").unwrap()));
        prefix.extend_from_slice(&b(&artifact.b::<16>("Artifact", "lease_id").unwrap()));
        assert!(request.starts_with(&prefix));
        assert_eq!(request.get(prefix.len()), Some(&0x50));
        let attempt: [u8; 16] = request[prefix.len() + 1..prefix.len() + 17]
            .try_into()
            .unwrap();
        assert_ne!(attempt, [0; 16]);
        let activation = activation_for_attempt(&self.original_activation, attempt);
        let verifier = self.namespace.verifier.lock().unwrap();
        let admission = self
            .environment
            .reserve_direct_credentials(
                &[&*verifier],
                crate::namespace_v4::verifier::credential::DirectCredentialInput {
                    artifact: &self.artifact,
                    client_certificate: &self.client,
                    server_certificate: &self.server,
                    activation: &activation,
                    source: ActivationSource::LiveAuthority,
                    candidate_index: 0,
                },
            )
            .unwrap();
        drop(verifier);
        // Compare the entire canonical request, including the selected route,
        // original identities, account deadline and winner ordinal.
        let mut expected = prefix;
        for bytes in [
            attempt.as_slice(),
            admission.artifact_digest.as_slice(),
            admission.certificate_digests[0].as_slice(),
            admission.certificate_digests[1].as_slice(),
        ] {
            expected.extend_from_slice(&b(bytes));
        }
        expected.push(0x83);
        expected.extend_from_slice(&u(0));
        expected.extend_from_slice(&b(&admission.candidate_id));
        expected.extend_from_slice(&b(&admission.route_digest));
        let artifact = crate::codec_v4::decode(
            &self.artifact,
            "Artifact",
            crate::codec_v4::Limits {
                bytes: 65536,
                nodes: 16384,
            },
            None,
        )
        .unwrap();
        expected.extend_from_slice(&u(artifact
            .u("Artifact", "initiation_not_after_ms")
            .unwrap()));
        expected.extend_from_slice(&u(1));
        assert_eq!(request, expected);
        if let Some(publication) = self.publication.lock().unwrap().take() {
            publication
                .publish_original(activation.clone(), &CancellationToken::new())
                .unwrap();
        }
        if let Some(sender) = self.admission.lock().unwrap().take() {
            sender.send(admission).unwrap();
        }
        activation
    }
    async fn reply(
        &self,
        request: http::Request<hyper::body::Incoming>,
    ) -> std::io::Result<http::Response<Full<Bytes>>> {
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.headers()[http::header::CONTENT_TYPE],
            "application/cbor"
        );
        let path = request.uri().path().to_owned();
        let mut body = request.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let data = frame.unwrap().into_data().unwrap();
            assert!(bytes.len() + data.len() <= 1024);
            bytes.extend_from_slice(&data);
        }
        let response = match path.as_str() {
            "/issue/direct" => {
                assert_eq!(self.txa.fetch_add(1, Ordering::AcqRel), 0);
                assert_eq!(bytes.len(), 35);
                assert_eq!(&bytes[..3], &[0x81, 0x58, 0x20]);
                self.artifact.clone()
            }
            "/live/authorize" => {
                let proof = self.authorize(&bytes);
                if self.lose_confirmation {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "original TxB confirmation lost",
                    ));
                }
                proof
            }
            _ => panic!("unexpected authority path"),
        };
        Ok(http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/cbor")
            .header(http::header::CONTENT_LENGTH, response.len().to_string())
            .header(http::header::CONNECTION, "close")
            .body(Full::new(Bytes::from(response)))
            .unwrap())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_live_mtls_txa_prepare_txb_native_ready_and_lost_confirmation() {
    async fn within_phase<T>(
        case: &str,
        phase: &str,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = T> + '_>>,
    ) -> T {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap_or_else(|_| panic!("{case}: {phase} exceeded 10 seconds"))
    }

    for (profile, lose_confirmation, replace_generation) in [
        (Profile::X25519, false, false),
        (Profile::P256, false, false),
        (Profile::X25519, true, false),
        (Profile::X25519, false, true),
    ] {
        let case = format!(
            "original-live profile={} lose_confirmation={lose_confirmation} replace_generation={replace_generation}",
            profile.name()
        );
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let (tls, wss_ca, _) = tls_identity();
        let server_keys = LocalKeys::generate(profile).unwrap();
        let ed = server_keys.ed_public();
        let mut fixture = Fixture::with_identity(
            ActivationSource::LiveAuthority,
            profile.name(),
            Some([
                (server_keys.dh_public(), &ed),
                (server_keys.dh_public(), &ed),
            ]),
        );
        let keys = fixture.environment.identity_keys(profile.name()).unwrap();
        fixture.set_client_keys(&keys);
        fixture.set_wss_route(listener.local_addr().unwrap().port(), None);
        let placeholder = fixture.reserve().unwrap();
        let namespace = Arc::new(Namespace::new(fixture.verifier));
        let environment = Arc::new(fixture.environment);
        let control_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let (control_tls, control) = control_tls(control_listener.local_addr().unwrap().port());
        let prepared = Arc::new(AtomicBool::new(false));
        let (admission, accepted) = oneshot::channel();
        let authority = Arc::new(LiveAuthority {
            environment: environment.clone(),
            namespace: namespace.clone(),
            artifact: fixture.artifact.clone(),
            client: fixture.client.clone(),
            server: fixture.server.clone(),
            original_activation: fixture.activation,
            prepared: prepared.clone(),
            txa: AtomicUsize::new(0),
            txb: AtomicUsize::new(0),
            admission: Mutex::new(Some(admission)),
            publication: Mutex::new(None),
            lose_confirmation,
        });
        let authority_task = {
            let authority = authority.clone();
            tokio::spawn(async move {
                // The SDK makes exactly two independent fixed mTLS calls.
                for _ in 0..2 {
                    let (tcp, _) = control_listener.accept().await.unwrap();
                    let tls = tokio_rustls::TlsAcceptor::from(control_tls.clone())
                        .accept(tcp)
                        .await
                        .unwrap();
                    assert!(
                        tls.get_ref()
                            .1
                            .peer_certificates()
                            .is_some_and(|chain| !chain.is_empty())
                    );
                    assert_eq!(
                        tls.get_ref().1.protocol_version(),
                        Some(rustls::ProtocolVersion::TLSv1_3)
                    );
                    let original = authority.clone();
                    let service = hyper::service::service_fn(move |request| {
                        let original = original.clone();
                        async move { original.reply(request).await }
                    });
                    let result = hyper::server::conn::http1::Builder::new()
                        .max_buf_size(16384)
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                    if !authority.lose_confirmation || authority.txb.load(Ordering::Acquire) == 0 {
                        result.unwrap();
                    }
                }
            })
        };
        let peer = Peer {
            listener,
            tls,
            admission: placeholder,
            keys: server_keys,
            artifact: fixture.artifact,
            certificate: fixture.server.clone(),
        };
        let peer_task = tokio::spawn(async move {
            let socket = peer.socket().await.unwrap();
            prepared.store(true, Ordering::Release);
            let mut peer = peer;
            peer.admission = accepted.await.unwrap();
            if lose_confirmation {
                let mut socket = socket;
                let next = socket.next().await;
                assert!(
                    matches!(next, None | Some(Err(_)) | Some(Ok(Message::Close(_)))),
                    "no HELLO may follow an unknown TxB"
                );
                None
            } else {
                Some(peer.handshake_socket(socket).await)
            }
        });
        let configuration = || LiveAuthoritySourceConfiguration {
            namespaces: vec![namespace.clone()],
            identity: keys.clone(),
            client_certificate: fixture.client.clone(),
            server_certificate: fixture.server.clone(),
            artifact_issuer_key_id: [5; 16],
            activation_signing_key_id: "activate-1".into(),
            issuance: control.clone(),
            activation: control.clone(),
            carrier: crate::LiveAuthorityCarrier::WebSocket,
            provider: WssConnectOptions {
                ca_certificates_der: vec![wss_ca.clone()],
                remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                binding_mode: BindingMode::AuthenticatedContext,
                origin: None,
                timeout: Duration::from_secs(3),
                publication_timeout: Duration::from_secs(2),
                queue_messages: 2,
                prepare_bytes: 65536,
                native_runtime_bytes: 1 << 20,
            },
            application_profile: crate::ApplicationProfile::Transport,
        };
        let mut initial = configuration();
        if replace_generation {
            initial.issuance.base_path = "/unpublished-generation".into();
        }
        let source =
            crate::LocalDirectMaterialSource::live_authority(&environment, initial).unwrap();
        if replace_generation {
            source.replace_live_generation(configuration()).unwrap();
            let mut invalid = configuration();
            invalid.activation_signing_key_id.clear();
            assert!(source.replace_live_generation(invalid).is_err());
        }
        let unsupported = crate::ConnectionRequest {
            requirements: crate::ConnectionRequirements {
                independent_reliable_read_progress: true,
                ..crate::ConnectionRequirements::default()
            },
            handlers: None,
        };
        assert!(matches!(
            source
                .acquire_async(&environment, &unsupported, &CancellationToken::new())
                .await,
            Err(crate::MaterialSourceError::RequiredGuaranteeUnavailable)
        ));
        assert_eq!(
            authority.txa.load(Ordering::Acquire),
            0,
            "unavailable guarantees must not issue an Artifact"
        );
        assert_eq!(authority.txb.load(Ordering::Acquire), 0);
        let result = within_phase(
            &case,
            "connect",
            Box::pin(async {
                if replace_generation {
                    let material = source
                        .acquire_async(
                            &environment,
                            &crate::ConnectionRequest::default(),
                            &CancellationToken::new(),
                        )
                        .await
                        .unwrap();
                    let mut replacement = configuration();
                    replacement.activation.base_path = "/next-generation".into();
                    source.replace_live_generation(replacement).unwrap();
                    // TxB belongs to the already acquired generation. The authority
                    // accepts only the original path and sees one issuance/activation.
                    environment
                        .connect_material(material, CancellationToken::new())
                        .await
                } else {
                    environment
                        .connect(
                            &source,
                            crate::ConnectionRequest::default(),
                            CancellationToken::new(),
                        )
                        .await
                }
            }),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(10), authority_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authority.txa.load(Ordering::Acquire), 1);
        assert_eq!(authority.txb.load(Ordering::Acquire), 1);
        if lose_confirmation {
            assert!(matches!(
                result,
                Err(crate::ConnectionError::Connect(
                    ConnectError::LiveAuthorizationUnknown
                ))
            ));
            assert!(
                tokio::time::timeout(Duration::from_secs(5), peer_task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_none()
            );
        } else {
            let client = result.unwrap();
            let (socket, engine) = tokio::time::timeout(Duration::from_secs(5), peer_task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let (server, pump) = peer_session(&environment, socket, engine);
            let (stream, incoming) = within_phase(
                &case,
                "OPEN",
                Box::pin(async {
                    tokio::join!(
                        client.open_stream("example.original-live", Metadata::empty(), 65536),
                        async { server.next_open().await.unwrap().accept(65536).unwrap() }
                    )
                }),
            )
            .await;
            let stream = stream.unwrap();
            within_phase(
                &case,
                "transfer+FIN",
                Box::pin(async {
                    stream
                        .write(Bytes::from_static(b"original-live-ready"))
                        .await
                        .unwrap();
                    assert_eq!(
                        incoming.read().await.unwrap().unwrap().as_ref(),
                        b"original-live-ready"
                    );
                    stream.close_write().await.unwrap();
                    assert!(incoming.read().await.unwrap().is_none());
                    incoming.close_write().await.unwrap();
                    assert!(stream.read().await.unwrap().is_none());
                }),
            )
            .await;
            let (sent, received) = within_phase(
                &case,
                "finish",
                Box::pin(async { tokio::join!(stream.finish(), incoming.finish()) }),
            )
            .await;
            sent.unwrap();
            received.unwrap();
            client.close();
            server.close();
            within_phase(&case, "pump", Box::pin(pump)).await.unwrap();
        }
        source.close();
        drop(source);
        drop(authority);
        let _ = within_phase(&case, "environment cleanup", Box::pin(environment.close())).await;
    }
}

#[derive(Debug)]
struct LiveServeCallbacks {
    plan: serve::HandlerPlan,
    prepared: Arc<AtomicBool>,
}
#[derive(Debug)]
struct LiveServeLease;
#[async_trait::async_trait]
impl serve::ApplicationAuthorizationLease for LiveServeLease {
    fn close(&self) {}
    async fn wait_cleanup(
        &self,
    ) -> std::result::Result<crate::api_v4::CleanupStatus, serve::ServeError> {
        Ok(crate::api_v4::CleanupStatus {
            complete: true,
            cleanup_incomplete: false,
            pending_callbacks: 0,
        })
    }
}
#[async_trait::async_trait]
impl serve::ServeCallbacks for LiveServeCallbacks {
    async fn authorize_request(
        &self,
        _: serve::ServeRequestContext,
    ) -> std::result::Result<serve::RequestAuthorization, serve::ServeError> {
        self.prepared.store(true, Ordering::Release);
        Ok(serve::RequestAuthorization { allowed: true })
    }
    async fn resolve_handlers(
        &self,
        _: serve::AuthenticatedRequestContext,
    ) -> std::result::Result<serve::HandlerPlan, serve::ServeError> {
        Ok(self.plan.clone())
    }
    async fn authorize_application(
        &self,
        context: serve::AuthenticatedRequestContext,
        handlers: serve::HandlerPlan,
    ) -> std::result::Result<serve::AuthorizeApplicationResult, serve::ServeError> {
        context.reserve_lease(context.binding(), Arc::new(LiveServeLease))?;
        Ok(serve::AuthorizeApplicationResult::Authorized { handlers })
    }
    async fn on_session(
        &self,
        _: Session,
        _: serve::AuthenticatedRequestContext,
    ) -> std::result::Result<serve::SessionAcceptance, serve::ServeError> {
        Ok(serve::SessionAcceptance::Queue)
    }
    async fn release(
        &self,
        _: serve::ServeReleaseContext,
    ) -> std::result::Result<crate::api_v4::CleanupStatus, serve::ServeError> {
        Ok(crate::api_v4::CleanupStatus {
            complete: true,
            cleanup_incomplete: false,
            pending_callbacks: 0,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_original_mtls_publication_enters_production_serve_admission_and_dual_ready() {
    use crate::pool_v4::{
        admission::{SQLiteAdmissionAuthority, SQLiteAdmissionBinding},
        tests::StoreFixture,
    };
    for (profile, lose_confirmation) in [
        (Profile::X25519, false),
        (Profile::P256, false),
        (Profile::X25519, true),
    ] {
        let generated = LocalKeys::generate(profile).unwrap();
        let public = generated.ed_public();
        let mut fixture = Fixture::with_identity(
            ActivationSource::LiveAuthority,
            profile.name(),
            Some([
                (generated.dh_public(), &public),
                (generated.dh_public(), &public),
            ]),
        );
        let client_keys = fixture.environment.identity_keys(profile.name()).unwrap();
        let server_keys = fixture.environment.identity_keys(profile.name()).unwrap();
        fixture.set_client_keys(&client_keys);
        fixture.set_server_keys(&server_keys);
        let local = StoreFixture::with_authority(&fixture, Some("accept.example"));
        let parent = StoreFixture::with_authority(&fixture, Some("live-winner.example"));
        let provisioning = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = provisioning.local_addr().unwrap();
        drop(provisioning);
        fixture.set_wss_route(address.port(), None);
        let facts = fixture.reserve().unwrap();
        let admission = SQLiteAdmissionAuthority::new(
            local.store.clone(),
            parent.store.clone(),
            vec![SQLiteAdmissionBinding {
                tenant: "tenant".into(),
                issuer: [5; 16],
                server_identity_digest: facts.certificate_digests[1],
                audience: "service".into(),
            }],
        )
        .unwrap();
        drop(facts);
        let namespace = Arc::new(Namespace::new(fixture.verifier));
        let environment = Arc::new(fixture.environment);
        let server_source = environment
            .live_accepted_material_source(vec![namespace.clone()], server_keys.clone(), 2)
            .unwrap();
        let publication = server_source
            .register_original(PoolCredentialBytes {
                artifact: fixture.artifact.clone(),
                client_certificate: fixture.client.clone(),
                server_certificate: fixture.server.clone(),
                activation: Vec::new(),
            })
            .unwrap();
        let prepared = Arc::new(AtomicBool::new(false));
        let (identity, wss_ca, _) = tls_provisioning();
        let handle = environment
            .serve_wss(
                vec![namespace.clone()],
                server_keys,
                server_source.clone(),
                admission,
                identity,
                serve::WssServeOptions {
                    callbacks: Arc::new(LiveServeCallbacks {
                        prepared: prepared.clone(),
                        plan: environment
                            .handler_plan(serve::HandlerPlanOptions {
                                streams: serve::StreamDispatch::Manual,
                                application_bytes: 4096,
                            })
                            .unwrap(),
                    }),
                    application_limits: serve::ApplicationLimits {
                        ordinary_callbacks: 4,
                        ordinary_callback_bytes: 32768,
                        control_callback_bytes: 32768,
                    },
                    cancellation: CancellationToken::new(),
                    binding_mode: BindingMode::AuthenticatedContext,
                    listen_address: address,
                    host: "example.com".into(),
                    origin: None,
                    max_connections: 2,
                    max_frame_bytes: 65536,
                    handshake_timeout: Duration::from_secs(5),
                    publication_timeout: Duration::from_secs(2),
                    queue_messages: 2,
                    prepare_bytes: 65536,
                    native_runtime_bytes: 1 << 20,
                },
            )
            .await
            .unwrap();
        let control_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let (control_tls, control) = control_tls(control_listener.local_addr().unwrap().port());
        let authority = Arc::new(LiveAuthority {
            environment: environment.clone(),
            namespace: namespace.clone(),
            artifact: fixture.artifact.clone(),
            client: fixture.client.clone(),
            server: fixture.server.clone(),
            original_activation: fixture.activation,
            prepared,
            txa: AtomicUsize::new(0),
            txb: AtomicUsize::new(0),
            admission: Mutex::new(None),
            publication: Mutex::new(Some(publication)),
            lose_confirmation,
        });
        let authority_task = {
            let authority = authority.clone();
            tokio::spawn(async move {
                for _ in 0..2 {
                    let (tcp, _) = control_listener.accept().await.unwrap();
                    let tls = tokio_rustls::TlsAcceptor::from(control_tls.clone())
                        .accept(tcp)
                        .await
                        .unwrap();
                    assert!(
                        tls.get_ref()
                            .1
                            .peer_certificates()
                            .is_some_and(|chain| !chain.is_empty())
                    );
                    assert_eq!(
                        tls.get_ref().1.protocol_version(),
                        Some(rustls::ProtocolVersion::TLSv1_3)
                    );
                    let original = authority.clone();
                    let service = hyper::service::service_fn(move |request| {
                        let original = original.clone();
                        async move { original.reply(request).await }
                    });
                    let result = hyper::server::conn::http1::Builder::new()
                        .max_buf_size(16384)
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                    if !authority.lose_confirmation || authority.txb.load(Ordering::Acquire) == 0 {
                        result.unwrap();
                    }
                }
            })
        };
        let source = crate::LocalDirectMaterialSource::live_authority(
            &environment,
            LiveAuthoritySourceConfiguration {
                namespaces: vec![namespace],
                identity: client_keys,
                client_certificate: fixture.client,
                server_certificate: fixture.server,
                artifact_issuer_key_id: [5; 16],
                activation_signing_key_id: "activate-1".into(),
                issuance: control.clone(),
                activation: control,
                carrier: crate::LiveAuthorityCarrier::WebSocket,
                provider: WssConnectOptions {
                    ca_certificates_der: vec![wss_ca],
                    remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                    binding_mode: BindingMode::AuthenticatedContext,
                    origin: None,
                    timeout: Duration::from_secs(3),
                    publication_timeout: Duration::from_secs(2),
                    queue_messages: 2,
                    prepare_bytes: 65536,
                    native_runtime_bytes: 1 << 20,
                },
                application_profile: crate::ApplicationProfile::Transport,
            },
        )
        .unwrap();
        let connected = environment
            .connect(
                &source,
                crate::ConnectionRequest::default(),
                CancellationToken::new(),
            )
            .await;
        tokio::time::timeout(Duration::from_secs(10), authority_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authority.txa.load(Ordering::Acquire), 1);
        assert_eq!(authority.txb.load(Ordering::Acquire), 1);
        if lose_confirmation {
            assert!(matches!(
                connected,
                Err(crate::ConnectionError::Connect(
                    ConnectError::LiveAuthorizationUnknown
                ))
            ));
            assert!(
                tokio::time::timeout(Duration::from_millis(50), handle.accept())
                    .await
                    .is_err()
            );
            assert_eq!(local.admitted_count(), 0);
            assert_eq!(parent.winner_count(), 0);
        } else {
            let client = connected.unwrap();
            let server = tokio::time::timeout(Duration::from_secs(2), handle.accept())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                client
                    .probe_liveness(Duration::from_secs(2))
                    .await
                    .unwrap()
                    .outcome,
                ProbeOutcome::Responsive
            );
            let (outgoing, incoming) = tokio::join!(
                client.open_stream("terminal/live_v1", Metadata::empty(), 32768),
                async { server.next_open().await.unwrap().accept(32768).unwrap() }
            );
            let outgoing = outgoing.unwrap();
            outgoing
                .write(Bytes::from_static(b"original live production READY"))
                .await
                .unwrap();
            assert_eq!(
                incoming.read().await.unwrap().unwrap().as_ref(),
                b"original live production READY"
            );
            assert_eq!(local.admitted_count(), 1);
            assert_eq!(parent.winner_count(), 1);
            assert!(
                server_source
                    .register_original(PoolCredentialBytes {
                        artifact: authority.artifact.clone(),
                        client_certificate: authority.client.clone(),
                        server_certificate: authority.server.clone(),
                        activation: Vec::new(),
                    })
                    .is_err(),
                "an original publication cannot be reconstructed for the consumed lease"
            );
            outgoing.close().await.unwrap();
            incoming.close().await.unwrap();
            client.close();
            server.close();
        }
        source.close();
        server_source.close();
        handle.close();
        assert!(
            tokio::time::timeout(Duration::from_secs(10), handle.wait_cleanup())
                .await
                .unwrap()
                .unwrap()
                .complete
        );
        environment.close().await.unwrap();
        local.store.close();
        parent.store.close();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_live_server_delivery_registers_publishes_once_and_cleans_up() {
    original_delivery_public_lifecycle(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_live_server_delivery_consumes_invalid_publication_without_reopening() {
    original_delivery_public_lifecycle(true).await;
}

async fn original_delivery_public_lifecycle(invalid_proof: bool) {
    use sha2::{Digest, Sha256};

    let generated = LocalKeys::generate(Profile::X25519).unwrap();
    let public = generated.ed_public();
    let fixture = Fixture::with_identity(
        ActivationSource::LiveAuthority,
        Profile::X25519.name(),
        Some([
            (generated.dh_public(), &public),
            (generated.dh_public(), &public),
        ]),
    );
    let server_keys = fixture
        .environment
        .identity_keys(Profile::X25519.name())
        .unwrap();
    let mut fixture = fixture;
    fixture.set_server_keys(&server_keys);
    let namespace = Arc::new(Namespace::new(fixture.verifier));
    let environment = Arc::new(fixture.environment);
    let server_source = environment
        .live_accepted_material_source(vec![namespace.clone()], server_keys, 2)
        .unwrap();

    let (identity, delivery_ca, _) = tls_provisioning();
    let (_, authority_control) = control_tls(1);
    let (_, unregistered_authority) = control_tls(1);
    let authority_leaf_digest: [u8; 32] =
        Sha256::digest(&authority_control.client_chain_der[0]).into();
    let delivery_listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let delivery_address = delivery_listener.local_addr().unwrap();
    let options = crate::LiveServerDeliveryOptions {
        listen_address: delivery_address,
        authority: format!("example.com:{}", delivery_address.port()),
        client_roots_der: [
            authority_control.roots_der.clone(),
            unregistered_authority.roots_der.clone(),
        ]
        .concat(),
        authority_leaf_digests: vec![authority_leaf_digest],
        maximum_connections: 1,
        timeout: Duration::from_secs(3),
        provider_runtime_bytes: 1 << 20,
        cancellation: CancellationToken::new(),
    };
    drop(delivery_listener);
    let handle = server_source
        .serve_original_delivery(identity, options)
        .await
        .unwrap();

    let authority_configuration = ControlHTTPSConfiguration {
        host: "example.com".into(),
        port: handle.local_address().port(),
        remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
        base_path: String::new(),
        roots_der: vec![delivery_ca],
        client_chain_der: authority_control.client_chain_der,
        client_key_pkcs8: authority_control.client_key_pkcs8,
        timeout: Duration::from_secs(2),
        provider_runtime_bytes: 1 << 20,
    };
    assert!(matches!(
        environment.original_live_server_delivery(ControlHTTPSConfiguration {
            base_path: "/relocated".into(),
            ..authority_configuration.clone()
        }),
        Err(crate::ControlHTTPSFailure::Configuration)
    ));
    let unknown_authority = environment
        .original_live_server_delivery(ControlHTTPSConfiguration {
            client_chain_der: unregistered_authority.client_chain_der,
            client_key_pkcs8: unregistered_authority.client_key_pkcs8,
            ..authority_configuration.clone()
        })
        .unwrap();
    let delivery = environment
        .original_live_server_delivery(authority_configuration)
        .unwrap();
    let cancellation = CancellationToken::new();
    let bytes = PoolCredentialBytes {
        artifact: fixture.artifact.clone(),
        client_certificate: fixture.client.clone(),
        server_certificate: fixture.server.clone(),
        activation: Vec::new(),
    };
    let original_bytes = || PoolCredentialBytes {
        artifact: bytes.artifact.clone(),
        client_certificate: bytes.client_certificate.clone(),
        server_certificate: bytes.server_certificate.clone(),
        activation: Vec::new(),
    };
    assert!(
        unknown_authority
            .register_original(original_bytes(), &cancellation)
            .await
            .is_err()
    );
    let canceled = CancellationToken::new();
    canceled.cancel();
    assert!(matches!(
        delivery
            .register_original(original_bytes(), &canceled)
            .await,
        Err(crate::ControlHTTPSFailure::Canceled)
    ));
    assert!(matches!(
        handle
            .next_tunnel_publication(Duration::ZERO, &cancellation)
            .await,
        Err(ConnectError::Configuration)
    ));
    assert!(matches!(
        handle
            .next_tunnel_publication(Duration::from_secs(1), &canceled)
            .await,
        Err(ConnectError::Canceled)
    ));
    assert!(matches!(
        handle
            .next_tunnel_publication(Duration::from_millis(10), &cancellation)
            .await,
        Err(ConnectError::Deadline)
    ));
    let waiting = CancellationToken::new();
    let mut pending = Box::pin(handle.next_tunnel_publication(Duration::from_secs(2), &waiting));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    assert!(matches!(
        handle
            .next_tunnel_publication(Duration::from_secs(1), &cancellation)
            .await,
        Err(ConnectError::Capacity)
    ));
    waiting.cancel();
    assert!(matches!(pending.await, Err(ConnectError::Canceled)));
    let publication = delivery
        .register_original(
            PoolCredentialBytes {
                artifact: bytes.artifact.clone(),
                client_certificate: bytes.client_certificate.clone(),
                server_certificate: bytes.server_certificate.clone(),
                activation: Vec::new(),
            },
            &cancellation,
        )
        .await
        .unwrap();
    let mut proof = fixture.activation.clone();
    if invalid_proof {
        *proof.last_mut().unwrap() ^= 1;
        assert!(
            publication
                .publish_original(proof, &cancellation)
                .await
                .is_err()
        );
    } else {
        publication
            .publish_original(proof, &cancellation)
            .await
            .unwrap();
    }
    assert!(
        delivery
            .register_original(bytes, &cancellation)
            .await
            .is_err()
    );

    let mut pending =
        Box::pin(handle.next_tunnel_publication(Duration::from_secs(2), &cancellation));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    handle.close();
    assert!(matches!(pending.await, Err(ConnectError::Canceled)));
    assert!(
        tokio::time::timeout(Duration::from_secs(5), handle.wait_cleanup())
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    server_source.close();
    environment.close().await.unwrap();
}

fn authorize_original_relay(namespace: &Namespace, server_certificate: &[u8]) -> Vec<u8> {
    fn decode<'a>(raw: &'a [u8], schema: &str) -> codec::Value<'a> {
        codec::decode(
            raw,
            schema,
            Limits {
                bytes: 65536,
                nodes: 16384,
            },
            Some(codec::StateLimits {
                bytes: 8192,
                issuers: 16,
                certificates: 16,
                leases: 16,
                segments: 16,
            }),
        )
        .unwrap()
    }
    let capacity = encode_map(&[
        (0, t("tenant")),
        (1, t("authority")),
        (2, t("capacity-1")),
        (3, u(8192)),
        (4, u(16)),
        (5, u(16)),
        (6, u(16)),
        (7, u(16)),
        (8, u(795)),
        (9, u(1 << 20)),
        (10, u(1024)),
        (11, u(0)),
        (12, u(100)),
        (13, u(100_000)),
        (14, u(100_000)),
    ]);
    let cap = codec::digest(
        "namespace_capacity_digest",
        decode(&capacity, "NamespaceCapacity"),
    )
    .unwrap();
    let original = decode(server_certificate, "IdentityCertificate");
    assert_eq!(
        cap,
        original
            .b::<32>("IdentityCertificate", "namespace_capacity_digest")
            .unwrap()
    );
    let issuer = Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap();
    let permission = encode_map(&[
        (0, b(&[13; 16])),
        (1, t("tenant")),
        (2, t("authority")),
        (3, b(&cap)),
        (4, u(1)),
        (5, u(0)),
        (6, b(&[4; 16])),
        (7, b(ring::signature::KeyPair::public_key(&issuer).as_ref())),
        (8, t("service")),
        (9, u(1)),
        (10, u(10_000)),
        (11, u(0)),
        (12, u(500)),
        (13, u(100_000)),
        (14, t("relay")),
        (15, t(Profile::X25519.name())),
        (16, u(2)),
        (24, array(&[u(500), vec![0xf6]])),
    ]);
    let head_signer = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let delegation = encode_map(&[
        (0, t(codec::tests::schema_revision())),
        (1, t("tenant")),
        (2, t("authority")),
        (3, b(&cap)),
        (4, u(1)),
        (5, b(&[2; 16])),
        (6, b(&[3; 16])),
        (
            7,
            b(ring::signature::KeyPair::public_key(&head_signer).as_ref()),
        ),
        (8, u(0)),
        (9, t("publication")),
        (10, u(1)),
        (11, u(1)),
        (12, u(1)),
        (13, u(90_000)),
    ]);
    // Original endpoint and activation delegations remain in authenticated
    // history; this new root-signed revision adds only relay issuance.
    let trust = sign(
        "TrustConfig",
        &[
            (0, t(codec::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, u(1)),
            (4, u(2)),
            (5, u(1)),
            (6, u(100_000)),
            (7, capacity),
            (
                8,
                encode_map(&[
                    (0, t("publication")),
                    (1, u(1)),
                    (2, u(60_000)),
                    (3, u(90_000)),
                ]),
            ),
            (9, array(&[])),
            (10, array(&[permission])),
            (11, array(std::slice::from_ref(&delegation))),
            (12, array(&[])),
            (13, array(&[])),
            (14, array(&[])),
            (15, array(&[])),
            (16, b(&[1; 16])),
        ],
        &Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap(),
    );
    let state = encode_map(&[
        (0, t(codec::tests::schema_revision())),
        (1, t("tenant")),
        (2, t("authority")),
        (3, b(&cap)),
        (4, u(1)),
        (5, array(&[u(0), u(0)])),
        (6, t("publication")),
        (7, u(1)),
        (8, array(&[])),
        (9, array(&[])),
        (10, array(&[])),
        (
            11,
            array(&[encode_map(&[
                (0, u(0)),
                (1, u(500)),
                (2, u(100_000)),
                (3, u(100_000)),
            ])]),
        ),
    ]);
    let head = sign(
        "FreshnessHead",
        &[
            (0, t(codec::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, b(&cap)),
            (4, u(1)),
            (5, array(&[u(0), u(0)])),
            (6, t("publication")),
            (7, u(1)),
            (8, u(2)),
            (9, u(900)),
            (10, u(60_000)),
            (
                11,
                b(
                    &codec::digest("revocation_state_digest", decode(&state, "RevocationState"))
                        .unwrap(),
                ),
            ),
            (12, u(state.len() as u64)),
            (13, b(&[3; 16])),
            (
                14,
                b(&codec::digest(
                    "head_signer_delegation_digest",
                    decode(&delegation, "HeadSignerDelegation"),
                )
                .unwrap()),
            ),
        ],
        &head_signer,
    );
    namespace.refresh(Some(&trust), &head, &state).unwrap();
    let relay = LocalKeys::generate(Profile::X25519).unwrap();
    let mut children = original.children().unwrap();
    let mut fields = Vec::new();
    while let Some(id) = children.next() {
        let id = id.unwrap().uint().unwrap();
        let value = children.next().unwrap().unwrap();
        if id == 16 {
            continue;
        }
        fields.push((
            id,
            match id {
                1 => t("relay"),
                3 => encode_map(&[(0, u(0)), (1, b(relay.dh_public()))]),
                4 => b(&relay.ed_public()),
                5 => u(2),
                _ => value.raw().to_vec(),
            },
        ));
    }
    let certificate = sign("IdentityCertificate", &fields, &issuer);
    codec::verify_signature(
        "IdentityCertificate",
        decode(&certificate, "IdentityCertificate"),
        &ring::signature::KeyPair::public_key(&issuer)
            .as_ref()
            .try_into()
            .unwrap(),
        &mut Vec::with_capacity(8192),
    )
    .unwrap();
    certificate
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tunnel_registration_waits_for_wss_upgrade_and_closes_physical_carrier() {
    original_tunnel_preparation_lifecycle(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tunnel_registration_retires_rejected_wss_upgrade_without_reopening() {
    original_tunnel_preparation_lifecycle(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tunnel_registration_cancels_pending_upgrade_and_joins_physical_cleanup() {
    original_tunnel_preparation_lifecycle(false, true).await;
}

#[expect(
    clippy::result_large_err,
    reason = "Tungstenite fixes the HTTP upgrade error response type."
)]
async fn original_tunnel_preparation_lifecycle(reject_upgrade: bool, cancel_preparation: bool) {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let relay_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let relay_port = relay_listener.local_addr().unwrap().port();
    let (relay_tls, relay_ca, _) = tls_identity();
    let generated = LocalKeys::generate(Profile::X25519).unwrap();
    let public = generated.ed_public();
    let mut fixture = Fixture::with_identity(
        ActivationSource::LiveAuthority,
        Profile::X25519.name(),
        Some([
            (generated.dh_public(), &public),
            (generated.dh_public(), &public),
        ]),
    );
    let server_keys = fixture
        .environment
        .identity_keys(Profile::X25519.name())
        .unwrap();
    fixture.set_server_keys(&server_keys);
    fixture.set_wss_route(relay_port, None);
    fixture = tunnelize_live_fixture(fixture);
    let artifact = codec::decode(
        &fixture.artifact,
        "Artifact",
        Limits {
            bytes: 65536,
            nodes: 16384,
        },
        None,
    )
    .unwrap();
    let original_candidate = artifact
        .field("Artifact", "candidates")
        .unwrap()
        .at(0)
        .unwrap();
    let server_leg = encode_map(&[
        (0, u(0)),
        (1, b(&[42; 16])),
        (2, u(1)),
        (3, u(1)),
        (4, u(2)),
        (5, u(1)),
        (6, t("example.com")),
        (7, u(u64::from(relay_port))),
        (8, t("/flowersec/v4/tunnel")),
        (9, t("http/1.1")),
        (10, t("flowersec.tunnel.v4")),
        (11, encode_map(&[(0, u(0)), (1, vec![0xf5])])),
    ]);
    let candidate = replace_map(
        original_candidate.raw(),
        "Candidate",
        &[(5, server_leg)],
        None,
    );
    fixture.artifact = replace_map(
        &fixture.artifact,
        "Artifact",
        &[(12, array(&[candidate]))],
        Some(12),
    );
    let namespace = Arc::new(Namespace::new(fixture.verifier));
    let relay_certificate = authorize_original_relay(&namespace, &fixture.server);
    let environment = Arc::new(fixture.environment);
    let source = environment
        .live_accepted_material_source(vec![namespace], server_keys, 2)
        .unwrap();
    let (identity, delivery_ca, _) = tls_provisioning();
    let (_, authority_control) = control_tls(1);
    let reserved = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let handle = source
        .serve_original_delivery(
            identity,
            crate::LiveServerDeliveryOptions {
                listen_address: address,
                authority: format!("example.com:{}", address.port()),
                client_roots_der: authority_control.roots_der.clone(),
                authority_leaf_digests: vec![
                    Sha256::digest(&authority_control.client_chain_der[0]).into(),
                ],
                maximum_connections: 1,
                timeout: Duration::from_secs(3),
                provider_runtime_bytes: 1 << 20,
                cancellation: CancellationToken::new(),
            },
        )
        .await
        .unwrap();
    let configuration = ControlHTTPSConfiguration {
        port: handle.local_address().port(),
        roots_der: vec![delivery_ca],
        ..authority_control
    };
    let control = environment
        .live_tunnel_authority_control(crate::LiveTunnelAuthorityControlConfiguration {
            activation: configuration.clone(),
            relay_preparation: configuration.clone(),
            activation_signing_key_id: "activate-1".into(),
        })
        .unwrap();
    let provider = WssConnectOptions {
        ca_certificates_der: vec![relay_ca],
        remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
        binding_mode: BindingMode::AuthenticatedContext,
        origin: None,
        timeout: Duration::from_secs(3),
        publication_timeout: Duration::from_secs(2),
        queue_messages: 2,
        prepare_bytes: 65536,
        native_runtime_bytes: 1 << 20,
    };
    handle
        .configure_original_tunnel_carrier_preparation(provider.clone(), control.clone())
        .unwrap();
    assert!(matches!(
        handle.configure_original_tunnel_carrier_preparation(provider, control),
        Err(ConnectError::Configuration)
    ));
    let delivery = environment
        .original_live_tunnel_server_delivery(configuration.clone(), configuration)
        .unwrap();
    let original_bytes = || PoolCredentialBytes {
        artifact: fixture.artifact.clone(),
        client_certificate: fixture.client.clone(),
        server_certificate: fixture.server.clone(),
        activation: Vec::new(),
    };
    let canceled = CancellationToken::new();
    canceled.cancel();
    assert!(matches!(
        delivery
            .register_tunnel_original(
                original_bytes(),
                relay_certificate.clone(),
                "service".into(),
                "service".into(),
                &canceled
            )
            .await,
        Err(crate::ControlHTTPSFailure::Canceled)
    ));
    let (tls_ready_tx, tls_ready_rx) = oneshot::channel();
    let (upgrade_tx, upgrade_rx) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (tcp, _) = relay_listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(relay_tls)
            .accept(tcp)
            .await
            .unwrap();
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        tls_ready_tx.send(()).unwrap();
        upgrade_rx.await.unwrap();
        if !cancel_preparation {
            let upgrade = tokio_tungstenite::accept_hdr_async(
                &mut tls,
                |request: &Request, mut response: Response| {
                    assert_eq!(request.uri().path(), "/flowersec/v4/tunnel");
                    assert_eq!(
                        request.headers()["sec-websocket-protocol"],
                        "flowersec.tunnel.v4"
                    );
                    if reject_upgrade {
                        return Err(http::Response::builder()
                            .status(http::StatusCode::FORBIDDEN)
                            .body(Some("Original relay carrier refused".into()))
                            .unwrap());
                    }
                    response.headers_mut().insert(
                        "sec-websocket-protocol",
                        "flowersec.tunnel.v4".parse().unwrap(),
                    );
                    Ok(response)
                },
            )
            .await;
            if reject_upgrade {
                assert!(upgrade.is_err());
            } else {
                let mut socket = upgrade.unwrap();
                let terminal = socket.next().await;
                assert!(
                    matches!(terminal, None | Some(Ok(Message::Close(_))) | Some(Err(_))),
                    "Prepare must send no HOP or application payload before TxB: {terminal:?}"
                );
            }
        }
        // Observe the actual transport ending after the SDK retires its
        // original provider, including an upgrade that never completed.
        let mut input = [0u8; 1024];
        let mut pending_upgrade_bytes = 0usize;
        loop {
            match tls.read(&mut input).await {
                Ok(0) => break,
                Ok(count) => {
                    assert!(cancel_preparation);
                    pending_upgrade_bytes += count;
                    assert!(pending_upgrade_bytes <= 8192);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("original carrier did not end cleanly: {error}"),
            }
        }
    });
    let cancellation = CancellationToken::new();
    let registering = {
        let delivery = delivery.clone();
        let cancellation = cancellation.clone();
        let bytes = original_bytes();
        let relay_certificate = relay_certificate.clone();
        tokio::spawn(async move {
            delivery
                .register_tunnel_original(
                    bytes,
                    relay_certificate,
                    "service".into(),
                    "service".into(),
                    &cancellation,
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), tls_ready_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !registering.is_finished(),
        "registration must wait for the actual WSS upgrade"
    );
    if cancel_preparation {
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(3), registering)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(crate::ControlHTTPSFailure::Canceled)));
        handle.close();
        upgrade_tx.send(()).unwrap();
    } else {
        upgrade_tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(3), registering)
            .await
            .unwrap()
            .unwrap();
        if reject_upgrade {
            assert!(result.is_err());
        } else {
            drop(result.unwrap());
        }
        assert!(
            delivery
                .register_tunnel_original(
                    original_bytes(),
                    relay_certificate,
                    "service".into(),
                    "service".into(),
                    &cancellation
                )
                .await
                .is_err(),
            "the original lease cannot reopen after its preparation outcome"
        );
        handle.close();
    }
    tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), handle.wait_cleanup())
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    source.close();
    environment.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registered_live_source_rejects_unavailable_requirements_before_consuming_artifact() {
    let _listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (tls, wss_ca, _) = tls_identity();
    let generated = LocalKeys::generate(Profile::X25519).unwrap();
    let public = generated.ed_public();
    let mut fixture = Fixture::with_identity(
        ActivationSource::LiveAuthority,
        Profile::X25519.name(),
        Some([
            (generated.dh_public(), &public),
            (generated.dh_public(), &public),
        ]),
    );
    let keys = fixture
        .environment
        .identity_keys(Profile::X25519.name())
        .unwrap();
    fixture.set_client_keys(&keys);
    fixture = tunnelize_live_fixture(fixture);
    drop(tls);
    let namespace = Arc::new(Namespace::new(fixture.verifier));
    let environment = Arc::new(fixture.environment);
    let (_, mut control) = control_tls(1);
    control.base_path = "/flowersec/control/live".into();
    let issuance = ControlHTTPSConfiguration {
        base_path: String::new(),
        ..control.clone()
    };
    let source = crate::LocalDirectMaterialSource::registered_live_tunnel_authority(
        &environment,
        crate::RegisteredLiveTunnelSourceConfiguration {
            source: LiveAuthoritySourceConfiguration {
                namespaces: vec![namespace],
                identity: keys,
                client_certificate: fixture.client,
                server_certificate: fixture.server,
                artifact_issuer_key_id: [5; 16],
                activation_signing_key_id: "activate-1".into(),
                issuance,
                activation: control.clone(),
                carrier: crate::LiveAuthorityCarrier::WebSocket,
                provider: WssConnectOptions {
                    ca_certificates_der: vec![wss_ca],
                    remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                    binding_mode: BindingMode::AuthenticatedContext,
                    origin: Some("https://app.example".into()),
                    timeout: Duration::from_secs(3),
                    publication_timeout: Duration::from_secs(2),
                    queue_messages: 2,
                    prepare_bytes: 65536,
                    native_runtime_bytes: 4 << 20,
                },
                application_profile: crate::ApplicationProfile::Transport,
            },
            tunnel: crate::LiveTunnelSourceConfiguration {
                control: crate::LiveTunnelAuthorityControlConfiguration {
                    activation: control.clone(),
                    relay_preparation: control,
                    activation_signing_key_id: "activate-1".into(),
                },
                relay_certificate: vec![1],
                relay_service: "service".into(),
                relay_audience: "audience".into(),
            },
            artifact: fixture.artifact,
            authority: "authority".into(),
        },
    )
    .unwrap();
    let unsupported = crate::ConnectionRequest {
        requirements: crate::ConnectionRequirements {
            independent_reliable_read_progress: true,
            ..crate::ConnectionRequirements::default()
        },
        handlers: None,
    };
    assert!(matches!(
        source
            .acquire_async(&environment, &unsupported, &CancellationToken::new())
            .await,
        Err(crate::MaterialSourceError::RequiredGuaranteeUnavailable)
    ));
    let acquired = source
        .acquire_async(
            &environment,
            &crate::ConnectionRequest::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    drop(acquired);
    let canceled = CancellationToken::new();
    canceled.cancel();
    assert!(matches!(
        source
            .acquire_async(
                &environment,
                &crate::ConnectionRequest::default(),
                &canceled,
            )
            .await,
        Err(crate::MaterialSourceError::Canceled)
    ));
    source.close();
    environment.close().await.unwrap();
}
