use super::*;
use crate::{
    codec_v4::ActivationSource,
    namespace_v4::verifier::credential::tests::Fixture,
    pool_v4::{admission::SQLiteAdmissionBinding, tests::StoreFixture},
    transport::ByteStream,
};
use bytes::Bytes;
use std::result::Result;
#[derive(Debug)]
struct TestCallbacks {
    plan: HandlerPlan,
}
#[derive(Debug)]
struct TestLease;
#[async_trait]
impl ApplicationAuthorizationLease for TestLease {
    fn close(&self) {}
    async fn wait_cleanup(&self) -> Result<CleanupStatus, ServeError> {
        Ok(application::complete())
    }
}
#[async_trait]
impl ServeCallbacks for TestCallbacks {
    async fn authorize_request(
        &self,
        _: ServeRequestContext,
    ) -> Result<RequestAuthorization, ServeError> {
        Ok(RequestAuthorization { allowed: true })
    }
    async fn resolve_handlers(
        &self,
        _: AuthenticatedRequestContext,
    ) -> Result<HandlerPlan, ServeError> {
        Ok(self.plan.clone())
    }
    async fn authorize_application(
        &self,
        context: AuthenticatedRequestContext,
        handlers: HandlerPlan,
    ) -> Result<AuthorizeApplicationResult, ServeError> {
        context.reserve_lease(context.binding(), Arc::new(TestLease))?;
        Ok(AuthorizeApplicationResult::Authorized { handlers })
    }
    async fn on_session(
        &self,
        _: Session,
        _: AuthenticatedRequestContext,
    ) -> Result<SessionAcceptance, ServeError> {
        Ok(SessionAcceptance::Queue)
    }
    async fn release(&self, _: ServeReleaseContext) -> Result<CleanupStatus, ServeError> {
        Ok(application::complete())
    }
}
#[derive(Debug, Default)]
struct Source(Mutex<Option<PoolCredentialBytes>>);
#[async_trait]
impl AcceptedMaterialSource for Source {
    async fn resolve(&self, _: &[u8], _: CancellationToken) -> ConnectResult<PoolCredentialBytes> {
        let lock = self.0.lock().unwrap();
        let b = lock.as_ref().ok_or(ConnectError::Authorization)?;
        Ok(PoolCredentialBytes {
            artifact: b.artifact.clone(),
            client_certificate: b.client_certificate.clone(),
            server_certificate: b.server_certificate.clone(),
            activation: b.activation.clone(),
        })
    }
}
fn credential_bytes(f: &Fixture) -> PoolCredentialBytes {
    PoolCredentialBytes {
        artifact: f.artifact.clone(),
        client_certificate: f.client.clone(),
        server_certificate: f.server.clone(),
        activation: f.activation.clone(),
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_listener_durable_admission_and_original_serve_children() {
    for (profile, pin, pending_only, binding_mode) in [
        (
            Profile::X25519,
            true,
            false,
            BindingMode::AuthenticatedContext,
        ),
        (
            Profile::P256,
            false,
            false,
            BindingMode::AuthenticatedContext,
        ),
        (
            Profile::X25519,
            true,
            true,
            BindingMode::AuthenticatedContext,
        ),
        (Profile::X25519, true, false, BindingMode::DirectExporter),
        (Profile::P256, false, false, BindingMode::DirectExporter),
        (Profile::X25519, true, true, BindingMode::DirectExporter),
    ] {
        let stage = std::cell::Cell::new("setup");
        let scenario = async {
            let generated = LocalKeys::generate(profile).unwrap();
            let ed = generated.ed_public();
            let mut f = Fixture::with_identity(
                ActivationSource::PreauthorizedPool,
                profile.name(),
                Some([(generated.dh_public(), &ed), (generated.dh_public(), &ed)]),
            );
            let client_keys = f.environment.identity_keys(profile.name()).unwrap();
            let server_keys = f.environment.identity_keys(profile.name()).unwrap();
            f.set_client_keys(&client_keys);
            f.set_server_keys(&server_keys);
            let facts = f.reserve().unwrap();
            let winner_name = facts.pool.as_ref().unwrap().winner_authority.clone();
            let local = StoreFixture::with_authority(&f, Some("accept.example"));
            let parent = StoreFixture::with_authority(&f, Some(&winner_name));
            let pool = StoreFixture::new(&f);
            let a = decode(&f.artifact, "Artifact", 65536, Context::default()).unwrap();
            let authority = SQLiteAdmissionAuthority::new(
                local.store.clone(),
                parent.store.clone(),
                vec![SQLiteAdmissionBinding {
                    tenant: a
                        .field("Artifact", "tenant_id")
                        .unwrap()
                        .text()
                        .unwrap()
                        .into(),
                    issuer: a.b("Artifact", "issuer_key_id").unwrap(),
                    server_identity_digest: facts.certificate_digests[1],
                    audience: a
                        .field("Artifact", "audience")
                        .unwrap()
                        .text()
                        .unwrap()
                        .into(),
                }],
            )
            .unwrap();
            drop(facts);
            let (identity, ca, digest) = super::super::tests::tls_provisioning();
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);
            f.set_wss_route(address.port(), pin.then_some(digest));
            let server_bytes = credential_bytes(&f);
            let client_bytes = credential_bytes(&f);
            let source = Arc::new(Source(Mutex::new(Some(server_bytes))));
            let namespace = Arc::new(Namespace::new(f.verifier));
            let environment = f.environment;
            stage.set("start listener");
            let handle = environment
                .serve_pool_wss(
                    vec![namespace.clone()],
                    server_keys,
                    source,
                    authority,
                    identity,
                    WssServeOptions {
                        callbacks: Arc::new(TestCallbacks {
                            plan: environment
                                .handler_plan(HandlerPlanOptions {
                                    streams: StreamDispatch::Manual,
                                    application_bytes: 4096,
                                })
                                .unwrap(),
                        }),
                        application_limits: ApplicationLimits {
                            ordinary_callbacks: 4,
                            ordinary_callback_bytes: 32768,
                            control_callback_bytes: 32768,
                        },
                        cancellation: CancellationToken::new(),
                        binding_mode,
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
            if pending_only {
                let pending = tokio::net::TcpStream::connect(address).await.unwrap();
                // Closing the shared Environment also wakes an otherwise idle
                // accept pump; it must retain the pending TLS socket until exit.
                stage.set("close Environment with pending TLS");
                environment.close().await.unwrap();
                stage.set("Serve cleanup");
                assert!(handle.wait_cleanup().await.unwrap().complete);
                assert_eq!(environment.resource_usage().connections, 0);
                drop(pending);
                return;
            }
            let material = environment
                .pool_connection_material(vec![namespace], client_keys, client_bytes)
                .unwrap();
            stage.set("connect client");
            let client = environment
                .connect_pool_wss(
                    material,
                    pool.store.clone(),
                    WssConnectOptions {
                        binding_mode,
                        remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                        origin: None,
                        ca_certificates_der: if pin { vec![] } else { vec![ca] },
                        timeout: Duration::from_secs(5),
                        publication_timeout: Duration::from_secs(2),
                        queue_messages: 2,
                        prepare_bytes: 65536,
                        native_runtime_bytes: 1 << 20,
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            stage.set("accept Session");
            let server = tokio::time::timeout(Duration::from_secs(2), handle.accept())
                .await
                .unwrap()
                .unwrap();
            stage.set("probe");
            assert_eq!(
                client
                    .probe_liveness(Duration::from_secs(2))
                    .await
                    .unwrap()
                    .outcome,
                ProbeOutcome::Responsive
            );
            stage.set("open stream");
            let (outgoing, incoming) = tokio::join!(
                client.open_stream("serve.test", Metadata::empty(), 128),
                async { server.next_open().await.unwrap().accept(128).unwrap() }
            );
            let outgoing = outgoing.unwrap();
            stage.set("write request");
            outgoing
                .write(Bytes::from_static(b"actual accepted server"))
                .await
                .unwrap();
            stage.set("read request");
            assert_eq!(
                incoming.read().await.unwrap().unwrap(),
                Bytes::from_static(b"actual accepted server")
            );
            stage.set("rekey");
            client.rekey().await.unwrap();
            stage.set("write response");
            incoming
                .write(Bytes::from_static(b"new epoch"))
                .await
                .unwrap();
            stage.set("read response");
            assert_eq!(
                outgoing.read().await.unwrap().unwrap(),
                Bytes::from_static(b"new epoch")
            );
            if pin {
                // Drain seals new publication immediately but preserves this
                // previously published stream until its actual FIN/retirement.
                stage.set("drain");
                handle.drain(Duration::from_secs(2)).unwrap();
                outgoing
                    .write(Bytes::from_static(b"draining child"))
                    .await
                    .unwrap();
                assert_eq!(
                    incoming.read().await.unwrap().unwrap(),
                    Bytes::from_static(b"draining child")
                );
                outgoing.close_write().await.unwrap();
                assert!(incoming.read().await.unwrap().is_none());
                incoming.close_write().await.unwrap();
                assert!(outgoing.read().await.unwrap().is_none());
                stage.set("finish stream");
                outgoing.finish().await.unwrap();
            } else {
                handle.close();
            }
            stage.set("Serve cleanup");
            assert!(handle.wait_cleanup().await.unwrap().complete);
            let drained = handle.wait_drain().await.unwrap();
            assert_eq!(
                drained.outcome,
                if pin {
                    DrainOutcome::Drained
                } else {
                    DrainOutcome::Failed
                }
            );
            assert!(drained.cleanup.complete);
            stage.set("server Session cleanup");
            assert!(server.wait_cleanup().await.complete);
            client.close();
            stage.set("client Session cleanup");
            assert!(client.wait_cleanup().await.complete);
            assert!(!environment.is_closed());
            assert_eq!(environment.resource_usage().connections, 0);
        };
        tokio::time::timeout(Duration::from_secs(15), scenario)
            .await
            .unwrap_or_else(|_| {
                panic!("Serve {profile:?} pin={pin} pending={pending_only} binding={binding_mode:?} timed out during {}", stage.get())
            });
    }
}
