use super::*;
use crate::{
    codec_v4::ActivationSource,
    namespace_v4::verifier::credential::tests::Fixture,
    pool_v4::{admission::SQLiteAdmissionBinding, tests::StoreFixture},
    transport::ByteStream,
};
use bytes::Bytes;
use std::result::Result;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Normal,
    RejectRequest,
    RejectApplication,
    MissingLease,
    PanicAuthorization,
    HoldAuthorization,
    ReserveAfterCancellation,
    WaitRequestCancellation,
    HoldPublication,
    HoldRelease,
    UnknownRelease,
    Registered,
}
#[derive(Debug)]
struct Lease {
    closes: AtomicUsize,
    observations: AtomicUsize,
    clean: AtomicBool,
}
#[async_trait]
impl ApplicationAuthorizationLease for Lease {
    fn close(&self) {
        self.closes.fetch_add(1, Ordering::AcqRel);
    }
    async fn wait_cleanup(&self) -> Result<CleanupStatus, ServeError> {
        self.observations.fetch_add(1, Ordering::AcqRel);
        Ok(if self.clean.load(Ordering::Acquire) {
            application::complete()
        } else {
            CleanupStatus {
                complete: false,
                cleanup_incomplete: true,
                pending_callbacks: 1,
            }
        })
    }
}
#[derive(Debug)]
struct Callbacks {
    mode: Mode,
    plan: HandlerPlan,
    events: Mutex<Vec<&'static str>>,
    lease: Arc<Lease>,
    entered: Semaphore,
    resume: Semaphore,
    releases: Mutex<Vec<ServeReleaseContext>>,
}
impl Callbacks {
    fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }
    async fn block(&self) {
        self.entered.add_permits(1);
        self.resume.acquire().await.unwrap().forget();
    }
    async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
}
#[async_trait]
impl ServeCallbacks for Callbacks {
    async fn authorize_request(
        &self,
        context: ServeRequestContext,
    ) -> Result<RequestAuthorization, ServeError> {
        assert_eq!(context.method, "GET");
        assert_eq!(context.target, "/flowersec/v4/direct");
        assert!(
            context.local_address.ip().is_loopback() && context.remote_address.ip().is_loopback()
        );
        assert!(context.headers.len() <= 32);
        self.event("request");
        if self.mode == Mode::WaitRequestCancellation {
            self.entered.add_permits(1);
            context.cancellation.cancelled().await;
            self.event("request_canceled");
            self.block().await;
        }
        Ok(RequestAuthorization {
            allowed: self.mode != Mode::RejectRequest,
        })
    }
    async fn resolve_handlers(
        &self,
        context: AuthenticatedRequestContext,
    ) -> Result<HandlerPlan, ServeError> {
        assert_ne!(context.binding().client_identity, [0; 32]);
        assert!(
            context
                .reserve_lease(context.binding(), self.lease.clone())
                .is_err()
        );
        self.event("resolve");
        Ok(self.plan.clone())
    }
    async fn authorize_application(
        &self,
        context: AuthenticatedRequestContext,
        handlers: HandlerPlan,
    ) -> Result<AuthorizeApplicationResult, ServeError> {
        self.event("authorize");
        if self.mode == Mode::MissingLease {
            return Ok(AuthorizeApplicationResult::Authorized { handlers });
        }
        let mut foreign = context.binding();
        foreign.attempt[0] ^= 1;
        assert!(context.reserve_lease(foreign, self.lease.clone()).is_err());
        if self.mode == Mode::ReserveAfterCancellation {
            self.block().await;
        }
        context.reserve_lease(context.binding(), self.lease.clone())?;
        assert!(
            context
                .reserve_lease(context.binding(), self.lease.clone())
                .is_err()
        );
        if matches!(
            self.mode,
            Mode::HoldAuthorization | Mode::ReserveAfterCancellation
        ) {
            self.block().await;
        }
        if self.mode == Mode::PanicAuthorization {
            panic!("application secret must not become a ServeError");
        }
        Ok(if self.mode == Mode::RejectApplication {
            AuthorizeApplicationResult::Rejected
        } else {
            AuthorizeApplicationResult::Authorized { handlers }
        })
    }
    async fn on_session(
        &self,
        session: Session,
        context: AuthenticatedRequestContext,
    ) -> Result<SessionAcceptance, ServeError> {
        self.event("session");
        assert!(
            context
                .reserve_lease(context.binding(), self.lease.clone())
                .is_err()
        );
        if self.mode == Mode::Registered {
            assert!(session.next_open().await.is_err());
        }
        if self.mode == Mode::HoldPublication {
            self.block().await;
        }
        Ok(SessionAcceptance::Queue)
    }
    async fn release(&self, context: ServeReleaseContext) -> Result<CleanupStatus, ServeError> {
        self.event("release");
        self.releases.lock().unwrap().push(context);
        if self.mode == Mode::HoldRelease {
            self.block().await;
        }
        Ok(if self.mode == Mode::UnknownRelease {
            CleanupStatus {
                complete: false,
                cleanup_incomplete: true,
                pending_callbacks: 1,
            }
        } else {
            application::complete()
        })
    }
}
#[derive(Debug)]
struct Echo;
#[async_trait]
impl RawStreamHandler for Echo {
    async fn authorize(
        &self,
        _: ApplicationBinding,
        metadata: Metadata,
        _: CancellationToken,
    ) -> Result<StreamAuthorization, ServeError> {
        assert!(metadata.encoded().is_empty());
        Ok(StreamAuthorization::Accept {
            receive_window: 256,
        })
    }
    async fn handle(
        &self,
        stream: Stream,
        _: Metadata,
        _: CancellationToken,
    ) -> Result<(), ServeError> {
        while let Some(bytes) = stream
            .read()
            .await
            .map_err(|_| ServeError::new(ServeFailure::Failed))?
        {
            stream
                .write(bytes)
                .await
                .map_err(|_| ServeError::new(ServeFailure::Failed))?;
        }
        stream
            .close_write()
            .await
            .map_err(|_| ServeError::new(ServeFailure::Failed))?;
        Ok(())
    }
}
#[derive(Debug)]
struct HeldHandler {
    entered: Arc<Semaphore>,
    resume: Arc<Semaphore>,
}
#[async_trait]
impl RawStreamHandler for HeldHandler {
    async fn authorize(
        &self,
        _: ApplicationBinding,
        _: Metadata,
        _: CancellationToken,
    ) -> Result<StreamAuthorization, ServeError> {
        Ok(StreamAuthorization::Accept {
            receive_window: 256,
        })
    }
    async fn handle(
        &self,
        _: Stream,
        _: Metadata,
        cancellation: CancellationToken,
    ) -> Result<(), ServeError> {
        self.entered.add_permits(1);
        cancellation.cancelled().await;
        self.resume.acquire().await.unwrap().forget();
        Err(ServeError::new(ServeFailure::Canceled))
    }
}
#[derive(Debug)]
struct Source {
    bytes: Mutex<Option<PoolCredentialBytes>>,
    callbacks: Arc<Callbacks>,
}
#[async_trait]
impl AcceptedMaterialSource for Source {
    async fn resolve(&self, _: &[u8], _: CancellationToken) -> ConnectResult<PoolCredentialBytes> {
        self.callbacks.event("material");
        self.bytes
            .lock()
            .unwrap()
            .take()
            .ok_or(ConnectError::Authorization)
    }
}
struct Running {
    environment: TransportEnvironment,
    handle: Arc<ServeHandle>,
    callbacks: Arc<Callbacks>,
    material: Option<PoolConnectionMaterial>,
    cancellation: CancellationToken,
    local: StoreFixture,
    _parent: StoreFixture,
    pool: StoreFixture,
}
fn bytes(f: &Fixture) -> PoolCredentialBytes {
    PoolCredentialBytes {
        artifact: f.artifact.clone(),
        client_certificate: f.client.clone(),
        server_certificate: f.server.clone(),
        activation: f.activation.clone(),
    }
}
impl Running {
    async fn new(mode: Mode) -> Self {
        let profile = Profile::X25519;
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
        let local = StoreFixture::with_authority(&f, Some("accept.example"));
        let parent =
            StoreFixture::with_authority(&f, Some(&facts.pool.as_ref().unwrap().winner_authority));
        let pool = StoreFixture::new(&f);
        let artifact = decode(&f.artifact, "Artifact", 65536, Context::default()).unwrap();
        let authority = SQLiteAdmissionAuthority::new(
            local.store.clone(),
            parent.store.clone(),
            vec![SQLiteAdmissionBinding {
                tenant: artifact
                    .field("Artifact", "tenant_id")
                    .unwrap()
                    .text()
                    .unwrap()
                    .into(),
                issuer: artifact.b("Artifact", "issuer_key_id").unwrap(),
                server_identity_digest: facts.certificate_digests[1],
                audience: artifact
                    .field("Artifact", "audience")
                    .unwrap()
                    .text()
                    .unwrap()
                    .into(),
            }],
        )
        .unwrap();
        drop(facts);
        let (identity, _, digest) = super::super::tests::tls_provisioning();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        f.set_wss_route(address.port(), Some(digest));
        let client_bytes = bytes(&f);
        let server_bytes = bytes(&f);
        let namespace = Arc::new(Namespace::new(f.verifier));
        let environment = f.environment;
        let plan = environment
            .handler_plan(HandlerPlanOptions {
                streams: if mode == Mode::Registered {
                    StreamDispatch::Registered(vec![RawStreamRegistration {
                        kind: "test.echo".into(),
                        metadata: None,
                        handler: Arc::new(Echo),
                    }])
                } else {
                    StreamDispatch::Manual
                },
                application_bytes: 4096,
            })
            .unwrap();
        let callbacks = Arc::new(Callbacks {
            mode,
            plan,
            events: Mutex::new(Vec::new()),
            lease: Arc::new(Lease {
                closes: AtomicUsize::new(0),
                observations: AtomicUsize::new(0),
                clean: AtomicBool::new(true),
            }),
            entered: Semaphore::new(0),
            resume: Semaphore::new(0),
            releases: Mutex::new(Vec::new()),
        });
        let cancellation = CancellationToken::new();
        let handle = Arc::new(
            environment
                .serve_wss(
                    vec![namespace.clone()],
                    server_keys,
                    Arc::new(Source {
                        bytes: Mutex::new(Some(server_bytes)),
                        callbacks: callbacks.clone(),
                    }),
                    authority,
                    identity,
                    WssServeOptions {
                        callbacks: callbacks.clone(),
                        application_limits: ApplicationLimits {
                            ordinary_callbacks: 2,
                            ordinary_callback_bytes: 32768,
                            control_callback_bytes: 32768,
                        },
                        cancellation: cancellation.clone(),
                        binding_mode: BindingMode::AuthenticatedContext,
                        listen_address: address,
                        host: "example.com".into(),
                        origin: None,
                        max_connections: 2,
                        max_frame_bytes: 65536,
                        handshake_timeout: Duration::from_secs(
                            if mode == Mode::WaitRequestCancellation {
                                1
                            } else {
                                5
                            },
                        ),
                        publication_timeout: Duration::from_secs(2),
                        queue_messages: 4,
                        prepare_bytes: 65536,
                        native_runtime_bytes: 1 << 20,
                    },
                )
                .await
                .unwrap(),
        );
        let material = Some(
            environment
                .pool_connection_material(vec![namespace], client_keys, client_bytes)
                .unwrap(),
        );
        Self {
            environment,
            handle,
            callbacks,
            material,
            cancellation,
            local,
            _parent: parent,
            pool,
        }
    }
    async fn connect(&mut self) -> ConnectResult<Session> {
        self.environment
            .connect_pool_wss(
                self.material.take().unwrap(),
                self.pool.store.clone(),
                Self::connect_options(),
                CancellationToken::new(),
            )
            .await
    }
    fn connect_options() -> WssConnectOptions {
        WssConnectOptions {
            binding_mode: BindingMode::AuthenticatedContext,
            remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
            origin: None,
            ca_certificates_der: vec![],
            timeout: Duration::from_secs(5),
            publication_timeout: Duration::from_secs(2),
            queue_messages: 4,
            prepare_bytes: 65536,
            native_runtime_bytes: 1 << 20,
        }
    }
    async fn connect_with_plan(&mut self, plan: HandlerPlan) -> ConnectResult<Session> {
        self.environment
            .connect_pool_wss_with_handler_plan(
                self.material.take().unwrap(),
                self.pool.store.clone(),
                Self::connect_options(),
                plan,
                ApplicationLimits {
                    ordinary_callbacks: 2,
                    ordinary_callback_bytes: 32768,
                    control_callback_bytes: 32768,
                },
                CancellationToken::new(),
            )
            .await
    }
    async fn clean(&self) {
        self.handle.close();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), self.handle.wait_cleanup())
                .await
                .unwrap()
                .unwrap()
                .complete
        );
        assert!(
            self.handle
                .owner
                .gate
                .lock()
                .unwrap()
                .slots
                .iter()
                .all(Option::is_none)
        );
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_callbacks_reject_before_cas_and_release_original_lease_after_panic() {
    for mode in [
        Mode::RejectRequest,
        Mode::RejectApplication,
        Mode::PanicAuthorization,
        Mode::MissingLease,
    ] {
        let mut running = Running::new(mode).await;
        assert!(running.connect().await.is_err());
        running.clean().await;
        assert_eq!(running.local.admission_rows(), 0);
        let events = running.callbacks.events.lock().unwrap();
        assert_eq!(
            events.as_slice(),
            if mode == Mode::RejectRequest {
                &["request", "release"][..]
            } else {
                &["request", "material", "resolve", "authorize", "release"][..]
            }
        );
        assert_eq!(
            running.callbacks.lease.closes.load(Ordering::Acquire),
            usize::from(!matches!(mode, Mode::RejectRequest | Mode::MissingLease))
        );
        let releases = running.callbacks.releases.lock().unwrap();
        assert_eq!(releases.len(), 1);
        assert!(!releases[0].published && releases[0].cleanup.complete);
        assert_eq!(
            releases[0].authorization,
            match mode {
                Mode::RejectRequest => ApplicationAuthorization::NotStarted,
                Mode::RejectApplication => ApplicationAuthorization::Rejected,
                _ => ApplicationAuthorization::Unknown,
            }
        );
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_late_authorization_is_cleaned_without_cas_or_session_publication() {
    let mut running = Running::new(Mode::HoldAuthorization).await;
    let callbacks = running.callbacks.clone();
    let handle = running.handle.clone();
    let (connected, ()) = tokio::join!(running.connect(), async {
        callbacks.entered().await;
        handle.close();
        assert!(!handle.cleanup_status().complete);
        tokio::time::timeout(Duration::from_secs(1), async {
            while callbacks.lease.closes.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(callbacks.releases.lock().unwrap().is_empty());
        callbacks.resume.add_permits(1);
    });
    assert!(connected.is_err());
    running.clean().await;
    assert_eq!(running.local.admission_rows(), 0);
    assert_eq!(callbacks.lease.closes.load(Ordering::Acquire), 1);
    assert!(!callbacks.releases.lock().unwrap()[0].published);
    assert!(!callbacks.events.lock().unwrap().contains(&"session"));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_lease_registered_after_cancellation_is_closed_while_authorizer_still_runs() {
    let mut running = Running::new(Mode::ReserveAfterCancellation).await;
    let callbacks = running.callbacks.clone();
    let handle = running.handle.clone();
    let (connected, ()) = tokio::join!(running.connect(), async {
        callbacks.entered().await;
        handle.close();
        assert_eq!(callbacks.lease.closes.load(Ordering::Acquire), 0);
        callbacks.resume.add_permits(1);
        callbacks.entered().await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while callbacks.lease.closes.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(callbacks.releases.lock().unwrap().is_empty());
        assert!(!handle.cleanup_status().complete);
        callbacks.resume.add_permits(1);
    });
    assert!(connected.is_err());
    running.clean().await;
    assert_eq!(running.local.admission_rows(), 0);
    assert_eq!(callbacks.lease.closes.load(Ordering::Acquire), 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_request_deadline_cancels_original_callback_without_discarding_its_tail() {
    let mut running = Running::new(Mode::WaitRequestCancellation).await;
    let callbacks = running.callbacks.clone();
    let handle = running.handle.clone();
    let (connected, ()) = tokio::join!(running.connect(), async {
        callbacks.entered().await;
        callbacks.entered().await;
        assert_eq!(
            callbacks.events.lock().unwrap().as_slice(),
            &["request", "request_canceled"]
        );
        assert!(!handle.cleanup_status().complete);
        assert!(callbacks.releases.lock().unwrap().is_empty());
        callbacks.resume.add_permits(1);
    });
    assert!(connected.is_err());
    running.clean().await;
    assert_eq!(running.local.admission_rows(), 0);
    assert_eq!(callbacks.releases.lock().unwrap().len(), 1);
    assert!(callbacks.releases.lock().unwrap()[0].cleanup.complete);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_parent_cancellation_closes_idle_listener_without_a_new_socket() {
    let running = Running::new(Mode::Normal).await;
    running.cancellation.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), running.handle.wait_cleanup())
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    assert!(running.callbacks.events.lock().unwrap().is_empty());
    assert!(
        tokio::net::TcpStream::connect(running.handle.local_address())
            .await
            .is_err()
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_publication_claim_survives_close_during_original_on_session() {
    let mut running = Running::new(Mode::HoldPublication).await;
    let client = running.connect().await.unwrap();
    running.callbacks.entered().await;
    assert_eq!(running.local.admission_rows(), 1);
    running.handle.close();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), running.handle.accept())
            .await
            .is_err()
    );
    assert!(!running.handle.cleanup_status().complete);
    running.callbacks.resume.add_permits(1);
    let server = tokio::time::timeout(Duration::from_secs(2), running.handle.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(server.termination_cause().is_some());
    running.clean().await;
    assert!(server.cleanup_status().complete);
    assert!(running.callbacks.releases.lock().unwrap()[0].published);
    assert_eq!(
        running
            .callbacks
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|&&event| event == "session")
            .count(),
        1
    );
    client.close();
    assert!(client.wait_cleanup().await.complete);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_release_waits_for_real_provider_and_preserves_original_budget() {
    let mut running = Running::new(Mode::HoldRelease).await;
    let client = running.connect().await.unwrap();
    let server = running.handle.accept().await.unwrap();
    running.handle.close();
    running.callbacks.entered().await;
    assert!(server.core_cleanup_status().complete);
    assert!(!server.cleanup_status().complete && !running.handle.cleanup_status().complete);
    let held = running.environment.resource_usage();
    assert!(
        running.callbacks.releases.lock().unwrap()[0]
            .cleanup
            .complete
    );
    running.callbacks.resume.add_permits(1);
    running.clean().await;
    assert!(server.cleanup_status().complete);
    assert!(running.environment.resource_usage().tasks < held.tasks);
    client.close();
    assert!(client.wait_cleanup().await.complete);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_unknown_release_never_retries_or_refunds_original_responsibility() {
    let mut running = Running::new(Mode::UnknownRelease).await;
    let client = running.connect().await.unwrap();
    let server = running.handle.accept().await.unwrap();
    running.handle.close();
    let status = tokio::time::timeout(Duration::from_secs(3), running.handle.wait_cleanup())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.complete && status.cleanup_incomplete);
    assert!(server.core_cleanup_status().complete && !server.cleanup_status().complete);
    // Both peers share this environment. Join the client's physical cleanup
    // before measuring the server's unresolved application responsibility.
    client.close();
    assert!(client.wait_cleanup().await.complete);
    let held = running.environment.resource_usage();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(running.callbacks.releases.lock().unwrap().len(), 1);
    assert_eq!(running.callbacks.lease.closes.load(Ordering::Acquire), 1);
    assert_eq!(running.environment.resource_usage(), held);
    assert!(!server.cleanup_status().complete && !running.handle.cleanup_status().complete);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_registered_handler_plan_dispatches_real_io_and_drains_callbacks() {
    let mut running = Running::new(Mode::Registered).await;
    let client = running.connect().await.unwrap();
    let server = running.handle.accept().await.unwrap();
    // Closing the reusable declaration seals future captures, not this Session.
    running.callbacks.plan.close();
    assert!(server.next_open().await.is_err());
    assert!(
        client
            .open_stream("unknown.kind", Metadata::empty(), 256)
            .await
            .is_err()
    );
    let stream = client
        .open_stream("test.echo", Metadata::empty(), 256)
        .await
        .unwrap();
    stream
        .write(Bytes::from_static(b"authenticated handler"))
        .await
        .unwrap();
    assert_eq!(
        stream.read().await.unwrap().unwrap(),
        Bytes::from_static(b"authenticated handler")
    );
    let second = client
        .open_stream("test.echo", Metadata::empty(), 256)
        .await
        .unwrap();
    assert!(
        client
            .open_stream("test.echo", Metadata::empty(), 256)
            .await
            .is_err()
    );
    second.close_write().await.unwrap();
    assert!(second.read().await.unwrap().is_none());
    second.finish().await.unwrap();
    let drain = running.handle.drain(Duration::from_secs(2)).unwrap();
    assert_eq!(drain.result().outcome, DrainOutcome::Pending);
    stream.close_write().await.unwrap();
    assert!(stream.read().await.unwrap().is_none());
    stream.finish().await.unwrap();
    assert_eq!(drain.wait().await.unwrap().outcome, DrainOutcome::Drained);
    running.clean().await;
    assert!(server.cleanup_status().complete);
    client.close();
    assert!(client.wait_cleanup().await.complete);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_uses_serve_handler_plan_for_authenticated_inbound_streams() {
    let mut running = Running::new(Mode::Normal).await;
    let plan = running
        .environment
        .handler_plan(HandlerPlanOptions {
            streams: StreamDispatch::Registered(vec![RawStreamRegistration {
                kind: "test.echo".into(),
                metadata: None,
                handler: Arc::new(Echo),
            }]),
            application_bytes: 4096,
        })
        .unwrap();
    let client = running.connect_with_plan(plan.clone()).await.unwrap();
    let server = running.handle.accept().await.unwrap();
    plan.close();
    assert!(client.next_open().await.is_err());
    let stream = server
        .open_stream("test.echo", Metadata::empty(), 256)
        .await
        .unwrap();
    stream
        .write(Bytes::from_static(b"client handler"))
        .await
        .unwrap();
    stream.close_write().await.unwrap();
    assert_eq!(
        stream.read().await.unwrap().unwrap(),
        Bytes::from_static(b"client handler")
    );
    assert!(stream.read().await.unwrap().is_none());
    stream.finish().await.unwrap();
    client.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), client.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    running.clean().await;
    assert!(server.cleanup_status().complete);
}

#[derive(Debug)]
struct TypedRegisteredHandler {
    metadata: Metadata,
    allowed: AtomicBool,
    authorizations: AtomicUsize,
    calls: AtomicUsize,
    completed: Semaphore,
    stream: Mutex<Option<crate::TypedMessageStream<Vec<u8>, String>>>,
}
#[async_trait]
impl crate::MessageStreamHandler<Vec<u8>, String> for TypedRegisteredHandler {
    fn application_bytes(&self) -> u64 {
        1024
    }
    async fn authorize(
        &self,
        authentication: ApplicationBinding,
        application: Metadata,
        _: CancellationToken,
        context: crate::ApplicationInvocationContext,
    ) -> Result<StreamAuthorization, ServeError> {
        assert_ne!(authentication.client_identity, [0; 32]);
        assert_eq!(application.encoded(), self.metadata.encoded());
        context.check_cancellation().unwrap();
        self.authorizations.fetch_add(1, Ordering::AcqRel);
        Ok(if self.allowed.load(Ordering::Acquire) {
            StreamAuthorization::Accept {
                receive_window: 256,
            }
        } else {
            StreamAuthorization::Reject
        })
    }
    async fn handle(
        &self,
        stream: crate::TypedMessageStream<Vec<u8>, String>,
        cancellation: CancellationToken,
        context: crate::ApplicationInvocationContext,
    ) -> Result<(), ServeError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        assert_eq!(
            stream.application_metadata().encoded(),
            self.metadata.encoded()
        );
        *self.stream.lock().unwrap() = Some(stream.clone());
        let message = stream
            .receive(Some(context.clone()), &cancellation)
            .await
            .unwrap();
        assert_eq!(message.value.as_deref(), Some([0, 255, 4].as_slice()));
        assert_eq!(
            stream
                .receive(Some(context.clone()), &cancellation)
                .await
                .unwrap()
                .terminal,
            crate::MessageReceiveTerminal::Eof
        );
        assert_eq!(
            stream
                .send(
                    Arc::new("typed reply".to_owned()),
                    Some(context),
                    &cancellation
                )
                .await
                .unwrap(),
            11
        );
        stream.close_write().await.unwrap();
        self.completed.add_permits(1);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registered_typed_stream_dispatch_preserves_authorization_metadata_fin_and_cleanup() {
    let mut running = Running::new(Mode::Normal).await;
    let incoming = crate::MessageDefinition::new([81; 32], "bytes.v1".into(), 32).unwrap();
    let outgoing = crate::MessageDefinition::new([82; 32], "text.v1".into(), 64).unwrap();
    let definition = running
        .environment
        .define_message_stream(
            "test.typed",
            "messages.v1",
            incoming.clone(),
            outgoing.clone(),
        )
        .unwrap();
    let metadata = Metadata::new(
        "example/document",
        7,
        &std::collections::BTreeMap::from([("cursor".into(), Bytes::from_static(&[0, 255, 3]))]),
    )
    .unwrap();
    let handler = Arc::new(TypedRegisteredHandler {
        metadata: metadata.clone(),
        allowed: AtomicBool::new(false),
        authorizations: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
        completed: Semaphore::new(0),
        stream: Mutex::new(None),
    });
    let registration = crate::register_message_stream(
        definition.clone(),
        Arc::new(crate::BytesMessageCodec::new(incoming.clone())),
        Arc::new(crate::UTF8MessageCodec::new(outgoing.clone())),
        crate::MessageStreamOptions::default(),
        handler.clone(),
    )
    .unwrap();
    let plan = running
        .environment
        .handler_plan(HandlerPlanOptions {
            streams: StreamDispatch::Registered(vec![registration]),
            application_bytes: 4096,
        })
        .unwrap();
    let client = running.connect_with_plan(plan.clone()).await.unwrap();
    let server = running.handle.accept().await.unwrap();
    plan.close();
    assert!(client.next_open().await.is_err());
    assert!(
        server
            .open_message_stream(
                definition.clone(),
                metadata.clone(),
                Arc::new(crate::UTF8MessageCodec::new(outgoing.clone())),
                Arc::new(crate::BytesMessageCodec::new(incoming.clone())),
                256,
                crate::MessageStreamOptions::default()
            )
            .await
            .is_err()
    );
    assert_eq!(handler.authorizations.load(Ordering::Acquire), 1);
    assert_eq!(handler.calls.load(Ordering::Acquire), 0);

    handler.allowed.store(true, Ordering::Release);
    let stream = server
        .open_message_stream(
            definition,
            metadata.clone(),
            Arc::new(crate::UTF8MessageCodec::new(outgoing.clone())),
            Arc::new(crate::BytesMessageCodec::new(incoming)),
            256,
            crate::MessageStreamOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(stream.application_metadata().encoded(), metadata.encoded());
    let cancellation = CancellationToken::new();
    assert_eq!(
        stream
            .send(Arc::new(vec![0, 255, 4]), None, &cancellation)
            .await
            .unwrap(),
        3
    );
    stream.close_write().await.unwrap();
    let response = stream.receive(None, &cancellation).await.unwrap();
    assert_eq!(response.definition, outgoing);
    assert_eq!(response.value.as_deref(), Some("typed reply"));
    assert_eq!(
        stream.receive(None, &cancellation).await.unwrap().terminal,
        crate::MessageReceiveTerminal::Eof
    );
    stream.finish().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), handler.completed.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert_eq!(handler.authorizations.load(Ordering::Acquire), 2);
    assert_eq!(handler.calls.load(Ordering::Acquire), 1);
    let original = handler.stream.lock().unwrap().take().unwrap();
    original.finish().await.unwrap();
    original.close();
    stream.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), original.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    assert!(stream.wait_cleanup().await.complete);
    client.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), client.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    running.clean().await;
    assert!(server.cleanup_status().complete);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_connect_handler_plan_fails_before_pool_spend() {
    let mut running = Running::new(Mode::Normal).await;
    let plan = running
        .environment
        .handler_plan(HandlerPlanOptions {
            streams: StreamDispatch::Manual,
            application_bytes: 4096,
        })
        .unwrap();
    plan.close();
    assert!(matches!(
        running.connect_with_plan(plan).await,
        Err(ConnectError::Authorization)
    ));
    assert_eq!(running.pool.rows(), 0);
    running.clean().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_manual_handler_plan_preserves_explicit_accept_and_cleanup() {
    let mut running = Running::new(Mode::Normal).await;
    let plan = running
        .environment
        .handler_plan(HandlerPlanOptions {
            streams: StreamDispatch::Manual,
            application_bytes: 4096,
        })
        .unwrap();
    let client = running.connect_with_plan(plan.clone()).await.unwrap();
    let server = running.handle.accept().await.unwrap();
    plan.close();
    let (outgoing, incoming) = tokio::join!(
        server.open_stream("test.manual", Metadata::empty(), 256),
        async { client.next_open().await.unwrap().accept(256) }
    );
    let outgoing = outgoing.unwrap();
    let incoming = incoming.unwrap();
    outgoing
        .write(Bytes::from_static(b"manual input"))
        .await
        .unwrap();
    assert_eq!(
        incoming.read().await.unwrap().unwrap(),
        Bytes::from_static(b"manual input")
    );
    incoming.close_write().await.unwrap();
    outgoing.close_write().await.unwrap();
    assert!(incoming.read().await.unwrap().is_none());
    assert!(outgoing.read().await.unwrap().is_none());
    outgoing.finish().await.unwrap();
    incoming.finish().await.unwrap();
    client.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), client.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    running.clean().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_close_retains_running_handler_until_callback_exit() {
    let mut running = Running::new(Mode::Normal).await;
    let entered = Arc::new(Semaphore::new(0));
    let resume = Arc::new(Semaphore::new(0));
    let plan = running
        .environment
        .handler_plan(HandlerPlanOptions {
            streams: StreamDispatch::Registered(vec![RawStreamRegistration {
                kind: "test.held".into(),
                metadata: None,
                handler: Arc::new(HeldHandler {
                    entered: entered.clone(),
                    resume: resume.clone(),
                }),
            }]),
            application_bytes: 4096,
        })
        .unwrap();
    let client = running.connect_with_plan(plan).await.unwrap();
    let server = running.handle.accept().await.unwrap();
    let stream = server
        .open_stream("test.held", Metadata::empty(), 256)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    client.close();
    assert!(!client.cleanup_status().complete);
    tokio::task::yield_now().await;
    assert!(client.cleanup_status().pending_callbacks >= 1);
    resume.add_permits(1);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), client.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    let _ = stream.close().await;
    running.clean().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_incomplete_lease_observation_reuses_owner_without_repeating_release() {
    let mut running = Running::new(Mode::Normal).await;
    running
        .callbacks
        .lease
        .clean
        .store(false, Ordering::Release);
    let client = running.connect().await.unwrap();
    let server = running.handle.accept().await.unwrap();
    running.handle.close();
    tokio::time::timeout(Duration::from_secs(3), async {
        while running.callbacks.releases.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!server.cleanup_status().complete);
    assert!(
        running.callbacks.releases.lock().unwrap()[0]
            .cleanup
            .cleanup_incomplete
    );
    running.callbacks.lease.clean.store(true, Ordering::Release);
    running.clean().await;
    assert_eq!(running.callbacks.releases.lock().unwrap().len(), 1);
    assert_eq!(running.callbacks.lease.closes.load(Ordering::Acquire), 1);
    assert!(running.callbacks.lease.observations.load(Ordering::Acquire) >= 2);
    client.close();
    assert!(client.wait_cleanup().await.complete);
}
