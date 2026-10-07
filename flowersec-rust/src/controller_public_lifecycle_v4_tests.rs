//! Public managed lifecycles over real native TLS/WSS connections and journals.
use super::*;
use crate::{
    ControllerNotificationEvent, ControllerNotificationGap, ControllerNotificationObservation,
    ControllerNotificationObserver, ControllerNotificationOptions,
    ControllerNotificationSourcePhase, ControllerNotificationSubscription,
    MaterialConnectionController, MaterialControllerError, MaterialSessionReplaceOptions,
    MaterialSessionRetirement, MaterialSourceOwnership, NotificationDropPolicy, NotificationPeer,
    ServiceError, ServiceFailure,
};
use std::sync::{Mutex, atomic::AtomicUsize};

fn signed_field(raw: &[u8], schema: &str, field: u64, value: Vec<u8>, seed: u8) -> Vec<u8> {
    let parsed = crate::codec_v4::decode_context(
        raw,
        schema,
        crate::codec_v4::Limits {
            bytes: 65536,
            nodes: 16384,
        },
        None,
        crate::codec_v4::Context::with_activation_source(ActivationSource::PreauthorizedPool),
    )
    .unwrap();
    let mut fields = Vec::new();
    let mut children = parsed.children().unwrap();
    while let Some(id) = children.next() {
        let id = id.unwrap().uint().unwrap();
        let child = children.next().unwrap().unwrap();
        fields.push((
            id,
            if id == field {
                value.clone()
            } else {
                child.raw().to_vec()
            },
        ));
    }
    fields.pop();
    crate::codec_v4::tests::sign(
        schema,
        &fields,
        &ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap(),
    )
}

fn copy_pool_credential(value: &PoolCredentialBytes) -> PoolCredentialBytes {
    PoolCredentialBytes {
        artifact: value.artifact.clone(),
        client_certificate: value.client_certificate.clone(),
        server_certificate: value.server_certificate.clone(),
        activation: value.activation.clone(),
    }
}

struct Remote {
    session: Session,
    services: crate::ServicePeer,
    notifications: NotificationPeer,
    echo: Arc<ControllerEcho>,
    pump: tokio::task::JoinHandle<()>,
}
impl Remote {
    async fn publish(&self, contract: &ServiceContract, value: u8) {
        self.notifications
            .publish_encoded(
                contract,
                &[value],
                Duration::from_secs(3),
                None,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
    }
    async fn close(self) {
        self.echo.release.add_permits(8);
        self.notifications.close();
        self.services.close();
        self.session.close();
        tokio::time::timeout(Duration::from_secs(3), self.pump)
            .await
            .unwrap()
            .unwrap();
    }
}
struct Harness {
    _environment: Arc<TransportEnvironment>,
    pool: StoreFixture,
    source: crate::ConnectionMaterialSource,
    controller: MaterialConnectionController,
    initializer: Arc<NativeCandidateInitializer>,
    contract: ServiceContract,
    codec: Arc<ControllerNotificationLockOrderCodec>,
    echo_method: crate::MethodDefinition,
    options: crate::MaterialControllerOptions,
    credentials: Vec<PoolCredentialBytes>,
    identity: crate::IdentityKeys,
    peers: Vec<tokio::task::JoinHandle<Remote>>,
}
impl Harness {
    async fn new(count: u8, ownership: MaterialSourceOwnership) -> Self {
        let server_keys = LocalKeys::generate(Profile::X25519).unwrap();
        let ed = server_keys.ed_public();
        // Both endpoints live in this fixture's Environment. Each simultaneous
        // client/server pair needs its own session bytes, items and timers.
        let pairs = u64::from(count.max(2));
        let defaults = crate::TransportEnvironmentOptions::default();
        let environment = TransportEnvironment::with_options(crate::TransportEnvironmentOptions {
            application_executor: crate::ApplicationExecutorConfig {
                execution: true,
                ..Default::default()
            },
            clock: Some(crate::environment_v4::tests::TestClock::new(1000, 1010)),
            tenant_limits: crate::environment_v4::ResourceLimits {
                sdk_bytes: pairs * (32 << 20),
                items: pairs * 16_384,
                timers: pairs * 4096,
                ..defaults.tenant_limits
            },
            root_limits: crate::environment_v4::ResourceLimits {
                sdk_bytes: 128 << 20,
                ..defaults.root_limits
            },
            session_limits: crate::environment_v4::ResourceLimits {
                sdk_bytes: 16 << 20,
                ..defaults.session_limits
            },
            ..defaults
        })
        .unwrap();
        let mut fixture = Fixture::with_identity_and_environment(
            ActivationSource::PreauthorizedPool,
            Profile::X25519.name(),
            Some([
                (server_keys.dh_public(), &ed),
                (server_keys.dh_public(), &ed),
            ]),
            environment,
        );
        fixture.enable_execution_recovery();
        let keys = fixture
            .environment
            .identity_keys(Profile::X25519.name())
            .unwrap();
        fixture.set_client_keys(&keys);
        let pool = StoreFixture::new(&fixture);
        let (tls, ca, _) = tls_identity();
        let mut peers = Vec::new();
        let mut credentials = Vec::new();
        for index in 0..count {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            // Each host-issued credential has its own signed lease and activation.
            let lease = [30 + index; 16];
            fixture.artifact = signed_field(&fixture.artifact, "Artifact", 6, b(&lease), 12);
            fixture.set_wss_route(listener.local_addr().unwrap().port(), None);
            fixture.activation = signed_field(
                &fixture.activation,
                "ActivationAuthorization",
                5,
                b(&lease),
                13,
            );
            peers.push(Peer {
                listener,
                tls: tls.clone(),
                admission: fixture.reserve().unwrap(),
                keys: server_keys.clone(),
                artifact: fixture.artifact.clone(),
                certificate: fixture.server.clone(),
            });
            credentials.push(PoolCredentialBytes {
                artifact: fixture.artifact.clone(),
                client_certificate: fixture.client.clone(),
                server_certificate: fixture.server.clone(),
                activation: fixture.activation.clone(),
            });
        }
        let environment = Arc::new(fixture.environment);
        let source = crate::LocalDirectMaterialSource::preauthorized_pool(
            &environment,
            crate::PreauthorizedPoolSourceConfiguration {
                namespaces: vec![Arc::new(Namespace::new(fixture.verifier))],
                identity: keys.clone(),
                credentials: credentials.iter().map(copy_pool_credential).collect(),
                spend_ledger: pool.store.clone(),
                application_profile: crate::ApplicationProfile::Execution,
                provider: WssConnectOptions {
                    binding_mode: BindingMode::AuthenticatedContext,
                    remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                    origin: None,
                    ca_certificates_der: vec![ca],
                    timeout: Duration::from_secs(3),
                    publication_timeout: Duration::from_secs(2),
                    queue_messages: 2,
                    prepare_bytes: 65536,
                    native_runtime_bytes: 1 << 20,
                },
            },
        )
        .unwrap();
        let (contract, definition, binding, registration, codec, query) =
            controller_notification_lock_order_service(&environment);
        let (echo_contract, echo_definition, echo_method, echo_binding) =
            controller_echo_service(&environment);
        let peers = peers
            .into_iter()
            .map(|peer| {
                let environment = environment.clone();
                let registration = registration.clone();
                let echo_contract = echo_contract.clone();
                tokio::spawn(async move {
                    let (socket, engine) = peer.handshake().await;
                    let (session, pump) = peer_session(&environment, socket, engine);
                    let echo = Arc::new(ControllerEcho::default());
                    let services = session
                        .services(
                            query,
                            vec![crate::UnaryServiceRegistration {
                                contract: echo_contract,
                                offer: None,
                                offer_window_ms: None,
                                query_allowed: true,
                                resident: false,
                                handler: echo.clone(),
                                execution: None,
                                caller: None,
                            }],
                        )
                        .unwrap();
                    let notifications = session.notifications(vec![registration]).unwrap();
                    services.attach_notifications(&notifications).unwrap();
                    Remote {
                        session,
                        services,
                        notifications,
                        echo,
                        pump,
                    }
                })
            })
            .collect();
        let handler_plan = environment
            .handler_plan(crate::HandlerPlanOptions {
                streams: crate::StreamDispatch::Manual,
                application_bytes: 65536,
            })
            .unwrap()
            .with_services(crate::ServicePlan {
                query,
                unary: vec![],
                notifications: vec![registration],
                streaming: vec![],
                resume: vec![],
                result_read: None,
                management: None,
            })
            .unwrap();
        let initializer = Arc::new(NativeCandidateInitializer {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            calls: AtomicUsize::new(0),
        });
        let mut options = native_controller_options(
            source.clone(),
            ownership,
            CancellationToken::new(),
            Some(initializer.clone()),
        );
        options.retain_replaced_for = Duration::ZERO;
        options.request.handlers = Some((
            handler_plan,
            crate::ApplicationLimits {
                ordinary_callbacks: 4,
                ordinary_callback_bytes: 65536,
                control_callback_bytes: 65536,
            },
        ));
        options.managed_services = vec![crate::ManagedServiceConfiguration::new(
            definition,
            query,
            vec![binding],
            Duration::from_secs(2),
        )];
        options
            .managed_services
            .push(crate::ManagedServiceConfiguration::new(
                echo_definition,
                query,
                vec![echo_binding],
                Duration::from_secs(2),
            ));
        let controller =
            MaterialConnectionController::new(environment.clone(), options.clone()).unwrap();
        Self {
            _environment: environment,
            pool,
            source,
            controller,
            initializer,
            contract,
            codec,
            echo_method,
            options,
            credentials,
            identity: keys,
            peers,
        }
    }
    async fn initialized(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.initializer.entered.acquire())
            .await
            .unwrap_or_else(|e| panic!("initializer {e}: {:?}", self.controller.progress()))
            .unwrap()
            .forget();
    }
    async fn current(&self, generation: u64) -> crate::MaterialConnectionSnapshot {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.controller
                .wait_current(generation, &CancellationToken::new()),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn remote(&mut self) -> Remote {
        tokio::time::timeout(Duration::from_secs(5), self.peers.remove(0))
            .await
            .unwrap()
            .unwrap()
    }
    async fn close(&self) {
        self.controller.close();
        assert!(self.controller.wait_cleanup().await.complete);
        self.source.close();
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.initializer.release.add_permits(8);
        self.controller.close();
        self.source.close();
        for peer in &self.peers {
            peer.abort();
        }
    }
}
#[derive(Debug, Default)]
struct Events {
    values: Mutex<Vec<(u8, u64, ControllerNotificationSourcePhase)>>,
    gaps: Mutex<Vec<ControllerNotificationGap>>,
}
#[async_trait::async_trait]
impl ControllerNotificationObserver<u8> for Events {
    fn application_bytes(&self) -> u64 {
        1024
    }
    async fn observe(
        &self,
        event: ControllerNotificationEvent<u8>,
    ) -> std::result::Result<(), ServiceError> {
        match event {
            ControllerNotificationEvent::Notification {
                value,
                source_generation,
                source_phase,
                ..
            } => self
                .values
                .lock()
                .unwrap()
                .push((value, source_generation, source_phase)),
            ControllerNotificationEvent::ObservationGap { gap } => {
                self.gaps.lock().unwrap().push(gap)
            }
        }
        Ok(())
    }
}
async fn until(predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct ControllerEcho {
    requests: Mutex<Vec<Vec<u8>>>,
    release: Semaphore,
}
impl Default for ControllerEcho {
    fn default() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            release: Semaphore::new(0),
        }
    }
}
#[async_trait::async_trait]
impl crate::UnaryServiceHandler for ControllerEcho {
    async fn authorize(
        &self,
        _: crate::UnaryRequestContext,
    ) -> std::result::Result<(), ServiceError> {
        Ok(())
    }
    async fn handle(
        &self,
        _: crate::UnaryRequestContext,
        request: &[u8],
    ) -> std::result::Result<crate::UnaryResponse, ServiceError> {
        self.requests.lock().unwrap().push(request.to_vec());
        self.release.acquire().await.unwrap().forget();
        Ok(crate::UnaryResponse {
            payload: request.to_vec(),
            application_error_code: None,
        })
    }
}

fn controller_echo_service(
    environment: &TransportEnvironment,
) -> (
    ServiceContract,
    crate::ServiceDefinition,
    crate::MethodDefinition,
    crate::ServiceBindingOptions,
) {
    use crate::codec_v4::tests::{encode_map, t, u};
    let message = crate::MessageDefinition::new([11; 32], "bytes.v1".into(), 128).unwrap();
    let method = crate::MethodDefinition::new(crate::MethodDefinitionOptions {
        type_id: 101,
        shape: crate::ServiceShape::Unary,
        semantics: crate::ServiceSemantics::Transient,
        request: message.clone(),
        response: Some(message),
        response_revision: "bytes.v1".into(),
        request_max_bytes: 128,
        min_response_limit_bytes: 1,
        max_response_bytes: 128,
        require_durable: false,
        checkpoint_format: None,
        restart_flush_deadline_ms: None,
        streaming: None,
        content: None,
        errors: Vec::new(),
    })
    .unwrap();
    let contract = ServiceContract::capture(
        environment,
        &encode_map(&[
            (0, t("example/controller")),
            (1, u(101)),
            (2, u(0)),
            (3, u(0)),
            (6, t("bytes.v1")),
            (7, t("bytes.v1")),
            (8, u(1)),
            (9, u(1)),
            (10, u(128)),
            (11, u(5000)),
            (12, u(5000)),
            (21, vec![0xf4]),
            (23, u(128)),
            (27, vec![0x80]),
        ]),
    )
    .unwrap();
    let definition = crate::ServiceDefinition::new(
        "example/controller".into(),
        vec![crate::ServiceMethod {
            name: "Echo".into(),
            export_name: "echo".into(),
            method: method.clone(),
        }],
    )
    .unwrap();
    let binding = crate::ServiceBindingOptions {
        method: method.clone(),
        acceptance: crate::ContractAcceptance::exact(),
        response_limit: crate::ResponseLimitPolicy::FollowContractMaximum,
        execution_reference_identity: None,
        streaming: None,
        resume: None,
    };
    (contract, definition, method, binding)
}

fn queued_options() -> crate::UnaryPrepareOptions {
    crate::UnaryPrepareOptions {
        timeout: Duration::from_secs(3),
        admission: crate::ServiceAdmission::Queue,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_pool_generation_capture_refusal_preserves_new_route() {
    let mut test = Harness::new(2, MaterialSourceOwnership::Borrowed).await;
    test.initialized().await;
    test.initializer.release.add_permits(1);
    test.current(0).await;
    let original = test.remote().await;
    let credential = copy_pool_credential(&test.credentials[1]);
    test.source
        .replace_pool_generation(
            vec![copy_pool_credential(&credential)],
            test.identity.clone(),
        )
        .unwrap();
    let mut invalid = credential;
    invalid.client_certificate[0] ^= 1;
    assert_eq!(
        test.source
            .replace_pool_generation(vec![invalid], test.identity.clone())
            .unwrap_err(),
        crate::MaterialSourceError::MaterialUnavailable
    );
    assert_eq!(
        test.source
            .replace_pool_generation(Vec::new(), test.identity.clone())
            .unwrap_err(),
        crate::MaterialSourceError::ConfigurationCapacity
    );
    assert_eq!(test.pool.rows(), 1);
    test.initializer.release.add_permits(1);
    let replaced = test
        .controller
        .replace_session_with_options(
            MaterialSessionReplaceOptions {
                retirement: MaterialSessionRetirement::Retain {
                    retain_until_ms: 4000,
                },
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(replaced.current.generation, 2);
    let current = test.remote().await;
    let service = test.controller.service("example/controller").unwrap();
    let operation = service
        .prepare_unary(
            &test.echo_method,
            &b"replacement-material".to_vec(),
            Arc::new(crate::BytesMessageCodec::new(
                test.echo_method.options().request.clone(),
            )),
            Arc::new(crate::BytesMessageCodec::new(
                test.echo_method.options().response.clone().unwrap(),
            )),
            queued_options(),
        )
        .unwrap();
    test.source.close();
    current.echo.release.add_permits(1);
    operation.start().unwrap();
    assert_eq!(
        operation
            .wait_encoded(CancellationToken::new())
            .await
            .unwrap()
            .payload,
        b"replacement-material"
    );
    assert!(original.echo.requests.lock().unwrap().is_empty());
    assert_eq!(
        *current.echo.requests.lock().unwrap(),
        vec![b"replacement-material".to_vec()]
    );
    assert_eq!(test.pool.rows(), 2);
    operation.close();
    assert!(operation.wait_cleanup().await.complete);
    test.controller.close();
    original.close().await;
    current.close().await;
    test.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_queued_unary_reselects_once_and_fixed_capture_keeps_original() {
    let mut test = Harness::new(2, MaterialSourceOwnership::Borrowed).await;
    test.initialized().await;
    test.initializer.release.add_permits(1);
    let first = test.current(0).await;
    let first_remote = test.remote().await;
    let service = test.controller.service("example/controller").unwrap();
    let request = Arc::new(crate::BytesMessageCodec::new(
        test.echo_method.options().request.clone(),
    ));
    let response = Arc::new(crate::BytesMessageCodec::new(
        test.echo_method.options().response.clone().unwrap(),
    ));
    let queued = service
        .prepare_unary(
            &test.echo_method,
            &b"queued".to_vec(),
            request.clone(),
            response.clone(),
            queued_options(),
        )
        .unwrap();
    let captured = service.capture_method(&test.echo_method).unwrap();
    let fixed = captured
        .client()
        .prepare_unary(
            &test.echo_method,
            &b"fixed".to_vec(),
            request,
            response,
            queued_options(),
        )
        .unwrap();
    assert_eq!(queued.status(), crate::OperationStatus::NotStarted);
    assert!(first_remote.echo.requests.lock().unwrap().is_empty());
    let cancellation = CancellationToken::new();
    let mut replacing = Box::pin(test.controller.replace_session_with_options(
        MaterialSessionReplaceOptions {
            retirement: MaterialSessionRetirement::Retain {
                retain_until_ms: 4000,
            },
        },
        &cancellation,
    ));
    tokio::select! { _ = test.initialized() => {}, result = &mut replacing => panic!("premature {result:?}") }
    assert_eq!(
        service
            .capture_method(&test.echo_method)
            .unwrap()
            .generation(),
        1
    );
    test.initializer.release.add_permits(1);
    assert_eq!(replacing.await.unwrap().current.generation, 2);
    let second_remote = test.remote().await;
    assert_eq!(captured.generation(), 1);
    assert_eq!(
        service
            .capture_method(&test.echo_method)
            .unwrap()
            .generation(),
        2
    );
    assert_eq!(
        queued.try_start().unwrap(),
        crate::ServiceStartResult::Admitted
    );
    queued.start().unwrap();
    fixed.start_on(&first.session).unwrap();
    until(|| {
        first_remote.echo.requests.lock().unwrap().len() == 1
            && second_remote.echo.requests.lock().unwrap().len() == 1
    })
    .await;
    assert_eq!(
        *first_remote.echo.requests.lock().unwrap(),
        vec![b"fixed".to_vec()]
    );
    assert_eq!(
        *second_remote.echo.requests.lock().unwrap(),
        vec![b"queued".to_vec()]
    );
    let canceled = CancellationToken::new();
    canceled.cancel();
    assert_eq!(
        queued.wait_encoded(canceled).await.unwrap_err().0,
        ServiceFailure::Canceled
    );
    assert!(queued.progress().started);
    first_remote.echo.release.add_permits(1);
    second_remote.echo.release.add_permits(1);
    assert_eq!(
        queued
            .wait_encoded(CancellationToken::new())
            .await
            .unwrap()
            .payload,
        b"queued"
    );
    assert_eq!(
        fixed
            .wait_encoded(CancellationToken::new())
            .await
            .unwrap()
            .payload,
        b"fixed"
    );
    assert_eq!(test.pool.rows(), 2);
    queued.close();
    fixed.close();
    assert!(queued.wait_cleanup().await.complete);
    assert!(fixed.wait_cleanup().await.complete);
    test.controller.close();
    first_remote.close().await;
    second_remote.close().await;
    test.close().await;
}

struct ControllerAsyncBytes {
    definition: crate::MessageDefinition,
    encodes: AtomicUsize,
    decodes: AtomicUsize,
}
#[async_trait::async_trait]
impl crate::AsyncMessageCodec<Vec<u8>> for ControllerAsyncBytes {
    fn definition(&self) -> &crate::MessageDefinition {
        &self.definition
    }
    fn application_bytes(&self) -> u64 {
        1024
    }
    async fn encode(
        &self,
        value: &Vec<u8>,
        _: crate::ApplicationInvocationContext,
    ) -> std::result::Result<Vec<u8>, ServiceError> {
        self.encodes.fetch_add(1, Ordering::AcqRel);
        Ok(value.clone())
    }
    async fn decode(
        &self,
        value: &[u8],
        _: crate::ApplicationInvocationContext,
    ) -> std::result::Result<Vec<u8>, ServiceError> {
        self.decodes.fetch_add(1, Ordering::AcqRel);
        Ok(value.to_vec())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_mapped_async_unary_tracks_secondary_generation_and_cleanup() {
    let mut test = Harness::new(3, MaterialSourceOwnership::Borrowed).await;
    test.initialized().await;
    test.initializer.release.add_permits(1);
    test.current(0).await;
    let primary_remote = test.remote().await;
    let mut options = test.options.clone();
    options.initialize_session = None;
    let secondary = MaterialConnectionController::new(test._environment.clone(), options).unwrap();
    secondary
        .wait_current(0, &CancellationToken::new())
        .await
        .unwrap();
    let old_remote = test.remote().await;
    let selector = || test.controller.service("example/controller").unwrap();
    assert!(matches!(
        selector().with_method_source(secondary.clone(), vec![]),
        Err(MaterialControllerError::Configuration)
    ));
    assert!(matches!(
        selector().with_method_source(
            secondary.clone(),
            vec![test.echo_method.clone(), test.echo_method.clone()]
        ),
        Err(MaterialControllerError::Configuration)
    ));
    let mapped = selector()
        .with_method_source(secondary.clone(), vec![test.echo_method.clone()])
        .unwrap();
    let already_mapped = selector()
        .with_method_source(secondary.clone(), vec![test.echo_method.clone()])
        .unwrap();
    assert!(matches!(
        already_mapped.with_method_source(secondary.clone(), vec![test.echo_method.clone()]),
        Err(MaterialControllerError::Configuration)
    ));
    let codec = Arc::new(ControllerAsyncBytes {
        definition: test.echo_method.options().request.clone(),
        encodes: AtomicUsize::new(0),
        decodes: AtomicUsize::new(0),
    });
    let operation = mapped
        .prepare_unary_async(
            &test.echo_method,
            Arc::new(b"secondary".to_vec()),
            codec.clone(),
            codec.clone(),
            queued_options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(codec.encodes.load(Ordering::Acquire), 1);
    assert!(old_remote.echo.requests.lock().unwrap().is_empty());
    secondary
        .replace_session_with_options(
            MaterialSessionReplaceOptions {
                retirement: MaterialSessionRetirement::Retain {
                    retain_until_ms: 4000,
                },
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "secondary replacement {error:?}; progress={:?}; resources={:?}; spent={}",
                secondary.progress(),
                test._environment.resource_usage(),
                test.pool.rows(),
            )
        });
    let new_remote = test.remote().await;
    assert_eq!(mapped.capture().unwrap().generation(), 1);
    assert_eq!(
        mapped
            .capture_method(&test.echo_method)
            .unwrap()
            .generation(),
        2
    );
    operation.start().unwrap();
    operation.start().unwrap();
    until(|| new_remote.echo.requests.lock().unwrap().len() == 1).await;
    assert!(primary_remote.echo.requests.lock().unwrap().is_empty());
    assert!(old_remote.echo.requests.lock().unwrap().is_empty());
    assert_eq!(
        *new_remote.echo.requests.lock().unwrap(),
        vec![b"secondary".to_vec()]
    );
    new_remote.echo.release.add_permits(1);
    let result = operation
        .wait_typed(CancellationToken::new())
        .await
        .unwrap();
    assert!(
        matches!(result.value, crate::TypedUnaryValue::Response(ref bytes) if bytes == b"secondary")
    );
    drop(result);
    assert_eq!(codec.encodes.load(Ordering::Acquire), 1);
    assert_eq!(codec.decodes.load(Ordering::Acquire), 1);
    operation.close();
    assert!(operation.wait_cleanup().await.complete);
    secondary.close();
    assert!(matches!(
        mapped.capture_method(&test.echo_method),
        Err(MaterialControllerError::NotReady)
    ));
    old_remote.close().await;
    new_remote.close().await;
    assert!(secondary.wait_cleanup().await.complete);
    assert!(!test.source.is_closed());
    assert_eq!(test.pool.rows(), 3);
    test.controller.close();
    primary_remote.close().await;
    test.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_retained_replacement_reports_original_notification_generations() {
    let mut test = Harness::new(2, MaterialSourceOwnership::Borrowed).await;
    let service = test.controller.service("example/lock-order").unwrap();
    assert!(matches!(
        test.controller.service("missing"),
        Err(MaterialControllerError::ServiceUnavailable)
    ));
    let observer = Arc::new(Events::default());
    let subscription = service
        .subscribe_notification_events_with_options(
            test.contract.clone(),
            test.codec.clone(),
            NotificationDropPolicy::KeepLatest,
            observer.clone(),
            ControllerNotificationOptions {
                observation: ControllerNotificationObservation::DrainAware,
                max_observed_sessions: 2,
            },
        )
        .unwrap();
    let cloned = subscription.clone();
    assert!(!subscription.cleanup_status().complete);
    test.initialized().await;
    assert!(matches!(
        service.capture(),
        Err(MaterialControllerError::NotReady)
    ));
    test.initializer.release.add_permits(1);
    let first = test.current(0).await;
    let first_remote = test.remote().await;
    until(|| subscription.snapshot().attached).await;
    assert_eq!(service.capture().unwrap().generation(), 1);
    first_remote.publish(&test.contract, 1).await;
    until(|| observer.values.lock().unwrap().len() == 1).await;
    let cancellation = CancellationToken::new();
    let mut replacement = Box::pin(test.controller.replace_session_with_options(
        MaterialSessionReplaceOptions {
            retirement: MaterialSessionRetirement::Retain {
                retain_until_ms: 4000,
            },
        },
        &cancellation,
    ));
    tokio::select! { _ = test.initialized() => {}, result = &mut replacement => panic!("premature {result:?}") }
    assert!(
        test.controller
            .capture_session()
            .unwrap()
            .same_original(&first.session)
    );
    assert_eq!(test.controller.current().unwrap().generation, 1);
    assert_eq!(
        test.controller
            .replace_session(&CancellationToken::new())
            .await
            .unwrap_err(),
        MaterialControllerError::Capacity
    );
    let canceled = CancellationToken::new();
    canceled.cancel();
    assert_eq!(
        test.controller
            .replace_session(&canceled)
            .await
            .unwrap_err(),
        MaterialControllerError::Canceled
    );
    test.initializer.release.add_permits(1);
    let replaced = replacement.await.unwrap();
    assert_eq!(replaced.current.generation, 2);
    assert!(
        replaced
            .previous
            .as_ref()
            .unwrap()
            .same_original(&first.session)
    );
    assert!(!replaced.previous_cleanup_status().complete);
    assert!(test.controller.progress().retained_session);
    let second_remote = test.remote().await;
    until(|| {
        subscription.snapshot().generation == 2 && subscription.snapshot().observed_sources == 2
    })
    .await;
    assert_eq!(service.capture().unwrap().generation(), 2);
    first_remote.publish(&test.contract, 2).await;
    second_remote.publish(&test.contract, 3).await;
    until(|| observer.values.lock().unwrap().len() == 3).await;
    let values = observer.values.lock().unwrap().clone();
    assert!(values.contains(&(1, 1, ControllerNotificationSourcePhase::Current)));
    assert!(values.contains(&(2, 1, ControllerNotificationSourcePhase::Retained)));
    assert!(values.contains(&(3, 2, ControllerNotificationSourcePhase::Current)));
    assert_eq!(test.pool.rows(), 2);
    cloned.close();
    assert!(
        subscription
            .wait_closed(Duration::from_secs(3))
            .await
            .complete
    );
    assert!(subscription.snapshot().closing);
    test.controller.close();
    assert!(!test.source.is_closed());
    first_remote.close().await;
    second_remote.close().await;
    test.close().await;
    assert!(matches!(
        service.capture(),
        Err(MaterialControllerError::Closed)
    ));
    assert!(matches!(
        test.controller
            .wait_current(2, &CancellationToken::new())
            .await,
        Err(MaterialControllerError::Closed)
    ));
    assert!(matches!(
        test.controller
            .replace_session(&CancellationToken::new())
            .await,
        Err(MaterialControllerError::Closed)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_canceled_initializer_disables_dispatch_and_owned_cleanup_waits_for_exit()
{
    let mut test = Harness::new(2, MaterialSourceOwnership::Owned).await;
    test.initialized().await;
    test.initializer.release.add_permits(1);
    let first = test.current(0).await;
    let first_remote = test.remote().await;
    let canceled = CancellationToken::new();
    let mut replacement = Box::pin(test.controller.replace_session(&canceled));
    tokio::select! { _ = test.initialized() => {}, result = &mut replacement => panic!("premature {result:?}") }
    canceled.cancel();
    assert_eq!(
        replacement.await.unwrap_err(),
        MaterialControllerError::Canceled
    );
    until(|| {
        test.controller.progress().failure == Some(MaterialControllerError::InitializationUnknown)
    })
    .await;
    assert!(matches!(
        test.controller.capture_session(),
        Err(MaterialControllerError::InitializationUnknown)
    ));
    assert!(test.controller.current().is_none());
    assert!(first.session.termination_cause().is_none());
    let second_remote = test.remote().await;
    test.controller.close();
    assert!(!test.controller.cleanup_status().complete);
    assert_eq!(test.controller.progress().generation, 1);
    test.initializer.release.add_permits(1);
    first_remote.close().await;
    second_remote.close().await;
    assert!(test.controller.wait_cleanup().await.complete);
    assert!(test.source.is_closed());
    assert_eq!(test.initializer.calls.load(Ordering::Acquire), 2);
    assert_eq!(test.pool.rows(), 2);
    test.close().await;
}

#[derive(Debug)]
struct HeldObserver {
    entered: Semaphore,
    release: Semaphore,
    subscription: Mutex<Option<ControllerNotificationSubscription<u8>>>,
    self_waits: Mutex<Vec<crate::CleanupStatus>>,
    values: Mutex<Vec<u8>>,
}
#[async_trait::async_trait]
impl crate::ServiceNotificationObserver<u8> for HeldObserver {
    fn application_bytes(&self) -> u64 {
        1024
    }
    async fn observe(
        &self,
        value: u8,
        _: crate::NotificationContext,
    ) -> std::result::Result<(), ServiceError> {
        self.values.lock().unwrap().push(value);
        let subscription = self.subscription.lock().unwrap().clone().unwrap();
        let status = subscription.wait_cleanup(Duration::from_secs(2)).await;
        self.self_waits.lock().unwrap().push(status);
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        Err(ServiceError(ServiceFailure::Canceled))
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_notification_cleanup_keeps_original_application_callback() {
    let mut test = Harness::new(1, MaterialSourceOwnership::Borrowed).await;
    test.initialized().await;
    test.initializer.release.add_permits(1);
    test.current(0).await;
    let remote = test.remote().await;
    let service = test.controller.service("example/lock-order").unwrap();
    let observer = Arc::new(HeldObserver {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        subscription: Mutex::new(None),
        self_waits: Mutex::new(Vec::new()),
        values: Mutex::new(Vec::new()),
    });
    assert!(matches!(
        service.subscribe_notification_with_options(
            test.contract.clone(),
            test.codec.clone(),
            NotificationDropPolicy::DropNewest,
            observer.clone(),
            ControllerNotificationOptions {
                observation: ControllerNotificationObservation::CurrentOnly,
                max_observed_sessions: 0
            }
        ),
        Err(crate::ControllerServiceError::Controller(
            MaterialControllerError::Configuration
        ))
    ));
    let subscription = service
        .subscribe_notification(
            test.contract.clone(),
            test.codec.clone(),
            NotificationDropPolicy::DropNewest,
            observer.clone(),
        )
        .unwrap();
    *observer.subscription.lock().unwrap() = Some(subscription.clone());
    until(|| subscription.snapshot().attached).await;
    remote.publish(&test.contract, 7).await;
    tokio::time::timeout(Duration::from_secs(3), observer.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert!(!observer.self_waits.lock().unwrap()[0].complete);
    subscription.close();
    subscription.close();
    assert!(
        !subscription
            .wait_cleanup(Duration::from_millis(10))
            .await
            .complete
    );
    test.controller.close();
    assert!(!test.controller.cleanup_status().complete);
    observer.release.add_permits(1);
    assert!(
        subscription
            .wait_cleanup(Duration::from_secs(3))
            .await
            .complete
    );
    observer.subscription.lock().unwrap().take();
    assert_eq!(*observer.values.lock().unwrap(), [7]);
    remote.close().await;
    test.close().await;
}

#[derive(Debug)]
struct DrainDecoder {
    definition: MessageDefinition,
    entered: Semaphore,
    blocked: Mutex<bool>,
    changed: std::sync::Condvar,
}
impl DrainDecoder {
    fn release(&self) {
        *self.blocked.lock().unwrap() = false;
        self.changed.notify_all();
    }
}
impl MessageCodec<u8> for DrainDecoder {
    fn definition(&self) -> &MessageDefinition {
        &self.definition
    }
    fn encode(&self, value: &u8, output: &mut [u8]) -> std::result::Result<usize, ServiceError> {
        output[0] = *value;
        Ok(1)
    }
    fn decode(&self, input: &[u8]) -> std::result::Result<u8, ServiceError> {
        if input[0] == 8 {
            self.entered.add_permits(1);
            let mut blocked = self.blocked.lock().unwrap();
            while *blocked {
                let waited = self
                    .changed
                    .wait_timeout(blocked, Duration::from_secs(5))
                    .unwrap();
                blocked = waited.0;
                if waited.1.timed_out() && *blocked {
                    return Err(ServiceError(ServiceFailure::DeadlineExceeded));
                }
            }
        }
        Ok(input[0])
    }
}
struct ReleaseDecoder(Arc<DrainDecoder>);
impl Drop for ReleaseDecoder {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_drain_replacement_keeps_original_stream_and_notification_source() {
    let mut test = Harness::new(2, MaterialSourceOwnership::Borrowed).await;
    test.initialized().await;
    test.initializer.release.add_permits(1);
    let first = test.current(0).await;
    let first_remote = test.remote().await;
    let service = test.controller.service("example/lock-order").unwrap();
    let observer = Arc::new(Events::default());
    let decoder = Arc::new(DrainDecoder {
        definition: test.codec.definition.clone(),
        entered: Semaphore::new(0),
        blocked: Mutex::new(true),
        changed: std::sync::Condvar::new(),
    });
    let _release = ReleaseDecoder(decoder.clone());
    let subscription = service
        .subscribe_notification_events_with_options(
            test.contract.clone(),
            decoder.clone(),
            NotificationDropPolicy::DropNewest,
            observer.clone(),
            ControllerNotificationOptions {
                observation: ControllerNotificationObservation::DrainAware,
                max_observed_sessions: 2,
            },
        )
        .unwrap();
    until(|| subscription.snapshot().attached).await;
    let (opened, accepted) = tokio::join!(
        first
            .session
            .open_stream("example.drain", Metadata::empty(), 65536),
        async {
            first_remote
                .session
                .next_open()
                .await
                .unwrap()
                .accept(65536)
                .unwrap()
        }
    );
    let opened = opened.unwrap();
    first_remote.publish(&test.contract, 8).await;
    tokio::time::timeout(Duration::from_secs(3), decoder.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let cancel = CancellationToken::new();
    let mut replacement = Box::pin(
        test.controller
            .replace_session_with_options(MaterialSessionReplaceOptions::default(), &cancel),
    );
    tokio::select! { _ = test.initialized() => {}, result = &mut replacement => panic!("premature {result:?}") }
    test.initializer.release.add_permits(1);
    let replacement = replacement.await.unwrap();
    assert_eq!(replacement.retirement, MaterialSessionRetirement::Drain);
    assert_eq!(replacement.current.generation, 2);
    assert!(!replacement.previous_cleanup_status().complete);
    let second_remote = test.remote().await;
    until(|| subscription.snapshot().generation == 2).await;
    opened
        .write(Bytes::from_static(b"original stream after replacement"))
        .await
        .unwrap();
    assert_eq!(
        accepted.read().await.unwrap().unwrap().as_ref(),
        b"original stream after replacement"
    );
    until(|| first.session.application_draining()).await;
    decoder.release();
    second_remote.publish(&test.contract, 9).await;
    until(|| observer.values.lock().unwrap().len() == 2).await;
    let values = observer.values.lock().unwrap().clone();
    assert!(values.contains(&(8, 1, ControllerNotificationSourcePhase::Draining)));
    assert!(values.contains(&(9, 2, ControllerNotificationSourcePhase::Current)));
    opened.close_write().await.unwrap();
    assert!(accepted.read().await.unwrap().is_none());
    accepted.close_write().await.unwrap();
    assert!(opened.read().await.unwrap().is_none());
    let (opened, accepted) = tokio::join!(opened.finish(), accepted.finish());
    opened.unwrap();
    accepted.unwrap();
    // The test owns the remote transport lifetime; retire it after its original
    // stream finishes before asserting both sides' physical cleanup.
    first_remote.close().await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while test.controller.progress().retained_session { tokio::task::yield_now().await; }
    }).await.unwrap_or_else(|error| {
        let services = first.session.configured_services().unwrap();
        panic!("retired cleanup {error}; original={:?}; core={:?}; service={:?}; notification={:?}; root={:?}; controller={:?}",
            first.session.cleanup_status(), first.session.core_cleanup_status(), services.service_peer().cleanup_status(),
            services.notifications().map(|peer| peer.cleanup_status()), subscription.snapshot(), test.controller.cleanup_status());
    });
    assert!(replacement.previous_cleanup_status().complete);
    assert_eq!(
        test.controller
            .replace_session(&CancellationToken::new())
            .await
            .unwrap_err(),
        MaterialControllerError::ConnectionFailed
    );
    assert_eq!(test.controller.current().unwrap().generation, 2);
    subscription.close();
    assert!(
        subscription
            .wait_cleanup(Duration::from_secs(3))
            .await
            .complete
    );
    second_remote.close().await;
    test.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_current_only_handoff_keeps_finite_old_decoder_until_exit() {
    for maximum in [1, 2] {
        let mut test = Harness::new(2, MaterialSourceOwnership::Borrowed).await;
        test.initialized().await;
        test.initializer.release.add_permits(1);
        let first = test.current(0).await;
        let first_remote = test.remote().await;
        let service = test.controller.service("example/lock-order").unwrap();
        let observer = Arc::new(Events::default());
        let decoder = Arc::new(DrainDecoder {
            definition: test.codec.definition.clone(),
            entered: Semaphore::new(0),
            blocked: Mutex::new(true),
            changed: std::sync::Condvar::new(),
        });
        let _release = ReleaseDecoder(decoder.clone());
        let subscription = service
            .subscribe_notification_events_with_options(
                test.contract.clone(),
                decoder.clone(),
                NotificationDropPolicy::KeepLatest,
                observer.clone(),
                ControllerNotificationOptions {
                    observation: ControllerNotificationObservation::CurrentOnly,
                    max_observed_sessions: maximum,
                },
            )
            .unwrap();
        until(|| subscription.snapshot().attached).await;
        first_remote.publish(&test.contract, 8).await;
        tokio::time::timeout(Duration::from_secs(3), decoder.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        let cancellation = CancellationToken::new();
        let mut replacement = Box::pin(test.controller.replace_session_with_options(
            MaterialSessionReplaceOptions {
                retirement: MaterialSessionRetirement::Retain {
                    retain_until_ms: 4000,
                },
            },
            &cancellation,
        ));
        tokio::select! { _ = test.initialized() => {}, result = &mut replacement => panic!("premature {result:?}") }
        test.initializer.release.add_permits(1);
        assert_eq!(replacement.await.unwrap().current.generation, 2);
        assert!(first.session.termination_cause().is_none());
        let second_remote = test.remote().await;
        assert!(subscription.snapshot().observed_sources <= maximum);
        assert!(!subscription.cleanup_status().complete);
        assert!(observer.values.lock().unwrap().is_empty());
        decoder.release();
        until(|| subscription.snapshot().generation == 2 && subscription.snapshot().attached).await;
        second_remote.publish(&test.contract, 9).await;
        until(|| !observer.values.lock().unwrap().is_empty()).await;
        assert_eq!(
            *observer.values.lock().unwrap(),
            [(9, 2, ControllerNotificationSourcePhase::Current)]
        );
        until(|| {
            observer.gaps.lock().unwrap().iter().any(|gap| {
                gap.reasons
                    .contains(&crate::ControllerNotificationGapReason::Handoff)
            })
        })
        .await;
        subscription.close();
        assert!(
            subscription
                .wait_cleanup(Duration::from_secs(3))
                .await
                .complete
        );
        first_remote.close().await;
        second_remote.close().await;
        test.close().await;
    }
}

#[derive(Debug)]
struct FailingNotificationCodec(MessageDefinition);
impl MessageCodec<u8> for FailingNotificationCodec {
    fn definition(&self) -> &MessageDefinition {
        &self.0
    }
    fn encode(
        &self,
        value: &u8,
        destination: &mut [u8],
    ) -> std::result::Result<usize, ServiceError> {
        destination[0] = *value;
        Ok(1)
    }
    fn decode(&self, source: &[u8]) -> std::result::Result<u8, ServiceError> {
        if source[0] == 1 {
            Err(ServiceError(ServiceFailure::DecodeFailed))
        } else {
            Ok(source[0])
        }
    }
}
#[derive(Debug, Default)]
struct FailingEvents(Events);
#[async_trait::async_trait]
impl ControllerNotificationObserver<u8> for FailingEvents {
    fn application_bytes(&self) -> u64 {
        1024
    }
    async fn observe(
        &self,
        event: ControllerNotificationEvent<u8>,
    ) -> std::result::Result<(), ServiceError> {
        let fail = matches!(
            event,
            ControllerNotificationEvent::Notification { value: 2, .. }
        );
        self.0.observe(event).await?;
        if fail {
            Err(ServiceError(ServiceFailure::Protocol))
        } else {
            Ok(())
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_controller_notification_gaps_preserve_later_delivery_after_application_failures() {
    let mut test = Harness::new(1, MaterialSourceOwnership::Borrowed).await;
    test.initialized().await;
    test.initializer.release.add_permits(1);
    test.current(0).await;
    let remote = test.remote().await;
    let observer = Arc::new(FailingEvents::default());
    let service = test.controller.service("example/lock-order").unwrap();
    let subscription = service
        .subscribe_notification_events_with_options(
            test.contract.clone(),
            Arc::new(FailingNotificationCodec(test.codec.definition.clone())),
            NotificationDropPolicy::DropOldest,
            observer.clone(),
            ControllerNotificationOptions::default(),
        )
        .unwrap();
    until(|| subscription.snapshot().attached).await;
    remote.publish(&test.contract, 1).await;
    until(|| {
        observer.0.gaps.lock().unwrap().iter().any(|gap| {
            gap.reasons
                .contains(&crate::ControllerNotificationGapReason::DecodeError)
        })
    })
    .await;
    assert!(observer.0.values.lock().unwrap().is_empty());
    remote.publish(&test.contract, 2).await;
    until(|| {
        observer.0.gaps.lock().unwrap().iter().any(|gap| {
            gap.reasons
                .contains(&crate::ControllerNotificationGapReason::HandlerError)
        })
    })
    .await;
    remote.publish(&test.contract, 3).await;
    until(|| observer.0.values.lock().unwrap().len() == 2).await;
    assert_eq!(
        *observer.0.values.lock().unwrap(),
        [
            (2, 1, ControllerNotificationSourcePhase::Current),
            (3, 1, ControllerNotificationSourcePhase::Current)
        ]
    );
    assert!(subscription.snapshot().attached);
    assert!(subscription.snapshot().gap.unwrap().known_dropped >= 1);
    subscription.close();
    assert!(
        subscription
            .wait_cleanup(Duration::from_secs(3))
            .await
            .complete
    );
    remote.close().await;
    test.close().await;
}
