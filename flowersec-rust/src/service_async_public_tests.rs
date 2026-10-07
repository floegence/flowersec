mod async_service_public_regressions {
    use super::{Profile, link};
    use crate::codec_v4::tests::{b, encode_map, t, u};
    use crate::{
        ApplicationErrorCodec, ApplicationErrorDefinition, ApplicationInvocationContext,
        AsyncMessageCodec, BytesMessageCodec, ContractAcceptance, FixedContractQuery,
        MessageDefinition, MethodDefinition, MethodDefinitionOptions, ResponseLimitPolicy,
        ServiceBindingOptions, ServiceClient, ServiceContract, ServiceDefinition, ServiceError,
        ServiceFailure, ServiceMethod, ServicePeer, ServiceSemantics, ServiceShape,
        TypedUnaryValue, UnaryPrepareOptions, UnaryRequestContext, UnaryResponse,
        UnaryServiceHandler, UnaryServiceRegistration,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::sync::Semaphore;
    use tokio_util::sync::CancellationToken;

    #[derive(Clone, Copy)]
    enum Fault {
        None,
        Oversized,
        Failure,
        Panic,
    }
    struct AsyncBytes {
        definition: MessageDefinition,
        hold_encode: bool,
        hold_decode: bool,
        fault: Fault,
        entered: Semaphore,
        release: Semaphore,
        encodes: AtomicUsize,
        decodes: AtomicUsize,
        exits: AtomicUsize,
    }
    impl AsyncBytes {
        fn new(
            definition: MessageDefinition,
            encode: bool,
            decode: bool,
            fault: Fault,
        ) -> Arc<Self> {
            Arc::new(Self {
                definition,
                hold_encode: encode,
                hold_decode: decode,
                fault,
                entered: Semaphore::new(0),
                release: Semaphore::new(0),
                encodes: AtomicUsize::new(0),
                decodes: AtomicUsize::new(0),
                exits: AtomicUsize::new(0),
            })
        }
        fn outcome(&self, bytes: &[u8], failure: ServiceFailure) -> Result<Vec<u8>, ServiceError> {
            match self.fault {
                Fault::None => Ok(bytes.to_vec()),
                Fault::Oversized => Ok(vec![1; self.definition.max_message_bytes() as usize + 1]),
                Fault::Failure => Err(ServiceError(failure)),
                Fault::Panic => panic!("controlled application codec panic"),
            }
        }
    }
    #[async_trait::async_trait]
    impl AsyncMessageCodec<Vec<u8>> for AsyncBytes {
        fn definition(&self) -> &MessageDefinition {
            &self.definition
        }
        fn application_bytes(&self) -> u64 {
            1024
        }
        async fn encode(
            &self,
            value: &Vec<u8>,
            _: ApplicationInvocationContext,
        ) -> Result<Vec<u8>, ServiceError> {
            self.encodes.fetch_add(1, Ordering::AcqRel);
            if self.hold_encode {
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
            }
            self.exits.fetch_add(1, Ordering::AcqRel);
            self.outcome(value, ServiceFailure::EncodeFailed)
        }
        async fn decode(
            &self,
            value: &[u8],
            _: ApplicationInvocationContext,
        ) -> Result<Vec<u8>, ServiceError> {
            self.decodes.fetch_add(1, Ordering::AcqRel);
            if self.hold_decode {
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
            }
            self.exits.fetch_add(1, Ordering::AcqRel);
            self.outcome(value, ServiceFailure::DecodeFailed)
        }
    }
    #[derive(Debug)]
    struct Echo {
        error: Option<u32>,
        entries: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl UnaryServiceHandler for Echo {
        async fn authorize(&self, _: UnaryRequestContext) -> Result<(), ServiceError> {
            Ok(())
        }
        async fn handle(
            &self,
            _: UnaryRequestContext,
            request: &[u8],
        ) -> Result<UnaryResponse, ServiceError> {
            self.entries.fetch_add(1, Ordering::AcqRel);
            Ok(UnaryResponse {
                payload: request.to_vec(),
                application_error_code: self.error,
            })
        }
    }
    async fn bind(
        environment: &crate::TransportEnvironment,
        client: &crate::Session,
        server: &crate::Session,
        handler: Arc<Echo>,
    ) -> (ServiceClient, ServicePeer, ServicePeer, MethodDefinition) {
        let message = MessageDefinition::new([31; 32], "bytes.v1".into(), 128).unwrap();
        let errors = handler
            .error
            .map(|code| ApplicationErrorDefinition {
                code,
                message: message.clone(),
                max_payload_bytes: 128,
            })
            .into_iter()
            .collect::<Vec<_>>();
        let method = MethodDefinition::new(MethodDefinitionOptions {
            type_id: 101,
            shape: ServiceShape::Unary,
            semantics: ServiceSemantics::Transient,
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
            errors: errors.clone(),
        })
        .unwrap();
        let mut catalog = vec![0x80 + errors.len() as u8];
        for error in errors {
            catalog.extend(encode_map(&[
                (0, u(error.code as u64)),
                (1, t("bytes.v1")),
                (2, u(128)),
                (3, b(&[31; 32])),
            ]));
        }
        let contract = ServiceContract::capture(
            environment,
            &encode_map(&[
                (0, t("example/async")),
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
                (27, catalog),
            ]),
        )
        .unwrap();
        let definition = ServiceDefinition::new(
            "example/async".into(),
            vec![ServiceMethod {
                name: "Echo".into(),
                export_name: "echo".into(),
                method: method.clone(),
            }],
        )
        .unwrap();
        let query = FixedContractQuery {
            type_id: 1,
            contract_digest: [1; 32],
        };
        let server_peer = server
            .services(
                query,
                vec![UnaryServiceRegistration {
                    contract,
                    offer: None,
                    offer_window_ms: None,
                    query_allowed: true,
                    resident: false,
                    handler,
                    execution: None,
                    caller: None,
                }],
            )
            .unwrap();
        let peer = client.services(query, Vec::new()).unwrap();
        let service = peer
            .bind(
                definition,
                vec![ServiceBindingOptions {
                    method: method.clone(),
                    acceptance: ContractAcceptance::exact(),
                    response_limit: ResponseLimitPolicy::Fixed(128),
                    execution_reference_identity: None,
                    streaming: None,
                    resume: None,
                }],
                Duration::from_secs(2),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        (service, peer, server_peer, method)
    }
    async fn settled(check: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !check() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn options() -> UnaryPrepareOptions {
        UnaryPrepareOptions {
            timeout: Duration::from_secs(3),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn asynchronous_unary_keeps_one_decode_after_wait_cancellation() {
        for profile in [Profile::X25519, Profile::P256] {
            let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(profile);
            let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
            let handler = Arc::new(Echo {
                error: None,
                entries: AtomicUsize::new(0),
            });
            let (service, peer, server_peer, method) =
                bind(&fixture.environment, &client, &server, handler.clone()).await;
            let request =
                AsyncBytes::new(method.options().request.clone(), false, false, Fault::None);
            let response = AsyncBytes::new(
                method.options().response.clone().unwrap(),
                false,
                true,
                Fault::None,
            );
            let operation = service
                .prepare_unary_async(
                    &method,
                    Arc::new(b"original".to_vec()),
                    request.clone(),
                    response.clone(),
                    options(),
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            assert_eq!(operation.status(), crate::OperationStatus::NotStarted);
            assert_eq!(request.encodes.load(Ordering::Acquire), 1);
            operation.start().unwrap();
            operation.start().unwrap();
            let cancellation = CancellationToken::new();
            let waiter = tokio::spawn({
                let operation = operation.clone();
                let cancellation = cancellation.clone();
                async move { operation.wait_typed(cancellation).await }
            });
            response.entered.acquire().await.unwrap().forget();
            cancellation.cancel();
            assert_eq!(
                waiter.await.unwrap().unwrap_err().0,
                ServiceFailure::Canceled
            );
            assert_eq!(
                operation
                    .wait_encoded(CancellationToken::new())
                    .await
                    .unwrap_err()
                    .0,
                ServiceFailure::ResultModeConflict
            );
            assert_eq!(response.decodes.load(Ordering::Acquire), 1);
            assert!(!operation.cleanup_status().complete);
            response.release.add_permits(1);
            let result = operation
                .wait_typed(CancellationToken::new())
                .await
                .unwrap();
            assert!(result.application_input_provided);
            assert_eq!(result.codec_identity.unwrap().schema_digest, [31; 32]);
            match result.value {
                TypedUnaryValue::Response(value) => assert_eq!(value, b"original"),
                other => panic!("unexpected result {other:?}"),
            }
            assert_eq!(handler.entries.load(Ordering::Acquire), 1);
            assert_eq!(response.decodes.load(Ordering::Acquire), 1);
            assert_eq!(
                operation
                    .wait_typed(CancellationToken::new())
                    .await
                    .unwrap_err()
                    .0,
                ServiceFailure::Closed
            );
            operation.close();
            assert!(operation.wait_cleanup().await.complete);
            service.close();
            peer.close();
            server_peer.close();
            client.close();
            server.close();
            c_task.abort();
            s_task.abort();
        }
    }

    #[tokio::test]
    async fn canceled_async_preparation_keeps_its_original_encoder_without_dispatch() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let handler = Arc::new(Echo {
            error: None,
            entries: AtomicUsize::new(0),
        });
        let (service, peer, server_peer, method) =
            bind(&fixture.environment, &client, &server, handler.clone()).await;
        let request = AsyncBytes::new(method.options().request.clone(), true, false, Fault::None);
        let response = AsyncBytes::new(
            method.options().response.clone().unwrap(),
            false,
            false,
            Fault::None,
        );
        let baseline = fixture.environment.resource_usage().sdk_bytes;
        let cancellation = CancellationToken::new();
        let preparing = tokio::spawn({
            let service = service.clone();
            let method = method.clone();
            let request = request.clone();
            let cancellation = cancellation.clone();
            async move {
                service
                    .prepare_unary_async(
                        &method,
                        Arc::new(b"late".to_vec()),
                        request,
                        response,
                        options(),
                        cancellation,
                    )
                    .await
            }
        });
        request.entered.acquire().await.unwrap().forget();
        cancellation.cancel();
        assert_eq!(
            preparing.await.unwrap().unwrap_err().0,
            ServiceFailure::Canceled
        );
        assert_eq!(handler.entries.load(Ordering::Acquire), 0);
        assert_eq!(request.exits.load(Ordering::Acquire), 0);
        assert!(fixture.environment.resource_usage().sdk_bytes > baseline);
        request.release.add_permits(1);
        settled(|| {
            request.exits.load(Ordering::Acquire) == 1
                && fixture.environment.resource_usage().sdk_bytes == baseline
        })
        .await;
        assert_eq!(handler.entries.load(Ordering::Acquire), 0);
        service.close();
        peer.close();
        server_peer.close();
        client.close();
        server.close();
        c_task.abort();
        s_task.abort();
    }

    #[tokio::test]
    async fn async_encode_failure_oversize_and_panic_release_preparation_before_retry() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let handler = Arc::new(Echo {
            error: None,
            entries: AtomicUsize::new(0),
        });
        let (service, peer, server_peer, method) =
            bind(&fixture.environment, &client, &server, handler.clone()).await;
        let baseline = fixture.environment.resource_usage().sdk_bytes;
        for fault in [Fault::Failure, Fault::Oversized, Fault::Panic] {
            let request = AsyncBytes::new(method.options().request.clone(), false, false, fault);
            let response = AsyncBytes::new(
                method.options().response.clone().unwrap(),
                false,
                false,
                Fault::None,
            );
            assert_eq!(
                service
                    .prepare_unary_async(
                        &method,
                        Arc::new(vec![1]),
                        request,
                        response,
                        options(),
                        CancellationToken::new()
                    )
                    .await
                    .unwrap_err()
                    .0,
                ServiceFailure::EncodeFailed
            );
            settled(|| fixture.environment.resource_usage().sdk_bytes == baseline).await;
        }
        assert_eq!(handler.entries.load(Ordering::Acquire), 0);
        service.close();
        peer.close();
        server_peer.close();
        client.close();
        server.close();
        c_task.abort();
        s_task.abort();
    }

    #[tokio::test]
    async fn application_errors_use_only_installed_sync_or_async_decoders_and_preserve_raw_result()
    {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let handler = Arc::new(Echo {
            error: Some(7),
            entries: AtomicUsize::new(0),
        });
        let (service, peer, server_peer, method) =
            bind(&fixture.environment, &client, &server, handler.clone()).await;
        let definition = method.options().errors[0].clone();
        for mode in 0..5 {
            let bytes = Arc::new(BytesMessageCodec::new(definition.message.clone()));
            let mut preparation = options();
            if mode == 1 {
                preparation.application_error_codecs.push(
                    ApplicationErrorCodec::synchronous(definition.clone(), bytes.clone()).unwrap(),
                );
            }
            if mode >= 2 {
                let fault = if mode == 3 {
                    Fault::Failure
                } else if mode == 4 {
                    Fault::Panic
                } else {
                    Fault::None
                };
                preparation.application_error_codecs.push(
                    ApplicationErrorCodec::asynchronous(
                        definition.clone(),
                        AsyncBytes::new(definition.message.clone(), false, false, fault),
                    )
                    .unwrap(),
                );
            }
            let operation = service
                .prepare_unary(
                    &method,
                    &b"business-error".to_vec(),
                    bytes.clone(),
                    bytes,
                    preparation,
                )
                .unwrap();
            operation.start().unwrap();
            let result = operation.wait_typed(CancellationToken::new()).await;
            if mode >= 3 {
                assert_eq!(result.unwrap_err().0, ServiceFailure::DecodeFailed);
            } else {
                let result = result.unwrap();
                assert_eq!(result.application_input_provided, mode != 0);
                match result.value {
                    TypedUnaryValue::ApplicationError { code, payload } if mode == 0 => {
                        assert_eq!(code, 7);
                        assert_eq!(payload, b"business-error");
                    }
                    TypedUnaryValue::DecodedApplicationError { code, value } if mode > 0 => {
                        assert_eq!(code, 7);
                        assert!(value.is::<Vec<u8>>());
                        assert_eq!(value.downcast_ref::<Vec<u8>>().unwrap(), b"business-error");
                        assert_eq!(value.into_value::<Vec<u8>>().unwrap(), b"business-error");
                    }
                    other => panic!("unexpected application result {other:?}"),
                }
            }
            operation.close();
            assert!(operation.wait_cleanup().await.complete);
        }
        assert_eq!(handler.entries.load(Ordering::Acquire), 5);
        service.close();
        peer.close();
        server_peer.close();
        client.close();
        server.close();
        c_task.abort();
        s_task.abort();
    }

    #[derive(Debug)]
    struct Watch {
        entries: AtomicUsize,
        retained: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }
    struct Items(std::collections::VecDeque<Vec<u8>>);
    #[async_trait::async_trait]
    impl crate::StreamingItemSource for Items {
        async fn next(
            &mut self,
            _: UnaryRequestContext,
        ) -> Result<Option<crate::ServiceStreamItem>, ServiceError> {
            Ok(self.0.pop_front().map(|payload| crate::ServiceStreamItem {
                payload,
                application_error_code: None,
            }))
        }
    }
    #[async_trait::async_trait]
    impl crate::StreamingServiceHandler for Watch {
        async fn authorize(&self, _: UnaryRequestContext) -> Result<(), ServiceError> {
            Ok(())
        }
        async fn start(
            &self,
            _: UnaryRequestContext,
            request: &[u8],
        ) -> Result<Box<dyn crate::StreamingItemSource>, ServiceError> {
            self.entries.fetch_add(1, Ordering::AcqRel);
            *self.retained.lock().unwrap() = vec![request.to_vec(), b"tail".to_vec()];
            Ok(Box::new(Items([request.to_vec(), b"tail".to_vec()].into())))
        }
    }
    #[derive(Debug)]
    struct ContentReader(Arc<std::sync::Mutex<Vec<Vec<u8>>>>);
    #[async_trait::async_trait]
    impl UnaryServiceHandler for ContentReader {
        async fn authorize(&self, _: UnaryRequestContext) -> Result<(), ServiceError> {
            Ok(())
        }
        async fn handle(
            &self,
            _: UnaryRequestContext,
            request: &[u8],
        ) -> Result<UnaryResponse, ServiceError> {
            let index = request
                .first()
                .copied()
                .ok_or(ServiceError(ServiceFailure::ServiceFailed))?;
            let payload = self
                .0
                .lock()
                .unwrap()
                .get(usize::from(index))
                .cloned()
                .ok_or(ServiceError(ServiceFailure::ServiceFailed))?;
            Ok(UnaryResponse {
                payload,
                application_error_code: None,
            })
        }
    }
    #[tokio::test]
    async fn asynchronous_stream_preparation_and_item_waits_preserve_original_ownership() {
        streaming_workflow(false, false).await;
        streaming_workflow(true, false).await;
        streaming_workflow(false, true).await;
    }
    async fn streaming_workflow(pooled: bool, retained_content: bool) {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(if pooled {
            Profile::P256
        } else {
            Profile::X25519
        });
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let message = MessageDefinition::new([31; 32], "bytes.v1".into(), 128).unwrap();
        let mut method = MethodDefinition::new(MethodDefinitionOptions {
            type_id: 102,
            shape: ServiceShape::ServerStreaming,
            semantics: ServiceSemantics::Transient,
            request: message.clone(),
            response: Some(message),
            response_revision: "bytes.v1".into(),
            request_max_bytes: 128,
            min_response_limit_bytes: 1,
            max_response_bytes: 128,
            require_durable: false,
            checkpoint_format: None,
            restart_flush_deadline_ms: None,
            streaming: Some(crate::StreamingLimits {
                max_item_count: 4,
                max_payload_bytes: 512,
                max_duration_ms: 5000,
            }),
            content: None,
            errors: Vec::new(),
        })
        .unwrap();
        let mut retained = method.options().clone();
        retained.semantics = ServiceSemantics::Execution;
        retained.content = Some(crate::StreamContentDefinition {
            schema_revision: "content.v1".into(),
            canonical: vec![0xa0],
            read_type_id: 103,
        });
        let retained_method = MethodDefinition::new(retained.clone()).unwrap();
        let content_entry = ServiceMethod {
            name: "Watch".into(),
            export_name: "watch".into(),
            method: retained_method.clone(),
        };
        assert_eq!(
            ServiceDefinition::new("example/async".into(), vec![content_entry.clone()])
                .unwrap_err()
                .0,
            ServiceFailure::ConfigurationCapacity
        );
        let mut reader = method.options().clone();
        reader.type_id = 103;
        let wrong_reader = ServiceMethod {
            name: "Read".into(),
            export_name: "read".into(),
            method: MethodDefinition::new(reader.clone()).unwrap(),
        };
        assert_eq!(
            ServiceDefinition::new("example/async".into(), vec![content_entry, wrong_reader])
                .unwrap_err()
                .0,
            ServiceFailure::ConfigurationCapacity
        );
        reader.shape = ServiceShape::Unary;
        reader.streaming = None;
        let reader = MethodDefinition::new(reader).unwrap();
        retained.content.as_mut().unwrap().read_type_id = retained.type_id;
        assert_eq!(
            MethodDefinition::new(retained.clone()).unwrap_err().0,
            ServiceFailure::ConfigurationCapacity
        );
        retained.content.as_mut().unwrap().read_type_id = 103;
        retained.shape = ServiceShape::Unary;
        retained.streaming = None;
        assert_eq!(
            MethodDefinition::new(retained).unwrap_err().0,
            ServiceFailure::ConfigurationCapacity
        );
        if retained_content {
            method = retained_method;
        }
        let mut methods = vec![ServiceMethod {
            name: "Watch".into(),
            export_name: "watch".into(),
            method: method.clone(),
        }];
        if retained_content {
            methods.push(ServiceMethod {
                name: "Read".into(),
                export_name: "read".into(),
                method: reader.clone(),
            });
        }
        let definition = ServiceDefinition::new("example/async".into(), methods).unwrap();
        let mut contract_fields = vec![
            (0, t("example/async")),
            (1, u(102)),
            (2, u(1)),
            (4, u(0)),
            (6, t("bytes.v1")),
            (7, t("bytes.v1")),
            (8, u(1)),
            (9, u(1)),
            (10, u(128)),
            (11, u(5000)),
            (12, u(5000)),
            (21, vec![0xf4]),
            (23, u(128)),
            (24, u(4)),
            (25, u(512)),
            (26, u(5000)),
            (27, vec![0x80]),
        ];
        if retained_content {
            contract_fields.retain(|(id, _)| !matches!(id, 4 | 11 | 12));
            contract_fields.extend([
                (4, u(1)),
                (13, u(0)),
                (14, u(10000)),
                (16, u(2000)),
                (17, u(10000)),
                (18, u(8000)),
                (19, u(1)),
                (
                    28,
                    encode_map(&[
                        (0, u(1)),
                        (1, u(1)),
                        (2, u(10000)),
                        (3, u(4)),
                        (4, u(512)),
                        (5, t("content.v1")),
                        (6, b(&[0xa0])),
                    ]),
                ),
            ]);
            contract_fields.sort_by_key(|(id, _)| *id);
        }
        let contract =
            ServiceContract::capture(&fixture.environment, &encode_map(&contract_fields)).unwrap();
        let history = retained_content.then(|| {
            crate::ExecutionService::new(
                &fixture.environment,
                crate::ExecutionServiceOptions {
                    tenant: "tenant".into(),
                    audience: "service".into(),
                    namespace: "example/async".into(),
                    caller_authorities: vec![[42; 32]],
                    max_records: 8,
                    max_active: 2,
                    result_bytes: 65536,
                },
            )
            .unwrap()
        });
        let retained_items = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler = Arc::new(Watch {
            entries: AtomicUsize::new(0),
            retained: retained_items.clone(),
        });
        let binding = crate::ServiceStreamBinding {
            stream_kind: "example.async.watch".into(),
            stream_metadata: super::Metadata::empty(),
        };
        let registered = crate::RegisteredStreamingService::new(
            &fixture.environment,
            crate::StreamingServiceConfig {
                binding: binding.clone(),
                definition: definition.clone(),
                method: method.clone(),
                contract,
                handler: handler.clone(),
                execution: history,
                offer: None,
                offer_window_ms: retained_content.then_some(2000),
            },
        )
        .unwrap();
        let query = FixedContractQuery {
            type_id: 1,
            contract_digest: [1; 32],
        };
        let mut unary = Vec::new();
        if retained_content {
            let contract = ServiceContract::capture(
                &fixture.environment,
                &encode_map(&[
                    (0, t("example/async")),
                    (1, u(103)),
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
            unary.push(UnaryServiceRegistration {
                contract,
                offer: None,
                offer_window_ms: None,
                query_allowed: true,
                resident: false,
                handler: Arc::new(ContentReader(retained_items.clone())),
                execution: None,
                caller: None,
            });
        }
        let server_peer = server.services(query, unary).unwrap();
        server_peer
            .attach_streaming(vec![crate::StreamingServiceRegistration {
                service: registered.clone(),
                caller: retained_content.then(|| crate::ExecutionIdentity {
                    authority: [42; 32],
                    subject: "client".into(),
                    identity_digest: server.service_identity().unwrap().2,
                }),
                query_allowed: true,
            }])
            .unwrap();
        let peer = client.services(query, Vec::new()).unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let dispatch = tokio::spawn({
            let server = server.clone();
            let raw = registered.raw_registration().handler;
            let accepted = accepted.clone();
            async move {
                let mut handlers = tokio::task::JoinSet::new();
                while let Ok(request) = server.next_open().await {
                    accepted.fetch_add(1, Ordering::AcqRel);
                    let raw = raw.clone();
                    handlers.spawn(async move {
                        crate::streaming_service_v4::handle_sdk_streaming_open(
                            raw,
                            request,
                            CancellationToken::new(),
                        )
                        .await
                    });
                }
                while let Some(result) = handlers.join_next().await {
                    // Parent Close also ends the unused replenished stream.
                    // The consumed stream's complete result is asserted below.
                    let _ = result.unwrap();
                }
            }
        });
        let mut bindings = vec![ServiceBindingOptions {
            method: method.clone(),
            acceptance: ContractAcceptance::exact(),
            response_limit: ResponseLimitPolicy::Fixed(128),
            execution_reference_identity: retained_content.then(|| {
                crate::ExecutionReferenceIdentity {
                    target_domain: "content-test".into(),
                    tenant: "tenant".into(),
                    audience: "service".into(),
                    caller_subject: "client".into(),
                    caller_authority: [42; 32],
                }
            }),
            streaming: Some(binding),
            resume: None,
        }];
        if retained_content {
            bindings.push(ServiceBindingOptions {
                method: reader.clone(),
                acceptance: ContractAcceptance::exact(),
                response_limit: ResponseLimitPolicy::Fixed(128),
                execution_reference_identity: None,
                streaming: None,
                resume: None,
            });
        }
        let service = peer
            .bind_with_streaming_pools(
                definition,
                bindings,
                if pooled {
                    vec![crate::StreamingPoolRequirement {
                        method: method.clone(),
                        policy: crate::StreamingPoolPolicy::RequiredForDispatch,
                    }]
                } else {
                    Vec::new()
                },
                Duration::from_secs(2),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.load(Ordering::Acquire), usize::from(pooled));
        assert_eq!(handler.entries.load(Ordering::Acquire), 0);
        let prepare_options = crate::StreamingPrepareOptions {
            timeout: Duration::from_secs(3),
            ..Default::default()
        };
        let baseline = fixture.environment.resource_usage().sdk_bytes;
        for fault in [Fault::Failure, Fault::Oversized, Fault::Panic] {
            let request = AsyncBytes::new(method.options().request.clone(), false, false, fault);
            let response = AsyncBytes::new(
                method.options().response.clone().unwrap(),
                false,
                false,
                Fault::None,
            );
            assert_eq!(
                service
                    .prepare_stream_operation_async(
                        &method,
                        Arc::new(vec![1]),
                        request,
                        response,
                        prepare_options.clone(),
                        CancellationToken::new()
                    )
                    .await
                    .unwrap_err()
                    .0,
                ServiceFailure::EncodeFailed
            );
            settled(|| fixture.environment.resource_usage().sdk_bytes == baseline).await;
        }
        let cancellation = CancellationToken::new();
        let held = AsyncBytes::new(method.options().request.clone(), true, false, Fault::None);
        let preparation = tokio::spawn({
            let service = service.clone();
            let method = method.clone();
            let held = held.clone();
            let options = prepare_options.clone();
            let cancellation = cancellation.clone();
            async move {
                let response = AsyncBytes::new(
                    method.options().response.clone().unwrap(),
                    false,
                    false,
                    Fault::None,
                );
                service
                    .prepare_stream_operation_async(
                        &method,
                        Arc::new(vec![2]),
                        held,
                        response,
                        options,
                        cancellation,
                    )
                    .await
            }
        });
        held.entered.acquire().await.unwrap().forget();
        cancellation.cancel();
        assert_eq!(
            preparation.await.unwrap().unwrap_err().0,
            ServiceFailure::Canceled
        );
        assert!(fixture.environment.resource_usage().sdk_bytes > baseline);
        held.release.add_permits(1);
        settled(|| {
            held.exits.load(Ordering::Acquire) == 1
                && fixture.environment.resource_usage().sdk_bytes == baseline
        })
        .await;
        assert_eq!(handler.entries.load(Ordering::Acquire), 0);
        let request = AsyncBytes::new(method.options().request.clone(), false, false, Fault::None);
        let response = AsyncBytes::new(
            method.options().response.clone().unwrap(),
            false,
            true,
            Fault::None,
        );
        let operation = service
            .prepare_stream_operation_async(
                &method,
                Arc::new(b"head".to_vec()),
                request.clone(),
                response.clone(),
                prepare_options,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(operation.status(), crate::OperationStatus::NotStarted);
        operation.start().unwrap();
        operation.start().unwrap();
        let cancellation = CancellationToken::new();
        let waiting = tokio::spawn({
            let operation = operation.clone();
            let cancellation = cancellation.clone();
            async move { operation.read_next(&cancellation).await }
        });
        response.entered.acquire().await.unwrap().forget();
        cancellation.cancel();
        assert_eq!(
            waiting.await.unwrap().unwrap_err().0,
            ServiceFailure::Canceled
        );
        assert_eq!(
            operation
                .read_next_encoded(&CancellationToken::new())
                .await
                .unwrap_err()
                .0,
            ServiceFailure::ResultModeConflict
        );
        response.release.add_permits(2);
        for expected in [b"head".as_slice(), b"tail".as_slice()] {
            let item = operation
                .read_next(&CancellationToken::new())
                .await
                .unwrap()
                .unwrap();
            assert!(!item.terminal);
            match item.value {
                TypedUnaryValue::Response(value) => assert_eq!(value, expected),
                other => panic!("unexpected stream item {other:?}"),
            }
        }
        assert!(
            operation
                .read_next(&CancellationToken::new())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(operation.status(), crate::OperationStatus::Completed);
        assert_eq!(operation.progress().delivered_items, 2);
        assert_eq!(response.decodes.load(Ordering::Acquire), 2);
        assert_eq!(request.encodes.load(Ordering::Acquire), 1);
        assert_eq!(handler.entries.load(Ordering::Acquire), 1);
        operation.close();
        assert!(operation.wait_cleanup().await.complete);
        if retained_content {
            assert_eq!(
                *retained_items.lock().unwrap(),
                vec![b"head".to_vec(), b"tail".to_vec()]
            );
            let read = service
                .prepare_unary(
                    &reader,
                    &vec![1u8],
                    Arc::new(BytesMessageCodec::new(reader.options().request.clone())),
                    Arc::new(BytesMessageCodec::new(
                        reader.options().response.clone().unwrap(),
                    )),
                    options(),
                )
                .unwrap();
            read.start().unwrap();
            let result = read.wait_encoded(CancellationToken::new()).await.unwrap();
            assert_eq!(result.payload, b"tail");
            read.close();
            assert!(read.wait_cleanup().await.complete);
        }
        if pooled {
            settled(|| accepted.load(Ordering::Acquire) == 2).await;
            assert_eq!(handler.entries.load(Ordering::Acquire), 1);
        }
        service.close();
        peer.close();
        server_peer.close();
        client.close();
        server.close();
        tokio::time::timeout(Duration::from_secs(3), dispatch)
            .await
            .unwrap()
            .unwrap();
        assert!(client.wait_cleanup().await.complete);
        assert!(server.wait_cleanup().await.complete);
        c_task.abort();
        s_task.abort();
    }
}
