mod execution_management_public_regressions {
    use super::{Profile, link};
    use crate::codec_v4::tests::{encode_map, t, u};
    use crate::{
        BytesMessageCodec, ContractAcceptance, ExecutionAbsence, ExecutionCancelResult,
        ExecutionHistoryGrant, ExecutionIdentity, ExecutionService, ExecutionServiceOptions,
        ExecutionState, FixedContractQuery, FixedResultRead, MessageDefinition, MethodDefinition,
        MethodDefinitionOptions, ResponseLimitPolicy, ServiceBindingOptions, ServiceContract,
        ServiceDefinition, ServiceError, ServiceFailure, ServiceMethod, ServiceSemantics,
        ServiceShape, UnaryPrepareOptions, UnaryRequestContext, UnaryResponse, UnaryServiceHandler,
        UnaryServiceRegistration,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::Semaphore;
    use tokio_util::sync::CancellationToken;

    #[derive(Debug)]
    struct Handler {
        entered: Semaphore,
        release: Semaphore,
        calls: AtomicUsize,
        publications: std::sync::Mutex<Vec<crate::ResponsePublication>>,
        foreign_maintenance: Option<crate::MaintenanceOwner>,
    }
    #[async_trait::async_trait]
    impl UnaryServiceHandler for Handler {
        async fn authorize(&self, _: UnaryRequestContext) -> Result<(), ServiceError> {
            Ok(())
        }
        async fn handle(
            &self,
            context: UnaryRequestContext,
            request: &[u8],
        ) -> Result<UnaryResponse, ServiceError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let publication = context.response_publication();
            if let Some(foreign) = &self.foreign_maintenance {
                assert_eq!(
                    publication.state().state,
                    crate::ResponsePublicationState::Pending
                );
                assert_eq!(
                    publication
                        .wait(&CancellationToken::new())
                        .await
                        .unwrap_err()
                        .0,
                    ServiceFailure::KnownApplicationDependency
                );
                assert_eq!(
                    publication.transfer_to(foreign),
                    crate::ResponseTransferResult::OwnerUnavailable
                );
                let maintenance = context.maintenance_owner().unwrap();
                assert_eq!(
                    publication.transfer_to(&maintenance),
                    crate::ResponseTransferResult::Success
                );
                assert_eq!(
                    publication.transfer_to(&maintenance),
                    crate::ResponseTransferResult::AlreadyTransferred
                );
            } else {
                assert_eq!(
                    publication
                        .wait(&CancellationToken::new())
                        .await
                        .unwrap()
                        .state,
                    crate::ResponsePublicationState::NotApplicable
                );
            }
            self.publications.lock().unwrap().push(publication);
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            Ok(UnaryResponse {
                payload: request.to_vec(),
                application_error_code: None,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum SaveBehavior {
        Confirm,
        Unknown,
        Fail,
        Panic,
    }
    #[derive(Debug)]
    struct ReferenceStore {
        behavior: SaveBehavior,
        bytes: u64,
        held: bool,
        entered: Semaphore,
        release: Semaphore,
        references: std::sync::Mutex<Vec<crate::OperationReference>>,
    }
    impl ReferenceStore {
        fn new(behavior: SaveBehavior, bytes: u64, held: bool) -> Arc<Self> {
            Arc::new(Self {
                behavior,
                bytes,
                held,
                entered: Semaphore::new(0),
                release: Semaphore::new(0),
                references: std::sync::Mutex::new(Vec::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl crate::OperationReferenceStore for ReferenceStore {
        fn application_bytes(&self) -> u64 {
            self.bytes
        }
        async fn save(
            &self,
            reference: crate::OperationReference,
            _: crate::ApplicationInvocationContext,
        ) -> Result<crate::ReferenceSaveOutcome, ServiceError> {
            self.references.lock().unwrap().push(reference);
            self.entered.add_permits(1);
            if self.held {
                self.release.acquire().await.unwrap().forget();
            }
            match self.behavior {
                SaveBehavior::Confirm => Ok(crate::ReferenceSaveOutcome::Confirmed),
                SaveBehavior::Unknown => Ok(crate::ReferenceSaveOutcome::Unknown),
                SaveBehavior::Fail => Err(ServiceError(ServiceFailure::ServiceFailed)),
                SaveBehavior::Panic => panic!("controlled reference store panic"),
            }
        }
    }
    async fn prepare_saved(
        client: &crate::ServiceClient,
        method: &MethodDefinition,
        store: Arc<ReferenceStore>,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<crate::SavedUnaryPreparation<Vec<u8>>, crate::PrepareAndSaveError> {
        client
            .prepare_and_save_unary(
                method,
                &b"retained result".to_vec(),
                Arc::new(BytesMessageCodec::new(method.options().request.clone())),
                Arc::new(BytesMessageCodec::new(
                    method.options().response.clone().unwrap(),
                )),
                UnaryPrepareOptions {
                    timeout,
                    ..UnaryPrepareOptions::default()
                },
                store,
                cancellation,
            )
            .await
    }
    async fn verify_reference_save_receipts(
        client: &crate::ServiceClient,
        method: &MethodDefinition,
        management: &crate::ExecutionManagement,
        handler: &Handler,
    ) -> crate::UnaryOperation<Vec<u8>> {
        for (behavior, bytes, expected) in [
            (
                SaveBehavior::Confirm,
                0,
                ServiceFailure::ConfigurationCapacity,
            ),
            (
                SaveBehavior::Unknown,
                1024,
                ServiceFailure::ServiceUnavailable,
            ),
            (SaveBehavior::Fail, 1024, ServiceFailure::ServiceFailed),
            (SaveBehavior::Panic, 1024, ServiceFailure::ServiceFailed),
        ] {
            let store = ReferenceStore::new(behavior, bytes, false);
            let error = prepare_saved(
                client,
                method,
                store.clone(),
                Duration::from_secs(3),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
            let crate::PrepareAndSaveError::Save(failure) = error else {
                panic!("expected reference save failure: {error:?}");
            };
            assert_eq!(failure.failure, expected);
            let snapshot = failure
                .receipt
                .wait_settled(CancellationToken::new())
                .await
                .unwrap();
            assert!(snapshot.settled);
            assert_eq!(snapshot.attempted, bytes != 0);
            assert_eq!(snapshot.application_input_provided, bytes != 0);
            assert_eq!(snapshot.outcome, crate::ReferenceSaveOutcome::Unknown);
            assert_eq!(
                store.references.lock().unwrap().len(),
                usize::from(bytes != 0)
            );
            assert_eq!(handler.calls.load(Ordering::Acquire), 0);
        }
        // Closing the observer cannot turn an entered durable callback into a
        // rollback. Its eventual receipt records the original adapter's fact.
        for by_deadline in [false, true] {
            let store = ReferenceStore::new(SaveBehavior::Confirm, 1024, true);
            let cancellation = CancellationToken::new();
            let pending = tokio::spawn({
                let client = client.clone();
                let method = method.clone();
                let store = store.clone();
                let cancellation = cancellation.clone();
                async move {
                    prepare_saved(
                        &client,
                        &method,
                        store,
                        if by_deadline {
                            Duration::from_millis(100)
                        } else {
                            Duration::from_secs(3)
                        },
                        cancellation,
                    )
                    .await
                }
            });
            tokio::time::timeout(Duration::from_secs(2), store.entered.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
            if !by_deadline {
                cancellation.cancel();
            }
            let error = pending.await.unwrap().unwrap_err();
            let crate::PrepareAndSaveError::Save(failure) = error else {
                panic!("expected save observer cancellation: {error:?}");
            };
            assert_eq!(
                failure.failure,
                if by_deadline {
                    ServiceFailure::DeadlineExceeded
                } else {
                    ServiceFailure::Canceled
                }
            );
            let snapshot = failure.receipt.snapshot();
            assert!(snapshot.attempted && snapshot.application_input_provided);
            assert!(!snapshot.settled);
            assert_eq!(snapshot.outcome, crate::ReferenceSaveOutcome::Unknown);
            assert_eq!(
                store.references.lock().unwrap().as_slice(),
                std::slice::from_ref(&snapshot.reference)
            );
            let observer = CancellationToken::new();
            observer.cancel();
            assert_eq!(
                failure.receipt.wait_settled(observer).await.unwrap_err().0,
                ServiceFailure::Canceled
            );
            store.release.add_permits(1);
            let settled = tokio::time::timeout(
                Duration::from_secs(2),
                failure.receipt.wait_settled(CancellationToken::new()),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(settled.settled);
            assert_eq!(settled.reference, snapshot.reference);
            assert_eq!(settled.outcome, crate::ReferenceSaveOutcome::Confirmed);
            let state = management
                .query_operation(&settled.reference, 1000, &CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(state.absence, Some(ExecutionAbsence::NotRegistered));
            assert_eq!(handler.calls.load(Ordering::Acquire), 0);
        }
        let store = ReferenceStore::new(SaveBehavior::Confirm, 1024, false);
        let saved = prepare_saved(
            client,
            method,
            store.clone(),
            Duration::from_secs(3),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(saved.operation.status(), crate::OperationStatus::NotStarted);
        assert_eq!(saved.operation.reference().unwrap(), saved.reference);
        assert_eq!(
            store.references.lock().unwrap().as_slice(),
            std::slice::from_ref(&saved.reference)
        );
        let snapshot = saved.receipt.snapshot();
        assert!(snapshot.attempted && snapshot.settled && snapshot.application_input_provided);
        assert_eq!(snapshot.outcome, crate::ReferenceSaveOutcome::Confirmed);
        assert_eq!(snapshot.reference, saved.reference);
        assert_eq!(handler.calls.load(Ordering::Acquire), 0);
        saved.operation
    }

    #[tokio::test]
    async fn management_tracks_original_execution_and_retains_results_after_response_close() {
        for (profile, restart) in [
            (Profile::X25519, false),
            (Profile::P256, false),
            (Profile::X25519, true),
        ] {
            let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(profile);
            let (client_session, server_session, c_task, s_task) = link(&fixture.environment, c, s);
            let maintenance = restart.then(|| {
                fixture
                    .environment
                    .maintenance_owner(crate::MaintenanceOwnerOptions {
                        max_observations: 1,
                    })
                    .unwrap()
            });
            // The in-memory transport fixture adopts READY engines directly;
            // install the same original capability normally captured by HandlerPlan.
            server_session.install_maintenance_owner(maintenance.clone());
            let history = ExecutionService::new(
                &fixture.environment,
                ExecutionServiceOptions {
                    tenant: "tenant".into(),
                    audience: "service".into(),
                    namespace: "example/history".into(),
                    caller_authorities: vec![[42; 32]],
                    max_records: 8,
                    max_active: 2,
                    result_bytes: 65536,
                },
            )
            .unwrap();
            let identity = ExecutionIdentity {
                authority: [42; 32],
                subject: "client".into(),
                identity_digest: server_session.service_identity().unwrap().2,
            };
            let grant = ExecutionHistoryGrant::own_history(
                &server_session,
                history.clone(),
                identity.clone(),
                true,
                true,
            )
            .unwrap();
            let server_management = server_session
                .execution_management(vec![grant.clone()])
                .await
                .unwrap();
            // Reacquiring the same policy retains the original manager and its
            // serial sequence; a conflicting policy cannot replace it.
            let same_management = server_session
                .execution_management(vec![grant.clone()])
                .await
                .unwrap();
            let restricted = ExecutionHistoryGrant::own_history(
                &server_session,
                history.clone(),
                identity,
                true,
                false,
            )
            .unwrap();
            assert_eq!(
                server_session
                    .execution_management(vec![restricted])
                    .await
                    .unwrap_err()
                    .0,
                ServiceFailure::ConfigurationCapacity
            );
            let management = client_session
                .execution_management(Vec::new())
                .await
                .unwrap();
            let method = MethodDefinition::new(MethodDefinitionOptions {
                type_id: 101,
                shape: ServiceShape::Unary,
                semantics: ServiceSemantics::Execution,
                request: MessageDefinition::new([11; 32], "bytes.v1".into(), 128).unwrap(),
                response: Some(MessageDefinition::new([12; 32], "bytes.v1".into(), 128).unwrap()),
                response_revision: "bytes.v1".into(),
                request_max_bytes: 128,
                min_response_limit_bytes: 1,
                max_response_bytes: 128,
                require_durable: false,
                checkpoint_format: None,
                restart_flush_deadline_ms: restart.then_some(1000),
                streaming: None,
                content: None,
                errors: Vec::new(),
            })
            .unwrap();
            let definition = ServiceDefinition::new(
                "example/history".into(),
                vec![ServiceMethod {
                    name: "Echo".into(),
                    export_name: "echo".into(),
                    method: method.clone(),
                }],
            )
            .unwrap();
            let mut contract_fields = vec![
                (0, t("example/history")),
                (1, u(101)),
                (2, u(0)),
                (3, u(1)),
                (6, t("bytes.v1")),
                (7, t("bytes.v1")),
                (8, u(1)),
                (9, u(1)),
                (10, u(128)),
                (13, u(0)),
                (14, u(10000)),
                (15, u(5000)),
                (16, u(2000)),
                (17, u(10000)),
                (18, u(8000)),
                (19, u(1)),
                (21, vec![if restart { 0xf5 } else { 0xf4 }]),
                (23, u(128)),
                (27, vec![0x80]),
            ];
            if restart {
                contract_fields.push((22, u(1000)));
                contract_fields.sort_by_key(|(id, _)| *id);
            }
            let contract =
                ServiceContract::capture(&fixture.environment, &encode_map(&contract_fields))
                    .unwrap();
            let handler = Arc::new(Handler {
                entered: Semaphore::new(0),
                release: Semaphore::new(0),
                calls: AtomicUsize::new(0),
                publications: std::sync::Mutex::new(Vec::new()),
                foreign_maintenance: restart.then(|| {
                    fixture
                        .environment
                        .maintenance_owner(crate::MaintenanceOwnerOptions {
                            max_observations: 1,
                        })
                        .unwrap()
                }),
            });
            let query = FixedContractQuery {
                type_id: 1,
                contract_digest: [1; 32],
            };
            let result_read = FixedResultRead {
                type_id: 2,
                contract_digest: [2; 32],
                max_result_bytes: 128,
                grants: vec![grant],
            };
            let server = server_session
                .services_with_result_read(
                    query,
                    vec![UnaryServiceRegistration {
                        contract,
                        offer: None,
                        offer_window_ms: Some(2000),
                        query_allowed: true,
                        resident: false,
                        handler: handler.clone(),
                        execution: Some(history.clone()),
                        caller: Some(ExecutionIdentity {
                            authority: [42; 32],
                            subject: "client".into(),
                            identity_digest: server_session.service_identity().unwrap().2,
                        }),
                    }],
                    result_read.clone(),
                )
                .unwrap();
            let peer = client_session
                .services_with_result_read(
                    query,
                    Vec::new(),
                    FixedResultRead {
                        grants: Vec::new(),
                        ..result_read
                    },
                )
                .unwrap();
            let client = peer
                .bind(
                    definition,
                    vec![ServiceBindingOptions {
                        method: method.clone(),
                        acceptance: ContractAcceptance::exact(),
                        response_limit: ResponseLimitPolicy::Fixed(128),
                        execution_reference_identity: Some(crate::ExecutionReferenceIdentity {
                            target_domain: "history-test".into(),
                            tenant: "tenant".into(),
                            audience: "service".into(),
                            caller_subject: "client".into(),
                            caller_authority: [42; 32],
                        }),
                        streaming: None,
                        resume: None,
                    }],
                    Duration::from_secs(3),
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            let operation =
                verify_reference_save_receipts(&client, &method, &management, &handler).await;
            let reference = operation.reference().unwrap();
            let cancellation = CancellationToken::new();
            let before = management
                .query_operation(&reference, 1000, &cancellation)
                .await
                .unwrap();
            assert_eq!(before.absence, Some(ExecutionAbsence::NotRegistered));
            assert!(before.observation.is_none());
            assert_eq!(
                management
                    .request_cancel(&reference, 1000, &cancellation)
                    .await
                    .unwrap()
                    .cancellation,
                Some(ExecutionCancelResult::NotRegistered)
            );
            assert_eq!(handler.calls.load(Ordering::Acquire), 0);
            let canceled = CancellationToken::new();
            canceled.cancel();
            assert_eq!(
                management
                    .query_operation(&reference, 1000, &canceled)
                    .await
                    .unwrap_err()
                    .0,
                ServiceFailure::Canceled
            );
            operation.start().unwrap();
            tokio::time::timeout(Duration::from_secs(2), handler.entered.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
            let publication = handler.publications.lock().unwrap().pop().unwrap();
            if let Some(maintenance) = &maintenance {
                assert_eq!(maintenance.cleanup_status().pending_callbacks, 1);
                let canceled = CancellationToken::new();
                canceled.cancel();
                assert_eq!(
                    publication.wait(&canceled).await.unwrap_err().0,
                    ServiceFailure::Canceled
                );
                assert_eq!(
                    publication.state().state,
                    crate::ResponsePublicationState::Pending
                );
            }
            let active = management
                .query_operation(&reference, 1000, &cancellation)
                .await
                .unwrap()
                .observation
                .unwrap();
            assert_eq!(active.state, ExecutionState::Executing);
            assert!(active.work_active);
            assert!(!active.result_available);
            handler.release.add_permits(1);
            let response = operation
                .wait_encoded(CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(response.payload, b"retained result");
            assert_eq!(
                publication
                    .wait(&CancellationToken::new())
                    .await
                    .unwrap()
                    .state,
                if restart {
                    crate::ResponsePublicationState::Flushed
                } else {
                    crate::ResponsePublicationState::NotApplicable
                }
            );
            if let Some(maintenance) = &maintenance {
                maintenance.close();
                assert!(!maintenance.cleanup_status().complete);
                let canceled = CancellationToken::new();
                canceled.cancel();
                assert_eq!(
                    maintenance.wait_cleanup(&canceled).await.unwrap_err().0,
                    ServiceFailure::Canceled
                );
            }
            assert!(operation.wait_cleanup().await.complete);
            operation.close();
            drop(response);
            let completed = management
                .query_operation(&reference, 1000, &cancellation)
                .await
                .unwrap()
                .observation
                .unwrap();
            assert_eq!(completed.state, ExecutionState::Completed);
            assert!(!completed.work_active);
            assert!(completed.result_available);
            assert_eq!(
                management
                    .request_cancel(&reference, 1000, &cancellation)
                    .await
                    .unwrap()
                    .cancellation,
                Some(ExecutionCancelResult::Terminal)
            );
            assert_eq!(
                peer.read_result(&reference, Duration::from_secs(1), CancellationToken::new())
                    .await
                    .unwrap()
                    .as_ref(),
                b"retained result"
            );
            assert_eq!(handler.calls.load(Ordering::Acquire), 1);
            management.close();
            server_management.close();
            same_management.close();
            peer.close();
            server.close();
            client_session.close();
            server_session.close();
            assert!(management.wait_cleanup().await.complete);
            assert!(server_management.wait_cleanup().await.complete);
            let client_cleanup = client_session.wait_cleanup().await;
            assert!(
                client_cleanup.complete,
                "client={client_cleanup:?}; core={:?}; tails={:?}; worker={}; peer={:?}; server={:?}",
                client_session.core_cleanup_status(),
                client_session.owner.tails.status(),
                client_session.owner.worker_done.load(Ordering::Acquire),
                peer.cleanup_status(),
                server.cleanup_status()
            );
            assert!(server_session.wait_cleanup().await.complete);
            c_task.abort();
            s_task.abort();
            let _ = c_task.await;
            let _ = s_task.await;
            drop((
                client,
                peer,
                server,
                management,
                server_management,
                same_management,
                operation,
                reference,
                history,
                handler,
            ));
            drop((client_session, server_session));
            drop(publication);
            if let Some(maintenance) = maintenance {
                assert!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        maintenance.wait_cleanup(&CancellationToken::new())
                    )
                    .await
                    .unwrap()
                    .unwrap()
                    .complete
                );
                drop(maintenance);
            }
            let _ = fixture.environment.close().await;
        }
    }
}
