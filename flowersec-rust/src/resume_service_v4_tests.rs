mod registered_resume_regressions {
    use super::{link, Metadata, Profile};
    use crate::{ApplicationCheckpoint, ApplicationCheckpointToken, ApplicationResumeResult, ApplicationResumeStatus,
        BytesMessageCodec, ContractAcceptance, ExecutionIdentity, ExecutionInvocation, ExecutionRecoveryPolicy,
        ExecutionReferenceIdentity, ExecutionService, ExecutionServiceOptions, ExecutionState, FixedContractQuery,
        MessageDefinition, MethodDefinition, MethodDefinitionOptions, OperationReference, RegisteredResumeService,
        ResponseLimitPolicy, ResumeServiceConfig, ResumeServiceHandler, ResumeServiceRegistration, ServiceBindingOptions,
        ServiceContract, ServiceDefinition, ServiceError, ServiceFailure, ServiceMethod, ServiceResumeBinding,
        ServiceSemantics, ServiceShape, SQLiteExecutionStoreOptions, UnaryPrepareOptions, UnaryRequestContext,
        UnaryResponse, UnaryResumeServiceHandler, UnaryServiceHandler, UnaryServiceRegistration};
    use crate::codec_v4::tests::{encode_map, t, u};
    use crate::rpc_wire_v4::{ApplicationHeader, HeaderScalar};
    use crate::transport::ByteStream;
    use std::{sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}, time::Duration};
    use tokio::sync::{Semaphore, oneshot};
    use tokio_util::sync::CancellationToken;

    fn contract(environment: &crate::TransportEnvironment, id: u32, request_max: u32, response_max: u32) -> ServiceContract {
        ServiceContract::capture(environment, &encode_map(&[
            (0, t("example/recovery")), (1, u(id as u64)), (2, u(0)), (3, u(1)),
            (6, t("bytes.v1")), (7, t("bytes.v1")), (8, u(1)), (9, u(1)), (10, u(response_max as u64)),
            (13, u(1)), (14, u(10000)), (15, u(5000)), (16, u(2000)), (17, u(10000)), (18, u(8000)),
            (19, u(1)), (20, t("cursor.v1")), (21, vec![0xf4]), (23, u(request_max as u64)), (27, vec![0x80]),
        ])).unwrap()
    }
    fn method(id: u32, request_max: u32, response_max: u32) -> MethodDefinition {
        MethodDefinition::new(MethodDefinitionOptions { type_id: id, shape: ServiceShape::Unary, semantics: ServiceSemantics::Execution,
            request: MessageDefinition::new([id as u8; 32], "bytes.v1".into(), request_max).unwrap(),
            response: Some(MessageDefinition::new([id as u8 + 1; 32], "bytes.v1".into(), response_max).unwrap()),
            response_revision: "bytes.v1".into(), request_max_bytes: request_max, min_response_limit_bytes: 1, max_response_bytes: response_max,
            require_durable: true, checkpoint_format: Some("cursor.v1".into()), restart_flush_deadline_ms: None,
            streaming: None, content: None, errors: Vec::new() }).unwrap()
    }
    #[derive(Debug)]
    struct Original {
        token: Mutex<Option<oneshot::Sender<ApplicationCheckpointToken>>>, entries: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl UnaryServiceHandler for Original {
        async fn authorize(&self, _: UnaryRequestContext) -> Result<(), ServiceError> { Ok(()) }
        async fn handle(&self, context: UnaryRequestContext, _: &[u8]) -> Result<UnaryResponse, ServiceError> {
            self.entries.fetch_add(1, Ordering::AcqRel);
            let checkpoint = ApplicationCheckpoint::new("cursor.v1".into(), vec![7]).unwrap();
            let token = context.execution.as_ref().unwrap().issue_checkpoint(&checkpoint, 2000)?;
            self.token.lock().unwrap().take().unwrap().send(token).unwrap();
            Err(ServiceError(ServiceFailure::ServiceFailed))
        }
    }
    #[derive(Debug)]
    struct Continuation { entries: AtomicUsize, entered: Semaphore, release: Semaphore }
    #[async_trait::async_trait]
    impl UnaryResumeServiceHandler for Continuation {
        async fn authorize(&self, _: UnaryRequestContext, checkpoint: &ApplicationCheckpoint) -> Result<(), ServiceError> {
            if checkpoint.position() != [7] { return Err(ServiceError(ServiceFailure::PermissionDenied)); } Ok(())
        }
        async fn resume(&self, _: UnaryRequestContext, checkpoint: ApplicationCheckpoint, target: crate::Stream) -> Result<UnaryResponse, ServiceError> {
            assert_eq!(checkpoint.position(), [7]); self.entries.fetch_add(1, Ordering::AcqRel);
            target.write(bytes::Bytes::from_static(b"tail")).await.map_err(|_| ServiceError(ServiceFailure::ServiceUnavailable))?;
            self.entered.add_permits(1); self.release.acquire().await.unwrap().forget();
            Ok(UnaryResponse { payload: b"retained-original-result".to_vec(), application_error_code: None })
        }
    }
    fn binding(method: MethodDefinition, limit: u32, resume: Option<ServiceResumeBinding>) -> ServiceBindingOptions {
        ServiceBindingOptions { method, acceptance: ContractAcceptance::exact(), response_limit: ResponseLimitPolicy::Fixed(limit),
            execution_reference_identity: Some(ExecutionReferenceIdentity { target_domain: "recovery-test".into(),
                tenant: "tenant".into(), audience: "service".into(), caller_subject: "client".into(), caller_authority: [42; 32] }),
            streaming: None, resume }
    }
    fn request(account: &crate::environment_v4::ResourceAccount, contract: &ServiceContract, operation_byte: u8, payload: &[u8], resume: bool) -> ApplicationHeader {
        let now = account.security_time().unwrap();
        let mut operation = [operation_byte; 32]; operation[..8].copy_from_slice(&(now.lower_ms + 1500).to_be_bytes());
        let mut fields = [None; 11];
        fields[1] = Some(HeaderScalar::Bytes(operation)); fields[2] = Some(HeaderScalar::Uint(contract.type_id() as u64));
        fields[3] = Some(HeaderScalar::Uint(payload.len() as u64)); fields[4] = Some(HeaderScalar::Bytes([0; 32]));
        fields[5] = Some(HeaderScalar::Uint(now.lower_ms + 5000)); fields[6] = Some(HeaderScalar::Bytes(contract.digest()));
        fields[7] = Some(HeaderScalar::Uint(0)); fields[8] = Some(HeaderScalar::Uint(contract.uint(10).unwrap()));
        let kind = if resume { "resume_request" } else { "execution_unary_request" };
        let header = ApplicationHeader::create(kind, fields).unwrap();
        fields[4] = Some(HeaderScalar::Bytes(crate::rpc_wire_v4::execution_digest(contract.encoded(), &header, payload).unwrap()));
        ApplicationHeader::create(kind, fields).unwrap()
    }
    fn durable(environment: &crate::TransportEnvironment, path: std::path::PathBuf) -> ExecutionService {
        let service = ExecutionService::new_durable(environment, ExecutionServiceOptions { tenant: "tenant".into(), audience: "service".into(),
            namespace: "example/recovery".into(), caller_authorities: vec![[42; 32]], max_records: 16, max_active: 1, result_bytes: 65536 },
            SQLiteExecutionStoreOptions { path, max_pages: 64, provider_runtime_bytes: 262144, disk_overhead_bytes: 65536 }).unwrap();
        service.configure_recovery(ExecutionRecoveryPolicy { max_issued_duration_ms: 10000, max_token_bytes: 4980,
            max_checkpoint_issues_per_operation: 8, minimum_checkpoint_interval_ms: 0 },
            crate::ServiceCheckpointSigningKey::new(crate::CheckpointTokenProtection::HmacSha256, [5; 16], [6; 32]).unwrap()).unwrap();
        service
    }
    fn options() -> UnaryPrepareOptions { UnaryPrepareOptions { timeout: Duration::from_secs(3), ..UnaryPrepareOptions::default() } }
    fn scratch() -> tempfile::TempDir {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        tempfile::Builder::new().prefix("flowersec-recovery-regression-").tempdir_in(root).unwrap()
    }
    async fn inactive(service: &ExecutionService, reference: &OperationReference, identity: &ExecutionIdentity, session: &crate::Session) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let observed = service.observe_authorized(&reference.target(), identity, &session.application_account(), false, false, None, || Ok(())).unwrap();
                if observed.observation.as_ref().is_some_and(|observation| !observation.work_active) { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn registered_resume_transfers_one_active_slot_and_preserves_raw_target_after_result_close() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let directory = scratch(); let path = std::fs::canonicalize(directory.path()).unwrap().join("execution.sqlite");
        let service = durable(&fixture.environment, path.clone());
        let (client_session, server_session, c_task, s_task) = link(&fixture.environment, c, s);
        let identity = ExecutionIdentity { authority: [42; 32], subject: "client".into(), identity_digest: server_session.service_identity().unwrap().2 };
        let original_method = method(101, 128, 128); let resume_method = method(102, 9345, 4248);
        let original_contract = contract(&fixture.environment, 101, 128, 128); let resume_contract = contract(&fixture.environment, 102, 9345, 4248);
        let definition = ServiceDefinition::new("example/recovery".into(), vec![
            ServiceMethod { name: "Original".into(), export_name: "original".into(), method: original_method.clone() },
            ServiceMethod { name: "Resume".into(), export_name: "resume".into(), method: resume_method.clone() },
        ]).unwrap();
        let (token_send, token_recv) = oneshot::channel();
        let original = Arc::new(Original { token: Mutex::new(Some(token_send)), entries: AtomicUsize::new(0) });
        let continuation = Arc::new(Continuation { entries: AtomicUsize::new(0), entered: Semaphore::new(0), release: Semaphore::new(0) });
        let stream_binding = ServiceResumeBinding { stream_kind: "recover".into(), stream_metadata: Metadata::empty() };
        let registration = RegisteredResumeService::new(&fixture.environment, ResumeServiceConfig { binding: stream_binding.clone(),
            definition: definition.clone(), method: resume_method.clone(), contract: resume_contract, original_contract: original_contract.clone(),
            handler: ResumeServiceHandler::Unary(continuation.clone()), execution: service.clone(), offer: None, offer_window_ms: Some(2000) }).unwrap();
        let query = FixedContractQuery { type_id: 1, contract_digest: [1; 32] };
        let server = server_session.services(query, vec![UnaryServiceRegistration { contract: original_contract, offer: None, offer_window_ms: Some(2000),
            query_allowed: true, resident: false, handler: original.clone(), execution: Some(service.clone()), caller: Some(identity.clone()) }]).unwrap();
        server.attach_resume(vec![ResumeServiceRegistration { service: registration.clone(), caller: identity.clone(), query_allowed: true }]).unwrap();
        let peer = client_session.services(query, Vec::new()).unwrap();
        let client = peer.bind(definition, vec![binding(original_method.clone(), 128, None), binding(resume_method.clone(), 4248, Some(stream_binding))],
            Duration::from_secs(3), CancellationToken::new()).await.unwrap();
        let codec = Arc::new(BytesMessageCodec::new(original_method.options().request.clone()));
        let response_codec = Arc::new(BytesMessageCodec::new(original_method.options().response.clone().unwrap()));
        let operation = client.prepare_unary(&original_method, &vec![1], codec, response_codec,
            UnaryPrepareOptions { admission: crate::ServiceAdmission::TryNow, ..options() }).unwrap();
        let reference = operation.reference().unwrap();
        let (blocker_stream, blocker_peer) = tokio::join!(client_session.open_stream("staging-check", Metadata::empty(), 65536), async {
            server_session.next_open().await.unwrap().accept(65536).unwrap()
        });
        let blocker_stream = Arc::new(blocker_stream.unwrap());
        let mut blockers = Vec::new();
        for _ in 0..128 {
            match crate::WriteOperation::try_prepare(blocker_stream.clone(), bytes::Bytes::from(vec![0u8; 16384])) {
                Ok(blocker) => blockers.push(blocker),
                Err(crate::SessionError::ResourceExhausted) => break,
                Err(error) => panic!("unexpected staging refusal: {error:?}"),
            }
        }
        assert_eq!(operation.try_start().unwrap(), crate::ServiceStartResult::NotAdmitted {
            publication: crate::ServicePublication::NotSubmitted, reason: crate::ServiceStartRefusal::ResourceExhausted,
        });
        assert_eq!(operation.status(), crate::OperationStatus::NotStarted);
        assert_eq!(operation.reference().unwrap().target(), reference.target());
        assert_eq!(original.entries.load(Ordering::Acquire), 0);
        for blocker in &blockers { blocker.cancel(); }
        drop(blockers); blocker_stream.reset().await.unwrap(); blocker_peer.reset().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match operation.try_start().unwrap() {
                    crate::ServiceStartResult::Admitted => break,
                    crate::ServiceStartResult::NotAdmitted { reason: crate::ServiceStartRefusal::ResourceExhausted, .. } => tokio::task::yield_now().await,
                    refusal => panic!("unexpected retry of original prepared request: {refusal:?}"),
                }
            }
        }).await.unwrap();
        let token = token_recv.await.unwrap(); assert!(operation.wait_encoded(CancellationToken::new()).await.is_err());
        inactive(&service, &reference, &identity, &server_session).await;
        let dispatch = tokio::spawn({ let session = server_session.clone(); let handler = registration.raw_registration().handler;
            async move { let opening = session.next_open().await.unwrap(); crate::resume_service_v4::handle_sdk_resume_open(handler, opening, CancellationToken::new()).await } });
        let target = client_session.open_stream("recover", Metadata::empty(), 65536).await.unwrap();
        let recovery = client.prepare_resume(&resume_method, &target, &token, options()).unwrap();
        let recovery_reference = recovery.reference().unwrap(); recovery.start().unwrap();
        let result = recovery.wait_encoded(CancellationToken::new()).await.unwrap();
        let confirmation = ApplicationResumeResult::capture(&result.payload).unwrap();
        assert_eq!(confirmation.status(), ApplicationResumeStatus::Accepted); assert_eq!(confirmation.progress().unwrap().generation, token.generation() + 1);
        tokio::time::timeout(Duration::from_secs(3), continuation.entered.acquire()).await.unwrap().unwrap().forget();
        assert!(recovery.wait_cleanup().await.complete); recovery.close();
        assert_eq!(target.read().await.unwrap().unwrap().as_ref(), b"tail");
        let original_fact = service.observe_authorized(&reference.target(), &identity, &server_session.application_account(), false, false, None, || Ok(())).unwrap().observation.unwrap();
        let exchange_fact = service.observe_authorized(&recovery_reference.target(), &identity, &server_session.application_account(), false, false, None, || Ok(())).unwrap().observation.unwrap();
        assert!(original_fact.work_active); assert_eq!(original_fact.state, ExecutionState::Executing);
        assert!(!exchange_fact.work_active); assert!(exchange_fact.result_available);
        assert_eq!(original.entries.load(Ordering::Acquire), 1); assert_eq!(continuation.entries.load(Ordering::Acquire), 1);
        // The live store owns an exclusive SQLite connection. Inspect its
        // persisted rows under the store lock while the continuation is active.
        let active: u32 = service.with_test_store_connection(|database| database.query_row(
            "SELECT COUNT(*) FROM execution_record WHERE json_extract(CAST(metadata AS TEXT),'$.active')=1", [], |row| row.get(0)).unwrap());
        assert_eq!(active, 1);
        continuation.release.add_permits(1); inactive(&service, &reference, &identity, &server_session).await;
        let mut original_result = [0; 128]; let (count, code) = service.read_authorized(&reference.target(), &identity, &server_session.application_account(), false,
            &mut original_result, || Ok(())).unwrap();
        assert_eq!(&original_result[..count], b"retained-original-result"); assert_eq!(code, None);
        dispatch.await.unwrap().unwrap(); target.reset().await.unwrap(); operation.close(); peer.close(); server.close();
        client_session.close(); server_session.close(); c_task.abort(); s_task.abort();
        drop(service); let _ = fixture.environment.close().await; drop(fixture); drop(directory);
    }
    #[tokio::test]
    async fn lost_confirmation_reissuance_is_idempotent_and_refuses_entry_of_a_consumed_generation() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let directory = scratch(); let path = std::fs::canonicalize(directory.path()).unwrap().join("execution.sqlite");
        let service = durable(&fixture.environment, path.clone());
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let identity = ExecutionIdentity { authority: [42; 32], subject: "client".into(), identity_digest: server.service_identity().unwrap().2 };
        let account = server.application_account();
        let original_contract = contract(&fixture.environment, 101, 128, 128);
        let resume_contract = contract(&fixture.environment, 102, 9345, 4248);
        let issuance_contract = contract(&fixture.environment, 103, 128, 128);
        let offer = |contract: &ServiceContract| {
            let now = account.security_time().unwrap();
            crate::AdmissionOffer::current(contract, now.lower_ms, now.upper_ms, 2000).unwrap()
        };
        let original_header = request(&account, &original_contract, 1, b"original", false);
        let original = Arc::new(service.admit(&original_contract, &offer(&original_contract), &identity,
            &original_header, b"original", &account, || Ok(())).unwrap());
        original.enter(|| Ok(())).unwrap();
        let checkpoint = ApplicationCheckpoint::new("cursor.v1".into(), vec![7]).unwrap();
        let token = ExecutionInvocation::for_request(original.clone(), server.link(), &original_contract).unwrap().unwrap()
            .issue_checkpoint(&checkpoint, 2000).unwrap();
        let target = crate::ExecutionTarget { tenant: "tenant".into(), audience: "service".into(), namespace: "example/recovery".into(),
            caller_subject: identity.subject.clone(), caller_authority: identity.authority, operation_id: original_header.bytes(1).unwrap(),
            request_digest: original_header.bytes(4).unwrap(), contract_digest: original_contract.digest() };
        let codec = fixture.environment.operation_reference_codec("recovery-test".into()).unwrap();
        let reference = codec.capture(target.clone(), &original_header, &original_contract).unwrap();
        original.fail(ServiceFailure::ServiceUnavailable); original.exit();
        let (raw, accepted) = tokio::join!(client.open_stream("recover", Metadata::empty(), 65536), async { server.next_open().await.unwrap().accept(65536).unwrap() });
        let raw = raw.unwrap(); let (qualified, permit, mut claim) = accepted.claim_resume(&server, "recover").unwrap();
        let resume_payload = crate::checkpoint_v4::ApplicationResumeRequest::prepare(&token, claim.binding().clone()).unwrap().encoded().unwrap();
        let exchange_header = request(&account, &resume_contract, 2, &resume_payload, true);
        let exchange = Arc::new(service.admit(&resume_contract, &offer(&resume_contract), &identity,
            &exchange_header, &resume_payload, &account, || Ok(())).unwrap());
        exchange.enter(|| Ok(())).unwrap();
        let (continued, confirmation) = service.consume_checkpoint(&server, &target, &identity, &original_contract, token.encoded(),
            &checkpoint, token.generation(), &exchange, &resume_contract, &qualified).unwrap();
        assert_eq!(confirmation.status(), ApplicationResumeStatus::Accepted);
        // The durable confirmation exists, but no resumed callback has entered.
        continued.fail(ServiceFailure::ServiceUnavailable); continued.exit(); exchange.exit();
        drop(permit); claim.settle_unsubmitted(); drop(claim);
        let _ = qualified.reset().await;
        let _ = raw.reset().await;
        let _ = tokio::time::timeout(Duration::from_secs(1), qualified.wait_cleanup()).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), raw.wait_cleanup()).await;
        drop(raw); drop(qualified);
        let issuer_header = request(&account, &issuance_contract, 3, b"replace", false);
        let issuer = Arc::new(service.admit(&issuance_contract, &offer(&issuance_contract), &identity,
            &issuer_header, b"replace", &account, || Ok(())).unwrap());
        issuer.enter(|| Ok(())).unwrap();
        let issuance = ExecutionInvocation::for_request(issuer.clone(), server.link(), &issuance_contract).unwrap().unwrap();
        let replacement = issuance.reissue_checkpoint(&reference, &original_contract, token.encoded(), 1500).unwrap();
        let same = issuance.reissue_checkpoint(&reference, &original_contract, token.encoded(), 1500).unwrap();
        assert_eq!(replacement.encoded(), same.encoded()); assert_eq!(replacement.expires_at_ms(), same.expires_at_ms());
        assert_eq!(issuance.reissue_checkpoint(&reference, &original_contract, token.encoded(), 1000).unwrap_err().0, ServiceFailure::OperationConflict);
        assert_eq!(replacement.generation(), token.generation() + 2);
        issuer.exit();
        let (next_raw_result, next_accepted_result) = tokio::join!(
            client.open_stream("recover", Metadata::empty(), 65536),
            async { server.next_open().await.and_then(|open| open.accept(65536)) },
        );
        let next_raw = next_raw_result.unwrap_or_else(|error| panic!("next client open failed: {error:?}"));
        let next_accepted = next_accepted_result.unwrap_or_else(|error| panic!("next server accept failed: {error:?}"));
        let (next_qualified, next_permit, mut next_claim) = next_accepted.claim_resume(&server, "recover").unwrap();
        let next_payload = crate::checkpoint_v4::ApplicationResumeRequest::prepare(&replacement, next_claim.binding().clone()).unwrap().encoded().unwrap();
        let next_header = request(&account, &resume_contract, 4, &next_payload, true);
        let next_exchange = Arc::new(service.admit(&resume_contract, &offer(&resume_contract), &identity,
            &next_header, &next_payload, &account, || Ok(())).unwrap());
        next_exchange.enter(|| Ok(())).unwrap();
        let (entered, _) = service.consume_checkpoint(&server, &target, &identity, &original_contract, replacement.encoded(),
            &checkpoint, replacement.generation(), &next_exchange, &resume_contract, &next_qualified).unwrap();
        entered.enter(|| Ok(())).unwrap(); entered.fail(ServiceFailure::ServiceUnavailable); entered.exit(); next_exchange.exit();
        drop(next_permit); next_claim.settle_unsubmitted(); drop(next_claim);
        let another_header = request(&account, &issuance_contract, 5, b"replace-after-entry", false);
        let another = Arc::new(service.admit(&issuance_contract, &offer(&issuance_contract), &identity,
            &another_header, b"replace-after-entry", &account, || Ok(())).unwrap());
        another.enter(|| Ok(())).unwrap();
        let another_issuance = ExecutionInvocation::for_request(another.clone(), server.link(), &issuance_contract).unwrap().unwrap();
        assert_eq!(another_issuance.reissue_checkpoint(&reference, &original_contract, replacement.encoded(), 1500).unwrap_err().0,
            ServiceFailure::OperationConflict);
        drop(another_issuance);
        another.exit();
        drop(another); drop(entered); drop(continued); drop(next_exchange); drop(exchange); drop(original);
        drop(issuance); drop(issuer);
        service.0.close();
        drop(service);
        let database = rusqlite::Connection::open(&path).unwrap();
        database.busy_timeout(Duration::from_secs(3)).unwrap();
        let metadata: Vec<u8> = database.query_row("SELECT metadata FROM execution_record WHERE operation=?1",
            [target.operation_id.as_slice()], |row| row.get(0)).unwrap();
        let persisted: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(persisted["retained_checkpoint"]["consumption"]["callback_entered"], true);
        assert_eq!(persisted["retained_checkpoint"]["reissuance"]["requested_lifetime_ms"], 1500);
        assert!(persisted["run_started_ms"].as_u64().is_some_and(|started| started >= 1000)); drop(database);
        next_raw.reset().await.unwrap(); client.close(); server.close(); c_task.abort(); s_task.abort();
        let _ = fixture.environment.close().await; drop(fixture); drop(directory);
    }

    fn streaming_method(id: u32) -> MethodDefinition {
        let mut options = method(id, 128, 128).options().clone();
        options.shape = ServiceShape::ServerStreaming;
        options.streaming = Some(crate::StreamingLimits { max_item_count: 4, max_payload_bytes: 512, max_duration_ms: 5000 });
        MethodDefinition::new(options).unwrap()
    }
    fn streaming_contract(environment: &crate::TransportEnvironment, id: u32) -> ServiceContract {
        ServiceContract::capture(environment, &encode_map(&[
            (0, t("example/recovery")), (1, u(id as u64)), (2, u(1)), (4, u(1)),
            (6, t("bytes.v1")), (7, t("bytes.v1")), (8, u(1)), (9, u(1)), (10, u(128)),
            (13, u(1)), (14, u(10000)), (16, u(2000)), (17, u(10000)), (18, u(8000)),
            (19, u(1)), (20, t("cursor.v1")), (21, vec![0xf4]), (23, u(128)),
            (24, u(4)), (25, u(512)), (26, u(5000)), (27, vec![0x80]),
            (28, encode_map(&[(0, u(0))])),
        ])).unwrap()
    }
    #[derive(Debug)]
    struct StreamingOriginal {
        token: Mutex<Option<oneshot::Sender<ApplicationCheckpointToken>>>, entries: Arc<AtomicUsize>,
    }
    struct CheckpointItems { step: u8, token: Option<oneshot::Sender<ApplicationCheckpointToken>> }
    #[async_trait::async_trait]
    impl crate::StreamingItemSource for CheckpointItems {
        async fn next(&mut self, context: UnaryRequestContext) -> Result<Option<crate::ServiceStreamItem>, ServiceError> {
            if self.step == 0 {
                self.step = 1;
                return Ok(Some(crate::ServiceStreamItem { payload: b"head".to_vec(), application_error_code: None }));
            }
            let checkpoint = ApplicationCheckpoint::new("cursor.v1".into(), vec![7]).unwrap();
            let token = context.execution.as_ref().unwrap().issue_checkpoint(&checkpoint, 2000)?;
            self.token.take().unwrap().send(token).unwrap();
            Err(ServiceError(ServiceFailure::ServiceUnavailable))
        }
    }
    #[async_trait::async_trait]
    impl crate::StreamingServiceHandler for StreamingOriginal {
        async fn authorize(&self, _: UnaryRequestContext) -> Result<(), ServiceError> { Ok(()) }
        async fn start(&self, _: UnaryRequestContext, request: &[u8]) -> Result<Box<dyn crate::StreamingItemSource>, ServiceError> {
            assert_eq!(request, [1]); self.entries.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(CheckpointItems { step: 0, token: self.token.lock().unwrap().take() }))
        }
    }
    #[derive(Debug)]
    struct StreamingContinuation { entries: Arc<AtomicUsize> }
    struct TailItems(bool);
    #[async_trait::async_trait]
    impl crate::StreamingItemSource for TailItems {
        async fn next(&mut self, _: UnaryRequestContext) -> Result<Option<crate::ServiceStreamItem>, ServiceError> {
            if std::mem::replace(&mut self.0, false) {
                Ok(Some(crate::ServiceStreamItem { payload: b"tail".to_vec(), application_error_code: None }))
            } else { Ok(None) }
        }
    }
    #[async_trait::async_trait]
    impl crate::StreamingResumeServiceHandler for StreamingContinuation {
        async fn authorize(&self, _: UnaryRequestContext, checkpoint: &ApplicationCheckpoint) -> Result<(), ServiceError> {
            if checkpoint.position() != [7] { return Err(ServiceError(ServiceFailure::PermissionDenied)); } Ok(())
        }
        async fn resume(&self, _: UnaryRequestContext, checkpoint: ApplicationCheckpoint)
            -> Result<Box<dyn crate::StreamingItemSource>, ServiceError> {
            assert_eq!(checkpoint.position(), [7]); self.entries.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(TailItems(true)))
        }
    }
    struct AsyncStreamingBytes(MessageDefinition);
    #[async_trait::async_trait]
    impl crate::AsyncMessageCodec<Vec<u8>> for AsyncStreamingBytes {
        fn definition(&self) -> &MessageDefinition { &self.0 }
        fn application_bytes(&self) -> u64 { 1024 }
        async fn encode(&self, value: &Vec<u8>, context: crate::ApplicationInvocationContext) -> Result<Vec<u8>, ServiceError> {
            context.check_cancellation()?;
            Ok(value.clone())
        }
        async fn decode(&self, value: &[u8], context: crate::ApplicationInvocationContext) -> Result<Vec<u8>, ServiceError> {
            context.check_cancellation()?;
            Ok(value.to_vec())
        }
    }
    #[derive(Clone, Copy, Debug)]
    enum StreamingSaveBehavior { Unknown, Fail, Panic, CommitThenHold }
    #[derive(Debug)]
    struct StreamingSaveStore {
        behavior: StreamingSaveBehavior,
        bytes: u64,
        persistent: Arc<crate::SQLiteOperationReferenceStore>,
        entered: Semaphore,
        release: Semaphore,
        calls: AtomicUsize,
        persisted: Mutex<Option<OperationReference>>,
    }
    #[async_trait::async_trait]
    impl crate::OperationReferenceStore for StreamingSaveStore {
        fn application_bytes(&self) -> u64 { self.bytes }
        async fn save(&self, reference: OperationReference, context: crate::ApplicationInvocationContext)
            -> Result<crate::ReferenceSaveOutcome, ServiceError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            match self.behavior {
                StreamingSaveBehavior::Unknown => Ok(crate::ReferenceSaveOutcome::Unknown),
                StreamingSaveBehavior::Fail => Err(ServiceError(ServiceFailure::ServiceFailed)),
                StreamingSaveBehavior::Panic => panic!("controlled streaming reference store panic"),
                StreamingSaveBehavior::CommitThenHold => {
                    let result = crate::OperationReferenceStore::save(self.persistent.as_ref(), reference.clone(), context.clone()).await?;
                    assert_eq!(result, crate::ReferenceSaveOutcome::Confirmed);
                    let persisted = self.persistent.load(&reference, context).await?;
                    assert_eq!(persisted.as_ref(), Some(&reference));
                    *self.persisted.lock().unwrap() = persisted;
                    self.entered.add_permits(1);
                    self.release.acquire().await.unwrap().forget();
                    Ok(result)
                }
            }
        }
    }
    async fn prepare_saved_stream(
        client: &crate::ServiceClient,
        method: &MethodDefinition,
        asynchronous: bool,
        store: Arc<dyn crate::OperationReferenceStore>,
        cancellation: CancellationToken,
        timeout: Duration,
    ) -> Result<crate::SavedStreamingPreparation<Vec<u8>>, crate::PrepareAndSaveError> {
        let options = crate::StreamingPrepareOptions { timeout, ..Default::default() };
        if asynchronous {
            client.prepare_and_save_stream_async(method, Arc::new(vec![1]),
                Arc::new(AsyncStreamingBytes(method.options().request.clone())),
                Arc::new(AsyncStreamingBytes(method.options().response.clone().unwrap())),
                options, store, cancellation).await
        } else {
            client.prepare_and_save_stream(method, &vec![1],
                Arc::new(BytesMessageCodec::new(method.options().request.clone())),
                Arc::new(BytesMessageCodec::new(method.options().response.clone().unwrap())),
                options, store, cancellation).await
        }
    }
    fn assert_stream_reference_persisted(environment: &crate::TransportEnvironment, path: &std::path::Path, reference: &OperationReference) {
        let connection = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let codec = environment.operation_reference_codec("recovery-test".into()).unwrap();
        let mut statement = connection.prepare("SELECT canonical FROM operation_reference").unwrap();
        let references = statement.query_map([], |row| row.get::<_, Vec<u8>>(0)).unwrap()
            .map(|row| codec.import(&row.unwrap()).unwrap()).collect::<Vec<_>>();
        assert!(references.contains(reference), "the original canonical reference must be committed before Start is returned");
    }
    #[tokio::test]
    async fn public_streaming_resume_and_save_preserves_original_items_reference_and_target() {
        saved_streaming_resume(false).await;
    }
    #[tokio::test]
    async fn public_async_streaming_save_preserves_commit_after_observer_cancellation() {
        saved_streaming_resume(true).await;
    }
    async fn saved_streaming_resume(asynchronous: bool) {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let directory = scratch(); let base = std::fs::canonicalize(directory.path()).unwrap();
        let service = durable(&fixture.environment, base.join("execution.sqlite"));
        let reference_store = Arc::new(fixture.environment.sqlite_operation_reference_store(crate::SQLiteReferenceStoreOptions {
            path: base.join("references.sqlite"), target_domain: "recovery-test".into(), max_records: 16, max_pages: 64,
            provider_runtime_bytes: 262144, disk_overhead_bytes: 65536,
        }).unwrap());
        let (client_session, server_session, c_task, s_task) = link(&fixture.environment, c, s);
        let identity = ExecutionIdentity { authority: [42; 32], subject: "client".into(), identity_digest: server_session.service_identity().unwrap().2 };
        let original_method = streaming_method(104); let resume_method = method(105, 9345, 4248);
        let original_contract = streaming_contract(&fixture.environment, 104);
        let definition = ServiceDefinition::new("example/recovery".into(), vec![
            ServiceMethod { name: "Watch".into(), export_name: "watch".into(), method: original_method.clone() },
            ServiceMethod { name: "Resume".into(), export_name: "resume".into(), method: resume_method.clone() },
        ]).unwrap();
        let (token_send, token_recv) = oneshot::channel();
        let original_entries = Arc::new(AtomicUsize::new(0)); let resumed_entries = Arc::new(AtomicUsize::new(0));
        let stream_binding = crate::ServiceStreamBinding { stream_kind: "recover-stream".into(), stream_metadata: Metadata::empty() };
        let resume_binding = ServiceResumeBinding { stream_kind: stream_binding.stream_kind.clone(), stream_metadata: Metadata::empty() };
        let streaming = crate::RegisteredStreamingService::new(&fixture.environment, crate::StreamingServiceConfig {
            binding: stream_binding.clone(), definition: definition.clone(), method: original_method.clone(), contract: original_contract.clone(),
            handler: Arc::new(StreamingOriginal { token: Mutex::new(Some(token_send)), entries: original_entries.clone() }),
            execution: Some(service.clone()), offer: None, offer_window_ms: Some(2000),
        }).unwrap();
        let resume = RegisteredResumeService::new(&fixture.environment, ResumeServiceConfig {
            binding: resume_binding.clone(), definition: definition.clone(), method: resume_method.clone(),
            contract: contract(&fixture.environment, 105, 9345, 4248), original_contract,
            handler: ResumeServiceHandler::Streaming(Arc::new(StreamingContinuation { entries: resumed_entries.clone() })),
            execution: service.clone(), offer: None, offer_window_ms: Some(2000),
        }).unwrap();
        let query = FixedContractQuery { type_id: 1, contract_digest: [1; 32] };
        let server = server_session.services(query, Vec::new()).unwrap();
        server.attach_streaming(vec![crate::StreamingServiceRegistration { service: streaming.clone(), caller: Some(identity.clone()), query_allowed: true }]).unwrap();
        server.attach_resume(vec![ResumeServiceRegistration { service: resume.clone(), caller: identity.clone(), query_allowed: true }]).unwrap();
        let peer = client_session.services(query, Vec::new()).unwrap();
        let mut original_binding = binding(original_method.clone(), 128, None); original_binding.streaming = Some(stream_binding);
        let client = peer.bind(definition, vec![original_binding, binding(resume_method.clone(), 4248, Some(resume_binding))],
            Duration::from_secs(3), CancellationToken::new()).await.unwrap();
        let first_dispatch = tokio::spawn({ let session = server_session.clone(); let handler = streaming.raw_registration().handler;
            async move { crate::streaming_service_v4::handle_sdk_streaming_open(handler, session.next_open().await.unwrap(), CancellationToken::new()).await } });
        let item_codec = Arc::new(BytesMessageCodec::new(original_method.options().response.clone().unwrap()));
        let mut saved_references = Vec::new();
        // Failed persistence never returns a Start-capable handle or invokes
        // the original execution handler. The adapter's receipt is retained.
        for (behavior, bytes, expected) in [
            (StreamingSaveBehavior::Unknown, 0, ServiceFailure::ConfigurationCapacity),
            (StreamingSaveBehavior::Unknown, 1024, ServiceFailure::ServiceUnavailable),
            (StreamingSaveBehavior::Fail, 1024, ServiceFailure::ServiceFailed),
            (StreamingSaveBehavior::Panic, 1024, ServiceFailure::ServiceFailed),
        ] {
            let store = Arc::new(StreamingSaveStore { behavior, bytes, persistent: reference_store.clone(),
                entered: Semaphore::new(0), release: Semaphore::new(0), calls: AtomicUsize::new(0), persisted: Mutex::new(None) });
            let error = prepare_saved_stream(&client, &original_method, asynchronous, store.clone(),
                CancellationToken::new(), Duration::from_secs(3)).await.unwrap_err();
            let crate::PrepareAndSaveError::Save(failure) = error else { panic!("unexpected preparation failure: {error:?}"); };
            assert_eq!(failure.failure, expected);
            let receipt = failure.receipt.wait_settled(CancellationToken::new()).await.unwrap();
            assert!(receipt.settled);
            assert_eq!(receipt.attempted, bytes != 0);
            assert_eq!(receipt.application_input_provided, bytes != 0);
            assert_eq!(receipt.outcome, crate::ReferenceSaveOutcome::Unknown);
            assert_eq!(store.calls.load(Ordering::Acquire), usize::from(bytes != 0));
            assert_eq!(original_entries.load(Ordering::Acquire), 0);
        }
        // The durable write has really committed before cancellation. Closing
        // its observer must retain the callback tail and its eventual receipt.
        for by_deadline in [false, true] {
            let store = Arc::new(StreamingSaveStore { behavior: StreamingSaveBehavior::CommitThenHold, bytes: 32768,
                persistent: reference_store.clone(), entered: Semaphore::new(0), release: Semaphore::new(0), calls: AtomicUsize::new(0), persisted: Mutex::new(None) });
            let cancellation = CancellationToken::new();
            let pending = tokio::spawn({
                let client = client.clone(); let method = original_method.clone(); let store = store.clone(); let cancellation = cancellation.clone();
                async move { prepare_saved_stream(&client, &method, asynchronous, store, cancellation,
                    if by_deadline { Duration::from_millis(100) } else { Duration::from_secs(3) }).await }
            });
            tokio::time::timeout(Duration::from_secs(2), store.entered.acquire()).await.unwrap().unwrap().forget();
            assert_eq!(original_entries.load(Ordering::Acquire), 0);
            if !by_deadline { cancellation.cancel(); }
            let error = tokio::time::timeout(Duration::from_secs(2), pending).await.unwrap().unwrap().unwrap_err();
            let crate::PrepareAndSaveError::Save(failure) = error else { panic!("unexpected preparation failure: {error:?}"); };
            assert_eq!(failure.failure, if by_deadline { ServiceFailure::DeadlineExceeded } else { ServiceFailure::Canceled });
            assert!(!failure.receipt.snapshot().settled);
            assert_eq!(store.calls.load(Ordering::Acquire), 1);
            let saved_reference = failure.receipt.snapshot().reference;
            assert_eq!(store.persisted.lock().unwrap().as_ref(), Some(&saved_reference));
            saved_references.push(saved_reference);
            store.release.add_permits(1);
            let receipt = tokio::time::timeout(Duration::from_secs(2), failure.receipt.wait_settled(CancellationToken::new())).await.unwrap().unwrap();
            assert!(receipt.attempted && receipt.application_input_provided && receipt.settled);
            assert_eq!(receipt.outcome, crate::ReferenceSaveOutcome::Confirmed);
            assert_eq!(original_entries.load(Ordering::Acquire), 0);
        }
        let store = Arc::new(StreamingSaveStore { behavior: StreamingSaveBehavior::CommitThenHold, bytes: 32768,
            persistent: reference_store.clone(), entered: Semaphore::new(0), release: Semaphore::new(1), calls: AtomicUsize::new(0), persisted: Mutex::new(None) });
        let prepared = prepare_saved_stream(&client, &original_method, asynchronous, store.clone(),
            CancellationToken::new(), Duration::from_secs(3)).await.unwrap();
        let receipt = prepared.receipt.snapshot();
        assert!(receipt.attempted && receipt.application_input_provided && receipt.settled);
        assert_eq!(receipt.outcome, crate::ReferenceSaveOutcome::Confirmed);
        assert_eq!(receipt.reference, prepared.reference);
        assert_eq!(original_entries.load(Ordering::Acquire), 0);
        assert_eq!(store.persisted.lock().unwrap().as_ref(), Some(&prepared.reference));
        saved_references.push(prepared.reference.clone());
        let original = prepared.operation;
        let original_reference = original.reference().unwrap();
        assert_eq!(original_reference, prepared.reference);
        original.start().unwrap(); original.start().unwrap();
        let head = original.read_next_encoded(&CancellationToken::new()).await.unwrap().unwrap(); assert_eq!(head.payload, b"head");
        let token = token_recv.await.unwrap();
        let selector = original.resume_state().unwrap(); let mut exported = [0; 4096];
        let count = selector.export(&mut exported).unwrap();
        let selector = fixture.environment.import_streaming_resume_state(&exported[..count], original_reference.clone()).unwrap();
        inactive(&service, &original_reference, &identity, &server_session).await;
        original.close(); let _ = first_dispatch.await.unwrap();
        let resume_dispatch = tokio::spawn({ let session = server_session.clone(); let handler = resume.raw_registration().handler;
            async move { crate::resume_service_v4::handle_sdk_resume_open(handler, session.next_open().await.unwrap(), CancellationToken::new()).await } });
        let target = client_session.open_stream("recover-stream", Metadata::empty(), 65536).await.unwrap();
        let saved = client.prepare_stream_resume_and_save(&resume_method, &original_method, &target, &token, &selector,
            item_codec, Vec::new(), options(), reference_store.clone(), CancellationToken::new()).await.unwrap();
        assert_eq!(saved.receipt.snapshot().outcome, crate::ReferenceSaveOutcome::Confirmed);
        assert!(saved.operation.take_continuation().is_err());
        let recovery_reference = saved.reference.clone(); saved.operation.start().unwrap();
        let confirmation = saved.operation.operation.wait_encoded(CancellationToken::new()).await.unwrap();
        assert_eq!(ApplicationResumeResult::capture(&confirmation.payload).unwrap().status(), ApplicationResumeStatus::Accepted);
        let continuation = saved.operation.take_continuation().unwrap();
        assert_eq!(continuation.reference().unwrap(), original_reference);
        saved.operation.operation.close();
        let tail = continuation.read_next_encoded(&CancellationToken::new()).await.unwrap().unwrap(); assert_eq!(tail.payload, b"tail");
        assert!(continuation.read_next_encoded(&CancellationToken::new()).await.unwrap().is_none());
        assert_eq!(continuation.progress().complete_items, 2); assert_eq!(continuation.progress().complete_payload_bytes, 8);
        assert_eq!(original_entries.load(Ordering::Acquire), 1); assert_eq!(resumed_entries.load(Ordering::Acquire), 1);
        let recovered = service.observe_authorized(&recovery_reference.target(), &identity, &server_session.application_account(), false, false, None, || Ok(())).unwrap().observation.unwrap();
        let original_fact = service.observe_authorized(&original_reference.target(), &identity, &server_session.application_account(), false, false, None, || Ok(())).unwrap().observation.unwrap();
        assert!(recovered.result_available); assert_eq!(original_fact.state, ExecutionState::Completed);
        resume_dispatch.await.unwrap().unwrap(); continuation.close(); peer.close(); server.close(); client_session.close(); server_session.close();
        c_task.abort(); s_task.abort(); reference_store.close();
        assert!(reference_store.wait_cleanup(CancellationToken::new()).await.unwrap().complete);
        for reference in saved_references {
            assert_stream_reference_persisted(&fixture.environment, &base.join("references.sqlite"), &reference);
        }
        drop(reference_store); drop(service);
        let _ = fixture.environment.close().await; drop(fixture); drop(directory);
    }

}
