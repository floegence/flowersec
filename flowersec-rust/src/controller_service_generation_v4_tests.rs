mod controller_service_generation_regressions {
    use super::{link, Profile};
    use crate::{BytesMessageCodec, ContractAcceptance, FixedContractQuery, MessageDefinition, MethodDefinition,
        MethodDefinitionOptions, ResponseLimitPolicy, ServiceBindingOptions, ServiceContract, ServiceDefinition,
        ServiceError, ServiceMethod, ServiceSemantics, ServiceShape, UnaryRequestContext,
        UnaryResponse, UnaryServiceHandler, UnaryServiceRegistration, UnaryPrepareOptions};
    use crate::codec_v4::tests::{encode_map, t, u};
    use std::{sync::Arc, time::Duration};
    use tokio_util::sync::CancellationToken;

    #[derive(Debug)]
    struct Echo;
    #[async_trait::async_trait]
    impl UnaryServiceHandler for Echo {
        async fn authorize(&self, _: UnaryRequestContext) -> Result<(), ServiceError> { Ok(()) }
        async fn handle(&self, _: UnaryRequestContext, request: &[u8]) -> Result<UnaryResponse, ServiceError> {
            Ok(UnaryResponse { payload: request.to_vec(), application_error_code: None })
        }
    }
    fn contract(environment: &crate::TransportEnvironment, maximum: u32) -> ServiceContract {
        ServiceContract::capture(environment, &encode_map(&[
            (0, t("example/controller")), (1, u(101)), (2, u(0)), (3, u(0)),
            (6, t("bytes.v1")), (7, t("bytes.v1")), (8, u(1)), (9, u(1)), (10, u(maximum as u64)),
            (11, u(1000)), (12, u(1000)), (21, vec![0xf4]), (23, u(128)), (27, vec![0x80]),
        ])).unwrap()
    }
    fn definition() -> (ServiceDefinition, MethodDefinition) {
        let message = MessageDefinition::new([11; 32], "bytes.v1".into(), 128).unwrap();
        let method = MethodDefinition::new(MethodDefinitionOptions {
            type_id: 101, shape: ServiceShape::Unary, semantics: ServiceSemantics::Transient,
            request: message.clone(), response: Some(message), response_revision: "bytes.v1".into(),
            request_max_bytes: 128, min_response_limit_bytes: 1, max_response_bytes: 128,
            require_durable: false, checkpoint_format: None, restart_flush_deadline_ms: None,
            streaming: None, content: None, errors: Vec::new(),
        }).unwrap();
        let definition = ServiceDefinition::new("example/controller".into(), vec![ServiceMethod {
            name: "Echo".into(), export_name: "echo".into(), method: method.clone(),
        }]).unwrap();
        (definition, method)
    }
    fn options(method: &MethodDefinition) -> ServiceBindingOptions {
        ServiceBindingOptions { method: method.clone(), acceptance: ContractAcceptance::exact(),
            response_limit: ResponseLimitPolicy::FollowContractMaximum, execution_reference_identity: None,
            streaming: None, resume: None }
    }
    #[tokio::test(start_paused = true)]
    async fn prepaid_replacement_binding_reuses_exact_verified_contract_and_keeps_old_operation() {
        async fn settle<F: std::future::Future>(work: F) -> F::Output {
            tokio::pin!(work);
            let watchdog = std::time::Instant::now();
            loop {
                assert!(watchdog.elapsed() < Duration::from_secs(10), "paused-clock work did not settle");
                // Keep the executor runnable while real RPC work settles, so
                // its idle auto-advance cannot spend the prepared deadline.
                tokio::select! {
                    biased;
                    result = &mut work => return result,
                    _ = tokio::task::yield_now() => {},
                }
            }
        }
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client_session, server_session, c_task, s_task) = link(&fixture.environment, c, s);
        let (definition, method) = definition();
        let original = contract(&fixture.environment, 128);
        let query = FixedContractQuery { type_id: 1, contract_digest: [1; 32] };
        let server = server_session.services(query, vec![UnaryServiceRegistration { contract: original.clone(),
            offer: None, offer_window_ms: None, query_allowed: true, resident: false,
            handler: Arc::new(Echo), execution: None, caller: None }]).unwrap();
        let peer = client_session.services(query, Vec::new()).unwrap();
        let binding = options(&method);
        let first = settle(peer.bind(definition.clone(), vec![binding.clone()], Duration::from_secs(2), CancellationToken::new())).await.unwrap();
        let request = Arc::new(BytesMessageCodec::new(method.options().request.clone()));
        let response = Arc::new(BytesMessageCodec::new(method.options().response.clone().unwrap()));
        let old_operation = first.prepare_unary(&method, &b"fixed-original".to_vec(), request, response,
            UnaryPrepareOptions { timeout: Duration::from_millis(500), ..UnaryPrepareOptions::default() }).unwrap();
        let original_deadline = old_operation.deadline();
        let prepared_at = tokio::time::Instant::now();
        let baseline = first.rebind_baseline().unwrap();
        let backing = client_session.application_account().reserve(
            crate::service_client_v4::ServiceBindingPreparation::preparation_limits(std::slice::from_ref(&binding)).unwrap()).unwrap();
        let replacement = settle(peer.bind_replacement_prepaid(definition, vec![binding], Duration::from_secs(2),
            CancellationToken::new(), backing, Some(baseline.clone()))).await.unwrap();
        assert!(!baseline.same_revision(&replacement.rebind_baseline().unwrap()));
        tokio::time::advance(Duration::from_millis(50)).await;
        assert_eq!(tokio::time::Instant::now().duration_since(prepared_at), Duration::from_millis(50));
        assert_eq!(old_operation.deadline(), original_deadline);
        old_operation.start().unwrap();
        assert_eq!(settle(old_operation.wait_encoded(CancellationToken::new())).await.unwrap().payload.as_slice(), b"fixed-original");
        assert_eq!(old_operation.progress().publication, crate::ServicePublication::Committed);
        peer.close(); server.close(); client_session.close(); server_session.close();
        c_task.abort(); s_task.abort();
    }
    #[tokio::test]
    async fn deferred_method_refusal_precedes_encoding_and_multi_refresh_preserves_success() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let (_, first) = definition();
        let mut second_options = first.options().clone(); second_options.type_id = 102;
        let second = MethodDefinition::new(second_options).unwrap();
        let definition = ServiceDefinition::new("example/controller".into(), vec![
            ServiceMethod { name: "Echo".into(), export_name: "echo".into(), method: first.clone() },
            ServiceMethod { name: "Deferred".into(), export_name: "deferred".into(), method: second.clone() },
        ]).unwrap();
        let query = FixedContractQuery { type_id: 1, contract_digest: [1; 32] };
        let server_peer = server.services(query, vec![UnaryServiceRegistration { contract: contract(&fixture.environment, 128),
            offer: None, offer_window_ms: None, query_allowed: true, resident: false, handler: Arc::new(Echo),
            execution: None, caller: None }]).unwrap();
        let peer = client.services(query, Vec::new()).unwrap();
        let service = peer.bind_selected(definition, vec![options(&first), options(&second)], crate::ServiceBindingSelection {
            initial_methods: Some(vec![first.clone()]),
        }, Vec::new(), Duration::from_secs(2), CancellationToken::new()).await.unwrap();
        assert_eq!(service.contract(&second).unwrap_err().0, crate::ServiceFailure::NotReady);
        let outcomes = service.refresh_methods(&[first, second], false, Duration::from_secs(2), CancellationToken::new()).await.unwrap();
        assert!(outcomes[0].result.is_ok()); assert!(outcomes[1].result.is_err());
        service.start_managed_offer_renewal(crate::ManagedOfferRenewal::default()).unwrap();
        service.close(); assert!(service.wait_cleanup().await.complete);
        peer.close(); server_peer.close(); client.close(); server.close(); c_task.abort(); s_task.abort();
    }
    #[tokio::test]
    async fn original_publication_gate_refuses_terminated_session_before_callback() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_limits(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let published = std::sync::atomic::AtomicBool::new(false);
        client.controller_publication_gate(|| published.store(true, std::sync::atomic::Ordering::Release)).unwrap();
        assert!(published.load(std::sync::atomic::Ordering::Acquire));
        client.close();
        assert!(client.controller_publication_gate(|| panic!("terminated Session cannot publish current")).is_err());
        server.close(); c_task.abort(); s_task.abort();
    }
    #[tokio::test]
    async fn session_capture_and_retain_do_not_reopen_a_drained_original_owner() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_limits(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        client.controller_dispatch_eligible().unwrap();
        let until = client.controller_retain_until(Duration::from_secs(1)).unwrap();
        let deadline = client.controller_retain_deadline(until).unwrap();
        let cutoff = tokio::time::Instant::now() + Duration::from_millis(20);
        assert_eq!(client.controller_install_retirement_deadline(cutoff), cutoff);
        assert_eq!(client.controller_install_retirement_deadline(deadline), cutoff);
        let drain = client.drain(Duration::from_secs(30)).unwrap();
        assert!(client.controller_dispatch_eligible().is_err());
        assert!(client.controller_retain_deadline(until).is_err());
        let original = client.owner.drain.lock().unwrap().as_ref().unwrap().clone();
        assert!(original.deadline() <= cutoff);
        drop(drain); client.close(); server.close(); c_task.abort(); s_task.abort();
    }
    #[derive(Debug)]
    struct DiagnosticBlockedEcho {
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
    }
    #[async_trait::async_trait]
    impl UnaryServiceHandler for DiagnosticBlockedEcho {
        async fn authorize(&self, _: UnaryRequestContext) -> Result<(), ServiceError> { Ok(()) }
        async fn handle(&self, _: UnaryRequestContext, request: &[u8]) -> Result<UnaryResponse, ServiceError> {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            Ok(UnaryResponse { payload: request.to_vec(), application_error_code: None })
        }
    }
    #[tokio::test]
    async fn diagnostics_follow_original_query_and_reselected_unary_across_cancel_wait() {
        use crate::{DiagnosticPhase, DiagnosticState, DiagnosticMetric, DiagnosticAttemptBucket};
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (sink, events) = crate::diagnostics_v4::capture_for_test(fixture.environment.root());
        let (client_session, server_session, c_task, s_task) = link(&fixture.environment, c, s);
        let (definition, method) = definition();
        let query = FixedContractQuery { type_id: 1, contract_digest: [1; 32] };
        let handler = Arc::new(DiagnosticBlockedEcho { entered: tokio::sync::Semaphore::new(0), release: tokio::sync::Semaphore::new(0) });
        let server = server_session.services(query, vec![UnaryServiceRegistration {
            contract: contract(&fixture.environment, 128), offer: None, offer_window_ms: None,
            query_allowed: true, resident: false, handler: handler.clone(), execution: None, caller: None,
        }]).unwrap();
        let peer = client_session.services(query, Vec::new()).unwrap();
        let service = peer.bind(definition, vec![options(&method)], Duration::from_secs(2), CancellationToken::new()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let ready = events.lock().unwrap().iter().filter(|event| event.phase == DiagnosticPhase::Application && event.state == DiagnosticState::Succeeded).count() == 2;
                if ready { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        let query_ids: std::collections::BTreeSet<_> = events.lock().unwrap().iter()
            .filter(|event| event.phase == DiagnosticPhase::Application && event.state == DiagnosticState::Started)
            .map(|event| event.correlation_id).collect();
        assert_eq!(query_ids.len(), 2, "caller and inbound query have independent original contexts");
        let failures = fixture.environment.diagnostic_metric(DiagnosticMetric::ApplicationFailures).total;
        let starts = fixture.environment.diagnostic_metric(DiagnosticMetric::ApplicationOperations).total;
        events.lock().unwrap().clear();
        let original = service.prepare_unary(&method, &b"original-diagnostic-operation".to_vec(),
            Arc::new(BytesMessageCodec::new(method.options().request.clone())),
            Arc::new(BytesMessageCodec::new(method.options().response.clone().unwrap())),
            UnaryPrepareOptions { timeout: Duration::from_millis(900), ..UnaryPrepareOptions::default() }).unwrap();
        let selected = service.reselect_unary(&method, &original).unwrap();
        assert_eq!(fixture.environment.diagnostic_metric(DiagnosticMetric::ApplicationOperations).total, starts + 1);
        selected.start().unwrap();
        handler.entered.acquire().await.unwrap().forget();
        let canceled = CancellationToken::new(); canceled.cancel();
        assert_eq!(selected.wait_encoded(canceled).await.unwrap_err().0, crate::ServiceFailure::Canceled);
        assert_eq!(fixture.environment.diagnostic_metric(DiagnosticMetric::ApplicationFailures).total, failures);
        handler.release.add_permits(1);
        assert_eq!(selected.wait_encoded(CancellationToken::new()).await.unwrap().payload, b"original-diagnostic-operation");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let ready = events.lock().unwrap().iter().filter(|event| event.phase == DiagnosticPhase::Application && event.state == DiagnosticState::Succeeded).count() == 2;
                if ready { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        let records = events.lock().unwrap().clone();
        let started: std::collections::BTreeSet<_> = records.iter().filter(|event| event.phase == DiagnosticPhase::Application && event.state == DiagnosticState::Started).map(|event| event.correlation_id).collect();
        let completed: std::collections::BTreeSet<_> = records.iter().filter(|event| event.phase == DiagnosticPhase::Application && event.state == DiagnosticState::Succeeded).map(|event| event.correlation_id).collect();
        assert_eq!(started.len(), 2);
        assert_eq!(started, completed);
        assert!(started.is_disjoint(&query_ids));
        assert!(records.iter().filter(|event| event.phase == DiagnosticPhase::Application).all(|event| event.attempt_bucket == DiagnosticAttemptBucket::One));
        assert!(!records.iter().any(|event| matches!(event.state, DiagnosticState::Failed | DiagnosticState::Canceled)));
        selected.close(); original.close(); service.close(); peer.close(); server.close();
        client_session.close(); server_session.close(); c_task.abort(); s_task.abort();
        sink.close(); assert!(sink.wait_cleanup().await.complete);
    }

}
