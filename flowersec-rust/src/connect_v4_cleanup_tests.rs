use super::*;

#[test]
fn cleanup_incomplete_preserves_original_authorization_and_ready_facts() {
    for original in [
        ConnectError::Canceled,
        ConnectError::LiveAuthorizationUnknown,
        ConnectError::LiveAuthorized(PostAuthorizationFailure::Capacity),
        ConnectError::Spent(PostSpendFailure::Canceled),
        ConnectError::AdmissionUnknown {
            profile: ConnectionSourceProfile::PreauthorizedPool,
            failure: PostSpendFailure::Deadline,
        },
        ConnectError::Admitted {
            profile: ConnectionSourceProfile::LiveAuthority,
            failure: PostSpendFailure::Carrier,
        },
        ConnectError::Ready {
            profile: ConnectionSourceProfile::PreauthorizedPool,
            failure: PostSpendFailure::Protocol,
        },
    ] {
        let incomplete = original.cleanup_incomplete();
        assert_eq!(incomplete.connection_facts(), original.connection_facts());
        assert_eq!(
            incomplete.post_spend_failure(),
            original.post_spend_failure()
        );
        assert_eq!(incomplete.cleanup_incomplete(), incomplete);
    }
    assert_eq!(
        ConnectError::LiveAuthorized(PostAuthorizationFailure::Capacity)
            .cleanup_incomplete()
            .post_spend_failure(),
        PostSpendFailure::Capacity,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_wss_receiver_tail_remains_charged_after_original_connect_cleanup_bound() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, false).await;
    let peer = tokio::spawn(async move {
        let mut socket = server.socket().await.unwrap();
        while socket.next().await.is_some() {}
    });
    let input = OriginalDirectInput::Pool(material, pool.store.clone());
    let account = input.account();
    let (sink, events) = crate::diagnostics_v4::capture_for_test(environment.root());
    let before = environment.resource_usage();
    let work = account.reserve(controller_work_limits()).unwrap();
    let diagnostic = account.diagnostic_activity(crate::DiagnosticPhase::Connect, 1);
    let cleanup = ConnectCleanup::new();
    let (provider, incoming) = direct_carrier::Provider::prepare_tracked_observed(
        account,
        input.policy(&options, false).unwrap(),
        options,
        Instant::now() + Duration::from_secs(2),
        CancellationToken::new(),
        cleanup.preparations(),
        &diagnostic,
    )
    .await
    .unwrap();
    let receiver = provider.receiver().unwrap();
    // A winner confirmed earlier keeps that original total-cleanup origin.
    // Starting this close cannot grant another ten seconds.
    let origin = Instant::now() - Duration::from_millis(9950);
    *cleanup.started.lock().unwrap() = Some(origin);
    let deadline = cleanup.deadline();
    assert_eq!(deadline, origin + Duration::from_secs(10));
    assert_eq!(cleanup.start(), origin);
    provider.close();
    diagnostic.fail(
        crate::DiagnosticCode::Canceled,
        crate::DiagnosticRetryDisposition::DoNotRetry,
    );
    diagnostic.closed();
    assert!(!wait_connect_cleanup(None, Some(&provider), &cleanup, deadline).await);
    report_connect_cleanup_timeout(&diagnostic);
    assert!(!provider.cleanup().complete);
    assert!(!cleanup.complete());
    assert!(environment.resource_usage().connections > before.connections);
    assert!(environment.resource_usage().provider_bytes > before.provider_bytes);
    assert_eq!(
        environment
            .diagnostic_metric(crate::DiagnosticMetric::CleanupTimeouts)
            .total,
        1
    );
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.state == crate::DiagnosticState::Closed)
    );

    drop(receiver);
    drop(incoming);
    // The public Connect wait has returned. Only observe its aggregate facts:
    // another call to provider.cleanup() must not be needed to retire the tail.
    tokio::time::timeout(Duration::from_secs(2), async {
        while !cleanup.complete()
            || !events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.state == crate::DiagnosticState::Closed)
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    peer.await.unwrap();
    assert!(provider.cleanup().complete);
    diagnostic.closed();
    let captured = events.lock().unwrap().clone();
    assert_eq!(
        captured
            .iter()
            .filter(|event| event.state == crate::DiagnosticState::Canceled)
            .count(),
        1
    );
    assert_eq!(
        captured
            .iter()
            .filter(|event| event.state == crate::DiagnosticState::Closed)
            .count(),
        1
    );
    assert!(
        captured
            .iter()
            .all(|event| event.correlation_id == captured[0].correlation_id)
    );
    assert_eq!(environment.resource_usage().connections, before.connections);
    assert_eq!(
        environment.resource_usage().provider_bytes,
        before.provider_bytes
    );
    assert_eq!(
        environment.resource_usage().native_handles,
        before.native_handles
    );
    drop(work);
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
}

#[tokio::test]
async fn failed_candidate_cleanup_does_not_wait_for_an_unfinished_alternative() {
    let cleanup = ConnectCleanup::new();
    let tail = direct_carrier::PreparationTail::new(cleanup.preparations());
    *cleanup.started.lock().unwrap() = Some(Instant::now() - Duration::from_millis(9990));
    let waiting = std::future::pending::<
        ConnectResult<(direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)>,
    >();
    let result = finish_after_candidate_failure(waiting, 1, &cleanup.candidates[0], &cleanup).await;
    assert!(matches!(
        result,
        Err(ConnectError::CleanupIncomplete {
            failure: PostSpendFailure::Deadline,
            ..
        })
    ));
    assert!(!cleanup.complete());
    drop(tail);
    assert!(cleanup.complete());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_wss_tail_retires_without_another_public_cleanup_probe() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, false).await;
    let address = server.listener.local_addr().unwrap();
    let peer = tokio::spawn(async move { TcpStream::connect(address).await.unwrap() });
    let (tcp, _) = server.listener.accept().await.unwrap();
    let tcp = tcp.into_std().unwrap();
    let peer = peer.await.unwrap();
    let input = OriginalDirectInput::Pool(material, pool.store.clone());
    let policy = input.policy(&options, false).unwrap();
    let root = environment.root();
    let (sink, events) = crate::diagnostics_v4::capture_for_test(root);
    let before = environment.resource_usage();
    let mut limits = policy.preparation_limits(&options).unwrap();
    limits.tls_handshakes = 0;
    let charge = root.reserve_environment(limits).unwrap();
    let tls = root
        .reserve_environment(ResourceLimits {
            tls_handshakes: 1,
            ..ResourceLimits::default()
        })
        .unwrap();
    let diagnostic = root.diagnostic_activity(crate::DiagnosticPhase::Connect, 1);
    let cleanup = ConnectCleanup::new();
    let caller = CancellationToken::new();
    let retained = Mutex::new(None);
    let receiver = Mutex::new(None);
    let result = wss::Provider::accept(
        root.clone(),
        tcp,
        serve::SocketPolicy {
            relay_unassigned: false,
            relay_budget: None,
            path_kind: 0,
            binding_mode: BindingMode::AuthenticatedContext,
            tls: server.tls.clone(),
            host: "example.com".into(),
            authority: format!("example.com:{}", address.port()),
            allow_absent_origin: true,
            origins: Vec::new(),
            validity: (0, 100_000),
            maximum: policy.maximum,
            publication_timeout: options.publication_timeout,
            queue_messages: options.queue_messages,
            prepare_bytes: options.prepare_bytes,
        },
        Instant::now() + Duration::from_secs(2),
        caller.clone(),
        (charge.into(), tls.into()),
        wss::AcceptHooks {
            retain: |provider: Arc<wss::Provider>| {
                provider.retain_connect_diagnostic(diagnostic.clone());
                provider.retain_connect_preparation(direct_carrier::PreparationTail::new(
                    cleanup.preparations(),
                ));
                *receiver.lock().unwrap() = Some(provider.receiver().unwrap());
                *retained.lock().unwrap() = Some(provider);
                caller.cancel();
            },
            authorize: |_| -> wss::RequestAuthorizationFuture {
                Box::pin(async { panic!("canceled TLS preparation cannot authorize a request") })
            },
        },
    )
    .await;
    assert!(matches!(result, Err(ConnectError::Canceled)));
    let provider = retained.into_inner().unwrap().unwrap();
    diagnostic.fail(
        crate::DiagnosticCode::Canceled,
        crate::DiagnosticRetryDisposition::DoNotRetry,
    );
    diagnostic.closed();
    assert!(!cleanup.complete());
    assert!(!provider.cleanup().complete);
    assert!(environment.resource_usage().tasks > before.tasks);
    assert!(environment.resource_usage().native_handles > before.native_handles);
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.state == crate::DiagnosticState::Closed)
    );
    drop(receiver.into_inner().unwrap());
    drop(peer);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !cleanup.complete()
            || !events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.state == crate::DiagnosticState::Closed)
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(provider.cleanup().complete);
    assert_eq!(environment.resource_usage().tasks, before.tasks);
    assert_eq!(
        environment.resource_usage().native_handles,
        before.native_handles
    );
    assert_eq!(environment.resource_usage().connections, before.connections);
    let captured = events.lock().unwrap().clone();
    assert_eq!(
        captured
            .iter()
            .filter(|event| event.state == crate::DiagnosticState::Canceled)
            .count(),
        1
    );
    assert_eq!(
        captured
            .iter()
            .filter(|event| event.state == crate::DiagnosticState::Closed)
            .count(),
        1
    );
    assert!(
        captured
            .iter()
            .all(|event| event.correlation_id == captured[0].correlation_id)
    );
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_public_connect_future_closes_its_original_diagnostic_after_native_exit() {
    let Setup {
        environment,
        material,
        pool,
        options,
        server,
    } = setup(Profile::X25519, true, false).await;
    let source = ordinary_pool_source(&environment, material, pool.store.clone(), options);
    let (sink, events) = crate::diagnostics_v4::capture_for_test(environment.root());
    let before = environment.resource_usage();
    let (entered, receive_entered) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let mut socket = server.socket().await.unwrap();
        receive(&mut socket, 1).await;
        entered.send(()).unwrap();
        while socket.next().await.is_some() {}
    });
    let mut connect = Box::pin(environment.connect(
        &source,
        crate::ConnectionRequest::default(),
        CancellationToken::new(),
    ));
    tokio::select! {
        _ = receive_entered => {},
        result = &mut connect => panic!("Connect settled before the held handshake: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("original handshake did not enter"),
    }
    drop(connect);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.state == crate::DiagnosticState::Closed)
            || environment.resource_usage().connections != before.connections
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    peer.await.unwrap();
    let captured = events.lock().unwrap().clone();
    assert_eq!(
        captured.iter().map(|event| event.state).collect::<Vec<_>>(),
        vec![
            crate::DiagnosticState::Started,
            crate::DiagnosticState::Canceled,
            crate::DiagnosticState::Closed
        ]
    );
    assert!(
        captured
            .iter()
            .all(|event| event.correlation_id == captured[0].correlation_id)
    );
    assert_eq!(
        environment.resource_usage().provider_bytes,
        before.provider_bytes
    );
    assert_eq!(
        environment.resource_usage().native_handles,
        before.native_handles
    );
    source.close();
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
}
