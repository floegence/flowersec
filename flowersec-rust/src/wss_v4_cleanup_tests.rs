use super::*;
use crate::environment_v4::tests::environment;

pub(crate) fn policy(address: std::net::SocketAddr) -> Policy {
    Policy {
        carrier: 1,
        preparation_budget: None,
        preparation_capacity: None,
        preparation_parallel: None,
        path_kind: 1,
        max_streams: 4,
        max_credit: 65536,
        artifact: [1; 32],
        binding_mode: BindingMode::AuthenticatedContext,
        host: "example.com".into(),
        port: address.port(),
        path: "/flowersec/v4/tunnel".into(),
        subprotocol: "flowersec.tunnel.v4".into(),
        origin: None,
        pins: None,
        maximum: 65544,
        live_maximum: 65544,
        ca: Vec::new(),
        relay_budget: None,
        original_prepare: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_tls_worker_ignores_receiver_wakes_until_done_and_retires_autonomously() {
    let root = environment();
    let (identity, _, _) = super::super::tests::tls_provisioning();
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
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
            rustls::pki_types::PrivatePkcs8KeyDer::from(identity.private_key_der.clone()).into(),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::net::TcpStream::connect(address).await.unwrap();
    let (tcp, _) = listener.accept().await.unwrap();
    let (sink, events) = crate::diagnostics_v4::capture_for_test(&root);
    let baseline = root.charged();
    let charge = root
        .reserve_environment(ResourceLimits {
            sdk_bytes: 1 << 20,
            provider_bytes: 2 << 20,
            items: 16,
            tasks: 6,
            work_slots: 8,
            timers: 3,
            connections: 1,
            native_handles: 8,
            ..ResourceLimits::default()
        })
        .unwrap();
    let tls_charge = root
        .reserve_environment(ResourceLimits {
            tls_handshakes: 1,
            ..ResourceLimits::default()
        })
        .unwrap();
    let diagnostic = root.diagnostic_activity(crate::DiagnosticPhase::Connect, 1);
    let cleanup = ConnectCleanup::new();
    let tail =
        direct_carrier::PreparationTail::with_diagnostic(cleanup.preparations(), &diagnostic)
            .with_cleanup(Some(cleanup.clone()));
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    let (retained, retained_provider) = oneshot::channel();
    let operation = tokio::spawn(Provider::accept_observed(
        root.clone(),
        tcp.into_std().unwrap(),
        serve::SocketPolicy {
            relay_unassigned: false,
            relay_budget: None,
            path_kind: 1,
            binding_mode: BindingMode::AuthenticatedContext,
            tls,
            host: "example.com".into(),
            authority: format!("example.com:{}", address.port()),
            allow_absent_origin: true,
            origins: Vec::new(),
            validity: (0, 100_000),
            maximum: 65544,
            publication_timeout: Duration::from_secs(1),
            queue_messages: 1,
            prepare_bytes: 16384,
        },
        Instant::now() + Duration::from_secs(5),
        cancellation,
        (charge.into(), tls_charge.into()),
        Some(tail),
        AcceptHooks {
            retain: move |provider: Arc<Provider>| {
                let receiver = provider.receiver().unwrap();
                // A second receiver's retirement wakes the original observer
                // while TLS still owns its current-thread runtime timers.
                drop(provider.receiver().unwrap());
                let _ = retained.send((provider, receiver));
            },
            authorize: |_| -> RequestAuthorizationFuture {
                Box::pin(async { panic!("an idle TLS peer cannot authorize") })
            },
        },
    ));
    let (provider, receiver) = retained_provider.await.unwrap();
    tokio::task::yield_now().await;
    assert!(!provider.done.load(Ordering::Acquire));
    assert!(!provider.preparation_observer_done.load(Ordering::Acquire));
    assert!(provider.charge.lock().unwrap().is_some());
    assert!(!cleanup.complete());
    cancel.cancel();
    assert!(matches!(
        operation.await.unwrap(),
        Err(ConnectError::Canceled)
    ));
    let first_close = cleanup.start();
    diagnostic.fail(
        crate::DiagnosticCode::Canceled,
        crate::DiagnosticRetryDisposition::DoNotRetry,
    );
    diagnostic.closed();
    assert!(root.charged().connections > baseline.connections);
    assert!(root.charged().tasks > baseline.tasks);
    assert!(!cleanup.complete());
    drop(receiver);
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
    assert!(provider.preparation_observer_done.load(Ordering::Acquire));
    assert!(provider.thread.lock().unwrap().is_none());
    assert!(provider.charge.lock().unwrap().is_none());
    assert_eq!(cleanup.start(), first_close);
    assert_eq!(root.charged().connections, baseline.connections);
    assert_eq!(root.charged().native_handles, baseline.native_handles);
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_authorization_frame_retains_charge_after_native_thread_exit() {
    let root = environment();
    let account = root
        .admit([33; 32], crate::environment_v4::tests::bounds())
        .unwrap();
    let (identity, _, digest) = super::super::tests::tls_provisioning();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
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
        rustls::pki_types::PrivatePkcs8KeyDer::from(identity.private_key_der.clone()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (sink, events) = crate::diagnostics_v4::capture_for_test(&root);
    let baseline = root.charged();
    let mut client_policy = policy(address);
    client_policy.pins = Some(vec![PinPolicy {
        digest,
        start: 0,
        end: 100_000,
    }]);
    let client = tokio::spawn(Provider::prepare(
        account,
        client_policy,
        WssConnectOptions {
            binding_mode: BindingMode::AuthenticatedContext,
            remote_address: address.ip(),
            origin: None,
            ca_certificates_der: Vec::new(),
            timeout: Duration::from_secs(5),
            publication_timeout: Duration::from_secs(1),
            queue_messages: 1,
            prepare_bytes: 16384,
            native_runtime_bytes: 2 << 20,
        },
        Instant::now() + Duration::from_secs(5),
        CancellationToken::new(),
    ));
    let (tcp, _) = listener.accept().await.unwrap();
    let charge = root
        .reserve_environment(ResourceLimits {
            sdk_bytes: 1 << 20,
            provider_bytes: 2 << 20,
            items: 16,
            tasks: 6,
            work_slots: 8,
            timers: 3,
            connections: 1,
            native_handles: 8,
            ..ResourceLimits::default()
        })
        .unwrap();
    let tls_charge = root
        .reserve_environment(ResourceLimits {
            tls_handshakes: 1,
            ..ResourceLimits::default()
        })
        .unwrap();
    let diagnostic = root.diagnostic_activity(crate::DiagnosticPhase::Connect, 1);
    let cleanup = ConnectCleanup::new();
    let tail =
        direct_carrier::PreparationTail::with_diagnostic(cleanup.preparations(), &diagnostic)
            .with_cleanup(Some(cleanup.clone()));
    let cancellation = CancellationToken::new();
    let (retained, retained_provider) = oneshot::channel();
    let (entered, authorization_entered) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let operation = tokio::spawn(Provider::accept_observed(
        root.clone(),
        tcp.into_std().unwrap(),
        serve::SocketPolicy {
            relay_unassigned: false,
            relay_budget: None,
            path_kind: 1,
            binding_mode: BindingMode::AuthenticatedContext,
            tls: Arc::new(tls),
            host: "example.com".into(),
            authority: format!("example.com:{}", address.port()),
            allow_absent_origin: true,
            origins: Vec::new(),
            validity: (0, 100_000),
            maximum: 65544,
            publication_timeout: Duration::from_secs(1),
            queue_messages: 1,
            prepare_bytes: 16384,
        },
        Instant::now() + Duration::from_secs(5),
        cancellation.clone(),
        (charge.into(), tls_charge.into()),
        Some(tail),
        AcceptHooks {
            retain: move |provider: Arc<Provider>| {
                let _ = retained.send(provider);
            },
            authorize: move |_| -> RequestAuthorizationFuture {
                Box::pin(async move {
                    let _ = entered.send(());
                    // Dropping the test's sender also releases this original
                    // callback if an earlier assertion fails.
                    let _ = released.await;
                    Ok(serve::RequestAuthorization { allowed: true })
                })
            },
        },
    ));
    let provider = retained_provider.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), authorization_entered)
        .await
        .unwrap()
        .unwrap();
    cancellation.cancel();
    diagnostic.fail(
        crate::DiagnosticCode::Canceled,
        crate::DiagnosticRetryDisposition::DoNotRetry,
    );
    diagnostic.closed();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let finished = provider.done.load(Ordering::Acquire)
                && provider
                    .thread
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(std::thread::JoinHandle::is_finished);
            if finished {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(!operation.is_finished());
    assert!(
        provider
            .accepted_preparation_pending
            .load(Ordering::Acquire)
    );
    assert!(provider.charge.lock().unwrap().is_some());
    assert!(!provider.cleanup().complete);
    assert!(!cleanup.complete());
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.state == crate::DiagnosticState::Closed)
    );
    release.send(()).unwrap();
    assert!(operation.await.unwrap().is_err());
    assert!(client.await.unwrap().is_err());
    tokio::time::timeout(Duration::from_secs(2), async {
        while !cleanup.complete()
            || root.charged().connections != baseline.connections
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
    assert!(
        !provider
            .accepted_preparation_pending
            .load(Ordering::Acquire)
    );
    assert!(provider.charge.lock().unwrap().is_none());
    assert_eq!(root.charged().provider_bytes, baseline.provider_bytes);
    assert_eq!(root.charged().native_handles, baseline.native_handles);
    {
        let captured = events.lock().unwrap();
        assert_eq!(
            captured
                .iter()
                .filter(|event| event.state == crate::DiagnosticState::Closed)
                .count(),
            1
        );
    }
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
}
