use super::*;
use crate::environment_v4::tests::{bounds, environment};

fn original_capture(
    root: Arc<EnvironmentRoot>,
    address: std::net::SocketAddr,
    runtime_bytes: u64,
) -> (Arc<Capture>, WssConnectOptions) {
    let (identity, _, _) = super::super::tests::tls_provisioning();
    Capture::new(
        root,
        ReverseTunnelProviderOptions {
            listen_address: address,
            identity,
            origin: None,
            timeout: Duration::from_secs(5),
            publication_timeout: Duration::from_secs(1),
            queue_messages: 1,
            prepare_bytes: 16384,
            native_runtime_bytes: runtime_bytes,
        },
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_original_bind_retires_both_observation_tails_and_prepaid_charges() {
    let root = environment();
    let account = root.admit([31; 32], bounds()).unwrap();
    let occupied = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = occupied.local_addr().unwrap();
    let (capture, options) = original_capture(root.clone(), address, 2 << 20);
    let (sink, events) = crate::diagnostics_v4::capture_for_test(&root);
    let baseline = root.charged();
    let diagnostic = account.diagnostic_activity(crate::DiagnosticPhase::Connect, 1);
    let cleanup = ConnectCleanup::new();
    let result = capture
        .prepare_physical(
            account,
            None,
            wss::cleanup_tests::policy(address),
            options,
            Instant::now() + Duration::from_secs(2),
            CancellationToken::new(),
            None,
            None,
            Some(diagnostic.clone()),
            Some(cleanup.clone()),
        )
        .await;
    assert!(matches!(result, Err(ConnectError::Carrier)));
    diagnostic.fail(
        crate::DiagnosticCode::Other,
        crate::DiagnosticRetryDisposition::DoNotRetry,
    );
    diagnostic.closed();
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
    assert!(!capture.ready.load(Ordering::Acquire));
    assert_eq!(root.charged().connections, baseline.connections);
    assert_eq!(root.charged().provider_bytes, baseline.provider_bytes);
    assert_eq!(root.charged().tasks, baseline.tasks);
    assert_eq!(root.charged().native_handles, baseline.native_handles);
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
}

async fn native_original_accept_retires_autonomously(cancel: bool) {
    let root = environment();
    let account = root.admit([32; 32], bounds()).unwrap();
    let available = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = available.local_addr().unwrap();
    drop(available);
    // Both listener and accepted-connection reservations coexist under the
    // original 128 MiB root; each also covers the native 16 MiB receive bound.
    let (capture, options) = original_capture(root.clone(), address, 32 << 20);
    let mut policy = wss::cleanup_tests::policy(address);
    policy.carrier = 0;
    let (sink, events) = crate::diagnostics_v4::capture_for_test(&root);
    let baseline = root.charged();
    let diagnostic = account.diagnostic_activity(crate::DiagnosticPhase::Connect, 1);
    let cleanup = ConnectCleanup::new();
    let cancellation = CancellationToken::new();
    let owner = capture.clone();
    let caller = cancellation.clone();
    let observation = diagnostic.clone();
    let cleanup_owner = cleanup.clone();
    let timeout = if cancel {
        Duration::from_secs(5)
    } else {
        Duration::from_millis(500)
    };
    let mut preparation = tokio::spawn(async move {
        owner
            .prepare_physical(
                account,
                None,
                policy,
                options,
                Instant::now() + timeout,
                caller,
                None,
                None,
                Some(observation),
                Some(cleanup_owner),
            )
            .await
    });
    let observer = CancellationToken::new();
    tokio::select! {
        ready = capture.wait_ready(Duration::from_secs(2), &observer) => { ready.unwrap(); },
        result = &mut preparation => panic!("preparation exited before its real listener was ready: {result:?}"),
    }
    assert!(!cleanup.complete());
    assert!(root.charged().provider_bytes > baseline.provider_bytes);
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.state == crate::DiagnosticState::Closed)
    );
    if cancel {
        cancellation.cancel();
    }
    let result = tokio::time::timeout(Duration::from_secs(2), preparation)
        .await
        .unwrap()
        .unwrap();
    if cancel {
        assert!(matches!(result, Err(ConnectError::Canceled)));
    } else {
        assert!(matches!(result, Err(ConnectError::Deadline)));
    }
    let first_close = cleanup.start();
    diagnostic.fail(
        if cancel {
            crate::DiagnosticCode::Canceled
        } else {
            crate::DiagnosticCode::Timeout
        },
        crate::DiagnosticRetryDisposition::DoNotRetry,
    );
    diagnostic.closed();
    // Only observe original facts. No provider/listener cleanup probe drives
    // retirement after the public preparation has returned.
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
    assert_eq!(cleanup.start(), first_close);
    assert!(!capture.ready.load(Ordering::Acquire));
    assert_eq!(root.charged().provider_bytes, baseline.provider_bytes);
    assert_eq!(root.charged().tasks, baseline.tasks);
    assert_eq!(root.charged().native_handles, baseline.native_handles);
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_native_original_accept_returns_and_retires_autonomously() {
    native_original_accept_retires_autonomously(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_native_original_accept_returns_and_retires_autonomously() {
    native_original_accept_retires_autonomously(false).await;
}
