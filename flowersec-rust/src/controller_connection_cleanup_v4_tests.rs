use super::*;
use crate::{
    codec_v4::ActivationSource,
    crypto_v4::connect::Namespace,
    diagnostics_v4::{DiagnosticEvent, DiagnosticSink},
    environment_v4::{
        EnvironmentError, TransportEnvironmentOptions, TrustedTimeSample, TrustedTimeSource,
        tests::TestClock,
    },
    namespace_v4::verifier::credential::tests::Fixture,
    pool_v4::tests::StoreFixture,
};
use cert_test_builder::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::sync::{Condvar, atomic::AtomicBool};
use tokio::{net::TcpListener, sync::Semaphore};

const PROFILE: &str = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";

// Trusted time is an ordinary host dependency. Its synchronous TLS sample can
// remain in flight after Connect stops waiting. Stall only the real WSS worker,
// outside every SDK security/resource lock, without replacing the provider.
#[derive(Debug)]
struct HeldTlsClock {
    clock: Arc<TestClock>,
    armed: AtomicBool,
    entered: Semaphore,
    released: Mutex<bool>,
    changed: Condvar,
}
impl HeldTlsClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            clock: TestClock::new(1000, 1010),
            armed: AtomicBool::new(false),
            entered: Semaphore::new(0),
            released: Mutex::new(false),
            changed: Condvar::new(),
        })
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
impl TrustedTimeSource for HeldTlsClock {
    fn sample(&self) -> Result<TrustedTimeSample, EnvironmentError> {
        if self.armed.load(Ordering::Acquire)
            && std::thread::current().name() == Some("flowersec-v4-wss")
        {
            self.entered.add_permits(1);
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.changed.wait(released).unwrap();
            }
        }
        self.clock.sample()
    }
}
struct ReleaseClock(Arc<HeldTlsClock>);
impl Drop for ReleaseClock {
    fn drop(&mut self) {
        self.0.release();
    }
}

type Events = Arc<Mutex<Vec<DiagnosticEvent>>>;

async fn captured_through_marker(sink: &DiagnosticSink, captured: &Events) -> Vec<DiagnosticEvent> {
    let count = captured
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.phase == crate::DiagnosticPhase::Other)
        .count();
    let marker = sink.begin().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !marker.emit(
            crate::DiagnosticState::Other,
            crate::DiagnosticAttemptBucket::Other,
            crate::DiagnosticPhase::Other,
            crate::DiagnosticCode::Other,
            crate::DiagnosticRetryDisposition::Other,
            crate::DiagnosticDurationBucket::Other,
        ) {
            tokio::task::yield_now().await;
        }
        // The real callback lane is serial. This observed marker drains every
        // earlier event, including a premature Closed if one was emitted.
        loop {
            if captured
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.phase == crate::DiagnosticPhase::Other)
                .count()
                > count
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    captured.lock().unwrap().clone()
}

async fn controller_with_held_tls_tail(cancel_parent: bool) {
    let clock = HeldTlsClock::new();
    let _release_on_failure = ReleaseClock(clock.clone());
    let environment = TransportEnvironment::with_options(TransportEnvironmentOptions {
        clock: Some(clock.clone()),
        tenant_limits: ResourceLimits {
            sdk_bytes: 64 << 20,
            ..TransportEnvironmentOptions::default().tenant_limits
        },
        root_limits: ResourceLimits {
            sdk_bytes: 128 << 20,
            ..TransportEnvironmentOptions::default().root_limits
        },
        session_limits: ResourceLimits {
            sdk_bytes: 8 << 20,
            ..TransportEnvironmentOptions::default().session_limits
        },
        ..TransportEnvironmentOptions::default()
    })
    .unwrap();
    let mut fixture = Fixture::with_identity_and_environment(
        ActivationSource::PreauthorizedPool,
        PROFILE,
        None,
        environment,
    );
    let keys = fixture.environment.identity_keys(PROFILE).unwrap();
    fixture.set_client_keys(&keys);
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["example.com".into()]).unwrap();
    params.not_before = time::OffsetDateTime::UNIX_EPOCH;
    params.not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(100);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params.self_signed(&key).unwrap();
    let digest = Sha256::digest(certificate.der().as_ref()).into();
    fixture.set_wss_route(listener.local_addr().unwrap().port(), Some(digest));
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate.der().to_vec())],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let pool = StoreFixture::new(&fixture);
    let environment = Arc::new(fixture.environment);
    let source = crate::LocalDirectMaterialSource::preauthorized_pool(
        &environment,
        crate::PreauthorizedPoolSourceConfiguration {
            namespaces: vec![Arc::new(Namespace::new(fixture.verifier))],
            identity: keys,
            credentials: vec![crate::PoolCredentialBytes {
                artifact: fixture.artifact,
                client_certificate: fixture.client,
                server_certificate: fixture.server,
                activation: fixture.activation,
            }],
            spend_ledger: pool.store.clone(),
            provider: crate::WssConnectOptions {
                binding_mode: crate::BindingMode::AuthenticatedContext,
                remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                origin: None,
                ca_certificates_der: Vec::new(),
                timeout: Duration::from_secs(if cancel_parent { 20 } else { 3 }),
                publication_timeout: Duration::from_secs(2),
                queue_messages: 2,
                prepare_bytes: 65536,
                native_runtime_bytes: 1 << 20,
            },
            application_profile: crate::ApplicationProfile::Transport,
        },
    )
    .unwrap();
    let (sink, events) = crate::diagnostics_v4::capture_for_test(environment.root());
    let baseline = environment.resource_usage();
    let connections = Arc::new(AtomicUsize::new(0));
    let peer = tokio::spawn({
        let clock = clock.clone();
        let connections = connections.clone();
        async move {
            let (tcp, _) = listener.accept().await.unwrap();
            connections.fetch_add(1, Ordering::AcqRel);
            // Arm before the server sends its certificate. The original WSS
            // certificate verifier must sample this same trusted clock.
            clock.armed.store(true, Ordering::Release);
            let accepted = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                .accept(tcp)
                .await;
            drop(accepted);
            listener
        }
    });
    let parent = CancellationToken::new();
    let controller = MaterialConnectionController::new(
        environment.clone(),
        MaterialControllerOptions {
            sources: vec![ControllerMaterialSource {
                source: source.clone(),
                ownership: MaterialSourceOwnership::Borrowed,
            }],
            managed_services: Vec::new(),
            request: ConnectionRequest::default(),
            parent: parent.clone(),
            initialize_session: None,
            max_attempts_per_outage: 2,
            retry_after: Duration::from_millis(20),
            candidate_timeout: Duration::from_secs(30),
            retain_replaced_for: Duration::ZERO,
            drain_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), clock.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    if cancel_parent {
        parent.cancel();
    }
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let changed = controller.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if controller.progress().failure == Some(MaterialControllerError::CleanupIncomplete) {
                break;
            }
            changed.await;
        }
    })
    .await
    .unwrap();

    let progress = controller.progress();
    assert_eq!(progress.attempts, 1);
    assert_eq!(progress.generation, 0);
    assert!(controller.current().is_none());
    let facts = progress.connection_facts.unwrap();
    assert_eq!(facts.spend_state, crate::ConnectionSpendState::Unspent);
    assert_eq!(
        facts.admission_state,
        crate::ConnectionAdmissionState::NotStarted
    );
    assert_eq!(
        facts.network_ready,
        crate::ConnectionNetworkReady::NotStarted
    );
    let cleanup = controller
        .0
        .state
        .lock()
        .unwrap()
        .connection_cleanup
        .clone()
        .unwrap();
    assert!(!cleanup.status().complete);
    assert!(cleanup.status().pending_callbacks > 0);
    assert!(controller.cleanup_status().pending_callbacks > 0);
    assert!(!controller.cleanup_status().complete);
    assert!(environment.resource_usage().connections > baseline.connections);
    assert!(environment.resource_usage().provider_bytes > baseline.provider_bytes);
    assert!(environment.resource_usage().native_handles > baseline.native_handles);
    assert_eq!(
        environment
            .diagnostic_metric(crate::DiagnosticMetric::CleanupTimeouts)
            .total,
        1
    );
    assert_eq!(pool.rows(), 0);
    let before_release = captured_through_marker(&sink, &events).await;
    let started: Vec<_> = before_release
        .iter()
        .filter(|event| {
            event.phase == crate::DiagnosticPhase::Connect
                && event.state == crate::DiagnosticState::Started
        })
        .collect();
    assert_eq!(started.len(), 1);
    let id = started[0].correlation_id;
    let outcome = if cancel_parent {
        crate::DiagnosticState::Canceled
    } else {
        crate::DiagnosticState::Failed
    };
    let code = if cancel_parent {
        crate::DiagnosticCode::Canceled
    } else {
        crate::DiagnosticCode::Timeout
    };
    assert_eq!(
        before_release
            .iter()
            .filter(|event| event.correlation_id == id
                && event.state == outcome
                && event.code == code)
            .count(),
        1
    );
    assert!(
        !before_release.iter().any(
            |event| event.correlation_id == id && event.state == crate::DiagnosticState::Closed
        )
    );

    if !cancel_parent {
        assert_eq!(controller.progress().state, MaterialControllerState::Failed);
        assert_eq!(
            controller
                .replace_session(&CancellationToken::new())
                .await
                .unwrap_err(),
            MaterialControllerError::CleanupIncomplete
        );
        assert_eq!(controller.progress().attempts, 1);
        assert_eq!(connections.load(Ordering::Acquire), 1);
        assert!(Arc::ptr_eq(
            &cleanup,
            controller
                .0
                .state
                .lock()
                .unwrap()
                .connection_cleanup
                .as_ref()
                .unwrap()
        ));
    }
    controller.close();
    assert!(!controller.cleanup_status().complete);
    assert!(controller.cleanup_status().pending_callbacks > 0);
    clock.release();
    let listener = tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    assert!(controller.wait_cleanup().await.complete);
    assert_eq!(controller.cleanup_status().pending_callbacks, 0);
    assert!(cleanup.complete());
    assert!(
        controller
            .0
            .state
            .lock()
            .unwrap()
            .connection_cleanup
            .is_none()
    );
    let after_release = captured_through_marker(&sink, &events).await;
    assert_eq!(
        after_release
            .iter()
            .filter(
                |event| event.correlation_id == id && event.state == crate::DiagnosticState::Closed
            )
            .count(),
        1
    );
    assert_eq!(
        after_release
            .iter()
            .filter(|event| event.correlation_id == id && event.state == outcome)
            .count(),
        1
    );
    assert_eq!(connections.load(Ordering::Acquire), 1);
    assert_eq!(
        environment.resource_usage().connections,
        baseline.connections
    );
    assert_eq!(
        environment.resource_usage().provider_bytes,
        baseline.provider_bytes
    );
    assert_eq!(
        environment.resource_usage().native_handles,
        baseline.native_handles
    );
    drop(controller);
    drop(cleanup);
    drop(listener);
    source.close();
    drop(source);
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
    drop(pool);
    assert!(environment.close().await.unwrap().complete);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_preserves_original_controller_cleanup_incomplete() {
    controller_with_held_tls_tail(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_native_connect_prevents_controller_retry_and_replacement() {
    controller_with_held_tls_tail(false).await;
}
