use super::wait_for_relay_assignment;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn assignment_before_reader_wait_is_observed() {
    let unassigned = AtomicBool::new(false);
    let assigned = tokio::sync::Notify::new();
    let cancellation = CancellationToken::new();
    let parent = CancellationToken::new();

    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_relay_assignment(&unassigned, &assigned, &cancellation, &parent),
        )
        .await
        .expect("assignment state was not observed")
    );
}

#[tokio::test]
async fn assignment_after_reader_wait_wakes_once() {
    let unassigned = AtomicBool::new(true);
    let assigned = tokio::sync::Notify::new();
    let cancellation = CancellationToken::new();
    let parent = CancellationToken::new();
    let wait = wait_for_relay_assignment(&unassigned, &assigned, &cancellation, &parent);
    tokio::pin!(wait);

    // Polling establishes that the real reader gate has registered its waiter
    // before assignment. A scheduler yield would not establish this ordering.
    poll_fn(|context| {
        assert!(matches!(wait.as_mut().poll(context), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    unassigned.store(false, Ordering::Release);
    assigned.notify_waiters();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("reader remained asleep after assignment")
    );
}

async fn cancellation_ends_wait(cancel_parent: bool) {
    let unassigned = AtomicBool::new(true);
    let assigned = tokio::sync::Notify::new();
    let cancellation = CancellationToken::new();
    let parent = CancellationToken::new();
    let wait = wait_for_relay_assignment(&unassigned, &assigned, &cancellation, &parent);
    tokio::pin!(wait);

    poll_fn(|context| {
        assert!(matches!(wait.as_mut().poll(context), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    if cancel_parent {
        parent.cancel();
    } else {
        cancellation.cancel();
    }
    assert!(
        !tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("cancellation did not end assignment wait")
    );
}

#[tokio::test]
async fn cancellation_ends_unassigned_wait() {
    cancellation_ends_wait(false).await;
}

#[tokio::test]
async fn parent_cancellation_ends_unassigned_wait() {
    cancellation_ends_wait(true).await;
}

struct AcceptedNative {
    root: std::sync::Arc<crate::environment_v4::EnvironmentRoot>,
    baseline: crate::environment_v4::ResourceLimits,
    provider: std::sync::Arc<super::Provider>,
    incoming: tokio::sync::mpsc::Receiver<Vec<u8>>,
    peer: flowersec_native_transport::RawQuicSession,
    listener: flowersec_native_transport::RawQuicListener,
}

impl AcceptedNative {
    async fn prepare(lifetime: Duration) -> Self {
        use super::*;
        use flowersec_native_transport::{RawQuicListener, RawQuicServerConfig};
        use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        let root = EnvironmentRoot::new(crate::environment_v4::TransportEnvironmentOptions {
            clock: Some(crate::environment_v4::tests::TestClock::new(1_000, 1_010)),
            ..Default::default()
        })
        .unwrap();
        let baseline = root.charged();
        let account = root
            .admit([0x73; 32], crate::environment_v4::tests::bounds())
            .unwrap();
        let (identity, ca, _) = super::super::tests::tls_provisioning();
        let limits = RawQuicLimits::for_session(16, Duration::from_secs(5)).unwrap();
        let listener = RawQuicListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            RawQuicServerConfig::new(
                PathProfile::TunnelV4,
                identity.certificate_chain_der.clone(),
                identity.private_key_der.clone(),
                limits,
            )
            .unwrap(),
        )
        .unwrap();
        let address = listener.local_address().unwrap();
        let cancellation = NativeCancellation::new();
        let configuration = RawQuicClientConfig::new_ca_with_time_provider(
            PathProfile::TunnelV4,
            vec![ca],
            limits,
            Arc::new(Clock(account)),
        )
        .unwrap();
        let (peer, accepted) = tokio::join!(
            RawQuicSession::dial(
                vec![address],
                "example.com".into(),
                configuration,
                &cancellation
            ),
            listener.accept(&cancellation),
        );
        let peer = peer.unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
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
            PrivatePkcs8KeyDer::from(identity.private_key_der.clone()).into(),
        )
        .unwrap();
        let charge = root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 1 << 20,
                provider_bytes: 4 << 20,
                items: 32,
                tasks: 16,
                work_slots: 16,
                timers: 8,
                connections: 1,
                native_handles: 16,
                ..ResourceLimits::default()
            })
            .unwrap();
        let tls_charge = root
            .reserve_environment(ResourceLimits {
                tls_handshakes: 1,
                ..ResourceLimits::default()
            })
            .unwrap();
        let (provider, incoming) = tokio::time::timeout(
            Duration::from_secs(1),
            Provider::accept_observed(
                root.clone(),
                Connection::Raw(accepted.unwrap()),
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
                    maximum: 4096,
                    publication_timeout: Duration::from_secs(1),
                    queue_messages: 4,
                    prepare_bytes: 16_384,
                },
                Instant::now() + lifetime,
                CancellationToken::new(),
                (charge.into(), tls_charge.into()),
                None,
                |_| {},
                |_| Box::pin(async { Ok(serve::RequestAuthorization { allowed: true }) }),
            ),
        )
        .await
        .expect("physical preparation waited for an invisible maintenance stream")
        .unwrap();
        assert!(provider.maintenance().is_err());
        Self {
            root,
            baseline,
            provider,
            incoming,
            peer,
            listener,
        }
    }

    async fn close(self, peer_stream: Option<flowersec_native_transport::RawQuicStream>) {
        self.provider.close();
        self.peer.abort();
        self.peer.wait_termination().await;
        if let Some(stream) = peer_stream {
            tokio::time::timeout(Duration::from_secs(3), stream.wait_termination_current())
                .await
                .expect("original peer stream callbacks did not retire");
            drop(stream);
        }
        self.listener.abort();
        self.listener.wait_termination().await;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !self.provider.cleanup().complete {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("original native callbacks did not retire");
        // The peer TLS verifier retains its independent clock Account until
        // the actual native connection handle is released.
        drop(self.peer);
        self.root.close();
        assert_eq!(self.root.cleanup(), (true, false));
        // The Environment's fixed account table remains allocated until its
        // own owner is dropped. Every provider and peer resource has returned.
        assert_eq!(self.root.charged(), self.baseline);
    }
}

fn maintenance_wire() -> Vec<u8> {
    let mut wire = vec![0; 12];
    wire[..4].copy_from_slice(&4u32.to_be_bytes());
    wire[4] = 16;
    wire[8..].copy_from_slice(b"test");
    wire
}

#[tokio::test]
async fn accepted_native_prepares_before_original_maintenance_publication() {
    let mut pair = AcceptedNative::prepare(Duration::from_secs(5)).await;
    let wire = maintenance_wire();
    let server = pair.provider.clone();
    let response = server.send(wire.clone());
    tokio::pin!(response);
    assert!(futures_util::poll!(response.as_mut()).is_pending());
    assert_eq!(server.maintenance_pending.load(Ordering::Acquire), 1);
    assert!(server.maintenance().is_err());
    let cancellation = flowersec_native_transport::Cancellation::new();
    let stream = pair.peer.open_stream(&cancellation).await.unwrap();
    stream.write_all_current(&wire).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), pair.incoming.recv())
            .await
            .unwrap()
            .unwrap(),
        wire
    );
    tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .unwrap()
        .unwrap();
    let mut received = Vec::new();
    while received.len() < wire.len() {
        received.extend(
            stream
                .read(wire.len() - received.len(), &cancellation)
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(received, wire);
    assert_eq!(server.maintenance_pending.load(Ordering::Acquire), 0);
    pair.close(Some(stream)).await;
}

#[tokio::test]
async fn accepted_native_close_wakes_original_maintenance_writer() {
    let pair = AcceptedNative::prepare(Duration::from_secs(5)).await;
    let provider = pair.provider.clone();
    let publication = provider.send(maintenance_wire());
    tokio::pin!(publication);
    assert!(futures_util::poll!(publication.as_mut()).is_pending());
    provider.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), publication)
            .await
            .unwrap()
            .is_err()
    );
    assert!(provider.maintenance().is_err());
    pair.close(None).await;
}

#[tokio::test]
async fn accepted_native_original_deadline_ends_maintenance_acceptance() {
    let pair = AcceptedNative::prepare(Duration::from_millis(200)).await;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            pair.provider.send(maintenance_wire())
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(pair.provider.maintenance().is_err());
    pair.close(None).await;
}
