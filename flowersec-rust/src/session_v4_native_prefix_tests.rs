// Authentication, native registration and application publication share the
// original Session gate. These tests use real signed READY/OPEN records.
#[tokio::test]
async fn native_prefix_installs_before_a_waiting_bootstrap_writer_can_publish() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let (fixture, client, server) =
        crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
    let mut client = client.into_session().unwrap();
    let (outbound, mut records) = mpsc::channel(8);
    client
        .materialize_bootstrap(&mut Link {
            send: outbound,
            closed: false,
            publication: Arc::new(Mutex::new(None)),
        })
        .unwrap();
    let prefix = records.recv().await.unwrap();
    let (outbound, mut replies) = mpsc::channel(8);
    let server = fixture
        .environment
        .adopt_ready_session(
            server,
            Box::new(Link {
                send: outbound,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    let bootstrap = server
        .claim_rpc_bootstrap_prepared(StreamPreparation::new(server.application_account()).unwrap())
        .unwrap();
    let writing = bootstrap.write(Bytes::from_static(b"ready"));
    tokio::pin!(writing);
    poll_fn(|context| {
        assert!(matches!(writing.as_mut().poll(context), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    assert!(replies.try_recv().is_err());
    let receiver = server.receiver();
    let installed = {
        // Native publication may already own transport. Incoming prefix
        // registration must complete without acquiring that mutex.
        let _transport = server.owner.transport.lock().unwrap();
        receiver
            .native_prefix(&prefix, |binding| {
                assert_eq!(binding.scope(), 1);
                assert!(
                    matches!(
                        server.owner.drive.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ),
                    "a writer must not observe the prefix before its native position is installed"
                );
                Some(binding)
            })
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), writing)
            .await
            .unwrap()
            .unwrap(),
        5
    );
    let reply = replies.recv().await.unwrap();
    assert_eq!(reply[4], 8);
    client.receive(1, &reply).unwrap();
    let handle = client.bootstrap_stream_handle().unwrap();
    let mut payload = [0; 5];
    assert_eq!(
        client.read(&handle, &mut payload).unwrap(),
        ReadState::Data(5)
    );
    assert_eq!(&payload, b"ready");
    drop(installed);
    server.close();
    assert!(server.wait_cleanup().await.complete);
}

#[tokio::test]
async fn native_prefix_authentication_failure_never_installs_a_provider_position() {
    let (fixture, client, server) = record_pair_for_limits(Profile::X25519);
    let mut client = client.into_session().unwrap();
    let (outbound, mut records) = mpsc::channel(8);
    client
        .open_stream(
            "example.native",
            &[],
            1024,
            &mut Link {
                send: outbound,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            },
        )
        .unwrap();
    let mut prefix = records.recv().await.unwrap();
    *prefix.last_mut().unwrap() ^= 1;
    let (outbound, _replies) = mpsc::channel(8);
    let server = fixture
        .environment
        .adopt_ready_session(
            server,
            Box::new(Link {
                send: outbound,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    assert!(
        server
            .receiver()
            .native_prefix::<()>(&prefix, |_| {
                panic!("untrusted OPEN cannot allocate an authenticated provider position")
            })
            .is_err()
    );
    assert!(server.wait_cleanup().await.complete);
}

#[tokio::test]
async fn native_prefix_capacity_rejection_keeps_the_session_and_sibling_available() {
    let (fixture, client, server) = record_pair_for_limits(Profile::X25519);
    let mut client = client.into_session().unwrap();
    let (outbound, mut records) = mpsc::channel(8);
    let mut publisher = Link {
        send: outbound,
        closed: false,
        publication: Arc::new(Mutex::new(None)),
    };
    let first = client
        .open_stream("example.native", &[], 1024, &mut publisher)
        .unwrap();
    let prefix = records.recv().await.unwrap();
    let (outbound, mut replies) = mpsc::channel(8);
    let server = fixture
        .environment
        .adopt_ready_session(
            server,
            Box::new(Link {
                send: outbound,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    let receiver = server.receiver();
    assert!(
        receiver
            .native_prefix::<()>(&prefix, |_| None)
            .unwrap()
            .is_none()
    );
    let rejection = tokio::time::timeout(Duration::from_secs(1), replies.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rejection[4], 9);
    client.receive(0, &rejection).unwrap();
    assert!(first.view.rejected.load(Ordering::Acquire));
    let sibling = client
        .open_stream("example.native", &[], 1024, &mut publisher)
        .unwrap();
    let prefix = records.recv().await.unwrap();
    let binding = receiver.native_prefix(&prefix, Some).unwrap().unwrap();
    assert_eq!(binding.scope(), sibling.scope());
    let incoming = server.next_open().await.unwrap().accept(1024).unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(1), replies.recv())
        .await
        .unwrap()
        .unwrap();
    client.receive(0, &accepted).unwrap();
    client
        .write(&sibling, b"sibling", false, &mut publisher)
        .unwrap();
    binding.receive(&records.recv().await.unwrap()).unwrap();
    assert_eq!(
        incoming.read().await.unwrap().unwrap(),
        Bytes::from_static(b"sibling")
    );
    server.close();
    assert!(server.wait_cleanup().await.complete);
}
