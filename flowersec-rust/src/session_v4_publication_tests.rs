// Pump only real records published by the original bounded provider.
async fn crypto_deliver_frame(input: &mut mpsc::Receiver<Vec<u8>>, peer: &Session, frame: u8) {
    loop {
        let wire = tokio::time::timeout(Duration::from_secs(2), input.recv())
            .await
            .unwrap()
            .unwrap();
        let reached = wire[4] == frame;
        peer.receive(&wire).unwrap();
        if reached {
            return;
        }
    }
}
async fn crypto_reverse_data(
    client: &Session,
    server: &Session,
    outgoing: &Stream,
    incoming: &Stream,
    c_rx: &mut mpsc::Receiver<Vec<u8>>,
    s_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let mut maintenance = Vec::new();
    incoming
        .write(Bytes::from_static(b"reverse"))
        .await
        .unwrap();
    loop {
        let wire = tokio::time::timeout(Duration::from_secs(2), s_rx.recv())
            .await
            .unwrap()
            .unwrap();
        if wire[4] == 8 {
            client.receive(&wire).unwrap();
            break;
        }
        maintenance.push(wire);
    }
    outgoing
        .write(Bytes::from_static(b"forward"))
        .await
        .unwrap();
    loop {
        let wire = tokio::time::timeout(Duration::from_secs(2), c_rx.recv())
            .await
            .unwrap()
            .unwrap();
        if wire[4] == 8 {
            server.receive(&wire).unwrap();
            break;
        }
        maintenance.push(wire);
    }
    // Both bound application lanes authenticate before either Read schedules
    // a CREDIT. Other real maintenance records remain in flight while their
    // original direction is held; native application delivery is independent.
    assert_eq!(
        outgoing.read().await.unwrap().unwrap(),
        Bytes::from_static(b"reverse")
    );
    assert_eq!(
        incoming.read().await.unwrap().unwrap(),
        Bytes::from_static(b"forward")
    );
    maintenance
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_session_held_open_and_retirement_digests_preserve_close_and_physical_tail() {
    for profile in [Profile::X25519, Profile::P256] {
        for retirement in [false, true] {
            for seal in [true, false] {
                let (fixture, c, s) = record_pair_for_limits(profile);
                let (client, server, mut c_rx, mut s_rx) =
                    crypto_manual_link(&fixture.environment, c, s);
                let (outgoing, incoming) =
                    crypto_open_manual(&client, &server, &mut c_rx, &mut s_rx).await;
                let target = if seal { client.clone() } else { server.clone() };
                let scope = if retirement { 0 } else { 3 };
                let frame = if retirement { 9 } else { 7 };
                let hold = target
                    .owner
                    .run_state(|session| {
                        Ok(session.engine.hold_record_crypto(scope, frame, seal, true))
                    })
                    .unwrap();
                let c = client.clone();
                let runtime = tokio::runtime::Handle::current();
                let mut opening = Some(tokio::task::spawn_blocking(move || {
                    runtime.block_on(c.open_stream("example.digest", Metadata::empty(), 8))
                }));
                let receiving = if retirement {
                    server.receive(&crypto_wire(&mut c_rx, 7).await).unwrap();
                    server.next_open().await.unwrap().reject().unwrap();
                    client.receive(&crypto_wire(&mut s_rx, 9).await).unwrap();
                    assert_eq!(
                        opening.take().unwrap().await.unwrap().unwrap_err(),
                        SessionError::StreamRejected
                    );
                    if seal {
                        None
                    } else {
                        let wire = crypto_wire(&mut c_rx, 9).await;
                        let original = server.clone();
                        Some(tokio::task::spawn_blocking(move || original.receive(&wire)))
                    }
                } else if seal {
                    None
                } else {
                    let wire = crypto_wire(&mut c_rx, 7).await;
                    let original = server.clone();
                    Some(tokio::task::spawn_blocking(move || original.receive(&wire)))
                };
                assert!(
                    hold.wait_entered(),
                    "the original Session must complete the real digest"
                );
                if !seal {
                    target
                        .owner
                        .run_state(|session| {
                            if retirement {
                                assert!(session.engine.streams.incoming.is_none());
                            } else {
                                assert!(session.engine.streams.index(3).is_none());
                            }
                            Ok(())
                        })
                        .unwrap();
                }
                let _in_flight = crypto_reverse_data(
                    &client, &server, &outgoing, &incoming, &mut c_rx, &mut s_rx,
                )
                .await;
                let closing = target.clone();
                tokio::time::timeout(
                    Duration::from_secs(1),
                    tokio::task::spawn_blocking(move || closing.close()),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(!target.cleanup_status().complete);
                assert!(target.cleanup_status().pending_callbacks >= 1);
                let charged = fixture.environment.resource_usage();
                assert!(charged.sdk_bytes > 0 && charged.work_slots > 0);
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), target.wait_cleanup())
                        .await
                        .is_err()
                );
                hold.release();
                if let Some(receiving) = receiving {
                    assert!(receiving.await.unwrap().is_err());
                }
                assert!(
                    tokio::time::timeout(Duration::from_secs(2), target.wait_cleanup())
                        .await
                        .unwrap()
                        .complete
                );
                // The late OPEN/RETIRE result never reaches the provider.
                if seal && retirement {
                    assert!(c_rx.try_recv().is_err());
                }
                if seal && !retirement {
                    while let Ok(wire) = c_rx.try_recv() {
                        assert_ne!(wire[4], 7, "late OPEN ciphertext reached the provider");
                    }
                }
                client.close();
                server.close();
                if let Some(opening) = opening {
                    assert!(opening.await.unwrap().is_err());
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_session_late_open_digest_retains_original_epoch_freeze_and_outcome() {
    for profile in [Profile::X25519, Profile::P256] {
        let (fixture, c, s) = record_pair_for_limits(profile);
        let (client, server, mut c_rx, mut s_rx) = crypto_manual_link(&fixture.environment, c, s);
        let hold = client
            .owner
            .run_state(|session| Ok(session.engine.hold_record_crypto(1, 7, true, true)))
            .unwrap();
        let c = client.clone();
        let runtime = tokio::runtime::Handle::current();
        let opening = tokio::task::spawn_blocking(move || {
            runtime.block_on(c.open_stream("example.late-open", Metadata::empty(), 8))
        });
        assert!(hold.wait_entered());
        let c = client.clone();
        let rekey = tokio::spawn(async move { c.rekey().await });
        server.receive(&crypto_wire(&mut c_rx, 6).await).unwrap();
        assert_ne!(
            server
                .owner
                .run_state(|session| Ok(session.engine.incoming_barrier_refs(1)))
                .unwrap(),
            0
        );
        assert!(!rekey.is_finished());
        hold.release();
        let wire = crypto_wire(&mut c_rx, 7).await;
        assert_eq!(u32::from_be_bytes(wire[8..12].try_into().unwrap()), 0);
        server.receive(&wire).unwrap();
        let incoming = server.next_open().await.unwrap().accept(8).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !opening.is_finished() || !rekey.is_finished() {
                tokio::select! {
                    wire = c_rx.recv() => { server.receive(&wire.unwrap()).unwrap(); },
                    wire = s_rx.recv() => { client.receive(&wire.unwrap()).unwrap(); },
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
        })
        .await
        .unwrap();
        let outgoing = opening.await.unwrap().unwrap();
        rekey.await.unwrap().unwrap();
        outgoing.write(Bytes::from_static(b"new")).await.unwrap();
        crypto_deliver_frame(&mut c_rx, &server, 8).await;
        assert_eq!(
            incoming.read().await.unwrap().unwrap(),
            Bytes::from_static(b"new")
        );
        client.close();
        server.close();
    }
}

fn crypto_manual_link(
    environment: &TransportEnvironment,
    c: RecordEngine,
    s: RecordEngine,
) -> (
    Session,
    Session,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
) {
    let (c_tx, c_rx) = mpsc::channel(32);
    let (s_tx, s_rx) = mpsc::channel(32);
    let client = environment
        .adopt_ready_session(
            c,
            Box::new(Link {
                send: c_tx,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    let server = environment
        .adopt_ready_session(
            s,
            Box::new(Link {
                send: s_tx,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    (client, server, c_rx, s_rx)
}
async fn crypto_wire(input: &mut mpsc::Receiver<Vec<u8>>, frame: u8) -> Vec<u8> {
    let wire = tokio::time::timeout(Duration::from_secs(2), input.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wire[4], frame);
    wire
}
async fn crypto_open_manual(
    client: &Session,
    server: &Session,
    c_rx: &mut mpsc::Receiver<Vec<u8>>,
    s_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> (Stream, Stream) {
    let c = client.clone();
    let opening =
        tokio::spawn(async move { c.open_stream("example.crypto", Metadata::empty(), 8).await });
    server.receive(&crypto_wire(c_rx, 7).await).unwrap();
    let incoming = server.next_open().await.unwrap().accept(8).unwrap();
    client.receive(&crypto_wire(s_rx, 9).await).unwrap();
    (opening.await.unwrap().unwrap(), incoming)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_session_held_aead_preserves_independent_work_freeze_and_physical_tail() {
    for profile in [Profile::X25519, Profile::P256] {
        for seal in [true, false] {
            let (fixture, c, s) = record_pair_for_limits(profile);
            let (client, server, mut c_rx, mut s_rx) =
                crypto_manual_link(&fixture.environment, c, s);
            let (outgoing, incoming) =
                crypto_open_manual(&client, &server, &mut c_rx, &mut s_rx).await;
            let target = if seal { client.clone() } else { server.clone() };
            let hold = target
                .owner
                .run_state(|session| {
                    Ok(session.engine.hold_record_crypto(
                        outgoing.inner.handle.scope(),
                        8,
                        seal,
                        false,
                    ))
                })
                .unwrap();
            let baseline = fixture.environment.resource_usage();
            let writing = if seal {
                let stream = outgoing.clone();
                let runtime = tokio::runtime::Handle::current();
                tokio::task::spawn_blocking(move || {
                    runtime.block_on(stream.write(Bytes::from_static(b"late")))
                })
            } else {
                outgoing.write(Bytes::from_static(b"late")).await.unwrap();
                let wire = crypto_wire(&mut c_rx, 8).await;
                let original = server.clone();
                tokio::task::spawn_blocking(move || original.receive(&wire).map(|_| 4))
            };
            assert!(
                hold.wait_entered(),
                "the public Session must reach actual AEAD completion"
            );
            if seal {
                assert!(fixture.environment.resource_usage().sdk_bytes > baseline.sdk_bytes);
            } else {
                // Receive borrows its already charged original input slot.
                assert!(target.owner.crypto.pending() >= 1);
                assert!(fixture.environment.resource_usage().work_slots >= baseline.work_slots);
            }
            incoming
                .write(Bytes::from_static(b"reverse"))
                .await
                .unwrap();
            client.receive(&crypto_wire(&mut s_rx, 8).await).unwrap();
            assert_eq!(
                outgoing.read().await.unwrap().unwrap(),
                Bytes::from_static(b"reverse")
            );
            let rekey = if seal {
                let c = client.clone();
                let rekey = tokio::spawn(async move { c.rekey().await });
                // Reading reverse DATA may schedule CREDIT before INIT.
                loop {
                    let wire = tokio::time::timeout(Duration::from_secs(2), c_rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    server.receive(&wire).unwrap();
                    if wire[4] == 6 {
                        break;
                    }
                }
                assert_ne!(
                    server
                        .owner
                        .run_state(|session| Ok(session
                            .engine
                            .incoming_barrier_refs(outgoing.inner.handle.scope())))
                        .unwrap(),
                    0
                );
                assert!(
                    !rekey.is_finished(),
                    "freeze must retain the not-yet-published DATA ticket"
                );
                Some(rekey)
            } else {
                // Native reliable directions can deliver maintenance separately
                // from this original bound application receive job.
                let s = server.clone();
                let probing =
                    tokio::spawn(async move { s.probe_liveness(Duration::from_secs(2)).await });
                client.receive(&crypto_wire(&mut s_rx, 14).await).unwrap();
                loop {
                    let wire = tokio::time::timeout(Duration::from_secs(2), c_rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    server.receive(&wire).unwrap();
                    if wire[4] == 15 {
                        break;
                    }
                }
                assert_eq!(
                    probing.await.unwrap().unwrap().outcome,
                    ProbeOutcome::Responsive
                );
                None
            };
            if !seal {
                target
                    .owner
                    .run_state(|session| {
                        let index = session
                            .engine
                            .streams
                            .index(incoming.inner.handle.scope())
                            .unwrap();
                        assert_eq!(
                            session.engine.streams.slots[index].directions[0]
                                .current
                                .offset,
                            0
                        );
                        Ok(())
                    })
                    .unwrap();
            }
            let closing = target.clone();
            tokio::time::timeout(
                Duration::from_secs(1),
                tokio::task::spawn_blocking(move || closing.close()),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!target.cleanup_status().complete);
            assert!(target.cleanup_status().pending_callbacks >= 1);
            let charged = fixture.environment.resource_usage();
            assert!(charged.sdk_bytes > 0 && charged.work_slots > 0);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), target.wait_cleanup())
                    .await
                    .is_err()
            );
            if !seal {
                assert_eq!(
                    outgoing
                        .inner
                        .handle
                        .view
                        .authenticated
                        .load(Ordering::Acquire),
                    0
                );
            }
            hold.release();
            assert!(writing.await.unwrap().is_err());
            if !seal {
                assert_eq!(
                    outgoing
                        .inner
                        .handle
                        .view
                        .authenticated
                        .load(Ordering::Acquire),
                    0
                );
                assert!(
                    incoming.read().await.is_err(),
                    "closed receive must never deliver late DATA"
                );
            }
            if let Some(rekey) = rekey {
                assert!(rekey.await.unwrap().is_err());
            }
            if seal {
                assert_eq!(
                    outgoing.inner.handle.view.accepted.load(Ordering::Acquire),
                    0
                );
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(2), target.wait_cleanup())
                    .await
                    .unwrap()
                    .complete
            );
            client.close();
            server.close();
        }
    }
}

// Real blocking native-publication regression coverage. The transport holds
// its synchronous provider call while authenticated state and Close progress.
#[derive(Default)]
struct PublicationGate {
    state: Mutex<(usize, bool, bool, bool)>,
    changed: Condvar,
    entered: Notify,
    physical_done: AtomicBool,
}
impl PublicationGate {
    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.2 = true;
        state.3 = true;
        self.changed.notify_all();
    }
    fn release_publication(&self) {
        let mut state = self.state.lock().unwrap();
        state.3 = true;
        self.changed.notify_all();
    }
    fn publication_idle(&self) -> bool {
        !self.state.lock().unwrap().1
    }
    fn cleanup(&self) -> CleanupStatus {
        let state = self.state.lock().unwrap();
        let complete = state.2 && !state.1 && self.physical_done.load(Ordering::Acquire);
        CleanupStatus {
            complete,
            cleanup_incomplete: false,
            pending_callbacks: u64::from(!complete),
        }
    }
}
struct BlockingLink {
    inner: Link,
    gate: Arc<PublicationGate>,
    frame: u8,
    ordinal: usize,
    fail: bool,
}
impl RecordPublisher for BlockingLink {
    fn try_claim_data(&mut self, scope: u64, maximum: usize) -> Result<DataPublicationClaim> {
        self.inner.try_claim_data(scope, maximum)
    }
    fn data_publication_permitted(&self, scope: u64) -> bool {
        self.inner.data_publication_permitted(scope)
    }
    fn publish(&mut self, record: &[u8]) -> Result<()> {
        if record.get(4) == Some(&self.frame) {
            let mut state = self.gate.state.lock().unwrap();
            state.0 += 1;
            if state.0 == self.ordinal {
                state.1 = true;
                self.gate.entered.notify_one();
                while !state.3 {
                    state = self.gate.changed.wait(state).unwrap();
                }
                state.1 = false;
                if self.fail {
                    return Err(CryptoError::State);
                }
            }
        }
        self.inner.publish(record)
    }
}
impl SessionTransport for BlockingLink {
    fn close(&mut self) {
        self.gate.close();
        self.inner.close();
    }
    fn close_signal(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let gate = self.gate.clone();
        Some(Arc::new(move || gate.close()))
    }
    fn cleanup_signal(&self) -> Option<Arc<dyn Fn() -> CleanupStatus + Send + Sync>> {
        let gate = self.gate.clone();
        Some(Arc::new(move || gate.cleanup()))
    }
    fn cleanup_status(&self) -> CleanupStatus {
        self.gate.cleanup()
    }
    fn stream_cleanup_status(&self, _: u64) -> CleanupStatus {
        self.gate.cleanup()
    }
}
// A legal provider may expose an independent cleanup observer without an
// independent close signal. Close must remain owned by the original transport
// mutex in that combination.
struct CleanupOnlyBlockingLink {
    inner: BlockingLink,
}
impl RecordPublisher for CleanupOnlyBlockingLink {
    fn try_claim_data(&mut self, scope: u64, maximum: usize) -> Result<DataPublicationClaim> {
        self.inner.try_claim_data(scope, maximum)
    }
    fn data_publication_permitted(&self, scope: u64) -> bool {
        self.inner.data_publication_permitted(scope)
    }
    fn publish(&mut self, record: &[u8]) -> Result<()> {
        self.inner.publish(record)
    }
}
impl SessionTransport for CleanupOnlyBlockingLink {
    fn close(&mut self) {
        self.inner.close();
    }
    fn cleanup_signal(&self) -> Option<Arc<dyn Fn() -> CleanupStatus + Send + Sync>> {
        let gate = self.inner.gate.clone();
        Some(Arc::new(move || gate.cleanup()))
    }
    fn cleanup_status(&self) -> CleanupStatus {
        self.inner.gate.cleanup()
    }
    fn stream_cleanup_status(&self, _: u64) -> CleanupStatus {
        self.inner.gate.cleanup()
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successful_prefix_survives_blocked_tail_and_close_waits_for_physical_cleanup() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (_sink, events) = crate::diagnostics_v4::capture_for_test(fixture.environment.root());
    let application_before = fixture
        .environment
        .root()
        .diagnostic_metric(crate::DiagnosticMetric::ApplicationOperations)
        .total;
    let gate = Arc::new(PublicationGate::default());
    let (c_tx, mut c_rx) = mpsc::channel(32);
    let (s_tx, mut s_rx) = mpsc::channel(32);
    let client = fixture
        .environment
        .adopt_ready_session(
            c,
            Box::new(BlockingLink {
                inner: Link {
                    send: c_tx,
                    closed: false,
                    publication: Arc::new(Mutex::new(None)),
                },
                gate: gate.clone(),
                frame: 8,
                ordinal: 2,
                fail: true,
            }),
        )
        .unwrap();
    let server = fixture
        .environment
        .adopt_ready_session(
            s,
            Box::new(Link {
                send: s_tx,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    let c_target = server.clone();
    let c_task = tokio::spawn(async move {
        while let Some(wire) = c_rx.recv().await {
            let _ = c_target.receive(&wire);
        }
    });
    let s_target = client.clone();
    let s_task = tokio::spawn(async move {
        while let Some(wire) = s_rx.recv().await {
            let _ = s_target.receive(&wire);
        }
    });
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("example.publication", Metadata::empty(), 65536),
        async { server.next_open().await.unwrap().accept(65536).unwrap() },
    );
    let outgoing = outgoing.unwrap();
    let handed_off = Arc::new(AtomicBool::new(false));
    let callback_state = handed_off.clone();
    let owner = client.owner.clone();
    let handle = outgoing.inner.handle.clone();
    let writing = tokio::task::spawn_blocking(move || {
        owner.run(|session, publisher| {
            publisher.prepare_publication(1024, 3).map_err(error)?;
            session
                .write(&handle, b"a", false, publisher)
                .map_err(error)?;
            publisher.defer_publication(DeferredPublication::handoff(Some(Arc::new(move || {
                callback_state.store(true, Ordering::Release);
            }))));
            session
                .write(&handle, b"b", true, publisher)
                .map_err(error)?;
            Ok(())
        })
    });
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        outgoing.inner.handle.view.accepted.load(Ordering::Acquire),
        1
    );
    assert!(
        !outgoing
            .inner
            .handle
            .view
            .fin_submitted
            .load(Ordering::Acquire)
    );
    assert!(handed_off.load(Ordering::Acquire));
    assert!(
        !client
            .owner
            .run_state(|session| {
                session
                    .native_projection(&outgoing.inner.handle)
                    .map_err(error)
            })
            .unwrap()
            .close_write,
        "staged FIN must not close the original native writer"
    );
    // A state read really runs while the synchronous publisher holds transport.
    assert!(
        client
            .owner
            .run_state(|session| session.phase(&outgoing.inner.handle).map_err(error))
            .is_ok()
    );
    let closing = client.clone();
    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::task::spawn_blocking(move || closing.close()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), writing)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(
        outgoing.inner.handle.view.accepted.load(Ordering::Acquire),
        1
    );
    assert!(
        !outgoing
            .inner
            .handle
            .view
            .fin_submitted
            .load(Ordering::Acquire)
    );
    assert!(!client.cleanup_status().complete);
    // The close diagnostic remains absent while the physical cleanup is held.
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.state == crate::DiagnosticState::Closed)
    );
    let waiting = client.clone();
    let cleanup = tokio::spawn(async move { waiting.wait_cleanup().await });
    tokio::task::yield_now().await;
    assert!(!cleanup.is_finished());
    gate.physical_done.store(true, Ordering::Release);
    client.owner.changed.notify_waiters();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), cleanup)
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    assert_eq!(
        fixture
            .environment
            .root()
            .diagnostic_metric(crate::DiagnosticMetric::ApplicationOperations)
            .total,
        application_before
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.state == crate::DiagnosticState::Closed)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    incoming.reset().await.unwrap();
    server.close();
    c_task.abort();
    s_task.abort();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fallback_close_retries_after_contended_publish_with_independent_cleanup() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let gate = Arc::new(PublicationGate::default());
    let (c_tx, mut c_rx) = mpsc::channel(32);
    let (s_tx, mut s_rx) = mpsc::channel(32);
    let client = fixture
        .environment
        .adopt_ready_session(
            c,
            Box::new(CleanupOnlyBlockingLink {
                inner: BlockingLink {
                    inner: Link {
                        send: c_tx,
                        closed: false,
                        publication: Arc::new(Mutex::new(None)),
                    },
                    gate: gate.clone(),
                    frame: 14,
                    ordinal: 1,
                    fail: false,
                },
            }),
        )
        .unwrap();
    let server = fixture
        .environment
        .adopt_ready_session(
            s,
            Box::new(Link {
                send: s_tx,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    let peer = server.clone();
    let outbound = tokio::spawn(async move {
        while let Some(wire) = c_rx.recv().await {
            let _ = peer.receive(&wire);
        }
    });
    let peer = client.clone();
    let inbound = tokio::spawn(async move {
        while let Some(wire) = s_rx.recv().await {
            let _ = peer.receive(&wire);
        }
    });
    let probe = client
        .owner
        .run_state(|session| session.start_probe(Duration::from_secs(2)).map_err(error))
        .unwrap();
    client.owner.changed.notify_waiters();
    tokio::time::timeout(Duration::from_secs(1), gate.entered.notified())
        .await
        .unwrap();
    let closing = client.clone();
    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::task::spawn_blocking(move || closing.close()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!client.cleanup_status().complete);
    gate.release_publication();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if gate.publication_idle() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!client.cleanup_status().complete);
    gate.physical_done.store(true, Ordering::Release);
    client.owner.changed.notify_waiters();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    probe.release();
    server.close();
    outbound.abort();
    inbound.abort();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_completion_waits_for_the_original_native_handoff() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let gate = Arc::new(PublicationGate::default());
    let (c_tx, mut c_rx) = mpsc::channel(32);
    let (s_tx, mut s_rx) = mpsc::channel(32);
    let client = fixture
        .environment
        .adopt_ready_session(
            c,
            Box::new(BlockingLink {
                inner: Link {
                    send: c_tx,
                    closed: false,
                    publication: Arc::new(Mutex::new(None)),
                },
                gate: gate.clone(),
                frame: 14,
                ordinal: 1,
                fail: false,
            }),
        )
        .unwrap();
    let server = fixture
        .environment
        .adopt_ready_session(
            s,
            Box::new(Link {
                send: s_tx,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    let peer = server.clone();
    let outbound = tokio::spawn(async move {
        while let Some(wire) = c_rx.recv().await {
            peer.receive(&wire).unwrap();
        }
    });
    let peer = client.clone();
    let inbound = tokio::spawn(async move {
        while let Some(wire) = s_rx.recv().await {
            peer.receive(&wire).unwrap();
        }
    });
    let probe = client
        .owner
        .run_state(|session| session.start_probe(Duration::from_secs(2)).map_err(error))
        .unwrap();
    client.owner.changed.notify_waiters();
    tokio::time::timeout(Duration::from_secs(1), gate.entered.notified())
        .await
        .unwrap();
    let during = probe.snapshot();
    assert!(during.submitted);
    assert!(!during.complete);
    assert_eq!(during.outcome, ProbeOutcome::Pending);
    gate.close();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let result = probe.snapshot();
            if result.outcome == ProbeOutcome::Responsive && result.complete {
                break;
            }
            assert!(matches!(
                result.outcome,
                ProbeOutcome::Pending | ProbeOutcome::Responsive
            ));
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    probe.release();
    gate.physical_done.store(true, Ordering::Release);
    client.close();
    server.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    outbound.abort();
    inbound.abort();
}
struct FailedDirectionLink {
    inner: Link,
    target: Arc<AtomicU64>,
    attempts: Arc<AtomicUsize>,
    failed_scope: Option<u64>,
}
impl RecordPublisher for FailedDirectionLink {
    fn try_claim_data(&mut self, scope: u64, maximum: usize) -> Result<DataPublicationClaim> {
        self.inner.try_claim_data(scope, maximum)
    }
    fn publish(&mut self, record: &[u8]) -> Result<()> {
        self.failed_scope = None;
        let scope = u64::from_be_bytes(record[12..20].try_into().unwrap());
        if record[4] == 8 && scope == self.target.load(Ordering::Acquire) {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            self.failed_scope = Some(scope);
            return Err(CryptoError::State);
        }
        self.inner.publish(record)
    }
    fn failed_stream_publication(&self, scope: u64) -> Option<bool> {
        (self.failed_scope == Some(scope)).then_some(false)
    }
}
impl SessionTransport for FailedDirectionLink {
    fn close(&mut self) {
        self.inner.close();
    }
    fn cleanup_status(&self) -> CleanupStatus {
        self.inner.cleanup_status()
    }
    fn stream_cleanup_status(&self, scope: u64) -> CleanupStatus {
        self.inner.stream_cleanup_status(scope)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_native_direction_releases_staging_and_publishes_healthy_sibling() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let target = Arc::new(AtomicU64::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (c_tx, mut c_rx) = mpsc::channel(32);
    let (s_tx, mut s_rx) = mpsc::channel(32);
    let client = fixture
        .environment
        .adopt_ready_session(
            c,
            Box::new(FailedDirectionLink {
                inner: Link {
                    send: c_tx,
                    closed: false,
                    publication: Arc::new(Mutex::new(None)),
                },
                target: target.clone(),
                attempts: attempts.clone(),
                failed_scope: None,
            }),
        )
        .unwrap();
    let server = fixture
        .environment
        .adopt_ready_session(
            s,
            Box::new(Link {
                send: s_tx,
                closed: false,
                publication: Arc::new(Mutex::new(None)),
            }),
        )
        .unwrap();
    let peer = server.clone();
    let outbound = tokio::spawn(async move {
        while let Some(wire) = c_rx.recv().await {
            let _ = peer.receive(&wire);
        }
    });
    let peer = client.clone();
    let inbound = tokio::spawn(async move {
        while let Some(wire) = s_rx.recv().await {
            let _ = peer.receive(&wire);
        }
    });
    let (failed, _failed_peer) = tokio::join!(
        client.open_stream("example.failed", Metadata::empty(), 65536),
        async { server.next_open().await.unwrap().accept(65536).unwrap() },
    );
    let failed = failed.unwrap();
    let (healthy, healthy_peer) = tokio::join!(
        client.open_stream("example.healthy", Metadata::empty(), 65536),
        async { server.next_open().await.unwrap().accept(65536).unwrap() },
    );
    let healthy = healthy.unwrap();
    target.store(failed.inner.handle.scope(), Ordering::Release);
    let handed_off = Arc::new(AtomicBool::new(false));
    let failed_handoff = handed_off.clone();
    assert_eq!(
        client.owner.run(|session, publisher| {
            publisher.prepare_publication(1024, 3).map_err(error)?;
            session
                .write(&failed.inner.handle, b"lost", false, publisher)
                .map_err(error)?;
            publisher.defer_publication(DeferredPublication::handoff(Some(Arc::new(move || {
                failed_handoff.store(true, Ordering::Release);
            }))));
            session
                .write(&failed.inner.handle, b"tail", true, publisher)
                .map_err(error)?;
            session
                .write(&healthy.inner.handle, b"kept", false, publisher)
                .map_err(error)?;
            Ok(())
        }),
        Err(SessionError::StreamReset)
    );
    assert_eq!(attempts.load(Ordering::Acquire), 1);
    assert_eq!(failed.inner.handle.view.accepted.load(Ordering::Acquire), 0);
    assert!(
        !failed
            .inner
            .handle
            .view
            .fin_submitted
            .load(Ordering::Acquire)
    );
    assert!(!handed_off.load(Ordering::Acquire));
    client
        .owner
        .run_state(|session| {
            assert!(!session.engine.closed);
            let index = session
                .engine
                .streams
                .resolve(&failed.inner.handle)
                .unwrap();
            assert_eq!(session.engine.streams.slots[index].unpublished, 0);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), healthy_peer.read())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Bytes::from_static(b"kept")
    );
    healthy.write(Bytes::from_static(b"again")).await.unwrap();
    assert_eq!(
        healthy_peer.read().await.unwrap().unwrap(),
        Bytes::from_static(b"again")
    );
    client.close();
    server.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    outbound.abort();
    inbound.abort();
}

#[tokio::test]
async fn reserved_bootstrap_write_waits_for_authenticated_open_or_session_close() {
    for deliver_open in [true, false] {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, outbound, inbound) = link(&fixture.environment, c, s);
        let outgoing = server
            .claim_rpc_bootstrap_prepared(
                StreamPreparation::new(server.owner.account.clone()).unwrap(),
            )
            .unwrap();
        let writing = outgoing.write(Bytes::from_static(b"bootstrap"));
        tokio::pin!(writing);
        assert!(futures_util::poll!(&mut writing).is_pending());
        assert_eq!(
            outgoing.inner.handle.view.accepted.load(Ordering::Acquire),
            0
        );
        if deliver_open {
            let incoming = client
                .claim_rpc_bootstrap_prepared(
                    StreamPreparation::new(client.owner.account.clone()).unwrap(),
                )
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), &mut writing)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                incoming.read().await.unwrap().unwrap(),
                Bytes::from_static(b"bootstrap")
            );
        } else {
            server.close();
            assert!(
                tokio::time::timeout(Duration::from_secs(2), &mut writing)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        client.close();
        server.close();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), server.wait_cleanup())
                .await
                .unwrap()
                .complete
        );
        outbound.abort();
        inbound.abort();
    }
}

struct RejectPreparation;
impl RecordPublisher for RejectPreparation {
    fn prepare_publication(&mut self, _: usize, _: usize) -> Result<()> {
        Err(CryptoError::Capacity)
    }
    fn publish(&mut self, _: &[u8]) -> Result<()> {
        panic!("preflight rejection cannot publish or consume a sequence")
    }
    fn is_deferred(&self) -> bool {
        true
    }
}
#[tokio::test]
async fn metadata_preflight_rejection_preserves_reliable_frontier_and_fin() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("example.preflight", Metadata::empty(), 65536),
        async { server.next_open().await.unwrap().accept(65536).unwrap() },
    );
    let outgoing = outgoing.unwrap();
    client
        .owner
        .run_state(|session| {
            let before = session
                .publication_frontier_for_test(&outgoing.inner.handle)
                .unwrap();
            assert_eq!(
                session.write(
                    &outgoing.inner.handle,
                    b"lost",
                    true,
                    &mut RejectPreparation
                ),
                Err(CryptoError::Capacity)
            );
            let after = session
                .publication_frontier_for_test(&outgoing.inner.handle)
                .unwrap();
            assert_eq!(after, before);
            assert!(!after.1);
            assert!(!session.engine.closed);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        outgoing.inner.handle.view.accepted.load(Ordering::Acquire),
        0
    );
    assert!(
        !outgoing
            .inner
            .handle
            .view
            .fin_submitted
            .load(Ordering::Acquire)
    );
    outgoing.write(Bytes::from_static(b"kept")).await.unwrap();
    assert_eq!(
        incoming.read().await.unwrap().unwrap(),
        Bytes::from_static(b"kept")
    );
    client.close();
    server.close();
    c_task.abort();
    s_task.abort();
}

#[tokio::test]
async fn late_connect_diagnostic_attach_closes_after_the_fixed_outcome() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (_sink, events) = crate::diagnostics_v4::capture_for_test(fixture.environment.root());
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    client.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.wait_cleanup())
            .await
            .unwrap()
            .complete
    );
    let diagnostic = client
        .owner
        .account
        .diagnostic_activity(crate::DiagnosticPhase::Connect, 1);
    diagnostic.succeed();
    client.attach_connect_diagnostic(diagnostic);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ordered = {
                let events = events.lock().unwrap();
                events.iter().find(|event| event.phase == crate::DiagnosticPhase::Connect
                    && event.state == crate::DiagnosticState::Succeeded).is_some_and(|succeeded| {
                    let same: Vec<_> = events.iter().filter(|event| event.correlation_id == succeeded.correlation_id).collect();
                    let success = same.iter().position(|event| event.state == crate::DiagnosticState::Succeeded);
                    let closed = same.iter().position(|event| event.state == crate::DiagnosticState::Closed);
                    matches!((success, closed), (Some(success), Some(closed)) if success < closed)
                })
            };
            if ordered { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    server.close();
    c_task.abort();
    s_task.abort();
}
