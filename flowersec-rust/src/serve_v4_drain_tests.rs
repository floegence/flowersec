use super::*;
use crate::{
    crypto_v4::{SessionTransport, tests::record_pair_for_limits},
    namespace_v4::verifier::credential::tests::Fixture,
    transport::ByteStream,
};
use bytes::Bytes;

struct Link {
    send: mpsc::Sender<Vec<u8>>,
    tail: Arc<AtomicBool>,
    closed: bool,
}
impl RecordPublisher for Link {
    fn publish(&mut self, wire: &[u8]) -> Result<()> {
        self.send
            .try_send(wire.to_vec())
            .map_err(|_| CryptoError::Capacity)
    }
}
impl SessionTransport for Link {
    fn close(&mut self) {
        self.closed = true;
    }
    fn cleanup_status(&self) -> CleanupStatus {
        let pending = !self.tail.load(Ordering::Acquire);
        CleanupStatus {
            complete: self.closed && !pending,
            cleanup_incomplete: false,
            pending_callbacks: u64::from(pending),
        }
    }
    fn stream_cleanup_status(&self, _: u64) -> CleanupStatus {
        CleanupStatus {
            complete: true,
            cleanup_incomplete: false,
            pending_callbacks: 0,
        }
    }
}
struct Pair {
    _fixture: Fixture,
    client: Session,
    server: Session,
    outgoing: Stream,
    incoming: Stream,
    tail: Arc<AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    stop: CancellationToken,
}
impl Pair {
    async fn new() -> Self {
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let (c_tx, mut c_rx) = mpsc::channel(32);
        let (s_tx, mut s_rx) = mpsc::channel(32);
        let tail = Arc::new(AtomicBool::new(true));
        let client = fixture
            .environment
            .adopt_ready_session(
                c,
                Box::new(Link {
                    send: c_tx,
                    tail: Arc::new(AtomicBool::new(true)),
                    closed: false,
                }),
            )
            .unwrap();
        let server = fixture
            .environment
            .adopt_ready_session(
                s,
                Box::new(Link {
                    send: s_tx,
                    tail: tail.clone(),
                    closed: false,
                }),
            )
            .unwrap();
        let stop = CancellationToken::new();
        let read_stop = stop.clone();
        let receiver = server.receiver();
        let c_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = read_stop.cancelled() => break,
                    wire = c_rx.recv() => match wire {
                        Some(wire) if receiver.receive(&wire).is_ok() => {},
                        _ => break,
                    }
                }
            }
        });
        let read_stop = stop.clone();
        let receiver = client.receiver();
        let s_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = read_stop.cancelled() => break,
                    wire = s_rx.recv() => match wire {
                        Some(wire) if receiver.receive(&wire).is_ok() => {},
                        _ => break,
                    }
                }
            }
        });
        let (outgoing, incoming) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                client.open_stream("serve.drain", Metadata::empty(), 128),
                async { server.next_open().await.unwrap().accept(128).unwrap() }
            )
        })
        .await
        .unwrap();
        Self {
            _fixture: fixture,
            client,
            server,
            outgoing: outgoing.unwrap(),
            incoming,
            tail,
            tasks: vec![c_task, s_task],
            stop,
        }
    }
    async fn finish_business(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            self.outgoing
                .write(Bytes::from_static(b"still serving"))
                .await
                .unwrap();
            assert_eq!(
                self.incoming.read().await.unwrap().unwrap(),
                Bytes::from_static(b"still serving")
            );
            self.outgoing.close_write().await.unwrap();
            assert!(self.incoming.read().await.unwrap().is_none());
            self.incoming.close_write().await.unwrap();
            assert!(self.outgoing.read().await.unwrap().is_none());
            self.outgoing.finish().await.unwrap();
        })
        .await
        .unwrap();
    }
    async fn cleanup(&mut self) {
        self.tail.store(true, Ordering::Release);
        self.client.close();
        self.server.close();
        self.stop.cancel();
        for task in self.tasks.drain(..) {
            task.await.unwrap();
        }
        assert!(self.client.wait_cleanup().await.complete);
        assert!(self.server.wait_cleanup().await.complete);
    }
}
impl Drop for Pair {
    fn drop(&mut self) {
        self.tail.store(true, Ordering::Release);
        self.client.close();
        self.server.close();
        self.stop.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

// The actual WSS tests cover publication and listener ownership. This fixture
// isolates the aggregate using real authenticated record engines and bounded
// transports whose final physical cleanup can be held independently.
fn group(sessions: &[Session]) -> ServeHandle {
    let root = crate::environment_v4::tests::environment();
    let charge = root
        .reserve_environment(serve_charge(sessions.len()))
        .unwrap();
    let diagnostic = root.diagnostic_activity(crate::DiagnosticPhase::Serve, 1);
    diagnostic.succeed();
    let owner = Arc::new(ServeOwner {
        root,
        diagnostic,
        diagnostic_closed: AtomicBool::new(false),
        gate: Mutex::new(Gate {
            closed: false,
            preparation: None,
            drain: None,
            generation: sessions.len() as u64,
            slots: sessions
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    Some(Slot {
                        generation: i as u64 + 1,
                        cancel: CancellationToken::new(),
                        session: Some(s.clone()),
                        provider: None,
                        prepared: true,
                        pending: false,
                        drain: None,
                        drain_done: false,
                        drain_starting: false,
                        tail_done: false,
                        invocation: None,
                        diagnostic: None,
                    })
                })
                .collect(),
        }),
        changed: Notify::new(),
        stop: CancellationToken::new(),
        pump_done: AtomicBool::new(true),
        charge: Mutex::new(Some(charge)),
        cleanup_deadline: Mutex::new(None),
        observers: AtomicUsize::new(0),
    });
    let (_, incoming) = mpsc::channel(1);
    ServeHandle {
        owner,
        incoming: tokio::sync::Mutex::new(incoming),
        address: "127.0.0.1:0".parse().unwrap(),
    }
}
fn collect(handle: &ServeHandle) {
    let children: Vec<_> = handle
        .owner
        .gate
        .lock()
        .unwrap()
        .slots
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            s.as_ref()
                .and_then(|s| s.session.clone().map(|session| (i, s.generation, session)))
        })
        .collect();
    for (index, generation, session) in children {
        if session.cleanup_status().complete {
            handle.owner.finish(index, generation);
        }
    }
    handle.owner.poll_drain();
}
async fn result(handle: &ServeHandle) -> ServeDrainResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            collect(handle);
            let result = handle.owner.drain_result();
            if result.outcome != DrainOutcome::Pending {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}
async fn cleanup(handle: &ServeHandle) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            collect(handle);
            if handle.cleanup_status().complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn first_group_deadline_bounds_existing_children_and_repeated_waits() {
    let mut pair = Pair::new().await;
    let child = pair.server.drain(Duration::from_secs(30)).unwrap();
    let handle = group(&[pair.server.clone()]);
    let operation = handle.drain(Duration::from_millis(200)).unwrap();
    let deadline = handle
        .owner
        .gate
        .lock()
        .unwrap()
        .drain
        .as_ref()
        .unwrap()
        .deadline;
    let repeat = handle.drain(Duration::from_secs(30)).unwrap();
    assert!(Arc::ptr_eq(&operation.owner, &repeat.owner));
    assert_eq!(
        deadline,
        handle
            .owner
            .gate
            .lock()
            .unwrap()
            .drain
            .as_ref()
            .unwrap()
            .deadline
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(5), operation.wait())
            .await
            .is_err()
    );
    assert_eq!(operation.result().outcome, DrainOutcome::Pending);
    tokio::time::sleep_until(deadline).await;
    assert_eq!(result(&handle).await.outcome, DrainOutcome::DeadlineAborted);
    assert_eq!(child.result().outcome, DrainOutcome::DeadlineAborted);
    handle.close();
    assert_eq!(operation.result().outcome, DrainOutcome::DeadlineAborted);
    pair.cleanup().await;
    cleanup(&handle).await;
}

#[tokio::test]
async fn failed_child_is_retained_in_result_after_collection_while_sibling_finishes() {
    let mut failed = Pair::new().await;
    let mut healthy = Pair::new().await;
    let handle = group(&[failed.server.clone(), healthy.server.clone()]);
    let operation = handle.drain(Duration::from_secs(2)).unwrap();
    failed.server.close();
    failed.cleanup().await;
    collect(&handle);
    assert!(handle.owner.gate.lock().unwrap().slots[0].is_none());
    assert_eq!(operation.result().outcome, DrainOutcome::Pending);
    healthy.finish_business().await;
    let result = result(&handle).await;
    assert_eq!(result.outcome, DrainOutcome::Failed);
    assert_eq!(result.error, Some(SessionError::Closed));
    healthy.cleanup().await;
    cleanup(&handle).await;
    assert_eq!(
        operation.wait().await.unwrap().outcome,
        DrainOutcome::Failed
    );
}

#[tokio::test]
async fn drained_business_reports_physical_tail_and_keeps_original_cleanup_deadline() {
    let mut pair = Pair::new().await;
    pair.tail.store(false, Ordering::Release);
    let handle = group(&[pair.server.clone()]);
    let operation = handle.drain(Duration::from_secs(30)).unwrap();
    assert!(handle.owner.cleanup_deadline.lock().unwrap().is_none());
    pair.finish_business().await;
    let result = result(&handle).await;
    assert_eq!(result.outcome, DrainOutcome::Drained);
    assert!(!result.cleanup.complete);
    assert_eq!(result.cleanup.pending_callbacks, 1);
    let deadline = handle.owner.cleanup_deadline.lock().unwrap().unwrap();
    assert!(deadline <= Instant::now() + Duration::from_secs(5));
    let held = handle.owner.root.charged();
    handle.close();
    handle.drain(Duration::from_secs(30)).unwrap();
    assert_eq!(
        handle.owner.cleanup_deadline.lock().unwrap().unwrap(),
        deadline
    );
    tokio::time::sleep_until(deadline).await;
    let status = operation.result();
    assert_eq!(status.outcome, DrainOutcome::Drained);
    assert!(status.cleanup.cleanup_incomplete && !status.cleanup.complete);
    assert_eq!(handle.owner.root.charged(), held);
    assert!(handle.owner.gate.lock().unwrap().slots[0].is_some());
    pair.cleanup().await;
    cleanup(&handle).await;
    assert!(operation.result().cleanup.complete);
    let released = handle.owner.root.charged();
    for ((held, released), charge) in held
        .values()
        .into_iter()
        .zip(released.values())
        .zip(serve_charge(1).values())
    {
        assert_eq!(held - released, charge);
    }
}

#[tokio::test]
async fn explicit_close_is_failed_and_cannot_be_changed_into_graceful_drain() {
    let mut pair = Pair::new().await;
    let handle = group(&[pair.server.clone()]);
    let operation = handle.drain(Duration::from_secs(30)).unwrap();
    handle.close();
    let deadline = handle.owner.cleanup_deadline.lock().unwrap().unwrap();
    let result = handle.wait_drain().await.unwrap();
    assert_eq!(result.outcome, DrainOutcome::Failed);
    assert_eq!(result.error, Some(SessionError::Closed));
    handle.drain(Duration::from_secs(30)).unwrap();
    assert_eq!(
        deadline,
        handle.owner.cleanup_deadline.lock().unwrap().unwrap()
    );
    assert_eq!(operation.result().outcome, DrainOutcome::Failed);
    pair.cleanup().await;
    cleanup(&handle).await;
}

#[tokio::test]
async fn historical_termination_and_unpublished_candidates_only_contribute_cleanup() {
    for published in [false, true] {
        let mut pair = Pair::new().await;
        pair.tail.store(false, Ordering::Release);
        let handle = group(&[pair.server.clone()]);
        if published {
            pair.server.close();
        } else {
            handle.owner.gate.lock().unwrap().slots[0]
                .as_mut()
                .unwrap()
                .pending = true;
        }
        let operation = handle.drain(Duration::from_secs(30)).unwrap();
        assert_eq!(operation.result().outcome, DrainOutcome::Drained);
        assert!(!operation.result().cleanup.complete);
        assert_eq!(operation.result().cleanup.pending_callbacks, 1);
        if !published {
            assert!(
                handle.owner.gate.lock().unwrap().slots[0]
                    .as_ref()
                    .unwrap()
                    .cancel
                    .is_cancelled()
            );
        }
        pair.cleanup().await;
        cleanup(&handle).await;
        assert_eq!(operation.result().outcome, DrainOutcome::Drained);
    }
}

#[tokio::test]
async fn late_child_start_keeps_group_deadline_and_post_gate_failure() {
    for fail in [false, true] {
        let mut pair = Pair::new().await;
        let handle = group(&[pair.server.clone()]);
        // Hold this slot's original iterator claim to reproduce a child whose
        // Session lock is not obtained until after the group publication gate.
        handle.owner.gate.lock().unwrap().slots[0]
            .as_mut()
            .unwrap()
            .drain_starting = true;
        let operation = handle.drain(Duration::from_millis(40)).unwrap();
        let deadline = handle
            .owner
            .gate
            .lock()
            .unwrap()
            .drain
            .as_ref()
            .unwrap()
            .deadline;
        tokio::time::sleep_until(deadline).await;
        if fail {
            pair.server.close();
        }
        handle.owner.gate.lock().unwrap().slots[0]
            .as_mut()
            .unwrap()
            .drain_starting = false;
        handle.owner.poll_drain();
        assert_eq!(
            operation.result().outcome,
            if fail {
                DrainOutcome::Failed
            } else {
                DrainOutcome::DeadlineAborted
            }
        );
        assert_eq!(
            operation.result().error,
            fail.then_some(SessionError::Closed)
        );
        pair.cleanup().await;
        cleanup(&handle).await;
    }
}

#[tokio::test]
async fn earlier_child_deadline_is_preserved_and_terminal_drain_is_not_lost_before_start() {
    let mut pair = Pair::new().await;
    let child = pair.server.drain(Duration::from_millis(100)).unwrap();
    let handle = group(&[pair.server.clone()]);
    handle.owner.gate.lock().unwrap().slots[0]
        .as_mut()
        .unwrap()
        .drain_starting = true;
    let operation = handle.drain(Duration::from_secs(2)).unwrap();
    let terminal = tokio::time::timeout(Duration::from_secs(1), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal.outcome, DrainOutcome::DeadlineAborted);
    handle.owner.gate.lock().unwrap().slots[0]
        .as_mut()
        .unwrap()
        .drain_starting = false;
    handle.owner.poll_drain();
    assert_eq!(operation.result().outcome, DrainOutcome::DeadlineAborted);
    pair.cleanup().await;
    cleanup(&handle).await;
}

#[tokio::test]
async fn exited_ingress_cannot_release_held_physical_tail_and_failure_closes_group() {
    let mut pair = Pair::new().await;
    pair.tail.store(false, Ordering::Release);
    let handle = group(&[pair.server.clone()]);
    handle.owner.ingress_stopped();
    assert!(handle.owner.stop.is_cancelled());
    assert_eq!(
        handle.wait_drain().await.unwrap().error,
        Some(SessionError::OperationFailed)
    );
    assert_eq!(
        pair.server.wait_termination().await.error,
        SessionError::Closed
    );
    handle.owner.finish(0, 1);
    assert!(handle.owner.gate.lock().unwrap().slots[0].is_some());
    assert!(!handle.cleanup_status().complete);
    pair.cleanup().await;
    cleanup(&handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_close_and_drain_fix_one_cleanup_window() {
    for _ in 0..20 {
        let mut pair = Pair::new().await;
        let handle = Arc::new(group(&[pair.server.clone()]));
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let closing = handle.clone();
        let ready = barrier.clone();
        let task = tokio::spawn(async move {
            ready.wait().await;
            closing.close();
            *closing.owner.cleanup_deadline.lock().unwrap()
        });
        barrier.wait().await;
        let operation = handle.drain(Duration::from_secs(30)).unwrap();
        let deadline = task.await.unwrap().unwrap();
        assert_eq!(operation.result().outcome, DrainOutcome::Failed);
        assert_eq!(
            handle.owner.cleanup_deadline.lock().unwrap().unwrap(),
            deadline
        );
        assert!(deadline <= Instant::now() + Duration::from_secs(5));
        pair.cleanup().await;
        cleanup(&handle).await;
    }
}

#[tokio::test]
async fn drain_and_cleanup_waits_share_bounded_prepaid_observers() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let handle = group(&[]);
    let mut waiters: Vec<_> = (0..MAX_OBSERVERS)
        .map(|_| Box::pin(handle.wait_drain()))
        .collect();
    let mut context = Context::from_waker(Waker::noop());
    for waiter in &mut waiters {
        assert!(waiter.as_mut().poll(&mut context).is_pending());
    }
    assert_eq!(
        handle.owner.observers.load(Ordering::Acquire),
        MAX_OBSERVERS
    );
    assert_eq!(handle.wait_drain().await, Err(ConnectError::Capacity));
    assert_eq!(handle.wait_cleanup().await, Err(ConnectError::Capacity));
    drop(waiters.pop());
    let mut cleanup_wait = Box::pin(handle.wait_cleanup());
    assert!(cleanup_wait.as_mut().poll(&mut context).is_pending());
    let operation = handle.drain(Duration::from_secs(1)).unwrap();
    assert_eq!(
        operation.wait().await.unwrap().outcome,
        DrainOutcome::Drained
    );
    assert!(handle.wait_cleanup().await.unwrap().complete);
    // Terminal observation does not need another slot; already registered
    // observers keep their original charge until their futures actually exit.
    assert!(handle.owner.charge.lock().unwrap().is_some());
    for waiter in waiters {
        assert_eq!(waiter.await.unwrap().outcome, DrainOutcome::Drained);
    }
    assert!(cleanup_wait.await.unwrap().complete);
    assert_eq!(handle.owner.observers.load(Ordering::Acquire), 0);
    assert!(handle.owner.charge.lock().unwrap().is_none());
}

#[tokio::test]
async fn stale_pending_observation_cannot_register_after_final_refund() {
    let handle = group(&[]);
    assert_eq!(handle.owner.drain_result().outcome, DrainOutcome::Pending);
    // Complete the group between a waiter's first status read and its original
    // observer admission. The retired vector must never gain another waiter.
    handle.drain(Duration::from_secs(1)).unwrap();
    assert!(handle.cleanup_status().complete);
    assert!(handle.owner.charge.lock().unwrap().is_none());
    assert!(handle.owner.observe().unwrap().is_none());
    assert_eq!(handle.owner.observers.load(Ordering::Acquire), 0);
    assert_eq!(
        handle.wait_drain().await.unwrap().outcome,
        DrainOutcome::Drained
    );
}

#[tokio::test]
async fn application_private_ready_child_retains_worker_after_failed_publication() {
    let mut pair = Pair::new().await;
    let application = ApplicationLifetime::new(
        pair.server.application_test_account(),
        ApplicationLimits {
            ordinary_callbacks: 1,
            ordinary_callback_bytes: 1024,
            control_callback_bytes: 1024,
        },
    )
    .unwrap();
    pair.server.attach_application(application.clone()).unwrap();
    let publication = application.enter(CallbackKind::Control).unwrap();
    let handle = group(&[pair.server.clone()]);
    {
        let mut gate = handle.owner.gate.lock().unwrap();
        let slot = gate.slots[0].as_mut().unwrap();
        slot.pending = true;
        slot.tail_done = true;
    }
    handle.close();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !pair.server.core_cleanup_status().complete {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    application.release(true).unwrap();
    drop(publication);
    // No yield: the original worker still has to observe the final receipt and
    // return its task charge, even though this child never became published.
    handle.owner.collect_finished();
    assert!(!handle.cleanup_status().complete);
    assert!(handle.owner.gate.lock().unwrap().slots[0].is_some());
    assert!(pair.server.wait_cleanup().await.complete);
    handle.owner.collect_finished();
    assert!(handle.cleanup_status().complete);
    pair.cleanup().await;
}
