use super::*;
use crate::codec_v4::tests::{encode_map, t, u};

fn root() -> Arc<Root<u8>> {
    let environment = crate::environment_v4::tests::environment();
    let contract = ServiceContract::capture_root(
        &environment,
        &encode_map(&[
            (0, t("example/observe")),
            (1, u(42)),
            (2, u(2)),
            (5, u(0)),
            (6, t("bytes.v1")),
            (7, t("none.v1")),
            (8, u(0)),
            (9, u(0)),
            (10, u(0)),
            (11, u(10000)),
            (21, vec![0xf4]),
            (23, u(128)),
            (27, vec![0x80]),
        ]),
    )
    .unwrap();
    Arc::new(Root {
        controller: Weak::new(),
        contract,
        resources: Mutex::new(None),
        _status_charge: environment
            .reserve_environment(crate::ResourceLimits {
                sdk_bytes: 1024,
                ..Default::default()
            })
            .unwrap(),
        resources_released: AtomicBool::new(false),
        application_bytes: 1024,
        delivery: Mutex::new(std::collections::VecDeque::with_capacity(16)),
        delivery_changed: Notify::new(),
        active_delivery: Mutex::new(None),
        callback_entry: Mutex::new(()),
        prefer_gap: AtomicBool::new(false),
        delivery_pending: Arc::new(AtomicUsize::new(0)),
        self_weak: OnceLock::new(),
        published_generation: AtomicU64::new(1),
        delivery_generation: AtomicU64::new(1),
        policy: NotificationDropPolicy::KeepLatest,
        options: ControllerNotificationOptions::default(),
        state: Mutex::new(NotificationState {
            current: None,
            retired: None,
            pending: None,
            pending_session: None,
            pending_generation: None,
            pending_phase: None,
            current_phase: None,
            retired_phase: None,
            generation: 1,
            source_phase: ControllerNotificationSourcePhase::Current,
            gap: None,
            gap_emitted: None,
            reader_gap_generation: 0,
            reader_gap_sequence: 0,
            service_failure: None,
            controller_failure: None,
        }),
        cancellation: CancellationToken::new(),
        close_deadline: Mutex::new(None),
        changed: Notify::new(),
        handles: AtomicUsize::new(1),
        done: AtomicBool::new(false),
        delivery_done: AtomicBool::new(false),
    })
}
fn task(generation: u64) -> EncodedNotification {
    EncodedNotification::new(generation, CancellationToken::new(), |_| async { Ok(()) })
}

#[test]
fn close_publication_and_subscription_close_prevent_pending_decoder_admission() {
    for winner in 0..3 {
        let root = root();
        let task = task(1);
        let control = task.control();
        let phase = Arc::new(AtomicU8::new(0));
        let entry = Mutex::new(());
        let cancellation = CancellationToken::new();
        match winner {
            0 => root.close(),
            1 => root.publication_stage(2),
            _ => {
                let _entry = entry.lock().unwrap();
                cancellation.cancel();
            }
        }
        assert!(!root.source_admit(1, &phase, &control, &entry, &cancellation));
        assert!(!root.source_admit(1, &phase, &control, &entry, &cancellation));
        assert_eq!(
            root.state
                .lock()
                .unwrap()
                .gap
                .as_ref()
                .unwrap()
                .known_dropped,
            1
        );
    }
}

#[test]
fn decoder_admission_holds_the_same_entry_gate_as_close_and_publication() {
    for publish in [false, true] {
        let root = root();
        let task = task(1);
        let control = task.control();
        let phase = Arc::new(AtomicU8::new(0));
        let entry = Mutex::new(());
        let cancellation = CancellationToken::new();
        std::thread::scope(|scope| {
            let blocked = entry.lock().unwrap();
            let admission =
                scope.spawn(|| root.source_admit(1, &phase, &control, &entry, &cancellation));
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while root.callback_entry.try_lock().is_ok() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::yield_now();
            }
            let transition = scope.spawn(|| {
                if publish {
                    root.publication_stage(2)
                } else {
                    root.close()
                }
            });
            drop(blocked);
            assert!(admission.join().unwrap());
            transition.join().unwrap();
        });
        assert!(!EncodedNotification::supersede_control(&control));
    }
}

#[test]
fn keep_latest_preserves_one_pending_input_and_counts_replacement_once() {
    let root = root();
    let first = task(1);
    let control = first.control();
    assert!(root.try_schedule(first).is_ok());
    let original = root.pop_delivery().unwrap();
    assert!(root.try_schedule(task(2)).is_err());
    assert_eq!(root.delivery.lock().unwrap().len(), 0);
    assert!(!EncodedNotification::control_is_admitted(&control));
    assert!(root.try_schedule(task(1)).is_ok());
    assert!(!EncodedNotification::try_admit_control(&control));
    assert_eq!(root.delivery.lock().unwrap().len(), 1);
    root.source_failed(1, ServiceFailure::Canceled, false, &control);
    let gap = root.state.lock().unwrap().gap.clone().unwrap();
    assert_eq!(gap.known_dropped, 2); // One unready candidate and one coalesced input.
    assert!(
        gap.reasons
            .contains(&ControllerNotificationGapReason::Coalesced)
    );
    drop(original);
    root.close();
    assert_eq!(root.delivery_pending.load(Ordering::Acquire), 0);
    assert_eq!(
        root.state
            .lock()
            .unwrap()
            .gap
            .as_ref()
            .unwrap()
            .known_dropped,
        3
    );
    root.close();
    assert_eq!(
        root.state
            .lock()
            .unwrap()
            .gap
            .as_ref()
            .unwrap()
            .known_dropped,
        3
    );
}

#[test]
fn reader_gap_is_immediate_and_deduplicated_without_a_later_notification() {
    let root = root();
    root.source_gap(1, 7);
    root.source_gap(1, 7);
    let state = root.state.lock().unwrap();
    let gap = state.gap.as_ref().unwrap();
    assert_eq!(gap.known_dropped, 1);
    assert_eq!(
        gap.reasons,
        [ControllerNotificationGapReason::DroppedBudget]
    );
}
