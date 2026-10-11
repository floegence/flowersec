use super::*;
use crate::TransportEnvironment;

type CapturedEvents = Arc<Mutex<Vec<DiagnosticEvent>>>;

async fn wait_for_capture(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

async fn drain_capture(sink: &DiagnosticSink, captured: &CapturedEvents) -> Vec<DiagnosticEvent> {
    let previous_markers = captured
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.state == DiagnosticState::Other)
        .count();
    let marker = sink.begin().unwrap();
    assert!(marker.emit(
        DiagnosticState::Other,
        DiagnosticAttemptBucket::Other,
        DiagnosticPhase::Other,
        DiagnosticCode::Other,
        DiagnosticRetryDisposition::Other,
        DiagnosticDurationBucket::Other,
    ));
    // The original callback lane is serial. Observing this marker proves that
    // every event queued before it has reached the real capture callback.
    wait_for_capture(|| {
        captured
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.state == DiagnosticState::Other)
            .count()
            > previous_markers
    })
    .await;
    captured
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.state != DiagnosticState::Other)
        .copied()
        .collect()
}

#[tokio::test]
async fn returned_failure_closes_only_after_both_original_physical_tails_exit() {
    let environment = TransportEnvironment::new();
    let (sink, captured) = capture_for_test(environment.root());
    let activity = environment
        .root()
        .diagnostic_activity(DiagnosticPhase::Connect, 1);
    let first_tail = activity.retain_physical();
    let last_tail = activity.retain_physical();
    let (release_first, first_release) = tokio::sync::oneshot::channel();
    let (release_last, last_release) = tokio::sync::oneshot::channel();
    let first_owner = tokio::spawn(async move {
        let _ = first_release.await;
        drop(first_tail);
    });
    let last_owner = tokio::spawn(async move {
        let _ = last_release.await;
        drop(last_tail);
    });

    activity.fail(
        DiagnosticCode::Timeout,
        DiagnosticRetryDisposition::DoNotRetry,
    );
    activity.closed();
    let returned_handle = activity.clone();
    drop(activity);
    let before_release = drain_capture(&sink, &captured).await;
    assert_eq!(
        before_release
            .iter()
            .map(|event| (
                event.state,
                event.phase,
                event.code,
                event.retry_disposition
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                DiagnosticState::Started,
                DiagnosticPhase::Connect,
                DiagnosticCode::None,
                DiagnosticRetryDisposition::None
            ),
            (
                DiagnosticState::Failed,
                DiagnosticPhase::Connect,
                DiagnosticCode::Timeout,
                DiagnosticRetryDisposition::DoNotRetry
            ),
        ]
    );

    release_first.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), first_owner)
        .await
        .unwrap()
        .unwrap();
    returned_handle.closed();
    assert_eq!(drain_capture(&sink, &captured).await, before_release);

    release_last.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), last_owner)
        .await
        .unwrap()
        .unwrap();
    let after_release = drain_capture(&sink, &captured).await;
    assert_eq!(
        &after_release[..before_release.len()],
        before_release.as_slice()
    );
    assert_eq!(after_release.len(), before_release.len() + 1);
    let closed = after_release.last().unwrap();
    assert_eq!(closed.state, DiagnosticState::Closed);
    assert_eq!(closed.phase, DiagnosticPhase::Close);
    assert_eq!(closed.code, DiagnosticCode::None);
    assert_eq!(closed.retry_disposition, DiagnosticRetryDisposition::None);

    // A retained caller handle and repeated terminal observations cannot
    // produce another outcome or another physical-close event.
    returned_handle.closed();
    returned_handle.fail(DiagnosticCode::Canceled, DiagnosticRetryDisposition::Retry);
    returned_handle.succeed();
    assert_eq!(drain_capture(&sink, &captured).await, after_release);
    assert_eq!(
        environment
            .diagnostic_metric(DiagnosticMetric::ConnectFailures)
            .total,
        1
    );
    assert_eq!(
        environment
            .diagnostic_metric(DiagnosticMetric::ConnectSuccesses)
            .total,
        0
    );
    assert_eq!(sink.counts().dropped_events, 0);
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
    assert!(environment.close().await.unwrap().complete);
    drop(returned_handle);
}

#[tokio::test]
async fn retained_closed_connect_handle_leaves_the_next_utc_bucket_available() {
    let environment = TransportEnvironment::new();
    let (sink, captured) = capture_for_test(environment.root());
    let returned_handle = environment
        .root()
        .diagnostic_activity(DiagnosticPhase::Connect, 1);
    let tail = returned_handle.retain_physical();
    returned_handle.fail(
        DiagnosticCode::Timeout,
        DiagnosticRetryDisposition::DoNotRetry,
    );
    // Physical exit may precede the caller's close request as well.
    drop(tail);
    returned_handle.closed();
    wait_for_capture(|| {
        captured
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.state == DiagnosticState::Closed)
    })
    .await;

    let still_live = sink.begin().unwrap();
    let old_bucket: Vec<_> = (0..MAX_IDS - 2).map(|_| sink.begin().unwrap()).collect();
    // Closing the activity does not refund an ID issued in the current bucket.
    assert_eq!(sink.begin().unwrap_err(), DiagnosticSinkError::Capacity);
    drop(old_bucket);
    // The next real begin/maintenance call performs the sink's UTC refresh.
    sink.advance_bucket_for_test();

    // The genuinely live observation retains one position. Holding the closed
    // activity must leave every other position available in the refreshed bucket.
    let next_bucket: Vec<_> = (0..MAX_IDS - 1).map(|_| sink.begin().unwrap()).collect();
    assert_eq!(sink.begin().unwrap_err(), DiagnosticSinkError::Capacity);
    assert!(still_live.emit(
        DiagnosticState::Other,
        DiagnosticAttemptBucket::Other,
        DiagnosticPhase::Other,
        DiagnosticCode::Other,
        DiagnosticRetryDisposition::Other,
        DiagnosticDurationBucket::Other,
    ));
    returned_handle.closed();
    drop(next_bucket);
    drop(still_live);
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
    assert!(environment.close().await.unwrap().complete);
    drop(returned_handle);
}

#[tokio::test]
async fn successful_outcome_closes_once_when_request_races_the_final_physical_exit() {
    let environment = TransportEnvironment::new();
    let (sink, captured) = capture_for_test(environment.root());
    let activity = environment
        .root()
        .diagnostic_activity(DiagnosticPhase::Connect, 1);
    let tail = activity.retain_physical();
    activity.succeed();
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            start.wait();
            activity.closed();
        });
        scope.spawn(|| {
            start.wait();
            drop(tail);
        });
    });

    let completed = drain_capture(&sink, &captured).await;
    assert_eq!(
        completed
            .iter()
            .map(|event| (event.state, event.phase))
            .collect::<Vec<_>>(),
        vec![
            (DiagnosticState::Started, DiagnosticPhase::Connect),
            (DiagnosticState::Succeeded, DiagnosticPhase::Connect),
            (DiagnosticState::Closed, DiagnosticPhase::Close),
        ]
    );
    activity.closed();
    activity.succeed();
    activity.fail(
        DiagnosticCode::Canceled,
        DiagnosticRetryDisposition::DoNotRetry,
    );
    assert_eq!(drain_capture(&sink, &captured).await, completed);
    assert_eq!(
        environment
            .diagnostic_metric(DiagnosticMetric::ConnectSuccesses)
            .total,
        1
    );
    assert_eq!(
        environment
            .diagnostic_metric(DiagnosticMetric::ConnectFailures)
            .total,
        0
    );
    assert_eq!(sink.counts().dropped_events, 0);
    sink.close();
    assert!(sink.wait_cleanup().await.complete);
    assert!(environment.close().await.unwrap().complete);
    drop(activity);
}

#[tokio::test]
async fn sink_local_bucket_rotation_preserves_physical_tail_and_other_sink_correlation() {
    let rotating_environment = TransportEnvironment::new();
    let independent_environment = TransportEnvironment::new();
    let (rotating_sink, rotating_capture) = capture_for_test(rotating_environment.root());
    let (independent_sink, independent_capture) = capture_for_test(independent_environment.root());
    let rotating = rotating_environment
        .root()
        .diagnostic_activity(DiagnosticPhase::Connect, 1);
    let independent = independent_environment
        .root()
        .diagnostic_activity(DiagnosticPhase::Connect, 1);
    let rotating_tail = rotating.retain_physical();
    let independent_tail = independent.retain_physical();
    let started = drain_capture(&rotating_sink, &rotating_capture).await;
    let independent_started = drain_capture(&independent_sink, &independent_capture).await;
    assert_eq!(started.len(), 1);
    assert_eq!(independent_started.len(), 1);
    let original_id = started[0].correlation_id;
    let independent_id = independent_started[0].correlation_id;

    rotating_sink.advance_bucket_for_test();
    rotating.fail(
        DiagnosticCode::Timeout,
        DiagnosticRetryDisposition::DoNotRetry,
    );
    independent.fail(
        DiagnosticCode::Timeout,
        DiagnosticRetryDisposition::DoNotRetry,
    );
    rotating.closed();
    independent.closed();
    let rotated = drain_capture(&rotating_sink, &rotating_capture).await;
    let unchanged = drain_capture(&independent_sink, &independent_capture).await;
    let rotated_failures: Vec<_> = rotated
        .iter()
        .filter(|event| event.state == DiagnosticState::Failed)
        .collect();
    assert_eq!(rotated_failures.len(), 1);
    let rotated_id = rotated_failures[0].correlation_id;
    assert_ne!(rotated_id, original_id);
    for (events, id) in [(&rotated, rotated_id), (&unchanged, independent_id)] {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.correlation_id == id
                    && event.state == DiagnosticState::Failed
                    && event.phase == DiagnosticPhase::Connect
                    && event.code == DiagnosticCode::Timeout)
                .count(),
            1
        );
        assert!(
            !events
                .iter()
                .any(|event| event.state == DiagnosticState::Closed)
        );
    }

    drop(rotating_tail);
    drop(independent_tail);
    let retired = drain_capture(&rotating_sink, &rotating_capture).await;
    let independent_retired = drain_capture(&independent_sink, &independent_capture).await;
    for (events, id) in [
        (&retired, rotated_id),
        (&independent_retired, independent_id),
    ] {
        assert_eq!(events.iter().filter(|event| event.correlation_id == id
            && event.state == DiagnosticState::Failed).count(), 1);
        assert_eq!(events.iter().filter(|event| event.correlation_id == id
            && event.state == DiagnosticState::Closed).count(), 1);
    }
    assert_eq!(
        retired
            .iter()
            .filter(|event| event.correlation_id == original_id
                && event.state == DiagnosticState::Started)
            .count(),
        1
    );
    assert!(
        !retired
            .iter()
            .any(|event| event.correlation_id == original_id
                && matches!(
                    event.state,
                    DiagnosticState::Failed | DiagnosticState::Closed
                ))
    );
    rotating_sink.close();
    independent_sink.close();
    assert!(rotating_sink.wait_cleanup().await.complete);
    assert!(independent_sink.wait_cleanup().await.complete);
    assert!(rotating_environment.close().await.unwrap().complete);
    assert!(independent_environment.close().await.unwrap().complete);
}
