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
    {
        // Use the same bucket control as the sink's existing expiry coverage.
        // The next real begin/maintenance call performs the UTC refresh.
        let mut state = sink.inner.state.lock().unwrap();
        state.bucket = current_bucket().saturating_sub(1);
    }

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
