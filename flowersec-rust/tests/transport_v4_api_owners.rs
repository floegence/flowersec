use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use bytes::Bytes;
use flowersec::{
    ByteStream, OperationHandle, OperationStatus, ReadCause, ReadError, ReadErrorCode,
    ReadMethodFailureReason, ReadStreamStatus, ReadWaitStatus, ReaderCursor, ReaderCursorOptions,
    SessionError, StreamReadOwner, StreamV4Ext, WriteOperation, WriteRequestAdmission,
    WriteStagingOwner,
};
use futures_util::poll;
use tokio::sync::{Notify, Semaphore};

type ReadStep = Result<Option<Bytes>, SessionError>;

#[derive(Debug, Default)]
struct ReadQueue {
    steps: StdMutex<VecDeque<ReadStep>>,
    changed: Notify,
}
#[derive(Clone)]
struct ReadSender(Arc<ReadQueue>);
impl ReadSender {
    fn send(&self, value: ReadStep) -> Result<(), ()> {
        self.0.steps.lock().unwrap().push_back(value);
        self.0.changed.notify_waiters();
        Ok(())
    }
}
#[derive(Debug)]
struct ControlledStream {
    reads: Arc<ReadQueue>,
    owner: Arc<StreamReadOwner>,
    write_staging: Arc<WriteStagingOwner>,
    read_calls: AtomicUsize,
    writes: AtomicUsize,
    write_entered: Semaphore,
    write_release: Semaphore,
    accepted: usize,
    resets: AtomicUsize,
}
impl ControlledStream {
    fn new(accepted: usize) -> (Arc<Self>, ReadSender) {
        let reads = Arc::new(ReadQueue::default());
        (
            Arc::new(Self {
                reads: reads.clone(),
                owner: Arc::new(StreamReadOwner::new(4096)),
                write_staging: Arc::new(WriteStagingOwner::new()),
                read_calls: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
                write_entered: Semaphore::new(0),
                write_release: Semaphore::new(0),
                accepted,
                resets: AtomicUsize::new(0),
            }),
            ReadSender(reads),
        )
    }
}

#[async_trait]
impl ByteStream for ControlledStream {
    fn kind(&self) -> &str {
        "test"
    }
    fn terminal_error(&self) -> Option<SessionError> {
        None
    }
    fn read_state(&self) -> (ReadStreamStatus, Option<ReadError>) {
        match self.reads.steps.lock().unwrap().front() {
            Some(Ok(None)) => (ReadStreamStatus::Eof, None),
            Some(Err(_)) => (ReadStreamStatus::Aborted, None),
            _ => (ReadStreamStatus::Open, None),
        }
    }
    fn read_owner(&self) -> Option<Arc<StreamReadOwner>> {
        Some(self.owner.clone())
    }
    fn read_delivery_owner(&self) -> Option<Arc<flowersec::ReadDeliveryAuthorization>> {
        Some(self.owner.delivery_authorization())
    }
    async fn read(&self) -> Result<Option<Bytes>, SessionError> {
        let permit = self.owner.acquire()?;
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        loop {
            let changed = self.reads.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut steps = self.reads.steps.lock().unwrap();
                if let Some(step) = steps.pop_front() {
                    if let Ok(Some(bytes)) = &step {
                        permit.advance(bytes.len())?;
                    }
                    return step;
                }
            }
            changed.await;
        }
    }
    async fn read_cursor_piece(&self, cursor: &ReaderCursor) -> Result<(), SessionError> {
        assert!(cursor.belongs_to(&self.owner));
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        loop {
            let changed = self.reads.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut steps = self.reads.steps.lock().unwrap();
                if let Some(step) = steps.front_mut() {
                    match step {
                        Ok(Some(bytes)) => {
                            let take = cursor.transfer_from(bytes)?;
                            *bytes = bytes.slice(take..);
                            if bytes.is_empty() {
                                steps.pop_front();
                            }
                        }
                        Ok(None) => {
                            cursor.terminate_input(ReadStreamStatus::Eof, None);
                            steps.pop_front();
                        }
                        Err(error) => {
                            let error = *error;
                            steps.pop_front();
                            return Err(error);
                        }
                    }
                    return Ok(());
                }
            }
            changed.await;
        }
    }
    async fn write(&self, _payload: Bytes) -> Result<usize, SessionError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.write_entered.add_permits(1);
        self.write_release.acquire().await.unwrap().forget();
        Ok(self.accepted)
    }
    fn write_staging_owner(&self) -> Option<Arc<WriteStagingOwner>> {
        Some(self.write_staging.clone())
    }
    async fn write_prepared(
        &self,
        payload: Bytes,
        admission: &WriteRequestAdmission,
    ) -> Result<(), SessionError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        // This controlled native owner accepts a prefix, then models an actual
        // publication tail before trying to accept the remaining suffix.
        admission.accept(payload.len().min(self.accepted))?;
        self.write_entered.add_permits(1);
        self.write_release.acquire().await.unwrap().forget();
        admission.accept(payload.len().saturating_sub(self.accepted))?;
        Ok(())
    }
    async fn close_write(&self) -> Result<(), SessionError> {
        panic!("read or write operation must not finish the stream")
    }
    async fn reset(&self) -> Result<(), SessionError> {
        self.resets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn close(&self) -> Result<(), SessionError> {
        self.reset().await
    }
}

fn exact(stream: Arc<ControlledStream>, target: u64) -> ReaderCursor {
    ReaderCursor::new(
        stream,
        ReaderCursorOptions {
            exact: Some(target),
            delimiter: None,
            max_bytes: 0,
        },
    )
    .unwrap()
}

fn until(stream: Arc<ControlledStream>, delimiter: &'static [u8], limit: u64) -> ReaderCursor {
    ReaderCursor::new(
        stream,
        ReaderCursorOptions {
            exact: None,
            delimiter: Some(Bytes::from_static(delimiter)),
            max_bytes: limit,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn read_owner_invalid_targets_and_mismatched_methods_do_not_consume_input() {
    let (stream, _send) = ControlledStream::new(0);
    for options in [
        ReaderCursorOptions {
            exact: Some(1),
            delimiter: Some(Bytes::from_static(b"\n")),
            max_bytes: 1,
        },
        ReaderCursorOptions {
            exact: None,
            delimiter: Some(Bytes::from_static(b"\r\n")),
            max_bytes: 1,
        },
        ReaderCursorOptions {
            exact: None,
            delimiter: Some(Bytes::from_static(b"\n")),
            max_bytes: 0,
        },
    ] {
        assert!(ReaderCursor::new(stream.clone(), options).is_err());
    }
    assert!(exact(stream.clone(), 3).read_until().await.is_err());
    assert!(until(stream.clone(), b"\r\n", 3).read_line().await.is_err());
    assert!(
        until(stream.clone(), b"\n", 3)
            .read_exactly()
            .await
            .is_err()
    );
    assert_eq!(stream.read_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn read_owner_exact_eof_and_stream_failure_return_the_retained_prefix() {
    for terminal in [Ok(None), Err(SessionError::StreamReset)] {
        let (stream, send) = ControlledStream::new(0);
        send.send(Ok(Some(Bytes::from_static(b"ab")))).unwrap();
        send.send(terminal.clone()).unwrap();
        let cursor = exact(stream, 5);
        let result = cursor.read_exactly().await.unwrap();
        assert_eq!(result.data, b"ab"[..]);
        assert_eq!(result.progress.filled, 2);
        assert_eq!(result.progress.offset, 2);
        assert_eq!(cursor.progress(), result.progress);
        if terminal.is_ok() {
            assert_eq!(result.stream_status, ReadStreamStatus::Eof);
            assert_eq!(result.cause, Some(ReadCause::UnexpectedEof));
            assert_eq!(result.error, None);
        } else {
            assert_ne!(result.stream_status, ReadStreamStatus::Eof);
            assert_eq!(result.cause, None);
            assert_eq!(result.stream_status, ReadStreamStatus::Aborted);
            assert_eq!(result.error, None);
        }
    }
}

#[tokio::test]
async fn read_owner_until_respects_the_inclusive_limit_and_preserves_line_bytes() {
    let (stream, send) = ControlledStream::new(0);
    send.send(Ok(Some(Bytes::from_static(b"ab\r")))).unwrap();
    send.send(Ok(Some(Bytes::from_static(b"\n")))).unwrap();
    let result = until(stream, b"\r\n", 4).read_until().await.unwrap();
    assert_eq!(result.data, b"ab\r\n"[..]);
    assert_eq!(result.cause, None);

    let (stream, send) = ControlledStream::new(0);
    send.send(Ok(Some(Bytes::from_static(b"abcd\n")))).unwrap();
    let result = until(stream, b"\n", 4).read_line().await.unwrap();
    assert_eq!(result.data, b"abcd"[..]);
    assert_eq!(result.cause, Some(ReadCause::DelimiterNotFound));
    assert_eq!(result.progress.filled, 4);
    assert_ne!(result.stream_status, ReadStreamStatus::Eof);
}

#[tokio::test]
async fn read_owner_dropping_a_read_wait_keeps_progress_and_the_partial_delimiter() {
    let (stream, send) = ControlledStream::new(0);
    send.send(Ok(Some(Bytes::from_static(b"abc\r")))).unwrap();
    let cursor = until(stream, b"\r\n", 8);
    let mut wait = Box::pin(cursor.read_until());
    assert!(poll!(wait.as_mut()).is_pending());
    assert_eq!(cursor.progress().filled, 4);
    assert!(cursor.read_until().await.is_err());
    drop(wait);
    send.send(Ok(Some(Bytes::from_static(b"\n")))).unwrap();
    let result = cursor.read_until().await.unwrap();
    assert_eq!(result.data, b"abc\r\n"[..]);
    assert_eq!(result.progress.filled, 5);
    assert_eq!(result.progress.offset, 5);
}

#[tokio::test]
async fn read_owner_take_prefix_freezes_without_reading_and_only_delivers_once() {
    let (stream, _send) = ControlledStream::new(0);
    let cursor = exact(stream.clone(), 4);
    let result = cursor.take_prefix().await.unwrap();
    assert!(result.data.is_empty());
    assert_ne!(result.stream_status, ReadStreamStatus::Eof);
    assert_eq!(result.cause, None);
    assert_eq!(result.progress.target, Some(4));
    assert_eq!(stream.read_calls.load(Ordering::SeqCst), 0);
    assert!(cursor.take_prefix().await.is_err());
    assert!(cursor.read_exactly().await.is_err());
}

#[tokio::test]
async fn read_owner_take_prefix_settles_the_active_wait_and_retains_its_prefix() {
    let (stream, send) = ControlledStream::new(0);
    send.send(Ok(Some(Bytes::from_static(b"ab")))).unwrap();
    let cursor = exact(stream.clone(), 4);
    let mut wait = Box::pin(cursor.read_exactly());
    assert!(poll!(wait.as_mut()).is_pending());
    let (prefix, interrupted) = tokio::join!(cursor.take_prefix(), wait);
    assert!(interrupted.is_err());
    let prefix = prefix.unwrap();
    assert_eq!(prefix.data, b"ab"[..]);
    assert_eq!(prefix.progress.filled, 2);
    assert_eq!(stream.resets.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn read_owner_a_write_survives_dropped_waits_and_repeated_start_is_single_flight() {
    let (stream, _send) = ControlledStream::new(2);
    let operation = WriteOperation::prepare(stream.clone(), Bytes::from_static(b"abcd"));
    operation.start().await.unwrap();
    operation.start().await.unwrap();
    stream.write_entered.acquire().await.unwrap().forget();
    let mut wait = Box::pin(operation.wait());
    assert!(poll!(wait.as_mut()).is_pending());
    drop(wait);
    assert!(!operation.cleanup_status().complete);
    assert_eq!(operation.cleanup_status().pending_callbacks, 1);
    stream.write_release.add_permits(1);
    let result = operation.wait().await.unwrap();
    assert_eq!(result.requested_bytes, 4);
    assert_eq!(result.accepted_bytes, 4);
    assert_eq!(result.terminal_reason.as_deref(), Some("complete"));
    assert!(result.cleanup.complete);
    assert_eq!(result.cleanup.pending_callbacks, 0);
    assert_eq!(stream.writes.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&stream), 1);
    operation.cancel();
    operation.start().await.unwrap();
    assert_eq!(operation.wait().await.unwrap(), result);
}

#[tokio::test]
async fn read_owner_canceled_writes_preserve_real_acceptance_without_resetting_the_stream() {
    let (stream, _send) = ControlledStream::new(2);
    let operation = WriteOperation::prepare(stream.clone(), Bytes::from_static(b"abcd"));
    operation.start().await.unwrap();
    stream.write_entered.acquire().await.unwrap().forget();
    assert_eq!(operation.progress().accepted_bytes, 2);
    operation.cancel();
    assert!(!operation.cleanup_status().complete);
    stream.write_release.add_permits(1);
    let result = operation.wait().await.unwrap();
    assert_eq!(result.accepted_bytes, 2);
    assert_eq!(result.terminal_reason.as_deref(), Some("canceled"));
    assert_eq!(stream.resets.load(Ordering::SeqCst), 0);

    let never_started = WriteOperation::prepare(stream.clone(), Bytes::from_static(b"abcd"));
    never_started.cancel();
    assert_eq!(never_started.start().await, Err(SessionError::Canceled));
    assert_eq!(never_started.wait().await.unwrap().accepted_bytes, 0);
    assert_eq!(stream.writes.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&stream), 1);
}

#[test]
fn read_owner_unavailable_execution_owner_never_creates_remote_execution_facts() {
    let operation = OperationHandle::prepare();
    assert_eq!(operation.start(), Err(SessionError::OperationFailed));
    assert_eq!(operation.status(), OperationStatus::NotStarted);
    assert!(operation.cleanup_status().complete);
    operation.request_cancel();
    assert_eq!(operation.status(), OperationStatus::NotStarted);
}

#[tokio::test]
async fn read_owner_suffix_stays_in_the_source_and_offsets_include_ordinary_reads() {
    let (stream, send) = ControlledStream::new(0);
    send.send(Ok(Some(Bytes::from_static(b"first")))).unwrap();
    assert_eq!(stream.read().await.unwrap().unwrap(), b"first"[..]);
    send.send(Ok(Some(Bytes::from_static(b"abc\nrest"))))
        .unwrap();
    let cursor = until(stream.clone(), b"\n", 8);
    assert_eq!(stream.read().await, Err(SessionError::ReadInProgress));
    let conflict = ReaderCursor::new(
        stream.clone(),
        ReaderCursorOptions {
            exact: Some(2),
            delimiter: None,
            max_bytes: 0,
        },
    )
    .unwrap_err();
    assert_eq!(conflict.reason, ReadMethodFailureReason::ReadInProgress);
    let result = cursor.read_line().await.unwrap();
    assert_eq!(result.data, b"abc\n"[..]);
    assert_eq!(result.progress.offset, 9);
    assert_eq!(result.progress.filled, 4);
    assert_eq!(result.wait_status, ReadWaitStatus::Ready);
    assert_eq!(
        cursor.read_line().await.unwrap_err().reason,
        ReadMethodFailureReason::AlreadyDelivered
    );
    assert_eq!(
        cursor.take_prefix().await.unwrap_err().reason,
        ReadMethodFailureReason::AlreadyDelivered
    );
    let next = exact(stream.clone(), 2).read_exactly().await.unwrap();
    assert_eq!(next.data, b"re"[..]);
    assert_eq!(next.progress.offset, 11);
    assert_eq!(stream.read().await.unwrap().unwrap(), b"st"[..]);
    let empty = exact(stream.clone(), 0).read_exactly().await.unwrap();
    assert_eq!(empty.progress.offset, 13);
    assert!(empty.data.is_empty());
    assert_eq!(Arc::strong_count(&stream), 1);
}

#[tokio::test]
async fn read_owner_cancel_retains_direction_and_close_releases_it() {
    let (stream, send) = ControlledStream::new(0);
    send.send(Ok(Some(Bytes::from_static(b"ab")))).unwrap();
    let cursor = exact(stream.clone(), 5);
    let mut wait = Box::pin(cursor.read_exactly());
    assert!(poll!(wait.as_mut()).is_pending());
    drop(wait);
    assert_eq!(stream.read().await, Err(SessionError::ReadInProgress));
    cursor.close();
    assert_eq!(
        cursor.read_exactly().await.unwrap_err().reason,
        ReadMethodFailureReason::Closed
    );
    send.send(Ok(Some(Bytes::from_static(b"cd")))).unwrap();
    let next = exact(stream, 2).read_exactly().await.unwrap();
    assert_eq!(next.data, b"cd"[..]);
    assert_eq!(next.progress.offset, 4);
}

#[tokio::test]
async fn read_owner_limit_retains_the_next_byte_and_error_has_registered_projection() {
    let (stream, send) = ControlledStream::new(0);
    send.send(Ok(Some(Bytes::from_static(b"abcd\n")))).unwrap();
    let result = until(stream.clone(), b"\n", 4).read_until().await.unwrap();
    assert_eq!(result.cause, Some(ReadCause::DelimiterNotFound));
    assert_eq!(result.stream_status, ReadStreamStatus::Open);
    assert_eq!(stream.read().await.unwrap().unwrap(), b"\n"[..]);
    send.send(Ok(Some(Bytes::from_static(b"x")))).unwrap();
    send.send(Err(SessionError::ResourceExhausted)).unwrap();
    let result = exact(stream, 4).read_exactly().await.unwrap();
    assert_eq!(result.data, b"x"[..]);
    assert_eq!(result.progress.offset, 6);
    assert_eq!(result.stream_status, ReadStreamStatus::Error);
    assert_eq!(
        result.error,
        Some(ReadError::new(ReadErrorCode::ResourceExhausted))
    );
}

#[tokio::test]
async fn read_owner_cursor_cap_is_checked_before_input_or_direction_consumption() {
    let (stream, send) = ControlledStream::new(0);
    let failure = ReaderCursor::new(
        stream.clone(),
        ReaderCursorOptions {
            exact: Some(4097),
            delimiter: None,
            max_bytes: 0,
        },
    )
    .unwrap_err();
    assert_eq!(failure.reason, ReadMethodFailureReason::InvalidArgument);
    assert!(failure.cursor.is_none());
    send.send(Ok(Some(Bytes::from_static(b"z")))).unwrap();
    assert_eq!(stream.read().await.unwrap().unwrap(), b"z"[..]);
}

#[tokio::test]
async fn read_owner_exact_zero_observes_a_terminal_committed_after_construction() {
    for terminal in [Ok(None), Err(SessionError::StreamReset)] {
        let (stream, send) = ControlledStream::new(0);
        let cursor = exact(stream.clone(), 0);
        send.send(terminal.clone()).unwrap();
        let result = cursor.read_exactly().await.unwrap();
        assert_eq!(
            result.stream_status,
            if terminal.is_ok() {
                ReadStreamStatus::Eof
            } else {
                ReadStreamStatus::Aborted
            }
        );
        assert!(result.data.is_empty());
        assert_eq!(stream.read_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn read_owner_delivery_gate_rejects_a_retained_prefix_after_owner_revocation() {
    let (stream, send) = ControlledStream::new(0);
    send.send(Ok(Some(Bytes::from_static(b"ab")))).unwrap();
    let cursor = exact(stream.clone(), 4);
    let mut wait = Box::pin(cursor.read_exactly());
    assert!(poll!(wait.as_mut()).is_pending());
    assert_eq!(cursor.progress().filled, 2);

    stream.owner.revoke_delivery();
    drop(wait);
    let failure = cursor.take_prefix().await.unwrap_err();
    assert_eq!(failure.reason, ReadMethodFailureReason::AuthorizationDenied);
    assert_eq!(failure.cursor.unwrap().transferred_bytes, 2);
}

#[tokio::test]
async fn prepared_write_rejects_payloads_beyond_the_shared_staging_cap() {
    let (stream, _send) = ControlledStream::new(0);
    let payload = Bytes::from(vec![0_u8; 1_048_577]);
    assert_eq!(
        StreamV4Ext::prepare_write(stream, payload).unwrap_err(),
        SessionError::ResourceExhausted
    );
}
