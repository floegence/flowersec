//! Application persistence retains its actual callback tail after the original
//! caller closes delivery. A saved reference never acquires a Start capability.
use crate::{
    ApplicationInvocationContext, OperationReference, ServiceError, ServiceFailure,
    StreamingOperation, UnaryOperation,
    application_executor_v4::ApplicationGroup,
    environment_v4::{ResourceAccount, ResourceLimits},
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{
    fmt,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, oneshot};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceSaveOutcome {
    Unknown,
    Confirmed,
}
#[async_trait]
pub trait OperationReferenceStore: fmt::Debug + Send + Sync + 'static {
    /// Confirmed means the adapter's declared durable create-or-compare
    /// transaction completed for these exact canonical bytes and identity.
    async fn save(
        &self,
        reference: OperationReference,
        context: ApplicationInvocationContext,
    ) -> Result<ReferenceSaveOutcome, ServiceError>;
    fn application_bytes(&self) -> u64;
}
#[derive(Clone, Debug)]
pub struct ReferenceSaveSnapshot {
    pub reference: OperationReference,
    pub attempted: bool,
    pub outcome: ReferenceSaveOutcome,
    pub settled: bool,
    pub application_input_provided: bool,
}
struct ReceiptInner {
    state: Mutex<ReferenceSaveSnapshot>,
    changed: Notify,
}
#[derive(Clone)]
pub struct ReferenceSaveReceipt(Arc<ReceiptInner>);
impl fmt::Debug for ReferenceSaveReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReferenceSaveReceipt { <opaque> }")
    }
}
impl ReferenceSaveReceipt {
    pub fn snapshot(&self) -> ReferenceSaveSnapshot {
        self.0.state.lock().expect("reference save").clone()
    }
    pub async fn wait_settled(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ReferenceSaveSnapshot, ServiceError> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let snapshot = self.snapshot();
            if snapshot.settled {
                return Ok(snapshot);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ServiceError(ServiceFailure::Canceled)) }
        }
    }
}
#[derive(Clone, Debug, thiserror::Error)]
#[error("operation reference save failed: {failure:?}")]
pub struct ReferenceSaveFailure {
    pub failure: ServiceFailure,
    pub receipt: ReferenceSaveReceipt,
}
#[derive(Debug)]
pub struct SavedUnaryPreparation<T> {
    pub operation: UnaryOperation<T>,
    pub reference: OperationReference,
    pub receipt: ReferenceSaveReceipt,
}
#[derive(Debug)]
pub struct SavedStreamingPreparation<T> {
    pub operation: StreamingOperation<T>,
    pub reference: OperationReference,
    pub receipt: ReferenceSaveReceipt,
}
#[derive(Debug)]
pub struct SavedStreamingResumePreparation<T> {
    pub operation: crate::StreamingResumeOperation<T>,
    pub reference: OperationReference,
    pub receipt: ReferenceSaveReceipt,
}
#[derive(Debug, thiserror::Error)]
pub enum PrepareAndSaveError {
    #[error("operation preparation failed: {0}")]
    Preparation(ServiceError),
    #[error("{0}")]
    Save(ReferenceSaveFailure),
}
struct Delivery {
    open: bool,
}
struct DeliveryObserver {
    delivery: Arc<Mutex<Delivery>>,
    cancellation: CancellationToken,
}
impl Drop for DeliveryObserver {
    fn drop(&mut self) {
        self.delivery.lock().expect("reference save delivery").open = false;
        self.cancellation.cancel();
    }
}
pub(crate) async fn save<T: Send + 'static>(
    operation: UnaryOperation<T>,
    store: Arc<dyn OperationReferenceStore>,
    account: ResourceAccount,
    group: ApplicationGroup,
    context: Option<ApplicationInvocationContext>,
    cancellation: CancellationToken,
) -> Result<SavedUnaryPreparation<T>, ReferenceSaveFailure> {
    let Some(reference) = operation.reference() else {
        // This helper is entered only after an execution preparation; the
        // public caller rejects transient shapes before it can reach here.
        unreachable!("execution preparation has its original reference");
    };
    let receipt = ReferenceSaveReceipt(Arc::new(ReceiptInner {
        state: Mutex::new(ReferenceSaveSnapshot {
            reference: reference.clone(),
            attempted: false,
            outcome: ReferenceSaveOutcome::Unknown,
            settled: false,
            application_input_provided: false,
        }),
        changed: Notify::new(),
    }));
    let failure = |code| ReferenceSaveFailure {
        failure: code,
        receipt: receipt.clone(),
    };
    let failure_before_run = |code| {
        receipt.0.state.lock().expect("reference save").settled = true;
        receipt.0.changed.notify_waiters();
        ReferenceSaveFailure {
            failure: code,
            receipt: receipt.clone(),
        }
    };
    operation
        .freeze_controller_reference()
        .map_err(|error| failure_before_run(error.0))?;
    operation
        .check_prepared_target()
        .map_err(|error| failure_before_run(error.0))?;
    let application_bytes = store.application_bytes();
    if application_bytes == 0 || application_bytes > 1 << 30 {
        return Err(failure_before_run(ServiceFailure::ConfigurationCapacity));
    }
    let charge = account
        .reserve(ResourceLimits {
            sdk_bytes: application_bytes + 8192,
            items: 2,
            tasks: 1,
            timers: 1,
            ..ResourceLimits::default()
        })
        .map_err(|error| failure_before_run(ServiceError::from(error).0))?;
    let position = group
        .try_ordinary(false, context.as_ref())
        .map_err(|error| failure_before_run(ServiceError::from(error).0))?;
    let delivery = Arc::new(Mutex::new(Delivery { open: true }));
    let scope_cancellation = cancellation.child_token();
    let _observer = DeliveryObserver {
        delivery: delivery.clone(),
        cancellation: scope_cancellation.clone(),
    };
    let (sender, receiver) = oneshot::channel();
    let original_receipt = receipt.clone();
    let original_reference = reference.clone();
    let deadline = operation.deadline();
    tokio::spawn(async move {
        let _charge = charge;
        let invocation = match position.enter() {
            Ok(invocation) => invocation,
            Err(error) => {
                original_receipt
                    .0
                    .state
                    .lock()
                    .expect("reference save")
                    .settled = true;
                original_receipt.0.changed.notify_waiters();
                let _ = sender.send(Err(ReferenceSaveFailure {
                    failure: ServiceError::from(error).0,
                    receipt: original_receipt,
                }));
                return;
            }
        };
        let accepted = account.with_security(|| {
            let gate = delivery.lock().expect("reference save delivery");
            if !gate.open || scope_cancellation.is_cancelled() {
                return false;
            }
            let mut state = original_receipt.0.state.lock().expect("reference save");
            state.attempted = true;
            state.application_input_provided = true;
            true
        });
        if !matches!(accepted, Ok(true)) {
            original_receipt
                .0
                .state
                .lock()
                .expect("reference save")
                .settled = true;
            original_receipt.0.changed.notify_waiters();
            let _ = sender.send(Err(ReferenceSaveFailure {
                failure: ServiceFailure::Canceled,
                receipt: original_receipt,
            }));
            return;
        }
        let callback =
            AssertUnwindSafe(store.save(original_reference.clone(), invocation.context()))
                .catch_unwind();
        tokio::pin!(callback);
        let outcome = loop {
            tokio::select! {
                outcome = &mut callback => break outcome,
                _ = scope_cancellation.cancelled() => {
                    delivery.lock().expect("reference save delivery").open = false;
                    invocation.cancel(); break callback.await;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    delivery.lock().expect("reference save delivery").open = false;
                    invocation.cancel(); break callback.await;
                }
                _ = account.security_changed() => {},
                _ = tokio::time::sleep(account.next_security_check()) => {},
            }
            if account.check().is_err() {
                delivery.lock().expect("reference save delivery").open = false;
                invocation.cancel();
                break callback.await;
            }
        }
        .unwrap_or(Err(ServiceError(ServiceFailure::ServiceFailed)));
        let confirmed = matches!(outcome, Ok(ReferenceSaveOutcome::Confirmed));
        {
            let mut state = original_receipt.0.state.lock().expect("reference save");
            state.outcome = if confirmed {
                ReferenceSaveOutcome::Confirmed
            } else {
                ReferenceSaveOutcome::Unknown
            };
            state.settled = true;
        }
        original_receipt.0.changed.notify_waiters();
        drop(invocation);
        drop(position);
        if !confirmed {
            operation.close();
            let _ = sender.send(Err(ReferenceSaveFailure {
                failure: outcome
                    .err()
                    .map_or(ServiceFailure::ServiceUnavailable, |error| error.0),
                receipt: original_receipt,
            }));
            return;
        }
        // Both returned send outcomes are dropped after the root gate. A
        // failed delivery can contain the last real operation resource owner.
        let target_view = operation.clone();
        let token_deadline = target_view.resume_token_deadline();
        let mut bundle = Some((sender, operation));
        let delivered = target_view.with_prepared_target(|| {
            account.with_security_time(|now| {
                let gate = delivery.lock().expect("reference save delivery");
                let (sender, operation) = bundle.take().expect("original reference save delivery");
                if !gate.open
                    || scope_cancellation.is_cancelled()
                    || tokio::time::Instant::now() >= deadline
                    || token_deadline.is_some_and(|expires| now.upper_ms >= expires)
                {
                    return Err((sender, operation));
                }
                Ok(sender.send(Ok(SavedUnaryPreparation {
                    operation,
                    reference: original_reference,
                    receipt: original_receipt.clone(),
                })))
            })
        });
        match delivered {
            Ok(Ok(Err((sender, operation)))) => {
                operation.close();
                let _ = sender.send(Err(ReferenceSaveFailure {
                    failure: ServiceFailure::Canceled,
                    receipt: original_receipt,
                }));
            }
            Ok(Ok(Ok(Err(Ok(prepared))))) => prepared.operation.close(),
            Err(error) => {
                if let Some((sender, operation)) = bundle.take() {
                    operation.close();
                    let _ = sender.send(Err(ReferenceSaveFailure {
                        failure: error.0,
                        receipt: original_receipt,
                    }));
                }
            }
            Ok(Err(error)) => {
                if let Some((sender, operation)) = bundle.take() {
                    operation.close();
                    let _ = sender.send(Err(ReferenceSaveFailure {
                        failure: ServiceError::from(error).0,
                        receipt: original_receipt,
                    }));
                }
            }
            _ => {}
        }
    });
    tokio::select! {
        result = receiver => result.unwrap_or_else(|_| Err(failure(ServiceFailure::ServiceUnavailable))),
        _ = cancellation.cancelled() => Err(failure(ServiceFailure::Canceled)),
        _ = tokio::time::sleep_until(deadline) => Err(failure(ServiceFailure::DeadlineExceeded)),
    }
}
pub(crate) async fn save_streaming<T: Send + 'static>(
    operation: StreamingOperation<T>,
    store: Arc<dyn OperationReferenceStore>,
    account: ResourceAccount,
    group: ApplicationGroup,
    context: Option<ApplicationInvocationContext>,
    cancellation: CancellationToken,
) -> Result<SavedStreamingPreparation<T>, ReferenceSaveFailure> {
    let Some(reference) = operation.reference() else {
        // This helper is entered only after an execution preparation; the
        // public caller rejects transient shapes before it can reach here.
        unreachable!("execution preparation has its original reference");
    };
    let receipt = ReferenceSaveReceipt(Arc::new(ReceiptInner {
        state: Mutex::new(ReferenceSaveSnapshot {
            reference: reference.clone(),
            attempted: false,
            outcome: ReferenceSaveOutcome::Unknown,
            settled: false,
            application_input_provided: false,
        }),
        changed: Notify::new(),
    }));
    let failure = |code| ReferenceSaveFailure {
        failure: code,
        receipt: receipt.clone(),
    };
    let failure_before_run = |code| {
        receipt.0.state.lock().expect("reference save").settled = true;
        receipt.0.changed.notify_waiters();
        ReferenceSaveFailure {
            failure: code,
            receipt: receipt.clone(),
        }
    };
    let application_bytes = store.application_bytes();
    if application_bytes == 0 || application_bytes > 1 << 30 {
        return Err(failure_before_run(ServiceFailure::ConfigurationCapacity));
    }
    let charge = account
        .reserve(ResourceLimits {
            sdk_bytes: application_bytes + 8192,
            items: 2,
            tasks: 1,
            timers: 1,
            ..ResourceLimits::default()
        })
        .map_err(|error| failure_before_run(ServiceError::from(error).0))?;
    let position = group
        .try_ordinary(false, context.as_ref())
        .map_err(|error| failure_before_run(ServiceError::from(error).0))?;
    let delivery = Arc::new(Mutex::new(Delivery { open: true }));
    let scope_cancellation = cancellation.child_token();
    let _observer = DeliveryObserver {
        delivery: delivery.clone(),
        cancellation: scope_cancellation.clone(),
    };
    let (sender, receiver) = oneshot::channel();
    let original_receipt = receipt.clone();
    let original_reference = reference.clone();
    let deadline = operation.deadline();
    tokio::spawn(async move {
        let _charge = charge;
        let invocation = match position.enter() {
            Ok(invocation) => invocation,
            Err(error) => {
                original_receipt
                    .0
                    .state
                    .lock()
                    .expect("reference save")
                    .settled = true;
                original_receipt.0.changed.notify_waiters();
                let _ = sender.send(Err(ReferenceSaveFailure {
                    failure: ServiceError::from(error).0,
                    receipt: original_receipt,
                }));
                return;
            }
        };
        let accepted = account.with_security(|| {
            let gate = delivery.lock().expect("reference save delivery");
            if !gate.open || scope_cancellation.is_cancelled() {
                return false;
            }
            let mut state = original_receipt.0.state.lock().expect("reference save");
            state.attempted = true;
            state.application_input_provided = true;
            true
        });
        if !matches!(accepted, Ok(true)) {
            original_receipt
                .0
                .state
                .lock()
                .expect("reference save")
                .settled = true;
            original_receipt.0.changed.notify_waiters();
            let _ = sender.send(Err(ReferenceSaveFailure {
                failure: ServiceFailure::Canceled,
                receipt: original_receipt,
            }));
            return;
        }
        let callback =
            AssertUnwindSafe(store.save(original_reference.clone(), invocation.context()))
                .catch_unwind();
        tokio::pin!(callback);
        let outcome = loop {
            tokio::select! {
                outcome = &mut callback => break outcome,
                _ = scope_cancellation.cancelled() => {
                    delivery.lock().expect("reference save delivery").open = false;
                    invocation.cancel(); break callback.await;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    delivery.lock().expect("reference save delivery").open = false;
                    invocation.cancel(); break callback.await;
                }
                _ = account.security_changed() => {},
                _ = tokio::time::sleep(account.next_security_check()) => {},
            }
            if account.check().is_err() {
                delivery.lock().expect("reference save delivery").open = false;
                invocation.cancel();
                break callback.await;
            }
        }
        .unwrap_or(Err(ServiceError(ServiceFailure::ServiceFailed)));
        let confirmed = matches!(outcome, Ok(ReferenceSaveOutcome::Confirmed));
        {
            let mut state = original_receipt.0.state.lock().expect("reference save");
            state.outcome = if confirmed {
                ReferenceSaveOutcome::Confirmed
            } else {
                ReferenceSaveOutcome::Unknown
            };
            state.settled = true;
        }
        original_receipt.0.changed.notify_waiters();
        drop(invocation);
        drop(position);
        if !confirmed {
            operation.close();
            let _ = sender.send(Err(ReferenceSaveFailure {
                failure: outcome
                    .err()
                    .map_or(ServiceFailure::ServiceUnavailable, |error| error.0),
                receipt: original_receipt,
            }));
            return;
        }
        // Both returned send outcomes are dropped after the root gate. A
        // failed delivery can contain the last real operation resource owner.
        let delivered = account.with_security(|| {
            let gate = delivery.lock().expect("reference save delivery");
            if !gate.open
                || scope_cancellation.is_cancelled()
                || tokio::time::Instant::now() >= deadline
            {
                return Err((sender, operation));
            }
            Ok(sender.send(Ok(SavedStreamingPreparation {
                operation,
                reference: original_reference,
                receipt: original_receipt.clone(),
            })))
        });
        match delivered {
            Ok(Err((sender, operation))) => {
                operation.close();
                let _ = sender.send(Err(ReferenceSaveFailure {
                    failure: ServiceFailure::Canceled,
                    receipt: original_receipt,
                }));
            }
            Ok(Ok(Err(Ok(prepared)))) => prepared.operation.close(),
            _ => {}
        }
    });
    tokio::select! {
        result = receiver => result.unwrap_or_else(|_| Err(failure(ServiceFailure::ServiceUnavailable))),
        _ = cancellation.cancelled() => Err(failure(ServiceFailure::Canceled)),
        _ = tokio::time::sleep_until(deadline) => Err(failure(ServiceFailure::DeadlineExceeded)),
    }
}
