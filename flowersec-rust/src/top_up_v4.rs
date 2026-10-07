//! A finite source-owned control operation. Caller cancellation ends observation;
//! durable pending intent and the original control invocation retain ownership.
#[cfg(test)]
#[path = "top_up_public_lifecycle_v4_tests.rs"]
mod public_lifecycle_tests;
use crate::codec_v4::{self as codec, Limits, Value};
use crate::environment_v4::{EnvironmentCharge, EnvironmentRoot, ResourceLimits};
use crate::pool_v4::top_up::{InstalledMaterial, JournalRecord};
use crate::{
    CleanupStatus, ConnectionMaterialSource, IdentityKeys, PoolCredentialBytes, SQLitePoolStore,
};
use async_trait::async_trait;
use futures_util::FutureExt;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::panic::AssertUnwindSafe;
use std::{
    fmt,
    future::Future,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, TopUpError>;
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("pool TopUp failed: {0:?}")]
pub struct TopUpError(pub TopUpErrorCode);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopUpErrorCode {
    SourceExhausted,
    SourceUnavailable,
    SourceContractInvalid,
    SourceStateUnknown,
    OperationConflict,
    StaleGeneration,
    FutureGeneration,
    StaleOperation,
    FutureOperation,
    SequenceGap,
    ConfigurationCapacity,
    CapacityExhausted,
    RelinkRequired,
    SpentUnknown,
    TopUpRequestExpired,
    SourceResetRequired,
    PermissionDenied,
    Canceled,
    DeadlineExceeded,
}
impl TopUpErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceExhausted => "source_exhausted",
            Self::SourceUnavailable => "source_unavailable",
            Self::SourceContractInvalid => "source_contract_invalid",
            Self::SourceStateUnknown => "source_state_unknown",
            Self::OperationConflict => "operation_conflict",
            Self::StaleGeneration => "stale_generation",
            Self::FutureGeneration => "future_generation",
            Self::StaleOperation => "stale_operation",
            Self::FutureOperation => "future_operation",
            Self::SequenceGap => "sequence_gap",
            Self::ConfigurationCapacity => "configuration_capacity",
            Self::CapacityExhausted => "capacity_exhausted",
            Self::RelinkRequired => "relink_required",
            Self::SpentUnknown => "spent_unknown",
            Self::TopUpRequestExpired => "top_up_request_expired",
            Self::SourceResetRequired => "source_reset_required",
            Self::PermissionDenied => "permission_denied",
            Self::Canceled => "canceled",
            Self::DeadlineExceeded => "deadline_exceeded",
        }
    }
    fn from_str(value: &str) -> Option<Self> {
        [
            Self::SourceExhausted,
            Self::SourceUnavailable,
            Self::SourceContractInvalid,
            Self::SourceStateUnknown,
            Self::OperationConflict,
            Self::StaleGeneration,
            Self::FutureGeneration,
            Self::StaleOperation,
            Self::FutureOperation,
            Self::SequenceGap,
            Self::ConfigurationCapacity,
            Self::CapacityExhausted,
            Self::RelinkRequired,
            Self::SpentUnknown,
            Self::TopUpRequestExpired,
            Self::SourceResetRequired,
            Self::PermissionDenied,
            Self::Canceled,
            Self::DeadlineExceeded,
        ]
        .into_iter()
        .find(|code| code.as_str() == value)
    }
    fn permits_terminal(self) -> bool {
        matches!(
            self,
            Self::TopUpRequestExpired
                | Self::SourceResetRequired
                | Self::CapacityExhausted
                | Self::ConfigurationCapacity
                | Self::RelinkRequired
                | Self::SpentUnknown
        )
    }
}
fn failure(code: TopUpErrorCode) -> TopUpError {
    TopUpError(code)
}
fn recovery_limits() -> ResourceLimits {
    // A recovery-class operation is bounded independently of the owner's
    // standing charge. The extra slot and task permit it to coexist with one
    // ordinary TopUp worker while keeping concurrent recovery-class work
    // finite; the byte/item budget covers the complete decoded batch.
    ResourceLimits {
        sdk_bytes: 524288 + 8192,
        items: 4,
        tasks: 1,
        timers: 1,
        work_slots: 1,
        ..ResourceLimits::default()
    }
}
fn restore_limits() -> ResourceLimits {
    // Restore reads up to 128 persisted records, retains their encoded bytes,
    // holds decoder-produced credentials, and then owns captured pool material
    // at the same time. Account for the artifact, both certificates and the
    // activation envelope per item, with four complete batch copies covering
    // the read/decoder/capture overlap plus bounded codec metadata.
    const MAX_ITEMS: u64 = 128;
    const MAX_ITEM_BYTES: u64 = 65536 + 8192 + 8192 + 4096;
    const MAX_BATCH_COPIES: u64 = 4;
    ResourceLimits {
        sdk_bytes: MAX_ITEMS * MAX_ITEM_BYTES * MAX_BATCH_COPIES + 2097152,
        items: MAX_ITEMS * MAX_BATCH_COPIES + 32,
        tasks: 1,
        timers: 1,
        work_slots: 1,
        ..ResourceLimits::default()
    }
}
fn parsed<T>(value: codec::Result<T>) -> Result<T> {
    value.map_err(|_| failure(TopUpErrorCode::SourceContractInvalid))
}
fn stored<T>(value: std::result::Result<T, crate::PoolStoreError>) -> Result<T> {
    value.map_err(|error| {
        failure(if error.write_state == crate::PoolWriteState::Unknown {
            TopUpErrorCode::SourceStateUnknown
        } else {
            match error.code {
                crate::PoolStoreFailure::Capacity => TopUpErrorCode::CapacityExhausted,
                crate::PoolStoreFailure::Fenced => TopUpErrorCode::StaleGeneration,
                crate::PoolStoreFailure::SpendConflict => TopUpErrorCode::OperationConflict,
                crate::PoolStoreFailure::HistoryUnknown
                | crate::PoolStoreFailure::StorageFormat => TopUpErrorCode::SourceStateUnknown,
                _ => TopUpErrorCode::SourceUnavailable,
            }
        })
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TopUpOptions {
    pub desired_count: u16,
    pub max_item_bytes: u32,
}
impl Default for TopUpOptions {
    fn default() -> Self {
        Self {
            desired_count: 4,
            max_item_bytes: 65536,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopUpState {
    Pending,
    Installed,
    Acked,
    Terminal,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopUpOutcome {
    Success,
    Replay,
    Rejected(TopUpError),
}
#[derive(Clone, Debug)]
pub struct TopUpResult {
    pub state: Option<TopUpState>,
    pub handle: Option<TopUpHandle>,
    pub options: Option<TopUpOptions>,
    pub outcome: Option<TopUpOutcome>,
    pub call_error: Option<TopUpError>,
}
#[derive(Clone, Debug)]
pub struct TopUpRecoveryResult {
    pub operations: Vec<TopUpResult>,
    pub call_error: Option<TopUpError>,
}
struct Observation {
    source: Weak<TopUpOwner>,
    operation: [u8; 16],
    options: TopUpOptions,
    state: Mutex<(TopUpState, Option<TopUpOutcome>)>,
    workers: AtomicUsize,
    changed: Notify,
}
/// An immutable reference to an original operation. It grants no send or takeover right.
#[derive(Clone)]
pub struct TopUpHandle(Arc<Observation>);
impl fmt::Debug for TopUpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TopUpHandle { <opaque> }")
    }
}
impl TopUpHandle {
    pub fn cleanup_status(&self) -> CleanupStatus {
        let pending = self.0.workers.load(Ordering::Acquire) as u64;
        CleanupStatus {
            complete: pending == 0,
            cleanup_incomplete: pending != 0,
            pending_callbacks: pending,
        }
    }
    pub async fn wait_cleanup(&self, cancellation: &CancellationToken) -> Result<CleanupStatus> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(TopUpErrorCode::Canceled)) }
        }
    }
}
/// Trusted authority input bound to the original source and intent, never a business execution ID.
#[derive(Clone, Debug)]
pub struct TopUpIntent {
    pub tenant_id: String,
    pub source_incarnation: [u8; 16],
    pub operation_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub client_identity_digest: [u8; 32],
    pub pool_digest: [u8; 32],
    pub binding_generation: u64,
    pub request_deadline_ms: u64,
    pub options: TopUpOptions,
}
#[async_trait]
pub trait TopUpFenceProvider: fmt::Debug + Send + Sync + 'static {
    async fn owner_fence_proof(
        &self,
        intent: &TopUpIntent,
        current_generation: u64,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>>;
}
#[derive(Debug)]
pub enum TopUpExchangeResult {
    Response {
        canonical_response: Vec<u8>,
        replay: bool,
    },
    AckConfirmed,
    /// Only an authenticated authoritative control result may use this branch.
    Terminal(TopUpError),
}
#[async_trait]
pub trait TopUpControlTransport: fmt::Debug + Send + Sync + 'static {
    async fn exchange(
        &self,
        method: u32,
        canonical_request: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<TopUpExchangeResult>;
}
/// The adapter owns the application material envelope. Captured signed credentials
/// are always verified again by the original source before the Applied transaction.
pub trait TopUpMaterialDecoder: fmt::Debug + Send + Sync + 'static {
    fn decode(&self, canonical_material: &[u8]) -> Result<PoolCredentialBytes>;
}
#[derive(Debug)]
pub struct PoolTopUpConfiguration {
    pub tenant_id: String,
    pub source_incarnation: [u8; 16],
    pub binding_generation: u64,
    pub pool_digest: [u8; 32],
    pub identity: Option<IdentityKeys>,
    pub identity_certificate: Option<Vec<u8>>,
    pub fence_authority_key_id: [u8; 16],
    pub fence_authority_public_key: [u8; 32],
    pub operation_lifetime: Duration,
    pub call_timeout: Duration,
    pub proof_provider: Arc<dyn TopUpFenceProvider>,
    pub control: Arc<dyn TopUpControlTransport>,
    pub material_decoder: Arc<dyn TopUpMaterialDecoder>,
}
struct Round {
    done: AtomicBool,
    error: Mutex<Option<TopUpError>>,
    changed: Notify,
    view: TopUpHandle,
}
pub(crate) struct TopUpOwner {
    source: ConnectionMaterialSource,
    root: Arc<EnvironmentRoot>,
    store: Arc<SQLitePoolStore>,
    configuration: PoolTopUpConfiguration,
    identity_digest: Option<[u8; 32]>,
    stop: CancellationToken,
    current: Mutex<Option<TopUpHandle>>,
    round: Mutex<Option<Arc<Round>>>,
    lifecycle: Mutex<()>,
    recovery_busy: AtomicBool,
    restore_busy: AtomicBool,
    process_tail_busy: AtomicBool,
    workers: AtomicUsize,
    changed: Notify,
    _charge: EnvironmentCharge,
}
struct RecoveryWork {
    owner: Arc<TopUpOwner>,
    cancellation: CancellationToken,
    charge: Option<EnvironmentCharge>,
}
impl Drop for RecoveryWork {
    fn drop(&mut self) {
        // Release finite backing before cleanup can report the worker retired.
        drop(self.charge.take());
        self.owner.recovery_busy.store(false, Ordering::Release);
        self.owner.workers.fetch_sub(1, Ordering::AcqRel);
        self.owner.changed.notify_waiters();
    }
}
struct RecoveryObservation(CancellationToken);
impl Drop for RecoveryObservation {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct RestoreWorker {
    owner: Arc<TopUpOwner>,
    charge: Option<EnvironmentCharge>,
}
impl Drop for RestoreWorker {
    fn drop(&mut self) {
        // Release the finite restore admission only after decoder, durable
        // cleanup, and the late source publication gate have all returned.
        drop(self.charge.take());
        self.owner.restore_busy.store(false, Ordering::Release);
        self.owner.workers.fetch_sub(1, Ordering::AcqRel);
        self.owner.changed.notify_waiters();
    }
}
fn refresh_requires_owner_close(result: std::result::Result<(), TopUpError>) -> bool {
    match result {
        // A temporarily unavailable source/storage observation only ends this
        // call. The owner remains eligible for a later retry.
        Err(TopUpError(TopUpErrorCode::SourceUnavailable)) => false,
        // Unknown continuity/write state, malformed journal facts, and
        // permanent fence failures cannot be safely projected later.
        Err(TopUpError(error)) => matches!(
            error,
            TopUpErrorCode::SourceStateUnknown
                | TopUpErrorCode::SourceContractInvalid
                | TopUpErrorCode::StaleGeneration
                | TopUpErrorCode::FutureGeneration
                | TopUpErrorCode::SequenceGap
                | TopUpErrorCode::SourceResetRequired
                | TopUpErrorCode::RelinkRequired
                | TopUpErrorCode::SpentUnknown
        ),
        Ok(()) => false,
    }
}

struct ProcessTail {
    owner: Arc<TopUpOwner>,
    view: TopUpHandle,
}
impl ProcessTail {
    fn try_new(owner: Arc<TopUpOwner>, view: TopUpHandle) -> Option<Self> {
        owner
            .process_tail_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        owner.workers.fetch_add(1, Ordering::AcqRel);
        view.0.workers.fetch_add(1, Ordering::AcqRel);
        Some(Self { owner, view })
    }
    fn spawn<F>(self, io: F)
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        tokio::spawn(async move {
            // Keep the tail guard alive until the IO future itself has been
            // dropped. This makes the capacity slot and worker counts describe
            // the real control/proof tail, even when its future completes with
            // an error or is canceled during teardown.
            {
                let _ = AssertUnwindSafe(io).catch_unwind().await;
            }
            // A bounded caller may return Installed while the authenticated
            // unary control tail is still running. Merge the tail's final
            // durable Acked/Terminal fact into this original observation
            // before releasing the single physical-operation slot; otherwise
            // a subsequent operation can replace the journal before the old
            // handle ever observes its terminal state.
            // Continuity/provider code can panic while reading history. An
            // unreadable final journal seals this owner before the busy slot is
            // released, so another intent cannot erase an unprojected result.
            // Existing observations keep their already known durable facts.
            let refreshed = AssertUnwindSafe(async { self.owner.refresh_view(&self.view) })
                .catch_unwind()
                .await;
            let close_owner = match refreshed {
                Ok(result) => refresh_requires_owner_close(result),
                // A panic means continuity facts are unknown even if the
                // journal read did not return a typed error.
                Err(_) => true,
            };
            if close_owner {
                self.owner.close();
            }
            drop(self);
        });
    }
}
impl Drop for ProcessTail {
    fn drop(&mut self) {
        self.view.0.workers.fetch_sub(1, Ordering::AcqRel);
        self.view.0.changed.notify_waiters();
        self.owner.workers.fetch_sub(1, Ordering::AcqRel);
        self.owner.process_tail_busy.store(false, Ordering::Release);
        self.owner.changed.notify_waiters();
    }
}
impl fmt::Debug for TopUpOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TopUpOwner { <opaque> }")
    }
}
#[derive(Clone)]
pub struct PreauthorizedPoolSource(Arc<TopUpOwner>);
impl fmt::Debug for PreauthorizedPoolSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreauthorizedPoolSource { <opaque> }")
    }
}
impl PreauthorizedPoolSource {
    pub fn new(
        source: ConnectionMaterialSource,
        configuration: PoolTopUpConfiguration,
    ) -> Result<Self> {
        let (root, store) = source
            .top_up_store_context()
            .map_err(|_| failure(TopUpErrorCode::SourceContractInvalid))?;
        if configuration.tenant_id.is_empty()
            || configuration.tenant_id.len() > 128
            || !configuration
                .tenant_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@-".contains(&byte))
            || configuration.source_incarnation == [0; 16]
            || configuration.binding_generation == 0
            || configuration.fence_authority_key_id == [0; 16]
            || configuration.fence_authority_public_key == [0; 32]
            || !(Duration::from_millis(1)..=Duration::from_secs(120))
                .contains(&configuration.operation_lifetime)
            || !(Duration::from_millis(1)..=Duration::from_secs(120))
                .contains(&configuration.call_timeout)
        {
            return Err(failure(TopUpErrorCode::SourceContractInvalid));
        }
        if configuration
            .identity_certificate
            .as_ref()
            .is_some_and(|certificate| certificate.is_empty() || certificate.len() > 8192)
            || configuration.identity.is_some() != configuration.identity_certificate.is_some()
        {
            return Err(failure(TopUpErrorCode::SourceContractInvalid));
        }
        let identity_digest: Option<[u8; 32]> = configuration
            .identity_certificate
            .as_deref()
            .map(certificate_digest)
            .transpose()?;
        let owner_tenant = configuration.tenant_id.clone();
        let owner_source = configuration.source_incarnation;
        let owner_generation = configuration.binding_generation;
        let charge = root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 3 * 524288 + 65536,
                items: 16,
                tasks: 1,
                timers: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| failure(TopUpErrorCode::ConfigurationCapacity))?;
        let owner = Arc::new(TopUpOwner {
            source: source.clone(),
            root,
            store: Arc::clone(&store),
            configuration,
            identity_digest,
            stop: CancellationToken::new(),
            current: Mutex::new(None),
            round: Mutex::new(None),
            lifecycle: Mutex::new(()),
            recovery_busy: AtomicBool::new(false),
            restore_busy: AtomicBool::new(false),
            process_tail_busy: AtomicBool::new(false),
            workers: AtomicUsize::new(0),
            changed: Notify::new(),
            _charge: charge,
        });
        // Claim the unique in-process owner before touching the durable fence.
        // A failed reconstruction must leave the still-live owner authoritative.
        source
            .claim_top_up(&owner)
            .map_err(|_| failure(TopUpErrorCode::OperationConflict))?;
        if let Err(error) =
            stored(store.top_up_source(&owner_tenant, &owner_source, owner_generation, true))
        {
            source.release_top_up(&owner);
            return Err(error);
        }
        // Applied recovery remains independent of old identity/key availability.
        // Durable unused pool restoration is a separate explicit pool startup step.
        Ok(Self(owner))
    }
    pub fn restore_installed_materials(&self) -> Result<()> {
        // Admission, source close, and the worker count must share the same
        // lifecycle gate. Otherwise a decoder blocked below can be invisible
        // to wait_cleanup, while Close races through the late install check.
        self.0.check()?;
        let _worker = {
            let _lifecycle = self
                .0
                .lifecycle
                .lock()
                .expect("original TopUp restore admission gate");
            self.0.check_without_source()?;
            if self.0.restore_busy.swap(true, Ordering::AcqRel) {
                return Err(failure(TopUpErrorCode::CapacityExhausted));
            }
            let charge = match self.0.root.reserve_environment(restore_limits()) {
                Ok(charge) => charge,
                Err(_) => {
                    self.0.restore_busy.store(false, Ordering::Release);
                    return Err(failure(TopUpErrorCode::ConfigurationCapacity));
                }
            };
            self.0.workers.fetch_add(1, Ordering::AcqRel);
            RestoreWorker {
                owner: self.0.clone(),
                charge: Some(charge),
            }
        };
        // Release the admission gate before decoding or durable restoration.
        // Close can now cancel the owner while this worker remains visible to
        // cleanup until the late install gate and all decoding work finish.
        let identity = self
            .0
            .configuration
            .identity
            .as_ref()
            .ok_or_else(|| failure(TopUpErrorCode::RelinkRequired))?;
        let certificate = self
            .0
            .configuration
            .identity_certificate
            .as_deref()
            .ok_or_else(|| failure(TopUpErrorCode::RelinkRequired))?;
        // Capture the source admission version before reading the durable
        // batch. Acquire increments this version while consuming a material;
        // the source publication gate rechecks it before any restore commit.
        let expected_acquisitions = self.0.source.acquisition_observation().acquisitions;
        let materials = stored(self.0.store.top_up_materials(
            &self.0.configuration.tenant_id,
            &self.0.configuration.source_incarnation,
            self.0.configuration.binding_generation,
        ))?;
        self.0
            .source
            .restore_top_up_materials(
                identity,
                certificate,
                materials,
                self.0.configuration.material_decoder.as_ref(),
                &self.0,
                expected_acquisitions,
            )
            .map_err(|_| failure(TopUpErrorCode::RelinkRequired))
    }
    pub fn material_source(&self) -> ConnectionMaterialSource {
        self.0.source.clone()
    }
    pub fn acquire(
        &self,
        environment: &crate::TransportEnvironment,
        request: &crate::ConnectionRequest,
        cancellation: &CancellationToken,
    ) -> std::result::Result<crate::ConnectionMaterial, crate::MaterialSourceError> {
        self.0.source.acquire(environment, request, cancellation)
    }
    pub fn close(&self) {
        self.0.close();
        self.0.source.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.0.cleanup_status()
    }
    pub async fn wait_cleanup(&self, cancellation: &CancellationToken) -> Result<CleanupStatus> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(TopUpErrorCode::Canceled)) }
        }
    }
    pub fn top_up_status(
        &self,
        handle: &TopUpHandle,
        cancellation: &CancellationToken,
    ) -> TopUpResult {
        let associated = handle
            .0
            .source
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(&owner, &self.0));
        if !associated {
            return refusal(failure(TopUpErrorCode::OperationConflict));
        }
        if cancellation.is_cancelled() {
            return observed(handle, Some(failure(TopUpErrorCode::Canceled)));
        }
        match self.0.check().and_then(|_| self.0.refresh_view(handle)) {
            Ok(()) => observed(handle, None),
            Err(error) => observed(handle, Some(error)),
        }
    }
    pub async fn recover_pending_top_ups(
        &self,
        tenant_id: &str,
        source_incarnation: [u8; 16],
        cancellation: &CancellationToken,
    ) -> TopUpRecoveryResult {
        let refusal = |error| TopUpRecoveryResult {
            operations: Vec::new(),
            call_error: Some(error),
        };
        if cancellation.is_cancelled() {
            return refusal(failure(TopUpErrorCode::Canceled));
        }
        if tenant_id != self.0.configuration.tenant_id
            || source_incarnation != self.0.configuration.source_incarnation
        {
            return refusal(failure(TopUpErrorCode::PermissionDenied));
        }
        let work = {
            let _gate = self
                .0
                .lifecycle
                .lock()
                .expect("original recovery admission");
            if let Err(error) = self.0.check() {
                return refusal(error);
            }
            if self.0.recovery_busy.swap(true, Ordering::AcqRel) {
                return refusal(failure(TopUpErrorCode::CapacityExhausted));
            }
            let charge = match self.0.root.reserve_environment(recovery_limits()) {
                Ok(charge) => charge,
                Err(_) => {
                    self.0.recovery_busy.store(false, Ordering::Release);
                    return refusal(failure(TopUpErrorCode::ConfigurationCapacity));
                }
            };
            self.0.workers.fetch_add(1, Ordering::AcqRel);
            RecoveryWork {
                owner: self.0.clone(),
                cancellation: self.0.stop.child_token(),
                charge: Some(charge),
            }
        };
        let stop = work.cancellation.clone();
        let _observation = RecoveryObservation(stop.clone());
        let timeout = self.0.configuration.call_timeout;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = AssertUnwindSafe(work.owner.recover(&work.cancellation))
                .catch_unwind()
                .await
                .unwrap_or(Err(failure(TopUpErrorCode::SourceContractInvalid)));
            // Order successful result delivery with Close, then retain the
            // worker count and backing through the complete publication tail.
            let source_closed = work.owner.source.is_closed();
            {
                let _gate = work
                    .owner
                    .lifecycle
                    .lock()
                    .expect("original recovery result");
                let result = result.and_then(|operations| {
                    if source_closed {
                        return Err(failure(TopUpErrorCode::SourceUnavailable));
                    }
                    work.owner.check_without_source()?;
                    if work.cancellation.is_cancelled() {
                        return Err(failure(TopUpErrorCode::Canceled));
                    }
                    Ok(operations)
                });
                let _ = sender.send(result);
            }
            drop(work);
        });
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(failure(TopUpErrorCode::Canceled)),
            _ = self.0.stop.cancelled() => Err(failure(TopUpErrorCode::SourceUnavailable)),
            _ = tokio::time::sleep(timeout) => Err(failure(TopUpErrorCode::DeadlineExceeded)),
            result = receiver => result.unwrap_or(Err(failure(TopUpErrorCode::SourceContractInvalid))),
        };
        match result {
            Ok(operations) => TopUpRecoveryResult {
                operations,
                call_error: None,
            },
            Err(error) => refusal(error),
        }
    }
    pub async fn top_up(
        &self,
        options: TopUpOptions,
        cancellation: &CancellationToken,
    ) -> TopUpResult {
        if cancellation.is_cancelled() {
            return refusal(failure(TopUpErrorCode::Canceled));
        }
        let round = {
            let mut active = self.0.round.lock().expect("original TopUp invocation gate");
            if let Some(round) = &*active {
                // An already active round owns the durable operation. Callers
                // join its observation even while a prior bounded caller has
                // detached a physical control tail.
                round.clone()
            } else {
                // A detached tail with no active round still occupies the one
                // finite operation slot. Do not start a second operation until
                // its real unary/cleanup tail has exited.
                if self.0.process_tail_busy.load(Ordering::Acquire) {
                    return refusal(failure(TopUpErrorCode::CapacityExhausted));
                }
                // Durable admission and worker accounting share the lifecycle
                // gate with Close. This prevents Close from publishing a
                // completed cleanup window after begin has passed its source
                // checks but before the original worker is counted.
                let _lifecycle = self
                    .0
                    .lifecycle
                    .lock()
                    .expect("original TopUp admission gate");
                let created = self.0.begin(options);
                let handle = match created {
                    Ok(handle) => handle,
                    Err(error) => return refusal(error),
                };
                let round = Arc::new(Round {
                    done: AtomicBool::new(false),
                    error: Mutex::new(None),
                    changed: Notify::new(),
                    view: handle,
                });
                round.view.0.workers.fetch_add(1, Ordering::AcqRel);
                self.0.workers.fetch_add(1, Ordering::AcqRel);
                *active = Some(round.clone());
                let owner = self.0.clone();
                let original = round.clone();
                tokio::spawn(async move {
                    // Decoder and provider panics can also poison the journal
                    // gate. Keep refresh inside the same unwind boundary so the
                    // original worker still retires its finite responsibility.
                    let error = match AssertUnwindSafe(async {
                        let error = owner.process(&original.view).await.err();
                        let _ = owner.refresh_view(&original.view);
                        error
                    })
                    .catch_unwind()
                    .await
                    {
                        Ok(error) => error,
                        Err(_) => Some(failure(TopUpErrorCode::SourceContractInvalid)),
                    };
                    *original.error.lock().expect("TopUp call result") = error;
                    original.view.0.workers.fetch_sub(1, Ordering::AcqRel);
                    original.view.0.changed.notify_waiters();
                    original.done.store(true, Ordering::Release);
                    original.changed.notify_waiters();
                    let mut active = owner.round.lock().expect("original TopUp tail exit");
                    if active
                        .as_ref()
                        .is_some_and(|round| Arc::ptr_eq(round, &original))
                    {
                        *active = None;
                    }
                    // Keep the owner worker live through the active-round
                    // teardown. Cleanup therefore waits for the complete
                    // worker tail, including removal from the join point.
                    owner.workers.fetch_sub(1, Ordering::AcqRel);
                    owner.changed.notify_waiters();
                });
                round
            }
        };
        loop {
            let changed = round.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if round.done.load(Ordering::Acquire) {
                return observed(&round.view, *round.error.lock().expect("TopUp call result"));
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return observed(&round.view, Some(failure(TopUpErrorCode::Canceled))) }
        }
    }
}
fn refusal(error: TopUpError) -> TopUpResult {
    TopUpResult {
        state: None,
        handle: None,
        options: None,
        outcome: None,
        call_error: Some(error),
    }
}
fn observed(handle: &TopUpHandle, error: Option<TopUpError>) -> TopUpResult {
    let (state, outcome) = *handle.0.state.lock().expect("TopUp observation");
    TopUpResult {
        state: Some(state),
        handle: (!matches!(state, TopUpState::Acked | TopUpState::Terminal))
            .then(|| handle.clone()),
        options: Some(handle.0.options),
        outcome,
        call_error: error,
    }
}
impl TopUpOwner {
    pub(crate) fn close(&self) {
        let _gate = self.lifecycle.lock().expect("original TopUp close gate");
        self.stop.cancel();
        self.changed.notify_waiters();
    }
    async fn recover(
        self: &Arc<Self>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<TopUpResult>> {
        self.check()?;
        if cancellation.is_cancelled() {
            return Err(failure(TopUpErrorCode::Canceled));
        }
        let snapshot = self.journal()?;
        let Some(record) = snapshot.record else {
            return Ok(Vec::new());
        };
        let mut original = intent(&record.request)?;
        original.binding_generation = record.generation;
        original.request_digest = record.digest;
        // This is the source-owned physical invocation. Canceling an observer
        // signals this token but cannot drop a proof provider that still runs.
        let proof = self
            .configuration
            .proof_provider
            .owner_fence_proof(
                &original,
                self.configuration.binding_generation,
                cancellation,
            )
            .await?;
        // Source close publishes its closed bit before taking this lifecycle
        // gate. Observe that bit before locking so recovery never takes
        // lifecycle -> source.state while close can take source.state ->
        // lifecycle. If close races after this observation, acquiring the
        // lifecycle gate first linearizes publication before close.
        if self.source.is_closed() {
            return Err(failure(TopUpErrorCode::SourceUnavailable));
        }
        let _gate = self
            .lifecycle
            .lock()
            .expect("original recovery publication");
        self.check_without_source()?;
        if cancellation.is_cancelled() {
            return Err(failure(TopUpErrorCode::Canceled));
        }
        self.verify_fence(&original, &proof)?;
        let latest = self.journal()?;
        let current = latest
            .record
            .as_ref()
            .filter(|current| {
                current.operation == record.operation && current.digest == record.digest
            })
            .ok_or_else(|| failure(TopUpErrorCode::SourceStateUnknown))?;
        let handle = self.view(current)?;
        Ok(vec![observed(&handle, None)])
    }
    fn check(&self) -> Result<()> {
        if self.source.is_closed() {
            return Err(failure(TopUpErrorCode::SourceUnavailable));
        }
        self.check_without_source()
    }
    fn check_without_source(&self) -> Result<()> {
        if self.stop.is_cancelled() || self.root.is_closed() {
            return Err(failure(TopUpErrorCode::SourceUnavailable));
        }
        self.root
            .sample()
            .map_err(|_| failure(TopUpErrorCode::SourceUnavailable))?;
        Ok(())
    }
    fn cleanup_status(&self) -> CleanupStatus {
        let pending = self.workers.load(Ordering::Acquire) as u64;
        let complete = (self.stop.is_cancelled() || self.source.is_closed()) && pending == 0;
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: pending,
        }
    }
    fn journal(&self) -> Result<crate::pool_v4::top_up::JournalSource> {
        let snapshot = stored(self.store.top_up_source(
            &self.configuration.tenant_id,
            &self.configuration.source_incarnation,
            self.configuration.binding_generation,
            false,
        ))?;
        if let Some(record) = &snapshot.record {
            let original = intent(&record.request)?;
            if original.request_digest != record.digest
                || original.operation_id != record.operation
                || original.client_identity_digest != record.identity
                || original.tenant_id != self.configuration.tenant_id
                || original.source_incarnation != self.configuration.source_incarnation
                || original.pool_digest != self.configuration.pool_digest
            {
                return Err(failure(TopUpErrorCode::SourceStateUnknown));
            }
        }
        Ok(snapshot)
    }
    fn begin(self: &Arc<Self>, options: TopUpOptions) -> Result<TopUpHandle> {
        self.check()?;
        let snapshot = self.journal()?;
        if let Some(record) = snapshot.record.as_ref() {
            if record.state < 3 {
                return self.view(record);
            }
            // The journal retains only one operation. Before replacing a
            // terminal record, synchronously merge its authoritative outcome
            // into the original handle. A detached refresh may have observed
            // a transient storage failure after the durable Ack/Terminal was
            // committed; allowing top_up_begin to delete that record first
            // would make the old handle permanently lose its final fact.
            self.view(record)?;
        }
        if !(1..=4).contains(&options.desired_count)
            || !(1..=65536).contains(&options.max_item_bytes)
        {
            return Err(failure(TopUpErrorCode::SourceContractInvalid));
        }
        let identity = self
            .configuration
            .identity
            .as_ref()
            .ok_or_else(|| failure(TopUpErrorCode::RelinkRequired))?;
        let certificate = self
            .configuration
            .identity_certificate
            .as_deref()
            .ok_or_else(|| failure(TopUpErrorCode::RelinkRequired))?;
        self.source
            .top_up_context(identity, certificate)
            .map_err(|_| failure(TopUpErrorCode::RelinkRequired))?;
        let identity_digest = self
            .identity_digest
            .ok_or_else(|| failure(TopUpErrorCode::RelinkRequired))?;
        let mut operation = [0; 16];
        operation[..8].copy_from_slice(&snapshot.next.to_be_bytes());
        SystemRandom::new()
            .fill(&mut operation[8..])
            .map_err(|_| failure(TopUpErrorCode::SourceUnavailable))?;
        let now = self
            .root
            .sample()
            .map_err(|_| failure(TopUpErrorCode::SourceUnavailable))?;
        let deadline = now
            .lower_ms
            .checked_add(self.configuration.operation_lifetime.as_millis() as u64)
            .filter(|deadline| *deadline > now.upper_ms)
            .ok_or_else(|| failure(TopUpErrorCode::DeadlineExceeded))?;
        let facts = TopUpIntent {
            tenant_id: self.configuration.tenant_id.clone(),
            source_incarnation: self.configuration.source_incarnation,
            operation_id: operation,
            request_digest: [0; 32],
            client_identity_digest: identity_digest,
            pool_digest: self.configuration.pool_digest,
            binding_generation: self.configuration.binding_generation,
            request_deadline_ms: deadline,
            options,
        };
        // An empty proof is never sent. Persist the canonical stable intent
        // projection first; the proof is separately renewed by the authority.
        let request = encode_intent(&facts, None);
        let digest = raw_digest(&request);
        let record = JournalRecord {
            operation,
            request,
            digest,
            identity: identity_digest,
            created_generation: self.configuration.binding_generation,
            generation: 0,
            state: 1,
            response: None,
            applied_entries: None,
            terminal: None,
        };
        stored(self.store.top_up_begin(
            &facts.tenant_id,
            &facts.source_incarnation,
            self.configuration.binding_generation,
            &record,
        ))?;
        self.view(&record)
    }
    fn view(self: &Arc<Self>, record: &JournalRecord) -> Result<TopUpHandle> {
        let mut current = self.current.lock().expect("original TopUp observation");
        if let Some(handle) = current
            .as_ref()
            .filter(|handle| handle.0.operation == record.operation)
        {
            update(handle, record)?;
            return Ok(handle.clone());
        }
        let facts = intent(&record.request)?;
        let handle = TopUpHandle(Arc::new(Observation {
            source: Arc::downgrade(self),
            operation: record.operation,
            options: facts.options,
            state: Mutex::new((TopUpState::Pending, None)),
            workers: AtomicUsize::new(0),
            changed: Notify::new(),
        }));
        update(&handle, record)?;
        *current = Some(handle.clone());
        Ok(handle)
    }
    fn refresh_view(&self, handle: &TopUpHandle) -> Result<()> {
        let snapshot = self.journal()?;
        if let Some(record) = snapshot
            .record
            .filter(|record| record.operation == handle.0.operation)
        {
            update(handle, &record)?;
        }
        // A closed observation remains immutable after the next intent replaces
        // the single retained terminal record. It does not reconstruct an owner.
        Ok(())
    }
    pub(crate) fn consume_material(
        &self,
        artifact: &[u8; 32],
    ) -> std::result::Result<(), crate::PoolStoreError> {
        if self.stop.is_cancelled() || self.root.is_closed() {
            return Err(crate::PoolStoreError {
                code: crate::PoolStoreFailure::Closed,
                write_state: crate::PoolWriteState::NotSubmitted,
                format: None,
            });
        }
        // Acquisition needs the original write state to distinguish a busy
        // transaction from an unknown durable removal. Do not flatten it here.
        self.store.top_up_consume(
            &self.configuration.tenant_id,
            &self.configuration.source_incarnation,
            self.configuration.binding_generation,
            artifact,
        )
    }
    fn verify_fence(&self, facts: &TopUpIntent, bytes: &[u8]) -> Result<()> {
        let proof = parsed(codec::decode(
            bytes,
            "OwnerFenceProof",
            Limits {
                bytes: 512,
                nodes: 64,
            },
            None,
        ))?;
        let mut message = Vec::with_capacity(1024);
        parsed(codec::verify_signature(
            "OwnerFenceProof",
            proof,
            &self.configuration.fence_authority_public_key,
            &mut message,
        ))?;
        let now = self
            .root
            .sample()
            .map_err(|_| failure(TopUpErrorCode::SourceUnavailable))?;
        if parsed(
            proof
                .field("OwnerFenceProof", "tenant_id")
                .and_then(Value::text),
        )? != facts.tenant_id
            || parsed(proof.b::<16>("OwnerFenceProof", "source_incarnation"))?
                != facts.source_incarnation
            || parsed(proof.b::<16>("OwnerFenceProof", "operation_id"))? != facts.operation_id
            || parsed(proof.b::<32>("OwnerFenceProof", "request_digest"))? != facts.request_digest
            || parsed(proof.b::<16>("OwnerFenceProof", "authority_key_id"))?
                != self.configuration.fence_authority_key_id
            || parsed(proof.u("OwnerFenceProof", "current_generation"))?
                != self.configuration.binding_generation
            || parsed(proof.u("OwnerFenceProof", "issued_at_ms"))? > now.lower_ms
            || parsed(proof.u("OwnerFenceProof", "expires_at_ms"))? <= now.upper_ms
        {
            return Err(failure(TopUpErrorCode::PermissionDenied));
        }
        Ok(())
    }
    fn commit_fence(
        &self,
        facts: &TopUpIntent,
        proof: &[u8],
    ) -> std::result::Result<(), crate::PoolStoreError> {
        // Installation already holds the source gate. Source Close cancels
        // this original owner before entering that gate, so do not relock it.
        let result = if self.stop.is_cancelled() || self.root.is_closed() {
            Err(failure(TopUpErrorCode::SourceUnavailable))
        } else {
            self.verify_fence(facts, proof)
        };
        result.map_err(|_| crate::PoolStoreError {
            code: crate::PoolStoreFailure::Fenced,
            write_state: crate::PoolWriteState::NotSubmitted,
            format: None,
        })
    }
    async fn process(self: &Arc<Self>, view: &TopUpHandle) -> Result<()> {
        self.check()?;
        let snapshot = self.journal()?;
        let record = snapshot
            .record
            .ok_or_else(|| failure(TopUpErrorCode::SourceStateUnknown))?;
        let mut facts = intent(&record.request)?;
        // The request projection intentionally omits binding generation. A
        // zero journal generation means this operation has not yet recorded
        // the authority's original accepted submission generation. Takeover
        // advances only the local owner fence; a verified response binds it.
        facts.binding_generation = record.generation;
        facts.request_digest = record.digest;
        if record.state >= 3 {
            return Ok(());
        }
        if record.state == 1 && self.identity_digest != Some(record.identity) {
            return Err(failure(TopUpErrorCode::RelinkRequired));
        }
        let call_until = Instant::now() + self.configuration.call_timeout;
        let call_cancel = self.stop.child_token();
        let io_cancel = call_cancel.clone();
        let owner = self.clone();
        let mut io = Box::pin(async move {
            let proof = owner
                .configuration
                .proof_provider
                .owner_fence_proof(&facts, owner.configuration.binding_generation, &io_cancel)
                .await?;
            owner.check()?;
            owner.verify_fence(&facts, &proof)?;
            stored(owner.store.top_up_takeover(
                &facts.tenant_id,
                &facts.source_incarnation,
                owner.configuration.binding_generation,
                &facts.operation_id,
                &record.digest,
                || owner.commit_fence(&facts, &proof),
            ))?;
            let applied = if record.state == 2 {
                let applied = applied_facts(
                    record
                        .response
                        .as_deref()
                        .ok_or_else(|| failure(TopUpErrorCode::SourceStateUnknown))?,
                    &facts,
                )?;
                verify_applied_entries(
                    record
                        .applied_entries
                        .as_deref()
                        .ok_or_else(|| failure(TopUpErrorCode::SourceStateUnknown))?,
                    &facts,
                    &applied,
                    owner.journal()?.frontier,
                )?;
                applied
            } else {
                let mut sending = facts.clone();
                sending.binding_generation = owner.configuration.binding_generation;
                let wire = Zeroizing::new(encode_intent(&sending, Some(&proof)));
                parsed(codec::decode(
                    &wire,
                    "TopUpRequest",
                    Limits {
                        bytes: 524288,
                        nodes: 256,
                    },
                    None,
                ))?;
                let (response, _replay) = {
                    let exchange = owner
                        .configuration
                        .control
                        .exchange(41006, &wire, &io_cancel)
                        .await?;
                    match exchange {
                        TopUpExchangeResult::Response {
                            canonical_response,
                            replay,
                        } => (canonical_response, replay),
                        TopUpExchangeResult::Terminal(error) if error.0.permits_terminal() => {
                            stored(owner.store.top_up_finish(
                                &facts.tenant_id,
                                &facts.source_incarnation,
                                owner.configuration.binding_generation,
                                &facts.operation_id,
                                &record.digest,
                                Some(error.0.as_str()),
                                || owner.commit_fence(&facts, &proof),
                            ))?;
                            return Ok(());
                        }
                        TopUpExchangeResult::Terminal(error) => return Err(error),
                        _ => return Err(failure(TopUpErrorCode::SourceContractInvalid)),
                    }
                };
                let response = Zeroizing::new(response);
                let mut batch = response_facts(&response, &facts)?;
                if batch.generation == 0
                    || (record.generation == 0
                        && (batch.generation < record.created_generation
                            || batch.generation > owner.configuration.binding_generation))
                    || (record.generation != 0 && batch.generation != record.generation)
                {
                    return Err(failure(TopUpErrorCode::StaleGeneration));
                }
                let frontier = owner.journal()?.frontier;
                let first = batch
                    .entries
                    .first()
                    .ok_or_else(|| failure(TopUpErrorCode::SourceContractInvalid))?
                    .sequence;
                if first
                    != frontier
                        .checked_add(1)
                        .ok_or_else(|| failure(TopUpErrorCode::SequenceGap))?
                    && !(batch.applied.retired.is_some_and(|retired| {
                        retired >= frontier && retired.checked_add(1) == Some(first)
                    }) && batch.applied.highest
                        == batch.entries.last().expect("nonempty batch").sequence)
                {
                    return Err(failure(TopUpErrorCode::SequenceGap));
                }
                // Keep the verified authority generation separate from the
                // current local owner fence. top_up_install persists both in
                // the same transaction as Applied material and the response.
                facts.binding_generation = batch.generation;
                let identity = owner
                    .configuration
                    .identity
                    .as_ref()
                    .ok_or_else(|| failure(TopUpErrorCode::RelinkRequired))?;
                let certificate = owner
                    .configuration
                    .identity_certificate
                    .as_deref()
                    .ok_or_else(|| failure(TopUpErrorCode::RelinkRequired))?;
                let applied_wire = encode_ack_fields(&facts, &batch.applied, None);
                let original_generation = batch.generation;
                let response_digest = batch.applied.digest;
                let installed_frontier = batch
                    .entries
                    .last()
                    .expect("nonempty verified batch")
                    .sequence;
                owner.source.install_top_up_materials(
                    identity,
                    certificate,
                    &mut batch.entries,
                    owner.configuration.material_decoder.as_ref(),
                    &owner,
                    None,
                    |installed| {
                        owner.verify_fence(&facts, &proof)?;
                        stored(owner.store.top_up_install(
                            &facts.tenant_id,
                            &facts.source_incarnation,
                            owner.configuration.binding_generation,
                            &facts.operation_id,
                            &record.digest,
                            original_generation,
                            &applied_wire,
                            &encode_applied_entries(
                                installed,
                                original_generation,
                                &facts,
                                &response_digest,
                                frontier,
                            ),
                            installed_frontier,
                            installed,
                            || owner.commit_fence(&facts, &proof),
                        ))
                    },
                )?;
                if let Some(handle) = owner
                    .current
                    .lock()
                    .expect("TopUp installed observation")
                    .as_ref()
                {
                    owner.refresh_view(handle)?;
                }
                batch.applied
            };
            // The durable Applied summary contains no material. Ack recovery
            // checks the exact original intent plus current source proof only.
            owner.verify_fence(&facts, &proof)?;
            let ack = encode_ack_fields(
                &facts,
                &applied,
                Some((owner.configuration.binding_generation, &proof)),
            );
            parsed(codec::decode(
                &ack,
                "TopUpAck",
                Limits {
                    bytes: 524288,
                    nodes: 256,
                },
                None,
            ))?;
            match owner
                .configuration
                .control
                .exchange(41007, &ack, &io_cancel)
                .await?
            {
                TopUpExchangeResult::AckConfirmed => stored(owner.store.top_up_finish(
                    &facts.tenant_id,
                    &facts.source_incarnation,
                    owner.configuration.binding_generation,
                    &facts.operation_id,
                    &record.digest,
                    None,
                    || owner.commit_fence(&facts, &proof),
                )),
                TopUpExchangeResult::Terminal(error) if error.0.permits_terminal() => {
                    // Authenticated authority retirement closes the original
                    // operation while its durable Applied facts remain intact.
                    stored(owner.store.top_up_finish(
                        &facts.tenant_id,
                        &facts.source_incarnation,
                        owner.configuration.binding_generation,
                        &facts.operation_id,
                        &record.digest,
                        Some(error.0.as_str()),
                        || owner.commit_fence(&facts, &proof),
                    ))
                }
                TopUpExchangeResult::Terminal(error) => Err(error),
                _ => Err(failure(TopUpErrorCode::SourceContractInvalid)),
            }
        });
        tokio::select! {
            result = &mut io => result,
            _ = self.stop.cancelled() => {
                call_cancel.cancel();
                let Some(tail) = ProcessTail::try_new(self.clone(), view.clone()) else {
                    drop(io);
                    return Err(failure(TopUpErrorCode::CapacityExhausted));
                };
                tail.spawn(io);
                Err(failure(TopUpErrorCode::SourceUnavailable))
            },
            _ = tokio::time::sleep_until(call_until) => {
                call_cancel.cancel();
                let Some(tail) = ProcessTail::try_new(self.clone(), view.clone()) else {
                    drop(io);
                    return Err(failure(TopUpErrorCode::CapacityExhausted));
                };
                tail.spawn(io);
                Err(failure(TopUpErrorCode::DeadlineExceeded))
            },
        }
    }
}
fn update(handle: &TopUpHandle, record: &JournalRecord) -> Result<()> {
    let state = match record.state {
        1 => TopUpState::Pending,
        2 => TopUpState::Installed,
        3 => TopUpState::Acked,
        4 => TopUpState::Terminal,
        _ => return Err(failure(TopUpErrorCode::SourceStateUnknown)),
    };
    let outcome = if state == TopUpState::Acked {
        Some(TopUpOutcome::Success)
    } else if state == TopUpState::Terminal {
        Some(TopUpOutcome::Rejected(failure(
            record
                .terminal
                .as_deref()
                .and_then(TopUpErrorCode::from_str)
                .filter(|code| code.permits_terminal())
                .ok_or_else(|| failure(TopUpErrorCode::SourceStateUnknown))?,
        )))
    } else {
        None
    };
    if record.operation != handle.0.operation {
        return Err(failure(TopUpErrorCode::SourceStateUnknown));
    }
    let mut current = handle
        .0
        .state
        .lock()
        .expect("TopUp durable state projection");
    if current.0 == state {
        return if current.1 == outcome {
            Ok(())
        } else {
            Err(failure(TopUpErrorCode::SourceStateUnknown))
        };
    }
    // Journal reads can finish out of order. Merge under the observation gate
    // so older durable snapshots cannot undo an already observed transition.
    match (current.0, state) {
        (TopUpState::Pending, _) | (TopUpState::Installed, TopUpState::Acked) => {
            *current = (state, outcome);
            drop(current);
            handle.0.changed.notify_waiters();
            Ok(())
        }
        (TopUpState::Installed, TopUpState::Terminal)
            if outcome
                == Some(TopUpOutcome::Rejected(failure(
                    TopUpErrorCode::SourceResetRequired,
                )))
                && record.response.is_some()
                && record.applied_entries.is_some() =>
        {
            *current = (state, outcome);
            drop(current);
            handle.0.changed.notify_waiters();
            Ok(())
        }
        (TopUpState::Installed, TopUpState::Pending)
        | (TopUpState::Acked, TopUpState::Pending | TopUpState::Installed)
        | (TopUpState::Terminal, TopUpState::Pending) => Ok(()),
        (TopUpState::Terminal, TopUpState::Installed)
            if current.1
                == Some(TopUpOutcome::Rejected(failure(
                    TopUpErrorCode::SourceResetRequired,
                ))) =>
        {
            Ok(())
        }
        // Only source_reset_required can close an installed operation. Acked
        // and Terminal remain distinct immutable authoritative facts.
        _ => Err(failure(TopUpErrorCode::SourceStateUnknown)),
    }
}
fn map(fields: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    codec::encode_head(&mut out, 5, fields.len() as u64);
    for (id, value) in fields {
        codec::encode_head(&mut out, 0, *id);
        out.extend_from_slice(value);
    }
    out
}
fn uint(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    codec::encode_head(&mut out, 0, value);
    out
}
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    codec::encode_head(&mut out, 2, value.len() as u64);
    out.extend_from_slice(value);
    out
}
fn text(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    codec::encode_head(&mut out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}
fn raw_digest(bytes: &[u8]) -> [u8; 32] {
    // topup_request_digest/topup_response_digest are sha256-raw domains:
    // the input is already the canonical projection map, with no length
    // prefix or domain label.
    Sha256::digest(bytes).into()
}
fn certificate_digest(bytes: &[u8]) -> Result<[u8; 32]> {
    let certificate = parsed(codec::decode(
        bytes,
        "IdentityCertificate",
        Limits {
            bytes: 8192,
            nodes: 128,
        },
        None,
    ))?;
    parsed(codec::digest("certificate_digest", certificate))
}
fn encode_intent(facts: &TopUpIntent, proof: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![
        (0, bytes(&facts.operation_id)),
        (1, text(&facts.tenant_id)),
        (2, bytes(&facts.source_incarnation)),
        (3, uint(u64::from(facts.options.desired_count))),
        (4, uint(u64::from(facts.options.max_item_bytes))),
        (5, bytes(&facts.pool_digest)),
    ];
    if let Some(proof) = proof {
        fields.extend([(6, uint(facts.binding_generation)), (7, bytes(proof))]);
    }
    fields.extend([
        (8, uint(facts.request_deadline_ms)),
        (9, bytes(&facts.client_identity_digest)),
    ]);
    map(&fields)
}
pub(crate) fn intent(wire: &[u8]) -> Result<TopUpIntent> {
    // Stored intent is the exact digest projection with proof/generation omitted.
    let value = parsed(codec::decode_shape_projection(
        wire,
        "TopUpRequest",
        &[6, 7],
        Limits {
            bytes: 524288,
            nodes: 256,
        },
    ))?;
    let mut facts = TopUpIntent {
        tenant_id: parsed(
            value
                .field("TopUpRequest", "tenant_id")
                .and_then(Value::text),
        )?
        .to_owned(),
        source_incarnation: parsed(value.b::<16>("TopUpRequest", "source_incarnation"))?,
        operation_id: parsed(value.b::<16>("TopUpRequest", "operation_id"))?,
        request_digest: [0; 32],
        client_identity_digest: parsed(value.b::<32>("TopUpRequest", "client_identity_digest"))?,
        pool_digest: parsed(value.b::<32>("TopUpRequest", "pool_digest"))?,
        binding_generation: 0,
        request_deadline_ms: parsed(value.u("TopUpRequest", "request_deadline_ms"))?,
        options: TopUpOptions {
            desired_count: parsed(value.u("TopUpRequest", "desired_count"))? as u16,
            max_item_bytes: parsed(value.u("TopUpRequest", "max_item_bytes"))? as u32,
        },
    };
    facts.request_digest = raw_digest(&encode_intent(&facts, None));
    Ok(facts)
}
struct AppliedFacts {
    digest: [u8; 32],
    highest: u64,
    retired: Option<u64>,
}
struct ResponseFacts {
    applied: AppliedFacts,
    generation: u64,
    entries: Vec<InstalledMaterial>,
}
fn response_facts(wire: &[u8], facts: &TopUpIntent) -> Result<ResponseFacts> {
    let value = parsed(codec::decode(
        wire,
        "TopUpResponse",
        Limits {
            bytes: 524288,
            nodes: 256,
        },
        None,
    ))?;
    if parsed(value.b::<16>("TopUpResponse", "operation_id"))? != facts.operation_id
        || parsed(value.b::<16>("TopUpResponse", "source_incarnation"))? != facts.source_incarnation
        || parsed(
            value
                .field("TopUpResponse", "tenant_id")
                .and_then(Value::text),
        )? != facts.tenant_id
    {
        return Err(failure(TopUpErrorCode::OperationConflict));
    }
    let digest = parsed(value.b::<32>("TopUpResponse", "response_digest"))?;
    if digest != raw_digest(&projection(value, &[9])?) {
        return Err(failure(TopUpErrorCode::OperationConflict));
    }
    let generation = parsed(value.u("TopUpResponse", "binding_generation"))?;
    let children = parsed(
        value
            .field("TopUpResponse", "entries")
            .and_then(Value::children),
    )?;
    let mut entries = Vec::with_capacity(4);
    for child in children {
        let child = parsed(child)?;
        let encoded_material = parsed(child.field("TopUpEntry", "material"))?;
        let material = parsed(encoded_material.bytes())?;
        if material.len() > facts.options.max_item_bytes as usize
            || encoded_material.raw().len() > facts.options.max_item_bytes as usize
        {
            return Err(failure(TopUpErrorCode::ConfigurationCapacity));
        }
        if entries.len() >= facts.options.desired_count as usize
            || parsed(child.b::<32>("TopUpEntry", "client_identity_digest"))?
                != facts.client_identity_digest
            || parsed(child.u("TopUpEntry", "binding_generation"))? != generation
            || parsed(child.b::<32>("TopUpEntry", "material_digest"))?
                != <[u8; 32]>::from(Sha256::digest(material))
        {
            return Err(failure(TopUpErrorCode::OperationConflict));
        }
        let sequence = parsed(child.u("TopUpEntry", "artifact_sequence"))?;
        if sequence == 0
            || entries.last().is_some_and(|prior: &InstalledMaterial| {
                prior.sequence.checked_add(1) != Some(sequence)
            })
        {
            return Err(failure(TopUpErrorCode::SequenceGap));
        }
        entries.push(InstalledMaterial {
            sequence,
            expiry: parsed(child.u("TopUpEntry", "expiry_ms"))?,
            artifact: [0; 32],
            bytes: material.to_vec(),
        });
    }
    if entries.len() != usize::from(facts.options.desired_count) {
        return Err(failure(TopUpErrorCode::OperationConflict));
    }
    let highest = parsed(value.u("TopUpResponse", "server_highest_artifact_sequence"))?;
    if entries.last().is_some_and(|entry| entry.sequence > highest) {
        return Err(failure(TopUpErrorCode::SequenceGap));
    }
    let retired = parsed(value.optional("TopUpResponse", "retired_artifact_through"))?
        .map(Value::uint)
        .transpose()
        .map_err(|_| failure(TopUpErrorCode::SourceContractInvalid))?;
    Ok(ResponseFacts {
        applied: AppliedFacts {
            digest,
            highest,
            retired,
        },
        generation,
        entries,
    })
}
fn encode_applied_entries(
    entries: &[InstalledMaterial],
    generation: u64,
    intent: &TopUpIntent,
    response_digest: &[u8; 32],
    previous_frontier: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    codec::encode_head(&mut out, 4, 6);
    for value in [
        bytes(&intent.operation_id),
        bytes(&intent.source_incarnation),
        bytes(&intent.request_digest),
        bytes(response_digest),
        uint(previous_frontier),
    ] {
        out.extend_from_slice(&value);
    }
    codec::encode_head(&mut out, 4, entries.len() as u64);
    for entry in entries {
        codec::encode_head(&mut out, 4, 6);
        for value in [
            uint(entry.sequence),
            uint(generation),
            uint(entry.expiry),
            bytes(&Sha256::digest(&entry.bytes)),
            bytes(&intent.client_identity_digest),
            bytes(&entry.artifact),
        ] {
            out.extend_from_slice(&value);
        }
    }
    out
}
fn verify_applied_entries(
    wire: &[u8],
    intent: &TopUpIntent,
    applied: &AppliedFacts,
    frontier: u64,
) -> Result<()> {
    let history = parsed(codec::decode_control_array(
        wire,
        Limits {
            bytes: 1024,
            nodes: 64,
        },
    ))?;
    if parsed(history.len())? != 6
        || parsed(history.at(0).and_then(Value::bytes))? != intent.operation_id
        || parsed(history.at(1).and_then(Value::bytes))? != intent.source_incarnation
        || parsed(history.at(2).and_then(Value::bytes))? != intent.request_digest
        || parsed(history.at(3).and_then(Value::bytes))? != applied.digest
    {
        return Err(failure(TopUpErrorCode::SourceStateUnknown));
    }
    let previous_frontier = parsed(history.at(4).and_then(Value::uint))?;
    let entries = parsed(history.at(5))?;
    let count = parsed(entries.len())?;
    if count != usize::from(intent.options.desired_count) || count == 0 || count > 4 {
        return Err(failure(TopUpErrorCode::SourceStateUnknown));
    }
    let mut previous = None;
    let mut generation = None;
    for entry in parsed(entries.children())? {
        let entry = parsed(entry)?;
        if parsed(entry.len())? != 6 {
            return Err(failure(TopUpErrorCode::SourceStateUnknown));
        }
        let sequence = parsed(entry.at(0).and_then(Value::uint))?;
        let original_generation = parsed(entry.at(1).and_then(Value::uint))?;
        let expiry = parsed(entry.at(2).and_then(Value::uint))?;
        let digest = parsed(entry.at(3).and_then(Value::bytes))?;
        let identity = parsed(entry.at(4).and_then(Value::bytes))?;
        let artifact = parsed(entry.at(5).and_then(Value::bytes))?;
        if sequence == 0
            || sequence > frontier
            || sequence > applied.highest
            || original_generation == 0
            || expiry == 0
            || digest.len() != 32
            || identity != intent.client_identity_digest
            || artifact.len() != 32
            || previous.is_some_and(|prior: u64| prior.checked_add(1) != Some(sequence))
            || generation.is_some_and(|prior| prior != original_generation)
        {
            return Err(failure(TopUpErrorCode::SourceStateUnknown));
        }
        if previous.is_none()
            && previous_frontier.checked_add(1) != Some(sequence)
            && !applied.retired.is_some_and(|retired| {
                retired >= previous_frontier && retired.checked_add(1) == Some(sequence)
            })
        {
            return Err(failure(TopUpErrorCode::SourceStateUnknown));
        }
        previous = Some(sequence);
        generation = Some(original_generation);
    }
    if generation != Some(intent.binding_generation)
        || applied
            .retired
            .is_some_and(|retired| previous.is_none_or(|last| retired >= last))
    {
        return Err(failure(TopUpErrorCode::SourceStateUnknown));
    }
    Ok(())
}
pub(crate) fn validate_applied_record(
    record: &JournalRecord,
    tenant: &str,
    source: &[u8; 16],
    frontier: u64,
) -> Result<()> {
    let mut original = intent(&record.request)?;
    original.binding_generation = record.generation;
    if record.generation == 0
        || original.request_digest != record.digest
        || original.operation_id != record.operation
        || original.client_identity_digest != record.identity
        || original.tenant_id != tenant
        || original.source_incarnation != *source
    {
        return Err(failure(TopUpErrorCode::SourceStateUnknown));
    }
    let applied = applied_facts(
        record
            .response
            .as_deref()
            .ok_or_else(|| failure(TopUpErrorCode::SourceStateUnknown))?,
        &original,
    )?;
    verify_applied_entries(
        record
            .applied_entries
            .as_deref()
            .ok_or_else(|| failure(TopUpErrorCode::SourceStateUnknown))?,
        &original,
        &applied,
        frontier,
    )
}

fn applied_facts(wire: &[u8], intent: &TopUpIntent) -> Result<AppliedFacts> {
    let value = parsed(codec::decode_shape_projection(
        wire,
        "TopUpAck",
        &[8, 9],
        Limits {
            bytes: 1024,
            nodes: 64,
        },
    ))?;
    if parsed(value.b::<16>("TopUpAck", "operation_id"))? != intent.operation_id
        || parsed(value.b::<32>("TopUpAck", "pool_digest"))? != intent.pool_digest
        || parsed(value.b::<32>("TopUpAck", "request_digest"))? != intent.request_digest
    {
        return Err(failure(TopUpErrorCode::SourceStateUnknown));
    }
    let gap = parsed(
        value
            .field("TopUpAck", "gap_authorized")
            .and_then(Value::boolean),
    )?;
    let retired = parsed(value.optional("TopUpAck", "retired_artifact_through"))?
        .map(Value::uint)
        .transpose()
        .map_err(|_| failure(TopUpErrorCode::SourceStateUnknown))?;
    if gap != retired.is_some() {
        return Err(failure(TopUpErrorCode::SourceStateUnknown));
    }
    Ok(AppliedFacts {
        digest: parsed(value.b::<32>("TopUpAck", "response_digest"))?,
        highest: parsed(value.u("TopUpAck", "server_highest_artifact_sequence"))?,
        retired,
    })
}
fn projection(value: Value<'_>, excluded: &[u64]) -> Result<Vec<u8>> {
    let mut children = parsed(value.children())?;
    let mut fields = Vec::new();
    while let Some(key) = children.next() {
        let key = parsed(key.and_then(Value::uint))?;
        let value = parsed(children.next().ok_or("truncated").and_then(|value| value))?;
        if !excluded.contains(&key) {
            fields.push((key, value.raw().to_vec()));
        }
    }
    Ok(map(&fields))
}
fn encode_ack_fields(
    intent: &TopUpIntent,
    response: &AppliedFacts,
    proof: Option<(u64, &[u8])>,
) -> Vec<u8> {
    let mut fields = vec![
        (0, bytes(&intent.operation_id)),
        (1, bytes(&intent.pool_digest)),
        (2, bytes(&response.digest)),
        (3, uint(response.highest)),
        (
            4,
            vec![if response.retired.is_some() {
                0xf5
            } else {
                0xf4
            }],
        ),
    ];
    if let Some(retired) = response.retired {
        fields.push((5, uint(retired)));
    }
    fields.extend([(6, vec![0xf5]), (7, bytes(&intent.request_digest))]);
    if let Some((generation, proof)) = proof {
        fields.extend([(8, uint(generation)), (9, bytes(proof))]);
    }
    map(&fields)
}

/// Redeven's two independent transient application methods. These calls never
/// synthesize a business execution operation ID or retry a business request.
#[derive(Clone, Debug)]
pub struct RedevenPoolControl {
    client: crate::ServiceClient,
    top_up: crate::MethodDefinition,
    ack: crate::MethodDefinition,
    reply_decoder: Arc<dyn TopUpControlReplyDecoder>,
    timeout: Duration,
}
/// The application's fixed response/error contract distinguishes an Ack
/// confirmation from an authoritative operation terminal. Local I/O failure
/// must never be returned as authoritative terminal evidence.
pub trait TopUpControlReplyDecoder: fmt::Debug + Send + Sync + 'static {
    fn decode(
        &self,
        method: u32,
        application_error_code: Option<u32>,
        payload: &[u8],
    ) -> Result<TopUpExchangeResult>;
}
impl RedevenPoolControl {
    pub fn new(
        client: crate::ServiceClient,
        top_up: crate::MethodDefinition,
        ack: crate::MethodDefinition,
        reply_decoder: Arc<dyn TopUpControlReplyDecoder>,
        timeout: Duration,
    ) -> Result<Self> {
        if top_up.type_id() != 41006
            || ack.type_id() != 41007
            || [top_up.clone(), ack.clone()].iter().any(|method| {
                method.semantics() != crate::ServiceSemantics::Transient
                    || method.shape() != crate::ServiceShape::Unary
                    || method.options().response.is_none()
            })
            || !(Duration::from_millis(1)..=Duration::from_secs(120)).contains(&timeout)
        {
            return Err(failure(TopUpErrorCode::SourceContractInvalid));
        }
        Ok(Self {
            client,
            top_up,
            ack,
            reply_decoder,
            timeout,
        })
    }
}
#[async_trait]
impl TopUpControlTransport for RedevenPoolControl {
    async fn exchange(
        &self,
        method: u32,
        canonical_request: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<TopUpExchangeResult> {
        let definition = match method {
            41006 => &self.top_up,
            41007 => &self.ack,
            _ => return Err(failure(TopUpErrorCode::SourceContractInvalid)),
        };
        let options = definition.options();
        let request_codec = Arc::new(crate::BytesMessageCodec::new(options.request.clone()));
        let response_codec = Arc::new(crate::BytesMessageCodec::new(
            options
                .response
                .clone()
                .ok_or_else(|| failure(TopUpErrorCode::SourceContractInvalid))?,
        ));
        let operation = self
            .client
            .prepare_unary(
                definition,
                &canonical_request.to_vec(),
                request_codec,
                response_codec,
                crate::UnaryPrepareOptions {
                    timeout: self.timeout,
                    response_limit_bytes: Some(options.max_response_bytes),
                    ..Default::default()
                },
            )
            .map_err(|_| failure(TopUpErrorCode::SourceUnavailable))?;
        if operation.start().is_err() {
            operation.close();
            // The public operation observation is bounded, but the original
            // TopUp worker remains responsible for the real unary tail until
            // the request/response/callback owners have actually exited.
            operation.wait_physical_cleanup().await;
            return Err(failure(TopUpErrorCode::SourceUnavailable));
        }
        let result = operation.wait_typed(cancellation.clone()).await;
        // The result waiter owns only the decoded result custody. Close the
        // actual operation before observing its physical cleanup tail on both
        // success and failure.
        operation.close();
        // Keep the source-owned worker and its handle observation active until
        // the actual unary tail exits. The outer TopUp process owns the bounded
        // caller deadline and can detach this wait into ProcessTail.
        operation.wait_physical_cleanup().await;
        let result = match result {
            Err(error) => {
                // Preserve cancellation/deadline semantics from the caller's
                // wait even when the bounded cleanup observation is incomplete.
                return Err(failure(match error.0 {
                    crate::ServiceFailure::Canceled => TopUpErrorCode::Canceled,
                    crate::ServiceFailure::DeadlineExceeded => TopUpErrorCode::DeadlineExceeded,
                    _ => TopUpErrorCode::SourceUnavailable,
                }));
            }
            Ok(result) => result,
        };
        match result.value {
            crate::TypedUnaryValue::Response(bytes) => {
                self.reply_decoder.decode(method, None, &bytes)
            }
            crate::TypedUnaryValue::ApplicationError { code, payload }
            | crate::TypedUnaryValue::UnknownApplicationError {
                code,
                raw_payload: payload,
            } => self.reply_decoder.decode(method, Some(code), &payload),
            _ => Err(failure(TopUpErrorCode::SourceContractInvalid)),
        }
    }
}

#[cfg(test)]
pub(crate) fn applied_record_fixture(tenant: &str, source: [u8; 16]) -> JournalRecord {
    let mut operation = [42; 16];
    operation[..8].copy_from_slice(&1u64.to_be_bytes());
    let mut original = TopUpIntent {
        tenant_id: tenant.to_owned(),
        source_incarnation: source,
        operation_id: operation,
        request_digest: [0; 32],
        client_identity_digest: [44; 32],
        pool_digest: [46; 32],
        binding_generation: 1,
        request_deadline_ms: 3000,
        options: TopUpOptions {
            desired_count: 1,
            max_item_bytes: 65536,
        },
    };
    let request = encode_intent(&original, None);
    original.request_digest = raw_digest(&request);
    let applied = AppliedFacts {
        digest: [47; 32],
        highest: 1,
        retired: None,
    };
    let materials = [InstalledMaterial {
        sequence: 1,
        expiry: 2000,
        artifact: [45; 32],
        bytes: b"original material".to_vec(),
    }];
    JournalRecord {
        operation,
        request,
        digest: original.request_digest,
        identity: original.client_identity_digest,
        created_generation: original.binding_generation,
        generation: original.binding_generation,
        state: 2,
        response: Some(encode_ack_fields(&original, &applied, None)),
        applied_entries: Some(encode_applied_entries(
            &materials,
            1,
            &original,
            &applied.digest,
            0,
        )),
        terminal: None,
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;

    #[derive(Debug)]
    struct UnusedTopUpAdapters;
    #[async_trait]
    impl TopUpFenceProvider for UnusedTopUpAdapters {
        async fn owner_fence_proof(
            &self,
            _: &TopUpIntent,
            _: u64,
            _: &CancellationToken,
        ) -> Result<Vec<u8>> {
            panic!("the detached-tail regression must not invoke a proof provider");
        }
    }
    #[async_trait]
    impl TopUpControlTransport for UnusedTopUpAdapters {
        async fn exchange(
            &self,
            _: u32,
            _: &[u8],
            _: &CancellationToken,
        ) -> Result<TopUpExchangeResult> {
            panic!("the detached-tail regression must not submit another control operation");
        }
    }
    impl TopUpMaterialDecoder for UnusedTopUpAdapters {
        fn decode(&self, _: &[u8]) -> Result<PoolCredentialBytes> {
            panic!("the detached-tail regression must not decode another material batch");
        }
    }

    fn detached_fixture() -> (
        crate::namespace_v4::verifier::credential::tests::Fixture,
        crate::pool_v4::tests::StoreFixture,
        PreauthorizedPoolSource,
        JournalRecord,
        TopUpHandle,
    ) {
        let profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
        let environment = crate::namespace_v4::verifier::credential::tests::Fixture::with_identity(
            codec::ActivationSource::PreauthorizedPool,
            profile,
            None,
        );
        let store = crate::pool_v4::tests::StoreFixture::new(&environment);
        let tenant = store.options.bindings[0].tenant.clone();
        let incarnation = [41; 16];
        let original = crate::pool_v4::top_up::terminal_tests::seed_installed(
            &store.store,
            &tenant,
            &incarnation,
        );
        let identity = environment
            .environment
            .import_identity_keys(profile, [14; 32], [16; 32])
            .unwrap();
        // Recovery of Applied facts does not need the old identity certificate
        // or unused credentials. The direct durable fixture isolates the
        // detached control tail and its original observation from carrier IO.
        let source = crate::LocalDirectMaterialSource::preauthorized_pool(
            &environment.environment,
            crate::PreauthorizedPoolSourceConfiguration {
                namespaces: Vec::new(),
                identity: identity.clone(),
                credentials: Vec::new(),
                spend_ledger: store.store.clone(),
                provider: crate::WssConnectOptions {
                    binding_mode: crate::BindingMode::DirectExporter,
                    remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                    origin: None,
                    ca_certificates_der: Vec::new(),
                    timeout: Duration::from_secs(1),
                    publication_timeout: Duration::from_secs(1),
                    queue_messages: 1,
                    prepare_bytes: 65536,
                    native_runtime_bytes: 1 << 20,
                },
                application_profile: crate::ApplicationProfile::Transport,
            },
        )
        .unwrap();
        let pool = PreauthorizedPoolSource::new(
            source,
            PoolTopUpConfiguration {
                tenant_id: tenant,
                source_incarnation: incarnation,
                binding_generation: 1,
                pool_digest: [46; 32],
                identity: Some(identity),
                identity_certificate: Some(environment.client.clone()),
                fence_authority_key_id: [1; 16],
                fence_authority_public_key: [2; 32],
                operation_lifetime: Duration::from_secs(1),
                call_timeout: Duration::from_millis(1),
                proof_provider: Arc::new(UnusedTopUpAdapters),
                control: Arc::new(UnusedTopUpAdapters),
                material_decoder: Arc::new(UnusedTopUpAdapters),
            },
        )
        .unwrap();
        let handle = pool.0.view(&original).unwrap();
        (environment, store, pool, original, handle)
    }

    async fn wait_tail(pool: &PreauthorizedPoolSource) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = pool.0.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if !pool.0.process_tail_busy.load(Ordering::Acquire) {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("the physical tail must retire its finite slot");
    }

    fn finish_original(owner: &TopUpOwner, original: &JournalRecord) {
        owner
            .store
            .top_up_finish(
                &owner.configuration.tenant_id,
                &owner.configuration.source_incarnation,
                owner.configuration.binding_generation,
                &original.operation,
                &original.digest,
                None,
                || Ok(()),
            )
            .unwrap();
    }

    fn replace_terminal_journal(owner: &TopUpOwner, original: &JournalRecord) -> JournalRecord {
        let mut facts = intent(&original.request).unwrap();
        facts.operation_id[..8].copy_from_slice(&owner.journal().unwrap().next.to_be_bytes());
        let request = encode_intent(&facts, None);
        let mut next = original.clone();
        next.operation = facts.operation_id;
        next.digest = raw_digest(&request);
        next.request = request;
        next.generation = 0;
        next.state = 1;
        next.response = None;
        next.applied_entries = None;
        next.terminal = None;
        owner
            .store
            .top_up_begin(
                &owner.configuration.tenant_id,
                &owner.configuration.source_incarnation,
                owner.configuration.binding_generation,
                &next,
            )
            .unwrap();
        next
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detached_late_ack_is_projected_before_next_journal_replaces_original() {
        let (_environment, _store, pool, original, handle) = detached_fixture();
        let tail = ProcessTail::try_new(pool.0.clone(), handle.clone()).unwrap();
        let owner = pool.0.clone();
        let late = original.clone();
        let (acked, ack_observer) = tokio::sync::oneshot::channel();
        let (cleanup, physical_exit) = tokio::sync::oneshot::channel();
        tail.spawn(async move {
            // The Ack is already durable while the original physical cleanup
            // is still occupied. No observation may start the next intent yet.
            finish_original(&owner, &late);
            acked.send(()).unwrap();
            physical_exit.await.unwrap();
            Ok(())
        });
        ack_observer.await.unwrap();
        assert_eq!(observed(&handle, None).state, Some(TopUpState::Installed));
        assert!(!handle.cleanup_status().complete);
        let refused = pool
            .top_up(TopUpOptions::default(), &CancellationToken::new())
            .await;
        assert_eq!(
            refused.call_error,
            Some(failure(TopUpErrorCode::CapacityExhausted))
        );
        cleanup.send(()).unwrap();
        wait_tail(&pool).await;
        assert!(handle.cleanup_status().complete);
        assert_eq!(pool.0.workers.load(Ordering::Acquire), 0);
        assert_eq!(observed(&handle, None).outcome, Some(TopUpOutcome::Success));
        let next = replace_terminal_journal(&pool.0, &original);
        assert_ne!(next.operation, original.operation);
        assert_eq!(
            pool.0.journal().unwrap().record.unwrap().operation,
            next.operation
        );
        let status = pool.top_up_status(&handle, &CancellationToken::new());
        assert_eq!(status.state, Some(TopUpState::Acked));
        assert_eq!(status.outcome, Some(TopUpOutcome::Success));
        assert!(status.handle.is_none());
        pool.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detached_io_panic_still_projects_committed_ack_before_slot_release() {
        let (_environment, _store, pool, original, handle) = detached_fixture();
        let tail = ProcessTail::try_new(pool.0.clone(), handle.clone()).unwrap();
        let owner = pool.0.clone();
        let late = original.clone();
        tail.spawn(async move {
            finish_original(&owner, &late);
            panic!("provider panic after the original Ack commit");
        });
        wait_tail(&pool).await;
        replace_terminal_journal(&pool.0, &original);
        let status = pool.top_up_status(&handle, &CancellationToken::new());
        assert_eq!(status.state, Some(TopUpState::Acked));
        assert_eq!(status.outcome, Some(TopUpOutcome::Success));
        assert!(handle.cleanup_status().complete);
        pool.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transient_detached_refresh_keeps_owner_open_without_erasing_known_facts() {
        let (_environment, store, pool, original, handle) = detached_fixture();
        let tail = ProcessTail::try_new(pool.0.clone(), handle.clone()).unwrap();
        let owner = pool.0.clone();
        let inaccessible = store.store.clone();
        tail.spawn(async move {
            finish_original(&owner, &original);
            // Losing journal access cannot authorize replacement of an intent
            // whose final durable facts have not reached the original view.
            inaccessible.close();
            Ok(())
        });
        wait_tail(&pool).await;
        assert!(!pool.0.stop.is_cancelled());
        assert!(handle.cleanup_status().complete);
        assert_eq!(pool.0.workers.load(Ordering::Acquire), 0);
        let status = pool.top_up_status(&handle, &CancellationToken::new());
        assert_eq!(status.state, Some(TopUpState::Installed));
        assert_eq!(status.outcome, None);
        assert_eq!(
            status.call_error,
            Some(failure(TopUpErrorCode::SourceUnavailable))
        );
        let refused = pool
            .top_up(TopUpOptions::default(), &CancellationToken::new())
            .await;
        assert_eq!(
            refused.call_error,
            Some(failure(TopUpErrorCode::SourceUnavailable))
        );
        assert!(
            !pool.0.stop.is_cancelled(),
            "transient storage failure must not seal the owner"
        );
        pool.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recovered_transient_refresh_projects_terminal_before_new_intent() {
        let (_environment, store, pool, original, handle) = detached_fixture();
        let tail = ProcessTail::try_new(pool.0.clone(), handle.clone()).unwrap();
        let owner = pool.0.clone();
        let continuity = store.proof.clone();
        let outage = continuity.clone();
        let late = original.clone();
        tail.spawn(async move {
            finish_original(&owner, &late);
            // The durable Ack is committed, but the detached refresh sees a
            // temporary storage outage. Its owner must remain open for a later
            // retry instead of allowing a new intent to erase this journal.
            outage.set_unavailable(true);
            Ok(())
        });
        wait_tail(&pool).await;
        assert!(!pool.0.stop.is_cancelled());
        assert_eq!(observed(&handle, None).state, Some(TopUpState::Installed));

        continuity.set_unavailable(false);
        let next = pool.0.begin(TopUpOptions::default()).unwrap();
        assert_ne!(next.0.operation, original.operation);
        assert_eq!(observed(&handle, None).state, Some(TopUpState::Acked));
        assert_eq!(observed(&handle, None).outcome, Some(TopUpOutcome::Success));
        assert_eq!(observed(&next, None).state, Some(TopUpState::Pending));
        pool.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panicking_detached_refresh_seals_owner_before_slot_release() {
        let (_environment, _store, pool, original, handle) = detached_fixture();
        // Poison only this observation gate, leaving the durable journal and
        // store cleanup intact. A failed projection must not free the owner
        // to replace a confirmed Ack with a new intent.
        let poison = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _gate = handle.0.state.lock().unwrap();
            panic!("original observation gate failure");
        }));
        assert!(poison.is_err());
        let tail = ProcessTail::try_new(pool.0.clone(), handle.clone()).unwrap();
        let owner = pool.0.clone();
        tail.spawn(async move {
            finish_original(&owner, &original);
            Ok(())
        });
        wait_tail(&pool).await;
        assert!(pool.0.stop.is_cancelled());
        assert!(handle.cleanup_status().complete);
        assert_eq!(pool.0.workers.load(Ordering::Acquire), 0);
        // Inspect the untouched last-known facts only after confirming that
        // production admission was sealed; poison repair is test-local.
        handle.0.state.clear_poison();
        let status = pool.top_up_status(&handle, &CancellationToken::new());
        assert_eq!(status.state, Some(TopUpState::Installed));
        assert_eq!(status.outcome, None);
        assert_eq!(
            status.call_error,
            Some(failure(TopUpErrorCode::SourceUnavailable))
        );
        let refused = pool
            .top_up(TopUpOptions::default(), &CancellationToken::new())
            .await;
        assert_eq!(
            refused.call_error,
            Some(failure(TopUpErrorCode::SourceUnavailable))
        );
        pool.close();
    }

    #[test]
    fn transient_source_unavailable_does_not_seal_owner_refresh_tail() {
        assert!(!refresh_requires_owner_close(Err(failure(
            TopUpErrorCode::SourceUnavailable
        ))));
        assert!(refresh_requires_owner_close(Err(failure(
            TopUpErrorCode::SourceStateUnknown
        ))));
        assert!(refresh_requires_owner_close(Err(failure(
            TopUpErrorCode::StaleGeneration
        ))));
        assert!(!refresh_requires_owner_close(Ok(())));
    }

    fn handle() -> TopUpHandle {
        TopUpHandle(Arc::new(Observation {
            source: Weak::new(),
            operation: [1; 16],
            options: TopUpOptions::default(),
            state: Mutex::new((TopUpState::Pending, None)),
            workers: AtomicUsize::new(0),
            changed: Notify::new(),
        }))
    }

    fn record(state: u8, terminal: Option<TopUpErrorCode>) -> JournalRecord {
        // Only the immutable operation and projected state participate in this
        // race; authenticated journal loading is exercised by store tests.
        JournalRecord {
            operation: [1; 16],
            request: Vec::new(),
            digest: [2; 32],
            identity: [3; 32],
            created_generation: 1,
            generation: 1,
            state,
            response: None,
            applied_entries: None,
            terminal: terminal.map(|code| code.as_str().to_owned()),
        }
    }

    #[test]
    fn pending_read_before_ack_cannot_restore_pending_after_ack() {
        let handle = handle();
        let pending_snapshot = record(1, None);
        update(&handle, &record(3, None)).unwrap();
        update(&handle, &pending_snapshot).unwrap();

        let result = observed(&handle, None);
        assert_eq!(result.state, Some(TopUpState::Acked));
        assert_eq!(result.outcome, Some(TopUpOutcome::Success));
        assert!(result.handle.is_none());
    }

    #[test]
    fn pending_read_before_install_cannot_restore_pending_after_install() {
        let handle = handle();
        let pending_snapshot = record(1, None);
        update(&handle, &record(2, None)).unwrap();
        update(&handle, &pending_snapshot).unwrap();

        let result = observed(&handle, None);
        assert_eq!(result.state, Some(TopUpState::Installed));
        assert_eq!(result.outcome, None);
        assert!(result.handle.is_some());

        let installed_snapshot = record(2, None);
        update(&handle, &record(3, None)).unwrap();
        update(&handle, &installed_snapshot).unwrap();
        assert_eq!(observed(&handle, None).state, Some(TopUpState::Acked));
    }

    #[test]
    fn pending_read_before_terminal_cannot_clear_authoritative_rejection() {
        let handle = handle();
        let pending_snapshot = record(1, None);
        let terminal = record(4, Some(TopUpErrorCode::TopUpRequestExpired));
        update(&handle, &terminal).unwrap();
        update(&handle, &pending_snapshot).unwrap();
        update(&handle, &terminal).unwrap();

        let result = observed(&handle, None);
        assert_eq!(result.state, Some(TopUpState::Terminal));
        assert_eq!(
            result.outcome,
            Some(TopUpOutcome::Rejected(failure(
                TopUpErrorCode::TopUpRequestExpired
            )))
        );
        assert!(result.handle.is_none());
    }

    #[test]
    fn installed_authority_reset_preserves_applied_history_and_rejects_stale_reads() {
        let handle = handle();
        let mut installed = record(2, None);
        installed.response = Some(b"original response".to_vec());
        installed.applied_entries = Some(b"original Applied".to_vec());
        update(&handle, &installed).unwrap();
        let mut terminal = installed.clone();
        terminal.state = 4;
        terminal.terminal = Some(TopUpErrorCode::SourceResetRequired.as_str().to_owned());
        update(&handle, &terminal).unwrap();
        update(&handle, &installed).unwrap();
        update(&handle, &record(1, None)).unwrap();

        let result = observed(&handle, None);
        assert_eq!(result.state, Some(TopUpState::Terminal));
        assert_eq!(
            result.outcome,
            Some(TopUpOutcome::Rejected(failure(
                TopUpErrorCode::SourceResetRequired
            )))
        );
        assert!(result.handle.is_none());
        assert_eq!(terminal.response, installed.response);
        assert_eq!(terminal.applied_entries, installed.applied_entries);
        assert_eq!(
            update(&handle, &record(3, None)),
            Err(failure(TopUpErrorCode::SourceStateUnknown))
        );
    }

    #[test]
    fn installed_terminal_cannot_erase_original_applied_summary() {
        let handle = handle();
        update(&handle, &record(2, None)).unwrap();
        assert_eq!(
            update(
                &handle,
                &record(4, Some(TopUpErrorCode::SourceResetRequired))
            ),
            Err(failure(TopUpErrorCode::SourceStateUnknown))
        );
        assert_eq!(observed(&handle, None).state, Some(TopUpState::Installed));
    }

    #[test]
    fn source_call_errors_cannot_become_authoritative_terminal_snapshots() {
        for code in [
            TopUpErrorCode::SourceExhausted,
            TopUpErrorCode::SourceUnavailable,
            TopUpErrorCode::SourceContractInvalid,
            TopUpErrorCode::PermissionDenied,
            TopUpErrorCode::Canceled,
            TopUpErrorCode::DeadlineExceeded,
        ] {
            let handle = handle();
            update(&handle, &record(2, None)).unwrap();
            assert_eq!(
                update(&handle, &record(4, Some(code))),
                Err(failure(TopUpErrorCode::SourceStateUnknown))
            );
            assert_eq!(observed(&handle, None).state, Some(TopUpState::Installed));
        }
    }

    #[test]
    fn conflicting_authoritative_snapshots_preserve_the_observed_fact() {
        let terminal = record(4, Some(TopUpErrorCode::TopUpRequestExpired));
        let changed_terminal = record(4, Some(TopUpErrorCode::SourceResetRequired));
        let acked = record(3, None);
        let installed = record(2, None);
        for (original, conflict) in [
            (&terminal, &changed_terminal),
            (&terminal, &acked),
            (&terminal, &installed),
            (&acked, &terminal),
            (&installed, &terminal),
        ] {
            let handle = handle();
            update(&handle, original).unwrap();
            let before = observed(&handle, None);
            assert_eq!(
                update(&handle, conflict),
                Err(failure(TopUpErrorCode::SourceStateUnknown))
            );
            let after = observed(&handle, None);
            assert_eq!(after.state, before.state);
            assert_eq!(after.outcome, before.outcome);
        }
    }
}
