//! The Environment's continuous execution history. Only its original
//! admitted attempt can enter business work; duplicate attempts observe facts.
use crate::{
    api_v4::TransportEnvironment,
    environment_v4::{EnvironmentCharge, EnvironmentRoot, ResourceAccount, ResourceLimits},
    rpc_wire_v4::{self, ApplicationHeader},
    service_contract::{
        AdmissionOffer, ServiceContract, ServiceError, ServiceFailure, ServiceSemantics,
        ServiceShape,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
/// The original management request's store boundary. Atomic stream state is
/// safe to inspect while the trusted-time and history locks are held.
pub(crate) struct ObservationDeadline {
    pub(crate) upper_ms: u64,
    pub(crate) drain: Option<Instant>,
    pub(crate) stream: Arc<crate::crypto_v4::Stream>,
}
pub(crate) fn id(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:/@-".contains(b))
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionServiceOptions {
    pub tenant: String,
    pub audience: String,
    pub namespace: String,
    pub caller_authorities: Vec<[u8; 32]>,
    pub max_records: u32,
    pub max_active: u32,
    pub result_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionIdentity {
    pub authority: [u8; 32],
    pub subject: String,
    pub identity_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ExecutionState {
    Accepted,
    Executing,
    Completed,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionObservation {
    pub state: ExecutionState,
    pub cancel_requested: bool,
    pub dispatched: bool,
    pub work_active: bool,
    pub history_not_before_gc_ms: u64,
    pub result_not_after_ms: Option<u64>,
    pub result_available: bool,
    pub result_deleted: bool,
    pub result_bytes: u32,
    pub result_digest: [u8; 32],
    pub application_error_code: Option<u32>,
    pub error: Option<ServiceFailure>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionAbsence {
    NotRegistered,
    HistoryUnknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionCancelResult {
    Requested,
    Terminal,
    NotRegistered,
    HistoryUnknown,
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionManagementResult {
    pub observation: Option<ExecutionObservation>,
    pub absence: Option<ExecutionAbsence>,
    pub cancellation: Option<ExecutionCancelResult>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTarget {
    pub tenant: String,
    pub audience: String,
    pub namespace: String,
    pub caller_subject: String,
    pub caller_authority: [u8; 32],
    pub operation_id: [u8; 32],
    pub request_digest: [u8; 32],
    pub contract_digest: [u8; 32],
}
impl ExecutionTarget {
    pub(crate) fn validate(&self) -> Result<()> {
        if ![
            self.tenant.as_str(),
            self.audience.as_str(),
            self.namespace.as_str(),
            self.caller_subject.as_str(),
        ]
        .into_iter()
        .all(id)
            || self.caller_authority == [0; 32]
            || self.operation_id == [0; 32]
            || self.request_digest == [0; 32]
            || self.contract_digest == [0; 32]
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Key {
    pub(crate) authority: [u8; 32],
    pub(crate) subject: String,
    pub(crate) operation: [u8; 32],
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionStreamProgress {
    pub(crate) request_header: Vec<u8>,
    pub(crate) max_items: u64,
    pub(crate) max_bytes: u64,
    pub(crate) duration_ms: u64,
    pub(crate) items: u64,
    pub(crate) bytes: u64,
}
impl ExecutionStreamProgress {
    fn capture(header: &ApplicationHeader, contract: &ServiceContract) -> Result<Self> {
        let mut request_header = vec![0; 512];
        let length = header.encode(&mut request_header)?;
        request_header.truncate(length);
        Ok(Self {
            request_header,
            max_items: contract.uint(24)?,
            max_bytes: contract.uint(25)?,
            duration_ms: contract.uint(26)?,
            items: 0,
            bytes: 0,
        })
    }
    pub(crate) fn validate(
        &self,
        key: &Key,
        request: [u8; 32],
        contract: [u8; 32],
        deadline: u64,
        limit: u32,
    ) -> Result<()> {
        let header = ApplicationHeader::decode(&self.request_header)?;
        if header.kind() != "execution_stream_request"
            || header.bytes(1)? != key.operation
            || header.bytes(4)? != request
            || header.bytes(6)? != contract
            || header.uint(5)? != deadline
            || header.uint(8)? != u64::from(limit)
            || self.max_items == 0
            || self.max_bytes == 0
            || self.duration_ms == 0
            || self.max_items > u64::from(u32::MAX)
            || self.items > self.max_items
            || self.bytes > self.max_bytes
            || self.items == 0 && self.bytes != 0
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        Ok(())
    }
    fn reserve_item(&mut self, payload_bytes: u64) -> Result<()> {
        let items = self
            .items
            .checked_add(1)
            .filter(|items| *items <= self.max_items)
            .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
        let bytes = self
            .bytes
            .checked_add(payload_bytes)
            .filter(|bytes| *bytes <= self.max_bytes)
            .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
        self.items = items;
        self.bytes = bytes;
        Ok(())
    }
}

pub(crate) struct Record {
    pub(crate) request: [u8; 32],
    pub(crate) contract: [u8; 32],
    pub(crate) cutoff: u64,
    pub(crate) history_until: u64,
    pub(crate) accepted_ms: u64,
    pub(crate) deadline_ms: u64,
    pub(crate) run_started_ms: Option<u64>,
    pub(crate) retention: u64,
    pub(crate) limit: u32,
    pub(crate) shape: ServiceShape,
    pub(crate) state: ExecutionState,
    pub(crate) cancel_mode: bool,
    pub(crate) cancel_requested: bool,
    pub(crate) active: bool,
    pub(crate) dispatched: bool,
    pub(crate) metadata_finished: bool,
    pub(crate) error: Option<ServiceFailure>,
    pub(crate) result: Option<Zeroizing<Vec<u8>>>,
    pub(crate) result_until: Option<u64>,
    pub(crate) result_bytes: u32,
    pub(crate) result_digest: [u8; 32],
    pub(crate) application_error: Option<u32>,
    pub(crate) retained_checkpoint: Option<crate::checkpoint_v4::RetainedCheckpoint>,
    pub(crate) stream_progress: Option<ExecutionStreamProgress>,
    pub(crate) resume_request: Option<Vec<u8>>,
    pub(crate) holders: u32,
    pub(crate) changed: Arc<Notify>,
    pub(crate) cancellation: CancellationToken,
}
fn original_execution_cap(
    record: &Record,
    requested_cap: u64,
    duration_ms: u64,
    lower_ms: u64,
    upper_ms: u64,
) -> Result<u64> {
    if duration_ms == 0 {
        return Err(failure(ServiceFailure::ContractMismatch));
    }
    let started = record.run_started_ms.unwrap_or(lower_ms);
    let cap = requested_cap.min(record.deadline_ms).min(
        started
            .checked_add(duration_ms)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?,
    );
    if upper_ms >= cap {
        return Err(failure(ServiceFailure::DeadlineExceeded));
    }
    Ok(cap)
}

// A declared application error is a completed business result with a body;
// uncertain SDK failures do not acquire the same retained-result authority.
fn retained_result(record: &Record, lower_ms: u64, upper_ms: u64) -> Result<(&[u8], Option<u32>)> {
    if let Some(error) = record.error {
        return Err(failure(error));
    }
    let terminal = record.state == ExecutionState::Completed
        || record.state == ExecutionState::Failed && record.application_error.is_some();
    if !terminal {
        return Err(failure(ServiceFailure::ServiceUnavailable));
    }
    let until = record
        .result_until
        .ok_or_else(|| failure(ServiceFailure::ResultExpired))?;
    if lower_ms >= until || record.result.is_none() {
        return Err(failure(ServiceFailure::ResultExpired));
    }
    if upper_ms >= until {
        return Err(failure(ServiceFailure::ServiceUnavailable));
    }
    Ok((
        record
            .result
            .as_ref()
            .expect("retained result checked")
            .as_slice(),
        record.application_error,
    ))
}

pub(crate) struct State {
    pub(crate) records: BTreeMap<Key, Record>,
    pub(crate) floors: BTreeMap<[u8; 32], u64>,
    pub(crate) active: u32,
    pub(crate) result_capacity: u64,
    pub(crate) closed: bool,
    pub(crate) persistence_failed: bool,
    pub(crate) gc_cursor: Option<Key>,
    pub(crate) history_started: bool,
}
pub(crate) struct HistoryOwner {
    pub(crate) root: Arc<EnvironmentRoot>,
    options: ExecutionServiceOptions,
    state: Mutex<State>,
    charge: Mutex<Option<EnvironmentCharge>>,
    store: Option<crate::SQLiteExecutionStore>,
    recovery: Mutex<Option<Arc<crate::checkpoint_v4::RecoveryOwner>>>,
}
impl fmt::Debug for HistoryOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecutionService { <opaque> }")
    }
}
#[derive(Clone, Debug)]
pub struct ExecutionService(pub(crate) Arc<HistoryOwner>);
impl ExecutionService {
    #[cfg(test)]
    pub(crate) fn with_test_store_connection<R>(
        &self,
        inspect: impl FnOnce(&rusqlite::Connection) -> R,
    ) -> R {
        self.0
            .store
            .as_ref()
            .expect("durable execution history")
            .with_test_connection(inspect)
    }
    pub fn new(
        environment: &TransportEnvironment,
        mut options: ExecutionServiceOptions,
    ) -> Result<Self> {
        Self::capture_options(&mut options)?;
        environment.root().execution_service(options, None)
    }
    pub fn new_durable(
        environment: &TransportEnvironment,
        mut options: ExecutionServiceOptions,
        store: crate::SQLiteExecutionStoreOptions,
    ) -> Result<Self> {
        Self::capture_options(&mut options)?;
        environment.root().execution_service(options, Some(store))
    }
    fn capture_options(options: &mut ExecutionServiceOptions) -> Result<()> {
        if ![
            options.tenant.as_str(),
            options.audience.as_str(),
            options.namespace.as_str(),
        ]
        .into_iter()
        .all(id)
            || options.max_records == 0
            || options.max_records > 8192
            || options.max_active == 0
            || options.max_active > options.max_records.min(1024)
            || options.result_bytes == 0
            || options.result_bytes > 16 << 20
            || options.caller_authorities.is_empty()
            || options.caller_authorities.len() > 16
            || options.caller_authorities.contains(&[0; 32])
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        options.caller_authorities.sort();
        if options
            .caller_authorities
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(())
    }
    /// Install one immutable application recovery key and finite issuance policy
    /// before work is admitted. A reopened store must match the original key
    /// fingerprint and policy; it never derives a signing key from history.
    pub fn configure_recovery(
        &self,
        policy: crate::ExecutionRecoveryPolicy,
        signing: crate::ServiceCheckpointSigningKey,
    ) -> Result<()> {
        policy.validate()?;
        let store = self
            .0
            .store
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let verification = signing.verification_key()?;
        let configuration = crate::checkpoint_v4::RecoveryConfiguration {
            policy,
            protection: signing.protection(),
            key_id: signing.key_id(),
            key_fingerprint: signing.fingerprint()?,
        };
        let charge = self.0.root.reserve_environment(ResourceLimits {
            sdk_bytes: 65536,
            work_slots: 1,
            items: 1,
            ..ResourceLimits::default()
        })?;
        let state = self.0.state.lock().expect("execution history");
        if state.closed || state.persistence_failed || state.active != 0 || state.history_started {
            return Err(failure(ServiceFailure::Closed));
        }
        let mut recovery = self.0.recovery.lock().expect("execution recovery policy");
        if let Some(original) = recovery.as_ref() {
            return if original.configuration == configuration {
                Ok(())
            } else {
                Err(failure(ServiceFailure::ContractMismatch))
            };
        }
        for (key, record) in &state.records {
            if let Some(retained) = &record.retained_checkpoint {
                let token =
                    crate::ApplicationCheckpointToken::verify(&retained.token, &verification)?;
                if token.tenant != self.0.options.tenant
                    || token.audience != self.0.options.audience
                    || token.namespace != self.0.options.namespace
                    || token.caller != key.subject
                    || token.operation != key.operation
                    || token.request != record.request
                    || token.generation() != retained.generation
                    || token.checkpoint().encoded() != retained.checkpoint
                    || token.expires_at_ms() != retained.expires_at_ms
                    || token.issued_at_ms() != retained.last_issue_ms
                    || token.expires_at_ms() > record.history_until
                    || token.expires_at_ms() - token.issued_at_ms()
                        > configuration.policy.max_issued_duration_ms
                    || retained.reissuance.as_ref().is_some_and(|receipt| {
                        receipt.requested_lifetime_ms > configuration.policy.max_issued_duration_ms
                    })
                    || retained.issues > configuration.policy.max_checkpoint_issues_per_operation
                    || retained.token.len() > configuration.policy.max_token_bytes as usize
                {
                    return Err(failure(ServiceFailure::ContractMismatch));
                }
            }
        }
        store.configure_recovery(
            &configuration,
            state
                .records
                .values()
                .any(|record| record.retained_checkpoint.is_some()),
        )?;
        *recovery = Some(Arc::new(crate::checkpoint_v4::RecoveryOwner {
            configuration,
            signing,
            _charge: charge,
        }));
        Ok(())
    }
    pub(crate) fn recovery_configured(&self) -> bool {
        self.0
            .recovery
            .lock()
            .expect("execution recovery policy")
            .is_some()
    }
    pub fn durable_store(&self) -> Option<crate::SQLiteExecutionStore> {
        self.0.store.clone()
    }
    pub fn options(&self) -> &ExecutionServiceOptions {
        &self.0.options
    }
    pub(crate) fn create(
        root: Arc<EnvironmentRoot>,
        options: ExecutionServiceOptions,
        store_options: Option<crate::SQLiteExecutionStoreOptions>,
    ) -> Result<Self> {
        let bytes = options
            .result_bytes
            .checked_mul(if store_options.is_some() { 2 } else { 1 })
            .and_then(|bytes| {
                bytes.checked_add(
                    u64::from(options.max_records)
                        * if store_options.is_some() { 65536 } else { 4096 }
                        + 32768,
                )
            })
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: bytes,
            items: u64::from(options.max_records) * 3 + 8,
            work_slots: u64::from(options.max_active) * 3 + 8,
            tasks: u64::from(options.max_active) * 3 + 8,
            ..ResourceLimits::default()
        })?;
        let floors = options
            .caller_authorities
            .iter()
            .map(|authority| (*authority, 0))
            .collect();
        let mut state = State {
            records: BTreeMap::new(),
            floors,
            active: 0,
            result_capacity: 0,
            closed: false,
            persistence_failed: false,
            gc_cursor: None,
            history_started: false,
        };
        let store = store_options
            .map(|store| crate::SQLiteExecutionStore::prepare(root.clone(), options.clone(), store))
            .transpose()?;
        if let Some(store) = &store {
            store.initialize(&mut state)?;
        }
        Ok(Self(Arc::new(HistoryOwner {
            root,
            options,
            state: Mutex::new(state),
            charge: Mutex::new(Some(charge)),
            store,
            recovery: Mutex::new(None),
        })))
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Execution admission and resume bind the original caller, contract, request and retained attempt together."
    )]
    pub(crate) fn admit(
        &self,
        contract: &ServiceContract,
        offer: &AdmissionOffer,
        identity: &ExecutionIdentity,
        header: &ApplicationHeader,
        payload: &[u8],
        account: &ResourceAccount,
        guard: impl Fn() -> Result<()>,
    ) -> Result<ExecutionAttempt> {
        contract.check_environment(&self.0.root)?;
        if !account.belongs_to(&self.0.root) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        if contract.semantics() != ServiceSemantics::Execution
            || contract.namespace() != self.0.options.namespace
            || contract.optional_uint(13) != Some(u64::from(self.0.store.is_some()))
            || header.type_id()? != contract.type_id()
            || header.bytes(6)? != contract.digest()
            || identity.authority == [0; 32]
            || identity.identity_digest == [0; 32]
            || !id(&identity.subject)
            || !self
                .0
                .options
                .caller_authorities
                .contains(&identity.authority)
            || !header.has(1)
            || header.is_response()
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let shape_matches = matches!(
            (contract.shape(), header.kind()),
            (
                ServiceShape::Unary,
                "execution_unary_request" | "resume_request"
            ) | (ServiceShape::ServerStreaming, "execution_stream_request")
                | (ServiceShape::Notify, "execution_notify")
        );
        if !shape_matches || payload.len() as u64 > contract.uint(23)? {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        if header.kind() == "resume_request" {
            if self.0.store.is_none() || contract.optional_uint(15).is_none() {
                return Err(failure(ServiceFailure::ContractPolicyRejected));
            }
            crate::checkpoint_v4::ApplicationResumeRequest::capture(payload)?;
        }
        let operation = header.bytes(1)?;
        let request = header.bytes(4)?;
        if rpc_wire_v4::execution_digest(contract.encoded(), header, payload)? != request {
            return Err(failure(ServiceFailure::Protocol));
        }
        let cutoff = u64::from_be_bytes(
            operation[..8]
                .try_into()
                .map_err(|_| failure(ServiceFailure::Protocol))?,
        );
        let deadline = header.uint(5)?;
        let key = Key {
            authority: identity.authority,
            subject: identity.subject.clone(),
            operation,
        };
        let limit = if header.has(8) {
            u32::try_from(header.uint(8)?).map_err(|_| failure(ServiceFailure::ContractMismatch))?
        } else {
            0
        };
        if header.has(8)
            && (u64::from(limit) < contract.uint(9)? || u64::from(limit) > contract.uint(10)?)
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        guard()?;
        account.with_security_time(|now| {
            offer.check_interval(contract, cutoff, now.lower_ms, now.upper_ms)?;
            if now.upper_ms >= deadline
                || deadline
                    > now
                        .lower_ms
                        .checked_add(contract.uint(17)?)
                        .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?
                || cutoff
                    > now
                        .lower_ms
                        .checked_add(contract.uint(16)?)
                        .ok_or_else(|| failure(ServiceFailure::AdmissionWindowClosed))?
            {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            let mut state = self.0.state.lock().expect("execution history");
            if state.closed {
                return Err(failure(ServiceFailure::Closed));
            }
            if state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            state.history_started = true;
            if let Some(record) = state.records.get_mut(&key) {
                if record.request != request || record.contract != contract.digest() {
                    return Err(failure(ServiceFailure::OperationConflict));
                }
                if record.holders >= 64 {
                    return Err(failure(ServiceFailure::ResourceExhausted));
                }
                record.holders += 1;
                return Ok(ExecutionAttempt {
                    owner: self.0.clone(),
                    key,
                    created: false,
                    resumed: false,
                    account: account.clone(),
                    exited: AtomicBool::new(false),
                });
            }
            if cutoff
                <= *state
                    .floors
                    .get(&identity.authority)
                    .ok_or_else(|| failure(ServiceFailure::PermissionDenied))?
            {
                return Err(failure(ServiceFailure::HistoryUnknown));
            }
            let retention = contract.optional_uint(15).unwrap_or(0);
            let result_capacity = if contract.shape() == ServiceShape::Unary && retention != 0 {
                u64::from(limit)
            } else {
                0
            };
            if state.records.len() >= self.0.options.max_records as usize
                || state.active >= self.0.options.max_active
                || state
                    .result_capacity
                    .checked_add(result_capacity)
                    .is_none_or(|n| n > self.0.options.result_bytes)
            {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            let history_until = cutoff
                .checked_add(contract.uint(14)?)
                .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
            let result = if result_capacity != 0 {
                Some(Zeroizing::new(Vec::with_capacity(limit as usize)))
            } else {
                None
            };
            state.records.insert(
                key.clone(),
                Record {
                    request,
                    contract: contract.digest(),
                    cutoff,
                    history_until,
                    retention,
                    limit,
                    accepted_ms: now.lower_ms,
                    deadline_ms: deadline,
                    run_started_ms: None,
                    shape: contract.shape(),
                    state: ExecutionState::Accepted,
                    cancel_mode: contract.uint(19)? == 1,
                    cancel_requested: false,
                    active: true,
                    dispatched: false,
                    metadata_finished: false,
                    error: None,
                    result,
                    result_until: None,
                    result_bytes: 0,
                    result_digest: [0; 32],
                    application_error: None,
                    retained_checkpoint: None,
                    stream_progress: if contract.shape() == ServiceShape::ServerStreaming {
                        Some(ExecutionStreamProgress::capture(header, contract)?)
                    } else {
                        None
                    },
                    resume_request: if header.kind() == "resume_request" {
                        Some(payload.to_vec())
                    } else {
                        None
                    },
                    holders: 1,
                    changed: Arc::new(Notify::new()),
                    cancellation: CancellationToken::new(),
                },
            );
            state.active += 1;
            state.result_capacity += result_capacity;
            if let Err(error) = self.0.persist_record(&mut state, &key) {
                let record = state
                    .records
                    .get_mut(&key)
                    .expect("original admitted claim");
                record.active = false;
                record.holders = 0;
                record.state = ExecutionState::Failed;
                record.error = Some(ServiceFailure::ServiceUnavailable);
                state.active -= 1;
                return Err(error);
            }
            Ok(ExecutionAttempt {
                owner: self.0.clone(),
                key,
                created: true,
                resumed: false,
                account: account.clone(),
                exited: AtomicBool::new(false),
            })
        })?
    }

    pub(crate) fn resume_execution_target(
        &self,
        caller: &ExecutionIdentity,
        request: &crate::checkpoint_v4::ApplicationResumeRequest,
        original: &ServiceContract,
    ) -> Result<ExecutionTarget> {
        if original.namespace() != self.0.options.namespace
            || !self
                .0
                .options
                .caller_authorities
                .contains(&caller.authority)
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok(ExecutionTarget {
            tenant: self.0.options.tenant.clone(),
            audience: self.0.options.audience.clone(),
            namespace: self.0.options.namespace.clone(),
            caller_authority: caller.authority,
            caller_subject: caller.subject.clone(),
            operation_id: request.operation,
            request_digest: request.request,
            contract_digest: original.digest(),
        })
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Management observations retain the original caller, authority, deadline and store guard."
    )]
    pub(crate) fn observe_authorized(
        &self,
        target: &ExecutionTarget,
        caller: &ExecutionIdentity,
        account: &ResourceAccount,
        cancel: bool,
        administrator: bool,
        deadline: Option<&ObservationDeadline>,
        guard: impl Fn() -> Result<()>,
    ) -> Result<ExecutionManagementResult> {
        target.validate()?;
        if !account.belongs_to(&self.0.root)
            || target.tenant != self.0.options.tenant
            || target.audience != self.0.options.audience
            || target.namespace != self.0.options.namespace
            || (!administrator
                && (target.caller_authority != caller.authority
                    || target.caller_subject != caller.subject))
            || !self
                .0
                .options
                .caller_authorities
                .contains(&target.caller_authority)
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        guard()?;
        let key = Key {
            authority: target.caller_authority,
            subject: target.caller_subject.clone(),
            operation: target.operation_id,
        };
        let (result, wake) = account.with_security_time(|now| {
            let mut state = self.0.state.lock().expect("execution history");
            // Waiting for the original store gate cannot extend the request.
            // Project the captured trusted sample without reentering its lock.
            let now = account
                .security_time_profile()
                .project(now, Instant::now())?;
            if let Some(deadline) = deadline {
                if deadline.stream.application_read_ended() {
                    return Err(failure(ServiceFailure::Closed));
                }
                if now.upper_ms >= deadline.upper_ms
                    || deadline.drain.is_some_and(|drain| Instant::now() >= drain)
                {
                    return Err(failure(ServiceFailure::DeadlineExceeded));
                }
            }
            if state.closed {
                return Err(failure(ServiceFailure::Closed));
            }
            if state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let Some(record) = state.records.get_mut(&key) else {
                let cutoff = u64::from_be_bytes(
                    target.operation_id[..8]
                        .try_into()
                        .map_err(|_| failure(ServiceFailure::Protocol))?,
                );
                let known = cutoff
                    > *state
                        .floors
                        .get(&target.caller_authority)
                        .ok_or_else(|| failure(ServiceFailure::PermissionDenied))?;
                return Ok((
                    ExecutionManagementResult {
                        observation: None,
                        absence: Some(if known {
                            ExecutionAbsence::NotRegistered
                        } else {
                            ExecutionAbsence::HistoryUnknown
                        }),
                        cancellation: cancel.then_some(if known {
                            ExecutionCancelResult::NotRegistered
                        } else {
                            ExecutionCancelResult::HistoryUnknown
                        }),
                    },
                    None,
                ));
            };
            if record.request != target.request_digest || record.contract != target.contract_digest
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            let mut cancellation = None;
            let mut wake = None;
            if cancel {
                if !record.cancel_mode {
                    cancellation = Some(ExecutionCancelResult::Unsupported);
                } else if matches!(
                    record.state,
                    ExecutionState::Accepted | ExecutionState::Executing | ExecutionState::Unknown
                ) {
                    if !record.cancel_requested {
                        wake = Some((record.cancellation.clone(), record.changed.clone()));
                    }
                    record.cancel_requested = true;
                    if !record.dispatched {
                        record.state = ExecutionState::Failed;
                        record.error = Some(ServiceFailure::ServiceUnavailable);
                    }
                    cancellation = Some(ExecutionCancelResult::Requested);
                } else {
                    cancellation = Some(ExecutionCancelResult::Terminal);
                }
            }
            let deleted = record
                .result_until
                .is_some_and(|until| now.lower_ms >= until || record.result.is_none());
            let observation = ExecutionObservation {
                state: record.state,
                cancel_requested: record.cancel_requested,
                dispatched: record.dispatched,
                work_active: record.active,
                history_not_before_gc_ms: record.history_until,
                result_not_after_ms: record.result_until,
                result_available: record.result.is_some()
                    && record
                        .result_until
                        .is_some_and(|until| now.upper_ms < until),
                result_deleted: deleted,
                result_bytes: record.result_bytes,
                result_digest: record.result_digest,
                application_error_code: record.application_error,
                error: record.error,
            };
            if cancel {
                self.0.persist_record(&mut state, &key)?;
            }
            Ok((
                ExecutionManagementResult {
                    observation: Some(observation),
                    absence: None,
                    cancellation,
                },
                wake,
            ))
        })??;
        // Cancellation may run application listeners; never invoke it while the
        // original resource or history gate is locked.
        if let Some((cancel, changed)) = wake {
            cancel.cancel();
            changed.notify_waiters();
        }
        Ok(result)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Execution admission and resume bind the original caller, contract, request and retained attempt together."
    )]
    pub(crate) fn consume_checkpoint(
        &self,
        session: &crate::crypto_v4::Session,
        target: &ExecutionTarget,
        caller: &ExecutionIdentity,
        contract: &ServiceContract,
        encoded_token: &[u8],
        expected: &crate::ApplicationCheckpoint,
        expected_generation: u64,
        exchange: &Arc<ExecutionAttempt>,
        exchange_contract: &ServiceContract,
        target_stream: &crate::crypto_v4::Stream,
    ) -> Result<(Arc<ExecutionAttempt>, crate::ApplicationResumeResult)> {
        target.validate()?;
        contract.check_environment(&self.0.root)?;
        exchange_contract.check_environment(&self.0.root)?;
        if exchange_contract.shape() != ServiceShape::Unary
            || exchange_contract.semantics() != ServiceSemantics::Execution
            || exchange_contract.optional_uint(13) != Some(1)
            || exchange_contract.optional_uint(15).is_none()
            || exchange_contract.namespace() != self.0.options.namespace
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let stream_binding = target_stream
            .resume_target(session)
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        if !Arc::ptr_eq(&exchange.owner, &self.0)
            || !exchange.created
            || exchange.resumed
            || exchange.exited.load(Ordering::Acquire)
            || exchange.key.authority != caller.authority
            || exchange.key.subject != caller.subject
            || exchange.key.operation == target.operation_id
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        let account = session.application_account();
        if !exchange.account.same_owner(&account) {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let (_, profile, identity) = session
            .service_identity()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        let signed = session
            .checkpoint_policy()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        if profile != 2
            || identity != caller.identity_digest
            || !account.belongs_to(&self.0.root)
            || target.tenant != self.0.options.tenant
            || target.audience != self.0.options.audience
            || target.namespace != self.0.options.namespace
            || target.caller_authority != caller.authority
            || target.caller_subject != caller.subject
            || !self
                .0
                .options
                .caller_authorities
                .contains(&caller.authority)
            || target.contract_digest != contract.digest()
            || contract.semantics() != ServiceSemantics::Execution
            || encoded_token.len() > signed.max_token_bytes as usize
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let _work = account.reserve(ResourceLimits {
            sdk_bytes: 65536,
            work_slots: 1,
            items: 1,
            ..ResourceLimits::default()
        })?;
        let recovery = self
            .0
            .recovery
            .lock()
            .expect("execution recovery policy")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let token = crate::ApplicationCheckpointToken::verify(
            encoded_token,
            &recovery.signing.verification_key()?,
        )?;
        if token.tenant != target.tenant
            || token.audience != target.audience
            || token.namespace != target.namespace
            || token.caller != caller.subject
            || token.operation != target.operation_id
            || token.request != target.request_digest
            || token.generation() != expected_generation
            || token.checkpoint() != expected
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let definition = crate::codec_v4::decode(
            contract.encoded(),
            "ServiceContract",
            crate::codec_v4::Limits {
                bytes: 8192,
                nodes: 1024,
            },
            None,
        )
        .map_err(|_| failure(ServiceFailure::ContractMismatch))?;
        if definition
            .field("ServiceContract", "checkpoint_format")
            .and_then(crate::codec_v4::Value::text)
            .map_err(|_| failure(ServiceFailure::ContractMismatch))?
            != expected.format()
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let key = Key {
            authority: caller.authority,
            subject: caller.subject.clone(),
            operation: target.operation_id,
        };
        account.with_security_time(|now| {
            if now.lower_ms < token.issued_at_ms() || now.upper_ms >= token.expires_at_ms() {
                return Err(failure(ServiceFailure::PermissionDenied));
            }
            let mut state = self.0.state.lock().expect("execution history");
            if state.closed || state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let outer = state
                .records
                .get(&exchange.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if outer.contract != exchange_contract.digest() {
                return Err(failure(ServiceFailure::ContractMismatch));
            }
            original_execution_cap(
                outer,
                outer.deadline_ms,
                exchange_contract.uint(18)?,
                now.lower_ms,
                now.upper_ms,
            )?;
            let resume = crate::checkpoint_v4::ApplicationResumeRequest::capture(
                outer
                    .resume_request
                    .as_deref()
                    .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?,
            )?;
            if !outer.active
                || !outer.dispatched
                || outer.state != ExecutionState::Executing
                || outer.error.is_some()
                || outer.metadata_finished
                || outer.result_until.is_some()
                || outer.retention == 0
                || outer.result.is_none()
                || outer.cancel_requested
                || outer.cancellation.is_cancelled()
                || now.upper_ms >= outer.deadline_ms
                || exchange.exited.load(Ordering::Acquire)
                || resume.operation != target.operation_id
                || resume.request != target.request_digest
                || resume.token != encoded_token
                || resume.expected != *expected
                || resume.generation != expected_generation
                || resume.protection != token.protection()
                || resume.target != stream_binding
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            let confirmation = crate::ApplicationResumeResult::accepted(
                expected.clone(),
                expected_generation
                    .checked_add(1)
                    .ok_or_else(|| failure(ServiceFailure::OperationConflict))?,
            )?;
            let result_payload = confirmation.encoded()?;
            if result_payload.len() > outer.limit as usize
                || result_payload.len() as u64 > exchange_contract.response_payload_limit(None)?
            {
                return Err(failure(ServiceFailure::ResponseLimitUnsupported));
            }
            let result_until = now
                .upper_ms
                .checked_add(outer.retention)
                .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
            let exchange_request = outer.request;
            let record = state
                .records
                .get(&key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if record.request != target.request_digest || record.contract != target.contract_digest
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            if let Some(progress) = &record.stream_progress
                && (progress.max_items != contract.uint(24)?
                    || progress.max_bytes != contract.uint(25)?
                    || progress.duration_ms != contract.uint(26)?)
            {
                return Err(failure(ServiceFailure::ContractMismatch));
            }
            let duration =
                contract
                    .uint(18)?
                    .min(if record.shape == ServiceShape::ServerStreaming {
                        contract.uint(26)?
                    } else {
                        u64::MAX
                    });
            original_execution_cap(
                record,
                record.deadline_ms,
                duration,
                now.lower_ms,
                now.upper_ms,
            )?;
            let retained = record
                .retained_checkpoint
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if record.active
                || !record.dispatched
                || record.state != ExecutionState::Unknown
                || record.cancel_requested
                || record.metadata_finished
                || record.result_until.is_some()
                || record.holders >= 64
                || now.upper_ms >= record.deadline_ms
                || retained.consumed
                || retained.token != encoded_token
                || retained.generation != expected_generation
                || retained.generation == u64::MAX
                || retained.checkpoint != expected.encoded()
                || token.expires_at_ms() > record.history_until
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            let additional_result = if record.shape == ServiceShape::Unary
                && record.retention != 0
                && record.result.is_none()
            {
                u64::from(record.limit)
            } else {
                0
            };
            if state
                .result_capacity
                .checked_add(additional_result)
                .is_none_or(|total| total > self.0.options.result_bytes)
            {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            let record = state
                .records
                .get_mut(&key)
                .expect("original recovery claim");
            if additional_result != 0 {
                record.result = Some(Zeroizing::new(Vec::with_capacity(record.limit as usize)));
            }
            let retained = record
                .retained_checkpoint
                .as_mut()
                .expect("verified generation");
            retained.consumed = true;
            retained.consumption = Some(crate::checkpoint_v4::CheckpointConsumption {
                exchange_operation: exchange.key.operation,
                exchange_request,
                generation: expected_generation + 1,
                target: stream_binding.clone(),
                callback_entered: false,
            });
            record.active = true;
            record.state = ExecutionState::Accepted;
            record.error = None;
            record.cancellation = CancellationToken::new();
            record.holders += 1;
            // Transfer the admitted outer execution slot in the same durable
            // transaction; the wire confirmation retains its own resources.
            state.result_capacity += additional_result;
            state.history_started = true;
            let outer = state
                .records
                .get_mut(&exchange.key)
                .expect("original Resume exchange");
            outer
                .result
                .as_mut()
                .expect("prepaid Resume result")
                .extend_from_slice(&result_payload);
            outer.result_digest = Sha256::digest(&result_payload).into();
            outer.result_bytes = result_payload.len() as u32;
            outer.result_until = Some(result_until);
            outer.state = ExecutionState::Completed;
            outer.active = false;
            let changed = outer.changed.clone();
            if let Err(error) = self.0.persist_pair(&mut state, &key, &exchange.key) {
                let record = state
                    .records
                    .get_mut(&key)
                    .expect("original recovery claim");
                record.active = false;
                record.holders -= 1;
                record.state = ExecutionState::Unknown;
                record.error = Some(ServiceFailure::ServiceUnavailable);
                state.active -= 1;
                let outer = state
                    .records
                    .get_mut(&exchange.key)
                    .expect("sealed Resume exchange");
                outer.state = ExecutionState::Unknown;
                outer.error = Some(ServiceFailure::ServiceUnavailable);
                outer.result_until = None;
                changed.notify_waiters();
                return Err(error);
            }
            changed.notify_waiters();
            Ok((
                Arc::new(ExecutionAttempt {
                    owner: self.0.clone(),
                    key,
                    created: true,
                    resumed: true,
                    account: account.clone(),
                    exited: AtomicBool::new(false),
                }),
                confirmation,
            ))
        })?
    }
    /// Copies retained bytes under the same authenticated history and delivery
    /// gate. The caller supplies its original finite output reservation.
    pub(crate) fn read_authorized(
        &self,
        target: &ExecutionTarget,
        caller: &ExecutionIdentity,
        account: &ResourceAccount,
        administrator: bool,
        destination: &mut [u8],
        guard: impl Fn() -> Result<()>,
    ) -> Result<(usize, Option<u32>)> {
        self.observe_authorized(target, caller, account, false, administrator, None, &guard)?;
        guard()?;
        account.with_security_time(|now| {
            let state = self.0.state.lock().expect("execution history");
            if state.closed {
                return Err(failure(ServiceFailure::Closed));
            }
            if state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let key = Key {
                authority: target.caller_authority,
                subject: target.caller_subject.clone(),
                operation: target.operation_id,
            };
            let record = state
                .records
                .get(&key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if record.request != target.request_digest || record.contract != target.contract_digest
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            if record.shape != ServiceShape::Unary {
                return Err(failure(ServiceFailure::ResultExpired));
            }
            let (payload, application_error) = retained_result(record, now.lower_ms, now.upper_ms)?;
            if payload.len() > destination.len() {
                return Err(failure(ServiceFailure::ResponseLimitUnsupported));
            }
            destination[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), application_error))
        })?
    }
    /// Bounded maintenance never removes active work, observers or unexpired
    /// results. The original domain floor is installed before deleting detail.
    pub fn maintain(&self) -> Result<()> {
        let now = self.0.root.sample()?;
        let mut state = self.0.state.lock().expect("execution history");
        if state.closed {
            return Err(failure(ServiceFailure::Closed));
        }
        if state.persistence_failed {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        use std::ops::Bound::{Excluded, Unbounded};
        let mut keys: Vec<_> = match &state.gc_cursor {
            Some(cursor) => state
                .records
                .range((Excluded(cursor.clone()), Unbounded))
                .take(8)
                .map(|(key, _)| key.clone())
                .collect(),
            None => state.records.keys().take(8).cloned().collect(),
        };
        if keys.is_empty() {
            keys = state.records.keys().take(8).cloned().collect();
        }
        state.gc_cursor = keys.last().cloned();
        for key in keys {
            let record = state.records.get_mut(&key).expect("retained record");
            if record.active || record.holders != 0 {
                continue;
            }
            let mut released = 0;
            if record.result.is_some()
                && record
                    .result_until
                    .is_none_or(|until| now.lower_ms >= until)
            {
                record.result = None;
                released = u64::from(record.limit);
            }
            let remove = record.result.is_none()
                && now.lower_ms >= record.history_until
                && now.lower_ms >= record.cutoff;
            let cutoff = record.cutoff;
            state.result_capacity -= released;
            if remove {
                let floor = state
                    .floors
                    .get_mut(&key.authority)
                    .expect("original domain");
                *floor = (*floor).max(cutoff);
                let floor = *floor;
                if let Some(store) = &self.0.store
                    && let Err(error) = store.collect(key.authority, floor, &key)
                {
                    state.persistence_failed = true;
                    return Err(error);
                }
                state.records.remove(&key);
            } else if released != 0 {
                self.0.persist_record(&mut state, &key)?;
            }
        }
        Ok(())
    }
}
impl HistoryOwner {
    pub(crate) fn matches(&self, options: &ExecutionServiceOptions) -> bool {
        self.options.tenant == options.tenant
            && self.options.audience == options.audience
            && self.options.namespace == options.namespace
    }
    pub(crate) fn configured(
        &self,
        options: &ExecutionServiceOptions,
        store: Option<&crate::SQLiteExecutionStoreOptions>,
    ) -> bool {
        &self.options == options
            && match (&self.store, store) {
                (None, None) => true,
                (Some(current), Some(requested)) => current.options() == requested,
                _ => false,
            }
    }
    fn persist_record(&self, state: &mut State, key: &Key) -> Result<()> {
        if state.persistence_failed {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        if let Some(store) = &self.store {
            let record = state
                .records
                .get(key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if let Err(error) = store.persist(key, record) {
                state.persistence_failed = true;
                return Err(error);
            }
        }
        Ok(())
    }
    fn persist_pair(&self, state: &mut State, original: &Key, exchange: &Key) -> Result<()> {
        if state.persistence_failed {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractPolicyRejected))?;
        let original_record = state
            .records
            .get(original)
            .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
        let exchange_record = state
            .records
            .get(exchange)
            .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
        if let Err(error) = store.persist_pair(original, original_record, exchange, exchange_record)
        {
            state.persistence_failed = true;
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn close(&self) {
        let cancellations = {
            let mut state = self.state.lock().expect("execution history");
            if state.closed {
                return;
            }
            state.closed = true;
            let cancellations = state
                .records
                .values_mut()
                .filter_map(|record| {
                    if record.metadata_finished
                        || record.result_until.is_some()
                        || record.state == ExecutionState::Completed
                    {
                        return None;
                    }
                    record.error = Some(ServiceFailure::ServiceUnavailable);
                    record.state = if record.dispatched {
                        ExecutionState::Unknown
                    } else {
                        ExecutionState::Failed
                    };
                    Some((record.cancellation.clone(), record.changed.clone()))
                })
                .collect::<Vec<_>>();
            let keys: Vec<_> = state.records.keys().cloned().collect();
            for key in keys {
                let _ = self.persist_record(&mut state, &key);
            }
            cancellations
        };
        for (cancel, changed) in cancellations {
            cancel.cancel();
            changed.notify_waiters();
        }
        self.collect_closed();
    }
    fn collect_closed(&self) {
        let release = {
            let mut state = self.state.lock().expect("execution history");
            if !state.closed
                || state.active != 0
                || state.records.values().any(|record| record.holders != 0)
            {
                return;
            }
            state.records.clear();
            state.floors.clear();
            state.result_capacity = 0;
            state.gc_cursor = None;
            self.charge.lock().expect("execution history charge").take()
        };
        if let Some(store) = &self.store {
            store.close();
        }
        let recovery = {
            self.recovery
                .lock()
                .expect("execution recovery policy")
                .take()
        };
        drop(recovery);
        drop(release);
    }
}

/// The original executing callback's recovery borrow. Saving this value after
/// callback exit cannot issue a token or acquire another execution claim.
#[derive(Clone)]
pub struct ExecutionInvocation {
    attempt: Arc<ExecutionAttempt>,
    session: crate::crypto_v4::SessionLink,
    format: String,
    run_duration_ms: u64,
}
impl fmt::Debug for ExecutionInvocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecutionInvocation { <opaque> }")
    }
}
impl ExecutionInvocation {
    pub(crate) fn for_request(
        attempt: Arc<ExecutionAttempt>,
        session: crate::crypto_v4::SessionLink,
        contract: &ServiceContract,
    ) -> Result<Option<Self>> {
        let Some(encoded) = contract.field(20) else {
            return Ok(None);
        };
        let parsed = crate::codec_v4::decode(
            contract.encoded(),
            "ServiceContract",
            crate::codec_v4::Limits {
                bytes: 8192,
                nodes: 1024,
            },
            None,
        )
        .map_err(|_| failure(ServiceFailure::ContractMismatch))?;
        let format = parsed
            .field("ServiceContract", "checkpoint_format")
            .and_then(crate::codec_v4::Value::text)
            .map_err(|_| failure(ServiceFailure::ContractMismatch))?;
        if encoded.is_empty() {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let run_duration_ms =
            contract
                .uint(18)?
                .min(if contract.shape() == ServiceShape::ServerStreaming {
                    contract.uint(26)?
                } else {
                    u64::MAX
                });
        Ok(Some(Self {
            attempt,
            session,
            format: format.to_owned(),
            run_duration_ms,
        }))
    }
    pub fn issue_checkpoint(
        &self,
        checkpoint: &crate::ApplicationCheckpoint,
        lifetime_ms: u64,
    ) -> Result<crate::ApplicationCheckpointToken> {
        if checkpoint.format() != self.format
            || !self.attempt.created
            || self.attempt.exited.load(Ordering::Acquire)
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let session = self
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let signed = session
            .checkpoint_policy()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        let _work = self.attempt.account.reserve(ResourceLimits {
            sdk_bytes: 65536,
            work_slots: 1,
            items: 1,
            ..ResourceLimits::default()
        })?;
        self.attempt.account.with_security_time(|now| {
            let mut state = self.attempt.owner.state.lock().expect("execution history");
            if state.closed || state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let recovery = self
                .attempt
                .owner
                .recovery
                .lock()
                .expect("execution recovery policy")
                .clone()
                .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
            let policy = &recovery.configuration.policy;
            let record = state
                .records
                .get_mut(&self.attempt.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if !record.active
                || !record.dispatched
                || record.state != ExecutionState::Executing
                || record.error.is_some()
                || record.cancel_requested
                || now.upper_ms >= record.deadline_ms
                || record
                    .run_started_ms
                    .and_then(|started| started.checked_add(self.run_duration_ms))
                    .is_none_or(|cap| now.upper_ms >= cap)
                || record.cancellation.is_cancelled()
                || self.attempt.exited.load(Ordering::Acquire)
            {
                return Err(failure(ServiceFailure::Closed));
            }
            if lifetime_ms == 0
                || lifetime_ms
                    > policy
                        .max_issued_duration_ms
                        .min(signed.max_issued_duration_ms)
            {
                return Err(failure(ServiceFailure::ContractPolicyRejected));
            }
            let encoded_checkpoint = checkpoint.encoded();
            if let Some(original) = &record.retained_checkpoint
                && (original.issues >= policy.max_checkpoint_issues_per_operation
                    || now.lower_ms < original.last_issue_ms
                    || now.lower_ms - original.last_issue_ms
                        < policy.minimum_checkpoint_interval_ms)
            {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            let expires = now
                .lower_ms
                .checked_add(lifetime_ms)
                .filter(|expires| now.upper_ms < *expires && *expires <= record.history_until)
                .ok_or_else(|| failure(ServiceFailure::ContractPolicyRejected))?;
            let generation = record
                .retained_checkpoint
                .as_ref()
                .map_or(Ok(1), |original| {
                    original
                        .generation
                        .checked_add(if original.consumed { 2 } else { 1 })
                        .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))
                })?;
            let issues = record
                .retained_checkpoint
                .as_ref()
                .map_or(1, |original| original.issues + 1);
            let target = ExecutionTarget {
                tenant: self.attempt.owner.options.tenant.clone(),
                audience: self.attempt.owner.options.audience.clone(),
                namespace: self.attempt.owner.options.namespace.clone(),
                caller_subject: self.attempt.key.subject.clone(),
                caller_authority: self.attempt.key.authority,
                operation_id: self.attempt.key.operation,
                request_digest: record.request,
                contract_digest: record.contract,
            };
            let token = recovery.signing.sign(&crate::checkpoint_v4::claims(
                &target,
                checkpoint,
                generation,
                now.lower_ms,
                expires,
            )?)?;
            if token.len() > policy.max_token_bytes.min(signed.max_token_bytes) as usize {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            record.retained_checkpoint = Some(crate::checkpoint_v4::RetainedCheckpoint {
                generation,
                issues,
                last_issue_ms: now.lower_ms,
                checkpoint: encoded_checkpoint,
                token: token.clone(),
                expires_at_ms: expires,
                consumed: false,
                consumption: None,
                reissuance: None,
            });
            self.attempt
                .owner
                .persist_record(&mut state, &self.attempt.key)?;
            crate::ApplicationCheckpointToken::verify(&token, &recovery.signing.verification_key()?)
        })?
    }
    /// Explicit application-authorized replacement after a consumed Resume
    /// confirmation was lost. Call only inside a separately registered durable
    /// issuance method after authorizing the current caller and original scope.
    /// Query and imported references never perform this mutation.
    pub fn reissue_checkpoint(
        &self,
        reference: &crate::OperationReference,
        original_contract: &ServiceContract,
        previous_token: &[u8],
        lifetime_ms: u64,
    ) -> Result<crate::ApplicationCheckpointToken> {
        if !self.attempt.created
            || self.attempt.exited.load(Ordering::Acquire)
            || previous_token.len() > 4980
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        original_contract.check_environment(&self.attempt.owner.root)?;
        let target = reference.target();
        target.validate()?;
        if original_contract.semantics() != ServiceSemantics::Execution
            || original_contract.optional_uint(13) != Some(1)
            || original_contract.field(20).is_none()
            || target.contract_digest != original_contract.digest()
            || target.tenant != self.attempt.owner.options.tenant
            || target.audience != self.attempt.owner.options.audience
            || target.namespace != self.attempt.owner.options.namespace
            || original_contract.namespace() != target.namespace
            || target.caller_authority != self.attempt.key.authority
            || target.caller_subject != self.attempt.key.subject
            || target.operation_id == self.attempt.key.operation
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let session = self
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let signed = session
            .checkpoint_policy()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        let recovery = self
            .attempt
            .owner
            .recovery
            .lock()
            .expect("execution recovery policy")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let policy = &recovery.configuration.policy;
        if lifetime_ms == 0
            || lifetime_ms
                > policy
                    .max_issued_duration_ms
                    .min(signed.max_issued_duration_ms)
            || previous_token.len() > policy.max_token_bytes.min(signed.max_token_bytes) as usize
        {
            return Err(failure(ServiceFailure::ContractPolicyRejected));
        }
        let previous = crate::ApplicationCheckpointToken::verify(
            previous_token,
            &recovery.signing.verification_key()?,
        )?;
        if previous.checkpoint().format() != self.format
            || previous.tenant != target.tenant
            || previous.audience != target.audience
            || previous.namespace != target.namespace
            || previous.caller != target.caller_subject
            || previous.operation != target.operation_id
            || previous.request != target.request_digest
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let _work = self.attempt.account.reserve(ResourceLimits {
            sdk_bytes: 65536,
            work_slots: 1,
            items: 1,
            ..ResourceLimits::default()
        })?;
        let key = Key {
            authority: target.caller_authority,
            subject: target.caller_subject.clone(),
            operation: target.operation_id,
        };
        let previous_digest: [u8; 32] = Sha256::digest(previous_token).into();
        self.attempt.account.with_security_time(|now| {
            let mut state = self
                .attempt
                .owner
                .state
                .lock()
                .expect("checkpoint reissuance");
            if state.closed
                || state.persistence_failed
                || self.attempt.exited.load(Ordering::Acquire)
            {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let issuer = state
                .records
                .get(&self.attempt.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if !issuer.active
                || !issuer.dispatched
                || issuer.state != ExecutionState::Executing
                || issuer.error.is_some()
                || issuer.cancel_requested
                || issuer.cancellation.is_cancelled()
                || issuer.shape != ServiceShape::Unary
                || issuer.retention == 0
            {
                return Err(failure(ServiceFailure::PermissionDenied));
            }
            original_execution_cap(
                issuer,
                issuer.deadline_ms,
                self.run_duration_ms,
                now.lower_ms,
                now.upper_ms,
            )?;
            let issuing_request = issuer.request;
            let record = state
                .records
                .get(&key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if record.request != target.request_digest
                || record.contract != target.contract_digest
                || record.shape != original_contract.shape()
                || record.metadata_finished
                || record.result_until.is_some()
                || record.cancel_requested
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            let duration =
                original_contract
                    .uint(18)?
                    .min(if record.shape == ServiceShape::ServerStreaming {
                        original_contract.uint(26)?
                    } else {
                        u64::MAX
                    });
            let original_cap = original_execution_cap(
                record,
                record.deadline_ms,
                duration,
                now.lower_ms,
                now.upper_ms,
            )?;
            let retained = record
                .retained_checkpoint
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            // Idempotent readback does not advance generation, nonce, TTL or
            // quota. Only the explicitly authorized issuance callback sees it.
            if let Some(receipt) = retained
                .reissuance
                .as_ref()
                .filter(|receipt| receipt.previous_token_digest == previous_digest)
            {
                if receipt.requested_lifetime_ms != lifetime_ms
                    || now.upper_ms >= retained.expires_at_ms
                    || retained.consumed
                {
                    return Err(failure(ServiceFailure::OperationConflict));
                }
                return crate::ApplicationCheckpointToken::verify(
                    &retained.token,
                    &recovery.signing.verification_key()?,
                );
            }
            if record.active
                || !record.dispatched
                || record.state != ExecutionState::Unknown
                || retained.token != previous_token
                || !retained.consumed
                || retained.checkpoint != previous.checkpoint().encoded()
                || retained.generation != previous.generation()
                || retained.issues >= policy.max_checkpoint_issues_per_operation
                || now.lower_ms < retained.last_issue_ms
                || now.lower_ms - retained.last_issue_ms < policy.minimum_checkpoint_interval_ms
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            let consumed = retained
                .consumption
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::OperationConflict))?;
            if consumed.callback_entered {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            let generation = consumed
                .generation
                .checked_add(1)
                .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
            let checkpoint = previous.checkpoint().clone();
            let issues = retained.issues + 1;
            let expires = now
                .lower_ms
                .checked_add(lifetime_ms)
                .map(|expiry| expiry.min(original_cap).min(record.history_until))
                .filter(|expiry| now.upper_ms < *expiry)
                .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
            let token = recovery.signing.sign(&crate::checkpoint_v4::claims(
                &target,
                &checkpoint,
                generation,
                now.lower_ms,
                expires,
            )?)?;
            if token.len() > policy.max_token_bytes.min(signed.max_token_bytes) as usize {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            let record = state
                .records
                .get_mut(&key)
                .expect("original reissuance record");
            record.retained_checkpoint = Some(crate::checkpoint_v4::RetainedCheckpoint {
                generation,
                issues,
                last_issue_ms: now.lower_ms,
                checkpoint: checkpoint.encoded(),
                token: token.clone(),
                expires_at_ms: expires,
                consumed: false,
                consumption: None,
                reissuance: Some(crate::checkpoint_v4::CheckpointReissuance {
                    previous_token_digest: previous_digest,
                    issuing_operation: self.attempt.key.operation,
                    issuing_request,
                    requested_lifetime_ms: lifetime_ms,
                }),
            });
            // Persist before returning protected bytes. A failed transaction
            // seals this history; its uncertain nonce is never retried locally.
            self.attempt.owner.persist_record(&mut state, &key)?;
            crate::ApplicationCheckpointToken::verify(&token, &recovery.signing.verification_key()?)
        })?
    }
}

pub(crate) struct ExecutionAttempt {
    owner: Arc<HistoryOwner>,
    key: Key,
    created: bool,
    resumed: bool,
    account: ResourceAccount,
    exited: AtomicBool,
}
impl fmt::Debug for ExecutionAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecutionAttempt { <opaque> }")
    }
}
impl ExecutionAttempt {
    pub(crate) fn cancellation(&self) -> Result<CancellationToken> {
        self.account.check()?;
        let state = self.owner.state.lock().expect("execution history");
        Ok(state
            .records
            .get(&self.key)
            .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?
            .cancellation
            .clone())
    }
    pub(crate) async fn wait_terminal(&self, cancellation: &CancellationToken) -> Result<()> {
        let changed = {
            self.account.check()?;
            let mut state = self.owner.state.lock().expect("execution history");
            let record = state
                .records
                .get_mut(&self.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if record.holders >= 64 {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            record.holders += 1;
            record.changed.clone()
        };
        let _wait = HistoryWait {
            owner: self.owner.clone(),
            key: self.key.clone(),
        };
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.account.check()?;
            {
                let state = self.owner.state.lock().expect("execution history");
                if state.closed {
                    return Err(failure(ServiceFailure::Closed));
                }
                if state.persistence_failed {
                    return Err(failure(ServiceFailure::ServiceUnavailable));
                }
                let record = state
                    .records
                    .get(&self.key)
                    .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
                if record.metadata_finished
                    || record.result_until.is_some()
                    || record.error.is_some()
                    || record.state == ExecutionState::Completed
                {
                    return Ok(());
                }
            }
            tokio::select! { _ = notified => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::ServiceUnavailable)) }
        }
    }
    pub(crate) fn created(&self) -> bool {
        self.created
    }
    pub(crate) fn enter(&self, guard: impl Fn() -> Result<()>) -> Result<()> {
        if !self.created || self.exited.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        guard()?;
        self.owner.root.sample()?;
        self.account.with_security_time(|now| {
            let mut state = self.owner.state.lock().expect("execution history");
            if state.closed {
                return Err(failure(ServiceFailure::Closed));
            }
            if state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let record = state
                .records
                .get_mut(&self.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if !record.active
                || record.dispatched != self.resumed
                || record.state != ExecutionState::Accepted
                || record.error.is_some()
            {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            if now.upper_ms >= record.deadline_ms
                || record.cancel_requested
                || record.cancellation.is_cancelled()
            {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            if record.run_started_ms.is_none() {
                record.run_started_ms = Some(now.lower_ms);
            }
            if self.resumed {
                let consumption = record
                    .retained_checkpoint
                    .as_mut()
                    .and_then(|retained| retained.consumption.as_mut())
                    .ok_or_else(|| failure(ServiceFailure::OperationConflict))?;
                if consumption.callback_entered {
                    return Err(failure(ServiceFailure::OperationConflict));
                }
                consumption.callback_entered = true;
            }
            record.dispatched = true;
            record.state = ExecutionState::Executing;
            self.owner.persist_record(&mut state, &self.key)?;
            Ok(())
        })?
    }
    /// The first real application entry owns the run clock. A resumed callback
    /// uses that same origin and the original execution deadline.
    pub(crate) fn execution_cap(&self, requested_cap: u64, duration_ms: u64) -> Result<u64> {
        self.account.with_security_time(|now| {
            let state = self.owner.state.lock().expect("execution history");
            if state.closed || state.persistence_failed || self.exited.load(Ordering::Acquire) {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let record = state
                .records
                .get(&self.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            original_execution_cap(
                record,
                requested_cap,
                duration_ms,
                now.lower_ms,
                now.upper_ms,
            )
        })?
    }
    pub(crate) fn original_stream_request(&self) -> Result<ApplicationHeader> {
        self.account.check()?;
        let state = self.owner.state.lock().expect("original stream request");
        if state.closed || state.persistence_failed || self.exited.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        let record = state
            .records
            .get(&self.key)
            .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
        let progress = record
            .stream_progress
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        progress.validate(
            &self.key,
            record.request,
            record.contract,
            record.deadline_ms,
            record.limit,
        )?;
        ApplicationHeader::decode(&progress.request_header)
    }
    pub(crate) fn original_response_limit(&self) -> Result<u32> {
        self.account.check()?;
        let state = self.owner.state.lock().expect("original response bound");
        if state.closed || state.persistence_failed || self.exited.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        Ok(state
            .records
            .get(&self.key)
            .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?
            .limit)
    }
    /// Persist cumulative output consumption before the item is handed to its
    /// original publisher. An uncertain publication does not refund the item.
    pub(crate) fn reserve_stream_item(
        &self,
        payload_bytes: u64,
        cap: u64,
        guard: impl Fn() -> Result<()>,
    ) -> Result<()> {
        if !self.created || self.exited.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        guard()?;
        self.account.with_security_time(|now| {
            if now.upper_ms >= cap {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            let mut state = self.owner.state.lock().expect("execution history");
            if state.closed || state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let record = state
                .records
                .get_mut(&self.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if !record.active
                || record.state != ExecutionState::Executing
                || !record.dispatched
                || record.error.is_some()
                || record.metadata_finished
                || record.cancel_requested
                || record.cancellation.is_cancelled()
                || self.exited.load(Ordering::Acquire)
            {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            if payload_bytes > u64::from(record.limit) {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            record
                .stream_progress
                .as_mut()
                .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?
                .reserve_item(payload_bytes)?;
            self.owner.persist_record(&mut state, &self.key)
        })?
    }
    pub(crate) fn finish(
        &self,
        payload: &[u8],
        application_error: Option<u32>,
        execution_cap: u64,
        guard: impl Fn() -> Result<()>,
    ) -> Result<()> {
        if !self.created || self.exited.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        guard()?;
        let changed = self.account.with_security_time(|now| {
            if now.upper_ms >= execution_cap {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            let mut state = self.owner.state.lock().expect("execution history");
            if state.closed {
                return Err(failure(ServiceFailure::Closed));
            }
            if state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let record = state
                .records
                .get_mut(&self.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            if !record.active
                || !record.dispatched
                || record.error.is_some()
                || record.state != ExecutionState::Executing
                || record.metadata_finished
                || record.result_until.is_some()
            {
                return Err(failure(ServiceFailure::ServiceFailed));
            }
            if record.shape == ServiceShape::Unary {
                if payload.len() > record.limit as usize {
                    return Err(failure(ServiceFailure::ResourceExhausted));
                }
                record.result_digest = Sha256::digest(payload).into();
                record.result_bytes = payload.len() as u32;
                if record.retention != 0 {
                    let until = now
                        .upper_ms
                        .checked_add(record.retention)
                        .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
                    let result = record
                        .result
                        .as_mut()
                        .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
                    result.extend_from_slice(payload);
                    record.result_until = Some(until);
                } else {
                    record.metadata_finished = true;
                }
            } else {
                if !payload.is_empty()
                    || record.shape == ServiceShape::Notify && application_error.is_some()
                {
                    return Err(failure(ServiceFailure::ContractMismatch));
                }
                record.metadata_finished = true;
            }
            record.application_error = application_error;
            record.state = if application_error.is_some() {
                ExecutionState::Failed
            } else {
                ExecutionState::Completed
            };
            let changed = record.changed.clone();
            self.owner.persist_record(&mut state, &self.key)?;
            Ok(changed)
        })??;
        changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn fail(&self, code: ServiceFailure) {
        let changed = {
            let mut state = self.owner.state.lock().expect("execution history");
            let Some(record) = state.records.get_mut(&self.key) else {
                return;
            };
            if record.metadata_finished
                || record.result_until.is_some()
                || record.state == ExecutionState::Completed
                || record.error.is_some()
            {
                return;
            }
            record.error = Some(code);
            record.state = if record.dispatched {
                ExecutionState::Unknown
            } else {
                ExecutionState::Failed
            };
            let changed = record.changed.clone();
            let _ = self.owner.persist_record(&mut state, &self.key);
            changed
        };
        changed.notify_waiters();
    }
    pub(crate) fn copy_result(&self, destination: &mut [u8]) -> Result<(usize, Option<u32>)> {
        self.account.with_security_time(|now| {
            let state = self.owner.state.lock().expect("execution history");
            if state.closed {
                return Err(failure(ServiceFailure::Closed));
            }
            if state.persistence_failed {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
            let record = state
                .records
                .get(&self.key)
                .ok_or_else(|| failure(ServiceFailure::HistoryUnknown))?;
            let (result, application_error) = retained_result(record, now.lower_ms, now.upper_ms)?;
            if destination.len() < result.len() {
                return Err(failure(ServiceFailure::ResourceExhausted));
            }
            destination[..result.len()].copy_from_slice(result);
            Ok((result.len(), application_error))
        })?
    }
    pub(crate) fn exit(&self) {
        if !self.created || self.exited.swap(true, Ordering::AcqRel) {
            return;
        }
        self.fail(ServiceFailure::ServiceFailed);
        let mut state = self.owner.state.lock().expect("execution history");
        if let Some(record) = state.records.get_mut(&self.key)
            && record.active
        {
            record.active = false;
            state.active -= 1;
        }
        let _ = self.owner.persist_record(&mut state, &self.key);
        drop(state);
        self.owner.collect_closed();
    }
}
/// Owns the actual callback lifetime independently of application-held context
/// clones. Retaining an invocation never retains dispatch or issuance authority.
pub(crate) struct ExecutionCallbackExit(Arc<ExecutionAttempt>);
impl ExecutionCallbackExit {
    pub(crate) fn new(attempt: Arc<ExecutionAttempt>) -> Self {
        Self(attempt)
    }
}
impl Drop for ExecutionCallbackExit {
    fn drop(&mut self) {
        self.0.exit();
    }
}

impl Drop for ExecutionAttempt {
    fn drop(&mut self) {
        self.exit();
        let mut state = self.owner.state.lock().expect("execution history");
        if let Some(record) = state.records.get_mut(&self.key) {
            record.holders -= 1;
        }
        drop(state);
        self.owner.collect_closed();
    }
}

struct HistoryWait {
    owner: Arc<HistoryOwner>,
    key: Key,
}
impl Drop for HistoryWait {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().expect("execution history");
        if let Some(record) = state.records.get_mut(&self.key) {
            record.holders -= 1;
        }
        drop(state);
        self.owner.collect_closed();
    }
}

#[cfg(test)]
mod retained_result_tests {
    use super::*;
    fn record() -> Record {
        Record {
            request: [1; 32],
            contract: [2; 32],
            cutoff: 2000,
            history_until: 10000,
            accepted_ms: 1000,
            deadline_ms: 3000,
            run_started_ms: Some(1000),
            retention: 1000,
            limit: 16,
            shape: ServiceShape::Unary,
            state: ExecutionState::Failed,
            cancel_mode: true,
            cancel_requested: false,
            active: false,
            dispatched: true,
            metadata_finished: false,
            error: None,
            result: Some(Zeroizing::new(vec![7, 8])),
            result_until: Some(4000),
            result_bytes: 2,
            result_digest: Sha256::digest([7, 8]).into(),
            application_error: Some(9),
            retained_checkpoint: None,
            stream_progress: None,
            resume_request: None,
            holders: 0,
            changed: Arc::new(Notify::new()),
            cancellation: CancellationToken::new(),
        }
    }
    fn active_attempt() -> (ExecutionService, Arc<ExecutionAttempt>, Key) {
        let root = crate::environment_v4::tests::environment();
        let account = root
            .admit([1; 32], crate::environment_v4::tests::bounds())
            .unwrap();
        let service = ExecutionService::create(
            root,
            ExecutionServiceOptions {
                tenant: "tenant".into(),
                audience: "service".into(),
                namespace: "example/files".into(),
                caller_authorities: vec![[1; 32]],
                max_records: 2,
                max_active: 1,
                result_bytes: 32,
            },
            None,
        )
        .unwrap();
        let key = Key {
            authority: [1; 32],
            subject: "client".into(),
            operation: [2; 32],
        };
        let mut original = record();
        original.active = true;
        original.holders = 1;
        original.state = ExecutionState::Executing;
        original.application_error = None;
        original.result_until = None;
        original.result = Some(Zeroizing::new(Vec::new()));
        {
            let mut state = service.0.state.lock().unwrap();
            state.records.insert(key.clone(), original);
            state.active = 1;
        }
        let attempt = Arc::new(ExecutionAttempt {
            owner: service.0.clone(),
            key: key.clone(),
            created: true,
            resumed: false,
            account,
            exited: AtomicBool::new(false),
        });
        (service, attempt, key)
    }
    #[test]
    fn callback_exit_releases_authority_even_while_the_application_retains_the_attempt() {
        let (service, attempt, key) = active_attempt();
        let application_retained = attempt.clone();
        let outcome: Result<()> = {
            let _callback_exit = ExecutionCallbackExit::new(attempt.clone());
            attempt.fail(ServiceFailure::Canceled);
            Err(failure(ServiceFailure::Canceled))
        };
        assert_eq!(outcome.unwrap_err().0, ServiceFailure::Canceled);
        assert!(application_retained.exited.load(Ordering::Acquire));
        assert_eq!(
            application_retained.enter(|| Ok(())).unwrap_err().0,
            ServiceFailure::ServiceUnavailable
        );
        let state = service.0.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert!(!state.records[&key].active);
        assert_eq!(state.records[&key].state, ExecutionState::Unknown);
        assert_eq!(state.records[&key].error, Some(ServiceFailure::Canceled));
        assert_eq!(state.records[&key].holders, 1);
    }
    #[tokio::test]
    async fn aborting_the_real_callback_future_releases_its_active_claim_despite_retained_context()
    {
        let (service, application_retained, key) = active_attempt();
        let callback_attempt = application_retained.clone();
        let (entered, observed) = tokio::sync::oneshot::channel();
        let callback = tokio::spawn(async move {
            let _callback_exit = ExecutionCallbackExit::new(callback_attempt);
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        observed.await.unwrap();
        callback.abort();
        assert!(callback.await.unwrap_err().is_cancelled());
        assert!(application_retained.exited.load(Ordering::Acquire));
        let state = service.0.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert!(!state.records[&key].active);
        assert_eq!(state.records[&key].state, ExecutionState::Unknown);
        assert_eq!(state.records[&key].holders, 1);
    }
    #[test]
    fn resumed_work_keeps_the_first_run_origin_and_original_deadline() {
        let mut original = record();
        original.run_started_ms = Some(1000);
        original.deadline_ms = 5000;
        assert_eq!(
            original_execution_cap(&original, 9000, 2000, 2500, 2510).unwrap(),
            3000
        );
        assert_eq!(
            original_execution_cap(&original, 2700, 2000, 2500, 2510).unwrap(),
            2700
        );
        assert_eq!(
            original_execution_cap(&original, 9000, 2000, 3000, 3000)
                .unwrap_err()
                .0,
            ServiceFailure::DeadlineExceeded
        );
        assert_eq!(
            original_execution_cap(&original, 9000, u64::MAX, 2500, 2510)
                .unwrap_err()
                .0,
            ServiceFailure::DeadlineExceeded
        );
    }
    #[test]
    fn cumulative_stream_limits_cannot_reset_or_wrap_after_recovery() {
        let mut progress = ExecutionStreamProgress {
            request_header: vec![],
            max_items: 3,
            max_bytes: 20,
            duration_ms: 1000,
            items: 2,
            bytes: 16,
        };
        progress.reserve_item(4).unwrap();
        assert_eq!((progress.items, progress.bytes), (3, 20));
        assert_eq!(
            progress.reserve_item(0).unwrap_err().0,
            ServiceFailure::ResourceExhausted
        );
        assert_eq!((progress.items, progress.bytes), (3, 20));
        progress.max_items = u64::MAX;
        progress.items = u64::MAX;
        assert_eq!(
            progress.reserve_item(0).unwrap_err().0,
            ServiceFailure::ResourceExhausted
        );
        progress.items = 0;
        progress.max_bytes = u64::MAX;
        progress.bytes = u64::MAX;
        assert_eq!(
            progress.reserve_item(1).unwrap_err().0,
            ServiceFailure::ResourceExhausted
        );
        assert_eq!((progress.items, progress.bytes), (0, u64::MAX));
    }
    #[test]
    fn declared_application_error_remains_readable_as_its_original_result() {
        let original = record();
        assert_eq!(
            retained_result(&original, 3000, 3000).unwrap(),
            (&[7, 8][..], Some(9))
        );
    }
    #[test]
    fn uncertain_expiry_is_unavailable_until_the_trusted_lower_bound_proves_expiry() {
        let original = record();
        assert_eq!(
            retained_result(&original, 3999, 4000).unwrap_err(),
            failure(ServiceFailure::ServiceUnavailable)
        );
        assert_eq!(
            retained_result(&original, 4000, 4000).unwrap_err(),
            failure(ServiceFailure::ResultExpired)
        );
    }
    #[test]
    fn original_sdk_failure_never_becomes_a_retained_application_result() {
        let mut original = record();
        original.state = ExecutionState::Unknown;
        original.error = Some(ServiceFailure::ServiceFailed);
        assert_eq!(
            retained_result(&original, 3000, 3000).unwrap_err(),
            failure(ServiceFailure::ServiceFailed)
        );
    }
}
