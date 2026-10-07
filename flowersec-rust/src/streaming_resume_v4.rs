//! Bounded continuation selectors retain original response identity and limits.
//! This state has no publication authority; a separately prepared Resume owns
//! the new operation and authenticates its checkpoint on the exact target.
use crate::{
    OperationReference, ServiceShape,
    environment_v4::{EnvironmentCharge, EnvironmentRoot, ResourceLimits},
    rpc_wire_v4::ApplicationHeader,
    service_contract::{ServiceError, ServiceFailure, StreamingLimits},
};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    version: u32,
    header: Vec<u8>,
    max_items: u32,
    max_bytes: u64,
    duration_ms: u64,
    completed_items: u32,
    completed_bytes: u64,
    original_until_ms: u64,
}
struct State {
    stored: StoredState,
    request: ApplicationHeader,
    reference: OperationReference,
    _charge: EnvironmentCharge,
}
#[derive(Clone)]
pub struct StreamingResumeState(Arc<State>);
impl fmt::Debug for StreamingResumeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamingResumeState { <opaque> }")
    }
}
impl StreamingResumeState {
    pub fn reference(&self) -> OperationReference {
        self.0.reference.clone()
    }
    /// Save beside the query-only operation reference and application checkpoint.
    pub fn export(&self, destination: &mut [u8]) -> Result<usize> {
        let encoded = serde_json::to_vec(&self.0.stored)
            .map_err(|_| failure(ServiceFailure::ContractMismatch))?;
        if encoded.len() > 4096 || encoded.len() > destination.len() {
            return Err(failure(ServiceFailure::ResourceExhausted));
        }
        destination[..encoded.len()].copy_from_slice(&encoded);
        Ok(encoded.len())
    }
    pub(crate) fn capture(
        root: &Arc<EnvironmentRoot>,
        request: ApplicationHeader,
        reference: OperationReference,
        limits: &StreamingLimits,
        completed_items: u32,
        completed_bytes: u64,
        original_until_ms: u64,
    ) -> Result<Self> {
        let mut header = vec![0; 512];
        let length = request.encode(&mut header)?;
        header.truncate(length);
        Self::from_stored(
            root,
            reference,
            StoredState {
                version: 1,
                header,
                max_items: limits.max_item_count,
                max_bytes: limits.max_payload_bytes,
                duration_ms: limits.max_duration_ms,
                completed_items,
                completed_bytes,
                original_until_ms,
            },
        )
    }
    fn from_stored(
        root: &Arc<EnvironmentRoot>,
        reference: OperationReference,
        stored: StoredState,
    ) -> Result<Self> {
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            ..ResourceLimits::default()
        })?;
        if stored.version != 1
            || stored.header.len() > 512
            || stored.max_items == 0
            || stored.max_bytes == 0
            || stored.duration_ms == 0
            || stored.completed_items > stored.max_items
            || stored.completed_bytes > stored.max_bytes
            || stored.original_until_ms == 0
            || stored.original_until_ms > reference.deadline_at_ms()
            || reference.shape() != ServiceShape::ServerStreaming
            || !reference.durable()
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let request = ApplicationHeader::decode(&stored.header)?;
        let target = reference.target();
        if request.kind() != "execution_stream_request"
            || request.bytes(1)? != target.operation_id
            || request.bytes(4)? != target.request_digest
            || request.bytes(6)? != target.contract_digest
            || request.uint(5)? != reference.deadline_at_ms()
            || request.uint(8)? == 0
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        Ok(Self(Arc::new(State {
            stored,
            request,
            reference,
            _charge: charge,
        })))
    }
    pub(crate) fn request(&self) -> ApplicationHeader {
        self.0.request.clone()
    }
    pub(crate) fn limits(&self) -> StreamingLimits {
        StreamingLimits {
            max_item_count: self.0.stored.max_items,
            max_payload_bytes: self.0.stored.max_bytes,
            max_duration_ms: self.0.stored.duration_ms,
        }
    }
    pub(crate) fn counters(&self) -> (u32, u64) {
        (self.0.stored.completed_items, self.0.stored.completed_bytes)
    }
    pub(crate) fn until_ms(&self) -> u64 {
        self.0.stored.original_until_ms
    }
}
impl crate::TransportEnvironment {
    /// Import only bounded selectors. Start requires a new independently
    /// authenticated checkpoint and its separately captured accepted target.
    pub fn import_streaming_resume_state(
        &self,
        encoded: &[u8],
        reference: OperationReference,
    ) -> Result<StreamingResumeState> {
        if encoded.len() > 4096 {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let stored = serde_json::from_slice(encoded)
            .map_err(|_| failure(ServiceFailure::ContractMismatch))?;
        StreamingResumeState::from_stored(self.root(), reference, stored)
    }
}
pub(crate) trait ResumeContinuationOwner: Send + Sync {
    fn request(&self) -> ApplicationHeader;
    fn activate(&self) -> Result<()>;
    fn refuse(&self, error: ServiceError);
}
/// One ordinary Resume handle plus one continuation prepared before Start.
/// Closing the Resume result after accepted handoff leaves the continuation
/// owned by this object until it is taken or explicitly abandoned.
pub struct StreamingResumeOperation<T> {
    pub operation: crate::UnaryOperation<crate::ApplicationResumeResult>,
    pub(crate) continuation: crate::StreamingOperation<T>,
}
impl<T: Send + 'static> StreamingResumeOperation<T> {
    pub fn start(&self) -> Result<()> {
        self.operation.start()
    }
    pub fn try_start(&self) -> Result<crate::ServiceStartResult> {
        self.operation.try_start()
    }
    pub fn take_continuation(&self) -> Result<crate::StreamingOperation<T>> {
        if !self.continuation.progress().started {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        Ok(self.continuation.clone())
    }
}
impl<T> fmt::Debug for StreamingResumeOperation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamingResumeOperation { <opaque> }")
    }
}
