//! One original ordered RPC channel with finite live message associations and
//! one publisher. Waiting futures never own the actual provider completion.
use crate::{
    api_v4::{CleanupStatus, WriteOperation},
    crypto_v4::Stream,
    environment_v4::{BusinessActivity, ResourceAccount, ResourceCharge, ResourceLimits},
    rpc_wire_v4::{ApplicationHeader, Fragment, FragmentKind, MessageInput},
    service_contract::{ServiceError, ServiceFailure},
    transport::{ByteStream, SessionError},
};
use bytes::Bytes;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, ServiceError>;
pub(crate) type BeginAdmissionGate = crate::api_v4::FirstByteGate;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn transport(error: SessionError) -> ServiceError {
    failure(match error {
        SessionError::ResourceExhausted => ServiceFailure::ResourceExhausted,
        SessionError::Timeout => ServiceFailure::DeadlineExceeded,
        SessionError::Closed => ServiceFailure::Closed,
        _ => ServiceFailure::ServiceUnavailable,
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationFact {
    NotSubmitted,
    Aborted,
    Committed,
    Unknown,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicationReceipt {
    pub(crate) fact: PublicationFact,
    pub(crate) error: Option<ServiceFailure>,
}
struct Input {
    diagnostics: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
    association: MessageInput,
    payload: Zeroizing<Vec<u8>>,
    slot: MessageSlot,
    stop: Arc<StopOwner>,
    reply_queue: Option<mpsc::OwnedPermit<Output>>,
}
struct IncomingState {
    highwater: u64,
    live: BTreeMap<u64, Input>,
    closed: bool,
}
struct PendingResponse {
    request: ApplicationHeader,
    completion: Option<oneshot::Sender<Result<IncomingMessage>>>,
    _slot: Option<MessageSlot>,
    response_charge: Option<ResourceCharge>,
    stop_charge: Option<ResourceCharge>,
    prepaid_response: bool,
}
struct OutgoingState {
    highwater: u64,
    sealed: bool,
    pending: BTreeMap<u64, PendingResponse>,
}
struct Core {
    stream: Mutex<Option<Arc<Stream>>>,
    account: ResourceAccount,
    limits: ChannelLimits,
    input: Mutex<IncomingState>,
    outgoing: Mutex<OutgoingState>,
    slots: AtomicUsize,
    shared_slots: Mutex<Option<Arc<AtomicUsize>>>,
    workers: AtomicUsize,
    cancel: CancellationToken,
    changed: Notify,
    charge: Mutex<Option<Arc<ResourceCharge>>>,
    tail: crate::application_tails_v4::ApplicationTail,
    output: mpsc::Sender<Output>,
    stops: Mutex<BTreeMap<u64, Weak<StopOwner>>>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChannelLimits {
    pub(crate) max_messages: usize,
    pub(crate) max_payload_bytes: usize,
    pub(crate) result_read_bytes: usize,
}
impl ChannelLimits {
    pub(crate) fn charge(self) -> Result<ResourceLimits> {
        if self.max_messages == 0
            || self.max_messages > 2052
            || self.max_payload_bytes > 1 << 20
            || self.result_read_bytes > 1 << 20
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(ResourceLimits {
            sdk_bytes: 65536 + self.max_messages as u64 * 1024,
            items: self.max_messages as u64 * 3 + 8,
            work_slots: 2,
            tasks: 2,
            ..ResourceLimits::default()
        })
    }
}
struct MessageSlot {
    core: Weak<Core>,
    _charge: ResourceCharge,
    _tail: crate::application_tails_v4::ApplicationTail,
    _business: Option<BusinessActivity>,
}
impl Drop for MessageSlot {
    fn drop(&mut self) {
        if let Some(core) = self.core.upgrade() {
            core.slots.fetch_sub(1, Ordering::AcqRel);
            if let Some(shared) = core
                .shared_slots
                .lock()
                .expect("RPC shared messages")
                .as_ref()
            {
                shared.fetch_sub(1, Ordering::AcqRel);
            }
            core.changed.notify_waiters();
        }
    }
}
struct StopOwner {
    core: Weak<Core>,
    serial: u64,
    cancellation: CancellationToken,
}
impl Drop for StopOwner {
    fn drop(&mut self) {
        if let Some(core) = self.core.upgrade() {
            core.stops
                .lock()
                .expect("RPC output interests")
                .remove(&self.serial);
        }
    }
}
#[derive(Clone)]
pub(crate) struct ChannelPreparation {
    charge: Arc<ResourceCharge>,
    tail: Arc<ResourceCharge>,
    reader: Arc<ResourceCharge>,
    reader_wait: Arc<ResourceCharge>,
}
impl ChannelPreparation {
    pub(crate) fn preparation_limits(limits: ChannelLimits) -> Result<ResourceLimits> {
        let resources = crate::crypto_v4::connect::candidate_add_limits(
            limits.charge()?,
            crate::application_tails_v4::ApplicationTails::resources(),
        )?;
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            resources,
            Self::reader_limits()?,
        )?)
    }
    fn reader_limits() -> Result<ResourceLimits> {
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            ResourceLimits {
                sdk_bytes: 16384,
                ..ResourceLimits::default()
            },
            Stream::message_wait_limits(),
        )?)
    }
    pub(crate) fn new_prepaid(
        account: &ResourceAccount,
        limits: ChannelLimits,
        mut backing: ResourceCharge,
    ) -> Result<Self> {
        if !backing.matches(account, Self::preparation_limits(limits)?) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let mut reader = backing.split(Self::reader_limits()?)?;
        let reader_wait = Arc::new(reader.split(Stream::message_wait_limits())?);
        Ok(Self {
            charge: Arc::new(backing.split(limits.charge()?)?),
            reader: Arc::new(reader),
            reader_wait,
            tail: Arc::new(backing),
        })
    }
}
pub(crate) struct IncomingMessage {
    diagnostics: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
    pub(crate) serial: u64,
    pub(crate) reply_to: u64,
    pub(crate) header: ApplicationHeader,
    pub(crate) payload: Zeroizing<Vec<u8>>,
    pub(crate) aborted: bool,
    pub(crate) admitted: bool,
    pub(crate) completed_at_upper_ms: u64,
    stop: Arc<StopOwner>,
    _slot: MessageSlot,
    reply_queue: Option<mpsc::OwnedPermit<Output>>,
}
impl IncomingMessage {
    /// Move complete input into a finite callback tail. The original reply
    /// reservation retains only a weak channel reference and resource ancestry.
    pub(crate) fn into_request(self) -> RequestInput {
        let Self {
            diagnostics,
            serial,
            reply_to: _,
            header,
            payload,
            aborted,
            admitted: _,
            completed_at_upper_ms: _,
            stop,
            _slot,
            reply_queue,
        } = self;
        RequestInput {
            header: header.clone(),
            payload,
            aborted,
            reply: ReplySlot {
                diagnostics,
                serial,
                request: header,
                stop,
                slot: _slot,
                queue: reply_queue,
            },
        }
    }
}
pub(crate) struct RequestInput {
    pub(crate) header: ApplicationHeader,
    pub(crate) payload: Zeroizing<Vec<u8>>,
    pub(crate) aborted: bool,
    pub(crate) reply: ReplySlot,
}
pub(crate) struct ReplySlot {
    diagnostics: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
    serial: u64,
    request: ApplicationHeader,
    stop: Arc<StopOwner>,
    slot: MessageSlot,
    queue: Option<mpsc::OwnedPermit<Output>>,
}
impl ReplySlot {
    pub(crate) fn request(&self) -> &ApplicationHeader {
        &self.request
    }
    pub(crate) fn publication_binding(&self) -> (u64, u64) {
        (
            self.serial,
            self.slot.core.upgrade().map_or(0, |core| {
                core.stream
                    .lock()
                    .expect("original RPC stream")
                    .as_ref()
                    .map_or(0, |stream| stream.internal_publication_generation())
            }),
        )
    }
}
impl fmt::Debug for IncomingMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IncomingRPCMessage { <opaque> }")
    }
}
struct Output {
    diagnostics: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
    serial: u64,
    header: ApplicationHeader,
    payload: Zeroizing<Vec<u8>>,
    guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    cancellation: CancellationToken,
    completion: oneshot::Sender<PublicationReceipt>,
    publication: PreparedPublication,
    _slot: MessageSlot,
    _interest: Option<Arc<StopOwner>>,
    control: Option<FragmentKind>,
}
pub(crate) struct PublishedMessage {
    pub(crate) serial: u64,
    pub(crate) origin: PublicationOrigin,
    pub(crate) publication: oneshot::Receiver<PublicationReceipt>,
    pub(crate) response: Option<oneshot::Receiver<Result<IncomingMessage>>>,
}
#[derive(Clone)]
pub(crate) struct PublicationOrigin(Arc<Core>);
/// A complete original RPC publication admission. It owns the message and
/// response slots before the application observes Start; serial assignment is
/// deliberately deferred until the ordered publisher accepts this value.
pub(crate) struct PreparedSend {
    core: Arc<Core>,
    header: ApplicationHeader,
    payload: Zeroizing<Vec<u8>>,
    cancellation: CancellationToken,
    guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    slot: Option<MessageSlot>,
    call_slot: Option<MessageSlot>,
    queue: mpsc::OwnedPermit<Output>,
    publication: PreparedPublication,
    response_charge: Option<ResourceCharge>,
    stop_charge: Option<ResourceCharge>,
}
impl fmt::Debug for PreparedSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedSend { <opaque> }")
    }
}
/// One controller contract query's bounded transport resources. The original
/// associations retain response and cancellation backing until they retire.
pub(crate) struct QuerySendPreparation {
    slot: ResourceCharge,
    call_slot: ResourceCharge,
    response: ResourceCharge,
    publication: ResourceCharge,
    stop: ResourceCharge,
}
impl QuerySendPreparation {
    const PAYLOAD: usize = 2048;
    const RESPONSE: usize = 73728;
    pub(crate) fn preparation_limits() -> Result<ResourceLimits> {
        let mut limits = Core::slot_limits(Self::PAYLOAD)?;
        limits = crate::crypto_v4::connect::candidate_add_limits(limits, Core::slot_limits(0)?)?;
        limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            Core::slot_limits(Self::RESPONSE)?,
        )?;
        limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            PreparedPublication::query_limits(false)?,
        )?;
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            limits,
            PreparedPublication::query_limits(true)?,
        )?)
    }
    pub(crate) fn new_prepaid(
        account: &ResourceAccount,
        mut charge: ResourceCharge,
    ) -> Result<Self> {
        if !charge.matches(account, Self::preparation_limits()?) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(Self {
            slot: charge.split(Core::slot_limits(Self::PAYLOAD)?)?,
            call_slot: charge.split(Core::slot_limits(0)?)?,
            response: charge.split(Core::slot_limits(Self::RESPONSE)?)?,
            publication: charge.split(PreparedPublication::query_limits(false)?)?,
            stop: charge.split(PreparedPublication::query_limits(true)?)?,
        })
    }
}
/// Prepaid fragment owners all delegate to the same original Stream and its
/// staging owner. No sender, provider, timer or staging claim is made by Start.
struct PreparedPublication {
    serial: Arc<AtomicU64>,
    abort_offset: Arc<AtomicU64>,
    fragments: Vec<WriteOperation>,
    abort: Option<WriteOperation>,
    _admission: Option<crate::crypto_v4::StreamPublicationAdmission>,
    _charge: Option<ResourceCharge>,
}
struct PreparedPublicationParts {
    _serial: Arc<AtomicU64>,
    abort_offset: Arc<AtomicU64>,
    fragments: Vec<WriteOperation>,
    abort: Option<WriteOperation>,
    _admission: Option<crate::crypto_v4::StreamPublicationAdmission>,
    _charge: ResourceCharge,
}
impl Drop for PreparedPublication {
    fn drop(&mut self) {
        for fragment in &self.fragments {
            fragment.cancel();
        }
        if let Some(abort) = &self.abort {
            abort.cancel();
        }
    }
}
struct OriginalFragmentPublisher {
    stream: Arc<Stream>,
    serial: Arc<AtomicU64>,
    offset: Option<Arc<AtomicU64>>,
    wire: Mutex<Option<Zeroizing<Vec<u8>>>>,
    wait: Mutex<Option<ResourceCharge>>,
    handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    _charge: ResourceCharge,
}
impl fmt::Debug for OriginalFragmentPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalFragmentPublisher { <opaque> }")
    }
}
#[async_trait::async_trait]
impl ByteStream for OriginalFragmentPublisher {
    #[cfg(test)]
    fn internal_test_id(&self) -> u64 {
        self.stream.internal_test_id()
    }
    fn kind(&self) -> &str {
        "flowersec.v4.rpc-publication"
    }
    fn terminal_error(&self) -> Option<SessionError> {
        self.stream.terminal_error()
    }
    fn write_staging_owner(&self) -> Option<Arc<crate::api_v4::WriteStagingOwner>> {
        self.stream.write_staging_owner()
    }
    async fn read(&self) -> std::result::Result<Option<Bytes>, SessionError> {
        Err(SessionError::OperationFailed)
    }
    async fn write(&self, _: Bytes) -> std::result::Result<usize, SessionError> {
        Err(SessionError::OperationFailed)
    }
    async fn write_prepared(
        &self,
        payload: Bytes,
        admission: &crate::api_v4::WriteRequestAdmission,
    ) -> std::result::Result<(), SessionError> {
        let mut wire = self
            .wire
            .lock()
            .expect("original RPC fragment")
            .take()
            .ok_or(SessionError::OperationFailed)?;
        if wire.len() != payload.len() {
            return Err(SessionError::OperationFailed);
        }
        let serial = self.serial.load(Ordering::Acquire);
        if serial == 0 {
            return Err(SessionError::OperationFailed);
        }
        wire[5..13].copy_from_slice(&serial.to_be_bytes());
        if let Some(offset) = &self.offset {
            let offset = u32::try_from(offset.load(Ordering::Acquire))
                .map_err(|_| SessionError::OperationFailed)?;
            wire[13..17].copy_from_slice(&offset.to_be_bytes());
        }
        let wait = self
            .wait
            .lock()
            .expect("original RPC sender wait")
            .take()
            .ok_or(SessionError::OperationFailed)?;
        // Keep the original zeroizing buffer until its native write finishes.
        // The exact snapshot is separately covered by the publisher charge.
        self.stream
            .write_message_prepared(
                Bytes::copy_from_slice(&wire),
                admission,
                wait,
                self.handoff.clone(),
            )
            .await
    }
    async fn close_write(&self) -> std::result::Result<(), SessionError> {
        Err(SessionError::OperationFailed)
    }
    async fn reset(&self) -> std::result::Result<(), SessionError> {
        Err(SessionError::OperationFailed)
    }
    async fn close(&self) -> std::result::Result<(), SessionError> {
        Err(SessionError::OperationFailed)
    }
}
impl PreparedPublication {
    fn into_parts(mut self) -> PreparedPublicationParts {
        // Empty the Drop owner before returning its resources. Its destructor
        // then observes only inert replacements and cannot cancel transferred
        // operations or release the transferred charge a second time.
        PreparedPublicationParts {
            _serial: std::mem::replace(&mut self.serial, Arc::new(AtomicU64::new(0))),
            abort_offset: std::mem::replace(&mut self.abort_offset, Arc::new(AtomicU64::new(0))),
            fragments: std::mem::take(&mut self.fragments),
            abort: self.abort.take(),
            _admission: self._admission.take(),
            _charge: self._charge.take().expect("prepared publication charge"),
        }
    }
    fn fragment_limits(size: usize) -> Result<ResourceLimits> {
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            ResourceLimits {
                sdk_bytes: (size * 2 + 256) as u64,
                items: 1,
                ..ResourceLimits::default()
            },
            Stream::message_wait_limits(),
        )?;
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            limits,
            WriteOperation::preparation_limits(size).map_err(transport)?,
        )?)
    }
    fn query_limits(control: bool) -> Result<ResourceLimits> {
        let mut limits = ResourceLimits {
            sdk_bytes: if control { 512 } else { 768 },
            items: if control { 2 } else { 3 },
            ..ResourceLimits::default()
        };
        if !control {
            limits = crate::crypto_v4::connect::candidate_add_limits(
                limits,
                Self::fragment_limits(512 + 23)?,
            )?;
            limits = crate::crypto_v4::connect::candidate_add_limits(
                limits,
                Self::fragment_limits(QuerySendPreparation::PAYLOAD + 17)?,
            )?;
        }
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            limits,
            Self::fragment_limits(17)?,
        )?)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "RPC publication transfers separately reserved backing, cancellation and first-byte authority to one sender."
    )]
    fn prepare_with_backing(
        core: &Arc<Core>,
        header: &ApplicationHeader,
        payload: &[u8],
        reply_to: u64,
        control: Option<FragmentKind>,
        cancellation: &CancellationToken,
        mut prepaid: Option<ResourceCharge>,
        begin_gate: Option<BeginAdmissionGate>,
        handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<Self> {
        if let Some(charge) = &prepaid
            && (payload.len() > QuerySendPreparation::PAYLOAD
                || !charge.matches(&core.account, Self::query_limits(control.is_some())?))
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let stream = core
            .stream
            .lock()
            .expect("original RPC stream")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let count = if control.is_some() {
            1
        } else {
            1 + payload.len().div_ceil(16367)
        };
        let limits = ResourceLimits {
            sdk_bytes: (count + 1) as u64 * 256,
            items: (count + 1) as u64,
            ..ResourceLimits::default()
        };
        let charge = if let Some(backing) = &mut prepaid {
            backing.split(limits)?
        } else {
            core.account.reserve(limits)?
        };
        let mut fragments = Vec::new();
        fragments
            .try_reserve_exact(count)
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        let try_now = control.is_none()
            && header.kind().ends_with("_request")
            && header.has(7)
            && header.uint(7)? == 1;
        let admission = if try_now {
            let mut header_wire = [0u8; 512];
            let size = header.encode(&mut header_wire)?;
            // Credit covers the complete original publication, including each
            // fragment envelope. Native sender admission still claims one
            // bounded record from that same publisher.
            let publication_bytes = payload
                .len()
                .checked_add(size + 23)
                .and_then(|bytes| {
                    (count - 1)
                        .checked_mul(17)
                        .and_then(|overhead| bytes.checked_add(overhead))
                })
                .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
            Some(
                stream
                    .try_admit_rpc_publication(publication_bytes)
                    .map_err(transport)?,
            )
        } else {
            None
        };
        let mut preparation = Self {
            serial: Arc::new(AtomicU64::new(0)),
            abort_offset: Arc::new(AtomicU64::new(0)),
            fragments,
            abort: None,
            _admission: admission,
            _charge: Some(charge),
        };
        let mut scratch = [0u8; 16384];
        let mut encoded_header = [0u8; 512];
        if let Some(control) = control {
            let fragment = Fragment {
                kind: control,
                serial: 1,
                reply_to: 0,
                offset: 0,
                bytes: &[],
            };
            let operation = preparation.fragment(
                core,
                &stream,
                fragment,
                &mut scratch,
                None,
                None,
                &mut prepaid,
                None,
            )?;
            preparation.fragments.push(operation);
        } else {
            let size = header.encode(&mut encoded_header)?;
            let business_guard = {
                let canceled = cancellation.clone();
                let closed = core.cancel.clone();
                let cap = header.has(5).then(|| header.uint(5)).transpose()?;
                Arc::new(move |now: crate::environment_v4::TrustedTimeSample| {
                    // WriteRequestAdmission holds the original request deadline.
                    // Response headers intentionally omit field 5; their outer
                    // reply guard carries the request's fixed deadline.
                    if canceled.is_cancelled() || closed.is_cancelled() {
                        return Err(SessionError::Canceled);
                    }
                    if cap.is_some_and(|cap| now.upper_ms >= cap) {
                        return Err(SessionError::Timeout);
                    }
                    Ok(())
                }) as crate::api_v4::FirstByteGate
            };
            // This callback runs at the native first-byte acceptance boundary,
            // after ordered responsibility exists. It must only inspect scalars.
            let begin_guard = {
                let business_guard = business_guard.clone();
                Arc::new(move |now| {
                    business_guard(now)?;
                    if let Some(gate) = &begin_gate {
                        gate(now)?;
                    }
                    Ok(())
                }) as crate::api_v4::FirstByteGate
            };
            let operation = preparation.fragment(
                core,
                &stream,
                Fragment {
                    kind: FragmentKind::Begin,
                    serial: 1,
                    reply_to,
                    offset: 0,
                    bytes: &encoded_header[..size],
                },
                &mut scratch,
                None,
                Some(begin_guard),
                &mut prepaid,
                payload.is_empty().then(|| handoff.clone()).flatten(),
            )?;
            preparation.fragments.push(operation);
            let mut offset = 0u32;
            for chunk in payload.chunks(16367) {
                let operation = preparation.fragment(
                    core,
                    &stream,
                    Fragment {
                        kind: FragmentKind::Data,
                        serial: 1,
                        reply_to: 0,
                        offset,
                        bytes: chunk,
                    },
                    &mut scratch,
                    None,
                    Some(business_guard.clone()),
                    &mut prepaid,
                    (offset as usize + chunk.len() == payload.len())
                        .then(|| handoff.clone())
                        .flatten(),
                )?;
                preparation.fragments.push(operation);
                offset += chunk.len() as u32;
            }
            preparation.abort = Some(preparation.fragment(
                core,
                &stream,
                Fragment {
                    kind: FragmentKind::Abort,
                    serial: 1,
                    reply_to: 0,
                    offset: 0,
                    bytes: &[],
                },
                &mut scratch,
                Some(preparation.abort_offset.clone()),
                None,
                &mut prepaid,
                None,
            )?);
        }
        encoded_header.fill(0);
        scratch.fill(0);
        Ok(preparation)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "RPC publication transfers separately reserved backing, cancellation and first-byte authority to one sender."
    )]
    fn fragment(
        &self,
        core: &Arc<Core>,
        stream: &Arc<Stream>,
        fragment: Fragment<'_>,
        scratch: &mut [u8],
        offset: Option<Arc<AtomicU64>>,
        gate: Option<crate::api_v4::FirstByteGate>,
        prepaid: &mut Option<ResourceCharge>,
        handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<WriteOperation> {
        let size = fragment.encode(scratch)?;
        let limits = ResourceLimits {
            sdk_bytes: (size * 2 + 256) as u64,
            items: 1,
            ..ResourceLimits::default()
        };
        let (charge, wait, staging) = if let Some(backing) = prepaid {
            (
                backing.split(limits)?,
                stream
                    .prepare_message_wait_prepaid(backing.split(Stream::message_wait_limits())?)
                    .map_err(transport)?,
                Some(backing.split(WriteOperation::preparation_limits(size).map_err(transport)?)?),
            )
        } else {
            (
                core.account.reserve(limits)?,
                stream.prepare_message_wait().map_err(transport)?,
                None,
            )
        };
        let mut wire = Zeroizing::new(Vec::new());
        wire.try_reserve_exact(size)
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        wire.extend_from_slice(&scratch[..size]);
        let publisher: Arc<dyn ByteStream> = Arc::new(OriginalFragmentPublisher {
            stream: stream.clone(),
            serial: self.serial.clone(),
            offset,
            wire: Mutex::new(Some(wire)),
            wait: Mutex::new(Some(wait)),
            handoff,
            _charge: charge,
        });
        if let Some(charge) = staging {
            WriteOperation::try_prepare_guarded_prepaid(
                publisher,
                Bytes::copy_from_slice(&scratch[..size]),
                gate,
                charge,
            )
            .map_err(transport)
        } else {
            WriteOperation::try_prepare_guarded(
                publisher,
                Bytes::copy_from_slice(&scratch[..size]),
                gate,
            )
            .map_err(transport)
        }
    }
}
/// One original general-RPC position, retained by a dedicated Stream until
/// its last FIN/error and actual physical tails retire.
pub(crate) struct StreamAssociation {
    _slot: MessageSlot,
}
pub(crate) struct RPCChannel {
    core: Arc<Core>,
    lanes: Mutex<Option<Arc<ChannelSet>>>,
    incoming: mpsc::Sender<IncomingMessage>,
    owns_core: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RPCChannelClass {
    #[default]
    Interactive,
    Bulk,
}
impl RPCChannelClass {
    fn index(self) -> usize {
        usize::from(self == Self::Bulk)
    }
}
struct LaneBacking {
    channel: ChannelPreparation,
    stream: Arc<ResourceCharge>,
    opening: Option<Arc<ResourceCharge>>,
}
struct LaneEntry {
    core: Arc<Core>,
    class: RPCChannelClass,
    local: bool,
    backing: Option<usize>,
}
struct LaneState {
    entries: Vec<LaneEntry>,
    free: Vec<usize>,
    wanted: [bool; 2],
    closed: bool,
}
struct ChannelSet {
    session: crate::crypto_v4::SessionLink,
    account: ResourceAccount,
    limits: ChannelLimits,
    incoming: mpsc::Sender<IncomingMessage>,
    state: Mutex<LaneState>,
    backing: Vec<LaneBacking>,
    cancellation: CancellationToken,
    changed: Notify,
    workers: AtomicUsize,
    shared_slots: Arc<AtomicUsize>,
    _charge: ResourceCharge,
    wait: Arc<ResourceCharge>,
    tail: crate::application_tails_v4::ApplicationTail,
}
pub(crate) struct ChannelSetPreparation {
    backing: Vec<LaneBacking>,
    charge: ResourceCharge,
    wait: Arc<ResourceCharge>,
    tail: ResourceCharge,
}
impl ChannelSetPreparation {
    pub(crate) fn limits(limits: ChannelLimits) -> Result<ResourceLimits> {
        let mut total = ResourceLimits {
            sdk_bytes: 8192,
            items: 9,
            tasks: 2,
            work_slots: 2,
            ..ResourceLimits::default()
        };
        total = crate::crypto_v4::connect::candidate_add_limits(
            total,
            ResourceLimits {
                sdk_bytes: 8192,
                items: 1,
                tasks: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            },
        )?;
        total = crate::crypto_v4::connect::candidate_add_limits(
            total,
            crate::application_tails_v4::ApplicationTails::resources(),
        )?;
        for _ in 0..7 {
            total = crate::crypto_v4::connect::candidate_add_limits(
                total,
                ChannelPreparation::preparation_limits(limits)?,
            )?;
            total = crate::crypto_v4::connect::candidate_add_limits(
                total,
                crate::crypto_v4::StreamPreparation::preparation_limits(),
            )?;
            total = crate::crypto_v4::connect::candidate_add_limits(
                total,
                ResourceLimits {
                    sdk_bytes: 256,
                    items: 1,
                    tasks: 1,
                    work_slots: 1,
                    ..ResourceLimits::default()
                },
            )?;
        }
        Ok(total)
    }
    pub(crate) fn new(
        account: &ResourceAccount,
        limits: ChannelLimits,
        mut prepaid: ResourceCharge,
    ) -> Result<Self> {
        if !prepaid.matches(account, Self::limits(limits)?) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let charge = prepaid.split(ResourceLimits {
            sdk_bytes: 8192,
            items: 9,
            tasks: 2,
            work_slots: 2,
            ..ResourceLimits::default()
        })?;
        let wait = Arc::new(prepaid.split(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            tasks: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?);
        let mut backing = Vec::with_capacity(7);
        for _ in 0..7 {
            backing.push(LaneBacking {
                channel: ChannelPreparation::new_prepaid(
                    account,
                    limits,
                    prepaid.split(ChannelPreparation::preparation_limits(limits)?)?,
                )?,
                stream: Arc::new(
                    prepaid.split(crate::crypto_v4::StreamPreparation::preparation_limits())?,
                ),
                opening: Some(Arc::new(prepaid.split(ResourceLimits {
                    sdk_bytes: 256,
                    items: 1,
                    tasks: 1,
                    work_slots: 1,
                    ..ResourceLimits::default()
                })?)),
            });
        }
        Ok(Self {
            backing,
            charge,
            wait,
            tail: prepaid,
        })
    }
}
impl ChannelSet {
    fn retire(state: &mut LaneState) {
        let mut i = 0;
        while i < state.entries.len() {
            let entry = &state.entries[i];
            if entry.backing.is_some()
                && entry.core.workers.load(Ordering::Acquire) == 0
                && entry.core.slots.load(Ordering::Acquire) == 0
            {
                let entry = state.entries.remove(i);
                state
                    .free
                    .push(entry.backing.expect("dynamic lane backing"));
            } else {
                i += 1;
            }
        }
    }
    fn select(&self, class: RPCChannelClass) -> Option<Arc<Core>> {
        let mut state = self.state.lock().expect("RPC lane registry");
        Self::retire(&mut state);
        if state.closed {
            return None;
        }
        let selected = state
            .entries
            .iter()
            .filter(|entry| {
                entry.class == class
                    && !entry.core.cancel.is_cancelled()
                    && entry.core.slots.load(Ordering::Acquire) < self.limits.max_messages
            })
            .min_by_key(|entry| entry.core.slots.load(Ordering::Acquire))
            .map(|entry| entry.core.clone());
        let local = state
            .entries
            .iter()
            .filter(|entry| entry.local && entry.class == class)
            .count();
        if selected
            .as_ref()
            .is_none_or(|core| core.slots.load(Ordering::Acquire) >= 2)
            && local < 2
        {
            state.wanted[class.index()] = true;
            self.changed.notify_waiters();
        }
        selected
    }
    fn close(&self) {
        let cores = {
            let mut state = self.state.lock().expect("RPC lane registry");
            state.closed = true;
            state
                .entries
                .iter()
                .map(|entry| entry.core.clone())
                .collect::<Vec<_>>()
        };
        self.cancellation.cancel();
        for core in cores {
            core.seal();
        }
        self.changed.notify_waiters();
    }
    fn status(&self) -> CleanupStatus {
        let state = self.state.lock().expect("RPC lane registry");
        let workers = self.workers.load(Ordering::Acquire) as u64
            + state
                .entries
                .iter()
                .map(|entry| entry.core.workers.load(Ordering::Acquire) as u64)
                .sum::<u64>();
        let slots = state
            .entries
            .iter()
            .map(|entry| entry.core.slots.load(Ordering::Acquire))
            .sum::<usize>();
        CleanupStatus {
            complete: workers == 0 && slots == 0,
            cleanup_incomplete: workers != 0 || slots != 0,
            pending_callbacks: workers,
        }
    }
    async fn receive(self: Arc<Self>) {
        loop {
            let session = match self.session.session() {
                Ok(session) => session,
                Err(_) => break,
            };
            let request = tokio::select! { _ = self.cancellation.cancelled() => break,
            request = session.next_rpc_open_shared(self.wait.clone()) => match request { Ok(request) => request, Err(_) => break } };
            let fields = request.metadata().byte_values();
            let class = match (
                request.metadata().namespace(),
                request.metadata().version(),
                fields.get("class").map(|value| value.as_ref()),
                fields.len(),
            ) {
                (Some("sdk.flowersec/rpc"), Some(1), Some(b"interactive"), 1) => {
                    RPCChannelClass::Interactive
                }
                (Some("sdk.flowersec/rpc"), Some(1), Some(b"bulk"), 1) => RPCChannelClass::Bulk,
                _ => {
                    let _ = request.reject();
                    continue;
                }
            };
            let index = {
                let mut state = self.state.lock().expect("RPC lane registry");
                Self::retire(&mut state);
                if state
                    .entries
                    .iter()
                    .filter(|entry| !entry.local && entry.class == class)
                    .count()
                    >= 2
                {
                    None
                } else {
                    state.free.pop()
                }
            };
            let Some(index) = index else {
                let _ = request.reject();
                continue;
            };
            let result: Result<Arc<Core>> = (|| {
                let backing = &self.backing[index];
                let prepared = crate::crypto_v4::StreamPreparation::new_shared(
                    self.account.clone(),
                    backing.stream.clone(),
                )
                .map_err(transport)?;
                let stream = request
                    .prepare_stream_reserved(prepared)
                    .map_err(transport)?;
                let core = RPCChannel::new_core(
                    Arc::new(stream.clone()),
                    self.account.clone(),
                    self.limits,
                    backing.channel.clone(),
                    self.incoming.clone(),
                    Some(self.shared_slots.clone()),
                )?;
                if request.accept_prepared(stream, 16384).is_err() {
                    core.seal();
                }
                Ok(core)
            })();
            match result {
                Ok(core) => {
                    let mut state = self.state.lock().expect("RPC lane registry");
                    if state.closed {
                        core.seal();
                    }
                    state.entries.push(LaneEntry {
                        core,
                        class,
                        local: false,
                        backing: Some(index),
                    });
                }
                Err(_) => {
                    self.state
                        .lock()
                        .expect("RPC lane registry")
                        .free
                        .push(index);
                }
            }
            self.changed.notify_waiters();
        }
        self.close();
        self.worker_exited();
    }
    async fn open(self: Arc<Self>) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.cancellation.is_cancelled() {
                break;
            }
            let choice = {
                let mut state = self.state.lock().expect("RPC lane registry");
                Self::retire(&mut state);
                (0..2)
                    .find(|class| {
                        state.wanted[*class]
                            && state
                                .entries
                                .iter()
                                .filter(|entry| entry.local && entry.class.index() == *class)
                                .count()
                                < 2
                    })
                    .and_then(|class| {
                        state.free.pop().map(|index| {
                            state.wanted[class] = false;
                            (class, index)
                        })
                    })
            };
            let Some((class, index)) = choice else {
                tokio::select! { _ = self.cancellation.cancelled() => break, _ = changed => {}, _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {} }
                continue;
            };
            let class = if class == 0 {
                RPCChannelClass::Interactive
            } else {
                RPCChannelClass::Bulk
            };
            let result = async {
                let session = self.session.session().map_err(transport)?;
                let backing = &self.backing[index];
                let values = BTreeMap::from([(
                    "class".to_owned(),
                    Bytes::from_static(if class == RPCChannelClass::Interactive {
                        b"interactive"
                    } else {
                        b"bulk"
                    }),
                )]);
                let metadata = crate::crypto_v4::Metadata::new("sdk.flowersec/rpc", 1, &values)
                    .map_err(transport)?;
                let prepared = crate::crypto_v4::StreamPreparation::new_shared(
                    self.account.clone(),
                    backing.stream.clone(),
                )
                .map_err(transport)?;
                let mut attached = None;
                let result = {
                    let opening = backing
                        .opening
                        .clone()
                        .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
                    let opened =
                        session.open_rpc_stream_prepared(metadata, prepared, opening, |stream| {
                            attached = Some(stream);
                        });
                    tokio::pin!(opened);
                    tokio::select! { result = &mut opened => result, _ = self.cancellation.cancelled() => Err(SessionError::Closed) }
                };
                let stream = attached.ok_or_else(|| failure(ServiceFailure::NotReady))?;
                let core = RPCChannel::new_core(
                    Arc::new(stream),
                    self.account.clone(),
                    self.limits,
                    backing.channel.clone(),
                    self.incoming.clone(),
                    Some(self.shared_slots.clone()),
                )?;
                if result.is_err() {
                    core.seal();
                }
                Ok(core)
            };
            let result: Result<Arc<Core>> = result.await;
            match result {
                Ok(core) => {
                    let mut state = self.state.lock().expect("RPC lane registry");
                    if state.closed {
                        core.seal();
                    }
                    state.entries.push(LaneEntry {
                        core,
                        class,
                        local: true,
                        backing: Some(index),
                    });
                }
                Err(_) => {
                    self.state
                        .lock()
                        .expect("RPC lane registry")
                        .free
                        .push(index);
                }
            }
            self.changed.notify_waiters();
        }
        self.worker_exited();
    }
    fn worker_exited(&self) {
        if self.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tail.finish();
        }
        self.changed.notify_waiters();
    }
}

impl fmt::Debug for RPCChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RPCChannel { <opaque> }")
    }
}
impl Core {
    fn slot_limits(bytes: usize) -> Result<ResourceLimits> {
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            ResourceLimits {
                sdk_bytes: bytes as u64 + 2048,
                items: 1,
                ..ResourceLimits::default()
            },
            crate::application_tails_v4::ApplicationTails::resources(),
        )?)
    }
    fn reserve(self: &Arc<Self>, bytes: usize) -> Result<MessageSlot> {
        self.reserve_with_backing(bytes, None)
    }
    fn reserve_with_backing(
        self: &Arc<Self>,
        bytes: usize,
        prepaid: Option<ResourceCharge>,
    ) -> Result<MessageSlot> {
        self.account.check()?;
        if self.cancel.is_cancelled()
            || bytes
                > self
                    .limits
                    .max_payload_bytes
                    .saturating_mul(2)
                    .saturating_add(256)
        {
            return Err(failure(ServiceFailure::Closed));
        }
        let (prepaid_charge, tail) = if let Some(mut backing) = prepaid {
            if !backing.matches(&self.account, Self::slot_limits(bytes)?) {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
            let charge = backing.split(ResourceLimits {
                sdk_bytes: bytes as u64 + 2048,
                items: 1,
                ..ResourceLimits::default()
            })?;
            let stream = self
                .stream
                .lock()
                .expect("original RPC stream")
                .clone()
                .ok_or_else(|| failure(ServiceFailure::Closed))?;
            (
                Some(charge),
                stream
                    .application_tail_reserved(backing)
                    .map_err(transport)?,
            )
        } else {
            (None, self.tail.sibling()?)
        };
        let shared = self
            .shared_slots
            .lock()
            .expect("RPC shared messages")
            .clone();
        // Slot acquisition and idle FIN share the original outgoing gate.
        // A response/handler/publication slot remains live until its last use.
        let outgoing = self.outgoing.lock().expect("RPC output admission");
        if outgoing.sealed || self.cancel.is_cancelled() {
            return Err(failure(ServiceFailure::Closed));
        }
        if let Some(shared) = &shared {
            shared
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |slots| {
                    (slots < self.limits.max_messages).then_some(slots + 1)
                })
                .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        }
        if self
            .slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |slots| {
                (slots < self.limits.max_messages).then_some(slots + 1)
            })
            .is_err()
        {
            if let Some(shared) = shared {
                shared.fetch_sub(1, Ordering::AcqRel);
            }
            return Err(failure(ServiceFailure::ResourceExhausted));
        }
        drop(outgoing);
        let charge = match prepaid_charge.map(Ok).unwrap_or_else(|| {
            self.account.reserve(ResourceLimits {
                sdk_bytes: bytes as u64 + 2048,
                items: 1,
                ..ResourceLimits::default()
            })
        }) {
            Ok(charge) => charge,
            Err(error) => {
                self.slots.fetch_sub(1, Ordering::AcqRel);
                if let Some(shared) = shared {
                    shared.fetch_sub(1, Ordering::AcqRel);
                }
                self.changed.notify_waiters();
                return Err(error.into());
            }
        };
        Ok(MessageSlot {
            core: Arc::downgrade(self),
            _charge: charge,
            _tail: tail,
            _business: None,
        })
    }
    fn seal(&self) {
        self.cancel.cancel();
        let live = {
            let mut input = self.input.lock().expect("RPC input associations");
            input.closed = true;
            std::mem::take(&mut input.live)
        };
        drop(live);
        let pending = std::mem::take(
            &mut self
                .outgoing
                .lock()
                .expect("RPC outgoing associations")
                .pending,
        );
        for (_, item) in pending {
            if let Some(completion) = item.completion {
                let _ = completion.send(Err(failure(ServiceFailure::Closed)));
            }
        }
        self.changed.notify_waiters();
    }
    fn worker_exited(&self) {
        if self.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            let stream = self.stream.lock().expect("RPC channel stream").take();
            drop(stream);
            self.charge.lock().expect("RPC channel charge").take();
            self.tail.finish();
        }
        self.changed.notify_waiters();
    }
    fn accept(self: &Arc<Self>, fragment: Fragment<'_>) -> Result<Option<IncomingMessage>> {
        let mut prepared = if fragment.kind == FragmentKind::Begin {
            let association = MessageInput::begin(fragment)?;
            let bytes = association.header.payload_bytes()?;
            let response_charge = if association.header.is_response() {
                let mut outgoing = self.outgoing.lock().expect("RPC outgoing associations");
                let pending = outgoing
                    .pending
                    .get_mut(&association.reply_to)
                    .ok_or_else(|| failure(ServiceFailure::Protocol))?;
                association.header.check_response(&pending.request)?;
                if pending.prepaid_response {
                    if bytes > QuerySendPreparation::RESPONSE {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    let mut charge = pending
                        .response_charge
                        .take()
                        .ok_or_else(|| failure(ServiceFailure::Protocol))?;
                    Some(charge.split(Self::slot_limits(bytes)?)?)
                } else {
                    None
                }
            } else {
                None
            };
            if bytes > self.limits.max_payload_bytes {
                return Err(failure(ServiceFailure::Protocol));
            }
            let reply_bytes = if association.header.is_response() {
                0
            } else {
                if association.header.kind() == "read_result_request" {
                    self.limits.result_read_bytes.max(256)
                } else {
                    association.header.uint(8).unwrap_or(73728).max(256) as usize
                }
            };
            let mut slot = self.reserve_with_backing(
                bytes
                    .checked_add(reply_bytes)
                    .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?,
                response_charge,
            )?;
            if !association.header.is_response() {
                let stream = self
                    .stream
                    .lock()
                    .expect("RPC request admission")
                    .clone()
                    .ok_or_else(|| failure(ServiceFailure::Closed))?;
                slot._business = stream.admit_application_request().map_err(transport)?;
            }
            let reply_queue = if association.header.is_response() {
                None
            } else {
                Some(self.output.clone().try_reserve_owned().map_err(|error| {
                    failure(match error {
                        mpsc::error::TrySendError::Full(_) => ServiceFailure::ResourceExhausted,
                        mpsc::error::TrySendError::Closed(_) => ServiceFailure::Closed,
                    })
                })?)
            };
            let stop = Arc::new(StopOwner {
                core: Arc::downgrade(self),
                serial: fragment.serial,
                cancellation: CancellationToken::new(),
            });
            Some(Input {
                diagnostics: (!association.header.is_response()).then(|| {
                    self.account
                        .diagnostic_activity(crate::DiagnosticPhase::Application, 1)
                }),
                association,
                payload: Zeroizing::new(Vec::with_capacity(bytes)),
                slot,
                stop,
                reply_queue,
            })
        } else {
            None
        };
        let mut stopping = None;
        let result = self.account.with_security_time(|now| {
            if self.cancel.is_cancelled() {
                return Err(failure(ServiceFailure::Closed));
            }
            match fragment.kind {
                FragmentKind::Begin => {
                    let mut input = self.input.lock().expect("RPC input associations");
                    if input.closed
                        || fragment.serial <= input.highwater
                        || input.live.len() >= self.limits.max_messages
                    {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    input.highwater = fragment.serial;
                    let message = prepared.take().expect("prepared RPC begin");
                    if !message.association.header.is_response() {
                        self.stops
                            .lock()
                            .expect("RPC output interests")
                            .insert(fragment.serial, Arc::downgrade(&message.stop));
                    }
                    if message.association.complete() {
                        return Ok(Some(Self::completed(message, false, now.upper_ms)));
                    }
                    input.live.insert(fragment.serial, message);
                    Ok(None)
                }
                FragmentKind::Data => {
                    let mut input = self.input.lock().expect("RPC input associations");
                    let message = input
                        .live
                        .get_mut(&fragment.serial)
                        .ok_or_else(|| failure(ServiceFailure::Protocol))?;
                    message.association.data(fragment)?;
                    message.payload.extend_from_slice(fragment.bytes);
                    if !message.association.complete() {
                        return Ok(None);
                    }
                    let message = input
                        .live
                        .remove(&fragment.serial)
                        .expect("complete live RPC message");
                    Ok(Some(Self::completed(message, false, now.upper_ms)))
                }
                FragmentKind::Abort => {
                    let mut input = self.input.lock().expect("RPC input associations");
                    let message = input
                        .live
                        .get_mut(&fragment.serial)
                        .ok_or_else(|| failure(ServiceFailure::Protocol))?;
                    message.association.abort(fragment)?;
                    let message = input
                        .live
                        .remove(&fragment.serial)
                        .expect("aborted live RPC message");
                    Ok(Some(Self::completed(message, true, now.upper_ms)))
                }
                FragmentKind::StopOutput => {
                    let input = self.input.lock().expect("RPC input associations");
                    if fragment.serial > input.highwater {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    let interest = self
                        .stops
                        .lock()
                        .expect("RPC output interests")
                        .get(&fragment.serial)
                        .cloned();
                    stopping = interest
                        .and_then(|interest| interest.upgrade())
                        .map(|owner| owner.cancellation.clone());
                    Ok(None)
                }
            }
        });
        // Drop unused reservations and invoke cancellations after leaving the
        // security gate. Neither resource destruction nor application wakeups
        // may reacquire that gate from inside its critical section.
        if let Some(cancel) = stopping {
            cancel.cancel();
        }
        result?
    }
    fn completed(input: Input, aborted: bool, completed_at_upper_ms: u64) -> IncomingMessage {
        IncomingMessage {
            admitted: input.association.header.is_response() || input.slot._business.is_some(),
            diagnostics: input.diagnostics,
            serial: input.association.serial,
            reply_to: input.association.reply_to,
            header: input.association.header,
            payload: input.payload,
            aborted,
            completed_at_upper_ms,
            stop: input.stop,
            _slot: input.slot,
            reply_queue: input.reply_queue,
        }
    }
}
impl RPCChannel {
    pub(crate) fn reserve_stream(&self, account: &ResourceAccount) -> Result<StreamAssociation> {
        if !account.same_owner(&self.core.account) {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok(StreamAssociation {
            _slot: self.core.reserve(0)?,
        })
    }
    pub(crate) fn new_prepared(
        stream: Arc<Stream>,
        account: ResourceAccount,
        limits: ChannelLimits,
        prepared: ChannelPreparation,
    ) -> Result<(Arc<Self>, mpsc::Receiver<IncomingMessage>)> {
        let (incoming, messages) = mpsc::channel(limits.max_messages);
        let core = Self::new_core(stream, account, limits, prepared, incoming.clone(), None)?;
        Ok((
            Arc::new(Self {
                core,
                lanes: Mutex::new(None),
                incoming,
                owns_core: true,
            }),
            messages,
        ))
    }
    fn new_core(
        stream: Arc<Stream>,
        account: ResourceAccount,
        limits: ChannelLimits,
        prepared: ChannelPreparation,
        incoming: mpsc::Sender<IncomingMessage>,
        shared_slots: Option<Arc<AtomicUsize>>,
    ) -> Result<Arc<Core>> {
        let tail = stream
            .application_tail_shared(prepared.tail)
            .map_err(transport)?;
        let charge = prepared.charge;
        let reader_charge = prepared.reader;
        let reader_wait = prepared.reader_wait;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
        let (output, receiver) = mpsc::channel(limits.max_messages);
        let core = Arc::new(Core {
            stream: Mutex::new(Some(stream)),
            account,
            limits,
            input: Mutex::new(IncomingState {
                highwater: 0,
                live: BTreeMap::new(),
                closed: false,
            }),
            outgoing: Mutex::new(OutgoingState {
                highwater: 0,
                sealed: false,
                pending: BTreeMap::new(),
            }),
            slots: AtomicUsize::new(0),
            shared_slots: Mutex::new(Some(
                shared_slots.unwrap_or_else(|| Arc::new(AtomicUsize::new(0))),
            )),
            workers: AtomicUsize::new(2),
            cancel: tail.cancellation(),
            tail,
            changed: Notify::new(),
            charge: Mutex::new(Some(charge)),
            output,
            stops: Mutex::new(BTreeMap::new()),
        });
        let reader = core.clone();
        runtime.spawn(async move {
            let _reader_buffer = reader_charge;
            let result = receive_loop(&reader, incoming, &reader_wait).await;
            if result.is_err() || reader.cancel.is_cancelled() {
                reader.seal();
            } else {
                reader.input.lock().expect("RPC input EOF").closed = true;
                reader.changed.notify_waiters();
            }
            let stream = reader.stream.lock().expect("RPC channel stream").clone();
            if let Some(stream) = stream {
                if result.is_err() || reader.cancel.is_cancelled() {
                    let _ = stream.reset().await;
                }
                loop {
                    if stream.cleanup_status().complete {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
            reader.worker_exited();
        });
        let writer = core.clone();
        runtime.spawn(async move {
            if publish_loop(&writer, receiver).await.is_err() {
                writer.seal();
            }
            writer.worker_exited();
        });
        Ok(core)
    }
    pub(crate) fn install_channels(
        &self,
        session: &crate::crypto_v4::Session,
        mut prepared: ChannelSetPreparation,
        bootstrap: ChannelPreparation,
    ) -> Result<()> {
        let (role, _, _) = session.service_identity().map_err(transport)?;
        let tail = session
            .application_tail_reserved(prepared.tail)
            .map_err(transport)?;
        let bootstrap_stream = self
            .core
            .stream
            .lock()
            .expect("bootstrap RPC stream")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        prepared.backing.push(LaneBacking {
            channel: bootstrap,
            stream: bootstrap_stream.shared_preparation(),
            opening: None,
        });
        let shared_slots = self
            .core
            .shared_slots
            .lock()
            .expect("RPC shared messages")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let channels = Arc::new(ChannelSet {
            session: session.link(),
            account: self.core.account.clone(),
            limits: self.core.limits,
            incoming: self.incoming.clone(),
            state: Mutex::new(LaneState {
                entries: vec![LaneEntry {
                    core: self.core.clone(),
                    class: RPCChannelClass::Interactive,
                    local: role == 0,
                    backing: Some(7),
                }],
                free: (0..7).rev().collect(),
                wanted: [false; 2],
                closed: false,
            }),
            backing: prepared.backing,
            cancellation: tail.cancellation(),
            changed: Notify::new(),
            workers: AtomicUsize::new(2),
            shared_slots,
            _charge: prepared.charge,
            wait: prepared.wait,
            tail,
        });
        let mut installed = self.lanes.lock().expect("RPC channel installation");
        if installed.is_some() {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        *installed = Some(channels.clone());
        drop(installed);
        tokio::spawn(channels.clone().receive());
        tokio::spawn(channels.open());
        Ok(())
    }
    fn for_core(&self, core: Arc<Core>) -> Self {
        Self {
            core,
            lanes: Mutex::new(None),
            incoming: self.incoming.clone(),
            owns_core: false,
        }
    }
    pub(crate) async fn wait_channel(
        &self,
        class: RPCChannelClass,
        cancellation: &CancellationToken,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let lanes = self.lanes.lock().expect("RPC channel installation").clone();
        let Some(lanes) = lanes else {
            return if self.core.cancel.is_cancelled() {
                Err(failure(ServiceFailure::Closed))
            } else {
                Ok(())
            };
        };
        loop {
            let changed = lanes.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if lanes.select(class).is_some() {
                return Ok(());
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = lanes.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
            _ = tokio::time::sleep_until(deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)) }
        }
    }
    pub(crate) fn prepare_class(
        &self,
        class: RPCChannelClass,
        header: ApplicationHeader,
        payload: &[u8],
        cancellation: CancellationToken,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
        begin_gate: BeginAdmissionGate,
    ) -> Result<PreparedSend> {
        let lanes = self.lanes.lock().expect("RPC channel installation").clone();
        let core = if let Some(lanes) = lanes {
            lanes
                .select(class)
                .ok_or_else(|| failure(ServiceFailure::NotReady))?
        } else {
            self.core.clone()
        };
        self.for_core(core).prepare_send_with_backing(
            header,
            payload,
            0,
            cancellation,
            guard,
            None,
            Some(begin_gate),
        )
    }
    pub(crate) fn prepare_send(
        &self,
        header: ApplicationHeader,
        payload: &[u8],
        reply_to: u64,
        cancellation: CancellationToken,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<PreparedSend> {
        self.prepare_send_with_backing(header, payload, reply_to, cancellation, guard, None, None)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "RPC publication transfers separately reserved backing, cancellation and first-byte authority to one sender."
    )]
    fn prepare_send_with_backing(
        &self,
        header: ApplicationHeader,
        payload: &[u8],
        reply_to: u64,
        cancellation: CancellationToken,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
        prepaid: Option<QuerySendPreparation>,
        begin_gate: Option<BeginAdmissionGate>,
    ) -> Result<PreparedSend> {
        if let Some(lanes) = self.lanes.lock().expect("RPC channel installation").clone() {
            let core = lanes
                .select(RPCChannelClass::Interactive)
                .ok_or_else(|| failure(ServiceFailure::NotReady))?;
            return self.for_core(core).prepare_send_with_backing(
                header,
                payload,
                reply_to,
                cancellation,
                guard,
                prepaid,
                begin_gate,
            );
        }
        if header.is_response() != (reply_to != 0) || header.payload_bytes()? != payload.len() {
            return Err(failure(ServiceFailure::Protocol));
        }
        guard()?;
        let (slot, call_slot, publication_charge, response_charge, stop_charge) =
            if let Some(mut backing) = prepaid {
                if header.kind() != "query_contracts_request"
                    || reply_to != 0
                    || payload.len() > QuerySendPreparation::PAYLOAD
                {
                    return Err(failure(ServiceFailure::ConfigurationCapacity));
                }
                let slot_charge = backing.slot.split(Core::slot_limits(payload.len())?)?;
                (
                    self.core
                        .reserve_with_backing(payload.len(), Some(slot_charge))?,
                    Some(self.core.reserve_with_backing(0, Some(backing.call_slot))?),
                    Some(backing.publication),
                    Some(backing.response),
                    Some(backing.stop),
                )
            } else {
                let slot = self.core.reserve(payload.len())?;
                let call_slot = if !header.is_response()
                    && !matches!(header.kind(), "execution_notify" | "observation_notify")
                {
                    Some(self.core.reserve(0)?)
                } else {
                    None
                };
                (slot, call_slot, None, None, None)
            };
        self.core.account.check()?;
        if self.core.cancel.is_cancelled() || cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::Closed));
        }
        let queue = self
            .core
            .output
            .clone()
            .try_reserve_owned()
            .map_err(|error| {
                failure(match error {
                    mpsc::error::TrySendError::Full(_) => ServiceFailure::ResourceExhausted,
                    mpsc::error::TrySendError::Closed(_) => ServiceFailure::Closed,
                })
            })?;
        let mut owned = Zeroizing::new(Vec::new());
        owned
            .try_reserve_exact(payload.len())
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        owned.extend_from_slice(payload);
        let publication = PreparedPublication::prepare_with_backing(
            &self.core,
            &header,
            payload,
            reply_to,
            None,
            &cancellation,
            publication_charge,
            begin_gate,
            None,
        )?;
        Ok(PreparedSend {
            core: self.core.clone(),
            header,
            payload: owned,
            cancellation,
            guard,
            slot: Some(slot),
            call_slot,
            queue,
            publication,
            response_charge,
            stop_charge,
        })
    }
    pub(crate) fn send_prepared(&self, mut prepared: PreparedSend) -> Result<PublishedMessage> {
        if !self.core.account.same_owner(&prepared.core.account) {
            return Err(failure(ServiceFailure::Protocol));
        }
        (prepared.guard)()?;
        prepared.core.account.check()?;
        if prepared.core.cancel.is_cancelled() || prepared.cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::Closed));
        }
        let mut slot = prepared
            .slot
            .take()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        if !prepared.header.is_response() {
            let stream = prepared
                .core
                .stream
                .lock()
                .expect("RPC publication admission")
                .clone()
                .ok_or_else(|| failure(ServiceFailure::Closed))?;
            slot._business = Some(
                stream
                    .admit_application_request()
                    .map_err(transport)?
                    .ok_or_else(|| failure(ServiceFailure::Closed))?,
            );
        }
        let call_slot = prepared.call_slot.take();
        let mut outgoing = prepared
            .core
            .outgoing
            .lock()
            .expect("RPC outgoing associations");
        if outgoing.pending.len() >= prepared.core.limits.max_messages {
            return Err(failure(ServiceFailure::ResourceExhausted));
        }
        let serial = outgoing
            .highwater
            .checked_add(1)
            .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
        let response_tx = if let Some(call_slot) = call_slot {
            let (sender, receiver) = oneshot::channel();
            outgoing.pending.insert(
                serial,
                PendingResponse {
                    request: prepared.header.clone(),
                    completion: Some(sender),
                    _slot: Some(call_slot),
                    prepaid_response: prepared.response_charge.is_some(),
                    response_charge: prepared.response_charge.take(),
                    stop_charge: prepared.stop_charge.take(),
                },
            );
            Some(receiver)
        } else {
            None
        };
        let (completion, publication) = oneshot::channel();
        prepared.publication.serial.store(serial, Ordering::Release);
        prepared.queue.send(Output {
            diagnostics: None,
            serial,
            header: prepared.header,
            payload: prepared.payload,
            guard: prepared.guard,
            cancellation: prepared.cancellation,
            completion,
            publication: prepared.publication,
            _slot: slot,
            _interest: None,
            control: None,
        });
        outgoing.highwater = serial;
        Ok(PublishedMessage {
            serial,
            origin: PublicationOrigin(prepared.core.clone()),
            publication,
            response: response_tx,
        })
    }
    pub(crate) fn send(
        &self,
        header: ApplicationHeader,
        payload: &[u8],
        reply_to: u64,
        cancellation: CancellationToken,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<PublishedMessage> {
        let prepared = self.prepare_send(header, payload, reply_to, cancellation, guard)?;
        self.send_prepared(prepared)
    }
    pub(crate) fn send_query_prepaid(
        &self,
        header: ApplicationHeader,
        payload: &[u8],
        cancellation: CancellationToken,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
        preparation: QuerySendPreparation,
    ) -> Result<PublishedMessage> {
        let prepared = self.prepare_send_with_backing(
            header,
            payload,
            0,
            cancellation,
            guard,
            Some(preparation),
            None,
        )?;
        self.send_prepared(prepared)
    }
    /// Consume the request's original output-queue position and association
    /// owner. The bounded publication's wire/staging preparation is captured
    /// before it enters the ordered output lane.
    pub(crate) fn reply(
        &self,
        slot: ReplySlot,
        header: ApplicationHeader,
        payload: &[u8],
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<oneshot::Receiver<PublicationReceipt>> {
        self.reply_observed(slot, header, payload, guard, None)
    }
    pub(crate) fn reply_observed(
        &self,
        slot: ReplySlot,
        header: ApplicationHeader,
        payload: &[u8],
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
        handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<oneshot::Receiver<PublicationReceipt>> {
        let core = slot
            .slot
            .core
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        header.check_response(&slot.request)?;
        if !header.is_response()
            || header.payload_bytes()? != payload.len()
            || header.sdk_error() && payload.len() > 256
        {
            return Err(failure(ServiceFailure::Protocol));
        }
        guard()?;
        core.account.check()?;
        if core.cancel.is_cancelled() || slot.stop.cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::Canceled));
        }
        let owned = Zeroizing::new(payload.to_vec());
        let prepared = PreparedPublication::prepare_with_backing(
            &core,
            &header,
            payload,
            slot.serial,
            None,
            &slot.stop.cancellation,
            None,
            None,
            handoff,
        )?;
        let mut outgoing = core.outgoing.lock().expect("RPC outgoing serial");
        let serial = outgoing
            .highwater
            .checked_add(1)
            .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
        let (completion, publication) = oneshot::channel();
        prepared.serial.store(serial, Ordering::Release);
        slot.queue
            .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?
            .send(Output {
                diagnostics: slot.diagnostics,
                serial,
                header,
                payload: owned,
                guard,
                cancellation: slot.stop.cancellation.clone(),
                completion,
                publication: prepared,
                _slot: slot.slot,
                _interest: Some(slot.stop),
                control: None,
            });
        outgoing.highwater = serial;
        Ok(publication)
    }
    /// Stop interest only after the original publication confirms complete
    /// input. Keep the bounded association tombstone until its response ends.
    pub(crate) fn abandon(
        &self,
        origin: &PublicationOrigin,
        serial: u64,
    ) -> Result<oneshot::Receiver<PublicationReceipt>> {
        let core = &origin.0;
        if !core.account.same_owner(&self.core.account) {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        core.account.check()?;
        let mut outgoing = core.outgoing.lock().expect("RPC outgoing associations");
        let pending = outgoing
            .pending
            .get_mut(&serial)
            .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
        let account = core.account.clone();
        let guard: Arc<dyn Fn() -> Result<()> + Send + Sync> = Arc::new(move || {
            account.check()?;
            Ok(())
        });
        let queue = core.output.clone().try_reserve_owned().map_err(|error| {
            failure(match error {
                mpsc::error::TrySendError::Full(_) => ServiceFailure::ResourceExhausted,
                mpsc::error::TrySendError::Closed(_) => ServiceFailure::Closed,
            })
        })?;
        let prepared = PreparedPublication::prepare_with_backing(
            core,
            &pending.request,
            &[],
            0,
            Some(FragmentKind::StopOutput),
            &CancellationToken::new(),
            pending.stop_charge.take(),
            None,
            None,
        )?;
        prepared.serial.store(serial, Ordering::Release);
        let slot = pending
            ._slot
            .take()
            .ok_or_else(|| failure(ServiceFailure::Canceled))?;
        let (completion, publication) = oneshot::channel();
        queue.send(Output {
            diagnostics: None,
            serial,
            header: pending.request.clone(),
            payload: Zeroizing::new(Vec::new()),
            guard,
            cancellation: CancellationToken::new(),
            completion,
            publication: prepared,
            _slot: slot,
            _interest: None,
            control: Some(FragmentKind::StopOutput),
        });
        pending.completion.take();
        Ok(publication)
    }
    pub(crate) fn close(&self) {
        if let Some(lanes) = self
            .lanes
            .lock()
            .expect("RPC channel installation")
            .as_ref()
        {
            lanes.close();
        } else {
            self.core.seal();
        }
    }
    pub(crate) fn cleanup_status(&self) -> CleanupStatus {
        if let Some(lanes) = self
            .lanes
            .lock()
            .expect("RPC channel installation")
            .as_ref()
        {
            return lanes.status();
        }
        let workers = self.core.workers.load(Ordering::Acquire);
        let slots = self.core.slots.load(Ordering::Acquire);
        CleanupStatus {
            complete: workers == 0 && slots == 0,
            cleanup_incomplete: workers != 0 || slots != 0,
            pending_callbacks: workers as u64,
        }
    }
    pub(crate) async fn wait_cleanup(&self) -> CleanupStatus {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let changed = self.core.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}, _ = tokio::time::sleep_until(deadline) => return self.cleanup_status() }
        }
    }
}
impl Drop for RPCChannel {
    fn drop(&mut self) {
        if self.owns_core {
            self.close();
        }
    }
}

async fn receive_loop(
    core: &Arc<Core>,
    incoming: mpsc::Sender<IncomingMessage>,
    wait: &ResourceCharge,
) -> Result<()> {
    let mut read_buffer = Zeroizing::new(vec![0u8; 16384]);
    let mut scratch = Zeroizing::new(vec![0u8; 16384]);
    let mut filled = 0usize;
    let mut required = 4usize;
    loop {
        let stream = core
            .stream
            .lock()
            .expect("RPC channel stream")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let chunk = tokio::select! {
            _ = core.cancel.cancelled() => return Ok(()),
            result = stream.read_rpc_prepared(&mut read_buffer, wait) => result.map_err(transport)?,
        };
        drop(stream);
        let Some(count) = chunk else {
            if filled != 0
                || !core
                    .input
                    .lock()
                    .expect("RPC input associations")
                    .live
                    .is_empty()
            {
                return Err(failure(ServiceFailure::Protocol));
            }
            return Ok(());
        };
        let chunk = &read_buffer[..count];
        let mut offset = 0;
        while offset < chunk.len() {
            let count = (required - filled).min(chunk.len() - offset);
            scratch[filled..filled + count].copy_from_slice(&chunk[offset..offset + count]);
            filled += count;
            offset += count;
            if filled != required {
                continue;
            }
            if required == 4 {
                let body = u32::from_be_bytes(
                    scratch[..4]
                        .try_into()
                        .map_err(|_| failure(ServiceFailure::Protocol))?,
                ) as usize;
                required = body
                    .checked_add(4)
                    .filter(|total| *total >= 5 && *total <= scratch.len())
                    .ok_or_else(|| failure(ServiceFailure::Protocol))?;
                continue;
            }
            let fragment = Fragment::decode(&scratch[..required])?;
            if let Some(message) = core.accept(fragment)? {
                if message.header.is_response() {
                    let mut outgoing = core.outgoing.lock().expect("RPC outgoing associations");
                    let pending = outgoing
                        .pending
                        .remove(&message.reply_to)
                        .ok_or_else(|| failure(ServiceFailure::Protocol))?;
                    message.header.check_response(&pending.request)?;
                    if let Some(completion) = pending.completion {
                        let _ = completion.send(Ok(message));
                    }
                } else {
                    incoming
                        .try_send(message)
                        .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
                }
            }
            scratch[..required].fill(0);
            filled = 0;
            required = 4;
        }
    }
}
async fn publish_fragment(
    core: &Arc<Core>,
    guard: &Arc<dyn Fn() -> Result<()> + Send + Sync>,
    cancellation: &CancellationToken,
    operation: WriteOperation,
    submitted: &mut bool,
    cleanup: bool,
) -> Result<()> {
    if !cleanup {
        (guard)()?;
    }
    core.account.check()?;
    if core.cancel.is_cancelled() || !cleanup && cancellation.is_cancelled() {
        return Err(failure(ServiceFailure::ServiceUnavailable));
    }
    if let Err(error) = operation.start().await {
        *submitted |= operation.progress().accepted_bytes != 0;
        return Err(transport(error));
    }
    let progress = tokio::select! {
        progress = operation.wait() => progress.map_err(transport)?,
        _ = cancellation.cancelled(), if !cleanup => { operation.cancel(); operation.wait().await.map_err(transport)? },
        _ = core.cancel.cancelled() => { operation.cancel(); operation.wait().await.map_err(transport)? },
    };
    *submitted |= progress.accepted_bytes != 0;
    if progress.accepted_bytes != progress.requested_bytes
        || progress.terminal_reason.as_deref() != Some("complete")
    {
        return Err(failure(ServiceFailure::ServiceUnavailable));
    }
    Ok(())
}
async fn publish_output(core: &Arc<Core>, output: Output) -> PublicationReceipt {
    let Output {
        diagnostics,
        serial,
        header,
        payload,
        guard,
        cancellation,
        completion,
        publication,
        _slot,
        _interest,
        control,
    } = output;
    let PreparedPublicationParts {
        abort_offset,
        fragments,
        abort,
        _admission,
        _charge,
        ..
    } = publication.into_parts();
    let mut fragments = fragments.into_iter();
    let mut began = false;
    let mut offset = 0u32;
    let mut fragment_submitted = false;
    let result = async {
        if control.is_some() {
            let operation = fragments
                .next()
                .ok_or_else(|| failure(ServiceFailure::Protocol))?;
            return publish_fragment(
                core,
                &guard,
                &cancellation,
                operation,
                &mut fragment_submitted,
                true,
            )
            .await;
        }
        let operation = fragments
            .next()
            .ok_or_else(|| failure(ServiceFailure::Protocol))?;
        publish_fragment(
            core,
            &guard,
            &cancellation,
            operation,
            &mut fragment_submitted,
            false,
        )
        .await?;
        began = true;
        for chunk in payload.chunks(16367) {
            let operation = fragments
                .next()
                .ok_or_else(|| failure(ServiceFailure::Protocol))?;
            fragment_submitted = false;
            publish_fragment(
                core,
                &guard,
                &cancellation,
                operation,
                &mut fragment_submitted,
                false,
            )
            .await?;
            offset += chunk.len() as u32;
        }
        Ok::<(), ServiceError>(())
    }
    .await;
    for operation in fragments {
        operation.cancel();
    }
    let receipt = match result {
        Ok(()) => PublicationReceipt {
            fact: PublicationFact::Committed,
            error: None,
        },
        Err(error) => {
            let fact = if began && !fragment_submitted && offset < payload.len() as u32 {
                let mut abort_submitted = false;
                abort_offset.store(u64::from(offset), Ordering::Release);
                if let Some(abort) = abort {
                    if publish_fragment(
                        core,
                        &guard,
                        &cancellation,
                        abort,
                        &mut abort_submitted,
                        true,
                    )
                    .await
                    .is_ok()
                    {
                        PublicationFact::Aborted
                    } else {
                        PublicationFact::Unknown
                    }
                } else {
                    PublicationFact::Unknown
                }
            } else if began || fragment_submitted {
                PublicationFact::Unknown
            } else {
                PublicationFact::NotSubmitted
            };
            PublicationReceipt {
                fact,
                error: Some(error.0),
            }
        }
    };
    let failed = receipt.error.is_some() && receipt.fact == PublicationFact::Unknown;
    if receipt.fact == PublicationFact::NotSubmitted && control.is_none() && !header.is_response() {
        let pending = core
            .outgoing
            .lock()
            .expect("RPC outgoing associations")
            .pending
            .remove(&serial);
        if let Some(pending) = pending
            && let Some(completion) = pending.completion
        {
            let _ = completion.send(Err(failure(
                receipt.error.unwrap_or(ServiceFailure::ServiceUnavailable),
            )));
        }
    }
    if let Some(diagnostics) = &diagnostics {
        if receipt.fact != PublicationFact::Committed {
            diagnostics.service_failure(failure(
                receipt.error.unwrap_or(ServiceFailure::ServiceUnavailable),
            ));
        } else if header.sdk_error() {
            diagnostics.service_failure(
                ServiceError::from_sdk_payload(&payload).unwrap_or_else(|error| error),
            );
        } else {
            diagnostics.succeed();
        }
    }
    let _ = completion.send(receipt);
    if failed {
        core.seal();
    }
    receipt
}

async fn publish_loop(core: &Arc<Core>, mut receiver: mpsc::Receiver<Output>) -> Result<()> {
    let stream = core
        .stream
        .lock()
        .expect("RPC channel stream")
        .clone()
        .ok_or_else(|| failure(ServiceFailure::Closed))?;
    let session_changed = stream.application_changed();
    let graceful = loop {
        let changed = core.changed.notified();
        let session_progress = session_changed.notified();
        tokio::pin!(changed, session_progress);
        changed.as_mut().enable();
        session_progress.as_mut().enable();
        let input_closed = core.input.lock().expect("RPC input EOF").closed;
        if input_closed || stream.application_draining() {
            let mut outgoing = core.outgoing.lock().expect("RPC idle output");
            if core.slots.load(Ordering::Acquire) == 0 && outgoing.pending.is_empty() {
                outgoing.sealed = true;
                break true;
            }
        }
        let output = tokio::select! {
            _ = core.cancel.cancelled() => break false,
            _ = changed => continue,
            _ = session_progress => continue,
            output = receiver.recv() => match output {
                Some(output) => output,
                None => break false,
            }
        };
        let failed = publish_output(core, output).await;
        if failed.fact == PublicationFact::Unknown {
            break false;
        }
    };
    receiver.close();
    if graceful {
        // Only the send direction is sealed. Accepted incoming work and the
        // original reader keep their owners until real EOF and terminal proof.
        return stream.request_application_close_write().map_err(transport);
    }
    while let Some(output) = receiver.recv().await {
        let _ = output.completion.send(PublicationReceipt {
            fact: PublicationFact::NotSubmitted,
            error: Some(ServiceFailure::Closed),
        });
    }
    Err(failure(ServiceFailure::Closed))
}
