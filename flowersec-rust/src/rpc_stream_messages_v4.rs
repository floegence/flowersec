//! Dedicated service Stream framing. It uses the original reliable Stream and
//! general RPC position, with one persistent cursor and demand-only advancement.
use crate::{
    api_v4::{CleanupStatus, ReadStreamStatus, StreamReadPermit},
    application_tails_v4::ApplicationTail,
    crypto_v4::{OpenRequest, ResumeMessageClaim, Session, Stream, StreamPreparation},
    environment_v4::{ResourceAccount, ResourceCharge, ResourceLimits},
    rpc_channel_v4::{RPCChannel, StreamAssociation},
    rpc_wire_v4::ApplicationHeader,
    service_contract::{ServiceError, ServiceFailure},
    service_operation_v4::ServicePublication,
    transport::ByteStream,
};
use bytes::Bytes;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn transport(_: crate::SessionError) -> ServiceError {
    failure(ServiceFailure::ServiceUnavailable)
}
const FLOOR: usize = 16384;

pub(crate) struct StreamMessage {
    pub(crate) header: ApplicationHeader,
    pub(crate) payload: Zeroizing<Vec<u8>>,
    pub(crate) charge: ResourceCharge,
    pub(crate) following_terminal: ReadStreamStatus,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamMessagePublication {
    pub(crate) accepted_bytes: u64,
    pub(crate) requested_bytes: u64,
    pub(crate) publication: ServicePublication,
    pub(crate) failure: Option<ServiceFailure>,
}
/// The full local publication vector exists before Start can consume the
/// immutable prepared request. Dropping this unused vector sends no byte.
pub(crate) struct PreparedStreamPublication {
    core: Arc<Core>,
    operation: crate::WriteOperation,
    terminal: bool,
    _admission: Option<crate::crypto_v4::StreamPublicationAdmission>,
    worker: Option<Worker>,
    charge: Option<ResourceCharge>,
    output: Option<tokio::sync::OwnedMutexGuard<()>>,
}
impl Drop for PreparedStreamPublication {
    fn drop(&mut self) {
        self.operation.cancel();
    }
}
impl PreparedStreamPublication {
    pub(crate) async fn publish(mut self) -> Result<StreamMessagePublication> {
        let worker = self.worker.take().expect("reserved message publisher");
        let charge = self.charge.take().expect("reserved message publication");
        let output = self.output.take().expect("original ordered publisher");
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let _worker = worker;
            let _charge = charge;
            let _output = output;
            let result = async {
                if self.core.output_closed.load(Ordering::Acquire) || self.core.output_terminal.load(Ordering::Acquire)
                    || self.core.cancellation.is_cancelled() { return Err(failure(ServiceFailure::Closed)); }
                if let Some(qualification) = self.core.resume_claim.lock().expect("Resume message qualification").as_mut() { qualification.begin(); }
                self.operation.start().await.map_err(transport)?;
                let progress = tokio::select! {
                    progress = self.operation.wait() => progress,
                    _ = self.core.cancellation.cancelled() => { self.operation.cancel(); self.operation.wait().await },
                }.map_err(transport)?;
                let publication = if progress.accepted_bytes == progress.requested_bytes && progress.terminal_reason.as_deref() == Some("complete") {
                    ServicePublication::Committed
                } else if progress.accepted_bytes == 0 { ServicePublication::NotSubmitted } else { ServicePublication::Unknown };
                if publication != ServicePublication::Committed { self.core.fail(failure(ServiceFailure::ServiceUnavailable)); }
                else if self.terminal { self.core.output_terminal.store(true, Ordering::Release); }
                let cause = match progress.terminal_reason.as_deref() {
                    Some("complete") => None, Some("deadline_exceeded") => Some(ServiceFailure::DeadlineExceeded),
                    Some("canceled") => Some(ServiceFailure::Canceled), _ => Some(ServiceFailure::ServiceUnavailable),
                };
                Ok(StreamMessagePublication { accepted_bytes: progress.accepted_bytes, requested_bytes: progress.requested_bytes, publication, failure: cause })
            }.await;
            let _ = sender.send(result);
        });
        receiver
            .await
            .map_err(|_| failure(ServiceFailure::Closed))?
    }
}
enum Direction {
    InitialRequest,
    Responses(ApplicationHeader),
    ResumeRequest,
    ResumeResponses(Option<ApplicationHeader>),
}
struct Input {
    prefix: [u8; 514],
    have: usize,
    need: usize,
    header: Option<ApplicationHeader>,
    body: Option<Zeroizing<Vec<u8>>>,
    body_charge: Option<ResourceCharge>,
    body_account: Option<ResourceAccount>,
    candidate: Option<StreamMessage>,
    demand: bool,
    waiter: bool,
    eof: bool,
    failure: Option<ServiceError>,
    frames: u64,
    direction: Direction,
    terminal_message: bool,
}
type ResumeInputBacking = (ResourceAccount, ResourceCharge, Zeroizing<Vec<u8>>);

struct Core {
    session: Session,
    account: ResourceAccount,
    stream: Mutex<Option<Arc<Stream>>>,
    input: Mutex<Input>,
    limit: usize,
    cancellation: CancellationToken,
    changed: Notify,
    output: Arc<AsyncMutex<()>>,
    activated: AtomicBool,
    closed: AtomicBool,
    output_closed: AtomicBool,
    output_terminal: AtomicBool,
    outbound: Mutex<Option<(ApplicationHeader, bool)>>,
    business_cancellation: Mutex<CancellationToken>,
    workers: AtomicUsize,
    retired: AtomicBool,
    tail: ApplicationTail,
    association: Mutex<Option<StreamAssociation>>,
    active_charge: Mutex<Option<ResourceCharge>>,
    peer_worker: Mutex<Option<crate::service_peer_v4::PeerWorker>>,
    resume_claim: Mutex<Option<ResumeMessageClaim>>,
    resume_deadline: Mutex<Option<Instant>>,
    resume_gate: Mutex<()>,
    prepaid_resume_input: Mutex<Option<ResumeInputBacking>>,
    _capture_charge: ResourceCharge,
}
/// A private write-only projection of this exact message owner. Preparation
/// captures the Session's existing staging budget and sender wait before Start;
/// only the original accepted typed Stream can consume them.
struct OriginalMessagePublisher {
    core: Arc<Core>,
    wait: Mutex<Option<ResourceCharge>>,
}
impl std::fmt::Debug for OriginalMessagePublisher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OriginalMessagePublisher { <opaque> }")
    }
}
#[async_trait::async_trait]
impl ByteStream for OriginalMessagePublisher {
    #[cfg(test)]
    fn internal_test_id(&self) -> u64 {
        self.core
            .stream
            .lock()
            .expect("original publication Stream")
            .as_ref()
            .map_or(0, |stream| stream.internal_test_id())
    }
    fn kind(&self) -> &str {
        "flowersec.v4.service-publication"
    }
    fn terminal_error(&self) -> Option<crate::SessionError> {
        if self.core.closed.load(Ordering::Acquire) || self.core.cancellation.is_cancelled() {
            Some(crate::SessionError::Closed)
        } else {
            self.core
                .stream
                .lock()
                .expect("original publication Stream")
                .as_ref()
                .and_then(|stream| stream.terminal_error())
        }
    }
    async fn read(&self) -> std::result::Result<Option<Bytes>, crate::SessionError> {
        Err(crate::SessionError::OperationFailed)
    }
    async fn write(&self, _payload: Bytes) -> std::result::Result<usize, crate::SessionError> {
        Err(crate::SessionError::OperationFailed)
    }
    fn write_staging_owner(&self) -> Option<Arc<crate::api_v4::WriteStagingOwner>> {
        Some(self.core.session.application_write_staging_owner())
    }
    async fn write_prepared(
        &self,
        payload: Bytes,
        admission: &crate::api_v4::WriteRequestAdmission,
    ) -> std::result::Result<(), crate::SessionError> {
        if !self.core.activated.load(Ordering::Acquire) || self.terminal_error().is_some() {
            return Err(crate::SessionError::Closed);
        }
        let stream = self
            .core
            .stream
            .lock()
            .expect("original publication Stream")
            .clone()
            .ok_or(crate::SessionError::OperationFailed)?;
        let wait = self
            .wait
            .lock()
            .expect("reserved original sender wait")
            .take()
            .ok_or(crate::SessionError::OperationFailed)?;
        stream
            .write_message_prepared(payload, admission, wait, None)
            .await
    }
    async fn close_write(&self) -> std::result::Result<(), crate::SessionError> {
        Err(crate::SessionError::OperationFailed)
    }
    async fn reset(&self) -> std::result::Result<(), crate::SessionError> {
        Err(crate::SessionError::OperationFailed)
    }
    async fn close(&self) -> std::result::Result<(), crate::SessionError> {
        Err(crate::SessionError::OperationFailed)
    }
}
pub(crate) struct StreamMessages {
    core: Arc<Core>,
}
struct Worker(Arc<Core>);
impl Drop for Worker {
    fn drop(&mut self) {
        if self.0.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            let qualification = self
                .0
                .resume_claim
                .lock()
                .expect("Resume message qualification")
                .take();
            drop(qualification);
            self.0
                .association
                .lock()
                .expect("dedicated RPC association")
                .take();
            self.0
                .active_charge
                .lock()
                .expect("dedicated Stream task charge")
                .take();
            self.0.tail.finish();
            self.0
                .peer_worker
                .lock()
                .expect("dedicated Stream peer worker")
                .take();
            self.0.retired.store(true, Ordering::Release);
        }
        self.0.changed.notify_waiters();
    }
}
struct Waiter(Arc<Core>);
impl Drop for Waiter {
    fn drop(&mut self) {
        let mut input = self.0.input.lock().expect("dedicated Stream input");
        input.waiter = false;
        input.demand = false;
        drop(input);
        self.0.changed.notify_waiters();
    }
}
impl StreamMessages {
    pub(crate) fn prepare(
        session: &Session,
        channel: &RPCChannel,
        limit: usize,
        response_to: Option<ApplicationHeader>,
    ) -> Result<(Self, StreamPreparation)> {
        if limit > 1 << 20 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let account = session.application_account();
        let tail = session.application_tail().map_err(transport)?;
        let association = channel.reserve_stream(&account)?;
        let capture = account.reserve(ResourceLimits {
            sdk_bytes: (2 * FLOOR + 8192) as u64,
            items: 8,
            ..ResourceLimits::default()
        })?;
        let active = account.reserve(ResourceLimits {
            tasks: 1,
            work_slots: 1,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        let mut preparation = StreamPreparation::new(account.clone()).map_err(transport)?;
        preparation
            .reserve_opening_wait(session)
            .map_err(transport)?;
        let permit = preparation.claim_typed().map_err(transport)?;
        let core = Self::core(
            session,
            account,
            tail,
            association,
            capture,
            active,
            limit,
            response_to,
        );
        let reader = core.clone();
        tokio::spawn(async move {
            let _worker = Worker(reader.clone());
            reader.read(permit).await;
            reader.retire().await;
        });
        Ok((Self { core }, preparation))
    }
    /// Borrow one existing accepted business Stream. Capture its immutable
    /// target before constructing any recovery ID, digest or saved reference.
    pub(crate) fn prepare_resume(
        session: &Session,
        channel: &RPCChannel,
        stream: &Stream,
        kind: &str,
        limit: usize,
        incoming: bool,
        deadline: Instant,
    ) -> Result<(Self, crate::checkpoint_v4::ResumeTargetBinding)> {
        if limit == 0 || limit > 1 << 20 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let account = session.application_account();
        let tail = session.application_tail().map_err(transport)?;
        let association = channel.reserve_stream(&account)?;
        let capture = account.reserve(ResourceLimits {
            sdk_bytes: (2 * FLOOR + 8192) as u64,
            items: 8,
            ..ResourceLimits::default()
        })?;
        let active = account.reserve(ResourceLimits {
            tasks: 2,
            work_slots: 1,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        let prepaid_input =
            Self::reserve_resume_input(&account, if incoming { 9345 } else { limit })?;
        let (stream, permit, qualification) =
            stream.claim_resume(session, kind).map_err(transport)?;
        let target = qualification.binding().clone();
        let core = Self::core(
            session,
            account,
            tail,
            association,
            capture,
            active,
            limit,
            None,
        );
        *core
            .prepaid_resume_input
            .lock()
            .expect("Resume prepaid input") = Some(prepaid_input);
        core.input.lock().expect("Resume input").direction = if incoming {
            Direction::ResumeRequest
        } else {
            Direction::ResumeResponses(None)
        };
        *core.stream.lock().expect("Resume target") = Some(Arc::new(stream));
        *core
            .resume_claim
            .lock()
            .expect("Resume message qualification") = Some(qualification);
        *core.resume_deadline.lock().expect("Resume deadline") =
            Some(deadline.min(Instant::now() + Duration::from_secs(60)));
        if incoming {
            core.activated.store(true, Ordering::Release);
        }
        Self::spawn_resume_reader(&core, permit);
        Ok((Self { core }, target))
    }
    pub(crate) fn set_resume_request(&self, request: ApplicationHeader) -> Result<()> {
        if request.kind() != "resume_request"
            || self.core.activated.load(Ordering::Acquire)
            || self.core.closed.load(Ordering::Acquire)
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        let mut input = self.core.input.lock().expect("Resume input");
        if !matches!(input.direction, Direction::ResumeResponses(None))
            || input.frames != 0
            || input.have != 0
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        input.direction = Direction::ResumeResponses(Some(request.clone()));
        drop(input);
        *self.core.outbound.lock().expect("Resume output") = Some((request, true));
        Ok(())
    }
    pub(crate) fn activate_resume(&self, deadline: Instant) -> Result<()> {
        self.core.account.check()?;
        let mut prepared = self.core.resume_deadline.lock().expect("Resume deadline");
        if self.core.closed.load(Ordering::Acquire)
            || self.core.activated.load(Ordering::Acquire)
            || prepared.is_none_or(|until| Instant::now() >= until)
        {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        if self.core.outbound.lock().expect("Resume output").is_none() {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        *prepared = Some(deadline);
        self.core.activated.store(true, Ordering::Release);
        drop(prepared);
        self.core.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn resume_stream(&self) -> Result<Stream> {
        if self
            .core
            .resume_claim
            .lock()
            .expect("Resume message qualification")
            .is_none()
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        self.core
            .stream
            .lock()
            .expect("Resume target")
            .as_ref()
            .map(|stream| stream.as_ref().clone())
            .ok_or_else(|| failure(ServiceFailure::Closed))
    }
    pub(crate) fn check_resume_target(
        &self,
        session: &Session,
        expected: &crate::checkpoint_v4::ResumeTargetBinding,
    ) -> Result<()> {
        self.with_prepared_resume_target(session, expected, || ())
    }
    pub(crate) fn with_prepared_resume_target<T>(
        &self,
        session: &Session,
        expected: &crate::checkpoint_v4::ResumeTargetBinding,
        action: impl FnOnce() -> T,
    ) -> Result<T> {
        let _gate = self.core.resume_gate.lock().expect("Resume handoff gate");
        if self.core.closed.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::Closed));
        }
        let stream = self.resume_stream()?;
        stream
            .with_resume_target(session, true, |actual| {
                if actual != *expected {
                    return Err(failure(ServiceFailure::OperationConflict));
                }
                Ok(action())
            })
            .map_err(transport)?
    }
    pub(crate) async fn settle_unsubmitted_resume(&self) -> Result<CleanupStatus> {
        {
            let input = self.core.input.lock().expect("Resume input");
            if input.frames != 0
                || input.have != 0
                || input.header.is_some()
                || input.body.is_some()
                || input.candidate.is_some()
                || self.core.output_terminal.load(Ordering::Acquire)
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
        }
        self.core
            .resume_claim
            .lock()
            .expect("Resume message qualification")
            .as_mut()
            .ok_or_else(|| failure(ServiceFailure::OperationConflict))?
            .settle_unsubmitted();
        self.core.close();
        Ok(self.wait_cleanup().await)
    }
    /// Close only this temporary framing owner after both complete boundaries.
    /// The final reader/sender exit returns the original raw Stream to its owner.
    pub(crate) async fn settle_resume(&self) -> Result<CleanupStatus> {
        {
            let input = self.core.input.lock().expect("Resume input");
            if !matches!(
                input.direction,
                Direction::ResumeRequest | Direction::ResumeResponses(Some(_))
            ) || input.frames != 1
                || input.have != 0
                || input.header.is_some()
                || input.body.is_some()
                || input.candidate.is_some()
                || input.waiter
                || input.failure.is_some()
                || !self.core.output_terminal.load(Ordering::Acquire)
            {
                return Err(failure(ServiceFailure::OperationConflict));
            }
        }
        self.core
            .resume_claim
            .lock()
            .expect("Resume message qualification")
            .as_mut()
            .ok_or_else(|| failure(ServiceFailure::OperationConflict))?
            .settle();
        self.core.close();
        let cleanup = self.wait_cleanup().await;
        if !cleanup.complete {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        Ok(cleanup)
    }
    /// The façade, exact reader and full original RPC vector exist while OPEN
    /// remains pending. ACCEPT only commits that same graph and physical scope.
    pub(crate) fn accept(request: OpenRequest, channel: &RPCChannel, limit: usize) -> Result<Self> {
        let session = request.session();
        if limit > 1 << 20 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let stream = request.prepare_stream().map_err(transport)?;
        let account = stream.account();
        let tail = stream.application_tail().map_err(transport)?;
        let association = channel.reserve_stream(&account)?;
        let capture = account.reserve(ResourceLimits {
            sdk_bytes: (2 * FLOOR + 8192) as u64,
            items: 8,
            ..ResourceLimits::default()
        })?;
        let active = account.reserve(ResourceLimits {
            tasks: 1,
            work_slots: 1,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        let (stream, permit) = stream.claim_typed().map_err(transport)?;
        let core = Self::core(
            &session,
            account,
            tail,
            association,
            capture,
            active,
            limit,
            None,
        );
        *core.stream.lock().expect("dedicated Stream") = Some(Arc::new(stream.clone()));
        request
            .accept_prepared(stream, FLOOR as u64)
            .map_err(transport)?;
        core.activated.store(true, Ordering::Release);
        let reader = core.clone();
        tokio::spawn(async move {
            let _worker = Worker(reader.clone());
            reader.read(permit).await;
            reader.retire().await;
        });
        Ok(Self { core })
    }
    /// Reserve the complete Resume graph while the original OPEN is pending.
    /// No resource acquisition or replacement of the physical target follows ACCEPT.
    pub(crate) fn accept_resume(
        request: OpenRequest,
        channel: &RPCChannel,
        kind: &str,
        limit: usize,
        deadline: Instant,
    ) -> Result<(Self, crate::checkpoint_v4::ResumeTargetBinding)> {
        if limit == 0 || limit > 1 << 20 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let session = request.session();
        let stream = request.prepare_stream().map_err(transport)?;
        let account = stream.account();
        let tail = stream.application_tail().map_err(transport)?;
        let association = channel.reserve_stream(&account)?;
        let capture = account.reserve(ResourceLimits {
            sdk_bytes: (2 * FLOOR + 8192) as u64,
            items: 8,
            ..ResourceLimits::default()
        })?;
        let active = account.reserve(ResourceLimits {
            tasks: 2,
            work_slots: 1,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        let prepaid_input = Self::reserve_resume_input(&account, 9345)?;
        let (stream, permit, qualification) = stream
            .claim_pending_resume(&session, kind)
            .map_err(transport)?;
        let target = qualification.binding().clone();
        let core = Self::core(
            &session,
            account,
            tail,
            association,
            capture,
            active,
            limit,
            None,
        );
        *core
            .prepaid_resume_input
            .lock()
            .expect("Resume prepaid input") = Some(prepaid_input);
        core.input.lock().expect("Resume input").direction = Direction::ResumeRequest;
        *core.stream.lock().expect("Resume target") = Some(Arc::new(stream.clone()));
        *core.resume_claim.lock().expect("Resume qualification") = Some(qualification);
        *core.resume_deadline.lock().expect("Resume deadline") = Some(deadline);
        request
            .accept_prepared(stream, FLOOR as u64)
            .map_err(transport)?;
        core.activated.store(true, Ordering::Release);
        Self::spawn_resume_reader(&core, permit);
        Ok((Self { core }, target))
    }
    /// The response sender has exited and the reader has reached its exact
    /// one-message boundary. Continue on this same exclusive owner without a
    /// new raw claim, a prefetch, or any application-controlled codec switch.
    pub(crate) async fn continue_resume_output(&self, original: ApplicationHeader) -> Result<()> {
        let _sender = self.core.output.lock().await;
        let _gate = self
            .core
            .resume_gate
            .lock()
            .expect("Resume continuation gate");
        let mut input = self
            .core
            .input
            .lock()
            .expect("Resume continuation boundary");
        if self.core.closed.load(Ordering::Acquire)
            || !self.core.output_terminal.load(Ordering::Acquire)
            || !matches!(input.direction, Direction::ResumeRequest)
            || input.frames != 1
            || input.have != 0
            || input.header.is_some()
            || input.body.is_some()
            || input.candidate.is_some()
            || input.waiter
            || input.failure.is_some()
            || self.core.workers.load(Ordering::Acquire) != 1
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        // The initial Resume reader has exited without prefetch. The compact
        // original owner retains the same qualification and ordered business
        // publisher through physical retirement.
        input.direction = Direction::Responses(original.clone());
        input.terminal_message = false;
        drop(input);
        *self
            .core
            .outbound
            .lock()
            .expect("Resume continuation output") = Some((original, false));
        self.core.output_terminal.store(false, Ordering::Release);
        *self.core.resume_deadline.lock().expect("Resume deadline") = None;
        Ok(())
    }
    /// Continue only a complete accepted Resume response on its original
    /// qualified target. No raw claim or generic codec switch is available.
    pub(crate) async fn continue_resume_input(&self, original: ApplicationHeader) -> Result<()> {
        self.wait_resume_boundary().await?;
        let _sender = self.core.output.lock().await;
        let _gate = self
            .core
            .resume_gate
            .lock()
            .expect("Resume continuation gate");
        let mut input = self
            .core
            .input
            .lock()
            .expect("Resume continuation boundary");
        if self.core.closed.load(Ordering::Acquire)
            || !self.core.output_terminal.load(Ordering::Acquire)
            || !matches!(input.direction, Direction::ResumeResponses(Some(_)))
            || input.frames != 1
            || input.have != 0
            || input.header.is_some()
            || input.body.is_some()
            || input.candidate.is_some()
            || input.waiter
            || input.failure.is_some()
            || input.eof
            || self.core.workers.load(Ordering::Acquire) != 1
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        let stream = self.resume_stream()?;
        let permit = stream.resume_continuation_reader().map_err(transport)?;
        input.direction = Direction::Responses(original.clone());
        input.frames = 0;
        input.terminal_message = false;
        input.demand = false;
        drop(input);
        *self
            .core
            .outbound
            .lock()
            .expect("Resume continuation output") = Some((original, true));
        *self.core.resume_deadline.lock().expect("Resume deadline") = None;
        self.core.workers.fetch_add(1, Ordering::AcqRel);
        let reader = self.core.clone();
        tokio::spawn(async move {
            let _worker = Worker(reader.clone());
            reader.read(permit).await;
        });
        Ok(())
    }
    fn reserve_resume_input(
        account: &ResourceAccount,
        limit: usize,
    ) -> Result<(ResourceAccount, ResourceCharge, Zeroizing<Vec<u8>>)> {
        let result = account.reserve_result()?;
        let charge = result.reserve(ResourceLimits {
            sdk_bytes: 2 * limit.max(256) as u64 + 1024,
            items: 1,
            ..ResourceLimits::default()
        })?;
        Ok((
            result,
            charge,
            Zeroizing::new(Vec::with_capacity(limit.max(256))),
        ))
    }
    fn spawn_resume_reader(core: &Arc<Core>, permit: StreamReadPermit) {
        core.workers.store(2, Ordering::Release);
        let reader = core.clone();
        tokio::spawn(async move {
            let _worker = Worker(reader.clone());
            reader.read(permit).await;
        });
        let owner = core.clone();
        tokio::spawn(async move {
            let _worker = Worker(owner.clone());
            owner.cancellation.cancelled().await;
            owner.retire().await;
        });
    }
    pub(crate) fn resume_raw_stream(&self) -> Result<Stream> {
        self.resume_stream()?.resume_raw_facade().map_err(transport)
    }
    pub(crate) async fn wait_resume_boundary(&self) -> Result<()> {
        loop {
            let changed = self.core.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.core.closed.load(Ordering::Acquire) {
                return Err(failure(ServiceFailure::Closed));
            }
            if self.core.workers.load(Ordering::Acquire) == 1 {
                return Ok(());
            }
            tokio::select! { _ = changed => {}, _ = self.core.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
            _ = self.core.resume_expired() => return Err(failure(ServiceFailure::DeadlineExceeded)) }
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "The dedicated stream owner takes the original association and distinct capture, active and tail charges."
    )]
    fn core(
        session: &Session,
        account: ResourceAccount,
        tail: ApplicationTail,
        association: StreamAssociation,
        capture: ResourceCharge,
        active: ResourceCharge,
        limit: usize,
        response_to: Option<ApplicationHeader>,
    ) -> Arc<Core> {
        Arc::new(Core {
            session: session.clone(),
            account,
            stream: Mutex::new(None),
            input: Mutex::new(Input {
                prefix: [0; 514],
                have: 0,
                need: 2,
                header: None,
                body: None,
                body_charge: None,
                body_account: None,
                candidate: None,
                demand: false,
                waiter: false,
                eof: false,
                failure: None,
                frames: 0,
                direction: response_to
                    .clone()
                    .map_or(Direction::InitialRequest, Direction::Responses),
                terminal_message: false,
            }),
            limit,
            cancellation: tail.cancellation(),
            changed: Notify::new(),
            output: Arc::new(AsyncMutex::new(())),
            activated: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            output_closed: AtomicBool::new(false),
            output_terminal: AtomicBool::new(false),
            outbound: Mutex::new(response_to.map(|header| (header, true))),
            business_cancellation: Mutex::new(CancellationToken::new()),
            workers: AtomicUsize::new(1),
            retired: AtomicBool::new(false),
            tail,
            association: Mutex::new(Some(association)),
            active_charge: Mutex::new(Some(active)),
            peer_worker: Mutex::new(None),
            resume_claim: Mutex::new(None),
            resume_deadline: Mutex::new(None),
            resume_gate: Mutex::new(()),
            prepaid_resume_input: Mutex::new(None),
            _capture_charge: capture,
        })
    }
    pub(crate) fn retain_peer(&self, peer: &crate::service_peer_v4::PeerInner) {
        let mut worker = self
            .core
            .peer_worker
            .lock()
            .expect("dedicated Stream peer worker");
        if worker.is_none() {
            *worker = Some(peer.retain_worker());
        }
    }
    pub(crate) fn bind_cancellation(&self, cancellation: CancellationToken) {
        *self
            .core
            .business_cancellation
            .lock()
            .expect("dedicated Stream publication gate") = cancellation;
        self.core.changed.notify_waiters();
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.core.cancellation.child_token()
    }
    pub(crate) fn attach(&self, stream: Stream) {
        if self
            .core
            .resume_claim
            .lock()
            .expect("Resume message qualification")
            .is_some()
        {
            self.core.close();
            return;
        }
        *self.core.stream.lock().expect("dedicated Stream") = Some(Arc::new(stream));
        self.core.changed.notify_waiters();
    }
    pub(crate) fn pool_ready(&self) -> bool {
        if self.core.closed.load(Ordering::Acquire) || self.core.activated.load(Ordering::Acquire) {
            return false;
        }
        self.core
            .stream
            .lock()
            .expect("dedicated Stream")
            .as_ref()
            .is_some_and(|stream| stream.pool_ready())
    }
    pub(crate) fn activate(&self) {
        self.core.activated.store(true, Ordering::Release);
        self.core.changed.notify_waiters();
    }
    pub(crate) fn set_response_request(&self, request: ApplicationHeader) -> Result<()> {
        let mut input = self.core.input.lock().expect("dedicated Stream input");
        if matches!(
            input.direction,
            Direction::ResumeRequest | Direction::ResumeResponses(_)
        ) || input.frames != 0
            || input.have != 0
            || input.header.is_some()
        {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        input.direction = Direction::Responses(request.clone());
        drop(input);
        *self
            .core
            .outbound
            .lock()
            .expect("dedicated output association") = Some((request, true));
        Ok(())
    }
    pub(crate) fn bind_response(&self, request: ApplicationHeader) -> Result<()> {
        let mut outbound = self
            .core
            .outbound
            .lock()
            .expect("dedicated output association");
        if outbound.is_some() {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        *outbound = Some((request, false));
        Ok(())
    }
    pub(crate) async fn next(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<StreamMessage>> {
        if let Some(qualification) = self
            .core
            .resume_claim
            .lock()
            .expect("Resume message qualification")
            .as_mut()
        {
            qualification.begin();
        }
        {
            let mut input = self.core.input.lock().expect("dedicated Stream input");
            if input.waiter {
                return Err(failure(ServiceFailure::ResultModeConflict));
            }
            if matches!(
                input.direction,
                Direction::ResumeRequest | Direction::ResumeResponses(_)
            ) && input.frames != 0
                && input.candidate.is_none()
            {
                return Err(failure(ServiceFailure::ResultModeConflict));
            }
            input.waiter = true;
            input.demand = true;
        }
        let _waiter = Waiter(self.core.clone());
        self.core.changed.notify_waiters();
        loop {
            let changed = self.core.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let ready = self.core.account.with_security(|| {
                let mut input = self.core.input.lock().expect("dedicated Stream input");
                if cancellation.is_cancelled() {
                    return Err(failure(ServiceFailure::Canceled));
                }
                if self.core.closed.load(Ordering::Acquire)
                    || self
                        .core
                        .business_cancellation
                        .lock()
                        .expect("dedicated Stream publication gate")
                        .is_cancelled()
                {
                    return Err(failure(ServiceFailure::Closed));
                }
                if let Some(message) = input.candidate.take() {
                    input.demand = false;
                    return Ok(Some(Some(message)));
                }
                if let Some(error) = input.failure {
                    return Err(error);
                }
                if input.eof {
                    return Ok(Some(None));
                }
                Ok(None)
            })??;
            if let Some(message) = ready {
                self.core.changed.notify_waiters();
                return Ok(message);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = self.core.cancellation.cancelled() => {
                let input = self.core.input.lock().expect("dedicated Stream input");
                if input.failure.is_none() && !input.eof && input.candidate.is_none() { return Err(failure(ServiceFailure::Closed)); }
            } }
        }
    }
    pub(crate) async fn write(
        &self,
        header: ApplicationHeader,
        payload: &[u8],
        deadline_ms: u64,
    ) -> Result<StreamMessagePublication> {
        self.write_guarded(header, payload, deadline_ms, None).await
    }
    pub(crate) async fn write_guarded(
        &self,
        header: ApplicationHeader,
        payload: &[u8],
        deadline_ms: u64,
        first_byte_gate: Option<crate::api_v4::FirstByteGate>,
    ) -> Result<StreamMessagePublication> {
        let output = self.core.output.clone().lock_owned().await;
        self.prepare_publication(header, payload, deadline_ms, first_byte_gate, output)?
            .publish()
            .await
    }
    pub(crate) fn try_prepare_publication(
        &self,
        header: ApplicationHeader,
        payload: &[u8],
        deadline_ms: u64,
        first_byte_gate: Option<crate::api_v4::FirstByteGate>,
    ) -> Result<PreparedStreamPublication> {
        let output = self
            .core
            .output
            .clone()
            .try_lock_owned()
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        self.prepare_publication(header, payload, deadline_ms, first_byte_gate, output)
    }
    fn prepare_publication(
        &self,
        header: ApplicationHeader,
        payload: &[u8],
        deadline_ms: u64,
        first_byte_gate: Option<crate::api_v4::FirstByteGate>,
        output: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<PreparedStreamPublication> {
        self.core.account.check()?;
        if payload.len() != header.payload_bytes()?
            || payload.len() > self.core.limit.max(256)
            || self.core.closed.load(Ordering::Acquire)
            || self.core.output_closed.load(Ordering::Acquire)
            || self.core.output_terminal.load(Ordering::Acquire)
        {
            return Err(failure(ServiceFailure::Protocol));
        }
        {
            let outbound = self
                .core
                .outbound
                .lock()
                .expect("dedicated output association");
            let (request, opener) = outbound
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::Protocol))?;
            if *opener {
                if header != *request {
                    return Err(failure(ServiceFailure::Protocol));
                }
            } else {
                header.check_response(request)?;
            }
        }
        let terminal = header.sdk_error()
            || header.application_error()
            || matches!(
                header.kind(),
                "resume_request" | "resume_response" | "resume_application_error"
            );
        let charge = self.core.account.reserve(ResourceLimits {
            sdk_bytes: (2 * (payload.len() + 514)) as u64,
            items: 2,
            tasks: 1,
            ..ResourceLimits::default()
        })?;
        let mut encoded = [0; 512];
        let length = header.encode(&mut encoded)?;
        let mut wire = Vec::with_capacity(2 + length + payload.len());
        wire.extend_from_slice(&(length as u16).to_be_bytes());
        wire.extend_from_slice(&encoded[..length]);
        wire.extend_from_slice(payload);
        let stream = self.core.stream.lock().expect("dedicated Stream").clone();
        let try_now = header.kind().ends_with("_request") && header.uint(7)? == 1;
        let admission =
            if try_now {
                // A cold OPEN cannot promise immediate publication. The unchanged
                // request remains prepared until its original target is available.
                let stream = stream
                    .as_ref()
                    .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
                Some(stream.try_admit_message_publication(wire.len()).map_err(
                    |error| match error {
                        crate::SessionError::ResourceExhausted => {
                            failure(ServiceFailure::ResourceExhausted)
                        }
                        crate::SessionError::OperationFailed => {
                            failure(ServiceFailure::ServiceUnavailable)
                        }
                        _ => transport(error),
                    },
                )?)
            } else {
                None
            };
        let wait = self
            .core
            .session
            .prepare_application_wait()
            .map_err(transport)?;
        let publisher: Arc<dyn ByteStream> = Arc::new(OriginalMessagePublisher {
            core: self.core.clone(),
            wait: Mutex::new(Some(wait)),
        });
        let cancel = self.core.cancellation.clone();
        let business_cancellation = self
            .core
            .business_cancellation
            .lock()
            .expect("dedicated Stream publication gate")
            .clone();
        self.core
            .workers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |workers| {
                (workers != 0
                    && workers < 129
                    && !self.core.closed.load(Ordering::Acquire)
                    && !self.core.cancellation.is_cancelled())
                .then(|| workers + 1)
            })
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let worker = Worker(self.core.clone());
        let operation = crate::WriteOperation::try_prepare_guarded(
            publisher,
            Bytes::from(wire),
            Some(Arc::new(move |now| {
                if cancel.is_cancelled() || business_cancellation.is_cancelled() {
                    return Err(crate::SessionError::Closed);
                }
                if now.upper_ms >= deadline_ms {
                    return Err(crate::SessionError::Timeout);
                }
                if let Some(gate) = &first_byte_gate {
                    gate(now)?;
                }
                Ok(())
            })),
        )
        .map_err(|error| match error {
            crate::SessionError::ResourceExhausted => failure(ServiceFailure::ResourceExhausted),
            _ => transport(error),
        })?;
        Ok(PreparedStreamPublication {
            core: self.core.clone(),
            operation,
            terminal,
            _admission: admission,
            worker: Some(worker),
            charge: Some(charge),
            output: Some(output),
        })
    }
    pub(crate) async fn close_write(&self) -> Result<()> {
        let wait = self
            .core
            .session
            .prepare_application_wait()
            .map_err(transport)?;
        self.close_write_prepared(wait).await
    }
    pub(crate) async fn close_write_prepared(&self, wait: ResourceCharge) -> Result<()> {
        let stream = self
            .core
            .stream
            .lock()
            .expect("dedicated Stream")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let _output = self.core.output.lock().await;
        if !self.core.output_closed.swap(true, Ordering::AcqRel) {
            stream
                .close_message_write_prepared(wait)
                .await
                .map_err(transport)?;
        }
        Ok(())
    }
    pub(crate) async fn finish(&self) -> Result<()> {
        self.close_write().await?;
        let stream = self
            .core
            .stream
            .lock()
            .expect("dedicated Stream")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let finished = tokio::time::timeout(Duration::from_secs(30), stream.finish())
            .await
            .map_err(|_| failure(ServiceFailure::DeadlineExceeded))?
            .map_err(transport);
        if finished.is_ok()
            && let Some(qualification) = self
                .core
                .resume_claim
                .lock()
                .expect("completed Resume continuation")
                .as_mut()
        {
            qualification.settle();
        }
        self.core.close();
        finished
    }
    pub(crate) fn close(&self) {
        self.core.close();
    }
    pub(crate) fn cleanup_status(&self) -> CleanupStatus {
        let workers = self.core.workers.load(Ordering::Acquire);
        let complete = workers == 0 && self.core.retired.load(Ordering::Acquire);
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: if complete { 0 } else { workers.max(1) as u64 },
        }
    }
    pub(crate) async fn wait_cleanup(&self) -> CleanupStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let changed = self.core.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(deadline) => return self.cleanup_status() }
        }
    }
}
impl Drop for StreamMessages {
    fn drop(&mut self) {
        self.core.close();
    }
}
impl Core {
    fn close(&self) {
        let _gate = self.resume_gate.lock().expect("Resume handoff gate");
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancellation.cancel();
        let (candidate, body, charge, account) = {
            let mut input = self.input.lock().expect("dedicated Stream input");
            input.demand = false;
            let account = input.body_account.take();
            (
                input.candidate.take(),
                input.body.take(),
                input.body_charge.take(),
                account,
            )
        };
        drop((candidate, body, charge, account));
        self.changed.notify_waiters();
    }
    fn fail(&self, error: ServiceError) {
        let mut input = self.input.lock().expect("dedicated Stream input");
        if input.failure.is_none() {
            input.failure = Some(error);
        }
        drop(input);
        self.changed.notify_waiters();
    }
    async fn retire(&self) {
        self.cancellation.cancel();
        self.changed.notify_waiters();
        let stream = self.stream.lock().expect("dedicated Stream").take();
        if let Some(stream) = stream {
            // Successful Resume preserves the caller-owned target. An unsettled
            // qualification resets only that target when the last worker exits.
            if self
                .resume_claim
                .lock()
                .expect("Resume message qualification")
                .is_some()
            {
                return;
            }
            let _ = stream.reset().await;
            loop {
                if stream.cleanup_status().complete {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    async fn resume_expired(&self) {
        let deadline = *self.resume_deadline.lock().expect("Resume deadline");
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    }
    async fn read(self: &Arc<Self>, permit: StreamReadPermit) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let business = self
                .business_cancellation
                .lock()
                .expect("dedicated Stream publication gate")
                .clone();
            {
                let input = self.input.lock().expect("Resume reader boundary");
                if matches!(
                    input.direction,
                    Direction::ResumeRequest | Direction::ResumeResponses(_)
                ) && input.frames == 1
                    && input.have == 0
                    && input.header.is_none()
                    && input.body.is_none()
                {
                    // Drop the original permit here; never inspect the next byte.
                    return;
                }
            }
            if self.cancellation.is_cancelled()
                || business.is_cancelled()
                || self
                    .resume_deadline
                    .lock()
                    .expect("Resume deadline")
                    .is_some_and(|deadline| Instant::now() >= deadline)
            {
                self.close();
                return;
            }
            let need = {
                let input = self.input.lock().expect("dedicated Stream input");
                if !self.activated.load(Ordering::Acquire)
                    || !input.demand
                    || input.candidate.is_some()
                    || input.eof
                    || input.failure.is_some()
                {
                    None
                } else {
                    Some(match &input.header {
                        Some(header) => header
                            .payload_bytes()
                            .unwrap_or(0)
                            .saturating_sub(input.body.as_ref().map_or(0, |body| body.len())),
                        None => input.need - input.have,
                    })
                }
            };
            let Some(need) = need else {
                tokio::select! { _ = changed => {}, _ = self.cancellation.cancelled() => return,
                _ = business.cancelled() => { self.close(); return; },
                _ = self.resume_expired() => { self.close(); return; } };
                continue;
            };
            if need == 0 {
                if let Err(error) = self.complete_frame(ReadStreamStatus::Open) {
                    self.fail(error);
                }
                continue;
            }
            let stream = self.stream.lock().expect("dedicated Stream").clone();
            let Some(stream) = stream else {
                tokio::select! { _ = changed => {}, _ = self.cancellation.cancelled() => return,
                _ = business.cancelled() => { self.close(); return; },
                _ = self.resume_expired() => { self.close(); return; } };
                continue;
            };
            let read = tokio::select! {
                read = stream.read_with_permit(need.min(FLOOR), &permit) => read,
                _ = changed => continue,
                _ = self.cancellation.cancelled() => return,
                _ = business.cancelled() => { self.close(); return; },
                _ = self.resume_expired() => { self.close(); return; },
            };
            let read = match read {
                Ok(read) => read,
                Err(_) => {
                    self.fail(failure(ServiceFailure::ServiceUnavailable));
                    return;
                }
            };
            if !read.data.is_empty()
                && let Err(error) = self.advance(&read.data, read.stream_status)
            {
                self.fail(error);
                return;
            }
            if read.stream_status != ReadStreamStatus::Open {
                if let Err(error) = self.complete_frame(read.stream_status) {
                    self.fail(error);
                    return;
                }
                let mut input = self.input.lock().expect("dedicated Stream input");
                if read.stream_status == ReadStreamStatus::Aborted {
                    input.failure = Some(failure(ServiceFailure::ServiceUnavailable));
                } else if input.have != 0 || input.header.is_some() {
                    input.failure = Some(failure(ServiceFailure::Protocol));
                } else {
                    input.eof = true;
                }
                drop(input);
                self.changed.notify_waiters();
                // Retain the original reader/ReplySlot until the owning handle
                // consumes its candidate and explicitly finishes or abandons.
            }
        }
    }
    fn advance(&self, bytes: &[u8], terminal: ReadStreamStatus) -> Result<()> {
        let pending = {
            let mut input = self.input.lock().expect("dedicated Stream input");
            if let Some(header) = &input.header {
                let limit = header.payload_bytes()?;
                let body = input
                    .body
                    .as_mut()
                    .ok_or_else(|| failure(ServiceFailure::Protocol))?;
                if body
                    .len()
                    .checked_add(bytes.len())
                    .is_none_or(|length| length > limit)
                {
                    return Err(failure(ServiceFailure::Protocol));
                }
                body.extend_from_slice(bytes);
                None
            } else {
                if input.have + bytes.len() > input.need {
                    return Err(failure(ServiceFailure::Protocol));
                }
                let start = input.have;
                input.prefix[start..start + bytes.len()].copy_from_slice(bytes);
                input.have += bytes.len();
                if input.have == 2 && input.need == 2 {
                    let length = u16::from_be_bytes([input.prefix[0], input.prefix[1]]) as usize;
                    if length == 0 || length > 512 {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    input.need = 2 + length;
                    None
                } else if input.have == input.need {
                    let header = ApplicationHeader::decode(&input.prefix[2..input.need])?;
                    match &input.direction {
                        Direction::InitialRequest => {
                            if input.frames != 0
                                || !matches!(
                                    header.kind(),
                                    "execution_stream_request" | "transient_stream_request"
                                )
                            {
                                return Err(failure(ServiceFailure::Protocol));
                            }
                        }
                        Direction::ResumeRequest => {
                            if input.frames != 0 || header.kind() != "resume_request" {
                                return Err(failure(ServiceFailure::Protocol));
                            }
                        }
                        Direction::ResumeResponses(request) => {
                            let request = request
                                .as_ref()
                                .ok_or_else(|| failure(ServiceFailure::Protocol))?;
                            if input.frames != 0
                                || !matches!(
                                    header.kind(),
                                    "resume_response" | "resume_application_error"
                                )
                            {
                                return Err(failure(ServiceFailure::Protocol));
                            }
                            header.check_response(request)?;
                        }
                        Direction::Responses(request) => {
                            if input.terminal_message {
                                return Err(failure(ServiceFailure::Protocol));
                            }
                            header.check_response(request)?;
                            if !matches!(
                                header.kind(),
                                "execution_stream_item"
                                    | "transient_stream_item"
                                    | "execution_stream_application_error"
                                    | "transient_stream_application_error"
                                    | "execution_stream_sdk_error"
                                    | "transient_stream_sdk_error"
                            ) {
                                return Err(failure(ServiceFailure::Protocol));
                            }
                        }
                    }
                    let length = header.payload_bytes()?;
                    if length > if header.sdk_error() { 256 } else { self.limit } {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    Some((header, length))
                } else {
                    None
                }
            }
        };
        if let Some((header, length)) = pending {
            // Complete header boundary: acquire the entire body before reading
            // any body byte. Resource/security methods never run under input.
            let prepaid = self
                .prepaid_resume_input
                .lock()
                .expect("Resume prepaid input")
                .take();
            let (account, charge, body) = match prepaid {
                Some((account, charge, body)) => {
                    if length > body.capacity() {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    (account, charge, body)
                }
                None => {
                    if matches!(
                        header.kind(),
                        "resume_request" | "resume_response" | "resume_application_error"
                    ) {
                        return Err(failure(ServiceFailure::Protocol));
                    }
                    let account = self.account.reserve_result()?;
                    let charge = account.reserve(ResourceLimits {
                        sdk_bytes: 2 * length.max(256) as u64 + 1024,
                        items: 1,
                        ..ResourceLimits::default()
                    })?;
                    (
                        account,
                        charge,
                        Zeroizing::new(Vec::with_capacity(length.max(256))),
                    )
                }
            };
            let mut prepared = Some((body, charge, account, header));
            self.account.with_security(|| {
                let mut input = self.input.lock().expect("dedicated Stream input");
                if self.closed.load(Ordering::Acquire) || self.cancellation.is_cancelled() {
                    return Err(failure(ServiceFailure::Closed));
                }
                let (body, charge, account, header) =
                    prepared.take().expect("prepaid dedicated body");
                input.body = Some(body);
                input.body_charge = Some(charge);
                input.body_account = Some(account);
                input.header = Some(header);
                Ok(())
            })??;
            drop(prepared);
        }
        self.complete_frame(terminal)
    }
    fn complete_frame(&self, terminal: ReadStreamStatus) -> Result<()> {
        let complete = {
            let mut input = self.input.lock().expect("dedicated Stream input");
            if input.header.as_ref().is_none_or(|header| {
                input
                    .body
                    .as_ref()
                    .is_none_or(|body| body.len() != header.payload_bytes().unwrap_or(usize::MAX))
            }) {
                return Ok(());
            }
            if input.candidate.is_some() {
                return Err(failure(ServiceFailure::Protocol));
            }
            let header = input.header.take().expect("complete dedicated header");
            input.terminal_message |= header.sdk_error()
                || header.application_error()
                || matches!(
                    header.kind(),
                    "resume_request" | "resume_response" | "resume_application_error"
                );
            let payload = input.body.take().expect("complete dedicated payload");
            if header.kind() == "resume_request" {
                crate::checkpoint_v4::ApplicationResumeRequest::capture(&payload)?;
            }
            if header.kind() == "resume_response" {
                crate::ApplicationResumeResult::capture(&payload)?;
            }
            let charge = input.body_charge.take().expect("prepaid dedicated payload");
            let account = input
                .body_account
                .take()
                .expect("original dedicated result account");
            input.frames = input
                .frames
                .checked_add(1)
                .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
            input.have = 0;
            input.need = 2;
            input.demand = false;
            if terminal == ReadStreamStatus::Eof {
                input.eof = true;
            } else if terminal == ReadStreamStatus::Aborted {
                input.failure = Some(failure(ServiceFailure::ServiceUnavailable));
            }
            (
                StreamMessage {
                    header,
                    payload,
                    charge,
                    following_terminal: terminal,
                },
                account,
            )
        };
        let (message, account) = complete;
        account.detach_result();
        let mut candidate = Some(message);
        account.with_security(|| {
            let mut input = self.input.lock().expect("dedicated Stream input");
            if !self.closed.load(Ordering::Acquire) {
                input.candidate = candidate.take();
            }
        })?;
        drop(candidate);
        self.changed.notify_waiters();
        Ok(())
    }
}
