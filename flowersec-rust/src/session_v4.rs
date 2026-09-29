//! Application handles over the original authenticated reliable owner.
//! Construction requires a real carrier and original once admission to provide
//! the completed READY owner and its ordered transport lifetime.
use super::*;
use crate::api_v4::{
    CleanupStatus, ReadCause, ReadError, ReadProgress, ReadResult, ReadStreamStatus,
    ReadWaitStatus, ReaderCursor, StreamReadOwner, WriteRequestAdmission, WriteStagingOwner,
};
use crate::application_lifetime_v4::ApplicationLifetime;
use crate::environment_v4::{EnvironmentError, EnvironmentRoot};
use crate::transport::{ByteStream, SessionError, SessionTermination};
use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, atomic::AtomicBool};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use unicode_normalization::UnicodeNormalization;

const QUANTUM: usize = 16 * 1024;

/// Immutable ordinary metadata. The empty object has the sole zero-byte wire
/// representation; nonempty metadata retains its exact canonical encoding.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Metadata(Bytes);

/// Primitive type accepted by a fixed raw Stream metadata projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawStreamMetadataType {
    String,
    Number,
    Boolean,
}

/// One bounded field in a raw Stream metadata projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawStreamMetadataField {
    pub name: String,
    pub value_type: RawStreamMetadataType,
    pub required: bool,
}

/// Data-only descriptor for projecting a fixed JSON metadata namespace.
/// It never changes the authenticated metadata bytes or installs a decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawStreamMetadataContract {
    pub contract_id: String,
    pub namespace: String,
    pub version: u16,
    pub codec: String,
    pub fields: Vec<RawStreamMetadataField>,
    pub max_encoded_bytes: usize,
    pub max_decoded_bytes: usize,
}

fn metadata_identifier(value: &str, max: usize) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max
        && value.nfc().eq(value.chars())
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn metadata_namespace(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with("flowersec/")
        || !value.is_ascii()
        || !value.nfc().eq(value.chars())
    {
        return false;
    }
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    fn part(value: &str) -> bool {
        let bytes = value.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 32
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
    }
    part(owner) && part(name)
}

impl RawStreamMetadataContract {
    /// Validate and freeze the descriptor shape used by projection.
    pub fn capture(mut self) -> std::result::Result<Self, SessionError> {
        if !metadata_identifier(&self.contract_id, 128)
            || !metadata_namespace(&self.namespace)
            || self.codec != "application/json"
            || self.fields.len() > 64
            || self.max_encoded_bytes == 0
            || self.max_encoded_bytes > 4096
            || self.max_decoded_bytes == 0
            || self.max_decoded_bytes > 4096
        {
            return Err(SessionError::OperationFailed);
        }
        let mut names = std::collections::BTreeSet::new();
        for field in &mut self.fields {
            if !metadata_identifier(&field.name, 64) || !names.insert(field.name.clone()) {
                return Err(SessionError::OperationFailed);
            }
        }
        Ok(self)
    }
}

impl Metadata {
    pub fn empty() -> Self {
        Self::default()
    }
    /// Capture ordinary application metadata without interpreting its bytes.
    /// Namespace, Unicode, byte and item limits use the current wire schema.
    pub fn new(
        namespace: &str,
        version: u16,
        values: &std::collections::BTreeMap<String, Bytes>,
    ) -> std::result::Result<Self, SessionError> {
        if !metadata_namespace(namespace) || values.len() > 64 {
            return Err(SessionError::OperationFailed);
        }
        fn head_size(value: usize) -> usize {
            if value < 24 {
                1
            } else if value <= 255 {
                2
            } else {
                3
            }
        }
        let mut fields = Vec::with_capacity(values.len());
        let mut size = 4
            + head_size(namespace.len())
            + namespace.len()
            + head_size(usize::from(version))
            + head_size(values.len());
        for (key, value) in values {
            if key.is_empty() || key.len() > 64 || value.len() > 1024 {
                return Err(SessionError::OperationFailed);
            }
            size += head_size(key.len()) + key.len() + head_size(value.len()) + value.len();
            if size > 4096 {
                return Err(SessionError::OperationFailed);
            }
            fields.push((key, value));
        }
        fields.sort_unstable_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then(a.cmp(b)));
        let mut wire = Vec::with_capacity(size);
        codec::encode_head(&mut wire, 5, 3);
        codec::encode_head(&mut wire, 0, 0);
        codec::encode_head(&mut wire, 3, namespace.len() as u64);
        wire.extend_from_slice(namespace.as_bytes());
        codec::encode_head(&mut wire, 0, 1);
        codec::encode_head(&mut wire, 0, u64::from(version));
        codec::encode_head(&mut wire, 0, 2);
        codec::encode_head(&mut wire, 5, fields.len() as u64);
        for (key, value) in fields {
            codec::encode_head(&mut wire, 3, key.len() as u64);
            wire.extend_from_slice(key.as_bytes());
            codec::encode_head(&mut wire, 2, value.len() as u64);
            wire.extend_from_slice(value);
            if wire.len() > 4096 {
                return Err(SessionError::OperationFailed);
            }
        }
        Self::from_encoded(&wire)
    }
    pub fn from_encoded(encoded: &[u8]) -> std::result::Result<Self, SessionError> {
        if !encoded.is_empty() {
            decode(encoded, "StreamMetadata", 4096, Context::default()).map_err(error)?;
        }
        Ok(Self(Bytes::copy_from_slice(encoded)))
    }
    pub fn encoded(&self) -> &[u8] {
        &self.0
    }
    pub fn namespace(&self) -> Option<&str> {
        self.projection()?
            .field("StreamMetadata", "namespace")
            .ok()?
            .text()
            .ok()
    }
    pub fn version(&self) -> Option<u16> {
        self.projection()?
            .field("StreamMetadata", "version")
            .ok()?
            .uint()
            .ok()
            .map(|v| v as u16)
    }
    /// Return immutable byte values detached from the retained wire storage.
    pub fn byte_values(&self) -> std::collections::BTreeMap<String, Bytes> {
        let mut result = std::collections::BTreeMap::new();
        if let Some(document) = self.projection() {
            let mut fields = document
                .field("StreamMetadata", "values")
                .expect("validated metadata values")
                .children()
                .expect("validated metadata map");
            while let Some(key) = fields.next() {
                let key = key
                    .expect("validated metadata key")
                    .text()
                    .expect("validated metadata text");
                let value = fields
                    .next()
                    .expect("validated metadata entry")
                    .expect("validated metadata value")
                    .bytes()
                    .expect("validated metadata bytes");
                result.insert(key.to_owned(), Bytes::copy_from_slice(value));
            }
        }
        result
    }
    /// Apply a captured fixed JSON descriptor without changing the original
    /// metadata. The returned values are detached and bounded by the
    /// descriptor's encoded/decoded caps.
    pub fn project_raw(
        &self,
        contract: &RawStreamMetadataContract,
    ) -> std::result::Result<BTreeMap<String, JsonValue>, SessionError> {
        let contract = contract.clone().capture()?;
        if self.encoded().len() > contract.max_encoded_bytes
            || self.namespace() != Some(contract.namespace.as_str())
            || self.version() != Some(contract.version)
        {
            return Err(SessionError::OperationFailed);
        }
        let fields: BTreeMap<&str, &RawStreamMetadataField> = contract
            .fields
            .iter()
            .map(|field| (field.name.as_str(), field))
            .collect();
        let bytes = self.byte_values();
        if bytes.keys().any(|key| !fields.contains_key(key.as_str()))
            || contract
                .fields
                .iter()
                .any(|field| field.required && !bytes.contains_key(&field.name))
        {
            return Err(SessionError::OperationFailed);
        }
        let mut output = BTreeMap::new();
        let mut decoded = 0usize;
        for (key, encoded) in bytes {
            let value: JsonValue =
                serde_json::from_slice(&encoded).map_err(|_| SessionError::OperationFailed)?;
            let field = fields
                .get(key.as_str())
                .ok_or(SessionError::OperationFailed)?;
            let width = match (field.value_type, &value) {
                (RawStreamMetadataType::String, JsonValue::String(value)) => value.len(),
                (RawStreamMetadataType::Number, JsonValue::Number(value))
                    if value.as_f64().is_some_and(f64::is_finite) =>
                {
                    8
                }
                (RawStreamMetadataType::Boolean, JsonValue::Bool(_)) => 1,
                _ => return Err(SessionError::OperationFailed),
            };
            decoded = decoded
                .checked_add(key.len())
                .and_then(|total| total.checked_add(width))
                .ok_or(SessionError::OperationFailed)?;
            if decoded > contract.max_decoded_bytes {
                return Err(SessionError::OperationFailed);
            }
            output.insert(key, value);
        }
        Ok(output)
    }
    fn projection(&self) -> Option<Value<'_>> {
        if self.0.is_empty() {
            return None;
        }
        Some(
            decode(&self.0, "StreamMetadata", 4096, Context::default())
                .expect("immutable validated metadata"),
        )
    }
}

/// The concrete carrier retains its own original cancellation and cleanup
/// state. Dropping a queue entry is never claimed as physical transport cleanup.
pub(crate) trait SessionTransport: RecordPublisher + Send {
    fn close(&mut self);
    fn cleanup_status(&self) -> CleanupStatus;
    fn stream_cleanup_status(&self, scope: u64) -> CleanupStatus;
}
struct Drive {
    session: Option<ReliableSession>,
    transport: Box<dyn SessionTransport>,
    termination: Option<SessionError>,
    termination_at: Option<Instant>,
    close_deadline: Option<Instant>,
}
struct Owner {
    drive: Mutex<Drive>,
    account: ResourceAccount,
    staging: Arc<WriteStagingOwner>,
    changed: Arc<Notify>,
    core_stopped: AtomicBool,
    worker_done: AtomicBool,
    registered_dispatch: AtomicBool,
    authentication_waiters: AtomicUsize,
    drain: Mutex<Option<Arc<controls::Drain>>>,
    application: Arc<OnceLock<Arc<ApplicationLifetime>>>,
    _charge: ResourceCharge,
}
impl Owner {
    fn run<T>(
        &self,
        action: impl FnOnce(
            &mut ReliableSession,
            &mut dyn SessionTransport,
        ) -> std::result::Result<T, SessionError>,
    ) -> std::result::Result<T, SessionError> {
        let mut drive = self.drive.lock().expect("v4 Session owner lock");
        let result = {
            let Drive {
                session,
                transport,
                termination,
                ..
            } = &mut *drive;
            if let Some(cause) = termination {
                return Err(*cause);
            }
            let session = session.as_mut().ok_or(SessionError::Closed)?;
            let result = action(session, transport.as_mut());
            if result.as_ref().err() == Some(&SessionError::ResourceExhausted) {
                session.local_liveness_stall();
            }
            result
        };
        if drive
            .session
            .as_ref()
            .is_some_and(|session| session.engine.closed)
        {
            Self::close_locked(
                &mut drive,
                result
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(SessionError::Closed),
            );
            self.staging.close();
        }
        result
    }
    fn close_locked(drive: &mut Drive, cause: SessionError) {
        if drive.termination.is_none() {
            if let Some(application) = drive.session.as_ref().and_then(|s| s.application.as_ref()) {
                application.close();
            }
            drive.termination = Some(cause);
            drive.termination_at = Some(Instant::now());
            drive.close_deadline = Some(Instant::now() + Duration::from_secs(5));
            if let Some(mut session) = drive.session.take() {
                session.engine.fail();
            }
            drive.transport.close();
        }
    }
    fn close(&self, cause: SessionError) {
        Self::close_locked(
            &mut self.drive.lock().expect("v4 Session owner lock"),
            cause,
        );
        self.staging.close();
        self.close_application();
        self.changed.notify_waiters();
    }
    fn close_application(&self) {
        if let Some(application) = self.application.get() {
            application.close();
        }
    }
    fn wait_charge(&self) -> std::result::Result<ResourceCharge, SessionError> {
        self.account
            .reserve(ResourceLimits {
                sdk_bytes: 256,
                items: 1,
                work_slots: 1,
                tasks: 1,
                sessions: 0,
                ..ResourceLimits::default()
            })
            .map_err(environment_error)
    }
    fn core_cleanup(&self) -> CleanupStatus {
        let drive = self.drive.lock().expect("v4 Session owner lock");
        let physical = drive.transport.cleanup_status();
        let complete = drive.termination.is_some()
            && physical.complete
            && self.core_stopped.load(Ordering::Acquire);
        CleanupStatus {
            complete,
            cleanup_incomplete: physical.cleanup_incomplete
                || (!complete && drive.close_deadline.is_some_and(|d| Instant::now() >= d)),
            pending_callbacks: physical.pending_callbacks,
        }
    }
    fn cleanup(&self) -> CleanupStatus {
        let mut status = self.core_cleanup();
        status.complete &= self.worker_done.load(Ordering::Acquire);
        if let Some(application) = self.application.get() {
            let app = application.cleanup_status();
            status.complete &= app.complete;
            status.cleanup_incomplete |= app.cleanup_incomplete;
            status.pending_callbacks += app.pending_callbacks;
        }
        status
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        Self::close_locked(
            self.drive.get_mut().expect("v4 Session owner lock"),
            SessionError::Closed,
        );
        self.staging.close();
        self.close_application();
        self.changed.notify_waiters();
    }
}
fn environment_error(value: EnvironmentError) -> SessionError {
    match value {
        EnvironmentError::Capacity => SessionError::ResourceExhausted,
        EnvironmentError::Closed => SessionError::Closed,
        _ => SessionError::OperationFailed,
    }
}
fn error(value: CryptoError) -> SessionError {
    match value {
        CryptoError::Capacity => SessionError::ResourceExhausted,
        CryptoError::Deadline => SessionError::Timeout,
        CryptoError::LivenessPathUnresponsive => SessionError::LivenessPathUnresponsive,
        CryptoError::Authorization(e) => environment_error(e),
        _ => SessionError::OperationFailed,
    }
}

/// A Session produced only by consuming the original authenticated READY owner.
#[derive(Clone)]
pub struct Session {
    owner: Arc<Owner>,
}
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("V4Session { <opaque> }")
    }
}
pub(crate) struct SessionReceiver {
    owner: std::sync::Weak<Owner>,
}
impl SessionReceiver {
    pub(crate) fn receive(&self, wire: &[u8]) -> std::result::Result<(), SessionError> {
        let owner = self.owner.upgrade().ok_or(SessionError::Closed)?;
        Session { owner }.receive(wire)
    }
    pub(crate) fn close(&self) {
        if let Some(owner) = self.owner.upgrade() {
            owner.close(SessionError::OperationFailed);
        }
    }
}
impl Session {
    #[cfg(test)]
    pub(crate) fn application_test_account(&self) -> ResourceAccount {
        self.owner.account.clone()
    }
    #[cfg(test)]
    pub(crate) fn rekey_diagnostic(&self) -> String {
        let Ok(drive) = self.owner.drive.try_lock() else {
            return "original owner busy".into();
        };
        match &drive.session {
            Some(session) => session.engine.rekey_diagnostic(),
            None => format!("terminated: {:?}", drive.termination),
        }
    }
    pub(crate) fn receiver(&self) -> SessionReceiver {
        SessionReceiver {
            owner: Arc::downgrade(&self.owner),
        }
    }
    pub(crate) fn adopt(
        environment: &Arc<EnvironmentRoot>,
        engine: RecordEngine,
        transport: Box<dyn SessionTransport>,
        reserved: Option<ResourceCharge>,
    ) -> std::result::Result<Self, SessionError> {
        if !engine.account.belongs_to(environment) {
            return Err(SessionError::OperationFailed);
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| SessionError::OperationFailed)?;
        let session = engine.into_session().map_err(error)?;
        let account = session.engine.account.clone();
        let mut charge = match reserved {
            Some(charge) => charge,
            None => account
                .reserve(ResourceLimits {
                    sdk_bytes: 4096,
                    items: 1,
                    timers: 2,
                    work_slots: 1,
                    tasks: 1,
                    sessions: 0,
                    ..ResourceLimits::default()
                })
                .map_err(environment_error)?,
        };
        let task_charge = charge
            .split(ResourceLimits {
                tasks: 1,
                timers: 2,
                ..ResourceLimits::default()
            })
            .map_err(environment_error)?;
        let changed = Arc::new(Notify::new());
        let application = Arc::new(OnceLock::<Arc<ApplicationLifetime>>::new());
        let owner = Arc::new(Owner {
            authentication_waiters: AtomicUsize::new(0),
            drive: Mutex::new(Drive {
                session: Some(session),
                transport,
                termination: None,
                termination_at: None,
                close_deadline: None,
            }),
            account: account.clone(),
            staging: Arc::new(WriteStagingOwner::from_account(account.clone())),
            changed: changed.clone(),
            core_stopped: AtomicBool::new(false),
            worker_done: AtomicBool::new(false),
            registered_dispatch: AtomicBool::new(false),
            drain: Mutex::new(None),
            application: application.clone(),
            _charge: charge,
        });
        let weak = Arc::downgrade(&owner);
        runtime.spawn(async move {
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let Some(owner) = weak.upgrade() else {
                    break;
                };
                let alive = owner
                    .drive
                    .lock()
                    .expect("v4 Session owner lock")
                    .termination
                    .is_none();
                if !alive {
                    owner.core_stopped.store(true, Ordering::Release);
                    owner.changed.notify_waiters();
                    break;
                }
                let action = owner.run(|session, transport| session.poll(transport).map_err(error));
                match action {
                    Ok(true) => owner.changed.notify_waiters(),
                    Ok(false) => {}
                    Err(cause) => owner.close(cause),
                }
                drop(owner);
                tokio::select! {
                    _ = notified => {},
                    _ = account.security_changed() => {},
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
            }
            // The same prepaid Session worker retains unconfirmed application
            // ownership even when every public Session handle is dropped.
            if let Some(application) = application.get() {
                application.close();
                let changed = application.changed();
                loop {
                    let notified = changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if application.cleanup_status().complete {
                        break;
                    }
                    notified.await;
                }
            }
            drop(application);
            drop(task_charge);
            // No application or core work remains, and the original task
            // capacity is returned before any observer can see completion.
            if let Some(owner) = weak.upgrade() {
                owner.worker_done.store(true, Ordering::Release);
            }
            changed.notify_waiters();
        });
        Ok(Self { owner })
    }
    pub(crate) fn attach_application(
        &self,
        application: Arc<ApplicationLifetime>,
    ) -> std::result::Result<(), SessionError> {
        if !application.belongs_to(&self.owner.account) {
            return Err(SessionError::OperationFailed);
        }
        let mut drive = self.owner.drive.lock().expect("v4 Session owner lock");
        if self.owner.application.get().is_some() || drive.termination.is_some() {
            return Err(SessionError::Closed);
        }
        let session = drive.session.as_mut().ok_or(SessionError::Closed)?;
        if session.engine.closed || session.engine.streams.draining {
            return Err(SessionError::Closed);
        }
        application
            .attach(self.owner.changed.clone(), || {
                session.application = Some(application.clone());
                self.owner
                    .application
                    .set(application.clone())
                    .expect("single application attachment");
            })
            .map_err(environment_error)?;
        Ok(())
    }
    pub(crate) fn core_cleanup_status(&self) -> CleanupStatus {
        self.owner.core_cleanup()
    }
    pub(crate) fn bind_registered_dispatch(&self) {
        self.owner
            .registered_dispatch
            .store(true, Ordering::Release);
    }
    /// The shared reader supplies only its authenticated Session association.
    /// Failure before a DATA tag authenticates cannot be assigned to a stream.
    pub(crate) fn receive(&self, wire: &[u8]) -> std::result::Result<(), SessionError> {
        if wire.len() < 28 {
            self.owner.close(SessionError::OperationFailed);
            return Err(SessionError::OperationFailed);
        }
        let scope = u64::from_be_bytes(
            wire[12..20]
                .try_into()
                .map_err(|_| SessionError::OperationFailed)?,
        );
        let result = self.owner.run(|session, transport| {
            session.observe_liveness_provider(transport);
            session.receive(scope, wire).map_err(error)
        });
        self.owner.changed.notify_waiters();
        result
    }
    pub async fn open_stream(
        &self,
        kind: &str,
        metadata: Metadata,
        receive_window: u64,
    ) -> std::result::Result<Stream, SessionError> {
        let _wait = self.owner.wait_charge()?;
        let handle = self.owner.run(|session, transport| {
            session
                .open_stream(kind, metadata.encoded(), receive_window, transport)
                .map_err(error)
        })?;
        let mut guard = Opening {
            owner: self.owner.clone(),
            handle: Some(handle.clone()),
        };
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let phase = self
                .owner
                .run(|session, _| session.phase(&handle).map_err(error))?;
            match phase {
                StreamPhase::Accepted => {
                    let stream = Stream::new(self.owner.clone(), handle, kind.to_owned())?;
                    guard.handle = None;
                    return Ok(stream);
                }
                StreamPhase::Recent | StreamPhase::Stable => {
                    return Err(SessionError::StreamRejected);
                }
                _ => notified.await,
            }
        }
    }
    /// Transfers one bounded pending request to its application authorizer.
    /// Dropping the request submits the ordinary authenticated rejection.
    pub async fn next_open(&self) -> std::result::Result<OpenRequest, SessionError> {
        if self.owner.registered_dispatch.load(Ordering::Acquire) {
            return Err(SessionError::OperationFailed);
        }
        self.next_registered_open().await
    }
    pub(crate) async fn next_registered_open(
        &self,
    ) -> std::result::Result<OpenRequest, SessionError> {
        let wait = self
            .owner
            .account
            .reserve(ResourceLimits {
                sdk_bytes: 8192,
                items: 1,
                work_slots: 1,
                tasks: 1,
                sessions: 0,
                ..ResourceLimits::default()
            })
            .map_err(environment_error)?;
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let request = self.owner.run(|session, _| {
                let Some(handle) = session.pending_open().map_err(error)? else {
                    return Ok(None);
                };
                let (kind, metadata) = session.pending_metadata(&handle).map_err(error)?;
                let projection = Metadata::from_encoded(metadata);
                match projection {
                    Ok(metadata) => Ok(Some((handle, kind.to_owned(), metadata))),
                    Err(_) => {
                        let i = session.engine.streams.resolve(&handle).map_err(error)?;
                        session.engine.streams.slots[i].forced_rejection =
                            Some(Rejection::Metadata);
                        Ok(None)
                    }
                }
            })?;
            if let Some((handle, kind, metadata)) = request {
                return Ok(OpenRequest {
                    owner: self.owner.clone(),
                    handle: Some(handle),
                    kind,
                    metadata,
                    _charge: wait,
                });
            }
            notified.await;
        }
    }
    pub async fn rekey(&self) -> std::result::Result<(), SessionError> {
        let _wait = self.owner.wait_charge()?;
        let epoch = self.owner.run(|session, transport| {
            let epoch = session.engine.epoch;
            session.rekey(transport).map_err(error)?;
            Ok(epoch)
        })?;
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.owner.run(|session, _| {
                session.check().map_err(error)?;
                Ok(session.engine.epoch > epoch)
            })? {
                return Ok(());
            }
            notified.await;
        }
    }
    /// Measures the authenticated maintenance path, including local queue time.
    /// Cancellation detaches this original matcher without closing the Session.
    pub async fn probe_liveness(
        &self,
        timeout: Duration,
    ) -> std::result::Result<ProbeResult, SessionError> {
        let probe = self.owner.run(|session, _| {
            session.check().map_err(error)?;
            if session.engine.rekey.busy() || session.engine.frozen {
                return Ok(None);
            }
            session.start_probe(timeout).map(Some).map_err(error)
        })?;
        let Some(probe) = probe else {
            return Ok(ProbeResult {
                outcome: ProbeOutcome::RekeyInProgress,
                submitted: false,
                complete: false,
                elapsed: Some(Duration::ZERO),
            });
        };
        let _guard = ProbeWait {
            owner: self.owner.clone(),
            probe: probe.clone(),
        };
        self.owner.changed.notify_waiters();
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let result = probe.snapshot();
            if result.outcome != ProbeOutcome::Pending {
                return Ok(result);
            }
            tokio::select! { _ = notified => {}, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
        }
    }
    /// Atomically closes new admission. Repeated calls return the same operation
    /// and cannot extend its original deadline, including after termination.
    pub fn drain(&self, timeout: Duration) -> std::result::Result<DrainOperation, SessionError> {
        let mut retained = self.owner.drain.lock().expect("v4 retained drain");
        if let Some(drain) = retained.as_ref() {
            return Ok(DrainOperation {
                owner: self.owner.clone(),
                drain: drain.clone(),
            });
        }
        let drain = self
            .owner
            .run(|session, _| session.start_drain(timeout).map_err(error))?;
        *retained = Some(drain.clone());
        self.owner.changed.notify_waiters();
        Ok(DrainOperation {
            owner: self.owner.clone(),
            drain,
        })
    }
    /// The original Serve may tighten an active child to its absolute group
    /// deadline. Already terminated business contributes only physical cleanup.
    pub(crate) fn drain_for_serve(
        &self,
        started_at: Instant,
        deadline: Instant,
    ) -> std::result::Result<Option<DrainOperation>, SessionError> {
        let mut retained = self.owner.drain.lock().expect("v4 retained drain");
        let mut drive = self.owner.drive.lock().expect("v4 Session owner lock");
        if let Some(cause) = drive.termination {
            if drive.termination_at.is_some_and(|at| at < started_at) {
                return Ok(None);
            }
            return retained
                .as_ref()
                .map(|drain| {
                    Some(DrainOperation {
                        owner: self.owner.clone(),
                        drain: drain.clone(),
                    })
                })
                .ok_or(cause);
        }
        let result = drive
            .session
            .as_mut()
            .ok_or(SessionError::Closed)?
            .start_drain_bounded(Duration::from_secs(30), Some(deadline))
            .map_err(error);
        if drive.session.as_ref().is_some_and(|s| s.engine.closed) {
            Owner::close_locked(
                &mut drive,
                result
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(SessionError::Closed),
            );
            self.owner.staging.close();
        }
        let drain = result?;
        *retained = Some(drain.clone());
        drop(drive);
        self.owner.changed.notify_waiters();
        Ok(Some(DrainOperation {
            owner: self.owner.clone(),
            drain,
        }))
    }
    pub(crate) fn termination_cause(&self) -> Option<SessionError> {
        self.owner
            .drive
            .lock()
            .expect("v4 Session owner lock")
            .termination
    }
    pub async fn wait_termination(&self) -> SessionTermination {
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(cause) = self
                .owner
                .drive
                .lock()
                .expect("v4 Session owner lock")
                .termination
            {
                return SessionTermination { error: cause };
            }
            notified.await;
        }
    }
    pub fn close(&self) {
        self.owner.close(SessionError::Closed);
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.owner.cleanup()
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete || status.cleanup_incomplete {
                return status;
            }
            tokio::select! { _ = notified => {}, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
        }
    }
}
struct ProbeWait {
    owner: Arc<Owner>,
    probe: Arc<controls::Probe>,
}
impl Drop for ProbeWait {
    fn drop(&mut self) {
        self.probe.release();
        self.owner.changed.notify_waiters();
    }
}
/// An observer of the original irreversible Drain operation. Dropping a wait
/// leaves its admission gate and deadline intact.
#[derive(Clone)]
pub struct DrainOperation {
    owner: Arc<Owner>,
    drain: Arc<controls::Drain>,
}
impl std::fmt::Debug for DrainOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("V4DrainOperation { <opaque> }")
    }
}
impl DrainOperation {
    /// Enforce the earlier aggregate deadline even if the ordinary Session
    /// worker has not received its next scheduling turn.
    pub(crate) fn expire_for_serve(&self, now: Instant) {
        let mut drive = self.owner.drive.lock().expect("v4 Session owner lock");
        if drive.termination.is_none() && now >= self.drain.deadline() {
            self.drain.finish(DrainOutcome::DeadlineAborted);
            Owner::close_locked(&mut drive, SessionError::Timeout);
            self.owner.staging.close();
            self.owner.changed.notify_waiters();
        }
    }
    pub fn result(&self) -> DrainResult {
        self.drain.snapshot()
    }
    pub async fn wait(&self) -> std::result::Result<DrainResult, SessionError> {
        let result = self.result();
        if result.outcome != DrainOutcome::Pending {
            return Ok(result);
        }
        let _wait = self.owner.wait_charge()?;
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let result = self.result();
            if result.outcome != DrainOutcome::Pending {
                return Ok(result);
            }
            notified.await;
        }
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.owner.cleanup()
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        Session {
            owner: self.owner.clone(),
        }
        .wait_cleanup()
        .await
    }
}
struct Opening {
    owner: Arc<Owner>,
    handle: Option<StreamHandle>,
}
impl Drop for Opening {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            let _ = self
                .owner
                .run(|session, _| session.reset(handle).map_err(error));
            self.owner.changed.notify_waiters();
        }
    }
}

pub struct OpenRequest {
    owner: Arc<Owner>,
    handle: Option<StreamHandle>,
    kind: String,
    metadata: Metadata,
    _charge: ResourceCharge,
}
impl std::fmt::Debug for OpenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("V4OpenRequest { <opaque> }")
    }
}
impl OpenRequest {
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    pub fn accept(mut self, receive_window: u64) -> std::result::Result<Stream, SessionError> {
        let handle = self.handle.as_ref().ok_or(SessionError::Closed)?;
        let stream = Stream::new(self.owner.clone(), handle.clone(), self.kind.clone())?;
        self.owner.run(|session, transport| {
            session
                .decide_open(handle, OpenDecision::Accept { receive_window }, transport)
                .map_err(error)?;
            if session.phase(handle).map_err(error)? != StreamPhase::Accepted {
                return Err(SessionError::StreamRejected);
            }
            Ok(())
        })?;
        self.handle = None;
        self.owner.changed.notify_waiters();
        Ok(stream)
    }
    pub fn reject(mut self) -> std::result::Result<(), SessionError> {
        let handle = self.handle.as_ref().ok_or(SessionError::Closed)?;
        self.owner.run(|session, transport| {
            session
                .decide_open(
                    handle,
                    OpenDecision::Reject(Rejection::Application),
                    transport,
                )
                .map_err(error)
        })?;
        self.handle = None;
        self.owner.changed.notify_waiters();
        Ok(())
    }
}
impl Drop for OpenRequest {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = self.owner.run(|session, _| {
                let i = session.engine.streams.resolve(&handle).map_err(error)?;
                if session.engine.streams.slots[i].phase == Phase::Pending {
                    session.engine.streams.slots[i].forced_rejection = Some(Rejection::Application);
                }
                Ok(())
            });
            self.owner.changed.notify_waiters();
        }
    }
}
struct StreamOwner {
    owner: Arc<Owner>,
    handle: StreamHandle,
    kind: String,
    read: Arc<StreamReadOwner>,
    write: AsyncMutex<()>,
    _charge: ResourceCharge,
}
impl Drop for StreamOwner {
    fn drop(&mut self) {
        let _ = self
            .owner
            .run(|session, _| session.reset(&self.handle).map_err(error));
        self.owner.changed.notify_waiters();
    }
}
#[derive(Clone)]
pub struct Stream {
    inner: Arc<StreamOwner>,
}
impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("V4Stream { <opaque> }")
    }
}
impl Stream {
    fn new(
        owner: Arc<Owner>,
        handle: StreamHandle,
        kind: String,
    ) -> std::result::Result<Self, SessionError> {
        let charge = owner
            .account
            .reserve(ResourceLimits {
                sdk_bytes: 1024,
                items: 1,
                work_slots: 1,
                tasks: 0,
                sessions: 0,
                ..ResourceLimits::default()
            })
            .map_err(environment_error)?;
        let read = Arc::new(StreamReadOwner::from_account(
            1 << 20,
            owner.account.clone(),
        ));
        Ok(Self {
            inner: Arc::new(StreamOwner {
                owner,
                handle,
                kind,
                read,
                write: AsyncMutex::new(()),
                _charge: charge,
            }),
        })
    }
    fn retained_eof(&self) -> bool {
        let drive = self
            .inner
            .owner
            .drive
            .lock()
            .expect("v4 Session owner lock");
        drive.termination.is_some() && self.inner.handle.view.end.load(Ordering::Acquire) == 1
    }
    fn eof_result(offset: u64) -> ReadResult {
        ReadResult {
            data: Bytes::new(),
            progress: ReadProgress {
                offset,
                filled: 0,
                target: None,
            },
            wait_status: ReadWaitStatus::Ready,
            stream_status: ReadStreamStatus::Eof,
            cause: None,
            error: None,
        }
    }
    fn state(&self) -> (ReadStreamStatus, Option<ReadError>) {
        let result = self.inner.owner.run(|session, _| {
            session.check().map_err(error)?;
            let handle = &self.inner.handle;
            let Some(i) = session.engine.streams.index(handle.scope()) else {
                return Ok(match handle.view.end.load(Ordering::Acquire) {
                    1 => ReadStreamStatus::Eof,
                    _ => ReadStreamStatus::Aborted,
                });
            };
            let slot = &session.engine.streams.slots[i];
            let d = slot.directions[usize::from(1 - session.engine.role)];
            Ok(if d.stop && !d.fin {
                ReadStreamStatus::Aborted
            } else if d.fin && slot.queue.is_empty() {
                ReadStreamStatus::Eof
            } else {
                ReadStreamStatus::Open
            })
        });
        match result {
            Ok(state) => (state, None),
            Err(_) if self.retained_eof() => (ReadStreamStatus::Eof, None),
            Err(_) => (ReadStreamStatus::Aborted, None),
        }
    }
    pub async fn read_result(
        &self,
        max_bytes: usize,
    ) -> std::result::Result<ReadResult, SessionError> {
        if max_bytes == 0 || max_bytes > 1 << 20 {
            return Err(SessionError::OperationFailed);
        }
        let permit = self.inner.read.acquire()?;
        // An authenticated, fully consumed terminal observation is metadata.
        // Reading it after Session cleanup requires no new payload allocation.
        if self.retained_eof() {
            return Ok(Self::eof_result(permit.start_offset()));
        }
        let _wait = self.inner.owner.wait_charge()?;
        let account = self
            .inner
            .owner
            .account
            .reserve_result()
            .map_err(environment_error)?;
        let charge = account
            .reserve(ResourceLimits {
                sdk_bytes: max_bytes as u64,
                ..ResourceLimits::default()
            })
            .map_err(environment_error)?;
        let mut out = Vec::new();
        out.try_reserve_exact(max_bytes)
            .map_err(|_| SessionError::ResourceExhausted)?;
        out.resize(max_bytes, 0);
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let read = match self
                .inner
                .owner
                .run(|session, _| session.read(&self.inner.handle, &mut out).map_err(error))
            {
                Ok(read) => read,
                Err(_) if self.retained_eof() => {
                    return Ok(Self::eof_result(permit.start_offset()));
                }
                Err(cause) => return Err(cause),
            };
            let (count, state) = match read {
                ReadState::Pending => {
                    notified.await;
                    continue;
                }
                ReadState::Data(count) => (count, self.state().0),
                ReadState::Eof => (0, ReadStreamStatus::Eof),
                ReadState::Aborted => (0, ReadStreamStatus::Aborted),
            };
            let offset = account
                .with_security(|| permit.advance(count))
                .map_err(environment_error)??;
            out.truncate(count);
            account.detach_result();
            let data = Bytes::from_owner(Payload {
                data: out,
                _charge: charge,
            });
            self.inner.owner.changed.notify_waiters();
            return Ok(ReadResult {
                data,
                progress: ReadProgress {
                    offset,
                    filled: count as u64,
                    target: None,
                },
                wait_status: ReadWaitStatus::Ready,
                stream_status: state,
                cause: None::<ReadCause>,
                error: None,
            });
        }
    }
    pub fn grant_receive_limit(&self, limit: u64) -> std::result::Result<(), SessionError> {
        let result = self
            .inner
            .owner
            .run(|session, _| session.grant(&self.inner.handle, limit).map_err(error));
        self.inner.owner.changed.notify_waiters();
        result
    }
    /// Observe authentication of an already accepted prefix. This never proves
    /// application consumption, and a dropped waiter does not reset the Stream.
    pub async fn wait_peer_authenticated(
        &self,
        offset: u64,
    ) -> std::result::Result<(), SessionError> {
        let view = &self.inner.handle.view;
        if offset > view.accepted.load(Ordering::Acquire) {
            return Err(SessionError::OperationFailed);
        }
        if offset <= view.authenticated.load(Ordering::Acquire) {
            return Ok(());
        }
        let _charge = self.inner.owner.wait_charge()?;
        let _stream_slot = AuthenticationWaitSlot::acquire(&view.authentication_waiters, 4)?;
        let _session_slot =
            AuthenticationWaitSlot::acquire(&self.inner.owner.authentication_waiters, 64)?;
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if offset <= view.authenticated.load(Ordering::Acquire) {
                return Ok(());
            }
            if view.send_end.load(Ordering::Acquire) != 0 {
                return Err(SessionError::StreamReset);
            }
            self.inner
                .owner
                .run(|session, _| session.check().map_err(error))?;
            notified.await;
        }
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let complete = self
            .inner
            .owner
            .run(|session, _| {
                Ok(matches!(
                    session.phase(&self.inner.handle).map_err(error)?,
                    StreamPhase::Recent | StreamPhase::Stable
                ))
            })
            .unwrap_or(false);
        let physical = self
            .inner
            .owner
            .drive
            .lock()
            .expect("v4 Session owner lock")
            .transport
            .stream_cleanup_status(self.inner.handle.scope());
        let session = self.inner.owner.cleanup();
        CleanupStatus {
            complete: (complete && physical.complete) || session.complete,
            cleanup_incomplete: physical.cleanup_incomplete || session.cleanup_incomplete,
            pending_callbacks: physical.pending_callbacks,
        }
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete || status.cleanup_incomplete {
                return status;
            }
            tokio::select! { _ = notified => {}, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
        }
    }
    async fn send(
        &self,
        payload: Bytes,
        admission: Option<&WriteRequestAdmission>,
        fin: bool,
    ) -> std::result::Result<usize, SessionError> {
        let _wait = self.inner.owner.wait_charge()?;
        let _write = self.inner.write.lock().await;
        let _blocked = BlockedWriter {
            owner: self.inner.owner.clone(),
            handle: self.inner.handle.clone(),
        };
        let mut accepted = 0;
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let result = self.inner.owner.run(|session, transport| {
                session.check().map_err(error)?;
                let i = session
                    .engine
                    .streams
                    .resolve(&self.inner.handle)
                    .map_err(error)?;
                let d =
                    session.engine.streams.slots[i].directions[usize::from(session.engine.role)];
                if fin && payload.is_empty() && d.terminal.is_some() {
                    return Ok(Some(0));
                }
                if d.stop || d.terminal.is_some() || d.fin_requested {
                    return Err(SessionError::StreamReset);
                }
                if session.engine.frozen {
                    return Ok(None);
                }
                let room = usize::try_from(d.limit - d.current.offset).unwrap_or(usize::MAX);
                let count = (payload.len() - accepted).min(room).min(QUANTUM);
                if count == 0 && accepted < payload.len() {
                    let now = session
                        .engine
                        .account
                        .security_time()
                        .map_err(CryptoError::from)
                        .map_err(error)?
                        .monotonic_sample;
                    session.engine.streams.slots[i]
                        .send_progress
                        .get_or_insert(now);
                    return Ok(None);
                }
                session.engine.streams.slots[i].send_progress = None;
                session
                    .write_with_admission(
                        &self.inner.handle,
                        &payload[accepted..accepted + count],
                        fin && accepted + count == payload.len(),
                        admission,
                        transport,
                    )
                    .map(Some)
                    .map_err(error)
            })?;
            match result {
                Some(count) => {
                    self.inner.owner.changed.notify_waiters();
                    accepted += count;
                    if accepted == payload.len() || admission.is_none() {
                        return Ok(accepted);
                    }
                }
                None => match admission {
                    Some(a) => {
                        tokio::select! { _ = notified => {}, _ = a.canceled() => return Err(SessionError::Canceled) }
                    }
                    None => notified.await,
                },
            }
        }
    }
}
struct BlockedWriter {
    owner: Arc<Owner>,
    handle: StreamHandle,
}
struct AuthenticationWaitSlot<'a>(&'a AtomicUsize);
impl<'a> AuthenticationWaitSlot<'a> {
    fn acquire(counter: &'a AtomicUsize, limit: usize) -> std::result::Result<Self, SessionError> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < limit).then_some(count + 1)
            })
            .map_err(|_| SessionError::ResourceExhausted)?;
        Ok(Self(counter))
    }
}
impl Drop for AuthenticationWaitSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Drop for BlockedWriter {
    fn drop(&mut self) {
        let _ = self.owner.run(|session, _| {
            if let Some(i) = session.engine.streams.index(self.handle.scope()) {
                session.engine.streams.slots[i].send_progress = None;
            }
            Ok(())
        });
    }
}
struct Payload {
    data: Vec<u8>,
    _charge: ResourceCharge,
}
impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[async_trait]
impl ByteStream for Stream {
    #[cfg(test)]
    fn internal_test_id(&self) -> u64 {
        self.inner.handle.scope()
    }
    fn kind(&self) -> &str {
        &self.inner.kind
    }
    fn terminal_error(&self) -> Option<SessionError> {
        (self.state().0 == ReadStreamStatus::Aborted).then_some(SessionError::StreamReset)
    }
    fn read_state(&self) -> (ReadStreamStatus, Option<ReadError>) {
        self.state()
    }
    fn read_owner(&self) -> Option<Arc<StreamReadOwner>> {
        Some(self.inner.read.clone())
    }
    fn read_delivery_owner(&self) -> Option<Arc<crate::api_v4::ReadDeliveryAuthorization>> {
        Some(self.inner.read.delivery_authorization())
    }
    async fn read_cursor_piece(
        &self,
        cursor: &ReaderCursor,
    ) -> std::result::Result<(), SessionError> {
        if !cursor.belongs_to(&self.inner.read) {
            return Err(SessionError::OperationFailed);
        }
        if self.retained_eof() {
            cursor.terminate_input(ReadStreamStatus::Eof, None);
            return Ok(());
        }
        let _wait = self.inner.owner.wait_charge()?;
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let progressed = self.inner.owner.run(|session, _| {
                session.check().map_err(error)?;
                let Some(i) = session.engine.streams.index(self.inner.handle.scope()) else {
                    let state = match self.inner.handle.view.end.load(Ordering::Acquire) {
                        1 => ReadStreamStatus::Eof,
                        _ => ReadStreamStatus::Aborted,
                    };
                    cursor.terminate_input(state, None);
                    return Ok(true);
                };
                let role = usize::from(1 - session.engine.role);
                let now = session
                    .engine
                    .account
                    .security_time()
                    .map_err(CryptoError::from)
                    .map_err(error)?
                    .monotonic_sample;
                let slot = &mut session.engine.streams.slots[i];
                let d = slot.directions[role];
                if d.stop && !d.fin {
                    cursor.terminate_input(ReadStreamStatus::Aborted, None);
                    return Ok(true);
                }
                if !slot.accepted() || d.current.epoch > session.engine.epoch {
                    return Ok(false);
                }
                if slot.queue.is_empty() {
                    if d.fin {
                        cursor.terminate_input(ReadStreamStatus::Eof, None);
                        return Ok(true);
                    }
                    return Ok(false);
                }
                let (front, _) = slot.queue.as_slices();
                let count = cursor.transfer_from(front)?;
                slot.queue.drain(..count);
                if count != 0 {
                    slot.receive_progress = (!slot.queue.is_empty()).then_some(now);
                }
                slot.directions[role].released += count as u64;
                session.engine.streams.promised -= count as u64;
                session.check().map_err(error)?;
                Ok(true)
            });
            let progressed = match progressed {
                Ok(progressed) => progressed,
                Err(_) if self.retained_eof() => {
                    cursor.terminate_input(ReadStreamStatus::Eof, None);
                    return Ok(());
                }
                Err(cause) => return Err(cause),
            };
            if progressed {
                self.inner.owner.changed.notify_waiters();
                return Ok(());
            }
            notified.await;
        }
    }
    async fn read(&self) -> std::result::Result<Option<Bytes>, SessionError> {
        let result = self.read_result(QUANTUM).await?;
        if !result.data.is_empty() {
            return Ok(Some(result.data));
        }
        if result.stream_status == ReadStreamStatus::Eof {
            Ok(None)
        } else {
            Err(SessionError::StreamReset)
        }
    }
    async fn write(&self, payload: Bytes) -> std::result::Result<usize, SessionError> {
        self.send(payload, None, false).await
    }
    fn write_staging_owner(&self) -> Option<Arc<WriteStagingOwner>> {
        Some(self.inner.owner.staging.clone())
    }
    async fn write_prepared(
        &self,
        payload: Bytes,
        admission: &WriteRequestAdmission,
    ) -> std::result::Result<(), SessionError> {
        self.send(payload, Some(admission), false).await.map(|_| ())
    }
    async fn close_write(&self) -> std::result::Result<(), SessionError> {
        if self.inner.handle.view.fin_submitted.load(Ordering::Acquire) {
            return Ok(());
        }
        let _wait = self.inner.owner.wait_charge()?;
        self.inner.owner.run(|session, _| {
            let i = session
                .engine
                .streams
                .resolve(&self.inner.handle)
                .map_err(error)?;
            let direction =
                session.engine.streams.slots[i].directions[usize::from(session.engine.role)];
            if direction.stop && !direction.fin {
                return Err(SessionError::StreamReset);
            }
            session
                .request_close_write(&self.inner.handle)
                .map_err(error)
        })?;
        self.inner.owner.changed.notify_waiters();
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.handle.view.fin_submitted.load(Ordering::Acquire) {
                return Ok(());
            }
            self.inner.owner.run(|session, _| {
                let i = session
                    .engine
                    .streams
                    .resolve(&self.inner.handle)
                    .map_err(error)?;
                let direction =
                    session.engine.streams.slots[i].directions[usize::from(session.engine.role)];
                if direction.stop && !direction.fin {
                    return Err(SessionError::StreamReset);
                }
                Ok(())
            })?;
            notified.await;
        }
    }
    async fn finish(&self) -> std::result::Result<(), SessionError> {
        match self.inner.handle.view.send_end.load(Ordering::Acquire) {
            1 => return Ok(()),
            2 => return Err(SessionError::StreamReset),
            _ => {}
        }
        self.close_write().await?;
        let _wait = self.inner.owner.wait_charge()?;
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.inner.handle.view.send_end.load(Ordering::Acquire) {
                1 => return Ok(()),
                2 => return Err(SessionError::StreamReset),
                _ => {}
            }
            // A missing live slot or closed Session is not a successful drain.
            // Only the retained observation of an authenticated normal proof
            // may satisfy this operation after retirement.
            self.inner
                .owner
                .run(|session, _| session.check().map_err(error))?;
            notified.await;
        }
    }
    async fn reset(&self) -> std::result::Result<(), SessionError> {
        self.inner.read.revoke_delivery();
        let result = self.inner.owner.run(|session, _| {
            if session
                .engine
                .streams
                .index(self.inner.handle.scope())
                .is_none()
            {
                return Ok(());
            }
            session.reset(&self.inner.handle).map_err(error)
        });
        self.inner.owner.changed.notify_waiters();
        result
    }
    async fn close(&self) -> std::result::Result<(), SessionError> {
        self.reset().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_v4::{ReaderCursorOptions, StreamV4Ext, TransportEnvironment};
    use crate::crypto_v4::tests::record_pair_for_limits;
    use tokio::sync::mpsc;
    struct Link {
        send: mpsc::Sender<Vec<u8>>,
        closed: bool,
    }
    impl RecordPublisher for Link {
        fn publish(&mut self, record: &[u8]) -> Result<()> {
            self.send
                .try_send(record.to_vec())
                .map_err(|_| CryptoError::Capacity)
        }
    }
    impl SessionTransport for Link {
        fn close(&mut self) {
            self.closed = true;
        }
        fn cleanup_status(&self) -> CleanupStatus {
            CleanupStatus {
                complete: self.closed,
                cleanup_incomplete: false,
                pending_callbacks: 0,
            }
        }
        fn stream_cleanup_status(&self, _: u64) -> CleanupStatus {
            CleanupStatus {
                complete: true,
                cleanup_incomplete: false,
                pending_callbacks: 0,
            }
        }
    }
    fn link(
        environment: &TransportEnvironment,
        client: RecordEngine,
        server: RecordEngine,
    ) -> (
        Session,
        Session,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (c_tx, mut c_rx) = mpsc::channel(32);
        let (s_tx, mut s_rx) = mpsc::channel(32);
        let client = environment
            .adopt_ready_session(
                client,
                Box::new(Link {
                    send: c_tx,
                    closed: false,
                }),
            )
            .unwrap();
        let server = environment
            .adopt_ready_session(
                server,
                Box::new(Link {
                    send: s_tx,
                    closed: false,
                }),
            )
            .unwrap();
        let c = client.clone();
        let s = server.clone();
        let c_task = tokio::spawn(async move {
            while let Some(wire) = c_rx.recv().await {
                s.receive(&wire).unwrap();
            }
        });
        let s_task = tokio::spawn(async move {
            while let Some(wire) = s_rx.recv().await {
                c.receive(&wire).unwrap();
            }
        });
        (client, server, c_task, s_task)
    }
    #[tokio::test]
    async fn public_probe_and_repeated_drain_observe_original_cleanup() {
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            client.probe_liveness(Duration::from_secs(1)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.outcome, ProbeOutcome::Responsive);
        assert!(result.submitted && result.elapsed.is_some());
        let operation = client.drain(Duration::from_secs(1)).unwrap();
        let repeated = client.drain(Duration::from_secs(30)).unwrap();
        assert!(Arc::ptr_eq(&operation.drain, &repeated.drain));
        let result = tokio::time::timeout(Duration::from_secs(2), operation.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.outcome, DrainOutcome::Drained);
        assert!(operation.wait_cleanup().await.complete);
        assert_eq!(
            client.drain(Duration::from_secs(30)).unwrap().result(),
            result
        );
        server.close();
        c_task.abort();
        s_task.abort();
    }
    fn application_limits() -> crate::application_lifetime_v4::ApplicationLimits {
        crate::application_lifetime_v4::ApplicationLimits {
            ordinary_callbacks: 2,
            ordinary_callback_bytes: 1024,
            control_callback_bytes: 1024,
        }
    }
    #[tokio::test]
    async fn original_application_work_keeps_drain_pending_after_transport_work_finishes() {
        use crate::application_lifetime_v4::CallbackKind;
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let application =
            ApplicationLifetime::new(c.account.clone(), application_limits()).unwrap();
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        client.attach_application(application.clone()).unwrap();
        assert!(client.attach_application(application.clone()).is_err());
        let callback = application.enter(CallbackKind::Ordinary).unwrap();
        let drain = client.drain(Duration::from_secs(2)).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), drain.wait())
                .await
                .is_err()
        );
        assert_eq!(drain.result().outcome, DrainOutcome::Pending);
        assert!(!application.cancellation().is_cancelled());
        drop(callback);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), drain.wait())
                .await
                .unwrap()
                .unwrap()
                .outcome,
            DrainOutcome::Drained
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while !client.core_cleanup_status().complete {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!client.cleanup_status().complete);
        assert!(application.cancellation().is_cancelled());
        let cleanup = application.enter(CallbackKind::Cleanup).unwrap();
        application.release(true).unwrap();
        assert!(!client.cleanup_status().complete);
        drop(cleanup);
        assert!(client.wait_cleanup().await.complete);
        server.close();
        c_task.abort();
        s_task.abort();
        let _ = c_task.await;
        let _ = s_task.await;
    }
    #[tokio::test]
    async fn close_keeps_application_callbacks_and_original_charge_until_actual_exit() {
        use crate::application_lifetime_v4::CallbackKind;
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let application =
            ApplicationLifetime::new(c.account.clone(), application_limits()).unwrap();
        let foreign = ApplicationLifetime::new(s.account.clone(), application_limits()).unwrap();
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        assert!(client.attach_application(foreign.clone()).is_err());
        foreign.release(true).unwrap();
        client.attach_application(application.clone()).unwrap();
        let callback = application.enter(CallbackKind::Ordinary).unwrap();
        let control = application.enter(CallbackKind::Control).unwrap();
        client.close();
        assert!(application.cancellation().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !client.core_cleanup_status().complete {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let held = fixture.environment.resource_usage();
        application.release(true).unwrap();
        assert_eq!(client.cleanup_status().pending_callbacks, 2);
        assert!(!client.cleanup_status().complete);
        assert_eq!(fixture.environment.resource_usage(), held);
        drop(control);
        assert_eq!(client.cleanup_status().pending_callbacks, 1);
        assert_eq!(fixture.environment.resource_usage(), held);
        drop(callback);
        // The current-thread worker cannot run between these synchronous
        // operations. Application exit alone must not report public cleanup.
        assert!(!client.cleanup_status().complete);
        let application_charge = application_limits().charge().unwrap();
        assert_eq!(
            fixture.environment.resource_usage().tasks,
            held.tasks - application_charge.tasks
        );
        assert!(client.wait_cleanup().await.complete);
        assert_eq!(
            fixture.environment.resource_usage().tasks,
            held.tasks - application_charge.tasks - 1
        );
        server.close();
        c_task.abort();
        s_task.abort();
        let _ = c_task.await;
        let _ = s_task.await;
    }
    #[tokio::test]
    async fn application_admission_is_sealed_before_the_core_can_observe_draining() {
        use crate::application_lifetime_v4::CallbackKind;
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let application =
            ApplicationLifetime::new(c.account.clone(), application_limits()).unwrap();
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        client.attach_application(application.clone()).unwrap();
        let admitted = application.enter(CallbackKind::Ordinary).unwrap();
        let drain = client
            .owner
            .run(|session, transport| {
                let drain = session.start_drain(Duration::from_secs(1)).map_err(error)?;
                // Exercise the exact former interleaving: core has committed Drain
                // and can poll before the public drain method regains control.
                assert!(session.engine.streams.draining);
                assert!(matches!(
                    application.enter(CallbackKind::Ordinary),
                    Err(EnvironmentError::Closed)
                ));
                session.poll(transport).map_err(error)?;
                assert_eq!(drain.snapshot().outcome, DrainOutcome::Pending);
                Ok(drain)
            })
            .unwrap();
        drop(admitted);
        client
            .owner
            .run(|session, transport| {
                session.poll(transport).map_err(error)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(drain.snapshot().outcome, DrainOutcome::Drained);
        application.release(true).unwrap();
        assert!(client.wait_cleanup().await.complete);
        server.close();
        c_task.abort();
        s_task.abort();
        let _ = c_task.await;
        let _ = s_task.await;
    }
    #[tokio::test]
    async fn application_attachment_rejects_retired_owners_and_draining_sessions() {
        use crate::application_lifetime_v4::CallbackKind;
        for retired in 0..4 {
            let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
            let application =
                ApplicationLifetime::new(c.account.clone(), application_limits()).unwrap();
            let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
            match retired {
                0 => application.close(),
                1 => application.release(true).unwrap(),
                2 => application.release(false).unwrap(),
                _ => {
                    client.drain(Duration::from_secs(1)).unwrap();
                }
            }
            let before = fixture.environment.resource_usage();
            assert!(client.attach_application(application.clone()).is_err());
            assert!(client.owner.application.get().is_none());
            assert_eq!(fixture.environment.resource_usage(), before);
            if retired < 3 {
                // Rejecting an owner does not close or mutate this Session.
                assert!(client.termination_cause().is_none());
                assert!(
                    client
                        .owner
                        .run(|session, _| {
                            assert!(!session.engine.streams.draining);
                            Ok(())
                        })
                        .is_ok()
                );
            } else {
                // A refused attachment leaves a still-active application owner
                // eligible to be cleaned by its original construction owner.
                drop(application.enter(CallbackKind::Ordinary).unwrap());
            }
            if retired == 0 || retired == 3 {
                application.release(true).unwrap();
            }
            client.close();
            server.close();
            c_task.abort();
            s_task.abort();
            let _ = c_task.await;
            let _ = s_task.await;
            assert!(client.wait_cleanup().await.complete);
        }
    }
    #[tokio::test]
    async fn original_worker_retains_application_after_all_public_handles_are_dropped() {
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let application =
            ApplicationLifetime::new(c.account.clone(), application_limits()).unwrap();
        let weak = Arc::downgrade(&application);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        client.attach_application(application.clone()).unwrap();
        server.close();
        c_task.abort();
        s_task.abort();
        let _ = c_task.await;
        let _ = s_task.await;
        assert!(server.wait_cleanup().await.complete);
        let owner_weak = Arc::downgrade(&client.owner);
        drop(application);
        drop(client);
        tokio::task::yield_now().await;
        assert!(owner_weak.upgrade().is_none());
        let retained = weak
            .upgrade()
            .expect("original worker retains application responsibility");
        assert!(retained.cancellation().is_cancelled());
        let held = fixture.environment.resource_usage();
        assert!(!retained.cleanup_status().complete);
        let application_charge = application_limits().charge().unwrap();
        assert!(held.tasks > application_charge.tasks);
        retained.release(true).unwrap();
        drop(retained);
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            fixture.environment.resource_usage().tasks,
            held.tasks - application_charge.tasks - 1
        );
    }
    #[tokio::test]
    async fn blocked_writer_expires_only_send_direction_and_cancellation_disarms_it() {
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let opening = client.open_stream("example.blocked", Metadata::empty(), 16);
        let accepting = async { server.next_open().await.unwrap().accept(0).unwrap() };
        let (outgoing, incoming) = tokio::join!(opening, accepting);
        let outgoing = outgoing.unwrap();
        let writer = outgoing.clone();
        let blocked =
            tokio::spawn(async move { writer.write(Bytes::from_static(b"blocked")).await });
        tokio::task::yield_now().await;
        client
            .owner
            .run(|session, _| {
                let i = session
                    .engine
                    .streams
                    .resolve(&outgoing.inner.handle)
                    .map_err(error)?;
                assert!(session.engine.streams.slots[i].send_progress.is_some());
                Ok(())
            })
            .unwrap();
        blocked.abort();
        let _ = blocked.await;
        client
            .owner
            .run(|session, _| {
                let i = session
                    .engine
                    .streams
                    .resolve(&outgoing.inner.handle)
                    .map_err(error)?;
                assert!(session.engine.streams.slots[i].send_progress.is_none());
                Ok(())
            })
            .unwrap();
        let writer = outgoing.clone();
        let blocked =
            tokio::spawn(async move { writer.write(Bytes::from_static(b"blocked")).await });
        tokio::task::yield_now().await;
        client
            .owner
            .run(|session, _| {
                let i = session
                    .engine
                    .streams
                    .resolve(&outgoing.inner.handle)
                    .map_err(error)?;
                assert!(session.engine.streams.slots[i].send_progress.is_some());
                session.engine.streams.slots[i].send_progress =
                    Some(Instant::now() - Duration::from_secs(31));
                session.poll_slow_consumers().map_err(error)
            })
            .unwrap();
        client.owner.changed.notify_waiters();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), blocked)
                .await
                .unwrap()
                .unwrap(),
            Err(SessionError::StreamReset)
        );
        incoming
            .write(Bytes::from_static(b"healthy reverse"))
            .await
            .unwrap();
        let data = tokio::time::timeout(Duration::from_secs(2), outgoing.read())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&data[..], b"healthy reverse");
        client.close();
        server.close();
        c_task.abort();
        s_task.abort();
    }
    #[tokio::test]
    async fn public_stream_cursor_prepared_write_and_cleanup_share_original_owner() {
        let (fixture, c, s) = record_pair_for_limits(Profile::P256);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let opening = client.open_stream("example.facade", Metadata::empty(), 32);
        let accepting = async { server.next_open().await.unwrap().accept(32).unwrap() };
        let (client_stream, server_stream) = tokio::join!(opening, accepting);
        let client_stream = client_stream.unwrap();
        let write = StreamV4Ext::prepare_write(
            Arc::new(client_stream.clone()),
            Bytes::from_static(b"hello\nrest"),
        )
        .unwrap();
        write.start().await.unwrap();
        let cursor = ReaderCursor::new(
            Arc::new(server_stream.clone()),
            ReaderCursorOptions {
                exact: None,
                delimiter: Some(Bytes::from_static(b"\n")),
                max_bytes: 32,
            },
        )
        .unwrap();
        let line = cursor.read_until().await.unwrap();
        assert_eq!(line.data, Bytes::from_static(b"hello\n"));
        drop(cursor);
        let tail = server_stream.read_result(32).await.unwrap();
        assert_eq!(tail.data, Bytes::from_static(b"rest"));
        assert_eq!(tail.progress.offset, 10);
        assert_eq!(write.progress().accepted_bytes, 10);
        client.rekey().await.unwrap();
        client_stream.close_write().await.unwrap();
        client_stream.close_write().await.unwrap();
        assert!(server_stream.read().await.unwrap().is_none());
        server_stream.close_write().await.unwrap();
        client_stream.finish().await.unwrap();
        assert!(client_stream.wait_cleanup().await.complete);
        client.close();
        server.close();
        assert!(client.wait_cleanup().await.complete);
        assert!(server.wait_cleanup().await.complete);
        c_task.abort();
        s_task.abort();
        let _ = c_task.await;
        let _ = s_task.await;
    }
    #[tokio::test]
    async fn authenticated_empty_eof_survives_close_without_hiding_discarded_data() {
        for unread in [false, true] {
            let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
            let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
            let (outgoing, incoming) = tokio::join!(
                client.open_stream("example.eof", Metadata::empty(), 32),
                async { server.next_open().await.unwrap().accept(32).unwrap() }
            );
            let outgoing = outgoing.unwrap();
            if unread {
                outgoing.write(Bytes::from_static(b"unread")).await.unwrap();
            }
            outgoing.close_write().await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), outgoing.finish())
                .await
                .unwrap()
                .unwrap();
            c_task.abort();
            s_task.abort();
            let _ = c_task.await;
            let _ = s_task.await;
            client.close();
            server.close();
            if unread {
                assert_eq!(incoming.read().await, Err(SessionError::Closed));
                assert_eq!(incoming.read_state().0, ReadStreamStatus::Aborted);
            } else {
                let result = incoming.read_result(32).await.unwrap();
                assert!(result.data.is_empty());
                assert_eq!(result.progress.offset, 0);
                assert_eq!(result.stream_status, ReadStreamStatus::Eof);
                assert_eq!(incoming.read_state().0, ReadStreamStatus::Eof);
                assert_eq!(incoming.read().await, Ok(None));
            }
        }
    }
    #[tokio::test]
    async fn dropped_close_write_waiter_keeps_original_fin_and_reset_is_not_finish() {
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let (outgoing, incoming) = tokio::join!(
            client.open_stream("example.half", Metadata::empty(), 32),
            async { server.next_open().await.unwrap().accept(32).unwrap() }
        );
        let outgoing = outgoing.unwrap();
        outgoing
            .write(Bytes::from_static(b"request"))
            .await
            .unwrap();
        let mut closing = Box::pin(outgoing.close_write());
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(closing.as_mut(), &mut context).is_pending());
        drop(closing);
        assert_eq!(
            outgoing.write(Bytes::from_static(b"late")).await,
            Err(SessionError::StreamReset)
        );
        tokio::time::timeout(Duration::from_secs(2), outgoing.finish())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            incoming.read().await.unwrap().unwrap(),
            Bytes::from_static(b"request")
        );
        assert!(incoming.read().await.unwrap().is_none());
        incoming.close_write().await.unwrap();
        outgoing.wait_cleanup().await;
        outgoing.finish().await.unwrap();
        outgoing.wait_peer_authenticated(7).await.unwrap();
        assert_eq!(
            outgoing.wait_peer_authenticated(8).await,
            Err(SessionError::OperationFailed)
        );

        let (outgoing, incoming) = tokio::join!(
            client.open_stream("example.abort", Metadata::empty(), 32),
            async { server.next_open().await.unwrap().accept(32).unwrap() }
        );
        let outgoing = outgoing.unwrap();
        incoming.reset().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), outgoing.wait_cleanup())
                .await
                .unwrap()
                .complete
        );
        assert_eq!(outgoing.finish().await, Err(SessionError::StreamReset));
        assert_eq!(incoming.finish().await, Err(SessionError::StreamReset));
        client.close();
        server.close();
        c_task.abort();
        s_task.abort();
    }
    #[tokio::test]
    async fn original_environment_identity_cannot_be_substituted_at_session_assembly() {
        let (_fixture, c, _) = record_pair_for_limits(Profile::P256);
        let other = TransportEnvironment::new();
        let (send, _recv) = mpsc::channel(1);
        assert!(
            other
                .adopt_ready_session(
                    c,
                    Box::new(Link {
                        send,
                        closed: false
                    })
                )
                .is_err()
        );
    }
    #[test]
    fn metadata_is_exact_canonical_bounded_and_reserves_sdk_namespaces() {
        use crate::codec_v4::tests::{b, encode_map, t, u};
        let mut values = vec![0xa1];
        values.extend(t("key"));
        values.extend(b(b"value"));
        let raw = encode_map(&[(0, t("example/request")), (1, u(1)), (2, values)]);
        assert_eq!(Metadata::from_encoded(&raw).unwrap().encoded(), raw);
        assert!(
            Metadata::from_encoded(&encode_map(&[
                (0, t("flowersec/request")),
                (1, u(1)),
                (2, vec![0xa0])
            ]))
            .is_err()
        );
        let mut noncanonical = vec![0xa1];
        noncanonical.extend(t("e\u{301}"));
        noncanonical.extend(b(&[]));
        assert!(
            Metadata::from_encoded(&encode_map(&[
                (0, t("example/request")),
                (1, u(1)),
                (2, noncanonical)
            ]))
            .is_err()
        );
        assert!(Metadata::from_encoded(&[0xa0]).is_err());
        assert!(Metadata::from_encoded(&[]).unwrap().encoded().is_empty());
    }

    fn raw_contract(max_decoded_bytes: usize) -> RawStreamMetadataContract {
        RawStreamMetadataContract {
            contract_id: "code.raw.v1".into(),
            namespace: "example/raw".into(),
            version: 1,
            codec: "application/json".into(),
            fields: vec![
                RawStreamMetadataField {
                    name: "message".into(),
                    value_type: RawStreamMetadataType::String,
                    required: true,
                },
                RawStreamMetadataField {
                    name: "count".into(),
                    value_type: RawStreamMetadataType::Number,
                    required: false,
                },
            ],
            max_encoded_bytes: 4096,
            max_decoded_bytes,
        }
    }

    #[test]
    fn raw_metadata_projection_preserves_wire_and_projects_typed_values() {
        let mut values = BTreeMap::new();
        values.insert("message".into(), Bytes::from_static(br#""hello""#));
        values.insert("count".into(), Bytes::from_static(b"2"));
        let metadata = Metadata::new("example/raw", 1, &values).unwrap();
        let original = metadata.encoded().to_vec();
        let projection = metadata.project_raw(&raw_contract(64)).unwrap();
        assert_eq!(
            projection.get("message"),
            Some(&JsonValue::String("hello".into()))
        );
        assert_eq!(projection.get("count").and_then(JsonValue::as_u64), Some(2));
        assert_eq!(metadata.encoded(), original.as_slice());
    }

    #[test]
    fn raw_metadata_projection_rejects_unknown_missing_and_type_mismatch() {
        let mut values = BTreeMap::new();
        values.insert("message".into(), Bytes::from_static(b"7"));
        let metadata = Metadata::new("example/raw", 1, &values).unwrap();
        assert!(metadata.project_raw(&raw_contract(64)).is_err());

        let mut values = BTreeMap::new();
        values.insert("other".into(), Bytes::from_static(br#""value""#));
        let metadata = Metadata::new("example/raw", 1, &values).unwrap();
        assert!(metadata.project_raw(&raw_contract(64)).is_err());
    }

    #[test]
    fn raw_metadata_projection_charges_utf8_decoded_bytes() {
        let mut values = BTreeMap::new();
        values.insert("message".into(), Bytes::from_static("\"😀\"".as_bytes()));
        let metadata = Metadata::new("example/raw", 1, &values).unwrap();
        assert!(metadata.project_raw(&raw_contract(10)).is_err());
        assert!(metadata.project_raw(&raw_contract(11)).is_ok());
    }

    #[test]
    fn raw_metadata_contract_rejects_noncanonical_namespace_and_identifiers() {
        let mut contract = raw_contract(64);
        contract.namespace = "Example/raw".into();
        assert!(contract.capture().is_err());
        let mut contract = raw_contract(64);
        contract.namespace = "flowersec/raw".into();
        assert!(contract.capture().is_err());
        let mut contract = raw_contract(64);
        contract.fields[0].name = "e\u{301}".into();
        assert!(contract.capture().is_err());
    }
}
