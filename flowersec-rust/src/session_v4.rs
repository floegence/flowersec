//! Application handles over the original authenticated reliable owner.
//! Construction requires a real carrier and original once admission to provide
//! the completed READY owner and its ordered transport lifetime.
use super::*;
use crate::api_v4::{
    CleanupStatus, ReadCause, ReadError, ReadProgress, ReadResult, ReadStreamStatus,
    ReadWaitStatus, ReaderCursor, StreamReadOwner, WriteRequestAdmission, WriteStagingOwner,
};
use crate::application_lifetime_v4::ApplicationLifetime;
use crate::application_tails_v4::{ApplicationTail, ApplicationTails};
use crate::crypto_v4::{DataPublicationClaim, DeferredPublication};
use crate::environment_v4::{EnvironmentError, EnvironmentRoot};
use crate::transport::{ByteStream, SessionError, SessionTermination};
use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::Condvar;
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio_util::sync::CancellationToken;
use unicode_normalization::UnicodeNormalization;

const QUANTUM: usize = 16 * 1024;

#[cfg(test)]
include!("session_v4_shared_input_test_support.rs");

#[cfg(test)]
pub(crate) struct TerminalPublicationProbe {
    state: Mutex<(bool, bool)>,
    target: Mutex<Option<std::sync::Weak<Owner>>>,
    changed: Condvar,
}
#[cfg(test)]
impl TerminalPublicationProbe {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new((false, false)),
            target: Mutex::new(None),
            changed: Condvar::new(),
        })
    }
    fn bind(&self, session: &Session) {
        *self
            .target
            .lock()
            .expect("terminal publication probe target") = Some(Arc::downgrade(&session.owner));
    }
    fn matches(&self, owner: &Owner) -> bool {
        self.target
            .lock()
            .expect("terminal publication probe target")
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|target| std::ptr::eq(Arc::as_ptr(&target), owner as *const Owner))
    }
    pub(crate) fn wait_entered(&self) {
        let mut state = self.state.lock().expect("terminal publication probe");
        while !state.0 {
            state = self
                .changed
                .wait(state)
                .expect("terminal publication probe wait");
        }
    }
    pub(crate) fn release(&self) {
        let mut state = self.state.lock().expect("terminal publication probe");
        state.1 = true;
        self.changed.notify_all();
    }
    fn block(&self) {
        let mut state = self.state.lock().expect("terminal publication probe");
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self
                .changed
                .wait(state)
                .expect("terminal publication probe block");
        }
    }
}
#[cfg(test)]
pub(crate) struct TerminalPublicationProbeGuard {
    probe: Arc<TerminalPublicationProbe>,
}
#[cfg(test)]
static TERMINAL_PUBLICATION_PROBES: OnceLock<Mutex<Vec<Arc<TerminalPublicationProbe>>>> =
    OnceLock::new();
#[cfg(test)]
pub(crate) fn install_terminal_publication_probe(
    session: &Session,
    probe: Arc<TerminalPublicationProbe>,
) -> TerminalPublicationProbeGuard {
    probe.bind(session);
    TERMINAL_PUBLICATION_PROBES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("terminal publication probe install")
        .push(probe.clone());
    TerminalPublicationProbeGuard { probe }
}
#[cfg(test)]
impl Drop for TerminalPublicationProbeGuard {
    fn drop(&mut self) {
        self.probe.release();
        if let Some(slot) = TERMINAL_PUBLICATION_PROBES.get() {
            let mut current = slot.lock().expect("terminal publication probe remove");
            current.retain(|probe| !Arc::ptr_eq(probe, &self.probe));
        }
    }
}
#[cfg(test)]
fn block_terminal_publication(owner: &Owner) {
    if let Some(probe) = TERMINAL_PUBLICATION_PROBES.get().and_then(|slot| {
        slot.lock()
            .ok()
            .and_then(|probes| probes.iter().find(|probe| probe.matches(owner)).cloned())
    }) {
        probe.block();
    }
}

#[cfg(test)]
pub(crate) struct MaintenanceReceiveProbe {
    state: Mutex<(usize, usize, bool)>,
    target: Mutex<Option<std::sync::Weak<Owner>>>,
    changed: Condvar,
}
#[cfg(test)]
impl MaintenanceReceiveProbe {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new((0, limit, false)),
            target: Mutex::new(None),
            changed: Condvar::new(),
        })
    }
    fn bind(&self, session: &Session) {
        *self
            .target
            .lock()
            .expect("maintenance receive probe target") = Some(Arc::downgrade(&session.owner));
    }
    fn matches(&self, owner: &Owner) -> bool {
        self.target
            .lock()
            .expect("maintenance receive probe target")
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|target| std::ptr::eq(Arc::as_ptr(&target), owner as *const Owner))
    }
    pub(crate) fn wait_for(&self, target: usize) {
        let mut state = self.state.lock().expect("maintenance receive probe");
        while state.0 < target && !state.2 {
            state = self
                .changed
                .wait(state)
                .expect("maintenance receive probe wait");
        }
    }
    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .expect("maintenance receive probe release");
        state.2 = true;
        self.changed.notify_all();
    }
    fn record(&self) {
        let mut state = self.state.lock().expect("maintenance receive probe record");
        if state.0 < state.1 {
            state.0 += 1;
            self.changed.notify_all();
        }
    }
}
#[cfg(test)]
pub(crate) struct MaintenanceReceiveProbeGuard {
    probe: Arc<MaintenanceReceiveProbe>,
}
#[cfg(test)]
static MAINTENANCE_RECEIVE_PROBES: OnceLock<Mutex<Vec<Arc<MaintenanceReceiveProbe>>>> =
    OnceLock::new();
#[cfg(test)]
pub(crate) fn install_maintenance_receive_probe(
    session: &Session,
    probe: Arc<MaintenanceReceiveProbe>,
) -> MaintenanceReceiveProbeGuard {
    probe.bind(session);
    MAINTENANCE_RECEIVE_PROBES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("maintenance receive probe install")
        .push(probe.clone());
    MaintenanceReceiveProbeGuard { probe }
}
#[cfg(test)]
impl Drop for MaintenanceReceiveProbeGuard {
    fn drop(&mut self) {
        self.probe.release();
        if let Some(slot) = MAINTENANCE_RECEIVE_PROBES.get() {
            let mut current = slot.lock().expect("maintenance receive probe remove");
            current.retain(|probe| !Arc::ptr_eq(probe, &self.probe));
        }
    }
}
#[cfg(test)]
fn record_maintenance_receive(owner: &Owner) {
    if let Some(probe) = MAINTENANCE_RECEIVE_PROBES.get().and_then(|slot| {
        slot.lock()
            .ok()
            .and_then(|probes| probes.iter().find(|probe| probe.matches(owner)).cloned())
    }) {
        probe.record();
    }
}

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
    pub(crate) fn from_typed_encoded(encoded: &[u8]) -> std::result::Result<Self, SessionError> {
        decode(encoded, "TypedMessageMetadata", 4096, Context::default()).map_err(error)?;
        Ok(Self(Bytes::copy_from_slice(encoded)))
    }
    pub(crate) fn from_open_encoded(encoded: &[u8]) -> std::result::Result<Self, SessionError> {
        Self::from_encoded(encoded).or_else(|_| Self::from_typed_encoded(encoded))
    }
    pub fn encoded(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn is_typed(&self) -> bool {
        !self.0.is_empty()
            && decode(&self.0, "TypedMessageMetadata", 4096, Context::default()).is_ok()
    }
    pub(crate) fn typed_definition(&self) -> Option<[u8; 32]> {
        let value = crate::codec_v4::decode(
            &self.0,
            "TypedMessageMetadata",
            crate::codec_v4::Limits {
                bytes: 4096,
                nodes: crate::codec_v4::TYPED_MESSAGE_METADATA_MAX_NODES,
            },
            None,
        )
        .ok()?;
        let values = value.field("TypedMessageMetadata", "values").ok()?;
        let mut fields = values.children().ok()?;
        while let Some(key) = fields.next() {
            let key = key.ok()?.text().ok()?;
            let value = fields.next()?.ok()?;
            if key == "definition" {
                return value.bytes().ok()?.try_into().ok();
            }
        }
        None
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
        if self.0.is_empty() || self.is_typed() {
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
    fn datagram_maximum(&self) -> Option<usize> {
        None
    }
    fn publish_datagram(
        &mut self,
        _wire: Vec<u8>,
        _original: DatagramLease,
    ) -> crate::transport::UnreliableSendOutcome {
        crate::transport::UnreliableSendOutcome::DroppedCarrier
    }
    fn capture_native_bindings(&mut self, _session: &mut ReliableSession) -> Result<()> {
        Ok(())
    }
    fn close(&mut self);
    /// Independent cancellation/cleanup handles captured before the transport
    /// enters the owner mutex. Native providers use these to abort a blocked
    /// publish without waiting for that mutex.
    fn close_signal(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        None
    }
    fn cleanup_signal(&self) -> Option<Arc<dyn Fn() -> CleanupStatus + Send + Sync>> {
        None
    }
    fn cleanup_status(&self) -> CleanupStatus;
    fn stream_cleanup_status(&self, scope: u64) -> CleanupStatus;
}
struct DeferredRecord {
    bytes: Vec<u8>,
    work: Option<RecordWork>,
    publication: Option<RecordPublication>,
    _physical: Option<CryptoTail>,
    send_view: Option<Arc<StreamView>>,
    aborted: bool,
}
impl Drop for DeferredRecord {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
struct PublicationStaging {
    records: Vec<DeferredRecord>,
    deferred: Vec<DeferredPublication>,
    // Fields drop in declaration order: bytes and completion metadata precede
    // the return of their actual staging reservation on every exit path.
    _charges: Vec<ResourceCharge>,
}
struct DeferredPublisher<'a> {
    transport: &'a mut dyn SessionTransport,
    records: Vec<DeferredRecord>,
    deferred: Vec<DeferredPublication>,
    charges: Vec<ResourceCharge>,
    account: ResourceAccount,
    deferred_error: Option<CryptoError>,
    prepared_record: Option<Vec<u8>>,
    reserved_deferred: usize,
    prepaid: Option<&'a ResourceCharge>,
    prepaid_bytes: u64,
    prepaid_items: u64,
}
impl<'a> DeferredPublisher<'a> {
    fn new(
        transport: &'a mut dyn SessionTransport,
        account: ResourceAccount,
        prepaid: Option<&'a ResourceCharge>,
    ) -> Self {
        Self {
            transport,
            records: Vec::new(),
            deferred: Vec::new(),
            charges: Vec::new(),
            account,
            deferred_error: None,
            prepared_record: None,
            reserved_deferred: 0,
            prepaid,
            prepaid_bytes: 0,
            prepaid_items: 0,
        }
    }
}
impl RecordPublisher for DeferredPublisher<'_> {
    fn prepare_management_stream(&mut self, scope: u64) -> Result<()> {
        self.transport.prepare_management_stream(scope)
    }
    fn prepare_publication(&mut self, record_bytes: usize, deferred_tails: usize) -> Result<()> {
        if self
            .prepared_record
            .as_ref()
            .is_some_and(|record| record.capacity() >= record_bytes)
            && self.reserved_deferred >= deferred_tails
        {
            return Ok(());
        }
        let additional_tails = deferred_tails.saturating_sub(self.reserved_deferred);
        let metadata = additional_tails
            .checked_mul(std::mem::size_of::<DeferredPublication>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DeferredRecord>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ResourceCharge>()))
            .ok_or(CryptoError::Capacity)?;
        let required = ResourceLimits {
            sdk_bytes: record_bytes
                .checked_add(metadata)
                .ok_or(CryptoError::Capacity)? as u64,
            items: additional_tails as u64,
            ..ResourceLimits::default()
        };
        if let Some(prepaid) = self.prepaid {
            let bytes = self
                .prepaid_bytes
                .checked_add(required.sdk_bytes)
                .ok_or(CryptoError::Capacity)?;
            let items = self
                .prepaid_items
                .checked_add(required.items)
                .ok_or(CryptoError::Capacity)?;
            if !prepaid.covers(
                &self.account,
                ResourceLimits {
                    sdk_bytes: bytes,
                    items,
                    ..ResourceLimits::default()
                },
            ) {
                return Err(CryptoError::Capacity);
            }
            self.prepaid_bytes = bytes;
            self.prepaid_items = items;
        } else {
            let charge = self
                .account
                .reserve(required)
                .map_err(|_| CryptoError::Capacity)?;
            self.charges
                .try_reserve_exact(1)
                .map_err(|_| CryptoError::Capacity)?;
            // Retain staging through actual publication, including failure.
            self.charges.push(charge);
        }
        self.records
            .try_reserve_exact(1)
            .map_err(|_| CryptoError::Capacity)?;
        self.deferred
            .try_reserve_exact(self.reserved_deferred.max(deferred_tails))
            .map_err(|_| CryptoError::Capacity)?;
        let mut record = Vec::new();
        record
            .try_reserve_exact(record_bytes)
            .map_err(|_| CryptoError::Capacity)?;
        self.prepared_record = Some(record);
        self.reserved_deferred += additional_tails;
        Ok(())
    }
    fn publish(&mut self, record: &[u8]) -> Result<()> {
        let mut copy = self.prepared_record.take().ok_or(CryptoError::State)?;
        if copy.capacity() < record.len() {
            return Err(CryptoError::State);
        }
        copy.extend_from_slice(record);
        self.records.push(DeferredRecord {
            bytes: copy,
            work: None,
            publication: None,
            _physical: None,
            send_view: None,
            aborted: false,
        });
        Ok(())
    }
    fn publish_seal(&mut self, work: RecordWork, record: &mut [u8]) -> Result<()> {
        self.publish(record)?;
        let record = self.records.last_mut().ok_or(CryptoError::State)?;
        record._physical = Some(work.physical_tail());
        record.send_view = work.send_view();
        record.work = Some(work);
        Ok(())
    }
    fn is_deferred(&self) -> bool {
        true
    }
    fn defer_publication(&mut self, mut publication: DeferredPublication) {
        if self.deferred_error.is_some() {
            return;
        }
        if self.reserved_deferred == 0 || self.deferred.len() == self.deferred.capacity() {
            self.deferred_error = Some(CryptoError::State);
            return;
        }
        self.reserved_deferred -= 1;
        publication.record_index = self.records.len();
        self.deferred.push(publication);
    }
    fn try_claim_data(&mut self, scope: u64, maximum: usize) -> Result<DataPublicationClaim> {
        self.transport.try_claim_data(scope, maximum)
    }
    fn data_publication_permitted(&self, scope: u64) -> bool {
        self.transport.data_publication_permitted(scope)
    }
    fn failed_stream_publication(&self, scope: u64) -> Option<bool> {
        self.transport.failed_stream_publication(scope)
    }
    fn liveness_stall_generation(&self) -> u64 {
        self.transport.liveness_stall_generation()
    }
    fn liveness_stalled(&self) -> bool {
        self.transport.liveness_stalled()
    }
}
impl SessionTransport for DeferredPublisher<'_> {
    fn datagram_maximum(&self) -> Option<usize> {
        self.transport.datagram_maximum()
    }
    fn publish_datagram(
        &mut self,
        wire: Vec<u8>,
        original: DatagramLease,
    ) -> crate::transport::UnreliableSendOutcome {
        self.transport.publish_datagram(wire, original)
    }
    fn capture_native_bindings(&mut self, _session: &mut ReliableSession) -> Result<()> {
        Ok(())
    }
    fn close(&mut self) {
        self.transport.close()
    }
    fn cleanup_status(&self) -> CleanupStatus {
        self.transport.cleanup_status()
    }
    fn stream_cleanup_status(&self, scope: u64) -> CleanupStatus {
        self.transport.stream_cleanup_status(scope)
    }
}
struct Drive {
    session: Option<ReliableSession>,
    // The action that sealed terminal output retains closure until its native
    // publication completes. Observers must not re-enter the closed engine or
    // abort that output by converting its closed state into an action failure.
    closing: Option<SessionError>,
    termination: Option<SessionError>,
    termination_at: Option<Instant>,
    close_deadline: Option<Instant>,
}
struct Owner {
    drive: Mutex<Drive>,
    transport: Mutex<Box<dyn SessionTransport>>,
    // A fallback transport without an independent close signal may be busy
    // publishing when Session::close runs. Keep the close intent until the
    // original cleanup observer can acquire that same transport owner.
    transport_close_requested: AtomicBool,
    crypto: Arc<CryptoLifetime>,
    unbound_receive: Arc<Mutex<()>>,
    maintenance_receive: Arc<Mutex<()>>,
    account: ResourceAccount,
    staging: Arc<WriteStagingOwner>,
    changed: Arc<Notify>,
    core_stopped: AtomicBool,
    worker_done: AtomicBool,
    maintenance: Mutex<Option<crate::MaintenanceOwner>>,
    registered_dispatch: AtomicBool,
    reserved_dispatch: Mutex<Option<Arc<[String]>>>,
    protocol_active: AtomicBool,
    stream_pools: crate::preaccepted_streams_v4::PoolDirectory,
    rpc_bootstrap_claimed: AtomicBool,
    management_claimed: AtomicBool,
    management: Mutex<Option<crate::ExecutionManagement>>,
    notifications_claimed: AtomicBool,
    authentication_waiters: AtomicUsize,
    drain: Mutex<Option<Arc<controls::Drain>>>,
    retirement_deadline: Mutex<Option<Instant>>,
    application: Arc<OnceLock<Arc<ApplicationLifetime>>>,
    tails: Arc<ApplicationTails>,
    transport_close: Option<Arc<dyn Fn() + Send + Sync>>,
    transport_cleanup: Option<Arc<dyn Fn() -> CleanupStatus + Send + Sync>>,
    diagnostic: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    diagnostic_closed: AtomicBool,
    connect_diagnostic: Arc<Mutex<Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>>>,
    _charge: ResourceCharge,
}
impl Owner {
    /// Run a state-only operation without waiting for the native transport.
    ///
    /// Native publication owns the transport mutex while it performs a
    /// blocking provider call.  State inspection and authenticated receive
    /// bookkeeping must therefore be able to make progress on the drive
    /// mutex alone.
    fn run_state<T>(
        &self,
        action: impl FnOnce(&mut ReliableSession) -> std::result::Result<T, SessionError>,
    ) -> std::result::Result<T, SessionError> {
        let mut drive = self.drive.lock().expect("v4 Session owner lock");
        if let Some(cause) = drive.termination.or(drive.closing) {
            return Err(cause);
        }
        let session = drive.session.as_mut().ok_or(SessionError::Closed)?;
        let mut result = action(session);
        let closed = session.engine.closed;
        if closed {
            Self::close_locked(
                &mut drive,
                result
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(SessionError::Closed),
            );
        }
        drop(drive);
        if !closed && let Err(cause) = self.complete_rekey_crypto() {
            result = Err(cause);
        }
        if closed {
            self.diagnostic.session_failure(
                result
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(SessionError::Closed),
            );
            self.close_transport();
            self.staging.close();
            self.close_application();
            self.changed.notify_waiters();
        }
        result
    }

    fn complete_rekey_crypto(&self) -> std::result::Result<(), SessionError> {
        loop {
            let work = {
                let mut drive = self.drive.lock().expect("original rekey work claim");
                if let Some(cause) = drive.termination {
                    return Err(cause);
                }
                if drive.closing.is_some() {
                    return Ok(());
                }
                drive
                    .session
                    .as_mut()
                    .ok_or(SessionError::Closed)?
                    .engine
                    .take_rekey_crypto()
            };
            let Some(work) = work else {
                return Ok(());
            };
            // Only immutable snapshots and original owned resources cross this
            // boundary. DH/KDF never retain a drive or transport guard.
            let completion = match work.execute() {
                Ok(completion) => completion,
                Err(cause) => {
                    let cause = error(cause);
                    self.close(cause);
                    return Err(cause);
                }
            };
            let result = {
                let mut drive = self.drive.lock().expect("original rekey work commit");
                if let Some(cause) = drive.termination.or(drive.closing) {
                    return Err(cause);
                }
                drive
                    .session
                    .as_mut()
                    .ok_or(SessionError::Closed)?
                    .engine
                    .finish_rekey_crypto(completion)
                    .map_err(error)
            };
            if let Err(cause) = result {
                self.close(cause);
            }
            self.changed.notify_waiters();
            result?;
        }
    }

    fn run<T>(
        &self,
        action: impl FnOnce(
            &mut ReliableSession,
            &mut dyn SessionTransport,
        ) -> std::result::Result<T, SessionError>,
    ) -> std::result::Result<T, SessionError> {
        self.run_with_publication(None, action)
    }

    /// Receive a carrier maintenance frame while preserving the physical
    /// reader during terminal publication. Once `Drive::closing` is set, the
    /// terminal engine no longer performs AEAD/authentication work; this path
    /// only retains the bounded input queue and physical reader responsibility.
    /// Before closing, the original direction retains authentication custody
    /// across the short claim/commit gates and lock-free crypto work.
    fn receive_maintenance(
        &self,
        wire: &[u8],
    ) -> std::result::Result<ReceiveDisposition, SessionError> {
        if wire.len() < 28 {
            self.close(SessionError::OperationFailed);
            return Err(SessionError::OperationFailed);
        }
        #[cfg(test)]
        record_maintenance_receive(self);
        let scope = u64::from_be_bytes(
            wire[12..20]
                .try_into()
                .expect("maintenance scope after length check"),
        );
        {
            let drive = self.drive.lock().expect("v4 maintenance receive gate");
            if let Some(cause) = drive.termination {
                return Err(cause);
            }
            if drive.closing.is_some() {
                return Ok(ReceiveDisposition::Applied);
            }
        }
        let result = self
            .receive_record(scope, wire, None, |_| Ok(()))
            .map(|(_, disposition)| disposition);
        self.changed.notify_waiters();
        result
    }
    /// Direction serialization is independent of the short Session gate. No
    /// mutable Session reference crosses AEAD, and Close never takes this lock.
    fn receive_record<T>(
        &self,
        scope: u64,
        wire: &[u8],
        bound: Option<&StreamHandle>,
        after: impl FnOnce(&mut ReliableSession) -> std::result::Result<T, SessionError>,
    ) -> std::result::Result<(T, ReceiveDisposition), SessionError> {
        loop {
            let (direction, pool) = {
                let drive = self.drive.lock().expect("v4 receive direction lookup");
                if let Some(cause) = drive.termination.or(drive.closing) {
                    return Err(cause);
                }
                let session = drive.session.as_ref().ok_or(SessionError::Closed)?;
                let direction = if scope == 0 {
                    self.maintenance_receive.clone()
                } else if let Some(index) = session.engine.streams.index(scope) {
                    session.engine.streams.slots[index]
                        .view
                        .receive_owner
                        .clone()
                } else {
                    self.unbound_receive.clone()
                };
                (direction, session.engine.streams.input_pool.clone())
            };
            let _direction = direction.lock().expect("original reliable input direction");
            let current = {
                let drive = self
                    .drive
                    .lock()
                    .expect("original receive owner confirmation");
                if let Some(cause) = drive.termination.or(drive.closing) {
                    return Err(cause);
                }
                let session = drive.session.as_ref().ok_or(SessionError::Closed)?;
                if scope == 0 {
                    self.maintenance_receive.clone()
                } else if let Some(index) = session.engine.streams.index(scope) {
                    session.engine.streams.slots[index]
                        .view
                        .receive_owner
                        .clone()
                } else {
                    self.unbound_receive.clone()
                }
            };
            if !Arc::ptr_eq(&current, &direction) {
                continue;
            }
            let lease = pool.acquire(scope == 0).map_err(error)?;
            let prepared = self.run_state(|session| {
                session
                    .prepare_receive_input(scope, wire, bound, lease)
                    .map_err(error)
            })?;
            let completed = prepared.map(|mut input| {
                let opened = input.execute(wire);
                (input, opened)
            });
            return self.run_state(|session| {
                let disposition = if let Some((input, opened)) = completed {
                    session
                        .finish_receive_input(input, wire, opened)
                        .map_err(error)?
                } else {
                    ReceiveDisposition::Discarded { scope }
                };
                after(session).map(|value| (value, disposition))
            });
        }
    }

    fn run_with_publication<T>(
        &self,
        prepaid: Option<&ResourceCharge>,
        action: impl FnOnce(
            &mut ReliableSession,
            &mut dyn SessionTransport,
        ) -> std::result::Result<T, SessionError>,
    ) -> std::result::Result<T, SessionError> {
        // The native transport is acquired first.  A provider publish may
        // block while holding this mutex, but no caller can then hold `drive`
        // while waiting for it.  This is the only lock order used by the
        // two-resource session path.
        let mut transport = self.transport.lock().expect("v4 Session transport lock");
        let (result, records, deferred, charges) = {
            let mut drive = self.drive.lock().expect("v4 Session owner lock");
            let cause = drive.termination.or(drive.closing);
            if let Some(cause) = cause {
                return Err(cause);
            }
            let session = drive.session.as_mut().ok_or(SessionError::Closed)?;
            let mut publisher =
                DeferredPublisher::new(transport.as_mut(), self.account.clone(), prepaid);
            let mut result = action(session, &mut publisher);
            // A deferred tail is recorded after its reliable record ticket has
            // committed.  If charging/staging that tail fails, the record must
            // remain publishable and the session must enter terminal cleanup;
            // dropping it would leave the caller's frontier ahead of the wire
            // and would incorrectly turn the failure into an ordinary retry.
            if let Some(failure) = publisher.deferred_error.take() {
                session.engine.fail();
                let _ = failure;
                result = Err(SessionError::OperationFailed);
            }
            // Any reliable prefix already committed by the action remains
            // publishable even when a later action step fails.  Clearing it
            // would advance the in-memory crypto frontier without a wire
            // record; the failed session is closed after that prefix drains.
            let preserve_staged_records = !publisher.records.is_empty();
            if result.is_err() && preserve_staged_records {
                session.engine.fail();
            }
            if result.is_ok()
                && publisher.records.is_empty()
                && publisher.deferred.is_empty()
                && let Err(failure) = publisher.transport.capture_native_bindings(session)
            {
                session.engine.fail();
                result = Err(error(failure));
            }
            if result.as_ref().err() == Some(&SessionError::ResourceExhausted) {
                session.local_liveness_stall();
            }
            if result.is_err() && !preserve_staged_records {
                publisher.records.clear();
                publisher.deferred.clear();
            }
            if session.engine.closed {
                drive.closing = Some(
                    result
                        .as_ref()
                        .err()
                        .copied()
                        .unwrap_or(SessionError::Closed),
                );
            }
            (
                result,
                publisher.records,
                publisher.deferred,
                publisher.charges,
            )
        };

        drop(transport);
        let mut staging = PublicationStaging {
            records,
            deferred,
            _charges: charges,
        };
        let deferred = std::mem::take(&mut staging.deferred);
        let records = &mut staging.records;
        self.complete_rekey_crypto()?;

        // State-only actions do not participate in the native publication
        // order.  In particular, a read or metadata check must not wait for a
        // preceding provider write to return.
        if records.is_empty() && deferred.is_empty() {
            let mut drive = self.drive.lock().expect("v4 Session owner lock");
            let closed = drive
                .session
                .as_ref()
                .is_some_and(|session| session.engine.closed);
            if closed {
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
            drop(drive);
            if closed {
                self.diagnostic.session_failure(
                    result
                        .as_ref()
                        .err()
                        .copied()
                        .unwrap_or(SessionError::Closed),
                );
                self.close_transport();
                self.close_application();
                self.changed.notify_waiters();
            }
            return result;
        }

        // Each committed direction owns its own publication order. A delayed
        // DATA job cannot prevent scope-0 maintenance from publishing.
        for record in records.iter_mut() {
            if let Some(mut work) = record.work.take() {
                record.publication = work.take_publication();
                let completion = match work.seal_with_completion(&mut record.bytes) {
                    Ok(completion) => completion,
                    Err(_) if work.aborted() => {
                        record.aborted = true;
                        continue;
                    }
                    Err(cause) => {
                        self.close(error(cause));
                        return Err(error(cause));
                    }
                };
                // CLOSE has already sealed the protocol gate, but still owns
                // its original key and provider publication tail. Only actual
                // metadata completions need a live protocol-state commit.
                if completion.needs_commit() {
                    self.run_state(|session| {
                        session.engine.finish_record_seal(completion).map_err(error)
                    })?;
                }
                // Publication can wait behind this direction's earlier
                // provider tail. Retain the original deadline/key fence and
                // recheck it at the actual handoff gate.
                record.work = Some(work);
            }
        }

        let mut publication_error = None;
        let mut stream_error = None;
        let mut commit_error = None;
        let has_records = !records.is_empty();
        // Tail insertion follows record sealing, so indices are already
        // monotonic and require no additional sorting allocation.
        let mut pending_deferred = deferred.into_iter().peekable();

        // A deferred tail is tied to the record immediately preceding it.
        // Record index zero is reserved for a tail with no preceding record;
        // when records exist it becomes observable after the first successful
        // provider call, avoiding a zero-index head that blocks later tails.
        let mut commit_ready = |published: usize, accepted: bool| {
            loop {
                let ready = pending_deferred.peek().is_some_and(|publication| {
                    publication.record_index <= published
                        && (publication.record_index != 0 || !has_records || published != 0)
                });
                if !ready {
                    break;
                }
                let publication = pending_deferred
                    .next()
                    .expect("peeked deferred publication");
                if let Some(probe) = publication.probe.filter(|_| accepted) {
                    probe.complete();
                    let (stalled, generation) = {
                        let transport = self.transport.lock().expect("v4 probe handoff transport");
                        (
                            transport.liveness_stalled(),
                            transport.liveness_stall_generation(),
                        )
                    };
                    let result = self.run_state(|session| {
                        session
                            .complete_probe_publication(probe, stalled, generation)
                            .map_err(error)
                    });
                    if let Err(cause) = result
                        && !matches!(cause, SessionError::Closed)
                        && commit_error.is_none()
                    {
                        commit_error = Some(cause);
                    }
                }
                if accepted && publication.rekey_success {
                    self.account
                        .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::RekeySuccesses);
                }
                let mut scopes = [0u64; 2];
                let mut scope_count = 0usize;
                if let Some(stream) = publication.stream {
                    if accepted {
                        stream.view.accepted.store(stream.end, Ordering::Release);
                        if stream.fin {
                            stream.view.fin_submitted.store(true, Ordering::Release);
                        }
                    }
                    scopes[scope_count] = stream.scope;
                    scope_count += 1;
                }
                if let Some(scope) = publication.published_scope
                    && scope_count < scopes.len()
                {
                    scopes[scope_count] = scope;
                    scope_count += 1;
                }
                for scope in scopes[..scope_count].iter().copied() {
                    if let Err(cause) = self.run_state(|session| {
                        session.engine.streams.published(scope);
                        session.check().map_err(error)?;
                        if !accepted {
                            return Ok(());
                        }
                        let now = session
                            .engine
                            .account
                            .security_time()
                            .map_err(|cause| error(cause.into()))?;
                        session.engine.streams.controls.activity(now).map_err(error)
                    }) && !matches!(cause, SessionError::Closed)
                        && commit_error.is_none()
                    {
                        commit_error = Some(cause);
                    }
                }
                // The provider call has completed and no transport mutex is
                // held here, so a handoff callback cannot block native close.
                if let Some(handoff) = publication.handoff.filter(|_| accepted) {
                    handoff();
                }
            }
        };
        for (index, staged) in records.iter_mut().enumerate() {
            if let Some(publication) = &staged.publication
                && let Err(cause) = publication.wait()
            {
                publication_error = Some(error(cause));
                break;
            }
            if staged.aborted
                || staged
                    .send_view
                    .as_ref()
                    .is_some_and(|view| view.send_aborted.load(Ordering::Acquire))
            {
                stream_error = Some(SessionError::StreamReset);
                commit_ready(index + 1, false);
                staged.publication.take();
                continue;
            }
            let record = &staged.bytes;
            // These headers belong to our sealed records, not peer input.
            let scope = u64::from_be_bytes(record[12..20].try_into().expect("sealed scope"));
            let data = scope != 0 && record[4] == 8;
            let ended = if data {
                self.run_state(|session| {
                    Ok(session
                        .engine
                        .streams
                        .handle(scope)
                        .view
                        .native_send_end
                        .load(Ordering::Acquire)
                        != 0)
                })
                .unwrap_or(false)
            } else {
                false
            };
            if ended {
                // An earlier native failure already ended this direction.
                // Release its staged tails without manufacturing acceptance.
                stream_error = Some(SessionError::StreamReset);
                commit_ready(index + 1, false);
                staged.publication.take();
                continue;
            }
            let publication = {
                let mut transport = self.transport.lock().expect("v4 Session transport lock");
                {
                    let drive = self
                        .drive
                        .lock()
                        .expect("original crypto publication commit");
                    if let Some(cause) = drive.termination {
                        publication_error = Some(cause);
                        break;
                    }
                    if staged
                        .send_view
                        .as_ref()
                        .is_some_and(|view| view.send_aborted.load(Ordering::Acquire))
                    {
                        drop(drive);
                        drop(transport);
                        stream_error = Some(SessionError::StreamReset);
                        commit_ready(index + 1, false);
                        staged.publication.take();
                        continue;
                    }
                    if drive.closing.is_none()
                        && let Some(session) = drive.session.as_ref()
                        && let Err(cause) = session.engine.check()
                    {
                        publication_error = Some(error(cause));
                        break;
                    }
                    if let Some(work) = &staged.work
                        && let Err(cause) = work.check()
                    {
                        publication_error = Some(error(cause));
                        break;
                    }
                }
                #[cfg(test)]
                if record.get(4) == Some(&12) {
                    // Hold the sealed terminal publication before handing it
                    // to the provider. The peer is still live and can deliver
                    // real maintenance frames through the original reader.
                    block_terminal_publication(self);
                }
                let outcome = transport.publish(record).map_err(error);
                let failed_stream = outcome.as_ref().err().and_then(|_| {
                    data.then(|| transport.failed_stream_publication(scope))
                        .flatten()
                });
                (outcome, failed_stream)
            };
            match publication {
                (Ok(()), _) => {
                    commit_ready(index + 1, true);
                }
                (Err(_), Some(normal)) => {
                    let hint = self.run_state(|session| {
                        let handle = session.engine.streams.handle(scope);
                        session.native_hint(&handle, true, normal).map_err(error)
                    });
                    if let Err(cause) = hint {
                        publication_error = Some(cause);
                        break;
                    }
                    stream_error = Some(SessionError::StreamReset);
                    commit_ready(index + 1, false);
                    self.changed.notify_waiters();
                }
                (Err(cause), None) => {
                    publication_error = Some(cause);
                    break;
                }
            }
            // The direction remains owned through its original scalar/tail
            // commit, so a later accepted offset cannot be overwritten.
            staged.publication.take();
        }

        // A deferred-only action has no native prefix to wait for.  It is
        // uncommon, but committing index zero here keeps the gate total.
        if records.is_empty() && publication_error.is_none() {
            commit_ready(0, true);
        }

        // Native binding capture still requires the transport and live drive;
        // retain the canonical transport -> drive order for this short tail.
        let commit = (|| {
            if publication_error.is_none() && result.is_ok() {
                let mut transport = self.transport.lock().expect("v4 Session transport lock");
                let mut drive = self.drive.lock().expect("v4 Session owner lock");
                if let Some(session) = drive
                    .session
                    .as_mut()
                    .filter(|session| !session.engine.closed)
                {
                    transport.capture_native_bindings(session).map_err(error)?;
                }
            }
            if let Some(cause) = commit_error {
                Err(cause)
            } else {
                Ok::<(), SessionError>(())
            }
        })();
        if let Err(cause) = commit {
            self.close(cause);
            return Err(cause);
        }
        if let Some(cause) = publication_error {
            self.close(cause);
            return Err(cause);
        }

        let mut drive = self.drive.lock().expect("v4 Session owner lock");
        let closed = drive
            .session
            .as_ref()
            .is_some_and(|session| session.engine.closed);
        if closed {
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
        drop(drive);
        if closed {
            self.diagnostic.session_failure(
                result
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(SessionError::Closed),
            );
            self.close_transport();
            self.close_application();
            self.changed.notify_waiters();
        }
        if let Some(cause) = stream_error {
            return Err(cause);
        }
        result
    }
    fn close_locked(drive: &mut Drive, cause: SessionError) {
        if drive.termination.is_none() {
            if let Some(application) = drive.session.as_ref().and_then(|s| s.application.as_ref()) {
                application.close();
            }
            drive.termination = Some(cause);
            drive.closing = None;
            drive.termination_at = Some(Instant::now());
            drive.close_deadline = Some(Instant::now() + Duration::from_secs(5));
            if let Some(mut session) = drive.session.take() {
                session.engine.crypto.stop();
                session.engine.fail();
            }
        }
    }
    fn close_transport(&self) {
        if let Some(close) = &self.transport_close {
            close();
        } else {
            // Do not drop a close merely because the original transport owner
            // is in a synchronous publish. The cleanup loop retries this
            // exact request after that owner releases the mutex.
            self.transport_close_requested
                .store(true, Ordering::Release);
            if let Ok(mut transport) = self.transport.try_lock() {
                transport.close();
                self.transport_close_requested
                    .store(false, Ordering::Release);
            }
        }
    }
    fn close(&self, cause: SessionError) {
        self.diagnostic.session_failure(cause);
        Self::close_locked(
            &mut self.drive.lock().expect("v4 Session owner lock"),
            cause,
        );
        self.close_transport();
        self.staging.close();
        self.close_application();
        self.changed.notify_waiters();
    }
    fn close_application(&self) {
        let management = self
            .management
            .lock()
            .expect("original management owner")
            .take();
        if let Some(management) = management {
            management.close();
        }
        self.tails.close();
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
    fn retry_transport_close(&self) {
        if !self.transport_close_requested.load(Ordering::Acquire) {
            return;
        }
        if let Ok(mut transport) = self.transport.try_lock() {
            transport.close();
            self.transport_close_requested
                .store(false, Ordering::Release);
        }
    }
    fn core_cleanup(&self) -> CleanupStatus {
        // A cleanup callback can expose physical state independently of the
        // transport mutex. Service a deferred fallback close before reading
        // either representation so a legal close-signal/cleanup-signal
        // combination cannot strand the original carrier.
        self.retry_transport_close();
        let (terminated, deadline_expired) = {
            let drive = self.drive.lock().expect("v4 Session owner lock");
            (
                drive.termination.is_some(),
                drive.close_deadline.is_some_and(|d| Instant::now() >= d),
            )
        };
        let mut physical = self.transport_cleanup.as_ref().map_or_else(
            || {
                self.transport.try_lock().map_or(
                    CleanupStatus {
                        complete: false,
                        cleanup_incomplete: false,
                        pending_callbacks: 1,
                    },
                    |transport| transport.cleanup_status(),
                )
            },
            |cleanup| cleanup(),
        );
        // An independent cleanup callback may report the provider idle while
        // the fallback transport owner is still between close attempts. Keep
        // that original close obligation visible until the mutex owner has
        // serviced it.
        if self.transport_close_requested.load(Ordering::Acquire) {
            physical.complete = false;
            physical.pending_callbacks = physical.pending_callbacks.max(1);
        }
        let crypto_pending = self.crypto.pending();
        physical.pending_callbacks = physical
            .pending_callbacks
            .saturating_add(u64::try_from(crypto_pending).unwrap_or(u64::MAX));
        let complete = terminated
            && physical.complete
            && crypto_pending == 0
            && self.core_stopped.load(Ordering::Acquire);
        CleanupStatus {
            complete,
            cleanup_incomplete: physical.cleanup_incomplete || (!complete && deadline_expired),
            pending_callbacks: physical.pending_callbacks,
        }
    }
    fn cleanup(&self) -> CleanupStatus {
        let mut status = self.core_cleanup();
        status.complete &= self.worker_done.load(Ordering::Acquire);
        let tails = self.tails.status();
        status.complete &= tails.complete;
        status.cleanup_incomplete |= tails.cleanup_incomplete;
        status.pending_callbacks = status
            .pending_callbacks
            .saturating_add(tails.pending_callbacks);
        if let Some(application) = self.application.get() {
            let app = application.cleanup_status();
            status.complete &= app.complete;
            status.cleanup_incomplete |= app.cleanup_incomplete;
            status.pending_callbacks += app.pending_callbacks;
        }
        if status.complete {
            // Attach and completion share this gate so a late Connect owner
            // cannot miss a cleanup that finished before its publication.
            let connect = self
                .connect_diagnostic
                .lock()
                .expect("Connect diagnostic owner");
            if !self.diagnostic_closed.swap(true, Ordering::AcqRel) {
                self.diagnostic.closed();
            }
            if let Some(diagnostic) = connect.as_ref() {
                diagnostic.closed();
            }
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
        self.transport
            .get_mut()
            .expect("v4 Session transport lock")
            .close();
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
    configured_services: Option<crate::AcceptedServices>,
}
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session { <opaque> }")
    }
}
#[derive(Clone)]
pub(crate) struct SessionLink {
    owner: std::sync::Weak<Owner>,
}
impl SessionLink {
    pub(crate) fn session(&self) -> std::result::Result<Session, SessionError> {
        let owner = self.owner.upgrade().ok_or(SessionError::Closed)?;
        if owner
            .drive
            .lock()
            .expect("v4 Session owner lock")
            .termination
            .is_some()
        {
            return Err(SessionError::Closed);
        }
        Ok(Session {
            owner,
            configured_services: None,
        })
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeStreamProjection {
    pub(crate) accepted: bool,
    pub(crate) retired: bool,
    pub(crate) close_write: bool,
    pub(crate) reset_write: bool,
    pub(crate) stop_read: bool,
    pub(crate) normal_read: bool,
}
/// An association produced by the current authenticated OPEN owner. Native
/// errors cannot select another scope by changing a record's untrusted header.
#[derive(Clone)]
pub(crate) struct NativeStreamBinding {
    owner: std::sync::Weak<Owner>,
    handle: StreamHandle,
}
impl std::fmt::Debug for NativeStreamBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeStreamBinding { <opaque> }")
    }
}
impl NativeStreamBinding {
    pub(crate) fn is_management(&self) -> bool {
        self.handle.is_management()
    }
    pub(crate) fn scope(&self) -> u64 {
        self.handle.scope()
    }
    pub(crate) fn projection(&self) -> std::result::Result<NativeStreamProjection, SessionError> {
        let owner = self.owner.upgrade().ok_or(SessionError::Closed)?;
        owner.run_state(|session| session.native_projection(&self.handle).map_err(error))
    }
    pub(crate) fn receive(&self, wire: &[u8]) -> std::result::Result<(), SessionError> {
        let owner = self.owner.upgrade().ok_or(SessionError::Closed)?;
        let result = owner
            .receive_record(self.handle.scope(), wire, Some(&self.handle), |_| Ok(()))
            .map(|_| ());
        owner.changed.notify_waiters();
        result
    }
    pub(crate) fn native_hint(&self, sending: bool, normal: bool) {
        if let Some(owner) = self.owner.upgrade() {
            let _ = owner.run_state(|session| {
                session
                    .native_hint(&self.handle, sending, normal)
                    .map_err(error)
            });
            owner.changed.notify_waiters();
        }
    }
    pub(crate) fn reset(&self) {
        if let Some(owner) = self.owner.upgrade() {
            let _ = owner.run_state(|session| session.reset(&self.handle).map_err(error));
            owner.changed.notify_waiters();
        }
    }
}
#[cfg(test)]
pub(crate) struct OwnerLifetimeProbe {
    owner: std::sync::Weak<Owner>,
}
#[cfg(test)]
impl OwnerLifetimeProbe {
    pub(crate) fn is_alive(&self) -> bool {
        self.owner.strong_count() != 0
    }
}
#[derive(Clone)]
pub(crate) struct SessionReceiver {
    owner: std::sync::Weak<Owner>,
}
impl SessionReceiver {
    /// Observe termination without retaining the original Owner. The Notify
    /// waiter is registered before checking the state so a concurrent close
    /// cannot be missed; once the temporary upgrade is dropped, only the weak
    /// receiver and the notification handle remain alive.
    pub(crate) async fn wait_termination(&self) {
        loop {
            let Some(owner) = self.owner.upgrade() else {
                return;
            };
            let changed = owner.changed.clone();
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let terminated = owner
                .drive
                .lock()
                .expect("original receiver termination observation")
                .termination
                .is_some();
            drop(owner);
            if terminated {
                return;
            }
            notified.await;
        }
    }
    pub(crate) fn receive_datagram(&self, wire: &[u8]) {
        if let Some(owner) = self.owner.upgrade() {
            let prepared =
                owner.run_state(|session| Ok(session.engine.prepare_datagram_open(wire)));
            if let Ok(Ok(Some(mut job))) = prepared {
                let opened = job.execute(wire);
                let _ =
                    owner.run_state(|session| Ok(session.engine.finish_datagram_open(job, opened)));
            }
            owner.changed.notify_waiters();
        }
    }
    pub(crate) fn receive(
        &self,
        wire: &[u8],
    ) -> std::result::Result<ReceiveDisposition, SessionError> {
        let owner = self.owner.upgrade().ok_or(SessionError::Closed)?;
        owner.receive_maintenance(wire)
    }
    pub(crate) fn original_native_binding(&self, handle: StreamHandle) -> NativeStreamBinding {
        NativeStreamBinding {
            owner: self.owner.clone(),
            handle,
        }
    }
    /// Authenticate the OPEN and install its bounded native position before
    /// any Session writer can observe the prefix. The installer may only
    /// reserve provider state; it must not re-enter the Session or perform I/O.
    pub(crate) fn native_prefix<T>(
        &self,
        wire: &[u8],
        install: impl FnOnce(NativeStreamBinding) -> Option<T>,
    ) -> std::result::Result<Option<T>, SessionError> {
        if wire.len() < 44 || wire[4] != 7 {
            self.close();
            return Err(SessionError::OperationFailed);
        }
        let scope = u64::from_be_bytes(
            wire[12..20]
                .try_into()
                .map_err(|_| SessionError::OperationFailed)?,
        );
        let owner = self.owner.upgrade().ok_or(SessionError::Closed)?;
        let result = owner.receive_record(scope, wire, None, |session| {
            let handle = session.capture_native_binding(scope).map_err(error)?;
            let binding = self.original_native_binding(handle.clone());
            let installed = install(binding);
            if installed.is_none() {
                // A rejected native position cannot leave a writable prefix
                // behind. Preserve ordinary per-stream capacity rejection.
                let index = session.engine.streams.resolve(&handle).map_err(error)?;
                let slot = &mut session.engine.streams.slots[index];
                if slot.phase == Phase::Pending {
                    slot.forced_rejection.get_or_insert(Rejection::Resource);
                } else {
                    session.reset(&handle).map_err(error)?;
                }
            }
            Ok(installed)
        });
        owner.changed.notify_waiters();
        result.map(|(installed, _)| installed)
    }
    pub(crate) fn close(&self) {
        if let Some(owner) = self.owner.upgrade() {
            {
                let mut drive = owner.drive.lock().expect("original receiver termination");
                // A terminal publisher may inspect this receiver while its
                // final record is still in flight. Keep that observation a
                // no-op; real carrier/input failure uses close_input below.
                if drive.termination.is_some() || drive.closing.is_some() {
                    return;
                }
                Owner::close_locked(&mut drive, SessionError::OperationFailed);
            }
            owner.close(SessionError::OperationFailed);
        }
    }
    /// End the original session because the carrier reader observed a real
    /// EOF or input failure. Unlike `close`, this must override an intermediate
    /// terminal publication state so the original publisher cannot outlive a
    /// dead carrier indefinitely.
    pub(crate) fn close_input(&self, cause: SessionError) {
        if let Some(owner) = self.owner.upgrade() {
            owner.close(cause);
        }
    }
}
impl Session {
    pub(crate) fn attach_connect_diagnostic(
        &self,
        diagnostic: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    ) {
        let mut connect = self
            .owner
            .connect_diagnostic
            .lock()
            .expect("Connect diagnostic owner");
        if connect.is_none() {
            *connect = Some(diagnostic);
        }
        if self.owner.diagnostic_closed.load(Ordering::Acquire)
            && let Some(diagnostic) = connect.as_ref()
        {
            diagnostic.closed();
        }
    }
    /// The service graphs installed from the original Connect HandlerPlan.
    /// Handles retain this generation; no method recreates a bootstrap lane.
    pub fn configured_services(&self) -> Option<crate::AcceptedServices> {
        self.configured_services.clone()
    }
    pub(crate) fn with_configured_services(mut self, services: crate::AcceptedServices) -> Self {
        self.configured_services = Some(services);
        self
    }
    async fn wait_protocol_active(&self) -> std::result::Result<(), SessionError> {
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.owner
                .run_state(|session| session.check().map_err(error))?;
            if self.owner.protocol_active.load(Ordering::Acquire) {
                return Ok(());
            }
            changed.await;
        }
    }
    /// Assemble the authenticated RPC bootstrap once, sharing contract queries
    /// and registered service methods on the original Session owner.
    pub fn services(
        &self,
        query: crate::service_peer_v4::FixedContractQuery,
        registrations: Vec<crate::service_peer_v4::UnaryServiceRegistration>,
    ) -> std::result::Result<
        crate::service_peer_v4::ServicePeer,
        crate::service_contract::ServiceError,
    > {
        crate::service_peer_v4::ServicePeer::create(self, query, registrations)
    }
    pub fn services_with_result_read(
        &self,
        query: crate::FixedContractQuery,
        registrations: Vec<crate::UnaryServiceRegistration>,
        result_read: crate::FixedResultRead,
    ) -> std::result::Result<crate::ServicePeer, crate::ServiceError> {
        crate::service_peer_v4::ServicePeer::create_with_result_read(
            self,
            query,
            registrations,
            Some(result_read),
        )
    }
    pub async fn execution_management(
        &self,
        grants: Vec<crate::execution_management_v4::ExecutionHistoryGrant>,
    ) -> std::result::Result<
        crate::execution_management_v4::ExecutionManagement,
        crate::service_contract::ServiceError,
    > {
        crate::execution_management_v4::ExecutionManagement::create(self, grants).await
    }
    pub(crate) fn installed_management(&self) -> Option<crate::ExecutionManagement> {
        self.owner
            .management
            .lock()
            .expect("original management owner")
            .clone()
    }
    pub(crate) fn retain_management(&self, management: &crate::ExecutionManagement) {
        let mut original = self
            .owner
            .management
            .lock()
            .expect("original management owner");
        assert!(original.is_none(), "one original management owner");
        *original = Some(management.clone());
        drop(original);
        // Installation may race original Session shutdown. Publish first,
        // then repeat close so shutdown cannot miss a late retained owner.
        if self
            .owner
            .drive
            .lock()
            .expect("v4 Session owner lock")
            .termination
            .is_some()
        {
            self.owner.close_application();
        }
    }
    pub(crate) fn service_identity(&self) -> std::result::Result<(u8, u8, [u8; 32]), SessionError> {
        self.owner.run_state(|session| {
            Ok((
                session.engine.role,
                session.engine.application_profile,
                session.engine.authenticated_identities[usize::from(1 - session.engine.role)],
            ))
        })
    }
    pub(crate) fn controller_service_authority(
        &self,
    ) -> std::result::Result<(u8, u8, [[u8; 32]; 2]), SessionError> {
        self.owner.run_state(|session| {
            Ok((
                session.engine.role,
                session.engine.application_profile,
                session.engine.service_authorities,
            ))
        })
    }
    pub(crate) fn checkpoint_policy(
        &self,
    ) -> std::result::Result<crate::checkpoint_v4::ResumeSessionPolicy, SessionError> {
        self.owner.run_state(|session| {
            session
                .engine
                .resume_policy
                .ok_or(SessionError::OperationFailed)
        })
    }
    pub(crate) fn claim_notifications(&self) -> std::result::Result<(), SessionError> {
        self.owner
            .notifications_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| SessionError::OperationFailed)
    }
    pub(crate) fn claim_management(&self) -> std::result::Result<(), SessionError> {
        self.owner
            .management_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| SessionError::OperationFailed)
    }
    pub(crate) fn application_account(&self) -> ResourceAccount {
        self.owner.account.clone()
    }
    pub(crate) fn application_write_staging_owner(&self) -> Arc<WriteStagingOwner> {
        self.owner.staging.clone()
    }
    pub(crate) fn install_maintenance_owner(&self, owner: Option<crate::MaintenanceOwner>) {
        *self
            .owner
            .maintenance
            .lock()
            .expect("original Runtime maintenance capability") = owner;
    }
    pub fn maintenance_owner(
        &self,
    ) -> std::result::Result<crate::MaintenanceOwner, crate::ServiceError> {
        let owner = self
            .owner
            .maintenance
            .lock()
            .expect("original Runtime maintenance capability")
            .clone()
            .ok_or(crate::ServiceError(
                crate::ServiceFailure::ServiceUnavailable,
            ))?;
        owner.check_root(self.owner.account.environment_root())?;
        Ok(owner)
    }

    pub(crate) fn prepare_application_wait(
        &self,
    ) -> std::result::Result<ResourceCharge, SessionError> {
        self.owner.wait_charge()
    }
    pub(crate) fn application_tail(&self) -> std::result::Result<ApplicationTail, SessionError> {
        // Serialize admission with original Session termination, before any
        // wire OPEN or callback graph publication.
        let drive = self.owner.drive.lock().expect("v4 Session owner lock");
        if drive.termination.is_some() {
            return Err(SessionError::Closed);
        }
        self.owner
            .tails
            .register(&self.owner.account)
            .map_err(environment_error)
    }
    pub(crate) fn application_tail_reserved(
        &self,
        charge: ResourceCharge,
    ) -> std::result::Result<ApplicationTail, SessionError> {
        let drive = self.owner.drive.lock().expect("v4 Session owner lock");
        if drive.termination.is_some() {
            return Err(SessionError::Closed);
        }
        self.owner
            .tails
            .register_reserved(&self.owner.account, charge)
            .map_err(environment_error)
    }
    pub(crate) fn application_tail_shared(
        &self,
        charge: Arc<ResourceCharge>,
    ) -> std::result::Result<ApplicationTail, SessionError> {
        let drive = self.owner.drive.lock().expect("v4 Session owner lock");
        if drive.termination.is_some() {
            return Err(SessionError::Closed);
        }
        self.owner
            .tails
            .register_shared(&self.owner.account, charge)
            .map_err(environment_error)
    }
    pub(crate) fn claim_rpc_bootstrap_prepared(
        &self,
        preparation: StreamPreparation,
    ) -> std::result::Result<Stream, SessionError> {
        let handle = self
            .owner
            .run_state(|session| session.bootstrap_stream_handle().map_err(error))?;
        self.owner
            .rpc_bootstrap_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SessionError::OperationFailed)?;
        let stream = Stream::from_prepared(
            self.owner.clone(),
            handle,
            "flowersec.rpc.v4".to_owned(),
            Metadata::empty(),
            preparation,
        );
        let publish = self.owner.run(|session, transport| {
            if self.owner.protocol_active.load(Ordering::Acquire) && session.engine.role == 0 {
                session.materialize_bootstrap(transport).map_err(error)?;
            }
            Ok(())
        });
        if let Err(error) = publish {
            self.owner.close(error);
            return Err(error);
        }
        self.owner.changed.notify_waiters();
        Ok(stream)
    }
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
    pub(crate) fn link(&self) -> SessionLink {
        SessionLink {
            owner: Arc::downgrade(&self.owner),
        }
    }
    pub(crate) fn receiver(&self) -> SessionReceiver {
        SessionReceiver {
            owner: Arc::downgrade(&self.owner),
        }
    }
    #[cfg(test)]
    pub(crate) fn owner_lifetime_probe_for_test(&self) -> OwnerLifetimeProbe {
        OwnerLifetimeProbe {
            owner: Arc::downgrade(&self.owner),
        }
    }
    #[cfg(test)]
    pub(crate) fn adopt(
        environment: &Arc<EnvironmentRoot>,
        engine: RecordEngine,
        transport: Box<dyn SessionTransport>,
        reserved: Option<ResourceCharge>,
    ) -> std::result::Result<Self, SessionError> {
        Self::adopt_with_activation(environment, engine, transport, reserved, true)
    }
    pub(crate) fn adopt_paused(
        environment: &Arc<EnvironmentRoot>,
        engine: RecordEngine,
        transport: Box<dyn SessionTransport>,
        reserved: Option<ResourceCharge>,
    ) -> std::result::Result<Self, SessionError> {
        Self::adopt_with_activation(environment, engine, transport, reserved, false)
    }
    fn adopt_with_activation(
        environment: &Arc<EnvironmentRoot>,
        engine: RecordEngine,
        transport: Box<dyn SessionTransport>,
        reserved: Option<ResourceCharge>,
        active: bool,
    ) -> std::result::Result<Self, SessionError> {
        if !engine.account.belongs_to(environment) {
            return Err(SessionError::OperationFailed);
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| SessionError::OperationFailed)?;
        let mut session = engine.into_session().map_err(error)?;
        session.engine.deferred_crypto = true;
        let maintenance_publication = session
            .engine
            .streams
            .maintenance_publication
            .take()
            .ok_or(SessionError::OperationFailed)?;
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
        let tails = ApplicationTails::new(account.clone(), changed.clone());
        let transport_close = transport.close_signal();
        let transport_cleanup = transport.cleanup_signal();
        let diagnostic = account.diagnostic_activity(crate::DiagnosticPhase::Session, 1);
        let connect_diagnostic = Arc::new(Mutex::new(None));
        let physical_cleanup = transport_cleanup.clone();
        let cleanup_diagnostic = diagnostic.clone();
        let cleanup_connect_diagnostic = connect_diagnostic.clone();
        let crypto = session.engine.crypto.clone();
        let owner = Arc::new(Owner {
            authentication_waiters: AtomicUsize::new(0),
            drive: Mutex::new(Drive {
                session: Some(session),
                closing: None,
                termination: None,
                termination_at: None,
                close_deadline: None,
            }),
            transport: Mutex::new(transport),
            transport_close_requested: AtomicBool::new(false),
            crypto,
            unbound_receive: Arc::new(Mutex::new(())),
            maintenance_receive: Arc::new(Mutex::new(())),
            account: account.clone(),
            staging: Arc::new(WriteStagingOwner::from_account(account.clone())),
            changed: changed.clone(),
            core_stopped: AtomicBool::new(false),
            worker_done: AtomicBool::new(false),
            maintenance: Mutex::new(None),
            registered_dispatch: AtomicBool::new(false),
            reserved_dispatch: Mutex::new(None),
            protocol_active: AtomicBool::new(active),
            stream_pools: crate::preaccepted_streams_v4::PoolDirectory::default(),
            rpc_bootstrap_claimed: AtomicBool::new(false),
            management_claimed: AtomicBool::new(false),
            management: Mutex::new(None),
            notifications_claimed: AtomicBool::new(false),
            drain: Mutex::new(None),
            retirement_deadline: Mutex::new(None),
            application: application.clone(),
            tails: tails.clone(),
            transport_close,
            transport_cleanup,
            diagnostic,
            diagnostic_closed: AtomicBool::new(false),
            connect_diagnostic,
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
                    owner.close_application();
                    owner.core_stopped.store(true, Ordering::Release);
                    owner.changed.notify_waiters();
                    break;
                }
                let closing = owner
                    .drive
                    .lock()
                    .expect("v4 Session owner lock")
                    .closing
                    .is_some();
                let action = if owner.protocol_active.load(Ordering::Acquire) && !closing {
                    // The single original maintenance worker retains one
                    // complete publication quantum, including ACK, terminal
                    // proofs and rekey tails, independently of ordinary load.
                    owner.run_with_publication(
                        Some(&maintenance_publication),
                        |session, transport| session.poll(transport).map_err(error),
                    )
                } else {
                    Ok(false)
                };
                match action {
                    Ok(true) => owner.changed.notify_waiters(),
                    Ok(false) => {}
                    // A deferred FIN can lose its original native direction
                    // while unrelated streams and control records stay live.
                    Err(SessionError::StreamReset) => owner.changed.notify_waiters(),
                    Err(cause) => {
                        // A concurrent publisher may have sealed the terminal
                        // prefix since the liveness check above. Its original
                        // publication still owns the final close transition.
                        let closing = owner
                            .drive
                            .lock()
                            .expect("v4 Session owner lock")
                            .closing
                            .is_some();
                        if !closing {
                            owner.close(cause);
                        }
                    }
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
            tails.close();
            tails.wait().await;
            drop(tails);
            // The existing prepaid worker observes physical release even
            // after the final public handle has dropped its Session owner.
            loop {
                let complete = weak.upgrade().map_or_else(
                    || {
                        physical_cleanup
                            .as_ref()
                            .is_some_and(|cleanup| cleanup().complete)
                    },
                    |owner| owner.core_cleanup().complete,
                );
                if complete {
                    break;
                }
                if physical_cleanup.is_none() && weak.strong_count() == 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            drop(maintenance_publication);
            drop(task_charge);
            // No application or core work remains, and the original task
            // capacity is returned before any observer can see completion.
            if let Some(owner) = weak.upgrade() {
                owner.worker_done.store(true, Ordering::Release);
                owner.cleanup();
            } else {
                cleanup_diagnostic.closed();
                if let Some(diagnostic) = cleanup_connect_diagnostic
                    .lock()
                    .expect("Connect diagnostic owner")
                    .as_ref()
                {
                    diagnostic.closed();
                }
            }
            changed.notify_waiters();
        });
        Ok(Self {
            owner,
            configured_services: None,
        })
    }
    pub(crate) fn demand_stream_pool(
        &self,
        peer: &Arc<crate::service_peer_v4::PeerInner>,
        target: crate::preaccepted_streams_v4::PoolTarget,
        policy: crate::StreamingPoolPolicy,
    ) -> std::result::Result<Option<crate::preaccepted_streams_v4::PoolDemand>, crate::ServiceError>
    {
        self.owner.stream_pools.demand(self, peer, target, policy)
    }
    pub(crate) fn demand_stream_pools(
        &self,
        peer: &Arc<crate::service_peer_v4::PeerInner>,
        requested: Vec<(
            crate::preaccepted_streams_v4::PoolTarget,
            crate::StreamingPoolPolicy,
        )>,
    ) -> std::result::Result<
        Vec<Option<crate::preaccepted_streams_v4::PoolDemand>>,
        crate::ServiceError,
    > {
        self.owner.stream_pools.demand_many(self, peer, requested)
    }
    pub(crate) fn stream_dispatch_capacity(&self) -> std::result::Result<usize, SessionError> {
        self.owner
            .run_state(|session| Ok(session.engine.streams.max_active))
    }
    pub(crate) fn stream_pool_changed(&self) -> Arc<Notify> {
        self.owner.changed.clone()
    }
    pub(crate) fn application_draining(&self) -> bool {
        let drive = self.owner.drive.lock().expect("original Session drain");
        drive.session.as_ref().is_some_and(|session| {
            session.engine.streams.draining || session.engine.streams.controls.peer_goaway.is_some()
        })
    }
    pub(crate) fn with_stream_pool_admission<T>(
        &self,
        checkout: impl FnOnce() -> T,
    ) -> std::result::Result<T, SessionError> {
        self.owner.run_state(|session| {
            session.check().map_err(error)?;
            if session.engine.frozen
                || session.engine.streams.draining
                || session.engine.streams.controls.peer_goaway.is_some()
            {
                return Err(SessionError::Closed);
            }
            Ok(checkout())
        })
    }
    pub(crate) fn activate_protocol(&self) {
        let activated = self.owner.run(|session, transport| {
            if self.owner.protocol_active.load(Ordering::Acquire) {
                return Ok(());
            }
            if self.owner.rpc_bootstrap_claimed.load(Ordering::Acquire) && session.engine.role == 0
            {
                session.materialize_bootstrap(transport).map_err(error)?;
            }
            self.owner.protocol_active.store(true, Ordering::Release);
            Ok(())
        });
        if let Err(cause) = activated {
            self.owner.close(cause);
        }
        self.owner.changed.notify_waiters();
    }
    pub(crate) fn bind_reserved_dispatch(&self, kinds: Arc<[String]>) {
        *self
            .owner
            .reserved_dispatch
            .lock()
            .expect("reserved Stream dispatch") = Some(kinds);
    }
    pub(crate) async fn next_reserved_open(
        &self,
    ) -> std::result::Result<OpenRequest, SessionError> {
        let kinds = self
            .owner
            .reserved_dispatch
            .lock()
            .expect("reserved Stream dispatch")
            .clone()
            .ok_or(SessionError::OperationFailed)?;
        self.next_open_filtered(false, None, Some((kinds, true)), None)
            .await
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
    /// The test reader supplies only its authenticated Session association.
    /// Failure before a DATA tag authenticates cannot be assigned to a stream.
    #[cfg(test)]
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
        // Receive only updates authenticated state and pending controls. The
        // existing maintenance owner publishes those controls later; input
        // must not wait behind the native output call it may unblock.
        let result = self.owner.receive_record(scope, wire, None, |_| Ok(()));
        self.owner.changed.notify_waiters();
        result.map(|_| ())
    }
    pub async fn open_stream(
        &self,
        kind: &str,
        metadata: Metadata,
        receive_window: u64,
    ) -> std::result::Result<Stream, SessionError> {
        if kind.is_empty() || kind.len() > 128 {
            return Err(SessionError::OperationFailed);
        }
        let preparation = StreamPreparation::new(self.owner.account.clone())?;
        let mut stream = None;
        self.open_stream_prepared(kind, metadata, receive_window, preparation, |candidate| {
            stream = Some(candidate)
        })
        .await?;
        stream.ok_or(SessionError::OperationFailed)
    }
    pub(crate) async fn open_stream_prepared(
        &self,
        kind: &str,
        metadata: Metadata,
        receive_window: u64,
        mut preparation: StreamPreparation,
        attach: impl FnOnce(Stream),
    ) -> std::result::Result<(), SessionError> {
        if kind.is_empty() || kind.len() > 128 {
            return Err(SessionError::OperationFailed);
        }
        self.wait_protocol_active().await?;
        let _wait = match preparation.opening_wait.take() {
            Some(wait) => wait,
            None => self.owner.wait_charge()?,
        };
        let owner = self.owner.clone();
        let kind_owned = kind.to_owned();
        let captured_metadata = metadata.clone();
        let handle = self.owner.run(|session, transport| {
            session
                .open_stream_prepared(
                    kind,
                    metadata.encoded(),
                    receive_window,
                    transport,
                    |handle| {
                        attach(Stream::from_prepared(
                            owner,
                            handle,
                            kind_owned,
                            captured_metadata,
                            preparation,
                        ));
                    },
                )
                .map_err(error)
        })?;
        let mut guard = Opening {
            owner: self.owner.clone(),
            handle: Some(handle.clone()),
        };
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self
                .owner
                .run_state(|session| session.phase(&handle).map_err(error))
            {
                Ok(StreamPhase::Accepted) => {
                    guard.handle = None;
                    return Ok(());
                }
                Ok(StreamPhase::Recent | StreamPhase::Stable) => {
                    return Err(SessionError::StreamRejected);
                }
                Ok(_) => changed.await,
                Err(e) => return Err(e),
            }
        }
    }
    pub(crate) async fn open_service_stream(
        &self,
        kind: &str,
    ) -> std::result::Result<Stream, SessionError> {
        if kind.is_empty() || kind.len() > 128 {
            return Err(SessionError::OperationFailed);
        }
        let wait = self.owner.wait_charge()?;
        let preparation = StreamPreparation::new(self.owner.account.clone())?;
        self.open_service_stream_prepared(kind, preparation, wait)
            .await
    }
    pub(crate) async fn open_service_stream_prepared(
        &self,
        kind: &str,
        preparation: StreamPreparation,
        wait: ResourceCharge,
    ) -> std::result::Result<Stream, SessionError> {
        if kind.is_empty() || kind.len() > 128 {
            return Err(SessionError::OperationFailed);
        }
        let _wait = wait;
        self.wait_protocol_active().await?;
        let mut stream = None;
        let owner = self.owner.clone();
        let kind_owned = kind.to_owned();
        let handle = self.owner.run(|session, transport| {
            session
                .open_service_stream_prepared(kind, 16384, transport, |handle| {
                    stream = Some(Stream::from_prepared(
                        owner,
                        handle,
                        kind_owned,
                        Metadata::empty(),
                        preparation,
                    ));
                })
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
            match self
                .owner
                .run_state(|session| session.phase(&handle).map_err(error))?
            {
                StreamPhase::Accepted => {
                    guard.handle = None;
                    return stream.take().ok_or(SessionError::OperationFailed);
                }
                StreamPhase::Recent | StreamPhase::Stable => {
                    return Err(SessionError::StreamRejected);
                }
                _ => notified.await,
            }
        }
    }
    /// The fixed manager keeps the allocated Stream even if its opening wait
    /// is canceled. Its supervisor must retire that exact Stream before reuse.
    pub(crate) async fn open_management_stream_prepared(
        &self,
        backing: Arc<ResourceCharge>,
        wait: Arc<ResourceCharge>,
        publication: &ResourceCharge,
        attach: impl FnOnce(Stream),
    ) -> std::result::Result<(), SessionError> {
        let _wait = wait;
        self.wait_protocol_active().await?;
        let mut attach = Some(attach);
        let handle = loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let opened =
                self.owner
                    .run_with_publication(Some(publication), |session, transport| {
                        session.check().map_err(error)?;
                        if session.engine.streams.draining
                            || session.engine.streams.controls.peer_goaway.is_some()
                        {
                            return Err(SessionError::GoingAway);
                        }
                        // Preparation is permitted during rekey. Only the real ticket
                        // freeze delays allocation, under the initializer's deadline.
                        if session.engine.frozen {
                            return Ok(None);
                        }
                        let preparation = StreamPreparation::new_shared(
                            self.owner.account.clone(),
                            backing.clone(),
                        )?;
                        session
                            .open_service_stream_prepared(
                                "flowersec.execution-management.v4",
                                16384,
                                transport,
                                |handle| {
                                    attach.take().expect("one management allocation")(
                                        Stream::from_prepared(
                                            self.owner.clone(),
                                            handle,
                                            "flowersec.execution-management.v4".to_owned(),
                                            Metadata::empty(),
                                            preparation,
                                        ),
                                    )
                                },
                            )
                            .map(Some)
                            .map_err(error)
                    })?;
            if let Some(handle) = opened {
                break handle;
            }
            changed.await;
        };
        let mut guard = Opening {
            owner: self.owner.clone(),
            handle: Some(handle.clone()),
        };
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let accepted = self.owner.run_state(|session| {
                let phase = session.phase(&handle).map_err(error)?;
                if phase == StreamPhase::Accepted {
                    let index = session.engine.streams.resolve(&handle).map_err(error)?;
                    if session.engine.streams.slots[index].cancel {
                        return Err(SessionError::GoingAway);
                    }
                    return Ok(true);
                }
                if matches!(phase, StreamPhase::Recent | StreamPhase::Stable) {
                    return Err(SessionError::StreamRejected);
                }
                if session.engine.streams.draining
                    || session.engine.streams.controls.peer_goaway.is_some()
                {
                    return Err(SessionError::GoingAway);
                }
                Ok(false)
            })?;
            if accepted {
                guard.handle = None;
                return Ok(());
            }
            changed.await;
        }
    }
    pub(crate) fn management_allocations_exhausted(&self) -> bool {
        self.owner
            .run_state(|session| Ok(session.management_allocations_exhausted()))
            .unwrap_or(true)
    }
    pub(crate) async fn open_rpc_stream_prepared(
        &self,
        metadata: Metadata,
        preparation: StreamPreparation,
        wait: Arc<ResourceCharge>,
        attach: impl FnOnce(Stream),
    ) -> std::result::Result<(), SessionError> {
        let _wait = wait;
        self.wait_protocol_active().await?;
        let owner = self.owner.clone();
        let captured = metadata.clone();
        let handle = self.owner.run(|session, transport| {
            session
                .open_rpc_stream_prepared(metadata.encoded(), transport, |handle| {
                    attach(Stream::from_prepared(
                        owner,
                        handle,
                        "flowersec.rpc.v4".to_owned(),
                        captured,
                        preparation,
                    ));
                })
                .map_err(error)
        })?;
        let mut opening = Opening {
            owner: self.owner.clone(),
            handle: Some(handle.clone()),
        };
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self
                .owner
                .run_state(|session| session.phase(&handle).map_err(error))?
            {
                StreamPhase::Accepted => {
                    opening.handle = None;
                    return Ok(());
                }
                StreamPhase::Recent | StreamPhase::Stable => {
                    return Err(SessionError::StreamRejected);
                }
                _ => changed.await,
            }
        }
    }
    /// Transfers one bounded pending request to its application authorizer.
    /// Dropping the request submits the ordinary authenticated rejection.
    pub async fn next_open(&self) -> std::result::Result<OpenRequest, SessionError> {
        if self.owner.registered_dispatch.load(Ordering::Acquire) {
            return Err(SessionError::OperationFailed);
        }
        let reserved = self
            .owner
            .reserved_dispatch
            .lock()
            .expect("reserved Stream dispatch")
            .clone();
        self.next_open_filtered(false, None, reserved.map(|kinds| (kinds, false)), None)
            .await
    }
    pub(crate) async fn next_registered_open(
        &self,
    ) -> std::result::Result<OpenRequest, SessionError> {
        self.next_open_class(false, None).await
    }
    pub(crate) async fn next_service_kind(
        &self,
        kind: &str,
    ) -> std::result::Result<OpenRequest, SessionError> {
        self.next_open_class(true, Some(kind)).await
    }
    pub(crate) async fn next_service_kind_shared(
        &self,
        kind: &str,
        wait: Arc<ResourceCharge>,
    ) -> std::result::Result<OpenRequest, SessionError> {
        self.next_open_filtered(true, Some(kind), None, Some(wait))
            .await
    }
    pub(crate) async fn next_rpc_open_shared(
        &self,
        wait: Arc<ResourceCharge>,
    ) -> std::result::Result<OpenRequest, SessionError> {
        self.next_open_filtered(true, Some("flowersec.rpc.v4"), None, Some(wait))
            .await
    }
    async fn next_open_class(
        &self,
        service: bool,
        kind: Option<&str>,
    ) -> std::result::Result<OpenRequest, SessionError> {
        self.next_open_filtered(service, kind, None, None).await
    }
    async fn next_open_filtered(
        &self,
        service: bool,
        kind: Option<&str>,
        business_filter: Option<(Arc<[String]>, bool)>,
        reserved: Option<Arc<ResourceCharge>>,
    ) -> std::result::Result<OpenRequest, SessionError> {
        let wait = match reserved {
            Some(charge) => charge,
            None => Arc::new(
                self.owner
                    .account
                    .reserve(ResourceLimits {
                        sdk_bytes: 8192,
                        items: 1,
                        work_slots: 1,
                        tasks: 1,
                        sessions: 0,
                        ..ResourceLimits::default()
                    })
                    .map_err(environment_error)?,
            ),
        };
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let request = self.owner.run_state(|session| {
                let pending = if let Some((kinds, include)) = &business_filter {
                    session.pending_business_kinds(kinds, *include)
                } else if let Some(kind) = kind {
                    session.pending_service_kind(kind)
                } else if service {
                    session.pending_service_open()
                } else {
                    session.pending_open()
                };
                let Some(handle) = pending.map_err(error)? else {
                    return Ok(None);
                };
                let (kind, metadata) = session.pending_metadata(&handle).map_err(error)?;
                let projection = Metadata::from_open_encoded(metadata);
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
            match self.owner.run_state(|session| {
                session.check().map_err(error)?;
                Ok(session.engine.epoch > epoch)
            }) {
                Ok(true) => {
                    return Ok(());
                }
                Ok(false) => {}
                Err(SessionError::Timeout) => {
                    return Err(SessionError::Timeout);
                }
                Err(error) => return Err(error),
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
        let probe = self.owner.run_state(|session| {
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
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
    }
    pub(crate) fn controller_retirement_deadline(
        &self,
        maximum: Duration,
    ) -> std::result::Result<Instant, SessionError> {
        self.owner.run_state(|session| {
            session.check().map_err(error)?;
            self.owner
                .account
                .retirement_deadline(maximum)
                .map_err(|_| SessionError::Closed)
        })
    }
    /// Capture/retention eligibility reads the original Session admission
    /// gate. It does not create work, resume a drained owner or renew authority.
    pub(crate) fn controller_dispatch_eligible(&self) -> std::result::Result<(), SessionError> {
        self.controller_publication_gate(|| ())
    }
    /// Controller publication and original Session termination share this gate.
    /// The callback must not reenter this Session or execute application code.
    pub(crate) fn controller_publication_gate<T>(
        &self,
        publish: impl FnOnce() -> T,
    ) -> std::result::Result<T, SessionError> {
        self.controller_publication_gate_with_retained(None, publish)
    }
    pub(crate) fn controller_publication_gate_with_retained<T>(
        &self,
        retained: Option<&Session>,
        publish: impl FnOnce() -> T,
    ) -> std::result::Result<T, SessionError> {
        let mut drive = self
            .owner
            .drive
            .lock()
            .expect("original controller Session publication");
        if let Some(cause) = drive.termination {
            return Err(cause);
        }
        let session = drive.session.as_mut().ok_or(SessionError::Closed)?;
        session.check().map_err(error)?;
        if self
            .owner
            .retirement_deadline
            .lock()
            .expect("original Session retirement cutoff")
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(SessionError::Closed);
        }
        if !session.engine.ready
            || session.engine.streams.draining
            || session.engine.streams.controls.peer_goaway.is_some()
        {
            return Err(SessionError::Closed);
        }
        match retained {
            Some(previous) => self
                .owner
                .account
                .with_security_pair(&previous.owner.account, publish)
                .map_err(environment_error),
            None => self
                .owner
                .account
                .with_security(publish)
                .map_err(environment_error),
        }
    }
    /// Hold old admission eligibility through a retain replacement. The
    /// candidate callback acquires its own security gate after this check.
    pub(crate) fn controller_retention_gate<T>(
        &self,
        publish: impl FnOnce() -> T,
    ) -> std::result::Result<T, SessionError> {
        let mut drive = self
            .owner
            .drive
            .lock()
            .expect("retained original Session publication");
        if let Some(cause) = drive.termination {
            return Err(cause);
        }
        let session = drive.session.as_mut().ok_or(SessionError::Closed)?;
        session.check().map_err(error)?;
        if !session.engine.ready
            || session.engine.streams.draining
            || session.engine.streams.controls.peer_goaway.is_some()
            || self
                .owner
                .retirement_deadline
                .lock()
                .expect("old retain cutoff")
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(SessionError::Closed);
        }
        Ok(publish())
    }
    pub(crate) fn controller_retain_deadline(
        &self,
        retain_until_ms: u64,
    ) -> std::result::Result<Instant, SessionError> {
        self.controller_dispatch_eligible()?;
        let sampled_at = Instant::now();
        let sample = self
            .owner
            .account
            .security_time()
            .map_err(environment_error)?;
        let remaining = retain_until_ms
            .checked_sub(sample.upper_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or(SessionError::Timeout)?;
        let requested = sampled_at
            .checked_add(Duration::from_millis(remaining))
            .ok_or(SessionError::OperationFailed)?;
        let authority = self
            .owner
            .account
            .retirement_deadline(Duration::from_millis(remaining))
            .map_err(environment_error)?;
        let deadline = requested.min(authority);
        if deadline <= Instant::now() {
            return Err(SessionError::Timeout);
        }
        Ok(deadline)
    }
    pub(crate) fn controller_install_retirement_deadline(&self, deadline: Instant) -> Instant {
        let mut retained = self
            .owner
            .retirement_deadline
            .lock()
            .expect("original Session retirement cutoff");
        let deadline = retained.map_or(deadline, |old| old.min(deadline));
        *retained = Some(deadline);
        deadline
    }
    pub(crate) fn controller_retain_until(
        &self,
        duration: Duration,
    ) -> std::result::Result<u64, SessionError> {
        let sample = self
            .owner
            .account
            .security_time()
            .map_err(environment_error)?;
        let millis =
            u64::try_from(duration.as_millis()).map_err(|_| SessionError::OperationFailed)?;
        sample
            .upper_ms
            .checked_add(millis)
            .ok_or(SessionError::OperationFailed)
    }
    pub fn drain(&self, timeout: Duration) -> std::result::Result<DrainOperation, SessionError> {
        let mut retained = self.owner.drain.lock().expect("v4 retained drain");
        if let Some(drain) = retained.as_ref() {
            return Ok(DrainOperation {
                owner: self.owner.clone(),
                drain: drain.clone(),
            });
        }
        let drain = self.owner.run_state(|session| {
            let until = self
                .owner
                .retirement_deadline
                .lock()
                .expect("original Session retirement cutoff");
            let timeout = until.map_or(timeout, |deadline| {
                timeout.min(deadline.saturating_duration_since(Instant::now()))
            });
            session.start_drain_bounded(timeout, *until).map_err(error)
        })?;
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
        let closed = drive.session.as_ref().is_some_and(|s| s.engine.closed);
        if closed {
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
        drop(drive);
        if closed {
            self.owner.close_transport();
            self.owner.close_application();
        }
        let drain = result?;
        *retained = Some(drain.clone());
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
        f.write_str("DrainOperation { <opaque> }")
    }
}
impl DrainOperation {
    /// Enforce the earlier aggregate deadline even if the ordinary Session
    /// worker has not received its next scheduling turn.
    pub(crate) fn expire_for_serve(&self, now: Instant) {
        let mut drive = self.owner.drive.lock().expect("v4 Session owner lock");
        let expire = drive.termination.is_none() && now >= self.drain.deadline();
        if expire {
            self.drain.finish(DrainOutcome::DeadlineAborted);
            Owner::close_locked(&mut drive, SessionError::Timeout);
            self.owner.staging.close();
        }
        drop(drive);
        if expire {
            self.owner.close_application();
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
            configured_services: None,
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
                .run_state(|session| session.reset(handle).map_err(error));
            self.owner.changed.notify_waiters();
        }
    }
}

pub struct OpenRequest {
    owner: Arc<Owner>,
    handle: Option<StreamHandle>,
    kind: String,
    metadata: Metadata,
    _charge: Arc<ResourceCharge>,
}
impl std::fmt::Debug for OpenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenRequest { <opaque> }")
    }
}
impl OpenRequest {
    pub(crate) fn account(&self) -> ResourceAccount {
        self.owner.account.clone()
    }
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    pub(crate) fn session(&self) -> Session {
        Session {
            owner: self.owner.clone(),
            configured_services: None,
        }
    }
    pub(crate) fn prepare_stream(&self) -> std::result::Result<Stream, SessionError> {
        let handle = self.handle.as_ref().ok_or(SessionError::Closed)?;
        Stream::new(
            self.owner.clone(),
            handle.clone(),
            self.kind.clone(),
            self.metadata.clone(),
        )
    }
    pub(crate) fn prepare_stream_reserved(
        &self,
        preparation: StreamPreparation,
    ) -> std::result::Result<Stream, SessionError> {
        let handle = self.handle.as_ref().ok_or(SessionError::Closed)?;
        Ok(Stream::from_prepared(
            self.owner.clone(),
            handle.clone(),
            self.kind.clone(),
            self.metadata.clone(),
            preparation,
        ))
    }
    pub(crate) fn accept_prepared(
        self,
        stream: Stream,
        receive_window: u64,
    ) -> std::result::Result<Stream, SessionError> {
        self.accept_prepared_with_publication(stream, receive_window, None)
    }
    pub(crate) fn accept_prepared_with_publication(
        mut self,
        stream: Stream,
        receive_window: u64,
        publication: Option<&ResourceCharge>,
    ) -> std::result::Result<Stream, SessionError> {
        let handle = self.handle.as_ref().ok_or(SessionError::Closed)?;
        if !Arc::ptr_eq(&stream.inner.owner, &self.owner)
            || stream.inner.handle.scope() != handle.scope()
        {
            return Err(SessionError::OperationFailed);
        }
        if self.metadata.is_typed() && !stream.inner.typed.lock().expect("Stream I/O mode").typed {
            return Err(SessionError::StreamRejected);
        }
        self.owner
            .run_with_publication(publication, |session, transport| {
                if self.kind == "flowersec.execution-management.v4"
                    && (session.engine.streams.draining
                        || session.engine.streams.controls.peer_goaway.is_some())
                {
                    return Err(SessionError::GoingAway);
                }
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
    pub fn accept(self, receive_window: u64) -> std::result::Result<Stream, SessionError> {
        let stream = self.prepare_stream()?;
        self.accept_prepared(stream, receive_window)
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
            let _ = self.owner.run_state(|session| {
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
#[derive(Debug)]
pub(crate) struct StreamPreparation {
    read: Arc<StreamReadOwner>,
    charge: Arc<ResourceCharge>,
    opening_wait: Option<ResourceCharge>,
    typed: bool,
}
impl StreamPreparation {
    pub(crate) fn preparation_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 5120,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn new(account: ResourceAccount) -> std::result::Result<Self, SessionError> {
        let charge = account
            .reserve(Self::preparation_limits())
            .map_err(environment_error)?;
        Self::new_prepaid(account, charge)
    }
    pub(crate) fn new_prepaid(
        account: ResourceAccount,
        charge: ResourceCharge,
    ) -> std::result::Result<Self, SessionError> {
        if !charge.matches(&account, Self::preparation_limits()) {
            return Err(SessionError::OperationFailed);
        }
        Ok(Self {
            read: Arc::new(StreamReadOwner::from_account(1 << 20, account)),
            charge: Arc::new(charge),
            opening_wait: None,
            typed: false,
        })
    }
    pub(crate) fn new_shared(
        account: ResourceAccount,
        charge: Arc<ResourceCharge>,
    ) -> std::result::Result<Self, SessionError> {
        if !charge.matches(&account, Self::preparation_limits()) {
            return Err(SessionError::OperationFailed);
        }
        Ok(Self {
            read: Arc::new(StreamReadOwner::from_account(1 << 20, account)),
            charge,
            opening_wait: None,
            typed: false,
        })
    }
    pub(crate) fn reserve_opening_wait(
        &mut self,
        session: &Session,
    ) -> std::result::Result<(), SessionError> {
        if self.opening_wait.is_some() {
            return Err(SessionError::OperationFailed);
        }
        self.opening_wait = Some(session.prepare_application_wait()?);
        Ok(())
    }
    pub(crate) fn claim_typed(
        &mut self,
    ) -> std::result::Result<crate::api_v4::StreamReadPermit, SessionError> {
        if self.typed {
            return Err(SessionError::OperationFailed);
        }
        let permit = self.read.acquire()?;
        self.typed = true;
        Ok(permit)
    }
}
#[derive(Clone, Copy)]
struct StreamIOMode {
    typed: bool,
    generation: u64,
}
impl StreamIOMode {
    fn allows(&self, stream: &Stream) -> bool {
        self.typed == stream.typed_access
            && (!self.typed || self.generation == stream.message_generation)
    }
}
/// The temporary message qualification belongs to the original Stream owner.
/// Its last reader/sender must exit before the qualification is dropped.
pub(crate) struct ResumeMessageClaim {
    stream: Stream,
    binding: crate::checkpoint_v4::ResumeTargetBinding,
    begun: bool,
    settled: bool,
    unsubmitted: bool,
}
impl ResumeMessageClaim {
    pub(crate) fn binding(&self) -> &crate::checkpoint_v4::ResumeTargetBinding {
        &self.binding
    }
    pub(crate) fn begin(&mut self) {
        self.begun = true;
    }
    pub(crate) fn settle(&mut self) {
        self.settled = true;
    }
    pub(crate) fn settle_unsubmitted(&mut self) {
        self.unsubmitted = true;
    }
}
impl Drop for ResumeMessageClaim {
    fn drop(&mut self) {
        let mut mode = self.stream.inner.typed.lock().expect("Stream I/O mode");
        if !mode.allows(&self.stream) {
            return;
        }
        let write = self.stream.inner.write.try_lock();
        let read = self.stream.inner.read.acquire();
        let idle = write.is_ok() && read.is_ok();
        let unused = (!self.begun || self.unsubmitted)
            && read.as_ref().is_ok_and(|permit| permit.start_offset() == 0)
            && self
                .stream
                .inner
                .handle
                .view
                .accepted
                .load(Ordering::Acquire)
                == 0;
        if !idle || !self.settled && !unused {
            self.stream.inner.read.revoke_delivery();
            let _ = self
                .stream
                .inner
                .owner
                .run_state(|session| session.reset(&self.stream.inner.handle).map_err(error));
            self.stream.inner.owner.changed.notify_waiters();
        }
        // No temporary facade can become usable when a later message owner
        // claims the same Stream: each claim has a distinct local generation.
        if idle {
            mode.typed = false;
        }
    }
}

pub(crate) struct StreamPublicationAdmission {
    claim: Option<crate::crypto_v4::DataPublicationClaim>,
    changed: Arc<Notify>,
    _charge: ResourceCharge,
}
impl Drop for StreamPublicationAdmission {
    fn drop(&mut self) {
        self.claim.take();
        self.changed.notify_waiters();
    }
}
struct StreamOwner {
    owner: Arc<Owner>,
    handle: StreamHandle,
    kind: String,
    metadata: Metadata,
    read: Arc<StreamReadOwner>,
    write: AsyncMutex<()>,
    prepared_writes: AtomicUsize,
    typed: Mutex<StreamIOMode>,
    _charge: Arc<ResourceCharge>,
}
impl Drop for StreamOwner {
    fn drop(&mut self) {
        let _ = self
            .owner
            .run_state(|session| session.reset(&self.handle).map_err(error));
        self.owner.changed.notify_waiters();
    }
}
#[derive(Clone)]
pub struct Stream {
    inner: Arc<StreamOwner>,
    typed_access: bool,
    message_generation: u64,
}
impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Stream { <opaque> }")
    }
}
type StreamReadClaim = (Stream, crate::api_v4::StreamReadPermit);

impl Stream {
    pub(crate) fn management_cleanup_complete(&self) -> bool {
        if !self.cleanup_status().complete {
            return false;
        }
        self.inner.owner.core_cleanup().complete
            || self
                .inner
                .owner
                .run_state(|session| {
                    session
                        .management_retired(&self.inner.handle)
                        .map_err(error)
                })
                .unwrap_or(false)
    }
    /// Existing management admission shares the original Session gate with
    /// business Drain completion. The callback performs only bounded SDK work.
    pub(crate) fn management_admission_gate<T>(
        &self,
        admit: impl FnOnce(Option<Instant>) -> T,
    ) -> std::result::Result<T, SessionError> {
        let (result, progressed) = self.inner.owner.run_state(|session| {
            session.check().map_err(error)?;
            // Seal management when original business communication is already
            // complete, without waiting for another driver scheduling turn.
            let progressed = session.poll_lifecycle_deadlines().map_err(error)?;
            let deadline = session
                .engine
                .streams
                .controls
                .drain
                .as_ref()
                .map(|drain| drain.deadline());
            let result = session.check().map_err(error).and_then(|()| {
                let index = session
                    .engine
                    .streams
                    .resolve(&self.inner.handle)
                    .map_err(error)?;
                if session.engine.streams.slots[index].cancel || self.application_read_ended() {
                    Err(SessionError::Closed)
                } else if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    Err(SessionError::Timeout)
                } else {
                    Ok(admit(deadline))
                }
            });
            Ok((result, progressed))
        })?;
        if progressed {
            self.inner.owner.changed.notify_waiters();
        }
        result
    }
    pub(crate) fn application_read_ended(&self) -> bool {
        self.inner.handle.view.end.load(Ordering::Acquire) != 0
    }
    pub(crate) fn application_changed(&self) -> Arc<Notify> {
        self.inner.owner.changed.clone()
    }
    pub(crate) fn application_draining(&self) -> bool {
        let drive = self
            .inner
            .owner
            .drive
            .lock()
            .expect("original Session drain");
        drive.session.as_ref().is_some_and(|session| {
            session.engine.streams.draining || session.engine.streams.controls.peer_goaway.is_some()
        })
    }
    /// A fixed RPC channel may retain accepted replies during Drain, while
    /// each new request still crosses the original Session admission gate.
    pub(crate) fn admit_application_request(
        &self,
    ) -> std::result::Result<Option<crate::environment_v4::BusinessActivity>, SessionError> {
        self.inner.owner.run_state(|session| {
            session.check().map_err(error)?;
            if session.engine.streams.draining
                || session.engine.streams.controls.peer_goaway.is_some()
            {
                return Ok(None);
            }
            Ok(Some(self.inner.owner.account.begin_business_work()))
        })
    }
    /// The original application publisher has already joined its accepted
    /// writes. Request FIN on the existing stream sender without allocating a
    /// new waiter, task or publication owner. The reader retains physical cleanup.
    pub(crate) fn request_application_close_write(&self) -> std::result::Result<(), SessionError> {
        let mode = self.inner.typed.lock().expect("Stream I/O mode");
        if !mode.allows(self) {
            return Err(SessionError::OperationFailed);
        }
        if self.inner.handle.view.fin_submitted.load(Ordering::Acquire) {
            return Ok(());
        }
        self.inner.owner.run_state(|session| {
            session
                .request_close_write(&self.inner.handle)
                .map_err(error)
        })?;
        self.inner.owner.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn internal_publication_generation(&self) -> u64 {
        self.inner.handle.scope()
    }
    fn new(
        owner: Arc<Owner>,
        handle: StreamHandle,
        kind: String,
        metadata: Metadata,
    ) -> std::result::Result<Self, SessionError> {
        let preparation = StreamPreparation::new(owner.account.clone())?;
        Ok(Self::from_prepared(
            owner,
            handle,
            kind,
            metadata,
            preparation,
        ))
    }
    fn from_prepared(
        owner: Arc<Owner>,
        handle: StreamHandle,
        kind: String,
        metadata: Metadata,
        preparation: StreamPreparation,
    ) -> Self {
        let generation = u64::from(preparation.typed);
        Self {
            typed_access: preparation.typed,
            message_generation: generation,
            inner: Arc::new(StreamOwner {
                owner,
                handle,
                kind,
                metadata,
                read: preparation.read,
                write: AsyncMutex::new(()),
                prepared_writes: AtomicUsize::new(0),
                typed: Mutex::new(StreamIOMode {
                    typed: preparation.typed,
                    generation,
                }),
                _charge: preparation.charge,
            }),
        }
    }
    pub(crate) fn application_tail(&self) -> std::result::Result<ApplicationTail, SessionError> {
        Session {
            owner: self.inner.owner.clone(),
            configured_services: None,
        }
        .application_tail()
    }
    pub(crate) fn shared_preparation(&self) -> Arc<ResourceCharge> {
        self.inner._charge.clone()
    }
    pub(crate) fn application_tail_shared(
        &self,
        charge: Arc<ResourceCharge>,
    ) -> std::result::Result<ApplicationTail, SessionError> {
        Session {
            owner: self.inner.owner.clone(),
            configured_services: None,
        }
        .application_tail_shared(charge)
    }
    pub(crate) fn application_tail_reserved(
        &self,
        charge: ResourceCharge,
    ) -> std::result::Result<ApplicationTail, SessionError> {
        Session {
            owner: self.inner.owner.clone(),
            configured_services: None,
        }
        .application_tail_reserved(charge)
    }
    pub(crate) fn pool_ready(&self) -> bool {
        matches!(
            self.inner
                .owner
                .run_state(|session| session.phase(&self.inner.handle).map_err(error)),
            Ok(StreamPhase::Accepted)
        )
    }
    pub(crate) fn account(&self) -> ResourceAccount {
        self.inner.owner.account.clone()
    }
    pub(crate) fn message_wait_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 256,
            items: 1,
            work_slots: 1,
            tasks: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn management_publication_limits() -> ResourceLimits {
        // One bounded OPEN/accept or <=1538-byte M message record, its
        // encoded staging and original deferred completion metadata.
        ResourceLimits {
            sdk_bytes: 8192,
            items: 8,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn prepare_message_wait(&self) -> std::result::Result<ResourceCharge, SessionError> {
        self.inner.owner.wait_charge()
    }
    pub(crate) fn prepare_message_wait_prepaid(
        &self,
        charge: ResourceCharge,
    ) -> std::result::Result<ResourceCharge, SessionError> {
        if !charge.matches(&self.inner.owner.account, Self::message_wait_limits()) {
            return Err(SessionError::OperationFailed);
        }
        Ok(charge)
    }
    pub(crate) fn resume_target(
        &self,
        session: &Session,
    ) -> std::result::Result<crate::checkpoint_v4::ResumeTargetBinding, SessionError> {
        self.with_resume_target(session, false, |binding| binding)
    }
    pub(crate) fn with_resume_target<T>(
        &self,
        session: &Session,
        admission: bool,
        action: impl FnOnce(crate::checkpoint_v4::ResumeTargetBinding) -> T,
    ) -> std::result::Result<T, SessionError> {
        if !Arc::ptr_eq(&self.inner.owner, &session.owner) || !self.typed_access {
            return Err(SessionError::OperationFailed);
        }
        let mode = self.inner.typed.lock().expect("Stream I/O mode");
        if !mode.allows(self) {
            return Err(SessionError::OperationFailed);
        }
        self.inner.owner.run(|reliable, _| {
            reliable.check().map_err(error)?;
            if !reliable.engine.ready
                || reliable.engine.resume_policy.is_none()
                || reliable.phase(&self.inner.handle).map_err(error)? != StreamPhase::Accepted
                || admission
                    && (reliable.engine.streams.draining
                        || reliable.engine.streams.controls.peer_goaway.is_some())
            {
                return Err(SessionError::OperationFailed);
            }
            Ok(action(crate::checkpoint_v4::ResumeTargetBinding {
                context: reliable.engine.context,
                stream: self.inner.handle.scope(),
            }))
        })
    }

    fn check_io_mode(&self) -> std::result::Result<(), SessionError> {
        if !self
            .inner
            .typed
            .lock()
            .expect("Stream I/O mode")
            .allows(self)
        {
            return Err(SessionError::OperationFailed);
        }
        Ok(())
    }
    pub(crate) fn claim_typed(
        &self,
    ) -> std::result::Result<(Stream, crate::api_v4::StreamReadPermit), SessionError> {
        let mut mode = self.inner.typed.lock().expect("Stream I/O mode");
        if mode.typed
            || self.typed_access
            || self.inner.prepared_writes.load(Ordering::Acquire) != 0
        {
            return Err(SessionError::OperationFailed);
        }
        let _write = self
            .inner
            .write
            .try_lock()
            .map_err(|_| SessionError::OperationFailed)?;
        let permit = self.inner.read.acquire()?;
        if permit.start_offset() != 0
            || self.inner.handle.view.accepted.load(Ordering::Acquire) != 0
        {
            return Err(SessionError::OperationFailed);
        }
        let generation = mode
            .generation
            .checked_add(1)
            .ok_or(SessionError::OperationFailed)?;
        mode.typed = true;
        mode.generation = generation;
        Ok((
            Stream {
                inner: self.inner.clone(),
                typed_access: true,
                message_generation: generation,
            },
            permit,
        ))
    }
    /// Claim both original I/O gates without consuming input.  The bridge only
    /// accepts unused business streams; no owner is transferred on failure.
    pub(crate) fn claim_bridge_pair(
        a: &Stream,
        b: &Stream,
    ) -> std::result::Result<(StreamReadClaim, StreamReadClaim), SessionError> {
        if a.same_bridge_endpoint(b) {
            return Err(SessionError::OperationFailed);
        }
        // try_lock avoids reversed-order contention between concurrent claims.
        let mut a_mode = a
            .inner
            .typed
            .try_lock()
            .map_err(|_| SessionError::OperationFailed)?;
        let mut b_mode = b
            .inner
            .typed
            .try_lock()
            .map_err(|_| SessionError::OperationFailed)?;
        if a_mode.typed
            || b_mode.typed
            || a.typed_access
            || b.typed_access
            || a.inner.prepared_writes.load(Ordering::Acquire) != 0
            || b.inner.prepared_writes.load(Ordering::Acquire) != 0
        {
            return Err(SessionError::OperationFailed);
        }
        let _a_write = a
            .inner
            .write
            .try_lock()
            .map_err(|_| SessionError::OperationFailed)?;
        let _b_write = b
            .inner
            .write
            .try_lock()
            .map_err(|_| SessionError::OperationFailed)?;
        let a_read = a.inner.read.acquire()?;
        let b_read = b.inner.read.acquire()?;
        if a_read.start_offset() != 0
            || b_read.start_offset() != 0
            || a.inner.handle.view.accepted.load(Ordering::Acquire) != 0
            || b.inner.handle.view.accepted.load(Ordering::Acquire) != 0
            || a.inner.handle.view.fin_submitted.load(Ordering::Acquire)
            || b.inner.handle.view.fin_submitted.load(Ordering::Acquire)
            || !a.pool_ready()
            || !b.pool_ready()
        {
            return Err(SessionError::OperationFailed);
        }
        for stream in [a, b] {
            stream.inner.owner.run_state(|session| {
                let index = session
                    .engine
                    .streams
                    .resolve(&stream.inner.handle)
                    .map_err(error)?;
                let slot = &session.engine.streams.slots[index];
                let outgoing = slot.directions[usize::from(session.engine.role)];
                if slot.class != Class::Business
                    || outgoing.fin
                    || outgoing.fin_requested
                    || outgoing.stop
                {
                    return Err(SessionError::OperationFailed);
                }
                Ok(())
            })?;
        }
        let a_generation = a_mode
            .generation
            .checked_add(1)
            .ok_or(SessionError::OperationFailed)?;
        let b_generation = b_mode
            .generation
            .checked_add(1)
            .ok_or(SessionError::OperationFailed)?;
        a_mode.typed = true;
        a_mode.generation = a_generation;
        b_mode.typed = true;
        b_mode.generation = b_generation;
        Ok((
            (
                Stream {
                    inner: a.inner.clone(),
                    typed_access: true,
                    message_generation: a_generation,
                },
                a_read,
            ),
            (
                Stream {
                    inner: b.inner.clone(),
                    typed_access: true,
                    message_generation: b_generation,
                },
                b_read,
            ),
        ))
    }
    /// A native bridge acquires the original raw Stream gates while the
    /// independently SDK-owned TCP endpoint holds its own unpublished gate.
    pub(crate) fn claim_bridge_endpoint_with(
        &self,
        before_claim: impl FnOnce() -> std::result::Result<(), SessionError>,
    ) -> std::result::Result<(Stream, crate::api_v4::StreamReadPermit), SessionError> {
        let mut mode = self
            .inner
            .typed
            .try_lock()
            .map_err(|_| SessionError::OperationFailed)?;
        if mode.typed
            || self.typed_access
            || self.inner.prepared_writes.load(Ordering::Acquire) != 0
        {
            return Err(SessionError::OperationFailed);
        }
        let _writer = self
            .inner
            .write
            .try_lock()
            .map_err(|_| SessionError::OperationFailed)?;
        let permit = self.inner.read.acquire()?;
        if permit.start_offset() != 0
            || self.inner.handle.view.accepted.load(Ordering::Acquire) != 0
            || self.inner.handle.view.fin_submitted.load(Ordering::Acquire)
            || !self.pool_ready()
        {
            return Err(SessionError::OperationFailed);
        }
        let generation = mode
            .generation
            .checked_add(1)
            .ok_or(SessionError::OperationFailed)?;
        // Qualification is a local ownership transition. Hold the original
        // Session gate through validation, charge transfer and publication;
        // no fallible provider capture follows a successful transfer.
        let drive = self
            .inner
            .owner
            .drive
            .lock()
            .expect("v4 Session owner lock");
        if let Some(cause) = drive.termination {
            return Err(cause);
        }
        let session = drive.session.as_ref().ok_or(SessionError::Closed)?;
        if session.engine.closed {
            return Err(SessionError::Closed);
        }
        let index = session
            .engine
            .streams
            .resolve(&self.inner.handle)
            .map_err(error)?;
        let slot = &session.engine.streams.slots[index];
        let outgoing = slot.directions[usize::from(session.engine.role)];
        if slot.phase != Phase::Accepted
            || slot.class != Class::Business
            || outgoing.fin
            || outgoing.fin_requested
            || outgoing.stop
        {
            return Err(SessionError::OperationFailed);
        }
        // The private source owner transfers its already reserved physical
        // vector before either endpoint publishes its new qualification.
        before_claim()?;
        mode.typed = true;
        mode.generation = generation;
        Ok((
            Stream {
                inner: self.inner.clone(),
                typed_access: true,
                message_generation: generation,
            },
            permit,
        ))
    }
    pub(crate) fn same_bridge_endpoint(&self, other: &Stream) -> bool {
        Arc::ptr_eq(&self.inner.owner, &other.inner.owner)
            && self.inner.handle.scope() == other.inner.handle.scope()
    }
    /// Pure local full-vector admission for the exclusive original message
    /// publisher. No byte or transport acceptance is manufactured here.
    pub(crate) fn try_admit_message_publication(
        &self,
        bytes: usize,
    ) -> std::result::Result<StreamPublicationAdmission, SessionError> {
        let mode = self
            .inner
            .typed
            .try_lock()
            .map_err(|_| SessionError::ResourceExhausted)?;
        if !self.typed_access || !mode.allows(self) {
            return Err(SessionError::OperationFailed);
        }
        self.try_admit_original_publication(bytes)
    }
    /// The sole ordered RPC publisher retains this original raw Stream. This
    /// crate-private projection cannot manufacture a separate publication owner.
    pub(crate) fn try_admit_rpc_publication(
        &self,
        bytes: usize,
    ) -> std::result::Result<StreamPublicationAdmission, SessionError> {
        let mode = self
            .inner
            .typed
            .try_lock()
            .map_err(|_| SessionError::ResourceExhausted)?;
        if self.typed_access || !mode.allows(self) {
            return Err(SessionError::OperationFailed);
        }
        self.try_admit_original_publication(bytes)
    }
    fn try_admit_original_publication(
        &self,
        bytes: usize,
    ) -> std::result::Result<StreamPublicationAdmission, SessionError> {
        let _writer = self
            .inner
            .write
            .try_lock()
            .map_err(|_| SessionError::ResourceExhausted)?;
        let charge = self.inner.owner.wait_charge()?;
        let mut drive = self
            .inner
            .owner
            .drive
            .try_lock()
            .map_err(|_| SessionError::ResourceExhausted)?;
        if let Some(cause) = drive.termination {
            return Err(cause);
        }
        let reliable = drive.session.as_mut().ok_or(SessionError::Closed)?;
        let mut transport = self
            .inner
            .owner
            .transport
            .try_lock()
            .map_err(|_| SessionError::ResourceExhausted)?;
        reliable.check().map_err(error)?;
        let i = reliable
            .engine
            .streams
            .resolve(&self.inner.handle)
            .map_err(error)?;
        let slot = &reliable.engine.streams.slots[i];
        let direction = slot.directions[usize::from(reliable.engine.role)];
        if !reliable.engine.ready
            || slot.phase != Phase::Accepted
            || !slot.prefix
            || reliable.engine.streams.draining
            || reliable.engine.streams.controls.peer_goaway.is_some()
            || direction.stop
            || direction.fin
            || direction.fin_requested
            || direction.terminal.is_some()
        {
            return Err(SessionError::OperationFailed);
        }
        if direction
            .current
            .offset
            .checked_add(bytes as u64)
            .is_none_or(|end| end > direction.limit)
            || reliable.engine.max_frame <= 128
        {
            return Err(SessionError::ResourceExhausted);
        }
        let record_bytes = bytes.min(QUANTUM).min(reliable.engine.max_frame - 128) + 128 + 8;
        // A frozen epoch alone does not decline this claim. Its original
        // bounded sender waits for the same rekey ticket after Start.
        let claim = transport
            .try_claim_data(self.inner.handle.scope(), record_bytes)
            .map_err(error)?;
        Ok(StreamPublicationAdmission {
            claim: Some(claim),
            changed: self.inner.owner.changed.clone(),
            _charge: charge,
        })
    }
    /// Used only by the SDK Resume owner. Access stays blocked until its exact
    /// framing qualification has settled and its real reader has exited.
    pub(crate) fn resume_raw_facade(&self) -> std::result::Result<Stream, SessionError> {
        let mode = self.inner.typed.lock().expect("Stream I/O mode");
        if !self.typed_access || !mode.allows(self) {
            return Err(SessionError::OperationFailed);
        }
        Ok(Stream {
            inner: self.inner.clone(),
            typed_access: false,
            message_generation: 0,
        })
    }
    /// Only the original SDK Resume framing owner can reacquire its reader,
    /// after the complete confirmation reader has actually exited.
    pub(crate) fn resume_continuation_reader(
        &self,
    ) -> std::result::Result<crate::api_v4::StreamReadPermit, SessionError> {
        let mode = self
            .inner
            .typed
            .lock()
            .expect("Resume continuation I/O mode");
        if !self.typed_access || !mode.allows(self) {
            return Err(SessionError::OperationFailed);
        }
        self.inner.read.acquire()
    }
    /// Capture the exact fresh accepted business Stream before a recovery ID
    /// or digest exists. This performs no OPEN, read, write or store operation.
    pub(crate) fn check_resume_metadata(
        &self,
        session: &Session,
        kind: &str,
        metadata: &Metadata,
    ) -> std::result::Result<(), SessionError> {
        if !Arc::ptr_eq(&self.inner.owner, &session.owner) || &self.inner.metadata != metadata {
            return Err(SessionError::OperationFailed);
        }
        self.inner.owner.run(|reliable, _| {
            let i = reliable
                .engine
                .streams
                .resolve(&self.inner.handle)
                .map_err(error)?;
            let slot = &reliable.engine.streams.slots[i];
            if slot.kind != kind {
                return Err(SessionError::OperationFailed);
            }
            Ok(())
        })
    }
    pub(crate) fn claim_resume(
        &self,
        session: &Session,
        kind: &str,
    ) -> std::result::Result<
        (Stream, crate::api_v4::StreamReadPermit, ResumeMessageClaim),
        SessionError,
    > {
        self.claim_resume_phase(session, kind, false)
    }
    pub(crate) fn claim_pending_resume(
        &self,
        session: &Session,
        kind: &str,
    ) -> std::result::Result<
        (Stream, crate::api_v4::StreamReadPermit, ResumeMessageClaim),
        SessionError,
    > {
        self.claim_resume_phase(session, kind, true)
    }
    fn claim_resume_phase(
        &self,
        session: &Session,
        kind: &str,
        pending: bool,
    ) -> std::result::Result<
        (Stream, crate::api_v4::StreamReadPermit, ResumeMessageClaim),
        SessionError,
    > {
        if !Arc::ptr_eq(&self.inner.owner, &session.owner)
            || self.inner.kind != kind
            || self.typed_access
        {
            return Err(SessionError::OperationFailed);
        }
        let mut mode = self.inner.typed.lock().expect("Stream I/O mode");
        if mode.typed {
            return Err(SessionError::OperationFailed);
        }
        let _write = self
            .inner
            .write
            .try_lock()
            .map_err(|_| SessionError::OperationFailed)?;
        let permit = self.inner.read.acquire()?;
        if permit.start_offset() != 0 {
            return Err(SessionError::OperationFailed);
        }
        let binding = self.inner.owner.run(|reliable, _| {
            reliable.check().map_err(error)?;
            let i = reliable
                .engine
                .streams
                .resolve(&self.inner.handle)
                .map_err(error)?;
            let slot = &reliable.engine.streams.slots[i];
            let output = &slot.directions[usize::from(reliable.engine.role)];
            if !reliable.engine.ready
                || reliable.engine.resume_policy.is_none()
                || reliable.engine.streams.draining
                || reliable.engine.streams.controls.peer_goaway.is_some()
                || slot.phase
                    != (if pending {
                        Phase::Pending
                    } else {
                        Phase::Accepted
                    })
                || slot.class != Class::Business
                || slot.kind != kind
                || output.current.offset != 0
                || output.fin
                || output.fin_requested
                || output.stop
                || slot.directions[usize::from(1 - reliable.engine.role)].released != 0
            {
                return Err(SessionError::OperationFailed);
            }
            Ok(crate::checkpoint_v4::ResumeTargetBinding {
                context: reliable.engine.context,
                stream: self.inner.handle.scope(),
            })
        })?;
        let generation = mode
            .generation
            .checked_add(1)
            .ok_or(SessionError::OperationFailed)?;
        mode.typed = true;
        mode.generation = generation;
        let stream = Stream {
            inner: self.inner.clone(),
            typed_access: true,
            message_generation: generation,
        };
        let claim = ResumeMessageClaim {
            stream: stream.clone(),
            binding,
            begun: false,
            settled: false,
            unsubmitted: false,
        };
        Ok((stream, permit, claim))
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
        let result = self.inner.owner.run_state(|session| {
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
        let permit = {
            let mode = self.inner.typed.lock().expect("Stream I/O mode");
            if !mode.allows(self) {
                return Err(SessionError::OperationFailed);
            }
            self.inner.read.acquire()?
        };
        self.read_with_permit(max_bytes, &permit).await
    }
    pub(crate) async fn read_with_permit(
        &self,
        max_bytes: usize,
        permit: &crate::api_v4::StreamReadPermit,
    ) -> std::result::Result<ReadResult, SessionError> {
        self.check_io_mode()?;
        if !permit.belongs_to(&self.inner.read) || max_bytes == 0 || max_bytes > 1 << 20 {
            return Err(SessionError::OperationFailed);
        }
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
                .run_state(|session| session.read(&self.inner.handle, &mut out).map_err(error))
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
    /// The bridge's source frontier and charged payload handoff commit while
    /// the original receive queue is still under its owner gate.  No caller
    /// continuation must run to record bytes that have already left the queue.
    pub(crate) async fn read_bridge_piece(
        &self,
        max_bytes: usize,
        permit: &crate::api_v4::StreamReadPermit,
        stop: &tokio_util::sync::CancellationToken,
        transfer_gate: &Mutex<()>,
        commit: impl Fn(Bytes, ReadStreamStatus) + Send + Sync,
    ) -> std::result::Result<ReadStreamStatus, SessionError> {
        self.check_io_mode()?;
        if !permit.belongs_to(&self.inner.read)
            || max_bytes == 0
            || max_bytes > 1 << 20
            || !permit.can_advance(max_bytes)
        {
            return Err(SessionError::OperationFailed);
        }
        if self.retained_eof() {
            let _transfer = transfer_gate.lock().expect("bridge read gate");
            if stop.is_cancelled() {
                return Err(SessionError::Canceled);
            }
            commit(Bytes::new(), ReadStreamStatus::Eof);
            return Ok(ReadStreamStatus::Eof);
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
        let mut payload = Some(Payload {
            data: out,
            _charge: charge,
        });
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let result = self.inner.owner.run_state(|session| {
                // session.read performs the original authenticated transfer;
                // all accounting and handoff below remain in this same gate.
                let _transfer = transfer_gate.lock().expect("bridge read gate");
                if stop.is_cancelled() {
                    return Err(SessionError::Canceled);
                }
                let read = session
                    .read(
                        &self.inner.handle,
                        &mut payload.as_mut().expect("bridge payload").data,
                    )
                    .map_err(error)?;
                let (count, state) = match read {
                    ReadState::Pending => return Ok(None),
                    ReadState::Data(count) => (count, ReadStreamStatus::Open),
                    ReadState::Eof => (0, ReadStreamStatus::Eof),
                    ReadState::Aborted => (0, ReadStreamStatus::Aborted),
                };
                permit.advance(count)?;
                let mut payload = payload.take().expect("bridge payload");
                payload.data.truncate(count);
                account.detach_result();
                commit(Bytes::from_owner(payload), state);
                Ok(Some(state))
            })?;
            if let Some(state) = result {
                self.inner.owner.changed.notify_waiters();
                return Ok(state);
            }
            notified.await;
        }
    }
    pub(crate) fn replenish_bridge_credit(
        &self,
        window: usize,
    ) -> std::result::Result<(), SessionError> {
        self.check_io_mode()?;
        self.inner.owner.run_state(|session| {
            let Some(index) = session.engine.streams.index(self.inner.handle.scope()) else {
                return Ok(());
            };
            let incoming = session.engine.streams.slots[index].directions
                [usize::from(1 - session.engine.role)];
            if incoming.fin || incoming.stop || incoming.terminal.is_some() {
                return Ok(());
            }
            let next = incoming
                .released
                .checked_add(window as u64)
                .ok_or(SessionError::OperationFailed)?;
            if next > incoming.limit {
                session.grant(&self.inner.handle, next).map_err(error)?;
            }
            Ok(())
        })?;
        self.inner.owner.changed.notify_waiters();
        Ok(())
    }
    pub fn grant_receive_limit(&self, limit: u64) -> std::result::Result<(), SessionError> {
        let result = self
            .inner
            .owner
            .run_state(|session| session.grant(&self.inner.handle, limit).map_err(error));
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
                .run_state(|session| session.check().map_err(error))?;
            notified.await;
        }
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let complete = self
            .inner
            .owner
            .run_state(|session| {
                Ok(matches!(
                    session.phase(&self.inner.handle).map_err(error)?,
                    StreamPhase::Recent | StreamPhase::Stable
                ))
            })
            .unwrap_or(false);
        let physical = self
            .inner
            .owner
            .transport
            .lock()
            .expect("v4 Session transport lock")
            .stream_cleanup_status(self.inner.handle.scope());
        // A Stream's physical cleanup cannot depend on application tails
        // that are themselves awaiting this Stream's retirement.
        let session = self.inner.owner.core_cleanup();
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
        let wait = self.inner.owner.wait_charge()?;
        self.send_reserved(payload, admission, fin, wait, None)
            .await
    }
    pub(crate) async fn close_message_write_prepared(
        &self,
        _wait: ResourceCharge,
    ) -> std::result::Result<(), SessionError> {
        {
            let mode = self.inner.typed.lock().expect("Stream I/O mode");
            if !mode.allows(self) {
                return Err(SessionError::OperationFailed);
            }
            if self.inner.handle.view.fin_submitted.load(Ordering::Acquire) {
                return Ok(());
            }
            self.inner.owner.run_state(|session| {
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
        }
        self.inner.owner.changed.notify_waiters();
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.handle.view.fin_submitted.load(Ordering::Acquire) {
                return Ok(());
            }
            self.inner.owner.run_state(|session| {
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
    /// The ordered RPC reader retains its original bounded input buffer and
    /// waiter. No application result account or escaping payload is created.
    pub(crate) async fn read_rpc_prepared(
        &self,
        buffer: &mut [u8],
        wait: &ResourceCharge,
    ) -> std::result::Result<Option<usize>, SessionError> {
        if buffer.is_empty()
            || buffer.len() > QUANTUM
            || !wait.matches(&self.inner.owner.account, Self::message_wait_limits())
        {
            return Err(SessionError::OperationFailed);
        }
        let permit = {
            let mode = self.inner.typed.lock().expect("Stream I/O mode");
            if self.typed_access || !mode.allows(self) {
                return Err(SessionError::OperationFailed);
            }
            self.inner.read.acquire()?
        };
        if self.retained_eof() {
            return Ok(None);
        }
        loop {
            let notified = self.inner.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let read = match self
                .inner
                .owner
                .run_state(|session| session.read(&self.inner.handle, buffer).map_err(error))
            {
                Ok(read) => read,
                Err(_) if self.retained_eof() => return Ok(None),
                Err(cause) => return Err(cause),
            };
            let count = match read {
                ReadState::Pending => {
                    notified.await;
                    continue;
                }
                ReadState::Data(count) => count,
                ReadState::Eof => return Ok(None),
                ReadState::Aborted => return Err(SessionError::StreamReset),
            };
            self.inner
                .owner
                .account
                .with_security(|| permit.advance(count))
                .map_err(environment_error)??;
            self.inner.owner.changed.notify_waiters();
            return Ok(Some(count));
        }
    }
    pub(crate) async fn write_message_prepared(
        &self,
        payload: Bytes,
        admission: &WriteRequestAdmission,
        wait: ResourceCharge,
        handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> std::result::Result<(), SessionError> {
        self.send_reserved(payload, Some(admission), false, wait, handoff)
            .await
            .map(|_| ())
    }
    /// The fixed management writer already owns its complete bounded payload
    /// and task before READY. Use that original waiter and the normal Stream
    /// record/publication engine without competing for public prepared writes.
    pub(crate) async fn write_management_prepared(
        &self,
        payload: &[u8],
        wait: &ResourceCharge,
        publication: &ResourceCharge,
        deadline: Option<u64>,
        cancellation: &CancellationToken,
        mut before_accept: impl FnMut() -> std::result::Result<(), SessionError>,
    ) -> std::result::Result<(), (usize, SessionError)> {
        if self.inner.kind != "flowersec.execution-management.v4"
            || payload.is_empty()
            || payload.len() > 1538
            || !wait.matches(&self.inner.owner.account, Self::message_wait_limits())
            || !publication.matches(
                &self.inner.owner.account,
                Self::management_publication_limits(),
            )
        {
            return Err((0, SessionError::OperationFailed));
        }
        let _write = self.inner.write.lock().await;
        let _blocked = BlockedWriter {
            owner: self.inner.owner.clone(),
            handle: self.inner.handle.clone(),
        };
        let mut accepted = 0;
        loop {
            let changed = self.inner.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let result = self
                .inner
                .owner
                .run_with_publication(Some(publication), |session, transport| {
                    session.poll_lifecycle_deadlines().map_err(error)?;
                    session.check().map_err(error)?;
                    if cancellation.is_cancelled() {
                        return Err(SessionError::Canceled);
                    }
                    let now = session
                        .engine
                        .account
                        .security_time()
                        .map_err(environment_error)?;
                    if deadline.is_some_and(|deadline| now.upper_ms >= deadline) {
                        return Err(SessionError::Timeout);
                    }
                    let index = session
                        .engine
                        .streams
                        .resolve(&self.inner.handle)
                        .map_err(error)?;
                    let slot = &session.engine.streams.slots[index];
                    if slot.cancel || self.application_read_ended() {
                        return Err(SessionError::Closed);
                    }
                    let direction = slot.directions[usize::from(session.engine.role)];
                    if direction.stop || direction.terminal.is_some() || direction.fin_requested {
                        return Err(SessionError::StreamReset);
                    }
                    if session.engine.frozen
                        || !transport.data_publication_permitted(self.inner.handle.scope())
                    {
                        return Ok(None);
                    }
                    let room =
                        usize::try_from(direction.limit.saturating_sub(direction.current.offset))
                            .unwrap_or(usize::MAX);
                    let count = (payload.len() - accepted)
                        .min(room)
                        .min(QUANTUM)
                        .min(session.engine.max_frame.saturating_sub(128));
                    if count == 0 {
                        session.engine.streams.slots[index]
                            .send_progress
                            .get_or_insert(now.monotonic_sample);
                        return Ok(None);
                    }
                    session.engine.streams.slots[index].send_progress = None;
                    // Eligibility and this real record handoff share the original
                    // Session gate; Drain cannot reopen between the two.
                    let mut admission_failure = None;
                    let account = session.engine.account.clone();
                    let result = session.write_management(
                        &self.inner.handle,
                        &payload[accepted..accepted + count],
                        transport,
                        &mut || {
                            let result = (|| {
                                if cancellation.is_cancelled() {
                                    return Err(SessionError::Canceled);
                                }
                                let now = account.security_time().map_err(environment_error)?;
                                if deadline.is_some_and(|deadline| now.upper_ms >= deadline) {
                                    return Err(SessionError::Timeout);
                                }
                                before_accept()
                            })();
                            result.map_err(|cause| {
                                admission_failure = Some(cause);
                                CryptoError::State
                            })
                        },
                    );
                    result
                        .map(Some)
                        .map_err(|cause| admission_failure.unwrap_or_else(|| error(cause)))
                })
                .map_err(|error| (accepted, error))?;
            if let Some(count) = result {
                accepted += count;
                self.inner.owner.changed.notify_waiters();
                if accepted == payload.len() {
                    return Ok(());
                }
                continue;
            }
            let remaining = match deadline {
                Some(deadline) => {
                    let now = self
                        .inner
                        .owner
                        .account
                        .security_time()
                        .map_err(|error| (accepted, environment_error(error)))?;
                    Duration::from_millis(deadline.saturating_sub(now.upper_ms))
                        .min(self.inner.owner.account.next_security_check())
                }
                None => self.inner.owner.account.next_security_check(),
            };
            tokio::select! {
                _ = changed => {},
                _ = cancellation.cancelled() => return Err((accepted, SessionError::Canceled)),
                _ = self.inner.owner.account.security_changed() => {},
                _ = tokio::time::sleep(remaining) => {},
            }
        }
    }
    async fn send_reserved(
        &self,
        payload: Bytes,
        admission: Option<&WriteRequestAdmission>,
        fin: bool,
        _wait: ResourceCharge,
        handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> std::result::Result<usize, SessionError> {
        let _write = self.inner.write.lock().await;
        Session {
            owner: self.inner.owner.clone(),
            configured_services: None,
        }
        .wait_protocol_active()
        .await?;
        self.check_io_mode()?;
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
                if session.engine.frozen
                    // The server's reserved RPC bootstrap can be claimed at
                    // READY before its peer OPEN arrives on a native stream.
                    // Keep the original write pending until that authenticated
                    // prefix is available; it does not allocate another lane.
                    || !session.engine.streams.slots[i].prefix
                    || !transport.data_publication_permitted(self.inner.handle.scope())
                {
                    return Ok(None);
                }
                let room = usize::try_from(d.limit - d.current.offset).unwrap_or(usize::MAX);
                let count = (payload.len() - accepted)
                    .min(room)
                    .min(QUANTUM)
                    .min(session.engine.max_frame.saturating_sub(128));
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
                if accepted == 0
                    && admission.is_some()
                    && session.engine.streams.slots[i].class == Class::Management
                {
                    // Repeat the existing management eligibility under the same
                    // Session gate as first-byte acceptance. A queued request
                    // cannot outlive business completion or the original Drain.
                    session.poll_lifecycle_deadlines().map_err(error)?;
                    session.check().map_err(error)?;
                    let slot = &session.engine.streams.slots[i];
                    if slot.cancel || self.application_read_ended() {
                        return Err(SessionError::Closed);
                    }
                }
                session
                    .write_with_admission_observed(
                        &self.inner.handle,
                        &payload[accepted..accepted + count],
                        fin && accepted + count == payload.len(),
                        admission,
                        transport,
                        handoff
                            .clone()
                            .filter(|_| accepted + count == payload.len()),
                        None,
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
        let _ = self.owner.run_state(|session| {
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
        if self.check_io_mode().is_ok() {
            Some(self.inner.read.clone())
        } else {
            None
        }
    }
    fn read_delivery_owner(&self) -> Option<Arc<crate::api_v4::ReadDeliveryAuthorization>> {
        Some(self.inner.read.delivery_authorization())
    }
    async fn read_cursor_piece(
        &self,
        cursor: &ReaderCursor,
    ) -> std::result::Result<(), SessionError> {
        self.check_io_mode()?;
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
            let progressed = self.inner.owner.run_state(|session| {
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
    fn write_preparation_permit(
        &self,
    ) -> std::result::Result<Option<crate::api_v4::StreamWritePreparationPermit>, SessionError>
    {
        let mode = self.inner.typed.lock().expect("Stream I/O mode");
        if !mode.allows(self) {
            return Err(SessionError::OperationFailed);
        }
        self.inner
            .prepared_writes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| SessionError::ResourceExhausted)?;
        let inner = self.inner.clone();
        Ok(Some(crate::api_v4::StreamWritePreparationPermit::new(
            move || {
                inner.prepared_writes.fetch_sub(1, Ordering::AcqRel);
            },
        )))
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
        let wait = self.inner.owner.wait_charge()?;
        self.close_message_write_prepared(wait).await
    }
    async fn finish(&self) -> std::result::Result<(), SessionError> {
        self.check_io_mode()?;
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
                .run_state(|session| session.check().map_err(error))?;
            notified.await;
        }
    }
    async fn reset(&self) -> std::result::Result<(), SessionError> {
        let mode = self.inner.typed.lock().expect("Stream I/O mode");
        if !mode.allows(self) {
            return Err(SessionError::OperationFailed);
        }
        self.inner.read.revoke_delivery();
        let result = self.inner.owner.run_state(|session| {
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
    use crate::api_v4::{ReaderCursorOptions, StreamExt, TransportEnvironment};
    use crate::crypto_v4::tests::record_pair_for_limits;
    use tokio::sync::mpsc;
    struct LinkPublication {
        scope: u64,
        first_record: Option<mpsc::OwnedPermit<Vec<u8>>>,
    }
    struct Link {
        send: mpsc::Sender<Vec<u8>>,
        closed: bool,
        publication: Arc<Mutex<Option<LinkPublication>>>,
    }
    impl RecordPublisher for Link {
        fn try_claim_data(
            &mut self,
            scope: u64,
            _maximum_record_bytes: usize,
        ) -> Result<crate::crypto_v4::DataPublicationClaim> {
            let mut publication = self.publication.lock().expect("test link publication");
            if self.closed || scope == 0 || publication.is_some() {
                return Err(CryptoError::Capacity);
            }
            let first_record = self
                .send
                .clone()
                .try_reserve_owned()
                .map_err(|_| CryptoError::Capacity)?;
            *publication = Some(LinkPublication {
                scope,
                first_record: Some(first_record),
            });
            let original = self.publication.clone();
            Ok(crate::crypto_v4::DataPublicationClaim::new(move || {
                original.lock().expect("test link publication").take();
            }))
        }
        fn data_publication_permitted(&self, scope: u64) -> bool {
            self.publication
                .lock()
                .expect("test link publication")
                .as_ref()
                .is_none_or(|claim| claim.scope == scope)
        }
        fn publish(&mut self, record: &[u8]) -> Result<()> {
            // Keep the first business record's actual bounded queue position
            // reserved while maintenance uses the other original positions.
            let reserved = if record.len() >= 20 && record[4] == 7 {
                let scope =
                    u64::from_be_bytes(record[12..20].try_into().expect("test record scope"));
                self.publication
                    .lock()
                    .expect("test link publication")
                    .as_mut()
                    .filter(|claim| claim.scope == scope)
                    .and_then(|claim| claim.first_record.take())
            } else {
                None
            };
            if let Some(position) = reserved {
                position.send(record.to_vec());
                Ok(())
            } else {
                self.send
                    .try_send(record.to_vec())
                    .map_err(|_| CryptoError::Capacity)
            }
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
                    publication: Arc::new(Mutex::new(None)),
                }),
            )
            .unwrap();
        let server = environment
            .adopt_ready_session(
                server,
                Box::new(Link {
                    send: s_tx,
                    closed: false,
                    publication: Arc::new(Mutex::new(None)),
                }),
            )
            .unwrap();
        let c = client.clone();
        let s = server.clone();
        let c_task = tokio::spawn(async move {
            while let Some(wire) = c_rx.recv().await {
                if let Err(e) = s.receive(&wire) {
                    panic!("receive failed: {e:?}");
                }
            }
        });
        let s_task = tokio::spawn(async move {
            while let Some(wire) = s_rx.recv().await {
                if let Err(e) = c.receive(&wire) {
                    panic!("receive failed: {e:?}");
                }
            }
        });
        (client, server, c_task, s_task)
    }
    include!("session_v4_publication_tests.rs");
    include!("session_v4_native_prefix_tests.rs");
    include!("resume_service_v4_tests.rs");
    include!("execution_management_public_tests.rs");
    include!("service_async_public_tests.rs");
    include!("typed_message_stream_v4_tests.rs");
    include!("duplex_bridge_v4_tests.rs");
    include!("controller_service_generation_v4_tests.rs");
    include!("notification_delivery_v4_tests.rs");
    #[tokio::test]
    async fn resume_qualification_uses_signed_policy_and_preserves_the_original_raw_target() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let metadata = Metadata::new(
            "example/recovery",
            1,
            &std::collections::BTreeMap::from([("purpose".into(), Bytes::from_static(b"resume"))]),
        )
        .unwrap();
        let (target, accepted) = tokio::join!(
            client.open_stream("recover", metadata.clone(), 65536),
            async { server.next_open().await.unwrap().accept(65536).unwrap() }
        );
        let target = target.unwrap();
        target
            .check_resume_metadata(&client, "recover", &metadata)
            .unwrap();
        assert!(
            target
                .check_resume_metadata(&client, "recover", &Metadata::empty())
                .is_err()
        );
        assert!(target.claim_resume(&server, "recover").is_err());
        let (borrowed, permit, claim) = target.claim_resume(&client, "recover").unwrap();
        assert!(target.read_owner().is_none());
        assert!(target.claim_resume(&client, "recover").is_err());
        let binding = claim.binding().clone();
        assert_eq!(binding, borrowed.resume_target(&client).unwrap());
        drop(permit);
        drop(claim);
        assert!(target.read_owner().is_some());
        assert!(borrowed.check_io_mode().is_err());
        let (_, permit, second) = target.claim_resume(&client, "recover").unwrap();
        assert_eq!(second.binding(), &binding);
        assert!(borrowed.check_io_mode().is_err());
        drop(permit);
        drop(second);
        target.write(Bytes::from_static(b"a")).await.unwrap();
        assert!(target.claim_resume(&client, "recover").is_err());
        assert!(target.claim_typed().is_err());
        drop(accepted);
        client.close();
        server.close();
        c_task.abort();
        s_task.abort();
    }
    #[tokio::test]
    async fn resume_qualification_refuses_an_ordinary_session_without_signed_recovery() {
        let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let (target, accepted) = tokio::join!(
            client.open_stream("recover", Metadata::empty(), 65536),
            async { server.next_open().await.unwrap().accept(65536).unwrap() }
        );
        let target = target.unwrap();
        assert!(target.claim_resume(&client, "recover").is_err());
        assert!(target.read_owner().is_some());
        drop(accepted);
        client.close();
        server.close();
        c_task.abort();
        s_task.abort();
    }
    #[tokio::test]
    async fn a_resume_borrow_refuses_existing_reader_and_uncertain_boundary_resets_only_its_target()
    {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
        let (target, accepted) = tokio::join!(
            client.open_stream("recover", Metadata::empty(), 65536),
            async { server.next_open().await.unwrap().accept(65536).unwrap() }
        );
        let target = target.unwrap();
        let reader = target.read_owner().unwrap().acquire().unwrap();
        assert!(target.claim_resume(&client, "recover").is_err());
        drop(reader);
        let (_, permit, mut claim) = target.claim_resume(&client, "recover").unwrap();
        claim.begin();
        drop(permit);
        drop(claim);
        assert_eq!(target.read_state().0, ReadStreamStatus::Aborted);
        assert!(client.service_identity().is_ok());
        drop(accepted);
        client.close();
        server.close();
        c_task.abort();
        s_task.abort();
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
    async fn terminal_publication_retains_close_cause_during_state_observation() {
        struct TerminalTransport {
            owner: Arc<OnceLock<std::sync::Weak<Owner>>>,
            published: Arc<AtomicBool>,
            closed: bool,
            fail: bool,
        }
        impl RecordPublisher for TerminalTransport {
            fn publish(&mut self, record: &[u8]) -> Result<()> {
                if record[4] == 12 {
                    let owner = self.owner.get().unwrap().upgrade().unwrap();
                    assert_eq!(
                        owner.run_state(|session| session.check().map_err(error)),
                        Err(SessionError::Closed)
                    );
                    let receiver = SessionReceiver {
                        owner: Arc::downgrade(&owner),
                    };
                    receiver.close();
                    // A late maintenance frame must not drop the physical
                    // reader while the terminal record is still publishing.
                    assert!(receiver.receive(record).is_ok());
                    assert!(owner.drive.lock().unwrap().termination.is_none());
                    assert!(!self.closed);
                    self.published.store(true, Ordering::Release);
                    if self.fail {
                        return Err(CryptoError::State);
                    }
                }
                Ok(())
            }
        }
        impl SessionTransport for TerminalTransport {
            fn close(&mut self) {
                assert!(self.published.load(Ordering::Acquire));
                self.closed = true;
            }
            fn cleanup_status(&self) -> CleanupStatus {
                CleanupStatus {
                    complete: self.closed,
                    cleanup_incomplete: false,
                    pending_callbacks: u64::from(!self.closed),
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
        for fail in [false, true] {
            let (fixture, client, _server) = record_pair_for_limits(Profile::X25519);
            let owner = Arc::new(OnceLock::new());
            let published = Arc::new(AtomicBool::new(false));
            let session = fixture
                .environment
                .adopt_ready_session(
                    client,
                    Box::new(TerminalTransport {
                        owner: owner.clone(),
                        published: published.clone(),
                        closed: false,
                        fail,
                    }),
                )
                .unwrap();
            owner.set(Arc::downgrade(&session.owner)).unwrap();
            let drain = session.drain(Duration::from_secs(1)).unwrap();
            assert_eq!(drain.wait().await.unwrap().outcome, DrainOutcome::Drained);
            let terminal = session.wait_termination().await;
            assert_eq!(
                terminal.error,
                if fail {
                    SessionError::OperationFailed
                } else {
                    SessionError::Closed
                }
            );
            assert!(published.load(Ordering::Acquire));
            assert!(session.wait_cleanup().await.complete);
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
                        .run_state(|session| {
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
        let _services = fixture.environment.root().application_services().unwrap();
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
            .run_state(|session| {
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
            .run_state(|session| {
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
            .run_state(|session| {
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
        let write = StreamExt::prepare_write(
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
                        closed: false,
                        publication: Arc::new(Mutex::new(None))
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

/// An original Session's carrier-neutral unreliable channel. It cannot follow
/// a Controller replacement or acquire another authorization.
#[derive(Clone)]
pub struct UnreliableMessages {
    session: Session,
}
impl fmt::Debug for UnreliableMessages {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnreliableMessages { <opaque> }")
    }
}
fn unreliable_error(value: SessionError) -> crate::transport::UnreliableMessageError {
    match value {
        SessionError::Closed => crate::transport::UnreliableMessageError::Closed,
        _ => crate::transport::UnreliableMessageError::OperationFailed,
    }
}
impl Session {
    pub fn unreliable_messages(
        &self,
    ) -> std::result::Result<UnreliableMessages, crate::transport::UnreliableMessageError> {
        let available = self
            .owner
            .run(|session, transport| {
                Ok(session.engine.datagram_available()
                    && transport
                        .datagram_maximum()
                        .is_some_and(|maximum| RecordEngine::datagram_maximum(maximum) > 0))
            })
            .map_err(unreliable_error)?;
        if !available {
            return Err(crate::transport::UnreliableMessageError::Unavailable);
        }
        Ok(UnreliableMessages {
            session: self.clone(),
        })
    }
}
impl UnreliableMessages {
    pub fn info(
        &self,
    ) -> std::result::Result<
        crate::transport::UnreliableMessagesInfo,
        crate::transport::UnreliableMessageError,
    > {
        self.session
            .owner
            .run(|session, transport| {
                Ok(transport
                    .datagram_maximum()
                    .ok_or(crate::transport::UnreliableMessageError::Unavailable)
                    .and_then(|maximum| session.engine.datagram_info(maximum)))
            })
            .map_err(unreliable_error)?
    }
    /// A conservative local submission bound; it is not a peer delivery promise.
    pub fn max_message_bytes(&self) -> usize {
        self.session
            .owner
            .run(|session, transport| {
                Ok(if session.engine.datagram_available() {
                    transport
                        .datagram_maximum()
                        .map(RecordEngine::datagram_maximum)
                        .unwrap_or(0)
                } else {
                    0
                })
            })
            .unwrap_or(0)
    }
    pub async fn send(
        &self,
        payload: &[u8],
        expires_at: std::time::SystemTime,
    ) -> std::result::Result<
        crate::transport::UnreliableSendOutcome,
        crate::transport::UnreliableMessageError,
    > {
        use crate::transport::{
            UnreliableMessageError as Failure, UnreliableSendOutcome as Outcome,
        };
        let expires = u64::try_from(
            expires_at
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Failure::InvalidMessage)?
                .as_millis(),
        )
        .ok()
        .filter(|value| *value > 0)
        .ok_or(Failure::InvalidMessage)?;
        self.session
            .wait_protocol_active()
            .await
            .map_err(unreliable_error)?;
        let owner = &self.session.owner;
        let maximum = owner
            .transport
            .lock()
            .expect("original datagram provider capacity")
            .datagram_maximum()
            .ok_or(Failure::Unavailable)?;
        let prepared = owner
            .run_state(|session| {
                Ok((|| -> std::result::Result<_, Failure> {
                    if session
                        .engine
                        .account
                        .security_time()
                        .map_err(|_| Failure::OperationFailed)?
                        .upper_ms
                        >= expires
                    {
                        return Ok(Err(Outcome::DroppedExpired));
                    }
                    if payload.len() > RecordEngine::datagram_maximum(maximum) {
                        return Err(Failure::TooLarge);
                    }
                    let backing = session
                        .engine
                        .datagram_backing()
                        .ok_or(Failure::Unavailable)?;
                    let Some(original) = backing.send() else {
                        return Ok(Err(Outcome::DroppedBudget));
                    };
                    match session.engine.prepare_datagram(payload, maximum, expires)? {
                        Ok(job) => Ok(Ok((job, original))),
                        Err(outcome) => Ok(Err(outcome)),
                    }
                })())
            })
            .map_err(unreliable_error)??;
        let (mut job, original) = match prepared {
            Ok(value) => value,
            Err(outcome) => return Ok(outcome),
        };
        if let Err(cause) = job.execute() {
            if cause == CryptoError::Deadline
                && job.expired().map_err(|_| Failure::OperationFailed)?
            {
                return Ok(Outcome::DroppedExpired);
            }
            return Err(Failure::OperationFailed);
        }
        let mut transport = owner
            .transport
            .lock()
            .expect("original datagram publication");
        let live = {
            let mut drive = owner.drive.lock().expect("original datagram final commit");
            if let Some(cause) = drive.termination.or(drive.closing) {
                return Err(unreliable_error(cause));
            }
            let session = drive.session.as_mut().ok_or(Failure::Unavailable)?;
            session
                .check()
                .map_err(|cause| unreliable_error(error(cause)))?;
            job.check().map_err(|_| Failure::OperationFailed)?;
            if session
                .engine
                .account
                .security_time()
                .map_err(|_| Failure::OperationFailed)?
                .upper_ms
                >= expires
            {
                Some(Outcome::DroppedExpired)
            } else if session.engine.frozen || session.engine.epoch != job.epoch() {
                Some(Outcome::DroppedBudget)
            } else {
                None
            }
        };
        if let Some(outcome) = live {
            return Ok(outcome);
        }
        Ok(transport.publish_datagram(job.take_wire(), original))
    }
    pub async fn receive(
        &self,
    ) -> std::result::Result<bytes::Bytes, crate::transport::UnreliableMessageError> {
        use crate::transport::UnreliableMessageError as Failure;
        self.session
            .wait_protocol_active()
            .await
            .map_err(unreliable_error)?;
        let backing = self
            .session
            .owner
            .run_state(|session| Ok(session.engine.datagram_backing()))
            .map_err(unreliable_error)?
            .ok_or(Failure::Unavailable)?;
        let _original = backing.receive()?;
        loop {
            let changed = self.session.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let message = self
                .session
                .owner
                .run_state(|session| Ok(session.engine.take_datagram()))
                .map_err(unreliable_error)??;
            if let Some(message) = message {
                return Ok(message);
            }
            changed.await;
        }
    }
}
#[async_trait::async_trait]
impl crate::transport::UnreliableMessageChannel for UnreliableMessages {
    fn max_message_size(&self) -> usize {
        self.max_message_bytes()
    }
    async fn send(
        &self,
        payload: bytes::Bytes,
        expires_at: std::time::SystemTime,
    ) -> std::result::Result<
        crate::transport::UnreliableSendOutcome,
        crate::transport::UnreliableMessageError,
    > {
        UnreliableMessages::send(self, &payload, expires_at).await
    }
    async fn receive(
        &self,
    ) -> std::result::Result<bytes::Bytes, crate::transport::UnreliableMessageError> {
        UnreliableMessages::receive(self).await
    }
}
