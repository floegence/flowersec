//! Strict v3 opaque tunnel relay runtime.
//!
//! The relay validates FSB3 framing, delegates authorization to an
//! application-owned callback, pairs complementary legs, and forwards carrier
//! streams and datagrams. It never receives a Session PSK or parses FSH3.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    hash::Hash,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec_native_transport::PathProfile as NativePathProfile;
use futures_util::future::join_all;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::{
    artifact_v3::{ArtifactV3, CarrierWireV3, decode_tunnel_fsb3},
    raw_quic_v3::RawQuicListenerV3,
    transport_v3::{
        CarrierKind, CarrierSessionV3, CarrierStreamV3, CarrierUnreliableMessageErrorV3,
        carrier_inbound_stream_limit_v3,
    },
    websocket_v3::WebSocketListener,
};

const MAX_ADMISSION_BYTES: usize = 32 * 1024;
const CONTROL_HALF_CLOSE_GRACE: Duration = Duration::from_secs(2);
const DEFAULT_ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_CONCURRENT_ADMISSIONS: usize = 1024;
const FSA3_REJECT: u8 = 1;
const FSA3_RETRY: u8 = 2;
const BUILT_IN_ADMISSION_REASONS: &[&str] = &[
    "authorization_expired",
    "capacity",
    "credential_replay",
    "expired_artifact",
    "invalid_credential",
    "not_authorized",
    "pair_mismatch",
    "pair_timeout",
    "replaced",
    "replacement_denied",
];
const FORBIDDEN_TRANSPORT_SECURITY_REASONS: &[&str] = &[
    "browser_pin_opaque",
    "ca_untrusted",
    "pin_mismatch",
    "pin_tls_unknown",
    "tls_failed",
    "tls_pin_mismatch",
    "tls_policy_expired",
    "tls_untrusted",
    "tls_unsupported",
    "transport_security_failed",
    "transport_security_unsupported",
];

/// Redacted failure returned by an application-owned authorization callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec tunnel authorization failed")]
pub struct TunnelAuthorizationError;

/// Opaque deployment authorization request for one observed FSB3 tunnel leg.
#[derive(Clone)]
pub struct RuntimeAuthorizationRequest {
    encoded: Arc<[u8]>,
    raw_fsb3: Arc<[u8]>,
    binding: [u8; 32],
    lookup_key: Arc<str>,
    carrier: &'static str,
    remote_address: Arc<str>,
    claims: Arc<FsbClaims>,
}

impl fmt::Debug for RuntimeAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeAuthorizationRequest { <opaque> }")
    }
}

impl RuntimeAuthorizationRequest {
    /// Returns the non-secret credential digest used to locate authorization state.
    pub fn lookup_key(&self) -> &str {
        &self.lookup_key
    }

    /// Returns the separately observed carrier identity.
    pub const fn carrier(&self) -> &'static str {
        self.carrier
    }

    /// Returns the separately observed remote socket address.
    pub fn remote_address(&self) -> &str {
        &self.remote_address
    }

    /// Returns a defensive copy suitable for a deployment authorization API.
    pub fn json(&self) -> Vec<u8> {
        self.encoded.to_vec()
    }

    fn verify_artifact(
        &self,
        artifact: &ArtifactV3,
    ) -> Result<VerifiedArtifactClaims, TunnelAuthorizationError> {
        let expected = artifact
            .encode_fsb3(&self.claims.chosen_candidate_id)
            .map_err(|_| TunnelAuthorizationError)?;
        if expected.raw.len() != self.raw_fsb3.len()
            || expected.raw.ct_eq(self.raw_fsb3.as_ref()).unwrap_u8() != 1
        {
            return Err(TunnelAuthorizationError);
        }
        let expires_at_unix_seconds = artifact.expires_at_unix_seconds();
        if expires_at_unix_seconds <= unix_seconds() {
            return Err(TunnelAuthorizationError);
        }
        let expected_peer = artifact
            .tunnel_expected_peer_endpoint_instance_id()
            .ok_or(TunnelAuthorizationError)?
            .to_owned();
        Ok(VerifiedArtifactClaims {
            request_binding: self.binding,
            expected_peer,
            expires_at: UNIX_EPOCH + Duration::from_secs(expires_at_unix_seconds),
        })
    }
}

struct VerifiedArtifactClaims {
    request_binding: [u8; 32],
    expected_peer: String,
    expires_at: SystemTime,
}

#[derive(Clone)]
struct VerifiedGrant {
    request_binding: [u8; 32],
    lease_id: String,
    expected_peer: String,
    expires_at: SystemTime,
    allow_replacement: bool,
}

/// Opaque, secret-free deployment response for one tunnel leg.
#[derive(Clone)]
pub struct TunnelAuthorizationResponse {
    encoded: Arc<[u8]>,
    verified_grant: Option<Arc<VerifiedGrant>>,
}

impl fmt::Debug for TunnelAuthorizationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelAuthorizationResponse { <opaque> }")
    }
}

impl TunnelAuthorizationResponse {
    /// Parses a strict response produced by the deployment authorization service.
    pub fn parse(encoded: impl AsRef<[u8]>) -> Result<Self, TunnelAuthorizationError> {
        let encoded = encoded.as_ref();
        if encoded.is_empty() || encoded.len() > 16 * 1024 {
            return Err(TunnelAuthorizationError);
        }
        let value: Value = serde_json::from_slice(encoded).map_err(|_| TunnelAuthorizationError)?;
        validate_authorization_shape(&value)?;
        Ok(Self {
            encoded: encoded.into(),
            verified_grant: None,
        })
    }

    /// Builds a secret-free allow response after exact application-owned
    /// verification against the stored Artifact.
    pub fn allow(
        request: &RuntimeAuthorizationRequest,
        artifact: &ArtifactV3,
        lease_id: &str,
        allow_replacement: bool,
    ) -> Result<Self, TunnelAuthorizationError> {
        if !valid_id(lease_id, 128) {
            return Err(TunnelAuthorizationError);
        }
        let verified = request.verify_artifact(artifact)?;
        let seconds = verified
            .expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TunnelAuthorizationError)?
            .as_secs();
        if seconds > i64::MAX as u64 {
            return Err(TunnelAuthorizationError);
        }
        let expires_at = time::OffsetDateTime::from_unix_timestamp(seconds as i64)
            .map_err(|_| TunnelAuthorizationError)?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| TunnelAuthorizationError)?;
        let encoded = serde_json::to_vec(&json!({
            "allow_replacement": allow_replacement,
            "credential_id": request.lookup_key(),
            "decision": "allow",
            "expected_peer_endpoint_instance_id": verified.expected_peer,
            "expires_at": expires_at,
            "lease_id": lease_id,
        }))
        .map_err(|_| TunnelAuthorizationError)?;
        validate_authorization_shape(
            &serde_json::from_slice(&encoded).map_err(|_| TunnelAuthorizationError)?,
        )?;
        Ok(Self {
            encoded: encoded.into(),
            verified_grant: Some(Arc::new(VerifiedGrant {
                request_binding: verified.request_binding,
                lease_id: lease_id.into(),
                expected_peer: verified.expected_peer,
                expires_at: verified.expires_at,
                allow_replacement,
            })),
        })
    }

    /// Binds an allow response returned by an external authorization service
    /// to the locally stored Artifact and the exact observed FSB3 request.
    /// Parsed allow responses remain unusable until this verification succeeds.
    pub fn bind_to_artifact(
        mut self,
        request: &RuntimeAuthorizationRequest,
        artifact: &ArtifactV3,
    ) -> Result<Self, TunnelAuthorizationError> {
        let verified = request.verify_artifact(artifact)?;
        let value: Value =
            serde_json::from_slice(&self.encoded).map_err(|_| TunnelAuthorizationError)?;
        validate_authorization_shape(&value)?;
        let object = value.as_object().ok_or(TunnelAuthorizationError)?;
        if object.get("decision").and_then(Value::as_str) != Some("allow")
            || object.get("credential_id").and_then(Value::as_str) != Some(request.lookup_key())
            || object
                .get("expected_peer_endpoint_instance_id")
                .and_then(Value::as_str)
                != Some(verified.expected_peer.as_str())
        {
            return Err(TunnelAuthorizationError);
        }
        let lease_id = object
            .get("lease_id")
            .and_then(Value::as_str)
            .ok_or(TunnelAuthorizationError)?;
        let allow_replacement = object
            .get("allow_replacement")
            .and_then(Value::as_bool)
            .ok_or(TunnelAuthorizationError)?;
        let parsed_expiry = time::OffsetDateTime::parse(
            object
                .get("expires_at")
                .and_then(Value::as_str)
                .ok_or(TunnelAuthorizationError)?,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| TunnelAuthorizationError)?;
        let verified_seconds = verified
            .expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TunnelAuthorizationError)?
            .as_secs();
        if parsed_expiry.unix_timestamp() < 0
            || parsed_expiry.unix_timestamp() as u64 != verified_seconds
        {
            return Err(TunnelAuthorizationError);
        }
        self.verified_grant = Some(Arc::new(VerifiedGrant {
            request_binding: verified.request_binding,
            lease_id: lease_id.into(),
            expected_peer: verified.expected_peer,
            expires_at: verified.expires_at,
            allow_replacement,
        }));
        Ok(self)
    }

    /// Builds a bounded terminal or retryable rejection response.
    pub fn reject(reason: &str, retryable: bool) -> Result<Self, TunnelAuthorizationError> {
        if !valid_reason(reason)
            || forbidden_transport_security_reason(reason)
            || reason == "expired_artifact" && !retryable
        {
            return Err(TunnelAuthorizationError);
        }
        let encoded = serde_json::to_vec(&json!({
            "decision": if retryable { "retry" } else { "reject" },
            "reason": reason,
        }))
        .map_err(|_| TunnelAuthorizationError)?;
        Self::parse(encoded)
    }

    pub fn json(&self) -> Vec<u8> {
        self.encoded.to_vec()
    }
}

/// Application-owned authorization boundary for strict v3 tunnel legs.
#[async_trait]
pub trait TunnelAuthorizer: Send + Sync + 'static {
    /// Implementations must release any application-owned reservation that has
    /// not yet been returned as a lease when cancellation is observed.
    async fn authorize(
        &self,
        request: RuntimeAuthorizationRequest,
        cancellation: CancellationToken,
    ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError>;

    async fn release(&self, _lease_id: &str) {}
}

/// Resource, bind, TLS identity, and origin policy for one opaque relay.
pub struct TunnelRuntimeOptions {
    pub bind_address: SocketAddr,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
    pub allowed_origins: Vec<String>,
    pub admission_reasons: Vec<String>,
    pub max_inbound_streams: u16,
    pub pair_timeout: Duration,
    pub max_pending_legs: usize,
    pub max_active_pairs: usize,
}

impl Clone for TunnelRuntimeOptions {
    fn clone(&self) -> Self {
        Self {
            bind_address: self.bind_address,
            certificate_chain_der: self.certificate_chain_der.clone(),
            private_key_der: self.private_key_der.clone(),
            allowed_origins: self.allowed_origins.clone(),
            admission_reasons: self.admission_reasons.clone(),
            max_inbound_streams: self.max_inbound_streams,
            pair_timeout: self.pair_timeout,
            max_pending_legs: self.max_pending_legs,
            max_active_pairs: self.max_active_pairs,
        }
    }
}

impl fmt::Debug for TunnelRuntimeOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelRuntimeOptions")
            .field("bind_address", &self.bind_address)
            .field("certificate_chain_der", &"[REDACTED]")
            .field("private_key_der", &"[REDACTED]")
            .field("allowed_origins", &"[REDACTED]")
            .field("admission_reasons", &"[REDACTED]")
            .field("max_inbound_streams", &self.max_inbound_streams)
            .field("pair_timeout", &self.pair_timeout)
            .field("max_pending_legs", &self.max_pending_legs)
            .field("max_active_pairs", &self.max_active_pairs)
            .finish()
    }
}

/// Bounds work performed before an authorized leg enters pairing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelAdmissionOptions {
    pub admission_timeout: Duration,
    pub max_concurrent_admissions: usize,
}

impl Default for TunnelAdmissionOptions {
    fn default() -> Self {
        Self {
            admission_timeout: DEFAULT_ADMISSION_TIMEOUT,
            max_concurrent_admissions: DEFAULT_MAX_CONCURRENT_ADMISSIONS,
        }
    }
}

/// Production strict-v3 opaque tunnel relay.
pub struct TunnelRuntime {
    listener: StdMutex<Option<Arc<TunnelListener>>>,
    authorizer: Arc<dyn TunnelAuthorizer>,
    options: TunnelRuntimeOptions,
    admission_options: TunnelAdmissionOptions,
    state: Arc<TunnelState>,
}

impl fmt::Debug for TunnelRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelRuntime { <opaque> }")
    }
}

enum TunnelListener {
    RawQuic(RawQuicListenerV3),
    WebSocket(WebSocketListener),
}

impl TunnelListener {
    fn local_address(&self) -> io::Result<SocketAddr> {
        match self {
            Self::RawQuic(listener) => listener.local_address().map_err(io::Error::other),
            Self::WebSocket(listener) => listener.local_addr(),
        }
    }

    async fn accept(&self) -> Result<AcceptedCarrier, TunnelRuntimeError> {
        match self {
            Self::RawQuic(listener) => listener
                .accept()
                .await
                .map(|(carrier, remote_address)| AcceptedCarrier {
                    carrier,
                    remote_address,
                })
                .map_err(|_| TunnelRuntimeError::Closed),
            Self::WebSocket(listener) => listener
                .accept_with_peer()
                .await
                .map(|(carrier, remote_address)| AcceptedCarrier {
                    carrier,
                    remote_address,
                })
                .map_err(|_| TunnelRuntimeError::Closed),
        }
    }

    fn abort(&self) {
        if let Self::RawQuic(listener) = self {
            listener.abort();
        }
    }
}

struct AcceptedCarrier {
    carrier: Arc<dyn CarrierSessionV3>,
    remote_address: SocketAddr,
}

impl TunnelRuntime {
    pub fn bind_raw_quic(
        options: TunnelRuntimeOptions,
        authorizer: Arc<dyn TunnelAuthorizer>,
    ) -> Result<Self, TunnelRuntimeError> {
        Self::bind_raw_quic_with_admission_options(
            options,
            TunnelAdmissionOptions::default(),
            authorizer,
        )
    }

    pub fn bind_raw_quic_with_admission_options(
        options: TunnelRuntimeOptions,
        admission_options: TunnelAdmissionOptions,
        authorizer: Arc<dyn TunnelAuthorizer>,
    ) -> Result<Self, TunnelRuntimeError> {
        validate_options(&options, admission_options)?;
        let listener = RawQuicListenerV3::bind(
            options.bind_address,
            NativePathProfile::Tunnel,
            options.certificate_chain_der.clone(),
            options.private_key_der.clone(),
            options.max_inbound_streams,
            admission_options.admission_timeout,
        )
        .map_err(|_| TunnelRuntimeError::BindFailed)?;
        Ok(Self::new(
            TunnelListener::RawQuic(listener),
            options,
            admission_options,
            authorizer,
        ))
    }

    pub fn bind_websocket(
        options: TunnelRuntimeOptions,
        authorizer: Arc<dyn TunnelAuthorizer>,
    ) -> Result<Self, TunnelRuntimeError> {
        Self::bind_websocket_with_admission_options(
            options,
            TunnelAdmissionOptions::default(),
            authorizer,
        )
    }

    pub fn bind_websocket_with_admission_options(
        options: TunnelRuntimeOptions,
        admission_options: TunnelAdmissionOptions,
        authorizer: Arc<dyn TunnelAuthorizer>,
    ) -> Result<Self, TunnelRuntimeError> {
        validate_options(&options, admission_options)?;
        let capacity = carrier_inbound_stream_limit_v3(options.max_inbound_streams)
            .map_err(|_| TunnelRuntimeError::InvalidConfiguration)?;
        let listener = WebSocketListener::bind_tunnel(
            options.bind_address,
            options.certificate_chain_der.clone(),
            options.private_key_der.clone(),
            options.allowed_origins.clone(),
            capacity,
        )
        .map_err(|_| TunnelRuntimeError::BindFailed)?;
        Ok(Self::new(
            TunnelListener::WebSocket(listener),
            options,
            admission_options,
            authorizer,
        ))
    }

    fn new(
        listener: TunnelListener,
        options: TunnelRuntimeOptions,
        admission_options: TunnelAdmissionOptions,
        authorizer: Arc<dyn TunnelAuthorizer>,
    ) -> Self {
        Self {
            listener: StdMutex::new(Some(Arc::new(listener))),
            authorizer,
            options,
            admission_options,
            state: Arc::new(TunnelState::new(
                admission_options.max_concurrent_admissions,
            )),
        }
    }

    pub fn local_address(&self) -> Result<SocketAddr, TunnelRuntimeError> {
        self.listener
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .ok_or(TunnelRuntimeError::Closed)?
            .local_address()
            .map_err(|_| TunnelRuntimeError::Closed)
    }

    /// Serves until cancellation or explicit close.
    pub async fn serve(&self, cancellation: CancellationToken) -> Result<(), TunnelRuntimeError> {
        loop {
            let listener = self
                .listener
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .cloned()
                .ok_or(TunnelRuntimeError::Closed)?;
            self.state.active_accepts.fetch_add(1, Ordering::AcqRel);
            let accepted = tokio::select! {
                biased;
                _ = cancellation.cancelled() => None,
                _ = self.state.closed.cancelled() => None,
                result = listener.accept() => Some(result),
            };
            self.state.active_accepts.fetch_sub(1, Ordering::AcqRel);
            self.state.accepts_done.notify_waiters();
            drop(listener);
            let Some(accepted) = accepted else {
                if cancellation.is_cancelled() {
                    self.close().await;
                }
                return Ok(());
            };
            match accepted {
                Ok(accepted) if !self.state.closed.is_cancelled() => {
                    self.dispatch(accepted).await;
                }
                Ok(accepted) => accepted.carrier.abort(),
                Err(_) if self.state.closed.is_cancelled() => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    async fn dispatch(&self, accepted: AcceptedCarrier) {
        let _dispatch_barrier = self.state.dispatch_barrier.lock().await;
        if self.state.closed.is_cancelled() {
            accepted.carrier.abort();
            return;
        }
        let Ok(permit) = self.state.admission_permits.clone().try_acquire_owned() else {
            accepted.carrier.abort();
            return;
        };
        let runtime = TaskRuntime {
            authorizer: self.authorizer.clone(),
            options: self.options.clone(),
            admission_options: self.admission_options,
            state: self.state.clone(),
        };
        spawn_tracked(self.state.clone(), async move {
            runtime.process(accepted, permit).await;
        });
    }

    pub async fn close(&self) {
        let close_gate = self.state.close_gate.lock().await;
        if !self.state.close_started.load(Ordering::Acquire) {
            let dispatch_barrier = self.state.dispatch_barrier.lock().await;
            if !self.state.close_started.swap(true, Ordering::AcqRel) {
                self.state.closed.cancel();
                if let Some(listener) = self
                    .listener
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    listener.abort();
                }
                drop(dispatch_barrier);

                let state = self.state.clone();
                let authorizer = self.authorizer.clone();
                let admission_timeout = self.admission_options.admission_timeout;
                tokio::spawn(async move {
                    let _completion = CloseCompletionGuard {
                        state: state.clone(),
                    };
                    wait_for_zero(&state.active_accepts, &state.accepts_done).await;
                    let pending = state
                        .pending
                        .lock()
                        .await
                        .drain()
                        .map(|(_, entry)| entry.value)
                        .collect::<Vec<_>>();
                    let cleanup_deadline = Instant::now() + admission_timeout;
                    let authorizer = authorizer.as_ref();
                    join_all(pending.into_iter().map(|leg| async move {
                        leg.carrier.abort();
                        release_bounded(authorizer, &leg.lease_id, cleanup_deadline).await;
                    }))
                    .await;
                    let active = state
                        .active_carriers
                        .lock()
                        .await
                        .values()
                        .cloned()
                        .collect::<Vec<_>>();
                    for pair in active {
                        pair.client.abort();
                        pair.server.abort();
                    }
                    wait_for_zero(&state.active_tasks, &state.tasks_done).await;
                });
            } else {
                drop(dispatch_barrier);
            }
        }
        drop(close_gate);

        loop {
            let notified = self.state.close_done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.close_finished.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

fn validate_options(
    options: &TunnelRuntimeOptions,
    admission: TunnelAdmissionOptions,
) -> Result<(), TunnelRuntimeError> {
    let mut admission_reasons = HashSet::new();
    if options.pair_timeout.is_zero()
        || options.max_pending_legs == 0
        || options.max_active_pairs == 0
        || carrier_inbound_stream_limit_v3(options.max_inbound_streams).is_err()
        || admission.admission_timeout < Duration::from_millis(1)
        || admission.max_concurrent_admissions == 0
        || admission.max_concurrent_admissions > Semaphore::MAX_PERMITS
        || options.admission_reasons.iter().any(|reason| {
            !valid_reason(reason)
                || forbidden_transport_security_reason(reason)
                || BUILT_IN_ADMISSION_REASONS.contains(&reason.as_str())
                || !admission_reasons.insert(reason.as_str())
        })
    {
        return Err(TunnelRuntimeError::InvalidConfiguration);
    }
    Ok(())
}

struct TunnelState {
    dispatch_barrier: Mutex<()>,
    close_gate: Mutex<()>,
    close_started: AtomicBool,
    close_finished: AtomicBool,
    close_done: Notify,
    pending: Mutex<HashMap<AuthorityKey, PendingEntry<Leg>>>,
    credentials: Mutex<HashMap<String, SystemTime>>,
    active_pairs: Mutex<usize>,
    active_carriers: Mutex<HashMap<u64, ActivePair>>,
    admission_permits: Arc<Semaphore>,
    next_pending_id: AtomicU64,
    next_pair_id: AtomicU64,
    active_tasks: AtomicUsize,
    tasks_done: Notify,
    active_accepts: AtomicUsize,
    accepts_done: Notify,
    closed: CancellationToken,
}

struct CloseCompletionGuard {
    state: Arc<TunnelState>,
}

impl Drop for CloseCompletionGuard {
    fn drop(&mut self) {
        self.state.close_finished.store(true, Ordering::Release);
        self.state.close_done.notify_waiters();
    }
}

#[derive(Clone)]
struct ActivePair {
    key: AuthorityKey,
    contract_hash: String,
    candidate_set_hash: String,
    client: Arc<dyn CarrierSessionV3>,
    server: Arc<dyn CarrierSessionV3>,
    peer_lease_id: String,
    leg_lease_id: String,
    cleanup_claimed: Arc<AtomicBool>,
}

impl TunnelState {
    fn new(max_concurrent_admissions: usize) -> Self {
        Self {
            dispatch_barrier: Mutex::new(()),
            close_gate: Mutex::new(()),
            close_started: AtomicBool::new(false),
            close_finished: AtomicBool::new(false),
            close_done: Notify::new(),
            pending: Mutex::new(HashMap::new()),
            credentials: Mutex::new(HashMap::new()),
            active_pairs: Mutex::new(0),
            active_carriers: Mutex::new(HashMap::new()),
            admission_permits: Arc::new(Semaphore::new(max_concurrent_admissions)),
            next_pending_id: AtomicU64::new(1),
            next_pair_id: AtomicU64::new(1),
            active_tasks: AtomicUsize::new(0),
            tasks_done: Notify::new(),
            active_accepts: AtomicUsize::new(0),
            accepts_done: Notify::new(),
            closed: CancellationToken::new(),
        }
    }
}

struct TaskRuntime {
    authorizer: Arc<dyn TunnelAuthorizer>,
    options: TunnelRuntimeOptions,
    admission_options: TunnelAdmissionOptions,
    state: Arc<TunnelState>,
}

#[derive(Clone)]
struct Leg {
    carrier: Arc<dyn CarrierSessionV3>,
    admission: Arc<dyn CarrierStreamV3>,
    claims: Arc<FsbClaims>,
    expected_peer: String,
    lease_id: String,
    expires_at: SystemTime,
    allow_replacement: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AuthorityKey {
    profile: String,
    channel: String,
    group: String,
    audience: String,
    contract_hash: String,
    candidate_set_hash: String,
}

struct PendingEntry<T> {
    generation_id: u64,
    value: T,
}

impl TaskRuntime {
    async fn process(self, accepted: AcceptedCarrier, permit: OwnedSemaphorePermit) {
        let carrier = accepted.carrier.clone();
        if self.admit_and_pair(accepted, permit).await.is_err() {
            carrier.abort();
        }
    }

    async fn authorize_bounded(
        &self,
        request: RuntimeAuthorizationRequest,
        deadline: Instant,
    ) -> Result<Result<TunnelAuthorizationResponse, TunnelAuthorizationError>, TunnelRuntimeError>
    {
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let authorizer = self.authorizer.clone();
        let mut task =
            tokio::spawn(async move { authorizer.authorize(request, task_cancellation).await });
        let boundary = tokio::select! {
            biased;
            _ = self.state.closed.cancelled() => Err(TunnelRuntimeError::Closed),
            result = tokio::time::timeout_at(deadline, &mut task) => {
                result.map_err(|_| TunnelRuntimeError::AdmissionFailed)
            }
        };
        match boundary {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Ok(Err(TunnelAuthorizationError)),
            Err(error) => {
                cancellation.cancel();
                let cleanup_deadline = Instant::now() + self.admission_options.admission_timeout;
                match tokio::time::timeout_at(cleanup_deadline, &mut task).await {
                    Ok(Ok(Ok(response))) => {
                        if let Some(lease_id) = response_lease_id(&response) {
                            release_bounded(self.authorizer.as_ref(), lease_id, cleanup_deadline)
                                .await;
                        }
                    }
                    Ok(Ok(Err(_))) | Ok(Err(_)) => {}
                    Err(_) => {
                        task.abort();
                        let _ = task.await;
                    }
                }
                Err(error)
            }
        }
    }

    async fn admit_and_pair(
        &self,
        accepted: AcceptedCarrier,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), TunnelRuntimeError> {
        let admission_deadline = Instant::now() + self.admission_options.admission_timeout;
        let admission = await_bounded(
            admission_deadline,
            &self.state.closed,
            accepted.carrier.accept_stream(),
        )
        .await?
        .map_err(|_| TunnelRuntimeError::AdmissionFailed)?;
        let raw = await_bounded(
            admission_deadline,
            &self.state.closed,
            read_admission(admission.as_ref()),
        )
        .await??;
        let request =
            parse_authorization_request(&raw, accepted.carrier.kind(), accepted.remote_address)?;
        let lookup = request.lookup_key().to_owned();
        let credential_replay = {
            let now = SystemTime::now();
            let mut credentials = self.state.credentials.lock().await;
            credentials.retain(|_, expiry| *expiry > now);
            if credentials.contains_key(&lookup) {
                true
            } else {
                credentials.insert(lookup.clone(), now + self.options.pair_timeout);
                false
            }
        };
        if credential_replay {
            let _ = send_fsa3(
                admission.as_ref(),
                FSA3_REJECT,
                "credential_replay",
                &self.options.admission_reasons,
                admission_deadline,
                &self.state.closed,
            )
            .await;
            return Err(TunnelRuntimeError::Rejected);
        }
        let response = match self
            .authorize_bounded(request.clone(), admission_deadline)
            .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                self.state.credentials.lock().await.remove(&lookup);
                let _ = send_fsa3(
                    admission.as_ref(),
                    FSA3_REJECT,
                    "not_authorized",
                    &self.options.admission_reasons,
                    admission_deadline,
                    &self.state.closed,
                )
                .await;
                return Err(TunnelRuntimeError::Rejected);
            }
            Err(error) => {
                self.state.credentials.lock().await.remove(&lookup);
                return Err(error);
            }
        };
        // The semaphore bounds authorization work only. Pair wait and
        // bridging are tracked by the pending/active registries instead.
        drop(permit);
        let decision = match parse_authorization_decision(
            &response,
            &request,
            &self.options.admission_reasons,
        ) {
            Ok(decision) => decision,
            Err(error) => {
                self.state.credentials.lock().await.remove(&lookup);
                if let Some(lease_id) = response_lease_id(&response) {
                    release_bounded(self.authorizer.as_ref(), lease_id, admission_deadline).await;
                }
                let _ = send_fsa3(
                    admission.as_ref(),
                    FSA3_REJECT,
                    "invalid_credential",
                    &self.options.admission_reasons,
                    admission_deadline,
                    &self.state.closed,
                )
                .await;
                return Err(error);
            }
        };
        let allowed = match decision {
            AuthorizationDecision::Deny { status, reason } => {
                self.state.credentials.lock().await.remove(&lookup);
                // An expired allow is represented as a retryable deny so the
                // caller receives the correct artifact-expiry reason. It
                // still carries the authorizer's lease and must be released
                // before retiring the admission.
                if reason == "expired_artifact" {
                    if let Some(lease_id) = response_lease_id(&response) {
                        release_bounded(self.authorizer.as_ref(), lease_id, admission_deadline)
                            .await;
                    }
                }
                let _ = send_fsa3(
                    admission.as_ref(),
                    status,
                    &reason,
                    &self.options.admission_reasons,
                    admission_deadline,
                    &self.state.closed,
                )
                .await;
                return Err(TunnelRuntimeError::Rejected);
            }
            AuthorizationDecision::Allow(allowed) => allowed,
        };
        self.state
            .credentials
            .lock()
            .await
            .insert(lookup, allowed.expires_at);
        let leg = Leg {
            carrier: accepted.carrier,
            admission,
            claims: request.claims,
            expected_peer: allowed.expected_peer,
            lease_id: allowed.lease_id,
            expires_at: allowed.expires_at,
            allow_replacement: allowed.allow_replacement,
        };
        self.register_leg(leg, admission_deadline).await
    }

    async fn register_leg(
        &self,
        leg: Leg,
        admission_deadline: Instant,
    ) -> Result<(), TunnelRuntimeError> {
        let key = AuthorityKey::from(leg.claims.as_ref());
        if let Some(active) = self.active_pair_for_key(&key).await {
            if active.contract_hash != leg.claims.contract_hash
                || active.candidate_set_hash != leg.claims.candidate_set_hash
            {
                self.reject_leg(&leg, FSA3_REJECT, "pair_mismatch", admission_deadline)
                    .await;
                return Err(TunnelRuntimeError::Rejected);
            }
            if !leg.allow_replacement {
                self.reject_leg(&leg, FSA3_REJECT, "replacement_denied", admission_deadline)
                    .await;
                return Err(TunnelRuntimeError::Rejected);
            }
            self.replace_active_pair(active, admission_deadline).await;
        }
        let generation_id = self.state.next_pending_id.fetch_add(1, Ordering::Relaxed);
        let (peer, pending_capacity, replacement_denied, replaced, incoming_mismatch) = {
            let mut pending = self.state.pending.lock().await;
            if let Some(entry) = pending.get(&key) {
                let pending_leg = &entry.value;
                if !mirrored_claims_match(pending_leg.claims.as_ref(), leg.claims.as_ref())
                    || (pending_leg.claims.role != leg.claims.role
                        && !pair_claims_match(pending_leg, &leg))
                {
                    (None, false, false, None, true)
                } else if pending_leg.claims.role == leg.claims.role {
                    if leg.allow_replacement {
                        let replaced = pending
                            .remove(&key)
                            .expect("pending entry remains under the mutex")
                            .value;
                        pending.insert(
                            key.clone(),
                            PendingEntry {
                                generation_id,
                                value: leg.clone(),
                            },
                        );
                        (None, false, false, Some(replaced), false)
                    } else {
                        (None, false, true, None, false)
                    }
                } else {
                    (
                        Some(
                            pending
                                .remove(&key)
                                .expect("pending peer remains under the mutex")
                                .value,
                        ),
                        false,
                        false,
                        None,
                        false,
                    )
                }
            } else if pending.len() >= self.options.max_pending_legs {
                (None, true, false, None, false)
            } else {
                pending.insert(
                    key.clone(),
                    PendingEntry {
                        generation_id,
                        value: leg.clone(),
                    },
                );
                (None, false, false, None, false)
            }
        };
        if incoming_mismatch {
            self.reject_leg(&leg, FSA3_REJECT, "pair_mismatch", admission_deadline)
                .await;
            return Err(TunnelRuntimeError::Rejected);
        }
        if replacement_denied {
            self.reject_leg(&leg, FSA3_REJECT, "replacement_denied", admission_deadline)
                .await;
            return Err(TunnelRuntimeError::Rejected);
        }
        if let Some(replaced) = replaced {
            let _ = send_fsa3(
                replaced.admission.as_ref(),
                FSA3_REJECT,
                "replaced",
                &self.options.admission_reasons,
                admission_deadline,
                &self.state.closed,
            )
            .await;
            replaced.carrier.abort();
            release_bounded(
                self.authorizer.as_ref(),
                &replaced.lease_id,
                admission_deadline,
            )
            .await;
        }
        if pending_capacity {
            let _ = send_fsa3(
                leg.admission.as_ref(),
                FSA3_RETRY,
                "capacity",
                &self.options.admission_reasons,
                admission_deadline,
                &self.state.closed,
            )
            .await;
            leg.carrier.abort();
            release_bounded(self.authorizer.as_ref(), &leg.lease_id, admission_deadline).await;
            return Err(TunnelRuntimeError::Capacity);
        }
        let Some(peer) = peer else {
            let expiry_deadline = Instant::now()
                + leg
                    .expires_at
                    .duration_since(SystemTime::now())
                    .unwrap_or_default();
            let pair_timeout_deadline = Instant::now() + self.options.pair_timeout;
            // Admission timeout ends credential intake. Once this leg is
            // registered, the independent pair timeout owns the wait for its
            // peer; only artifact expiry can shorten that pairing window.
            let pair_deadline = pair_timeout_deadline.min(expiry_deadline);
            let expiry_first = expiry_deadline <= pair_deadline;
            tokio::select! {
                biased;
                _ = self.state.closed.cancelled() => {}
                _ = tokio::time::sleep_until(pair_deadline) => {}
            }
            let expired = {
                let mut pending = self.state.pending.lock().await;
                remove_pending_generation(&mut pending, &key, generation_id)
            };
            if let Some(expired) = expired {
                let reason = if expiry_first {
                    "expired_artifact"
                } else {
                    "pair_timeout"
                };
                // Pairing may outlive admission intake. Give the terminal
                // response and lease cleanup a fresh bounded window instead
                // of reusing the already elapsed admission deadline.
                let cleanup_deadline = Instant::now() + self.admission_options.admission_timeout;
                let _ = send_fsa3(
                    expired.admission.as_ref(),
                    FSA3_RETRY,
                    reason,
                    &self.options.admission_reasons,
                    cleanup_deadline,
                    &self.state.closed,
                )
                .await;
                expired.carrier.abort();
                release_bounded(
                    self.authorizer.as_ref(),
                    &expired.lease_id,
                    cleanup_deadline,
                )
                .await;
                return Err(TunnelRuntimeError::AdmissionFailed);
            }
            return Ok(());
        };

        if !pair_claims_match(&peer, &leg) {
            self.reject_legs(
                &peer,
                &leg,
                FSA3_REJECT,
                "pair_mismatch",
                admission_deadline,
            )
            .await;
            return Err(TunnelRuntimeError::Rejected);
        }
        if peer.expires_at <= SystemTime::now() || leg.expires_at <= SystemTime::now() {
            self.reject_legs(
                &peer,
                &leg,
                FSA3_RETRY,
                "expired_artifact",
                admission_deadline,
            )
            .await;
            return Err(TunnelRuntimeError::Rejected);
        }
        let active_capacity = {
            let mut active = self.state.active_pairs.lock().await;
            if *active >= self.options.max_active_pairs {
                true
            } else {
                *active += 1;
                false
            }
        };
        if active_capacity {
            self.reject_legs(&peer, &leg, FSA3_RETRY, "capacity", admission_deadline)
                .await;
            return Err(TunnelRuntimeError::Capacity);
        }
        let (client, server) = if peer.claims.role == 1 {
            (peer.carrier.clone(), leg.carrier.clone())
        } else {
            (leg.carrier.clone(), peer.carrier.clone())
        };
        let pair_id = self.state.next_pair_id.fetch_add(1, Ordering::Relaxed);
        let active_pair = ActivePair {
            key: key.clone(),
            contract_hash: peer.claims.contract_hash.clone(),
            candidate_set_hash: peer.claims.candidate_set_hash.clone(),
            client: client.clone(),
            server: server.clone(),
            peer_lease_id: peer.lease_id.clone(),
            leg_lease_id: leg.lease_id.clone(),
            cleanup_claimed: Arc::new(AtomicBool::new(false)),
        };
        self.state
            .active_carriers
            .lock()
            .await
            .insert(pair_id, active_pair.clone());
        if client.kind() == CarrierKind::Wss {
            if client.set_multiplexer_client(false).is_err() {
                self.rollback_active_pair(active_pair.clone(), admission_deadline)
                    .await;
                return Err(TunnelRuntimeError::AdmissionFailed);
            }
            if server.set_multiplexer_client(true).is_err() {
                self.rollback_active_pair(active_pair.clone(), admission_deadline)
                    .await;
                return Err(TunnelRuntimeError::AdmissionFailed);
            }
        }
        if send_fsa3(
            peer.admission.as_ref(),
            0,
            "",
            &self.options.admission_reasons,
            admission_deadline,
            &self.state.closed,
        )
        .await
        .is_err()
        {
            self.rollback_active_pair(active_pair.clone(), admission_deadline)
                .await;
            return Err(TunnelRuntimeError::AdmissionFailed);
        }
        if send_fsa3(
            leg.admission.as_ref(),
            0,
            "",
            &self.options.admission_reasons,
            admission_deadline,
            &self.state.closed,
        )
        .await
        .is_err()
        {
            self.rollback_active_pair(active_pair.clone(), admission_deadline)
                .await;
            return Err(TunnelRuntimeError::AdmissionFailed);
        }
        bridge(
            client.clone(),
            server.clone(),
            self.state.closed.clone(),
            self.admission_options.admission_timeout,
        )
        .await;
        close_carrier_pair_within(client.as_ref(), server.as_ref(), CONTROL_HALF_CLOSE_GRACE).await;
        self.state.active_carriers.lock().await.remove(&pair_id);
        let release_deadline = Instant::now() + CONTROL_HALF_CLOSE_GRACE;
        self.finish_active_pair(active_pair, release_deadline).await;
        Ok(())
    }

    async fn active_pair_for_key(&self, key: &AuthorityKey) -> Option<ActivePair> {
        self.state
            .active_carriers
            .lock()
            .await
            .values()
            .find(|pair| &pair.key == key)
            .cloned()
    }

    async fn replace_active_pair(&self, active: ActivePair, deadline: Instant) {
        {
            let mut carriers = self.state.active_carriers.lock().await;
            carriers.retain(|_, pair| !Arc::ptr_eq(&pair.cleanup_claimed, &active.cleanup_claimed));
        }
        active.client.abort();
        active.server.abort();
        self.finish_active_pair(active, deadline).await;
    }

    async fn finish_active_pair(&self, pair: ActivePair, deadline: Instant) {
        if pair
            .cleanup_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let mut active = self.state.active_pairs.lock().await;
        *active = active.saturating_sub(1);
        drop(active);
        let _ = tokio::join!(
            release_bounded(self.authorizer.as_ref(), &pair.peer_lease_id, deadline),
            release_bounded(self.authorizer.as_ref(), &pair.leg_lease_id, deadline),
        );
    }

    async fn reject_leg(&self, leg: &Leg, status: u8, reason: &str, deadline: Instant) {
        let _ = send_fsa3(
            leg.admission.as_ref(),
            status,
            reason,
            &self.options.admission_reasons,
            deadline,
            &self.state.closed,
        )
        .await;
        leg.carrier.abort();
        release_bounded(self.authorizer.as_ref(), &leg.lease_id, deadline).await;
    }

    async fn reject_legs(
        &self,
        peer: &Leg,
        leg: &Leg,
        status: u8,
        reason: &str,
        deadline: Instant,
    ) {
        let _ = tokio::join!(
            send_fsa3(
                peer.admission.as_ref(),
                status,
                reason,
                &self.options.admission_reasons,
                deadline,
                &self.state.closed,
            ),
            send_fsa3(
                leg.admission.as_ref(),
                status,
                reason,
                &self.options.admission_reasons,
                deadline,
                &self.state.closed,
            ),
        );
        peer.carrier.abort();
        leg.carrier.abort();
        let _ = tokio::join!(
            release_bounded(self.authorizer.as_ref(), &peer.lease_id, deadline),
            release_bounded(self.authorizer.as_ref(), &leg.lease_id, deadline),
        );
    }

    async fn rollback_active_pair(&self, pair: ActivePair, deadline: Instant) {
        pair.client.abort();
        pair.server.abort();
        let _ = tokio::time::timeout_at(deadline, async {
            tokio::join!(pair.client.close(), pair.server.close())
        })
        .await;
        self.state
            .active_carriers
            .lock()
            .await
            .retain(|_, current| !Arc::ptr_eq(&current.cleanup_claimed, &pair.cleanup_claimed));
        self.finish_active_pair(pair, deadline).await;
    }
}

async fn close_carrier_pair_within(
    client: &dyn CarrierSessionV3,
    server: &dyn CarrierSessionV3,
    timeout: Duration,
) {
    if tokio::time::timeout(timeout, async {
        let _ = tokio::join!(client.close(), server.close());
    })
    .await
    .is_err()
    {
        client.abort();
        server.abort();
    }
}

impl From<&FsbClaims> for AuthorityKey {
    fn from(claims: &FsbClaims) -> Self {
        Self {
            profile: claims.profile.clone(),
            channel: claims.channel.clone(),
            group: claims.group.clone(),
            audience: claims.audience.clone(),
            contract_hash: claims.contract_hash.clone(),
            candidate_set_hash: claims.candidate_set_hash.clone(),
        }
    }
}

fn mirrored_claims_match(first: &FsbClaims, second: &FsbClaims) -> bool {
    first.contract_hash == second.contract_hash
        && first.candidate_set_hash == second.candidate_set_hash
}

fn pair_claims_match(peer: &Leg, leg: &Leg) -> bool {
    peer.claims.role != leg.claims.role
        && mirrored_claims_match(peer.claims.as_ref(), leg.claims.as_ref())
        && peer.claims.endpoint == leg.expected_peer
        && leg.claims.endpoint == peer.expected_peer
}

fn remove_pending_generation<K, T>(
    pending: &mut HashMap<K, PendingEntry<T>>,
    key: &K,
    generation_id: u64,
) -> Option<T>
where
    K: Eq + Hash,
{
    if pending.get(key)?.generation_id != generation_id {
        return None;
    }
    pending.remove(key).map(|entry| entry.value)
}

#[derive(Clone, Debug)]
struct FsbClaims {
    profile: String,
    role: u8,
    endpoint: String,
    chosen_candidate_id: String,
    channel: String,
    group: String,
    audience: String,
    contract_hash: String,
    candidate_set_hash: String,
}

fn parse_authorization_request(
    raw: &[u8],
    carrier: CarrierKind,
    remote_address: SocketAddr,
) -> Result<RuntimeAuthorizationRequest, TunnelRuntimeError> {
    let decoded = decode_tunnel_fsb3(raw, carrier_wire(carrier))
        .map_err(|_| TunnelRuntimeError::InvalidWire)?;
    let credential = decoded.attach_token;
    let claims = Arc::new(FsbClaims {
        profile: "flowersec/3".into(),
        role: decoded.role,
        endpoint: decoded.endpoint_instance_id,
        chosen_candidate_id: decoded.chosen_candidate_id,
        channel: decoded.channel_id,
        group: decoded.rendezvous_group_id,
        audience: decoded.listener_audience,
        contract_hash: decoded.session_contract_hash_b64u,
        candidate_set_hash: decoded.candidate_set_hash_b64u,
    });
    let carrier = carrier_name(carrier);
    let remote_address = remote_address.to_string();
    let encoded = serde_json::to_vec(&json!({
        "carrier": carrier,
        "fsb3_base64url": URL_SAFE_NO_PAD.encode(raw),
        "remote_address": remote_address,
    }))
    .map_err(|_| TunnelRuntimeError::InvalidWire)?;
    Ok(RuntimeAuthorizationRequest {
        encoded: encoded.into(),
        raw_fsb3: raw.into(),
        binding: Sha256::digest(
            [b"flowersec-v3-verified-tunnel-request\0".as_slice(), raw].concat(),
        )
        .into(),
        lookup_key: URL_SAFE_NO_PAD
            .encode(Sha256::digest(credential.as_bytes()))
            .into(),
        carrier,
        remote_address: remote_address.into(),
        claims,
    })
}

fn carrier_name(carrier: CarrierKind) -> &'static str {
    match carrier {
        CarrierKind::Wss => "websocket",
        CarrierKind::RawQuic => "raw_quic",
        CarrierKind::WebTransport => "webtransport",
    }
}

fn carrier_wire(carrier: CarrierKind) -> CarrierWireV3 {
    match carrier {
        CarrierKind::Wss => CarrierWireV3::Websocket,
        CarrierKind::RawQuic => CarrierWireV3::RawQuic,
        CarrierKind::WebTransport => CarrierWireV3::Webtransport,
    }
}

enum AuthorizationDecision {
    Allow(AllowedClaims),
    Deny { status: u8, reason: String },
}

struct AllowedClaims {
    lease_id: String,
    expected_peer: String,
    expires_at: SystemTime,
    allow_replacement: bool,
}

fn validate_authorization_shape(value: &Value) -> Result<(), TunnelAuthorizationError> {
    let object = value.as_object().ok_or(TunnelAuthorizationError)?;
    match object.get("decision").and_then(Value::as_str) {
        Some("reject" | "retry")
            if object.len() == 2
                && object
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(valid_reason) =>
        {
            Ok(())
        }
        Some("allow") => {
            let fields = [
                "allow_replacement",
                "credential_id",
                "decision",
                "expected_peer_endpoint_instance_id",
                "expires_at",
                "lease_id",
            ];
            if object.len() != fields.len()
                || object.keys().any(|key| !fields.contains(&key.as_str()))
                || object
                    .get("allow_replacement")
                    .and_then(Value::as_bool)
                    .is_none()
                || !object
                    .get("credential_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| valid_id(value, 64))
                || !object
                    .get("lease_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| valid_id(value, 128))
                || !object
                    .get("expected_peer_endpoint_instance_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| valid_id(value, 128))
                || object.get("expires_at").and_then(Value::as_str).is_none()
            {
                return Err(TunnelAuthorizationError);
            }
            Ok(())
        }
        _ => Err(TunnelAuthorizationError),
    }
}

fn parse_authorization_decision(
    response: &TunnelAuthorizationResponse,
    request: &RuntimeAuthorizationRequest,
    admission_reasons: &[String],
) -> Result<AuthorizationDecision, TunnelRuntimeError> {
    let value: Value =
        serde_json::from_slice(&response.encoded).map_err(|_| TunnelRuntimeError::Rejected)?;
    validate_authorization_shape(&value).map_err(|_| TunnelRuntimeError::Rejected)?;
    let object = value.as_object().expect("validated object");
    match object["decision"].as_str().expect("validated decision") {
        "reject" | "retry" => {
            let reason = object["reason"].as_str().expect("validated reason");
            if !valid_server_reason(reason, admission_reasons)
                || reason == "expired_artifact" && object["decision"] != "retry"
            {
                return Err(TunnelRuntimeError::Rejected);
            }
            Ok(AuthorizationDecision::Deny {
                status: if object["decision"] == "retry" {
                    FSA3_RETRY
                } else {
                    FSA3_REJECT
                },
                reason: reason.into(),
            })
        }
        "allow" => {
            let grant = response
                .verified_grant
                .as_deref()
                .ok_or(TunnelRuntimeError::Rejected)?;
            if object["credential_id"].as_str() != Some(request.lookup_key())
                || grant.request_binding.ct_eq(&request.binding).unwrap_u8() != 1
                || object["lease_id"].as_str() != Some(grant.lease_id.as_str())
                || object["expected_peer_endpoint_instance_id"].as_str()
                    != Some(grant.expected_peer.as_str())
                || object["allow_replacement"].as_bool() != Some(grant.allow_replacement)
            {
                return Err(TunnelRuntimeError::Rejected);
            }
            let parsed = time::OffsetDateTime::parse(
                object["expires_at"].as_str().expect("validated expiry"),
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| TunnelRuntimeError::Rejected)?;
            let seconds = parsed.unix_timestamp();
            let grant_seconds = grant
                .expires_at
                .duration_since(UNIX_EPOCH)
                .map_err(|_| TunnelRuntimeError::Rejected)?
                .as_secs();
            if seconds < 0 || seconds as u64 != grant_seconds {
                return Err(TunnelRuntimeError::Rejected);
            }
            if seconds <= unix_seconds() as i64 {
                return Ok(AuthorizationDecision::Deny {
                    status: FSA3_RETRY,
                    reason: "expired_artifact".into(),
                });
            }
            Ok(AuthorizationDecision::Allow(AllowedClaims {
                lease_id: grant.lease_id.clone(),
                expected_peer: grant.expected_peer.clone(),
                expires_at: grant.expires_at,
                allow_replacement: grant.allow_replacement,
            }))
        }
        _ => Err(TunnelRuntimeError::Rejected),
    }
}

fn response_lease_id(response: &TunnelAuthorizationResponse) -> Option<&str> {
    response
        .verified_grant
        .as_deref()
        .map(|grant| grant.lease_id.as_str())
}

async fn read_admission(stream: &dyn CarrierStreamV3) -> Result<Vec<u8>, TunnelRuntimeError> {
    let mut header = [0_u8; 12];
    read_exact(stream, &mut header).await?;
    if &header[..4] != b"FSB3" || header[4] != 3 || header[5] != 2 || header[6..8] != [0, 0] {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    let length = u32::from_be_bytes(header[8..12].try_into().expect("fixed header")) as usize;
    if length == 0 || length > MAX_ADMISSION_BYTES {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    let mut raw = Vec::with_capacity(12 + length);
    raw.extend_from_slice(&header);
    raw.resize(12 + length, 0);
    read_exact(stream, &mut raw[12..]).await?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).await.map_err(map_io)? != 0 {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    Ok(raw)
}

async fn send_fsa3(
    stream: &dyn CarrierStreamV3,
    status: u8,
    reason: &str,
    admission_reasons: &[String],
    deadline: Instant,
    closed: &CancellationToken,
) -> Result<(), TunnelRuntimeError> {
    if !matches!(status, 0..=2)
        || status == 0 && !reason.is_empty()
        || status == FSA3_REJECT && reason == "expired_artifact"
        || status != 0 && !valid_server_reason(reason, admission_reasons)
    {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    let mut frame = Vec::with_capacity(8 + reason.len());
    frame.extend_from_slice(b"FSA3");
    frame.extend_from_slice(&[3, status]);
    frame.extend_from_slice(&(reason.len() as u16).to_be_bytes());
    frame.extend_from_slice(reason.as_bytes());
    await_bounded(deadline, closed, async {
        write_all(stream, &frame).await?;
        stream.close_write_delivered().await.map_err(map_io)
    })
    .await?
}

async fn release_bounded(authorizer: &dyn TunnelAuthorizer, lease_id: &str, deadline: Instant) {
    let cleanup_deadline = deadline.max(Instant::now() + Duration::from_millis(100));
    let _ = tokio::time::timeout_at(cleanup_deadline, authorizer.release(lease_id)).await;
}

async fn bridge(
    client: Arc<dyn CarrierSessionV3>,
    server: Arc<dyn CarrierSessionV3>,
    runtime_closed: CancellationToken,
    activation_timeout: Duration,
) {
    let activation_deadline = Instant::now() + activation_timeout;
    let control = match tokio::select! {
        _ = runtime_closed.cancelled() => return,
        result = tokio::time::timeout_at(activation_deadline, client.accept_stream()) => result,
    } {
        Ok(Ok(control)) => control,
        Ok(Err(_)) | Err(_) => return,
    };
    let control_peer = match tokio::select! {
        _ = runtime_closed.cancelled() => return,
        result = tokio::time::timeout_at(activation_deadline, server.open_stream()) => result,
    } {
        Ok(Ok(control_peer)) => control_peer,
        Ok(Err(_)) | Err(_) => return,
    };
    let closed = CancellationToken::new();
    let mut control_task = tokio::spawn(bridge_control_pair_with_grace(
        control,
        control_peer,
        closed.clone(),
        CONTROL_HALF_CLOSE_GRACE,
    ));
    let runtime_shutdown = tokio::select! {
        _ = runtime_closed.cancelled() => true,
        _ = closed.cancelled() => false,
        _ = async {
            tokio::join!(
                bridge_stream_direction(client.clone(), server.clone(), closed.clone()),
                bridge_stream_direction(server.clone(), client.clone(), closed.clone()),
                bridge_datagram_direction(client.clone(), server.clone(), closed.clone()),
                bridge_datagram_direction(server, client, closed.clone()),
            );
        } => false,
    };
    if runtime_shutdown {
        closed.cancel();
    } else if !control_task.is_finished() {
        let _ = tokio::time::timeout(CONTROL_HALF_CLOSE_GRACE, &mut control_task).await;
    }
    closed.cancel();
    if !control_task.is_finished() {
        control_task.abort();
        let _ = control_task.await;
    }
}

async fn bridge_control_pair_with_grace(
    first: Arc<dyn CarrierStreamV3>,
    second: Arc<dyn CarrierStreamV3>,
    closed: CancellationToken,
    half_close_grace: Duration,
) {
    let (first_eof_tx, first_eof_rx) = oneshot::channel();
    let (second_eof_tx, second_eof_rx) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(copy_control_stream(
        first.clone(),
        second.clone(),
        first_eof_tx,
    ));
    tasks.spawn(copy_control_stream(second, first, second_eof_tx));
    let graceful_half_close = tokio::select! {
        biased;
        result = first_eof_rx => result.is_ok(),
        result = second_eof_rx => result.is_ok(),
        _ = closed.cancelled() => false,
    };
    if graceful_half_close {
        let completed = tokio::time::timeout(half_close_grace, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        if completed {
            closed.cancel();
            return;
        }
    }
    closed.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn copy_control_stream(
    source: Arc<dyn CarrierStreamV3>,
    target: Arc<dyn CarrierStreamV3>,
    eof: oneshot::Sender<()>,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).await?;
        if count == 0 {
            let _ = eof.send(());
            return target.close_write().await;
        }
        write_all(target.as_ref(), &buffer[..count])
            .await
            .map_err(|_| io::Error::other("tunnel control stream forwarding failed"))?;
    }
}

async fn bridge_stream_direction(
    source: Arc<dyn CarrierSessionV3>,
    target: Arc<dyn CarrierSessionV3>,
    closed: CancellationToken,
) {
    let mut tasks = JoinSet::new();
    loop {
        let inbound = match tokio::select! {
            biased;
            _ = closed.cancelled() => break,
            result = source.accept_stream() => result,
        } {
            Ok(stream) => stream,
            Err(_) => break,
        };
        let Ok(outbound) = target.open_stream().await else {
            let _ = inbound.reset().await;
            break;
        };
        tasks.spawn(async move {
            let _ = tokio::join!(
                copy_stream(inbound.clone(), outbound.clone()),
                copy_stream(outbound, inbound),
            );
        });
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    closed.cancel();
}

async fn bridge_datagram_direction(
    source: Arc<dyn CarrierSessionV3>,
    target: Arc<dyn CarrierSessionV3>,
    closed: CancellationToken,
) {
    let Some(target_maximum) = target.unreliable_message_max_size() else {
        return;
    };
    if source.unreliable_message_max_size().is_none() {
        return;
    }
    loop {
        let payload = tokio::select! {
            biased;
            _ = closed.cancelled() => return,
            result = source.receive_unreliable_message() => match result {
                Ok(payload) => payload,
                Err(_) => { closed.cancel(); return; }
            }
        };
        if payload.len() <= target_maximum {
            match target.send_unreliable_message(payload).await {
                Ok(()) | Err(CarrierUnreliableMessageErrorV3::Dropped) => {}
                Err(CarrierUnreliableMessageErrorV3::TooLarge) => {}
                Err(_) => {
                    closed.cancel();
                    return;
                }
            }
        }
    }
}

async fn copy_stream(
    source: Arc<dyn CarrierStreamV3>,
    target: Arc<dyn CarrierStreamV3>,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).await?;
        if count == 0 {
            return target.close_write().await;
        }
        write_all(target.as_ref(), &buffer[..count])
            .await
            .map_err(|_| io::Error::other("tunnel stream forwarding failed"))?;
    }
}

async fn read_exact(
    stream: &dyn CarrierStreamV3,
    mut output: &mut [u8],
) -> Result<(), TunnelRuntimeError> {
    while !output.is_empty() {
        let count = stream.read(output).await.map_err(map_io)?;
        if count == 0 {
            return Err(TunnelRuntimeError::InvalidWire);
        }
        output = &mut output[count..];
    }
    Ok(())
}

async fn write_all(
    stream: &dyn CarrierStreamV3,
    mut input: &[u8],
) -> Result<(), TunnelRuntimeError> {
    while !input.is_empty() {
        let count = stream.write(input).await.map_err(map_io)?;
        if count == 0 {
            return Err(TunnelRuntimeError::InvalidWire);
        }
        input = &input[count..];
    }
    Ok(())
}

async fn await_bounded<F, T>(
    deadline: Instant,
    closed: &CancellationToken,
    future: F,
) -> Result<T, TunnelRuntimeError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        _ = closed.cancelled() => Err(TunnelRuntimeError::Closed),
        result = tokio::time::timeout_at(deadline, future) => {
            result.map_err(|_| TunnelRuntimeError::AdmissionFailed)
        }
    }
}

fn spawn_tracked<F>(state: Arc<TunnelState>, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    state.active_tasks.fetch_add(1, Ordering::AcqRel);
    tokio::spawn(async move {
        future.await;
        state.active_tasks.fetch_sub(1, Ordering::AcqRel);
        state.tasks_done.notify_waiters();
    });
}

async fn wait_for_zero(counter: &AtomicUsize, notification: &Notify) {
    loop {
        let notified = notification.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if counter.load(Ordering::Acquire) == 0 {
            return;
        }
        notified.await;
    }
}

fn map_io(_: io::Error) -> TunnelRuntimeError {
    TunnelRuntimeError::AdmissionFailed
}

fn valid_reason(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn forbidden_transport_security_reason(value: &str) -> bool {
    FORBIDDEN_TRANSPORT_SECURITY_REASONS.contains(&value)
}

fn valid_server_reason(value: &str, admission_reasons: &[String]) -> bool {
    valid_reason(value)
        && !forbidden_transport_security_reason(value)
        && (BUILT_IN_ADMISSION_REASONS.contains(&value)
            || admission_reasons
                .iter()
                .any(|registered| registered == value))
}

fn valid_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Stable relay lifecycle failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TunnelRuntimeError {
    #[error("invalid tunnel runtime configuration")]
    InvalidConfiguration,
    #[error("tunnel runtime bind failed")]
    BindFailed,
    #[error("tunnel runtime is closed")]
    Closed,
    #[error("tunnel admission failed")]
    AdmissionFailed,
    #[error("tunnel admission rejected")]
    Rejected,
    #[error("tunnel runtime capacity reached")]
    Capacity,
    #[error("tunnel wire is invalid")]
    InvalidWire,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::future::pending;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct AbortProbeCarrier {
        inner: Arc<dyn CarrierSessionV3>,
        aborted: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct ActivationProbeCarrier {
        accepted: Arc<AtomicBool>,
        opened: Arc<AtomicBool>,
        accept_used: AtomicBool,
        open_used: AtomicBool,
        aborted: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct HangingActivationCarrier {
        aborted: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct ControlEofStream;

    #[derive(Debug)]
    struct ControlHangingStream;

    #[derive(Debug)]
    struct DatagramProbeCarrier {
        received: StdMutex<std::collections::VecDeque<Bytes>>,
        sends: AtomicUsize,
        drop_first_send: bool,
        aborted: AtomicBool,
        hang_close: bool,
    }

    impl DatagramProbeCarrier {
        fn source(payloads: impl IntoIterator<Item = Bytes>) -> Self {
            Self {
                received: StdMutex::new(payloads.into_iter().collect()),
                sends: AtomicUsize::new(0),
                drop_first_send: false,
                aborted: AtomicBool::new(false),
                hang_close: false,
            }
        }

        fn dropping_target() -> Self {
            Self {
                received: StdMutex::new(std::collections::VecDeque::new()),
                sends: AtomicUsize::new(0),
                drop_first_send: true,
                aborted: AtomicBool::new(false),
                hang_close: false,
            }
        }

        fn hanging_close() -> Self {
            Self {
                received: StdMutex::new(std::collections::VecDeque::new()),
                sends: AtomicUsize::new(0),
                drop_first_send: false,
                aborted: AtomicBool::new(false),
                hang_close: true,
            }
        }
    }

    #[async_trait]
    impl CarrierStreamV3 for ControlEofStream {
        async fn read(&self, _payload: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }

        async fn write(&self, payload: &[u8]) -> io::Result<usize> {
            Ok(payload.len())
        }

        async fn close_write(&self) -> io::Result<()> {
            Ok(())
        }

        async fn stop_sending(&self) -> io::Result<()> {
            Ok(())
        }

        async fn reset(&self) -> io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl CarrierStreamV3 for ControlHangingStream {
        async fn read(&self, _payload: &mut [u8]) -> io::Result<usize> {
            pending().await
        }

        async fn write(&self, payload: &[u8]) -> io::Result<usize> {
            Ok(payload.len())
        }

        async fn close_write(&self) -> io::Result<()> {
            pending().await
        }

        async fn stop_sending(&self) -> io::Result<()> {
            Ok(())
        }

        async fn reset(&self) -> io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl CarrierSessionV3 for DatagramProbeCarrier {
        fn kind(&self) -> CarrierKind {
            CarrierKind::RawQuic
        }

        fn inbound_bidirectional_stream_capacity(&self) -> u32 {
            8
        }

        async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            pending().await
        }

        async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            pending().await
        }

        fn unreliable_message_max_size(&self) -> Option<usize> {
            Some(1_200)
        }

        async fn send_unreliable_message(
            &self,
            _payload: Bytes,
        ) -> Result<(), CarrierUnreliableMessageErrorV3> {
            let index = self.sends.fetch_add(1, Ordering::SeqCst);
            if self.drop_first_send && index == 0 {
                Err(CarrierUnreliableMessageErrorV3::Dropped)
            } else {
                Ok(())
            }
        }

        async fn receive_unreliable_message(
            &self,
        ) -> Result<Bytes, CarrierUnreliableMessageErrorV3> {
            if let Some(payload) = self.received.lock().unwrap().pop_front() {
                return Ok(payload);
            }
            pending().await
        }

        async fn close(&self) -> io::Result<()> {
            if self.hang_close {
                pending().await
            }
            Ok(())
        }

        fn abort(&self) {
            self.aborted.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CarrierSessionV3 for HangingActivationCarrier {
        fn kind(&self) -> CarrierKind {
            CarrierKind::RawQuic
        }

        fn inbound_bidirectional_stream_capacity(&self) -> u32 {
            8
        }

        async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            pending().await
        }

        async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            pending().await
        }

        async fn close(&self) -> io::Result<()> {
            self.aborted.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn abort(&self) {
            self.aborted.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CarrierSessionV3 for ActivationProbeCarrier {
        fn kind(&self) -> CarrierKind {
            CarrierKind::RawQuic
        }

        fn inbound_bidirectional_stream_capacity(&self) -> u32 {
            8
        }

        async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            if self.open_used.swap(true, Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "probe open complete",
                ));
            }
            self.opened.store(true, Ordering::SeqCst);
            self.accepted.store(true, Ordering::SeqCst);
            Ok(Arc::new(ImmediateWriteStream))
        }

        async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            if self.accept_used.swap(true, Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "probe accept complete",
                ));
            }
            self.accepted.store(true, Ordering::SeqCst);
            Ok(Arc::new(ImmediateWriteStream))
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }

        fn abort(&self) {
            self.aborted.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CarrierSessionV3 for AbortProbeCarrier {
        fn kind(&self) -> CarrierKind {
            self.inner.kind()
        }

        fn inbound_bidirectional_stream_capacity(&self) -> u32 {
            self.inner.inbound_bidirectional_stream_capacity()
        }

        async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            self.inner.open_stream().await
        }

        async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            self.inner.accept_stream().await
        }

        async fn close(&self) -> io::Result<()> {
            self.inner.close().await
        }

        fn abort(&self) {
            self.aborted.store(true, Ordering::SeqCst);
            self.inner.abort();
        }
    }

    #[derive(Debug)]
    struct CursorReadStream {
        bytes: StdMutex<(Vec<u8>, usize)>,
    }

    #[async_trait]
    impl CarrierStreamV3 for CursorReadStream {
        async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
            let mut bytes = self.bytes.lock().unwrap();
            let remaining = bytes.0.len().saturating_sub(bytes.1);
            let count = remaining.min(payload.len());
            payload[..count].copy_from_slice(&bytes.0[bytes.1..bytes.1 + count]);
            bytes.1 += count;
            Ok(count)
        }

        async fn write(&self, payload: &[u8]) -> io::Result<usize> {
            Ok(payload.len())
        }

        async fn close_write(&self) -> io::Result<()> {
            Ok(())
        }

        async fn stop_sending(&self) -> io::Result<()> {
            Ok(())
        }

        async fn reset(&self) -> io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct RecordingAdmissionStream {
        bytes: StdMutex<(Vec<u8>, usize)>,
        writes: Arc<StdMutex<Vec<u8>>>,
    }

    #[async_trait]
    impl CarrierStreamV3 for RecordingAdmissionStream {
        async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
            let mut bytes = self.bytes.lock().unwrap();
            let remaining = bytes.0.len().saturating_sub(bytes.1);
            let count = remaining.min(payload.len());
            payload[..count].copy_from_slice(&bytes.0[bytes.1..bytes.1 + count]);
            bytes.1 += count;
            Ok(count)
        }

        async fn write(&self, payload: &[u8]) -> io::Result<usize> {
            self.writes.lock().unwrap().extend_from_slice(payload);
            Ok(payload.len())
        }

        async fn close_write(&self) -> io::Result<()> {
            Ok(())
        }

        async fn stop_sending(&self) -> io::Result<()> {
            Ok(())
        }

        async fn reset(&self) -> io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AdmissionCarrier {
        inner: Arc<dyn CarrierSessionV3>,
        admission: StdMutex<Option<Arc<dyn CarrierStreamV3>>>,
    }

    #[async_trait]
    impl CarrierSessionV3 for AdmissionCarrier {
        fn kind(&self) -> CarrierKind {
            self.inner.kind()
        }

        fn inbound_bidirectional_stream_capacity(&self) -> u32 {
            self.inner.inbound_bidirectional_stream_capacity()
        }

        async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            self.inner.open_stream().await
        }

        async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
            if let Some(admission) = self.admission.lock().unwrap().take() {
                return Ok(admission);
            }
            self.inner.accept_stream().await
        }

        async fn close(&self) -> io::Result<()> {
            self.inner.close().await
        }

        fn abort(&self) {
            self.inner.abort();
        }
    }

    fn vector_tunnel_artifact(role: u8, endpoint: &str, token: &str) -> ArtifactV3 {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/artifact_vectors.json"
        ))
        .unwrap();
        let vector = vectors["positive"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["id"] == "tunnel-mixed-security")
            .unwrap();
        let mut value: Value = serde_json::from_str(vector["artifact_json"].as_str().unwrap())
            .expect("vector artifact JSON");
        value["path"]["role"] = Value::from(role);
        value["path"]["local_endpoint_instance_id"] = Value::String(endpoint.into());
        value["path"]["expected_peer_endpoint_instance_id"] = Value::String(
            if role == 1 {
                "endpoint-server"
            } else {
                "endpoint-client"
            }
            .into(),
        );
        value["path"]["token"] = Value::String(token.into());
        ArtifactV3::parse(crate::artifact_v3::jcs_value(&value).unwrap()).unwrap()
    }

    fn vector_tunnel_admission(role: u8, endpoint: &str, token: &str) -> Vec<u8> {
        vector_tunnel_artifact(role, endpoint, token)
            .encode_fsb3("q-pin")
            .unwrap()
            .raw
    }

    fn vector_authorization_request() -> RuntimeAuthorizationRequest {
        parse_authorization_request(
            &vector_tunnel_admission(1, "endpoint-client", "attach-token-v3"),
            CarrierKind::RawQuic,
            "127.0.0.1:12345".parse().unwrap(),
        )
        .unwrap()
    }

    fn recompute_vector_session_contract(value: &mut Value) {
        let session = &value["session"];
        let projection = json!({
            "allowed_suites": session["allowed_suites"],
            "channel_id": session["channel_id"],
            "default_suite": session["default_suite"],
            "establish_timeout_seconds": session["establish_timeout_seconds"],
            "idle_timeout_seconds": session["idle_timeout_seconds"],
            "max_inbound_streams": session["max_inbound_streams"],
            "profile": "flowersec/3",
            "rekey_completion_timeout_seconds": session["rekey_completion_timeout_seconds"],
            "rekey_prepare_timeout_seconds": session["rekey_prepare_timeout_seconds"],
            "selected_features": session["selected_features"],
        });
        value["session"]["contract_hash_b64u"] =
            Value::String(URL_SAFE_NO_PAD.encode(crate::artifact_v3::hash_lp(
                crate::artifact_v3::SESSION_CONTRACT_LABEL_V3,
                &crate::artifact_v3::jcs_value(&projection).unwrap(),
            )));
    }

    fn accepted_with_admission(raw: Vec<u8>) -> AcceptedCarrier {
        let (inner, _peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        AcceptedCarrier {
            carrier: Arc::new(AdmissionCarrier {
                inner,
                admission: StdMutex::new(Some(Arc::new(CursorReadStream {
                    bytes: StdMutex::new((raw, 0)),
                }))),
            }),
            remote_address: "127.0.0.1:12345".parse().unwrap(),
        }
    }

    fn accepted_with_recorded_admission(raw: Vec<u8>) -> (AcceptedCarrier, Arc<StdMutex<Vec<u8>>>) {
        let (inner, _peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let writes = Arc::new(StdMutex::new(Vec::new()));
        let stream = RecordingAdmissionStream {
            bytes: StdMutex::new((raw, 0)),
            writes: writes.clone(),
        };
        (
            AcceptedCarrier {
                carrier: Arc::new(AdmissionCarrier {
                    inner,
                    admission: StdMutex::new(Some(Arc::new(stream))),
                }),
                remote_address: "127.0.0.1:12345".parse().unwrap(),
            },
            writes,
        )
    }

    #[derive(Debug)]
    struct NoopAuthorizer;

    #[async_trait]
    impl TunnelAuthorizer for NoopAuthorizer {
        async fn authorize(
            &self,
            _request: RuntimeAuthorizationRequest,
            _cancellation: CancellationToken,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            Err(TunnelAuthorizationError)
        }
    }

    #[derive(Debug, Default)]
    struct CountingAuthorizer {
        releases: AtomicUsize,
    }

    #[async_trait]
    impl TunnelAuthorizer for CountingAuthorizer {
        async fn authorize(
            &self,
            _request: RuntimeAuthorizationRequest,
            _cancellation: CancellationToken,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            Err(TunnelAuthorizationError)
        }

        async fn release(&self, _lease_id: &str) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct HangingReleaseAuthorizer;

    #[async_trait]
    impl TunnelAuthorizer for HangingReleaseAuthorizer {
        async fn authorize(
            &self,
            _request: RuntimeAuthorizationRequest,
            _cancellation: CancellationToken,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            Err(TunnelAuthorizationError)
        }

        async fn release(&self, _lease_id: &str) {
            pending().await
        }
    }

    #[derive(Debug, Default)]
    struct LeaseRecordingAuthorizer {
        artifacts: StdMutex<Vec<ArtifactV3>>,
        releases: StdMutex<Vec<String>>,
    }

    #[async_trait]
    impl TunnelAuthorizer for LeaseRecordingAuthorizer {
        async fn authorize(
            &self,
            request: RuntimeAuthorizationRequest,
            _cancellation: CancellationToken,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            self.artifacts
                .lock()
                .unwrap()
                .iter()
                .find_map(|artifact| {
                    TunnelAuthorizationResponse::allow(&request, artifact, "lease-allow", false)
                        .ok()
                })
                .ok_or(TunnelAuthorizationError)
        }

        async fn release(&self, lease_id: &str) {
            self.releases.lock().unwrap().push(lease_id.to_owned());
        }
    }

    #[derive(Debug, Default)]
    struct LateAllowAuthorizer {
        cancellation_observed: AtomicBool,
        artifacts: StdMutex<Vec<ArtifactV3>>,
        releases: StdMutex<Vec<String>>,
    }

    #[async_trait]
    impl TunnelAuthorizer for LateAllowAuthorizer {
        async fn authorize(
            &self,
            request: RuntimeAuthorizationRequest,
            cancellation: CancellationToken,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            cancellation.cancelled().await;
            self.cancellation_observed.store(true, Ordering::SeqCst);
            self.artifacts
                .lock()
                .unwrap()
                .iter()
                .find_map(|artifact| {
                    TunnelAuthorizationResponse::allow(&request, artifact, "lease-late", false).ok()
                })
                .ok_or(TunnelAuthorizationError)
        }

        async fn release(&self, lease_id: &str) {
            self.releases.lock().unwrap().push(lease_id.to_owned());
        }
    }

    #[derive(Debug, Default)]
    struct MalformedAuthorizer {
        releases: StdMutex<Vec<String>>,
    }

    #[async_trait]
    impl TunnelAuthorizer for MalformedAuthorizer {
        async fn authorize(
            &self,
            request: RuntimeAuthorizationRequest,
            _cancellation: CancellationToken,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            TunnelAuthorizationResponse::parse(
                serde_json::to_vec(&json!({
                    "allow_replacement": false,
                    "credential_id": request.lookup_key(),
                    "decision": "allow",
                    "expected_peer_endpoint_instance_id": "endpoint-server",
                    "expires_at": "not-rfc3339",
                    "lease_id": "lease-malformed",
                }))
                .unwrap(),
            )
        }

        async fn release(&self, lease_id: &str) {
            self.releases.lock().unwrap().push(lease_id.to_owned());
        }
    }

    #[derive(Debug, Default)]
    struct ExpiredAuthorizer {
        releases: StdMutex<Vec<String>>,
    }

    #[async_trait]
    impl TunnelAuthorizer for ExpiredAuthorizer {
        async fn authorize(
            &self,
            request: RuntimeAuthorizationRequest,
            _cancellation: CancellationToken,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            TunnelAuthorizationResponse::parse(
                serde_json::to_vec(&json!({
                    "allow_replacement": false,
                    "credential_id": request.lookup_key(),
                    "decision": "allow",
                    "expected_peer_endpoint_instance_id": "endpoint-server",
                    "expires_at": "2000-01-01T00:00:00Z",
                    "lease_id": "lease-expired",
                }))
                .unwrap(),
            )
        }

        async fn release(&self, lease_id: &str) {
            self.releases.lock().unwrap().push(lease_id.to_owned());
        }
    }

    #[derive(Debug)]
    struct HangingWriteStream;

    #[async_trait]
    impl CarrierStreamV3 for HangingWriteStream {
        async fn read(&self, _payload: &mut [u8]) -> io::Result<usize> {
            pending().await
        }

        async fn write(&self, _payload: &[u8]) -> io::Result<usize> {
            pending().await
        }

        async fn close_write(&self) -> io::Result<()> {
            Ok(())
        }

        async fn stop_sending(&self) -> io::Result<()> {
            Ok(())
        }

        async fn reset(&self) -> io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ImmediateWriteStream;

    #[async_trait]
    impl CarrierStreamV3 for ImmediateWriteStream {
        async fn read(&self, _payload: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }

        async fn write(&self, payload: &[u8]) -> io::Result<usize> {
            Ok(payload.len())
        }

        async fn close_write(&self) -> io::Result<()> {
            Ok(())
        }

        async fn stop_sending(&self) -> io::Result<()> {
            Ok(())
        }

        async fn reset(&self) -> io::Result<()> {
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn test_runtime(
        authorizer: Arc<dyn TunnelAuthorizer>,
        pair_timeout: Duration,
        max_pending_legs: usize,
    ) -> TaskRuntime {
        TaskRuntime {
            authorizer,
            options: TunnelRuntimeOptions {
                bind_address: "127.0.0.1:0".parse().unwrap(),
                certificate_chain_der: Vec::new(),
                private_key_der: Vec::new(),
                allowed_origins: Vec::new(),
                admission_reasons: Vec::new(),
                max_inbound_streams: 8,
                pair_timeout,
                max_pending_legs,
                max_active_pairs: 1,
            },
            admission_options: TunnelAdmissionOptions {
                admission_timeout: Duration::from_secs(1),
                max_concurrent_admissions: 1,
            },
            state: Arc::new(TunnelState::new(1)),
        }
    }

    fn test_leg(
        lease_id: &str,
        role: u8,
        endpoint: &str,
        expected_peer: &str,
        expires_at: SystemTime,
        allow_replacement: bool,
        carrier: Arc<dyn CarrierSessionV3>,
    ) -> Leg {
        test_leg_with_hashes(
            lease_id,
            role,
            endpoint,
            expected_peer,
            expires_at,
            allow_replacement,
            "contract",
            "candidates",
            carrier,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn test_leg_with_hashes(
        lease_id: &str,
        role: u8,
        endpoint: &str,
        expected_peer: &str,
        expires_at: SystemTime,
        allow_replacement: bool,
        contract_hash: &str,
        candidate_set_hash: &str,
        carrier: Arc<dyn CarrierSessionV3>,
    ) -> Leg {
        Leg {
            carrier,
            admission: Arc::new(ImmediateWriteStream),
            claims: Arc::new(FsbClaims {
                profile: "flowersec/3".into(),
                role,
                endpoint: endpoint.into(),
                chosen_candidate_id: "candidate".into(),
                channel: "channel".into(),
                group: "group".into(),
                audience: "audience".into(),
                contract_hash: contract_hash.into(),
                candidate_set_hash: candidate_set_hash.into(),
            }),
            expected_peer: expected_peer.into(),
            lease_id: lease_id.into(),
            expires_at,
            allow_replacement,
        }
    }

    #[tokio::test]
    async fn fsa3_send_is_bounded_by_the_admission_deadline() {
        let closed = CancellationToken::new();
        let result = send_fsa3(
            &HangingWriteStream,
            FSA3_REJECT,
            "pair_mismatch",
            &[],
            Instant::now() + Duration::from_millis(10),
            &closed,
        )
        .await;
        assert!(matches!(result, Err(TunnelRuntimeError::AdmissionFailed)));
    }

    #[tokio::test]
    async fn fsa3_encoder_rejects_terminal_expired_artifact() {
        let closed = CancellationToken::new();
        let result = send_fsa3(
            &ImmediateWriteStream,
            FSA3_REJECT,
            "expired_artifact",
            &[],
            Instant::now() + Duration::from_secs(1),
            &closed,
        )
        .await;
        assert!(matches!(result, Err(TunnelRuntimeError::InvalidWire)));
    }

    #[tokio::test]
    async fn malformed_authorization_cannot_release_an_unverified_lease() {
        let authorizer = Arc::new(MalformedAuthorizer::default());
        let runtime = test_runtime(authorizer.clone(), Duration::from_secs(1), 1);
        let permit = runtime
            .state
            .admission_permits
            .clone()
            .try_acquire_owned()
            .unwrap();
        let (accepted, writes) = accepted_with_recorded_admission(vector_tunnel_admission(
            1,
            "endpoint-client",
            "attach-token-v3",
        ));
        let result = runtime.admit_and_pair(accepted, permit).await;
        assert_eq!(result, Err(TunnelRuntimeError::Rejected));
        let response = crate::artifact_v3::decode_fsa3(&writes.lock().unwrap()).unwrap();
        assert_eq!(
            response.status,
            crate::artifact_v3::AdmissionStatusV3::Reject
        );
        assert_eq!(response.reason, "invalid_credential");

        let retry_permit = runtime
            .state
            .admission_permits
            .clone()
            .try_acquire_owned()
            .unwrap();
        let (retry, retry_writes) = accepted_with_recorded_admission(vector_tunnel_admission(
            1,
            "endpoint-client",
            "attach-token-v3",
        ));
        let retry_result = runtime.admit_and_pair(retry, retry_permit).await;
        assert_eq!(retry_result, Err(TunnelRuntimeError::Rejected));
        let retry_response =
            crate::artifact_v3::decode_fsa3(&retry_writes.lock().unwrap()).unwrap();
        assert_eq!(
            retry_response.status,
            crate::artifact_v3::AdmissionStatusV3::Reject
        );
        assert_eq!(retry_response.reason, "invalid_credential");
        assert!(authorizer.releases.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn parsed_expired_allow_cannot_release_an_unverified_lease() {
        let authorizer = Arc::new(ExpiredAuthorizer::default());
        let runtime = test_runtime(authorizer.clone(), Duration::from_secs(1), 1);
        let permit = runtime
            .state
            .admission_permits
            .clone()
            .try_acquire_owned()
            .unwrap();
        let (accepted, writes) = accepted_with_recorded_admission(vector_tunnel_admission(
            1,
            "endpoint-client",
            "attach-token-v3",
        ));
        let result = runtime.admit_and_pair(accepted, permit).await;
        assert_eq!(result, Err(TunnelRuntimeError::Rejected));
        let response = crate::artifact_v3::decode_fsa3(&writes.lock().unwrap()).unwrap();
        assert_eq!(
            response.status,
            crate::artifact_v3::AdmissionStatusV3::Reject
        );
        assert_eq!(response.reason, "invalid_credential");
        assert!(authorizer.releases.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn authorization_timeout_cancels_and_releases_a_late_allow() {
        let authorizer = Arc::new(LateAllowAuthorizer::default());
        authorizer
            .artifacts
            .lock()
            .unwrap()
            .push(vector_tunnel_artifact(
                1,
                "endpoint-client",
                "attach-token-v3",
            ));
        let mut runtime = test_runtime(authorizer.clone(), Duration::from_secs(1), 1);
        runtime.admission_options.admission_timeout = Duration::from_millis(10);
        let permit = runtime
            .state
            .admission_permits
            .clone()
            .try_acquire_owned()
            .unwrap();
        let accepted = accepted_with_admission(vector_tunnel_admission(
            1,
            "endpoint-client",
            "attach-token-v3",
        ));

        let result = runtime.admit_and_pair(accepted, permit).await;

        assert_eq!(result, Err(TunnelRuntimeError::AdmissionFailed));
        assert!(authorizer.cancellation_observed.load(Ordering::SeqCst));
        assert_eq!(
            authorizer.releases.lock().unwrap().as_slice(),
            ["lease-late"]
        );
        assert_eq!(runtime.state.admission_permits.available_permits(), 1);
        assert!(runtime.state.credentials.lock().await.is_empty());
        assert_eq!(runtime.state.active_tasks.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn admission_permit_is_available_during_pending_pair_wait() {
        let authorizer = Arc::new(LeaseRecordingAuthorizer::default());
        authorizer
            .artifacts
            .lock()
            .unwrap()
            .push(vector_tunnel_artifact(
                1,
                "endpoint-client",
                "attach-token-v3",
            ));
        let runtime = Arc::new(test_runtime(authorizer.clone(), Duration::from_secs(1), 1));
        let permit = runtime
            .state
            .admission_permits
            .clone()
            .try_acquire_owned()
            .unwrap();
        let task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .admit_and_pair(
                        accepted_with_admission(vector_tunnel_admission(
                            1,
                            "endpoint-client",
                            "attach-token-v3",
                        )),
                        permit,
                    )
                    .await
            })
        };
        wait_for_pending(runtime.as_ref()).await;
        assert_eq!(runtime.state.admission_permits.available_permits(), 1);
        runtime.state.closed.cancel();
        let _ = task.await;
        assert_eq!(
            authorizer.releases.lock().unwrap().as_slice(),
            ["lease-allow"]
        );
    }

    #[tokio::test]
    async fn close_barrier_rejects_a_dispatch_that_races_shutdown() {
        let state = Arc::new(TunnelState::new(1));
        let runtime = Arc::new(TunnelRuntime {
            listener: StdMutex::new(None),
            authorizer: Arc::new(NoopAuthorizer),
            options: TunnelRuntimeOptions {
                bind_address: "127.0.0.1:0".parse().unwrap(),
                certificate_chain_der: Vec::new(),
                private_key_der: Vec::new(),
                allowed_origins: Vec::new(),
                admission_reasons: Vec::new(),
                max_inbound_streams: 8,
                pair_timeout: Duration::from_secs(1),
                max_pending_legs: 1,
                max_active_pairs: 1,
            },
            admission_options: TunnelAdmissionOptions::default(),
            state: state.clone(),
        });
        let barrier = state.dispatch_barrier.lock().await;
        let (inner, _peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let aborted = Arc::new(AtomicBool::new(false));
        let accepted = AcceptedCarrier {
            carrier: Arc::new(AbortProbeCarrier {
                inner,
                aborted: aborted.clone(),
            }),
            remote_address: "127.0.0.1:12345".parse().unwrap(),
        };
        let dispatch = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.dispatch(accepted).await })
        };
        tokio::task::yield_now().await;
        let close = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.close().await })
        };
        tokio::task::yield_now().await;
        assert!(!dispatch.is_finished());
        drop(barrier);
        let _ = dispatch.await;
        let _ = close.await;
        assert!(aborted.load(Ordering::SeqCst));
        assert_eq!(state.admission_permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn close_releases_pending_legs_with_one_cleanup_window() {
        let state = Arc::new(TunnelState::new(1));
        let runtime = TunnelRuntime {
            listener: StdMutex::new(None),
            authorizer: Arc::new(HangingReleaseAuthorizer),
            options: TunnelRuntimeOptions {
                bind_address: "127.0.0.1:0".parse().unwrap(),
                certificate_chain_der: Vec::new(),
                private_key_der: Vec::new(),
                allowed_origins: Vec::new(),
                admission_reasons: Vec::new(),
                max_inbound_streams: 8,
                pair_timeout: Duration::from_secs(1),
                max_pending_legs: 4,
                max_active_pairs: 1,
            },
            admission_options: TunnelAdmissionOptions {
                admission_timeout: Duration::from_millis(10),
                max_concurrent_admissions: 1,
            },
            state: state.clone(),
        };
        let mut peer_carriers = Vec::new();
        for index in 0..4 {
            let lease_id = format!("lease-{index}");
            let endpoint = format!("endpoint-{index}");
            let expected_peer = format!("peer-{index}");
            let (carrier, peer_carrier) = crate::session_v3::memory_carrier_pair_v3();
            peer_carriers.push(peer_carrier);
            let leg = test_leg(
                &lease_id,
                1,
                &endpoint,
                &expected_peer,
                SystemTime::now() + Duration::from_secs(30),
                false,
                carrier,
            );
            let key = AuthorityKey::from(leg.claims.as_ref());
            state.pending.lock().await.insert(
                key,
                PendingEntry {
                    generation_id: index,
                    value: leg,
                },
            );
        }

        let started = std::time::Instant::now();
        runtime.close().await;
        assert!(started.elapsed() < Duration::from_millis(300));
        drop(peer_carriers);
    }

    #[tokio::test]
    async fn canceled_close_leaves_owned_cleanup_for_later_close() {
        let state = Arc::new(TunnelState::new(1));
        let runtime = Arc::new(TunnelRuntime {
            listener: StdMutex::new(None),
            authorizer: Arc::new(HangingReleaseAuthorizer),
            options: TunnelRuntimeOptions {
                bind_address: "127.0.0.1:0".parse().unwrap(),
                certificate_chain_der: Vec::new(),
                private_key_der: Vec::new(),
                allowed_origins: Vec::new(),
                admission_reasons: Vec::new(),
                max_inbound_streams: 8,
                pair_timeout: Duration::from_secs(1),
                max_pending_legs: 1,
                max_active_pairs: 1,
            },
            admission_options: TunnelAdmissionOptions {
                admission_timeout: Duration::from_millis(10),
                max_concurrent_admissions: 1,
            },
            state: state.clone(),
        });
        let (carrier, peer_carrier) = crate::session_v3::memory_carrier_pair_v3();
        let leg = test_leg(
            "lease-canceled-close",
            1,
            "endpoint-canceled-close",
            "peer-canceled-close",
            SystemTime::now() + Duration::from_secs(30),
            false,
            carrier,
        );
        state.pending.lock().await.insert(
            AuthorityKey::from(leg.claims.as_ref()),
            PendingEntry {
                generation_id: 1,
                value: leg,
            },
        );

        let first = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.close().await })
        };
        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if state.close_started.load(Ordering::Acquire)
                    && state.pending.lock().await.is_empty()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("close did not take ownership of pending cleanup");
        first.abort();

        tokio::time::timeout(Duration::from_millis(300), runtime.close())
            .await
            .expect("later close did not await owned cleanup");
        assert!(state.close_finished.load(Ordering::Acquire));
        drop(peer_carrier);
    }

    #[tokio::test]
    async fn release_is_bounded_when_authorizer_does_not_return() {
        let started = std::time::Instant::now();
        release_bounded(
            &HangingReleaseAuthorizer,
            "lease",
            Instant::now() + Duration::from_millis(10),
        )
        .await;
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn pending_pair_deadline_respects_authorization_expiry() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let runtime = test_runtime(authorizer.clone(), Duration::from_secs(1), 1);
        let (carrier, _) = crate::session_v3::memory_carrier_pair_v3();
        let started = std::time::Instant::now();
        let result = runtime
            .register_leg(
                test_leg(
                    "expiring-lease",
                    1,
                    "endpoint-first",
                    "endpoint-second",
                    SystemTime::now() + Duration::from_millis(20),
                    false,
                    carrier,
                ),
                Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert!(matches!(result, Err(TunnelRuntimeError::AdmissionFailed)));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pending_pair_wait_is_independent_of_admission_timeout() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let mut runtime = test_runtime(authorizer.clone(), Duration::from_millis(100), 1);
        runtime.admission_options.admission_timeout = Duration::from_millis(10);
        let (carrier, _) = crate::session_v3::memory_carrier_pair_v3();
        let started = std::time::Instant::now();
        let result = runtime
            .register_leg(
                test_leg(
                    "pair-timeout-lease",
                    1,
                    "endpoint-first",
                    "endpoint-second",
                    SystemTime::now() + Duration::from_secs(1),
                    false,
                    carrier,
                ),
                Instant::now() + Duration::from_millis(10),
            )
            .await;
        let elapsed = started.elapsed();
        assert!(matches!(result, Err(TunnelRuntimeError::AdmissionFailed)));
        assert!(elapsed >= Duration::from_millis(70));
        assert!(elapsed < Duration::from_millis(500));
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replacement_retires_the_old_pending_generation() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let runtime = Arc::new(test_runtime(authorizer.clone(), Duration::from_secs(1), 1));
        let key = AuthorityKey {
            profile: "flowersec/3".into(),
            channel: "channel".into(),
            group: "group".into(),
            audience: "audience".into(),
            contract_hash: "contract".into(),
            candidate_set_hash: "candidates".into(),
        };
        let (first_inner, _first_peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let first_aborted = Arc::new(AtomicBool::new(false));
        let first_carrier: Arc<dyn CarrierSessionV3> = Arc::new(AbortProbeCarrier {
            inner: first_inner,
            aborted: first_aborted.clone(),
        });
        let first_runtime = runtime.clone();
        let first_task = tokio::spawn(async move {
            first_runtime
                .register_leg(
                    test_leg(
                        "old-lease",
                        1,
                        "endpoint-first",
                        "endpoint-second",
                        SystemTime::now() + Duration::from_secs(1),
                        false,
                        first_carrier,
                    ),
                    Instant::now() + Duration::from_secs(1),
                )
                .await
        });
        wait_for_pending_key(runtime.as_ref(), &key).await;
        let (second_inner, _second_peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let second_result = runtime
            .register_leg(
                test_leg(
                    "new-lease",
                    1,
                    "endpoint-first",
                    "endpoint-second",
                    SystemTime::now() + Duration::from_millis(30),
                    true,
                    second_inner,
                ),
                Instant::now() + Duration::from_millis(100),
            )
            .await;
        let _ = first_task.await;
        assert!(matches!(
            second_result,
            Err(TunnelRuntimeError::AdmissionFailed)
        ));
        assert!(first_aborted.load(Ordering::SeqCst));
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn opposite_role_hash_mismatch_uses_a_separate_pair_generation() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let runtime = Arc::new(test_runtime(authorizer.clone(), Duration::from_secs(1), 2));
        let (first_inner, _first_peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let first_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(
                        test_leg_with_hashes(
                            "pending-lease",
                            1,
                            "endpoint-first",
                            "endpoint-second",
                            SystemTime::now() + Duration::from_secs(1),
                            false,
                            "contract-a",
                            "candidates-a",
                            first_inner,
                        ),
                        Instant::now() + Duration::from_secs(1),
                    )
                    .await
            })
        };
        let key = AuthorityKey {
            profile: "flowersec/3".into(),
            channel: "channel".into(),
            group: "group".into(),
            audience: "audience".into(),
            contract_hash: "contract-a".into(),
            candidate_set_hash: "candidates-a".into(),
        };
        wait_for_pending_key(runtime.as_ref(), &key).await;
        let (incoming, _) = crate::session_v3::memory_carrier_pair_v3();
        let second_runtime = runtime.clone();
        let second_task = tokio::spawn(async move {
            second_runtime
                .register_leg(
                    test_leg_with_hashes(
                        "incoming-lease",
                        2,
                        "endpoint-second",
                        "endpoint-first",
                        SystemTime::now() + Duration::from_secs(1),
                        false,
                        "contract-a",
                        "candidates-b",
                        incoming,
                    ),
                    Instant::now() + Duration::from_secs(1),
                )
                .await
        });
        wait_for_pending_len(runtime.as_ref(), 2).await;
        let pending = runtime.state.pending.lock().await;
        assert_eq!(pending.len(), 2);
        assert_eq!(pending.get(&key).unwrap().value.lease_id, "pending-lease");
        drop(pending);
        runtime.state.closed.cancel();
        let _ = first_task.await;
        let _ = second_task.await;
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn authority_key_isolates_each_hash_independently() {
        let base = FsbClaims {
            profile: "flowersec/3".into(),
            role: 1,
            endpoint: "endpoint-first".into(),
            chosen_candidate_id: "candidate".into(),
            channel: "channel".into(),
            group: "group".into(),
            audience: "audience".into(),
            contract_hash: "contract-a".into(),
            candidate_set_hash: "candidates-a".into(),
        };
        let mut contract_changed = base.clone();
        contract_changed.contract_hash = "contract-b".into();
        let mut candidates_changed = base.clone();
        candidates_changed.candidate_set_hash = "candidates-b".into();
        assert_ne!(
            AuthorityKey::from(&base),
            AuthorityKey::from(&contract_changed)
        );
        assert_ne!(
            AuthorityKey::from(&base),
            AuthorityKey::from(&candidates_changed)
        );
    }

    async fn wait_for_active_pair(runtime: &TaskRuntime) {
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if !runtime.state.active_carriers.lock().await.is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("active pair was not registered");
    }

    async fn wait_for_pending(runtime: &TaskRuntime) {
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if !runtime.state.pending.lock().await.is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("pending leg was not registered");
    }

    async fn wait_for_pending_key(runtime: &TaskRuntime, key: &AuthorityKey) {
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if runtime.state.pending.lock().await.contains_key(key) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("expected pending leg was not registered");
    }

    async fn wait_for_pending_len(runtime: &TaskRuntime, expected: usize) {
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if runtime.state.pending.lock().await.len() == expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("expected pending leg count was not reached");
    }

    #[tokio::test]
    async fn active_replacement_releases_old_pair_exactly_once() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let runtime = Arc::new(test_runtime(authorizer.clone(), Duration::from_secs(1), 1));
        let (first_inner, _first_peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let first_aborted = Arc::new(AtomicBool::new(false));
        let first_carrier: Arc<dyn CarrierSessionV3> = Arc::new(AbortProbeCarrier {
            inner: first_inner,
            aborted: first_aborted.clone(),
        });
        let first = test_leg(
            "active-client",
            1,
            "endpoint-first",
            "endpoint-second",
            SystemTime::now() + Duration::from_secs(1),
            false,
            first_carrier,
        );
        let (second_inner, _second_peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let second = test_leg(
            "active-server",
            2,
            "endpoint-second",
            "endpoint-first",
            SystemTime::now() + Duration::from_secs(1),
            false,
            second_inner,
        );
        let first_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(first, Instant::now() + Duration::from_secs(1))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(second, Instant::now() + Duration::from_secs(1))
                    .await
            })
        };
        wait_for_active_pair(runtime.as_ref()).await;
        let (replacement, _) = crate::session_v3::memory_carrier_pair_v3();
        let replacement_result = runtime
            .register_leg(
                test_leg(
                    "replacement-lease",
                    1,
                    "endpoint-first",
                    "endpoint-second",
                    SystemTime::now() + Duration::from_millis(20),
                    true,
                    replacement,
                ),
                Instant::now() + Duration::from_millis(100),
            )
            .await;
        assert_eq!(replacement_result, Err(TunnelRuntimeError::AdmissionFailed));
        let _ = first_task.await;
        let _ = second_task.await;
        assert!(first_aborted.load(Ordering::SeqCst));
        assert_eq!(*runtime.state.active_pairs.lock().await, 0);
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn active_replacement_establishes_a_new_pair_before_cleanup() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let runtime = Arc::new(test_runtime(authorizer.clone(), Duration::from_secs(1), 2));
        let old_client_aborted = Arc::new(AtomicBool::new(false));
        let old_server_aborted = Arc::new(AtomicBool::new(false));
        let (old_client, _old_client_guard) = crate::session_v3::memory_carrier_pair_v3();
        let (old_server, _old_server_guard) = crate::session_v3::memory_carrier_pair_v3();
        let old_pair = ActivePair {
            key: AuthorityKey {
                profile: "flowersec/3".into(),
                channel: "channel".into(),
                group: "group".into(),
                audience: "audience".into(),
                contract_hash: "contract".into(),
                candidate_set_hash: "candidates".into(),
            },
            contract_hash: "contract".into(),
            candidate_set_hash: "candidates".into(),
            client: Arc::new(AbortProbeCarrier {
                inner: old_client,
                aborted: old_client_aborted.clone(),
            }),
            server: Arc::new(AbortProbeCarrier {
                inner: old_server,
                aborted: old_server_aborted.clone(),
            }),
            peer_lease_id: "old-client".into(),
            leg_lease_id: "old-server".into(),
            cleanup_claimed: Arc::new(AtomicBool::new(false)),
        };
        *runtime.state.active_pairs.lock().await = 1;
        runtime
            .state
            .active_carriers
            .lock()
            .await
            .insert(1, old_pair);
        let replacement_client_accepted = Arc::new(AtomicBool::new(false));
        let replacement_client_opened = Arc::new(AtomicBool::new(false));
        let replacement_client_aborted = Arc::new(AtomicBool::new(false));
        let replacement_server_accepted = Arc::new(AtomicBool::new(false));
        let replacement_server_opened = Arc::new(AtomicBool::new(false));
        let replacement_server_aborted = Arc::new(AtomicBool::new(false));
        let replacement_client = test_leg(
            "replacement-client",
            1,
            "endpoint-first",
            "endpoint-second",
            SystemTime::now() + Duration::from_secs(1),
            true,
            Arc::new(ActivationProbeCarrier {
                accepted: replacement_client_accepted.clone(),
                opened: replacement_client_opened.clone(),
                accept_used: AtomicBool::new(false),
                open_used: AtomicBool::new(false),
                aborted: replacement_client_aborted.clone(),
            }),
        );
        let replacement_server = test_leg(
            "replacement-server",
            2,
            "endpoint-second",
            "endpoint-first",
            SystemTime::now() + Duration::from_secs(1),
            false,
            Arc::new(ActivationProbeCarrier {
                accepted: replacement_server_accepted.clone(),
                opened: replacement_server_opened.clone(),
                accept_used: AtomicBool::new(false),
                open_used: AtomicBool::new(false),
                aborted: replacement_server_aborted.clone(),
            }),
        );
        let replacement_client_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(replacement_client, Instant::now() + Duration::from_secs(1))
                    .await
            })
        };
        tokio::task::yield_now().await;
        let replacement_server_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(replacement_server, Instant::now() + Duration::from_secs(1))
                    .await
            })
        };
        assert_eq!(replacement_client_task.await.unwrap(), Ok(()));
        assert_eq!(replacement_server_task.await.unwrap(), Ok(()));
        assert!(replacement_client_accepted.load(Ordering::SeqCst));
        assert!(replacement_server_opened.load(Ordering::SeqCst));
        assert!(!replacement_client_aborted.load(Ordering::SeqCst));
        assert!(!replacement_server_aborted.load(Ordering::SeqCst));
        assert!(old_client_aborted.load(Ordering::SeqCst));
        assert!(old_server_aborted.load(Ordering::SeqCst));
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn silent_control_activation_releases_quota_and_allows_a_later_pair() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let mut configured = test_runtime(authorizer.clone(), Duration::from_millis(100), 2);
        configured.admission_options.admission_timeout = Duration::from_millis(20);
        let runtime = Arc::new(configured);
        let first_aborted = Arc::new(AtomicBool::new(false));
        let second_aborted = Arc::new(AtomicBool::new(false));
        let first = test_leg(
            "silent-client",
            1,
            "endpoint-first",
            "endpoint-second",
            SystemTime::now() + Duration::from_secs(1),
            false,
            Arc::new(HangingActivationCarrier {
                aborted: first_aborted.clone(),
            }),
        );
        let second = test_leg(
            "silent-server",
            2,
            "endpoint-second",
            "endpoint-first",
            SystemTime::now() + Duration::from_secs(1),
            false,
            Arc::new(HangingActivationCarrier {
                aborted: second_aborted.clone(),
            }),
        );
        let first_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(first, Instant::now() + Duration::from_secs(1))
                    .await
            })
        };
        tokio::task::yield_now().await;
        let second_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(second, Instant::now() + Duration::from_secs(1))
                    .await
            })
        };
        tokio::time::timeout(Duration::from_millis(500), async {
            let _ = first_task.await;
            let _ = second_task.await;
        })
        .await
        .expect("silent admitted pair retained active quota");
        assert_eq!(*runtime.state.active_pairs.lock().await, 0);
        assert!(runtime.state.active_carriers.lock().await.is_empty());
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 2);

        let accepted = Arc::new(AtomicBool::new(false));
        let opened = Arc::new(AtomicBool::new(false));
        let retry_client = test_leg(
            "retry-client",
            1,
            "endpoint-first",
            "endpoint-second",
            SystemTime::now() + Duration::from_secs(1),
            false,
            Arc::new(ActivationProbeCarrier {
                accepted: accepted.clone(),
                opened: Arc::new(AtomicBool::new(false)),
                accept_used: AtomicBool::new(false),
                open_used: AtomicBool::new(false),
                aborted: Arc::new(AtomicBool::new(false)),
            }),
        );
        let retry_server = test_leg(
            "retry-server",
            2,
            "endpoint-second",
            "endpoint-first",
            SystemTime::now() + Duration::from_secs(1),
            false,
            Arc::new(ActivationProbeCarrier {
                accepted: Arc::new(AtomicBool::new(false)),
                opened: opened.clone(),
                accept_used: AtomicBool::new(false),
                open_used: AtomicBool::new(false),
                aborted: Arc::new(AtomicBool::new(false)),
            }),
        );
        let retry_first = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(retry_client, Instant::now() + Duration::from_secs(1))
                    .await
            })
        };
        tokio::task::yield_now().await;
        let retry_second = runtime
            .register_leg(retry_server, Instant::now() + Duration::from_secs(1))
            .await;
        assert!(retry_second.is_ok());
        assert!(retry_first.await.unwrap().is_ok());
        assert!(accepted.load(Ordering::SeqCst));
        assert!(opened.load(Ordering::SeqCst));
        assert!(first_aborted.load(Ordering::SeqCst));
        assert!(second_aborted.load(Ordering::SeqCst));
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn active_replacement_denial_preserves_the_existing_pair() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let runtime = Arc::new(test_runtime(authorizer.clone(), Duration::from_secs(1), 1));
        let (first, _first_peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let (second, _second_peer_guard) = crate::session_v3::memory_carrier_pair_v3();
        let first_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(
                        test_leg(
                            "active-client",
                            1,
                            "endpoint-first",
                            "endpoint-second",
                            SystemTime::now() + Duration::from_secs(1),
                            false,
                            first,
                        ),
                        Instant::now() + Duration::from_secs(1),
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second_task = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .register_leg(
                        test_leg(
                            "active-server",
                            2,
                            "endpoint-second",
                            "endpoint-first",
                            SystemTime::now() + Duration::from_secs(1),
                            false,
                            second,
                        ),
                        Instant::now() + Duration::from_secs(1),
                    )
                    .await
            })
        };
        wait_for_active_pair(runtime.as_ref()).await;
        let (incoming, _) = crate::session_v3::memory_carrier_pair_v3();
        let result = runtime
            .register_leg(
                test_leg(
                    "denied-lease",
                    1,
                    "endpoint-first",
                    "endpoint-second",
                    SystemTime::now() + Duration::from_secs(1),
                    false,
                    incoming,
                ),
                Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert_eq!(result, Err(TunnelRuntimeError::Rejected));
        assert_eq!(runtime.state.active_carriers.lock().await.len(), 1);
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 1);
        runtime.state.closed.cancel();
        for pair in runtime.state.active_carriers.lock().await.values() {
            pair.client.abort();
            pair.server.abort();
        }
        let _ = first_task.await;
        let _ = second_task.await;
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn built_in_authorizer_denials_use_the_runtime_registry() {
        let request = vector_authorization_request();
        let response = TunnelAuthorizationResponse::reject("capacity", true).unwrap();
        assert!(matches!(
            parse_authorization_decision(&response, &request, &[]),
            Ok(AuthorizationDecision::Deny {
                status: FSA3_RETRY,
                reason
            }) if reason == "capacity"
        ));
        assert!(TunnelAuthorizationResponse::reject("expired_artifact", false).is_err());
        assert!(TunnelAuthorizationResponse::reject("expired_artifact", true).is_ok());
        let terminal_expiry = TunnelAuthorizationResponse::parse(
            br#"{"decision":"reject","reason":"expired_artifact"}"#,
        )
        .unwrap();
        assert!(matches!(
            parse_authorization_decision(&terminal_expiry, &request, &[]),
            Err(TunnelRuntimeError::Rejected)
        ));
    }

    #[test]
    fn parsed_allow_cannot_mint_a_verified_grant() {
        let request = vector_authorization_request();
        let response = serde_json::to_vec(&json!({
            "allow_replacement": false,
            "credential_id": request.lookup_key(),
            "decision": "allow",
            "expected_peer_endpoint_instance_id": "endpoint-server",
            "expires_at": "2033-05-18T03:33:20Z",
            "lease_id": "lease-forged",
        }))
        .unwrap();
        let response = TunnelAuthorizationResponse::parse(response).unwrap();
        assert!(matches!(
            parse_authorization_decision(&response, &request, &[]),
            Err(TunnelRuntimeError::Rejected)
        ));
    }

    #[test]
    fn verified_grant_binds_the_complete_observed_fsb3_to_the_artifact() {
        let artifact = vector_tunnel_artifact(1, "endpoint-client", "attach-token-v3");
        let raw = artifact.encode_fsb3("q-pin").unwrap().raw;
        let request = parse_authorization_request(
            &raw,
            CarrierKind::RawQuic,
            "127.0.0.1:12345".parse().unwrap(),
        )
        .unwrap();
        let response =
            TunnelAuthorizationResponse::allow(&request, &artifact, "lease-verified", false)
                .unwrap();
        assert!(matches!(
            parse_authorization_decision(&response, &request, &[]),
            Ok(AuthorizationDecision::Allow(AllowedClaims {
                lease_id,
                expected_peer,
                ..
            })) if lease_id == "lease-verified" && expected_peer == "endpoint-server"
        ));

        let encoded = response.json();
        let rebound = TunnelAuthorizationResponse::parse(encoded)
            .unwrap()
            .bind_to_artifact(&request, &artifact)
            .unwrap();
        assert!(matches!(
            parse_authorization_decision(&rebound, &request, &[]),
            Ok(AuthorizationDecision::Allow(_))
        ));

        let base: Value = serde_json::from_slice(&artifact.encode()).unwrap();
        let mut mutations = Vec::new();

        let mut candidate = base.clone();
        candidate["path"]["candidates"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|item| item["id"] == "q-pin")
            .unwrap()["url"] = Value::String("quic://[2001:db8::2]".into());
        mutations.push(("candidate", candidate));

        let mut session = base.clone();
        session["session"]["idle_timeout_seconds"] = Value::from(61);
        recompute_vector_session_contract(&mut session);
        mutations.push(("session", session));

        let mut tls = base.clone();
        tls["path"]["candidates"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|item| item["id"] == "q-pin")
            .unwrap()["tls"]["pins"][0]["value_b64u"] =
            Value::String(URL_SAFE_NO_PAD.encode([0x42_u8; 32]));
        mutations.push(("TLS", tls));

        let mut role = base.clone();
        role["path"]["role"] = Value::from(2);
        mutations.push(("role", role));

        let mut endpoint = base.clone();
        endpoint["path"]["local_endpoint_instance_id"] = Value::String("endpoint-other".into());
        mutations.push(("endpoint", endpoint));

        for (name, value) in mutations {
            let mismatched =
                ArtifactV3::parse(crate::artifact_v3::jcs_value(&value).unwrap()).unwrap();
            assert!(
                TunnelAuthorizationResponse::allow(&request, &mismatched, "lease-mismatch", false,)
                    .is_err(),
                "same-token {name} mutation minted a grant"
            );
            let mismatched_request = parse_authorization_request(
                &mismatched.encode_fsb3("q-pin").unwrap().raw,
                CarrierKind::RawQuic,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .unwrap();
            assert!(
                matches!(
                    parse_authorization_decision(&response, &mismatched_request, &[]),
                    Err(TunnelRuntimeError::Rejected)
                ),
                "grant was reusable for same-token {name} mutation"
            );
        }
    }

    #[test]
    fn verified_grant_rejects_an_expired_artifact() {
        let artifact = vector_tunnel_artifact(1, "endpoint-client", "attach-token-v3");
        let raw = artifact.encode_fsb3("q-pin").unwrap().raw;
        let request = parse_authorization_request(
            &raw,
            CarrierKind::RawQuic,
            "127.0.0.1:12345".parse().unwrap(),
        )
        .unwrap();
        let mut value: Value = serde_json::from_slice(&artifact.encode()).unwrap();
        value["session"]["init_expire_at_unix_s"] = Value::from(1);
        let expired = ArtifactV3::parse(crate::artifact_v3::jcs_value(&value).unwrap()).unwrap();
        assert!(
            TunnelAuthorizationResponse::allow(
                &request,
                &expired,
                "lease-expired-artifact",
                false,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn rejecting_a_pair_aborts_both_carriers() {
        let runtime = TaskRuntime {
            authorizer: Arc::new(NoopAuthorizer),
            options: TunnelRuntimeOptions {
                bind_address: "127.0.0.1:0".parse().unwrap(),
                certificate_chain_der: Vec::new(),
                private_key_der: Vec::new(),
                allowed_origins: Vec::new(),
                admission_reasons: Vec::new(),
                max_inbound_streams: 8,
                pair_timeout: Duration::from_secs(1),
                max_pending_legs: 1,
                max_active_pairs: 1,
            },
            admission_options: TunnelAdmissionOptions {
                admission_timeout: Duration::from_secs(1),
                max_concurrent_admissions: 1,
            },
            state: Arc::new(TunnelState::new(1)),
        };
        let make_leg = |lease_id: &str,
                        endpoint: &str,
                        expected_peer: &str,
                        carrier: Arc<dyn CarrierSessionV3>,
                        admission: Arc<dyn CarrierStreamV3>| {
            Leg {
                carrier,
                admission,
                claims: Arc::new(FsbClaims {
                    profile: "flowersec/3".into(),
                    role: 1,
                    endpoint: endpoint.into(),
                    chosen_candidate_id: "candidate".into(),
                    channel: "channel".into(),
                    group: "group".into(),
                    audience: "audience".into(),
                    contract_hash: "contract".into(),
                    candidate_set_hash: "candidates".into(),
                }),
                expected_peer: expected_peer.into(),
                lease_id: lease_id.into(),
                expires_at: SystemTime::now() + Duration::from_secs(1),
                allow_replacement: false,
            }
        };
        let (first_inner, _) = crate::session_v3::memory_carrier_pair_v3();
        let (second_inner, _) = crate::session_v3::memory_carrier_pair_v3();
        let first_aborted = Arc::new(AtomicBool::new(false));
        let second_aborted = Arc::new(AtomicBool::new(false));
        let first_carrier = Arc::new(AbortProbeCarrier {
            inner: first_inner.clone(),
            aborted: first_aborted.clone(),
        });
        let second_carrier = Arc::new(AbortProbeCarrier {
            inner: second_inner.clone(),
            aborted: second_aborted.clone(),
        });
        let first = make_leg(
            "lease-first",
            "endpoint-first",
            "endpoint-second",
            first_carrier,
            Arc::new(ImmediateWriteStream),
        );
        let second = make_leg(
            "lease-second",
            "endpoint-second",
            "endpoint-first",
            second_carrier,
            Arc::new(ImmediateWriteStream),
        );
        runtime
            .reject_legs(
                &first,
                &second,
                FSA3_REJECT,
                "pair_mismatch",
                Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert!(first_aborted.load(Ordering::SeqCst));
        assert!(second_aborted.load(Ordering::SeqCst));
    }

    #[test]
    fn fsa3_reasons_require_a_lowercase_lead_and_exclude_tls_failures() {
        assert!(TunnelAuthorizationResponse::reject("policy_denied", false).is_ok());
        assert!(TunnelAuthorizationResponse::reject("1policy_denied", false).is_err());
        assert!(TunnelAuthorizationResponse::reject("_policy_denied", false).is_err());
        assert!(TunnelAuthorizationResponse::reject("tls_pin_mismatch", false).is_err());
        assert!(valid_server_reason("capacity", &[]));
        assert!(valid_server_reason(
            "policy_denied",
            &["policy_denied".into()]
        ));
        assert!(!valid_server_reason("policy_denied", &[]));
        assert!(!valid_server_reason(
            "transport_security_failed",
            &["transport_security_failed".into()]
        ));
    }

    #[test]
    fn authorizer_denials_require_the_runtime_owned_registry() {
        let request = vector_authorization_request();
        let response = TunnelAuthorizationResponse::reject("policy_denied", true).unwrap();
        assert!(matches!(
            parse_authorization_decision(&response, &request, &[]),
            Err(TunnelRuntimeError::Rejected)
        ));
        assert!(matches!(
            parse_authorization_decision(
                &response,
                &request,
                &["policy_denied".into()]
            ),
            Ok(AuthorizationDecision::Deny {
                status: FSA3_RETRY,
                reason
            }) if reason == "policy_denied"
        ));
    }

    #[test]
    fn runtime_configuration_rejects_duplicate_builtin_and_tls_reasons() {
        let options = |admission_reasons| TunnelRuntimeOptions {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            certificate_chain_der: Vec::new(),
            private_key_der: Vec::new(),
            allowed_origins: Vec::new(),
            admission_reasons,
            max_inbound_streams: 1,
            pair_timeout: Duration::from_secs(1),
            max_pending_legs: 1,
            max_active_pairs: 1,
        };
        assert!(
            validate_options(&options(vec!["policy_denied".into()]), Default::default()).is_ok()
        );
        for invalid in [
            vec!["policy_denied".into(), "policy_denied".into()],
            vec!["capacity".into()],
            vec!["tls_untrusted".into()],
        ] {
            assert_eq!(
                validate_options(&options(invalid), Default::default()),
                Err(TunnelRuntimeError::InvalidConfiguration)
            );
        }
    }

    #[test]
    fn runtime_options_debug_redacts_tls_origins_and_admission_reasons() {
        let options = TunnelRuntimeOptions {
            bind_address: "127.0.0.1:43211".parse().unwrap(),
            certificate_chain_der: vec![b"certificate-sentinel".to_vec()],
            private_key_der: b"private-key-sentinel".to_vec(),
            allowed_origins: vec!["https://origin-sentinel.example".into()],
            admission_reasons: vec!["reason_sentinel".into()],
            max_inbound_streams: 9,
            pair_timeout: Duration::from_secs(13),
            max_pending_legs: 17,
            max_active_pairs: 19,
        };
        let debug = format!("{options:?}");
        for secret in [
            "certificate-sentinel",
            "private-key-sentinel",
            "origin-sentinel",
            "reason_sentinel",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("127.0.0.1:43211"));
        assert!(debug.contains("max_inbound_streams: 9"));
        assert!(debug.contains("pair_timeout: 13s"));
        assert!(debug.contains("max_pending_legs: 17"));
        assert!(debug.contains("max_active_pairs: 19"));
    }

    #[tokio::test]
    async fn control_half_close_grace_starts_before_fin_delivery_completes() {
        tokio::time::timeout(
            Duration::from_millis(100),
            bridge_control_pair_with_grace(
                Arc::new(ControlEofStream),
                Arc::new(ControlHangingStream),
                CancellationToken::new(),
                Duration::from_millis(10),
            ),
        )
        .await
        .expect("control pair retained a stuck FIN past the half-close grace");
    }

    #[tokio::test]
    async fn completed_control_copies_are_joined_exactly_once() {
        tokio::time::timeout(
            Duration::from_millis(100),
            bridge_control_pair_with_grace(
                Arc::new(ControlEofStream),
                Arc::new(ControlEofStream),
                CancellationToken::new(),
                Duration::from_millis(10),
            ),
        )
        .await
        .expect("completed control copies were not reaped");
    }

    #[tokio::test]
    async fn dropped_datagram_does_not_cancel_the_reliable_pair() {
        let source = Arc::new(DatagramProbeCarrier::source([
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
        ]));
        let target = Arc::new(DatagramProbeCarrier::dropping_target());
        let closed = CancellationToken::new();
        let forwarding = tokio::spawn(bridge_datagram_direction(
            source,
            target.clone(),
            closed.clone(),
        ));
        tokio::time::timeout(Duration::from_millis(100), async {
            while target.sends.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("forwarding stopped after a lossy datagram drop");
        assert!(!closed.is_cancelled());
        closed.cancel();
        forwarding.await.unwrap();
    }

    #[tokio::test]
    async fn carrier_close_timeout_aborts_both_sides() {
        let first = DatagramProbeCarrier::hanging_close();
        let second = DatagramProbeCarrier::hanging_close();
        close_carrier_pair_within(&first, &second, Duration::from_millis(10)).await;
        assert!(first.aborted.load(Ordering::SeqCst));
        assert!(second.aborted.load(Ordering::SeqCst));
    }
}
