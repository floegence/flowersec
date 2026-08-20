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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::{
    artifact_v3::{CarrierWireV3, decode_tunnel_fsb3},
    raw_quic_v3::RawQuicListenerV3,
    transport_v3::{
        CarrierKind, CarrierSessionV3, CarrierStreamV3, carrier_inbound_stream_limit_v3,
    },
    websocket_v2::WebSocketListener,
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
}

/// Opaque, secret-free deployment response for one tunnel leg.
#[derive(Clone)]
pub struct TunnelAuthorizationResponse {
    encoded: Arc<[u8]>,
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
        })
    }

    /// Builds a secret-free allow response after application-owned verification.
    pub fn allow(
        request: &RuntimeAuthorizationRequest,
        lease_id: &str,
        expires_at: SystemTime,
        expected_peer_endpoint_instance_id: &str,
        allow_replacement: bool,
    ) -> Result<Self, TunnelAuthorizationError> {
        if !valid_id(lease_id, 128)
            || !valid_id(expected_peer_endpoint_instance_id, 128)
            || expected_peer_endpoint_instance_id == request.claims.endpoint
        {
            return Err(TunnelAuthorizationError);
        }
        let seconds = expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TunnelAuthorizationError)?
            .as_secs();
        if seconds <= unix_seconds() || seconds > i64::MAX as u64 {
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
            "expected_peer_endpoint_instance_id": expected_peer_endpoint_instance_id,
            "expires_at": expires_at,
            "lease_id": lease_id,
        }))
        .map_err(|_| TunnelAuthorizationError)?;
        Self::parse(encoded)
    }

    /// Builds a bounded terminal or retryable rejection response.
    pub fn reject(reason: &str, retryable: bool) -> Result<Self, TunnelAuthorizationError> {
        if !valid_reason(reason) || forbidden_transport_security_reason(reason) {
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
    async fn authorize(
        &self,
        request: RuntimeAuthorizationRequest,
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
            .field("allowed_origins", &self.allowed_origins)
            .field("admission_reasons", &self.admission_reasons)
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
                .accept_with_peer_v3()
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
        let listener = WebSocketListener::bind_tunnel_v3(
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
        let dispatch_barrier = self.state.dispatch_barrier.lock().await;
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
        wait_for_zero(&self.state.active_accepts, &self.state.accepts_done).await;
        let pending = self
            .state
            .pending
            .lock()
            .await
            .drain()
            .map(|(_, entry)| entry.value)
            .collect::<Vec<_>>();
        let cleanup_deadline = Instant::now() + self.admission_options.admission_timeout;
        for leg in pending {
            leg.carrier.abort();
            release_bounded(self.authorizer.as_ref(), &leg.lease_id, cleanup_deadline).await;
        }
        let active = self
            .state
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
        wait_for_zero(&self.state.active_tasks, &self.state.tasks_done).await;
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
        let response = match await_bounded(
            admission_deadline,
            &self.state.closed,
            self.authorizer.authorize(request.clone()),
        )
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
            &response.encoded,
            &lookup,
            &self.options.admission_reasons,
        ) {
            Ok(decision) => decision,
            Err(error) => {
                self.state.credentials.lock().await.remove(&lookup);
                if let Some(lease_id) = response_lease_id(&response.encoded) {
                    release_bounded(self.authorizer.as_ref(), &lease_id, admission_deadline).await;
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
            let pair_deadline = (Instant::now() + self.options.pair_timeout)
                .min(admission_deadline)
                .min(expiry_deadline);
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
                let _ = send_fsa3(
                    expired.admission.as_ref(),
                    FSA3_RETRY,
                    "pair_timeout",
                    &self.options.admission_reasons,
                    admission_deadline,
                    &self.state.closed,
                )
                .await;
                expired.carrier.abort();
                release_bounded(
                    self.authorizer.as_ref(),
                    &expired.lease_id,
                    admission_deadline,
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
                FSA3_REJECT,
                "authorization_expired",
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
        bridge(client.clone(), server.clone(), self.state.closed.clone()).await;
        let _ = tokio::join!(client.close(), server.close());
        self.state.active_carriers.lock().await.remove(&pair_id);
        let release_deadline = Instant::now() + self.admission_options.admission_timeout;
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
        let _ = tokio::join!(pair.client.close(), pair.server.close());
        self.state
            .active_carriers
            .lock()
            .await
            .retain(|_, current| !Arc::ptr_eq(&current.cleanup_claimed, &pair.cleanup_claimed));
        self.finish_active_pair(pair, deadline).await;
    }
}

impl From<&FsbClaims> for AuthorityKey {
    fn from(claims: &FsbClaims) -> Self {
        Self {
            profile: claims.profile.clone(),
            channel: claims.channel.clone(),
            group: claims.group.clone(),
            audience: claims.audience.clone(),
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

#[derive(Debug)]
struct FsbClaims {
    profile: String,
    role: u8,
    endpoint: String,
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
    encoded: &[u8],
    lookup: &str,
    admission_reasons: &[String],
) -> Result<AuthorizationDecision, TunnelRuntimeError> {
    let value: Value = serde_json::from_slice(encoded).map_err(|_| TunnelRuntimeError::Rejected)?;
    validate_authorization_shape(&value).map_err(|_| TunnelRuntimeError::Rejected)?;
    let object = value.as_object().expect("validated object");
    match object["decision"].as_str().expect("validated decision") {
        "reject" | "retry" => {
            let reason = object["reason"].as_str().expect("validated reason");
            if !valid_server_reason(reason, admission_reasons) {
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
            if object["credential_id"].as_str() != Some(lookup) {
                return Err(TunnelRuntimeError::Rejected);
            }
            let parsed = time::OffsetDateTime::parse(
                object["expires_at"].as_str().expect("validated expiry"),
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| TunnelRuntimeError::Rejected)?;
            let seconds = parsed.unix_timestamp();
            if seconds <= unix_seconds() as i64 {
                return Err(TunnelRuntimeError::Rejected);
            }
            Ok(AuthorizationDecision::Allow(AllowedClaims {
                lease_id: object["lease_id"].as_str().expect("validated lease").into(),
                expected_peer: object["expected_peer_endpoint_instance_id"]
                    .as_str()
                    .expect("validated peer")
                    .into(),
                expires_at: UNIX_EPOCH + Duration::from_secs(seconds as u64),
                allow_replacement: object["allow_replacement"]
                    .as_bool()
                    .expect("validated replacement flag"),
            }))
        }
        _ => Err(TunnelRuntimeError::Rejected),
    }
}

fn response_lease_id(encoded: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(encoded).ok()?;
    let object = value.as_object()?;
    (object.get("decision").and_then(Value::as_str) == Some("allow"))
        .then(|| object.get("lease_id").and_then(Value::as_str))
        .flatten()
        .filter(|lease_id| valid_id(lease_id, 128))
        .map(str::to_owned)
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
    let _ = tokio::time::timeout_at(deadline, authorizer.release(lease_id)).await;
}

async fn bridge(
    client: Arc<dyn CarrierSessionV3>,
    server: Arc<dyn CarrierSessionV3>,
    runtime_closed: CancellationToken,
) {
    let Ok(control) = client.accept_stream().await else {
        return;
    };
    let Ok(control_peer) = server.open_stream().await else {
        return;
    };
    let closed = CancellationToken::new();
    let mut control_task = tokio::spawn(bridge_control_pair(control, control_peer, closed.clone()));
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

async fn bridge_control_pair(
    first: Arc<dyn CarrierStreamV3>,
    second: Arc<dyn CarrierStreamV3>,
    closed: CancellationToken,
) {
    let first_to_second = copy_stream(first.clone(), second.clone());
    let second_to_first = copy_stream(second, first);
    tokio::pin!(first_to_second);
    tokio::pin!(second_to_first);
    tokio::select! {
        _ = &mut first_to_second => {
            let _ = tokio::time::timeout(CONTROL_HALF_CLOSE_GRACE, &mut second_to_first).await;
        }
        _ = &mut second_to_first => {
            let _ = tokio::time::timeout(CONTROL_HALF_CLOSE_GRACE, &mut first_to_second).await;
        }
        _ = closed.cancelled() => {}
    }
    closed.cancel();
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
        if payload.len() <= target_maximum && target.send_unreliable_message(payload).await.is_err()
        {
            closed.cancel();
            return;
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
    use std::future::pending;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct AbortProbeCarrier {
        inner: Arc<dyn CarrierSessionV3>,
        aborted: Arc<AtomicBool>,
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

    fn vector_tunnel_admission(role: u8, endpoint: &str, token: &str) -> Vec<u8> {
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
        let hex = vector["winners"][0]["fsb3_hex"].as_str().unwrap();
        let mut raw = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let payload = String::from_utf8(raw[12..].to_vec()).unwrap();
        let payload = payload
            .replace("endpoint-client", endpoint)
            .replace("attach-token-v3", token)
            .replace("\"role\":1", &format!("\"role\":{role}"));
        raw[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        raw.truncate(12);
        raw.extend_from_slice(payload.as_bytes());
        raw
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

    #[derive(Debug)]
    struct NoopAuthorizer;

    #[async_trait]
    impl TunnelAuthorizer for NoopAuthorizer {
        async fn authorize(
            &self,
            _request: RuntimeAuthorizationRequest,
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
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            Err(TunnelAuthorizationError)
        }

        async fn release(&self, _lease_id: &str) {
            pending().await
        }
    }

    #[derive(Debug, Default)]
    struct LeaseRecordingAuthorizer {
        releases: StdMutex<Vec<String>>,
    }

    #[async_trait]
    impl TunnelAuthorizer for LeaseRecordingAuthorizer {
        async fn authorize(
            &self,
            request: RuntimeAuthorizationRequest,
        ) -> Result<TunnelAuthorizationResponse, TunnelAuthorizationError> {
            TunnelAuthorizationResponse::allow(
                &request,
                "lease-allow",
                SystemTime::now() + Duration::from_secs(30),
                if request.claims.role == 1 {
                    "endpoint-server"
                } else {
                    "endpoint-client"
                },
                false,
            )
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
    async fn malformed_authorization_releases_the_returned_lease() {
        let authorizer = Arc::new(MalformedAuthorizer::default());
        let runtime = test_runtime(authorizer.clone(), Duration::from_secs(1), 1);
        let permit = runtime
            .state
            .admission_permits
            .clone()
            .try_acquire_owned()
            .unwrap();
        let result = runtime
            .admit_and_pair(
                accepted_with_admission(vector_tunnel_admission(
                    1,
                    "endpoint-client",
                    "attach-token-v3",
                )),
                permit,
            )
            .await;
        assert_eq!(result, Err(TunnelRuntimeError::Rejected));
        assert_eq!(
            authorizer.releases.lock().unwrap().as_slice(),
            ["lease-malformed"]
        );
    }

    #[tokio::test]
    async fn admission_permit_is_available_during_pending_pair_wait() {
        let authorizer = Arc::new(LeaseRecordingAuthorizer::default());
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
        for _ in 0..50 {
            if !runtime.state.pending.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
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
    async fn replacement_retires_the_old_pending_generation() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let runtime = Arc::new(test_runtime(authorizer.clone(), Duration::from_secs(1), 1));
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
        for _ in 0..20 {
            if runtime
                .state
                .pending
                .lock()
                .await
                .contains_key(&AuthorityKey {
                    profile: "flowersec/3".into(),
                    channel: "channel".into(),
                    group: "group".into(),
                    audience: "audience".into(),
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
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
    async fn opposite_role_hash_mismatch_rejects_only_the_incoming_leg() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let runtime = Arc::new(test_runtime(authorizer.clone(), Duration::from_secs(1), 1));
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
        };
        for _ in 0..20 {
            if runtime.state.pending.lock().await.contains_key(&key) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let (incoming, _) = crate::session_v3::memory_carrier_pair_v3();
        let result = runtime
            .register_leg(
                test_leg_with_hashes(
                    "incoming-lease",
                    2,
                    "endpoint-second",
                    "endpoint-first",
                    SystemTime::now() + Duration::from_secs(1),
                    false,
                    "contract-b",
                    "candidates-b",
                    incoming,
                ),
                Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert_eq!(result, Err(TunnelRuntimeError::Rejected));
        let pending = runtime.state.pending.lock().await;
        assert_eq!(pending.get(&key).unwrap().value.lease_id, "pending-lease");
        drop(pending);
        runtime.state.closed.cancel();
        let _ = first_task.await;
        assert_eq!(authorizer.releases.load(Ordering::SeqCst), 2);
    }

    async fn wait_for_active_pair(runtime: &TaskRuntime) {
        for _ in 0..50 {
            if !runtime.state.active_carriers.lock().await.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("active pair was not registered");
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
        let response = TunnelAuthorizationResponse::reject("capacity", true).unwrap();
        assert!(matches!(
            parse_authorization_decision(&response.encoded, "unused", &[]),
            Ok(AuthorizationDecision::Deny {
                status: FSA3_RETRY,
                reason
            }) if reason == "capacity"
        ));
        assert_eq!(
            response_lease_id(br#"{"decision":"allow","lease_id":"lease-1"}"#),
            Some("lease-1".into())
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
        let response = TunnelAuthorizationResponse::reject("policy_denied", true).unwrap();
        assert!(matches!(
            parse_authorization_decision(&response.encoded, "unused", &[]),
            Err(TunnelRuntimeError::Rejected)
        ));
        assert!(matches!(
            parse_authorization_decision(
                &response.encoded,
                "unused",
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
}
