//! Opaque tunnel relay runtime.
//!
//! This module deliberately stops at the carrier boundary. It validates the
//! hop admission and pairing claims, then forwards encrypted carrier streams;
//! it never parses FSC2/FSH2, stores an application PSK, or creates a Session.

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::{
    controlplane::{ControlPlaneError, RuntimeAuthorizationRequest, TunnelAuthorizationResponse},
    raw_quic_v2::{RawQuicLimits, RawQuicListener, RawQuicPathProfile, RawQuicServerConfig},
    transport_v2::{CarrierKind, CarrierSessionV2, CarrierStreamV2},
    websocket_v2::WebSocketListener,
};

const MAX_ADMISSION_BYTES: usize = 32 * 1024;
const CONTROL_HALF_CLOSE_GRACE: Duration = Duration::from_secs(2);
const FSA2_REJECT: u8 = 1;
const FSA2_RETRY: u8 = 2;

/// Application-owned authorization boundary for relay legs.
#[async_trait]
pub trait TunnelAuthorizer: Send + Sync + 'static {
    async fn authorize(
        &self,
        request: RuntimeAuthorizationRequest,
    ) -> Result<TunnelAuthorizationResponse, ControlPlaneError>;

    async fn release(&self, _lease_id: &str) {}
}

/// Resource and origin policy for an opaque WebSocket tunnel relay.
pub struct TunnelRuntimeOptions {
    pub bind_address: SocketAddr,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
    pub allowed_origins: Vec<String>,
    pub max_inbound_streams: u16,
    pub pair_timeout: Duration,
    pub max_pending_legs: usize,
    pub max_active_pairs: usize,
}

impl fmt::Debug for TunnelRuntimeOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelRuntimeOptions")
            .field("bind_address", &self.bind_address)
            .field("certificate_chain_der", &"[REDACTED]")
            .field("private_key_der", &"[REDACTED]")
            .field("allowed_origins", &self.allowed_origins)
            .field("max_inbound_streams", &self.max_inbound_streams)
            .field("pair_timeout", &self.pair_timeout)
            .field("max_pending_legs", &self.max_pending_legs)
            .field("max_active_pairs", &self.max_active_pairs)
            .finish()
    }
}

pub struct TunnelRuntime {
    listener: StdMutex<Option<Arc<TunnelListener>>>,
    authorizer: Arc<dyn TunnelAuthorizer>,
    options: TunnelRuntimeOptions,
    state: Arc<TunnelState>,
}

enum TunnelListener {
    RawQuic(RawQuicListener),
    WebSocket(WebSocketListener),
}

struct AcceptedTunnelCarrier {
    carrier: Arc<dyn CarrierSessionV2>,
    remote_address: SocketAddr,
}

impl TunnelListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::RawQuic(listener) => listener.local_addr(),
            Self::WebSocket(listener) => listener.local_addr(),
        }
    }

    async fn accept(&self) -> Result<AcceptedTunnelCarrier, TunnelRuntimeError> {
        match self {
            Self::RawQuic(listener) => listener
                .accept()
                .await
                .map(|session| AcceptedTunnelCarrier {
                    remote_address: session.peer_address(),
                    carrier: Arc::new(session) as Arc<dyn CarrierSessionV2>,
                })
                .map_err(|_| TunnelRuntimeError::Closed),
            Self::WebSocket(listener) => listener
                .accept_with_peer()
                .await
                .map(|(carrier, remote_address)| AcceptedTunnelCarrier {
                    carrier,
                    remote_address,
                })
                .map_err(|_| TunnelRuntimeError::Closed),
        }
    }
}

impl fmt::Debug for TunnelRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelRuntime { <opaque> }")
    }
}

struct TunnelState {
    pending: Mutex<HashMap<String, Leg>>,
    credentials: Mutex<HashMap<String, SystemTime>>,
    active_pairs: Mutex<usize>,
    active_carriers: Mutex<HashMap<u64, ActivePairCarriers>>,
    next_pair_id: AtomicU64,
    active_tasks: AtomicUsize,
    tasks_done: Notify,
    active_accepts: AtomicUsize,
    accepts_done: Notify,
    closed: CancellationToken,
}

type ActivePairCarriers = (Arc<dyn CarrierSessionV2>, Arc<dyn CarrierSessionV2>);

struct Leg {
    carrier: Arc<dyn CarrierSessionV2>,
    admission: Arc<dyn CarrierStreamV2>,
    role: u8,
    expected_peer: String,
    endpoint: String,
    lease_id: String,
    expires_at: SystemTime,
}

impl TunnelRuntime {
    /// Binds a production opaque raw QUIC relay listener.
    pub fn bind_raw_quic(
        options: TunnelRuntimeOptions,
        authorizer: Arc<dyn TunnelAuthorizer>,
    ) -> Result<Self, TunnelRuntimeError> {
        Self::validate_options(&options)?;
        let limits =
            RawQuicLimits::for_session_v2(options.max_inbound_streams, options.pair_timeout)
                .map_err(|_| TunnelRuntimeError::InvalidConfiguration)?;
        let config = RawQuicServerConfig::new(
            RawQuicPathProfile::Tunnel,
            options.certificate_chain_der.clone(),
            options.private_key_der.clone(),
            limits,
        )
        .map_err(|_| TunnelRuntimeError::InvalidConfiguration)?;
        let listener = RawQuicListener::bind(options.bind_address, config)
            .map_err(|_| TunnelRuntimeError::BindFailed)?;
        Ok(Self {
            listener: StdMutex::new(Some(Arc::new(TunnelListener::RawQuic(listener)))),
            authorizer,
            options,
            state: Arc::new(TunnelState {
                pending: Mutex::new(HashMap::new()),
                credentials: Mutex::new(HashMap::new()),
                active_pairs: Mutex::new(0),
                active_carriers: Mutex::new(HashMap::new()),
                next_pair_id: AtomicU64::new(1),
                active_tasks: AtomicUsize::new(0),
                tasks_done: Notify::new(),
                active_accepts: AtomicUsize::new(0),
                accepts_done: Notify::new(),
                closed: CancellationToken::new(),
            }),
        })
    }

    pub fn bind_websocket(
        options: TunnelRuntimeOptions,
        authorizer: Arc<dyn TunnelAuthorizer>,
    ) -> Result<Self, TunnelRuntimeError> {
        if options.pair_timeout.is_zero()
            || options.max_pending_legs == 0
            || options.max_active_pairs == 0
            || options.max_inbound_streams == 0
        {
            return Err(TunnelRuntimeError::InvalidConfiguration);
        }
        let capacity =
            crate::transport_v2::carrier_inbound_stream_limit_v2(options.max_inbound_streams)
                .map_err(|_| TunnelRuntimeError::InvalidConfiguration)?;
        let listener = WebSocketListener::bind_tunnel(
            options.bind_address,
            options.certificate_chain_der.clone(),
            options.private_key_der.clone(),
            options.allowed_origins.clone(),
            capacity,
        )
        .map_err(|_| TunnelRuntimeError::BindFailed)?;
        Ok(Self {
            listener: StdMutex::new(Some(Arc::new(TunnelListener::WebSocket(listener)))),
            authorizer,
            options,
            state: Arc::new(TunnelState {
                pending: Mutex::new(HashMap::new()),
                credentials: Mutex::new(HashMap::new()),
                active_pairs: Mutex::new(0),
                active_carriers: Mutex::new(HashMap::new()),
                next_pair_id: AtomicU64::new(1),
                active_tasks: AtomicUsize::new(0),
                tasks_done: Notify::new(),
                active_accepts: AtomicUsize::new(0),
                accepts_done: Notify::new(),
                closed: CancellationToken::new(),
            }),
        })
    }

    fn validate_options(options: &TunnelRuntimeOptions) -> Result<(), TunnelRuntimeError> {
        if options.pair_timeout.is_zero()
            || options.max_pending_legs == 0
            || options.max_active_pairs == 0
            || options.max_inbound_streams == 0
        {
            return Err(TunnelRuntimeError::InvalidConfiguration);
        }
        Ok(())
    }

    pub fn local_address(&self) -> Result<SocketAddr, TunnelRuntimeError> {
        self.listener
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .ok_or(TunnelRuntimeError::Closed)?
            .local_addr()
            .map_err(|_| TunnelRuntimeError::Closed)
    }

    /// Serves until cancellation or listener shutdown. No application Session
    /// or handler callback is reachable from this runtime.
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
                _ = cancellation.cancelled() => {
                    None
                }
                _ = self.state.closed.cancelled() => None,
                accepted = listener.accept() => Some(accepted),
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
                    let runtime = self.clone_for_task();
                    spawn_tracked(self.state.clone(), async move {
                        runtime
                            .process(accepted.carrier, accepted.remote_address)
                            .await
                    });
                }
                Ok(accepted) => accepted.carrier.abort(),
                Err(_) if self.state.closed.is_cancelled() => return Ok(()),
                Err(_) => return Err(TunnelRuntimeError::Closed),
            }
        }
    }

    pub async fn close(&self) {
        self.state.closed.cancel();
        self.listener
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        wait_for_zero(&self.state.active_accepts, &self.state.accepts_done).await;
        let legs = {
            let mut pending = self.state.pending.lock().await;
            pending.drain().map(|(_, leg)| leg).collect::<Vec<_>>()
        };
        for leg in legs {
            let _ = send_fsa2(&*leg.admission, FSA2_REJECT, "runtime_closed").await;
            leg.carrier.abort();
            self.authorizer.release(&leg.lease_id).await;
        }
        let active = self
            .state
            .active_carriers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for (first, second) in active {
            first.abort();
            second.abort();
        }
        wait_for_zero(&self.state.active_tasks, &self.state.tasks_done).await;
    }

    fn clone_for_task(&self) -> TaskRuntime {
        TaskRuntime {
            authorizer: self.authorizer.clone(),
            options: self.options.clone_for_task(),
            state: self.state.clone(),
        }
    }
}

// A task runtime owns no listener operation; its field is intentionally absent
// from the processing path. Keeping this separate prevents accidental accepts.
struct TaskRuntime {
    authorizer: Arc<dyn TunnelAuthorizer>,
    options: TunnelRuntimeOptions,
    state: Arc<TunnelState>,
}

impl TaskRuntime {
    async fn process(self, carrier: Arc<dyn CarrierSessionV2>, remote_address: SocketAddr) {
        let result = self.process_inner(carrier.clone(), remote_address).await;
        if result.is_err() {
            carrier.abort();
        }
    }

    async fn process_inner(
        &self,
        carrier: Arc<dyn CarrierSessionV2>,
        remote_address: SocketAddr,
    ) -> Result<(), TunnelRuntimeError> {
        let admission = carrier
            .accept_stream()
            .await
            .map_err(|_| TunnelRuntimeError::AdmissionFailed)?;
        let raw = read_admission(&*admission).await?;
        let carrier_name = match carrier.kind() {
            CarrierKind::Wss => "websocket",
            CarrierKind::RawQuic => "raw_quic",
            CarrierKind::WebTransport => "webtransport",
        };
        let body = serde_json::json!({
            "fsb2_base64url": URL_SAFE_NO_PAD.encode(&raw),
            "carrier": carrier_name,
            "remote_address": remote_address.to_string(),
        });
        let request = RuntimeAuthorizationRequest::parse(
            &serde_json::to_vec(&body).map_err(|_| TunnelRuntimeError::AdmissionFailed)?,
        )
        .map_err(|_| TunnelRuntimeError::AdmissionFailed)?;
        let lookup = request.lookup_key().to_owned();
        {
            let now = SystemTime::now();
            let mut credentials = self.state.credentials.lock().await;
            credentials.retain(|_, expiry| *expiry > now);
            if credentials.contains_key(&lookup) {
                let _ = send_fsa2(&*admission, FSA2_REJECT, "credential_replay").await;
                return Err(TunnelRuntimeError::Rejected);
            }
            credentials.insert(lookup.clone(), now + self.options.pair_timeout);
        }
        let response = match tokio::select! {
            biased;
            _ = self.state.closed.cancelled() => return Err(TunnelRuntimeError::Closed),
            response = self.authorizer.authorize(request.clone()) => response,
        } {
            Ok(response) => response,
            Err(_) => {
                self.state.credentials.lock().await.remove(&lookup);
                let _ = send_fsa2(&*admission, FSA2_REJECT, "not_authorized").await;
                return Err(TunnelRuntimeError::Rejected);
            }
        };
        let claims = match TunnelAuthorizationDecision::parse(&response.json(), &lookup) {
            Ok(TunnelAuthorizationDecision::Allow(claims)) => claims,
            Ok(TunnelAuthorizationDecision::Deny { status, reason }) => {
                self.state.credentials.lock().await.remove(&lookup);
                let _ = send_fsa2(&*admission, status, &reason).await;
                return Err(TunnelRuntimeError::Rejected);
            }
            Err(error) => {
                self.state.credentials.lock().await.remove(&lookup);
                let _ = send_fsa2(&*admission, FSA2_REJECT, "invalid_authorization").await;
                return Err(error);
            }
        };
        self.state
            .credentials
            .lock()
            .await
            .insert(lookup, claims.expires_at);
        let value = match parse_fsb2_claims(&raw) {
            Ok(value) => value,
            Err(error) => {
                self.authorizer.release(&claims.lease_id).await;
                return Err(error);
            }
        };
        if value.role == 0 || value.role > 2 || value.endpoint == claims.expected_peer {
            self.authorizer.release(&claims.lease_id).await;
            let _ = send_fsa2(&*admission, FSA2_REJECT, "invalid_credential").await;
            return Err(TunnelRuntimeError::Rejected);
        }
        if carrier.kind() == CarrierKind::Wss
            && carrier.set_multiplexer_client(value.role == 2).is_err()
        {
            self.authorizer.release(&claims.lease_id).await;
            let _ = send_fsa2(&*admission, FSA2_REJECT, "invalid_carrier_state").await;
            return Err(TunnelRuntimeError::AdmissionFailed);
        }
        let key = format!(
            "{}:{}:{}:{}",
            value.channel, value.group, value.audience, value.contract_hash
        );
        let leg = Leg {
            carrier: carrier.clone(),
            admission,
            role: value.role,
            expected_peer: claims.expected_peer,
            endpoint: value.endpoint,
            lease_id: claims.lease_id,
            expires_at: claims.expires_at,
        };
        enum Registration {
            Pending,
            Paired(Leg),
            Capacity,
        }
        let registration = {
            let mut pending = self.state.pending.lock().await;
            if self.state.closed.is_cancelled() {
                Registration::Capacity
            } else if let Some(peer) = pending.remove(&key) {
                Registration::Paired(peer)
            } else if pending.len() >= self.options.max_pending_legs {
                Registration::Capacity
            } else {
                Registration::Pending
            }
        };
        if let Registration::Capacity = &registration {
            let _ = send_fsa2(&*leg.admission, FSA2_RETRY, "capacity").await;
            self.authorizer.release(&leg.lease_id).await;
            return Err(TunnelRuntimeError::Capacity);
        }
        let Registration::Paired(peer) = registration else {
            let pending_lifetime = leg
                .expires_at
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::from_millis(1));
            let mut pending = self.state.pending.lock().await;
            pending.insert(key.clone(), leg);
            let state = self.state.clone();
            let authorizer = self.authorizer.clone();
            let timeout = self.options.pair_timeout.min(pending_lifetime);
            spawn_tracked(self.state.clone(), async move {
                tokio::select! {
                    _ = state.closed.cancelled() => return,
                    _ = tokio::time::sleep(timeout) => {}
                }
                if let Some(leg) = state.pending.lock().await.remove(&key) {
                    let _ = send_fsa2(&*leg.admission, FSA2_RETRY, "pair_timeout").await;
                    leg.carrier.abort();
                    authorizer.release(&leg.lease_id).await;
                }
            });
            return Ok(());
        };
        if peer.role == leg.role
            || peer.endpoint != leg.expected_peer
            || leg.endpoint != peer.expected_peer
        {
            self.state.pending.lock().await.insert(key, peer);
            let _ = send_fsa2(&*leg.admission, FSA2_REJECT, "pair_mismatch").await;
            self.authorizer.release(&leg.lease_id).await;
            return Err(TunnelRuntimeError::Rejected);
        }
        {
            let mut active = self.state.active_pairs.lock().await;
            if *active >= self.options.max_active_pairs {
                self.state.pending.lock().await.insert(key, peer);
                let _ = send_fsa2(&*leg.admission, FSA2_RETRY, "capacity").await;
                self.authorizer.release(&leg.lease_id).await;
                return Err(TunnelRuntimeError::Capacity);
            }
            *active += 1;
        }
        let pair_id = self.state.next_pair_id.fetch_add(1, Ordering::Relaxed);
        self.state
            .active_carriers
            .lock()
            .await
            .insert(pair_id, (peer.carrier.clone(), leg.carrier.clone()));
        let state = self.state.clone();
        let authorizer = self.authorizer.clone();
        spawn_tracked(self.state.clone(), async move {
            let _ = send_fsa2(&*peer.admission, 0, "").await;
            let _ = send_fsa2(&*leg.admission, 0, "").await;
            let (client, server) = if peer.role == 1 {
                (peer.carrier.clone(), leg.carrier.clone())
            } else {
                (leg.carrier.clone(), peer.carrier.clone())
            };
            bridge(client, server, state.clone()).await;
            // The bridge has finished forwarding opaque carrier bytes. Close
            // each hop through its carrier API so queued close/FIN frames are
            // delivered before transport shutdown; aborting here truncates a
            // peer's session close handshake.
            let _ = peer.carrier.close().await;
            let _ = leg.carrier.close().await;
            authorizer.release(&peer.lease_id).await;
            authorizer.release(&leg.lease_id).await;
            state.active_carriers.lock().await.remove(&pair_id);
            let mut active = state.active_pairs.lock().await;
            *active = active.saturating_sub(1);
        });
        Ok(())
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
        if counter.load(Ordering::Acquire) == 0 {
            return;
        }
        notified.await;
    }
}

impl Clone for TunnelRuntimeOptions {
    fn clone(&self) -> Self {
        self.clone_for_task()
    }
}
impl TunnelRuntimeOptions {
    fn clone_for_task(&self) -> Self {
        Self {
            bind_address: self.bind_address,
            certificate_chain_der: self.certificate_chain_der.clone(),
            private_key_der: self.private_key_der.clone(),
            allowed_origins: self.allowed_origins.clone(),
            max_inbound_streams: self.max_inbound_streams,
            pair_timeout: self.pair_timeout,
            max_pending_legs: self.max_pending_legs,
            max_active_pairs: self.max_active_pairs,
        }
    }
}

#[derive(Debug, thiserror::Error)]
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

struct AllowedClaims {
    lease_id: String,
    expected_peer: String,
    expires_at: SystemTime,
}

enum TunnelAuthorizationDecision {
    Allow(AllowedClaims),
    Deny { status: u8, reason: String },
}

impl TunnelAuthorizationDecision {
    fn parse(raw: &[u8], lookup: &str) -> Result<Self, TunnelRuntimeError> {
        let value: Value = serde_json::from_slice(raw).map_err(|_| TunnelRuntimeError::Rejected)?;
        let object = value.as_object().ok_or(TunnelRuntimeError::Rejected)?;
        let decision = object
            .get("decision")
            .and_then(Value::as_str)
            .ok_or(TunnelRuntimeError::Rejected)?;
        if matches!(decision, "reject" | "retry") {
            if object.len() != 2 {
                return Err(TunnelRuntimeError::Rejected);
            }
            let reason = object
                .get("reason")
                .and_then(Value::as_str)
                .filter(|reason| valid_reason(reason))
                .ok_or(TunnelRuntimeError::Rejected)?
                .to_owned();
            return Ok(Self::Deny {
                status: if decision == "retry" {
                    FSA2_RETRY
                } else {
                    FSA2_REJECT
                },
                reason,
            });
        }
        AllowedClaims::parse_value(object, lookup).map(Self::Allow)
    }
}

impl AllowedClaims {
    fn parse_value(
        object: &serde_json::Map<String, Value>,
        lookup: &str,
    ) -> Result<Self, TunnelRuntimeError> {
        let decision = object
            .get("decision")
            .and_then(Value::as_str)
            .ok_or(TunnelRuntimeError::Rejected)?;
        if decision != "allow" {
            return Err(TunnelRuntimeError::Rejected);
        }
        let credential_id = object
            .get("credential_id")
            .and_then(Value::as_str)
            .ok_or(TunnelRuntimeError::Rejected)?;
        if credential_id != lookup {
            return Err(TunnelRuntimeError::Rejected);
        }
        let lease_id = object
            .get("lease_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or(TunnelRuntimeError::Rejected)?
            .to_owned();
        let expected_peer = object
            .get("expected_peer_endpoint_instance_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or(TunnelRuntimeError::Rejected)?
            .to_owned();
        let expiry = object
            .get("expires_at")
            .and_then(Value::as_str)
            .ok_or(TunnelRuntimeError::Rejected)?;
        let parsed =
            time::OffsetDateTime::parse(expiry, &time::format_description::well_known::Rfc3339)
                .map_err(|_| TunnelRuntimeError::Rejected)?;
        let seconds = parsed.unix_timestamp();
        if seconds
            <= SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        {
            return Err(TunnelRuntimeError::Rejected);
        }
        Ok(Self {
            lease_id,
            expected_peer,
            expires_at: UNIX_EPOCH + Duration::from_secs(seconds as u64),
        })
    }
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'_')
}

struct FsbClaims {
    role: u8,
    endpoint: String,
    channel: String,
    group: String,
    audience: String,
    contract_hash: String,
}

fn parse_fsb2_claims(raw: &[u8]) -> Result<FsbClaims, TunnelRuntimeError> {
    if raw.len() < 12 || &raw[..4] != b"FSB2" || raw[4] != 2 || raw[5] != 2 {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    let length = u32::from_be_bytes(raw[8..12].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_ADMISSION_BYTES || raw.len() != 12 + length {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    let value: Value =
        serde_json::from_slice(&raw[12..]).map_err(|_| TunnelRuntimeError::InvalidWire)?;
    let get = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .map(str::to_owned)
            .ok_or(TunnelRuntimeError::InvalidWire)
    };
    let role = value
        .get("role")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(TunnelRuntimeError::InvalidWire)?;
    Ok(FsbClaims {
        role,
        endpoint: get("endpoint_instance_id")?,
        channel: get("channel_id")?,
        group: get("rendezvous_group_id")?,
        audience: get("listener_audience")?,
        contract_hash: get("session_contract_hash_b64u")?,
    })
}

async fn read_admission(stream: &dyn CarrierStreamV2) -> Result<Vec<u8>, TunnelRuntimeError> {
    let mut header = [0_u8; 12];
    read_exact(stream, &mut header).await?;
    if &header[..4] != b"FSB2" || header[4] != 2 || header[5] != 2 {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    let length = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_ADMISSION_BYTES {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    let mut raw = Vec::with_capacity(12 + length);
    raw.extend_from_slice(&header);
    raw.resize(12 + length, 0);
    read_exact(stream, &mut raw[12..]).await?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .await
        .map_err(|_| TunnelRuntimeError::AdmissionFailed)?
        != 0
    {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    Ok(raw)
}

async fn read_exact(
    stream: &dyn CarrierStreamV2,
    mut target: &mut [u8],
) -> Result<(), TunnelRuntimeError> {
    while !target.is_empty() {
        let count = stream
            .read(target)
            .await
            .map_err(|_| TunnelRuntimeError::AdmissionFailed)?;
        if count == 0 {
            return Err(TunnelRuntimeError::InvalidWire);
        }
        target = &mut target[count..];
    }
    Ok(())
}

async fn send_fsa2(
    stream: &dyn CarrierStreamV2,
    status: u8,
    reason: &str,
) -> Result<(), TunnelRuntimeError> {
    if status == 0 && !reason.is_empty() || status != 0 && (reason.is_empty() || reason.len() > 64)
    {
        return Err(TunnelRuntimeError::InvalidWire);
    }
    let mut response = Vec::with_capacity(8 + reason.len());
    response.extend_from_slice(b"FSA2\x02");
    response.push(status);
    response.extend_from_slice(&(reason.len() as u16).to_be_bytes());
    response.extend_from_slice(reason.as_bytes());
    let mut offset = 0;
    while offset < response.len() {
        let count = stream
            .write(&response[offset..])
            .await
            .map_err(|_| TunnelRuntimeError::AdmissionFailed)?;
        if count == 0 {
            return Err(TunnelRuntimeError::AdmissionFailed);
        }
        offset += count;
    }
    stream
        .close_write()
        .await
        .map_err(|_| TunnelRuntimeError::AdmissionFailed)
}

async fn bridge(
    client: Arc<dyn CarrierSessionV2>,
    server: Arc<dyn CarrierSessionV2>,
    state: Arc<TunnelState>,
) {
    let Ok(control) = client.accept_stream().await else {
        return;
    };
    let Ok(control_peer) = server.open_stream().await else {
        return;
    };

    let closed = CancellationToken::new();
    let control_closed = closed.clone();
    let mut control_task = tokio::spawn(async move {
        bridge_control_pair(control, control_peer, control_closed).await;
    });
    let runtime_shutdown = tokio::select! {
        _ = state.closed.cancelled() => true,
        _ = closed.cancelled() => false,
        result = async {
            tokio::join!(
                bridge_direction(client.clone(), server.clone(), closed.clone()),
                bridge_direction(server.clone(), client.clone(), closed.clone()),
                bridge_unreliable_direction(client.clone(), server.clone(), closed.clone()),
                bridge_unreliable_direction(server, client, closed.clone()),
            )
        } => { let _ = result; false }
    };
    // A carrier can report its data directions closed immediately after the
    // peer has queued its SESSION_CLOSE reply. Keep the control bridge alive
    // through its half-close grace period so that reply reaches the other
    // endpoint before the relay tears down the pair.
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
    control: Arc<dyn CarrierStreamV2>,
    peer: Arc<dyn CarrierStreamV2>,
    closed: CancellationToken,
) {
    let client_to_server = copy_stream(control.clone(), peer.clone());
    let server_to_client = copy_stream(peer, control);
    tokio::pin!(client_to_server);
    tokio::pin!(server_to_client);
    tokio::select! {
        _ = &mut client_to_server => {
            let _ = tokio::time::timeout(CONTROL_HALF_CLOSE_GRACE, &mut server_to_client).await;
        }
        _ = &mut server_to_client => {
            let _ = tokio::time::timeout(CONTROL_HALF_CLOSE_GRACE, &mut client_to_server).await;
        }
        _ = closed.cancelled() => {}
    }
    closed.cancel();
}

async fn bridge_unreliable_direction(
    source: Arc<dyn CarrierSessionV2>,
    target: Arc<dyn CarrierSessionV2>,
    closed: CancellationToken,
) -> Result<(), ()> {
    let Some(target_maximum) = target.unreliable_message_max_size() else {
        return Ok(());
    };
    if source.unreliable_message_max_size().is_none() {
        return Ok(());
    }
    loop {
        let payload = tokio::select! {
            _ = closed.cancelled() => return Ok(()),
            payload = source.receive_unreliable_message() => payload.map_err(|_| ())?,
        };
        if payload.len() <= target_maximum {
            target
                .send_unreliable_message(payload)
                .await
                .map_err(|_| ())?;
        }
    }
}

async fn bridge_direction(
    source: Arc<dyn CarrierSessionV2>,
    target: Arc<dyn CarrierSessionV2>,
    closed: CancellationToken,
) -> Result<(), ()> {
    let mut stream_tasks = JoinSet::new();
    loop {
        let inbound = match tokio::select! {
            _ = closed.cancelled() => break,
            inbound = source.accept_stream() => inbound,
        } {
            Ok(stream) => stream,
            Err(_) => break,
        };
        let outbound = match target.open_stream().await {
            Ok(stream) => stream,
            Err(_) => {
                let _ = inbound.reset().await;
                break;
            }
        };
        stream_tasks.spawn(bridge_stream_pair(inbound, outbound));
    }
    stream_tasks.abort_all();
    while stream_tasks.join_next().await.is_some() {}
    Ok(())
}

async fn bridge_stream_pair(first: Arc<dyn CarrierStreamV2>, second: Arc<dyn CarrierStreamV2>) {
    let first_to_second = copy_stream(first.clone(), second.clone());
    let second_to_first = copy_stream(second.clone(), first.clone());
    let _ = tokio::join!(first_to_second, second_to_first);
}

async fn copy_stream(
    source: Arc<dyn CarrierStreamV2>,
    target: Arc<dyn CarrierStreamV2>,
) -> Result<(), ()> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = match source.read(&mut buffer).await {
            Ok(count) => count,
            Err(_) => {
                let _ = target.reset().await;
                return Err(());
            }
        };
        if count == 0 {
            return target.close_write().await.map_err(|_| ());
        }
        let mut offset = 0;
        while offset < count {
            let written = match target.write(&buffer[offset..count]).await {
                Ok(written) => written,
                Err(_) => {
                    let _ = source.reset().await;
                    return Err(());
                }
            };
            if written == 0 {
                return Err(());
            }
            offset += written;
        }
    }
}
