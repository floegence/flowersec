//! Production Flowersec v2 session actor shared by WSS/Yamux and native QUIC.

use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{
        Arc, Mutex as StdMutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{Mutex, Notify, OwnedMutexGuard, Semaphore, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

use crate::{
    e2ee::{Suite, generate_ephemeral_keypair},
    protocol_v2::{
        AEAD_TAG_V2_SIZE, CipherSuiteV2, DirectionV2, EpochRootsV2, INNER_HEADER_V2_SIZE,
        InnerRecordTypeV2, MAX_DATA_V2_BYTES, OpenPayloadV2, RECORD_HEADER_V2_SIZE, RecordHeaderV2,
        SETUP_PREFACE_V2_SIZE, SetupPrefaceV2, StreamOpenerRoleV2, compute_fss2_hash_v2,
        compute_open_hash_v2, compute_setup_mac_v2, decode_inner_record_v2, decode_open_payload_v2,
        derive_control_material_v2, derive_epoch_zero_v2, derive_next_epoch_v2,
        derive_stream_material_v2, encode_inner_record_v2, encode_open_payload_v2, open_record_v2,
        seal_record_v2, verify_setup_mac_v2,
    },
    transport_v2::{
        ByteStreamV2, CarrierKind, CarrierSessionV2, CarrierStreamV2, IncomingStreamV2,
        JsonObjectV2, PathKind, RpcPeerV2, SessionRole, SessionV2, carrier_inbound_stream_limit_v2,
    },
};

const CONTROL_PREFACE_BYTES: usize = 16;
const HANDSHAKE_HEADER_BYTES: usize = 12;
const MAX_HANDSHAKE_PAYLOAD_BYTES: usize = 8_192;
const RESERVED_RPC_KIND: &str = "flowersec.rpc.v2";
const MAX_LEDGER_SLOTS: u64 = 1_048_576;
const NORMAL_CLOSE_REASON_V2: u16 = 1;
const IDLE_TIMEOUT_REASON_V2: u16 = 4;

/// Authenticated configuration for one side of a v2 session.
#[derive(Clone)]
pub struct SessionConfigV2 {
    pub role: SessionRole,
    pub path: PathKind,
    pub channel_id: String,
    pub session_contract_hash: [u8; 32],
    pub suite: CipherSuiteV2,
    pub psk: [u8; 32],
    pub max_inbound_streams: u16,
    /// Idle timeout copied from the signed `idle_timeout_seconds` contract.
    /// Zero disables the application-level idle watchdog.
    pub idle_timeout: Duration,
    pub local_admission_binding: [u8; 32],
    pub peer_admission_binding: Option<[u8; 32]>,
    pub local_endpoint_instance_id: Option<String>,
    pub expected_peer_endpoint_instance_id: Option<String>,
    pub rpc_handler: Option<Arc<dyn RpcHandlerV2>>,
    pub deadlines: SessionDeadlinesV2,
}

impl std::fmt::Debug for SessionConfigV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionConfigV2")
            .field("role", &self.role)
            .field("path", &self.path)
            .field("channel_id", &self.channel_id)
            .field("session_contract_hash", &self.session_contract_hash)
            .field("suite", &self.suite)
            .field("psk", &format_args!("[REDACTED]"))
            .field("max_inbound_streams", &self.max_inbound_streams)
            .field("idle_timeout", &self.idle_timeout)
            .field("local_admission_binding", &format_args!("[REDACTED]"))
            .field("peer_admission_binding", &format_args!("[REDACTED]"))
            .field(
                "local_endpoint_instance_id",
                &self.local_endpoint_instance_id,
            )
            .field(
                "expected_peer_endpoint_instance_id",
                &self.expected_peer_endpoint_instance_id,
            )
            .field("has_rpc_handler", &self.rpc_handler.is_some())
            .field("deadlines", &self.deadlines)
            .finish()
    }
}

/// Internal upper bounds. Callers may cancel their future earlier; after a
/// rekey commit is written the owned completion task still uses this bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionDeadlinesV2 {
    pub establish: Duration,
    pub rekey_prepare: Duration,
    pub rekey_completion: Duration,
    /// Versioned upper bound for flushing GOAWAY and SESSION_CLOSE.
    pub close_flush: Duration,
}

impl Default for SessionDeadlinesV2 {
    fn default() -> Self {
        Self {
            establish: Duration::from_secs(30),
            rekey_prepare: Duration::from_secs(10),
            rekey_completion: Duration::from_secs(30),
            close_flush: Duration::from_secs(2),
        }
    }
}

impl SessionConfigV2 {
    fn validate(&self) -> io::Result<()> {
        let endpoint_shape_is_valid = match self.path {
            PathKind::Direct => {
                self.local_endpoint_instance_id.is_none()
                    && self.expected_peer_endpoint_instance_id.is_none()
            }
            PathKind::Tunnel => {
                self.local_endpoint_instance_id
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                    && self
                        .expected_peer_endpoint_instance_id
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
            }
        };
        carrier_inbound_stream_limit_v2(self.max_inbound_streams).map_err(io::Error::other)?;
        if !endpoint_shape_is_valid
            || self.channel_id.is_empty()
            || self.channel_id.len() > 255
            || self.deadlines.establish.is_zero()
            || self.deadlines.rekey_prepare.is_zero()
            || self.deadlines.rekey_completion.is_zero()
            || self.deadlines.close_flush.is_zero()
            || self
                .local_endpoint_instance_id
                .as_deref()
                .is_some_and(str::is_empty)
            || self
                .expected_peer_endpoint_instance_id
                .as_deref()
                .is_some_and(str::is_empty)
        {
            return Err(invalid("invalid Flowersec v2 session configuration"));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct HandshakeMaterialV2 {
    h3: [u8; 32],
    session_prk: [u8; 32],
    peer_endpoint_instance_id: Option<String>,
}

/// Application-owned bidirectional RPC dispatch for the reserved encrypted
/// `flowersec.rpc.v2` logical stream kind.
#[async_trait]
pub trait RpcHandlerV2: std::fmt::Debug + Send + Sync + 'static {
    async fn call(&self, type_id: u32, request: serde_json::Value)
    -> io::Result<serde_json::Value>;
    async fn notify(&self, type_id: u32, request: serde_json::Value) -> io::Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInitWire {
    channel_id: String,
    client_admission_binding_b64u: String,
    client_endpoint_instance_id: String,
    client_eph_pub_b64u: String,
    client_role: u8,
    max_inbound_streams: u16,
    nonce_c_b64u: String,
    profile: String,
    selected_features: u32,
    session_contract_hash_b64u: String,
    suite: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerCoreWire {
    handshake_id: String,
    max_inbound_streams: u16,
    nonce_s_b64u: String,
    selected_features: u32,
    server_admission_binding_b64u: String,
    server_endpoint_instance_id: String,
    server_eph_pub_b64u: String,
    session_contract_hash_b64u: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerFinishedWire {
    handshake_id: String,
    max_inbound_streams: u16,
    nonce_s_b64u: String,
    selected_features: u32,
    server_admission_binding_b64u: String,
    server_confirm_b64u: String,
    server_endpoint_instance_id: String,
    server_eph_pub_b64u: String,
    session_contract_hash_b64u: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientCoreWire {
    handshake_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientFinishedWire {
    client_confirm_b64u: String,
    handshake_id: String,
}

#[derive(Debug)]
struct EngineStateV2 {
    send_epoch: u32,
    recv_epoch: u32,
    send_roots: HashMap<u32, EpochRootsV2>,
    recv_roots: HashMap<u32, EpochRootsV2>,
    control_send_sequence: u64,
    control_recv_epoch: u32,
    control_recv_sequence: u64,
}

#[derive(Debug, Default)]
struct InboundResponderStateV2 {
    active: u64,
    local_frozen: bool,
    peer_frozen: bool,
}

#[derive(Debug, Default)]
struct PendingPingsV2 {
    entries: StdMutex<HashMap<u64, oneshot::Sender<Instant>>>,
}

impl PendingPingsV2 {
    fn register(
        self: &Arc<Self>,
        nonce: u64,
        sender: oneshot::Sender<Instant>,
    ) -> io::Result<PendingPingGuardV2> {
        let mut entries = self.entries.lock().expect("pending ping registry poisoned");
        if nonce == 0 || entries.contains_key(&nonce) {
            return Err(invalid("duplicate ping nonce"));
        }
        entries.insert(nonce, sender);
        drop(entries);
        Ok(PendingPingGuardV2 {
            pings: self.clone(),
            nonce,
        })
    }

    fn take(&self, nonce: u64) -> Option<oneshot::Sender<Instant>> {
        self.entries
            .lock()
            .expect("pending ping registry poisoned")
            .remove(&nonce)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("pending ping registry poisoned")
            .len()
    }
}

struct PendingPingGuardV2 {
    pings: Arc<PendingPingsV2>,
    nonce: u64,
}

impl Drop for PendingPingGuardV2 {
    fn drop(&mut self) {
        self.pings.take(self.nonce);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum LedgerStateV2 {
    Unseen = 0,
    AbandonedNoFss2 = 1,
    OpenSeen = 2,
    UsedOrTerminal = 3,
}

#[derive(Debug)]
struct StreamLedgerV2 {
    opener: StreamOpenerRoleV2,
    states: Vec<u8>,
    frontier: u64,
}

impl StreamLedgerV2 {
    fn new(opener: StreamOpenerRoleV2) -> Self {
        Self {
            opener,
            states: vec![0; (MAX_LEDGER_SLOTS / 4) as usize],
            frontier: 0,
        }
    }

    fn mark_fss2(&mut self, id: u64) -> io::Result<()> {
        let index = self.index(id)?;
        if self.state(index) != LedgerStateV2::Unseen {
            return Err(invalid("duplicate logical stream ID"));
        }
        self.set(index, LedgerStateV2::OpenSeen);
        Ok(())
    }

    fn mark_terminal(&mut self, id: u64) -> io::Result<()> {
        let index = self.index(id)?;
        match self.state(index) {
            LedgerStateV2::OpenSeen => self.set(index, LedgerStateV2::UsedOrTerminal),
            LedgerStateV2::UsedOrTerminal => return Ok(()),
            LedgerStateV2::Unseen | LedgerStateV2::AbandonedNoFss2 => {
                return Err(invalid("terminal stream was never opened"));
            }
        }
        self.advance();
        Ok(())
    }

    fn mark_peer_reset(&mut self, id: u64) -> io::Result<()> {
        let index = self.index(id)?;
        match self.state(index) {
            LedgerStateV2::Unseen => self.set(index, LedgerStateV2::AbandonedNoFss2),
            LedgerStateV2::OpenSeen => self.set(index, LedgerStateV2::UsedOrTerminal),
            LedgerStateV2::AbandonedNoFss2 | LedgerStateV2::UsedOrTerminal => return Ok(()),
        }
        self.advance();
        Ok(())
    }

    fn mark_late_fss2_for_abandoned(&mut self, id: u64) -> io::Result<()> {
        let index = self.index(id)?;
        if self.state(index) != LedgerStateV2::AbandonedNoFss2 {
            return Err(invalid("duplicate logical stream ID"));
        }
        self.set(index, LedgerStateV2::UsedOrTerminal);
        self.advance();
        Ok(())
    }

    fn frontier(&self) -> u64 {
        self.frontier
    }

    fn index(&self, id: u64) -> io::Result<u64> {
        let valid = match self.opener {
            StreamOpenerRoleV2::Client => id != 0 && id & 1 == 1,
            StreamOpenerRoleV2::Server => id != 0 && id & 1 == 0,
        };
        if !valid {
            return Err(invalid("invalid logical stream parity"));
        }
        let ordinal = match self.opener {
            StreamOpenerRoleV2::Client => id / 2 + 1,
            StreamOpenerRoleV2::Server => id / 2,
        };
        if ordinal == 0 || ordinal > MAX_LEDGER_SLOTS {
            return Err(invalid("logical stream ledger exhausted"));
        }
        Ok(ordinal - 1)
    }

    fn state(&self, index: u64) -> LedgerStateV2 {
        let shift = (index % 4) * 2;
        match (self.states[(index / 4) as usize] >> shift) & 3 {
            0 => LedgerStateV2::Unseen,
            1 => LedgerStateV2::AbandonedNoFss2,
            2 => LedgerStateV2::OpenSeen,
            _ => LedgerStateV2::UsedOrTerminal,
        }
    }

    fn set(&mut self, index: u64, state: LedgerStateV2) {
        let byte = &mut self.states[(index / 4) as usize];
        let shift = (index % 4) * 2;
        *byte = (*byte & !(3 << shift)) | ((state as u8) << shift);
    }

    fn advance(&mut self) {
        let mut next = if self.frontier == 0 {
            match self.opener {
                StreamOpenerRoleV2::Client => 1,
                StreamOpenerRoleV2::Server => 2,
            }
        } else {
            self.frontier.saturating_add(2)
        };
        while let Ok(index) = self.index(next) {
            if !matches!(
                self.state(index),
                LedgerStateV2::AbandonedNoFss2 | LedgerStateV2::UsedOrTerminal
            ) {
                break;
            }
            self.frontier = next;
            next = next.saturating_add(2);
        }
    }
}

/// Concrete carrier-neutral Flowersec v2 session.
pub struct EncryptedSessionV2 {
    carrier: Arc<dyn CarrierSessionV2>,
    config: SessionConfigV2,
    peer_endpoint_instance_id: Option<String>,
    h3: [u8; 32],
    send_direction: DirectionV2,
    recv_direction: DirectionV2,
    control: Arc<dyn CarrierStreamV2>,
    state: Mutex<EngineStateV2>,
    control_write: Mutex<()>,
    open_lock: Arc<Mutex<()>>,
    rekey_lock: Arc<Mutex<()>>,
    rekeying: AtomicBool,
    rekey_changed: Notify,
    inbound_responders: StdMutex<InboundResponderStateV2>,
    inbound_responders_changed: Notify,
    next_stream_id: AtomicU64,
    local_open_high_watermark: AtomicU64,
    outbound_ledger: Mutex<StreamLedgerV2>,
    peer_ledger: Mutex<StreamLedgerV2>,
    outbound_ledger_changed: Notify,
    next_transition: AtomicU64,
    recv_transition: AtomicU64,
    sent_goaway: AtomicBool,
    sent_goaway_last: AtomicU64,
    received_goaway: AtomicBool,
    received_goaway_last: AtomicU64,
    incoming_rx: Mutex<mpsc::Receiver<IncomingStreamV2>>,
    incoming_tx: mpsc::Sender<IncomingStreamV2>,
    outbound_permits: Arc<Semaphore>,
    inbound_permits: Arc<Semaphore>,
    inbound_rpc_opened: AtomicBool,
    streams: StdMutex<HashMap<u64, Weak<EncryptedStreamV2>>>,
    pings: Arc<PendingPingsV2>,
    rekeys: Mutex<HashMap<u64, PendingSessionRekeyV2>>,
    last_session_rekey_ack: Mutex<Option<[u8; 20]>>,
    next_ping: AtomicU64,
    activity_generation: AtomicU64,
    activity_changed: Notify,
    closed: AtomicBool,
    canceled: CancellationToken,
    terminal: StdMutex<Option<TerminalCauseV2>>,
    rpc: SessionRpcPeerV2,
    ready: Notify,
    self_weak: OnceLock<Weak<SelfSession>>,
}

impl std::fmt::Debug for EncryptedSessionV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedSessionV2")
            .field("role", &self.config.role)
            .field("path", &self.config.path)
            .field("carrier", &self.carrier.kind())
            .field("peer_endpoint_instance_id", &self.peer_endpoint_instance_id)
            .finish_non_exhaustive()
    }
}

/// Establishes FSC2/FSH2, verifies all authenticated bindings, and completes
/// SESSION_READY/SESSION_READY_ACK before returning the public session.
pub async fn establish_session_v2(
    carrier: Arc<dyn CarrierSessionV2>,
    config: SessionConfigV2,
) -> io::Result<Arc<dyn SessionV2>> {
    config.validate()?;
    let expected_carrier_limit =
        carrier_inbound_stream_limit_v2(config.max_inbound_streams).map_err(io::Error::other)?;
    if carrier.inbound_bidirectional_stream_capacity() != expected_carrier_limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "carrier stream limit does not match SessionV2 logical limit",
        ));
    }
    let deadline = config.deadlines.establish;
    tokio::time::timeout(deadline, establish_session_v2_inner(carrier, config))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Flowersec v2 establish timeout"))?
}

async fn establish_session_v2_inner(
    carrier: Arc<dyn CarrierSessionV2>,
    config: SessionConfigV2,
) -> io::Result<Arc<dyn SessionV2>> {
    let (control, material) = match config.role {
        SessionRole::Client => {
            let control = carrier.open_stream().await?;
            let material = client_handshake_v2(&control, &config).await?;
            (control, material)
        }
        SessionRole::Server => {
            let control = carrier.accept_stream().await?;
            let material = server_handshake_v2(&control, &config).await?;
            (control, material)
        }
    };
    let (send_direction, recv_direction, send_role) = match config.role {
        SessionRole::Client => (
            DirectionV2::ClientToServer,
            DirectionV2::ServerToClient,
            StreamOpenerRoleV2::Client,
        ),
        SessionRole::Server => (
            DirectionV2::ServerToClient,
            DirectionV2::ClientToServer,
            StreamOpenerRoleV2::Server,
        ),
    };
    let send_zero = derive_epoch_zero_v2(&material.session_prk, send_direction).map_err(proto)?;
    let recv_zero = derive_epoch_zero_v2(&material.session_prk, recv_direction).map_err(proto)?;
    let (incoming_tx, incoming_rx) = mpsc::channel(usize::from(config.max_inbound_streams));
    let mut send_roots = HashMap::new();
    send_roots.insert(0, send_zero);
    let mut recv_roots = HashMap::new();
    recv_roots.insert(0, recv_zero);
    let local_max_inbound_streams = config.max_inbound_streams;
    let session = Arc::new(SelfSession(EncryptedSessionV2 {
        carrier,
        config,
        peer_endpoint_instance_id: material.peer_endpoint_instance_id,
        h3: material.h3,
        send_direction,
        recv_direction,
        control,
        state: Mutex::new(EngineStateV2 {
            send_epoch: 0,
            recv_epoch: 0,
            send_roots,
            recv_roots,
            control_send_sequence: 0,
            control_recv_epoch: 0,
            control_recv_sequence: 0,
        }),
        control_write: Mutex::new(()),
        open_lock: Arc::new(Mutex::new(())),
        rekey_lock: Arc::new(Mutex::new(())),
        rekeying: AtomicBool::new(false),
        rekey_changed: Notify::new(),
        inbound_responders: StdMutex::new(InboundResponderStateV2::default()),
        inbound_responders_changed: Notify::new(),
        next_stream_id: AtomicU64::new(match send_role {
            StreamOpenerRoleV2::Client => 1,
            StreamOpenerRoleV2::Server => 2,
        }),
        local_open_high_watermark: AtomicU64::new(0),
        outbound_ledger: Mutex::new(StreamLedgerV2::new(send_role)),
        peer_ledger: Mutex::new(StreamLedgerV2::new(match send_role {
            StreamOpenerRoleV2::Client => StreamOpenerRoleV2::Server,
            StreamOpenerRoleV2::Server => StreamOpenerRoleV2::Client,
        })),
        outbound_ledger_changed: Notify::new(),
        next_transition: AtomicU64::new(1),
        recv_transition: AtomicU64::new(0),
        sent_goaway: AtomicBool::new(false),
        sent_goaway_last: AtomicU64::new(0),
        received_goaway: AtomicBool::new(false),
        received_goaway_last: AtomicU64::new(0),
        incoming_rx: Mutex::new(incoming_rx),
        incoming_tx,
        outbound_permits: Arc::new(Semaphore::new(usize::from(local_max_inbound_streams))),
        inbound_permits: Arc::new(Semaphore::new(usize::from(local_max_inbound_streams))),
        inbound_rpc_opened: AtomicBool::new(false),
        streams: StdMutex::new(HashMap::new()),
        pings: Arc::new(PendingPingsV2::default()),
        rekeys: Mutex::new(HashMap::new()),
        last_session_rekey_ack: Mutex::new(None),
        next_ping: AtomicU64::new(1),
        activity_generation: AtomicU64::new(0),
        activity_changed: Notify::new(),
        closed: AtomicBool::new(false),
        canceled: CancellationToken::new(),
        terminal: StdMutex::new(None),
        rpc: SessionRpcPeerV2 {
            session: OnceLock::new(),
            serial: Mutex::new(()),
            stream: Mutex::new(None),
            read_buffer: Mutex::new(VecDeque::new()),
            next_request_id: AtomicU64::new(1),
        },
        ready: Notify::new(),
        self_weak: OnceLock::new(),
    }));
    session
        .self_weak
        .set(Arc::downgrade(&session))
        .expect("session self reference is initialized once");
    session
        .rpc
        .session
        .set(Arc::downgrade(&session))
        .expect("RPC session reference is initialized once");
    finish_ready_v2(&session.0).await?;
    let accept_session = session.clone();
    tokio::spawn(async move { accept_carrier_loop_v2(accept_session).await });
    let control_session = session.clone();
    tokio::spawn(async move { control_loop_v2(control_session).await });
    if !session.config.idle_timeout.is_zero() {
        let idle_session = session.clone();
        tokio::spawn(async move { idle_watchdog_v2(idle_session).await });
    }
    Ok(session)
}

struct SelfSession(EncryptedSessionV2);

#[derive(Clone, Debug)]
struct TerminalCauseV2 {
    kind: io::ErrorKind,
    message: String,
}

impl std::ops::Deref for SelfSession {
    type Target = EncryptedSessionV2;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for SelfSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

struct SessionRpcPeerV2 {
    session: OnceLock<Weak<SelfSession>>,
    serial: Mutex<()>,
    stream: Mutex<Option<Box<dyn ByteStreamV2>>>,
    read_buffer: Mutex<VecDeque<u8>>,
    next_request_id: AtomicU64,
}

struct PendingSessionRekeyV2 {
    payload: [u8; 20],
    sender: oneshot::Sender<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AckDispositionV2 {
    Pending,
    Duplicate,
}

fn classify_ack_v2<T: Eq>(
    pending: Option<&T>,
    last: Option<&T>,
    received: &T,
) -> io::Result<AckDispositionV2> {
    if pending.is_some_and(|value| value == received) {
        return Ok(AckDispositionV2::Pending);
    }
    if pending.is_none() && last.is_some_and(|value| value == received) {
        return Ok(AckDispositionV2::Duplicate);
    }
    Err(invalid("unexpected rekey ACK"))
}

impl std::fmt::Debug for SessionRpcPeerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionRpcPeerV2(..)")
    }
}

#[async_trait]
impl RpcPeerV2 for SessionRpcPeerV2 {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> io::Result<serde_json::Value> {
        rpc_call_v2(self, type_id, request).await
    }
    async fn notify(&self, type_id: u32, request: serde_json::Value) -> io::Result<()> {
        rpc_notify_v2(self, type_id, request).await
    }
}

#[async_trait]
impl SessionV2 for SelfSession {
    fn path(&self) -> PathKind {
        self.config.path
    }
    fn endpoint_instance_id(&self) -> Option<&str> {
        self.peer_endpoint_instance_id.as_deref()
    }
    fn rpc(&self) -> &dyn RpcPeerV2 {
        &self.rpc
    }
    async fn open_stream(
        &self,
        kind: &str,
        metadata: JsonObjectV2,
    ) -> io::Result<Box<dyn ByteStreamV2>> {
        if kind == RESERVED_RPC_KIND {
            return Err(invalid("reserved RPC stream kind"));
        }
        open_stream_v2(self, kind, metadata).await
    }
    async fn accept_stream(&self) -> io::Result<IncomingStreamV2> {
        let mut incoming = self.incoming_rx.lock().await;
        tokio::select! {
            biased;
            _ = self.canceled.cancelled() => Err(terminal_error_v2(self)),
            value = incoming.recv() => value.ok_or_else(|| terminal_error_v2(self)),
        }
    }
    async fn rekey(&self) -> io::Result<()> {
        rekey_v2(self).await
    }
    async fn probe_liveness(&self) -> io::Result<Duration> {
        probe_v2(self).await
    }
    async fn wait_closed(&self) -> io::Result<()> {
        self.canceled.cancelled().await;
        Err(terminal_error_v2(self))
    }
    async fn close(&self) -> io::Result<()> {
        close_session_v2(self).await
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "Flowersec v2 session closed",
    )
}

fn record_terminal_v2(session: &EncryptedSessionV2, error: &io::Error) {
    let mut terminal = session.terminal.lock().expect("terminal lock poisoned");
    if terminal.is_none() {
        *terminal = Some(TerminalCauseV2 {
            kind: error.kind(),
            message: error.to_string(),
        });
    }
}

fn terminal_error_v2(session: &EncryptedSessionV2) -> io::Error {
    session
        .terminal
        .lock()
        .expect("terminal lock poisoned")
        .as_ref()
        .map(|cause| io::Error::new(cause.kind, cause.message.clone()))
        .unwrap_or_else(closed)
}
fn proto(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

async fn client_handshake_v2(
    control: &Arc<dyn CarrierStreamV2>,
    config: &SessionConfigV2,
) -> io::Result<HandshakeMaterialV2> {
    let (private, public) =
        generate_ephemeral_keypair(handshake_suite(config.suite)).map_err(proto)?;
    let mut nonce = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let preface = control_preface_v2();
    let init = ClientInitWire {
        channel_id: config.channel_id.clone(),
        client_admission_binding_b64u: b64(&config.local_admission_binding),
        client_endpoint_instance_id: config
            .local_endpoint_instance_id
            .clone()
            .unwrap_or_default(),
        client_eph_pub_b64u: b64(&public),
        client_role: 1,
        max_inbound_streams: config.max_inbound_streams,
        nonce_c_b64u: b64(&nonce),
        profile: "flowersec/2".into(),
        selected_features: 0,
        session_contract_hash_b64u: b64(&config.session_contract_hash),
        suite: suite_id(config.suite),
    };
    let init_raw = handshake_frame_v2(1, &init)?;
    write_all_v2(control, &preface).await?;
    write_all_v2(control, &init_raw).await?;
    let server_raw = read_handshake_frame_v2(control, 2).await?;
    let server: ServerFinishedWire = canonical_handshake_v2(&server_raw[HANDSHAKE_HEADER_BYTES..])?;
    validate_server_v2(&server, config)?;
    let peer_public = decode_b64(&server.server_eph_pub_b64u)?;
    let shared = private.derive_shared_secret(&peer_public).map_err(proto)?;
    let handshake_prk = hkdf_extract_v2(&config.psk, shared.expose());
    let h0 = hash_parts(&[
        b"flowersec-v2-handshake\0",
        &preface,
        &length_prefix(&init_raw),
    ]);
    let core = ServerCoreWire {
        handshake_id: server.handshake_id.clone(),
        max_inbound_streams: server.max_inbound_streams,
        nonce_s_b64u: server.nonce_s_b64u.clone(),
        selected_features: server.selected_features,
        server_admission_binding_b64u: server.server_admission_binding_b64u.clone(),
        server_endpoint_instance_id: server.server_endpoint_instance_id.clone(),
        server_eph_pub_b64u: server.server_eph_pub_b64u.clone(),
        session_contract_hash_b64u: server.session_contract_hash_b64u.clone(),
    };
    let core_raw = handshake_frame_v2(2, &core)?;
    let h1 = hash_parts(&[&h0, &length_prefix(&core_raw)]);
    let expected_server = confirm_v2(&handshake_prk, b"flowersec v2 server finished", &h1)?;
    if decode_fixed_32(&server.server_confirm_b64u)? != expected_server {
        return Err(invalid("FSH2 server confirmation mismatch"));
    }
    let client_core = ClientCoreWire {
        handshake_id: server.handshake_id.clone(),
    };
    let client_core_raw = handshake_frame_v2(3, &client_core)?;
    let h2 = hash_parts(&[
        &h1,
        &length_prefix(&server_raw),
        &length_prefix(&client_core_raw),
    ]);
    let client_confirm = confirm_v2(&handshake_prk, b"flowersec v2 client finished", &h2)?;
    let finished = ClientFinishedWire {
        client_confirm_b64u: b64(&client_confirm),
        handshake_id: server.handshake_id,
    };
    let finished_raw = handshake_frame_v2(3, &finished)?;
    write_all_v2(control, &finished_raw).await?;
    let h3 = hash_parts(&[&h2, &length_prefix(&finished_raw)]);
    Ok(HandshakeMaterialV2 {
        h3,
        session_prk: hkdf_extract_v2(&h3, &handshake_prk),
        peer_endpoint_instance_id: nonempty(server.server_endpoint_instance_id),
    })
}

async fn server_handshake_v2(
    control: &Arc<dyn CarrierStreamV2>,
    config: &SessionConfigV2,
) -> io::Result<HandshakeMaterialV2> {
    let mut preface = [0; CONTROL_PREFACE_BYTES];
    read_exact_v2(control, &mut preface).await?;
    if preface != control_preface_v2() {
        return Err(invalid("invalid FSC2 control preface"));
    }
    let init_raw = read_handshake_frame_v2(control, 1).await?;
    let init: ClientInitWire = canonical_handshake_v2(&init_raw[HANDSHAKE_HEADER_BYTES..])?;
    validate_client_v2(&init, config)?;
    let (private, public) =
        generate_ephemeral_keypair(handshake_suite(config.suite)).map_err(proto)?;
    let peer_public = decode_b64(&init.client_eph_pub_b64u)?;
    let shared = private.derive_shared_secret(&peer_public).map_err(proto)?;
    let handshake_prk = hkdf_extract_v2(&config.psk, shared.expose());
    let mut nonce = [0; 32];
    let mut handshake_id = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    rand::rngs::OsRng.fill_bytes(&mut handshake_id);
    let core = ServerCoreWire {
        handshake_id: b64(&handshake_id),
        max_inbound_streams: config.max_inbound_streams,
        nonce_s_b64u: b64(&nonce),
        selected_features: 0,
        server_admission_binding_b64u: b64(&config.local_admission_binding),
        server_endpoint_instance_id: config
            .local_endpoint_instance_id
            .clone()
            .unwrap_or_default(),
        server_eph_pub_b64u: b64(&public),
        session_contract_hash_b64u: b64(&config.session_contract_hash),
    };
    let h0 = hash_parts(&[
        b"flowersec-v2-handshake\0",
        &preface,
        &length_prefix(&init_raw),
    ]);
    let core_raw = handshake_frame_v2(2, &core)?;
    let h1 = hash_parts(&[&h0, &length_prefix(&core_raw)]);
    let confirm = confirm_v2(&handshake_prk, b"flowersec v2 server finished", &h1)?;
    let finished = ServerFinishedWire {
        handshake_id: core.handshake_id.clone(),
        max_inbound_streams: core.max_inbound_streams,
        nonce_s_b64u: core.nonce_s_b64u.clone(),
        selected_features: core.selected_features,
        server_admission_binding_b64u: core.server_admission_binding_b64u.clone(),
        server_confirm_b64u: b64(&confirm),
        server_endpoint_instance_id: core.server_endpoint_instance_id.clone(),
        server_eph_pub_b64u: core.server_eph_pub_b64u.clone(),
        session_contract_hash_b64u: core.session_contract_hash_b64u.clone(),
    };
    let server_raw = handshake_frame_v2(2, &finished)?;
    write_all_v2(control, &server_raw).await?;
    let client_raw = read_handshake_frame_v2(control, 3).await?;
    let client: ClientFinishedWire = canonical_handshake_v2(&client_raw[HANDSHAKE_HEADER_BYTES..])?;
    if client.handshake_id != core.handshake_id {
        return Err(invalid("FSH2 handshake ID mismatch"));
    }
    let client_core_raw = handshake_frame_v2(
        3,
        &ClientCoreWire {
            handshake_id: client.handshake_id.clone(),
        },
    )?;
    let h2 = hash_parts(&[
        &h1,
        &length_prefix(&server_raw),
        &length_prefix(&client_core_raw),
    ]);
    let expected_client = confirm_v2(&handshake_prk, b"flowersec v2 client finished", &h2)?;
    if decode_fixed_32(&client.client_confirm_b64u)? != expected_client {
        return Err(invalid("FSH2 client confirmation mismatch"));
    }
    let h3 = hash_parts(&[&h2, &length_prefix(&client_raw)]);
    Ok(HandshakeMaterialV2 {
        h3,
        session_prk: hkdf_extract_v2(&h3, &handshake_prk),
        peer_endpoint_instance_id: nonempty(init.client_endpoint_instance_id),
    })
}

fn validate_client_v2(init: &ClientInitWire, config: &SessionConfigV2) -> io::Result<()> {
    if init.profile != "flowersec/2"
        || init.channel_id != config.channel_id
        || init.client_role != 1
        || init.suite != suite_id(config.suite)
        || init.selected_features != 0
        || init.max_inbound_streams != config.max_inbound_streams
        || decode_fixed_32(&init.session_contract_hash_b64u)? != config.session_contract_hash
    {
        return Err(invalid("invalid FSH2 CLIENT_INIT"));
    }
    validate_peer_binding_v2(&init.client_admission_binding_b64u, config)?;
    validate_peer_endpoint_v2(&init.client_endpoint_instance_id, config)
}

fn validate_server_v2(server: &ServerFinishedWire, config: &SessionConfigV2) -> io::Result<()> {
    if server.selected_features != 0
        || server.max_inbound_streams != config.max_inbound_streams
        || decode_fixed_32(&server.session_contract_hash_b64u)? != config.session_contract_hash
        || decode_b64(&server.handshake_id)?.len() != 16
    {
        return Err(invalid("invalid FSH2 SERVER_FINISHED"));
    }
    validate_peer_binding_v2(&server.server_admission_binding_b64u, config)?;
    validate_peer_endpoint_v2(&server.server_endpoint_instance_id, config)
}

fn validate_peer_binding_v2(encoded: &str, config: &SessionConfigV2) -> io::Result<()> {
    let got = decode_fixed_32(encoded)?;
    if got == [0; 32]
        || config
            .peer_admission_binding
            .is_some_and(|expected| expected != got)
    {
        return Err(invalid("FSH2 admission binding mismatch"));
    }
    Ok(())
}

fn validate_peer_endpoint_v2(got: &str, config: &SessionConfigV2) -> io::Result<()> {
    let valid = match config.path {
        PathKind::Direct => got.is_empty(),
        PathKind::Tunnel => config
            .expected_peer_endpoint_instance_id
            .as_deref()
            .is_some_and(|expected| expected == got),
    };
    if !valid {
        return Err(invalid("FSH2 endpoint instance mismatch"));
    }
    Ok(())
}

fn handshake_suite(suite: CipherSuiteV2) -> Suite {
    match suite {
        CipherSuiteV2::ChaCha20Poly1305 => Suite::X25519HkdfSha256Aes256Gcm,
        CipherSuiteV2::Aes256Gcm => Suite::P256HkdfSha256Aes256Gcm,
    }
}
fn suite_id(suite: CipherSuiteV2) -> u16 {
    match suite {
        CipherSuiteV2::ChaCha20Poly1305 => 1,
        CipherSuiteV2::Aes256Gcm => 2,
    }
}
fn control_preface_v2() -> [u8; CONTROL_PREFACE_BYTES] {
    let mut raw = [0; CONTROL_PREFACE_BYTES];
    raw[..4].copy_from_slice(b"FSC2");
    raw[4] = 2;
    raw[5] = 1;
    raw
}
fn handshake_frame_v2<T: Serialize>(kind: u8, message: &T) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_vec(message).map_err(proto)?;
    if payload.is_empty() || payload.len() > MAX_HANDSHAKE_PAYLOAD_BYTES {
        return Err(invalid("FSH2 payload length"));
    }
    let mut raw = Vec::with_capacity(HANDSHAKE_HEADER_BYTES + payload.len());
    raw.extend_from_slice(b"FSH2");
    raw.extend_from_slice(&[2, kind, 0, 0]);
    raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    raw.extend_from_slice(&payload);
    Ok(raw)
}
async fn read_handshake_frame_v2(
    control: &Arc<dyn CarrierStreamV2>,
    kind: u8,
) -> io::Result<Vec<u8>> {
    let mut header = [0; HANDSHAKE_HEADER_BYTES];
    read_exact_v2(control, &mut header).await?;
    if &header[..4] != b"FSH2"
        || header[4] != 2
        || header[5] != kind
        || header[6] != 0
        || header[7] != 0
    {
        return Err(invalid("invalid FSH2 header"));
    }
    let length = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_HANDSHAKE_PAYLOAD_BYTES {
        return Err(invalid("invalid FSH2 length"));
    }
    let mut raw = header.to_vec();
    raw.resize(HANDSHAKE_HEADER_BYTES + length, 0);
    read_exact_v2(control, &mut raw[HANDSHAKE_HEADER_BYTES..]).await?;
    Ok(raw)
}
fn canonical_handshake_v2<T>(payload: &[u8]) -> io::Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(payload).map_err(proto)?;
    if serde_json::to_vec(&value).map_err(proto)? != payload {
        return Err(invalid("non-canonical FSH2 JSON"));
    }
    Ok(value)
}
fn b64(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}
fn decode_b64(value: &str) -> io::Result<Vec<u8>> {
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(proto)?;
    if b64(&raw) != value {
        return Err(invalid("non-canonical base64url"));
    }
    Ok(raw)
}
fn decode_fixed_32(value: &str) -> io::Result<[u8; 32]> {
    decode_b64(value)?
        .try_into()
        .map_err(|_| invalid("expected 32-byte base64url value"))
}
fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
fn length_prefix(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + raw.len());
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(raw);
    out
}
fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
fn hkdf_extract_v2(salt: &[u8], input: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), input);
    let mut out = [0; 32];
    out.copy_from_slice(prk.as_ref());
    out
}
fn confirm_v2(prk: &[u8; 32], label: &[u8], transcript: &[u8; 32]) -> io::Result<[u8; 32]> {
    let mut info = label.to_vec();
    info.extend_from_slice(transcript);
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(proto)?;
    let mut key = [0; 32];
    hkdf.expand(&info, &mut key).map_err(proto)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(proto)?;
    mac.update(transcript);
    Ok(mac.finalize().into_bytes().into())
}

async fn finish_ready_v2(session: &EncryptedSessionV2) -> io::Result<()> {
    match session.config.role {
        SessionRole::Server => {
            send_control_v2(session, InnerRecordTypeV2::SessionReady, &[]).await?;
            let (kind, _) = read_control_v2(session).await?;
            if kind != InnerRecordTypeV2::SessionReadyAck {
                return Err(invalid("expected SESSION_READY_ACK"));
            }
        }
        SessionRole::Client => {
            let (kind, _) = read_control_v2(session).await?;
            if kind != InnerRecordTypeV2::SessionReady {
                return Err(invalid("expected SESSION_READY"));
            }
            send_control_v2(session, InnerRecordTypeV2::SessionReadyAck, &[]).await?;
        }
    }
    session.ready.notify_waiters();
    Ok(())
}

async fn send_control_v2(
    session: &EncryptedSessionV2,
    kind: InnerRecordTypeV2,
    payload: &[u8],
) -> io::Result<()> {
    let _write = session.control_write.lock().await;
    let inner = encode_inner_record_v2(kind, payload).map_err(proto)?;
    let (epoch, sequence, key, nonce) = {
        let mut state = session.state.lock().await;
        let epoch = state.send_epoch;
        let sequence = state.control_send_sequence;
        state.control_send_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("control sequence exhausted"))?;
        let roots = state
            .send_roots
            .get(&epoch)
            .ok_or_else(|| invalid("missing send epoch roots"))?;
        let material = derive_control_material_v2(
            roots.control_root(),
            &session.h3,
            session.send_direction,
            epoch,
        )
        .map_err(proto)?;
        (
            epoch,
            sequence,
            *material.record_key(),
            *material.nonce_prefix(),
        )
    };
    let header = RecordHeaderV2::new(epoch, sequence, (inner.len() + AEAD_TAG_V2_SIZE) as u32);
    let ciphertext = seal_record_v2(
        session.config.suite,
        &key,
        &nonce,
        &session.h3,
        0,
        session.send_direction,
        &header,
        &inner,
    )
    .map_err(proto)?;
    write_all_v2(&session.control, &header.encode().map_err(proto)?).await?;
    write_all_v2(&session.control, &ciphertext).await?;
    touch_activity_v2(session);
    Ok(())
}

async fn read_control_v2(session: &EncryptedSessionV2) -> io::Result<(InnerRecordTypeV2, Vec<u8>)> {
    let mut raw_header = [0; RECORD_HEADER_V2_SIZE];
    read_exact_v2(&session.control, &mut raw_header).await?;
    let header = RecordHeaderV2::decode(&raw_header).map_err(proto)?;
    let mut ciphertext = vec![0; header.ciphertext_length() as usize];
    read_exact_v2(&session.control, &mut ciphertext).await?;
    let (key, nonce) = {
        let mut state = session.state.lock().await;
        if header.epoch() == state.control_recv_epoch {
            if header.sequence() != state.control_recv_sequence {
                return Err(invalid("invalid control sequence"));
            }
            state.control_recv_sequence = state
                .control_recv_sequence
                .checked_add(1)
                .ok_or_else(|| invalid("control sequence exhausted"))?;
        } else if header.epoch() == state.recv_epoch
            && header.epoch() == state.control_recv_epoch.saturating_add(1)
            && header.sequence() == 0
        {
            state.control_recv_epoch = header.epoch();
            state.control_recv_sequence = 1;
        } else {
            return Err(invalid("invalid control epoch"));
        }
        let roots = state
            .recv_roots
            .get(&header.epoch())
            .ok_or_else(|| invalid("missing receive epoch roots"))?;
        let material = derive_control_material_v2(
            roots.control_root(),
            &session.h3,
            session.recv_direction,
            header.epoch(),
        )
        .map_err(proto)?;
        (*material.record_key(), *material.nonce_prefix())
    };
    let plaintext = open_record_v2(
        session.config.suite,
        &key,
        &nonce,
        &session.h3,
        0,
        session.recv_direction,
        &header,
        &ciphertext,
    )
    .map_err(proto)?;
    let (kind, payload) = decode_inner_record_v2(&plaintext).map_err(proto)?;
    touch_activity_v2(session);
    Ok((kind, payload.to_vec()))
}

async fn control_loop_v2(session: Arc<SelfSession>) {
    loop {
        let result = read_control_v2(&session).await;
        let (kind, payload) = match result {
            Ok(value) => value,
            Err(error) => {
                fail_session_v2(&session, error);
                return;
            }
        };
        let handled = match kind {
            InnerRecordTypeV2::Ping => {
                send_control_v2(&session, InnerRecordTypeV2::Pong, &payload).await
            }
            InnerRecordTypeV2::Pong => {
                if payload.len() != 8 {
                    Err(invalid("invalid PONG"))
                } else {
                    let nonce = u64::from_be_bytes(payload[..8].try_into().unwrap());
                    if let Some(waiter) = session.pings.take(nonce) {
                        let _ = waiter.send(Instant::now());
                    }
                    Ok(())
                }
            }
            InnerRecordTypeV2::SessionKeyUpdate => receive_rekey_v2(&session, &payload).await,
            InnerRecordTypeV2::SessionKeyUpdateAck => {
                if payload.len() != 20 {
                    Err(invalid("invalid SESSION_KEY_UPDATE_ACK"))
                } else {
                    let transition = u64::from_be_bytes(payload[..8].try_into().unwrap());
                    let received: [u8; 20] = payload.as_slice().try_into().unwrap();
                    let disposition = {
                        let rekeys = session.rekeys.lock().await;
                        let last = session.last_session_rekey_ack.lock().await;
                        classify_ack_v2(
                            rekeys.get(&transition).map(|pending| &pending.payload),
                            last.as_ref(),
                            &received,
                        )
                    };
                    match disposition {
                        Ok(AckDispositionV2::Pending) => {
                            match session.rekeys.lock().await.remove(&transition) {
                                Some(pending) => {
                                    *session.last_session_rekey_ack.lock().await = Some(received);
                                    let _ = pending.sender.send(());
                                    Ok(())
                                }
                                None => Err(invalid("missing pending rekey ACK")),
                            }
                        }
                        Ok(AckDispositionV2::Duplicate) => Ok(()),
                        Err(_) => Err(invalid("unexpected SESSION_KEY_UPDATE_ACK")),
                    }
                }
            }
            InnerRecordTypeV2::StreamReset => receive_stream_reset_v2(&session, &payload).await,
            InnerRecordTypeV2::GoAway => receive_goaway_v2(&session, &payload).await,
            InnerRecordTypeV2::SessionClose => {
                validate_session_close_payload_v2(&payload).and_then(|()| Err(closed()))
            }
            _ => Err(invalid("unexpected control record")),
        };
        if let Err(error) = handled {
            fail_session_v2(&session, error);
            return;
        }
    }
}

async fn probe_v2(session: &EncryptedSessionV2) -> io::Result<Duration> {
    if session.closed.load(Ordering::Acquire) {
        return Err(closed());
    }
    let nonce = session.next_ping.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    let _pending = session.pings.register(nonce, tx)?;
    let start = Instant::now();
    send_control_v2(session, InnerRecordTypeV2::Ping, &nonce.to_be_bytes()).await?;
    let end = tokio::select! {
        _ = session.canceled.cancelled() => return Err(closed()),
        result = tokio::time::timeout(Duration::from_secs(10), rx) => {
            result
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Flowersec v2 liveness timeout"))?
                .map_err(|_| closed())?
        }
    };
    Ok(end.duration_since(start))
}

async fn rekey_v2(session: &EncryptedSessionV2) -> io::Result<()> {
    let session = session
        .self_weak
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(closed)?;
    let prepared = tokio::time::timeout(
        session.config.deadlines.rekey_prepare,
        prepare_rekey_v2(&session),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "Flowersec v2 rekey prepare timeout",
        )
    })??;
    // The prepared plan has no wire or epoch side effects. Ownership moves
    // before the first irreversible rekey record can be written.
    let (sender, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let result = run_owned_rekey_v2(&session, prepared).await;
        if let Err(error) = &result {
            fail_session_v2(&session, io::Error::new(error.kind(), error.to_string()));
        }
        let _ = sender.send(result);
    });
    receiver.await.map_err(|_| closed())?
}

struct PreparedRekeyV2 {
    transition: u64,
    next_epoch: u32,
    next_roots: EpochRootsV2,
    streams: Vec<Arc<EncryptedStreamV2>>,
    payload: [u8; 20],
    _rekey_lock: OwnedMutexGuard<()>,
    _open_lock: OwnedMutexGuard<()>,
    _responder_freeze: InboundResponderFreezeGuardV2,
    _activity: RekeyActivityGuardV2,
}

struct CommittedRekeyV2 {
    transition: u64,
    next_epoch: u32,
    streams: Vec<Arc<EncryptedStreamV2>>,
    session_ack: oneshot::Receiver<()>,
}

struct RekeyActivityGuardV2 {
    session: Arc<SelfSession>,
}

impl RekeyActivityGuardV2 {
    fn new(session: Arc<SelfSession>) -> Self {
        session.rekeying.store(true, Ordering::Release);
        Self { session }
    }
}

impl Drop for RekeyActivityGuardV2 {
    fn drop(&mut self) {
        self.session.rekeying.store(false, Ordering::Release);
        self.session.rekey_changed.notify_waiters();
    }
}

async fn prepare_rekey_v2(session: &Arc<SelfSession>) -> io::Result<PreparedRekeyV2> {
    let rekey_lock = session.rekey_lock.clone().lock_owned().await;
    let open_lock = session.open_lock.clone().lock_owned().await;
    if session.closed.load(Ordering::Acquire) {
        return Err(terminal_error_v2(session));
    }
    let activity = RekeyActivityGuardV2::new(session.clone());
    let responder_freeze = freeze_inbound_responders_v2(session, false).await?;
    let watermark = session.local_open_high_watermark.load(Ordering::Acquire);
    wait_outbound_frontier_v2(session, watermark).await?;
    let (next_epoch, next_roots) = {
        let state = session.state.lock().await;
        let next = state
            .send_epoch
            .checked_add(1)
            .ok_or_else(|| invalid("session epoch exhausted"))?;
        let roots = state
            .send_roots
            .get(&state.send_epoch)
            .ok_or_else(|| invalid("missing send epoch roots"))?;
        let next_roots = derive_next_epoch_v2(
            roots.rekey_root(),
            &session.h3,
            session.send_direction,
            next,
        )
        .map_err(proto)?;
        (next, next_roots)
    };
    let transition = session.next_transition.load(Ordering::Acquire);
    if transition == 0 || transition.checked_add(1).is_none() {
        return Err(invalid("rekey transition exhausted"));
    }
    let streams = active_send_streams_v2(session);
    let mut payload = [0; 20];
    payload[..8].copy_from_slice(&transition.to_be_bytes());
    payload[8..12].copy_from_slice(&next_epoch.to_be_bytes());
    payload[12..20].copy_from_slice(&watermark.to_be_bytes());
    Ok(PreparedRekeyV2 {
        transition,
        next_epoch,
        next_roots,
        streams,
        payload,
        _rekey_lock: rekey_lock,
        _open_lock: open_lock,
        _responder_freeze: responder_freeze,
        _activity: activity,
    })
}

async fn run_owned_rekey_v2(session: &SelfSession, prepared: PreparedRekeyV2) -> io::Result<()> {
    match tokio::time::timeout(
        session.config.deadlines.rekey_completion,
        commit_and_complete_rekey_v2(session, prepared),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Flowersec v2 rekey completion timeout",
        )),
    }
}

async fn commit_and_complete_rekey_v2(
    session: &EncryptedSessionV2,
    prepared: PreparedRekeyV2,
) -> io::Result<()> {
    let next_transition = prepared
        .transition
        .checked_add(1)
        .ok_or_else(|| invalid("rekey transition exhausted"))?;
    session
        .next_transition
        .compare_exchange(
            prepared.transition,
            next_transition,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| invalid("rekey transition changed during prepare"))?;
    {
        let mut state = session.state.lock().await;
        if state
            .send_epoch
            .checked_add(1)
            .ok_or_else(|| invalid("session epoch exhausted"))?
            != prepared.next_epoch
        {
            return Err(invalid("session epoch changed during rekey prepare"));
        }
        state
            .send_roots
            .insert(prepared.next_epoch, prepared.next_roots.clone());
    }
    let (tx, rx) = oneshot::channel();
    session.rekeys.lock().await.insert(
        prepared.transition,
        PendingSessionRekeyV2 {
            payload: prepared.payload,
            sender: tx,
        },
    );
    for stream in &prepared.streams {
        stream
            .send_stream_update(prepared.transition, prepared.next_epoch)
            .await?;
    }
    if let Err(error) = send_control_v2(
        session,
        InnerRecordTypeV2::SessionKeyUpdate,
        &prepared.payload,
    )
    .await
    {
        session.rekeys.lock().await.remove(&prepared.transition);
        return Err(error);
    }
    complete_rekey_v2(
        session,
        CommittedRekeyV2 {
            transition: prepared.transition,
            next_epoch: prepared.next_epoch,
            streams: prepared.streams.clone(),
            session_ack: rx,
        },
    )
    .await
}

async fn wait_outbound_frontier_v2(session: &EncryptedSessionV2, watermark: u64) -> io::Result<()> {
    loop {
        let changed = session.outbound_ledger_changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let frontier = session.outbound_ledger.lock().await.frontier();
        if frontier == watermark {
            return Ok(());
        }
        if frontier > watermark {
            return Err(invalid("outbound ledger frontier exceeded watermark"));
        }
        tokio::select! {
            _ = session.canceled.cancelled() => return Err(closed()),
            () = &mut changed => {}
        }
    }
}

async fn complete_rekey_v2(
    session: &EncryptedSessionV2,
    prepared: CommittedRekeyV2,
) -> io::Result<()> {
    prepared.session_ack.await.map_err(|_| closed())?;
    {
        let mut state = session.state.lock().await;
        state.send_epoch = prepared.next_epoch;
        state.control_send_sequence = 0;
    }
    for stream in prepared.streams {
        stream
            .await_stream_update_ack(prepared.transition, prepared.next_epoch)
            .await?;
    }
    {
        let mut state = session.state.lock().await;
        let current = state.send_epoch;
        retain_current_epoch_roots_v2(&mut state.send_roots, current);
        let current = state.recv_epoch;
        retain_current_epoch_roots_v2(&mut state.recv_roots, current);
    }
    Ok(())
}

async fn receive_rekey_v2(session: &EncryptedSessionV2, payload: &[u8]) -> io::Result<()> {
    tokio::time::timeout(session.config.deadlines.rekey_completion, async {
        let _responder_freeze = freeze_inbound_responders_v2(session, true).await?;
        receive_rekey_inner_v2(session, payload).await
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "Flowersec v2 peer rekey completion timeout",
        )
    })?
}

async fn receive_rekey_inner_v2(session: &EncryptedSessionV2, payload: &[u8]) -> io::Result<()> {
    if payload.len() != 20 {
        return Err(invalid("invalid SESSION_KEY_UPDATE"));
    }
    let transition = u64::from_be_bytes(payload[..8].try_into().unwrap());
    let next = u32::from_be_bytes(payload[8..12].try_into().unwrap());
    let watermark = u64::from_be_bytes(payload[12..20].try_into().unwrap());
    let expected_transition = session
        .recv_transition
        .load(Ordering::Acquire)
        .checked_add(1)
        .ok_or_else(|| invalid("receive transition exhausted"))?;
    if transition == 0 || transition != expected_transition {
        return Err(invalid("non-consecutive receive transition"));
    }
    {
        let mut state = session.state.lock().await;
        if next
            != state
                .recv_epoch
                .checked_add(1)
                .ok_or_else(|| invalid("session epoch exhausted"))?
        {
            return Err(invalid("non-consecutive session epoch"));
        }
        let roots = state
            .recv_roots
            .get(&state.recv_epoch)
            .ok_or_else(|| invalid("missing receive epoch roots"))?;
        let next_roots = derive_next_epoch_v2(
            roots.rekey_root(),
            &session.h3,
            session.recv_direction,
            next,
        )
        .map_err(proto)?;
        state.recv_roots.insert(next, next_roots);
    }
    if session.peer_ledger.lock().await.frontier() != watermark {
        return Err(invalid("rekey watermark does not match resolved frontier"));
    }
    let streams = active_receive_streams_v2(session);
    for stream in &streams {
        stream.await_stream_update(transition, next).await?;
    }
    {
        let mut state = session.state.lock().await;
        state.recv_epoch = next;
    }
    session.recv_transition.store(transition, Ordering::Release);
    for stream in streams {
        let mut update = stream.recv_update.lock().await;
        if *update == Some((transition, next)) {
            *update = None;
        }
    }
    send_control_v2(session, InnerRecordTypeV2::SessionKeyUpdateAck, payload).await?;
    if !session.rekeying.load(Ordering::Acquire) {
        let mut state = session.state.lock().await;
        let current = state.recv_epoch;
        retain_current_epoch_roots_v2(&mut state.recv_roots, current);
    }
    Ok(())
}

fn retain_current_epoch_roots_v2(roots: &mut HashMap<u32, EpochRootsV2>, current: u32) {
    roots.retain(|epoch, _| *epoch == current);
}

fn encode_stream_key_update_ack_v2(logical_id: u64, transition: u64, next_epoch: u32) -> [u8; 20] {
    let mut payload = [0; 20];
    payload[..8].copy_from_slice(&logical_id.to_be_bytes());
    payload[8..16].copy_from_slice(&transition.to_be_bytes());
    payload[16..].copy_from_slice(&next_epoch.to_be_bytes());
    payload
}

fn decode_stream_key_update_ack_v2(payload: &[u8]) -> io::Result<(u64, u64, u32)> {
    if payload.len() != 20 {
        return Err(invalid("invalid STREAM_KEY_UPDATE_ACK"));
    }
    Ok((
        u64::from_be_bytes(payload[..8].try_into().unwrap()),
        u64::from_be_bytes(payload[8..16].try_into().unwrap()),
        u32::from_be_bytes(payload[16..20].try_into().unwrap()),
    ))
}

fn active_send_streams_v2(session: &EncryptedSessionV2) -> Vec<Arc<EncryptedStreamV2>> {
    session
        .streams
        .lock()
        .expect("stream registry poisoned")
        .values()
        .filter_map(Weak::upgrade)
        .filter(|stream| {
            !stream.reset.load(Ordering::Acquire) && !stream.local_fin.load(Ordering::Acquire)
        })
        .collect()
}

fn active_receive_streams_v2(session: &EncryptedSessionV2) -> Vec<Arc<EncryptedStreamV2>> {
    session
        .streams
        .lock()
        .expect("stream registry poisoned")
        .values()
        .filter_map(Weak::upgrade)
        .filter(|stream| {
            !stream.reset.load(Ordering::Acquire) && !stream.remote_fin.load(Ordering::Acquire)
        })
        .collect()
}

async fn receive_stream_reset_v2(session: &EncryptedSessionV2, payload: &[u8]) -> io::Result<()> {
    let id = validate_stream_reset_payload_v2(payload)?;
    let stream = session
        .streams
        .lock()
        .expect("stream registry poisoned")
        .get(&id)
        .and_then(Weak::upgrade);
    if let Some(stream) = stream {
        stream.reset_local().await?;
    }
    if session.peer_ledger.lock().await.index(id).is_ok() {
        session.peer_ledger.lock().await.mark_peer_reset(id)?;
    } else if session.outbound_ledger.lock().await.index(id).is_ok() {
        session.outbound_ledger.lock().await.mark_peer_reset(id)?;
        session.outbound_ledger_changed.notify_waiters();
    } else {
        return Err(invalid("invalid STREAM_RESET logical stream ID"));
    }
    Ok(())
}

fn validate_stream_reset_payload_v2(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 10 || u16::from_be_bytes(payload[8..].try_into().unwrap()) == 0 {
        return Err(invalid("invalid STREAM_RESET"));
    }
    Ok(u64::from_be_bytes(payload[..8].try_into().unwrap()))
}

async fn receive_goaway_v2(session: &EncryptedSessionV2, payload: &[u8]) -> io::Result<()> {
    if payload.len() != 10 {
        return Err(invalid("invalid GOAWAY"));
    }
    let last = u64::from_be_bytes(payload[..8].try_into().unwrap());
    let reason = u16::from_be_bytes(payload[8..10].try_into().unwrap());
    let high = session.local_open_high_watermark.load(Ordering::Acquire);
    let valid = valid_goaway_boundary_v2(session.config.role, last, high);
    if reason == 0 || !valid {
        return Err(invalid("invalid GOAWAY boundary"));
    }
    if session.received_goaway.swap(true, Ordering::AcqRel)
        && session.received_goaway_last.load(Ordering::Acquire) != last
    {
        return Err(invalid("GOAWAY boundary changed"));
    }
    session.received_goaway_last.store(last, Ordering::Release);
    Ok(())
}

fn valid_goaway_boundary_v2(role: SessionRole, last: u64, high: u64) -> bool {
    last == 0
        || (last <= high
            && match role {
                SessionRole::Client => last & 1 == 1,
                SessionRole::Server => last & 1 == 0,
            })
}

async fn send_goaway_v2(session: &EncryptedSessionV2, reason: u16) -> io::Result<()> {
    if reason == 0 {
        return Err(invalid("invalid GOAWAY reason"));
    }
    let last = session.peer_ledger.lock().await.frontier();
    session.sent_goaway.store(true, Ordering::Release);
    session.sent_goaway_last.store(last, Ordering::Release);
    let mut payload = [0; 10];
    payload[..8].copy_from_slice(&last.to_be_bytes());
    payload[8..].copy_from_slice(&reason.to_be_bytes());
    send_control_v2(session, InnerRecordTypeV2::GoAway, &payload).await
}

async fn close_session_v2(session: &EncryptedSessionV2) -> io::Result<()> {
    if !session.closed.swap(true, Ordering::AcqRel) {
        record_terminal_v2(session, &closed());
        session.canceled.cancel();
        let deadline = tokio::time::Instant::now() + session.config.deadlines.close_flush;
        let flush = match tokio::time::timeout_at(deadline, async {
            send_goaway_v2(session, NORMAL_CLOSE_REASON_V2).await?;
            send_control_v2(
                session,
                InnerRecordTypeV2::SessionClose,
                &NORMAL_CLOSE_REASON_V2.to_be_bytes(),
            )
            .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Flowersec v2 close flush timeout",
            )),
        };
        let carrier = match tokio::time::timeout_at(deadline, session.carrier.close()).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Flowersec v2 carrier close timeout",
            )),
        };
        flush?;
        carrier?;
    }
    Ok(())
}

fn validate_session_close_payload_v2(payload: &[u8]) -> io::Result<()> {
    if payload.len() != 2 || u16::from_be_bytes(payload.try_into().unwrap()) == 0 {
        return Err(invalid("invalid SESSION_CLOSE reason"));
    }
    Ok(())
}

fn touch_activity_v2(session: &EncryptedSessionV2) {
    session.activity_generation.fetch_add(1, Ordering::AcqRel);
    session.activity_changed.notify_waiters();
}

async fn idle_watchdog_v2(session: Arc<SelfSession>) {
    let idle_timeout = session.config.idle_timeout;
    let mut observed = session.activity_generation.load(Ordering::Acquire);
    loop {
        let changed = session.activity_changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let current = session.activity_generation.load(Ordering::Acquire);
        if current != observed {
            observed = current;
            continue;
        }
        tokio::select! {
            _ = session.canceled.cancelled() => return,
            () = &mut changed => {
                observed = session.activity_generation.load(Ordering::Acquire);
            }
            () = tokio::time::sleep(idle_timeout) => {
                if session.activity_generation.load(Ordering::Acquire) != observed {
                    observed = session.activity_generation.load(Ordering::Acquire);
                    continue;
                }
                if !session.closed.swap(true, Ordering::AcqRel) {
                    record_terminal_v2(
                        &session,
                        &io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Flowersec v2 session idle timeout",
                        ),
                    );
                    session.canceled.cancel();
                    let _ = tokio::time::timeout(
                        session.config.deadlines.close_flush,
                        send_goaway_v2(&session, IDLE_TIMEOUT_REASON_V2),
                    )
                    .await;
                    let _ = tokio::time::timeout(
                        session.config.deadlines.close_flush,
                        session.carrier.close(),
                    )
                    .await;
                }
                return;
            }
        }
    }
}

fn fail_session_v2(session: &EncryptedSessionV2, error: io::Error) {
    if !session.closed.swap(true, Ordering::AcqRel) {
        record_terminal_v2(session, &error);
        session.canceled.cancel();
        let carrier = session.carrier.clone();
        let close_timeout = session.config.deadlines.close_flush;
        tokio::spawn(async move {
            let _ = tokio::time::timeout(close_timeout, carrier.close()).await;
        });
    }
}

struct OutboundOpenGuardV2 {
    session: Weak<SelfSession>,
    id: u64,
    carrier: Option<Arc<dyn CarrierStreamV2>>,
    armed: bool,
}

impl OutboundOpenGuardV2 {
    fn new(session: &Arc<SelfSession>, id: u64) -> Self {
        Self {
            session: Arc::downgrade(session),
            id,
            carrier: None,
            armed: true,
        }
    }

    fn set_carrier(&mut self, carrier: Arc<dyn CarrierStreamV2>) {
        self.carrier = Some(carrier);
    }

    async fn abandon(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let Some(session) = self.session.upgrade() else {
            return;
        };
        let id = self.id;
        let carrier = self.carrier.clone();
        let completion = tokio::spawn(async move {
            commit_outbound_abandonment_v2(session, id, carrier).await;
        });
        let _ = completion.await;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for OutboundOpenGuardV2 {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(session) = self.session.upgrade() else {
            return;
        };
        let id = self.id;
        let carrier = self.carrier.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                commit_outbound_abandonment_v2(session, id, carrier).await;
            });
        }
    }
}

async fn commit_outbound_abandonment_v2(
    session: Arc<SelfSession>,
    id: u64,
    carrier: Option<Arc<dyn CarrierStreamV2>>,
) {
    if let Some(carrier) = carrier {
        let _ = carrier.reset().await;
    }
    let mut payload = [0; 10];
    payload[..8].copy_from_slice(&id.to_be_bytes());
    payload[8..].copy_from_slice(&6_u16.to_be_bytes());
    if let Err(error) = send_control_v2(&session, InnerRecordTypeV2::StreamReset, &payload).await {
        if !session.closed.load(Ordering::Acquire) {
            fail_session_v2(&session, error);
        }
        return;
    }
    if let Err(error) = session.outbound_ledger.lock().await.mark_terminal(id) {
        fail_session_v2(&session, error);
        return;
    }
    session.outbound_ledger_changed.notify_waiters();
}

struct EncryptedStreamV2 {
    session: Weak<SelfSession>,
    carrier: Arc<dyn CarrierStreamV2>,
    id: u64,
    kind: String,
    send_epoch: AtomicU64,
    send_sequence: AtomicU64,
    recv_epoch: AtomicU64,
    recv_sequence: AtomicU64,
    prior_ack: Mutex<Option<(u32, u64)>>,
    recv_update: Mutex<Option<(u64, u32)>>,
    send_update: Mutex<Option<(u64, u32)>>,
    send_update_ack: Mutex<Option<(u64, u32)>>,
    send_update_changed: Notify,
    buffered_reads: Mutex<VecDeque<Option<Bytes>>>,
    send_lock: Mutex<()>,
    read_lock: Mutex<()>,
    local_fin: AtomicBool,
    remote_fin: AtomicBool,
    reset: AtomicBool,
    _outbound_permit: StdMutex<Option<tokio::sync::OwnedSemaphorePermit>>,
    _inbound_permit: StdMutex<Option<tokio::sync::OwnedSemaphorePermit>>,
}

impl std::fmt::Debug for EncryptedStreamV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedStreamV2")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("send_epoch", &self.send_epoch.load(Ordering::Acquire))
            .field("recv_epoch", &self.recv_epoch.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

async fn open_stream_v2(
    session: &SelfSession,
    kind: &str,
    metadata: JsonObjectV2,
) -> io::Result<Box<dyn ByteStreamV2>> {
    open_stream_with_capacity_v2(session, kind, metadata, true).await
}

async fn open_reserved_rpc_stream_v2(session: &SelfSession) -> io::Result<Box<dyn ByteStreamV2>> {
    open_stream_with_capacity_v2(session, RESERVED_RPC_KIND, JsonObjectV2::new(), false).await
}

async fn open_stream_with_capacity_v2(
    session: &SelfSession,
    kind: &str,
    metadata: JsonObjectV2,
    counts_toward_data_limit: bool,
) -> io::Result<Box<dyn ByteStreamV2>> {
    if session.closed.load(Ordering::Acquire) {
        return Err(closed());
    }
    let permit = if counts_toward_data_limit {
        Some(tokio::select! {
            biased;
            _ = session.canceled.cancelled() => return Err(terminal_error_v2(session)),
            permit = session.outbound_permits.clone().acquire_owned() => {
                permit.map_err(|_| terminal_error_v2(session))?
            }
        })
    } else {
        None
    };
    let _open = session.open_lock.lock().await;
    loop {
        let changed = session.rekey_changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if !session.rekeying.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            biased;
            _ = session.canceled.cancelled() => return Err(terminal_error_v2(session)),
            () = &mut changed => {}
        }
    }
    if session.closed.load(Ordering::Acquire) {
        return Err(terminal_error_v2(session));
    }
    if session.received_goaway.load(Ordering::Acquire) {
        return Err(going_away());
    }
    let id = session
        .next_stream_id
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(2))
        .map_err(|_| invalid("logical stream ID exhausted"))?;
    if let Err(error) = session.outbound_ledger.lock().await.mark_fss2(id) {
        let _ = send_goaway_v2(session, 5).await;
        return Err(error);
    }
    session
        .local_open_high_watermark
        .store(id, Ordering::Release);
    session.outbound_ledger_changed.notify_waiters();
    let owner = session_arc(session)?;
    let mut guard = OutboundOpenGuardV2::new(&owner, id);
    let carrier = match session.carrier.open_stream().await {
        Ok(carrier) => carrier,
        Err(error) => {
            guard.abandon().await;
            return Err(error);
        }
    };
    guard.set_carrier(carrier.clone());
    if !local_open_allowed_after_goaway_v2(session, id) {
        guard.abandon().await;
        return Err(going_away());
    }
    let (epoch, receive_epoch, setup_root) = {
        let state = session.state.lock().await;
        let Some(roots) = state.send_roots.get(&state.send_epoch) else {
            drop(state);
            guard.abandon().await;
            return Err(invalid("missing send roots"));
        };
        (state.send_epoch, state.recv_epoch, *roots.setup_root())
    };
    let role = match session.config.role {
        SessionRole::Client => StreamOpenerRoleV2::Client,
        SessionRole::Server => StreamOpenerRoleV2::Server,
    };
    let mut preface = SetupPrefaceV2::new(role, id, epoch);
    let setup_mac = match compute_setup_mac_v2(&setup_root, &session.h3, &preface) {
        Ok(value) => value,
        Err(error) => {
            guard.abandon().await;
            return Err(proto(error));
        }
    };
    preface.set_setup_mac(setup_mac);
    let raw_preface = match preface.encode() {
        Ok(value) => value,
        Err(error) => {
            guard.abandon().await;
            return Err(proto(error));
        }
    };
    if let Err(error) = write_all_v2(&carrier, &raw_preface).await {
        guard.abandon().await;
        return Err(error);
    }
    if !local_open_allowed_after_goaway_v2(session, id) {
        guard.abandon().await;
        return Err(going_away());
    }
    let fss2_hash = match compute_fss2_hash_v2(&raw_preface) {
        Ok(value) => value,
        Err(error) => {
            guard.abandon().await;
            return Err(proto(error));
        }
    };
    let metadata_raw = match serde_json::to_vec(&metadata) {
        Ok(value) => value,
        Err(error) => {
            guard.abandon().await;
            return Err(proto(error));
        }
    };
    let open = match encode_open_payload_v2(&OpenPayloadV2::new(
        id,
        fss2_hash,
        kind.to_owned(),
        metadata_raw,
    )) {
        Ok(value) => value,
        Err(error) => {
            guard.abandon().await;
            return Err(proto(error));
        }
    };
    if let Err(error) = write_stream_record_v2(
        session,
        &carrier,
        id,
        epoch,
        0,
        InnerRecordTypeV2::Open,
        &open,
    )
    .await
    {
        guard.abandon().await;
        return Err(error);
    }
    if !local_open_allowed_after_goaway_v2(session, id) {
        guard.abandon().await;
        return Err(going_away());
    }
    let (response, payload, response_epoch, response_sequence) =
        match read_stream_record_v2(session, &carrier, id).await {
            Ok(value) => value,
            Err(error) => {
                guard.abandon().await;
                return Err(error);
            }
        };
    if response_epoch != receive_epoch || response_sequence != 0 {
        guard.abandon().await;
        return Err(invalid("invalid OPEN response epoch/sequence"));
    }
    let open_hash = match compute_open_hash_v2(&open) {
        Ok(value) => value,
        Err(error) => {
            guard.abandon().await;
            return Err(proto(error));
        }
    };
    match response {
        InnerRecordTypeV2::OpenAck if payload == open_hash => {
            mark_outbound_resolved_v2(session, id).await?;
        }
        InnerRecordTypeV2::OpenReject => {
            let _reason = match validate_open_reject_payload_v2(&payload, &open_hash) {
                Ok(reason) => reason,
                Err(error) => {
                    guard.abandon().await;
                    return Err(error);
                }
            };
            mark_outbound_resolved_v2(session, id).await?;
            let _ = carrier.reset().await;
            guard.disarm();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "logical stream rejected",
            ));
        }
        _ => {
            guard.abandon().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid OPEN response kind={response:?} payload_len={} hash_match={}",
                    payload.len(),
                    payload == open_hash
                ),
            ));
        }
    }
    if !local_open_allowed_after_goaway_v2(session, id) {
        guard.abandon().await;
        return Err(going_away());
    }
    let stream = Arc::new(EncryptedStreamV2 {
        session: Arc::downgrade(&owner),
        carrier,
        id,
        kind: kind.to_owned(),
        send_epoch: AtomicU64::new(u64::from(epoch)),
        send_sequence: AtomicU64::new(1),
        recv_epoch: AtomicU64::new(u64::from(response_epoch)),
        recv_sequence: AtomicU64::new(1),
        prior_ack: Mutex::new(None),
        recv_update: Mutex::new(None),
        send_update: Mutex::new(None),
        send_update_ack: Mutex::new(None),
        send_update_changed: Notify::new(),
        buffered_reads: Mutex::new(VecDeque::new()),
        send_lock: Mutex::new(()),
        read_lock: Mutex::new(()),
        local_fin: AtomicBool::new(false),
        remote_fin: AtomicBool::new(false),
        reset: AtomicBool::new(false),
        _outbound_permit: StdMutex::new(permit),
        _inbound_permit: StdMutex::new(None),
    });
    session
        .streams
        .lock()
        .expect("stream registry poisoned")
        .insert(id, Arc::downgrade(&stream));
    guard.disarm();
    Ok(Box::new(StreamHandleV2(stream)))
}

fn going_away() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "peer is going away")
}

fn local_open_allowed_after_goaway_v2(session: &EncryptedSessionV2, id: u64) -> bool {
    !session.received_goaway.load(Ordering::Acquire)
        || (session.received_goaway_last.load(Ordering::Acquire) != 0
            && id <= session.received_goaway_last.load(Ordering::Acquire))
}

async fn mark_outbound_resolved_v2(session: &EncryptedSessionV2, id: u64) -> io::Result<()> {
    session.outbound_ledger.lock().await.mark_terminal(id)?;
    session.outbound_ledger_changed.notify_waiters();
    Ok(())
}

// Public methods receive `&SelfSession`; recover the owning Arc from a weak
// registry entry created during establishment without exposing self-references.
fn session_arc(session: &SelfSession) -> io::Result<Arc<SelfSession>> {
    session
        .self_weak
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(closed)
}

#[derive(Clone)]
struct StreamHandleV2(Arc<EncryptedStreamV2>);

impl std::fmt::Debug for StreamHandleV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

fn validate_open_reject_payload_v2(
    payload: &[u8],
    expected_open_hash: &[u8; 32],
) -> io::Result<u16> {
    if payload.len() != 34 || payload[..32] != expected_open_hash[..] {
        return Err(invalid("invalid OPEN_REJECT hash"));
    }
    let reason = u16::from_be_bytes(payload[32..34].try_into().unwrap());
    if reason == 0 {
        return Err(invalid("invalid OPEN_REJECT reason"));
    }
    Ok(reason)
}

#[async_trait]
impl ByteStreamV2 for StreamHandleV2 {
    fn id(&self) -> u64 {
        self.0.id
    }
    fn kind(&self) -> &str {
        &self.0.kind
    }
    fn terminal_error(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        None
    }
    async fn read(&self) -> io::Result<Option<Bytes>> {
        self.0.read_next().await
    }
    async fn write(&self, payload: Bytes) -> io::Result<usize> {
        self.0.write_data(payload).await
    }
    async fn close_write(&self) -> io::Result<()> {
        self.0.close_write_inner().await
    }
    async fn reset(&self) -> io::Result<()> {
        self.0.reset_inner().await
    }
    async fn close(&self) -> io::Result<()> {
        let _ = self.0.close_write_inner().await;
        let result = self.0.carrier.close().await;
        self.0.release_capacity();
        result
    }
}

impl EncryptedStreamV2 {
    async fn write_data(&self, payload: Bytes) -> io::Result<usize> {
        if payload.is_empty() {
            return Ok(0);
        }
        if self.local_fin.load(Ordering::Acquire) || self.reset.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "logical stream send direction closed",
            ));
        }
        let length = payload.len().min(MAX_DATA_V2_BYTES);
        self.write_record(InnerRecordTypeV2::Data, &payload[..length])
            .await?;
        Ok(length)
    }
    async fn close_write_inner(&self) -> io::Result<()> {
        if !self.local_fin.swap(true, Ordering::AcqRel) {
            self.write_record(InnerRecordTypeV2::Fin, &[]).await?;
            self.carrier.close_write().await?;
        }
        self.release_if_clean();
        Ok(())
    }
    async fn reset_inner(&self) -> io::Result<()> {
        if !self.reset.swap(true, Ordering::AcqRel) {
            if let Some(session) = self.session.upgrade() {
                let mut payload = [0; 10];
                payload[..8].copy_from_slice(&self.id.to_be_bytes());
                payload[8..].copy_from_slice(&1_u16.to_be_bytes());
                let _ = send_control_v2(&session, InnerRecordTypeV2::StreamReset, &payload).await;
            }
            self.carrier.reset().await?;
        }
        self.release_capacity();
        Ok(())
    }
    async fn reset_local(&self) -> io::Result<()> {
        self.reset.store(true, Ordering::Release);
        let result = self.carrier.reset().await;
        self.release_capacity();
        result
    }
    async fn write_record(&self, kind: InnerRecordTypeV2, payload: &[u8]) -> io::Result<()> {
        let session = self.session.upgrade().ok_or_else(closed)?;
        let _lock = self.send_lock.lock().await;
        let epoch = self.send_epoch.load(Ordering::Acquire) as u32;
        let sequence = self.send_sequence.fetch_add(1, Ordering::AcqRel);
        write_stream_record_v2(
            &session,
            &self.carrier,
            self.id,
            epoch,
            sequence,
            kind,
            payload,
        )
        .await
    }
    async fn read_next(&self) -> io::Result<Option<Bytes>> {
        if let Some(buffered) = self.buffered_reads.lock().await.pop_front() {
            return Ok(buffered);
        }
        let session = self.session.upgrade().ok_or_else(closed)?;
        let _lock = self.read_lock.lock().await;
        loop {
            let (kind, payload, epoch, sequence) =
                read_stream_record_v2(&session, &self.carrier, self.id).await?;
            let prior = *self.prior_ack.lock().await;
            if kind == InnerRecordTypeV2::StreamKeyUpdateAck && prior == Some((epoch, sequence)) {
                *self.prior_ack.lock().await = None;
            } else {
                self.accept_normal_header(epoch, sequence)?;
            }
            match kind {
                InnerRecordTypeV2::Data => return Ok(Some(Bytes::from(payload))),
                InnerRecordTypeV2::Fin => {
                    self.remote_fin.store(true, Ordering::Release);
                    self.release_if_clean();
                    return Ok(None);
                }
                InnerRecordTypeV2::StreamKeyUpdate => {
                    self.handle_stream_update_locked(&session, &payload).await?;
                }
                InnerRecordTypeV2::StreamKeyUpdateAck => {
                    self.process_stream_update_ack(&payload).await?;
                }
                _ => return Err(invalid("unexpected logical stream record")),
            }
        }
    }

    fn accept_normal_header(&self, epoch: u32, sequence: u64) -> io::Result<()> {
        let expected_epoch = self.recv_epoch.load(Ordering::Acquire) as u32;
        let expected_sequence = self.recv_sequence.load(Ordering::Acquire);
        if epoch != expected_epoch || sequence != expected_sequence {
            return Err(invalid("logical stream epoch or sequence mismatch"));
        }
        self.recv_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| invalid("logical stream receive sequence exhausted"))?;
        Ok(())
    }

    fn release_if_clean(&self) {
        if self.local_fin.load(Ordering::Acquire) && self.remote_fin.load(Ordering::Acquire) {
            self.release_capacity();
        }
    }

    fn release_capacity(&self) {
        self._outbound_permit
            .lock()
            .expect("outbound permit lock poisoned")
            .take();
        self._inbound_permit
            .lock()
            .expect("inbound permit lock poisoned")
            .take();
    }

    async fn send_stream_update(&self, transition: u64, next_epoch: u32) -> io::Result<()> {
        {
            let mut pending = self.send_update.lock().await;
            if pending.is_some() {
                return Err(invalid("stream rekey already pending"));
            }
            *pending = Some((transition, next_epoch));
            *self.send_update_ack.lock().await = None;
        }
        let mut payload = [0; 12];
        payload[..8].copy_from_slice(&transition.to_be_bytes());
        payload[8..].copy_from_slice(&next_epoch.to_be_bytes());
        if let Err(error) = self
            .write_record(InnerRecordTypeV2::StreamKeyUpdate, &payload)
            .await
        {
            *self.send_update.lock().await = None;
            return Err(error);
        }
        Ok(())
    }

    async fn await_stream_update(&self, transition: u64, next_epoch: u32) -> io::Result<()> {
        if *self.recv_update.lock().await == Some((transition, next_epoch)) {
            return Ok(());
        }
        let session = self.session.upgrade().ok_or_else(closed)?;
        let _read = self.read_lock.lock().await;
        loop {
            if *self.recv_update.lock().await == Some((transition, next_epoch)) {
                return Ok(());
            }
            let (kind, payload, epoch, sequence) =
                read_stream_record_v2(&session, &self.carrier, self.id).await?;
            self.accept_normal_header(epoch, sequence)?;
            match kind {
                InnerRecordTypeV2::Data => self
                    .buffered_reads
                    .lock()
                    .await
                    .push_back(Some(Bytes::from(payload))),
                InnerRecordTypeV2::Fin => {
                    self.remote_fin.store(true, Ordering::Release);
                    self.buffered_reads.lock().await.push_back(None);
                    self.release_if_clean();
                    return Ok(());
                }
                InnerRecordTypeV2::StreamKeyUpdate => {
                    self.handle_stream_update_locked(&session, &payload).await?;
                    if *self.recv_update.lock().await != Some((transition, next_epoch)) {
                        return Err(invalid("stream rekey transition mismatch"));
                    }
                    return Ok(());
                }
                _ => return Err(invalid("unexpected record while awaiting stream rekey")),
            }
        }
    }

    async fn handle_stream_update_locked(
        &self,
        session: &EncryptedSessionV2,
        payload: &[u8],
    ) -> io::Result<()> {
        if payload.len() != 12 {
            return Err(invalid("invalid STREAM_KEY_UPDATE"));
        }
        let transition = u64::from_be_bytes(payload[..8].try_into().unwrap());
        let next_epoch = u32::from_be_bytes(payload[8..12].try_into().unwrap());
        let current_epoch = self.recv_epoch.load(Ordering::Acquire) as u32;
        if transition == 0
            || next_epoch
                != current_epoch
                    .checked_add(1)
                    .ok_or_else(|| invalid("stream epoch exhausted"))?
        {
            return Err(invalid("invalid stream rekey transition"));
        }
        if self.recv_update.lock().await.is_some() {
            return Err(invalid("duplicate stream rekey transition"));
        }
        {
            let mut state = session.state.lock().await;
            if !state.recv_roots.contains_key(&next_epoch) {
                let roots = state
                    .recv_roots
                    .get(&current_epoch)
                    .ok_or_else(|| invalid("missing receive roots"))?;
                let next = derive_next_epoch_v2(
                    roots.rekey_root(),
                    &session.h3,
                    session.recv_direction,
                    next_epoch,
                )
                .map_err(proto)?;
                state.recv_roots.insert(next_epoch, next);
            }
        }
        let prior_sequence = self.recv_sequence.load(Ordering::Acquire);
        *self.prior_ack.lock().await = Some((current_epoch, prior_sequence));
        self.recv_epoch
            .store(u64::from(next_epoch), Ordering::Release);
        self.recv_sequence.store(0, Ordering::Release);
        *self.recv_update.lock().await = Some((transition, next_epoch));
        let ack = encode_stream_key_update_ack_v2(self.id, transition, next_epoch);
        self.write_record(InnerRecordTypeV2::StreamKeyUpdateAck, &ack)
            .await
    }

    async fn await_stream_update_ack(&self, transition: u64, next_epoch: u32) -> io::Result<()> {
        let session = self.session.upgrade().ok_or_else(closed)?;
        loop {
            if *self.send_update_ack.lock().await == Some((transition, next_epoch)) {
                return Ok(());
            }
            let changed = self.send_update_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            tokio::select! {
                () = &mut changed => continue,
                read = self.read_lock.lock() => {
                    let _read = read;
                    if *self.send_update_ack.lock().await == Some((transition, next_epoch)) {
                        return Ok(());
                    }
                    let (kind, payload, epoch, sequence) =
                        read_stream_record_v2(&session, &self.carrier, self.id).await?;
                    let prior = *self.prior_ack.lock().await;
                    if kind == InnerRecordTypeV2::StreamKeyUpdateAck
                        && prior == Some((epoch, sequence))
                    {
                        *self.prior_ack.lock().await = None;
                    } else {
                        self.accept_normal_header(epoch, sequence)?;
                    }
                    match kind {
                        InnerRecordTypeV2::StreamKeyUpdateAck => {
                            self.process_stream_update_ack(&payload).await?;
                        }
                        InnerRecordTypeV2::Data => self
                            .buffered_reads
                            .lock()
                            .await
                            .push_back(Some(Bytes::from(payload))),
                        InnerRecordTypeV2::Fin => {
                            self.remote_fin.store(true, Ordering::Release);
                            self.buffered_reads.lock().await.push_back(None);
                            self.release_if_clean();
                        }
                        InnerRecordTypeV2::StreamKeyUpdate => {
                            self.handle_stream_update_locked(&session, &payload).await?;
                        }
                        _ => return Err(invalid("unexpected record while awaiting stream rekey ACK")),
                    }
                }
            }
        }
    }

    async fn process_stream_update_ack(&self, payload: &[u8]) -> io::Result<()> {
        let (logical_id, transition, next_epoch) = decode_stream_key_update_ack_v2(payload)?;
        if logical_id != self.id {
            return Err(invalid("invalid STREAM_KEY_UPDATE_ACK"));
        }
        let pending = *self.send_update.lock().await;
        let last = *self.send_update_ack.lock().await;
        let received = (transition, next_epoch);
        match classify_ack_v2(pending.as_ref(), last.as_ref(), &received) {
            Ok(AckDispositionV2::Duplicate) => return Ok(()),
            Ok(AckDispositionV2::Pending) => {}
            Err(_) => return Err(invalid("unexpected STREAM_KEY_UPDATE_ACK")),
        }
        self.send_epoch
            .store(u64::from(next_epoch), Ordering::Release);
        self.send_sequence.store(0, Ordering::Release);
        *self.send_update.lock().await = None;
        *self.send_update_ack.lock().await = Some((transition, next_epoch));
        self.send_update_changed.notify_waiters();
        Ok(())
    }
}

async fn accept_carrier_loop_v2(session: Arc<SelfSession>) {
    loop {
        tokio::select! {
            _ = session.canceled.cancelled() => return,
            accepted = session.carrier.accept_stream() => match accepted {
                Ok(carrier) => {
                    let session = session.clone();
                    tokio::spawn(async move {
                        if let Err(error) = accept_one_stream_v2(session.clone(), carrier).await {
                            if !session.closed.load(Ordering::Acquire) { fail_session_v2(&session, error); }
                        }
                    });
                }
                Err(error) => { fail_session_v2(&session, error); return; }
            }
        }
    }
}

async fn accept_one_stream_v2(
    session: Arc<SelfSession>,
    carrier: Arc<dyn CarrierStreamV2>,
) -> io::Result<()> {
    let responder = enter_inbound_responder_v2(&session).await?;
    let mut raw_preface = [0; SETUP_PREFACE_V2_SIZE];
    if read_exact_v2(&carrier, &mut raw_preface).await.is_err() {
        let _ = carrier.reset().await;
        return Ok(());
    }
    let preface = match SetupPrefaceV2::decode(&raw_preface) {
        Ok(preface) => preface,
        Err(_) => {
            let _ = carrier.reset().await;
            return Ok(());
        }
    };
    let peer_role = match session.config.role {
        SessionRole::Client => StreamOpenerRoleV2::Server,
        SessionRole::Server => StreamOpenerRoleV2::Client,
    };
    if preface.opener_role() != peer_role {
        let _ = carrier.reset().await;
        return Ok(());
    }
    let setup_root = {
        let state = session.state.lock().await;
        if preface.initial_epoch() != state.recv_epoch {
            return Err(invalid("invalid FSS2 epoch"));
        }
        let Some(roots) = state.recv_roots.get(&state.recv_epoch) else {
            drop(state);
            let _ = carrier.reset().await;
            return Ok(());
        };
        *roots.setup_root()
    };
    if !verify_setup_mac_v2(&setup_root, &session.h3, &preface) {
        let _ = carrier.reset().await;
        return Ok(());
    }
    let id = preface.logical_stream_id();
    if session.sent_goaway.load(Ordering::Acquire)
        && (session.sent_goaway_last.load(Ordering::Acquire) == 0
            || id > session.sent_goaway_last.load(Ordering::Acquire))
    {
        carrier.reset().await?;
        return Ok(());
    }
    {
        let mut ledger = session.peer_ledger.lock().await;
        if ledger.state(ledger.index(id)?) == LedgerStateV2::AbandonedNoFss2 {
            ledger.mark_late_fss2_for_abandoned(id)?;
            drop(ledger);
            carrier.reset().await?;
            return Ok(());
        }
        ledger.mark_fss2(id)?;
    }
    let (kind, open_raw, epoch, sequence) = read_stream_record_v2(&session, &carrier, id).await?;
    if kind != InnerRecordTypeV2::Open || epoch != preface.initial_epoch() || sequence != 0 {
        return Err(invalid("invalid initial OPEN"));
    }
    let open = decode_open_payload_v2(&open_raw).map_err(proto)?;
    let fss2_hash = compute_fss2_hash_v2(&raw_preface).map_err(proto)?;
    if open.logical_stream_id() != id || open.fss2_hash() != &fss2_hash {
        return Err(invalid("OPEN does not bind FSS2"));
    }
    let metadata: JsonObjectV2 = serde_json::from_slice(open.metadata()).map_err(proto)?;
    let reserved_rpc = open.kind() == RESERVED_RPC_KIND;
    let permit = if reserved_rpc {
        if session
            .inbound_rpc_opened
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            carrier.reset().await?;
            return Err(invalid("duplicate reserved RPC stream"));
        }
        None
    } else {
        Some(tokio::select! {
            _ = session.canceled.cancelled() => return Err(closed()),
            permit = session.inbound_permits.clone().acquire_owned() => {
                permit.map_err(|_| closed())?
            }
        })
    };
    let ack = compute_open_hash_v2(&open_raw).map_err(proto)?;
    let send_epoch = session.state.lock().await.send_epoch;
    write_stream_record_v2(
        &session,
        &carrier,
        id,
        send_epoch,
        0,
        InnerRecordTypeV2::OpenAck,
        &ack,
    )
    .await?;
    let stream = Arc::new(EncryptedStreamV2 {
        session: Arc::downgrade(&session),
        carrier,
        id,
        kind: open.kind().to_owned(),
        send_epoch: AtomicU64::new(u64::from(send_epoch)),
        send_sequence: AtomicU64::new(1),
        recv_epoch: AtomicU64::new(u64::from(epoch)),
        recv_sequence: AtomicU64::new(1),
        prior_ack: Mutex::new(None),
        recv_update: Mutex::new(None),
        send_update: Mutex::new(None),
        send_update_ack: Mutex::new(None),
        send_update_changed: Notify::new(),
        buffered_reads: Mutex::new(VecDeque::new()),
        send_lock: Mutex::new(()),
        read_lock: Mutex::new(()),
        local_fin: AtomicBool::new(false),
        remote_fin: AtomicBool::new(false),
        reset: AtomicBool::new(false),
        _outbound_permit: StdMutex::new(None),
        _inbound_permit: StdMutex::new(permit),
    });
    session
        .streams
        .lock()
        .expect("stream registry poisoned")
        .insert(id, Arc::downgrade(&stream));
    session.peer_ledger.lock().await.mark_terminal(id)?;
    if reserved_rpc {
        drop(responder);
        return serve_rpc_stream_v2(&session, StreamHandleV2(stream)).await;
    }
    session
        .incoming_tx
        .send(IncomingStreamV2::new(
            open.kind(),
            metadata,
            Box::new(StreamHandleV2(stream)),
        ))
        .await
        .map_err(|_| closed())
}

struct InboundResponderGuardV2 {
    session: Weak<SelfSession>,
}

impl Drop for InboundResponderGuardV2 {
    fn drop(&mut self) {
        let Some(session) = self.session.upgrade() else {
            return;
        };
        let mut state = session
            .inbound_responders
            .lock()
            .expect("inbound responder state poisoned");
        state.active = state.active.saturating_sub(1);
        drop(state);
        session.inbound_responders_changed.notify_waiters();
    }
}

struct InboundResponderFreezeGuardV2 {
    session: Weak<SelfSession>,
    peer: bool,
}

impl Drop for InboundResponderFreezeGuardV2 {
    fn drop(&mut self) {
        let Some(session) = self.session.upgrade() else {
            return;
        };
        let mut state = session
            .inbound_responders
            .lock()
            .expect("inbound responder state poisoned");
        if self.peer {
            state.peer_frozen = false;
        } else {
            state.local_frozen = false;
        }
        drop(state);
        session.inbound_responders_changed.notify_waiters();
    }
}

async fn enter_inbound_responder_v2(
    session: &Arc<SelfSession>,
) -> io::Result<InboundResponderGuardV2> {
    loop {
        let changed = session.inbound_responders_changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        {
            let mut state = session
                .inbound_responders
                .lock()
                .expect("inbound responder state poisoned");
            if !state.local_frozen && !state.peer_frozen {
                state.active = state
                    .active
                    .checked_add(1)
                    .ok_or_else(|| invalid("inbound responder count exhausted"))?;
                return Ok(InboundResponderGuardV2 {
                    session: Arc::downgrade(session),
                });
            }
        }
        tokio::select! {
            _ = session.canceled.cancelled() => return Err(closed()),
            () = &mut changed => {}
        }
    }
}

async fn freeze_inbound_responders_v2(
    session: &EncryptedSessionV2,
    peer: bool,
) -> io::Result<InboundResponderFreezeGuardV2> {
    let weak = session.self_weak.get().cloned().ok_or_else(closed)?;
    {
        let mut state = session
            .inbound_responders
            .lock()
            .expect("inbound responder state poisoned");
        if peer {
            state.peer_frozen = true;
        } else {
            state.local_frozen = true;
        }
    }
    session.inbound_responders_changed.notify_waiters();
    let guard = InboundResponderFreezeGuardV2 {
        session: weak,
        peer,
    };
    loop {
        let changed = session.inbound_responders_changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if session
            .inbound_responders
            .lock()
            .expect("inbound responder state poisoned")
            .active
            == 0
        {
            return Ok(guard);
        }
        tokio::select! {
            _ = session.canceled.cancelled() => return Err(closed()),
            () = &mut changed => {}
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEnvelopeWireV2 {
    type_id: u32,
    request_id: u64,
    response_to: u64,
    payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcErrorWireV2>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcErrorWireV2 {
    code: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

const MAX_RPC_FRAME_BYTES: usize = 1 << 20;
const MAX_PORTABLE_RPC_ID: u64 = (1_u64 << 53) - 1;

async fn rpc_call_v2(
    peer: &SessionRpcPeerV2,
    type_id: u32,
    request: serde_json::Value,
) -> io::Result<serde_json::Value> {
    let _serial = peer.serial.lock().await;
    let request_id = peer
        .next_request_id
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            (value < MAX_PORTABLE_RPC_ID).then_some(value + 1)
        })
        .map_err(|_| invalid("portable RPC request ID exhausted"))?;
    let envelope = RpcEnvelopeWireV2 {
        type_id,
        request_id,
        response_to: 0,
        payload: request,
        error: None,
    };
    let session = peer
        .session
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(closed)?;
    let mut stream = peer.stream.lock().await;
    if stream.is_none() {
        *stream = Some(open_reserved_rpc_stream_v2(&session).await?);
    }
    let stream = stream.as_deref().ok_or_else(closed)?;
    write_rpc_frame_v2(stream, &envelope).await?;
    loop {
        let response = read_rpc_frame_v2(stream, &peer.read_buffer).await?;
        if response.response_to != request_id {
            if response.response_to == 0 && response.request_id == 0 {
                continue;
            }
            return Err(invalid("RPC response ID mismatch"));
        }
        if let Some(error) = response.error {
            return Err(io::Error::other(
                error
                    .message
                    .unwrap_or_else(|| format!("RPC error {}", error.code)),
            ));
        }
        return Ok(response.payload);
    }
}

async fn rpc_notify_v2(
    peer: &SessionRpcPeerV2,
    type_id: u32,
    request: serde_json::Value,
) -> io::Result<()> {
    let _serial = peer.serial.lock().await;
    let session = peer
        .session
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(closed)?;
    let mut stream = peer.stream.lock().await;
    if stream.is_none() {
        *stream = Some(open_reserved_rpc_stream_v2(&session).await?);
    }
    write_rpc_frame_v2(
        stream.as_deref().ok_or_else(closed)?,
        &RpcEnvelopeWireV2 {
            type_id,
            request_id: 0,
            response_to: 0,
            payload: request,
            error: None,
        },
    )
    .await
}

async fn serve_rpc_stream_v2(session: &SelfSession, stream: StreamHandleV2) -> io::Result<()> {
    let read_buffer = Mutex::new(VecDeque::new());
    loop {
        let request = read_rpc_frame_v2(&stream, &read_buffer).await?;
        if request.response_to != 0 || request.error.is_some() {
            return Err(invalid("invalid RPC request envelope"));
        }
        let handler = session.config.rpc_handler.as_ref();
        if request.request_id == 0 {
            if let Some(handler) = handler {
                handler.notify(request.type_id, request.payload).await?;
            }
            continue;
        }
        let (payload, error) = match handler {
            Some(handler) => match handler.call(request.type_id, request.payload).await {
                Ok(payload) => (payload, None),
                Err(error) => (
                    serde_json::Value::Null,
                    Some(RpcErrorWireV2 {
                        code: 500,
                        message: Some(error.to_string()),
                    }),
                ),
            },
            None => (
                serde_json::Value::Null,
                Some(RpcErrorWireV2 {
                    code: 404,
                    message: Some("handler not found".into()),
                }),
            ),
        };
        write_rpc_frame_v2(
            &stream,
            &RpcEnvelopeWireV2 {
                type_id: request.type_id,
                request_id: 0,
                response_to: request.request_id,
                payload,
                error,
            },
        )
        .await?;
    }
}

async fn write_rpc_frame_v2(
    stream: &dyn ByteStreamV2,
    envelope: &RpcEnvelopeWireV2,
) -> io::Result<()> {
    let json = serde_json::to_vec(envelope).map_err(proto)?;
    if json.len() > MAX_RPC_FRAME_BYTES {
        return Err(invalid("RPC JSON frame too large"));
    }
    let mut raw = Vec::with_capacity(4 + json.len());
    raw.extend_from_slice(&(json.len() as u32).to_be_bytes());
    raw.extend_from_slice(&json);
    let mut remaining = raw.as_slice();
    while !remaining.is_empty() {
        let written = stream.write(Bytes::copy_from_slice(remaining)).await?;
        if written == 0 || written > remaining.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "RPC stream accepted no bytes",
            ));
        }
        remaining = &remaining[written..];
    }
    Ok(())
}

async fn read_rpc_frame_v2(
    stream: &dyn ByteStreamV2,
    buffer: &Mutex<VecDeque<u8>>,
) -> io::Result<RpcEnvelopeWireV2> {
    fill_rpc_bytes_v2(stream, buffer, 4).await?;
    let length = {
        let mut buffer = buffer.lock().await;
        let header = [
            buffer.pop_front().unwrap(),
            buffer.pop_front().unwrap(),
            buffer.pop_front().unwrap(),
            buffer.pop_front().unwrap(),
        ];
        u32::from_be_bytes(header) as usize
    };
    if length > MAX_RPC_FRAME_BYTES {
        return Err(invalid("RPC JSON frame too large"));
    }
    fill_rpc_bytes_v2(stream, buffer, length).await?;
    let json = {
        let mut buffer = buffer.lock().await;
        buffer.drain(..length).collect::<Vec<_>>()
    };
    serde_json::from_slice(&json).map_err(proto)
}

async fn fill_rpc_bytes_v2(
    stream: &dyn ByteStreamV2,
    buffer: &Mutex<VecDeque<u8>>,
    needed: usize,
) -> io::Result<()> {
    while buffer.lock().await.len() < needed {
        let chunk = stream
            .read()
            .await?
            .ok_or_else(|| invalid("RPC stream truncated"))?;
        buffer.lock().await.extend(chunk);
    }
    Ok(())
}

async fn write_stream_record_v2(
    session: &EncryptedSessionV2,
    carrier: &Arc<dyn CarrierStreamV2>,
    id: u64,
    epoch: u32,
    sequence: u64,
    kind: InnerRecordTypeV2,
    payload: &[u8],
) -> io::Result<()> {
    let inner = encode_inner_record_v2(kind, payload).map_err(proto)?;
    let (key, nonce) = {
        let state = session.state.lock().await;
        let roots = state
            .send_roots
            .get(&epoch)
            .ok_or_else(|| invalid("missing stream send roots"))?;
        let material = derive_stream_material_v2(
            roots.stream_root(),
            &session.h3,
            id,
            session.send_direction,
            epoch,
        )
        .map_err(proto)?;
        (*material.record_key(), *material.nonce_prefix())
    };
    let header = RecordHeaderV2::new(
        epoch,
        sequence,
        (INNER_HEADER_V2_SIZE + payload.len() + AEAD_TAG_V2_SIZE) as u32,
    );
    let ciphertext = seal_record_v2(
        session.config.suite,
        &key,
        &nonce,
        &session.h3,
        id,
        session.send_direction,
        &header,
        &inner,
    )
    .map_err(proto)?;
    write_all_v2(carrier, &header.encode().map_err(proto)?).await?;
    write_all_v2(carrier, &ciphertext).await?;
    touch_activity_v2(session);
    Ok(())
}

async fn read_stream_record_v2(
    session: &EncryptedSessionV2,
    carrier: &Arc<dyn CarrierStreamV2>,
    id: u64,
) -> io::Result<(InnerRecordTypeV2, Vec<u8>, u32, u64)> {
    let mut raw = [0; RECORD_HEADER_V2_SIZE];
    read_exact_v2(carrier, &mut raw).await?;
    let header = RecordHeaderV2::decode(&raw).map_err(proto)?;
    let mut ciphertext = vec![0; header.ciphertext_length() as usize];
    read_exact_v2(carrier, &mut ciphertext).await?;
    let (key, nonce) = {
        let state = session.state.lock().await;
        let roots = state
            .recv_roots
            .get(&header.epoch())
            .ok_or_else(|| invalid("missing stream receive roots"))?;
        let material = derive_stream_material_v2(
            roots.stream_root(),
            &session.h3,
            id,
            session.recv_direction,
            header.epoch(),
        )
        .map_err(proto)?;
        (*material.record_key(), *material.nonce_prefix())
    };
    let plaintext = open_record_v2(
        session.config.suite,
        &key,
        &nonce,
        &session.h3,
        id,
        session.recv_direction,
        &header,
        &ciphertext,
    )
    .map_err(proto)?;
    let (kind, payload) = decode_inner_record_v2(&plaintext).map_err(proto)?;
    touch_activity_v2(session);
    Ok((kind, payload.to_vec(), header.epoch(), header.sequence()))
}

/// Creates a deterministic in-process carrier pair for protocol tests.
pub fn memory_carrier_pair_v2() -> (Arc<dyn CarrierSessionV2>, Arc<dyn CarrierSessionV2>) {
    memory_carrier_pair_v2_with_capacity(6)
}

/// Creates a deterministic carrier pair with an explicit physical capacity.
pub fn memory_carrier_pair_v2_with_capacity(
    inbound_bidirectional_stream_capacity: u32,
) -> (Arc<dyn CarrierSessionV2>, Arc<dyn CarrierSessionV2>) {
    let (client_tx, client_rx) = mpsc::channel(64);
    let (server_tx, server_rx) = mpsc::channel(64);
    (
        Arc::new(MemoryCarrierSessionV2 {
            outgoing: server_tx,
            incoming: Mutex::new(client_rx),
            canceled: CancellationToken::new(),
            inbound_bidirectional_stream_capacity,
        }),
        Arc::new(MemoryCarrierSessionV2 {
            outgoing: client_tx,
            incoming: Mutex::new(server_rx),
            canceled: CancellationToken::new(),
            inbound_bidirectional_stream_capacity,
        }),
    )
}

struct MemoryCarrierSessionV2 {
    outgoing: mpsc::Sender<Arc<dyn CarrierStreamV2>>,
    incoming: Mutex<mpsc::Receiver<Arc<dyn CarrierStreamV2>>>,
    canceled: CancellationToken,
    inbound_bidirectional_stream_capacity: u32,
}

impl std::fmt::Debug for MemoryCarrierSessionV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemoryCarrierSessionV2(..)")
    }
}

#[async_trait]
impl CarrierSessionV2 for MemoryCarrierSessionV2 {
    fn kind(&self) -> CarrierKind {
        CarrierKind::RawQuic
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inbound_bidirectional_stream_capacity
    }
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        if self.canceled.is_cancelled() {
            return Err(closed());
        }
        let (local, peer) = tokio::io::duplex(256 * 1024);
        let local: Arc<dyn CarrierStreamV2> = Arc::new(MemoryCarrierStreamV2::new(local));
        let peer: Arc<dyn CarrierStreamV2> = Arc::new(MemoryCarrierStreamV2::new(peer));
        self.outgoing.send(peer).await.map_err(|_| closed())?;
        Ok(local)
    }
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        let mut incoming = self.incoming.lock().await;
        tokio::select! {
            _ = self.canceled.cancelled() => Err(closed()),
            value = incoming.recv() => value.ok_or_else(closed),
        }
    }
    async fn close(&self) -> io::Result<()> {
        self.canceled.cancel();
        Ok(())
    }
}

struct MemoryCarrierStreamV2 {
    read: Mutex<ReadHalf<tokio::io::DuplexStream>>,
    write: Mutex<WriteHalf<tokio::io::DuplexStream>>,
    canceled: CancellationToken,
    finished: AtomicBool,
}

impl MemoryCarrierStreamV2 {
    fn new(stream: tokio::io::DuplexStream) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: Mutex::new(read),
            write: Mutex::new(write),
            canceled: CancellationToken::new(),
            finished: AtomicBool::new(false),
        }
    }
}

impl std::fmt::Debug for MemoryCarrierStreamV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemoryCarrierStreamV2(..)")
    }
}

#[async_trait]
impl CarrierStreamV2 for MemoryCarrierStreamV2 {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        let mut read = self.read.lock().await;
        tokio::select! {
            _ = self.canceled.cancelled() => Err(closed()),
            value = read.read(payload) => value,
        }
    }
    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        if self.finished.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "memory carrier FIN",
            ));
        }
        let mut write = self.write.lock().await;
        tokio::select! {
            _ = self.canceled.cancelled() => Err(closed()),
            value = write.write(payload) => value,
        }
    }
    async fn close_write(&self) -> io::Result<()> {
        if !self.finished.swap(true, Ordering::AcqRel) {
            self.write.lock().await.shutdown().await?;
        }
        Ok(())
    }
    async fn reset(&self) -> io::Result<()> {
        self.canceled.cancel();
        Ok(())
    }
    async fn close(&self) -> io::Result<()> {
        self.close_write().await
    }
}

async fn read_exact_v2(
    stream: &Arc<dyn CarrierStreamV2>,
    mut payload: &mut [u8],
) -> io::Result<()> {
    while !payload.is_empty() {
        let read = stream.read(payload).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "carrier stream truncated",
            ));
        }
        payload = &mut payload[read..];
    }
    Ok(())
}

async fn write_all_v2(stream: &Arc<dyn CarrierStreamV2>, mut payload: &[u8]) -> io::Result<()> {
    while !payload.is_empty() {
        let written = stream.write(payload).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "carrier accepted no bytes",
            ));
        }
        payload = &payload[written..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_two_bit_ledger_advances_only_across_contiguous_terminal_slots() {
        let mut ledger = StreamLedgerV2::new(StreamOpenerRoleV2::Client);
        assert_eq!(ledger.states.len(), 262_144);
        ledger.mark_fss2(1).unwrap();
        ledger.mark_fss2(3).unwrap();
        ledger.mark_terminal(3).unwrap();
        assert_eq!(ledger.frontier(), 0);
        ledger.mark_terminal(1).unwrap();
        assert_eq!(ledger.frontier(), 3);
        assert!(ledger.mark_fss2(1).is_err());
        assert!(ledger.mark_fss2(2).is_err());
        assert!(ledger.mark_fss2(2 * MAX_LEDGER_SLOTS + 1).is_err());
    }

    #[test]
    fn reset_before_fss2_advances_frontier_and_rejects_duplicate_late_setup() {
        let mut ledger = StreamLedgerV2::new(StreamOpenerRoleV2::Client);
        ledger.mark_peer_reset(3).unwrap();
        assert_eq!(ledger.frontier(), 0);
        assert_eq!(
            ledger.state(ledger.index(3).unwrap()),
            LedgerStateV2::AbandonedNoFss2
        );
        ledger.mark_fss2(1).unwrap();
        ledger.mark_terminal(1).unwrap();
        assert_eq!(ledger.frontier(), 3);
        ledger.mark_late_fss2_for_abandoned(3).unwrap();
        assert!(ledger.mark_late_fss2_for_abandoned(3).is_err());
    }

    #[test]
    fn epoch_root_cleanup_retains_only_the_current_epoch() {
        let roots = derive_epoch_zero_v2(&[7; 32], DirectionV2::ClientToServer).unwrap();
        let mut epochs = HashMap::from([(0, roots.clone()), (1, roots.clone()), (2, roots)]);
        retain_current_epoch_roots_v2(&mut epochs, 2);
        assert_eq!(epochs.len(), 1);
        assert!(epochs.contains_key(&2));
    }

    #[test]
    fn stream_key_update_ack_matches_the_shared_wire_vector() {
        use std::fmt::Write as _;

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/session_wire_vectors.json"
        ))
        .unwrap();
        let vector = &fixture["stream_key_update_ack"][0];
        let logical_id =
            u64::from_str_radix(vector["logical_id_hex"].as_str().unwrap(), 16).unwrap();
        let transition =
            u64::from_str_radix(vector["transition_id_hex"].as_str().unwrap(), 16).unwrap();
        let next_epoch =
            u32::from_str_radix(vector["next_epoch_hex"].as_str().unwrap(), 16).unwrap();
        let payload = encode_stream_key_update_ack_v2(logical_id, transition, next_epoch);
        let mut encoded = String::with_capacity(payload.len() * 2);
        for byte in payload {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        assert_eq!(encoded, vector["payload_hex"].as_str().unwrap());
        assert_eq!(
            decode_stream_key_update_ack_v2(&payload).unwrap(),
            (logical_id, transition, next_epoch)
        );
    }

    #[test]
    fn handshake_codec_and_kdf_match_the_shared_wire_vectors() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/handshake_vectors.json"
        ))
        .expect("parse handshake vectors");
        assert_eq!(fixture["version"], 1);
        assert_eq!(fixture["profile"], "flowersec/2");

        for vector in fixture["vectors"].as_array().expect("handshake vectors") {
            let id = vector["id"].as_str().expect("vector id");
            let suite = match vector["suite"].as_u64().expect("suite") {
                1 => CipherSuiteV2::ChaCha20Poly1305,
                2 => CipherSuiteV2::Aes256Gcm,
                other => panic!("{id}: unknown suite {other}"),
            };
            let fsc2 = vector_hex(vector, "fsc2_hex");
            assert_eq!(control_preface_v2().as_slice(), fsc2, "{id}: FSC2");

            let client_raw = vector_hex(vector, "client_init_hex");
            let client: ClientInitWire = canonical_handshake_v2(
                client_raw
                    .get(HANDSHAKE_HEADER_BYTES..)
                    .expect("CLIENT_INIT payload"),
            )
            .unwrap_or_else(|error| panic!("{id}: decode CLIENT_INIT: {error}"));
            assert_eq!(
                handshake_frame_v2(1, &client).expect("encode CLIENT_INIT"),
                client_raw,
                "{id}: CLIENT_INIT"
            );

            let server_core_raw = vector_hex(vector, "server_core_hex");
            let server_core: ServerCoreWire =
                canonical_handshake_v2(&server_core_raw[HANDSHAKE_HEADER_BYTES..])
                    .unwrap_or_else(|error| panic!("{id}: decode SERVER core: {error}"));
            assert_eq!(
                handshake_frame_v2(2, &server_core).expect("encode SERVER core"),
                server_core_raw,
                "{id}: SERVER core"
            );

            let server_raw = vector_hex(vector, "server_finished_hex");
            let server: ServerFinishedWire =
                canonical_handshake_v2(&server_raw[HANDSHAKE_HEADER_BYTES..])
                    .unwrap_or_else(|error| panic!("{id}: decode SERVER_FINISHED: {error}"));
            assert_eq!(
                handshake_frame_v2(2, &server).expect("encode SERVER_FINISHED"),
                server_raw,
                "{id}: SERVER_FINISHED"
            );

            let client_core_raw = vector_hex(vector, "client_core_hex");
            let client_core: ClientCoreWire =
                canonical_handshake_v2(&client_core_raw[HANDSHAKE_HEADER_BYTES..])
                    .unwrap_or_else(|error| panic!("{id}: decode CLIENT core: {error}"));
            assert_eq!(
                handshake_frame_v2(3, &client_core).expect("encode CLIENT core"),
                client_core_raw,
                "{id}: CLIENT core"
            );

            let client_finished_raw = vector_hex(vector, "client_finished_hex");
            let client_finished: ClientFinishedWire =
                canonical_handshake_v2(&client_finished_raw[HANDSHAKE_HEADER_BYTES..])
                    .unwrap_or_else(|error| panic!("{id}: decode CLIENT_FINISHED: {error}"));
            assert_eq!(
                handshake_frame_v2(3, &client_finished).expect("encode CLIENT_FINISHED"),
                client_finished_raw,
                "{id}: CLIENT_FINISHED"
            );

            let client_private = vector_hex(vector, "client_private_hex");
            let server_private = vector_hex(vector, "server_private_hex");
            let client_public = decode_b64(&client.client_eph_pub_b64u).expect("client public");
            let server_public = decode_b64(&server.server_eph_pub_b64u).expect("server public");
            assert_eq!(
                client.client_eph_pub_b64u, vector["client_public_b64u"],
                "{id}: client public"
            );
            assert_eq!(
                server.server_eph_pub_b64u, vector["server_public_b64u"],
                "{id}: server public"
            );
            let client_shared = crate::e2ee::derive_shared_secret(
                handshake_suite(suite),
                &client_private,
                &server_public,
            )
            .unwrap_or_else(|error| panic!("{id}: client ECDH: {error}"));
            let server_shared = crate::e2ee::derive_shared_secret(
                handshake_suite(suite),
                &server_private,
                &client_public,
            )
            .unwrap_or_else(|error| panic!("{id}: server ECDH: {error}"));
            assert_eq!(client_shared.expose(), server_shared.expose(), "{id}: ECDH");
            assert_eq!(
                client_shared.expose().as_slice(),
                vector_hex(vector, "shared_secret_hex"),
                "{id}: shared secret"
            );

            let psk = vector_hex(vector, "psk_hex");
            let handshake_prk = hkdf_extract_v2(&psk, client_shared.expose());
            assert_vector_hex(
                id,
                "handshake PRK",
                &handshake_prk,
                vector,
                "handshake_prk_hex",
            );
            let h0 = hash_parts(&[
                b"flowersec-v2-handshake\0",
                &fsc2,
                &length_prefix(&client_raw),
            ]);
            assert_vector_hex(id, "h0", &h0, vector, "h0_hex");
            let h1 = hash_parts(&[&h0, &length_prefix(&server_core_raw)]);
            assert_vector_hex(id, "h1", &h1, vector, "h1_hex");
            let server_confirm = confirm_v2(&handshake_prk, b"flowersec v2 server finished", &h1)
                .expect("server confirmation");
            assert_vector_hex(
                id,
                "server confirmation",
                &server_confirm,
                vector,
                "server_confirm_hex",
            );
            assert_eq!(
                decode_fixed_32(&server.server_confirm_b64u).expect("server confirmation wire"),
                server_confirm,
                "{id}: server confirmation wire"
            );

            let h2 = hash_parts(&[
                &h1,
                &length_prefix(&server_raw),
                &length_prefix(&client_core_raw),
            ]);
            assert_vector_hex(id, "h2", &h2, vector, "h2_hex");
            let client_confirm = confirm_v2(&handshake_prk, b"flowersec v2 client finished", &h2)
                .expect("client confirmation");
            assert_vector_hex(
                id,
                "client confirmation",
                &client_confirm,
                vector,
                "client_confirm_hex",
            );
            assert_eq!(
                decode_fixed_32(&client_finished.client_confirm_b64u)
                    .expect("client confirmation wire"),
                client_confirm,
                "{id}: client confirmation wire"
            );
            let h3 = hash_parts(&[&h2, &length_prefix(&client_finished_raw)]);
            assert_vector_hex(id, "h3", &h3, vector, "h3_hex");
            let session_prk = hkdf_extract_v2(&h3, &handshake_prk);
            assert_vector_hex(id, "session PRK", &session_prk, vector, "session_prk_hex");

            let mut noncanonical = client_raw[HANDSHAKE_HEADER_BYTES..].to_vec();
            noncanonical.push(b' ');
            assert!(canonical_handshake_v2::<ClientInitWire>(&noncanonical).is_err());
        }
    }

    fn vector_hex(vector: &serde_json::Value, field: &str) -> Vec<u8> {
        let value = vector[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field}"));
        assert_eq!(value.len() % 2, 0, "{field}: even hex length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digits = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(digits, 16).expect("valid hex")
            })
            .collect()
    }

    fn assert_vector_hex(
        id: &str,
        label: &str,
        actual: &[u8],
        vector: &serde_json::Value,
        field: &str,
    ) {
        assert_eq!(actual, vector_hex(vector, field), "{id}: {label}");
    }

    #[test]
    fn identical_rekey_ack_is_idempotent_but_mismatches_fail() {
        let ack = (7_u64, 3_u32);
        assert_eq!(
            classify_ack_v2(Some(&ack), None, &ack).unwrap(),
            AckDispositionV2::Pending
        );
        assert_eq!(
            classify_ack_v2(None, Some(&ack), &ack).unwrap(),
            AckDispositionV2::Duplicate
        );
        assert!(classify_ack_v2(Some(&ack), None, &(8, 3)).is_err());
        assert!(classify_ack_v2(None, Some(&ack), &(7, 4)).is_err());
    }

    #[test]
    fn goaway_boundary_uses_zero_sentinel_parity_and_high_watermark() {
        assert!(valid_goaway_boundary_v2(SessionRole::Client, 0, 0));
        assert!(valid_goaway_boundary_v2(SessionRole::Client, 3, 5));
        assert!(!valid_goaway_boundary_v2(SessionRole::Client, 4, 5));
        assert!(!valid_goaway_boundary_v2(SessionRole::Client, 7, 5));
        assert!(valid_goaway_boundary_v2(SessionRole::Server, 4, 6));
        assert!(!valid_goaway_boundary_v2(SessionRole::Server, 3, 6));
    }

    #[test]
    fn session_close_requires_a_nonzero_reason() {
        assert!(validate_session_close_payload_v2(&1_u16.to_be_bytes()).is_ok());
        assert!(validate_session_close_payload_v2(&0_u16.to_be_bytes()).is_err());
        assert!(validate_session_close_payload_v2(&[]).is_err());
        assert!(validate_session_close_payload_v2(&[0, 1, 2]).is_err());
    }

    #[test]
    fn stream_reset_requires_a_nonzero_reason() {
        let mut payload = [0_u8; 10];
        payload[..8].copy_from_slice(&1_u64.to_be_bytes());
        payload[8..].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(validate_stream_reset_payload_v2(&payload).unwrap(), 1);

        payload[8..].copy_from_slice(&0_u16.to_be_bytes());
        assert!(validate_stream_reset_payload_v2(&payload).is_err());
        assert!(validate_stream_reset_payload_v2(&payload[..9]).is_err());
    }

    #[tokio::test]
    async fn pending_ping_guard_cleans_error_timeout_and_cancellation_paths() {
        let pings = Arc::new(PendingPingsV2::default());

        let (sender, _receiver) = oneshot::channel();
        let failed: io::Result<()> = async {
            let _pending = pings.register(1, sender)?;
            Err(io::Error::other("injected ping send failure"))
        }
        .await;
        assert!(failed.is_err());
        assert_eq!(pings.len(), 0);

        let (sender, _receiver) = oneshot::channel();
        let timed_out = tokio::time::timeout(Duration::from_millis(1), async {
            let _pending = pings.register(2, sender).unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        assert!(timed_out.is_err());
        assert_eq!(pings.len(), 0);
    }

    #[test]
    fn open_reject_requires_the_expected_hash_and_a_nonzero_reason() {
        let expected = [7_u8; 32];
        let mut payload = Vec::from(expected);
        payload.extend_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            validate_open_reject_payload_v2(&payload, &expected).unwrap(),
            2
        );

        let mut zero_reason = Vec::from(expected);
        zero_reason.extend_from_slice(&0_u16.to_be_bytes());
        assert!(validate_open_reject_payload_v2(&zero_reason, &expected).is_err());

        payload[0] ^= 1;
        assert!(validate_open_reject_payload_v2(&payload, &expected).is_err());
    }
}
