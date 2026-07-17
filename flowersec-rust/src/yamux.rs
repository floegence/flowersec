use async_trait::async_trait;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex as SyncMutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};

use crate::{
    defaults,
    e2ee::{E2eeError, SecureChannel},
    transport::WebSocketTransport,
};

pub const VERSION: u8 = 0;
pub const HEADER_LEN: usize = 12;
pub const TYPE_DATA: u8 = 0;
pub const TYPE_WINDOW_UPDATE: u8 = 1;
pub const TYPE_PING: u8 = 2;
pub const TYPE_GO_AWAY: u8 = 3;
pub const FLAG_SYN: u16 = 1;
pub const FLAG_ACK: u16 = 2;
pub const FLAG_FIN: u16 = 4;
pub const FLAG_RST: u16 = 8;
pub const DEFAULT_STREAM_WINDOW: usize = 256 * 1024;
const CANCELED_FRAME_WRITE_ERROR: &str = "frame write canceled";
const CANCELED_PHASE_COMMIT_ERROR: &str = "frame phase commit canceled";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LivenessOptions {
    #[default]
    PathDefault,
    Disabled,
    Enabled {
        interval: Duration,
        timeout: Duration,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AutomaticLiveness {
    pub(crate) interval: Duration,
    pub(crate) timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("liveness interval and timeout must be greater than zero")]
pub(crate) struct InvalidLivenessOptions;

pub(crate) fn resolve_liveness(
    options: LivenessOptions,
    path_default_idle_timeout: Option<Duration>,
) -> Result<Option<AutomaticLiveness>, InvalidLivenessOptions> {
    match options {
        LivenessOptions::PathDefault => Ok(path_default_idle_timeout
            .filter(|idle| !idle.is_zero())
            .map(|idle| {
                let interval = (idle / 2).max(Duration::from_millis(500));
                AutomaticLiveness {
                    interval,
                    timeout: interval.min(Duration::from_secs(10)),
                }
            })),
        LivenessOptions::Disabled => Ok(None),
        LivenessOptions::Enabled { interval, timeout }
            if !interval.is_zero() && !timeout.is_zero() =>
        {
            Ok(Some(AutomaticLiveness { interval, timeout }))
        }
        LivenessOptions::Enabled { .. } => Err(InvalidLivenessOptions),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct YamuxLimits {
    pub max_active_streams: usize,
    pub max_inbound_streams: usize,
    pub max_frame_bytes: usize,
    pub preferred_outbound_frame_bytes: usize,
    pub max_stream_receive_bytes: usize,
    pub max_session_receive_bytes: usize,
    pub max_stream_write_queue_bytes: usize,
}

impl Default for YamuxLimits {
    fn default() -> Self {
        Self {
            max_active_streams: defaults::YAMUX_MAX_ACTIVE_STREAMS,
            max_inbound_streams: defaults::YAMUX_MAX_INBOUND_STREAMS,
            max_frame_bytes: defaults::YAMUX_MAX_FRAME_BYTES,
            preferred_outbound_frame_bytes: defaults::YAMUX_PREFERRED_OUTBOUND_FRAME_BYTES,
            max_stream_receive_bytes: defaults::YAMUX_MAX_STREAM_RECEIVE_BYTES,
            max_session_receive_bytes: defaults::YAMUX_MAX_SESSION_RECEIVE_BYTES,
            max_stream_write_queue_bytes: defaults::YAMUX_MAX_STREAM_WRITE_QUEUE_BYTES,
        }
    }
}

impl YamuxLimits {
    pub fn validate(self) -> Result<Self, YamuxError> {
        if self.max_active_streams == 0
            || self.max_inbound_streams == 0
            || self.max_frame_bytes == 0
            || self.preferred_outbound_frame_bytes == 0
            || self.max_stream_receive_bytes < DEFAULT_STREAM_WINDOW
            || self.max_session_receive_bytes == 0
            || self.max_stream_write_queue_bytes == 0
            || self.max_inbound_streams > self.max_active_streams
            || self.preferred_outbound_frame_bytes > self.max_frame_bytes
            || self.max_frame_bytes > self.max_stream_receive_bytes
            || self.max_stream_receive_bytes > self.max_session_receive_bytes
        {
            return Err(YamuxError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum YamuxError {
    #[error("Yamux session is closed")]
    Closed,
    #[error("Yamux stream is closed")]
    StreamClosed,
    #[error("Yamux stream was reset")]
    Reset,
    #[error("invalid Yamux limits")]
    InvalidLimits,
    #[error("invalid Yamux frame")]
    InvalidFrame,
    #[error("Yamux resource exhausted: {resource} ({current}/{limit})")]
    ResourceExhausted {
        resource: &'static str,
        current: usize,
        limit: usize,
    },
    #[error("Yamux ping timed out")]
    PingTimeout,
    #[error("Yamux transport failed: {0}")]
    Transport(String),
}

#[async_trait]
pub trait ByteDuplex: Send + Sync + 'static {
    async fn read(&self) -> Result<Vec<u8>, YamuxError>;
    async fn write(&self, bytes: &[u8]) -> Result<(), YamuxError>;
    async fn close(&self) -> Result<(), YamuxError>;
}

#[async_trait]
impl<T: WebSocketTransport> ByteDuplex for SecureChannel<T> {
    async fn read(&self) -> Result<Vec<u8>, YamuxError> {
        SecureChannel::read(self).await.map_err(map_secure_error)
    }

    async fn write(&self, bytes: &[u8]) -> Result<(), YamuxError> {
        SecureChannel::write(self, bytes)
            .await
            .map_err(map_secure_error)
    }

    async fn close(&self) -> Result<(), YamuxError> {
        SecureChannel::close(self).await.map_err(map_secure_error)
    }
}

fn map_secure_error(error: E2eeError) -> YamuxError {
    match error {
        E2eeError::OutboundBufferExceeded { current, limit } => YamuxError::ResourceExhausted {
            resource: "secure_channel_pending_write_bytes",
            current,
            limit,
        },
        error => YamuxError::Transport(error.to_string()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Header {
    frame_type: u8,
    flags: u16,
    stream_id: u32,
    length: u32,
}

impl Header {
    fn encode(self) -> [u8; HEADER_LEN] {
        let mut output = [0_u8; HEADER_LEN];
        output[0] = VERSION;
        output[1] = self.frame_type;
        output[2..4].copy_from_slice(&self.flags.to_be_bytes());
        output[4..8].copy_from_slice(&self.stream_id.to_be_bytes());
        output[8..12].copy_from_slice(&self.length.to_be_bytes());
        output
    }

    fn decode(input: &[u8]) -> Result<Self, YamuxError> {
        if input.len() != HEADER_LEN || input[0] != VERSION {
            return Err(YamuxError::InvalidFrame);
        }
        Ok(Self {
            frame_type: input[1],
            flags: u16::from_be_bytes(input[2..4].try_into().expect("fixed header")),
            stream_id: u32::from_be_bytes(input[4..8].try_into().expect("fixed header")),
            length: u32::from_be_bytes(input[8..12].try_into().expect("fixed header")),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamPhase {
    Initial,
    SynSent,
    SynReceived,
    Established,
    LocalClosed,
    RemoteClosed,
    Closed,
    Reset,
}

#[derive(Debug)]
struct StreamState {
    phase: StreamPhase,
    receive_window: usize,
    receive_queue: VecDeque<Vec<u8>>,
    receive_bytes: usize,
}

#[derive(Debug)]
struct StreamInner {
    id: u32,
    session: Weak<SessionInner>,
    state: Mutex<StreamState>,
    read_notify: Notify,
    write_notify: Notify,
    send_window: SyncMutex<usize>,
    write_queue_bytes: AtomicUsize,
    write_serial: Mutex<()>,
    exact_read_serial: Mutex<()>,
    exact_read_buffer: Mutex<VecDeque<u8>>,
    discarded: AtomicBool,
}

struct WriteQueueReservation<'a> {
    queued: &'a AtomicUsize,
    bytes: usize,
}

impl Drop for WriteQueueReservation<'_> {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.queued.fetch_sub(self.bytes, Ordering::Relaxed);
        }
    }
}

struct SendWindowReservation<'a> {
    window: &'a SyncMutex<usize>,
    bytes: usize,
    committed: bool,
}

struct FrameWriteGuard {
    session: Arc<SessionInner>,
    armed: bool,
}

impl FrameWriteGuard {
    fn new(session: Arc<SessionInner>) -> Self {
        Self {
            session,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FrameWriteGuard {
    fn drop(&mut self) {
        if self.armed {
            self.session.terminate_canceled_frame_write();
        }
    }
}

struct PostWritePhaseCommitGuard {
    session: Arc<SessionInner>,
    armed: bool,
}

impl PostWritePhaseCommitGuard {
    fn new(session: Arc<SessionInner>) -> Self {
        Self {
            session,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PostWritePhaseCommitGuard {
    fn drop(&mut self) {
        if self.armed {
            self.session.terminate_canceled_phase_commit();
        }
    }
}

struct SessionReceiveReservation<'a> {
    received: &'a AtomicUsize,
    bytes: usize,
    committed: bool,
}

impl SessionReceiveReservation<'_> {
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for SessionReceiveReservation<'_> {
    fn drop(&mut self) {
        if !self.committed && self.bytes > 0 {
            self.received.fetch_sub(self.bytes, Ordering::Relaxed);
        }
    }
}

impl SendWindowReservation<'_> {
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for SendWindowReservation<'_> {
    fn drop(&mut self) {
        if !self.committed && self.bytes > 0 {
            let mut window = lock_send_window(self.window);
            *window = window.saturating_add(self.bytes).min(DEFAULT_STREAM_WINDOW);
        }
    }
}

#[derive(Clone)]
pub struct YamuxStream(Arc<StreamInner>);

impl std::fmt::Debug for YamuxStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("YamuxStream")
            .field("id", &self.0.id)
            .finish_non_exhaustive()
    }
}

impl YamuxStream {
    pub fn id(&self) -> u32 {
        self.0.id
    }

    fn discard(&self) {
        self.0.discarded.store(true, Ordering::Release);
    }

    fn is_discarded(&self) -> bool {
        self.0.discarded.load(Ordering::Acquire)
    }

    pub async fn read(&self) -> Result<Option<Vec<u8>>, YamuxError> {
        loop {
            let notified = self.0.read_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let session = self.session()?;
            let (payload, terminal, finalize) = {
                let mut state = self.0.state.lock().await;
                if state.phase == StreamPhase::Reset {
                    return Err(YamuxError::Reset);
                }
                if let Some(payload_len) = state.receive_queue.front().map(Vec::len) {
                    let remaining = state.receive_bytes.saturating_sub(payload_len);
                    let target = DEFAULT_STREAM_WINDOW.saturating_sub(remaining);
                    let delta = target.saturating_sub(state.receive_window);
                    let (flags, next_phase) = planned_send_flags(state.phase);
                    if delta >= DEFAULT_STREAM_WINDOW / 2 || flags != 0 {
                        session
                            .write_frame(
                                Header {
                                    frame_type: TYPE_WINDOW_UPDATE,
                                    flags,
                                    stream_id: self.id(),
                                    length: delta as u32,
                                },
                                &[],
                            )
                            .await?;
                        state.phase = next_phase;
                        state.receive_window = state.receive_window.saturating_add(delta);
                    }
                    let payload = state
                        .receive_queue
                        .pop_front()
                        .expect("front payload remains present while stream state is locked");
                    state.receive_bytes -= payload_len;
                    session.release_receive_bytes(payload_len);
                    let finalize =
                        state.phase == StreamPhase::Closed && state.receive_queue.is_empty();
                    (Some(payload), false, finalize)
                } else {
                    let terminal =
                        matches!(state.phase, StreamPhase::Closed | StreamPhase::RemoteClosed);
                    let finalize = state.phase == StreamPhase::Closed;
                    (None, terminal, finalize)
                }
            };
            if let Some(payload) = payload {
                if finalize {
                    session.remove_stream_in_background(self.id());
                }
                return Ok(Some(payload));
            }
            if terminal {
                if finalize {
                    session.remove_stream_in_background(self.id());
                }
                return Ok(None);
            }
            notified.await;
        }
    }

    pub async fn write(&self, payload: &[u8]) -> Result<(), YamuxError> {
        let session = self.session()?;
        let _reservation = {
            let state = self.0.state.lock().await;
            ensure_writable(state.phase)?;
            reserve_write_queue_bytes(
                &self.0.write_queue_bytes,
                session.limits.max_stream_write_queue_bytes,
                payload.len(),
            )?
        };
        let _serial = self.0.write_serial.lock().await;
        self.write_serial(payload, &session).await
    }

    pub async fn read_exact(&self, length: usize) -> Result<Vec<u8>, YamuxError> {
        let _serial = self.0.exact_read_serial.lock().await;
        loop {
            {
                let mut buffered = self.0.exact_read_buffer.lock().await;
                if buffered.len() >= length {
                    return Ok(buffered.drain(..length).collect());
                }
            }
            let chunk = self.read().await?.ok_or(YamuxError::StreamClosed)?;
            self.0.exact_read_buffer.lock().await.extend(chunk);
        }
    }

    pub async fn close(&self) -> Result<(), YamuxError> {
        let session = self.session()?;
        let _serial = self.0.write_serial.lock().await;
        {
            let state = self.0.state.lock().await;
            if matches!(state.phase, StreamPhase::Closed | StreamPhase::Reset) {
                return Ok(());
            }
        }
        session
            .write_frame(
                Header {
                    frame_type: TYPE_WINDOW_UPDATE,
                    flags: FLAG_FIN,
                    stream_id: self.id(),
                    length: 0,
                },
                &[],
            )
            .await?;
        let mut phase_guard = PostWritePhaseCommitGuard::new(session.clone());
        let mut state = self.0.state.lock().await;
        state.phase = match state.phase {
            StreamPhase::RemoteClosed => StreamPhase::Closed,
            StreamPhase::Closed | StreamPhase::Reset => state.phase,
            _ => StreamPhase::LocalClosed,
        };
        phase_guard.disarm();
        let finalize = state.phase == StreamPhase::Closed && state.receive_queue.is_empty();
        drop(state);
        if finalize {
            session.remove_stream(self.id()).await;
        }
        self.0.read_notify.notify_waiters();
        Ok(())
    }

    pub async fn reset(&self) -> Result<(), YamuxError> {
        let session = self.session()?;
        self.mark_reset().await;
        session.send_reset(self.id()).await
    }

    async fn write_serial(
        &self,
        payload: &[u8],
        session: &Arc<SessionInner>,
    ) -> Result<(), YamuxError> {
        let mut offset = 0;
        while offset < payload.len() {
            let notified = self.0.write_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let reservation = {
                let state = self.0.state.lock().await;
                ensure_writable(state.phase)?;
                let mut send_window = lock_send_window(&self.0.send_window);
                if *send_window == 0 {
                    None
                } else {
                    let allowed = (payload.len() - offset)
                        .min(session.limits.preferred_outbound_frame_bytes)
                        .min(*send_window);
                    *send_window -= allowed;
                    Some(SendWindowReservation {
                        window: &self.0.send_window,
                        bytes: allowed,
                        committed: false,
                    })
                }
            };
            let Some(reservation) = reservation else {
                notified.await;
                continue;
            };
            let allowed = reservation.bytes;
            session
                .write_frame(
                    Header {
                        frame_type: TYPE_DATA,
                        flags: 0,
                        stream_id: self.id(),
                        length: allowed as u32,
                    },
                    &payload[offset..offset + allowed],
                )
                .await?;
            reservation.commit();
            offset += allowed;
        }
        Ok(())
    }

    async fn replenish_window(&self) -> Result<(), YamuxError> {
        let session = self.session()?;
        let mut state = self.0.state.lock().await;
        let target = DEFAULT_STREAM_WINDOW.saturating_sub(state.receive_bytes);
        let delta = target.saturating_sub(state.receive_window);
        let (flags, next_phase) = planned_send_flags(state.phase);
        if delta < DEFAULT_STREAM_WINDOW / 2 && flags == 0 {
            return Ok(());
        }
        session
            .write_frame(
                Header {
                    frame_type: TYPE_WINDOW_UPDATE,
                    flags,
                    stream_id: self.id(),
                    length: delta as u32,
                },
                &[],
            )
            .await?;
        state.phase = next_phase;
        state.receive_window = state.receive_window.saturating_add(delta);
        Ok(())
    }

    async fn on_data(&self, flags: u16, payload: Vec<u8>) -> Result<bool, YamuxError> {
        let mut state = self.0.state.lock().await;
        process_flags(&mut state.phase, flags & !FLAG_FIN);
        if matches!(state.phase, StreamPhase::Closed | StreamPhase::Reset) {
            return Ok(false);
        }
        if payload.len() > state.receive_window {
            drop(state);
            self.reset().await?;
            return Ok(false);
        }
        if !payload.is_empty() {
            state.receive_window -= payload.len();
            state.receive_bytes += payload.len();
            state.receive_queue.push_back(payload);
        }
        process_flags(&mut state.phase, flags & FLAG_FIN);
        let finalize = state.phase == StreamPhase::Closed && state.receive_queue.is_empty();
        drop(state);
        if finalize {
            self.session()?.remove_stream(self.id()).await;
        }
        self.0.read_notify.notify_waiters();
        Ok(true)
    }

    async fn on_window_update(&self, flags: u16, delta: usize) -> Result<(), YamuxError> {
        let finalize = {
            let mut state = self.0.state.lock().await;
            process_flags(&mut state.phase, flags);
            {
                let mut send_window = lock_send_window(&self.0.send_window);
                if delta > DEFAULT_STREAM_WINDOW.saturating_sub(*send_window) {
                    return Err(YamuxError::InvalidFrame);
                }
                *send_window += delta;
            }
            state.phase == StreamPhase::Closed && state.receive_queue.is_empty()
        };
        if finalize {
            self.session()?.remove_stream(self.id()).await;
        }
        self.0.write_notify.notify_one();
        self.0.read_notify.notify_waiters();
        Ok(())
    }

    async fn mark_reset(&self) {
        let released = {
            let mut state = self.0.state.lock().await;
            if state.phase == StreamPhase::Reset {
                return;
            }
            state.phase = StreamPhase::Reset;
            state.receive_queue.clear();
            let released = state.receive_bytes;
            state.receive_bytes = 0;
            released
        };
        if let Ok(session) = self.session() {
            session.release_receive_bytes(released);
            session.remove_stream(self.id()).await;
        }
        self.0.read_notify.notify_waiters();
        self.0.write_notify.notify_waiters();
    }

    fn session(&self) -> Result<Arc<SessionInner>, YamuxError> {
        self.0.session.upgrade().ok_or(YamuxError::Closed)
    }
}

#[derive(Debug)]
struct PingWaiter {
    started_at: Instant,
    sender: oneshot::Sender<Duration>,
}

struct PingWaiterGuard {
    session: Arc<SessionInner>,
    opaque: u32,
    armed: bool,
}

impl PingWaiterGuard {
    fn new(session: Arc<SessionInner>, opaque: u32) -> Self {
        Self {
            session,
            opaque,
            armed: true,
        }
    }

    async fn remove(&mut self) {
        if self.armed {
            self.session
                .state
                .lock()
                .await
                .ping_waiters
                .remove(&self.opaque);
            self.armed = false;
        }
    }
}

impl Drop for PingWaiterGuard {
    fn drop(&mut self) {
        if self.armed {
            self.session.remove_ping_waiter_in_background(self.opaque);
        }
    }
}

struct PendingStreamGuard {
    session: Arc<SessionInner>,
    stream: YamuxStream,
    armed: bool,
}

impl PendingStreamGuard {
    fn new(session: Arc<SessionInner>, stream: YamuxStream) -> Self {
        Self {
            session,
            stream,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    async fn remove(&mut self) {
        if self.armed {
            self.stream.discard();
            self.session.remove_stream(self.stream.id()).await;
            self.armed = false;
        }
    }
}

impl Drop for PendingStreamGuard {
    fn drop(&mut self) {
        if self.armed {
            self.stream.discard();
            self.session.remove_stream_in_background(self.stream.id());
        }
    }
}

#[derive(Debug)]
struct SessionState {
    streams: HashMap<u32, YamuxStream>,
    inbound_streams: usize,
    next_stream_id: u32,
    next_ping_id: u32,
    ping_waiters: HashMap<u32, PingWaiter>,
    closed: bool,
    terminal_error: Option<YamuxError>,
}

struct SessionInner {
    connection: Arc<dyn ByteDuplex>,
    runtime: tokio::runtime::Handle,
    read_abort: OnceLock<tokio::task::AbortHandle>,
    terminal_requested: AtomicBool,
    mode: Mode,
    limits: YamuxLimits,
    state: Mutex<SessionState>,
    receive_bytes: AtomicUsize,
    incoming_tx: mpsc::Sender<YamuxStream>,
    write_serial: Mutex<()>,
    close_notify: Notify,
}

impl std::fmt::Debug for SessionInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionInner")
            .field("mode", &self.mode)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct YamuxSession {
    inner: Arc<SessionInner>,
    incoming_rx: Arc<Mutex<mpsc::Receiver<YamuxStream>>>,
}

impl std::fmt::Debug for YamuxSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("YamuxSession")
            .field("mode", &self.inner.mode)
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}

impl YamuxSession {
    pub fn new(
        connection: Arc<dyn ByteDuplex>,
        mode: Mode,
        limits: YamuxLimits,
    ) -> Result<Self, YamuxError> {
        let limits = limits.validate()?;
        let (incoming_tx, incoming_rx) = mpsc::channel(limits.max_inbound_streams);
        let inner = Arc::new(SessionInner {
            connection,
            runtime: tokio::runtime::Handle::current(),
            read_abort: OnceLock::new(),
            terminal_requested: AtomicBool::new(false),
            mode,
            limits,
            state: Mutex::new(SessionState {
                streams: HashMap::new(),
                inbound_streams: 0,
                next_stream_id: if mode == Mode::Client { 1 } else { 2 },
                next_ping_id: 1,
                ping_waiters: HashMap::new(),
                closed: false,
                terminal_error: None,
            }),
            receive_bytes: AtomicUsize::new(0),
            incoming_tx,
            write_serial: Mutex::new(()),
            close_notify: Notify::new(),
        });
        let read_task = tokio::spawn(read_loop(inner.clone()));
        inner
            .read_abort
            .set(read_task.abort_handle())
            .expect("Yamux read task is initialized once");
        Ok(Self {
            inner,
            incoming_rx: Arc::new(Mutex::new(incoming_rx)),
        })
    }

    pub async fn open_stream(&self) -> Result<YamuxStream, YamuxError> {
        let stream = {
            let mut state = self.inner.state.lock().await;
            if self.inner.terminal_requested.load(Ordering::Acquire) || state.closed {
                return Err(state.terminal_error.clone().unwrap_or(YamuxError::Closed));
            }
            if state.streams.len() >= self.inner.limits.max_active_streams {
                remove_discarded_streams_from_state(&mut state, self.inner.mode);
            }
            if state.streams.len() >= self.inner.limits.max_active_streams {
                return Err(YamuxError::ResourceExhausted {
                    resource: "active_streams",
                    current: state.streams.len(),
                    limit: self.inner.limits.max_active_streams,
                });
            }
            let id = state.next_stream_id;
            state.next_stream_id =
                state
                    .next_stream_id
                    .checked_add(2)
                    .ok_or(YamuxError::ResourceExhausted {
                        resource: "stream_ids",
                        current: u32::MAX as usize,
                        limit: u32::MAX as usize,
                    })?;
            let stream = new_stream(&self.inner, id, StreamPhase::Initial);
            state.streams.insert(id, stream.clone());
            stream
        };
        let mut pending = PendingStreamGuard::new(self.inner.clone(), stream.clone());
        if let Err(error) = stream.replenish_window().await {
            pending.remove().await;
            return Err(error);
        }
        pending.disarm();
        Ok(stream)
    }

    pub async fn accept_stream(&self) -> Result<YamuxStream, YamuxError> {
        let mut incoming = self.incoming_rx.lock().await;
        loop {
            let closed = self.inner.close_notify.notified();
            tokio::pin!(closed);
            closed.as_mut().enable();
            {
                let state = self.inner.state.lock().await;
                if self.inner.terminal_requested.load(Ordering::Acquire) || state.closed {
                    return Err(state.terminal_error.clone().unwrap_or(YamuxError::Closed));
                }
            }
            tokio::select! {
                stream = incoming.recv() => {
                    return stream.ok_or(YamuxError::Closed);
                }
                () = &mut closed => {}
            }
        }
    }

    pub(crate) async fn terminal_error(&self) -> Option<YamuxError> {
        self.inner.state.lock().await.terminal_error.clone()
    }

    pub async fn probe_liveness(&self, timeout: Duration) -> Result<Duration, YamuxError> {
        if timeout.is_zero() {
            let error = YamuxError::PingTimeout;
            self.inner.abort_read_loop();
            self.inner
                .terminate_with_background_close(Some(error.clone()))
                .await;
            return Err(error);
        }
        let (opaque, receiver) = {
            let mut state = self.inner.state.lock().await;
            if self.inner.terminal_requested.load(Ordering::Acquire) || state.closed {
                return Err(state.terminal_error.clone().unwrap_or(YamuxError::Closed));
            }
            let mut opaque = state.next_ping_id;
            loop {
                state.next_ping_id = state.next_ping_id.wrapping_add(1).max(1);
                if opaque != 0 && !state.ping_waiters.contains_key(&opaque) {
                    break;
                }
                opaque = state.next_ping_id;
            }
            let (sender, receiver) = oneshot::channel();
            state.ping_waiters.insert(
                opaque,
                PingWaiter {
                    started_at: Instant::now(),
                    sender,
                },
            );
            (opaque, receiver)
        };
        let mut waiter = PingWaiterGuard::new(self.inner.clone(), opaque);
        let result = tokio::time::timeout(timeout, async {
            self.inner
                .write_frame(
                    Header {
                        frame_type: TYPE_PING,
                        flags: FLAG_SYN,
                        stream_id: 0,
                        length: opaque,
                    },
                    &[],
                )
                .await?;
            receiver.await.map_err(|_| YamuxError::Closed)
        })
        .await;
        match result {
            Ok(Ok(duration)) => {
                waiter.remove().await;
                Ok(duration)
            }
            Ok(Err(error)) => {
                waiter.remove().await;
                if matches!(error, YamuxError::Closed) {
                    Err(self
                        .inner
                        .state
                        .lock()
                        .await
                        .terminal_error
                        .clone()
                        .unwrap_or(YamuxError::Closed))
                } else {
                    Err(error)
                }
            }
            Err(_) => {
                waiter.remove().await;
                let error = YamuxError::PingTimeout;
                self.inner.abort_read_loop();
                self.inner
                    .replace_canceled_frame_write_error(error.clone())
                    .await;
                self.inner
                    .terminate_with_background_close(Some(error.clone()))
                    .await;
                Err(error)
            }
        }
    }

    pub(crate) fn start_automatic_liveness(
        &self,
        options: AutomaticLiveness,
        on_timeout: Option<Arc<dyn Fn() + Send + Sync>>,
    ) {
        let session = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = session.wait_closed() => return,
                    () = tokio::time::sleep(options.interval) => {}
                }
                if let Err(error) = session.probe_liveness(options.timeout).await {
                    if matches!(error, YamuxError::PingTimeout) {
                        if let Some(on_timeout) = &on_timeout {
                            on_timeout();
                        }
                    }
                    if session.terminal_error().await.is_none() {
                        session.inner.abort_read_loop();
                        session.inner.terminate_bounded(Some(error)).await;
                    }
                    return;
                }
            }
        });
    }

    pub async fn close(&self) -> Result<(), YamuxError> {
        self.inner.abort_read_loop();
        self.inner.close().await
    }

    pub(crate) async fn close_bounded(&self) {
        self.inner.abort_read_loop();
        self.inner.terminate_bounded(None).await;
    }

    pub(crate) fn close_in_background(&self) {
        let inner = self.inner.clone();
        inner.runtime.clone().spawn(async move {
            inner.abort_read_loop();
            inner.terminate_bounded(None).await;
        });
    }

    pub async fn wait_closed(&self) {
        let notified = self.inner.close_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.inner.state.lock().await.closed {
            return;
        }
        notified.await;
    }
}

impl SessionInner {
    fn abort_read_loop(&self) {
        if let Some(abort) = self.read_abort.get() {
            abort.abort();
        }
    }

    async fn write_frame(
        self: &Arc<Self>,
        header: Header,
        payload: &[u8],
    ) -> Result<(), YamuxError> {
        if header.frame_type == TYPE_DATA && payload.len() != header.length as usize {
            return Err(YamuxError::InvalidFrame);
        }
        if header.frame_type != TYPE_DATA && !payload.is_empty() {
            return Err(YamuxError::InvalidFrame);
        }
        let _serial = self.write_serial.lock().await;
        {
            let state = self.state.lock().await;
            if self.terminal_requested.load(Ordering::Acquire) || state.closed {
                return Err(state.terminal_error.clone().unwrap_or(YamuxError::Closed));
            }
        }
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(payload);
        let mut write_guard = FrameWriteGuard::new(self.clone());
        match self.connection.write(&frame).await {
            Ok(()) => {
                write_guard.disarm();
                Ok(())
            }
            Err(error) => {
                self.terminate_frame_write(error.clone()).await;
                write_guard.disarm();
                Err(error)
            }
        }
    }

    async fn send_reset(self: &Arc<Self>, stream_id: u32) -> Result<(), YamuxError> {
        self.remove_stream(stream_id).await;
        self.write_frame(
            Header {
                frame_type: TYPE_WINDOW_UPDATE,
                flags: FLAG_RST,
                stream_id,
                length: 0,
            },
            &[],
        )
        .await
    }

    async fn remove_stream(&self, stream_id: u32) {
        let mut state = self.state.lock().await;
        remove_stream_from_state(&mut state, self.mode, stream_id);
    }

    fn remove_stream_in_background(self: &Arc<Self>, stream_id: u32) {
        if let Ok(mut state) = self.state.try_lock() {
            remove_stream_from_state(&mut state, self.mode, stream_id);
            return;
        }
        let session = self.clone();
        self.runtime.spawn(async move {
            session.remove_stream(stream_id).await;
        });
    }

    fn remove_ping_waiter_in_background(self: &Arc<Self>, opaque: u32) {
        let session = self.clone();
        self.runtime.spawn(async move {
            session.state.lock().await.ping_waiters.remove(&opaque);
        });
    }

    fn reserve_receive_bytes(
        &self,
        bytes: usize,
    ) -> Result<SessionReceiveReservation<'_>, YamuxError> {
        reserve_receive_bytes(
            &self.receive_bytes,
            self.limits.max_session_receive_bytes,
            bytes,
        )
    }

    fn release_receive_bytes(&self, bytes: usize) {
        if bytes > 0 {
            self.receive_bytes.fetch_sub(bytes, Ordering::Relaxed);
        }
    }

    async fn close(&self) -> Result<(), YamuxError> {
        self.terminate(None).await
    }

    async fn terminate(&self, terminal_error: Option<YamuxError>) -> Result<(), YamuxError> {
        self.mark_terminated(terminal_error).await;
        self.connection.close().await
    }

    async fn terminate_bounded(&self, terminal_error: Option<YamuxError>) {
        self.mark_terminated(terminal_error).await;
        close_connection_bounded(self.connection.clone()).await;
    }

    async fn terminate_with_background_close(&self, terminal_error: Option<YamuxError>) {
        self.mark_terminated(terminal_error).await;
        let connection = self.connection.clone();
        self.runtime.spawn(close_connection_bounded(connection));
    }

    async fn terminate_frame_write(self: &Arc<Self>, terminal_error: YamuxError) {
        self.terminal_requested.store(true, Ordering::Release);
        self.abort_read_loop();
        let streams = {
            let mut state = self.state.lock().await;
            begin_termination(&mut state, Some(terminal_error))
        };
        if let Some(streams) = streams {
            self.finish_termination_in_background(streams);
        }
    }

    fn terminate_canceled_frame_write(self: &Arc<Self>) {
        self.terminate_canceled_frame_operation(CANCELED_FRAME_WRITE_ERROR);
    }

    fn terminate_canceled_phase_commit(self: &Arc<Self>) {
        self.terminate_canceled_frame_operation(CANCELED_PHASE_COMMIT_ERROR);
    }

    fn terminate_canceled_frame_operation(self: &Arc<Self>, message: &'static str) {
        self.terminal_requested.store(true, Ordering::Release);
        self.abort_read_loop();
        let terminal_error = YamuxError::Transport(message.to_owned());
        if let Ok(mut state) = self.state.try_lock() {
            let streams = begin_termination(&mut state, Some(terminal_error));
            drop(state);
            if let Some(streams) = streams {
                self.finish_termination_in_background(streams);
            }
            return;
        }
        let session = self.clone();
        self.runtime.spawn(async move {
            session.terminate_frame_write(terminal_error).await;
        });
    }

    async fn replace_canceled_frame_write_error(&self, terminal_error: YamuxError) {
        let mut state = self.state.lock().await;
        if matches!(
            &state.terminal_error,
            Some(YamuxError::Transport(message)) if message == CANCELED_FRAME_WRITE_ERROR
        ) {
            state.terminal_error = Some(terminal_error);
        }
    }

    fn finish_termination_in_background(self: &Arc<Self>, streams: Vec<YamuxStream>) {
        self.close_notify.notify_waiters();
        let session = self.clone();
        self.runtime.spawn(async move {
            for stream in streams {
                stream.mark_reset().await;
            }
            close_connection_bounded(session.connection.clone()).await;
        });
    }

    async fn mark_terminated(&self, terminal_error: Option<YamuxError>) {
        let streams = {
            let mut state = self.state.lock().await;
            begin_termination(&mut state, terminal_error)
        };
        let Some(streams) = streams else {
            return;
        };
        self.close_notify.notify_waiters();
        for stream in streams {
            stream.mark_reset().await;
        }
    }
}

fn begin_termination(
    state: &mut SessionState,
    terminal_error: Option<YamuxError>,
) -> Option<Vec<YamuxStream>> {
    if state.closed {
        return None;
    }
    state.closed = true;
    state.terminal_error = terminal_error;
    state.ping_waiters.clear();
    Some(state.streams.values().cloned().collect())
}

fn remove_stream_from_state(state: &mut SessionState, mode: Mode, stream_id: u32) {
    if state.streams.remove(&stream_id).is_some() && inbound_id_valid(mode, stream_id) {
        state.inbound_streams = state.inbound_streams.saturating_sub(1);
    }
}

fn remove_discarded_streams_from_state(state: &mut SessionState, mode: Mode) {
    let mut removed_inbound = 0;
    state.streams.retain(|stream_id, stream| {
        let keep = !stream.is_discarded();
        if !keep && inbound_id_valid(mode, *stream_id) {
            removed_inbound += 1;
        }
        keep
    });
    state.inbound_streams = state.inbound_streams.saturating_sub(removed_inbound);
}

async fn close_connection_bounded(connection: Arc<dyn ByteDuplex>) {
    match tokio::time::timeout(defaults::TRANSPORT_CLOSE_GRACE_PERIOD, connection.close()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "Yamux transport close failed"),
        Err(_) => tracing::warn!("Yamux transport close timed out"),
    }
}

async fn read_loop(session: Arc<SessionInner>) {
    let mut reader = ByteReader::new(session.connection.clone());
    loop {
        let result = async {
            let header = Header::decode(&reader.read_exact(HEADER_LEN).await?)?;
            match header.frame_type {
                TYPE_DATA => {
                    if header.stream_id == 0 {
                        return Err(YamuxError::InvalidFrame);
                    }
                    if header.length as usize > session.limits.max_frame_bytes {
                        return Err(YamuxError::ResourceExhausted {
                            resource: "frame_bytes",
                            current: header.length as usize,
                            limit: session.limits.max_frame_bytes,
                        });
                    }
                    let payload = reader.read_exact(header.length as usize).await?;
                    handle_data(&session, header, payload).await
                }
                TYPE_WINDOW_UPDATE => handle_window_update(&session, header).await,
                TYPE_PING => handle_ping(&session, header).await,
                TYPE_GO_AWAY => Err(YamuxError::Closed),
                _ => Err(YamuxError::InvalidFrame),
            }
        }
        .await;
        if let Err(error) = result {
            session.terminate_bounded(Some(error)).await;
            return;
        }
    }
}

async fn handle_data(
    session: &Arc<SessionInner>,
    header: Header,
    payload: Vec<u8>,
) -> Result<(), YamuxError> {
    let stream =
        get_or_accept_stream(session, header.stream_id, header.flags, payload.len()).await?;
    let Some(stream) = stream else {
        return Ok(());
    };
    let reservation = session.reserve_receive_bytes(payload.len())?;
    if stream.on_data(header.flags, payload).await? {
        reservation.commit();
    }
    Ok(())
}

async fn handle_window_update(
    session: &Arc<SessionInner>,
    header: Header,
) -> Result<(), YamuxError> {
    if header.stream_id == 0 {
        return Err(YamuxError::InvalidFrame);
    }
    let stream = get_or_accept_stream(session, header.stream_id, header.flags, 0).await?;
    if let Some(stream) = stream {
        stream
            .on_window_update(header.flags, header.length as usize)
            .await?;
    }
    Ok(())
}

async fn handle_ping(session: &Arc<SessionInner>, header: Header) -> Result<(), YamuxError> {
    if header.stream_id != 0 {
        return Err(YamuxError::InvalidFrame);
    }
    if header.flags & FLAG_SYN != 0 {
        return session
            .write_frame(
                Header {
                    frame_type: TYPE_PING,
                    flags: FLAG_ACK,
                    stream_id: 0,
                    length: header.length,
                },
                &[],
            )
            .await;
    }
    if header.flags & FLAG_ACK != 0 {
        let waiter = session
            .state
            .lock()
            .await
            .ping_waiters
            .remove(&header.length);
        if let Some(waiter) = waiter {
            match waiter.sender.send(waiter.started_at.elapsed()) {
                Ok(()) | Err(_) => {}
            }
        }
    }
    Ok(())
}

async fn get_or_accept_stream(
    session: &Arc<SessionInner>,
    stream_id: u32,
    flags: u16,
    incoming_bytes: usize,
) -> Result<Option<YamuxStream>, YamuxError> {
    let existing = {
        let mut state = session.state.lock().await;
        if state
            .streams
            .get(&stream_id)
            .is_some_and(YamuxStream::is_discarded)
        {
            remove_stream_from_state(&mut state, session.mode, stream_id);
        }
        state.streams.get(&stream_id).cloned()
    };
    if existing.is_some() {
        if let Some(stream) = &existing {
            let receive_bytes = stream.0.state.lock().await.receive_bytes;
            if receive_bytes.saturating_add(incoming_bytes)
                > session.limits.max_stream_receive_bytes
            {
                stream.reset().await?;
                return Ok(None);
            }
        }
        return Ok(existing);
    }
    if flags & FLAG_SYN == 0 || !inbound_id_valid(session.mode, stream_id) {
        session.send_reset(stream_id).await?;
        return Ok(None);
    }
    let stream = {
        let mut state = session.state.lock().await;
        if state.streams.len() >= session.limits.max_active_streams
            || state.inbound_streams >= session.limits.max_inbound_streams
        {
            remove_discarded_streams_from_state(&mut state, session.mode);
        }
        if state.streams.len() >= session.limits.max_active_streams
            || state.inbound_streams >= session.limits.max_inbound_streams
            || incoming_bytes > session.limits.max_stream_receive_bytes
        {
            drop(state);
            session.send_reset(stream_id).await?;
            return Ok(None);
        }
        let stream = new_stream(session, stream_id, StreamPhase::SynReceived);
        state.streams.insert(stream_id, stream.clone());
        state.inbound_streams += 1;
        stream
    };
    let mut pending = PendingStreamGuard::new(session.clone(), stream.clone());
    if let Err(error) = stream.replenish_window().await {
        pending.remove().await;
        return Err(error);
    }
    pending.disarm();
    if session.incoming_tx.send(stream.clone()).await.is_err() {
        stream.reset().await?;
        return Ok(None);
    }
    Ok(Some(stream))
}

fn new_stream(session: &Arc<SessionInner>, id: u32, phase: StreamPhase) -> YamuxStream {
    YamuxStream(Arc::new(StreamInner {
        id,
        session: Arc::downgrade(session),
        state: Mutex::new(StreamState {
            phase,
            receive_window: DEFAULT_STREAM_WINDOW,
            receive_queue: VecDeque::new(),
            receive_bytes: 0,
        }),
        read_notify: Notify::new(),
        write_notify: Notify::new(),
        send_window: SyncMutex::new(DEFAULT_STREAM_WINDOW),
        write_queue_bytes: AtomicUsize::new(0),
        write_serial: Mutex::new(()),
        exact_read_serial: Mutex::new(()),
        exact_read_buffer: Mutex::new(VecDeque::new()),
        discarded: AtomicBool::new(false),
    }))
}

fn lock_send_window(window: &SyncMutex<usize>) -> std::sync::MutexGuard<'_, usize> {
    window
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn reserve_write_queue_bytes(
    queued: &AtomicUsize,
    limit: usize,
    bytes: usize,
) -> Result<WriteQueueReservation<'_>, YamuxError> {
    if bytes == 0 {
        return Ok(WriteQueueReservation { queued, bytes: 0 });
    }
    let mut current = queued.load(Ordering::Relaxed);
    loop {
        let attempted = current.checked_add(bytes).unwrap_or(usize::MAX);
        if attempted > limit {
            return Err(YamuxError::ResourceExhausted {
                resource: "stream_write_queue_bytes",
                current: attempted,
                limit,
            });
        }
        match queued.compare_exchange_weak(current, attempted, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return Ok(WriteQueueReservation { queued, bytes }),
            Err(observed) => current = observed,
        }
    }
}

fn reserve_receive_bytes(
    received: &AtomicUsize,
    limit: usize,
    bytes: usize,
) -> Result<SessionReceiveReservation<'_>, YamuxError> {
    if bytes == 0 {
        return Ok(SessionReceiveReservation {
            received,
            bytes: 0,
            committed: false,
        });
    }
    let mut current = received.load(Ordering::Relaxed);
    loop {
        let attempted = current.checked_add(bytes).unwrap_or(usize::MAX);
        if attempted > limit {
            return Err(YamuxError::ResourceExhausted {
                resource: "session_receive_bytes",
                current: attempted,
                limit,
            });
        }
        match received.compare_exchange_weak(
            current,
            attempted,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                return Ok(SessionReceiveReservation {
                    received,
                    bytes,
                    committed: false,
                });
            }
            Err(observed) => current = observed,
        }
    }
}

fn planned_send_flags(phase: StreamPhase) -> (u16, StreamPhase) {
    match phase {
        StreamPhase::Initial => (FLAG_SYN, StreamPhase::SynSent),
        StreamPhase::SynReceived => (FLAG_ACK, StreamPhase::Established),
        other => (0, other),
    }
}

fn process_flags(phase: &mut StreamPhase, flags: u16) {
    if flags & FLAG_ACK != 0 && *phase == StreamPhase::SynSent {
        *phase = StreamPhase::Established;
    }
    if flags & FLAG_FIN != 0 {
        *phase = match *phase {
            StreamPhase::LocalClosed => StreamPhase::Closed,
            StreamPhase::Established | StreamPhase::SynSent | StreamPhase::SynReceived => {
                StreamPhase::RemoteClosed
            }
            other => other,
        };
    }
    if flags & FLAG_RST != 0 {
        *phase = StreamPhase::Reset;
    }
}

fn ensure_writable(phase: StreamPhase) -> Result<(), YamuxError> {
    match phase {
        StreamPhase::Reset => Err(YamuxError::Reset),
        StreamPhase::Closed | StreamPhase::LocalClosed => Err(YamuxError::StreamClosed),
        _ => Ok(()),
    }
}

fn inbound_id_valid(mode: Mode, stream_id: u32) -> bool {
    stream_id != 0
        && stream_id % 2
            == match mode {
                Mode::Client => 0,
                Mode::Server => 1,
            }
}

struct ByteReader {
    connection: Arc<dyn ByteDuplex>,
    buffered: VecDeque<u8>,
}

impl ByteReader {
    fn new(connection: Arc<dyn ByteDuplex>) -> Self {
        Self {
            connection,
            buffered: VecDeque::new(),
        }
    }

    async fn read_exact(&mut self, length: usize) -> Result<Vec<u8>, YamuxError> {
        while self.buffered.len() < length {
            let chunk = self.connection.read().await?;
            if chunk.is_empty() {
                return Err(YamuxError::Closed);
            }
            self.buffered.extend(chunk);
        }
        Ok(self.buffered.drain(..length).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        e2ee::{
            ClientHandshakeOptions, Secret32, ServerHandshakeCache, ServerHandshakeOptions, Suite,
            client_handshake, server_handshake,
        },
        transport::{WebSocketMessage, WebSocketTransport},
    };
    use std::{
        future::pending,
        io,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Debug)]
    struct PendingDuplex;

    #[async_trait]
    impl ByteDuplex for PendingDuplex {
        async fn read(&self) -> Result<Vec<u8>, YamuxError> {
            pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), YamuxError> {
            Ok(())
        }

        async fn close(&self) -> Result<(), YamuxError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct BlockingWriteDuplex {
        writes: AtomicUsize,
        write_started: Notify,
    }

    #[derive(Debug)]
    struct GatedWriteDuplex {
        pass_writes: usize,
        writes: AtomicUsize,
        finished_writes: AtomicUsize,
        blocked: AtomicBool,
        write_started: Notify,
        write_released: Notify,
        close_calls: AtomicUsize,
    }

    impl GatedWriteDuplex {
        fn new(pass_writes: usize) -> Self {
            Self {
                pass_writes,
                writes: AtomicUsize::new(0),
                finished_writes: AtomicUsize::new(0),
                blocked: AtomicBool::new(true),
                write_started: Notify::new(),
                write_released: Notify::new(),
                close_calls: AtomicUsize::new(0),
            }
        }

        fn release(&self) {
            self.blocked.store(false, Ordering::SeqCst);
            self.write_released.notify_waiters();
        }
    }

    #[derive(Debug)]
    struct ControlledSecureTransport {
        incoming: Mutex<mpsc::Receiver<WebSocketMessage>>,
        outgoing: mpsc::Sender<WebSocketMessage>,
        send_mode: AtomicUsize,
        send_started: Notify,
        send_released: Notify,
        closed: AtomicBool,
    }

    impl ControlledSecureTransport {
        fn block_sends(&self) {
            self.send_mode.store(1, Ordering::SeqCst);
        }

        fn fail_sends(&self) {
            self.send_mode.store(2, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl WebSocketTransport for ControlledSecureTransport {
        async fn receive(&self) -> io::Result<Option<WebSocketMessage>> {
            Ok(self.incoming.lock().await.recv().await)
        }

        async fn send(&self, message: WebSocketMessage) -> io::Result<()> {
            match self.send_mode.load(Ordering::SeqCst) {
                1 => {
                    self.send_started.notify_waiters();
                    loop {
                        let released = self.send_released.notified();
                        tokio::pin!(released);
                        released.as_mut().enable();
                        if self.send_mode.load(Ordering::SeqCst) != 1 {
                            break;
                        }
                        released.await;
                    }
                }
                2 => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "controlled secure transport write failure",
                    ));
                }
                _ => {}
            }
            if self.closed.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlled secure transport is closed",
                ));
            }
            self.outgoing
                .send(message)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer closed"))
        }

        async fn close(&self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            self.send_mode.store(0, Ordering::SeqCst);
            self.send_released.notify_waiters();
            Ok(())
        }
    }

    #[async_trait]
    impl ByteDuplex for GatedWriteDuplex {
        async fn read(&self) -> Result<Vec<u8>, YamuxError> {
            pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), YamuxError> {
            let write = self.writes.fetch_add(1, Ordering::SeqCst);
            if write < self.pass_writes {
                self.finished_writes.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            self.write_started.notify_waiters();
            loop {
                let released = self.write_released.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                if !self.blocked.load(Ordering::SeqCst) {
                    self.finished_writes.fetch_add(1, Ordering::SeqCst);
                    return Ok(());
                }
                released.await;
            }
        }

        async fn close(&self) -> Result<(), YamuxError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            self.release();
            Ok(())
        }
    }

    #[async_trait]
    impl ByteDuplex for BlockingWriteDuplex {
        async fn read(&self) -> Result<Vec<u8>, YamuxError> {
            pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), YamuxError> {
            if self.writes.fetch_add(1, Ordering::Relaxed) == 0 {
                return Ok(());
            }
            self.write_started.notify_one();
            pending().await
        }

        async fn close(&self) -> Result<(), YamuxError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailingWriteDuplex;

    #[async_trait]
    impl ByteDuplex for FailingWriteDuplex {
        async fn read(&self) -> Result<Vec<u8>, YamuxError> {
            pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), YamuxError> {
            Err(YamuxError::Transport("write failed".to_owned()))
        }

        async fn close(&self) -> Result<(), YamuxError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct HangingCloseDuplex {
        close_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ByteDuplex for HangingCloseDuplex {
        async fn read(&self) -> Result<Vec<u8>, YamuxError> {
            pending().await
        }

        async fn write(&self, _bytes: &[u8]) -> Result<(), YamuxError> {
            Ok(())
        }

        async fn close(&self) -> Result<(), YamuxError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            pending().await
        }
    }

    #[test]
    fn liveness_options_resolve_path_defaults_and_explicit_values() {
        assert_eq!(LivenessOptions::default(), LivenessOptions::PathDefault);
        assert_eq!(
            resolve_liveness(LivenessOptions::PathDefault, None),
            Ok(None)
        );
        assert_eq!(
            resolve_liveness(LivenessOptions::PathDefault, Some(Duration::from_secs(30))),
            Ok(Some(AutomaticLiveness {
                interval: Duration::from_secs(15),
                timeout: Duration::from_secs(10),
            }))
        );
        assert_eq!(
            resolve_liveness(
                LivenessOptions::PathDefault,
                Some(Duration::from_millis(200))
            ),
            Ok(Some(AutomaticLiveness {
                interval: Duration::from_millis(500),
                timeout: Duration::from_millis(500),
            }))
        );
        assert_eq!(
            resolve_liveness(LivenessOptions::Disabled, Some(Duration::from_secs(30))),
            Ok(None)
        );
        assert_eq!(
            resolve_liveness(
                LivenessOptions::Enabled {
                    interval: Duration::from_secs(3),
                    timeout: Duration::from_secs(1),
                },
                None,
            ),
            Ok(Some(AutomaticLiveness {
                interval: Duration::from_secs(3),
                timeout: Duration::from_secs(1),
            }))
        );
        assert!(
            resolve_liveness(
                LivenessOptions::Enabled {
                    interval: Duration::ZERO,
                    timeout: Duration::from_secs(1),
                },
                None,
            )
            .is_err()
        );
        assert!(
            resolve_liveness(
                LivenessOptions::Enabled {
                    interval: Duration::from_secs(1),
                    timeout: Duration::ZERO,
                },
                None,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn failed_ping_write_removes_its_waiter() {
        let session = YamuxSession::new(
            Arc::new(FailingWriteDuplex),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create session");

        let error = session
            .probe_liveness(Duration::from_secs(1))
            .await
            .expect_err("ping write must fail");
        assert!(matches!(error, YamuxError::Transport(_)));
        assert!(session.inner.state.lock().await.ping_waiters.is_empty());
        session.close().await.expect("close session");
    }

    #[tokio::test]
    async fn terminated_probe_preserves_the_session_error() {
        let session = YamuxSession::new(
            Arc::new(PendingDuplex),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create session");
        let probe_session = session.clone();
        let probe =
            tokio::spawn(async move { probe_session.probe_liveness(Duration::from_secs(1)).await });
        loop {
            if !session.inner.state.lock().await.ping_waiters.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        session
            .inner
            .terminate(Some(YamuxError::Transport("read failed".to_owned())))
            .await
            .expect("terminate session");

        let error = probe
            .await
            .expect("probe task")
            .expect_err("terminated probe must fail");
        assert!(matches!(error, YamuxError::Transport(message) if message == "read failed"));
    }

    #[tokio::test]
    async fn liveness_timeout_covers_a_blocked_ping_write() {
        let connection = Arc::new(GatedWriteDuplex::new(0));
        let session = YamuxSession::new(connection.clone(), Mode::Client, YamuxLimits::default())
            .expect("create session");
        let started = Instant::now();

        let error = session
            .probe_liveness(Duration::from_millis(10))
            .await
            .expect_err("blocked ping write must time out");

        assert!(matches!(error, YamuxError::PingTimeout));
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(session.inner.state.lock().await.ping_waiters.is_empty());
        assert!(matches!(
            session.terminal_error().await,
            Some(YamuxError::PingTimeout)
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.close_calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed out ping did not close the transport");
    }

    #[tokio::test]
    async fn canceling_liveness_probe_removes_its_waiter() {
        let connection = Arc::new(GatedWriteDuplex::new(0));
        let session = YamuxSession::new(connection.clone(), Mode::Client, YamuxLimits::default())
            .expect("create session");
        let probe_session = session.clone();
        let probe =
            tokio::spawn(
                async move { probe_session.probe_liveness(Duration::from_secs(10)).await },
            );

        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.writes.load(Ordering::SeqCst) == 0
                || session.inner.state.lock().await.ping_waiters.is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("probe did not register its waiter");
        probe.abort();
        assert!(
            probe
                .await
                .expect_err("probe task must be canceled")
                .is_cancelled()
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while !session.inner.state.lock().await.ping_waiters.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("canceled probe retained its waiter");
        session.close().await.expect("close session");
    }

    #[tokio::test]
    async fn liveness_timeout_does_not_wait_for_hanging_transport_close() {
        let close_calls = Arc::new(AtomicUsize::new(0));
        let connection = Arc::new(HangingCloseDuplex {
            close_calls: close_calls.clone(),
        });
        let weak = Arc::downgrade(&connection);
        let session = YamuxSession::new(connection.clone(), Mode::Client, YamuxLimits::default())
            .expect("create session");
        let started = Instant::now();

        let error = session
            .probe_liveness(Duration::from_millis(10))
            .await
            .expect_err("probe must time out");
        assert!(matches!(error, YamuxError::PingTimeout));
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(matches!(
            session.terminal_error().await,
            Some(YamuxError::PingTimeout)
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while close_calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background transport close did not start");

        drop(connection);
        drop(session);
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded liveness cleanup retained the connection");
    }

    #[tokio::test]
    async fn automatic_liveness_failure_sets_the_terminal_error() {
        let session = YamuxSession::new(
            Arc::new(FailingWriteDuplex),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("create session");
        session.start_automatic_liveness(
            AutomaticLiveness {
                interval: Duration::from_millis(1),
                timeout: Duration::from_secs(1),
            },
            None,
        );

        tokio::time::timeout(Duration::from_secs(1), session.wait_closed())
            .await
            .expect("automatic liveness did not terminate the session");
        assert!(matches!(
            session.terminal_error().await,
            Some(YamuxError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn canceling_open_stream_releases_active_stream_capacity() {
        let session = YamuxSession::new(
            Arc::new(PendingDuplex),
            Mode::Client,
            YamuxLimits {
                max_active_streams: 1,
                max_inbound_streams: 1,
                ..YamuxLimits::default()
            },
        )
        .expect("create session");
        let session_writer = session.inner.write_serial.lock().await;
        let mut open = Box::pin(session.open_stream());
        tokio::select! {
            result = &mut open => panic!("open unexpectedly completed: {result:?}"),
            () = async {
                loop {
                    if !session.inner.state.lock().await.streams.is_empty() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            } => {}
        }

        drop(open);
        drop(session_writer);
        assert!(session.inner.state.try_lock().unwrap().streams.is_empty());
        let stream = session
            .open_stream()
            .await
            .expect("capacity must be immediately reusable after canceled open");
        assert_eq!(session.inner.state.lock().await.streams.len(), 1);
        stream.reset().await.expect("reset replacement stream");
    }

    #[tokio::test]
    async fn canceled_open_under_session_state_contention_does_not_consume_capacity() {
        let session = YamuxSession::new(
            Arc::new(PendingDuplex),
            Mode::Client,
            YamuxLimits {
                max_active_streams: 1,
                max_inbound_streams: 1,
                ..YamuxLimits::default()
            },
        )
        .expect("create session");
        let session_writer = session.inner.write_serial.lock().await;
        let mut open = Box::pin(session.open_stream());
        assert!(futures_util::poll!(&mut open).is_pending());
        let state = session.inner.state.lock().await;
        assert_eq!(state.streams.len(), 1);

        drop(open);
        assert!(
            state
                .streams
                .values()
                .next()
                .expect("pending stream")
                .is_discarded()
        );
        drop(session_writer);
        drop(state);
        let stream = session
            .open_stream()
            .await
            .expect("discarded stream must not consume capacity on immediate retry");
        assert_eq!(session.inner.state.lock().await.streams.len(), 1);
        stream.reset().await.expect("reset replacement stream");
    }

    #[tokio::test]
    async fn canceling_fin_phase_commit_after_wire_write_terminates_the_session() {
        let connection = Arc::new(GatedWriteDuplex::new(1));
        let (session, stream) = test_stream_with(connection.clone()).await;
        let close_stream = stream.clone();
        let close = tokio::spawn(async move { close_stream.close().await });

        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.writes.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("FIN write did not start");
        let state = stream.0.state.lock().await;
        connection.release();
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.finished_writes.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("FIN write did not reach the transport");

        close.abort();
        assert!(
            close
                .await
                .expect_err("close task must be canceled")
                .is_cancelled()
        );
        tokio::time::timeout(Duration::from_secs(1), session.wait_closed())
            .await
            .expect("canceled FIN phase commit did not terminate the session");
        assert!(matches!(
            session.terminal_error().await,
            Some(YamuxError::Transport(message)) if message == CANCELED_PHASE_COMMIT_ERROR
        ));
        assert!(!matches!(
            state.phase,
            StreamPhase::LocalClosed | StreamPhase::Closed
        ));
        drop(state);
    }

    #[tokio::test]
    async fn canceled_secure_frame_write_terminates_the_session() {
        let (client_transport, client_session, server_session, client_stream, _server_stream) =
            secure_stream_pair().await;
        client_transport.block_sends();
        let send_started = client_transport.send_started.notified();
        tokio::pin!(send_started);
        send_started.as_mut().enable();
        let writer_stream = client_stream.clone();
        let writer =
            tokio::spawn(async move { writer_stream.write(b"blocked secure write").await });

        tokio::time::timeout(Duration::from_secs(1), send_started)
            .await
            .expect("secure transport write did not start");
        writer.abort();
        assert!(
            writer
                .await
                .expect_err("secure write task must be canceled")
                .is_cancelled()
        );
        tokio::time::timeout(Duration::from_secs(1), client_session.wait_closed())
            .await
            .expect("canceled secure frame write did not terminate the session");
        assert!(matches!(
            client_session.terminal_error().await,
            Some(YamuxError::Transport(message)) if message == "frame write canceled"
        ));
        assert!(matches!(
            client_session.open_stream().await,
            Err(YamuxError::Transport(_))
        ));
        server_session.close_bounded().await;
    }

    #[tokio::test]
    async fn failed_secure_frame_write_terminates_the_session() {
        let (client_transport, client_session, server_session, client_stream, _server_stream) =
            secure_stream_pair().await;
        client_transport.fail_sends();

        let error = client_stream
            .write(b"failed secure write")
            .await
            .expect_err("secure transport failure must fail the stream write");
        assert!(matches!(error, YamuxError::Transport(_)));
        tokio::time::timeout(Duration::from_secs(1), client_session.wait_closed())
            .await
            .expect("failed secure frame write did not terminate the session");
        assert!(matches!(
            client_session.terminal_error().await,
            Some(YamuxError::Transport(message))
                if message.contains("controlled secure transport write failure")
        ));
        assert!(matches!(
            client_session.open_stream().await,
            Err(YamuxError::Transport(_))
        ));
        server_session.close_bounded().await;
    }

    #[tokio::test]
    async fn canceling_read_preserves_payload_and_receive_accounting() {
        let (session, stream) = test_stream().await;
        let payload = vec![0x47; DEFAULT_STREAM_WINDOW / 2];
        let reservation = session
            .inner
            .reserve_receive_bytes(payload.len())
            .expect("reserve session receive bytes");
        assert!(
            stream
                .on_data(FLAG_ACK, payload.clone())
                .await
                .expect("queue test payload")
        );
        reservation.commit();
        let session_writer = session.inner.write_serial.lock().await;
        let mut reader = Box::pin(stream.read());
        assert!(futures_util::poll!(&mut reader).is_pending());
        drop(reader);
        {
            let state = stream.0.state.lock().await;
            assert_eq!(state.receive_queue.front(), Some(&payload));
            assert_eq!(state.receive_bytes, payload.len());
            assert_eq!(state.receive_window, DEFAULT_STREAM_WINDOW - payload.len());
        }
        assert_eq!(
            session.inner.receive_bytes.load(Ordering::SeqCst),
            payload.len()
        );

        drop(session_writer);
        assert_eq!(
            stream.read().await.expect("retry read"),
            Some(payload.clone())
        );
        let state = stream.0.state.lock().await;
        assert!(state.receive_queue.is_empty());
        assert_eq!(state.receive_bytes, 0);
        assert_eq!(state.receive_window, DEFAULT_STREAM_WINDOW);
        drop(state);
        assert_eq!(session.inner.receive_bytes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn canceled_write_waiting_for_serial_lock_releases_queue_budget() {
        let (_session, stream) = test_stream().await;
        let serial = stream.0.write_serial.lock().await;
        let task_stream = stream.clone();
        let task = tokio::spawn(async move { task_stream.write(&[0x41; 64]).await });

        wait_for_queued_bytes(&stream, 64).await;
        task.abort();
        assert!(
            task.await
                .expect_err("write must be canceled")
                .is_cancelled()
        );
        assert_eq!(stream.0.write_queue_bytes.load(Ordering::Relaxed), 0);
        drop(serial);
    }

    #[tokio::test]
    async fn canceled_write_waiting_for_window_releases_queue_budget() {
        let (_session, stream) = test_stream().await;
        {
            let mut state = stream.0.state.lock().await;
            state.phase = StreamPhase::Established;
        }
        *lock_send_window(&stream.0.send_window) = 0;
        let task_stream = stream.clone();
        let task = tokio::spawn(async move { task_stream.write(&[0x42; 64]).await });

        wait_for_queued_bytes(&stream, 64).await;
        task.abort();
        assert!(
            task.await
                .expect_err("write must be canceled")
                .is_cancelled()
        );
        assert_eq!(stream.0.write_queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn canceled_write_waiting_for_session_writer_restores_send_window() {
        let (session, stream) = test_stream().await;
        let session_writer = session.inner.write_serial.lock().await;
        let task_stream = stream.clone();
        let task = tokio::spawn(async move { task_stream.write(&[0x43; 64]).await });

        wait_for_send_window(&stream, DEFAULT_STREAM_WINDOW - 64).await;
        task.abort();
        assert!(
            task.await
                .expect_err("write must be canceled")
                .is_cancelled()
        );
        assert_eq!(
            *lock_send_window(&stream.0.send_window),
            DEFAULT_STREAM_WINDOW
        );
        assert_eq!(stream.0.write_queue_bytes.load(Ordering::Relaxed), 0);
        drop(session_writer);
    }

    #[tokio::test]
    async fn canceled_transport_write_restores_send_window() {
        let connection = Arc::new(BlockingWriteDuplex {
            writes: AtomicUsize::new(0),
            write_started: Notify::new(),
        });
        let (_session, stream) = test_stream_with(connection.clone()).await;
        let task_stream = stream.clone();
        let task = tokio::spawn(async move { task_stream.write(&[0x44; 64]).await });

        tokio::time::timeout(Duration::from_secs(1), connection.write_started.notified())
            .await
            .expect("transport write did not start");
        assert_eq!(
            *lock_send_window(&stream.0.send_window),
            DEFAULT_STREAM_WINDOW - 64
        );
        task.abort();
        assert!(
            task.await
                .expect_err("write must be canceled")
                .is_cancelled()
        );
        assert_eq!(
            *lock_send_window(&stream.0.send_window),
            DEFAULT_STREAM_WINDOW
        );
        assert_eq!(stream.0.write_queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn window_update_notification_is_retained_before_waiter_poll() {
        let (_session, stream) = test_stream().await;
        *lock_send_window(&stream.0.send_window) = 0;
        let notified = stream.0.write_notify.notified();

        stream
            .on_window_update(0, 1)
            .await
            .expect("apply window update");

        tokio::time::timeout(Duration::from_secs(1), notified)
            .await
            .expect("window update notification was lost");
        assert_eq!(*lock_send_window(&stream.0.send_window), 1);
    }

    #[tokio::test]
    async fn canceled_write_after_window_update_does_not_overcredit_window() {
        let connection = Arc::new(BlockingWriteDuplex {
            writes: AtomicUsize::new(0),
            write_started: Notify::new(),
        });
        let (_session, stream) = test_stream_with(connection.clone()).await;
        let task_stream = stream.clone();
        let task = tokio::spawn(async move { task_stream.write(&[0x45; 64]).await });

        tokio::time::timeout(Duration::from_secs(1), connection.write_started.notified())
            .await
            .expect("transport write did not start");
        assert_eq!(
            *lock_send_window(&stream.0.send_window),
            DEFAULT_STREAM_WINDOW - 64
        );
        stream
            .on_window_update(0, 64)
            .await
            .expect("apply concurrent window update");
        assert_eq!(
            *lock_send_window(&stream.0.send_window),
            DEFAULT_STREAM_WINDOW
        );

        task.abort();
        assert!(
            task.await
                .expect_err("write must be canceled")
                .is_cancelled()
        );
        assert_eq!(
            *lock_send_window(&stream.0.send_window),
            DEFAULT_STREAM_WINDOW
        );
        assert_eq!(stream.0.write_queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn concurrent_wait_closed_callers_observe_termination() {
        let (session, _stream) = test_stream().await;
        let mut waiters = Vec::new();
        for _ in 0..64 {
            let waiter = session.clone();
            waiters.push(tokio::spawn(async move { waiter.wait_closed().await }));
        }
        tokio::task::yield_now().await;
        session.close().await.expect("close session");

        tokio::time::timeout(Duration::from_secs(1), async {
            for waiter in waiters {
                waiter.await.expect("join close waiter");
            }
        })
        .await
        .expect("close notification was lost");
    }

    #[tokio::test]
    async fn reset_wakes_stream_read_and_window_waiters() {
        let (_session, stream) = test_stream().await;
        {
            let mut state = stream.0.state.lock().await;
            state.phase = StreamPhase::Established;
        }
        *lock_send_window(&stream.0.send_window) = 0;

        let reader_stream = stream.clone();
        let reader = tokio::spawn(async move { reader_stream.read().await });
        let writer_stream = stream.clone();
        let writer = tokio::spawn(async move { writer_stream.write(&[0x46; 64]).await });
        wait_for_queued_bytes(&stream, 64).await;
        tokio::task::yield_now().await;

        stream.mark_reset().await;
        let (read_result, write_result) = tokio::time::timeout(Duration::from_secs(1), async {
            (
                reader.await.expect("join reader"),
                writer.await.expect("join writer"),
            )
        })
        .await
        .expect("stream reset notification was lost");
        assert!(matches!(read_result, Err(YamuxError::Reset)));
        assert!(matches!(write_result, Err(YamuxError::Reset)));
        assert_eq!(stream.0.write_queue_bytes.load(Ordering::Relaxed), 0);
    }

    async fn secure_stream_pair() -> (
        Arc<ControlledSecureTransport>,
        YamuxSession,
        YamuxSession,
        YamuxStream,
        YamuxStream,
    ) {
        let (client_transport, server_transport) = secure_transport_pair();
        let psk = [0x52_u8; 32];
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs() as i64
            + 60;
        let server_handshake_task = tokio::spawn(async move {
            let cache = ServerHandshakeCache::default();
            let mut options = ServerHandshakeOptions::new(
                Secret32::new(psk),
                Suite::X25519HkdfSha256Aes256Gcm,
                expires,
            );
            options.channel_id = Some("yamux-secure-cancel-test".to_owned());
            server_handshake(server_transport, &cache, options)
                .await
                .expect("server secure handshake")
        });
        let client_secure = client_handshake(
            client_transport.clone(),
            ClientHandshakeOptions::new(
                Secret32::new(psk),
                Suite::X25519HkdfSha256Aes256Gcm,
                "yamux-secure-cancel-test",
            ),
        )
        .await
        .expect("client secure handshake");
        let server_secure = server_handshake_task.await.expect("server handshake task");
        let client_session = YamuxSession::new(
            Arc::new(client_secure),
            Mode::Client,
            YamuxLimits::default(),
        )
        .expect("client Yamux session");
        let server_session = YamuxSession::new(
            Arc::new(server_secure),
            Mode::Server,
            YamuxLimits::default(),
        )
        .expect("server Yamux session");
        let client_stream = client_session
            .open_stream()
            .await
            .expect("open secure Yamux stream");
        let server_stream =
            tokio::time::timeout(Duration::from_secs(1), server_session.accept_stream())
                .await
                .expect("server did not receive secure Yamux stream")
                .expect("accept secure Yamux stream");
        (
            client_transport,
            client_session,
            server_session,
            client_stream,
            server_stream,
        )
    }

    fn secure_transport_pair() -> (
        Arc<ControlledSecureTransport>,
        Arc<ControlledSecureTransport>,
    ) {
        let (client_tx, server_rx) = mpsc::channel(32);
        let (server_tx, client_rx) = mpsc::channel(32);
        (
            Arc::new(ControlledSecureTransport {
                incoming: Mutex::new(client_rx),
                outgoing: client_tx,
                send_mode: AtomicUsize::new(0),
                send_started: Notify::new(),
                send_released: Notify::new(),
                closed: AtomicBool::new(false),
            }),
            Arc::new(ControlledSecureTransport {
                incoming: Mutex::new(server_rx),
                outgoing: server_tx,
                send_mode: AtomicUsize::new(0),
                send_started: Notify::new(),
                send_released: Notify::new(),
                closed: AtomicBool::new(false),
            }),
        )
    }

    async fn test_stream() -> (YamuxSession, YamuxStream) {
        test_stream_with(Arc::new(PendingDuplex)).await
    }

    async fn test_stream_with(connection: Arc<dyn ByteDuplex>) -> (YamuxSession, YamuxStream) {
        let limits = YamuxLimits {
            max_stream_write_queue_bytes: 64,
            ..YamuxLimits::default()
        };
        let session = YamuxSession::new(connection, Mode::Client, limits).expect("create session");
        let stream = session.open_stream().await.expect("open stream");
        (session, stream)
    }

    async fn wait_for_queued_bytes(stream: &YamuxStream, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while stream.0.write_queue_bytes.load(Ordering::Relaxed) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("write did not reserve queue budget");
    }

    async fn wait_for_send_window(stream: &YamuxStream, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while *lock_send_window(&stream.0.send_window) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("write did not reserve send window");
    }
}
