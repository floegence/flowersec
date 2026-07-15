use async_trait::async_trait;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};

use crate::{defaults, e2ee::SecureChannel, transport::WebSocketTransport};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Client,
    Server,
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
            max_stream_write_queue_bytes: defaults::MAX_OUTBOUND_BUFFERED_BYTES,
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

#[derive(Debug, thiserror::Error)]
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
        SecureChannel::read(self)
            .await
            .map_err(|error| YamuxError::Transport(error.to_string()))
    }

    async fn write(&self, bytes: &[u8]) -> Result<(), YamuxError> {
        SecureChannel::write(self, bytes)
            .await
            .map_err(|error| YamuxError::Transport(error.to_string()))
    }

    async fn close(&self) -> Result<(), YamuxError> {
        SecureChannel::close(self)
            .await
            .map_err(|error| YamuxError::Transport(error.to_string()))
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
    send_window: usize,
    receive_queue: VecDeque<Vec<u8>>,
    receive_bytes: usize,
    write_queue_bytes: usize,
}

#[derive(Debug)]
struct StreamInner {
    id: u32,
    session: Weak<SessionInner>,
    state: Mutex<StreamState>,
    read_notify: Notify,
    write_notify: Notify,
    write_serial: Mutex<()>,
    exact_read_serial: Mutex<()>,
    exact_read_buffer: Mutex<VecDeque<u8>>,
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

    pub async fn read(&self) -> Result<Option<Vec<u8>>, YamuxError> {
        loop {
            let notified = self.0.read_notify.notified();
            let (payload, replenish, terminal) = {
                let mut state = self.0.state.lock().await;
                if state.phase == StreamPhase::Reset {
                    return Err(YamuxError::Reset);
                }
                let payload = state.receive_queue.pop_front();
                let replenish = payload.as_ref().map_or(0, Vec::len);
                if replenish > 0 {
                    state.receive_bytes -= replenish;
                }
                let terminal =
                    matches!(state.phase, StreamPhase::Closed | StreamPhase::RemoteClosed);
                (payload, replenish, terminal)
            };
            if let Some(payload) = payload {
                let session = self.session()?;
                session.release_receive_bytes(replenish).await;
                self.replenish_window().await?;
                return Ok(Some(payload));
            }
            if terminal {
                return Ok(None);
            }
            notified.await;
        }
    }

    pub async fn write(&self, payload: &[u8]) -> Result<(), YamuxError> {
        let session = self.session()?;
        let next_queued = {
            let mut state = self.0.state.lock().await;
            ensure_writable(state.phase)?;
            let next = state.write_queue_bytes.saturating_add(payload.len());
            if next > session.limits.max_stream_write_queue_bytes {
                return Err(YamuxError::ResourceExhausted {
                    resource: "stream_write_queue_bytes",
                    current: next,
                    limit: session.limits.max_stream_write_queue_bytes,
                });
            }
            state.write_queue_bytes = next;
            next
        };
        let _serial = self.0.write_serial.lock().await;
        let result = self.write_serial(payload, &session).await;
        let mut state = self.0.state.lock().await;
        state.write_queue_bytes = state
            .write_queue_bytes
            .saturating_sub(next_queued.min(payload.len()));
        result
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
        let flags = {
            let mut state = self.0.state.lock().await;
            if matches!(state.phase, StreamPhase::Closed | StreamPhase::Reset) {
                return Ok(());
            }
            let remote_closed = state.phase == StreamPhase::RemoteClosed;
            let flags = send_flags(&mut state.phase) | FLAG_FIN;
            state.phase = if remote_closed {
                StreamPhase::Closed
            } else {
                StreamPhase::LocalClosed
            };
            flags
        };
        session
            .write_frame(
                Header {
                    frame_type: TYPE_WINDOW_UPDATE,
                    flags,
                    stream_id: self.id(),
                    length: 0,
                },
                &[],
            )
            .await?;
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
            let (allowed, flags) = {
                let mut state = self.0.state.lock().await;
                ensure_writable(state.phase)?;
                if state.send_window == 0 {
                    (0, 0)
                } else {
                    let allowed = (payload.len() - offset)
                        .min(session.limits.preferred_outbound_frame_bytes)
                        .min(state.send_window);
                    state.send_window -= allowed;
                    (allowed, send_flags(&mut state.phase))
                }
            };
            if allowed == 0 {
                notified.await;
                continue;
            }
            session
                .write_frame(
                    Header {
                        frame_type: TYPE_DATA,
                        flags,
                        stream_id: self.id(),
                        length: allowed as u32,
                    },
                    &payload[offset..offset + allowed],
                )
                .await?;
            offset += allowed;
        }
        Ok(())
    }

    async fn replenish_window(&self) -> Result<(), YamuxError> {
        let session = self.session()?;
        let (delta, flags) = {
            let mut state = self.0.state.lock().await;
            let target = DEFAULT_STREAM_WINDOW.saturating_sub(state.receive_bytes);
            let delta = target.saturating_sub(state.receive_window);
            let flags = send_flags(&mut state.phase);
            if delta < DEFAULT_STREAM_WINDOW / 2 && flags == 0 {
                return Ok(());
            }
            state.receive_window = state.receive_window.saturating_add(delta);
            (delta, flags)
        };
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
            .await
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
        drop(state);
        self.0.read_notify.notify_waiters();
        Ok(true)
    }

    async fn on_window_update(&self, flags: u16, delta: usize) -> Result<(), YamuxError> {
        let mut state = self.0.state.lock().await;
        process_flags(&mut state.phase, flags);
        if delta > DEFAULT_STREAM_WINDOW.saturating_sub(state.send_window) {
            return Err(YamuxError::InvalidFrame);
        }
        state.send_window += delta;
        drop(state);
        self.0.write_notify.notify_waiters();
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
            session.release_receive_bytes(released).await;
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

#[derive(Debug)]
struct SessionState {
    streams: HashMap<u32, YamuxStream>,
    inbound_streams: usize,
    next_stream_id: u32,
    next_ping_id: u32,
    ping_waiters: HashMap<u32, PingWaiter>,
    receive_bytes: usize,
    closed: bool,
}

struct SessionInner {
    connection: Arc<dyn ByteDuplex>,
    mode: Mode,
    limits: YamuxLimits,
    state: Mutex<SessionState>,
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
            mode,
            limits,
            state: Mutex::new(SessionState {
                streams: HashMap::new(),
                inbound_streams: 0,
                next_stream_id: if mode == Mode::Client { 1 } else { 2 },
                next_ping_id: 1,
                ping_waiters: HashMap::new(),
                receive_bytes: 0,
                closed: false,
            }),
            incoming_tx,
            write_serial: Mutex::new(()),
            close_notify: Notify::new(),
        });
        tokio::spawn(read_loop(inner.clone()));
        Ok(Self {
            inner,
            incoming_rx: Arc::new(Mutex::new(incoming_rx)),
        })
    }

    pub async fn open_stream(&self) -> Result<YamuxStream, YamuxError> {
        let stream = {
            let mut state = self.inner.state.lock().await;
            if state.closed {
                return Err(YamuxError::Closed);
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
        stream.replenish_window().await?;
        Ok(stream)
    }

    pub async fn accept_stream(&self) -> Result<YamuxStream, YamuxError> {
        self.incoming_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(YamuxError::Closed)
    }

    pub async fn probe_liveness(&self, timeout: Duration) -> Result<Duration, YamuxError> {
        if timeout.is_zero() {
            return Err(YamuxError::PingTimeout);
        }
        let (opaque, receiver) = {
            let mut state = self.inner.state.lock().await;
            if state.closed {
                return Err(YamuxError::Closed);
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
        match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(duration)) => Ok(duration),
            _ => {
                self.inner.state.lock().await.ping_waiters.remove(&opaque);
                self.close().await?;
                Err(YamuxError::PingTimeout)
            }
        }
    }

    pub async fn close(&self) -> Result<(), YamuxError> {
        self.inner.close().await
    }

    pub async fn wait_closed(&self) {
        if self.inner.state.lock().await.closed {
            return;
        }
        self.inner.close_notify.notified().await;
    }
}

impl SessionInner {
    async fn write_frame(&self, header: Header, payload: &[u8]) -> Result<(), YamuxError> {
        if header.frame_type == TYPE_DATA && payload.len() != header.length as usize {
            return Err(YamuxError::InvalidFrame);
        }
        if header.frame_type != TYPE_DATA && !payload.is_empty() {
            return Err(YamuxError::InvalidFrame);
        }
        let _serial = self.write_serial.lock().await;
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(payload);
        self.connection.write(&frame).await
    }

    async fn send_reset(&self, stream_id: u32) -> Result<(), YamuxError> {
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
        if state.streams.remove(&stream_id).is_some() && inbound_id_valid(self.mode, stream_id) {
            state.inbound_streams = state.inbound_streams.saturating_sub(1);
        }
    }

    async fn release_receive_bytes(&self, bytes: usize) {
        let mut state = self.state.lock().await;
        state.receive_bytes = state.receive_bytes.saturating_sub(bytes);
    }

    async fn close(&self) -> Result<(), YamuxError> {
        let streams = {
            let mut state = self.state.lock().await;
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            state.ping_waiters.clear();
            state.streams.values().cloned().collect::<Vec<_>>()
        };
        self.close_notify.notify_waiters();
        for stream in streams {
            stream.mark_reset().await;
        }
        self.connection.close().await
    }
}

async fn read_loop(session: Arc<SessionInner>) {
    let mut reader = ByteReader::new(session.connection.clone());
    loop {
        let result = async {
            let header = Header::decode(&reader.read_exact(HEADER_LEN).await?)?;
            match header.frame_type {
                TYPE_DATA => {
                    if header.stream_id == 0
                        || header.length as usize > session.limits.max_frame_bytes
                    {
                        return Err(YamuxError::InvalidFrame);
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
        if result.is_err() {
            let _ = session.close().await;
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
    {
        let mut state = session.state.lock().await;
        if state.receive_bytes.saturating_add(payload.len())
            > session.limits.max_session_receive_bytes
        {
            return Err(YamuxError::ResourceExhausted {
                resource: "session_receive_bytes",
                current: state.receive_bytes.saturating_add(payload.len()),
                limit: session.limits.max_session_receive_bytes,
            });
        }
        state.receive_bytes += payload.len();
    }
    if !stream.on_data(header.flags, payload).await? {
        session.release_receive_bytes(header.length as usize).await;
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
            let _ = waiter.sender.send(waiter.started_at.elapsed());
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
    let existing = session.state.lock().await.streams.get(&stream_id).cloned();
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
    stream.replenish_window().await?;
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
            send_window: DEFAULT_STREAM_WINDOW,
            receive_queue: VecDeque::new(),
            receive_bytes: 0,
            write_queue_bytes: 0,
        }),
        read_notify: Notify::new(),
        write_notify: Notify::new(),
        write_serial: Mutex::new(()),
        exact_read_serial: Mutex::new(()),
        exact_read_buffer: Mutex::new(VecDeque::new()),
    }))
}

fn send_flags(phase: &mut StreamPhase) -> u16 {
    match phase {
        StreamPhase::Initial => {
            *phase = StreamPhase::SynSent;
            FLAG_SYN
        }
        StreamPhase::SynReceived => {
            *phase = StreamPhase::Established;
            FLAG_ACK
        }
        _ => 0,
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
