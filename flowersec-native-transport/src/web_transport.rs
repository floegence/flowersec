//! Dedicated, bounded native H3 CONNECT ownership. Application streams expose
//! only Flowersec bytes; their actual WT stream prefixes and HTTP datagram
//! contexts remain with this original physical connection.
use crate::quic_provider as quinn;
use crate::{
    Cancellation, CandidatePreparationBudget, DatagramSubmission, PathProfile, PreparationLimits,
    RawQuicClientConfig, RawQuicError, RawQuicLimits, RawQuicListener, RawQuicServerConfig,
    RawQuicSession, RawQuicStream,
};
use bytes::Bytes;
use qpack::{HeaderField, decode_stateless, encode_stateless};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Notify, Semaphore, mpsc};
use tokio_util::task::TaskTracker;

const H3_DATAGRAM: u64 = 0x33;
const CHROMIUM_DRAFT02: u64 = 0x2b603742;
const NATIVE_H3_SESSIONS: u64 = 0x2c7cf000;
fn protocol() -> RawQuicError {
    RawQuicError::WebTransportProtocol
}
#[derive(Clone, Debug)]
pub struct WebTransportConfig {
    pub server_name: String,
    pub path: String,
    pub tuples: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub allow_absent_origin: bool,
    pub header_bytes: usize,
    pub control_bytes: usize,
    pub handshake_timeout: Duration,
}
impl WebTransportConfig {
    pub fn validate(&self) -> Result<(), RawQuicError> {
        if self.server_name.is_empty()
            || self.server_name.len() > 253
            || !(1024..=65536).contains(&self.header_bytes)
            || !(16384..=1048576).contains(&self.control_bytes)
            || self.handshake_timeout.is_zero()
            || !matches!(
                self.path.as_str(),
                "/flowersec/webtransport/v4/direct" | "/flowersec/webtransport/v4/tunnel"
            )
            || self.tuples.is_empty()
            || self.tuples.len() > 2
            || self.allowed_origins.len() > 64
        {
            return Err(RawQuicError::InvalidLimits);
        }
        let mut unique = BTreeSet::new();
        for tuple in &self.tuples {
            if !unique.insert(tuple) || !matches!(tuple.as_str(), "chromium_draft02" | "native_h3")
            {
                return Err(RawQuicError::InvalidLimits);
            }
        }
        let mut unique = BTreeSet::new();
        for origin in &self.allowed_origins {
            let parsed = url::Url::parse(origin).map_err(|_| RawQuicError::InvalidLimits)?;
            if !unique.insert(origin)
                || origin.len() > 4096
                || !matches!(parsed.scheme(), "https" | "http")
                || parsed.origin().ascii_serialization() != *origin
            {
                return Err(RawQuicError::InvalidLimits);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct WebTransportRequest {
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub origin: Option<String>,
    pub tuple: String,
    pub protocol: String,
    pub connect_stream_id: u64,
}
#[derive(Debug)]
pub struct WebTransportListener {
    raw: Arc<RawQuicListener>,
    config: WebTransportConfig,
    capacity: u32,
    incoming_preparation: bool,
}
impl WebTransportListener {
    pub fn bind(
        address: SocketAddr,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        limits: RawQuicLimits,
        config: WebTransportConfig,
    ) -> Result<Self, RawQuicError> {
        Self::bind_internal(
            address,
            None,
            certificate_chain,
            private_key,
            limits,
            config,
            None,
            None,
            None,
        )
    }
    pub fn bind_with_time_provider(
        address: SocketAddr,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        limits: RawQuicLimits,
        config: WebTransportConfig,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
    ) -> Result<Self, RawQuicError> {
        Self::bind_internal(
            address,
            None,
            certificate_chain,
            private_key,
            limits,
            config,
            Some(time_provider),
            None,
            None,
        )
    }
    /// Take ownership of a UDP socket bound by the deployment owner so the
    /// installed WebTransport route and listener retain one endpoint identity.
    pub fn from_socket_with_time_provider(
        socket: std::net::UdpSocket,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        limits: RawQuicLimits,
        config: WebTransportConfig,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
    ) -> Result<Self, RawQuicError> {
        let address = socket.local_addr().map_err(RawQuicError::Endpoint)?;
        Self::bind_internal(
            address,
            Some(socket),
            certificate_chain,
            private_key,
            limits,
            config,
            Some(time_provider),
            None,
            None,
        )
    }
    pub fn bind_with_preparation_budget(
        address: SocketAddr,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        limits: RawQuicLimits,
        config: WebTransportConfig,
        budget: CandidatePreparationBudget,
    ) -> Result<Self, RawQuicError> {
        Self::bind_internal(
            address,
            None,
            certificate_chain,
            private_key,
            limits,
            config,
            None,
            Some(budget),
            None,
        )
    }
    pub fn from_socket_with_time_provider_and_preparation_budget(
        socket: std::net::UdpSocket,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        limits: RawQuicLimits,
        config: WebTransportConfig,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
        budget: CandidatePreparationBudget,
    ) -> Result<Self, RawQuicError> {
        let address = socket.local_addr().map_err(RawQuicError::Endpoint)?;
        Self::bind_internal(
            address,
            Some(socket),
            certificate_chain,
            private_key,
            limits,
            config,
            Some(time_provider),
            Some(budget),
            None,
        )
    }
    pub fn bind_with_incoming_preparation_capacity(
        address: SocketAddr,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        limits: RawQuicLimits,
        config: WebTransportConfig,
        capacity: PreparationLimits,
    ) -> Result<Self, RawQuicError> {
        Self::bind_internal(
            address,
            None,
            certificate_chain,
            private_key,
            limits,
            config,
            None,
            None,
            Some(capacity),
        )
    }
    pub fn bind_with_time_provider_and_incoming_preparation_capacity(
        address: SocketAddr,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        limits: RawQuicLimits,
        config: WebTransportConfig,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
        capacity: PreparationLimits,
    ) -> Result<Self, RawQuicError> {
        Self::bind_internal(
            address,
            None,
            certificate_chain,
            private_key,
            limits,
            config,
            Some(time_provider),
            None,
            Some(capacity),
        )
    }
    pub fn from_socket_with_time_provider_and_incoming_preparation_capacity(
        socket: std::net::UdpSocket,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        limits: RawQuicLimits,
        config: WebTransportConfig,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
        capacity: PreparationLimits,
    ) -> Result<Self, RawQuicError> {
        let address = socket.local_addr().map_err(RawQuicError::Endpoint)?;
        Self::bind_internal(
            address,
            Some(socket),
            certificate_chain,
            private_key,
            limits,
            config,
            Some(time_provider),
            None,
            Some(capacity),
        )
    }
    fn bind_internal(
        address: SocketAddr,
        socket: Option<std::net::UdpSocket>,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        mut limits: RawQuicLimits,
        config: WebTransportConfig,
        time_provider: Option<Arc<dyn rustls::time_provider::TimeProvider>>,
        budget: Option<CandidatePreparationBudget>,
        incoming_capacity: Option<PreparationLimits>,
    ) -> Result<Self, RawQuicError> {
        config.validate()?;
        let capacity = limits.max_inbound_bidirectional_streams;
        let incoming_preparation = incoming_capacity.is_some();
        // CONNECT owns a distinct native stream and does not consume an
        // advertised Flowersec application or maintenance stream position.
        limits.max_inbound_bidirectional_streams =
            capacity.checked_add(1).ok_or(RawQuicError::InvalidLimits)?;
        let server = match time_provider {
            Some(clock) => RawQuicServerConfig::new_with_time_provider(
                PathProfile::WebTransportV4,
                certificate_chain,
                private_key,
                limits,
                clock,
            )?,
            None => RawQuicServerConfig::new(
                PathProfile::WebTransportV4,
                certificate_chain,
                private_key,
                limits,
            )?,
        };
        let server = match budget {
            Some(budget) => server.with_preparation_budget(budget)?,
            None => server,
        };
        let server = match incoming_capacity {
            Some(capacity) => server.with_incoming_preparation_capacity(capacity)?,
            None => server,
        };
        let raw = match socket {
            Some(socket) => RawQuicListener::from_socket(socket, server)?,
            None => RawQuicListener::bind(address, server)?,
        };
        Ok(Self {
            raw: Arc::new(raw),
            config,
            capacity,
            incoming_preparation,
        })
    }
    pub fn local_address(&self) -> Result<SocketAddr, RawQuicError> {
        self.raw.local_address()
    }
    pub async fn accept(
        &self,
        cancellation: &Cancellation,
    ) -> Result<WebTransportSession, RawQuicError> {
        loop {
            match self.accept_once(cancellation).await {
                Err(error)
                    if self.incoming_preparation
                        && crate::raw_quic::incoming_preparation_failure(&error)
                        && !cancellation.is_canceled() =>
                {
                    tokio::task::yield_now().await;
                }
                result => return result,
            }
        }
    }
    async fn accept_once(
        &self,
        cancellation: &Cancellation,
    ) -> Result<WebTransportSession, RawQuicError> {
        let raw = self.raw.accept(cancellation).await?;
        let original = raw.clone();
        let result = tokio::select! {
            _ = cancellation.cancelled() => Err(RawQuicError::Canceled),
            result = tokio::time::timeout(self.config.handshake_timeout, WebTransportSession::start(raw, self.config.clone(), self.capacity, false)) => result.map_err(|_| RawQuicError::Timeout).and_then(|value| value),
        };
        let session = match result {
            Ok(value) => value,
            Err(error) => {
                original.abort();
                original.wait_termination().await;
                if let Some(budget) = original.preparation_budget() {
                    budget.check()?;
                }
                return Err(error);
            }
        };
        let handshake = async {
            loop {
                let notified = session.inner.ready.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if session.inner.request.get().is_some() {
                    return Ok(());
                }
                tokio::select! { _ = notified => {}, _ = session.inner.raw.h3_connection().closed() => return Err(protocol()) }
            }
        };
        let result = tokio::select! {
            _ = cancellation.cancelled() => Err(RawQuicError::Canceled),
            result = tokio::time::timeout(self.config.handshake_timeout, handshake) => result.map_err(|_| RawQuicError::Timeout).and_then(|value| value),
        };
        if let Err(error) = result {
            session.abort();
            session.wait_termination().await;
            if let Some(budget) = session.inner.raw.preparation_budget() {
                budget.check()?;
            }
            return Err(error);
        }
        Ok(session)
    }
    pub fn stop_accepting_current(&self) {
        self.raw.stop_accepting_current();
    }
    pub fn abort(&self) {
        self.raw.abort();
    }
    pub async fn close(&self) {
        self.raw.close().await;
    }
    pub async fn wait_termination(&self) {
        self.raw.wait_termination().await;
    }
}
#[derive(Debug)]
struct State {
    raw: RawQuicSession,
    config: WebTransportConfig,
    capacity: u32,
    is_client: bool,
    request: OnceLock<WebTransportRequest>,
    ready: Notify,
    settings: Mutex<Option<BTreeMap<u64, u64>>>,
    settings_ready: Notify,
    request_seen: AtomicU8,
    uni_seen: AtomicU8,
    slots: Arc<Semaphore>,
    incoming: Mutex<mpsc::Receiver<(RawQuicStream, tokio::sync::OwnedSemaphorePermit)>>,
    outgoing: mpsc::Sender<(RawQuicStream, tokio::sync::OwnedSemaphorePermit)>,
    workers: TaskTracker,
}
#[derive(Clone, Debug)]
pub struct WebTransportSession {
    inner: Arc<State>,
}
impl WebTransportSession {
    async fn start(
        raw: RawQuicSession,
        config: WebTransportConfig,
        capacity: u32,
        is_client: bool,
    ) -> Result<Self, RawQuicError> {
        let (outgoing, incoming) = mpsc::channel(capacity as usize);
        let inner = Arc::new(State {
            raw,
            config,
            capacity,
            is_client,
            request: OnceLock::new(),
            ready: Notify::new(),
            settings: Mutex::new(None),
            settings_ready: Notify::new(),
            request_seen: AtomicU8::new(0),
            uni_seen: AtomicU8::new(0),
            slots: Arc::new(Semaphore::new(capacity as usize + 1)),
            incoming: Mutex::new(incoming),
            outgoing,
            workers: TaskTracker::new(),
        });
        let session = Self {
            inner: inner.clone(),
        };
        let mut controls = Vec::with_capacity(3);
        let result = async {
            for kind in [0u64, 2, 3] {
                let mut stream = inner
                    .raw
                    .h3_connection()
                    .open_uni()
                    .await
                    .map_err(|_| protocol())?;
                let mut bytes = Vec::with_capacity(96);
                put_varint(&mut bytes, kind)?;
                if kind == 0 {
                    let mut settings = Vec::with_capacity(64);
                    for (id, value) in [
                        (1, 0),
                        (7, 0),
                        (6, inner.config.header_bytes as u64),
                        (8, 1),
                        (H3_DATAGRAM, 1),
                    ] {
                        put_varint(&mut settings, id)?;
                        put_varint(&mut settings, value)?;
                    }
                    for (tuple, id) in [
                        ("chromium_draft02", CHROMIUM_DRAFT02),
                        ("native_h3", NATIVE_H3_SESSIONS),
                    ] {
                        if inner.config.tuples.iter().any(|value| value == tuple) {
                            put_varint(&mut settings, id)?;
                            put_varint(&mut settings, 1)?;
                        }
                    }
                    put_varint(&mut bytes, 4)?;
                    put_varint(&mut bytes, settings.len() as u64)?;
                    bytes.extend_from_slice(&settings);
                }
                stream.write_all(&bytes).await.map_err(|_| protocol())?;
                controls.push(stream);
            }
            Ok::<(), RawQuicError>(())
        }
        .await;
        if let Err(error) = result {
            inner.raw.abort();
            inner.raw.wait_termination().await;
            if let Some(budget) = inner.raw.preparation_budget() {
                budget.check()?;
            }
            return Err(error);
        }
        let owner = inner.clone();
        inner.workers.spawn(async move {
            owner.raw.wait_termination().await;
            drop(controls);
        });
        let owner = inner.clone();
        inner.workers.spawn(async move {
            accept_uni(owner).await;
        });
        let owner = inner.clone();
        inner.workers.spawn(async move {
            accept_bidi(owner).await;
        });
        inner.workers.close();
        Ok(session)
    }
    /// One native QUIC connection, one fixed HTTP/3 CONNECT, with actual negotiated reset capability.
    pub async fn connect_native_h3(
        remote: SocketAddr,
        tls: RawQuicClientConfig,
        config: WebTransportConfig,
        capacity: u32,
        cancellation: &Cancellation,
    ) -> Result<Self, RawQuicError> {
        config.validate()?;
        if config.tuples != ["native_h3"] || capacity == 0 {
            return Err(RawQuicError::InvalidLimits);
        }
        let local = SocketAddr::new(
            if remote.is_ipv4() {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            },
            0,
        );
        let deadline = tokio::time::Instant::now() + config.handshake_timeout;
        let tls = tls.cap_handshake_timeout(config.handshake_timeout)?;
        let raw =
            RawQuicSession::dial_from(local, remote, config.server_name.clone(), tls, cancellation)
                .await?;
        if !raw.h3_connection().supports_reliable_reset() {
            raw.abort();
            raw.wait_termination().await;
            return Err(RawQuicError::WebTransportPartialResetUnavailable);
        }
        let original = raw.clone();
        let starting = tokio::select! {
            _ = cancellation.cancelled() => Err(RawQuicError::Canceled),
            result = tokio::time::timeout_at(deadline, Self::start(raw, config, capacity, true)) => result.unwrap_or(Err(RawQuicError::Timeout)),
        };
        let session = match starting {
            Ok(session) => session,
            Err(error) => {
                original.abort();
                original.wait_termination().await;
                if let Some(budget) = original.preparation_budget() {
                    budget.check()?;
                }
                return Err(error);
            }
        };
        let result = tokio::select! {
            _ = cancellation.cancelled() => Err(RawQuicError::Canceled),
            result = tokio::time::timeout_at(deadline, session.send_connect(cancellation)) => result.unwrap_or(Err(RawQuicError::Timeout)),
        };
        if let Err(error) = result {
            session.abort();
            session.wait_termination().await;
            if let Some(budget) = session.inner.raw.preparation_budget() {
                budget.check()?;
            }
            return Err(error);
        }
        Ok(session)
    }

    async fn send_connect(&self, cancellation: &Cancellation) -> Result<(), RawQuicError> {
        let owner = &self.inner;
        await_settings(owner, "native_h3").await?;
        let host = if owner.config.server_name.contains(':') {
            format!("[{}]", owner.config.server_name)
        } else {
            owner.config.server_name.clone()
        };
        let authority = if owner.raw.peer_address().port() == 443 {
            host
        } else {
            format!("{host}:{}", owner.raw.peer_address().port())
        };
        let stream = owner.raw.open_stream(cancellation).await?;
        let headers = encode_headers(
            &[
                (":method", "CONNECT"),
                (":scheme", "https"),
                (":authority", &authority),
                (":path", &owner.config.path),
                (":protocol", "webtransport-h3"),
            ],
            owner.config.header_bytes,
        )?;
        let mut frame = Vec::with_capacity(headers.len() + 16);
        put_varint(&mut frame, 1)?;
        put_varint(&mut frame, headers.len() as u64)?;
        frame.extend_from_slice(&headers);
        stream.write_all_current(&frame).await?;
        if read_stream_varint(&stream).await? != 1 {
            return Err(protocol());
        }
        let count = usize::try_from(read_stream_varint(&stream).await?).map_err(|_| protocol())?;
        if count == 0 || count > owner.config.header_bytes {
            return Err(protocol());
        }
        let mut block = vec![0; count];
        read_stream_exact(&stream, &mut block).await?;
        let response = decode_headers(&block, owner.config.header_bytes)?;
        block.fill(0);
        if response.get(":status").map(String::as_str) != Some("200")
            || response.keys().any(|key| {
                key.starts_with(':') && key != ":status"
                    || matches!(
                        key.as_str(),
                        "sec-webtransport-http3-draft02"
                            | "wt-available-protocols"
                            | "wt-protocol"
                            | "capsule-protocol"
                            | "connection"
                            | "upgrade"
                            | "transfer-encoding"
                    )
            })
        {
            return Err(protocol());
        }
        owner
            .request
            .set(WebTransportRequest {
                scheme: "https".into(),
                authority,
                path: owner.config.path.clone(),
                origin: None,
                tuple: "native_h3".into(),
                protocol: "webtransport-h3".into(),
                connect_stream_id: stream.stream_id(),
            })
            .map_err(|_| protocol())?;
        owner.ready.notify_waiters();
        let state = owner.clone();
        owner.workers.spawn(async move {
            serve_connect(state, stream).await;
        });
        Ok(())
    }

    pub fn request(&self) -> Result<WebTransportRequest, RawQuicError> {
        let request = self.inner.request.get().ok_or_else(protocol)?;
        if let Some(budget) = self.inner.raw.preparation_budget() {
            let bytes = request.scheme.len()
                + request.authority.len()
                + request.path.len()
                + request.origin.as_ref().map_or(0, String::len)
                + request.tuple.len()
                + request.protocol.len();
            budget.debit_input(bytes as u64, 1)?;
        }
        Ok(request.clone())
    }
    pub fn path(&self) -> &'static str {
        if self.inner.config.path.ends_with("/direct") {
            "direct"
        } else {
            "tunnel"
        }
    }
    pub fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.capacity
    }
    pub fn raw(&self) -> &RawQuicSession {
        &self.inner.raw
    }
    pub async fn open_stream(
        &self,
        cancellation: &Cancellation,
    ) -> Result<RawQuicStream, RawQuicError> {
        let id = self.request()?.connect_stream_id;
        let stream = self.inner.raw.open_stream(cancellation).await?;
        let mut prefix = Vec::with_capacity(16);
        put_varint(&mut prefix, 0x41)?;
        put_varint(&mut prefix, id)?;
        let written = if self.request()?.tuple == "native_h3" {
            stream.write_webtransport_prefix(&prefix).await
        } else {
            stream.write_all_current(&prefix).await
        };
        if let Err(error) = written {
            stream.cancel_current();
            self.abort();
            return Err(error);
        }
        Ok(stream)
    }
    pub async fn accept_stream(
        &self,
        cancellation: &Cancellation,
    ) -> Result<RawQuicStream, RawQuicError> {
        let mut receiver = self.inner.incoming.lock().await;
        tokio::select! {
            _ = cancellation.cancelled() => Err(RawQuicError::Canceled),
            _ = self.inner.raw.h3_connection().closed() => Err(RawQuicError::Closed),
            result = receiver.recv() => result.map(|(stream, permit)| { drop(permit); stream }).ok_or(RawQuicError::Closed),
        }
    }
    pub fn max_datagram_size(&self) -> Option<usize> {
        let id = self.inner.request.get()?.connect_stream_id / 4;
        self.inner
            .raw
            .max_datagram_size()?
            .checked_sub(varint_size(id))
    }
    pub fn submit_datagram(&self, payload: Vec<u8>) -> Option<DatagramSubmission> {
        if payload.is_empty() || payload.len() > self.max_datagram_size()? {
            return None;
        }
        let mut bytes = Vec::with_capacity(payload.len() + 8);
        put_varint(&mut bytes, self.inner.request.get()?.connect_stream_id / 4).ok()?;
        bytes.extend_from_slice(&payload);
        self.inner.raw.submit_datagram_current(bytes)
    }
    pub async fn receive_datagram(
        &self,
        maximum: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, RawQuicError> {
        if maximum == 0 || maximum > 65535 {
            return Err(RawQuicError::InvalidReadSize);
        }
        loop {
            let mut packet = self
                .inner
                .raw
                .receive_datagram_bounded(
                    maximum
                        .checked_add(8)
                        .ok_or(RawQuicError::InvalidReadSize)?
                        .min(65535),
                    cancellation,
                )
                .await?;
            if let Ok(payload) =
                strip_datagram(&mut packet, self.request()?.connect_stream_id, maximum)
            {
                return Ok(payload);
            }
            // Wrong association and malformed native datagram context are
            // untrusted unreliable input, not reliable Session close authority.
            tokio::task::yield_now().await;
        }
    }
    pub fn abort(&self) {
        self.inner.raw.abort();
    }
    pub async fn close(&self) {
        self.abort();
        self.wait_termination().await;
    }
    pub async fn wait_termination(&self) {
        self.inner.raw.wait_termination().await;
        self.inner.workers.wait().await;
        let mut incoming = self.inner.incoming.lock().await;
        while let Ok((stream, permit)) = incoming.try_recv() {
            stream.cancel_current();
            stream.wait_termination_current().await;
            drop(permit);
        }
    }
}
async fn accept_bidi(owner: Arc<State>) {
    loop {
        let permit = tokio::select! { _ = owner.raw.h3_connection().closed() => return, permit = owner.slots.clone().acquire_owned() => match permit { Ok(value) => value, Err(_) => return } };
        let stream = match owner.raw.accept_stream(&Cancellation::new()).await {
            Ok(value) => value,
            Err(_) => return,
        };
        let state = owner.clone();
        owner.workers.spawn(async move {
            let result = tokio::time::timeout(
                state.config.handshake_timeout,
                classify_bidi(&state, &stream),
            )
            .await;
            match result {
                Ok(Ok(true)) => {
                    if state.outgoing.send((stream, permit)).await.is_err() {
                        state.raw.abort();
                    }
                }
                Ok(Ok(false)) => {
                    drop(permit);
                    serve_connect(state, stream).await;
                }
                _ => {
                    stream.cancel_current();
                    state.raw.abort();
                    stream.wait_termination_current().await;
                    drop(permit);
                }
            }
        });
    }
}
async fn classify_bidi(owner: &Arc<State>, stream: &RawQuicStream) -> Result<bool, RawQuicError> {
    let first = read_stream_varint(stream).await?;
    if first == 0x41 {
        let id = read_stream_varint(stream).await?;
        loop {
            let ready = owner.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            if let Some(request) = owner.request.get() {
                if id != request.connect_stream_id {
                    return Err(protocol());
                }
                return Ok(true);
            }
            tokio::select! { _ = ready => {}, _ = owner.raw.h3_connection().closed() => return Err(RawQuicError::Closed) }
        }
    }
    if owner.is_client
        || first != 1
        || !stream.stream_id().is_multiple_of(4)
        || owner
            .request_seen
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Err(protocol());
    }
    let count = read_stream_varint(stream).await?;
    if count == 0 || count > owner.config.header_bytes as u64 {
        return Err(protocol());
    }
    let mut block = vec![0; count as usize];
    read_stream_exact(stream, &mut block).await?;
    let headers = decode_headers(&block, owner.config.header_bytes)?;
    block.fill(0);
    let get = |name: &str| headers.get(name).cloned().ok_or_else(protocol);
    if get(":method")? != "CONNECT"
        || get(":scheme")? != "https"
        || get(":path")? != owner.config.path
    {
        return Err(protocol());
    }
    if headers.keys().any(|key| {
        key.starts_with(':')
            && !matches!(
                key.as_str(),
                ":method" | ":scheme" | ":path" | ":authority" | ":protocol"
            )
    }) || [
        "wt-available-protocols",
        "wt-protocol",
        "capsule-protocol",
        "connection",
        "upgrade",
        "transfer-encoding",
    ]
    .iter()
    .any(|key| headers.contains_key(*key))
    {
        return Err(protocol());
    }
    let wire_protocol = get(":protocol")?;
    let tuple = match wire_protocol.as_str() {
        "webtransport"
            if headers
                .get("sec-webtransport-http3-draft02")
                .is_some_and(|value| value == "1") =>
        {
            "chromium_draft02"
        }
        "webtransport-h3" if !headers.contains_key("sec-webtransport-http3-draft02") => "native_h3",
        _ => return Err(protocol()),
    };
    if !owner.config.tuples.iter().any(|value| value == tuple) {
        return Err(protocol());
    }
    let authority = get(":authority")?;
    let origin = headers.get("origin").cloned();
    let address = owner.raw.local_address()?;
    let host = if owner.config.server_name.contains(':') {
        format!("[{}]", owner.config.server_name)
    } else {
        owner.config.server_name.clone()
    };
    let expected =
        url::Url::parse(&format!("https://{host}:{}/", address.port())).map_err(|_| protocol())?;
    let observed = url::Url::parse(&format!("https://{authority}/")).map_err(|_| protocol())?;
    if !observed.username().is_empty()
        || observed.password().is_some()
        || observed.host_str() != expected.host_str()
        || observed.port_or_known_default() != expected.port_or_known_default()
        || authority != observed[url::Position::BeforeHost..url::Position::AfterPort]
    {
        return Err(protocol());
    }
    match &origin {
        Some(value) if owner.config.allowed_origins.contains(value) => {}
        None if owner.config.allow_absent_origin => {}
        _ => return Err(protocol()),
    }
    await_settings(owner, tuple).await?;
    let response = encode_headers(&[(":status", "200")], owner.config.header_bytes)?;
    let mut frame = Vec::with_capacity(response.len() + 16);
    put_varint(&mut frame, 1)?;
    put_varint(&mut frame, response.len() as u64)?;
    frame.extend_from_slice(&response);
    stream.write_all_current(&frame).await?;
    owner
        .request
        .set(WebTransportRequest {
            scheme: "https".into(),
            authority,
            path: owner.config.path.clone(),
            origin,
            tuple: tuple.into(),
            protocol: wire_protocol,
            connect_stream_id: stream.stream_id(),
        })
        .map_err(|_| protocol())?;
    owner.ready.notify_waiters();
    Ok(false)
}
async fn serve_connect(owner: Arc<State>, stream: RawQuicStream) {
    let result = async {
        let mut used = 0usize;
        let mut pending = Vec::with_capacity(owner.config.control_bytes);
        loop {
            let kind = read_stream_varint(&stream).await?;
            let count =
                usize::try_from(read_stream_varint(&stream).await?).map_err(|_| protocol())?;
            used = used
                .checked_add(16)
                .and_then(|value| value.checked_add(count))
                .ok_or_else(protocol)?;
            if used > owner.config.control_bytes
                || kind != 0
                || pending
                    .len()
                    .checked_add(count)
                    .is_none_or(|length| length > owner.config.control_bytes)
            {
                return Err(protocol());
            }
            let start = pending.len();
            pending.resize(start + count, 0);
            read_stream_exact(&stream, &mut pending[start..]).await?;
            let mut consumed = 0;
            while consumed < pending.len() {
                let mut at = consumed;
                if !complete_varint(&pending, at) {
                    break;
                }
                let capsule = take_varint(&pending, &mut at)?;
                if !complete_varint(&pending, at) {
                    break;
                }
                let length =
                    usize::try_from(take_varint(&pending, &mut at)?).map_err(|_| protocol())?;
                if length > 1028 {
                    return Err(protocol());
                }
                let end = at.checked_add(length).ok_or_else(protocol)?;
                if end > pending.len() {
                    break;
                }
                match capsule {
                    0x2843 if length >= 4 => {
                        pending.fill(0);
                        return Ok(());
                    }
                    0x78ae if length == 0 => {}
                    _ => return Err(protocol()),
                }
                consumed = end;
            }
            if consumed > 0 {
                pending[..consumed].fill(0);
                pending.drain(..consumed);
            }
        }
    }
    .await;
    let _ = result;
    stream.cancel_current();
    owner.raw.abort();
    stream.wait_termination_current().await;
}
async fn accept_uni(owner: Arc<State>) {
    loop {
        let mut stream = match owner.raw.h3_connection().accept_uni().await {
            Ok(value) => value,
            Err(_) => return,
        };
        let kind = match tokio::time::timeout(
            owner.config.handshake_timeout,
            read_quinn_varint(&mut stream),
        )
        .await
        {
            Ok(Ok(value)) => value,
            _ => {
                owner.raw.abort();
                return;
            }
        };
        if kind == 0x54 {
            // A legal association may race the CONNECT response. Its finite
            // receive owner waits for that original request without blocking
            // acceptance of the peer's control SETTINGS stream.
            let state = owner.clone();
            owner.workers.spawn(async move {
                let association = async {
                    let id = read_quinn_varint(&mut stream).await?;
                    loop {
                        let ready = state.ready.notified(); tokio::pin!(ready); ready.as_mut().enable();
                        if let Some(request) = state.request.get() {
                            if request.connect_stream_id != id { return Err(protocol()); }
                            let _ = stream.stop(quinn::VarInt::from_u64_bounded(0x52e4a40fa8db + 0xf502 + 0xf502 / 0x1e));
                            return Ok(());
                        }
                        tokio::select! { _ = ready => {}, _ = state.raw.h3_connection().closed() => return Err(RawQuicError::Closed) }
                    }
                };
                if !matches!(tokio::time::timeout(state.config.handshake_timeout, association).await, Ok(Ok(()))) { state.raw.abort(); }
            });
            continue;
        }
        let bit = match kind {
            0 => 1,
            2 => 2,
            3 => 4,
            _ => {
                owner.raw.abort();
                return;
            }
        };
        if owner.uni_seen.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
            owner.raw.abort();
            return;
        }
        let state = owner.clone();
        owner.workers.spawn(async move {
            let result = if kind == 0 {
                read_control(&state, &mut stream).await
            } else {
                let mut byte = [0u8];
                match stream.read(&mut byte).await {
                    Ok(None) => Err(protocol()),
                    Ok(Some(_)) => Err(protocol()),
                    Err(_) => Err(RawQuicError::Closed),
                }
            };
            let _ = result;
            state.raw.abort();
        });
    }
}
async fn await_settings(owner: &Arc<State>, tuple: &str) -> Result<(), RawQuicError> {
    if tuple == "native_h3" && !owner.raw.h3_connection().supports_reliable_reset() {
        return Err(RawQuicError::WebTransportPartialResetUnavailable);
    }
    loop {
        let changed = owner.settings_ready.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if let Some(settings) = &*owner.settings.lock().await {
            let required = if tuple == "native_h3" {
                NATIVE_H3_SESSIONS
            } else {
                CHROMIUM_DRAFT02
            };
            if settings.get(&H3_DATAGRAM) != Some(&1)
                || settings.get(&required) != Some(&1)
                || owner.is_client && settings.get(&8) != Some(&1)
            {
                return Err(protocol());
            }
            return Ok(());
        }
        tokio::select! { _ = changed => {}, _ = owner.raw.h3_connection().closed() => return Err(RawQuicError::Closed) }
    }
}
async fn read_control(
    owner: &Arc<State>,
    stream: &mut quinn::RecvStream,
) -> Result<(), RawQuicError> {
    if read_quinn_varint(stream).await? != 4 {
        return Err(protocol());
    }
    let count = usize::try_from(read_quinn_varint(stream).await?).map_err(|_| protocol())?;
    if count > owner.config.control_bytes {
        return Err(protocol());
    }
    let mut payload = vec![0; count];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|_| protocol())?;
    let mut settings = BTreeMap::new();
    let mut at = 0;
    while at < payload.len() {
        let id = take_varint(&payload, &mut at)?;
        let value = take_varint(&payload, &mut at)?;
        if settings.len() >= 64
            || settings.insert(id, value).is_some()
            || matches!(id, 2..=5)
            || (id == H3_DATAGRAM || id == CHROMIUM_DRAFT02 || id == 8) && value > 1
        {
            return Err(protocol());
        }
        if matches!(id, 0x2b64 | 0x2b65 | 0x2b61) || id == NATIVE_H3_SESSIONS && value > 1 {
            return Err(protocol());
        }
    }
    payload.fill(0);
    drop(payload);
    *owner.settings.lock().await = Some(settings);
    owner.settings_ready.notify_waiters();
    let mut used = count + 16;
    loop {
        let kind = read_quinn_varint(stream).await?;
        let count = usize::try_from(read_quinn_varint(stream).await?).map_err(|_| protocol())?;
        used = used
            .checked_add(count)
            .and_then(|value| value.checked_add(16))
            .ok_or_else(protocol)?;
        if used > owner.config.control_bytes || matches!(kind, 0 | 1 | 4 | 7 | 0xd) {
            return Err(protocol());
        }
        let mut remaining = count;
        let mut scratch = [0u8; 4096];
        while remaining > 0 {
            let take = remaining.min(scratch.len());
            stream
                .read_exact(&mut scratch[..take])
                .await
                .map_err(|_| protocol())?;
            remaining -= take;
        }
    }
}
fn decode_headers(block: &[u8], maximum: usize) -> Result<BTreeMap<String, String>, RawQuicError> {
    let mut bytes = Bytes::copy_from_slice(block);
    let decoded = decode_stateless(&mut bytes, maximum as u64).map_err(|_| protocol())?;
    if decoded.dyn_ref || decoded.fields.len() > 64 {
        return Err(protocol());
    }
    let mut fields = BTreeMap::new();
    let mut regular = false;
    for field in decoded.fields {
        let name = std::str::from_utf8(&field.name).map_err(|_| protocol())?;
        let value = std::str::from_utf8(&field.value).map_err(|_| protocol())?;
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b':')
            })
            || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
            || name.starts_with(':') && regular
            || fields.insert(name.into(), value.into()).is_some()
        {
            return Err(protocol());
        }
        if !name.starts_with(':') {
            regular = true;
        }
    }
    Ok(fields)
}
fn encode_headers(headers: &[(&str, &str)], maximum: usize) -> Result<Vec<u8>, RawQuicError> {
    let fields = headers
        .iter()
        .map(|(name, value)| HeaderField::new(name.as_bytes(), value.as_bytes()))
        .collect::<Vec<_>>();
    let mut bytes = Vec::with_capacity(maximum);
    encode_stateless(&mut bytes, &fields).map_err(|_| protocol())?;
    if bytes.len() > maximum {
        return Err(protocol());
    }
    Ok(bytes)
}
fn varint_size(value: u64) -> usize {
    if value < 64 {
        1
    } else if value < 16384 {
        2
    } else if value < 1073741824 {
        4
    } else {
        8
    }
}
fn put_varint(bytes: &mut Vec<u8>, value: u64) -> Result<(), RawQuicError> {
    if value >= 1 << 62 {
        return Err(protocol());
    }
    let size = varint_size(value);
    let encoded = value
        | match size {
            1 => 0,
            2 => 1 << 14,
            4 => 2 << 30,
            _ => 3 << 62,
        };
    bytes.extend_from_slice(&encoded.to_be_bytes()[8 - size..]);
    Ok(())
}
fn take_varint(bytes: &[u8], at: &mut usize) -> Result<u64, RawQuicError> {
    let first = *bytes.get(*at).ok_or_else(protocol)?;
    let size = 1usize << (first >> 6);
    let end = at
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(protocol)?;
    let mut value = u64::from(first & 63);
    for byte in &bytes[*at + 1..end] {
        value = value << 8 | u64::from(*byte);
    }
    *at = end;
    Ok(value)
}
async fn read_stream_exact(
    stream: &RawQuicStream,
    destination: &mut [u8],
) -> Result<(), RawQuicError> {
    let cancellation = Cancellation::new();
    let mut at = 0;
    while at < destination.len() {
        let count = stream
            .read_into(&mut destination[at..], &cancellation)
            .await
            .map_err(|_| protocol())?;
        if count == 0 {
            return Err(protocol());
        }
        at += count;
    }
    Ok(())
}
async fn read_stream_varint(stream: &RawQuicStream) -> Result<u64, RawQuicError> {
    let mut bytes = [0u8; 8];
    read_stream_exact(stream, &mut bytes[..1]).await?;
    let size = 1usize << (bytes[0] >> 6);
    if size > 1 {
        read_stream_exact(stream, &mut bytes[1..size]).await?;
    }
    take_varint(&bytes[..size], &mut 0)
}
async fn read_quinn_varint(stream: &mut quinn::RecvStream) -> Result<u64, RawQuicError> {
    let mut bytes = [0u8; 8];
    stream
        .read_exact(&mut bytes[..1])
        .await
        .map_err(|_| protocol())?;
    let size = 1usize << (bytes[0] >> 6);
    if size > 1 {
        stream
            .read_exact(&mut bytes[1..size])
            .await
            .map_err(|_| protocol())?;
    }
    take_varint(&bytes[..size], &mut 0)
}

fn complete_varint(bytes: &[u8], at: usize) -> bool {
    bytes
        .get(at)
        .is_some_and(|first| bytes.len() - at >= 1usize << (*first >> 6))
}
fn strip_datagram(
    packet: &mut [u8],
    connect_stream_id: u64,
    maximum: usize,
) -> Result<Vec<u8>, RawQuicError> {
    let result = (|| {
        let mut at = 0;
        let context = take_varint(packet, &mut at)?;
        if !connect_stream_id.is_multiple_of(4)
            || context != connect_stream_id / 4
            || at == packet.len()
            || packet.len() - at > maximum
        {
            return Err(protocol());
        }
        Ok(packet[at..].to_vec())
    })();
    packet.fill(0);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn datagram_uses_actual_nonzero_connect_id_and_rejects_other_association() {
        let mut packet = vec![5, 0xf0, 0x04];
        assert_eq!(strip_datagram(&mut packet, 20, 2).unwrap(), [0xf0, 0x04]);
        assert!(packet.iter().all(|byte| *byte == 0));
        let mut wrong = vec![0, 0xf0, 0x04];
        assert!(strip_datagram(&mut wrong, 20, 2).is_err());
        assert!(wrong.iter().all(|byte| *byte == 0));
        let mut oversized = vec![5, 0xf0, 0x04];
        assert!(strip_datagram(&mut oversized, 20, 1).is_err());
    }
    #[test]
    fn duplicate_origin_and_pseudo_headers_are_rejected_before_connect_admission() {
        for headers in [
            vec![(":method", "CONNECT"), (":method", "CONNECT")],
            vec![
                ("origin", "https://app.example"),
                ("origin", "https://evil.example"),
            ],
            vec![("origin", "https://app.example"), (":method", "CONNECT")],
        ] {
            let block = encode_headers(&headers, 4096).unwrap();
            assert!(decode_headers(&block, 4096).is_err());
        }
    }
}
