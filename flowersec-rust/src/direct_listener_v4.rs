//! Dedicated current direct listener. Sealing native ingress preserves the
//! accepted connections until their original Serve owner finishes Drain.
use super::*;
use flowersec_native_transport::{
    Cancellation, CandidatePreparationBudget, PathProfile, RawQuicLimits, RawQuicListener,
    RawQuicServerConfig, WebTransportConfig, WebTransportListener,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
pub(super) enum Listener {
    WebSocket(TcpListener),
    Native(RawQuicListener),
    WebTransport(WebTransportListener),
}
pub(super) enum Incoming {
    WebSocket(std::net::TcpStream),
    Native(super::native::Connection),
}
pub(super) struct Options {
    pub(super) listen_address: SocketAddr,
    pub(super) host: String,
    pub(super) origin: Option<String>,
    pub(super) max_connections: usize,
    pub(super) max_frame_bytes: usize,
    pub(super) handshake_timeout: Duration,
    pub(super) prepare_bytes: usize,
    pub(super) native_runtime_bytes: u64,
}
impl From<&serve::WssServeOptions> for Options {
    fn from(options: &serve::WssServeOptions) -> Self {
        Self {
            listen_address: options.listen_address,
            host: options.host.clone(),
            origin: options.origin.clone(),
            max_connections: options.max_connections,
            max_frame_bytes: options.max_frame_bytes,
            handshake_timeout: options.handshake_timeout,
            prepare_bytes: options.prepare_bytes,
            native_runtime_bytes: options.native_runtime_bytes,
        }
    }
}
#[derive(Debug)]
struct Clock(Arc<EnvironmentRoot>);
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        self.0.sample().ok().map(|time| {
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_millis(time.upper_ms))
        })
    }
}
impl Listener {
    pub(super) fn from_websocket(
        listener: std::net::TcpListener,
        expected: SocketAddr,
    ) -> ConnectResult<Self> {
        if listener.local_addr().map_err(|_| ConnectError::Carrier)? != expected {
            return Err(ConnectError::Configuration);
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| ConnectError::Carrier)?;
        Ok(Self::WebSocket(
            TcpListener::from_std(listener).map_err(|_| ConnectError::Carrier)?,
        ))
    }
    pub(super) async fn bind(
        root: Arc<EnvironmentRoot>,
        carrier: u8,
        identity: &serve::WssServerIdentity,
        options: &serve::WssServeOptions,
    ) -> ConnectResult<Self> {
        Self::bind_path(root, carrier, 0, identity, &Options::from(options)).await
    }
    pub(super) async fn bind_path(
        root: Arc<EnvironmentRoot>,
        carrier: u8,
        path_kind: u8,
        identity: &serve::WssServerIdentity,
        options: &Options,
    ) -> ConnectResult<Self> {
        Self::bind_path_inner(root, carrier, path_kind, identity, options, None, None).await
    }
    pub(super) async fn bind_path_on_udp_socket(
        root: Arc<EnvironmentRoot>,
        carrier: u8,
        path_kind: u8,
        identity: &serve::WssServerIdentity,
        options: &Options,
        socket: std::net::UdpSocket,
    ) -> ConnectResult<Self> {
        Self::bind_path_inner(
            root,
            carrier,
            path_kind,
            identity,
            options,
            Some(socket),
            None,
        )
        .await
    }
    /// Bind only the original single accepted candidate. A long-lived Serve
    /// listener must use per-connection budgets rather than reuse this winner.
    pub(super) async fn bind_path_prepared(
        root: Arc<EnvironmentRoot>,
        carrier: u8,
        path_kind: u8,
        identity: &serve::WssServerIdentity,
        options: &Options,
    ) -> ConnectResult<Self> {
        let budget = if carrier == 1 {
            None
        } else {
            Some(super::native::original_preparation_budget(
                options.prepare_bytes,
            )?)
        };
        Self::bind_path_inner(root, carrier, path_kind, identity, options, None, budget).await
    }
    async fn bind_path_inner(
        root: Arc<EnvironmentRoot>,
        carrier: u8,
        path_kind: u8,
        identity: &serve::WssServerIdentity,
        options: &Options,
        socket: Option<std::net::UdpSocket>,
        budget: Option<CandidatePreparationBudget>,
    ) -> ConnectResult<Self> {
        if path_kind > 1 {
            return Err(ConnectError::Configuration);
        }
        match carrier {
            1 => {
                if socket.is_some() {
                    return Err(ConnectError::Configuration);
                }
                Ok(Self::WebSocket(
                    TcpListener::bind(options.listen_address)
                        .await
                        .map_err(|_| ConnectError::Carrier)?,
                ))
            }
            0 => {
                if options.origin.is_some()
                    || options.native_runtime_bytes
                        < (16 << 20) + options.prepare_bytes as u64 + 196608
                {
                    return Err(ConnectError::Configuration);
                }
                let backing = options
                    .native_runtime_bytes
                    .checked_sub((16 << 20) + options.prepare_bytes as u64 + 196608)
                    .ok_or(ConnectError::Capacity)?;
                let capacity = (backing / 16384).min(4097) as u32;
                if capacity < 14 {
                    return Err(ConnectError::Capacity);
                }
                let mut limits = RawQuicLimits::for_session(capacity, options.handshake_timeout)
                    .map_err(|_| ConnectError::Configuration)?;
                limits.pending_connections = options.max_connections as u32;
                limits.stream_receive_window = options.max_frame_bytes as u64 + 8;
                limits.connection_receive_window = 16 << 20;
                let config = RawQuicServerConfig::new_with_time_provider(
                    if path_kind == 1 {
                        PathProfile::TunnelV4
                    } else {
                        PathProfile::DirectV4
                    },
                    identity.certificate_chain_der.clone(),
                    identity.private_key_der.clone(),
                    limits,
                    Arc::new(Clock(root)),
                )
                .map_err(|error| super::native::preparation_error(error, ConnectError::Tls))?;
                let config = if let Some(budget) = budget {
                    config.with_preparation_budget(budget)
                } else {
                    config.with_incoming_preparation_capacity(super::native::preparation_limits(
                        options.prepare_bytes,
                    )?)
                }
                .map_err(|error| {
                    super::native::preparation_error(error, ConnectError::Configuration)
                })?;
                let listener = match socket {
                    Some(socket) => {
                        if socket.local_addr().map_err(|_| ConnectError::Carrier)?
                            != options.listen_address
                        {
                            return Err(ConnectError::Configuration);
                        }
                        RawQuicListener::from_socket(socket, config)
                    }
                    None => RawQuicListener::bind(options.listen_address, config),
                }
                .map_err(|error| super::native::preparation_error(error, ConnectError::Carrier))?;
                Ok(Self::Native(listener))
            }
            2 => {
                if options.native_runtime_bytes < (16 << 20) + options.prepare_bytes as u64 + 262144
                {
                    return Err(ConnectError::Capacity);
                }
                let backing = options
                    .native_runtime_bytes
                    .checked_sub((16 << 20) + options.prepare_bytes as u64 + 262144)
                    .ok_or(ConnectError::Capacity)?;
                let capacity = (backing / 16384).min(4096) as u32;
                if capacity < 14 {
                    return Err(ConnectError::Capacity);
                }
                let mut limits = RawQuicLimits::for_session(capacity, options.handshake_timeout)
                    .map_err(|_| ConnectError::Configuration)?;
                limits.pending_connections = options.max_connections as u32;
                limits.stream_receive_window = options.max_frame_bytes as u64 + 8;
                limits.connection_receive_window = 16 << 20;
                let config = WebTransportConfig {
                    server_name: options.host.clone(),
                    path: if path_kind == 1 {
                        "/flowersec/webtransport/v4/tunnel".to_owned()
                    } else {
                        "/flowersec/webtransport/v4/direct".to_owned()
                    },
                    tuples: vec!["native_h3".to_owned(), "chromium_draft02".to_owned()],
                    allowed_origins: options.origin.clone().into_iter().collect(),
                    allow_absent_origin: options.origin.is_none(),
                    header_bytes: 16384,
                    control_bytes: 65536,
                    handshake_timeout: options.handshake_timeout,
                };
                let clock = Arc::new(Clock(root));
                let listener=match socket {
                    Some(socket)=>{
                        if socket.local_addr().map_err(|_|ConnectError::Carrier)?!=options.listen_address{return Err(ConnectError::Configuration);}
                        if let Some(budget) = budget {
                            WebTransportListener::from_socket_with_time_provider_and_preparation_budget(socket, identity.certificate_chain_der.clone(),
                                identity.private_key_der.clone(), limits, config, clock, budget)
                        } else { WebTransportListener::from_socket_with_time_provider_and_incoming_preparation_capacity(socket,
                            identity.certificate_chain_der.clone(), identity.private_key_der.clone(), limits, config, clock,
                            super::native::preparation_limits(options.prepare_bytes)?) }
                    },
                    None=>if let Some(budget) = budget {
                        let socket = std::net::UdpSocket::bind(options.listen_address).map_err(|_| ConnectError::Carrier)?;
                        WebTransportListener::from_socket_with_time_provider_and_preparation_budget(socket, identity.certificate_chain_der.clone(),
                            identity.private_key_der.clone(), limits, config, clock, budget)
                    } else { WebTransportListener::bind_with_time_provider_and_incoming_preparation_capacity(options.listen_address,
                        identity.certificate_chain_der.clone(), identity.private_key_der.clone(), limits, config, clock,
                        super::native::preparation_limits(options.prepare_bytes)?) },
                }.map_err(|error| super::native::preparation_error(error, ConnectError::Tls))?;
                Ok(Self::WebTransport(listener))
            }
            _ => Err(ConnectError::Configuration),
        }
    }
    pub(super) fn local_address(&self) -> ConnectResult<SocketAddr> {
        match self {
            Self::WebSocket(listener) => listener.local_addr().map_err(|_| ConnectError::Carrier),
            Self::Native(listener) => listener.local_address().map_err(|_| ConnectError::Carrier),
            Self::WebTransport(listener) => {
                listener.local_address().map_err(|_| ConnectError::Carrier)
            }
        }
    }
    pub(super) async fn accept(&self, cancellation: &Cancellation) -> ConnectResult<Incoming> {
        match self {
            Self::WebSocket(listener) => {
                let (tcp, _) = tokio::select! {_ = cancellation.cancelled()=>return Err(ConnectError::Canceled),result=listener.accept()=>result.map_err(|_|ConnectError::Carrier)?};
                Ok(Incoming::WebSocket(
                    tcp.into_std().map_err(|_| ConnectError::Carrier)?,
                ))
            }
            Self::Native(listener) => Ok(Incoming::Native(super::native::Connection::Raw(
                listener.accept(cancellation).await.map_err(|error| {
                    super::native::preparation_error(error, ConnectError::Carrier)
                })?,
            ))),
            Self::WebTransport(listener) => {
                Ok(Incoming::Native(super::native::Connection::WebTransport(
                    listener.accept(cancellation).await.map_err(|error| {
                        super::native::preparation_error(error, ConnectError::Carrier)
                    })?,
                )))
            }
        }
    }
    pub(super) fn seal(&self) {
        match self {
            Self::Native(listener) => listener.stop_accepting_current(),
            Self::WebTransport(listener) => listener.stop_accepting_current(),
            Self::WebSocket(_) => {}
        }
    }
    pub(super) async fn finish(self) {
        match self {
            Self::Native(listener) => listener.wait_termination().await,
            Self::WebTransport(listener) => listener.wait_termination().await,
            Self::WebSocket(_) => {}
        }
    }
}

impl Incoming {
    pub(super) async fn abort_and_wait(self) {
        if let Self::Native(native) = self {
            native.abort();
            native.wait_termination().await;
        }
    }
}
