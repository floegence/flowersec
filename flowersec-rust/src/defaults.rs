//! Stable SDK defaults shared with the other Flowersec implementations.

use std::time::Duration;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const HANDSHAKE_CLOCK_SKEW: Duration = Duration::from_secs(30);
pub const MAX_HANDSHAKE_PAYLOAD_BYTES: usize = 8 * 1024;
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const OUTBOUND_RECORD_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_OUTBOUND_BUFFERED_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_JSON_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_STREAM_HELLO_BYTES: usize = 8 * 1024;

pub const YAMUX_MAX_ACTIVE_STREAMS: usize = 64;
pub const YAMUX_MAX_INBOUND_STREAMS: usize = 32;
pub const YAMUX_MAX_FRAME_BYTES: usize = 256 * 1024;
pub const YAMUX_PREFERRED_OUTBOUND_FRAME_BYTES: usize = 64 * 1024;
pub const YAMUX_MAX_STREAM_RECEIVE_BYTES: usize = 256 * 1024;
pub const YAMUX_MAX_SESSION_RECEIVE_BYTES: usize = 16 * 1024 * 1024;

pub const RPC_MAX_CONCURRENT_REQUESTS: usize = 32;
pub const RPC_MAX_QUEUED_REQUESTS: usize = 128;
pub const RPC_MAX_QUEUED_NOTIFICATIONS: usize = 128;

pub const CONTROLPLANE_MAX_REQUEST_BODY_BYTES: usize = 32 * 1024;
pub const CONTROLPLANE_MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

pub const PROXY_MAX_CHUNK_BYTES: usize = 256 * 1024;
pub const PROXY_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
pub const PROXY_MAX_WS_FRAME_BYTES: usize = 1024 * 1024;
pub const PROXY_DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const PROXY_MAX_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub const RECONNECT_MAX_ATTEMPTS: usize = 5;
pub const RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(500);
pub const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(10);
pub const RECONNECT_FACTOR: f64 = 1.8;
pub const RECONNECT_JITTER_RATIO: f64 = 0.2;
