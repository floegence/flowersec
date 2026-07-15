use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Path {
    Auto,
    Tunnel,
    Direct,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Validate,
    Scope,
    Connect,
    Transport,
    Attach,
    Handshake,
    Secure,
    Yamux,
    Rpc,
    Reconnect,
    Close,
}

#[derive(Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ErrorCode(String);

impl ErrorCode {
    pub const INVALID_INPUT: &'static str = "invalid_input";
    pub const INVALID_OPTION: &'static str = "invalid_option";
    pub const MISSING_GRANT: &'static str = "missing_grant";
    pub const MISSING_CONNECT_INFO: &'static str = "missing_connect_info";
    pub const ROLE_MISMATCH: &'static str = "role_mismatch";
    pub const MISSING_TUNNEL_URL: &'static str = "missing_tunnel_url";
    pub const MISSING_WS_URL: &'static str = "missing_ws_url";
    pub const MISSING_ORIGIN: &'static str = "missing_origin";
    pub const MISSING_CHANNEL_ID: &'static str = "missing_channel_id";
    pub const MISSING_TOKEN: &'static str = "missing_token";
    pub const MISSING_INIT_EXP: &'static str = "missing_init_exp";
    pub const INVALID_PSK: &'static str = "invalid_psk";
    pub const INVALID_SUITE: &'static str = "invalid_suite";
    pub const RESOLVE_FAILED: &'static str = "resolve_failed";
    pub const TRANSPORT_POLICY_DENIED: &'static str = "transport_policy_denied";
    pub const CREDENTIAL_COMMIT_FAILED: &'static str = "credential_commit_failed";
    pub const DIAL_FAILED: &'static str = "dial_failed";
    pub const ATTACH_FAILED: &'static str = "attach_failed";
    pub const TIMEOUT: &'static str = "timeout";
    pub const CANCELED: &'static str = "canceled";
    pub const HANDSHAKE_FAILED: &'static str = "handshake_failed";
    pub const OPEN_STREAM_FAILED: &'static str = "open_stream_failed";
    pub const ACCEPT_STREAM_FAILED: &'static str = "accept_stream_failed";
    pub const STREAM_HELLO_FAILED: &'static str = "stream_hello_failed";
    pub const RPC_FAILED: &'static str = "rpc_failed";
    pub const PING_FAILED: &'static str = "ping_failed";
    pub const NOT_CONNECTED: &'static str = "not_connected";
    pub const RESOURCE_EXHAUSTED: &'static str = "resource_exhausted";

    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ErrorCode").field(&self.0).finish()
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<&'static str> for ErrorCode {
    fn from(value: &'static str) -> Self {
        Self(value.to_owned())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{path:?}/{stage:?}/{code}: {message}")]
pub struct FlowersecError {
    pub path: Path,
    pub stage: Stage,
    pub code: ErrorCode,
    pub message: String,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl FlowersecError {
    pub fn new(
        path: Path,
        stage: Stage,
        code: impl Into<ErrorCode>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path,
            stage,
            code: code.into(),
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }
}
