use crate::{ErrorCode, FlowersecError, Path, Stage};
use std::{future::Future, pin::Pin, sync::Arc};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportRuntime {
    Rust,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportSecurityInput {
    pub path: Path,
    pub scheme: String,
    pub host: String,
    pub runtime: TransportRuntime,
}

type PolicyFuture = Pin<Box<dyn Future<Output = Result<(), FlowersecError>> + Send>>;
type PolicyFn = dyn Fn(TransportSecurityInput) -> PolicyFuture + Send + Sync;

#[derive(Clone)]
pub struct TransportSecurityPolicy(Arc<PolicyFn>);

impl std::fmt::Debug for TransportSecurityPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransportSecurityPolicy(..)")
    }
}

impl TransportSecurityPolicy {
    pub fn require_tls() -> Self {
        Self::new(|input| async move {
            if input.scheme == "wss" {
                Ok(())
            } else {
                Err(policy_denied("TLS is required"))
            }
        })
    }

    pub fn allow_plaintext_for_loopback() -> Self {
        Self::new(|input| async move {
            if input.scheme == "wss" || (input.scheme == "ws" && is_loopback_host(&input.host)) {
                Ok(())
            } else {
                Err(policy_denied(
                    "plaintext is only allowed for loopback hosts",
                ))
            }
        })
    }

    pub fn allow_plaintext() -> Self {
        Self::new(|_| async { Ok(()) })
    }

    pub fn new<F, Fut>(policy: F) -> Self
    where
        F: Fn(TransportSecurityInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), FlowersecError>> + Send + 'static,
    {
        Self(Arc::new(move |input| Box::pin(policy(input))))
    }

    pub async fn evaluate(&self, url: &Url, path: Path) -> Result<(), FlowersecError> {
        let input = TransportSecurityInput {
            path,
            scheme: url.scheme().to_ascii_lowercase(),
            host: url.host_str().unwrap_or_default().to_ascii_lowercase(),
            runtime: TransportRuntime::Rust,
        };
        (self.0)(input).await
    }
}

impl Default for TransportSecurityPolicy {
    fn default() -> Self {
        Self::require_tls()
    }
}

fn policy_denied(message: &str) -> FlowersecError {
    FlowersecError::new(
        Path::Auto,
        Stage::Transport,
        ErrorCode::TRANSPORT_POLICY_DENIED,
        message,
    )
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}
