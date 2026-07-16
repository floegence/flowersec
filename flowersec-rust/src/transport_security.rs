use crate::{ErrorCode, FlowersecError, Path, Stage};
use std::{collections::BTreeSet, future::Future, net::IpAddr, pin::Pin, sync::Arc};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaintextRiskAcceptance {
    AcceptPreE2ECredentialExposure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPlaintextPolicyOptions {
    pub allowed_hosts: Vec<String>,
    pub risk_acceptance: PlaintextRiskAcceptance,
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

    pub fn network_plaintext(
        options: NetworkPlaintextPolicyOptions,
    ) -> Result<Self, FlowersecError> {
        if options.risk_acceptance != PlaintextRiskAcceptance::AcceptPreE2ECredentialExposure {
            return Err(invalid_network_plaintext_policy(
                "explicit pre-E2EE credential exposure acceptance is required",
            ));
        }
        if options.allowed_hosts.is_empty() {
            return Err(invalid_network_plaintext_policy(
                "at least one allowed host is required",
            ));
        }
        let allowed_hosts = options
            .allowed_hosts
            .into_iter()
            .map(|host| canonical_network_plaintext_host(&host))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self::new(move |input| {
            let allowed_hosts = allowed_hosts.clone();
            async move {
                if input.scheme == "wss"
                    || (input.scheme == "ws" && allowed_hosts.contains(&input.host))
                {
                    Ok(())
                } else {
                    Err(policy_denied("plaintext host is not explicitly allowed"))
                }
            }
        }))
    }

    #[deprecated(note = "use require_tls, allow_plaintext_for_loopback, or network_plaintext")]
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
            host: url
                .host_str()
                .unwrap_or_default()
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or_else(|| url.host_str().unwrap_or_default())
                .to_ascii_lowercase(),
            runtime: TransportRuntime::Rust,
        };
        (self.0)(input).await
    }
}

fn invalid_network_plaintext_policy(message: &str) -> FlowersecError {
    FlowersecError::new(
        Path::Auto,
        Stage::Validate,
        ErrorCode::TRANSPORT_POLICY_DENIED,
        message,
    )
}

fn canonical_network_plaintext_host(raw_host: &str) -> Result<String, FlowersecError> {
    let host = raw_host.trim();
    if host.is_empty()
        || host != host.to_ascii_lowercase()
        || host.chars().any(|ch| "@/?#%[]".contains(ch))
    {
        return Err(invalid_network_plaintext_policy(
            "allowed host must be a canonical IP literal",
        ));
    }
    let address = host.parse::<IpAddr>().map_err(|_| {
        invalid_network_plaintext_policy("allowed host must be a canonical IP literal")
    })?;
    if address.to_string() != host {
        return Err(invalid_network_plaintext_policy(
            "allowed host must be a canonical IP literal",
        ));
    }
    let denied = match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_link_local()
                || address == std::net::Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.to_ipv4_mapped().is_some()
        }
    };
    if denied {
        return Err(invalid_network_plaintext_policy(
            "allowed host must be a non-loopback unicast IP literal",
        ));
    }
    Ok(host.to_owned())
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
