use crate::{ErrorCode, FlowersecError, Path, Stage};
use std::{collections::BTreeSet, future::Future, net::IpAddr, pin::Pin, sync::Arc};
use url::Url;

pub(crate) fn validate_websocket_url(value: &str, path: Path) -> Result<Url, FlowersecError> {
    let invalid = || {
        FlowersecError::new(
            path,
            Stage::Validate,
            match path {
                Path::Tunnel => ErrorCode::MISSING_TUNNEL_URL,
                Path::Auto | Path::Direct => ErrorCode::MISSING_WS_URL,
            },
            "invalid WebSocket URL",
        )
    };
    let url = Url::parse(value.trim()).map_err(|error| invalid().with_source(error))?;
    if !matches!(url.scheme(), "ws" | "wss")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(url)
}

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
                Err(policy_denied(input.path, "TLS is required"))
            }
        })
    }

    pub fn allow_plaintext_for_loopback() -> Self {
        Self::new(|input| async move {
            if input.scheme == "wss" || (input.scheme == "ws" && is_loopback_host(&input.host)) {
                Ok(())
            } else {
                Err(policy_denied(
                    input.path,
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
                    Err(policy_denied(
                        input.path,
                        "plaintext host is not explicitly allowed",
                    ))
                }
            }
        }))
    }

    pub fn new<F, Fut>(policy: F) -> Self
    where
        F: Fn(TransportSecurityInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), FlowersecError>> + Send + 'static,
    {
        Self(Arc::new(move |input| Box::pin(policy(input))))
    }

    pub async fn evaluate(&self, url: &Url, path: Path) -> Result<(), FlowersecError> {
        self.evaluate_input(
            url.scheme(),
            url.host_str()
                .unwrap_or_default()
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or_else(|| url.host_str().unwrap_or_default())
                .to_ascii_lowercase(),
            path,
        )
        .await
    }

    pub(crate) async fn evaluate_raw(
        &self,
        raw_url: &str,
        url: &Url,
        path: Path,
    ) -> Result<(), FlowersecError> {
        let host = raw_websocket_host(raw_url)
            .ok_or_else(|| policy_denied(path, "invalid WebSocket URL"))?;
        self.evaluate_input(url.scheme(), host, path).await
    }

    async fn evaluate_input(
        &self,
        scheme: &str,
        host: String,
        path: Path,
    ) -> Result<(), FlowersecError> {
        let input = TransportSecurityInput {
            path,
            scheme: scheme.to_ascii_lowercase(),
            host,
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

fn policy_denied(path: Path, message: &str) -> FlowersecError {
    FlowersecError::new(
        path,
        Stage::Validate,
        ErrorCode::TRANSPORT_POLICY_DENIED,
        message,
    )
}

fn raw_websocket_host(value: &str) -> Option<String> {
    let raw = value.trim();
    let scheme_end = raw.find("://")?;
    let scheme = raw[..scheme_end].to_ascii_lowercase();
    if !matches!(scheme.as_str(), "ws" | "wss") {
        return None;
    }
    let target = &raw[scheme_end + 3..];
    let authority_end = target.find(['/', '?', '#']).unwrap_or(target.len());
    let authority = &target[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']')?;
        let suffix = &bracketed[end + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':')
                || suffix.len() == 1
                || !suffix[1..].bytes().all(|byte| byte.is_ascii_digit()))
        {
            return None;
        }
        &bracketed[..end]
    } else {
        let mut pieces = authority.split(':');
        let host = pieces.next()?;
        if let Some(port) = pieces.next() {
            if port.is_empty()
                || !port.bytes().all(|byte| byte.is_ascii_digit())
                || pieces.next().is_some()
            {
                return None;
            }
        }
        host
    };
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn raw_loopback_policy_rejects_noncanonical_ipv4() {
        let policy = TransportSecurityPolicy::allow_plaintext_for_loopback();
        for raw in ["ws://127.1/ws", "ws://127.0.00.1/ws", "ws://2130706433/ws"] {
            let url = validate_websocket_url(raw, Path::Direct).expect("parse WebSocket URL");
            let error = policy
                .evaluate_raw(raw, &url, Path::Direct)
                .await
                .expect_err("noncanonical loopback URL must be denied");
            assert_eq!(error.path, Path::Direct);
            assert_eq!(error.stage, Stage::Validate);
            assert_eq!(error.code.as_str(), ErrorCode::TRANSPORT_POLICY_DENIED);
        }
    }
}
