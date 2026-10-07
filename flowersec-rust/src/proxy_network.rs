use std::{
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::proxy_server::ProxyServerError;

const MAX_ADDRESSES: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The proxy's upstream transport uses independently installed CA roots and
/// TLS 1.3 for both HTTP and WebSocket. Session protocol selection is unrelated
/// to this application's upstream connection.
pub(crate) fn client_tls(
    trust_roots_der: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ClientConfig>, ProxyServerError> {
    if trust_roots_der.is_empty() {
        return Err(ProxyServerError::InvalidOptions);
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in trust_roots_der {
        roots
            .add(rustls::pki_types::CertificateDer::from(certificate))
            .map_err(|_| ProxyServerError::InvalidOptions)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut configuration = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ProxyServerError::InvalidOptions)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(configuration))
}

#[derive(Debug)]
struct Prefix {
    address: IpAddr,
    shift: u32,
}

#[derive(Debug)]
struct NetworkPool {
    permits: Arc<Semaphore>,
    active: AtomicUsize,
    completed: Notify,
}

pub(crate) struct ProxyNativeOwnership {
    pub(crate) authentication: Option<crate::ApplicationBinding>,
    pub(crate) _charge: Arc<crate::environment_v4::ResourceCharge>,
    pub(crate) _tail: Arc<crate::application_tails_v4::ApplicationTail>,
}
impl std::fmt::Debug for ProxyNativeOwnership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyNativeOwnership { <opaque> }")
    }
}
struct NetworkWork {
    pool: Arc<NetworkPool>,
    permit: Option<OwnedSemaphorePermit>,
    _ownership: Option<Arc<ProxyNativeOwnership>>,
}

// Ownership follows the actual native I/O, including a detached Hyper task's
// cancellation tail. Releasing a handler permit cannot release this slot.
pub(crate) struct ProxySocket {
    socket: TcpStream,
    _work: Arc<NetworkWork>,
}

impl AsyncRead for ProxySocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buffer)
    }
}
impl AsyncWrite for ProxySocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
impl Drop for NetworkWork {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.pool.active.fetch_sub(1, Ordering::AcqRel);
        self.pool.completed.notify_waiters();
    }
}

/// Immutable address authority shared by HTTP and WebSocket. DNS native
/// allocations belong to the host allowance; retained results and resolver
/// tails have explicit limits owned by this policy.
#[derive(Debug)]
pub(crate) struct ProxyNetworkPolicy {
    pub(crate) host: String,
    port: u16,
    numeric: Option<IpAddr>,
    prefixes: Vec<Prefix>,
    pool: Arc<NetworkPool>,
}

fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or(address, IpAddr::V4),
        _ => address,
    }
}
fn value(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(value) => u32::from(value).into(),
        IpAddr::V6(value) => u128::from(value),
    }
}
fn usable(address: IpAddr) -> bool {
    !address.is_unspecified() && !address.is_multicast()
}
fn shifted(value: u128, shift: u32) -> u128 {
    if shift == 128 { 0 } else { value >> shift }
}
fn invalid() -> io::Error {
    io::Error::other("proxy network policy rejected destination")
}

impl Prefix {
    fn parse(raw: &str) -> Result<Self, ProxyServerError> {
        let (ip, bits) = match raw.split_once('/') {
            Some((ip, bits)) => {
                if bits.is_empty()
                    || bits.len() > 3
                    || !bits.bytes().all(|byte| byte.is_ascii_digit())
                    || bits.len() > 1 && bits.starts_with('0')
                {
                    return Err(ProxyServerError::InvalidOptions);
                }
                (
                    ip,
                    Some(
                        bits.parse::<u32>()
                            .map_err(|_| ProxyServerError::InvalidOptions)?,
                    ),
                )
            }
            None => (raw, None),
        };
        let original: IpAddr = ip.parse().map_err(|_| ProxyServerError::InvalidOptions)?;
        let width = if original.is_ipv4() { 32 } else { 128 };
        let mut bits = bits.unwrap_or(width);
        if bits > width {
            return Err(ProxyServerError::InvalidOptions);
        }
        let address = normalize(original);
        if original.is_ipv6() && address.is_ipv4() {
            bits = bits
                .checked_sub(96)
                .ok_or(ProxyServerError::InvalidOptions)?;
        }
        let shift = (if address.is_ipv4() { 32 } else { 128 }) - bits;
        let number = value(address);
        if shift == 128 && number != 0 || shift < 128 && shifted(number, shift) << shift != number {
            return Err(ProxyServerError::InvalidOptions);
        }
        Ok(Self { address, shift })
    }
    fn contains(&self, address: IpAddr) -> bool {
        self.address.is_ipv4() == address.is_ipv4()
            && shifted(value(self.address), self.shift) == shifted(value(address), self.shift)
    }
}

impl ProxyNetworkPolicy {
    pub(crate) fn compile(
        upstream: &Url,
        ranges: &[String],
        maximum: usize,
    ) -> Result<Self, ProxyServerError> {
        if ranges.len() > MAX_ADDRESSES || maximum == 0 || maximum > Semaphore::MAX_PERMITS {
            return Err(ProxyServerError::InvalidOptions);
        }
        let (host, numeric) = match upstream.host().ok_or(ProxyServerError::InvalidOptions)? {
            Host::Ipv4(ip) => (ip.to_string(), Some(IpAddr::V4(ip))),
            Host::Ipv6(ip) => (ip.to_string(), Some(normalize(IpAddr::V6(ip)))),
            Host::Domain(name) => {
                if !valid_dns_name(name) || ranges.is_empty() {
                    return Err(ProxyServerError::InvalidOptions);
                }
                (name.to_owned(), None)
            }
        };
        let port = upstream
            .port_or_known_default()
            .filter(|port| *port != 0)
            .ok_or(ProxyServerError::InvalidOptions)?;
        let mut policy = Self {
            host,
            port,
            numeric,
            prefixes: ranges
                .iter()
                .map(|raw| Prefix::parse(raw))
                .collect::<Result<_, _>>()?,
            pool: Arc::new(NetworkPool {
                permits: Arc::new(Semaphore::new(maximum)),
                active: AtomicUsize::new(0),
                completed: Notify::new(),
            }),
        };
        if let Some(address) = numeric {
            if !usable(address) || !ranges.is_empty() && !policy.allows(address) {
                return Err(ProxyServerError::InvalidOptions);
            }
            // Explicit ranges can restrict, but cannot widen a numeric host.
            policy.prefixes = vec![Prefix { address, shift: 0 }];
        }
        Ok(policy)
    }

    fn allows(&self, address: IpAddr) -> bool {
        let address = normalize(address);
        usable(address) && self.prefixes.iter().any(|prefix| prefix.contains(address))
    }

    fn validate_answer(
        &self,
        addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> io::Result<Vec<SocketAddr>> {
        let mut result = Vec::new();
        for mut address in addresses {
            if result.len() == MAX_ADDRESSES
                || address.port() != self.port
                || !self.allows(address.ip())
                || matches!(address, SocketAddr::V6(value) if value.scope_id() != 0)
            {
                return Err(invalid());
            }
            address.set_ip(normalize(address.ip()));
            result.push(address);
        }
        if result.is_empty() {
            return Err(invalid());
        }
        Ok(result)
    }

    fn work(&self, ownership: Option<Arc<ProxyNativeOwnership>>) -> io::Result<Arc<NetworkWork>> {
        let permit = self
            .pool
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| invalid())?;
        self.pool.active.fetch_add(1, Ordering::AcqRel);
        Ok(Arc::new(NetworkWork {
            pool: self.pool.clone(),
            permit: Some(permit),
            _ownership: ownership,
        }))
    }

    async fn resolve(&self, work: Arc<NetworkWork>) -> io::Result<Vec<SocketAddr>> {
        if let Some(address) = self.numeric {
            return Ok(vec![SocketAddr::new(address, self.port)]);
        }
        let host = self.host.clone();
        let port = self.port;
        // Cancellation cannot stop an OS resolver. The actual blocking job
        // retains its permit until it exits; a dropped waiter cannot dial.
        let addresses = tokio::task::spawn_blocking(move || {
            let _work = work;
            let mut result = Vec::new();
            for address in (host.as_str(), port).to_socket_addrs()? {
                if result.len() == MAX_ADDRESSES {
                    return Err(invalid());
                }
                result.push(address);
            }
            Ok(result)
        })
        .await
        .map_err(|_| invalid())??;
        self.validate_answer(addresses)
    }

    #[cfg(test)]
    pub(crate) async fn connect(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> io::Result<ProxySocket> {
        self.connect_owned(deadline, cancellation, None).await
    }
    pub(crate) async fn connect_owned(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
        ownership: Option<Arc<ProxyNativeOwnership>>,
    ) -> io::Result<ProxySocket> {
        let work = self.work(ownership)?;
        let deadline = deadline.min(Instant::now() + CONNECT_TIMEOUT);
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "proxy connection canceled")),
            result = tokio::time::timeout_at(deadline, async {
                let addresses = self.resolve(work.clone()).await?;
                let mut last_error = invalid();
                for address in addresses.into_iter().take(3) {
                    if cancellation.is_cancelled() || Instant::now() >= deadline { return Err(io::Error::new(io::ErrorKind::TimedOut, "proxy connection expired")); }
                    match TcpStream::connect(address).await {
                        Ok(socket) => {
                            let peer = socket.peer_addr()?;
                            if normalize(peer.ip()) != address.ip() || peer.port() != self.port || !self.allows(peer.ip()) || matches!(peer, SocketAddr::V6(value) if value.scope_id() != 0) || cancellation.is_cancelled() || Instant::now() >= deadline { return Err(invalid()); }
                            return Ok(ProxySocket { socket, _work: work });
                        }
                        Err(error) => last_error = error,
                    }
                }
                Err(last_error)
            }) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy connection timed out"))?,
        }
    }

    pub(crate) async fn close(&self) {
        self.pool.permits.close();
        loop {
            let completed = self.pool.completed.notified();
            tokio::pin!(completed);
            completed.as_mut().enable();
            if self.pool.active.load(Ordering::Acquire) == 0 {
                return;
            }
            completed.await;
        }
    }
}

fn valid_dns_name(host: &str) -> bool {
    host.len() <= 253
        && !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && host.rsplit('.').next().is_some_and(|last| {
            !last.bytes().all(|byte| byte.is_ascii_digit())
                && !last
                    .strip_prefix("0x")
                    .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn actual_socket_retains_network_capacity_until_cleanup() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let policy = ProxyNetworkPolicy::compile(&url, &[], 1).unwrap();
        let cancellation = CancellationToken::new();
        let socket = policy
            .connect(Instant::now() + CONNECT_TIMEOUT, &cancellation)
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        assert!(
            policy
                .connect(Instant::now() + CONNECT_TIMEOUT, &cancellation)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(5), policy.close())
                .await
                .is_err()
        );
        drop(socket);
        tokio::time::timeout(Duration::from_secs(1), policy.close())
            .await
            .unwrap();
        assert!(
            policy
                .connect(Instant::now() + CONNECT_TIMEOUT, &cancellation)
                .await
                .is_err()
        );
    }

    #[test]
    fn policy_requires_independent_address_authority_and_complete_answers() {
        let url = Url::parse("http://proxy.test:8080").unwrap();
        assert!(ProxyNetworkPolicy::compile(&url, &[], 1).is_err());
        let policy = ProxyNetworkPolicy::compile(&url, &["127.0.0.1".into()], 1).unwrap();
        assert!(
            policy
                .validate_answer([
                    "127.0.0.1:8080".parse().unwrap(),
                    "192.0.2.1:8080".parse().unwrap()
                ])
                .is_err()
        );
        assert!(
            policy
                .validate_answer(["[::ffff:127.0.0.1]:8080".parse().unwrap()])
                .is_ok()
        );
        assert!(
            policy
                .validate_answer(["127.0.0.1:8081".parse().unwrap()])
                .is_err()
        );
        assert!(
            policy
                .validate_answer(vec!["127.0.0.1:8080".parse().unwrap(); 65])
                .is_err()
        );
        assert!(policy.validate_answer([]).is_err());
    }

    #[test]
    fn numeric_authority_is_pinned_and_ranges_are_canonical() {
        let url = Url::parse("http://[::ffff:7f00:1]:8080").unwrap();
        let policy = ProxyNetworkPolicy::compile(&url, &["127.0.0.0/8".into()], 1).unwrap();
        assert!(policy.allows(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!policy.allows("127.0.0.2".parse().unwrap()));
        for raw in [
            "192.0.2.1/24",
            "::ffff:127.0.0.1/95",
            "0.0.0.0/033",
            "fe80::1%en0",
            "127.1",
        ] {
            assert!(Prefix::parse(raw).is_err(), "{raw}");
        }
        for host in [
            "127.1",
            "0x7f.0.0.1",
            "2130706433",
            "a..test",
            "example.test.",
        ] {
            assert!(!valid_dns_name(host), "{host}");
        }
    }
}
