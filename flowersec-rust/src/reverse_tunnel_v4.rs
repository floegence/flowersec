//! One original physical listener preparation for a reverse tunnel leg. Its
//! logical endpoint role and original consume owner remain unchanged.
use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

pub struct ReverseTunnelProviderOptions {
    pub listen_address: std::net::SocketAddr,
    pub identity: serve::WssServerIdentity,
    pub origin: Option<String>,
    pub timeout: Duration,
    pub publication_timeout: Duration,
    pub queue_messages: usize,
    pub prepare_bytes: usize,
    pub native_runtime_bytes: u64,
}
impl fmt::Debug for ReverseTunnelProviderOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReverseTunnelProviderOptions { <redacted> }")
    }
}
pub(super) enum PreboundSocket {
    Tcp(std::net::TcpListener),
    Udp(std::net::UdpSocket),
}
pub(crate) struct Capture {
    root: Arc<EnvironmentRoot>,
    address: std::net::SocketAddr,
    identity: serve::WssServerIdentity,
    tls: Arc<rustls::ServerConfig>,
    prebound_listener: Mutex<Option<PreboundSocket>>,
    ready: AtomicBool,
    changed: tokio::sync::Notify,
    observers: std::sync::atomic::AtomicUsize,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for Capture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalReverseTunnelListener { <opaque> }")
    }
}
impl Capture {
    pub(crate) fn new(
        root: Arc<EnvironmentRoot>,
        options: ReverseTunnelProviderOptions,
    ) -> ConnectResult<(Arc<Self>, WssConnectOptions)> {
        Self::new_with_socket(root, options, None)
    }
    pub(super) fn new_with_socket(
        root: Arc<EnvironmentRoot>,
        options: ReverseTunnelProviderOptions,
        prebound_listener: Option<PreboundSocket>,
    ) -> ConnectResult<(Arc<Self>, WssConnectOptions)> {
        let identity = options.identity;
        if options.listen_address.port() == 0
            || options.listen_address.ip().is_unspecified()
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
            || options.publication_timeout.is_zero()
            || options.publication_timeout > Duration::from_secs(5)
            || !(1..=64).contains(&options.queue_messages)
            || !(16384..=262144).contains(&options.prepare_bytes)
            || options.native_runtime_bytes < 1048576
            || options
                .origin
                .as_ref()
                .is_some_and(|origin| origin.len() > 2048 || origin.capacity() > 4096)
            || identity.certificate_chain_der.is_empty()
            || identity.certificate_chain_der.capacity() > 16
            || identity
                .certificate_chain_der
                .iter()
                .any(|certificate| certificate.is_empty() || certificate.capacity() > 65536)
            || identity.private_key_der.is_empty()
            || identity.private_key_der.capacity() > 16384
        {
            return Err(ConnectError::Configuration);
        }
        let bytes = identity
            .certificate_chain_der
            .iter()
            .try_fold(identity.private_key_der.capacity(), |bytes, certificate| {
                bytes.checked_add(certificate.capacity())
            })
            .ok_or(ConnectError::Capacity)?;
        if bytes > 262144 {
            return Err(ConnectError::Configuration);
        }
        if let Some(listener) = prebound_listener.as_ref() {
            let address = match listener {
                PreboundSocket::Tcp(listener) => listener.local_addr(),
                PreboundSocket::Udp(socket) => socket.local_addr(),
            }
            .map_err(|_| ConnectError::Carrier)?;
            if address != options.listen_address {
                return Err(ConnectError::Configuration);
            }
        }
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: bytes as u64 + 32768,
            provider_bytes: 262144,
            items: 20,
            work_slots: 17,
            timers: 16,
            ..ResourceLimits::default()
        })?;
        wss::interval(&identity.certificate_chain_der[0], root.sample()?)
            .map_err(|_| ConnectError::Tls)?;
        let key = PrivateKeyDer::try_from(identity.private_key_der.clone())
            .map_err(|_| ConnectError::Configuration)?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ConnectError::Configuration)?
        .with_no_client_auth()
        .with_single_cert(
            identity
                .certificate_chain_der
                .iter()
                .cloned()
                .map(CertificateDer::from)
                .collect(),
            key,
        )
        .map_err(|_| ConnectError::Tls)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.max_early_data_size = 0;
        tls.send_tls13_tickets = 0;
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let provider = WssConnectOptions {
            binding_mode: BindingMode::AuthenticatedContext,
            remote_address: options.listen_address.ip(),
            origin: options.origin,
            ca_certificates_der: Vec::new(),
            timeout: options.timeout,
            publication_timeout: options.publication_timeout,
            queue_messages: options.queue_messages,
            prepare_bytes: options.prepare_bytes,
            native_runtime_bytes: options.native_runtime_bytes,
        };
        Ok((
            Arc::new(Self {
                root,
                address: options.listen_address,
                identity,
                tls: Arc::new(tls),
                prebound_listener: Mutex::new(prebound_listener),
                ready: AtomicBool::new(false),
                changed: tokio::sync::Notify::new(),
                observers: std::sync::atomic::AtomicUsize::new(0),
                _charge: charge,
            }),
            provider,
        ))
    }
    /// Observes a physical bind only. This conveys no consume, HOP, admission,
    /// Session or retry authority and cannot redirect the original listener.
    pub(crate) async fn wait_ready(
        self: &Arc<Self>,
        timeout: Duration,
        caller: &CancellationToken,
    ) -> ConnectResult<std::net::SocketAddr> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(ConnectError::Configuration);
        }
        self.observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = PreparationObserver(self.clone());
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ConnectError::Configuration)?;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if caller.is_cancelled() || self.root.is_closed() {
                return Err(ConnectError::Canceled);
            }
            if self.ready.load(Ordering::Acquire) {
                return Ok(self.address);
            }
            tokio::select! {
                _ = changed => {}, _ = caller.cancelled() => return Err(ConnectError::Canceled),
                _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline),
            }
        }
    }
    pub(crate) fn validate(
        &self,
        material: &PoolConnectionMaterial,
        options: &WssConnectOptions,
    ) -> ConnectResult<()> {
        let policy = wss::Policy::new_reverse_endpoint(material, options)?;
        self.check_policy(&policy, &material.admission.account)
            .map(|_| ())
    }
    pub(crate) fn validate_live(
        &self,
        artifact: &[u8],
        admission: &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
        options: &WssConnectOptions,
    ) -> ConnectResult<()> {
        let policy = wss::Policy::new_live_reverse_tunnel(artifact, admission, options)?;
        self.check_policy(&policy, &admission.account).map(|_| ())
    }
    fn check_policy(
        &self,
        policy: &wss::Policy,
        account: &ResourceAccount,
    ) -> ConnectResult<(u64, u64)> {
        if !account.belongs_to(&self.root)
            || policy.path_kind != 1
            || policy.port != self.address.port()
            || policy
                .host
                .parse::<IpAddr>()
                .is_ok_and(|address| address != self.address.ip())
        {
            return Err(ConnectError::Configuration);
        }
        let now = account.security_time()?;
        let leaf = &self.identity.certificate_chain_der[0];
        let interval = wss::interval(leaf, now).map_err(|_| ConnectError::Tls)?;
        if let Some(pins) = &policy.pins {
            wss::pin_profile(leaf).map_err(|_| ConnectError::Tls)?;
            let digest: [u8; 32] = Sha256::digest(leaf).into();
            if !pins.iter().any(|pin| {
                pin.digest == digest
                    && pin.start >= interval.0
                    && pin.end <= interval.1
                    && now.lower_ms >= pin.start
                    && now.upper_ms < pin.end
            }) {
                return Err(ConnectError::Tls);
            }
        }
        Ok(interval)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Reverse preparation preserves distinct material, prepaid charges, caller cancellation and cleanup custody."
    )]
    pub(super) async fn prepare(
        self: &Arc<Self>,
        account: ResourceAccount,
        artifact: &[u8],
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        diagnostic: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
        cleanup: Option<Arc<ConnectCleanup>>,
    ) -> ConnectResult<(direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)> {
        self.prepare_physical(
            account,
            Some(artifact),
            policy,
            options,
            deadline,
            caller,
            None,
            None,
            diagnostic,
            cleanup,
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Reverse preparation preserves distinct material, prepaid charges, caller cancellation and cleanup custody."
    )]
    pub(super) async fn prepare_prepaid(
        self: &Arc<Self>,
        account: ResourceAccount,
        artifact: &[u8],
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        prepaid: ControllerProviderCharges,
        diagnostic: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
        cleanup: Option<Arc<ConnectCleanup>>,
    ) -> ConnectResult<(direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)> {
        self.prepare_physical(
            account,
            Some(artifact),
            policy,
            options,
            deadline,
            caller,
            Some(prepaid),
            None,
            diagnostic,
            cleanup,
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Reverse preparation preserves distinct material, prepaid charges, caller cancellation and cleanup custody."
    )]
    pub(super) async fn prepare_live(
        self: &Arc<Self>,
        account: ResourceAccount,
        artifact: &[u8],
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        prepaid: Option<ControllerProviderCharges>,
        control: Arc<crate::live_material_source_v4::LiveTunnelAuthorityControl>,
        pending: &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
        diagnostic: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
        cleanup: Option<Arc<ConnectCleanup>>,
    ) -> ConnectResult<(direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)> {
        self.prepare_physical(
            account,
            Some(artifact),
            policy,
            options,
            deadline,
            caller,
            prepaid,
            Some((control, pending)),
            diagnostic,
            cleanup,
        )
        .await
    }
    pub(super) fn controller_preparation_costs(
        &self,
        policy: &wss::Policy,
        account: &ResourceAccount,
        options: &WssConnectOptions,
    ) -> ConnectResult<ControllerProviderCosts> {
        self.check_policy(policy, account)?;
        Self::controller_costs(policy.maximum, policy.carrier, options)
    }
    pub(crate) fn controller_upper_costs(
        options: &WssConnectOptions,
    ) -> ConnectResult<ControllerProviderCosts> {
        Self::controller_costs(1_048_584, 0, options)
    }
    fn controller_costs(
        maximum: usize,
        carrier: u8,
        options: &WssConnectOptions,
    ) -> ConnectResult<ControllerProviderCosts> {
        Ok(ControllerProviderCosts {
            listener: Some(ResourceLimits {
                sdk_bytes: 65536,
                provider_bytes: options.native_runtime_bytes,
                items: 4,
                tasks: 2,
                work_slots: 2,
                timers: 1,
                native_handles: if carrier == 1 { 1 } else { 16 },
                ..ResourceLimits::default()
            }),
            connection: ResourceLimits {
                sdk_bytes: (maximum as u64)
                    .checked_mul(options.queue_messages as u64 + 4)
                    .and_then(|bytes| bytes.checked_add(819200))
                    .ok_or(ConnectError::Capacity)?,
                provider_bytes: options
                    .native_runtime_bytes
                    .checked_add(options.prepare_bytes as u64)
                    .and_then(|bytes| bytes.checked_add(524288))
                    .ok_or(ConnectError::Capacity)?,
                items: options.queue_messages as u64 + 16,
                tasks: if carrier == 1 { 6 } else { 24 },
                work_slots: if carrier == 1 { 8 } else { 24 },
                timers: if carrier == 1 { 3 } else { 8 },
                connections: 1,
                native_handles: if carrier == 1 { 8 } else { 32 },
                ..ResourceLimits::default()
            },
            tls: Some(ResourceLimits {
                tls_handshakes: 1,
                ..ResourceLimits::default()
            }),
        })
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Reverse preparation preserves distinct material, prepaid charges, caller cancellation and cleanup custody."
    )]
    async fn prepare_physical(
        self: &Arc<Self>,
        account: ResourceAccount,
        artifact: Option<&[u8]>,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        prepaid: Option<ControllerProviderCharges>,
        readiness: Option<(
            Arc<crate::live_material_source_v4::LiveTunnelAuthorityControl>,
            &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
        )>,
        diagnostic: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
        cleanup: Option<Arc<ConnectCleanup>>,
    ) -> ConnectResult<(direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)> {
        let validity = self.check_policy(&policy, &account)?;
        let costs = self.controller_preparation_costs(&policy, &account, &options)?;
        // Every accepted worker and handshake is prepaid before the first
        // listener can accept. Failure cannot consume the original pool row.
        let listener_limits = costs.listener.ok_or(ConnectError::Configuration)?;
        let tls_limits = costs.tls.ok_or(ConnectError::Configuration)?;
        let (listener_charge, connection_charge, tls_charge) = if let Some(prepaid) = prepaid {
            let listener = prepaid.listener.ok_or(ConnectError::Configuration)?;
            let tls = prepaid.tls.ok_or(ConnectError::Configuration)?;
            if !listener.matches(&account, listener_limits)
                || !prepaid.connection.matches(&account, costs.connection)
                || !tls.matches(&account, tls_limits)
            {
                return Err(ConnectError::Configuration);
            }
            (
                PreparationCharge::Account(listener),
                PreparationCharge::Account(prepaid.connection),
                PreparationCharge::Account(tls),
            )
        } else {
            (
                self.root.reserve_environment(listener_limits)?.into(),
                self.root.reserve_environment(costs.connection)?.into(),
                self.root.reserve_environment(tls_limits)?.into(),
            )
        };
        let operation_cancel = caller.child_token();
        let mut withdrawal = OriginalPreparationWithdrawal {
            cancel: operation_cancel.clone(),
            cleanup: cleanup.clone(),
            delivered: false,
        };
        let worker_cancel = operation_cancel.clone();
        let worker_cleanup = cleanup.clone();
        let capture = self.clone();
        // The bounded public observer does not own the accept future. Its
        // original prepaid listener task keeps all custody through bind,
        // accepted-connection abort and listener termination after withdrawal.
        let artifact = artifact.map(|bytes| bytes.to_vec());
        let (completed, mut completion) = tokio::sync::oneshot::channel();
        let preparation = cleanup.as_ref().map(|owner| {
            direct_carrier::PreparationTail::new(owner.preparations()).with_cleanup(cleanup.clone())
        });
        let diagnostic_tail = diagnostic
            .as_ref()
            .map(|activity| activity.retain_physical());
        tokio::spawn(async move {
            let mut tail = ListenerTail {
                listener: None,
                charge: Some(listener_charge),
                preparation,
                diagnostic: diagnostic_tail,
                cleanup: worker_cleanup.clone(),
                capture: capture.clone(),
            };
            let result = async {
                let physical = direct_listener::Options {
                    listen_address: capture.address,
                    host: policy.host.clone(),
                    origin: options.origin.clone(),
                    max_connections: 1,
                    max_frame_bytes: policy.maximum - 8,
                    handshake_timeout: deadline.saturating_duration_since(Instant::now()),
                    prepare_bytes: options.prepare_bytes,
                    native_runtime_bytes: options.native_runtime_bytes,
                };
                // Native bind reports failure before spawning an endpoint
                // driver; successful binds are adopted immediately by tail.
                tail.listener = Some(direct_listener::Listener::bind_path_prepared(
                    capture.root.clone(), policy.carrier, 1, &capture.identity, &physical,
                ).await?);
                if tail.listener.as_ref().ok_or(ConnectError::Configuration)?.local_address()? != capture.address {
                    return Err(ConnectError::Configuration);
                }
                capture.ready.store(true, Ordering::Release);
                capture.changed.notify_waiters();
                let cancellation = flowersec_native_transport::Cancellation::new();
                let accepted = {
                    let listener = tail.listener.as_ref().ok_or(ConnectError::Configuration)?;
                    let original_accept = listener.accept(&cancellation);
                    tokio::pin!(original_accept);
                    tokio::select! {
                        result = &mut original_accept => result,
                        _ = worker_cancel.cancelled() => {
                            if let Some(cleanup) = &worker_cleanup { cleanup.start(); }
                            cancellation.cancel();
                            if let Ok(incoming) = original_accept.await { incoming.abort_and_wait().await; }
                            return Err(ConnectError::Canceled);
                        },
                        _ = tokio::time::sleep_until(deadline) => {
                            if let Some(cleanup) = &worker_cleanup { cleanup.start(); }
                            cancellation.cancel();
                            if let Ok(incoming) = original_accept.await { incoming.abort_and_wait().await; }
                            return Err(ConnectError::Deadline);
                        },
                    }?
                };
                let authority = if policy.host.parse::<std::net::Ipv6Addr>().is_ok() {
                    format!("[{}]:{}", policy.host, policy.port)
                } else { format!("{}:{}", policy.host, policy.port) };
                let relay_limits = (policy.max_streams, policy.max_credit, policy.live_maximum);
                let socket = serve::SocketPolicy {
                    relay_unassigned: false, relay_budget: policy.relay_budget.clone(), path_kind: 1,
                    binding_mode: BindingMode::AuthenticatedContext, tls: capture.tls.clone(),
                    host: policy.host, authority, allow_absent_origin: options.origin.is_none(),
                    origins: options.origin.into_iter().collect(), validity, maximum: policy.maximum,
                    publication_timeout: options.publication_timeout,
                    queue_messages: options.queue_messages, prepare_bytes: options.prepare_bytes,
                };
                let retained = Mutex::new(None);
                let provider_tail = worker_cleanup.as_ref().map(|owner| {
                    match diagnostic.as_ref() {
                        Some(diagnostic) => direct_carrier::PreparationTail::with_diagnostic(owner.preparations(), diagnostic),
                        None => direct_carrier::PreparationTail::new(owner.preparations()),
                    }.with_cleanup(worker_cleanup.clone())
                });
                let prepared = direct_carrier::Provider::accept_with_charges_observed(
                    capture.root.clone(), accepted, socket, deadline, worker_cancel.clone(),
                    (connection_charge, tls_charge), provider_tail,
                    |provider| {
                        if let Some(diagnostic) = diagnostic.as_ref() {
                            provider.retain_connect_diagnostic(diagnostic.clone());
                        }
                        *retained.lock().expect("reverse physical owner") = Some(provider);
                    },
                    |_| Box::pin(async { Ok(serve::RequestAuthorization { allowed: true }) }),
                ).await;
                let provider = retained.into_inner().expect("reverse physical owner");
                let retired = match &provider {
                    Some(provider) => tail.retire(Some(provider)),
                    None => Ok(()),
                };
                let (provider, incoming) = match prepared {
                    Ok(prepared) => prepared,
                    Err(failure) => {
                        if let Some(cleanup) = &worker_cleanup { cleanup.start(); }
                        if let Some(provider) = &provider { provider.close(); }
                        return Err(failure);
                    },
                };
                let mut guard = direct_carrier::Guard(Some(provider.clone()));
                retired?;
                if let Some(artifact) = artifact.as_deref() {
                    provider.bind_contract(decode(artifact, "Artifact", 65536, Context::default())?)?;
                } else { provider.bind_relay_limits(relay_limits.0, relay_limits.1, relay_limits.2)?; }
                provider.attach(account)?;
                provider.check()?;
                guard.0 = None;
                Ok(PreparedReverse {
                    guard: direct_carrier::Guard(Some(provider.clone())),
                    provider,
                    incoming,
                })
            }.await;
            let failed = result.is_err();
            // Publish the actual preparation result before waking cancellation;
            // otherwise the outer bounded observer can report Canceled and
            // discard a real Carrier/Deadline failure.
            let _ = completed.send(result);
            if failed {
                if let Some(cleanup) = &worker_cleanup {
                    cleanup.start();
                }
                worker_cancel.cancel();
            }
            // Unobserved successful results retain close custody in their
            // Guard. Failed native preparations retain their own charged tail.
        });
        // Readiness and the original bind/accept are concurrent: readiness
        // cannot await its relay ACK before the original listener can accept.
        let announce = async {
            let result = if let Some((control, pending)) = readiness {
                tokio::select! {
                    result = control.relay_ready(pending, &operation_cancel) => result,
                    _ = operation_cancel.cancelled() => Err(ConnectError::Canceled),
                    _ = tokio::time::sleep_until(deadline) => Err(ConnectError::Deadline),
                }
            } else {
                Ok(())
            };
            if result.is_err() {
                if let Some(cleanup) = &cleanup {
                    cleanup.start();
                }
                operation_cancel.cancel();
            }
            result
        };
        let prepare = async {
            tokio::select! {
                biased;
                result = &mut completion => result.unwrap_or(Err(ConnectError::Carrier)),
                _ = operation_cancel.cancelled() => {
                    if let Some(cleanup) = &cleanup { cleanup.start(); }
                    Err(ConnectError::Canceled)
                },
                _ = tokio::time::sleep_until(deadline) => {
                    if let Some(cleanup) = &cleanup { cleanup.start(); }
                    operation_cancel.cancel();
                    Err(ConnectError::Deadline)
                },
            }
        };
        let (announced, prepared) = tokio::join!(announce, prepare);
        // Preparation failure cancels the announcement waiter. Preserve that
        // actual failure instead of projecting its wakeup as caller withdrawal.
        // A substantive announcement failure still owns its original outcome.
        let mut prepared = match (announced, prepared) {
            (Err(ConnectError::Canceled), Err(failure)) => return Err(failure),
            (Err(failure), _) => return Err(failure),
            (Ok(()), prepared) => prepared?,
        };
        prepared.guard.0 = None;
        withdrawal.delivered = true;
        Ok((prepared.provider, prepared.incoming))
    }
}
struct OriginalPreparationWithdrawal {
    cancel: CancellationToken,
    cleanup: Option<Arc<ConnectCleanup>>,
    delivered: bool,
}
impl Drop for OriginalPreparationWithdrawal {
    fn drop(&mut self) {
        if !self.delivered {
            if let Some(cleanup) = &self.cleanup {
                cleanup.start();
            }
            self.cancel.cancel();
        }
    }
}
struct PreparedReverse {
    provider: direct_carrier::Provider,
    incoming: mpsc::Receiver<Vec<u8>>,
    guard: direct_carrier::Guard,
}
struct PreparationObserver(Arc<Capture>);
impl Drop for PreparationObserver {
    fn drop(&mut self) {
        self.0.observers.fetch_sub(1, Ordering::AcqRel);
    }
}
struct ListenerTail {
    listener: Option<direct_listener::Listener>,
    charge: Option<PreparationCharge>,
    preparation: Option<direct_carrier::PreparationTail>,
    diagnostic: Option<crate::diagnostics_v4::DiagnosticPhysicalTail>,
    cleanup: Option<Arc<ConnectCleanup>>,
    capture: Arc<Capture>,
}
impl ListenerTail {
    fn retire(&mut self, provider: Option<&direct_carrier::Provider>) -> ConnectResult<()> {
        let Some(listener) = self.listener.take() else {
            return Ok(());
        };
        if let Some(cleanup) = &self.cleanup {
            cleanup.start();
        }
        self.capture.ready.store(false, Ordering::Release);
        self.capture.changed.notify_waiters();
        let charge = self.charge.take();
        if matches!(listener, direct_listener::Listener::WebSocket(_)) {
            drop(listener);
            drop(charge);
            drop(self.diagnostic.take());
            drop(self.preparation.take());
            return Ok(());
        }
        listener.seal();
        let done = Arc::new(AtomicBool::new(false));
        let bound = provider.map_or(Ok(()), |provider| {
            provider.retain_listener_cleanup(done.clone())
        });
        let preparation = self.preparation.take();
        let diagnostic = self.diagnostic.take();
        tokio::spawn(async move {
            listener.finish().await;
            drop(charge);
            drop(diagnostic);
            done.store(true, Ordering::Release);
            drop(preparation);
        });
        bound
    }
}
impl Drop for ListenerTail {
    fn drop(&mut self) {
        let _ = self.retire(None);
        // Bind failure has no listener to retire. Preserve the same charge,
        // diagnostic, then aggregate-count retirement ordering in that case.
        drop(self.charge.take());
        drop(self.diagnostic.take());
        drop(self.preparation.take());
    }
}

// A relay listener is shared by its original pending publications. Routing a
// HELLO selects only an already installed original continuation; it never
// creates a publication, claim, winner or endpoint admission capability.
struct RelayRoute {
    id: u64,
    grant: Vec<u8>,
    account: ResourceAccount,
    policy: wss::Policy,
    deadline: Instant,
    cancellation: CancellationToken,
    reply: tokio::sync::oneshot::Sender<ConnectResult<AcceptedRelayLeg>>,
    provider_charge: Option<ResourceCharge>,
    _tls_prepaid: ResourceCharge,
    _charge: ResourceCharge,
}
struct SharedGate {
    started: bool,
    closed: bool,
    generation: u64,
    routes: Vec<RelayRoute>,
}
pub(super) struct AcceptedRelayLeg {
    pub(super) provider: direct_carrier::Provider,
    pub(super) incoming: mpsc::Receiver<Vec<u8>>,
    pub(super) first_hello: Option<Vec<u8>>,
    pub(super) guard: direct_carrier::Guard,
}
pub(super) struct SharedRelayListener {
    capture: Arc<Capture>,
    options: WssConnectOptions,
    maximum_pairs: usize,
    endpoint_listener: bool,
    gate: Mutex<SharedGate>,
    cancellation: CancellationToken,
    done: AtomicBool,
    workers: tokio_util::task::TaskTracker,
    host: Mutex<Option<(u8, String)>>,
    cleanup_changed: Mutex<Option<Arc<tokio::sync::Notify>>>,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for SharedRelayListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedRelayListener { <opaque> }")
    }
}
impl SharedRelayListener {
    pub(super) fn new(
        capture: Arc<Capture>,
        options: WssConnectOptions,
        maximum_pairs: usize,
        endpoint_listener: bool,
    ) -> ConnectResult<Arc<Self>> {
        let maximum_pairs = maximum_pairs.checked_mul(2).ok_or(ConnectError::Capacity)?;
        let charge = capture.root.reserve_environment(ResourceLimits {
            sdk_bytes: 65536,
            items: maximum_pairs as u64 + 4,
            tasks: maximum_pairs as u64 + 1,
            work_slots: maximum_pairs as u64 + 1,
            timers: maximum_pairs as u64 + 1,
            native_handles: 16,
            provider_bytes: options.native_runtime_bytes,
            ..ResourceLimits::default()
        })?;
        Ok(Arc::new(Self {
            capture,
            options,
            maximum_pairs,
            endpoint_listener,
            gate: Mutex::new(SharedGate {
                started: false,
                closed: false,
                generation: 0,
                routes: Vec::with_capacity(maximum_pairs),
            }),
            cancellation: CancellationToken::new(),
            done: AtomicBool::new(false),
            workers: tokio_util::task::TaskTracker::new(),
            host: Mutex::new(None),
            cleanup_changed: Mutex::new(None),
            _charge: charge,
        }))
    }
    /// Bind only the independently installed physical ingress. No route,
    /// account, Grant, HOP claim or application callback is installed here.
    pub(super) fn start_installed(
        self: &Arc<Self>,
        carrier: u8,
        host: String,
    ) -> ConnectResult<()> {
        if carrier > 2
            || host.is_empty()
            || host.len() > 253
            || host.capacity() > 512
            || host.bytes().any(|byte| {
                byte <= 32 || byte >= 127 || matches!(byte, b'/' | b'@' | b'#' | b'?' | b'[' | b']')
            })
            || host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip != self.capture.address.ip())
            || !tokio::runtime::Handle::try_current().is_ok_and(|runtime| {
                runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            })
        {
            return Err(ConnectError::Configuration);
        }
        let validity = wss::interval(
            &self.capture.identity.certificate_chain_der[0],
            self.capture.root.sample()?,
        )
        .map_err(|_| ConnectError::Tls)?;
        let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]:{}", self.capture.address.port())
        } else {
            format!("{host}:{}", self.capture.address.port())
        };
        let socket = serve::SocketPolicy {
            relay_unassigned: true,
            relay_budget: None,
            path_kind: 1,
            binding_mode: BindingMode::AuthenticatedContext,
            tls: self.capture.tls.clone(),
            host: host.clone(),
            authority,
            allow_absent_origin: self.options.origin.is_none(),
            origins: self.options.origin.clone().into_iter().collect(),
            validity,
            maximum: (1 << 20) + 8,
            publication_timeout: self.options.publication_timeout,
            queue_messages: 1,
            prepare_bytes: self.options.prepare_bytes,
        };
        {
            let mut gate = self
                .gate
                .lock()
                .expect("original installed live listener start");
            if gate.closed || self.capture.root.is_closed() || self.cancellation.is_cancelled() {
                return Err(ConnectError::Canceled);
            }
            let mut installed = self
                .host
                .lock()
                .expect("fixed installed live listener host");
            if gate.started {
                return if installed
                    .as_ref()
                    .is_some_and(|policy| policy.0 == carrier && policy.1 == host)
                {
                    Ok(())
                } else {
                    Err(ConnectError::Configuration)
                };
            }
            *installed = Some((carrier, host));
            gate.started = true;
        }
        let owner = self.clone();
        tokio::spawn(async move {
            owner.listen(socket, carrier).await;
        });
        Ok(())
    }
    pub(super) fn belongs_to(&self, root: &Arc<EnvironmentRoot>) -> bool {
        Arc::ptr_eq(root, &self.capture.root)
    }
    pub(super) fn local_address(&self) -> std::net::SocketAddr {
        self.capture.address
    }
    pub(super) fn observe_cleanup(&self, changed: Arc<tokio::sync::Notify>) -> ConnectResult<()> {
        // An original standby listener transfers this observation to its
        // consuming Serve owner. The socket and all worker owners stay fixed.
        *self
            .cleanup_changed
            .lock()
            .expect("original listener cleanup observer") = Some(changed);
        Ok(())
    }
    pub(super) fn installed_as(&self, carrier: u8, host: &str) -> bool {
        let gate = self
            .gate
            .lock()
            .expect("installed original listener policy");
        gate.started
            && !gate.closed
            && !self.cancellation.is_cancelled()
            && self
                .host
                .lock()
                .expect("installed original listener host")
                .as_ref()
                .is_some_and(|policy| policy.0 == carrier && policy.1 == host)
    }
    pub(super) fn same_address(&self, other: &Self) -> bool {
        self.capture.address == other.capture.address
    }
    pub(super) fn matches_reverse_installation(
        &self,
        options: &ReverseTunnelProviderOptions,
    ) -> bool {
        self.capture.address == options.listen_address
            && self.capture.identity.certificate_chain_der == options.identity.certificate_chain_der
            && self.capture.identity.private_key_der == options.identity.private_key_der
            && self.options.origin == options.origin
            && self.options.timeout == options.timeout
            && self.options.publication_timeout == options.publication_timeout
            && self.options.queue_messages == options.queue_messages
            && self.options.prepare_bytes == options.prepare_bytes
            && self.options.native_runtime_bytes == options.native_runtime_bytes
    }
    pub(super) fn same_installation(&self, other: &Self) -> bool {
        self.endpoint_listener == other.endpoint_listener
            && self.same_address(other)
            && self.capture.identity.certificate_chain_der
                == other.capture.identity.certificate_chain_der
            && self.capture.identity.private_key_der == other.capture.identity.private_key_der
            && self.options.origin == other.options.origin
            && self.options.timeout == other.options.timeout
            && self.options.publication_timeout == other.options.publication_timeout
            && self.options.queue_messages == other.options.queue_messages
            && self.options.prepare_bytes == other.options.prepare_bytes
            && self.options.native_runtime_bytes == other.options.native_runtime_bytes
    }
    pub(super) fn close(&self) {
        self.cancellation.cancel();
        let mut gate = self.gate.lock().expect("shared relay listener close");
        gate.closed = true;
        for route in gate.routes.drain(..) {
            let _ = route.reply.send(Err(ConnectError::Canceled));
        }
        if !gate.started {
            self.done.store(true, Ordering::Release);
        }
        self.capture.ready.store(false, Ordering::Release);
        self.capture.changed.notify_waiters();
    }
    pub(super) fn cleanup_complete(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
    pub(super) async fn wait_original_cleanup(
        self: &Arc<Self>,
        timeout: Duration,
    ) -> ConnectResult<bool> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(ConnectError::Configuration);
        }
        self.capture
            .observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = PreparationObserver(self.capture.clone());
        let until = Instant::now()
            .checked_add(timeout)
            .ok_or(ConnectError::Configuration)?;
        loop {
            let changed = self.capture.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.cleanup_complete() {
                return Ok(true);
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(until) => return Ok(self.cleanup_complete()) }
        }
    }
    pub(super) async fn wait_ready(
        self: &Arc<Self>,
        timeout: Duration,
        caller: &CancellationToken,
    ) -> ConnectResult<std::net::SocketAddr> {
        self.capture.wait_ready(timeout, caller).await
    }
    pub(super) fn physical_binding_ready(&self) -> ConnectResult<bool> {
        let gate = self
            .gate
            .lock()
            .expect("original physical listener bind observation");
        if gate.closed || self.capture.root.is_closed() || self.cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        if self.done.load(Ordering::Acquire) {
            return Err(ConnectError::Carrier);
        }
        Ok(gate.started && self.capture.ready.load(Ordering::Acquire))
    }
    pub(super) fn validate(
        &self,
        material: &PoolConnectionMaterial,
        options: &WssConnectOptions,
    ) -> ConnectResult<()> {
        self.capture.validate(material, options)
    }
    pub(super) fn validate_live_server_registration(
        &self,
        artifact: &[u8],
        registration: &crate::namespace_v4::verifier::credential::VerifiedLiveTunnelRegistration,
        options: &WssConnectOptions,
    ) -> ConnectResult<()> {
        let policy =
            wss::Policy::new_live_server_listener_registration(artifact, registration, options)?;
        self.capture.check_policy(&policy, registration.account())?;
        if !self.installed_as(policy.carrier, &policy.host) {
            return Err(ConnectError::Configuration);
        }
        Ok(())
    }
    pub(super) async fn prepare(
        self: &Arc<Self>,
        account: ResourceAccount,
        grant: &[u8],
        policy: wss::Policy,
        deadline: Instant,
        caller: CancellationToken,
    ) -> ConnectResult<AcceptedRelayLeg> {
        if self.endpoint_listener || policy.relay_budget.is_none() {
            return Err(ConnectError::Configuration);
        }
        self.prepare_original(account, grant, policy, deadline, caller)
            .await
    }
    pub(super) async fn prepare_endpoint(
        self: &Arc<Self>,
        account: ResourceAccount,
        grant: &[u8],
        policy: wss::Policy,
        deadline: Instant,
        caller: CancellationToken,
    ) -> ConnectResult<AcceptedRelayLeg> {
        if !self.endpoint_listener || policy.relay_budget.is_some() {
            return Err(ConnectError::Configuration);
        }
        self.prepare_original(account, grant, policy, deadline, caller)
            .await
    }
    async fn prepare_original(
        self: &Arc<Self>,
        account: ResourceAccount,
        grant: &[u8],
        policy: wss::Policy,
        deadline: Instant,
        caller: CancellationToken,
    ) -> ConnectResult<AcceptedRelayLeg> {
        if policy.carrier > 2 || grant.is_empty() || grant.len() > 9302 {
            return Err(ConnectError::Configuration);
        }
        let validity = self.capture.check_policy(&policy, &account)?;
        let mut provider_charge =
            policy.take_preparation(&account, self.preparation_limits(&policy, &account)?)?;
        let tls_prepaid = provider_charge.split(ResourceLimits {
            tls_handshakes: 1,
            ..ResourceLimits::default()
        })?;
        let charge = account.reserve(ResourceLimits {
            sdk_bytes: 16384,
            items: 1,
            tasks: 1,
            work_slots: 1,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        let authority = if policy.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", policy.host, policy.port)
        } else {
            format!("{}:{}", policy.host, policy.port)
        };
        let socket = serve::SocketPolicy {
            relay_unassigned: true,
            relay_budget: None,
            path_kind: 1,
            binding_mode: BindingMode::AuthenticatedContext,
            tls: self.capture.tls.clone(),
            host: policy.host.clone(),
            authority,
            allow_absent_origin: self.options.origin.is_none(),
            origins: self.options.origin.clone().into_iter().collect(),
            validity,
            maximum: (1 << 20) + 8,
            publication_timeout: self.options.publication_timeout,
            queue_messages: 1,
            prepare_bytes: self.options.prepare_bytes,
        };
        let carrier = policy.carrier;
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        let (id, start) = {
            let mut gate = self.gate.lock().expect("original shared relay route");
            if gate.closed || self.capture.root.is_closed() || caller.is_cancelled() {
                return Err(ConnectError::Canceled);
            }
            if gate.routes.len() >= self.maximum_pairs
                || gate.routes.iter().any(|route| route.grant == grant)
            {
                return Err(ConnectError::Capacity);
            }
            let mut host = self.host.lock().expect("frozen relay listener host");
            if host
                .as_ref()
                .is_some_and(|host| host.0 != policy.carrier || host.1 != policy.host)
            {
                return Err(ConnectError::Configuration);
            }
            if host.is_none() {
                *host = Some((policy.carrier, policy.host.clone()));
            }
            let id = gate
                .generation
                .checked_add(1)
                .ok_or(ConnectError::Capacity)?;
            gate.generation = id;
            let start = !gate.started;
            gate.started = true;
            gate.routes.push(RelayRoute {
                id,
                grant: grant.to_vec(),
                account,
                policy,
                deadline,
                cancellation: caller.clone(),
                reply: sender,
                provider_charge: Some(provider_charge),
                _tls_prepaid: tls_prepaid,
                _charge: charge,
            });
            (id, start)
        };
        self.capture.changed.notify_waiters();
        if start {
            let owner = self.clone();
            tokio::spawn(async move {
                owner.listen(socket, carrier).await;
            });
        }
        let failure = tokio::select! {
            result = &mut receiver => return self.finish_delivery(result, &caller).await,
            _ = caller.cancelled() => ConnectError::Canceled,
            _ = self.cancellation.cancelled() => ConnectError::Canceled,
            _ = tokio::time::sleep_until(deadline) => ConnectError::Deadline,
        };
        // Remove an unclaimed route, or await the exact worker that already
        // removed it. Neither cancellation nor timeout starts a replacement.
        {
            let mut gate = self.gate.lock().expect("original relay route withdrawal");
            if let Some(index) = gate.routes.iter().position(|route| route.id == id) {
                gate.routes.swap_remove(index);
            }
        }
        if let Ok(Ok(leg)) = receiver.await {
            leg.provider.close();
            wait_relay_provider(&leg.provider).await;
            drop(leg);
        }
        Err(failure)
    }
    async fn finish_delivery(
        &self,
        delivery: std::result::Result<
            ConnectResult<AcceptedRelayLeg>,
            tokio::sync::oneshot::error::RecvError,
        >,
        caller: &CancellationToken,
    ) -> ConnectResult<AcceptedRelayLeg> {
        let leg = delivery.map_err(|_| ConnectError::Carrier)??;
        if caller.is_cancelled()
            || self.cancellation.is_cancelled()
            || self.capture.root.is_closed()
        {
            leg.provider.close();
            wait_relay_provider(&leg.provider).await;
            return Err(ConnectError::Canceled);
        }
        Ok(leg)
    }
    async fn listen(self: Arc<Self>, socket: serve::SocketPolicy, carrier: u8) {
        let result = self.listen_original(socket, carrier).await;
        self.cancellation.cancel();
        self.workers.close();
        self.workers.wait().await;
        let mut gate = self.gate.lock().expect("shared relay listener retirement");
        gate.closed = true;
        for route in gate.routes.drain(..) {
            let _ = route
                .reply
                .send(Err(result.err().unwrap_or(ConnectError::Canceled)));
        }
        self.capture.ready.store(false, Ordering::Release);
        self.done.store(true, Ordering::Release);
        self.capture.changed.notify_waiters();
        if let Some(changed) = self
            .cleanup_changed
            .lock()
            .expect("original listener cleanup observer")
            .as_ref()
        {
            changed.notify_waiters();
        }
    }
    pub(super) fn preparation_limits(
        &self,
        policy: &wss::Policy,
        account: &ResourceAccount,
    ) -> ConnectResult<ResourceLimits> {
        self.capture.check_policy(policy, account)?;
        if policy.carrier != 1 {
            let base = (16u64 << 20)
                + self.options.prepare_bytes as u64
                + if policy.carrier == 2 { 262144 } else { 196608 };
            let backing = self
                .options
                .native_runtime_bytes
                .checked_sub(base)
                .ok_or(ConnectError::Capacity)?;
            let available = (backing / 16384).min(if policy.carrier == 2 { 4096 } else { 4097 });
            let required = (policy.max_streams as u64)
                .checked_mul(2)
                .and_then(|value| value.checked_add(4))
                .ok_or(ConnectError::Capacity)?;
            if available < required.max(14) {
                return Err(ConnectError::Capacity);
            }
        }
        let mut limits = self.connection_limits((1 << 20) + 8, policy.carrier);
        limits.tls_handshakes = 1;
        Ok(limits)
    }
    fn connection_limits(&self, maximum: usize, carrier: u8) -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: maximum as u64 * 5 + 819200,
            provider_bytes: self.options.native_runtime_bytes
                + self.options.prepare_bytes as u64
                + 524288,
            items: 17,
            tasks: if carrier == 1 { 6 } else { 24 },
            work_slots: if carrier == 1 { 8 } else { 24 },
            timers: if carrier == 1 { 3 } else { 8 },
            connections: 1,
            native_handles: if carrier == 1 { 8 } else { 32 },
            ..ResourceLimits::default()
        }
    }
    async fn listen_original(
        self: &Arc<Self>,
        socket: serve::SocketPolicy,
        carrier: u8,
    ) -> ConnectResult<()> {
        let physical = direct_listener::Options {
            listen_address: self.capture.address,
            host: socket.host.clone(),
            origin: self.options.origin.clone(),
            max_connections: self.maximum_pairs,
            max_frame_bytes: socket.maximum - 8,
            handshake_timeout: self.options.timeout,
            prepare_bytes: self.options.prepare_bytes,
            native_runtime_bytes: self.options.native_runtime_bytes,
        };
        let prebound = {
            self.capture
                .prebound_listener
                .lock()
                .expect("reverse relay bound listener")
                .take()
        };
        let listener = match prebound {
            Some(PreboundSocket::Tcp(listener)) if carrier == 1 => {
                direct_listener::Listener::from_websocket(listener, self.capture.address)?
            }
            Some(PreboundSocket::Udp(socket)) if carrier != 1 => {
                direct_listener::Listener::bind_path_on_udp_socket(
                    self.capture.root.clone(),
                    carrier,
                    1,
                    &self.capture.identity,
                    &physical,
                    socket,
                )
                .await?
            }
            Some(_) => return Err(ConnectError::Configuration),
            None => {
                direct_listener::Listener::bind_path(
                    self.capture.root.clone(),
                    carrier,
                    1,
                    &self.capture.identity,
                    &physical,
                )
                .await?
            }
        };
        let address = listener.local_address();
        if address != Ok(self.capture.address) {
            listener.seal();
            listener.finish().await;
            return Err(ConnectError::Configuration);
        }
        let mut tail = ListenerTail {
            listener: Some(listener),
            charge: None,
            preparation: None,
            diagnostic: None,
            cleanup: None,
            capture: self.capture.clone(),
        };
        self.capture.ready.store(true, Ordering::Release);
        self.capture.changed.notify_waiters();
        if let Some(changed) = self
            .cleanup_changed
            .lock()
            .expect("original physical listener bind observer")
            .as_ref()
        {
            changed.notify_waiters();
        }
        let positions = Arc::new(tokio::sync::Semaphore::new(self.maximum_pairs));
        let result = async { loop {
            let permit = tokio::select! { _ = self.cancellation.cancelled() => return Ok(()),
                result = positions.clone().acquire_owned() => result.map_err(|_| ConnectError::Capacity)? };
            // The initial socket, full bounded read queue, TLS and native thread
            // are prepaid before accept. Unknown peers cannot borrow a parent.
            let connection = self.capture.root.reserve_environment(self.connection_limits(socket.maximum, carrier))?;
            let tls = self.capture.root.reserve_environment(ResourceLimits { tls_handshakes: 1, ..ResourceLimits::default() })?;
            let native_cancel = flowersec_native_transport::Cancellation::new();
            let accepting = tail.listener.as_ref().ok_or(ConnectError::Configuration)?.accept(&native_cancel);
            tokio::pin!(accepting);
            let accepted = loop { tokio::select! {
                result = &mut accepting => break result?,
                _ = self.cancellation.cancelled() => {
                    native_cancel.cancel();
                    if let Ok(incoming) = accepting.await { incoming.abort_and_wait().await; }
                    return Ok(());
                },
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    if self.capture.root.is_closed() {
                        native_cancel.cancel();
                        if let Ok(incoming) = accepting.await { incoming.abort_and_wait().await; }
                        return Err(ConnectError::Canceled);
                    }
                }
            }};
            let mut policy = socket.clone(); policy.validity = wss::interval(&self.capture.identity.certificate_chain_der[0],
                self.capture.root.sample()?).map_err(|_| ConnectError::Tls)?;
            let owner = self.clone();
            self.workers.spawn(async move { let _permit = permit; owner.route_socket(accepted, policy, (connection, tls)).await; });
        }}.await;
        self.cancellation.cancel();
        self.workers.close();
        self.workers.wait().await;
        if let Some(listener) = tail.listener.take() {
            listener.seal();
            listener.finish().await;
        }
        result
    }
    async fn route_socket(
        self: Arc<Self>,
        incoming_socket: direct_listener::Incoming,
        socket: serve::SocketPolicy,
        charges: (EnvironmentCharge, EnvironmentCharge),
    ) {
        let deadline = Instant::now() + self.options.timeout;
        let retained = Mutex::new(None);
        let prepared = direct_carrier::Provider::accept(
            self.capture.root.clone(),
            incoming_socket,
            socket,
            deadline,
            self.cancellation.clone(),
            charges,
            |provider| {
                *retained.lock().expect("shared ingress provider") = Some(provider);
            },
            |_| Box::pin(async { Ok(serve::RequestAuthorization { allowed: true }) }),
        )
        .await;
        let retained = retained.into_inner().expect("shared ingress provider");
        let (provider, mut incoming) = match prepared {
            Ok(value) => value,
            Err(_) => {
                if let Some(provider) = retained {
                    provider.close();
                    wait_relay_provider(&provider).await;
                }
                return;
            }
        };
        let guard = direct_carrier::Guard(Some(provider.clone()));
        let mut route = None;
        let delivered = async {
            provider.complete_preparation()?;
            // An endpoint listener already owns its queued original material.
            // The relay HELLO has no Grant and belongs to EndpointHop's sole
            // reader. Relay listeners instead dispatch the endpoint's HELLO
            // to the exact installed Grant before any HOP authentication.
            let first = if self.endpoint_listener { None } else { Some(tokio::select! {
                _ = self.cancellation.cancelled() => return Err(ConnectError::Canceled),
                result = tokio::time::timeout_at(deadline, provider.receive_prepared(&mut incoming)) => result.map_err(|_| ConnectError::Deadline)??,
            }) };
            let hello = match &first {
                Some(wire) => Some(decode(payload(wire, 16, 10346)?, "HOP_AUTH_HELLO", 10346, Context::hop_endpoint())?),
                None => None,
            };
            let grant = hello.as_ref().map(|hello| hello.field("HOP_AUTH_HELLO", "grant")?.bytes()).transpose()?;
            // A bounded accepted socket may precede the original publication.
            // Keep its root charge and fixed deadline while waiting for the
            // queued material (endpoint) or exact HELLO Grant (relay). Neither
            // dispatch authenticates the peer or adds a new material choice.
            loop {
                let changed = self.capture.changed.notified(); tokio::pin!(changed); changed.as_mut().enable();
                {
                    let mut gate = self.gate.lock().expect("exact original relay HELLO dispatch");
                    if gate.closed || self.capture.root.is_closed() { return Err(ConnectError::Canceled); }
                    let index = if let Some(grant) = grant {
                        gate.routes.iter().position(|route| route.grant == grant)
                    } else {
                        gate.routes.iter().enumerate().min_by_key(|(_, route)| route.id).map(|(index, _)| index)
                    };
                    if let Some(index) = index {
                        route = Some(gate.routes.swap_remove(index)); break;
                    }
                }
                tokio::select! {
                    _ = changed => {},
                    _ = self.cancellation.cancelled() => return Err(ConnectError::Canceled),
                    _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Authorization),
                }
            }
            let original = route.as_mut().ok_or(ConnectError::Configuration)?;
            if original.cancellation.is_cancelled() || Instant::now() >= original.deadline { return Err(ConnectError::Canceled); }
            let prepaid = original.provider_charge.take().ok_or(ConnectError::Configuration)?;
            if let Some(budget) = original.policy.relay_budget.clone() {
                let assigned = async { match &provider {
                    direct_carrier::Provider::WebSocket(wss) => wss.assign_relay(original.account.clone(), budget, first.as_ref().map_or(0, Vec::len), prepaid).await,
                    direct_carrier::Provider::Native(native) => native.assign_relay(original.account.clone(), budget, first.as_ref().map_or(0, Vec::len), prepaid).await,
                }};
                tokio::time::timeout_at(original.deadline, assigned).await.map_err(|_| ConnectError::Deadline)??;
                let mappings = original.policy.max_streams.checked_mul(2).ok_or(ConnectError::Capacity)?;
                provider.bind_relay_limits(mappings, original.policy.max_credit, original.policy.live_maximum)?;
            } else {
                // This is only original-material dispatch. EndpointHop still
                // owns its first HELLO read and verifies relay possession before
                // Session admission. Install its signed envelope limit first.
                provider.bind_endpoint_limits(original.policy.max_streams, original.policy.max_credit, original.policy.live_maximum)?;
                match &provider {
                    direct_carrier::Provider::WebSocket(wss) => wss.assign_endpoint(original.account.clone(), prepaid)?,
                    direct_carrier::Provider::Native(native) => native.assign_endpoint(original.account.clone(), prepaid)?,
                }
            }
            Ok::<_, ConnectError>(first)
        }.await;
        match delivered {
            Ok(first_hello) => {
                let Some(route) = route else {
                    provider.close();
                    wait_relay_provider(&provider).await;
                    return;
                };
                let leg = AcceptedRelayLeg {
                    provider: provider.clone(),
                    incoming,
                    first_hello,
                    guard,
                };
                if let Err(returned) = route.reply.send(Ok(leg))
                    && let Ok(leg) = returned
                {
                    leg.provider.close();
                    wait_relay_provider(&leg.provider).await;
                }
            }
            Err(failure) => {
                provider.close();
                wait_relay_provider(&provider).await;
                if let Some(route) = route {
                    let _ = route.reply.send(Err(failure));
                }
                drop(guard);
            }
        }
    }
}
async fn wait_relay_provider(provider: &direct_carrier::Provider) {
    while !provider.cleanup().complete {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
impl Drop for SharedRelayListener {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
#[path = "reverse_tunnel_v4_cleanup_tests.rs"]
mod cleanup_tests;
