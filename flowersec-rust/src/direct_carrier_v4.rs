//! The current direct handshake chooses its fixed carrier from the signed route.
use super::*;
use crate::api_v4::CleanupStatus;
use tokio::sync::mpsc;
/// Tracks actual native preparation worker and failed-handle join custody.
/// This count is an observation barrier, never an authorization or refund.
pub(super) struct PreparationTail {
    counter: Arc<std::sync::atomic::AtomicUsize>,
    diagnostic: Option<crate::diagnostics_v4::DiagnosticPhysicalTail>,
    cleanup: Option<Arc<ConnectCleanup>>,
}
impl PreparationTail {
    pub(super) fn new(counter: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self {
            counter,
            diagnostic: None,
            cleanup: None,
        }
    }
    pub(super) fn with_diagnostic(
        counter: Arc<std::sync::atomic::AtomicUsize>,
        diagnostic: &Arc<crate::diagnostics_v4::DiagnosticActivity>,
    ) -> Self {
        let mut tail = Self::new(counter);
        tail.diagnostic = Some(diagnostic.retain_physical());
        tail
    }
    pub(super) fn with_cleanup(mut self, cleanup: Option<Arc<ConnectCleanup>>) -> Self {
        self.cleanup = cleanup;
        self
    }
    pub(super) fn cleanup_owner(&self) -> Option<Arc<ConnectCleanup>> {
        self.cleanup.clone()
    }
    pub(super) fn start_cleanup(&self) {
        if let Some(cleanup) = &self.cleanup {
            cleanup.start();
        }
    }
}
impl Drop for PreparationTail {
    fn drop(&mut self) {
        drop(self.diagnostic.take());
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
#[derive(Clone, Debug)]
pub(super) enum Provider {
    WebSocket(Arc<wss::Provider>),
    Native(Arc<native::Provider>),
}
impl Provider {
    pub(super) async fn prepare(
        account: ResourceAccount,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
    ) -> ConnectResult<(Self, mpsc::Receiver<Vec<u8>>)> {
        let diagnostic_root = account.environment_root().clone();
        let outcome = async {
            match policy.carrier {
                1 => {
                    let (provider, incoming) =
                        wss::Provider::prepare(account, policy, options, deadline, caller).await?;
                    Ok((Self::WebSocket(provider), incoming))
                }
                0 | 2 => {
                    let (provider, incoming) =
                        native::Provider::prepare(account, policy, options, deadline, caller)
                            .await?;
                    Ok((Self::Native(provider), incoming))
                }
                _ => Err(ConnectError::Configuration),
            }
        }
        .await;
        if matches!(&outcome, Err(ConnectError::Tls)) {
            diagnostic_root.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::TlsFailures);
        }
        outcome
    }
    #[cfg(test)]
    pub(super) async fn prepare_tracked_observed(
        account: ResourceAccount,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        pending: Arc<std::sync::atomic::AtomicUsize>,
        diagnostic: &Arc<crate::diagnostics_v4::DiagnosticActivity>,
    ) -> ConnectResult<(Self, mpsc::Receiver<Vec<u8>>)> {
        Self::prepare_with_tail(
            account,
            policy,
            options,
            deadline,
            caller,
            PreparationTail::with_diagnostic(pending, diagnostic),
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Carrier acceptance transfers distinct socket, cancellation, authorization and reserved cleanup owners."
    )]
    pub(super) async fn prepare_tracked_observed_with_cleanup(
        account: ResourceAccount,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        pending: Arc<std::sync::atomic::AtomicUsize>,
        diagnostic: &Arc<crate::diagnostics_v4::DiagnosticActivity>,
        cleanup: Option<Arc<ConnectCleanup>>,
    ) -> ConnectResult<(Self, mpsc::Receiver<Vec<u8>>)> {
        Self::prepare_with_tail(
            account,
            policy,
            options,
            deadline,
            caller,
            PreparationTail::with_diagnostic(pending, diagnostic).with_cleanup(cleanup),
        )
        .await
    }
    pub(super) async fn prepare_tracked(
        account: ResourceAccount,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        pending: Arc<std::sync::atomic::AtomicUsize>,
    ) -> ConnectResult<(Self, mpsc::Receiver<Vec<u8>>)> {
        Self::prepare_with_tail(
            account,
            policy,
            options,
            deadline,
            caller,
            PreparationTail::new(pending),
        )
        .await
    }
    async fn prepare_with_tail(
        account: ResourceAccount,
        policy: wss::Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        tail: PreparationTail,
    ) -> ConnectResult<(Self, mpsc::Receiver<Vec<u8>>)> {
        let diagnostic_root = account.environment_root().clone();
        let outcome = async {
            match policy.carrier {
                1 => {
                    let (provider, incoming) = wss::Provider::prepare_observed(
                        account, policy, options, deadline, caller, tail,
                    )
                    .await?;
                    Ok((Self::WebSocket(provider), incoming))
                }
                0 | 2 => {
                    let (provider, incoming) = native::Provider::prepare_observed(
                        account, policy, options, deadline, caller, tail,
                    )
                    .await?;
                    Ok((Self::Native(provider), incoming))
                }
                _ => Err(ConnectError::Configuration),
            }
        }
        .await;
        if matches!(&outcome, Err(ConnectError::Tls)) {
            diagnostic_root.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::TlsFailures);
        }
        outcome
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Carrier acceptance transfers distinct socket, cancellation, authorization and reserved cleanup owners."
    )]
    pub(super) async fn accept(
        root: Arc<EnvironmentRoot>,
        incoming: super::direct_listener::Incoming,
        policy: serve::SocketPolicy,
        deadline: Instant,
        caller: CancellationToken,
        charges: (EnvironmentCharge, EnvironmentCharge),
        retain: impl FnOnce(Self),
        authorize: impl FnOnce(serve::ServeRequestContext) -> wss::RequestAuthorizationFuture,
    ) -> ConnectResult<(Self, mpsc::Receiver<Vec<u8>>)> {
        Self::accept_with_charges(
            root,
            incoming,
            policy,
            deadline,
            caller,
            (charges.0.into(), charges.1.into()),
            retain,
            authorize,
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Carrier acceptance transfers distinct socket, cancellation, authorization and reserved cleanup owners."
    )]
    pub(super) async fn accept_with_charges(
        root: Arc<EnvironmentRoot>,
        incoming: super::direct_listener::Incoming,
        policy: serve::SocketPolicy,
        deadline: Instant,
        caller: CancellationToken,
        charges: (PreparationCharge, PreparationCharge),
        retain: impl FnOnce(Self),
        authorize: impl FnOnce(serve::ServeRequestContext) -> wss::RequestAuthorizationFuture,
    ) -> ConnectResult<(Self, mpsc::Receiver<Vec<u8>>)> {
        Self::accept_with_charges_observed(
            root, incoming, policy, deadline, caller, charges, None, retain, authorize,
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Carrier acceptance transfers distinct socket, cancellation, authorization and reserved cleanup owners."
    )]
    pub(super) async fn accept_with_charges_observed(
        root: Arc<EnvironmentRoot>,
        incoming: super::direct_listener::Incoming,
        policy: serve::SocketPolicy,
        deadline: Instant,
        caller: CancellationToken,
        charges: (PreparationCharge, PreparationCharge),
        preparation_tail: Option<PreparationTail>,
        retain: impl FnOnce(Self),
        authorize: impl FnOnce(serve::ServeRequestContext) -> wss::RequestAuthorizationFuture,
    ) -> ConnectResult<(Self, mpsc::Receiver<Vec<u8>>)> {
        let diagnostic_root = root.clone();
        let outcome = async {
            match incoming {
                super::direct_listener::Incoming::WebSocket(tcp) => {
                    let (provider, input) = wss::Provider::accept_observed(
                        root,
                        tcp,
                        policy,
                        deadline,
                        caller,
                        charges,
                        preparation_tail,
                        wss::AcceptHooks {
                            retain: |provider| retain(Self::WebSocket(provider)),
                            authorize,
                        },
                    )
                    .await?;
                    Ok((Self::WebSocket(provider), input))
                }
                super::direct_listener::Incoming::Native(native) => {
                    let (provider, input) = super::native::Provider::accept_observed(
                        root,
                        native,
                        policy,
                        deadline,
                        caller,
                        charges,
                        preparation_tail,
                        |provider| retain(Self::Native(provider)),
                        authorize,
                    )
                    .await?;
                    Ok((Self::Native(provider), input))
                }
            }
        }
        .await;
        if matches!(&outcome, Err(ConnectError::Tls)) {
            diagnostic_root.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::TlsFailures);
        }
        outcome
    }
    pub(super) fn fund_application(
        &self,
        account: &ResourceAccount,
        maximum: usize,
        profile: u8,
        charge: Option<ResourceCharge>,
    ) -> ConnectResult<()> {
        match self {
            Self::Native(provider) => {
                let charge = match charge {
                    Some(charge) => charge,
                    None => account.reserve(native::Provider::application_preparation_limits(
                        maximum, profile,
                    )?)?,
                };
                provider.fund_application(account, maximum, profile, charge)
            }
            // A mixed candidate acquisition may prepay the native maximum.
            // Selecting its original WSS candidate releases that unused part.
            Self::WebSocket(_) => {
                drop(charge);
                Ok(())
            }
        }
    }
    pub(super) fn attach(&self, account: ResourceAccount) -> ConnectResult<()> {
        match self {
            Self::WebSocket(p) => p.attach(account),
            Self::Native(p) => p.attach(account),
        }
    }
    pub(super) fn bind_contract(&self, artifact: Value<'_>) -> ConnectResult<()> {
        let contract = artifact.field("Artifact", "session_contract")?;
        let maximum = contract.u("SessionContract", "max_frame")? as usize + 8;
        match self {
            Self::WebSocket(p) => p.bind_frame_limit(maximum),
            Self::Native(p) => p.bind_contract(
                contract.u("SessionContract", "max_streams")? as usize,
                contract.u("SessionContract", "max_credit")?,
                maximum,
            ),
        }
    }
    pub(super) fn bind_endpoint_limits(
        &self,
        streams: usize,
        credit: u64,
        maximum: usize,
    ) -> ConnectResult<()> {
        match self {
            Self::WebSocket(provider) => provider.bind_frame_limit(maximum),
            Self::Native(provider) => provider.bind_contract(streams, credit, maximum),
        }
    }
    pub(super) fn bind_relay_limits(
        &self,
        streams: usize,
        _credit: u64,
        maximum: usize,
    ) -> ConnectResult<()> {
        match self {
            Self::WebSocket(provider) => provider.bind_frame_limit(maximum),
            Self::Native(provider) => provider.bind_relay_limits(streams, maximum),
        }
    }
    pub(super) fn feature_mask(&self) -> u64 {
        match self {
            Self::WebSocket(_) => 2,
            Self::Native(provider) => {
                if provider
                    .datagram_maximum()
                    .is_some_and(|maximum| maximum > 75)
                {
                    3
                } else {
                    2
                }
            }
        }
    }
    pub(super) fn feature_mask_for(&self, artifact: Value<'_>) -> ConnectResult<u64> {
        self.feature_mask_for_candidate(artifact, 0)
    }
    pub(super) fn feature_mask_for_candidate(
        &self,
        artifact: Value<'_>,
        index: u8,
    ) -> ConnectResult<u64> {
        let candidate = artifact
            .field("Artifact", "candidates")?
            .at(index as usize)?;
        let mut mask = self.feature_mask();
        if candidate.u("Candidate", "path_kind")? == 1 {
            for field in ["client_leg", "server_leg"] {
                if candidate.field("Candidate", field)?.u("Leg", "carrier")? == 1 {
                    mask &= !1;
                }
            }
        }
        Ok(mask)
    }
    pub(super) fn check(&self) -> ConnectResult<()> {
        match self {
            Self::WebSocket(p) => p.check(),
            Self::Native(p) => p.check(),
        }
    }
    pub(super) fn close(&self) {
        match self {
            Self::WebSocket(p) => p.close(),
            Self::Native(p) => p.close(),
        }
    }
    pub(super) fn identity(&self) -> [u8; 16] {
        match self {
            Self::WebSocket(p) => p.identity(),
            Self::Native(p) => p.identity(),
        }
    }
    pub(super) fn cancellation(&self) -> CancellationToken {
        match self {
            Self::WebSocket(p) => p.cancellation(),
            Self::Native(p) => p.cancellation(),
        }
    }
    pub(super) fn binding(
        &self,
        mode: BindingMode,
        artifact: [u8; 32],
    ) -> ConnectResult<Option<Zeroizing<[u8; 32]>>> {
        match self {
            Self::WebSocket(p) => p.binding(mode, artifact),
            Self::Native(p) => p.binding(mode, artifact),
        }
    }
    pub(super) async fn receive_prepared(
        &self,
        incoming: &mut mpsc::Receiver<Vec<u8>>,
    ) -> ConnectResult<Vec<u8>> {
        match incoming.recv().await {
            Some(wire) => {
                self.check()?;
                Ok(wire)
            }
            None => Err(self.check().err().unwrap_or(ConnectError::Carrier)),
        }
    }
    pub(super) async fn send(&self, wire: Vec<u8>) -> ConnectResult<()> {
        match self {
            Self::WebSocket(p) => p.send(wire).await,
            Self::Native(p) => p.send(wire).await,
        }
    }
    pub(super) fn receive_maintenance(
        &self,
        receiver: &SessionReceiver,
        wire: &[u8],
    ) -> std::result::Result<(), crate::transport::SessionError> {
        if matches!(self, Self::Native(_))
            && (wire.len() < 44 || !matches!(wire[4], 6 | 9 | 11..=15) || wire[12..20] != [0; 8])
        {
            receiver.close_input(crate::transport::SessionError::OperationFailed);
            return Err(crate::transport::SessionError::OperationFailed);
        }
        receiver.receive(wire)
    }
    pub(super) fn bind_receiver(&self, receiver: SessionReceiver) -> ConnectResult<()> {
        match self {
            Self::WebSocket(_) => Ok(()),
            Self::Native(p) => p.bind_receiver(receiver),
        }
    }
    pub(super) fn complete_preparation(&self) -> ConnectResult<()> {
        match self {
            Self::WebSocket(provider) => provider.complete_preparation(),
            Self::Native(provider) => provider.complete_preparation(),
        }
    }
    pub(super) fn activate(&self) {
        match self {
            Self::WebSocket(p) => p.activate(),
            Self::Native(p) => p.activate(),
        }
    }
    pub(super) fn transport(
        &self,
        keys: IdentityKeys,
        namespaces: Vec<Arc<Namespace>>,
    ) -> Box<dyn SessionTransport> {
        match self {
            Self::WebSocket(p) => Box::new(wss::Transport::new(p.clone(), keys, namespaces)),
            Self::Native(p) => Box::new(native::Transport::new(p.clone(), keys, namespaces)),
        }
    }
    pub(super) fn receiver(&self) -> ConnectResult<ReceiverGuard> {
        match self {
            Self::WebSocket(p) => Ok(ReceiverGuard::WebSocket {
                _guard: p.receiver()?,
            }),
            Self::Native(p) => Ok(ReceiverGuard::Native {
                _guard: p.receiver()?,
            }),
        }
    }
    pub(super) fn cleanup(&self) -> CleanupStatus {
        match self {
            Self::WebSocket(p) => p.cleanup(),
            Self::Native(p) => p.cleanup(),
        }
    }
    pub(super) fn retain_connect_diagnostic(
        &self,
        diagnostic: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    ) {
        match self {
            Self::WebSocket(provider) => provider.retain_connect_diagnostic(diagnostic),
            Self::Native(provider) => provider.retain_connect_diagnostic(diagnostic),
        }
    }
    pub(super) fn retain_listener_cleanup(
        &self,
        done: Arc<std::sync::atomic::AtomicBool>,
    ) -> ConnectResult<()> {
        match self {
            Self::WebSocket(_) => Err(ConnectError::Configuration),
            Self::Native(p) => p.retain_listener_cleanup(done),
        }
    }
}
pub(super) enum ReceiverGuard {
    WebSocket { _guard: wss::ReceiverGuard },
    Native { _guard: native::ReceiverGuard },
}
pub(super) struct Guard(pub(super) Option<Provider>);
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take() {
            provider.close();
        }
    }
}
