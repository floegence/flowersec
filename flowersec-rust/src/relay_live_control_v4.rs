//! Staged live relay control installed independently of endpoint credentials.
//! Each deployment is one original, bounded public TxA projection. Only its
//! fixed mTLS owners can complete preparation and deliver their actual Grants.
use super::super::{
    relay_publication::{
        LiveRelayLegPublicationInput, OriginalLiveRelayLegPublication, capture_remote_live_leg,
        pair_remote_live_legs,
    },
    wss_relay_host::OriginalRelayPreparation,
};
use super::*;
use crate::namespace_v4::verifier::credential::{relay_public, tunnel::TunnelLimits};

pub(super) const READY: &str = "/tunnel/relay-ready";
pub(super) const PREPARE: &str = "/tunnel/relay-prepare";
pub(super) const SERVER: &str = "/tunnel/relay-server-grant";
pub(super) const CLIENT: &str = "/tunnel/relay-activate-client";

/// Trusted local geometry prepaid before any native dial. The actual signed
/// Grants must match this geometry; a control request cannot enlarge it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLivePreparationLimits {
    pub max_envelope_bytes: u64,
    pub max_total_bytes: u64,
    pub max_datagram_bytes: u64,
    pub max_rate_bytes_per_s: u64,
    pub max_queue_bytes: u64,
    pub max_queue_items: u64,
    pub max_pending_native_mappings: u64,
    pub max_resident_native_mappings: u64,
    pub max_total_native_mappings: u64,
}
impl RelayLivePreparationLimits {
    fn limits(self) -> TunnelLimits {
        TunnelLimits {
            max_envelope_bytes: self.max_envelope_bytes,
            max_total_bytes: self.max_total_bytes,
            max_datagram_bytes: self.max_datagram_bytes,
            max_rate_bytes_per_s: self.max_rate_bytes_per_s,
            max_queue_bytes: self.max_queue_bytes,
            max_queue_items: self.max_queue_items,
            max_pending_native_mappings: self.max_pending_native_mappings,
            max_resident_native_mappings: self.max_resident_native_mappings,
            max_total_native_mappings: self.max_total_native_mappings,
        }
    }
}
/// One public issuance projection installed by the trusted deployment owner.
/// It contains no Artifact, PSK, session nonce, client activation permit or
/// bearer publication handle. A terminal projection cannot be reinstalled in
/// this receiver, and every control leg is a single original submission.
pub struct RelayLiveControlDeployment {
    pub issuer_leaf_digest: [u8; 32],
    pub client_leaf_digest: [u8; 32],
    pub server_leaf_digest: [u8; 32],
    pub artifact_digest: [u8; 32],
    pub lease_id: [u8; 16],
    pub initiation_not_after_ms: u64,
    pub session_not_after_ms: u64,
    pub candidate: Vec<u8>,
    pub session_contract: Vec<u8>,
    pub client_certificate: Vec<u8>,
    pub server_certificate: Vec<u8>,
    pub relay_certificate: Vec<u8>,
    pub limits: RelayLivePreparationLimits,
}
impl fmt::Debug for RelayLiveControlDeployment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayLiveControlDeployment { <public original projection> }")
    }
}
struct PreparedControl {
    preparation: OriginalRelayPreparation,
    preparation_ack: bool,
    server: Option<OriginalLiveRelayLegPublication>,
    server_ack: bool,
}
#[expect(
    clippy::large_enum_variant,
    reason = "The preallocated control slot changes phase without allocating during publication or retirement."
)]
enum Phase {
    Dormant,
    Preparing,
    Prepared(PreparedControl),
    Published {
        publication: Arc<WssRelayPublication>,
        accounts: [ResourceAccount; 2],
        initiation_end: u64,
        started: bool,
    },
    Retiring(OriginalRelayPreparation),
    Joining,
    Done,
}
struct State {
    ready: [bool; 2],
    ready_pending: [bool; 2],
    request: Option<Vec<u8>>,
    request_cutoff: Option<u64>,
    phase: Phase,
    failed: bool,
    published: bool,
    progress: (bool, bool, bool),
    result: Option<ConnectResult<()>>,
}
struct Installed {
    deployment: RelayLiveControlDeployment,
    issuer: RelayOriginalIssuer,
    candidate: [u8; 16],
    route: [u8; 32],
    cancellation: CancellationToken,
    state: Mutex<State>,
}
pub(super) struct LiveControl {
    root: Arc<EnvironmentRoot>,
    host: Arc<WssRelayHost>,
    installed: Vec<Installed>,
    cancellation: CancellationToken,
    changed: Notify,
    _charge: EnvironmentCharge,
}
#[derive(Clone, Copy)]
enum AckStage {
    Ready(usize),
    Prepare,
    Server,
    Client,
}
pub(super) struct Acknowledgement {
    control: Arc<LiveControl>,
    index: usize,
    stage: AckStage,
    confirmed: bool,
}
impl Drop for Acknowledgement {
    fn drop(&mut self) {
        if !self.confirmed {
            self.control.retire(self.index);
        }
    }
}
impl Acknowledgement {
    pub(super) fn written(mut self) -> ConnectResult<()> {
        self.control.check(self.index)?;
        let installed = &self.control.installed[self.index];
        let mut state = installed.state.lock().expect("original relay control ACK");
        if state.failed
            || state.request_cutoff.is_some_and(|cutoff| {
                !self
                    .control
                    .root
                    .sample()
                    .is_ok_and(|now| now.upper_ms < cutoff)
            })
        {
            return Err(ConnectError::Canceled);
        }
        match &state.phase {
            Phase::Prepared(prepared) => {
                prepared.preparation.check()?;
                self.control.host.check_live_listener_preparation()?;
                if let Some(server) = &prepared.server {
                    server.check()?;
                }
            }
            Phase::Published {
                accounts,
                initiation_end,
                ..
            } => {
                if self.control.root.sample()?.upper_ms >= *initiation_end {
                    return Err(ConnectError::Authorization);
                }
                for account in accounts {
                    account.check()?;
                }
            }
            _ => {}
        }
        match self.stage {
            AckStage::Ready(role) if state.ready_pending[role] => {
                state.ready_pending[role] = false;
                state.ready[role] = true;
            }
            AckStage::Prepare => match &mut state.phase {
                Phase::Prepared(prepared) if !prepared.preparation_ack => {
                    prepared.preparation_ack = true
                }
                _ => return Err(ConnectError::Authorization),
            },
            AckStage::Server => match &mut state.phase {
                Phase::Prepared(prepared) if prepared.server.is_some() && !prepared.server_ack => {
                    prepared.server_ack = true
                }
                _ => return Err(ConnectError::Authorization),
            },
            AckStage::Client => match &mut state.phase {
                Phase::Published {
                    publication,
                    started,
                    ..
                } if !*started => {
                    publication.start()?;
                    *started = true;
                }
                _ => return Err(ConnectError::Authorization),
            },
            _ => return Err(ConnectError::Authorization),
        }
        self.confirmed = true;
        drop(state);
        self.control.changed.notify_waiters();
        if let AckStage::Ready(_) = self.stage
            && let Err(failure) = self.control.start_when_ready(self.index)
        {
            self.control.retire(self.index);
            return Err(failure);
        }
        Ok(())
    }
}
struct OriginalInvocation {
    control: Arc<LiveControl>,
    index: usize,
    handed_off: bool,
}
impl Drop for OriginalInvocation {
    fn drop(&mut self) {
        if !self.handed_off {
            self.control.retire(self.index);
        }
    }
}
impl LiveControl {
    pub(super) fn new(
        root: Arc<EnvironmentRoot>,
        host: Arc<WssRelayHost>,
        options: &RelayOriginalDeliveryOptions,
        deployments: Vec<RelayLiveControlDeployment>,
        cancellation: CancellationToken,
    ) -> ConnectResult<Option<Arc<Self>>> {
        if deployments.is_empty() {
            return Ok(None);
        }
        if deployments.len() > options.maximum_publications
            || deployments.capacity() > options.maximum_publications
        {
            return Err(ConnectError::Configuration);
        }
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: deployments.len() as u64 * 262144,
            items: deployments.len() as u64 * 16,
            tasks: deployments.len() as u64 * 2,
            work_slots: deployments.len() as u64 * 2,
            timers: deployments.len() as u64,
            ..ResourceLimits::default()
        })?;
        let mut installed = Vec::with_capacity(deployments.len());
        for deployment in deployments {
            let issuer = options
                .issuers
                .iter()
                .find(|issuer| issuer.leaf_digest == deployment.issuer_leaf_digest)
                .ok_or(ConnectError::Configuration)?
                .clone();
            if [
                deployment.issuer_leaf_digest,
                deployment.client_leaf_digest,
                deployment.server_leaf_digest,
                deployment.artifact_digest,
            ]
            .contains(&[0; 32])
                || deployment.issuer_leaf_digest == deployment.client_leaf_digest
                || deployment.issuer_leaf_digest == deployment.server_leaf_digest
                || deployment.client_leaf_digest == deployment.server_leaf_digest
                || deployment.lease_id == [0; 16]
                || deployment.initiation_not_after_ms == 0
                || deployment.initiation_not_after_ms > deployment.session_not_after_ms
                || root.sample()?.upper_ms >= deployment.initiation_not_after_ms
                || [
                    &deployment.client_certificate,
                    &deployment.server_certificate,
                    &deployment.relay_certificate,
                ]
                .iter()
                .any(|wire| wire.is_empty() || wire.len() > 8192 || wire.capacity() > 8192)
                || [&deployment.candidate, &deployment.session_contract]
                    .iter()
                    .any(|wire| wire.is_empty() || wire.len() > 65536 || wire.capacity() > 65536)
                || installed.iter().any(|old: &Installed| {
                    old.deployment.artifact_digest == deployment.artifact_digest
                })
            {
                return Err(ConnectError::Configuration);
            }
            let candidate = decode(
                &deployment.candidate,
                "Candidate",
                65536,
                Context::default(),
            )?;
            if candidate.u("Candidate", "path_kind")? != 1 {
                return Err(ConnectError::Configuration);
            }
            decode(
                &deployment.session_contract,
                "SessionContract",
                65536,
                Context::default(),
            )?;
            let candidate_id = candidate.b("Candidate", "candidate_id")?;
            let route = relay_public::preparation_route_digest(&deployment.candidate)?;
            // Start the independently configured ingress before endpoint native
            // Prepare. This exposes no Grant route, HOP or forwarding permit.
            for role in 0..2 {
                if host.live_leg_is_listener(role)? {
                    let leg = candidate.field(
                        "Candidate",
                        if role == 0 {
                            "client_leg"
                        } else {
                            "server_leg"
                        },
                    )?;
                    if leg.u("Leg", "listener_role")? != 2 {
                        return Err(ConnectError::Configuration);
                    }
                    let carrier = match leg.u("Leg", "carrier")? {
                        0 => crate::LiveAuthorityCarrier::RawQuic,
                        1 => crate::LiveAuthorityCarrier::WebSocket,
                        2 => crate::LiveAuthorityCarrier::WebTransport,
                        _ => return Err(ConnectError::Configuration),
                    };
                    host.prepare_live_listener(
                        role as u8,
                        carrier,
                        leg.field("Leg", "host")?.text()?.to_owned(),
                    )?;
                }
            }
            installed.push(Installed {
                deployment,
                issuer,
                candidate: candidate_id,
                route,
                cancellation: cancellation.child_token(),
                state: Mutex::new(State {
                    ready: [false; 2],
                    ready_pending: [false; 2],
                    request: None,
                    request_cutoff: None,
                    phase: Phase::Dormant,
                    failed: false,
                    published: false,
                    progress: (false, false, false),
                    result: None,
                }),
            });
        }
        Ok(Some(Arc::new(Self {
            root,
            host,
            installed,
            cancellation,
            changed: Notify::new(),
            _charge: charge,
        })))
    }
    pub(super) fn forwarding_progress(&self) -> ConnectResult<RelayLiveForwardingProgress> {
        let mut progress = RelayLiveForwardingProgress {
            installed: self.installed.len() as u64,
            ..Default::default()
        };
        for installed in &self.installed {
            let state = installed
                .state
                .lock()
                .expect("original live relay forwarding observation");
            let milestones = match &state.phase {
                Phase::Published { publication, .. } => publication.forwarding_progress()?,
                _ => state.progress,
            };
            progress.published += u64::from(state.published);
            progress.paired += u64::from(milestones.0);
            progress.ready_forwarded += u64::from(milestones.1);
            progress.datagram_forwarded += u64::from(milestones.2);
            progress.completed += u64::from(matches!(state.phase, Phase::Done));
            progress.failed +=
                u64::from(state.failed || state.result.is_some_and(|result| result.is_err()));
        }
        Ok(progress)
    }
    pub(super) fn accepts_peer(&self, peer: [u8; 32]) -> bool {
        self.installed.iter().any(|installed| {
            [
                installed.deployment.issuer_leaf_digest,
                installed.deployment.client_leaf_digest,
                installed.deployment.server_leaf_digest,
            ]
            .contains(&peer)
        })
    }
    fn check(&self, index: usize) -> ConnectResult<()> {
        if self.cancellation.is_cancelled()
            || self.root.is_closed()
            || self.host.original_delivery_closed()
        {
            return Err(ConnectError::Canceled);
        }
        if self.root.sample()?.upper_ms >= self.installed[index].deployment.initiation_not_after_ms
        {
            return Err(ConnectError::Authorization);
        }
        Ok(())
    }
    fn retire(&self, index: usize) {
        self.installed[index].cancellation.cancel();
        let mut state = self.installed[index]
            .state
            .lock()
            .expect("original live relay retirement");
        // Closing an observation handle cannot rewrite a physically completed
        // original result. Capture a completed publication before retiring its
        // watcher, including a completion racing this close operation.
        if matches!(state.phase, Phase::Done) {
            return;
        }
        let completed = match &state.phase {
            Phase::Published { publication, .. } => publication
                .original_result()
                .map(|result| (result, publication.forwarding_progress())),
            _ => None,
        };
        if let Some((result, milestones)) = completed {
            match milestones {
                Ok(progress) => {
                    state.progress = progress;
                    state.result = Some(result);
                }
                Err(failure) => {
                    state.failed = true;
                    state.result = Some(Err(failure));
                }
            }
            state.phase = Phase::Done;
            drop(state);
            self.changed.notify_waiters();
            return;
        }
        state.failed = true;
        let phase = std::mem::replace(&mut state.phase, Phase::Done);
        state.phase = match phase {
            Phase::Prepared(prepared) => {
                prepared.preparation.close();
                Phase::Retiring(prepared.preparation)
            }
            Phase::Published {
                publication,
                accounts,
                initiation_end,
                started,
            } => {
                publication.close();
                Phase::Published {
                    publication,
                    accounts,
                    initiation_end,
                    started,
                }
            }
            Phase::Retiring(preparation) => Phase::Retiring(preparation),
            Phase::Preparing => Phase::Preparing,
            Phase::Joining => Phase::Joining,
            _ => Phase::Done,
        };
        drop(state);
        self.changed.notify_waiters();
    }
    pub(super) fn close(&self) {
        self.cancellation.cancel();
        for index in 0..self.installed.len() {
            self.retire(index);
        }
    }
    pub(super) fn start_workers(self: &Arc<Self>, owner: &Arc<Owner>) {
        for index in 0..self.installed.len() {
            owner.workers.fetch_add(1, Ordering::AcqRel);
            let control = self.clone();
            let owner = owner.clone();
            tokio::spawn(async move {
                let _worker = Worker(owner);
                control.watch_original(index).await;
            });
            if self.start_when_ready(index).is_err() {
                self.retire(index);
            }
        }
    }
    async fn watch_original(self: &Arc<Self>, index: usize) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let (preparing, cutoff, physical_failure) = {
                let state = self.installed[index]
                    .state
                    .lock()
                    .expect("original live relay watcher");
                let preparing = matches!(
                    state.phase,
                    Phase::Dormant
                        | Phase::Preparing
                        | Phase::Prepared(_)
                        | Phase::Published { started: false, .. }
                );
                let mut cutoff = state
                    .request_cutoff
                    .unwrap_or(self.installed[index].deployment.initiation_not_after_ms);
                if let Phase::Published { initiation_end, .. } = &state.phase {
                    cutoff = cutoff.min(*initiation_end);
                }
                let physical_failure = if let Phase::Prepared(prepared) = &state.phase {
                    prepared.preparation.check().is_err()
                        || self.host.check_live_listener_preparation().is_err()
                } else {
                    false
                };
                (preparing, cutoff, physical_failure)
            };
            if preparing
                && (physical_failure
                    || self.check(index).is_err()
                    || !self.root.sample().is_ok_and(|now| now.upper_ms < cutoff))
            {
                self.retire(index);
            }
            let retired = {
                let mut state = self.installed[index]
                    .state
                    .lock()
                    .expect("original live relay cleanup custody");
                if matches!(state.phase, Phase::Retiring(_)) {
                    match std::mem::replace(&mut state.phase, Phase::Joining) {
                        Phase::Retiring(preparation) => Some(preparation),
                        _ => None,
                    }
                } else {
                    if let Phase::Published { publication, .. } = &state.phase
                        && let Some(result) = publication.original_result()
                    {
                        let milestones = publication.forwarding_progress();
                        match milestones {
                            Ok(progress) => {
                                state.progress = progress;
                                state.result = Some(result);
                            }
                            Err(failure) => {
                                state.failed = true;
                                state.result = Some(Err(failure));
                            }
                        }
                        state.phase = Phase::Done;
                        self.changed.notify_waiters();
                    }
                    if matches!(state.phase, Phase::Done) {
                        return;
                    }
                    None
                }
            };
            if let Some(preparation) = retired {
                preparation.wait_cleanup().await;
                self.installed[index]
                    .state
                    .lock()
                    .expect("original live relay cleanup exit")
                    .phase = Phase::Done;
                self.changed.notify_waiters();
                return;
            }
            tokio::select! { _ = &mut changed => {}, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
        }
    }
    pub(super) async fn receive(
        self: &Arc<Self>,
        peer: [u8; 32],
        path: &str,
        wire: &[u8],
    ) -> ConnectResult<(Vec<u8>, Acknowledgement)> {
        let selected = self.select(peer, path, wire);
        let (index, fields) = match selected {
            Ok(selected) => selected,
            Err(failure) => {
                for (index, installed) in self.installed.iter().enumerate() {
                    if [
                        installed.deployment.issuer_leaf_digest,
                        installed.deployment.client_leaf_digest,
                        installed.deployment.server_leaf_digest,
                    ]
                    .contains(&peer)
                    {
                        self.retire(index);
                    }
                }
                return Err(failure);
            }
        };
        let mut invocation = OriginalInvocation {
            control: self.clone(),
            index,
            handed_off: false,
        };
        let result = self.receive_original(index, path, &fields).await;
        match result {
            Ok(stage) => {
                invocation.handed_off = true;
                Ok((
                    vec![0xf5],
                    Acknowledgement {
                        control: self.clone(),
                        index,
                        stage,
                        confirmed: false,
                    },
                ))
            }
            Err(failure) => {
                self.retire(index);
                Err(failure)
            }
        }
    }
    fn select<'a>(
        &self,
        peer: [u8; 32],
        path: &str,
        wire: &'a [u8],
    ) -> ConnectResult<(usize, Vec<&'a [u8]>)> {
        let (artifact, fields, role) = if path == READY {
            let value = codec::decode_control_array(
                wire,
                codec::Limits {
                    bytes: 1024,
                    nodes: 32,
                },
            )
            .map_err(|_| ConnectError::Configuration)?;
            if value.raw().first().map(|byte| byte >> 5) != Some(4)
                || value.len()? != 5
                || value.at(0)?.text()? != "tunnel-relay-ready-1"
                || value.at(4)?.uint()? > 1
            {
                return Err(ConnectError::Configuration);
            }
            let role = value.at(4)?.uint()? as usize;
            (
                value.at(1)?.bytes()?,
                vec![
                    value.at(2)?.bytes()?,
                    value.at(3)?.bytes()?,
                    value.at(4)?.raw(),
                ],
                role,
            )
        } else {
            let fields = match path {
                PREPARE => vec![wire],
                SERVER => decode_envelope(wire, b"tunnel-relay-server-grant-1", 3)?,
                CLIENT => decode_envelope(wire, b"tunnel-relay-activate-client-1", 3)?,
                _ => return Err(ConnectError::Configuration),
            };
            let request = codec::decode_control_array(
                fields[0],
                codec::Limits {
                    bytes: 1024,
                    nodes: 64,
                },
            )
            .map_err(|_| ConnectError::Configuration)?;
            if request.raw().first().map(|byte| byte >> 5) != Some(4)
                || request.len()? != 13
                || request.at(0)?.text()? != "live-authorization-1"
            {
                return Err(ConnectError::Configuration);
            }
            (
                request.at(7)?.bytes()?,
                fields,
                if path == SERVER { 2 } else { 0 },
            )
        };
        let index = self
            .installed
            .iter()
            .position(|installed| {
                let deployment = &installed.deployment;
                deployment.artifact_digest.as_slice() == artifact
                    && match role {
                        0 => deployment.client_leaf_digest == peer,
                        1 => deployment.server_leaf_digest == peer,
                        _ => deployment.issuer_leaf_digest == peer,
                    }
            })
            .ok_or(ConnectError::Authorization)?;
        Ok((index, fields))
    }
    async fn receive_original(
        self: &Arc<Self>,
        index: usize,
        path: &str,
        fields: &[&[u8]],
    ) -> ConnectResult<AckStage> {
        self.check(index)?;
        let installed = &self.installed[index];
        let deployment = &installed.deployment;
        if path == READY {
            if fields[0] != installed.candidate || fields[1] != installed.route {
                return Err(ConnectError::Authorization);
            }
            let role = if fields[2] == [0] {
                0
            } else if fields[2] == [1] {
                1
            } else {
                return Err(ConnectError::Configuration);
            };
            if self.host.live_leg_is_listener(role)? {
                return Err(ConnectError::Authorization);
            }
            let mut state = installed
                .state
                .lock()
                .expect("original live relay bind readiness");
            if state.failed
                || !matches!(state.phase, Phase::Dormant)
                || state.ready[role]
                || state.ready_pending[role]
            {
                return Err(ConnectError::Authorization);
            }
            state.ready_pending[role] = true;
            return Ok(AckStage::Ready(role));
        }
        if path == PREPARE {
            let cutoff = relay_public::match_live_preparation_request(
                fields[0],
                [
                    &deployment.client_certificate,
                    &deployment.server_certificate,
                ],
                &deployment.candidate,
                &installed.issuer.binding.tenant,
                installed.issuer.binding.parent_issuer,
                deployment.artifact_digest,
                deployment.lease_id,
                deployment.initiation_not_after_ms,
            )?;
            if self.root.sample()?.upper_ms >= cutoff {
                return Err(ConnectError::Authorization);
            }
            {
                let mut state = installed
                    .state
                    .lock()
                    .expect("original live relay request capture");
                if state.failed
                    || state.request.is_some()
                    || !matches!(
                        state.phase,
                        Phase::Dormant | Phase::Preparing | Phase::Prepared(_)
                    )
                {
                    return Err(ConnectError::Authorization);
                }
                state.request = Some(fields[0].to_vec());
                state.request_cutoff = Some(cutoff);
            }
            self.wait_prior_ack(index, path).await?;
            self.start_when_ready(index)?;
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                self.check(index)?;
                if self.root.sample()?.upper_ms >= cutoff {
                    return Err(ConnectError::Authorization);
                }
                {
                    let state = installed
                        .state
                        .lock()
                        .expect("original live relay Prepare observation");
                    if state.failed {
                        return Err(ConnectError::Canceled);
                    }
                    match &state.phase {
                        Phase::Prepared(prepared) => {
                            prepared.preparation.check()?;
                            self.host.check_live_listener_preparation()?;
                            return Ok(AckStage::Prepare);
                        }
                        Phase::Preparing => {}
                        _ => return Err(ConnectError::Authorization),
                    }
                }
                tokio::select! { _ = &mut changed => {}, _ = installed.cancellation.cancelled() => return Err(ConnectError::Canceled),
                _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
            }
        }
        self.wait_prior_ack(index, path).await?;
        let mut state = installed
            .state
            .lock()
            .expect("original live relay Grant handoff");
        if state.failed {
            return Err(ConnectError::Canceled);
        }
        if state.request.as_deref() != Some(fields[0])
            || state
                .request_cutoff
                .is_none_or(|cutoff| !self.root.sample().is_ok_and(|now| now.upper_ms < cutoff))
        {
            return Err(ConnectError::Authorization);
        }
        let Phase::Prepared(prepared) = &mut state.phase else {
            return Err(ConnectError::Authorization);
        };
        if !prepared.preparation_ack {
            return Err(ConnectError::Authorization);
        }
        prepared.preparation.check()?;
        self.host.check_live_listener_preparation()?;
        let role = if path == SERVER { 1 } else { 0 };
        if role == 1 && prepared.server.is_some()
            || role == 0 && (!prepared.server_ack || prepared.server.is_none())
        {
            return Err(ConnectError::Authorization);
        }
        let leg = capture_remote_live_leg(
            self.root.clone(),
            installed.issuer.namespaces.clone(),
            &installed.issuer.binding,
            self.host.original_delivery_ledger().parent_authority_id(),
            LiveRelayLegPublicationInput {
                request: fields[0],
                activation: fields[1],
                grant: fields[2],
                certificates: [
                    &deployment.client_certificate,
                    &deployment.server_certificate,
                ],
                relay_certificate: &deployment.relay_certificate,
                candidate: &deployment.candidate,
                contract: &deployment.session_contract,
                role,
                prepared_account: Some(&prepared.preparation.accounts[role as usize]),
            },
        )?;
        if leg.limits() != deployment.limits.limits() {
            return Err(ConnectError::Authorization);
        }
        if role == 1 {
            prepared.server = Some(leg);
            return Ok(AckStage::Server);
        }
        let phase = std::mem::replace(&mut state.phase, Phase::Joining);
        let Phase::Prepared(mut prepared) = phase else {
            return Err(ConnectError::Configuration);
        };
        let server = prepared.server.take().ok_or(ConnectError::Authorization)?;
        let publication = match pair_remote_live_legs(
            self.root.clone(),
            &installed.issuer.binding,
            leg,
            server,
        ) {
            Ok(publication) => publication,
            Err(failure) => {
                prepared.preparation.close();
                state.phase = Phase::Retiring(prepared.preparation);
                drop(state);
                self.changed.notify_waiters();
                return Err(failure);
            }
        };
        let accounts = prepared.preparation.accounts.clone();
        let initiation_end = publication.facts.initiation_end;
        let publication = match self
            .host
            .publish_prepared_live(publication, prepared.preparation)
        {
            Ok(publication) => Arc::new(publication),
            Err((failure, preparation)) => {
                preparation.close();
                state.phase = Phase::Retiring(preparation);
                drop(state);
                self.changed.notify_waiters();
                return Err(failure);
            }
        };
        state.published = true;
        state.phase = Phase::Published {
            publication,
            accounts,
            initiation_end,
            started: false,
        };
        drop(state);
        self.changed.notify_waiters();
        Ok(AckStage::Client)
    }
    async fn wait_prior_ack(&self, index: usize, path: &str) -> ConnectResult<()> {
        let installed = &self.installed[index];
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.check(index)?;
            let waiting = {
                let state = installed
                    .state
                    .lock()
                    .expect("original live relay prior ACK observation");
                if state.failed {
                    return Err(ConnectError::Canceled);
                }
                if path == PREPARE {
                    if !matches!(
                        state.phase,
                        Phase::Dormant | Phase::Preparing | Phase::Prepared(_)
                    ) {
                        return Err(ConnectError::Authorization);
                    }
                    let mut waiting = false;
                    for role in 0..2 {
                        if !self.host.live_leg_is_listener(role)? && !state.ready[role] {
                            if !state.ready_pending[role] {
                                return Err(ConnectError::Authorization);
                            }
                            waiting = true;
                        }
                    }
                    waiting
                } else {
                    let Phase::Prepared(prepared) = &state.phase else {
                        return Err(ConnectError::Authorization);
                    };
                    if path == SERVER {
                        !prepared.preparation_ack
                    } else if prepared.server.is_none() {
                        return Err(ConnectError::Authorization);
                    } else {
                        !prepared.server_ack
                    }
                }
            };
            if !waiting {
                return Ok(());
            }
            tokio::select! { _ = &mut changed => {}, _ = installed.cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
        }
    }
    fn start_when_ready(self: &Arc<Self>, index: usize) -> ConnectResult<()> {
        self.check(index)?;
        let installed = &self.installed[index];
        {
            let mut state = installed
                .state
                .lock()
                .expect("original live relay readiness start");
            if state.failed {
                return Err(ConnectError::Canceled);
            }
            if !matches!(state.phase, Phase::Dormant) {
                return Ok(());
            }
            for role in 0..2 {
                if !self.host.live_leg_is_listener(role)? && !state.ready[role] {
                    return Ok(());
                }
            }
            state.phase = Phase::Preparing;
        }
        let control = self.clone();
        // This worker and the original watcher retain custody until every
        // physical cancellation/join tail exits, even if HTTP is interrupted.
        tokio::spawn(async move {
            let preparation = control.prepare(index).await;
            let mut state = control.installed[index]
                .state
                .lock()
                .expect("original live relay Prepare capture");
            match preparation {
                Ok(preparation) if !state.failed && control.check(index).is_ok() => {
                    state.phase = Phase::Prepared(PreparedControl {
                        preparation,
                        preparation_ack: false,
                        server: None,
                        server_ack: false,
                    });
                }
                Ok(preparation) => {
                    preparation.close();
                    state.phase = Phase::Retiring(preparation);
                }
                Err(_) => {
                    state.failed = true;
                    state.phase = Phase::Done;
                }
            }
            drop(state);
            control.changed.notify_waiters();
        });
        Ok(())
    }
    async fn prepare(&self, index: usize) -> ConnectResult<OriginalRelayPreparation> {
        let installed = &self.installed[index];
        let deployment = &installed.deployment;
        let mut namespaces = installed.issuer.namespaces.clone();
        namespaces.sort_unstable_by_key(Arc::as_ptr);
        let accounts = {
            let guards: Vec<_> = namespaces
                .iter()
                .map(|namespace| {
                    namespace
                        .verifier
                        .lock()
                        .expect("live relay preparation namespace")
                })
                .collect();
            let verifiers: Vec<_> = guards.iter().map(|guard| &**guard).collect();
            relay_public::reserve_live_preparation(
                &self.root,
                &verifiers,
                [
                    &deployment.client_certificate,
                    &deployment.server_certificate,
                ],
                &installed.issuer.binding.tenant,
                deployment.initiation_not_after_ms,
                deployment.session_not_after_ms,
            )?
        };
        self.host
            .prepare_original_live(
                accounts,
                &deployment.candidate,
                deployment.artifact_digest,
                deployment.limits.limits(),
                installed.cancellation.clone(),
            )
            .await
    }
}
