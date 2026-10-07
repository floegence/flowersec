//! Original issuer-side public relay projection. Verification may inspect the
//! parent only at this boundary; the detached relay object contains no Artifact,
//! PSK, Noise secret, Session nonce or endpoint activation/admission handle.
use super::serve::live_source::remote::encode_envelope;
use super::*;
use crate::namespace_v4::verifier::credential::relay_public::{
    self, RelayPublicInput, RelayPublicLegAdmission, RelayPublicLegInput,
};
const PUBLIC_TAG: &[u8] = b"flowersec/rust-relay-pool-publication/2";
const LIVE_PUBLIC_TAG: &[u8] = b"flowersec/rust-relay-live-publication/1";
use crate::namespace_v4::verifier::credential::tunnel::{
    TunnelHopInput, VerifiedTunnelHop, reserve_tunnel_connection,
};
use crate::pool_v4::{
    parent::ParentWinnerSelection,
    relay::{RegisteredRelayParent, SQLiteRelayBinding, SQLiteRelayLedger, VerifiedRelayParent},
};

/// Consumed inside the trusted original pool issuance/control owner. These are
/// the exact original signed bytes, not a replay receipt or peer HELLO.
pub struct RelayPoolPublicationInput {
    pub connection: PoolCredentialBytes,
    pub grants: [Vec<u8>; 2],
    pub relay_certificate: Vec<u8>,
    pub candidate_index: u8,
    pub server_admission_authority: String,
    pub service: String,
    pub relay_audience: String,
}
impl fmt::Debug for RelayPoolPublicationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayPoolPublicationInput { <redacted> }")
    }
}
impl Drop for RelayPoolPublicationInput {
    fn drop(&mut self) {
        self.connection.artifact.zeroize();
    }
}
pub(super) struct RelayEndpoint {
    pub(super) hop: VerifiedTunnelHop,
    pub(super) grant: Vec<u8>,
    pub(super) certificate: Vec<u8>,
}
/// A non-cloneable detached original issuer publication. The SDK verified all
/// parent, activation, identity, route and namespace dependencies before this
/// value existed. Copying or looking up public rows cannot recreate it.
pub struct OriginalRelayPoolPublication {
    pub(super) source: codec::ActivationSource,
    pub(super) facts: VerifiedRelayParent,
    pub(super) endpoints: [RelayEndpoint; 2],
    relay_certificate: Vec<u8>,
    // Retain the original verification owners through publication and physical
    // forwarding. Dropping their last Arc terminates the admitted namespaces.
    _namespaces: [Vec<Arc<Namespace>>; 2],
    _charge: ResourceCharge,
}
impl fmt::Debug for OriginalRelayPoolPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalRelayPoolPublication { <opaque> }")
    }
}
pub struct RelayParentRegistration {
    pub(super) original: Arc<RegisteredRelayParent>,
    pub(super) endpoints: [RelayEndpoint; 2],
    pub(super) relay_certificate: Vec<u8>,
    pub(super) cancellation: CancellationToken,
    _namespaces: [Vec<Arc<Namespace>>; 2],
    _charge: ResourceCharge,
}
impl fmt::Debug for RelayParentRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayParentRegistration { <opaque> }")
    }
}
/// One original continuation for an independently installed issuer. Matching
/// public bytes cannot create it or select a winner; only the actual HOP claim
/// in this original relay's protected parent store supplies the winner fact.
#[derive(Debug)]
pub struct OriginalRelayPoolWinner {
    original: Arc<RegisteredRelayParent>,
    lease: Vec<u8>,
    projection: Vec<u8>,
    deadline: Instant,
    consumed: bool,
    _charge: ResourceCharge,
}
impl OriginalRelayPoolWinner {
    /// Consume the sole match position while retaining physical reply custody
    /// until the caller drops this owner after its control writer has exited.
    pub fn match_original(&mut self, lease: &[u8], projection: &[u8]) -> ConnectResult<()> {
        if std::mem::replace(&mut self.consumed, true) {
            return Err(ConnectError::Authorization);
        }
        if Instant::now() >= self.deadline || lease != self.lease || projection != self.projection {
            return Err(ConnectError::Authorization);
        }
        self.original.match_original_pool_winner()?;
        if Instant::now() >= self.deadline {
            return Err(ConnectError::Deadline);
        }
        Ok(())
    }
}
impl RelayParentRegistration {
    pub fn take_pool_winner_continuation(&mut self) -> ConnectResult<OriginalRelayPoolWinner> {
        let charge = self.original.account(0)?.reserve(ResourceLimits {
            sdk_bytes: 32768,
            items: 1,
            work_slots: 1,
            tasks: 1,
            ..ResourceLimits::default()
        })?;
        let (lease, projection, deadline) = self.original.take_pool_winner_control()?;
        Ok(OriginalRelayPoolWinner {
            original: self.original.clone(),
            lease,
            projection,
            deadline,
            consumed: false,
            _charge: charge,
        })
    }
    pub fn close(&self) {
        self.cancellation.cancel();
    }
}
impl Drop for RelayParentRegistration {
    fn drop(&mut self) {
        self.close();
    }
}
impl OriginalRelayPoolPublication {
    /// The independently installed ledger mapping and common parent authority
    /// are mandatory. Registration does not claim either physical leg and does
    /// not choose a pool winner; verified original HOP possession does that.
    pub fn register(
        self,
        ledger: Arc<SQLiteRelayLedger>,
        cancellation: CancellationToken,
    ) -> ConnectResult<RelayParentRegistration> {
        let Self {
            facts,
            endpoints,
            relay_certificate,
            _namespaces,
            _charge,
            source: _,
        } = self;
        let original = ledger.register_original(facts, cancellation.clone())?;
        Ok(RelayParentRegistration {
            original,
            endpoints,
            relay_certificate,
            cancellation,
            _namespaces,
            _charge,
        })
    }
}

pub(crate) fn capture_pool(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    input: RelayPoolPublicationInput,
) -> ConnectResult<OriginalRelayPoolPublication> {
    capture_original(
        root,
        namespaces,
        input,
        codec::ActivationSource::PreauthorizedPool,
        None,
    )
}

/// Called only by the trusted original live TxB continuation while it still
/// owns the confirmed result and its publication position. The winner mapping
/// is installed deployment policy; it cannot be inferred from a copied proof.
pub(crate) fn capture_live(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    input: RelayPoolPublicationInput,
    winner_authority: String,
) -> ConnectResult<OriginalRelayPoolPublication> {
    if winner_authority.is_empty()
        || winner_authority.len() > 128
        || winner_authority.capacity() > 256
        || !winner_authority.bytes().all(|byte| byte.is_ascii_graphic())
        || input.candidate_index != 0
    {
        return Err(ConnectError::Configuration);
    }
    capture_original(
        root,
        namespaces,
        input,
        codec::ActivationSource::LiveAuthority,
        Some(winner_authority),
    )
}

fn capture_original(
    root: Arc<EnvironmentRoot>,
    mut namespaces: Vec<Arc<Namespace>>,
    mut input: RelayPoolPublicationInput,
    source: codec::ActivationSource,
    live_winner_authority: Option<String>,
) -> ConnectResult<OriginalRelayPoolPublication> {
    if namespaces.is_empty()
        || namespaces.len() > 8
        || namespaces.capacity() > 8
        || input.server_admission_authority.is_empty()
        || input.server_admission_authority.len() > 128
        || input.service.is_empty()
        || input.service.len() > 128
        || input.relay_audience.is_empty()
        || input.relay_audience.len() > 128
        || input.connection.artifact.is_empty()
        || input.connection.artifact.capacity() > 65536
        || input.connection.activation.is_empty()
        || input.connection.activation.capacity() > 4096
        || [
            &input.connection.client_certificate,
            &input.connection.server_certificate,
            &input.relay_certificate,
        ]
        .iter()
        .any(|bytes| bytes.is_empty() || bytes.capacity() > 8192)
        || input
            .grants
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.capacity() > 9302)
        || namespaces.iter().enumerate().any(|(index, namespace)| {
            namespaces[..index]
                .iter()
                .any(|old| Arc::ptr_eq(old, namespace))
        })
    {
        return Err(ConnectError::Configuration);
    }
    namespaces.sort_unstable_by_key(Arc::as_ptr);
    let guards: Vec<_> = namespaces
        .iter()
        .map(|namespace| {
            namespace
                .verifier
                .lock()
                .expect("original relay issuance namespace")
        })
        .collect();
    let verifiers: Vec<_> = guards.iter().map(|guard| &**guard).collect();
    let verify = |role| {
        reserve_tunnel_connection(
            &root,
            &verifiers,
            DirectCredentialInput {
                artifact: &input.connection.artifact,
                client_certificate: &input.connection.client_certificate,
                server_certificate: &input.connection.server_certificate,
                activation: &input.connection.activation,
                source,
                candidate_index: input.candidate_index,
            },
            TunnelHopInput {
                grant: &input.grants[role as usize],
                relay_certificate: &input.relay_certificate,
                endpoint_role: role,
                service: &input.service,
                audience: &input.relay_audience,
            },
        )
    };
    let mut first = verify(0)?;
    let mut second = verify(1)?;
    drop(guards);
    let a = first.tunnel.take().ok_or(ConnectError::Configuration)?;
    let b = second.tunnel.take().ok_or(ConnectError::Configuration)?;
    if first.artifact_digest != second.artifact_digest
        || first.activation_digest != second.activation_digest
        || first.certificate_digests != second.certificate_digests
        || first.candidate_id != second.candidate_id
        || first.route_digest != second.route_digest
        || first.attempt_id != second.attempt_id
        || a.pairing_id != b.pairing_id
        || a.relay_identity_digest != b.relay_identity_digest
        || a.relay_key != b.relay_key
        || a.endpoint_role != 0
        || b.endpoint_role != 1
    {
        return Err(ConnectError::Authorization);
    }
    let charge = first.account.reserve(ResourceLimits {
        sdk_bytes: 262144,
        items: 8,
        work_slots: 2,
        ..ResourceLimits::default()
    })?;
    let artifact = decode(
        &input.connection.artifact,
        "Artifact",
        65536,
        Context::default(),
    )?;
    let tenant = artifact.field("Artifact", "tenant_id")?.text()?.to_owned();
    let issuer = artifact.b("Artifact", "issuer_key_id")?;
    let lease = artifact.b("Artifact", "lease_id")?;
    let parent_initiation_end = artifact.u("Artifact", "initiation_not_after_ms")?;
    let parent_session_end = artifact.u("Artifact", "session_not_after_ms")?;
    let audience = artifact.field("Artifact", "audience")?.text()?;
    let winner_authority = match source {
        codec::ActivationSource::PreauthorizedPool => first
            .pool
            .as_ref()
            .ok_or(ConnectError::Configuration)?
            .winner_authority
            .clone(),
        codec::ActivationSource::LiveAuthority => {
            live_winner_authority.ok_or(ConnectError::Configuration)?
        }
    };
    let winner_projection = ParentWinnerSelection {
        source: first.source,
        tenant: &tenant,
        authority: &winner_authority,
        server_authority: &input.server_admission_authority,
        audience,
        artifact: first.artifact_digest,
        activation: first.activation_digest,
        proof: &input.connection.activation,
        candidate: first.candidate_id,
        route: first.route_digest,
        attempt: first.attempt_id,
        identities: first.certificate_digests,
        parent_initiation_end,
        parent_session_end,
    }
    .encode(65536)?;
    let activation = decode(
        &input.connection.activation,
        "ActivationAuthorization",
        4096,
        Context::with_activation_source(source),
    )?;
    let set = match source {
        codec::ActivationSource::PreauthorizedPool => relay_public::pool_set(artifact, activation)?,
        codec::ActivationSource::LiveAuthority => Vec::new(),
    };
    let candidate = artifact
        .field("Artifact", "candidates")?
        .at(input.candidate_index as usize)?;
    let contract = artifact.field("Artifact", "session_contract")?;
    let public_record = encode_envelope(
        match source {
            codec::ActivationSource::PreauthorizedPool => PUBLIC_TAG,
            codec::ActivationSource::LiveAuthority => LIVE_PUBLIC_TAG,
        },
        &[
            &input.connection.activation,
            &input.grants[0],
            &input.grants[1],
            &input.connection.client_certificate,
            &input.connection.server_certificate,
            &input.relay_certificate,
            candidate.raw(),
            &set,
            contract.raw(),
            &[input.candidate_index],
        ],
    );
    if public_record.len() > 65536 || public_record.capacity() > 65536 {
        return Err(ConnectError::Capacity);
    }
    // Only public facts and exact signed public bytes cross this boundary.
    let relay_certificate = std::mem::take(&mut input.relay_certificate);
    let endpoints = [
        RelayEndpoint {
            hop: a,
            grant: std::mem::take(&mut input.grants[0]),
            certificate: std::mem::take(&mut input.connection.client_certificate),
        },
        RelayEndpoint {
            hop: b,
            grant: std::mem::take(&mut input.grants[1]),
            certificate: std::mem::take(&mut input.connection.server_certificate),
        },
    ];
    let facts = VerifiedRelayParent {
        binding: SQLiteRelayBinding {
            tenant,
            parent_issuer: issuer,
            server_admission_authority: std::mem::take(&mut input.server_admission_authority),
            service: std::mem::take(&mut input.service),
            relay_audience: std::mem::take(&mut input.relay_audience),
            relay_identity_digest: endpoints[0].hop.relay_identity_digest,
        },
        lease,
        candidate: first.candidate_id,
        attempt: first.attempt_id,
        public_record,
        winner_projection,
        winner_authority,
        accounts: [first.account, second.account],
        initiation_end: first
            .initiation_not_after_ms
            .min(second.initiation_not_after_ms),
        session_end: parent_session_end,
    };
    Ok(OriginalRelayPoolPublication {
        source,
        facts,
        endpoints,
        relay_certificate,
        _namespaces: [namespaces, Vec::new()],
        _charge: charge,
    })
}

/// Private original mTLS receiver boundary. The installed identity mapping and
/// ledger, rather than these public bytes, establish the caller's provenance.
pub(super) fn capture_remote_pool(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    binding: &SQLiteRelayBinding,
    wire: &[u8],
) -> ConnectResult<OriginalRelayPoolPublication> {
    capture_remote_original(
        root,
        namespaces,
        binding,
        wire,
        codec::ActivationSource::PreauthorizedPool,
        None,
    )
}
pub(super) fn capture_remote_live(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    binding: &SQLiteRelayBinding,
    wire: &[u8],
    winner_authority: &str,
) -> ConnectResult<OriginalRelayPoolPublication> {
    capture_remote_original(
        root,
        namespaces,
        binding,
        wire,
        codec::ActivationSource::LiveAuthority,
        Some(winner_authority),
    )
}
fn capture_remote_original(
    root: Arc<EnvironmentRoot>,
    mut namespaces: Vec<Arc<Namespace>>,
    binding: &SQLiteRelayBinding,
    wire: &[u8],
    source: codec::ActivationSource,
    live_winner_authority: Option<&str>,
) -> ConnectResult<OriginalRelayPoolPublication> {
    if wire.is_empty()
        || wire.len() > 65536
        || namespaces.is_empty()
        || namespaces.len() > 8
        || namespaces.capacity() > 8
        || namespaces.iter().enumerate().any(|(index, namespace)| {
            namespaces[..index]
                .iter()
                .any(|old| Arc::ptr_eq(old, namespace))
        })
    {
        return Err(ConnectError::Configuration);
    }
    let projection = codec::decode_control_array(
        wire,
        codec::Limits {
            bytes: 65536,
            nodes: 32,
        },
    )
    .map_err(|_| ConnectError::Configuration)?;
    let tag = match source {
        codec::ActivationSource::PreauthorizedPool => PUBLIC_TAG,
        codec::ActivationSource::LiveAuthority => LIVE_PUBLIC_TAG,
    };
    if projection.len()? != 11 || projection.at(0)?.text()?.as_bytes() != tag {
        return Err(ConnectError::Configuration);
    }
    let mut fields = Vec::with_capacity(10);
    for index in 0..10 {
        let field = projection.at(index + 1)?.bytes()?;
        if field.is_empty() && !(source == codec::ActivationSource::LiveAuthority && index == 7) {
            return Err(ConnectError::Configuration);
        }
        fields.push(field);
    }
    if fields[9].len() != 1 {
        return Err(ConnectError::Configuration);
    }
    namespaces.sort_unstable_by_key(Arc::as_ptr);
    let guards: Vec<_> = namespaces
        .iter()
        .map(|namespace| {
            namespace
                .verifier
                .lock()
                .expect("original remote relay namespace")
        })
        .collect();
    let verifiers: Vec<_> = guards.iter().map(|guard| &**guard).collect();
    let admission = relay_public::reserve_original_publication(
        &root,
        &verifiers,
        RelayPublicInput {
            source,
            live_winner_authority,
            activation: fields[0],
            grants: [fields[1], fields[2]],
            certificates: [fields[3], fields[4]],
            relay_certificate: fields[5],
            candidate: fields[6],
            selection_set: fields[7],
            contract: fields[8],
            candidate_index: fields[9][0],
            service: &binding.service,
            relay_audience: &binding.relay_audience,
        },
    )?;
    drop(guards);
    if admission.tenant != binding.tenant
        || admission.issuer != binding.parent_issuer
        || admission.hops[0].relay_identity_digest != binding.relay_identity_digest
    {
        return Err(ConnectError::Authorization);
    }
    let charge = admission.accounts[0].reserve(ResourceLimits {
        sdk_bytes: 262144,
        items: 8,
        work_slots: 2,
        ..ResourceLimits::default()
    })?;
    let winner_projection = ParentWinnerSelection {
        source,
        tenant: &admission.tenant,
        authority: &admission.winner_authority,
        server_authority: &binding.server_admission_authority,
        audience: &admission.audience,
        artifact: admission.artifact,
        activation: admission.activation,
        proof: fields[0],
        candidate: admission.candidate,
        route: admission.route,
        attempt: admission.attempt,
        identities: admission.identities,
        parent_initiation_end: admission.parent_initiation,
        parent_session_end: admission.parent_end,
    }
    .encode(65536)?;
    let [a, b] = admission.hops;
    let endpoints = [
        RelayEndpoint {
            hop: a,
            grant: fields[1].to_vec(),
            certificate: fields[3].to_vec(),
        },
        RelayEndpoint {
            hop: b,
            grant: fields[2].to_vec(),
            certificate: fields[4].to_vec(),
        },
    ];
    let facts = VerifiedRelayParent {
        binding: binding.clone(),
        lease: admission.lease,
        candidate: admission.candidate,
        attempt: admission.attempt,
        public_record: wire.to_vec(),
        winner_projection,
        winner_authority: admission.winner_authority,
        accounts: admission.accounts,
        initiation_end: admission.initiation,
        session_end: admission.parent_end,
    };
    Ok(OriginalRelayPoolPublication {
        source,
        facts,
        endpoints,
        relay_certificate: fields[5].to_vec(),
        _namespaces: [namespaces, Vec::new()],
        _charge: charge,
    })
}

/// Inputs come only from the authenticated original live control handler. Its
/// installed public candidate, contract and identity configuration stay fixed
/// while the two original TxB deliveries arrive separately.
pub(super) struct LiveRelayLegPublicationInput<'a> {
    pub(super) request: &'a [u8],
    pub(super) activation: &'a [u8],
    pub(super) grant: &'a [u8],
    pub(super) certificates: [&'a [u8]; 2],
    pub(super) relay_certificate: &'a [u8],
    pub(super) candidate: &'a [u8],
    pub(super) contract: &'a [u8],
    pub(super) role: u8,
    pub(super) prepared_account: Option<&'a ResourceAccount>,
}
/// One exact verified leg retained by the original live handler. This is not
/// an endpoint activation owner and exposes no lookup, adoption or retry API.
pub(super) struct OriginalLiveRelayLegPublication {
    admission: RelayPublicLegAdmission,
    request: Vec<u8>,
    activation: Vec<u8>,
    grant: Vec<u8>,
    certificates: [Vec<u8>; 2],
    relay_certificate: Vec<u8>,
    candidate: Vec<u8>,
    contract: Vec<u8>,
    namespaces: Vec<Arc<Namespace>>,
    _charge: ResourceCharge,
}
impl fmt::Debug for OriginalLiveRelayLegPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalLiveRelayLegPublication { <opaque> }")
    }
}
impl OriginalLiveRelayLegPublication {
    pub(super) fn check(&self) -> ConnectResult<()> {
        if self.admission.account.security_time()?.upper_ms >= self.admission.initiation {
            return Err(ConnectError::Authorization);
        }
        self.admission.account.check().map_err(Into::into)
    }
    pub(super) fn limits(&self) -> crate::namespace_v4::verifier::credential::tunnel::TunnelLimits {
        self.admission.hop.limits
    }
}
pub(super) fn capture_remote_live_leg(
    root: Arc<EnvironmentRoot>,
    mut namespaces: Vec<Arc<Namespace>>,
    binding: &SQLiteRelayBinding,
    winner_authority: &str,
    input: LiveRelayLegPublicationInput<'_>,
) -> ConnectResult<OriginalLiveRelayLegPublication> {
    if input.role > 1
        || input.request.is_empty()
        || input.request.len() > 1024
        || input.activation.is_empty()
        || input.activation.len() > 4096
        || input.grant.is_empty()
        || input.grant.len() > 9302
        || input
            .certificates
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.len() > 8192)
        || input.relay_certificate.is_empty()
        || input.relay_certificate.len() > 8192
        || input.candidate.is_empty()
        || input.candidate.len() > 65536
        || input.contract.is_empty()
        || input.contract.len() > 65536
        || namespaces.is_empty()
        || namespaces.len() > 8
        || namespaces.capacity() > 8
        || namespaces.iter().enumerate().any(|(index, namespace)| {
            namespaces[..index]
                .iter()
                .any(|old| Arc::ptr_eq(old, namespace))
        })
    {
        return Err(ConnectError::Configuration);
    }
    namespaces.sort_unstable_by_key(Arc::as_ptr);
    let guards: Vec<_> = namespaces
        .iter()
        .map(|namespace| {
            namespace
                .verifier
                .lock()
                .expect("original live relay leg namespace")
        })
        .collect();
    let verifiers: Vec<_> = guards.iter().map(|guard| &**guard).collect();
    let mut admission = relay_public::reserve_original_leg(
        &root,
        &verifiers,
        RelayPublicLegInput {
            source: codec::ActivationSource::LiveAuthority,
            live_winner_authority: Some(winner_authority),
            activation: input.activation,
            grant: input.grant,
            certificates: input.certificates,
            relay_certificate: input.relay_certificate,
            candidate: input.candidate,
            selection_set: &[],
            contract: input.contract,
            candidate_index: 0,
            service: &binding.service,
            relay_audience: &binding.relay_audience,
            endpoint_role: input.role,
            prepared_account: input.prepared_account,
        },
    )?;
    drop(guards);
    if admission.tenant != binding.tenant
        || admission.issuer != binding.parent_issuer
        || admission.hop.relay_identity_digest != binding.relay_identity_digest
    {
        return Err(ConnectError::Authorization);
    }
    let request = codec::decode_control_array(
        input.request,
        codec::Limits {
            bytes: 1024,
            nodes: 64,
        },
    )
    .map_err(|_| ConnectError::Configuration)?;
    if request.raw().first().map(|byte| byte >> 5) != Some(4)
        || request.len()? != 13
        || request.at(0)?.text()? != "live-authorization-1"
        || request.at(1)?.text()? != admission.tenant
        || request.at(2)?.text()? != admission.audience
        || request.at(4)?.bytes()? != admission.issuer
        || request.at(5)?.bytes()? != admission.lease
        || request.at(6)?.bytes()? != admission.attempt
        || request.at(7)?.bytes()? != admission.artifact
        || request.at(8)?.bytes()? != admission.identities[0]
        || request.at(9)?.bytes()? != admission.identities[1]
        || request.at(12)?.uint()? != 1
    {
        return Err(ConnectError::Authorization);
    }
    let certificate = decode(
        input.certificates[0],
        "IdentityCertificate",
        8192,
        Context::default(),
    )?;
    let winner = request.at(10)?;
    let cutoff = request.at(11)?.uint()?;
    if request.at(3)?.text()?
        != certificate
            .field("IdentityCertificate", "crypto_profile_id")?
            .text()?
        || winner.raw().first().map(|byte| byte >> 5) != Some(4)
        || winner.len()? != 3
        || winner.at(0)?.uint()? != 0
        || winner.at(1)?.bytes()? != admission.candidate
        || winner.at(2)?.bytes()? != admission.route
        || cutoff == 0
        || cutoff > admission.parent_initiation
        || root.sample()?.upper_ms >= cutoff
    {
        return Err(ConnectError::Authorization);
    }
    admission.initiation = admission.initiation.min(cutoff);
    let charge = admission.account.reserve(ResourceLimits {
        sdk_bytes: 262144,
        items: 8,
        work_slots: 2,
        ..ResourceLimits::default()
    })?;
    Ok(OriginalLiveRelayLegPublication {
        admission,
        request: input.request.to_vec(),
        activation: input.activation.to_vec(),
        grant: input.grant.to_vec(),
        certificates: [
            input.certificates[0].to_vec(),
            input.certificates[1].to_vec(),
        ],
        relay_certificate: input.relay_certificate.to_vec(),
        candidate: input.candidate.to_vec(),
        contract: input.contract.to_vec(),
        namespaces,
        _charge: charge,
    })
}
/// Consume the exact two live handler positions. Joining their public evidence
/// transfers the same verified Accounts into the original paired publication.
pub(super) fn pair_remote_live_legs(
    root: Arc<EnvironmentRoot>,
    binding: &SQLiteRelayBinding,
    a: OriginalLiveRelayLegPublication,
    b: OriginalLiveRelayLegPublication,
) -> ConnectResult<OriginalRelayPoolPublication> {
    a.check()?;
    b.check()?;
    if a.request != b.request
        || a.activation != b.activation
        || a.certificates != b.certificates
        || a.relay_certificate != b.relay_certificate
        || a.candidate != b.candidate
        || a.contract != b.contract
    {
        return Err(ConnectError::Authorization);
    }
    let admission = relay_public::pair_original_legs(a.admission, b.admission)?;
    if admission
        .accounts
        .iter()
        .any(|account| !account.belongs_to(&root))
        || admission.tenant != binding.tenant
        || admission.issuer != binding.parent_issuer
        || admission.hops[0].relay_identity_digest != binding.relay_identity_digest
        || root.sample()?.upper_ms >= admission.initiation
    {
        return Err(ConnectError::Authorization);
    }
    let charge = admission.accounts[0].reserve(ResourceLimits {
        sdk_bytes: 262144,
        items: 8,
        work_slots: 2,
        ..ResourceLimits::default()
    })?;
    let public_record = encode_envelope(
        LIVE_PUBLIC_TAG,
        &[
            &a.activation,
            &a.grant,
            &b.grant,
            &a.certificates[0],
            &a.certificates[1],
            &a.relay_certificate,
            &a.candidate,
            &[],
            &a.contract,
            &[0],
        ],
    );
    if public_record.len() > 65536 || public_record.capacity() > 65536 {
        return Err(ConnectError::Capacity);
    }
    let winner_projection = ParentWinnerSelection {
        source: codec::ActivationSource::LiveAuthority,
        tenant: &admission.tenant,
        authority: &admission.winner_authority,
        server_authority: &binding.server_admission_authority,
        audience: &admission.audience,
        artifact: admission.artifact,
        activation: admission.activation,
        proof: &a.activation,
        candidate: admission.candidate,
        route: admission.route,
        attempt: admission.attempt,
        identities: admission.identities,
        parent_initiation_end: admission.parent_initiation,
        parent_session_end: admission.parent_end,
    }
    .encode(65536)?;
    let [first, second] = admission.hops;
    let [client, server] = a.certificates;
    let endpoints = [
        RelayEndpoint {
            hop: first,
            grant: a.grant,
            certificate: client,
        },
        RelayEndpoint {
            hop: second,
            grant: b.grant,
            certificate: server,
        },
    ];
    let facts = VerifiedRelayParent {
        binding: binding.clone(),
        lease: admission.lease,
        candidate: admission.candidate,
        attempt: admission.attempt,
        public_record,
        winner_projection,
        winner_authority: admission.winner_authority,
        accounts: admission.accounts,
        initiation_end: admission.initiation,
        session_end: admission.parent_end,
    };
    Ok(OriginalRelayPoolPublication {
        source: codec::ActivationSource::LiveAuthority,
        facts,
        endpoints,
        relay_certificate: a.relay_certificate,
        _namespaces: [a.namespaces, b.namespaces],
        _charge: charge,
    })
}
