//! Endpoint-local tunnel credential closure. These verified public facts do
//! not grant relay claim dispatch, parent admission, or forwarding authority.

use super::*;

const GRANT_BYTES: usize = 9_302;

/// Service and audience are installed independently of the application
/// Artifact audience. The endpoint role is logical, never physical direction.
pub(crate) struct TunnelHopInput<'a> {
    pub(crate) grant: &'a [u8],
    pub(crate) relay_certificate: &'a [u8],
    pub(crate) endpoint_role: u8,
    pub(crate) service: &'a str,
    pub(crate) audience: &'a str,
}
impl std::fmt::Debug for TunnelHopInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TunnelHopInput { <redacted> }")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TunnelLimits {
    pub(crate) max_envelope_bytes: u64,
    pub(crate) max_total_bytes: u64,
    pub(crate) max_datagram_bytes: u64,
    pub(crate) max_rate_bytes_per_s: u64,
    pub(crate) max_queue_bytes: u64,
    pub(crate) max_pending_native_mappings: u64,
    pub(crate) max_resident_native_mappings: u64,
    pub(crate) max_total_native_mappings: u64,
    pub(crate) max_queue_items: u64,
}

/// Immutable signed projection held by the original prepared carrier owner.
/// It contains no Artifact, decoder arena, PSK, or authority callback.
#[derive(Debug)]
pub(crate) struct VerifiedTunnelHop {
    pub(crate) grant_digest: [u8; 32],
    pub(crate) route_digest: [u8; 32],
    pub(crate) _grant_id: [u8; 16],
    pub(crate) _replay_nonce: [u8; 32],
    pub(crate) pairing_id: [u8; 16],
    pub(crate) attempt_id: [u8; 16],
    pub(crate) leg_id: [u8; 16],
    pub(crate) endpoint_role: u8,
    pub(crate) dialer_role: u8,
    pub(crate) listener_role: u8,
    authenticated_carrier: Option<[u8; 16]>,
    pub(crate) endpoint_key: [u8; 32],
    pub(crate) relay_key: [u8; 32],
    pub(crate) relay_identity_digest: [u8; 32],
    pub(crate) limits: TunnelLimits,
}
impl VerifiedTunnelHop {
    pub(crate) fn authenticated(&self) -> bool {
        self.authenticated_carrier.is_some()
    }
    pub(crate) fn complete_possession(
        &mut self,
        carrier: [u8; 16],
    ) -> Result<(), EnvironmentError> {
        if carrier == [0; 16] || self.authenticated_carrier.is_some() {
            return Err(EnvironmentError::Configuration);
        }
        self.authenticated_carrier = Some(carrier);
        Ok(())
    }
}

pub(crate) struct EndpointHopVerification {
    pub(crate) facts: VerifiedTunnelHop,
    pub(crate) bindings: [NamespaceBinding; 2],
    pub(crate) not_before_ms: u64,
    pub(crate) not_after_ms: u64,
}

pub(crate) fn reserve_tunnel_connection(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: DirectCredentialInput<'_>,
    hop: TunnelHopInput<'_>,
) -> Result<CredentialAdmission, EnvironmentError> {
    reserve_connection(environment, verifiers, input, Some(hop))
}

fn match_parent(
    grant: Value<'_>,
    artifact: Value<'_>,
    digest: [u8; 32],
) -> Result<(), EnvironmentError> {
    let parent = grant.field("Grant", "parent_ref").map_err(invalid)?;
    for (field, original) in [
        ("tenant_id", "tenant_id"),
        ("revocation_authority_id", "revocation_authority_id"),
        ("authority_generation", "revocation_authority_generation"),
        ("namespace_capacity_digest", "namespace_capacity_digest"),
        ("revocation_policy_id", "revocation_policy_id"),
        ("revocation_policy_revision", "revocation_policy_revision"),
        ("artifact_issuer_key_id", "issuer_key_id"),
        ("lease_id", "lease_id"),
        ("revocation_epoch", "revocation_epoch"),
        ("issued_at_ms", "issued_at_ms"),
        ("initiation_not_after_ms", "initiation_not_after_ms"),
        ("session_not_after_ms", "session_not_after_ms"),
    ] {
        if parent
            .field("GrantParentRef", field)
            .map_err(invalid)?
            .raw()
            != artifact.field("Artifact", original).map_err(invalid)?.raw()
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    if bytes::<32>(parent, "GrantParentRef", "artifact_digest")? != digest {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    Ok(())
}

fn verify_grant_issuer(
    context: NamespaceContext<'_>,
    grant: Value<'_>,
    cohort: u64,
    end: u64,
    scratch: &mut Vec<u8>,
) -> Result<[u8; 16], EnvironmentError> {
    let issuer = bytes::<16>(grant, "Grant", "issuer_key_id")?;
    if context.is_retired(issuer)? {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let issued = uint(grant, "Grant", "issued_at_ms")?;
    let parent = grant.field("Grant", "parent_ref").map_err(invalid)?;
    let schema = "CredentialIssuerAuthorization";
    for original in context.verifier.history.iter().rev() {
        let trust = decode(
            original,
            "TrustConfig",
            super::super::TRUST_BYTES,
            Context::default(),
        )?;
        for entry in trust
            .field("TrustConfig", "issuer_authorizations")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let entry = entry.map_err(invalid)?;
            if bytes::<16>(entry, schema, "issuer_key_id")? != issuer
                || uint(entry, schema, "credential_kind")? != 2
                || text(entry, schema, "tenant_id")? != context.verifier.root.tenant
                || text(entry, schema, "revocation_authority_id")?
                    != context.verifier.root.authority
                || bytes::<32>(entry, schema, "namespace_capacity_digest")?
                    != context.capacity_digest
                || uint(entry, schema, "authority_generation")? != context.generation
                || text(entry, schema, "audience")? != text(grant, "Grant", "audience")?
                || text(entry, schema, "service")? != text(grant, "Grant", "service")?
                || issued < uint(entry, schema, "signing_not_before_ms")?
                || issued >= uint(entry, schema, "signing_not_after_ms")?
                || cohort < uint(entry, schema, "first_cohort")?
                || cohort > uint(entry, schema, "last_cohort")?
                || end > uint(entry, schema, "max_credential_not_after_ms")?
                || text(entry, schema, "parent_authority_id")?
                    != text(parent, "GrantParentRef", "revocation_authority_id")?
                || bytes::<32>(entry, schema, "parent_capacity_digest")?
                    != bytes(parent, "GrantParentRef", "namespace_capacity_digest")?
                || uint(entry, schema, "parent_generation")?
                    != uint(parent, "GrantParentRef", "authority_generation")?
                || bytes::<16>(entry, schema, "parent_artifact_issuer_key_id")?
                    != bytes(parent, "GrantParentRef", "artifact_issuer_key_id")?
                || uint(parent, "GrantParentRef", "revocation_epoch")?
                    < uint(entry, schema, "first_parent_cohort")?
                || uint(parent, "GrantParentRef", "revocation_epoch")?
                    > uint(entry, schema, "last_parent_cohort")?
            {
                continue;
            }
            codec::verify_signature(
                "Grant",
                grant,
                &bytes(entry, schema, "issuer_public_key")?,
                scratch,
            )
            .map_err(invalid)?;
            return Ok(issuer);
        }
    }
    Err(EnvironmentError::AuthorizationDenied)
}

fn check_endpoint_closure(
    candidate: Value<'_>,
    contexts: [NamespaceContext<'_>; 5],
    role: u8,
) -> Result<(), EnvironmentError> {
    let refs = candidate
        .field("Candidate", "revocation_namespace_refs")
        .map_err(invalid)?;
    let local_bit = 1u64 << role;
    let hop_mask = 4 | local_bit;
    // The remote Grant may have an independently installed namespace that is
    // absent from this leg. Check only references applicable to this endpoint.
    for reference in refs.children().map_err(invalid)? {
        let reference = reference.map_err(invalid)?;
        if uint(reference, "RevocationNamespaceRef", "role_mask")? & local_bit == 0 {
            continue;
        }
        let wanted = namespace(reference, "RevocationNamespaceRef")?;
        if !contexts
            .iter()
            .any(|context| context.verifier.key == wanted)
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    for (index, context) in contexts.into_iter().enumerate() {
        let mask = if index < 3 { 7 } else { hop_mask };
        let mut found = false;
        for reference in refs.children().map_err(invalid)? {
            let reference = reference.map_err(invalid)?;
            if namespace(reference, "RevocationNamespaceRef")? != context.verifier.key {
                continue;
            }
            if bytes::<32>(
                reference,
                "RevocationNamespaceRef",
                "namespace_capacity_digest",
            )? != context.capacity_digest
                || uint(reference, "RevocationNamespaceRef", "generation")? != context.generation
                || uint(reference, "RevocationNamespaceRef", "role_mask")? & mask != mask
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            found = true;
        }
        if !found {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "HOP verification keeps independent authority bindings and prepaid verification scratch explicit."
)]
pub(super) fn verify_endpoint_hop(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: TunnelHopInput<'_>,
    artifact: Value<'_>,
    candidate: Value<'_>,
    contexts: [NamespaceContext<'_>; 3],
    bindings: [NamespaceBinding; 3],
    certificates: [Value<'_>; 2],
    now: TrustedTimeSample,
    signature: &mut Vec<u8>,
    route_scratch: &mut Vec<u8>,
) -> Result<EndpointHopVerification, EnvironmentError> {
    let grant = decode(input.grant, "Grant", GRANT_BYTES, Context::default())?;
    match_parent(grant, artifact, bindings[0].credential)?;
    verify_public_hop(
        environment,
        verifiers,
        input,
        candidate,
        contexts,
        bindings,
        certificates,
        text(artifact, "Artifact", "tenant_id")?,
        text(artifact, "Artifact", "crypto_profile_id")?,
        artifact
            .field("Artifact", "session_contract")
            .map_err(invalid)?,
        now,
        signature,
        route_scratch,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "HOP verification keeps independent authority bindings and prepaid verification scratch explicit."
)]
pub(super) fn verify_public_hop(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: TunnelHopInput<'_>,
    candidate: Value<'_>,
    contexts: [NamespaceContext<'_>; 3],
    bindings: [NamespaceBinding; 3],
    certificates: [Value<'_>; 2],
    tenant: &str,
    profile: &str,
    contract: Value<'_>,
    now: TrustedTimeSample,
    signature: &mut Vec<u8>,
    route_scratch: &mut Vec<u8>,
) -> Result<EndpointHopVerification, EnvironmentError> {
    if input.endpoint_role > 1 || input.service.is_empty() || input.audience.is_empty() {
        return Err(EnvironmentError::Configuration);
    }
    let grant = decode(input.grant, "Grant", GRANT_BYTES, Context::default())?;
    let ns = grant.field("Grant", "namespace").map_err(invalid)?;
    if text(grant, "Grant", "tenant_id")? != tenant
        || text(ns, "GrantNamespace", "tenant_id")? != text(grant, "Grant", "tenant_id")?
        || uint(ns, "GrantNamespace", "role_mask")? != (4 | (1u64 << input.endpoint_role))
        || text(grant, "Grant", "service")? != input.service
        || text(grant, "Grant", "audience")? != input.audience
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let own = NamespaceContext::resolve_namespace(
        environment,
        verifiers,
        ns,
        "GrantNamespace",
        "generation",
        now,
    )?;
    let issued = uint(grant, "Grant", "issued_at_ms")?;
    let end = uint(grant, "Grant", "not_after_ms")?;
    super::super::interval(now, issued, end)?;
    let origin = uint(own.capacity, "NamespaceCapacity", "cohort_time_origin_ms")?;
    let duration = uint(own.capacity, "NamespaceCapacity", "cohort_duration_ms")?;
    let cohort = uint(ns, "GrantNamespace", "revocation_epoch")?;
    if duration == 0
        || issued.checked_sub(origin).map(|delta| delta / duration) != Some(cohort)
        || end > own.impact_deadline(cohort, CredentialKind::Connection)?
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let issuer = verify_grant_issuer(own, grant, cohort, end, signature)?;
    let grant_digest = codec::digest("grant_digest", grant).map_err(invalid)?;
    let (max_staleness_ms, max_head_signer_lifetime_ms) = own.policy(ns, "GrantNamespace")?;
    let grant_binding = NamespaceBinding {
        namespace: own.verifier.key,
        generation: own.generation,
        kind: CredentialKind::Connection,
        cohort,
        issuer,
        credential: grant_digest,
        lease: None,
        max_staleness_ms,
        max_head_signer_lifetime_ms,
    };
    let relay = decode(
        input.relay_certificate,
        "IdentityCertificate",
        CERTIFICATE_BYTES,
        Context::default(),
    )?;
    let relay_context =
        NamespaceContext::resolve(environment, verifiers, relay, "IdentityCertificate", now)?;
    if uint(relay, "IdentityCertificate", "role")? != 2
        || text(relay, "IdentityCertificate", "tenant_id")? != tenant
        || text(relay, "IdentityCertificate", "audience")? != input.audience
        || text(relay, "IdentityCertificate", "crypto_profile_id")? != profile
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let relay_start = uint(relay, "IdentityCertificate", "issued_at_ms")?;
    let relay_end = uint(relay, "IdentityCertificate", "expires_at_ms")?;
    super::super::interval(now, relay_start, relay_end)?;
    let relay_cohort = relay_context.issuance(
        relay,
        "IdentityCertificate",
        CredentialKind::Certificate,
        relay_end,
    )?;
    let relay_issuer = relay_context.verify_issuer(
        relay,
        "IdentityCertificate",
        0,
        relay_cohort,
        relay_end,
        signature,
    )?;
    verify_identity_key(relay)?;
    let relay_digest = codec::digest("certificate_digest", relay).map_err(invalid)?;
    if bytes::<32>(grant, "Grant", "relay_identity_digest")? != relay_digest {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let relay_binding = relay_context.binding(
        relay,
        "IdentityCertificate",
        CredentialKind::Certificate,
        relay_cohort,
        relay_digest,
        relay_issuer,
    )?;
    let route = route_digest(candidate, route_scratch)?;
    if bytes::<32>(grant, "Grant", "route_digest")? != route
        || grant
            .field("Grant", "route_descriptor")
            .map_err(invalid)?
            .raw()
            != route_scratch.as_slice()
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let identities = grant.field("Grant", "identity_digests").map_err(invalid)?;
    let legs = grant.field("Grant", "legs").map_err(invalid)?;
    for (role, field) in [(0, "client_leg"), (1, "server_leg")] {
        let reference = legs.at(role).map_err(invalid)?;
        let descriptor = candidate.field("Candidate", field).map_err(invalid)?;
        if identities
            .at(role)
            .and_then(Value::bytes)
            .map_err(invalid)?
            != bindings[role + 1].credential.as_slice()
            || uint(reference, "GrantLegRef", "logical_role")? != role as u64
            || bytes::<16>(reference, "GrantLegRef", "leg_id")?
                != bytes(descriptor, "Leg", "leg_id")?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    let own_leg = candidate
        .field(
            "Candidate",
            if input.endpoint_role == 0 {
                "client_leg"
            } else {
                "server_leg"
            },
        )
        .map_err(invalid)?;
    let dialer_role = uint(own_leg, "Leg", "dialer_role")? as u8;
    let listener_role = uint(own_leg, "Leg", "listener_role")? as u8;
    if !((dialer_role == input.endpoint_role && listener_role == 2)
        || (dialer_role == 2 && listener_role == input.endpoint_role))
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let limits = grant.field("Grant", "limits").map_err(invalid)?;
    let max_envelope_bytes = uint(limits, "GrantLimits", "max_envelope_bytes")?;
    if bytes::<32>(grant, "Grant", "session_contract_digest")?
        != codec::digest("session_contract_digest", contract).map_err(invalid)?
        || uint(contract, "SessionContract", "max_frame")?.checked_add(8)
            != Some(max_envelope_bytes)
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    check_endpoint_closure(
        candidate,
        [contexts[0], contexts[1], contexts[2], own, relay_context],
        input.endpoint_role,
    )?;
    Ok(EndpointHopVerification {
        facts: VerifiedTunnelHop {
            grant_digest,
            route_digest: route,
            _grant_id: bytes(grant, "Grant", "grant_id")?,
            _replay_nonce: bytes(grant, "Grant", "replay_nonce")?,
            pairing_id: bytes(grant, "Grant", "pairing_id")?,
            attempt_id: bytes(grant, "Grant", "attempt_id")?,
            leg_id: bytes(
                legs.at(input.endpoint_role as usize).map_err(invalid)?,
                "GrantLegRef",
                "leg_id",
            )?,
            endpoint_role: input.endpoint_role,
            dialer_role,
            listener_role,
            authenticated_carrier: None,
            endpoint_key: bytes(
                certificates[input.endpoint_role as usize],
                "IdentityCertificate",
                "ed25519_public_key",
            )?,
            relay_key: bytes(relay, "IdentityCertificate", "ed25519_public_key")?,
            relay_identity_digest: relay_digest,
            limits: TunnelLimits {
                max_envelope_bytes,
                max_total_bytes: uint(limits, "GrantLimits", "max_total_bytes")?,
                max_datagram_bytes: uint(limits, "GrantLimits", "max_datagram_bytes")?,
                max_rate_bytes_per_s: uint(limits, "GrantLimits", "max_rate_bytes_per_s")?,
                max_queue_bytes: uint(limits, "GrantLimits", "max_queue_bytes")?,
                max_pending_native_mappings: uint(
                    limits,
                    "GrantLimits",
                    "max_pending_native_mappings",
                )?,
                max_resident_native_mappings: uint(
                    limits,
                    "GrantLimits",
                    "max_resident_native_mappings",
                )?,
                max_total_native_mappings: uint(
                    limits,
                    "GrantLimits",
                    "max_total_native_mappings",
                )?,
                max_queue_items: uint(limits, "GrantLimits", "max_queue_items")?,
            },
        },
        bindings: [grant_binding, relay_binding],
        not_before_ms: issued.max(relay_start),
        not_after_ms: end.min(relay_end),
    })
}
