//! Private credential admission before spend, carrier activation and READY.
//! The result owns an Environment reservation and its complete direct-route
//! credential gates. It conveys no durable spend/admission or network success.

use super::{NamespaceVerifier, invalid, key};
use crate::{
    codec_v4::{self as codec, ActivationSource, Context, Limits, Value},
    environment_v4::{
        AuthorizationBounds, EnvironmentError, EnvironmentRoot, ResourceAccount, ResourceLimits,
        TrustedTimeSample,
    },
    namespace_v4::{CredentialKind, NamespaceBinding, NamespaceKey},
};
use p256::elliptic_curve::sec1::ToSec1Point;
use std::sync::Arc;
use zeroize::Zeroizing;

const ARTIFACT_BYTES: usize = 65_536;
const CERTIFICATE_BYTES: usize = 8_192;
const ACTIVATION_BYTES: usize = 4_096;
const SET_BYTES: usize = 2_048;

#[path = "relay_public_credentials_v4.rs"]
pub(crate) mod relay_public;
#[path = "tunnel_credentials_v4.rs"]
pub(crate) mod tunnel;

/// These bytes and the source discriminant belong to the original material
/// owner. This private input is never an assertion that verification succeeded.
pub(crate) struct DirectCredentialInput<'a> {
    pub(crate) artifact: &'a [u8],
    pub(crate) client_certificate: &'a [u8],
    pub(crate) server_certificate: &'a [u8],
    pub(crate) activation: &'a [u8],
    pub(crate) source: ActivationSource,
    pub(crate) candidate_index: u8,
}
impl std::fmt::Debug for DirectCredentialInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectCredentialInput { <redacted> }")
    }
}

#[derive(Debug)]
pub(crate) struct CredentialAdmission {
    pub(crate) account: ResourceAccount,
    pub(crate) artifact_digest: [u8; 32],
    pub(crate) certificate_digests: [[u8; 32]; 2],
    pub(crate) activation_digest: [u8; 32],
    pub(crate) candidate_id: [u8; 16],
    pub(crate) route_digest: [u8; 32],
    pub(crate) attempt_id: [u8; 16],
    pub(crate) initiation_not_after_ms: u64,
    pub(crate) source: ActivationSource,
    pub(crate) pool: Option<crate::pool_v4::VerifiedPoolFacts>,
    pub(crate) pool_activation: Option<crate::pool_v4::PoolActivation>,
    pub(crate) tunnel: Option<tunnel::VerifiedTunnelHop>,
}

impl CredentialAdmission {
    pub(crate) fn select_prepared_candidate(
        &mut self,
        artifact_bytes: &[u8],
        index: u8,
    ) -> Result<(), EnvironmentError> {
        self.account.check()?;
        let artifact = decode(
            artifact_bytes,
            "Artifact",
            ARTIFACT_BYTES,
            Context::default(),
        )?;
        if codec::digest("artifact_digest", artifact).map_err(invalid)? != self.artifact_digest {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let candidate = artifact
            .field("Artifact", "candidates")
            .and_then(|candidates| candidates.at(index as usize))
            .map_err(invalid)?;
        if uint(candidate, "Candidate", "path_kind")? != u64::from(self.tunnel.is_some()) {
            return Err(EnvironmentError::Configuration);
        }
        let _scratch = self.account.reserve(ResourceLimits {
            sdk_bytes: 8192,
            items: 2,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let mut route_scratch = Vec::with_capacity(4096);
        let mut set_scratch = Vec::with_capacity(2048);
        let route = route_digest(candidate, &mut route_scratch)?;
        let facts = self.pool.as_mut().ok_or(EnvironmentError::Configuration)?;
        let activation = decode(
            &facts.proof,
            "ActivationAuthorization",
            ACTIVATION_BYTES,
            Context::with_activation_source(ActivationSource::PreauthorizedPool),
        )?;
        let once = decode(
            &facts.selection,
            "PoolSelectionRef",
            ACTIVATION_BYTES,
            Context::default(),
        )?
        .field("PoolSelectionRef", "once_authority_ref")
        .map_err(invalid)?;
        verify_selection(
            activation,
            artifact,
            ActivationSource::PreauthorizedPool,
            index,
            Some(once),
            route,
            (&mut route_scratch, &mut set_scratch),
        )?;
        let id = bytes(candidate, "Candidate", "candidate_id")?;
        // A preissued tunnel Grant has one exact candidate binding. Another
        // path requires independently acquired matching Grant custody.
        if self.tunnel.is_some() && id != self.candidate_id {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        facts.candidate_index = index;
        self.candidate_id = id;
        self.route_digest = route;
        Ok(())
    }
}

fn decode<'a>(
    raw: &'a [u8],
    name: &str,
    cap: usize,
    context: Context,
) -> Result<Value<'a>, EnvironmentError> {
    codec::decode_context(
        raw,
        name,
        Limits {
            bytes: cap,
            nodes: 1 << 16,
        },
        None,
        context,
    )
    .map_err(invalid)
}
fn text<'a>(value: Value<'a>, schema: &str, field: &str) -> Result<&'a str, EnvironmentError> {
    value
        .field(schema, field)
        .and_then(Value::text)
        .map_err(invalid)
}
fn bytes<const N: usize>(
    value: Value<'_>,
    schema: &str,
    field: &str,
) -> Result<[u8; N], EnvironmentError> {
    value.b(schema, field).map_err(invalid)
}
fn uint(value: Value<'_>, schema: &str, field: &str) -> Result<u64, EnvironmentError> {
    value.u(schema, field).map_err(invalid)
}
fn namespace(value: Value<'_>, schema: &str) -> Result<NamespaceKey, EnvironmentError> {
    Ok(NamespaceKey {
        tenant: key(text(value, schema, "tenant_id")?),
        authority: key(text(value, schema, "revocation_authority_id")?),
    })
}

#[derive(Clone, Copy)]
struct NamespaceContext<'a> {
    verifier: &'a NamespaceVerifier,
    trust: Value<'a>,
    capacity: Value<'a>,
    state: Value<'a>,
    generation: u64,
    capacity_digest: [u8; 32],
}
impl<'a> NamespaceContext<'a> {
    fn resolve(
        environment: &Arc<EnvironmentRoot>,
        verifiers: &[&'a NamespaceVerifier],
        credential: Value<'_>,
        schema: &str,
        now: TrustedTimeSample,
    ) -> Result<Self, EnvironmentError> {
        Self::resolve_namespace(
            environment,
            verifiers,
            credential,
            schema,
            "revocation_authority_generation",
            now,
        )
    }
    fn resolve_namespace(
        environment: &Arc<EnvironmentRoot>,
        verifiers: &[&'a NamespaceVerifier],
        credential: Value<'_>,
        schema: &str,
        generation_field: &str,
        now: TrustedTimeSample,
    ) -> Result<Self, EnvironmentError> {
        let wanted = namespace(credential, schema)?;
        let verifier = verifiers
            .iter()
            .copied()
            .find(|v| v.key == wanted)
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        if !Arc::ptr_eq(environment, &verifier.environment) || !verifier.bootstrapped {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        verifier.check()?;
        if text(credential, schema, "tenant_id")? != verifier.root.tenant
            || text(credential, schema, "revocation_authority_id")? != verifier.root.authority
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let trust = decode(
            verifier
                .history
                .last()
                .ok_or(EnvironmentError::AuthorizationDenied)?,
            "TrustConfig",
            super::TRUST_BYTES,
            Context::default(),
        )?;
        super::interval(
            now,
            uint(trust, "TrustConfig", "issued_at_ms")?,
            uint(trust, "TrustConfig", "not_after_ms")?,
        )?;
        let capacity = trust.field("TrustConfig", "capacity").map_err(invalid)?;
        let capacity_digest =
            codec::digest("namespace_capacity_digest", capacity).map_err(invalid)?;
        let generation = uint(trust, "TrustConfig", "authority_generation")?;
        if bytes::<32>(credential, schema, "namespace_capacity_digest")? != capacity_digest
            || uint(credential, schema, generation_field)? != generation
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let state = codec::decode(
            &verifier.previous,
            "RevocationState",
            Limits {
                bytes: verifier.state_bytes,
                nodes: verifier.node_cap,
            },
            Some(verifier.capacity_limits(capacity)?),
        )
        .map_err(invalid)?;
        Ok(Self {
            verifier,
            trust,
            capacity,
            state,
            generation,
            capacity_digest,
        })
    }
    fn is_retired(self, issuer: [u8; 16]) -> Result<bool, EnvironmentError> {
        Ok(self
            .trust
            .field("TrustConfig", "retired_issuers")
            .and_then(Value::children)
            .map_err(invalid)?
            .any(|v| v.and_then(Value::bytes) == Ok(issuer.as_slice())))
    }
    fn issuance(
        self,
        credential: Value<'_>,
        schema: &str,
        class: CredentialKind,
        end: u64,
    ) -> Result<u64, EnvironmentError> {
        let issued = uint(credential, schema, "issued_at_ms")?;
        let origin = uint(self.capacity, "NamespaceCapacity", "cohort_time_origin_ms")?;
        let duration = uint(self.capacity, "NamespaceCapacity", "cohort_duration_ms")?;
        let e = uint(credential, schema, "revocation_epoch")?;
        if duration == 0 || issued.checked_sub(origin).map(|n| n / duration) != Some(e) {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        if end > self.impact_deadline(e, class)? {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        Ok(e)
    }
    fn impact_deadline(self, e: u64, class: CredentialKind) -> Result<u64, EnvironmentError> {
        let origin = uint(self.capacity, "NamespaceCapacity", "cohort_time_origin_ms")?;
        let duration = uint(self.capacity, "NamespaceCapacity", "cohort_duration_ms")?;
        let (global, field) = match class {
            CredentialKind::Certificate => ("max_certificate_impact_ms", "certificate_impact_ms"),
            CredentialKind::Connection => ("max_connection_impact_ms", "connection_impact_ms"),
        };
        let global = uint(self.capacity, "NamespaceCapacity", global)?;
        let mut selected = None;
        for segment in self
            .state
            .field("RevocationState", "cohort_policy_segments")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let segment = segment.map_err(invalid)?;
            let Some(limit) = segment
                .optional("CohortPolicySegment", field)
                .map_err(invalid)?
            else {
                continue;
            };
            if e < uint(segment, "CohortPolicySegment", "first_cohort")?
                || e > uint(segment, "CohortPolicySegment", "last_cohort")?
            {
                continue;
            }
            if selected.is_some() {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            selected = Some(limit.uint().map_err(invalid)?);
        }
        let impact = selected.ok_or(EnvironmentError::AuthorizationDenied)?;
        if impact == 0 || impact > global {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        e.checked_add(1)
            .and_then(|n| n.checked_mul(duration))
            .and_then(|n| n.checked_add(origin))
            .and_then(|n| n.checked_add(impact))
            .ok_or(EnvironmentError::AuthorizationDenied)
    }
    fn policy(self, credential: Value<'_>, schema: &str) -> Result<(u64, u64), EnvironmentError> {
        let id = text(credential, schema, "revocation_policy_id")?;
        let revision = uint(credential, schema, "revocation_policy_revision")?;
        for original in self.verifier.history.iter().rev() {
            let trust = decode(
                original,
                "TrustConfig",
                super::TRUST_BYTES,
                Context::default(),
            )?;
            for entry in trust
                .field("TrustConfig", "credential_policies")
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                if text(entry, "CredentialRevocationPolicy", "revocation_policy_id")? == id
                    && uint(
                        entry,
                        "CredentialRevocationPolicy",
                        "revocation_policy_revision",
                    )? == revision
                {
                    return Ok((
                        uint(entry, "CredentialRevocationPolicy", "max_staleness_ms")?,
                        uint(
                            entry,
                            "CredentialRevocationPolicy",
                            "max_head_signer_lifetime_ms",
                        )?,
                    ));
                }
            }
        }
        Err(EnvironmentError::AuthorizationDenied)
    }
    fn verify_issuer(
        self,
        credential: Value<'_>,
        schema: &str,
        kind: u64,
        e: u64,
        end: u64,
        scratch: &mut Vec<u8>,
    ) -> Result<[u8; 16], EnvironmentError> {
        let issuer = bytes::<16>(credential, schema, "issuer_key_id")?;
        if self.is_retired(issuer)? {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let issued = uint(credential, schema, "issued_at_ms")?;
        let purpose = "CredentialIssuerAuthorization";
        for original in self.verifier.history.iter().rev() {
            let trust = decode(
                original,
                "TrustConfig",
                super::TRUST_BYTES,
                Context::default(),
            )?;
            for entry in trust
                .field("TrustConfig", "issuer_authorizations")
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                if bytes::<16>(entry, purpose, "issuer_key_id")? != issuer
                    || uint(entry, purpose, "credential_kind")? != kind
                    || text(entry, purpose, "audience")? != text(credential, schema, "audience")?
                    || text(entry, purpose, "crypto_profile_id")?
                        != text(credential, schema, "crypto_profile_id")?
                    || issued < uint(entry, purpose, "signing_not_before_ms")?
                    || issued >= uint(entry, purpose, "signing_not_after_ms")?
                    || e < uint(entry, purpose, "first_cohort")?
                    || e > uint(entry, purpose, "last_cohort")?
                    || end > uint(entry, purpose, "max_credential_not_after_ms")?
                {
                    continue;
                }
                if kind == 0
                    && (text(entry, purpose, "subject_id")?
                        != text(credential, schema, "subject_id")?
                        || uint(entry, purpose, "role")? != uint(credential, schema, "role")?)
                {
                    continue;
                }
                codec::verify_signature(
                    schema,
                    credential,
                    &bytes(entry, purpose, "issuer_public_key")?,
                    scratch,
                )
                .map_err(invalid)?;
                return Ok(issuer);
            }
        }
        Err(EnvironmentError::AuthorizationDenied)
    }
    fn binding(
        self,
        credential: Value<'_>,
        schema: &str,
        class: CredentialKind,
        e: u64,
        digest: [u8; 32],
        issuer: [u8; 16],
    ) -> Result<NamespaceBinding, EnvironmentError> {
        let (max_staleness_ms, max_head_signer_lifetime_ms) = self.policy(credential, schema)?;
        Ok(NamespaceBinding {
            namespace: self.verifier.key,
            generation: self.generation,
            kind: class,
            cohort: e,
            issuer,
            credential: digest,
            lease: if class == CredentialKind::Connection {
                Some((
                    bytes(credential, schema, "issuer_key_id")?,
                    bytes(credential, schema, "lease_id")?,
                ))
            } else {
                None
            },
            max_staleness_ms,
            max_head_signer_lifetime_ms,
        })
    }
}

fn verify_identity_key(certificate: Value<'_>) -> Result<(), EnvironmentError> {
    let key = bytes(certificate, "IdentityCertificate", "ed25519_public_key")?;
    if !codec::valid_ed25519_key(&key) {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let noise = certificate
        .field("IdentityCertificate", "noise_static_public_key")
        .map_err(invalid)?;
    let public = noise
        .field("NoiseStaticPublicKey", "public_key_bytes")
        .and_then(Value::bytes)
        .map_err(invalid)?;
    match uint(noise, "NoiseStaticPublicKey", "algorithm")? {
        0 => {
            let encoded: [u8; 32] = public
                .try_into()
                .map_err(|_| EnvironmentError::AuthorizationDenied)?;
            // This public contributory check does not replace the actual Noise
            // DH or possession proof. Original certificate bytes stay intact.
            let peer = x25519_dalek::PublicKey::from(encoded);
            let public_test_scalar = x25519_dalek::StaticSecret::from([0x5a; 32]);
            if !public_test_scalar.diffie_hellman(&peer).was_contributory() {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        1 => {
            if public.len() != 65 || public[0] != 4 {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            let key = p256::PublicKey::from_sec1_bytes(public)
                .map_err(|_| EnvironmentError::AuthorizationDenied)?;
            if key.to_sec1_point(false).as_bytes() != public {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        _ => return Err(EnvironmentError::AuthorizationDenied),
    }
    Ok(())
}

fn verify_certificate(
    context: NamespaceContext<'_>,
    certificate: Value<'_>,
    artifact: Value<'_>,
    role: u64,
    now: TrustedTimeSample,
    scratch: &mut Vec<u8>,
) -> Result<(NamespaceBinding, u64, u64), EnvironmentError> {
    verify_public_certificate(
        context,
        certificate,
        text(artifact, "Artifact", "tenant_id")?,
        text(artifact, "Artifact", "audience")?,
        text(artifact, "Artifact", "crypto_profile_id")?,
        role,
        bytes(
            artifact,
            "Artifact",
            if role == 0 {
                "client_identity_digest"
            } else {
                "server_identity_digest"
            },
        )?,
        now,
        scratch,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Credential verification requires the original parent bindings, validity interval and reusable scratch together."
)]
fn verify_public_certificate(
    context: NamespaceContext<'_>,
    certificate: Value<'_>,
    tenant: &str,
    audience: &str,
    profile: &str,
    role: u64,
    expected_digest: [u8; 32],
    now: TrustedTimeSample,
    scratch: &mut Vec<u8>,
) -> Result<(NamespaceBinding, u64, u64), EnvironmentError> {
    let schema = "IdentityCertificate";
    if text(certificate, schema, "tenant_id")? != tenant
        || text(certificate, schema, "audience")? != audience
        || text(certificate, schema, "crypto_profile_id")? != profile
        || uint(certificate, schema, "role")? != role
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let digest = codec::digest("certificate_digest", certificate).map_err(invalid)?;
    if digest != expected_digest {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let issued = uint(certificate, schema, "issued_at_ms")?;
    let end = uint(certificate, schema, "expires_at_ms")?;
    super::interval(now, issued, end)?;
    let e = context.issuance(certificate, schema, CredentialKind::Certificate, end)?;
    let issuer = context.verify_issuer(certificate, schema, 0, e, end, scratch)?;
    verify_identity_key(certificate)?;
    Ok((
        context.binding(
            certificate,
            schema,
            CredentialKind::Certificate,
            e,
            digest,
            issuer,
        )?,
        issued,
        end,
    ))
}

fn route_digest(candidate: Value<'_>, scratch: &mut Vec<u8>) -> Result<[u8; 32], EnvironmentError> {
    let kind = uint(candidate, "Candidate", "path_kind")?;
    scratch.clear();
    codec::encode_head(scratch, 5, if kind == 0 { 3 } else { 4 });
    for (id, field) in [(0, "path_kind"), (1, "candidate_id")] {
        codec::encode_head(scratch, 0, id);
        scratch.extend_from_slice(candidate.field("Candidate", field).map_err(invalid)?.raw());
    }
    for (id, field) in [(2, "direct_leg"), (3, "client_leg"), (4, "server_leg")] {
        if let Some(value) = candidate.optional("Candidate", field).map_err(invalid)? {
            codec::encode_head(scratch, 0, id);
            scratch.extend_from_slice(value.raw());
        }
    }
    let route = decode(scratch, "Route", ARTIFACT_BYTES, Context::default())?;
    codec::digest("route_digest", route).map_err(invalid)
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    codec::encode_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
fn once_authority<'a>(
    context: NamespaceContext<'a>,
    issuer: [u8; 16],
) -> Result<Value<'a>, EnvironmentError> {
    for original in context.verifier.history.iter().rev() {
        let trust = decode(
            original,
            "TrustConfig",
            super::TRUST_BYTES,
            Context::default(),
        )?;
        for entry in trust
            .field("TrustConfig", "once_authorities")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let entry = entry.map_err(invalid)?;
            if bytes::<16>(entry, "OnceAuthorityRef", "artifact_issuer_key_id")? == issuer {
                if text(entry, "OnceAuthorityRef", "tenant_id")? != context.verifier.root.tenant {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                return Ok(entry);
            }
        }
    }
    Err(EnvironmentError::AuthorizationDenied)
}
fn verify_selection(
    activation: Value<'_>,
    artifact: Value<'_>,
    source: ActivationSource,
    index: u8,
    authority: Option<Value<'_>>,
    route: [u8; 32],
    scratch: (&mut Vec<u8>, &mut Vec<u8>),
) -> Result<(), EnvironmentError> {
    let (route_scratch, set_scratch) = scratch;
    let candidates = artifact.field("Artifact", "candidates").map_err(invalid)?;
    let candidate = candidates.at(index as usize).map_err(invalid)?;
    match source {
        ActivationSource::LiveAuthority => {
            if bytes::<16>(activation, "ActivationAuthorization", "candidate_selection")?
                != bytes(candidate, "Candidate", "candidate_id")?
                || bytes::<32>(activation, "ActivationAuthorization", "route_selection")? != route
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        ActivationSource::PreauthorizedPool => {
            let authority = authority.ok_or(EnvironmentError::Configuration)?;
            let selection = activation
                .field("ActivationAuthorization", "candidate_selection")
                .map_err(invalid)?;
            if selection
                .field("PoolSelectionRef", "once_authority_ref")
                .map_err(invalid)?
                .raw()
                != authority.raw()
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            let indices = selection
                .field("PoolSelectionRef", "candidate_indices")
                .map_err(invalid)?;
            set_scratch.clear();
            codec::encode_head(set_scratch, 5, 2);
            codec::encode_head(set_scratch, 0, 0);
            put_bytes(
                set_scratch,
                &bytes::<32>(activation, "ActivationAuthorization", "artifact_digest")?,
            );
            codec::encode_head(set_scratch, 0, 1);
            codec::encode_head(set_scratch, 4, indices.len().map_err(invalid)? as u64);
            let mut found = false;
            for selected in indices.children().map_err(invalid)? {
                let n = selected.and_then(Value::uint).map_err(invalid)?;
                let candidate = candidates.at(n as usize).map_err(invalid)?;
                let digest = route_digest(candidate, route_scratch)?;
                found |= n == u64::from(index);
                codec::encode_head(set_scratch, 5, 3);
                codec::encode_head(set_scratch, 0, 0);
                codec::encode_head(set_scratch, 0, n);
                codec::encode_head(set_scratch, 0, 1);
                put_bytes(
                    set_scratch,
                    &bytes::<16>(candidate, "Candidate", "candidate_id")?,
                );
                codec::encode_head(set_scratch, 0, 2);
                put_bytes(set_scratch, &digest);
            }
            let set = decode(
                set_scratch,
                "PoolSelectionSet",
                SET_BYTES,
                Context::default(),
            )?;
            if !found
                || codec::digest("candidate_set_digest", set).map_err(invalid)?
                    != bytes(selection, "PoolSelectionRef", "candidate_set_digest")?
                || codec::digest("route_set_digest", set).map_err(invalid)?
                    != bytes(activation, "ActivationAuthorization", "route_selection")?
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Credential verification requires the original parent bindings, validity interval and reusable scratch together."
)]
fn verify_activation(
    context: NamespaceContext<'_>,
    artifact: Value<'_>,
    activation: Value<'_>,
    source: ActivationSource,
    artifact_digest: [u8; 32],
    parent: NamespaceBinding,
    now: TrustedTimeSample,
    scratch: &mut Vec<u8>,
) -> Result<(NamespaceBinding, u64, u64, u64), EnvironmentError> {
    let schema = "ActivationAuthorization";
    for (field, original) in [
        ("tenant_id", "tenant_id"),
        ("artifact_issuer_key_id", "issuer_key_id"),
        ("lease_id", "lease_id"),
        ("client_identity_digest", "client_identity_digest"),
        ("server_identity_digest", "server_identity_digest"),
        ("audience", "audience"),
    ] {
        if activation.field(schema, field).map_err(invalid)?.raw()
            != artifact.field("Artifact", original).map_err(invalid)?.raw()
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    if bytes::<32>(activation, schema, "artifact_digest")? != artifact_digest {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    verify_public_activation(
        context,
        activation,
        source,
        parent,
        uint(artifact, "Artifact", "issued_at_ms")?,
        uint(artifact, "Artifact", "initiation_not_after_ms")?,
        uint(artifact, "Artifact", "session_not_after_ms")?,
        now,
        scratch,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Credential verification requires the original parent bindings, validity interval and reusable scratch together."
)]
fn verify_public_activation(
    context: NamespaceContext<'_>,
    activation: Value<'_>,
    source: ActivationSource,
    parent: NamespaceBinding,
    parent_issued: u64,
    parent_initiation: u64,
    parent_end: u64,
    now: TrustedTimeSample,
    scratch: &mut Vec<u8>,
) -> Result<(NamespaceBinding, u64, u64, u64), EnvironmentError> {
    let schema = "ActivationAuthorization";
    if source == ActivationSource::PreauthorizedPool {
        let authority = once_authority(context, parent.issuer)?;
        if text(activation, schema, "authority_id")?
            != text(authority, "OnceAuthorityRef", "spend_authority_id")?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    let issued = uint(activation, schema, "issued_at_ms")?;
    let initiation = uint(activation, schema, "activation_not_after_ms")?;
    let end = uint(activation, schema, "session_not_after_ms")?;
    super::interval(now, issued, initiation)?;
    if issued < parent_issued
        || initiation > parent_initiation
        || end > parent_end
        || end > context.impact_deadline(parent.cohort, CredentialKind::Connection)?
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let id = text(activation, schema, "signing_key_id")?;
    let delegation_schema = "ConnectionActivationDelegation";
    for original in context.verifier.history.iter().rev() {
        let trust = decode(
            original,
            "TrustConfig",
            super::TRUST_BYTES,
            Context::default(),
        )?;
        for delegation in trust
            .field("TrustConfig", "activation_delegations")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let delegation = delegation.map_err(invalid)?;
            if text(delegation, delegation_schema, "signing_key_id")? != id {
                continue;
            }
            let issuer = bytes(delegation, delegation_schema, "issuer_key_id")?;
            if context.is_retired(issuer)?
                || uint(delegation, delegation_schema, "purpose")? != 1
                || bytes::<16>(delegation, delegation_schema, "artifact_issuer_key_id")?
                    != parent.issuer
                || text(delegation, delegation_schema, "authority_id")?
                    != text(activation, schema, "authority_id")?
                || issued < uint(delegation, delegation_schema, "signing_not_before_ms")?
                || issued >= uint(delegation, delegation_schema, "signing_not_after_ms")?
                || parent.cohort < uint(delegation, delegation_schema, "first_parent_cohort")?
                || parent.cohort > uint(delegation, delegation_schema, "last_parent_cohort")?
                || initiation > uint(delegation, delegation_schema, "max_activation_not_after_ms")?
                || end > uint(delegation, delegation_schema, "max_session_not_after_ms")?
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            codec::verify_signature(
                schema,
                activation,
                &bytes(delegation, delegation_schema, "signer_public_key")?,
                scratch,
            )
            .map_err(invalid)?;
            return Ok((
                NamespaceBinding { issuer, ..parent },
                issued,
                initiation,
                end,
            ));
        }
    }
    Err(EnvironmentError::AuthorizationDenied)
}

fn check_direct_closure(
    candidate: Value<'_>,
    contexts: [NamespaceContext<'_>; 3],
) -> Result<(), EnvironmentError> {
    let refs = candidate
        .field("Candidate", "revocation_namespace_refs")
        .map_err(invalid)?;
    for reference in refs.children().map_err(invalid)? {
        let reference = reference.map_err(invalid)?;
        let key = namespace(reference, "RevocationNamespaceRef")?;
        let Some(context) = contexts.iter().find(|c| c.verifier.key == key) else {
            return Err(EnvironmentError::AuthorizationDenied);
        };
        if bytes::<32>(
            reference,
            "RevocationNamespaceRef",
            "namespace_capacity_digest",
        )? != context.capacity_digest
            || uint(reference, "RevocationNamespaceRef", "generation")? != context.generation
            || uint(reference, "RevocationNamespaceRef", "role_mask")? != 3
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    for context in contexts {
        if !refs.children().map_err(invalid)?.any(|r| {
            r.is_ok_and(|r| namespace(r, "RevocationNamespaceRef") == Ok(context.verifier.key))
        }) {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    Ok(())
}

/// Reserve the original direct-route account after all four independent
/// credential gates pass. A later transport assembly must still qualify the
/// provider/resources, perform original once spend/admission, prove both keys
/// through Noise/READY, and recheck this same account before publication.
pub(crate) fn reserve_direct_connection(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: DirectCredentialInput<'_>,
) -> Result<CredentialAdmission, EnvironmentError> {
    reserve_connection(environment, verifiers, input, None)
}
/// Verify the separately issued server Grant against the same original pool
/// closure without admitting another Account or consuming an activation.
pub(crate) fn verify_pool_server_allow(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    original: &CredentialAdmission,
    input: DirectCredentialInput<'_>,
    hop: tunnel::TunnelHopInput<'_>,
) -> Result<tunnel::EndpointHopVerification, EnvironmentError> {
    if hop.endpoint_role != 1 {
        return Err(EnvironmentError::Configuration);
    }
    verify_pool_hop(environment, verifiers, original, input, hop)
}
/// Verify another public hop against the original admitted pool closure.
pub(crate) fn verify_pool_hop(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    original: &CredentialAdmission,
    input: DirectCredentialInput<'_>,
    hop: tunnel::TunnelHopInput<'_>,
) -> Result<tunnel::EndpointHopVerification, EnvironmentError> {
    original.account.check()?;
    if original.source != ActivationSource::PreauthorizedPool
        || input.source != original.source
        || hop.endpoint_role > 1
        || verifiers.is_empty()
        || verifiers.len() > 8
        || !original.account.belongs_to(environment)
        || verifiers
            .iter()
            .any(|verifier| !Arc::ptr_eq(environment, &verifier.environment))
    {
        return Err(EnvironmentError::Configuration);
    }
    let _work = original.account.reserve(ResourceLimits {
        sdk_bytes: (2 * ARTIFACT_BYTES + 8192) as u64,
        items: 1,
        work_slots: 1,
        ..ResourceLimits::default()
    })?;
    let mut signature = Zeroizing::new(Vec::new());
    signature
        .try_reserve_exact(ARTIFACT_BYTES + 128)
        .map_err(|_| EnvironmentError::Capacity)?;
    let mut route_scratch = Vec::new();
    route_scratch
        .try_reserve_exact(ARTIFACT_BYTES)
        .map_err(|_| EnvironmentError::Capacity)?;
    let now = environment.sample()?;
    let artifact = decode(
        input.artifact,
        "Artifact",
        ARTIFACT_BYTES,
        Context::default(),
    )?;
    if codec::digest("artifact_digest", artifact).map_err(invalid)? != original.artifact_digest {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let parent_context =
        NamespaceContext::resolve(environment, verifiers, artifact, "Artifact", now)?;
    let parent_end = uint(artifact, "Artifact", "session_not_after_ms")?;
    let cohort =
        parent_context.issuance(artifact, "Artifact", CredentialKind::Connection, parent_end)?;
    let issuer = parent_context.verify_issuer(
        artifact,
        "Artifact",
        1,
        cohort,
        parent_end,
        &mut signature,
    )?;
    let parent = parent_context.binding(
        artifact,
        "Artifact",
        CredentialKind::Connection,
        cohort,
        original.artifact_digest,
        issuer,
    )?;
    let client = decode(
        input.client_certificate,
        "IdentityCertificate",
        CERTIFICATE_BYTES,
        Context::default(),
    )?;
    let server = decode(
        input.server_certificate,
        "IdentityCertificate",
        CERTIFICATE_BYTES,
        Context::default(),
    )?;
    let client_context =
        NamespaceContext::resolve(environment, verifiers, client, "IdentityCertificate", now)?;
    let server_context =
        NamespaceContext::resolve(environment, verifiers, server, "IdentityCertificate", now)?;
    let (client_binding, _, _) =
        verify_certificate(client_context, client, artifact, 0, now, &mut signature)?;
    let (server_binding, _, _) =
        verify_certificate(server_context, server, artifact, 1, now, &mut signature)?;
    if [client_binding.credential, server_binding.credential] != original.certificate_digests {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let candidate = artifact
        .field("Artifact", "candidates")
        .and_then(|candidates| candidates.at(input.candidate_index as usize))
        .map_err(invalid)?;
    let verified = tunnel::verify_endpoint_hop(
        environment,
        verifiers,
        hop,
        artifact,
        candidate,
        [parent_context, client_context, server_context],
        [parent, client_binding, server_binding],
        [client, server],
        now,
        &mut signature,
        &mut route_scratch,
    )?;
    let client_hop = original
        .tunnel
        .as_ref()
        .ok_or(EnvironmentError::Configuration)?;
    if verified.facts.attempt_id != original.attempt_id
        || verified.facts.pairing_id != client_hop.pairing_id
        || verified.facts.relay_identity_digest != client_hop.relay_identity_digest
        || verified.facts.route_digest != original.route_digest
        || bytes::<16>(candidate, "Candidate", "candidate_id")? != original.candidate_id
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    original.account.check()?;
    Ok(verified)
}

fn reserve_connection(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: DirectCredentialInput<'_>,
    tunnel_input: Option<tunnel::TunnelHopInput<'_>>,
) -> Result<CredentialAdmission, EnvironmentError> {
    let verifier_limit = if tunnel_input.is_some() { 8 } else { 3 };
    if verifiers.is_empty() || verifiers.len() > verifier_limit {
        return Err(EnvironmentError::Configuration);
    }
    for (i, verifier) in verifiers.iter().enumerate() {
        if !Arc::ptr_eq(environment, &verifier.environment)
            || verifiers[..i].iter().any(|old| old.key == verifier.key)
        {
            return Err(EnvironmentError::Configuration);
        }
    }
    // All inputs remain borrowed. Reserve every copied signature/projection
    // byte before allocation; the Artifact signature scratch contains its PSK
    // and is zeroized when this original synchronous verification exits.
    let _work = environment.reserve_environment(ResourceLimits {
        sdk_bytes: (2 * ARTIFACT_BYTES + SET_BYTES + 8192) as u64,
        items: 1,
        work_slots: 1,
        ..ResourceLimits::default()
    })?;
    let mut signature = Zeroizing::new(Vec::new());
    signature
        .try_reserve_exact(ARTIFACT_BYTES + 128)
        .map_err(|_| EnvironmentError::Capacity)?;
    let mut route_scratch = Vec::new();
    route_scratch
        .try_reserve_exact(ARTIFACT_BYTES)
        .map_err(|_| EnvironmentError::Capacity)?;
    let mut set_scratch = Vec::new();
    set_scratch
        .try_reserve_exact(SET_BYTES)
        .map_err(|_| EnvironmentError::Capacity)?;
    let now = environment.sample()?;
    let artifact = decode(
        input.artifact,
        "Artifact",
        ARTIFACT_BYTES,
        Context::default(),
    )?;
    let artifact_digest = codec::digest("artifact_digest", artifact).map_err(invalid)?;
    let parent_context =
        NamespaceContext::resolve(environment, verifiers, artifact, "Artifact", now)?;
    let issued = uint(artifact, "Artifact", "issued_at_ms")?;
    let initiation = uint(artifact, "Artifact", "initiation_not_after_ms")?;
    let parent_end = uint(artifact, "Artifact", "session_not_after_ms")?;
    super::interval(now, issued, initiation)?;
    let parent_cohort =
        parent_context.issuance(artifact, "Artifact", CredentialKind::Connection, parent_end)?;
    let issuer = parent_context.verify_issuer(
        artifact,
        "Artifact",
        1,
        parent_cohort,
        parent_end,
        &mut signature,
    )?;
    let parent = parent_context.binding(
        artifact,
        "Artifact",
        CredentialKind::Connection,
        parent_cohort,
        artifact_digest,
        issuer,
    )?;
    let candidate = artifact
        .field("Artifact", "candidates")
        .and_then(|v| v.at(input.candidate_index as usize))
        .map_err(invalid)?;
    if uint(candidate, "Candidate", "path_kind")? != u64::from(tunnel_input.is_some()) {
        return Err(EnvironmentError::Configuration);
    }
    let client = decode(
        input.client_certificate,
        "IdentityCertificate",
        CERTIFICATE_BYTES,
        Context::default(),
    )?;
    let server = decode(
        input.server_certificate,
        "IdentityCertificate",
        CERTIFICATE_BYTES,
        Context::default(),
    )?;
    let client_context =
        NamespaceContext::resolve(environment, verifiers, client, "IdentityCertificate", now)?;
    let server_context =
        NamespaceContext::resolve(environment, verifiers, server, "IdentityCertificate", now)?;
    let (client_binding, client_start, client_end) =
        verify_certificate(client_context, client, artifact, 0, now, &mut signature)?;
    let (server_binding, server_start, server_end) =
        verify_certificate(server_context, server, artifact, 1, now, &mut signature)?;
    let verified_tunnel = if let Some(hop) = tunnel_input {
        Some(tunnel::verify_endpoint_hop(
            environment,
            verifiers,
            hop,
            artifact,
            candidate,
            [parent_context, client_context, server_context],
            [parent, client_binding, server_binding],
            [client, server],
            now,
            &mut signature,
            &mut route_scratch,
        )?)
    } else {
        check_direct_closure(candidate, [parent_context, client_context, server_context])?;
        None
    };
    let activation = decode(
        input.activation,
        "ActivationAuthorization",
        ACTIVATION_BYTES,
        Context::with_activation_source(input.source),
    )?;
    let (activation_binding, activation_start, activation_end, session_end) = verify_activation(
        parent_context,
        artifact,
        activation,
        input.source,
        artifact_digest,
        parent,
        now,
        &mut signature,
    )?;
    let route = route_digest(candidate, &mut route_scratch)?;
    verify_selection(
        activation,
        artifact,
        input.source,
        input.candidate_index,
        if input.source == ActivationSource::PreauthorizedPool {
            Some(once_authority(parent_context, issuer)?)
        } else {
            None
        },
        route,
        (&mut route_scratch, &mut set_scratch),
    )?;
    if verified_tunnel.as_ref().is_some_and(|hop| {
        bytes::<16>(activation, "ActivationAuthorization", "attempt_id") != Ok(hop.facts.attempt_id)
    }) {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let tunnel_start = verified_tunnel.as_ref().map_or(0, |hop| hop.not_before_ms);
    let tunnel_end = verified_tunnel
        .as_ref()
        .map_or(u64::MAX, |hop| hop.not_after_ms);
    let initiation = initiation.min(activation_end).min(tunnel_end);
    let account = environment.admit(
        parent.namespace.tenant,
        AuthorizationBounds {
            not_before_ms: issued
                .max(client_start)
                .max(server_start)
                .max(activation_start)
                .max(tunnel_start),
            not_after_ms: session_end.min(client_end).min(server_end).min(tunnel_end),
            freshness_not_after_ms: initiation,
        },
    )?;
    let mut bindings = [parent; 8];
    let mut count = 0;
    for binding in [parent, client_binding, server_binding, activation_binding]
        .into_iter()
        .chain(
            verified_tunnel
                .as_ref()
                .into_iter()
                .flat_map(|hop| hop.bindings),
        )
    {
        if !bindings[..count].contains(&binding) {
            bindings[count] = binding;
            count += 1;
        }
    }
    account.bind_namespaces(&bindings[..count])?;
    // Signature/namespace work may have consumed time. The initial-use cutoff
    // is checked again without turning that cutoff into a Session lifetime.
    let final_time = environment.sample()?;
    super::interval(final_time, issued.max(activation_start), initiation)?;
    account.check()?;
    let pool = if input.source == ActivationSource::PreauthorizedPool {
        let once = once_authority(parent_context, issuer)?;
        let selection = activation
            .field("ActivationAuthorization", "candidate_selection")
            .map_err(invalid)?;
        let pool_charge = account.reserve(ResourceLimits {
            sdk_bytes: 16_384,
            items: 1,
            work_slots: 0,
            tasks: 0,
            sessions: 0,
            ..ResourceLimits::default()
        })?;
        Some(crate::pool_v4::VerifiedPoolFacts {
            tenant: text(artifact, "Artifact", "tenant_id")?.to_owned(),
            issuer,
            lease: bytes(artifact, "Artifact", "lease_id")?,
            authority: text(once, "OnceAuthorityRef", "spend_authority_id")?.to_owned(),
            winner_authority: text(once, "OnceAuthorityRef", "winner_authority_id")?.to_owned(),
            proof: input.activation.to_vec(),
            selection: selection.raw().to_vec(),
            route_set: bytes(activation, "ActivationAuthorization", "route_selection")?,
            candidate_index: input.candidate_index,
            issued_at: activation_start,
            parent_initiation_end: uint(artifact, "Artifact", "initiation_not_after_ms")?,
            session_end,
            session_nonce: bytes(artifact, "Artifact", "session_nonce")?,
            _charge: pool_charge,
        })
    } else {
        None
    };
    Ok(CredentialAdmission {
        account,
        artifact_digest,
        certificate_digests: [client_binding.credential, server_binding.credential],
        activation_digest: codec::digest("activation_digest", activation).map_err(invalid)?,
        candidate_id: bytes(candidate, "Candidate", "candidate_id")?,
        route_digest: route,
        attempt_id: bytes(activation, "ActivationAuthorization", "attempt_id")?,
        initiation_not_after_ms: initiation,
        source: input.source,
        pool,
        pool_activation: None,
        tunnel: verified_tunnel.map(|hop| hop.facts),
    })
}

/// Verify configured identities and activation delegation before an issuance
/// request exists. No sample Artifact/Activation can select source authority.
pub(crate) fn verify_live_source_configuration(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    certificates: [&[u8]; 2],
    artifact_issuer: [u8; 16],
    signing_key_id: &str,
) -> Result<[[u8; 32]; 2], EnvironmentError> {
    if verifiers.is_empty()
        || verifiers.len() > 8
        || artifact_issuer == [0; 16]
        || signing_key_id.is_empty()
        || signing_key_id.len() > 128
        || verifiers
            .iter()
            .any(|verifier| !Arc::ptr_eq(environment, &verifier.environment))
    {
        return Err(EnvironmentError::Configuration);
    }
    let _work = environment.reserve_environment(ResourceLimits {
        sdk_bytes: 32768,
        items: 1,
        work_slots: 1,
        ..ResourceLimits::default()
    })?;
    let mut scratch = Zeroizing::new(Vec::with_capacity(16384));
    let now = environment.sample()?;
    let mut digests = [[0; 32]; 2];
    let mut client_tenant = None;
    let client_document = decode(
        certificates[0],
        "IdentityCertificate",
        CERTIFICATE_BYTES,
        Context::default(),
    )?;
    for (role, raw) in certificates.into_iter().enumerate() {
        let certificate = decode(
            raw,
            "IdentityCertificate",
            CERTIFICATE_BYTES,
            Context::default(),
        )?;
        if uint(certificate, "IdentityCertificate", "role")? != role as u64 {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        for field in ["tenant_id", "audience", "crypto_profile_id"] {
            if certificate
                .field("IdentityCertificate", field)
                .map_err(invalid)?
                .raw()
                != client_document
                    .field("IdentityCertificate", field)
                    .map_err(invalid)?
                    .raw()
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        let context = NamespaceContext::resolve(
            environment,
            verifiers,
            certificate,
            "IdentityCertificate",
            now,
        )?;
        let issued = uint(certificate, "IdentityCertificate", "issued_at_ms")?;
        let end = uint(certificate, "IdentityCertificate", "expires_at_ms")?;
        super::interval(now, issued, end)?;
        let cohort = context.issuance(
            certificate,
            "IdentityCertificate",
            CredentialKind::Certificate,
            end,
        )?;
        let issuer = context.verify_issuer(
            certificate,
            "IdentityCertificate",
            0,
            cohort,
            end,
            &mut scratch,
        )?;
        let digest = codec::digest("certificate_digest", certificate).map_err(invalid)?;
        environment.check_namespace_binding(context.binding(
            certificate,
            "IdentityCertificate",
            CredentialKind::Certificate,
            cohort,
            digest,
            issuer,
        )?)?;
        verify_identity_key(certificate)?;
        digests[role] = codec::digest("certificate_digest", certificate).map_err(invalid)?;
        if role == 0 {
            client_tenant = Some(context.verifier.key.tenant);
        } else if client_tenant != Some(context.verifier.key.tenant) {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    for verifier in verifiers {
        if Some(verifier.key.tenant) != client_tenant {
            continue;
        }
        for original in verifier.history.iter().rev() {
            let trust = decode(
                original,
                "TrustConfig",
                super::TRUST_BYTES,
                Context::default(),
            )?;
            for delegation in trust
                .field("TrustConfig", "activation_delegations")
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let delegation = delegation.map_err(invalid)?;
                let schema = "ConnectionActivationDelegation";
                if text(delegation, schema, "signing_key_id")? != signing_key_id
                    || bytes::<16>(delegation, schema, "artifact_issuer_key_id")? != artifact_issuer
                {
                    continue;
                }
                if uint(delegation, schema, "purpose")? != 1
                    || now.lower_ms < uint(delegation, schema, "signing_not_before_ms")?
                    || now.upper_ms >= uint(delegation, schema, "signing_not_after_ms")?
                {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                let issuer = bytes::<16>(delegation, schema, "issuer_key_id")?;
                if !verifier.bootstrapped {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                verifier.check()?;
                let current = decode(
                    verifier
                        .history
                        .last()
                        .ok_or(EnvironmentError::AuthorizationDenied)?,
                    "TrustConfig",
                    super::TRUST_BYTES,
                    Context::default(),
                )?;
                super::interval(
                    now,
                    uint(current, "TrustConfig", "issued_at_ms")?,
                    uint(current, "TrustConfig", "not_after_ms")?,
                )?;
                if current
                    .field("TrustConfig", "retired_issuers")
                    .and_then(Value::children)
                    .map_err(invalid)?
                    .any(|entry| {
                        entry.and_then(Value::bytes).is_ok_and(|retired| {
                            retired == issuer.as_slice() || retired == artifact_issuer.as_slice()
                        })
                    })
                {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                return Ok(digests);
            }
        }
    }
    Err(EnvironmentError::AuthorizationDenied)
}

/// The original verified direct route before live TxB. This type cannot be
/// passed to Handshake; only a matching signed proof can consume it and produce
/// CredentialAdmission for the same already-prepared account.
#[derive(Debug)]
pub(crate) struct PendingDirectAdmission {
    pub(crate) account: ResourceAccount,
    pub(crate) artifact_digest: [u8; 32],
    pub(crate) certificate_digests: [[u8; 32]; 2],
    pub(crate) candidate_id: [u8; 16],
    pub(crate) route_digest: [u8; 32],
    pub(crate) candidate_index: u8,
    pub(crate) attempt_id: [u8; 16],
    pub(crate) initiation_not_after_ms: u64,
    pub(crate) path_kind: u8,
    parent: NamespaceBinding,
    activation_signing_key_id: String,
    signature: Zeroizing<Vec<u8>>,
    route_scratch: Vec<u8>,
    set_scratch: Vec<u8>,
    _verification: crate::environment_v4::ResourceCharge,
}
pub(crate) fn reserve_live_direct_preparation(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: DirectCredentialInput<'_>,
    attempt_id: [u8; 16],
    activation_signing_key_id: &str,
) -> Result<PendingDirectAdmission, EnvironmentError> {
    reserve_live_preparation(
        environment,
        verifiers,
        input,
        attempt_id,
        activation_signing_key_id,
        0,
        false,
    )
}
pub(crate) fn reserve_live_tunnel_preparation(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: DirectCredentialInput<'_>,
    attempt_id: [u8; 16],
    activation_signing_key_id: &str,
) -> Result<PendingDirectAdmission, EnvironmentError> {
    reserve_live_preparation(
        environment,
        verifiers,
        input,
        attempt_id,
        activation_signing_key_id,
        1,
        false,
    )
}
/// Verification of a server's independently installed live registry before
/// TxB. It owns namespace/account backing but has no original client attempt
/// and exposes no completion or activation operation.
pub(crate) struct VerifiedLiveTunnelRegistration {
    pending: PendingDirectAdmission,
}
impl VerifiedLiveTunnelRegistration {
    pub(crate) fn account(&self) -> &ResourceAccount {
        &self.pending.account
    }
    pub(crate) fn artifact_digest(&self) -> [u8; 32] {
        self.pending.artifact_digest
    }
    pub(crate) fn candidate_id(&self) -> [u8; 16] {
        self.pending.candidate_id
    }
    pub(crate) fn route_digest(&self) -> [u8; 32] {
        self.pending.route_digest
    }
}
pub(crate) fn reserve_live_tunnel_registration(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: DirectCredentialInput<'_>,
    activation_signing_key_id: &str,
) -> Result<VerifiedLiveTunnelRegistration, EnvironmentError> {
    let pending = reserve_live_preparation(
        environment,
        verifiers,
        input,
        [0; 16],
        activation_signing_key_id,
        1,
        true,
    )?;
    Ok(VerifiedLiveTunnelRegistration { pending })
}
/// Private B publication custody. The registration itself remains a zero-
/// attempt observation and cannot complete or activate any client connection.
/// Only this separately retained original server publication can consume its
/// actual signed server delivery into a role-1 admission on the same Account.
pub(crate) struct OriginalLiveTunnelServerRegistration {
    registration: VerifiedLiveTunnelRegistration,
    signing_keys: Vec<OriginalLiveActivationSigner>,
    _signing_storage: crate::environment_v4::ResourceCharge,
}
struct OriginalLiveActivationSigner {
    key: String,
    delegation: Vec<u8>,
}
impl OriginalLiveTunnelServerRegistration {
    pub(crate) fn registration(&self) -> &VerifiedLiveTunnelRegistration {
        &self.registration
    }
    pub(crate) fn restrict_signer(&mut self, key: &str) -> Result<(), EnvironmentError> {
        self.registration.account().check()?;
        if !self
            .signing_keys
            .iter()
            .any(|installed| installed.key == key)
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        self.signing_keys.retain(|installed| installed.key == key);
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Credential verification requires the original parent bindings, validity interval and reusable scratch together."
    )]
    pub(crate) fn consume_server_delivery(
        mut self,
        environment: &Arc<EnvironmentRoot>,
        verifiers: &[&NamespaceVerifier],
        artifact: &[u8],
        client: &[u8],
        server: &[u8],
        proof: &[u8],
        grant: &[u8],
        relay: &[u8],
        service: &str,
        audience: &str,
    ) -> Result<CredentialAdmission, EnvironmentError> {
        self.registration.account().check()?;
        let proof_view = decode(
            proof,
            "ActivationAuthorization",
            ACTIVATION_BYTES,
            Context::with_activation_source(ActivationSource::LiveAuthority),
        )?;
        let key = text(proof_view, "ActivationAuthorization", "signing_key_id")?;
        let installed = self
            .signing_keys
            .iter()
            .find(|installed| installed.key == key)
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        let delegation = decode(
            &installed.delegation,
            "ConnectionActivationDelegation",
            8192,
            Context::default(),
        )?;
        let issued = uint(proof_view, "ActivationAuthorization", "issued_at_ms")?;
        if text(proof_view, "ActivationAuthorization", "authority_id")?
            != text(delegation, "ConnectionActivationDelegation", "authority_id")?
            || issued
                < uint(
                    delegation,
                    "ConnectionActivationDelegation",
                    "signing_not_before_ms",
                )?
            || issued
                >= uint(
                    delegation,
                    "ConnectionActivationDelegation",
                    "signing_not_after_ms",
                )?
            || uint(
                proof_view,
                "ActivationAuthorization",
                "activation_not_after_ms",
            )? > uint(
                delegation,
                "ConnectionActivationDelegation",
                "max_activation_not_after_ms",
            )?
            || uint(
                proof_view,
                "ActivationAuthorization",
                "session_not_after_ms",
            )? > uint(
                delegation,
                "ConnectionActivationDelegation",
                "max_session_not_after_ms",
            )?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        codec::verify_signature(
            "ActivationAuthorization",
            proof_view,
            &bytes(
                delegation,
                "ConnectionActivationDelegation",
                "signer_public_key",
            )?,
            &mut self.registration.pending.signature,
        )
        .map_err(invalid)?;
        // Trust refresh may tighten or retire this original delegation. It may
        // not reinterpret its frozen key ID as a different signer or authority.
        let artifact_view = decode(artifact, "Artifact", ARTIFACT_BYTES, Context::default())?;
        let context = NamespaceContext::resolve(
            environment,
            verifiers,
            artifact_view,
            "Artifact",
            environment.sample()?,
        )?;
        let mut original_signer = false;
        'history: for history in context.verifier.history.iter().rev() {
            let trust = decode(
                history,
                "TrustConfig",
                super::TRUST_BYTES,
                Context::default(),
            )?;
            for current in trust
                .field("TrustConfig", "activation_delegations")
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let current = current.map_err(invalid)?;
                let schema = "ConnectionActivationDelegation";
                if text(current, schema, "signing_key_id")? != key {
                    continue;
                }
                for field in [
                    "issuer_key_id",
                    "signer_public_key",
                    "authority_id",
                    "artifact_issuer_key_id",
                ] {
                    if current.field(schema, field).map_err(invalid)?.raw()
                        != delegation.field(schema, field).map_err(invalid)?.raw()
                    {
                        return Err(EnvironmentError::AuthorizationDenied);
                    }
                }
                original_signer = true;
                break 'history;
            }
        }
        if !original_signer {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        self.registration.pending.activation_signing_key_id = key.to_owned();
        self.registration.pending.complete_tunnel_for_role(
            environment,
            verifiers,
            artifact,
            client,
            server,
            proof,
            grant,
            relay,
            service,
            audience,
            1,
        )
    }
}
pub(crate) fn reserve_original_live_tunnel_server_registration(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: DirectCredentialInput<'_>,
    signing_key: Option<&str>,
) -> Result<OriginalLiveTunnelServerRegistration, EnvironmentError> {
    let mut work = environment.reserve_environment(ResourceLimits {
        sdk_bytes: 196608,
        items: 20,
        work_slots: 2,
        ..ResourceLimits::default()
    })?;
    let now = environment.sample()?;
    let artifact = decode(
        input.artifact,
        "Artifact",
        ARTIFACT_BYTES,
        Context::default(),
    )?;
    let context = NamespaceContext::resolve(environment, verifiers, artifact, "Artifact", now)?;
    let issuer = bytes::<16>(artifact, "Artifact", "issuer_key_id")?;
    let parent_end = uint(artifact, "Artifact", "session_not_after_ms")?;
    let cohort = context.issuance(artifact, "Artifact", CredentialKind::Connection, parent_end)?;
    let mut signing_keys: Vec<OriginalLiveActivationSigner> = Vec::with_capacity(16);
    for history in context.verifier.history.iter().rev() {
        let trust = decode(
            history,
            "TrustConfig",
            super::TRUST_BYTES,
            Context::default(),
        )?;
        for entry in trust
            .field("TrustConfig", "activation_delegations")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let entry = entry.map_err(invalid)?;
            let schema = "ConnectionActivationDelegation";
            let key = text(entry, schema, "signing_key_id")?;
            if signing_key.is_some_and(|installed| installed != key)
                || signing_keys.iter().any(|installed| installed.key == key)
                || bytes::<16>(entry, schema, "artifact_issuer_key_id")? != issuer
                || uint(entry, schema, "purpose")? != 1
                || now.lower_ms < uint(entry, schema, "signing_not_before_ms")?
                || now.upper_ms >= uint(entry, schema, "signing_not_after_ms")?
                || cohort < uint(entry, schema, "first_parent_cohort")?
                || cohort > uint(entry, schema, "last_parent_cohort")?
                || context.is_retired(bytes(entry, schema, "issuer_key_id")?)?
            {
                continue;
            }
            if signing_keys.len() == 16 {
                return Err(EnvironmentError::Capacity);
            }
            if entry.raw().len() > 8192 {
                return Err(EnvironmentError::Capacity);
            }
            signing_keys.push(OriginalLiveActivationSigner {
                key: key.to_owned(),
                delegation: entry.raw().to_vec(),
            });
        }
    }
    let key = signing_keys
        .first()
        .ok_or(EnvironmentError::AuthorizationDenied)?;
    let registration = reserve_live_tunnel_registration(environment, verifiers, input, &key.key)?;
    let signing_storage = work.attach(registration.account())?;
    Ok(OriginalLiveTunnelServerRegistration {
        registration,
        signing_keys,
        _signing_storage: signing_storage,
    })
}
fn reserve_live_preparation(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: DirectCredentialInput<'_>,
    attempt_id: [u8; 16],
    activation_signing_key_id: &str,
    expected_path_kind: u8,
    registration_only: bool,
) -> Result<PendingDirectAdmission, EnvironmentError> {
    if input.source != ActivationSource::LiveAuthority
        || !input.activation.is_empty()
        || registration_only != (attempt_id == [0; 16])
        || registration_only && expected_path_kind != 1
        || activation_signing_key_id.is_empty()
        || activation_signing_key_id.len() > 128
        || !activation_signing_key_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err(EnvironmentError::Configuration);
    }
    let verifier_limit = if expected_path_kind == 1 { 8 } else { 3 };
    if verifiers.is_empty() || verifiers.len() > verifier_limit {
        return Err(EnvironmentError::Configuration);
    }
    for (i, verifier) in verifiers.iter().enumerate() {
        if !Arc::ptr_eq(environment, &verifier.environment)
            || verifiers[..i].iter().any(|old| old.key == verifier.key)
        {
            return Err(EnvironmentError::Configuration);
        }
    }
    // All inputs remain borrowed. Reserve every copied signature/projection
    // byte before allocation; the Artifact signature scratch contains its PSK
    // and is zeroized when this original synchronous verification exits.
    let mut original_work = environment.reserve_environment(ResourceLimits {
        sdk_bytes: (2 * ARTIFACT_BYTES + SET_BYTES + 8192) as u64,
        items: 1,
        work_slots: 1,
        ..ResourceLimits::default()
    })?;
    let mut signature = Zeroizing::new(Vec::new());
    signature
        .try_reserve_exact(ARTIFACT_BYTES + 128)
        .map_err(|_| EnvironmentError::Capacity)?;
    let mut route_scratch = Vec::new();
    route_scratch
        .try_reserve_exact(ARTIFACT_BYTES)
        .map_err(|_| EnvironmentError::Capacity)?;
    let mut set_scratch = Vec::new();
    set_scratch
        .try_reserve_exact(SET_BYTES)
        .map_err(|_| EnvironmentError::Capacity)?;
    let now = environment.sample()?;
    let artifact = decode(
        input.artifact,
        "Artifact",
        ARTIFACT_BYTES,
        Context::default(),
    )?;
    let artifact_digest = codec::digest("artifact_digest", artifact).map_err(invalid)?;
    let parent_context =
        NamespaceContext::resolve(environment, verifiers, artifact, "Artifact", now)?;
    let issued = uint(artifact, "Artifact", "issued_at_ms")?;
    let initiation = uint(artifact, "Artifact", "initiation_not_after_ms")?;
    let parent_end = uint(artifact, "Artifact", "session_not_after_ms")?;
    super::interval(now, issued, initiation)?;
    let parent_cohort =
        parent_context.issuance(artifact, "Artifact", CredentialKind::Connection, parent_end)?;
    let issuer = parent_context.verify_issuer(
        artifact,
        "Artifact",
        1,
        parent_cohort,
        parent_end,
        &mut signature,
    )?;
    let parent = parent_context.binding(
        artifact,
        "Artifact",
        CredentialKind::Connection,
        parent_cohort,
        artifact_digest,
        issuer,
    )?;
    let candidate = artifact
        .field("Artifact", "candidates")
        .and_then(|v| v.at(input.candidate_index as usize))
        .map_err(invalid)?;
    if uint(candidate, "Candidate", "path_kind")? != u64::from(expected_path_kind) {
        return Err(EnvironmentError::Configuration);
    }
    let client = decode(
        input.client_certificate,
        "IdentityCertificate",
        CERTIFICATE_BYTES,
        Context::default(),
    )?;
    let server = decode(
        input.server_certificate,
        "IdentityCertificate",
        CERTIFICATE_BYTES,
        Context::default(),
    )?;
    let client_context =
        NamespaceContext::resolve(environment, verifiers, client, "IdentityCertificate", now)?;
    let server_context =
        NamespaceContext::resolve(environment, verifiers, server, "IdentityCertificate", now)?;
    let (client_binding, client_start, client_end) =
        verify_certificate(client_context, client, artifact, 0, now, &mut signature)?;
    let (server_binding, server_start, server_end) =
        verify_certificate(server_context, server, artifact, 1, now, &mut signature)?;
    if expected_path_kind == 0 {
        check_direct_closure(candidate, [parent_context, client_context, server_context])?;
    } else {
        // Before TxB the relay namespace is intentionally unavailable. Verify
        // every endpoint reference that is already attributable to the parent
        // and endpoint identities; the relay reference is closed later by the
        // signed Grant in the same original continuation.
        let refs = candidate
            .field("Candidate", "revocation_namespace_refs")
            .map_err(invalid)?;
        for reference in refs.children().map_err(invalid)? {
            let reference = reference.map_err(invalid)?;
            let mask = uint(reference, "RevocationNamespaceRef", "role_mask")?;
            if mask & 3 == 0 {
                continue;
            }
            let wanted = namespace(reference, "RevocationNamespaceRef")?;
            let contexts = [parent_context, client_context, server_context];
            let context = contexts
                .iter()
                .find(|context| context.verifier.key == wanted)
                .ok_or(EnvironmentError::AuthorizationDenied)?;
            if bytes::<32>(
                reference,
                "RevocationNamespaceRef",
                "namespace_capacity_digest",
            )? != context.capacity_digest
                || uint(reference, "RevocationNamespaceRef", "generation")? != context.generation
                || mask & 3 != 3
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
    }
    let route = route_digest(candidate, &mut route_scratch)?;
    // Independently configured signing authority is resolved before TxB.
    // Neither an activation sample nor a successful network reply creates it.
    let mut delegated = false;
    for original in parent_context.verifier.history.iter().rev() {
        let trust = decode(
            original,
            "TrustConfig",
            super::TRUST_BYTES,
            Context::default(),
        )?;
        for entry in trust
            .field("TrustConfig", "activation_delegations")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let entry = entry.map_err(invalid)?;
            let schema = "ConnectionActivationDelegation";
            if text(entry, schema, "signing_key_id")? != activation_signing_key_id {
                continue;
            }
            let signer = bytes(entry, schema, "issuer_key_id")?;
            if parent_context.is_retired(signer)?
                || uint(entry, schema, "purpose")? != 1
                || bytes::<16>(entry, schema, "artifact_issuer_key_id")? != issuer
                || now.lower_ms < uint(entry, schema, "signing_not_before_ms")?
                || now.upper_ms >= uint(entry, schema, "signing_not_after_ms")?
                || parent.cohort < uint(entry, schema, "first_parent_cohort")?
                || parent.cohort > uint(entry, schema, "last_parent_cohort")?
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            delegated = true;
            break;
        }
        if delegated {
            break;
        }
    }
    if !delegated {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let account = environment.admit(
        parent.namespace.tenant,
        AuthorizationBounds {
            not_before_ms: issued.max(client_start).max(server_start),
            not_after_ms: parent_end.min(client_end).min(server_end),
            freshness_not_after_ms: initiation,
        },
    )?;
    let mut bindings = [parent, client_binding, server_binding];
    let mut count = 0;
    for binding in [parent, client_binding, server_binding] {
        if !bindings[..count].contains(&binding) {
            bindings[count] = binding;
            count += 1;
        }
    }
    account.bind_namespaces(&bindings[..count])?;
    let verification = original_work.attach(&account)?;
    account.check()?;
    Ok(PendingDirectAdmission {
        account,
        artifact_digest,
        certificate_digests: [client_binding.credential, server_binding.credential],
        candidate_id: bytes(candidate, "Candidate", "candidate_id")?,
        route_digest: route,
        candidate_index: input.candidate_index,
        attempt_id,
        initiation_not_after_ms: initiation,
        path_kind: expected_path_kind,
        parent,
        activation_signing_key_id: activation_signing_key_id.to_owned(),
        signature,
        route_scratch,
        set_scratch,
        _verification: verification,
    })
}
impl PendingDirectAdmission {
    pub(crate) fn complete(
        mut self,
        environment: &Arc<EnvironmentRoot>,
        verifiers: &[&NamespaceVerifier],
        artifact_bytes: &[u8],
        proof: &[u8],
    ) -> Result<CredentialAdmission, EnvironmentError> {
        self.account.check()?;
        if !self.account.belongs_to(environment)
            || verifiers.is_empty()
            || verifiers.len() > 3
            || verifiers
                .iter()
                .any(|verifier| !Arc::ptr_eq(environment, &verifier.environment))
        {
            return Err(EnvironmentError::Configuration);
        }
        let now = environment.sample()?;
        let artifact = decode(
            artifact_bytes,
            "Artifact",
            ARTIFACT_BYTES,
            Context::default(),
        )?;
        if codec::digest("artifact_digest", artifact).map_err(invalid)? != self.artifact_digest {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let context = NamespaceContext::resolve(environment, verifiers, artifact, "Artifact", now)?;
        let activation = decode(
            proof,
            "ActivationAuthorization",
            ACTIVATION_BYTES,
            Context::with_activation_source(ActivationSource::LiveAuthority),
        )?;
        if text(activation, "ActivationAuthorization", "signing_key_id")?
            != self.activation_signing_key_id
            || bytes::<16>(activation, "ActivationAuthorization", "attempt_id")? != self.attempt_id
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let (binding, start, activation_end, session_end) = verify_activation(
            context,
            artifact,
            activation,
            ActivationSource::LiveAuthority,
            self.artifact_digest,
            self.parent,
            now,
            &mut self.signature,
        )?;
        verify_selection(
            activation,
            artifact,
            ActivationSource::LiveAuthority,
            self.candidate_index,
            None,
            self.route_digest,
            (&mut self.route_scratch, &mut self.set_scratch),
        )?;
        let candidate = artifact
            .field("Artifact", "candidates")
            .and_then(|candidates| candidates.at(self.candidate_index as usize))
            .map_err(invalid)?;
        if bytes::<16>(candidate, "Candidate", "candidate_id")? != self.candidate_id {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let initiation = self.initiation_not_after_ms.min(activation_end);
        super::interval(environment.sample()?, start, initiation)?;
        self.account.install_live_activation(
            binding,
            AuthorizationBounds {
                not_before_ms: start,
                not_after_ms: session_end,
                freshness_not_after_ms: initiation,
            },
        )?;
        Ok(CredentialAdmission {
            account: self.account,
            artifact_digest: self.artifact_digest,
            certificate_digests: self.certificate_digests,
            activation_digest: codec::digest("activation_digest", activation).map_err(invalid)?,
            candidate_id: self.candidate_id,
            route_digest: self.route_digest,
            attempt_id: self.attempt_id,
            initiation_not_after_ms: initiation,
            source: ActivationSource::LiveAuthority,
            pool: None,
            pool_activation: None,
            tunnel: None,
        })
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Credential verification requires the original parent bindings, validity interval and reusable scratch together."
    )]
    pub(crate) fn complete_tunnel(
        self,
        environment: &Arc<EnvironmentRoot>,
        verifiers: &[&NamespaceVerifier],
        artifact_bytes: &[u8],
        client_certificate: &[u8],
        server_certificate: &[u8],
        proof: &[u8],
        grant: &[u8],
        relay_certificate: &[u8],
        service: &str,
        audience: &str,
    ) -> Result<CredentialAdmission, EnvironmentError> {
        self.complete_tunnel_for_role(
            environment,
            verifiers,
            artifact_bytes,
            client_certificate,
            server_certificate,
            proof,
            grant,
            relay_certificate,
            service,
            audience,
            0,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Credential verification requires the original parent bindings, validity interval and reusable scratch together."
    )]
    fn complete_tunnel_for_role(
        mut self,
        environment: &Arc<EnvironmentRoot>,
        verifiers: &[&NamespaceVerifier],
        artifact_bytes: &[u8],
        client_certificate: &[u8],
        server_certificate: &[u8],
        proof: &[u8],
        grant: &[u8],
        relay_certificate: &[u8],
        service: &str,
        audience: &str,
        role: u8,
    ) -> Result<CredentialAdmission, EnvironmentError> {
        self.account.check()?;
        if role > 1 || (role == 1) != (self.attempt_id == [0; 16]) {
            return Err(EnvironmentError::Configuration);
        }
        if self.path_kind != 1
            || !self.account.belongs_to(environment)
            || verifiers.is_empty()
            || verifiers.len() > 8
            || verifiers
                .iter()
                .any(|verifier| !Arc::ptr_eq(environment, &verifier.environment))
        {
            return Err(EnvironmentError::Configuration);
        }
        let now = environment.sample()?;
        let artifact = decode(
            artifact_bytes,
            "Artifact",
            ARTIFACT_BYTES,
            Context::default(),
        )?;
        if codec::digest("artifact_digest", artifact).map_err(invalid)? != self.artifact_digest {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let parent_context =
            NamespaceContext::resolve(environment, verifiers, artifact, "Artifact", now)?;
        let client = decode(
            client_certificate,
            "IdentityCertificate",
            CERTIFICATE_BYTES,
            Context::default(),
        )?;
        let server = decode(
            server_certificate,
            "IdentityCertificate",
            CERTIFICATE_BYTES,
            Context::default(),
        )?;
        let client_context =
            NamespaceContext::resolve(environment, verifiers, client, "IdentityCertificate", now)?;
        let server_context =
            NamespaceContext::resolve(environment, verifiers, server, "IdentityCertificate", now)?;
        let (client_binding, client_start, client_end) = verify_certificate(
            client_context,
            client,
            artifact,
            0,
            now,
            &mut self.signature,
        )?;
        let (server_binding, server_start, server_end) = verify_certificate(
            server_context,
            server,
            artifact,
            1,
            now,
            &mut self.signature,
        )?;
        if client_binding.credential != self.certificate_digests[0]
            || server_binding.credential != self.certificate_digests[1]
            || parent_context.verifier.key != self.parent.namespace
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let candidate = artifact
            .field("Artifact", "candidates")
            .and_then(|candidates| candidates.at(self.candidate_index as usize))
            .map_err(invalid)?;
        let activation = decode(
            proof,
            "ActivationAuthorization",
            ACTIVATION_BYTES,
            Context::with_activation_source(ActivationSource::LiveAuthority),
        )?;
        let actual_attempt = bytes::<16>(activation, "ActivationAuthorization", "attempt_id")?;
        if text(activation, "ActivationAuthorization", "signing_key_id")?
            != self.activation_signing_key_id
            || actual_attempt == [0; 16]
            || role == 0 && actual_attempt != self.attempt_id
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let (binding, start, activation_end, session_end) = verify_activation(
            parent_context,
            artifact,
            activation,
            ActivationSource::LiveAuthority,
            self.artifact_digest,
            self.parent,
            now,
            &mut self.signature,
        )?;
        verify_selection(
            activation,
            artifact,
            ActivationSource::LiveAuthority,
            self.candidate_index,
            None,
            self.route_digest,
            (&mut self.route_scratch, &mut self.set_scratch),
        )?;
        if bytes::<16>(candidate, "Candidate", "candidate_id")? != self.candidate_id {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let refs: Vec<_> = verifiers.iter().map(|verifier| &**verifier).collect();
        let hop = tunnel::verify_endpoint_hop(
            environment,
            &refs,
            tunnel::TunnelHopInput {
                grant,
                relay_certificate,
                endpoint_role: role,
                service,
                audience,
            },
            artifact,
            candidate,
            [parent_context, client_context, server_context],
            [self.parent, client_binding, server_binding],
            [client, server],
            now,
            &mut self.signature,
            &mut self.route_scratch,
        )?;
        if hop.facts.attempt_id != actual_attempt {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        // Each original endpoint delivery carries only its own signed Grant.
        // Role 0 completes the original client attempt; role 1 completes the
        // retained zero-attempt server registration with that delivery's actual
        // attempt. The relay verifies the matching two-leg projection.
        let initiation = self
            .initiation_not_after_ms
            .min(activation_end)
            .min(hop.not_after_ms);
        super::interval(
            environment.sample()?,
            start
                .max(client_start)
                .max(server_start)
                .max(hop.not_before_ms),
            initiation,
        )?;
        let bounds = AuthorizationBounds {
            not_before_ms: start
                .max(client_start)
                .max(server_start)
                .max(hop.not_before_ms),
            not_after_ms: session_end
                .min(client_end)
                .min(server_end)
                .min(hop.not_after_ms),
            freshness_not_after_ms: initiation,
        };
        self.account.install_live_activation(binding, bounds)?;
        // The original preparation already subscribed this Account to its
        // parent and endpoint certificates. Add only the independently verified
        // Grant/relay dependencies; rebinding would replace its original owner.
        let mut added = Vec::with_capacity(2);
        for dependency in hop.bindings {
            if [self.parent, client_binding, server_binding, binding].contains(&dependency)
                || added.contains(&dependency)
            {
                continue;
            }
            self.account.install_live_activation(dependency, bounds)?;
            added.push(dependency);
        }
        Ok(CredentialAdmission {
            account: self.account,
            artifact_digest: self.artifact_digest,
            certificate_digests: self.certificate_digests,
            activation_digest: codec::digest("activation_digest", activation).map_err(invalid)?,
            candidate_id: self.candidate_id,
            route_digest: self.route_digest,
            attempt_id: actual_attempt,
            initiation_not_after_ms: initiation,
            source: ActivationSource::LiveAuthority,
            pool: None,
            pool_activation: None,
            tunnel: Some(hop.facts),
        })
    }
}

#[cfg(test)]
#[path = "credential_verifier_v4_tests.rs"]
pub(crate) mod tests;
