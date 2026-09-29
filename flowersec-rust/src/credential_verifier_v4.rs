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
            || uint(credential, schema, "revocation_authority_generation")? != generation
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
    let schema = "IdentityCertificate";
    for field in ["tenant_id", "audience", "crypto_profile_id"] {
        if text(certificate, schema, field)? != text(artifact, "Artifact", field)? {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    if uint(certificate, schema, "role")? != role {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let digest = codec::digest("certificate_digest", certificate).map_err(invalid)?;
    let wanted = if role == 0 {
        "client_identity_digest"
    } else {
        "server_identity_digest"
    };
    if digest != bytes(artifact, "Artifact", wanted)? {
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
    authority: Value<'_>,
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

fn verify_activation(
    context: NamespaceContext<'_>,
    artifact: Value<'_>,
    activation: Value<'_>,
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
    let authority = once_authority(context, parent.issuer)?;
    if text(activation, schema, "authority_id")?
        != text(authority, "OnceAuthorityRef", "spend_authority_id")?
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let issued = uint(activation, schema, "issued_at_ms")?;
    let initiation = uint(activation, schema, "activation_not_after_ms")?;
    let end = uint(activation, schema, "session_not_after_ms")?;
    super::interval(now, issued, initiation)?;
    if issued < uint(artifact, "Artifact", "issued_at_ms")?
        || initiation > uint(artifact, "Artifact", "initiation_not_after_ms")?
        || end > uint(artifact, "Artifact", "session_not_after_ms")?
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
    if verifiers.is_empty() || verifiers.len() > 3 {
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
    if uint(candidate, "Candidate", "path_kind")? != 0 {
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
    check_direct_closure(candidate, [parent_context, client_context, server_context])?;
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
        once_authority(parent_context, issuer)?,
        route,
        (&mut route_scratch, &mut set_scratch),
    )?;
    let initiation = initiation.min(activation_end);
    let account = environment.admit(
        parent.namespace.tenant,
        AuthorizationBounds {
            not_before_ms: issued
                .max(client_start)
                .max(server_start)
                .max(activation_start),
            not_after_ms: session_end.min(client_end).min(server_end),
            freshness_not_after_ms: initiation,
        },
    )?;
    let mut bindings = [parent, client_binding, server_binding, activation_binding];
    let mut count = 0;
    for binding in [parent, client_binding, server_binding, activation_binding] {
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
    })
}

#[cfg(test)]
#[path = "credential_verifier_v4_tests.rs"]
pub(crate) mod tests;
