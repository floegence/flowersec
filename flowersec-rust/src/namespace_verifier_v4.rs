//! Namespace verification belongs to the original Environment and independent
//! trust root. No public assertion can mint a verified update.

use super::{CredentialKind, Denial, Head, NamespaceAnchor, NamespaceKey, VerifiedNamespaceUpdate};
use crate::{
    codec_v4::{self as codec, Limits, StateLimits, Value},
    environment_v4::{
        EnvironmentCharge, EnvironmentError, EnvironmentRoot, ResourceLimits, TrustedTimeSample,
    },
};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

const TRUST_BYTES: usize = 262_144;
const RESPONSE_BYTES: usize = 270_336;
const MAX_HISTORY: usize = 8;

#[path = "credential_verifier_v4.rs"]
pub(crate) mod credential;

#[derive(Clone, Debug)]
pub struct NamespaceTrustRoot {
    pub tenant: String,
    pub authority: String,
    pub key_id: [u8; 16],
    pub public_key: [u8; 32],
    pub max_lifetime_ms: u64,
}
#[derive(Debug)]
pub(crate) struct NamespaceVerifier {
    environment: Arc<EnvironmentRoot>,
    root: NamespaceTrustRoot,
    owner: Arc<AtomicBool>,
    key: NamespaceKey,
    state_bytes: usize,
    node_cap: usize,
    history: Vec<Box<[u8]>>,
    signature_input: Vec<u8>,
    nonce: [u8; 32],
    bootstrap_deadline: Instant,
    bootstrap_end: u64,
    bootstrapped: bool,
    previous: Vec<u8>,
    _charge: EnvironmentCharge,
}
fn invalid(_: codec::Error) -> EnvironmentError {
    EnvironmentError::AuthorizationDenied
}
fn raw_copy(input: &[u8]) -> Result<Box<[u8]>, EnvironmentError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(input.len())
        .map_err(|_| EnvironmentError::Capacity)?;
    copy.extend_from_slice(input);
    Ok(copy.into_boxed_slice())
}
fn key(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}
fn interval(now: TrustedTimeSample, start: u64, end: u64) -> Result<(), EnvironmentError> {
    if start >= end || now.upper_ms >= end {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    if now.lower_ms < start {
        return Err(EnvironmentError::TimePending);
    }
    Ok(())
}
fn decode<'a>(
    input: &'a [u8],
    name: &str,
    bytes: usize,
    nodes: usize,
    state: Option<StateLimits>,
) -> Result<Value<'a>, EnvironmentError> {
    codec::decode(input, name, Limits { bytes, nodes }, state).map_err(invalid)
}
impl NamespaceVerifier {
    pub(crate) fn new(
        environment: Arc<EnvironmentRoot>,
        root: NamespaceTrustRoot,
        state_bytes: usize,
        node_cap: usize,
    ) -> Result<Self, EnvironmentError> {
        let valid_id = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:/@-".contains(&b))
        };
        if !valid_id(&root.tenant)
            || !valid_id(&root.authority)
            || root.key_id == [0; 16]
            || root.public_key == [0; 32]
            || root.max_lifetime_ms == 0
            || state_bytes == 0
            || state_bytes > 1 << 24
            || node_cap == 0
            || node_cap > 1 << 20
        {
            return Err(EnvironmentError::Configuration);
        }
        let bytes = (MAX_HISTORY * TRUST_BYTES
            + RESPONSE_BYTES
            + 128
            + state_bytes
            + std::mem::size_of::<Self>()) as u64;
        let charge = environment.reserve_environment(ResourceLimits {
            sdk_bytes: bytes,
            items: (MAX_HISTORY + 3) as u64,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let now = environment.sample()?;
        let bootstrap_end = now
            .lower_ms
            .checked_add(90_000)
            .ok_or(EnvironmentError::TimeUnavailable)?;
        let bootstrap_deadline = Instant::now()
            .checked_add(Duration::from_secs(89))
            .ok_or(EnvironmentError::TimeUnavailable)?;
        let mut nonce = [0; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
            .map_err(|_| EnvironmentError::TimeUnavailable)?;
        let mut signature_input = Vec::new();
        signature_input
            .try_reserve_exact(RESPONSE_BYTES + 128)
            .map_err(|_| EnvironmentError::Capacity)?;
        let mut previous = Vec::new();
        previous
            .try_reserve_exact(state_bytes)
            .map_err(|_| EnvironmentError::Capacity)?;
        let mut history = Vec::new();
        history
            .try_reserve_exact(MAX_HISTORY)
            .map_err(|_| EnvironmentError::Capacity)?;
        let key = NamespaceKey {
            tenant: key(&root.tenant),
            authority: key(&root.authority),
        };
        let owner = Arc::new(AtomicBool::new(false));
        environment.claim_namespace_verifier(key, &owner)?;
        Ok(Self {
            environment,
            root,
            owner,
            key,
            state_bytes,
            node_cap,
            history,
            signature_input,
            nonce,
            bootstrap_deadline,
            bootstrap_end,
            bootstrapped: false,
            previous,
            _charge: charge,
        })
    }
    pub(crate) fn bootstrap_nonce(&self) -> [u8; 32] {
        self.nonce
    }
    fn check(&self) -> Result<TrustedTimeSample, EnvironmentError> {
        if self.owner.load(Ordering::Acquire) {
            return Err(EnvironmentError::Closed);
        }
        self.environment.sample()
    }
    /// The original nonce-bound authority response authenticates startup
    /// freshness. A cached TrustConfig/Head pair alone cannot bootstrap.
    pub(crate) fn bootstrap(
        &mut self,
        response: &[u8],
        state: &[u8],
    ) -> Result<(), EnvironmentError> {
        let now = self.check()?;
        if self.bootstrapped
            || Instant::now() >= self.bootstrap_deadline
            || now.upper_ms >= self.bootstrap_end
        {
            return Err(EnvironmentError::Closed);
        }
        let response = decode(
            response,
            "TrustBootstrapResponse",
            RESPONSE_BYTES,
            self.node_cap,
            None,
        )?;
        codec::verify_signature(
            "TrustBootstrapResponse",
            response,
            &self.root.public_key,
            &mut self.signature_input,
        )
        .map_err(invalid)?;
        self.check_root(response, "TrustBootstrapResponse")?;
        if response
            .b::<32>("TrustBootstrapResponse", "request_nonce")
            .map_err(invalid)?
            != self.nonce
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        interval(
            now,
            response
                .u("TrustBootstrapResponse", "issued_at_ms")
                .map_err(invalid)?,
            response
                .u("TrustBootstrapResponse", "not_after_ms")
                .map_err(invalid)?
                .min(self.bootstrap_end),
        )?;
        let trust = response
            .field("TrustBootstrapResponse", "trust_config")
            .and_then(Value::bytes)
            .map_err(invalid)?;
        let head = response
            .field("TrustBootstrapResponse", "freshness_head")
            .and_then(Value::bytes)
            .map_err(invalid)?;
        self.update_trust(trust, now)?;
        let update = self.verify_pair(head, state, now)?;
        self.environment
            .install_verified_namespace(&update, &self.owner)?;
        self.previous.clear();
        self.previous.extend_from_slice(state);
        self.bootstrapped = true;
        self.nonce.fill(0);
        Ok(())
    }
    pub(crate) fn refresh(
        &mut self,
        trust: Option<&[u8]>,
        head: &[u8],
        state: &[u8],
    ) -> Result<(), EnvironmentError> {
        let now = self.check()?;
        if !self.bootstrapped {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        if let Some(trust) = trust {
            self.update_trust(trust, now)?;
        }
        let update = self.verify_pair(head, state, now)?;
        self.environment
            .install_verified_namespace(&update, &self.owner)?;
        self.previous.clear();
        self.previous.extend_from_slice(state);
        Ok(())
    }
    fn check_root(&self, value: Value<'_>, schema: &str) -> Result<(), EnvironmentError> {
        if value
            .field(schema, "tenant_id")
            .and_then(Value::text)
            .map_err(invalid)?
            != self.root.tenant
            || value
                .field(schema, "revocation_authority_id")
                .and_then(Value::text)
                .map_err(invalid)?
                != self.root.authority
            || value.b::<16>(schema, "signing_key_id").map_err(invalid)? != self.root.key_id
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        Ok(())
    }
    fn update_trust(
        &mut self,
        bytes: &[u8],
        now: TrustedTimeSample,
    ) -> Result<(), EnvironmentError> {
        if self.history.last().is_some_and(|old| old.as_ref() == bytes) {
            let old = decode(bytes, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            return interval(
                now,
                old.u("TrustConfig", "issued_at_ms").map_err(invalid)?,
                old.u("TrustConfig", "not_after_ms").map_err(invalid)?,
            );
        }
        if self.history.len() == MAX_HISTORY {
            return Err(EnvironmentError::Capacity);
        }
        let trust = decode(bytes, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
        codec::verify_signature(
            "TrustConfig",
            trust,
            &self.root.public_key,
            &mut self.signature_input,
        )
        .map_err(invalid)?;
        self.check_root(trust, "TrustConfig")?;
        let issued = trust.u("TrustConfig", "issued_at_ms").map_err(invalid)?;
        let end = trust.u("TrustConfig", "not_after_ms").map_err(invalid)?;
        interval(now, issued, end)?;
        if end - issued > self.root.max_lifetime_ms {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let capacity = trust.field("TrustConfig", "capacity").map_err(invalid)?;
        let generation = trust
            .u("TrustConfig", "authority_generation")
            .map_err(invalid)?;
        if generation == 0 {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        self.capacity_limits(capacity)?;
        if let Some(previous) = self.history.last() {
            let old = decode(previous, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            if generation
                != old
                    .u("TrustConfig", "authority_generation")
                    .map_err(invalid)?
            {
                self.owner.store(true, Ordering::Release);
                let _ = self.environment.terminate_namespace(self.key);
                return Err(EnvironmentError::AuthorizationDenied);
            }
            if trust.u("TrustConfig", "revision").map_err(invalid)?
                <= old.u("TrustConfig", "revision").map_err(invalid)?
                || issued < old.u("TrustConfig", "issued_at_ms").map_err(invalid)?
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            for field in ["capacity", "publication"] {
                if trust.field("TrustConfig", field).map_err(invalid)?.raw()
                    != old.field("TrustConfig", field).map_err(invalid)?.raw()
                {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
            }
            self.check_trust_history(trust)?;
        }
        let capacity_digest =
            codec::digest("namespace_capacity_digest", capacity).map_err(invalid)?;
        self.check_issuer_history(trust)?;
        for (field, schema) in [
            ("issuer_authorizations", "CredentialIssuerAuthorization"),
            ("head_delegations", "HeadSignerDelegation"),
            ("activation_delegations", "ConnectionActivationDelegation"),
        ] {
            for entry in trust
                .field("TrustConfig", field)
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                self.check_namespace(entry, schema, capacity_digest, generation)?;
                if schema == "HeadSignerDelegation" {
                    self.check_publication(
                        entry,
                        schema,
                        trust.field("TrustConfig", "publication").map_err(invalid)?,
                    )?;
                }
            }
        }
        let total = self
            .history
            .iter()
            .try_fold(bytes.len() as u64, |n, b| n.checked_add(b.len() as u64))
            .ok_or(EnvironmentError::Capacity)?;
        if total
            > capacity
                .u("NamespaceCapacity", "max_trust_proof_bytes")
                .map_err(invalid)?
        {
            return Err(EnvironmentError::Capacity);
        }
        let mut entries = 0u64;
        for original in self
            .history
            .iter()
            .map(|b| b.as_ref())
            .chain(std::iter::once(bytes))
        {
            let original = decode(original, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            for field in [
                "credential_policies",
                "issuer_authorizations",
                "head_delegations",
                "activation_delegations",
                "once_authorities",
            ] {
                entries = entries
                    .checked_add(
                        original
                            .field("TrustConfig", field)
                            .and_then(Value::len)
                            .map_err(invalid)? as u64,
                    )
                    .ok_or(EnvironmentError::Capacity)?;
            }
        }
        if entries
            > capacity
                .u("NamespaceCapacity", "max_trust_proof_entries")
                .map_err(invalid)?
        {
            return Err(EnvironmentError::Capacity);
        }
        // Independent rejection takes effect before a replacement Head exists.
        let mut rejected = [None; 64];
        for (i, id) in trust
            .field("TrustConfig", "rejected_head_signers")
            .and_then(Value::children)
            .map_err(invalid)?
            .enumerate()
        {
            rejected[i] = Some(
                id.and_then(Value::bytes)
                    .map_err(invalid)?
                    .try_into()
                    .map_err(|_| EnvironmentError::AuthorizationDenied)?,
            );
        }
        self.environment
            .reject_namespace_signers(self.key, &rejected)?;
        let mut retired = [None; 64];
        for (i, id) in trust
            .field("TrustConfig", "retired_issuers")
            .and_then(Value::children)
            .map_err(invalid)?
            .enumerate()
        {
            retired[i] = Some(
                id.and_then(Value::bytes)
                    .map_err(invalid)?
                    .try_into()
                    .map_err(|_| EnvironmentError::AuthorizationDenied)?,
            );
        }
        self.environment
            .reject_namespace_issuers(self.key, &retired)?;
        self.history.push(raw_copy(bytes)?);
        Ok(())
    }
    fn check_trust_history(&self, next: Value<'_>) -> Result<(), EnvironmentError> {
        for original in &self.history {
            let old = decode(original, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            for (field, schema, id) in [
                (
                    "issuer_authorizations",
                    "CredentialIssuerAuthorization",
                    "authorization_id",
                ),
                ("head_delegations", "HeadSignerDelegation", "signer_key_id"),
                (
                    "activation_delegations",
                    "ConnectionActivationDelegation",
                    "signing_key_id",
                ),
                (
                    "credential_policies",
                    "CredentialRevocationPolicy",
                    "revocation_policy_id",
                ),
                (
                    "once_authorities",
                    "OnceAuthorityRef",
                    "artifact_issuer_key_id",
                ),
            ] {
                for entry in old
                    .field("TrustConfig", field)
                    .and_then(Value::children)
                    .map_err(invalid)?
                {
                    let entry = entry.map_err(invalid)?;
                    for replacement in next
                        .field("TrustConfig", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                    {
                        let replacement = replacement.map_err(invalid)?;
                        if entry.field(schema, id).map_err(invalid)?.raw()
                            == replacement.field(schema, id).map_err(invalid)?.raw()
                            && (schema != "CredentialRevocationPolicy"
                                || entry
                                    .u(schema, "revocation_policy_revision")
                                    .map_err(invalid)?
                                    == replacement
                                        .u(schema, "revocation_policy_revision")
                                        .map_err(invalid)?)
                            && entry.raw() != replacement.raw()
                        {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    }
                }
            }
            for field in ["retired_issuers", "rejected_head_signers"] {
                for id in old
                    .field("TrustConfig", field)
                    .and_then(Value::children)
                    .map_err(invalid)?
                {
                    let id = id.map_err(invalid)?;
                    if !next
                        .field("TrustConfig", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                        .any(|v| v.is_ok_and(|v| v.raw() == id.raw()))
                    {
                        return Err(EnvironmentError::AuthorizationDenied);
                    }
                }
            }
        }
        Ok(())
    }
    fn check_issuer_history(&self, next: Value<'_>) -> Result<(), EnvironmentError> {
        const GROUPS: [(&str, &str, &str); 2] = [
            (
                "issuer_authorizations",
                "CredentialIssuerAuthorization",
                "issuer_public_key",
            ),
            (
                "activation_delegations",
                "ConnectionActivationDelegation",
                "signer_public_key",
            ),
        ];
        let mut originals = [None; MAX_HISTORY + 1];
        for (i, raw) in self.history.iter().enumerate() {
            originals[i] = Some(decode(
                raw,
                "TrustConfig",
                TRUST_BYTES,
                self.node_cap,
                None,
            )?);
        }
        originals[self.history.len()] = Some(next);
        let previous = if self.previous.is_empty() {
            None
        } else {
            Some(decode(
                &self.previous,
                "RevocationState",
                self.state_bytes,
                self.node_cap,
                Some(
                    self.capacity_limits(next.field("TrustConfig", "capacity").map_err(invalid)?)?,
                ),
            )?)
        };
        for (field, schema, public_field) in GROUPS {
            for entry in next
                .field("TrustConfig", field)
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                let issuer = entry.b::<16>(schema, "issuer_key_id").map_err(invalid)?;
                let public = entry.b::<32>(schema, public_field).map_err(invalid)?;
                if !codec::valid_ed25519_key(&public) {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                let mut already_known = false;
                let mut retired = false;
                for original in originals[..self.history.len()].iter().flatten() {
                    retired |= original
                        .field("TrustConfig", "retired_issuers")
                        .and_then(Value::children)
                        .map_err(invalid)?
                        .any(|v| v.and_then(Value::bytes) == Ok(issuer.as_slice()));
                    for existing in original
                        .field("TrustConfig", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                    {
                        already_known |= existing.map_err(invalid)?.raw() == entry.raw();
                    }
                }
                if !already_known && retired {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
                // One issuer revocation identity cannot acquire another public
                // key through a distinct permission or signing-key identifier.
                for original in originals.iter().flatten() {
                    for (other_field, other_schema, other_public) in GROUPS {
                        for other in original
                            .field("TrustConfig", other_field)
                            .and_then(Value::children)
                            .map_err(invalid)?
                        {
                            let other = other.map_err(invalid)?;
                            if other
                                .b::<16>(other_schema, "issuer_key_id")
                                .map_err(invalid)?
                                == issuer
                                && other.b::<32>(other_schema, other_public).map_err(invalid)?
                                    != public
                            {
                                return Err(EnvironmentError::AuthorizationDenied);
                            }
                        }
                    }
                }
                if !already_known
                    && let Some(state) = previous
                    && state
                        .field("RevocationState", "revoked_issuers")
                        .and_then(Value::children)
                        .map_err(invalid)?
                        .any(|v| {
                            v.is_ok_and(|v| {
                                v.b::<16>("RevokedIssuerEntry", "issuer_key_id") == Ok(issuer)
                            })
                        })
                {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
            }
        }
        Ok(())
    }
    fn check_namespace(
        &self,
        value: Value<'_>,
        schema: &str,
        capacity: [u8; 32],
        generation: u64,
    ) -> Result<(), EnvironmentError> {
        if value
            .field(schema, "tenant_id")
            .and_then(Value::text)
            .map_err(invalid)?
            != self.root.tenant
            || value
                .field(schema, "revocation_authority_id")
                .and_then(Value::text)
                .map_err(invalid)?
                != self.root.authority
            || value
                .b::<32>(schema, "namespace_capacity_digest")
                .map_err(invalid)?
                != capacity
            || value.u(schema, "authority_generation").map_err(invalid)? != generation
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        Ok(())
    }
    fn check_publication(
        &self,
        value: Value<'_>,
        schema: &str,
        publication: Value<'_>,
    ) -> Result<(), EnvironmentError> {
        for field in ["publication_policy_id", "publication_policy_revision"] {
            if value.field(schema, field).map_err(invalid)?.raw()
                != publication
                    .field("PublicationPolicy", field)
                    .map_err(invalid)?
                    .raw()
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        Ok(())
    }
    fn capacity_limits(&self, capacity: Value<'_>) -> Result<StateLimits, EnvironmentError> {
        let u = |name| capacity.u("NamespaceCapacity", name).map_err(invalid);
        let limits = StateLimits {
            bytes: u("max_state_encoded_bytes")?,
            issuers: u("max_revoked_issuers")?,
            certificates: u("max_revoked_certificates")?,
            leases: u("max_revoked_leases")?,
            segments: u("max_cohort_policy_segments")?,
        };
        if limits.bytes > self.state_bytes as u64
            || u("max_head_encoded_bytes")? > super::MAX_HEAD_BYTES as u64
            || limits
                .issuers
                .checked_add(limits.certificates)
                .and_then(|n| n.checked_add(limits.leases))
                .is_none_or(|n| n > super::MAX_DENIALS as u64)
        {
            return Err(EnvironmentError::Capacity);
        }
        Ok(limits)
    }
    fn verify_pair(
        &mut self,
        head_bytes: &[u8],
        state_bytes: &[u8],
        now: TrustedTimeSample,
    ) -> Result<VerifiedNamespaceUpdate, EnvironmentError> {
        let trust = decode(
            self.history
                .last()
                .ok_or(EnvironmentError::AuthorizationDenied)?,
            "TrustConfig",
            TRUST_BYTES,
            self.node_cap,
            None,
        )?;
        let capacity = trust.field("TrustConfig", "capacity").map_err(invalid)?;
        let limits = self.capacity_limits(capacity)?;
        let publication = trust.field("TrustConfig", "publication").map_err(invalid)?;
        let capacity_digest =
            codec::digest("namespace_capacity_digest", capacity).map_err(invalid)?;
        let generation = trust
            .u("TrustConfig", "authority_generation")
            .map_err(invalid)?;
        let head = decode(head_bytes, "FreshnessHead", 795, self.node_cap, None)?;
        self.check_namespace(head, "FreshnessHead", capacity_digest, generation)?;
        self.check_publication(head, "FreshnessHead", publication)?;
        let signer = head
            .b::<16>("FreshnessHead", "signing_key_id")
            .map_err(invalid)?;
        if trust
            .field("TrustConfig", "rejected_head_signers")
            .and_then(Value::children)
            .map_err(invalid)?
            .any(|v| v.and_then(Value::bytes) == Ok(signer.as_slice()))
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let delegation = trust
            .field("TrustConfig", "head_delegations")
            .and_then(Value::children)
            .map_err(invalid)?
            .find_map(|v| {
                v.ok()
                    .filter(|v| v.b::<16>("HeadSignerDelegation", "signer_key_id") == Ok(signer))
            })
            .ok_or(EnvironmentError::AuthorizationDenied)?;
        if codec::digest("head_signer_delegation_digest", delegation).map_err(invalid)?
            != head
                .b::<32>("FreshnessHead", "signer_delegation_digest")
                .map_err(invalid)?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let signer_key = delegation
            .b::<32>("HeadSignerDelegation", "signer_public_key")
            .map_err(invalid)?;
        codec::verify_signature(
            "FreshnessHead",
            head,
            &signer_key,
            &mut self.signature_input,
        )
        .map_err(invalid)?;
        let issued = head.u("FreshnessHead", "this_update_ms").map_err(invalid)?;
        let next = head.u("FreshnessHead", "next_update_ms").map_err(invalid)?;
        let delegation_issued = delegation
            .u("HeadSignerDelegation", "issued_at_ms")
            .map_err(invalid)?;
        let delegation_end = delegation
            .u("HeadSignerDelegation", "not_after_ms")
            .map_err(invalid)?;
        let trust_end = trust.u("TrustConfig", "not_after_ms").map_err(invalid)?;
        let end = next.min(delegation_end).min(trust_end);
        interval(
            now,
            issued
                .max(delegation_issued)
                .max(trust.u("TrustConfig", "issued_at_ms").map_err(invalid)?),
            end,
        )?;
        if issued < delegation_issued
            || issued >= delegation_end
            || next - issued
                > publication
                    .u("PublicationPolicy", "max_head_validity_ms")
                    .map_err(invalid)?
            || delegation_end - delegation_issued
                > publication
                    .u("PublicationPolicy", "max_signer_lifetime_ms")
                    .map_err(invalid)?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        let state = decode(
            state_bytes,
            "RevocationState",
            self.state_bytes,
            self.node_cap,
            Some(limits),
        )?;
        if state_bytes.len() as u64
            != head
                .u("FreshnessHead", "state_encoded_bytes")
                .map_err(invalid)?
            || codec::digest("revocation_state_digest", state).map_err(invalid)?
                != head
                    .b::<32>("FreshnessHead", "state_digest")
                    .map_err(invalid)?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        for field in [
            "schema_revision",
            "tenant_id",
            "revocation_authority_id",
            "namespace_capacity_digest",
            "authority_generation",
            "credential_revocation_floors",
            "publication_policy_id",
            "publication_policy_revision",
        ] {
            if state
                .field("RevocationState", field)
                .map_err(invalid)?
                .raw()
                != head.field("FreshnessHead", field).map_err(invalid)?.raw()
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
        }
        let floors = [
            head.field("FreshnessHead", "credential_revocation_floors")
                .and_then(|v| v.at(0))
                .and_then(Value::uint)
                .map_err(invalid)?,
            head.field("FreshnessHead", "credential_revocation_floors")
                .and_then(|v| v.at(1))
                .and_then(Value::uint)
                .map_err(invalid)?,
        ];
        self.check_state(state, trust, capacity, floors, now, limits)?;
        let charge = self.environment.reserve_environment(ResourceLimits {
            sdk_bytes: (head_bytes.len()
                + state_bytes.len()
                + super::MAX_DENIALS * std::mem::size_of::<Denial>()) as u64,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let mut denials = Vec::new();
        denials
            .try_reserve_exact(super::MAX_DENIALS)
            .map_err(|_| EnvironmentError::Capacity)?;
        for (field, schema, kind) in [
            ("revoked_issuers", "RevokedIssuerEntry", None),
            (
                "revoked_certificates",
                "RevokedCertificateEntry",
                Some(CredentialKind::Certificate),
            ),
            (
                "revoked_leases",
                "RevokedLeaseEntry",
                Some(CredentialKind::Connection),
            ),
        ] {
            for entry in state
                .field("RevocationState", field)
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                denials.push(match kind {
                    None => Denial::Issuer(entry.b(schema, "issuer_key_id").map_err(invalid)?),
                    Some(CredentialKind::Certificate) => Denial::Credential(
                        CredentialKind::Certificate,
                        entry.b(schema, "certificate_digest").map_err(invalid)?,
                    ),
                    Some(CredentialKind::Connection) => Denial::Lease(
                        entry.b(schema, "issuer_key_id").map_err(invalid)?,
                        entry.b(schema, "lease_id").map_err(invalid)?,
                    ),
                });
            }
        }
        Ok(VerifiedNamespaceUpdate {
            anchor: NamespaceAnchor {
                key: self.key,
                generation,
                capacity_digest,
            },
            head: Head {
                generation,
                sequence: head.u("FreshnessHead", "head_sequence").map_err(invalid)?,
                digest: codec::digest("freshness_head_digest", head).map_err(invalid)?,
                state_digest: head.b("FreshnessHead", "state_digest").map_err(invalid)?,
                floors,
                this_update_ms: issued,
                next_update_ms: end,
                signer,
                signer_lifetime_ms: delegation_end - delegation_issued,
            },
            head_bytes: raw_copy(head_bytes)?,
            state_bytes: raw_copy(state_bytes)?,
            denials: denials.into_boxed_slice(),
            owner: Some(self.owner.clone()),
            _charge: Some(charge),
        })
    }
    fn check_state(
        &self,
        state: Value<'_>,
        trust: Value<'_>,
        capacity: Value<'_>,
        floors: [u64; 2],
        now: TrustedTimeSample,
        limits: StateLimits,
    ) -> Result<(), EnvironmentError> {
        let origin = capacity
            .u("NamespaceCapacity", "cohort_time_origin_ms")
            .map_err(invalid)?;
        let duration = capacity
            .u("NamespaceCapacity", "cohort_duration_ms")
            .map_err(invalid)?;
        let impacts = [
            capacity
                .u("NamespaceCapacity", "max_certificate_impact_ms")
                .map_err(invalid)?,
            capacity
                .u("NamespaceCapacity", "max_connection_impact_ms")
                .map_err(invalid)?,
        ];
        let end = |cohort: u64| {
            cohort
                .checked_add(1)
                .and_then(|n| n.checked_mul(duration))
                .and_then(|n| n.checked_add(origin))
                .ok_or(EnvironmentError::AuthorizationDenied)
        };
        for class in 0..2 {
            if floors[class] > 0
                && now.lower_ms
                    < end(floors[class] - 1)?
                        .checked_add(impacts[class])
                        .ok_or(EnvironmentError::AuthorizationDenied)?
            {
                return Err(EnvironmentError::TimePending);
            }
        }
        let segments = state
            .field("RevocationState", "cohort_policy_segments")
            .map_err(invalid)?;
        // The complete signed State bounds this loop. Reject overlap independently
        // in each class; an absent class does not participate in that interval.
        for (i, entry) in segments.children().map_err(invalid)?.enumerate() {
            let entry = entry.map_err(invalid)?;
            let first = entry
                .u("CohortPolicySegment", "first_cohort")
                .map_err(invalid)?;
            let last = entry
                .u("CohortPolicySegment", "last_cohort")
                .map_err(invalid)?;
            for (class, field) in ["certificate_impact_ms", "connection_impact_ms"]
                .iter()
                .enumerate()
            {
                if let Some(impact) = entry
                    .optional("CohortPolicySegment", field)
                    .map_err(invalid)?
                {
                    let impact = impact.uint().map_err(invalid)?;
                    if impact > impacts[class] || end(last)?.checked_add(impact).is_none() {
                        return Err(EnvironmentError::AuthorizationDenied);
                    }
                    for before in segments.children().map_err(invalid)?.take(i) {
                        let before = before.map_err(invalid)?;
                        if before
                            .optional("CohortPolicySegment", field)
                            .map_err(invalid)?
                            .is_some()
                            && first
                                <= before
                                    .u("CohortPolicySegment", "last_cohort")
                                    .map_err(invalid)?
                            && last
                                >= before
                                    .u("CohortPolicySegment", "first_cohort")
                                    .map_err(invalid)?
                        {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    }
                }
            }
        }
        for (field, schema, time, class) in [
            (
                "revoked_certificates",
                "RevokedCertificateEntry",
                "expires_at_ms",
                0,
            ),
            (
                "revoked_leases",
                "RevokedLeaseEntry",
                "latest_impact_not_after_ms",
                1,
            ),
        ] {
            for entry in state
                .field("RevocationState", field)
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let entry = entry.map_err(invalid)?;
                if entry.u(schema, time).map_err(invalid)?
                    > end(entry.u(schema, "cohort").map_err(invalid)?)?
                        .checked_add(impacts[class])
                        .ok_or(EnvironmentError::AuthorizationDenied)?
                {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
            }
        }
        // Every revoked issuer must carry all independently retained original
        // issuance/delegation impacts, including earlier TrustConfig revisions.
        for entry in state
            .field("RevocationState", "revoked_issuers")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let entry = entry.map_err(invalid)?;
            let issuer = entry
                .b::<16>("RevokedIssuerEntry", "issuer_key_id")
                .map_err(invalid)?;
            let evidence = entry
                .field("RevokedIssuerEntry", "authorizations")
                .map_err(invalid)?;
            for impact in evidence.children().map_err(invalid)? {
                let impact = impact.map_err(invalid)?;
                if !self.original_impact_matches(issuer, impact)? {
                    return Err(EnvironmentError::AuthorizationDenied);
                }
            }
            for original in &self.history {
                let config = decode(original, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
                for (field, schema, domain) in [
                    (
                        "issuer_authorizations",
                        "CredentialIssuerAuthorization",
                        "credential_issuer_authorization_digest",
                    ),
                    (
                        "activation_delegations",
                        "ConnectionActivationDelegation",
                        "connection_activation_delegation_digest",
                    ),
                ] {
                    for authorization in config
                        .field("TrustConfig", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                    {
                        let authorization = authorization.map_err(invalid)?;
                        if authorization
                            .b::<16>(schema, "issuer_key_id")
                            .map_err(invalid)?
                            != issuer
                        {
                            continue;
                        }
                        let digest = codec::digest(domain, authorization).map_err(invalid)?;
                        if !evidence.children().map_err(invalid)?.any(|v| {
                            v.is_ok_and(|v| {
                                v.b::<32>("IssuerAuthorizationImpact", "authorization_digest")
                                    == Ok(digest)
                            })
                        }) {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    }
                }
            }
        }
        if !self.previous.is_empty() {
            let old = decode(
                &self.previous,
                "RevocationState",
                self.state_bytes,
                self.node_cap,
                Some(limits),
            )?;
            for (field, schema, id, class) in [
                (
                    "revoked_certificates",
                    "RevokedCertificateEntry",
                    "certificate_digest",
                    Some(0),
                ),
                ("revoked_leases", "RevokedLeaseEntry", "lease_id", Some(1)),
                (
                    "revoked_issuers",
                    "RevokedIssuerEntry",
                    "issuer_key_id",
                    None,
                ),
            ] {
                for entry in old
                    .field("RevocationState", field)
                    .and_then(Value::children)
                    .map_err(invalid)?
                {
                    let entry = entry.map_err(invalid)?;
                    let mut retained = None;
                    for next in state
                        .field("RevocationState", field)
                        .and_then(Value::children)
                        .map_err(invalid)?
                    {
                        let next = next.map_err(invalid)?;
                        if next.field(schema, id).map_err(invalid)?.raw()
                            == entry.field(schema, id).map_err(invalid)?.raw()
                            && (schema != "RevokedLeaseEntry"
                                || next.field(schema, "issuer_key_id").map_err(invalid)?.raw()
                                    == entry.field(schema, "issuer_key_id").map_err(invalid)?.raw())
                        {
                            retained = Some(next);
                            break;
                        }
                    }
                    if let Some(retained) = retained {
                        if schema == "RevokedIssuerEntry" {
                            for impact in entry
                                .field(schema, "authorizations")
                                .and_then(Value::children)
                                .map_err(invalid)?
                            {
                                let impact = impact.map_err(invalid)?;
                                if !retained
                                    .field(schema, "authorizations")
                                    .and_then(Value::children)
                                    .map_err(invalid)?
                                    .any(|v| v.is_ok_and(|v| v.raw() == impact.raw()))
                                {
                                    return Err(EnvironmentError::AuthorizationDenied);
                                }
                            }
                        } else if schema == "RevokedLeaseEntry" {
                            for field in ["cohort", "artifact_digest"] {
                                if entry.field(schema, field).map_err(invalid)?.raw()
                                    != retained.field(schema, field).map_err(invalid)?.raw()
                                {
                                    return Err(EnvironmentError::AuthorizationDenied);
                                }
                            }
                            if retained
                                .u(schema, "latest_impact_not_after_ms")
                                .map_err(invalid)?
                                < entry
                                    .u(schema, "latest_impact_not_after_ms")
                                    .map_err(invalid)?
                            {
                                return Err(EnvironmentError::AuthorizationDenied);
                            }
                        } else if entry.raw() != retained.raw() {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    } else if let Some(class) = class {
                        if entry.u(schema, "cohort").map_err(invalid)? >= floors[class] {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                    } else {
                        let issuer = entry.field(schema, "issuer_key_id").map_err(invalid)?;
                        if !trust
                            .field("TrustConfig", "retired_issuers")
                            .and_then(Value::children)
                            .map_err(invalid)?
                            .any(|v| v.is_ok_and(|v| v.raw() == issuer.raw()))
                        {
                            return Err(EnvironmentError::AuthorizationDenied);
                        }
                        for impact in entry
                            .field(schema, "authorizations")
                            .and_then(Value::children)
                            .map_err(invalid)?
                        {
                            let impact = impact
                                .map_err(invalid)?
                                .field("IssuerAuthorizationImpact", "max_affected_cohorts")
                                .map_err(invalid)?;
                            for (class, floor) in floors.iter().enumerate() {
                                let cohort = impact.at(class).map_err(invalid)?;
                                if !cohort.is_null() && cohort.uint().map_err(invalid)? >= *floor {
                                    return Err(EnvironmentError::AuthorizationDenied);
                                }
                            }
                        }
                    }
                }
            }
            for old in old
                .field("RevocationState", "cohort_policy_segments")
                .and_then(Value::children)
                .map_err(invalid)?
            {
                let old = old.map_err(invalid)?;
                if segments
                    .children()
                    .map_err(invalid)?
                    .any(|v| v.is_ok_and(|v| v.raw() == old.raw()))
                {
                    continue;
                }
                for (class, field) in ["certificate_impact_ms", "connection_impact_ms"]
                    .iter()
                    .enumerate()
                {
                    if old
                        .optional("CohortPolicySegment", field)
                        .map_err(invalid)?
                        .is_some()
                        && old
                            .u("CohortPolicySegment", "last_cohort")
                            .map_err(invalid)?
                            >= floors[class]
                    {
                        return Err(EnvironmentError::AuthorizationDenied);
                    }
                }
            }
        }
        Ok(())
    }
    fn original_impact_matches(
        &self,
        issuer: [u8; 16],
        impact: Value<'_>,
    ) -> Result<bool, EnvironmentError> {
        let digest = impact
            .b::<32>("IssuerAuthorizationImpact", "authorization_digest")
            .map_err(invalid)?;
        for original in &self.history {
            let config = decode(original, "TrustConfig", TRUST_BYTES, self.node_cap, None)?;
            for (field, schema, domain) in [
                (
                    "issuer_authorizations",
                    "CredentialIssuerAuthorization",
                    "credential_issuer_authorization_digest",
                ),
                (
                    "activation_delegations",
                    "ConnectionActivationDelegation",
                    "connection_activation_delegation_digest",
                ),
            ] {
                for entry in config
                    .field("TrustConfig", field)
                    .and_then(Value::children)
                    .map_err(invalid)?
                {
                    let entry = entry.map_err(invalid)?;
                    if entry.b::<16>(schema, "issuer_key_id").map_err(invalid)? != issuer
                        || codec::digest(domain, entry).map_err(invalid)? != digest
                    {
                        continue;
                    }
                    for field in [
                        "max_affected_cohorts",
                        "signing_not_before_ms",
                        "signing_not_after_ms",
                    ] {
                        if entry.field(schema, field).map_err(invalid)?.raw()
                            != impact
                                .field("IssuerAuthorizationImpact", field)
                                .map_err(invalid)?
                                .raw()
                        {
                            return Ok(false);
                        }
                    }
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
impl Drop for NamespaceVerifier {
    fn drop(&mut self) {
        self.owner.store(true, Ordering::Release);
        let _ = self.environment.terminate_namespace(self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec_v4::tests::{array, b, encode_map, sign, t, u};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    fn digest(name: &str, raw: &[u8], schema: &str) -> [u8; 32] {
        codec::digest(
            name,
            decode(
                raw,
                schema,
                1 << 20,
                1 << 20,
                Some(StateLimits {
                    bytes: 1 << 20,
                    issuers: 64,
                    certificates: 64,
                    leases: 64,
                    segments: 64,
                }),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn fixture(
        nonce: [u8; 32],
        sequence: u64,
        revoked: bool,
    ) -> (NamespaceTrustRoot, Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signer = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        let capacity = encode_map(&[
            (0, t("tenant")),
            (1, t("authority")),
            (2, t("cap-1")),
            (3, u(4096)),
            (4, u(8)),
            (5, u(8)),
            (6, u(8)),
            (7, u(8)),
            (8, u(795)),
            (9, u(1 << 20)),
            (10, u(1024)),
            (11, u(0)),
            (12, u(100)),
            (13, u(1000)),
            (14, u(1000)),
        ]);
        let cap = digest("namespace_capacity_digest", &capacity, "NamespaceCapacity");
        let publication = encode_map(&[
            (0, t("publication")),
            (1, u(1)),
            (2, u(10_000)),
            (3, u(20_000)),
        ]);
        let delegation = encode_map(&[
            (0, t(crate::codec_v4::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, b(&cap)),
            (4, u(1)),
            (5, b(&[2; 16])),
            (6, b(&[3; 16])),
            (7, b(signer.public_key().as_ref())),
            (8, u(0)),
            (9, t("publication")),
            (10, u(1)),
            (11, u(1)),
            (12, u(1)),
            (13, u(20_000)),
        ]);
        let trust = sign(
            "TrustConfig",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, u(1)),
                (4, u(1)),
                (5, u(1)),
                (6, u(30_000)),
                (7, capacity),
                (8, publication),
                (9, array(&[])),
                (10, array(&[])),
                (11, array(std::slice::from_ref(&delegation))),
                (12, array(&[])),
                (13, array(&[])),
                (14, array(&[])),
                (15, array(&[])),
                (16, b(&[1; 16])),
            ],
            &root,
        );
        let segments = array(&[encode_map(&[
            (0, u(0)),
            (1, u(100)),
            (2, u(1000)),
            (3, u(1000)),
        ])]);
        let revoked = if revoked {
            array(&[encode_map(&[(0, b(&[8; 32])), (1, u(8)), (2, u(1800))])])
        } else {
            array(&[])
        };
        let state = encode_map(&[
            (0, t(crate::codec_v4::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, b(&cap)),
            (4, u(1)),
            (5, array(&[u(0), u(0)])),
            (6, t("publication")),
            (7, u(1)),
            (8, array(&[])),
            (9, revoked),
            (10, array(&[])),
            (11, segments),
        ]);
        let head = sign(
            "FreshnessHead",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, b(&cap)),
                (4, u(1)),
                (5, array(&[u(0), u(0)])),
                (6, t("publication")),
                (7, u(1)),
                (8, u(sequence)),
                (9, u(900)),
                (10, u(10_000)),
                (
                    11,
                    b(&digest(
                        "revocation_state_digest",
                        &state,
                        "RevocationState",
                    )),
                ),
                (12, u(state.len() as u64)),
                (13, b(&[3; 16])),
                (
                    14,
                    b(&digest(
                        "head_signer_delegation_digest",
                        &delegation,
                        "HeadSignerDelegation",
                    )),
                ),
            ],
            &signer,
        );
        let response = sign(
            "TrustBootstrapResponse",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, b(&nonce)),
                (4, u(900)),
                (5, u(5_000)),
                (6, b(&trust)),
                (7, b(&head)),
                (8, b(&[1; 16])),
            ],
            &root,
        );
        (
            NamespaceTrustRoot {
                tenant: "tenant".into(),
                authority: "authority".into(),
                key_id: [1; 16],
                public_key: root.public_key().as_ref().try_into().unwrap(),
                max_lifetime_ms: 40_000,
            },
            response,
            head,
            state,
        )
    }
    #[test]
    fn authenticated_bootstrap_and_refresh_drive_the_original_namespace_gate() {
        use crate::environment_v4::tests::{bounds, environment};
        let environment = environment();
        let (root, _, _, _) = fixture([0; 32], 1, false);
        let mut verifier = NamespaceVerifier::new(environment.clone(), root, 4096, 16384).unwrap();
        let (_, response, head, state) = fixture(verifier.bootstrap_nonce(), 1, false);
        verifier.bootstrap(&response, &state).unwrap();
        let account = environment.admit(key("tenant"), bounds()).unwrap();
        account
            .bind_namespaces(&[super::super::NamespaceBinding {
                namespace: verifier.key,
                generation: 1,
                kind: CredentialKind::Certificate,
                cohort: 8,
                issuer: [4; 16],
                credential: [8; 32],
                lease: None,
                max_staleness_ms: 10_000,
                max_head_signer_lifetime_ms: 20_000,
            }])
            .unwrap();
        account.check().unwrap();
        assert_eq!(
            verifier.bootstrap(&response, &state),
            Err(EnvironmentError::Closed)
        );
        let mut forged = head.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(
            verifier.refresh(None, &forged, &state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        account.check().unwrap();
        let (_, _, next, state2) = fixture([0; 32], 2, true);
        verifier.refresh(None, &next, &state2).unwrap();
        assert_eq!(account.check(), Err(EnvironmentError::Closed));
        let (_, _, missing, state3) = fixture([0; 32], 3, false);
        assert_eq!(
            verifier.refresh(None, &missing, &state3),
            Err(EnvironmentError::AuthorizationDenied)
        );
    }
    #[test]
    fn bootstrap_nonce_and_full_state_binding_are_required() {
        use crate::environment_v4::tests::environment;
        let environment = environment();
        let (root, _, _, _) = fixture([0; 32], 1, false);
        let mut verifier =
            NamespaceVerifier::new(environment.clone(), root.clone(), 4096, 16384).unwrap();
        assert_eq!(
            NamespaceVerifier::new(environment, root, 4096, 16384).unwrap_err(),
            EnvironmentError::AuthorizationDenied
        );
        let (_, wrong, _, state) = fixture([0; 32], 1, false);
        assert_eq!(
            verifier.bootstrap(&wrong, &state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        let (_, response, _, state) = fixture(verifier.bootstrap_nonce(), 1, false);
        let mut wrong_state = state.clone();
        let last = wrong_state.len() - 1;
        wrong_state[last] ^= 1;
        assert_eq!(
            verifier.bootstrap(&response, &wrong_state),
            Err(EnvironmentError::AuthorizationDenied)
        );
        verifier.bootstrap(&response, &state).unwrap();
    }
}
