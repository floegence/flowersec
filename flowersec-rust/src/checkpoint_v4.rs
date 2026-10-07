//! Application progress tokens use independent recovery keys and the original
//! execution history. Token verification alone grants no dispatch authority.
use crate::{
    codec_v4::{self as codec, Limits, Value},
    service_contract::{ServiceError, ServiceFailure},
};
use hmac::{Hmac, Mac, digest::KeyInit};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn parsed<T>(value: codec::Result<T>) -> Result<T> {
    value.map_err(|_| failure(ServiceFailure::ContractMismatch))
}
fn head(output: &mut Vec<u8>, major: u8, value: u64) {
    codec::encode_head(output, major, value);
}
fn uint(output: &mut Vec<u8>, value: u64) {
    head(output, 0, value);
}
fn bytes(output: &mut Vec<u8>, value: &[u8]) {
    head(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}
fn text(output: &mut Vec<u8>, value: &str) {
    head(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}
fn map<'a>(encoded: &'a [u8], schema: &str, maximum: usize) -> Result<Value<'a>> {
    parsed(codec::decode(
        encoded,
        schema,
        Limits {
            bytes: maximum,
            nodes: 128,
        },
        None,
    ))
}
#[derive(Clone, Eq, PartialEq)]
pub struct ApplicationCheckpoint {
    format: String,
    position: Vec<u8>,
}
impl fmt::Debug for ApplicationCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicationCheckpoint { <opaque> }")
    }
}
impl ApplicationCheckpoint {
    pub fn new(format: String, position: Vec<u8>) -> Result<Self> {
        if !crate::execution_history::id(&format) || position.len() > 4096 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(Self { format, position })
    }
    pub fn format(&self) -> &str {
        &self.format
    }
    pub fn position(&self) -> &[u8] {
        &self.position
    }
    pub fn encoded(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.position.len() + self.format.len() + 16);
        head(&mut output, 5, 2);
        uint(&mut output, 0);
        text(&mut output, &self.format);
        uint(&mut output, 1);
        bytes(&mut output, &self.position);
        output
    }
    pub fn capture(encoded: &[u8]) -> Result<Self> {
        Self::from_value(map(encoded, "ResumeCheckpoint", 4232)?)
    }
    fn from_value(value: Value<'_>) -> Result<Self> {
        Self::new(
            parsed(
                value
                    .field("ResumeCheckpoint", "format")
                    .and_then(Value::text),
            )?
            .to_owned(),
            parsed(
                value
                    .field("ResumeCheckpoint", "position")
                    .and_then(Value::bytes),
            )?
            .to_vec(),
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CheckpointTokenProtection {
    Ed25519,
    HmacSha256,
}
impl CheckpointTokenProtection {
    pub(crate) fn schema(self) -> &'static str {
        match self {
            Self::Ed25519 => "ResumeSignedToken",
            Self::HmacSha256 => "ResumeMACToken",
        }
    }
    pub(crate) fn wire(self) -> u64 {
        match self {
            Self::Ed25519 => 0,
            Self::HmacSha256 => 1,
        }
    }
}
struct SigningOwner {
    protection: CheckpointTokenProtection,
    key_id: [u8; 16],
    secret: Zeroizing<[u8; 32]>,
}
#[derive(Clone)]
pub struct ServiceCheckpointSigningKey(Arc<SigningOwner>);
impl fmt::Debug for ServiceCheckpointSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceCheckpointSigningKey { <opaque> }")
    }
}
impl ServiceCheckpointSigningKey {
    pub fn new(
        protection: CheckpointTokenProtection,
        key_id: [u8; 16],
        secret: [u8; 32],
    ) -> Result<Self> {
        let secret = Zeroizing::new(secret);
        if key_id == [0; 16] || *secret == [0; 32] {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        if protection == CheckpointTokenProtection::Ed25519 {
            Ed25519KeyPair::from_seed_unchecked(secret.as_slice())
                .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?;
        }
        Ok(Self(Arc::new(SigningOwner {
            protection,
            key_id,
            secret,
        })))
    }
    pub fn protection(&self) -> CheckpointTokenProtection {
        self.0.protection
    }
    pub(crate) fn key_id(&self) -> [u8; 16] {
        self.0.key_id
    }
    pub fn verification_key(&self) -> Result<CheckpointVerificationKey> {
        let key = match self.0.protection {
            CheckpointTokenProtection::Ed25519 => {
                Ed25519KeyPair::from_seed_unchecked(self.0.secret.as_slice())
                    .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?
                    .public_key()
                    .as_ref()
                    .try_into()
                    .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?
            }
            CheckpointTokenProtection::HmacSha256 => *self.0.secret,
        };
        CheckpointVerificationKey::new(self.0.protection, self.0.key_id, key)
    }
    pub(crate) fn fingerprint(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.verification_key()?.0.key.as_slice()).into())
    }
    pub(crate) fn sign(&self, claims: &[u8]) -> Result<Vec<u8>> {
        map(claims, "ResumeTokenClaims", 4893)?;
        let mut projection = Vec::with_capacity(claims.len() + 32);
        head(&mut projection, 5, 2);
        uint(&mut projection, 0);
        projection.extend_from_slice(claims);
        uint(&mut projection, 1);
        bytes(&mut projection, &self.0.key_id);
        let message = token_message(self.0.protection, &projection)?;
        let tag: Vec<u8> = match self.0.protection {
            CheckpointTokenProtection::Ed25519 => {
                Ed25519KeyPair::from_seed_unchecked(self.0.secret.as_slice())
                    .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?
                    .sign(&message)
                    .as_ref()
                    .to_vec()
            }
            CheckpointTokenProtection::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.0.secret.as_slice())
                    .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
                mac.update(&message);
                mac.finalize().into_bytes().to_vec()
            }
        };
        let mut output = Vec::with_capacity(projection.len() + tag.len() + 4);
        head(&mut output, 5, 3);
        output.extend_from_slice(&projection[1..]);
        uint(&mut output, 2);
        bytes(&mut output, &tag);
        map(&output, self.0.protection.schema(), 4980)?;
        Ok(output)
    }
}
struct VerificationOwner {
    protection: CheckpointTokenProtection,
    key_id: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}
#[derive(Clone)]
pub struct CheckpointVerificationKey(Arc<VerificationOwner>);
impl fmt::Debug for CheckpointVerificationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckpointVerificationKey { <opaque> }")
    }
}
impl CheckpointVerificationKey {
    pub fn new(
        protection: CheckpointTokenProtection,
        key_id: [u8; 16],
        key: [u8; 32],
    ) -> Result<Self> {
        if key_id == [0; 16] || key == [0; 32] {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(Self(Arc::new(VerificationOwner {
            protection,
            key_id,
            key: Zeroizing::new(key),
        })))
    }
}
fn token_message(
    protection: CheckpointTokenProtection,
    projection: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let name = match protection {
        CheckpointTokenProtection::Ed25519 => "resume_token_signature",
        CheckpointTokenProtection::HmacSha256 => "resume_token_mac",
    };
    let domain = parsed(codec::wire_domain(name))?;
    let encoded = domain["label_bytes"]
        .as_str()
        .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
    let expected = match protection {
        CheckpointTokenProtection::Ed25519 => "without_signature",
        CheckpointTokenProtection::HmacSha256 => "without_mac",
    };
    if encoded.len() > 256
        || encoded.len() % 2 != 0
        || domain["input_schema"]["parts"][0]["schema_ref"] != protection.schema()
        || domain["input_schema"]["parts"][0]["projection"] != expected
    {
        return Err(failure(ServiceFailure::ConfigurationCapacity));
    }
    let mut output = Zeroizing::new(Vec::with_capacity(encoded.len() / 2 + 4 + projection.len()));
    for pair in encoded.as_bytes().as_chunks::<2>().0 {
        output.push(
            u8::from_str_radix(
                std::str::from_utf8(pair)
                    .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?,
                16,
            )
            .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?,
        );
    }
    output.extend_from_slice(&(projection.len() as u32).to_be_bytes());
    output.extend_from_slice(projection);
    Ok(output)
}
#[derive(Clone)]
pub struct ApplicationCheckpointToken {
    pub(crate) tenant: String,
    pub(crate) caller: String,
    pub(crate) audience: String,
    pub(crate) namespace: String,
    pub(crate) operation: [u8; 32],
    pub(crate) request: [u8; 32],
    checkpoint: ApplicationCheckpoint,
    generation: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    encoded: Vec<u8>,
    protection: CheckpointTokenProtection,
}
impl fmt::Debug for ApplicationCheckpointToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicationCheckpointToken { <opaque> }")
    }
}
impl ApplicationCheckpointToken {
    /// Verify the original independent application key. Current Session policy,
    /// caller authorization and generation consumption remain separate gates.
    pub fn verify(encoded: &[u8], key: &CheckpointVerificationKey) -> Result<Self> {
        let schema = key.0.protection.schema();
        let token = map(encoded, schema, 4980)?;
        if parsed(token.b::<16>(schema, "key_id"))? != key.0.key_id {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let claims = parsed(token.field(schema, "claims"))?;
        let mut projection = Vec::with_capacity(encoded.len());
        head(&mut projection, 5, 2);
        uint(&mut projection, 0);
        projection.extend_from_slice(claims.raw());
        uint(&mut projection, 1);
        bytes(&mut projection, &key.0.key_id);
        let message = token_message(key.0.protection, &projection)?;
        let verified = match key.0.protection {
            CheckpointTokenProtection::Ed25519 => codec::strict_verify(
                parsed(token.field(schema, "signature").and_then(Value::bytes))?,
                &message,
                &key.0.key,
            ),
            CheckpointTokenProtection::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key.0.key.as_slice())
                    .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
                mac.update(&message);
                mac.verify_slice(parsed(token.field(schema, "mac").and_then(Value::bytes))?)
                    .is_ok()
            }
        };
        if !verified {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let token = Self {
            tenant: parsed(
                claims
                    .field("ResumeTokenClaims", "tenant_id")
                    .and_then(Value::text),
            )?
            .to_owned(),
            caller: parsed(
                claims
                    .field("ResumeTokenClaims", "caller_identity")
                    .and_then(Value::text),
            )?
            .to_owned(),
            audience: parsed(
                claims
                    .field("ResumeTokenClaims", "audience")
                    .and_then(Value::text),
            )?
            .to_owned(),
            namespace: parsed(
                claims
                    .field("ResumeTokenClaims", "service_namespace")
                    .and_then(Value::text),
            )?
            .to_owned(),
            operation: parsed(claims.b("ResumeTokenClaims", "operation_id"))?,
            request: parsed(claims.b("ResumeTokenClaims", "request_digest"))?,
            checkpoint: ApplicationCheckpoint::from_value(parsed(
                claims.field("ResumeTokenClaims", "checkpoint"),
            )?)?,
            generation: parsed(claims.u("ResumeTokenClaims", "generation"))?,
            issued_at_ms: parsed(claims.u("ResumeTokenClaims", "issued_at_ms"))?,
            expires_at_ms: parsed(claims.u("ResumeTokenClaims", "expires_at_ms"))?,
            encoded: encoded.to_vec(),
            protection: key.0.protection,
        };
        if token.generation == 0 || token.expires_at_ms <= token.issued_at_ms {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        Ok(token)
    }
    pub fn checkpoint(&self) -> &ApplicationCheckpoint {
        &self.checkpoint
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    pub fn protection(&self) -> CheckpointTokenProtection {
        self.protection
    }
}
/// Application confirmation facts. A transport receipt never constructs this
/// result; accepted progress comes from the original application transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationResumeStatus {
    Accepted,
    Rejected,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationResumeProgress {
    pub checkpoint: ApplicationCheckpoint,
    pub generation: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationResumeResult {
    status: ApplicationResumeStatus,
    progress: Option<ApplicationResumeProgress>,
}
impl ApplicationResumeResult {
    pub fn capture(encoded: &[u8]) -> Result<Self> {
        let value = map(encoded, "ResumeResult", 4248)?;
        let status = match parsed(value.u("ResumeResult", "status"))? {
            0 => ApplicationResumeStatus::Accepted,
            1 => ApplicationResumeStatus::Rejected,
            2 => ApplicationResumeStatus::Unknown,
            _ => return Err(failure(ServiceFailure::Protocol)),
        };
        let progress = parsed(value.optional("ResumeResult", "progress"))?
            .map(|progress| -> Result<_> {
                let generation = parsed(progress.u("ResumeProgress", "new_generation"))?;
                if generation == 0 {
                    return Err(failure(ServiceFailure::Protocol));
                }
                Ok(ApplicationResumeProgress {
                    checkpoint: ApplicationCheckpoint::from_value(parsed(
                        progress.field("ResumeProgress", "confirmed_checkpoint"),
                    )?)?,
                    generation,
                })
            })
            .transpose()?;
        if status == ApplicationResumeStatus::Accepted && progress.is_none() {
            return Err(failure(ServiceFailure::Protocol));
        }
        Ok(Self { status, progress })
    }
    pub fn status(&self) -> ApplicationResumeStatus {
        self.status
    }
    pub fn progress(&self) -> Option<&ApplicationResumeProgress> {
        self.progress.as_ref()
    }
    pub(crate) fn refused(unknown: bool) -> Self {
        Self {
            status: if unknown {
                ApplicationResumeStatus::Unknown
            } else {
                ApplicationResumeStatus::Rejected
            },
            progress: None,
        }
    }
    pub(crate) fn accepted(checkpoint: ApplicationCheckpoint, generation: u64) -> Result<Self> {
        if generation == 0 {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        Ok(Self {
            status: ApplicationResumeStatus::Accepted,
            progress: Some(ApplicationResumeProgress {
                checkpoint,
                generation,
            }),
        })
    }
    pub(crate) fn encoded(&self) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(4248);
        head(&mut output, 5, if self.progress.is_some() { 2 } else { 1 });
        uint(&mut output, 0);
        uint(
            &mut output,
            match self.status {
                ApplicationResumeStatus::Accepted => 0,
                ApplicationResumeStatus::Rejected => 1,
                ApplicationResumeStatus::Unknown => 2,
            },
        );
        if let Some(progress) = &self.progress {
            uint(&mut output, 1);
            head(&mut output, 5, 2);
            uint(&mut output, 0);
            output.extend_from_slice(&progress.checkpoint.encoded());
            uint(&mut output, 1);
            uint(&mut output, progress.generation);
        }
        map(&output, "ResumeResult", 4248)?;
        Ok(output)
    }
}

/// Captured by the actual accepted Stream owner. Applications do not assemble
/// transport coordinates or substitute another Session while preparing Resume.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResumeTargetBinding {
    pub(crate) context: [u8; 32],
    pub(crate) stream: u64,
}
impl ResumeTargetBinding {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.context == [0; 32] || self.stream == 0 || self.stream > i64::MAX as u64 {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct ApplicationResumeRequest {
    pub(crate) operation: [u8; 32],
    pub(crate) request: [u8; 32],
    pub(crate) protection: CheckpointTokenProtection,
    pub(crate) token: Vec<u8>,
    pub(crate) generation: u64,
    pub(crate) expected: ApplicationCheckpoint,
    pub(crate) target: ResumeTargetBinding,
}
impl ApplicationResumeRequest {
    pub(crate) fn prepare(
        token: &ApplicationCheckpointToken,
        target: ResumeTargetBinding,
    ) -> Result<Self> {
        target.validate()?;
        Ok(Self {
            operation: token.operation,
            request: token.request,
            protection: token.protection(),
            token: token.encoded().to_vec(),
            generation: token.generation(),
            expected: token.checkpoint().clone(),
            target,
        })
    }
    pub(crate) fn capture(encoded: &[u8]) -> Result<Self> {
        let value = map(encoded, "ResumeRequest", 9345)?;
        let protection = match parsed(value.u("ResumeRequest", "protection"))? {
            0 => CheckpointTokenProtection::Ed25519,
            1 => CheckpointTokenProtection::HmacSha256,
            _ => return Err(failure(ServiceFailure::Protocol)),
        };
        let request = Self {
            operation: parsed(value.b("ResumeRequest", "original_operation_id"))?,
            request: parsed(value.b("ResumeRequest", "original_request_digest"))?,
            protection,
            token: parsed(value.field("ResumeRequest", "token").and_then(Value::bytes))?.to_vec(),
            generation: parsed(value.u("ResumeRequest", "generation"))?,
            expected: ApplicationCheckpoint::from_value(parsed(
                value.field("ResumeRequest", "expected_checkpoint"),
            )?)?,
            target: ResumeTargetBinding {
                context: parsed(value.b("ResumeRequest", "transport_context_digest"))?,
                stream: parsed(value.u("ResumeRequest", "stream_id"))?,
            },
        };
        request.target.validate()?;
        if request.operation == [0; 32] || request.request == [0; 32] || request.generation == 0 {
            return Err(failure(ServiceFailure::Protocol));
        }
        Ok(request)
    }
    pub(crate) fn encoded(&self) -> Result<Vec<u8>> {
        self.target.validate()?;
        let mut output = Vec::with_capacity(9345);
        head(&mut output, 5, 8);
        uint(&mut output, 0);
        bytes(&mut output, &self.operation);
        uint(&mut output, 1);
        bytes(&mut output, &self.request);
        uint(&mut output, 2);
        uint(&mut output, self.protection.wire());
        uint(&mut output, 3);
        bytes(&mut output, &self.token);
        uint(&mut output, 4);
        uint(&mut output, self.generation);
        uint(&mut output, 5);
        output.extend_from_slice(&self.expected.encoded());
        uint(&mut output, 6);
        bytes(&mut output, &self.target.context);
        uint(&mut output, 7);
        uint(&mut output, self.target.stream);
        map(&output, "ResumeRequest", 9345)?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecoveryPolicy {
    pub max_issued_duration_ms: u64,
    pub max_token_bytes: u32,
    pub max_checkpoint_issues_per_operation: u32,
    pub minimum_checkpoint_interval_ms: u64,
}
impl ExecutionRecoveryPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_issued_duration_ms == 0
            || self.max_token_bytes == 0
            || self.max_token_bytes > 8192
            || self.max_checkpoint_issues_per_operation == 0
            || self.max_checkpoint_issues_per_operation > 1024
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryConfiguration {
    pub(crate) policy: ExecutionRecoveryPolicy,
    pub(crate) protection: CheckpointTokenProtection,
    pub(crate) key_id: [u8; 16],
    pub(crate) key_fingerprint: [u8; 32],
}
pub(crate) struct RecoveryOwner {
    pub(crate) configuration: RecoveryConfiguration,
    pub(crate) signing: ServiceCheckpointSigningKey,
    pub(crate) _charge: crate::environment_v4::EnvironmentCharge,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointConsumption {
    pub(crate) exchange_operation: [u8; 32],
    pub(crate) exchange_request: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) target: ResumeTargetBinding,
    // Missing historical evidence cannot authorize another callback entry.
    #[serde(default = "unknown_callback_entry")]
    pub(crate) callback_entered: bool,
}
fn unknown_callback_entry() -> bool {
    true
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointReissuance {
    pub(crate) previous_token_digest: [u8; 32],
    pub(crate) issuing_operation: [u8; 32],
    pub(crate) issuing_request: [u8; 32],
    pub(crate) requested_lifetime_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedCheckpoint {
    pub(crate) generation: u64,
    pub(crate) issues: u32,
    pub(crate) last_issue_ms: u64,
    pub(crate) checkpoint: Vec<u8>,
    pub(crate) token: Vec<u8>,
    pub(crate) expires_at_ms: u64,
    pub(crate) consumed: bool,
    pub(crate) consumption: Option<CheckpointConsumption>,
    #[serde(default)]
    pub(crate) reissuance: Option<CheckpointReissuance>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResumeSessionPolicy {
    pub(crate) max_issued_duration_ms: u64,
    pub(crate) max_token_bytes: u32,
}
pub(crate) fn application_features(artifact: Value<'_>) -> codec::Result<u64> {
    let policy = artifact.field("Artifact", "resume_policy")?;
    Ok((artifact.u("Artifact", "allowed_features")? & 1)
        | if policy.field("ResumePolicy", "enabled")?.boolean()?
            && artifact
                .field("Artifact", "session_contract")?
                .u("SessionContract", "application_profile")?
                == 2
        {
            artifact.u("Artifact", "allowed_features")? & 2
        } else {
            0
        })
}
impl ResumeSessionPolicy {
    pub(crate) fn capture(artifact: Value<'_>, selected: u64) -> codec::Result<Option<Self>> {
        if selected & 2 == 0 {
            return Ok(None);
        }
        if application_features(artifact)? & 2 == 0 {
            return Err("resume_policy");
        }
        let policy = artifact.field("Artifact", "resume_policy")?;
        Ok(Some(Self {
            max_issued_duration_ms: policy.u("ResumePolicy", "max_issued_token_duration_ms")?,
            max_token_bytes: u32::try_from(policy.u("ResumePolicy", "max_token_bytes")?)
                .map_err(|_| "resume_policy")?,
        }))
    }
}
pub(crate) fn claims(
    target: &crate::ExecutionTarget,
    checkpoint: &ApplicationCheckpoint,
    generation: u64,
    issued: u64,
    expires: u64,
) -> Result<Vec<u8>> {
    let mut nonce = [0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
        .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
    let mut output = Vec::with_capacity(4893);
    head(&mut output, 5, 11);
    for id in 0..11 {
        uint(&mut output, id);
        match id {
            0 => text(&mut output, &target.tenant),
            1 => text(&mut output, &target.caller_subject),
            2 => text(&mut output, &target.audience),
            3 => text(&mut output, &target.namespace),
            4 => bytes(&mut output, &target.operation_id),
            5 => bytes(&mut output, &target.request_digest),
            6 => output.extend_from_slice(&checkpoint.encoded()),
            7 => uint(&mut output, generation),
            8 => uint(&mut output, issued),
            9 => uint(&mut output, expires),
            10 => bytes(&mut output, &nonce),
            _ => unreachable!(),
        }
    }
    map(&output, "ResumeTokenClaims", 4893)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> crate::ExecutionTarget {
        crate::ExecutionTarget {
            tenant: "tenant".into(),
            audience: "service".into(),
            namespace: "example/files".into(),
            caller_subject: "client".into(),
            caller_authority: [1; 32],
            operation_id: [2; 32],
            request_digest: [3; 32],
            contract_digest: [4; 32],
        }
    }
    #[test]
    fn original_token_binds_checkpoint_generation_and_principal_under_both_independent_keys() {
        for protection in [
            CheckpointTokenProtection::Ed25519,
            CheckpointTokenProtection::HmacSha256,
        ] {
            let signing = ServiceCheckpointSigningKey::new(protection, [5; 16], [6; 32]).unwrap();
            let checkpoint = ApplicationCheckpoint::new("cursor".into(), vec![7, 8]).unwrap();
            let token = signing
                .sign(&claims(&target(), &checkpoint, 9, 1000, 5000).unwrap())
                .unwrap();
            let verified =
                ApplicationCheckpointToken::verify(&token, &signing.verification_key().unwrap())
                    .unwrap();
            assert_eq!(verified.generation(), 9);
            assert_eq!(verified.checkpoint(), &checkpoint);
            assert_eq!(verified.tenant, "tenant");
            assert_eq!(verified.caller, "client");
            assert_eq!(verified.operation, [2; 32]);
            assert_eq!(verified.request, [3; 32]);
            assert_eq!(verified.issued_at_ms(), 1000);
            assert_eq!(verified.expires_at_ms(), 5000);
            assert_eq!(verified.encoded(), token.as_slice());
            let other = ServiceCheckpointSigningKey::new(protection, [5; 16], [10; 32]).unwrap();
            assert_eq!(
                ApplicationCheckpointToken::verify(&token, &other.verification_key().unwrap())
                    .unwrap_err()
                    .0,
                ServiceFailure::PermissionDenied
            );
            let mut corrupted = token;
            *corrupted.last_mut().unwrap() ^= 1;
            assert_eq!(
                ApplicationCheckpointToken::verify(
                    &corrupted,
                    &signing.verification_key().unwrap()
                )
                .unwrap_err()
                .0,
                ServiceFailure::PermissionDenied
            );
        }
    }
    #[test]
    fn resume_request_fixes_the_verified_progress_and_the_captured_transport_target() {
        for protection in [
            CheckpointTokenProtection::Ed25519,
            CheckpointTokenProtection::HmacSha256,
        ] {
            let signing = ServiceCheckpointSigningKey::new(protection, [5; 16], [6; 32]).unwrap();
            let checkpoint = ApplicationCheckpoint::new("cursor".into(), vec![7]).unwrap();
            let encoded_token = signing
                .sign(&claims(&target(), &checkpoint, 9, 1000, 5000).unwrap())
                .unwrap();
            let token = ApplicationCheckpointToken::verify(
                &encoded_token,
                &signing.verification_key().unwrap(),
            )
            .unwrap();
            let captured = ResumeTargetBinding {
                context: [8; 32],
                stream: 3,
            };
            let request = ApplicationResumeRequest::prepare(&token, captured.clone()).unwrap();
            let decoded = ApplicationResumeRequest::capture(&request.encoded().unwrap()).unwrap();
            assert_eq!(decoded.target, captured);
            assert_eq!(decoded.operation, token.operation);
            assert_eq!(decoded.generation, 9);
            assert_eq!(decoded.expected, checkpoint);
            assert_eq!(decoded.token, encoded_token);
            let mut conflicting = request.clone();
            conflicting.generation = 10;
            assert!(conflicting.encoded().is_err());
            let mut conflicting = request.clone();
            conflicting.request = [10; 32];
            assert!(conflicting.encoded().is_err());
            let mut conflicting = request;
            conflicting.expected = ApplicationCheckpoint::new("cursor".into(), vec![9]).unwrap();
            assert!(conflicting.encoded().is_err());
        }
    }
    #[test]
    fn resume_confirmation_requires_progress_and_cannot_be_inferred_from_an_ack() {
        assert!(ApplicationResumeResult::capture(&[0xa1, 0, 0]).is_err());
        let checkpoint = ApplicationCheckpoint::new("cursor".into(), vec![7]).unwrap();
        let accepted = ApplicationResumeResult::accepted(checkpoint.clone(), 10).unwrap();
        assert_eq!(
            ApplicationResumeResult::capture(&accepted.encoded().unwrap()).unwrap(),
            accepted
        );
        assert_eq!(accepted.progress().unwrap().checkpoint, checkpoint);
        assert_eq!(accepted.progress().unwrap().generation, 10);
        for (code, status) in [
            (1, ApplicationResumeStatus::Rejected),
            (2, ApplicationResumeStatus::Unknown),
        ] {
            let result = ApplicationResumeResult::capture(&[0xa1, 0, code]).unwrap();
            assert_eq!(result.status(), status);
            assert!(result.progress().is_none());
        }
        assert!(ApplicationResumeResult::accepted(checkpoint, 0).is_err());
    }
    #[test]
    fn mac_uses_the_registered_full_unsigned_token_projection_including_key_id() {
        let signing = ServiceCheckpointSigningKey::new(
            CheckpointTokenProtection::HmacSha256,
            [5; 16],
            [6; 32],
        )
        .unwrap();
        let checkpoint = ApplicationCheckpoint::new("cursor".into(), vec![7]).unwrap();
        let claims = claims(&target(), &checkpoint, 1, 1000, 5000).unwrap();
        let token = signing.sign(&claims).unwrap();
        let value = map(&token, "ResumeMACToken", 4948).unwrap();
        let mut projection = Vec::new();
        head(&mut projection, 5, 2);
        uint(&mut projection, 0);
        projection.extend_from_slice(&claims);
        uint(&mut projection, 1);
        bytes(&mut projection, &[5; 16]);
        let mut mac = Hmac::<Sha256>::new_from_slice(&[6; 32]).unwrap();
        mac.update(b"flowersec/v4/resume-token/mac\0");
        mac.update(&(projection.len() as u32).to_be_bytes());
        mac.update(&projection);
        assert_eq!(
            parsed(value.field("ResumeMACToken", "mac").and_then(Value::bytes)).unwrap(),
            mac.finalize().into_bytes().as_slice()
        );
    }
    #[test]
    fn checkpoint_boundary_and_noncanonical_encoding_are_not_token_authority() {
        let checkpoint = ApplicationCheckpoint::new("cursor".into(), vec![7; 4096]).unwrap();
        assert_eq!(
            ApplicationCheckpoint::capture(&checkpoint.encoded()).unwrap(),
            checkpoint
        );
        assert!(ApplicationCheckpoint::new("cursor".into(), vec![7; 4097]).is_err());
        let mut encoded = checkpoint.encoded();
        encoded.push(0);
        assert!(ApplicationCheckpoint::capture(&encoded).is_err());
        assert!(
            ExecutionRecoveryPolicy {
                max_issued_duration_ms: 0,
                max_token_bytes: 8192,
                max_checkpoint_issues_per_operation: 16,
                minimum_checkpoint_interval_ms: 1000
            }
            .validate()
            .is_err()
        );
    }
}
