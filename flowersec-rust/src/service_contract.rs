//! Immutable application definitions and canonical service advertisements.
//! These values describe a method; only the original authenticated invocation
//! can grant dispatch, publication or recovery authority.
use crate::{
    api_v4::TransportEnvironment,
    codec_v4::{self as codec, Limits, Value},
    contract_acceptance_v4::ContractAcceptance,
    environment_v4::{
        EnvironmentError, EnvironmentRoot, ResourceAccount, ResourceCharge, ResourceLimits,
    },
};
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ServiceShape {
    Unary,
    ServerStreaming,
    Notify,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSemantics {
    Transient,
    Execution,
    Observation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceError(pub ServiceFailure);
impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let ServiceFailure::StorageFormatIncompatible(format) = self.0 {
            f.write_str(format.code())
        } else {
            write!(f, "service contract failed: {:?}", self.0)
        }
    }
}
impl std::error::Error for ServiceError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ServiceFailure {
    ConfigurationCapacity,
    ResourceExhausted,
    Closed,
    NotReady,
    ContractMismatch,
    ContractPolicyRejected,
    AdmissionWindowClosed,
    DeadlineExceeded,
    PermissionDenied,
    OperationConflict,
    HistoryUnknown,
    ResultExpired,
    ServiceUnavailable,
    ServiceFailed,
    Protocol,
    Canceled,
    DecodeFailed,
    EncodeFailed,
    DependencyUnavailable,
    CompletionDependencyUnavailable,
    KnownApplicationDependency,
    ResultModeConflict,
    ResponseLimitUnsupported,
    RequestMessageAborted,
    StorageFormatIncompatible(crate::StorageFormatIncompatibility),
}
impl ServiceError {
    pub fn storage_format(&self) -> Option<&crate::StorageFormatIncompatibility> {
        match &self.0 {
            ServiceFailure::StorageFormatIncompatible(format) => Some(format),
            _ => None,
        }
    }
    pub(crate) fn from_sdk_payload(payload: &[u8]) -> Result<Self> {
        let value = syntax(codec::decode(
            payload,
            "ApplicationSDKError",
            Limits {
                bytes: 256,
                nodes: 4,
            },
            None,
        ))?;
        let code = syntax(value.u("ApplicationSDKError", "code"))?;
        Ok(Self(match code {
            3 => ServiceFailure::ContractMismatch,
            4 => ServiceFailure::ResponseLimitUnsupported,
            5 => ServiceFailure::ResourceExhausted,
            7 => ServiceFailure::PermissionDenied,
            8 => ServiceFailure::DeadlineExceeded,
            9 => ServiceFailure::ServiceFailed,
            11 => ServiceFailure::OperationConflict,
            12 => ServiceFailure::ResultExpired,
            1 | 2 | 6 | 10 => ServiceFailure::ServiceUnavailable,
            _ => ServiceFailure::Protocol,
        }))
    }
}
impl From<crate::ApplicationInvocationError> for ServiceError {
    fn from(error: crate::ApplicationInvocationError) -> Self {
        use crate::ApplicationInvocationError as E;
        Self(match error {
            E::DependencyUnavailable => ServiceFailure::DependencyUnavailable,
            E::CompletionDependencyUnavailable => ServiceFailure::CompletionDependencyUnavailable,
            E::KnownApplicationDependency => ServiceFailure::KnownApplicationDependency,
            E::ResourceExhausted => ServiceFailure::ResourceExhausted,
            E::Canceled => ServiceFailure::Canceled,
            E::Closed => ServiceFailure::Closed,
        })
    }
}
impl From<EnvironmentError> for ServiceError {
    fn from(error: EnvironmentError) -> Self {
        Self(match error {
            EnvironmentError::Capacity => ServiceFailure::ResourceExhausted,
            EnvironmentError::Closed => ServiceFailure::Closed,
            _ => ServiceFailure::ServiceUnavailable,
        })
    }
}
pub(crate) type Result<T> = std::result::Result<T, ServiceError>;
fn syntax<T>(value: codec::Result<T>) -> Result<T> {
    value.map_err(|_| ServiceError(ServiceFailure::ContractMismatch))
}
fn configuration() -> ServiceError {
    ServiceError(ServiceFailure::ConfigurationCapacity)
}
fn security_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
}
fn identifier(text: &str) -> bool {
    security_id(text)
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:/@-".contains(&b))
}
fn export_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && !matches!(
            text,
            "bind" | "close" | "constructor" | "prototype" | "__proto__"
        )
}

/// The codec schema is an application-owned definition. Its callbacks borrow
/// only the current owned payload; they do not receive a Session or key owner.
pub trait MessageCodec<T>: std::any::Any + Send + Sync + 'static {
    fn definition(&self) -> &MessageDefinition;
    fn encode(&self, value: &T, destination: &mut [u8]) -> Result<usize>;
    fn decode(&self, source: &[u8]) -> Result<T>;
    fn application_bytes(&self) -> u64 {
        65536
    }
    fn encode_with_context(
        &self,
        value: &T,
        destination: &mut [u8],
        context: &crate::ApplicationInvocationContext,
    ) -> Result<usize> {
        context.check_cancellation()?;
        self.encode(value, destination)
    }
    fn decode_with_context(
        &self,
        source: &[u8],
        context: &crate::ApplicationInvocationContext,
    ) -> Result<T> {
        context.check_cancellation()?;
        self.decode(source)
    }
}
#[async_trait::async_trait]
pub trait AsyncMessageCodec<T>: Send + Sync + 'static {
    fn definition(&self) -> &MessageDefinition;
    fn application_bytes(&self) -> u64;
    async fn encode(
        &self,
        value: &T,
        context: crate::ApplicationInvocationContext,
    ) -> Result<Vec<u8>>;
    async fn decode(
        &self,
        source: &[u8],
        context: crate::ApplicationInvocationContext,
    ) -> Result<T>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageDefinition {
    schema_digest: [u8; 32],
    revision: String,
    maximum: u32,
}
impl MessageDefinition {
    pub fn new(schema_digest: [u8; 32], revision: String, maximum: u32) -> Result<Self> {
        if schema_digest == [0; 32] || !identifier(&revision) || maximum == 0 || maximum > 1 << 20 {
            return Err(configuration());
        }
        Ok(Self {
            schema_digest,
            revision,
            maximum,
        })
    }
    pub fn schema_digest(&self) -> [u8; 32] {
        self.schema_digest
    }
    pub fn revision(&self) -> &str {
        &self.revision
    }
    pub fn max_message_bytes(&self) -> u32 {
        self.maximum
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationErrorDefinition {
    pub code: u32,
    pub message: MessageDefinition,
    pub max_payload_bytes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamContentDefinition {
    pub schema_revision: String,
    pub canonical: Vec<u8>,
    pub read_type_id: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamingLimits {
    pub max_item_count: u32,
    pub max_payload_bytes: u64,
    pub max_duration_ms: u64,
}
#[derive(Clone, Debug)]
pub struct MethodDefinitionOptions {
    pub type_id: u32,
    pub shape: ServiceShape,
    pub semantics: ServiceSemantics,
    pub request: MessageDefinition,
    pub response: Option<MessageDefinition>,
    pub response_revision: String,
    pub request_max_bytes: u32,
    pub min_response_limit_bytes: u32,
    pub max_response_bytes: u32,
    pub require_durable: bool,
    pub checkpoint_format: Option<String>,
    pub restart_flush_deadline_ms: Option<u64>,
    pub streaming: Option<StreamingLimits>,
    pub content: Option<StreamContentDefinition>,
    pub errors: Vec<ApplicationErrorDefinition>,
}
#[derive(Clone, Debug)]
pub struct MethodDefinition(Arc<MethodDefinitionOptions>);
impl MethodDefinition {
    pub fn new(options: MethodDefinitionOptions) -> Result<Self> {
        let o = &options;
        if o.type_id == 0
            || o.request_max_bytes > o.request.maximum
            || o.max_response_bytes > 1 << 20
            || o.min_response_limit_bytes > o.max_response_bytes
            || !identifier(&o.response_revision)
            || o.errors.len() > 64
            || o.shape == ServiceShape::Notify
                && (o.response.is_some()
                    || o.max_response_bytes != 0
                    || o.min_response_limit_bytes != 0
                    || !o.errors.is_empty())
            || o.shape != ServiceShape::Notify
                && o.response.as_ref().is_none_or(|r| {
                    r.revision != o.response_revision || o.max_response_bytes > r.maximum
                })
            || o.shape == ServiceShape::Notify && o.semantics == ServiceSemantics::Transient
            || o.shape != ServiceShape::Notify && o.semantics == ServiceSemantics::Observation
            || o.require_durable && o.semantics != ServiceSemantics::Execution
            || o.restart_flush_deadline_ms
                .is_some_and(|n| n == 0 || n > 120000)
            || o.restart_flush_deadline_ms.is_some()
                && (o.shape != ServiceShape::Unary || o.semantics != ServiceSemantics::Execution)
            || o.checkpoint_format.as_ref().is_some_and(|f| !identifier(f))
            || o.checkpoint_format.is_some() && o.semantics != ServiceSemantics::Execution
            || (o.shape == ServiceShape::ServerStreaming) != o.streaming.is_some()
            || o.streaming.is_some_and(|s| {
                s.max_item_count == 0 || s.max_payload_bytes == 0 || s.max_duration_ms == 0
            })
            || o.content.as_ref().is_some_and(|c| {
                o.shape != ServiceShape::ServerStreaming
                    || o.semantics != ServiceSemantics::Execution
                    || !identifier(&c.schema_revision)
                    || c.read_type_id == 0
                    || c.read_type_id == o.type_id
                    || c.canonical.is_empty()
                    || c.canonical.len() > 2048
            })
        {
            return Err(configuration());
        }
        for (index, error) in o.errors.iter().enumerate() {
            if error.code == 0
                || error.max_payload_bytes > error.message.maximum
                || o.errors[..index].iter().any(|old| old.code == error.code)
            {
                return Err(configuration());
            }
        }
        let mut options = options;
        options.errors.sort_by_key(|error| error.code);
        Ok(Self(Arc::new(options)))
    }
    pub fn type_id(&self) -> u32 {
        self.0.type_id
    }
    pub fn shape(&self) -> ServiceShape {
        self.0.shape
    }
    pub fn semantics(&self) -> ServiceSemantics {
        self.0.semantics
    }
    pub fn options(&self) -> &MethodDefinitionOptions {
        &self.0
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
#[derive(Clone, Debug)]
pub struct ServiceMethod {
    pub name: String,
    pub export_name: String,
    pub method: MethodDefinition,
}
#[derive(Clone, Debug)]
pub struct ServiceDefinition {
    namespace: String,
    methods: Arc<[ServiceMethod]>,
}
impl ServiceDefinition {
    pub fn new(namespace: String, methods: Vec<ServiceMethod>) -> Result<Self> {
        if !identifier(&namespace) || methods.is_empty() || methods.len() > 256 {
            return Err(configuration());
        }
        for (index, entry) in methods.iter().enumerate() {
            if !export_name(&entry.name)
                || !export_name(&entry.export_name)
                || methods[..index].iter().any(|old| {
                    old.name == entry.name
                        || old.export_name == entry.export_name
                        || old.method.type_id() == entry.method.type_id()
                })
            {
                return Err(configuration());
            }
        }
        for entry in &methods {
            if let Some(content) = &entry.method.options().content
                && !methods.iter().any(|reader| {
                    reader.method.type_id() == content.read_type_id
                        && reader.method.shape() == ServiceShape::Unary
                })
            {
                return Err(configuration());
            }
        }
        Ok(Self {
            namespace,
            methods: methods.into(),
        })
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn methods(&self) -> &[ServiceMethod] {
        &self.methods
    }
    pub(crate) fn contains(&self, method: &MethodDefinition) -> bool {
        self.methods.iter().any(|entry| entry.method.same(method))
    }
}

struct ContractBody {
    canonical: Zeroizing<Vec<u8>>,
    digest: [u8; 32],
    root: Arc<EnvironmentRoot>,
    namespace: String,
    uints: [Option<u64>; 29],
    spans: [Option<(u16, u16)>; 29],
    _charge: crate::crypto_v4::connect::PreparationCharge,
}
impl fmt::Debug for ContractBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceContract { <opaque> }")
    }
}
#[derive(Clone, Debug)]
pub struct ServiceContract(Arc<ContractBody>);
impl ServiceContract {
    pub fn capture(environment: &TransportEnvironment, canonical: &[u8]) -> Result<Self> {
        Self::capture_root(environment.root(), canonical)
    }
    pub(crate) fn preparation_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 12288,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn capture_root(root: &Arc<EnvironmentRoot>, canonical: &[u8]) -> Result<Self> {
        let charge = root.reserve_environment(Self::preparation_limits())?;
        Self::capture_with_charge(root, canonical, charge.into())
    }
    pub(crate) fn capture_prepaid(
        account: &ResourceAccount,
        canonical: &[u8],
        charge: ResourceCharge,
    ) -> Result<Self> {
        if !charge.matches(account, Self::preparation_limits()) {
            return Err(ServiceError(ServiceFailure::ConfigurationCapacity));
        }
        Self::capture_with_charge(account.environment_root(), canonical, charge.into())
    }
    fn capture_with_charge(
        root: &Arc<EnvironmentRoot>,
        canonical: &[u8],
        charge: crate::crypto_v4::connect::PreparationCharge,
    ) -> Result<Self> {
        let value = syntax(codec::decode(
            canonical,
            "ServiceContract",
            Limits {
                bytes: 8192,
                nodes: 16384,
            },
            None,
        ))?;
        let digest = syntax(codec::digest("service_contract_digest", value))?;
        let namespace = syntax(
            value
                .field("ServiceContract", "service_namespace")
                .and_then(Value::text),
        )?
        .to_owned();
        let mut uints = [None; 29];
        let mut spans = [None; 29];
        let mut children = syntax(value.children())?;
        while let Some(key) = children.next() {
            let key = syntax(key.and_then(Value::uint))? as usize;
            let field = syntax(children.next().ok_or("truncated").and_then(|v| v))?;
            if key >= spans.len() {
                return Err(ServiceError(ServiceFailure::ContractMismatch));
            }
            let start = field.raw().as_ptr() as usize - canonical.as_ptr() as usize;
            spans[key] = Some((start as u16, (start + field.raw().len()) as u16));
            if field.raw()[0] >> 5 == 0 {
                uints[key] = Some(syntax(field.uint())?);
            }
        }
        Ok(Self(Arc::new(ContractBody {
            canonical: Zeroizing::new(canonical.to_vec()),
            digest,
            root: root.clone(),
            namespace,
            uints,
            spans,
            _charge: charge,
        })))
    }
    pub fn namespace(&self) -> &str {
        &self.0.namespace
    }
    pub fn type_id(&self) -> u32 {
        self.0.uints[1].expect("validated type id") as u32
    }
    pub fn shape(&self) -> ServiceShape {
        match self.0.uints[2].expect("validated shape") {
            0 => ServiceShape::Unary,
            1 => ServiceShape::ServerStreaming,
            _ => ServiceShape::Notify,
        }
    }
    pub fn semantics(&self) -> ServiceSemantics {
        let id = match self.shape() {
            ServiceShape::Unary => 3,
            ServiceShape::ServerStreaming => 4,
            ServiceShape::Notify => 5,
        };
        if self.0.uints[id] == Some(1) {
            ServiceSemantics::Execution
        } else if self.shape() == ServiceShape::Notify {
            ServiceSemantics::Observation
        } else {
            ServiceSemantics::Transient
        }
    }
    pub fn digest(&self) -> [u8; 32] {
        self.0.digest
    }
    pub fn encoded(&self) -> &[u8] {
        &self.0.canonical
    }
    pub fn request_revision(&self) -> Result<&str> {
        let value = syntax(codec::decode(
            self.encoded(),
            "ServiceContract",
            Limits {
                bytes: 8192,
                nodes: 16384,
            },
            None,
        ))?;
        syntax(
            value
                .field("ServiceContract", "request_schema_revision")
                .and_then(Value::text),
        )
    }
    pub(crate) fn uint(&self, id: usize) -> Result<u64> {
        self.0
            .uints
            .get(id)
            .copied()
            .flatten()
            .ok_or(ServiceError(ServiceFailure::ContractMismatch))
    }
    pub(crate) fn bool(&self, id: usize) -> Result<bool> {
        let encoded = self
            .field(id)
            .ok_or(ServiceError(ServiceFailure::ContractMismatch))?;
        match encoded {
            [0xf4] => Ok(false),
            [0xf5] => Ok(true),
            _ => Err(ServiceError(ServiceFailure::ContractMismatch)),
        }
    }
    pub(crate) fn optional_uint(&self, id: usize) -> Option<u64> {
        self.0.uints.get(id).copied().flatten()
    }
    pub(crate) fn response_payload_limit(&self, application_error: Option<u32>) -> Result<u64> {
        let Some(code) = application_error else {
            return self.uint(10);
        };
        let value = syntax(codec::decode(
            self.encoded(),
            "ServiceContract",
            Limits {
                bytes: 8192,
                nodes: 16384,
            },
            None,
        ))?;
        let catalog = syntax(value.optional("ServiceContract", "application_error_catalog"))?
            .ok_or(ServiceError(ServiceFailure::ContractMismatch))?;
        for entry in syntax(catalog.children())? {
            let entry = syntax(entry)?;
            if syntax(entry.u("ErrorDefinition", "code"))? == u64::from(code) {
                return syntax(entry.u("ErrorDefinition", "max_payload_bytes"));
            }
        }
        Err(ServiceError(ServiceFailure::ContractMismatch))
    }
    pub(crate) fn check_environment(&self, root: &Arc<EnvironmentRoot>) -> Result<()> {
        if !Arc::ptr_eq(&self.0.root, root) {
            return Err(configuration());
        }
        if root.is_closed() {
            return Err(ServiceError(ServiceFailure::Closed));
        }
        Ok(())
    }
    pub(crate) fn field(&self, id: usize) -> Option<&[u8]> {
        self.0
            .spans
            .get(id)
            .copied()
            .flatten()
            .map(|(a, b)| &self.0.canonical[usize::from(a)..usize::from(b)])
    }
    pub fn check_policy(
        &self,
        acceptance: ContractAcceptance,
        current: Option<&Self>,
        explicit_update: bool,
    ) -> Result<()> {
        acceptance
            .check(self.encoded(), current.map(Self::encoded), explicit_update)
            .map_err(|_| ServiceError(ServiceFailure::ContractPolicyRejected))
    }
    pub fn check_method(
        &self,
        definition: &ServiceDefinition,
        method: &MethodDefinition,
    ) -> Result<()> {
        if !definition.contains(method)
            || self.namespace() != definition.namespace()
            || self.type_id() != method.type_id()
            || self.shape() != method.shape()
            || self.semantics() != method.semantics()
        {
            return Err(ServiceError(ServiceFailure::ContractMismatch));
        }
        let o = method.options();
        let value = syntax(codec::decode(
            self.encoded(),
            "ServiceContract",
            Limits {
                bytes: 8192,
                nodes: 16384,
            },
            None,
        ))?;
        let revision = |id: u64| -> Result<Option<&str>> {
            let mut children = syntax(value.children())?;
            while let Some(key) = children.next() {
                let key = syntax(key.and_then(Value::uint))?;
                let field = syntax(children.next().ok_or("truncated").and_then(|v| v))?;
                if key == id {
                    return Ok(Some(syntax(field.text())?));
                }
            }
            Ok(None)
        };
        if revision(6)? != Some(o.request.revision())
            || revision(7)? != Some(o.response_revision.as_str())
            || self.uint(23)? > u64::from(o.request_max_bytes)
            || self.uint(9)? < u64::from(o.min_response_limit_bytes)
            || self.uint(10)? > u64::from(o.max_response_bytes)
            || o.require_durable && self.optional_uint(13) != Some(1)
            || revision(20)? != o.checkpoint_format.as_deref()
        {
            return Err(ServiceError(ServiceFailure::ContractMismatch));
        }
        if let Some(stream) = o.streaming
            && (self.uint(24)? > u64::from(stream.max_item_count)
                || self.uint(25)? > stream.max_payload_bytes
                || self.uint(26)? > stream.max_duration_ms)
        {
            return Err(ServiceError(ServiceFailure::ContractMismatch));
        }
        let restart = syntax(
            value
                .field("ServiceContract", "restart_flush")
                .and_then(Value::boolean),
        )?;
        if restart != o.restart_flush_deadline_ms.is_some() {
            return Err(ServiceError(ServiceFailure::ContractMismatch));
        }
        if let Some(deadline) = o.restart_flush_deadline_ms
            && self.uint(22)? != deadline
        {
            return Err(ServiceError(ServiceFailure::ContractMismatch));
        }
        let catalog = value
            .optional("ServiceContract", "application_error_catalog")
            .map_err(|_| ServiceError(ServiceFailure::ContractMismatch))?;
        if let Some(catalog) = catalog {
            let entries = syntax(catalog.children())?;
            let mut count = 0;
            for entry in entries {
                let entry = syntax(entry)?;
                let code = syntax(entry.u("ErrorDefinition", "code"))? as u32;
                let Some(error) = o.errors.iter().find(|error| error.code == code) else {
                    return Err(ServiceError(ServiceFailure::ContractMismatch));
                };
                if syntax(
                    entry
                        .field("ErrorDefinition", "schema_revision")
                        .and_then(Value::text),
                )? != error.message.revision()
                    || syntax(entry.u("ErrorDefinition", "max_payload_bytes"))?
                        > u64::from(error.max_payload_bytes)
                    || syntax(entry.b::<32>("ErrorDefinition", "schema_digest"))?
                        != error.message.schema_digest()
                {
                    return Err(ServiceError(ServiceFailure::ContractMismatch));
                }
                count += 1;
            }
            if count != o.errors.len() {
                return Err(ServiceError(ServiceFailure::ContractMismatch));
            }
        } else if !o.errors.is_empty() {
            return Err(ServiceError(ServiceFailure::ContractMismatch));
        }
        match &o.content {
            None => {
                if self.shape() == ServiceShape::ServerStreaming
                    && self.semantics() == ServiceSemantics::Execution
                    && self.field(28) != Some(&[0xa1, 0x00, 0x00][..])
                {
                    return Err(ServiceError(ServiceFailure::ContractMismatch));
                }
            }
            Some(content) => {
                let policy = syntax(value.field("ServiceContract", "stream_content_policy"))?;
                let definition = syntax(
                    policy
                        .field("StreamContentPolicy", "definition_bytes")
                        .and_then(Value::bytes),
                )?;
                if syntax(policy.u("StreamContentPolicy", "mode"))? != 1
                    || syntax(
                        policy
                            .field("StreamContentPolicy", "definition_schema_revision")
                            .and_then(Value::text),
                    )? != content.schema_revision
                    || definition != content.canonical.as_slice()
                {
                    return Err(ServiceError(ServiceFailure::ContractMismatch));
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionOffer {
    contract_digest: [u8; 32],
    not_before_ms: u64,
    not_after_ms: u64,
}
impl AdmissionOffer {
    pub fn capture(
        canonical: &[u8],
        contract: &ServiceContract,
        maximum_window_ms: u64,
    ) -> Result<Self> {
        if maximum_window_ms == 0 || contract.semantics() != ServiceSemantics::Execution {
            return Err(configuration());
        }
        let value = syntax(codec::decode(
            canonical,
            "AdmissionOffer",
            Limits {
                bytes: 256,
                nodes: 16,
            },
            None,
        ))?;
        let digest = syntax(value.b("AdmissionOffer", "service_contract_digest"))?;
        let before = syntax(value.u("AdmissionOffer", "not_before_ms"))?;
        let after = syntax(value.u("AdmissionOffer", "not_after_ms"))?;
        if digest != contract.digest() || before >= after || after - before > maximum_window_ms {
            return Err(ServiceError(ServiceFailure::ContractMismatch));
        }
        Ok(Self {
            contract_digest: digest,
            not_before_ms: before,
            not_after_ms: after,
        })
    }
    pub(crate) fn current(
        contract: &ServiceContract,
        lower: u64,
        upper: u64,
        window_ms: u64,
    ) -> Result<Self> {
        if contract.semantics() != ServiceSemantics::Execution
            || window_ms == 0
            || window_ms > contract.uint(16)?
        {
            return Err(configuration());
        }
        let after = lower.checked_add(window_ms).ok_or(configuration())?;
        if upper >= after {
            return Err(ServiceError(ServiceFailure::AdmissionWindowClosed));
        }
        Ok(Self {
            contract_digest: contract.digest(),
            not_before_ms: lower,
            not_after_ms: after,
        })
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(64);
        codec::encode_head(&mut encoded, 5, 3);
        codec::encode_head(&mut encoded, 0, 0);
        codec::encode_head(&mut encoded, 2, 32);
        encoded.extend_from_slice(&self.contract_digest);
        codec::encode_head(&mut encoded, 0, 1);
        codec::encode_head(&mut encoded, 0, self.not_before_ms);
        codec::encode_head(&mut encoded, 0, 2);
        codec::encode_head(&mut encoded, 0, self.not_after_ms);
        encoded
    }
    pub fn not_before_ms(&self) -> u64 {
        self.not_before_ms
    }
    pub fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }
    pub(crate) fn check_interval(
        &self,
        contract: &ServiceContract,
        cutoff: u64,
        lower_ms: u64,
        upper_ms: u64,
    ) -> Result<()> {
        if self.contract_digest != contract.digest() {
            return Err(ServiceError(ServiceFailure::ContractMismatch));
        }
        if lower_ms < self.not_before_ms || upper_ms >= cutoff || cutoff > self.not_after_ms {
            return Err(ServiceError(ServiceFailure::AdmissionWindowClosed));
        }
        Ok(())
    }
}
