//! Canonical query-only persistence. Imported selectors never recreate a
//! local operation, Session, publication right, payload owner or credential.
use crate::{
    codec_v4::{self as codec, Limits, Value},
    environment_v4::{
        EnvironmentCharge, EnvironmentRoot, ResourceAccount, ResourceCharge, ResourceLimits,
    },
    execution_history::ExecutionTarget,
    rpc_wire_v4::ApplicationHeader,
    service_contract::{
        ServiceContract, ServiceError, ServiceFailure, ServiceSemantics, ServiceShape,
    },
};
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn error(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn parsed<T>(value: codec::Result<T>) -> Result<T> {
    value.map_err(|_| error(ServiceFailure::ContractMismatch))
}
fn head(bytes: &mut Vec<u8>, kind: u8, value: u64) {
    codec::encode_head(bytes, kind, value);
}
fn text(bytes: &mut Vec<u8>, value: &str) {
    head(bytes, 3, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}
fn data(bytes: &mut Vec<u8>, value: &[u8]) {
    head(bytes, 2, value.len() as u64);
    bytes.extend_from_slice(value);
}
struct Body {
    bytes: Zeroizing<Vec<u8>>,
    domain: String,
    target: ExecutionTarget,
    deadline_at_ms: u64,
    shape: ServiceShape,
    durable: bool,
    cooperative_cancel: bool,
    _charge: EnvironmentCharge,
}
#[derive(Clone)]
pub struct OperationReference(Arc<Body>);
impl fmt::Debug for OperationReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationReference { <opaque> }")
    }
}
impl PartialEq for OperationReference {
    fn eq(&self, other: &Self) -> bool {
        self.0.bytes.as_slice() == other.0.bytes.as_slice()
    }
}
impl Eq for OperationReference {}
impl OperationReference {
    pub fn target_domain(&self) -> &str {
        &self.0.domain
    }
    pub fn target(&self) -> ExecutionTarget {
        self.0.target.clone()
    }
    pub fn deadline_at_ms(&self) -> u64 {
        self.0.deadline_at_ms
    }
    pub fn admission_not_after_ms(&self) -> u64 {
        u64::from_be_bytes(
            self.0.target.operation_id[..8]
                .try_into()
                .expect("bounded operation identity"),
        )
    }
    pub fn shape(&self) -> ServiceShape {
        self.0.shape
    }
    pub fn durable(&self) -> bool {
        self.0.durable
    }
    pub fn cooperative_cancel(&self) -> bool {
        self.0.cooperative_cancel
    }
}
pub struct OperationReferenceCodec {
    root: Arc<EnvironmentRoot>,
    domain: String,
    workspace: Mutex<Zeroizing<Vec<u8>>>,
    _charge: crate::crypto_v4::connect::PreparationCharge,
}
impl fmt::Debug for OperationReferenceCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationReferenceCodec { <opaque> }")
    }
}
impl OperationReferenceCodec {
    pub(crate) fn preparation_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 16384,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        }
    }
    pub(crate) fn new(root: Arc<EnvironmentRoot>, domain: String) -> Result<Self> {
        let charge = root.reserve_environment(Self::preparation_limits())?;
        Self::new_with_charge(root, domain, charge.into())
    }
    pub(crate) fn new_prepaid(
        account: &ResourceAccount,
        domain: String,
        charge: ResourceCharge,
    ) -> Result<Self> {
        if !charge.matches(account, Self::preparation_limits()) {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        Self::new_with_charge(account.environment_root().clone(), domain, charge.into())
    }
    fn new_with_charge(
        root: Arc<EnvironmentRoot>,
        domain: String,
        charge: crate::crypto_v4::connect::PreparationCharge,
    ) -> Result<Self> {
        if domain.is_empty()
            || domain.len() > 128
            || !domain.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:/@-".contains(&byte)
            })
        {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        Ok(Self {
            root,
            domain,
            workspace: Mutex::new(Zeroizing::new(Vec::with_capacity(2048))),
            _charge: charge,
        })
    }
    pub fn import(&self, canonical: &[u8]) -> Result<OperationReference> {
        let charge = self.root.reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            ..ResourceLimits::default()
        })?;
        let value = parsed(codec::decode(
            canonical,
            "OperationReference",
            Limits {
                bytes: 2048,
                nodes: 64,
            },
            None,
        ))?;
        let domain = parsed(
            value
                .field("OperationReference", "target_domain")
                .and_then(Value::text),
        )?;
        if domain != self.domain {
            return Err(error(ServiceFailure::ContractMismatch));
        }
        let target = parsed(value.field("OperationReference", "target"))?;
        let string = |name| {
            parsed(
                target
                    .field("ExecutionManagementTarget", name)
                    .and_then(Value::text),
            )
            .map(str::to_owned)
        };
        let target = ExecutionTarget {
            tenant: string("tenant_id")?,
            audience: string("audience")?,
            namespace: string("service_namespace")?,
            caller_subject: string("caller_subject")?,
            caller_authority: parsed(target.b("ExecutionManagementTarget", "caller_authority"))?,
            operation_id: parsed(target.b("ExecutionManagementTarget", "operation_id"))?,
            request_digest: parsed(target.b("ExecutionManagementTarget", "request_digest"))?,
            contract_digest: parsed(
                target.b("ExecutionManagementTarget", "service_contract_digest"),
            )?,
        };
        target.validate()?;
        let deadline_at_ms = parsed(value.u("OperationReference", "deadline_at_ms"))?;
        let cutoff = u64::from_be_bytes(
            target.operation_id[..8]
                .try_into()
                .map_err(|_| error(ServiceFailure::ContractMismatch))?,
        );
        if cutoff == 0 || cutoff > deadline_at_ms {
            return Err(error(ServiceFailure::ContractMismatch));
        }
        let shape = match parsed(value.u("OperationReference", "call_shape"))? {
            0 => ServiceShape::Unary,
            1 => ServiceShape::ServerStreaming,
            2 => ServiceShape::Notify,
            _ => return Err(error(ServiceFailure::ContractMismatch)),
        };
        Ok(OperationReference(Arc::new(Body {
            bytes: Zeroizing::new(canonical.to_vec()),
            domain: domain.to_owned(),
            target,
            deadline_at_ms,
            shape,
            durable: parsed(value.u("OperationReference", "execution_mode"))? == 1,
            cooperative_cancel: parsed(value.u("OperationReference", "cancel_mode"))? == 1,
            _charge: charge,
        })))
    }
    pub fn export(&self, reference: &OperationReference, destination: &mut [u8]) -> Result<usize> {
        if reference.target_domain() != self.domain || destination.len() < reference.0.bytes.len() {
            return Err(error(ServiceFailure::ContractMismatch));
        }
        destination[..reference.0.bytes.len()].copy_from_slice(&reference.0.bytes);
        Ok(reference.0.bytes.len())
    }
    pub(crate) fn capture(
        &self,
        target: ExecutionTarget,
        header: &ApplicationHeader,
        contract: &ServiceContract,
    ) -> Result<OperationReference> {
        target.validate()?;
        contract.check_environment(&self.root)?;
        if contract.semantics() != ServiceSemantics::Execution
            || target.operation_id != header.bytes(1)?
            || target.request_digest != header.bytes(4)?
            || target.contract_digest != header.bytes(6)?
            || contract.digest() != target.contract_digest
            || contract.namespace() != target.namespace
            || contract.type_id() != header.type_id()?
        {
            return Err(error(ServiceFailure::ContractMismatch));
        }
        let mut bytes = self.workspace.lock().expect("reference workspace");
        bytes.clear();
        head(&mut bytes, 5, 7);
        head(&mut bytes, 0, 0);
        head(&mut bytes, 0, 1);
        head(&mut bytes, 0, 1);
        text(&mut bytes, &self.domain);
        head(&mut bytes, 0, 2);
        encode_target(&mut bytes, &target);
        head(&mut bytes, 0, 3);
        head(
            &mut bytes,
            0,
            match contract.shape() {
                ServiceShape::Unary => 0,
                ServiceShape::ServerStreaming => 1,
                ServiceShape::Notify => 2,
            },
        );
        head(&mut bytes, 0, 4);
        head(&mut bytes, 0, contract.uint(13)?);
        head(&mut bytes, 0, 5);
        head(&mut bytes, 0, header.uint(5)?);
        head(&mut bytes, 0, 6);
        head(&mut bytes, 0, contract.uint(19)?);
        let reference = self.import(&bytes);
        bytes.fill(0);
        bytes.clear();
        reference
    }
}
pub(crate) fn encode_target(bytes: &mut Vec<u8>, target: &ExecutionTarget) {
    head(bytes, 5, 8);
    for (index, value) in [
        &target.tenant,
        &target.audience,
        &target.namespace,
        &target.caller_subject,
    ]
    .into_iter()
    .enumerate()
    {
        head(bytes, 0, index as u64);
        text(bytes, value);
    }
    for (index, value) in [
        &target.caller_authority,
        &target.operation_id,
        &target.request_digest,
        &target.contract_digest,
    ]
    .into_iter()
    .enumerate()
    {
        head(bytes, 0, index as u64 + 4);
        data(bytes, value);
    }
}
