//! Independent test-only application byte relations. No authentication, live
//! channel/serial ownership, admission, dispatch or publication is established.
use super::cbor::{Error, Value};
use super::domains::{Argument, Arguments, descriptors};
use super::oracles::encoded;
use super::registry;
use super::shape::{Context, integer, lookup};
use super::text::Text;
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Deserialize)]
pub struct Variant {
    pub code: u64,
    pub fields: Vec<u64>,
    #[serde(default)]
    pub constants: BTreeMap<String, u64>,
    pub request: Option<String>,
    #[serde(default)]
    pub sdk_error: bool,
    #[serde(default)]
    pub application_error: bool,
    pub max_encoded_bytes: u64,
}
#[derive(Deserialize)]
pub struct Policy {
    pub execution_requests: Vec<String>,
    pub contract_variants: BTreeMap<String, BTreeMap<String, u64>>,
}
#[derive(Deserialize)]
pub struct SDKErrors {
    pub payload_schema: String,
}
#[derive(Deserialize)]
pub struct Registry {
    pub kinds: BTreeMap<String, Variant>,
    pub policy: Policy,
    pub sdk_errors: SDKErrors,
    pub sdk_error_codes: BTreeMap<String, u64>,
}
pub fn application_registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY
        .get_or_init(|| serde_json::from_str(registry::APPLICATION_HEADER_REGISTRY_JSON).unwrap())
}

// Borrowed syntax cannot outlive or mutate the caller's immutable byte slice.
// Digest/error results below own their bytes/scalars and retain no header owner.
#[derive(Debug)]
pub struct Header<'a> {
    pub kind: &'static str,
    pub value: Value<'a>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct BusinessResult {
    pub classification: &'static str,
    pub code: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub struct SDKResult {
    pub code: &'static str,
}
fn bounded(input: &[u8], cap: u64) -> Result<(), Error> {
    if u64::try_from(input.len()).map_err(|_| "application_input_size")? > cap {
        return Err("application_input_size");
    }
    Ok(())
}
fn uint(value: &Value<'_>) -> Result<u64, Error> {
    if let Value::Unsigned(n) = value {
        Ok(*n)
    } else {
        Err("integer_type")
    }
}

impl Text {
    fn app_bound(&self, name: &str) -> Result<u64, Error> {
        integer(&self.shape.descriptor(name)?["max_encoded_bytes"])
    }
    pub fn app_value<'v, 'a>(
        &self,
        name: &str,
        value: &'v Value<'a>,
        field: &str,
    ) -> Result<&'v Value<'a>, Error> {
        self.shape
            .named_value(name, value, field)?
            .ok_or("missing_field")
    }
    fn app_map<'a>(&self, name: &str, input: &'a [u8]) -> Result<Value<'a>, Error> {
        let cap = self.app_bound(name)?;
        bounded(input, cap)?;
        self.wire_map(input, name, &Context::default(), cap)
    }
    pub fn app_hash(&self, name: &str, args: Arguments) -> Result<Vec<u8>, Error> {
        self.evaluate_domain(
            name,
            &args,
            &Context::default(),
            self.app_bound("ServiceContract")?,
        )?
        .output
        .ok_or("registry_unresolved")
    }
    pub fn application_header<'a>(&self, input: &'a [u8]) -> Result<Header<'a>, Error> {
        let value = self.app_map("ApplicationHeader", input)?;
        let code = uint(self.app_value("ApplicationHeader", &value, "message_kind")?)?;
        let (kind, variant) = application_registry()
            .kinds
            .iter()
            .find(|(_, v)| v.code == code)
            .ok_or("application_kind")?;
        let Value::Map(pairs) = &value else {
            return Err("map_type");
        };
        if pairs.len() != variant.fields.len()
            || variant
                .fields
                .iter()
                .any(|id| lookup(&value, *id).is_none())
        {
            return Err("application_fields");
        }
        for (id, expected) in &variant.constants {
            let actual = lookup(&value, id.parse().map_err(|_| "registry_unresolved")?)
                .ok_or("application_fields")?;
            if uint(actual)? != *expected {
                return Err("application_constant");
            }
        }
        if variant.sdk_error
            && uint(self.app_value("ApplicationHeader", &value, "payload_length")?)?
                > self.app_bound(&application_registry().sdk_errors.payload_schema)?
        {
            return Err("application_sdk_error_limit");
        }
        Ok(Header { kind, value })
    }
    pub fn application_response<'a>(
        &self,
        original: &[u8],
        input: &'a [u8],
    ) -> Result<Header<'a>, Error> {
        let request = self.application_header(original)?;
        let result = self.application_header(input)?;
        let variant = &application_registry().kinds[result.kind];
        if variant.request.as_deref() != Some(request.kind) {
            return Err("application_response_kind");
        }
        for field in [
            "operation_id",
            "type_id",
            "request_digest",
            "service_contract_digest",
            "control_serial",
        ] {
            if self
                .shape
                .named_value("ApplicationHeader", &request.value, field)?
                != self
                    .shape
                    .named_value("ApplicationHeader", &result.value, field)?
            {
                return Err("application_response_binding");
            }
        }
        if let Some(limit) =
            self.shape
                .named_value("ApplicationHeader", &request.value, "response_limit_bytes")?
            && !variant.sdk_error
            && uint(self.app_value("ApplicationHeader", &result.value, "payload_length")?)?
                > uint(limit)?
        {
            return Err("application_response_limit");
        }
        Ok(result)
    }
    fn app_contract<'a>(
        &self,
        header: &Header<'_>,
        kind: &str,
        input: &'a [u8],
    ) -> Result<Value<'a>, Error> {
        let value = self.app_map("ServiceContract", input)?;
        let digest = self.app_hash(
            "service_contract_digest",
            [("contract".into(), Argument::Bytes(input.to_vec()))].into(),
        )?;
        if self.app_value(
            "ApplicationHeader",
            &header.value,
            "service_contract_digest",
        )? != &Value::Bytes(&digest)
            || self.app_value("ApplicationHeader", &header.value, "type_id")?
                != self.app_value("ServiceContract", &value, "type_id")?
        {
            return Err("application_contract_binding");
        }
        let expected = application_registry()
            .policy
            .contract_variants
            .get(kind)
            .ok_or("application_contract_variant")?;
        for (id, n) in expected {
            if lookup(&value, id.parse().map_err(|_| "registry_unresolved")?)
                != Some(&Value::Unsigned(*n))
            {
                return Err("application_contract_variant");
            }
        }
        Ok(value)
    }
    pub fn application_execution_digest(
        &self,
        input: &[u8],
        contract: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let header = self.application_header(input)?;
        if !application_registry()
            .policy
            .execution_requests
            .iter()
            .any(|kind| kind == header.kind)
        {
            return Err("application_execution_request");
        }
        let definition = self.app_contract(&header, header.kind, contract)?;
        bounded(
            payload,
            integer(
                &self
                    .shape
                    .named_field("ApplicationHeader", "payload_length")?
                    .1["max"],
            )?,
        )?;
        if payload.len() as u64
            != uint(self.app_value("ApplicationHeader", &header.value, "payload_length")?)?
        {
            return Err("application_payload_length");
        }
        if payload.len() as u64
            > uint(self.app_value("ServiceContract", &definition, "request_max_bytes")?)?
        {
            return Err("application_request_limit");
        }
        let limit =
            uint(self.app_value("ApplicationHeader", &header.value, "response_limit_bytes")?)?;
        if limit
            < uint(self.app_value("ServiceContract", &definition, "min_response_limit_bytes")?)?
            || limit
                > uint(self.app_value("ServiceContract", &definition, "max_response_bytes")?)?
        {
            return Err("application_response_limit");
        }
        let mut args: Arguments = [
            ("contract".into(), Argument::Bytes(contract.to_vec())),
            ("payload".into(), Argument::Bytes(payload.to_vec())),
        ]
        .into();
        for field in [
            "message_kind",
            "operation_id",
            "type_id",
            "deadline_at_ms",
            "admission_mode",
            "response_limit_bytes",
        ] {
            let argument = match self.app_value("ApplicationHeader", &header.value, field)? {
                Value::Unsigned(n) => Argument::UInt(u128::from(*n)),
                Value::Bytes(raw) => Argument::Bytes(raw.to_vec()),
                _ => return Err("field_type"),
            };
            args.insert(field.into(), argument);
        }
        self.app_hash("execution_request_digest", args)
    }
    pub fn verify_application_execution(
        &self,
        input: &[u8],
        contract: &[u8],
        payload: &[u8],
    ) -> Result<(), Error> {
        let header = self.application_header(input)?;
        let expected = self.application_execution_digest(input, contract, payload)?;
        if self.app_value("ApplicationHeader", &header.value, "request_digest")?
            != &Value::Bytes(&expected)
        {
            return Err("application_request_digest");
        }
        Ok(())
    }
    pub fn match_application_error_schema(
        &self,
        definition: &[u8],
        registered: &[u8],
    ) -> Result<(), Error> {
        let value = self.app_map("ErrorDefinition", definition)?;
        let domain = descriptors()
            .iter()
            .find(|d| d["name"] == "business_error_schema_digest")
            .ok_or("registry_unresolved")?;
        bounded(
            registered,
            integer(&domain["input_schema"]["parts"][0]["max_length"])?,
        )?;
        let digest = self.app_hash(
            "business_error_schema_digest",
            [("error_schema".into(), Argument::Bytes(registered.to_vec()))].into(),
        )?;
        if self.app_value("ErrorDefinition", &value, "schema_digest")? != &Value::Bytes(&digest) {
            return Err("application_error_schema_mismatch");
        }
        Ok(())
    }
    pub fn match_application_error_catalog(
        &self,
        input: &[u8],
        definitions: &[Vec<u8>],
    ) -> Result<(), Error> {
        let value = self.app_map("ServiceContract", input)?;
        if definitions.len() as u64
            > integer(
                &self
                    .shape
                    .named_field("ServiceContract", "application_error_catalog")?
                    .1["max_items"],
            )?
        {
            return Err("application_error_catalog_size");
        }
        let Value::Array(catalog) =
            self.app_value("ServiceContract", &value, "application_error_catalog")?
        else {
            return Err("field_type");
        };
        if catalog.len() != definitions.len() {
            return Err("application_error_catalog_mismatch");
        }
        for (item, raw) in catalog.iter().zip(definitions) {
            if encoded(item) != encoded(&self.app_map("ErrorDefinition", raw)?) {
                return Err("application_error_catalog_mismatch");
            }
        }
        Ok(())
    }
    pub fn application_business_error(
        &self,
        original: &[u8],
        input: &[u8],
        contract: &[u8],
        payload: &[u8],
    ) -> Result<BusinessResult, Error> {
        let header = self.application_response(original, input)?;
        let variant = &application_registry().kinds[header.kind];
        if !variant.application_error {
            return Err("application_error_kind");
        }
        let definition = self.app_contract(
            &header,
            variant.request.as_deref().ok_or("application_error_kind")?,
            contract,
        )?;
        let length = uint(self.app_value("ApplicationHeader", &header.value, "payload_length")?)?;
        bounded(payload, length)?;
        if payload.len() as u64 != length {
            return Err("application_payload_length");
        }
        let code =
            uint(self.app_value("ApplicationHeader", &header.value, "application_error_code")?)?;
        let Value::Array(catalog) =
            self.app_value("ServiceContract", &definition, "application_error_catalog")?
        else {
            return Err("field_type");
        };
        let mut classification = "unknown_application_error";
        for entry in catalog {
            if uint(self.app_value("ErrorDefinition", entry, "code")?)? == code {
                classification = if payload.len() as u64
                    > uint(self.app_value("ErrorDefinition", entry, "max_payload_bytes")?)?
                {
                    "application_result_decode_failed"
                } else {
                    "known_application_error"
                };
                break;
            }
        }
        Ok(BusinessResult {
            classification,
            code,
        })
    }
    pub fn application_sdk_error(
        &self,
        original: &[u8],
        input: &[u8],
        payload: &[u8],
    ) -> Result<SDKResult, Error> {
        let header = self.application_response(original, input)?;
        if !application_registry().kinds[header.kind].sdk_error {
            return Err("application_sdk_error_kind");
        }
        let name = &application_registry().sdk_errors.payload_schema;
        bounded(payload, self.app_bound(name)?)?;
        if payload.len() as u64
            != uint(self.app_value("ApplicationHeader", &header.value, "payload_length")?)?
        {
            return Err("application_payload_length");
        }
        let value = self.app_map(name, payload)?;
        let code = uint(self.app_value(name, &value, "code")?)?;
        let code = application_registry()
            .sdk_error_codes
            .iter()
            .find(|(_, n)| **n == code)
            .map(|(name, _)| name.as_str())
            .ok_or("application_sdk_error_code")?;
        let stream = matches!(
            header.kind,
            "execution_stream_sdk_error" | "transient_stream_sdk_error"
        );
        if stream && matches!(code, "request_message_aborted" | "response_output_stopped") {
            return Err("streaming_sdk_error_code");
        }
        if !stream && code == "source_overflow" {
            return Err("application_sdk_error_code");
        }
        // A declared execution digest is only an association on aborted input.
        Ok(SDKResult { code })
    }
}
