//! Test-only generated domain inputs and primitives, not live key/provider authority.
use super::cbor::{Error, Value};
use super::oracles::encoded;
use super::registry;
use super::shape::{Context, integer};
use super::text::Text;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Argument {
    UInt(u128),
    Bytes(Vec<u8>),
    Text(String),
    Invalid,
}
pub type Arguments = BTreeMap<String, Argument>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub label: Vec<u8>,
    pub input: Vec<u8>,
    pub output: Option<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
    pub ikm: Option<Vec<u8>>,
    pub output_length: Option<u64>,
}

pub fn descriptors() -> &'static Vec<Json> {
    static DOMAINS: OnceLock<Vec<Json>> = OnceLock::new();
    DOMAINS.get_or_init(|| serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).unwrap())
}
pub fn hex(text: &str) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(2) {
        return Err("registry_unresolved");
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| "registry_unresolved")?,
                16,
            )
            .map_err(|_| "registry_unresolved")
        })
        .collect()
}
fn text(value: &Json) -> Result<&str, Error> {
    value.as_str().ok_or("registry_unresolved")
}
fn list(value: &Json) -> Result<&Vec<Json>, Error> {
    value.as_array().ok_or("registry_unresolved")
}
fn uint(value: &Argument) -> Result<u128, Error> {
    if let Argument::UInt(n) = value {
        Ok(*n)
    } else {
        Err("domain_integer_type")
    }
}
pub fn fixed_unsigned(value: &Argument, width: usize) -> Result<Vec<u8>, Error> {
    if ![1, 4, 8].contains(&width) {
        return Err("registry_unresolved");
    }
    let n = uint(value)?;
    if n >= 1u128 << (width * 8) {
        return Err("domain_integer_range");
    }
    Ok(n.to_be_bytes()[16 - width..].to_vec())
}
fn lp(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let n = u32::try_from(raw.len()).map_err(|_| "domain_integer_range")?;
    let mut out = n.to_be_bytes().to_vec();
    out.extend_from_slice(raw);
    Ok(out)
}
fn matches(actual: &Value<'_>, expected: &Argument) -> bool {
    match (actual, expected) {
        (Value::Unsigned(a), Argument::UInt(b)) => u128::from(*a) == *b,
        (Value::Bytes(a), Argument::Bytes(b)) => *a == b.as_slice(),
        (Value::Text(a), Argument::Text(b)) => *a == b,
        _ => false,
    }
}

impl Text {
    fn domain_map(
        &self,
        part: &Json,
        raw: &[u8],
        args: &Arguments,
        context: &Context,
        cap: u64,
    ) -> Result<Vec<u8>, Error> {
        let selector;
        let name = if let Some(name) = part["schema_ref"].as_str() {
            name
        } else {
            selector = uint(
                args.get(text(&part["selector"])?)
                    .ok_or("domain_arguments")?,
            )?
            .to_string();
            part["schema_cases"][&selector]
                .as_str()
                .ok_or("domain_variant")?
        };
        let value = self.wire_map(raw, name, context, cap)?;
        let Value::Map(pairs) = &value else {
            return Err("map_type");
        };
        if let Some(bindings) = part.get("bindings") {
            for (field, arg) in bindings.as_object().ok_or("registry_unresolved")? {
                let actual = self
                    .shape
                    .named_value(name, &value, field)?
                    .ok_or("missing_field")?;
                if !matches(actual, args.get(text(arg)?).ok_or("domain_arguments")?) {
                    return Err("domain_binding");
                }
            }
        }
        if let Some(bindings) = part.get("one_of_bindings") {
            for (arg, fields) in bindings.as_object().ok_or("registry_unresolved")? {
                let expected = args.get(arg).ok_or("domain_arguments")?;
                let mut found = false;
                for field in list(fields)? {
                    let actual = self
                        .shape
                        .named_value(name, &value, text(field)?)?
                        .ok_or("missing_field")?;
                    found |= matches(actual, expected);
                }
                if !found {
                    return Err("domain_binding");
                }
            }
        }
        let projection = text(&part["projection"])?;
        if projection == "full" {
            return lp(raw);
        }
        let definition = self.shape.descriptor(name)?;
        let excluded = match projection {
            "without_signature" => vec![integer(&definition["signature_field"])?],
            "without_mac" => vec![integer(&definition["mac_field"])?],
            "without_open_digest" => vec![self.shape.named_field(name, "open_digest")?.0],
            "without_fields" | "without_fields_raw" => list(&part["fields"])?
                .iter()
                .map(|field| Ok(self.shape.named_field(name, text(field)?)?.0))
                .collect::<Result<Vec<_>, Error>>()?,
            _ => return Err("domain_projection"),
        };
        let unique: BTreeSet<_> = excluded.iter().copied().collect();
        if unique.len() != excluded.len()
            || excluded
                .iter()
                .any(|id| !pairs.iter().any(|(key, _)| key == &Value::Unsigned(*id)))
        {
            return Err("domain_projection");
        }
        let projected = encoded(&Value::Map(
            pairs
                .iter()
                .filter(|(key, _)| !matches!(key,Value::Unsigned(id) if unique.contains(id)))
                .cloned()
                .collect(),
        ));
        // Surviving field IDs never shift; only the named projection is applied.
        if projection == "without_fields_raw" {
            Ok(projected)
        } else {
            lp(&projected)
        }
    }

    fn domain_part(
        &self,
        part: &Json,
        args: &Arguments,
        context: &Context,
        cap: u64,
    ) -> Result<Vec<u8>, Error> {
        let encoding = text(&part["encoding"])?;
        if encoding == "hex" {
            return hex(text(&part["hex"])?);
        }
        let constant;
        let value = if let Some(name) = part["const_ref"].as_str() {
            constant = Argument::Text(text(self.shape.field_registry(name)?)?.into());
            &constant
        } else if let Some(value) = part.get("const") {
            constant = Argument::UInt(u128::from(integer(value)?));
            &constant
        } else {
            args.get(text(&part["name"])?).ok_or("domain_arguments")?
        };
        let width = match encoding {
            "u8" => Some(1),
            "u32" => Some(4),
            "u64" => Some(8),
            _ => None,
        };
        if let Some(width) = width {
            let output = fixed_unsigned(value, width)?;
            let n = uint(value)?;
            if let Some(values) = part.get("enum") {
                let allowed = list(values)?
                    .iter()
                    .map(integer)
                    .collect::<Result<Vec<_>, _>>()?;
                if !allowed.iter().any(|v| u128::from(*v) == n) {
                    return Err("domain_enum");
                }
            }
            if let Some(min) = part.get("min")
                && n < u128::from(integer(min)?)
            {
                return Err("domain_integer_range");
            }
            if let Some(max) = part.get("max")
                && n > u128::from(integer(max)?)
            {
                return Err("domain_integer_range");
            }
            if let Some(divisor) = part.get("multiple_of") {
                let divisor = u128::from(integer(divisor)?);
                if divisor == 0 {
                    return Err("registry_unresolved");
                }
                if !n.is_multiple_of(divisor) {
                    return Err("domain_integer_multiple");
                }
            }
            return Ok(output);
        }
        if encoding == "lp-ascii" {
            let Argument::Text(value) = value else {
                return Err("domain_ascii");
            };
            if value.is_empty() || !value.is_ascii() {
                return Err("domain_ascii");
            }
            if let Some(name) = part["text_enum_ref"].as_str()
                && !self
                    .shape
                    .field_registry(name)?
                    .as_object()
                    .ok_or("registry_unresolved")?
                    .contains_key(value)
            {
                return Err("domain_enum");
            }
            return lp(value.as_bytes());
        }
        let Argument::Bytes(raw) = value else {
            return Err("domain_bytes_type");
        };
        if encoding == "lp-map" {
            return self.domain_map(part, raw, args, context, cap);
        }
        if !["raw", "lp-bytes"].contains(&encoding) {
            return Err("registry_unresolved");
        }
        let length = raw.len() as u64;
        if let Some(exact) = part.get("length") {
            if length != integer(exact)? {
                return Err("domain_bytes_length");
            }
        } else if length > integer(&part["max_length"])? {
            return Err("domain_bytes_length");
        }
        if part["nonzero"] == true && raw.iter().all(|b| *b == 0) {
            return Err("domain_zero_secret");
        }
        if encoding == "raw" {
            Ok(raw.clone())
        } else {
            lp(raw)
        }
    }

    pub fn evaluate_domain(
        &self,
        name: &str,
        args: &Arguments,
        caller: &Context,
        cap: u64,
    ) -> Result<Output, Error> {
        if cap == 0 {
            return Err("limit_unresolved");
        }
        let domain = descriptors()
            .iter()
            .find(|d| d["name"] == name)
            .ok_or("domain_unknown")?;
        let spec = &domain["input_schema"];
        let parts = list(&spec["parts"])?;
        let all = parts.iter().chain(
            ["key", "salt", "ikm"]
                .into_iter()
                .filter_map(|key| spec.get(key)),
        );
        let names = all
            .filter_map(|part| part["name"].as_str())
            .collect::<BTreeSet<_>>();
        if args.len() != names.len() || names.iter().any(|name| !args.contains_key(*name)) {
            return Err("domain_arguments");
        }
        let mut context = caller.clone();
        if let Some(profile) = args.get("profile") {
            if let Some(current) = caller.selectors.get("crypto_profile_id")
                && profile != &Argument::Text(current.clone())
            {
                return Err("domain_context");
            }
            let Argument::Text(profile) = profile else {
                return Err("domain_ascii");
            };
            context
                .selectors
                .insert("crypto_profile_id".into(), profile.clone());
        }
        let label = hex(text(&domain["label_bytes"])?)?;
        let mut content = Vec::new();
        for part in parts {
            content.extend(self.domain_part(part, args, &context, cap)?);
        }
        if let Some(relations) = spec.get("relations") {
            for rule in list(relations)? {
                let left = uint(args.get(text(&rule["left"])?).ok_or("domain_arguments")?)?;
                let right = uint(args.get(text(&rule["right"])?).ok_or("domain_arguments")?)?;
                let valid = match text(&rule["op"])? {
                    "successor" => left.checked_add(1) == Some(right),
                    "allowed_pairs" => {
                        let pairs = list(&rule["pairs"])?
                            .iter()
                            .map(|pair| Ok((integer(&pair[0])?, integer(&pair[1])?)))
                            .collect::<Result<Vec<_>, Error>>()?;
                        pairs
                            .iter()
                            .any(|(a, b)| u128::from(*a) == left && u128::from(*b) == right)
                    }
                    _ => return Err("registry_unresolved"),
                };
                if !valid {
                    return Err("domain_relation");
                }
            }
        }
        let operation = text(&domain["operation"])?;
        let mut input = if ["tls-exporter", "sha256-raw"].contains(&operation) {
            Vec::new()
        } else {
            label.clone()
        };
        input.extend(content);
        let mut result = Output {
            label,
            input,
            output: None,
            salt: None,
            ikm: None,
            output_length: None,
        };
        if [
            "sha256",
            "sha256-raw",
            "hmac-sha256",
            "hkdf-expand",
            "hkdf-extract",
        ]
        .contains(&operation)
            && domain["output_length"] != 32
        {
            return Err("registry_unresolved");
        }
        match operation {
            "sha256" | "sha256-raw" => result.output = Some(Sha256::digest(&result.input).to_vec()),
            "hmac-sha256" | "hkdf-expand" => {
                let key = self.domain_part(&spec["key"], args, &context, cap)?;
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&key).map_err(|_| "registry_unresolved")?;
                mac.update(&result.input);
                if operation == "hkdf-expand" {
                    mac.update(&[1]);
                }
                result.output = Some(mac.finalize().into_bytes().to_vec());
            }
            "hkdf-extract" => {
                if !result.label.is_empty() || !parts.is_empty() {
                    return Err("registry_unresolved");
                }
                let salt = self.domain_part(&spec["salt"], args, &context, cap)?;
                let ikm = self.domain_part(&spec["ikm"], args, &context, cap)?;
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&salt).map_err(|_| "registry_unresolved")?;
                mac.update(&ikm);
                result.output = Some(mac.finalize().into_bytes().to_vec());
                result.salt = Some(salt);
                result.ikm = Some(ikm);
            }
            "tls-exporter" => result.output_length = Some(integer(&domain["output_length"])?),
            "ed25519" | "aead-aad" | "noise-prologue" => {}
            _ => return Err("registry_unresolved"),
        }
        Ok(result)
    }
}
