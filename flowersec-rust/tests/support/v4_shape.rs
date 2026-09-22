//! Test-only field-schema validation. Map relations, variants, host/Origin,
//! authentication and live resource authority remain separate checks.
use super::cbor::{Error, Limits, Reference, Value};
use regex_lite::Regex;
use serde_json::Value as Json;
use std::collections::BTreeMap;

#[derive(Default, Clone)]
pub struct Context {
    pub limits: Limits,
    pub selectors: BTreeMap<String, String>,
}

pub struct Shape {
    pub(super) syntax: Reference,
    pub registry: Json,
    patterns: BTreeMap<String, Regex>,
}

pub fn integer(value: &Json) -> Result<u64, Error> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|n| n.parse().ok()))
        .ok_or("registry_unresolved")
}

pub(super) fn lookup<'v, 'a>(value: &'v Value<'a>, id: u64) -> Option<&'v Value<'a>> {
    let Value::Map(pairs) = value else {
        return None;
    };
    pairs.iter().find_map(|(key, value)| {
        if key == &Value::Unsigned(id) {
            Some(value)
        } else {
            None
        }
    })
}

fn size(value: &Value<'_>) -> u64 {
    let mut encoded = Vec::new();
    value.encode(&mut encoded);
    encoded.len() as u64
}

impl Shape {
    pub fn new(json: &str) -> Self {
        let registry: Json = serde_json::from_str(json).unwrap();
        let patterns = registry["field_registries"]["text_patterns"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), Regex::new(value.as_str().unwrap()).unwrap()))
            .collect();
        Self {
            syntax: Reference::new(json),
            registry,
            patterns,
        }
    }

    pub fn decode<'a>(
        &self,
        input: &'a [u8],
        name: &str,
        context: &Context,
        cap: u64,
    ) -> Result<Value<'a>, Error> {
        let (value, _) = self.syntax.decode(input, name, &context.limits, cap);
        let value = value?;
        if !name.is_empty() {
            self.check_map(name, &value, context)?;
        }
        Ok(value)
    }

    pub(super) fn descriptor(&self, name: &str) -> Result<&Json, Error> {
        self.registry["frame_maps"]
            .get(name)
            .ok_or("unknown_schema")
    }

    pub(super) fn field_registry(&self, name: &str) -> Result<&Json, Error> {
        self.registry["field_registries"]
            .get(name)
            .ok_or("registry_unresolved")
    }

    pub(super) fn map_context(
        &self,
        map: &Json,
        value: &Value<'_>,
        original: &Context,
    ) -> Result<Context, Error> {
        let mut context = original.clone();
        if let Some(selectors) = map["context_fields"].as_object() {
            for (selector, field_name) in selectors {
                let (id, field) = map["fields"]
                    .as_object()
                    .ok_or("registry_unresolved")?
                    .iter()
                    .find(|(_, field)| field["name"] == *field_name)
                    .ok_or("registry_unresolved")?;
                let actual = lookup(value, id.parse().map_err(|_| "registry_unresolved")?)
                    .ok_or("missing_field")?;
                let Value::Unsigned(n) = actual else {
                    return Err("integer_type");
                };
                let label = field["enum"]
                    .as_object()
                    .ok_or("context_unresolved")?
                    .iter()
                    .find(|(_, ordinal)| ordinal.as_u64() == Some(*n))
                    .ok_or("context_unresolved")?
                    .0;
                // A containing discriminator establishes child context. It
                // never mutates caller selectors or an adjacent sibling scope.
                context.selectors.insert(selector.clone(), label.clone());
            }
        }
        Ok(context)
    }

    pub fn check_map(&self, name: &str, value: &Value<'_>, context: &Context) -> Result<(), Error> {
        let map = self.descriptor(name)?;
        let Value::Map(pairs) = value else {
            return Err("map_type");
        };
        let context = self.map_context(map, value, context)?;
        for (key, value) in pairs {
            let Value::Unsigned(id) = key else {
                return Err("field_id_type");
            };
            let field = map["fields"].get(id.to_string()).ok_or("unknown_field")?;
            self.field(field, value, &context)?;
        }
        for id in map["required"].as_array().ok_or("registry_unresolved")? {
            if lookup(value, integer(id)?).is_none() {
                return Err("missing_field");
            }
        }
        let bytes = size(value);
        if let Some(max) = map.get("max_encoded_bytes")
            && bytes > integer(max)?
        {
            return Err("map_size");
        }
        if let Some(exact) = map.get("encoded_bytes")
            && bytes != integer(exact)?
        {
            return Err("map_size");
        }
        if let Some(name) = map["max_encoded_bytes_ref"].as_str() {
            let bound = context
                .limits
                .get(name)
                .copied()
                .filter(|&n| n > 0)
                .ok_or("limit_unresolved")?;
            if bytes > bound {
                return Err("map_size");
            }
        }
        Ok(())
    }

    fn bounded(
        n: u64,
        field: &Json,
        min: &str,
        max: &str,
        exact: Option<&str>,
        error: Error,
    ) -> Result<(), Error> {
        if let Some(value) = field.get(min)
            && n < integer(value)?
        {
            return Err(error);
        }
        if let Some(value) = field.get(max)
            && n > integer(value)?
        {
            return Err(error);
        }
        if let Some(value) = exact.and_then(|key| field.get(key))
            && n != integer(value)?
        {
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn field(
        &self,
        field: &Json,
        value: &Value<'_>,
        context: &Context,
    ) -> Result<(), Error> {
        let kind = field["type"].as_str().ok_or("schema_type_unresolved")?;
        if kind == "context_variant" {
            let key = field["context"].as_str().ok_or("registry_unresolved")?;
            let selected = context.selectors.get(key).ok_or("context_unresolved")?;
            let descriptor = field["cases"].get(selected).ok_or("context_unresolved")?;
            return self.field(descriptor, value, context);
        }
        if kind == "uint64" && field["nullable"] == true && matches!(value, Value::Null) {
            return Ok(());
        }
        match kind {
            "uint8" | "uint16" | "uint32" | "uint64" => {
                let Value::Unsigned(n) = value else {
                    return Err("integer_type");
                };
                let width: u32 = kind[4..].parse().map_err(|_| "registry_unresolved")?;
                if width < 64 && *n >= 1u64 << width {
                    return Err("integer_range");
                }
                Self::bounded(*n, field, "min", "max", None, "field_range")?;
                if let Some(bits) = field.get("bitmask")
                    && n & !integer(bits)? != 0
                {
                    return Err("unknown_bits");
                }
                if let Some(exact) = field.get("const")
                    && *n != integer(exact)?
                {
                    return Err("constant_mismatch");
                }
                if let Some(entries) = field["enum"].as_object()
                    && !entries.values().any(|entry| entry.as_u64() == Some(*n))
                {
                    return Err("enum_value");
                }
                if let Some(name) = field["enum_ref"].as_str() {
                    let mut found = false;
                    for entry in self
                        .field_registry(name)?
                        .as_object()
                        .ok_or("registry_unresolved")?
                        .values()
                    {
                        if integer(entry.get("code").unwrap_or(entry))? == *n {
                            found = true;
                        }
                    }
                    if !found {
                        return Err("enum_value");
                    }
                }
            }
            "bytes" | "text" => {
                let raw = match (kind, value) {
                    ("bytes", Value::Bytes(raw)) => *raw,
                    ("text", Value::Text(text)) => text.as_bytes(),
                    _ => return Err("field_type"),
                };
                let n = raw.len() as u64;
                Self::bounded(
                    n,
                    field,
                    "min_bytes",
                    "max_bytes",
                    Some("length"),
                    "field_length",
                )?;
                if field["nonzero"] == true && raw.iter().all(|&b| b == 0) {
                    return Err("field_nonzero");
                }
                if field["profile_public_key"] == true {
                    let profile_name = context
                        .selectors
                        .get("crypto_profile_id")
                        .ok_or("context_unresolved")?;
                    let profile = self
                        .field_registry("crypto_profiles")?
                        .get(profile_name)
                        .ok_or("context_unresolved")?;
                    if n != integer(&profile["dh_public_bytes"])? {
                        return Err("field_length");
                    }
                    if profile["dh_algorithm"] == 1 && raw.first() != Some(&4) {
                        return Err("field_prefix");
                    }
                }
                if let Some(exact) = field.get("const")
                    && raw != exact.as_str().ok_or("registry_unresolved")?.as_bytes()
                {
                    return Err("constant_mismatch");
                }
                if let Some(name) = field["const_ref"].as_str()
                    && raw
                        != self
                            .field_registry(name)?
                            .as_str()
                            .ok_or("registry_unresolved")?
                            .as_bytes()
                {
                    return Err("constant_mismatch");
                }
                if let Some(pattern) = field["pattern_ref"].as_str() {
                    let re = self.patterns.get(pattern).ok_or("pattern_unresolved")?;
                    let text = std::str::from_utf8(raw).map_err(|_| "text_pattern")?;
                    if !re
                        .find(text)
                        .is_some_and(|m| m.start() == 0 && m.end() == text.len())
                    {
                        return Err("text_pattern");
                    }
                }
                if let Some(name) = field["text_enum_ref"].as_str() {
                    let text = std::str::from_utf8(raw).map_err(|_| "enum_value")?;
                    if self.field_registry(name)?.get(text).is_none() {
                        return Err("enum_value");
                    }
                }
                if let Some(prefix) = field["forbidden_prefix"].as_str()
                    && raw.starts_with(prefix.as_bytes())
                {
                    return Err("reserved_namespace");
                }
                if let Some(name) = field["encoded_schema_ref"].as_str()
                    && !(field["allow_empty"] == true && raw.is_empty())
                {
                    self.decode(raw, name, context, n + 1)?;
                }
                if let Some(name) = field["max_ref"].as_str()
                    && n > *context.limits.get(name).ok_or("limit_unresolved")?
                {
                    return Err("field_length");
                }
            }
            "bool" => {
                let Value::Bool(b) = value else {
                    return Err("field_type");
                };
                if let Some(exact) = field.get("const")
                    && exact.as_bool() != Some(*b)
                {
                    return Err("field_equality");
                }
            }
            "map" => self.check_map(
                field["schema_ref"].as_str().ok_or("registry_unresolved")?,
                value,
                context,
            )?,
            "text_map" => {
                let Value::Map(pairs) = value else {
                    return Err("map_type");
                };
                if field.get("min_items").is_none() || field.get("max_items").is_none() {
                    return Err("schema_type_unresolved");
                }
                Self::bounded(
                    pairs.len() as u64,
                    field,
                    "min_items",
                    "max_items",
                    None,
                    "map_length",
                )?;
                for (key, value) in pairs {
                    self.field(&field["keys"], key, context)?;
                    let Value::Text(text) = key else {
                        return Err("field_type");
                    };
                    let child = if let Some(entries) = field.get("entries") {
                        entries.get(*text).ok_or("unknown_field")?
                    } else {
                        field.get("values").ok_or("schema_type_unresolved")?
                    };
                    self.field(child, value, context)?;
                }
                if let Some(entries) = field["entries"].as_object() {
                    for key in entries.keys() {
                        if !pairs.iter().any(|(k, _)| k == &Value::Text(key)) {
                            return Err("missing_field");
                        }
                    }
                }
            }
            "array" | "array<uint64>" => {
                let Value::Array(items) = value else {
                    return Err("field_type");
                };
                let mut max = integer(
                    field
                        .get("max_items")
                        .unwrap_or(&self.registry["encoding"]["ordinary_array_items"]),
                )?;
                if let Some(name) = field["max_items_ref"].as_str() {
                    max = context
                        .limits
                        .get(name)
                        .copied()
                        .filter(|&n| n <= u32::MAX.into())
                        .ok_or("limit_unresolved")?;
                }
                let min = integer(field.get("min_items").ok_or("schema_type_unresolved")?)?;
                if (items.len() as u64) < min || items.len() as u64 > max {
                    return Err("array_length");
                }
                for item in items {
                    if kind == "array<uint64>" {
                        if !matches!(item, Value::Unsigned(_)) {
                            return Err("integer_type");
                        }
                    } else {
                        self.field(&field["items"], item, context)?;
                    }
                }
            }
            _ => return Err("schema_type_unresolved"),
        }
        Ok(())
    }
}
