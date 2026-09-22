//! Closed variants/ranges only. Relations, authentication and live ownership
//! require their own checks; successful decoding never grants authority.
use super::cbor::{Error, Value};
use super::shape::{Context, Shape, integer};
use serde::Deserialize;
use serde_json::Value as Json;
use std::collections::BTreeMap;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Branch {
    absent: Vec<String>,
    required: Vec<String>,
    constants: BTreeMap<String, Json>,
    enum_values: BTreeMap<String, Vec<u64>>,
    equal: Vec<[String; 2]>,
    less_or_equal: Vec<[String; 2]>,
    nonzero: Vec<String>,
    zero_bytes: Vec<String>,
    byte_lengths: BTreeMap<String, u64>,
    byte_prefixes: BTreeMap<String, String>,
    registered: BTreeMap<String, String>,
}

pub(super) fn raw_equal(value: Option<&Value<'_>>, expected: &Json) -> bool {
    match value {
        Some(Value::Unsigned(n)) => expected.as_u64() == Some(*n),
        Some(Value::Bool(b)) => expected.as_bool() == Some(*b),
        Some(Value::Text(text)) => expected.as_str() == Some(*text),
        _ => false,
    }
}

impl Shape {
    pub fn variants<'a>(
        &self,
        input: &'a [u8],
        name: &str,
        context: &Context,
        cap: u64,
    ) -> Result<Value<'a>, Error> {
        let value = self.decode(input, name, context, cap)?;
        if !name.is_empty() {
            self.walk_rules(name, &value, context, &|name, value, context| {
                self.check_variants(name, value, context)
            })?;
        }
        Ok(value)
    }

    pub(super) fn rule_applies(
        &self,
        name: &str,
        value: &Value<'_>,
        when: Option<&Json>,
        context: &Context,
    ) -> Result<bool, Error> {
        let Some(when) = when else { return Ok(true) };
        if let Some(selector) = when["context"].as_str() {
            let text = context
                .selectors
                .get(selector)
                .ok_or("context_unresolved")?;
            return Ok(when["value"].as_str() == Some(text.as_str()));
        }
        let actual = self.rule_path(
            name,
            value,
            when["field"].as_str().ok_or("rule_unresolved")?,
            context,
        )?;
        Ok(raw_equal(actual.as_ref(), &when["value"]))
    }

    pub(super) fn check_variants(
        &self,
        name: &str,
        value: &Value<'_>,
        context: &Context,
    ) -> Result<(), Error> {
        let Some(rules) = self.registry["variant_rules"].get(name) else {
            return Ok(());
        };
        for rule in rules.as_array().ok_or("rule_unresolved")? {
            let object = rule.as_object().ok_or("rule_unresolved")?;
            let mut branch_fields = object.clone();
            for key in [
                "op",
                "when",
                "field",
                "min",
                "max",
                "discriminator",
                "value",
                "context",
                "cases",
            ] {
                branch_fields.remove(key);
            }
            // Fail closed on any unimplemented branch instruction, even when
            // this particular input does not select that branch.
            let branch: Branch = serde_json::from_value(Json::Object(branch_fields))
                .map_err(|_| "rule_unresolved")?;
            if !self.rule_applies(name, value, rule.get("when"), context)? {
                continue;
            }
            match rule["op"].as_str().ok_or("rule_unresolved")? {
                "range" => {
                    let field = rule["field"].as_str().ok_or("rule_unresolved")?;
                    let Some(Value::Unsigned(n)) = self.rule_path(name, value, field, context)?
                    else {
                        return Err("field_range");
                    };
                    if n < integer(&rule["min"])? || n > integer(&rule["max"])? {
                        return Err("field_range");
                    }
                }
                "variant" => {
                    let field = rule["discriminator"].as_str().ok_or("rule_unresolved")?;
                    let actual = self.rule_path(name, value, field, context)?;
                    if raw_equal(actual.as_ref(), &rule["value"]) {
                        self.check_branch(name, value, &branch, context)?;
                    }
                }
                "context_variant" => {
                    let selector = rule["context"].as_str().ok_or("rule_unresolved")?;
                    let selected = context
                        .selectors
                        .get(selector)
                        .ok_or("context_unresolved")?;
                    let case = rule["cases"].get(selected).ok_or("context_unresolved")?;
                    let branch: Branch =
                        serde_json::from_value(case.clone()).map_err(|_| "rule_unresolved")?;
                    self.check_branch(name, value, &branch, context)?;
                }
                _ => return Err("rule_unresolved"),
            }
        }
        Ok(())
    }

    fn check_branch(
        &self,
        name: &str,
        value: &Value<'_>,
        branch: &Branch,
        context: &Context,
    ) -> Result<(), Error> {
        let get = |path: &str| self.rule_path(name, value, path, context);
        for path in &branch.absent {
            if get(path)?.is_some() {
                return Err("variant_absent");
            }
        }
        for path in &branch.required {
            if get(path)?.is_none() {
                return Err("variant_required");
            }
        }
        for (path, constant) in &branch.constants {
            if !raw_equal(get(path)?.as_ref(), constant) {
                return Err("variant_constant");
            }
        }
        for (path, allowed) in &branch.enum_values {
            if !matches!(get(path)?, Some(Value::Unsigned(n)) if allowed.contains(&n)) {
                return Err("enum_value");
            }
        }
        for [a, b] in &branch.equal {
            if get(a)? != get(b)? {
                return Err("field_equality");
            }
        }
        for [a, b] in &branch.less_or_equal {
            if !matches!((get(a)?, get(b)?), (Some(Value::Unsigned(a)), Some(Value::Unsigned(b))) if a <= b)
            {
                return Err("field_order");
            }
        }
        for path in &branch.nonzero {
            let valid = match get(path)? {
                Some(Value::Unsigned(n)) => n > 0,
                Some(Value::Bytes(raw)) => raw.iter().any(|&b| b != 0),
                _ => false,
            };
            if !valid {
                return Err("variant_nonzero");
            }
        }
        for path in &branch.zero_bytes {
            if !matches!(get(path)?, Some(Value::Bytes(raw)) if raw.iter().all(|&b| b == 0)) {
                return Err("variant_zero_bytes");
            }
        }
        for (path, length) in &branch.byte_lengths {
            if !matches!(get(path)?, Some(Value::Bytes(raw)) if raw.len() as u64 == *length) {
                return Err("field_length");
            }
        }
        for (path, prefix) in &branch.byte_prefixes {
            let raw = prefix.as_bytes();
            if !raw.len().is_multiple_of(2) {
                return Err("registry_unresolved");
            }
            let prefix = raw
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
                .collect::<Result<Vec<_>, _>>()?;
            if !matches!(get(path)?, Some(Value::Bytes(raw)) if raw.starts_with(&prefix)) {
                return Err("field_prefix");
            }
        }
        for (path, registry) in &branch.registered {
            let Some(Value::Unsigned(n)) = get(path)? else {
                return Err("enum_value");
            };
            let entries = self
                .field_registry(registry)?
                .as_object()
                .ok_or("registry_unresolved")?;
            let mut found = false;
            for entry in entries.values() {
                found |= integer(entry.get("code").unwrap_or(entry))? == n;
            }
            if !found {
                return Err("enum_value");
            }
        }
        Ok(())
    }
}
