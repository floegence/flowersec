//! Stateless generated map relations. These checks do not authenticate signed
//! facts, establish history, or grant runtime/ledger/provider authority.
use super::cbor::{Error, Value};
use super::registry;
use super::shape::{Context, Shape, integer, lookup};
use super::variants::raw_equal;
use serde::Deserialize;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::BTreeSet, sync::OnceLock};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Selector {
    field: String,
    context: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Relation {
    op: String,
    field: String,
    left: String,
    right: String,
    profile: String,
    algorithm: String,
    registry: String,
    source: String,
    domain: String,
    when: Option<Json>,
    fields: Vec<String>,
    pairs: Vec<Vec<u64>>,
    rows: Vec<Vec<u64>>,
    max: Option<Json>,
    item_field_id: Option<u64>,
    item_fields: Vec<String>,
    item_field: String,
    value: Json,
    feature: String,
    present: Option<bool>,
    code_field: String,
    target_scope_field: String,
    stream_id_field: String,
    retry_after_field: String,
    selectors: Vec<Selector>,
}

fn unsigned(value: Option<Value<'_>>) -> Result<u64, Error> {
    match value {
        Some(Value::Unsigned(n)) => Ok(n),
        _ => Err("integer_type"),
    }
}

fn compare(a: &Value<'_>, b: &Value<'_>) -> Result<Ordering, Error> {
    match (a, b) {
        (Value::Unsigned(a), Value::Unsigned(b)) => Ok(a.cmp(b)),
        (Value::Bytes(a), Value::Bytes(b)) => Ok(a.cmp(b)),
        _ => Err("field_type"),
    }
}

fn encoded(value: &Value<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.encode(&mut bytes);
    bytes
}

fn map_digest(
    domain_name: &str,
    source: Option<Value<'_>>,
    target: Option<Value<'_>>,
) -> Result<(), Error> {
    let Some(Value::Bytes(target)) = target else {
        return Err("field_type");
    };
    let map;
    let source = match source {
        Some(Value::Bytes(raw)) => raw,
        Some(value @ Value::Map(_)) => {
            map = encoded(&value);
            &map
        }
        _ => return Err("field_type"),
    };
    static DOMAINS: OnceLock<Json> = OnceLock::new();
    let domains =
        DOMAINS.get_or_init(|| serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).unwrap());
    let domain = domains
        .as_array()
        .ok_or("registry_unresolved")?
        .iter()
        .find(|d| d["name"] == domain_name)
        .ok_or("registry_unresolved")?;
    let parts = domain["input_schema"]["parts"]
        .as_array()
        .ok_or("domain_projection")?;
    if domain["operation"] != "sha256"
        || domain["output_length"] != 32
        || parts.len() != 1
        || parts[0]["encoding"] != "lp-map"
        || parts[0]["projection"] != "full"
    {
        return Err("domain_projection");
    }
    let hex = domain["label_bytes"]
        .as_str()
        .ok_or("registry_unresolved")?
        .as_bytes();
    if !hex.len().is_multiple_of(2) {
        return Err("registry_unresolved");
    }
    let label = hex
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
    let length = u32::try_from(source.len()).map_err(|_| "map_size")?;
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update(length.to_be_bytes());
    // Embedded documents use original complete bytes, including signatures.
    digest.update(source);
    if target != digest.finalize().as_slice() {
        return Err("map_digest_mismatch");
    }
    Ok(())
}

impl Shape {
    pub fn relations<'a>(
        &self,
        input: &'a [u8],
        name: &str,
        context: &Context,
        cap: u64,
    ) -> Result<Value<'a>, Error> {
        let value = self.decode(input, name, context, cap)?;
        if !name.is_empty() {
            self.walk_rules(name, &value, context, &|name, value, context| {
                self.check_variants(name, value, context)?;
                if let Some(rules) = self.registry["relation_rules"].get(name) {
                    for rule in rules.as_array().ok_or("rule_unresolved")? {
                        let rule: Relation =
                            serde_json::from_value(rule.clone()).map_err(|_| "rule_unresolved")?;
                        if self.rule_applies(name, value, rule.when.as_ref(), context)? {
                            self.check_relation(name, value, &rule, context)?;
                        }
                    }
                }
                Ok(())
            })?;
        }
        Ok(value)
    }

    fn check_relation(
        &self,
        name: &str,
        value: &Value<'_>,
        rule: &Relation,
        context: &Context,
    ) -> Result<(), Error> {
        let get = |path: &str| self.rule_path(name, value, path, context);
        match rule.op.as_str() {
            "is_null" => {
                if !matches!(get(&rule.field)?, Some(Value::Null)) {
                    return Err("field_null");
                }
            }
            "at_least_one" => {
                let mut found = false;
                for field in &rule.fields {
                    found |= get(field)?.is_some();
                }
                if !found {
                    return Err("field_presence");
                }
            }
            "equal" | "equal_if_present" | "not_equal" => {
                let (a, b) = (get(&rule.left)?, get(&rule.right)?);
                if rule.op == "equal_if_present" && (a.is_none() || b.is_none()) {
                    return Ok(());
                }
                if rule.op == "not_equal" {
                    if a == b {
                        return Err("field_distinctness");
                    }
                } else if a != b {
                    return Err("field_equality");
                }
            }
            "less_than" | "less_or_equal" | "max_difference" | "bit_subset" => {
                let a = unsigned(get(&rule.left)?)?;
                let b = unsigned(get(&rule.right)?)?;
                match rule.op.as_str() {
                    "less_than" if a >= b => return Err("field_order"),
                    "less_or_equal" if a > b => return Err("field_order"),
                    "max_difference" => {
                        let limit = integer(rule.max.as_ref().ok_or("rule_unresolved")?)?;
                        if a > b || b - a > limit {
                            return Err("field_duration");
                        }
                    }
                    "bit_subset" if a & !b != 0 => return Err("feature_subset"),
                    _ => {}
                }
            }
            "allowed_pairs" | "allowed_tuples" => {
                let pair = [rule.left.clone(), rule.right.clone()];
                let (fields, rows) = if rule.op == "allowed_pairs" {
                    (pair.as_slice(), &rule.pairs)
                } else {
                    (rule.fields.as_slice(), &rule.rows)
                };
                let mut found = false;
                for row in rows {
                    if row.len() != fields.len() {
                        return Err("rule_unresolved");
                    }
                    let mut matches = true;
                    for (field, n) in fields.iter().zip(row) {
                        matches &= get(field)? == Some(Value::Unsigned(*n));
                    }
                    found |= matches;
                }
                if !found {
                    return Err(if rule.op == "allowed_pairs" {
                        "field_pair"
                    } else {
                        "field_tuple"
                    });
                }
            }
            "feature_bit" => {
                let bit = integer(&self.field_registry("feature_registry")?[&rule.feature]["bit"])?;
                if bit >= 64 {
                    return Err("registry_unresolved");
                }
                let present = rule.present.ok_or("registry_unresolved")?;
                if (unsigned(get(&rule.field)?)? & (1u64 << bit) != 0) != present {
                    return Err("feature_policy");
                }
            }
            "profile_algorithm" => {
                let Some(Value::Text(profile)) = get(&rule.profile)? else {
                    return Err("field_type");
                };
                let algorithm = unsigned(get(&rule.algorithm)?)?;
                if algorithm
                    != integer(&self.field_registry("crypto_profiles")?[profile]["dh_algorithm"])?
                {
                    return Err("profile_algorithm");
                }
            }
            "error_scope" => {
                let code = get(&rule.code_field)?;
                let label = self
                    .field_registry("error_codes")?
                    .as_object()
                    .ok_or("registry_unresolved")?
                    .iter()
                    .find(|(_, n)| raw_equal(code.as_ref(), n))
                    .ok_or("enum_value")?
                    .0;
                let policy = &self.field_registry("error_code_metadata")?[label];
                let target = unsigned(get(&rule.target_scope_field)?).map_err(|_| "error_scope")?;
                let stream = get(&rule.stream_id_field)?;
                match policy["scope"].as_str().ok_or("registry_unresolved")? {
                    "session" => {
                        if target != 0 || stream.is_some() {
                            return Err("error_scope");
                        }
                    }
                    "stream" => {
                        if target == 0 || stream != Some(Value::Unsigned(target)) {
                            return Err("error_scope");
                        }
                    }
                    _ => return Err("registry_unresolved"),
                }
                if !policy["retryable"].as_bool().ok_or("registry_unresolved")?
                    && get(&rule.retry_after_field)?.is_some()
                {
                    return Err("retry_after_forbidden");
                }
            }
            "registry_tuple" => {
                let mut tuple = self.field_registry(&rule.registry)?;
                for selector in &rule.selectors {
                    let key = if selector.context.is_empty() {
                        let actual = get(&selector.field)?;
                        let field = self.descriptor(name)?["fields"]
                            .as_object()
                            .ok_or("registry_unresolved")?
                            .values()
                            .find(|f| f["name"] == selector.field)
                            .ok_or("unknown_rule_field")?;
                        field["enum"]
                            .as_object()
                            .ok_or("registry_unresolved")?
                            .iter()
                            .find(|(_, n)| raw_equal(actual.as_ref(), n))
                            .ok_or("context_unresolved")?
                            .0
                    } else {
                        context
                            .selectors
                            .get(&selector.context)
                            .ok_or("context_unresolved")?
                    };
                    tuple = tuple.get(key).ok_or("context_unresolved")?;
                }
                for field in &rule.fields {
                    if !raw_equal(
                        get(field)?.as_ref(),
                        tuple.get(field).ok_or("registry_unresolved")?,
                    ) {
                        return Err("carrier_tuple");
                    }
                }
            }
            "map_digest" => map_digest(&rule.domain, get(&rule.source)?, get(&rule.field)?)?,
            "unique_by" | "increasing_tuple" | "ordinal_indices" | "increasing"
            | "increasing_bytes" | "increasing_cbor" | "increasing_scopes" | "exclusive_item" => {
                self.array_relation(name, value, rule, context)?
            }
            _ => return Err("rule_unresolved"),
        }
        Ok(())
    }

    fn array_relation(
        &self,
        name: &str,
        value: &Value<'_>,
        rule: &Relation,
        context: &Context,
    ) -> Result<(), Error> {
        let get = |path: &str| self.rule_path(name, value, path, context);
        let array = get(&rule.field)?;
        if array.is_none() && matches!(rule.op.as_str(), "increasing_bytes" | "increasing_cbor") {
            return Ok(());
        }
        let Some(Value::Array(items)) = array else {
            return Err("field_type");
        };
        let scope_max = if rule.op == "increasing_scopes" {
            integer(&self.field_registry("resource_caps")?["scope_id"]["max"])?
        } else {
            0
        };
        let mut previous = Vec::new();
        let mut previous_bytes = Vec::new();
        let mut seen = BTreeSet::new();
        for (index, item) in items.iter().enumerate() {
            let current = match rule.item_field_id {
                Some(id) => lookup(item, id).ok_or("unknown_rule_field")?,
                None => item,
            };
            let base = format!("{}.{index}.", rule.field);
            match rule.op.as_str() {
                "unique_by" | "increasing_tuple" => {
                    let tuple = rule
                        .item_fields
                        .iter()
                        .map(|field| get(&(base.clone() + field))?.ok_or("unknown_rule_field"))
                        .collect::<Result<Vec<_>, _>>()?;
                    if rule.op == "unique_by" {
                        if !seen.insert(encoded(&Value::Array(tuple.clone()))) {
                            return Err("item_identity");
                        }
                    } else if index > 0 {
                        let mut order = Ordering::Equal;
                        for (a, b) in previous.iter().zip(&tuple) {
                            order = compare(a, b)?;
                            if order != Ordering::Equal {
                                break;
                            }
                        }
                        if order != Ordering::Less {
                            return Err("item_order");
                        }
                    }
                    previous = tuple;
                }
                "ordinal_indices" => {
                    if current != &Value::Unsigned(index as u64) {
                        return Err("item_index");
                    }
                }
                "increasing" | "increasing_scopes" => {
                    let Value::Unsigned(n) = current else {
                        return Err("integer_type");
                    };
                    let unordered = index > 0 && compare(&previous[0], current)? != Ordering::Less;
                    if rule.op == "increasing_scopes" {
                        if *n == 0 || *n > scope_max || unordered {
                            return Err("scope_order");
                        }
                    } else if unordered {
                        return Err("item_order");
                    }
                    previous = vec![current.clone()];
                }
                "increasing_bytes" | "increasing_cbor" => {
                    let current_bytes = if rule.op == "increasing_cbor" {
                        encoded(current)
                    } else {
                        let Value::Bytes(raw) = current else {
                            return Err("field_type");
                        };
                        raw.to_vec()
                    };
                    // Array ordering is bytewise, not CBOR map-key length order.
                    if index > 0 && previous_bytes >= current_bytes {
                        return Err("item_order");
                    }
                    previous_bytes = current_bytes;
                }
                "exclusive_item" => {
                    if raw_equal(get(&(base + &rule.item_field))?.as_ref(), &rule.value)
                        && items.len() != 1
                    {
                        return Err("item_exclusive");
                    }
                }
                _ => return Err("rule_unresolved"),
            }
        }
        Ok(())
    }
}
