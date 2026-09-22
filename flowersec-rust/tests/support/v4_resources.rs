//! Independent test-only resource arithmetic, without reservation or authority.
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, &'static str>;
type Totals = BTreeMap<String, BTreeMap<String, u64>>;

pub struct Resources {
    keys: Vec<String>,
    bindings: Vec<String>,
    boundaries: Vec<String>,
    dimensions: Vec<String>,
    components: Vec<String>,
    features: Vec<String>,
    maximum: u64,
}
#[derive(Clone)]
struct Charge {
    key: Vec<String>,
    binding: Vec<String>,
    boundary: String,
    vector: BTreeMap<String, u64>,
}

fn object<'a>(
    input: &'a Value,
    allowed: &[String],
    required: &[String],
) -> Result<&'a Map<String, Value>> {
    let object = input.as_object().ok_or("resource_object")?;
    if object.keys().any(|key| !allowed.contains(key)) {
        return Err("resource_field");
    }
    if required.iter().any(|key| !object.contains_key(key)) {
        return Err("resource_missing_field");
    }
    Ok(object)
}
fn array(input: &Value, limit: u64) -> Result<&[Value]> {
    let values = input.as_array().ok_or("resource_array")?;
    if values.len() as u64 > limit {
        return Err("resource_reference_limit");
    }
    Ok(values)
}
fn names(input: &Value) -> Vec<String> {
    input
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}
impl Resources {
    pub fn new(registry: &str, cbor: &str) -> Self {
        let registry: Value = serde_json::from_str(registry).unwrap();
        let cbor: Value = serde_json::from_str(cbor).unwrap();
        Self {
            keys: names(&registry["owner_key_fields"]),
            bindings: names(&registry["binding_fields"]),
            boundaries: names(&registry["control_boundaries"]),
            dimensions: names(&registry["dimensions"]),
            components: names(&registry["base_components"]),
            features: cbor["field_registries"]["feature_registry"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect(),
            maximum: registry["quantity_max"].as_str().unwrap().parse().unwrap(),
        }
    }
    fn charge(&self, input: &Value) -> Result<Charge> {
        let fields: Vec<String> = self
            .keys
            .iter()
            .chain(&self.bindings)
            .cloned()
            .chain(["control_boundary".into(), "vector".into()])
            .collect();
        let value = object(input, &fields, &fields)?;
        let identity = |fields: &[String]| -> Result<Vec<String>> {
            fields
                .iter()
                .map(|key| {
                    let text = value[key].as_str().ok_or("resource_identity")?;
                    if text.is_empty() || text.encode_utf16().count() > 256 {
                        return Err("resource_identity");
                    }
                    Ok(text.to_owned())
                })
                .collect()
        };
        let key = identity(&self.keys)?;
        let mut binding = identity(&self.bindings)?;
        let boundary = value["control_boundary"]
            .as_str()
            .ok_or("resource_control_boundary")?
            .to_owned();
        if !self.boundaries.contains(&boundary) {
            return Err("resource_control_boundary");
        }
        binding.push(boundary.clone());
        let vector = object(&value["vector"], &self.dimensions, &self.dimensions)?;
        let mut amounts = BTreeMap::new();
        for dimension in &self.dimensions {
            let text = vector[dimension].as_str().ok_or("resource_quantity")?;
            if text.is_empty()
                || text.len() > 20
                || !text.bytes().all(|b| b.is_ascii_digit())
                || (text.len() > 1 && text.starts_with('0'))
            {
                return Err("resource_quantity");
            }
            let n: u64 = text.parse().map_err(|_| "resource_quantity")?;
            if n > self.maximum {
                return Err("resource_quantity");
            }
            amounts.insert(dimension.clone(), n);
            binding.push(text.to_owned());
        }
        Ok(Charge {
            key,
            binding,
            boundary,
            vector: amounts,
        })
    }
    fn zero(&self) -> Totals {
        self.boundaries
            .iter()
            .map(|boundary| {
                (
                    boundary.clone(),
                    self.dimensions.iter().map(|d| (d.clone(), 0)).collect(),
                )
            })
            .collect()
    }
    pub fn minimum(&self, input: &Value) -> Result<Value> {
        let fields = ["reference_limit", "base", "features", "legal_selections"].map(str::to_owned);
        let plan = object(input, &fields, &fields)?;
        let mut remaining = plan["reference_limit"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 9_007_199_254_740_991)
            .ok_or("resource_reference_limit")?;
        let base = object(&plan["base"], &self.components, &self.components)?;
        let features = object(&plan["features"], &self.features, &[])?;
        if self.features.len() > 16 {
            return Err("resource_feature_registry");
        }
        let alternatives = array(&plan["legal_selections"], 1 << self.features.len())?;
        if alternatives.is_empty() {
            return Err("resource_legal_selections_missing");
        }
        let mut seen = BTreeSet::new();
        let mut selections = Vec::new();
        for alternative in alternatives {
            let values = array(alternative, self.features.len() as u64)?;
            let mut selected = Vec::new();
            for value in values {
                let name = value.as_str().ok_or("resource_feature_unknown")?.to_owned();
                if !self.features.contains(&name) {
                    return Err("resource_feature_unknown");
                }
                if selected.contains(&name) {
                    return Err("resource_feature_duplicate");
                }
                selected.push(name);
            }
            selected.sort();
            if !seen.insert(selected.clone()) {
                return Err("resource_selection_duplicate");
            }
            if selected.iter().any(|name| !features.contains_key(name)) {
                return Err("resource_feature_missing");
            }
            selections.push(selected);
        }
        let mut bindings = BTreeMap::new();
        let mut capture = |input: &Value| -> Result<Vec<Charge>> {
            let values = array(input, remaining)?;
            remaining -= values.len() as u64;
            values
                .iter()
                .map(|value| {
                    let charge = self.charge(value)?;
                    if bindings
                        .get(&charge.key)
                        .is_some_and(|old| old != &charge.binding)
                    {
                        return Err("resource_owner_conflict");
                    }
                    bindings.insert(charge.key.clone(), charge.binding.clone());
                    Ok(charge)
                })
                .collect()
        };
        let mut common = Vec::new();
        for component in &self.components {
            common.extend(capture(&base[component])?);
        }
        let mut feature_charges = BTreeMap::new();
        for feature in &self.features {
            if let Some(values) = features.get(feature) {
                feature_charges.insert(feature, capture(values)?);
            }
        }
        let mut maximum = self.zero();
        for selected in selections {
            let mut union = BTreeMap::new();
            for charge in &common {
                union.insert(&charge.key, charge);
            }
            for feature in &selected {
                for charge in &feature_charges[feature] {
                    union.insert(&charge.key, charge);
                }
            }
            let mut totals = self.zero();
            for charge in union.values() {
                for dimension in &self.dimensions {
                    let total = totals
                        .get_mut(&charge.boundary)
                        .unwrap()
                        .get_mut(dimension)
                        .unwrap();
                    *total = total
                        .checked_add(charge.vector[dimension])
                        .filter(|n| *n <= self.maximum)
                        .ok_or("resource_sum_overflow")?;
                }
            }
            for (boundary, vector) in totals {
                for (dimension, value) in vector {
                    let amount = maximum
                        .get_mut(&boundary)
                        .unwrap()
                        .get_mut(&dimension)
                        .unwrap();
                    *amount = (*amount).max(value);
                }
            }
        }
        Ok(serde_json::to_value(
            maximum
                .into_iter()
                .map(|(boundary, vector)| {
                    (
                        boundary,
                        vector
                            .into_iter()
                            .map(|(dimension, n)| (dimension, n.to_string()))
                            .collect::<BTreeMap<_, _>>(),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap())
    }
}
