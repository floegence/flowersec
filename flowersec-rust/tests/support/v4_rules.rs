//! Shared test-only rule traversal over already shape-checked canonical input.
use super::cbor::{Error, Value};
use super::shape::{Context, Shape, lookup};
use serde_json::{Value as Json, json};

impl Shape {
    pub(super) fn selected_field<'r>(
        &self,
        field: &'r Json,
        context: &Context,
    ) -> Result<&'r Json, Error> {
        if field["type"] == "context_variant" {
            let selector = field["context"].as_str().ok_or("registry_unresolved")?;
            let selected = context
                .selectors
                .get(selector)
                .ok_or("context_unresolved")?;
            return field["cases"].get(selected).ok_or("context_unresolved");
        }
        Ok(field)
    }

    // Only the returned subtree is cloned. Byte/text leaves still borrow the
    // original immutable input, including inside an embedded canonical map.
    pub fn rule_path<'a>(
        &self,
        name: &str,
        value: &Value<'a>,
        path: &str,
        context: &Context,
    ) -> Result<Option<Value<'a>>, Error> {
        self.path_field(
            &json!({"type":"map", "schema_ref":name}),
            value,
            &path.split('.').collect::<Vec<_>>(),
            context,
        )
    }

    fn path_field<'a>(
        &self,
        field: &Json,
        value: &Value<'a>,
        path: &[&str],
        context: &Context,
    ) -> Result<Option<Value<'a>>, Error> {
        let Some((part, rest)) = path.split_first() else {
            return Ok(Some(value.clone()));
        };
        let field = self.selected_field(field, context)?;
        if matches!(field["type"].as_str(), Some("array" | "array<uint64>")) {
            let index = part.parse::<u64>().map_err(|_| "unknown_rule_field")?;
            let Value::Array(items) = value else {
                return Err("unknown_rule_field");
            };
            if index >= items.len() as u64 {
                return Ok(None);
            }
            let scalar = json!({"type":"uint64"});
            let child = if field["type"] == "array<uint64>" {
                &scalar
            } else {
                &field["items"]
            };
            return self.path_field(child, &items[index as usize], rest, context);
        }
        let embedded;
        let (name, map_value) = if let Some(name) = field["encoded_schema_ref"].as_str() {
            let Value::Bytes(raw) = value else {
                return Err("unknown_rule_field");
            };
            embedded = self.decode(raw, name, context, raw.len() as u64 + 1)?;
            (name, &embedded)
        } else {
            (
                field["schema_ref"].as_str().ok_or("unknown_rule_field")?,
                value,
            )
        };
        let descriptor = self.descriptor(name)?;
        let context = self.map_context(descriptor, map_value, context)?;
        let (id, child) = descriptor["fields"]
            .as_object()
            .ok_or("registry_unresolved")?
            .iter()
            .find(|(_, f)| f["name"] == *part)
            .ok_or("unknown_rule_field")?;
        match lookup(map_value, id.parse().map_err(|_| "registry_unresolved")?) {
            Some(child_value) => self.path_field(child, child_value, rest, &context),
            None => Ok(None),
        }
    }

    pub(super) fn walk_rules(
        &self,
        name: &str,
        value: &Value<'_>,
        context: &Context,
        check: &impl Fn(&str, &Value<'_>, &Context) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let descriptor = self.descriptor(name)?;
        let context = self.map_context(descriptor, value, context)?;
        let Value::Map(pairs) = value else {
            return Err("map_type");
        };
        for (key, child) in pairs {
            let Value::Unsigned(id) = key else {
                return Err("field_id_type");
            };
            let field = descriptor["fields"]
                .get(id.to_string())
                .ok_or("unknown_field")?;
            self.walk_field(field, child, &context, check)?;
        }
        check(name, value, &context)
    }

    fn walk_field(
        &self,
        field: &Json,
        value: &Value<'_>,
        context: &Context,
        check: &impl Fn(&str, &Value<'_>, &Context) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let field = self.selected_field(field, context)?;
        match field["type"].as_str().ok_or("registry_unresolved")? {
            "map" => self.walk_rules(
                field["schema_ref"].as_str().ok_or("registry_unresolved")?,
                value,
                context,
                check,
            )?,
            "array" => {
                let Value::Array(items) = value else {
                    return Err("field_type");
                };
                for child in items {
                    self.walk_field(&field["items"], child, context, check)?;
                }
            }
            "text_map" => {
                let Value::Map(pairs) = value else {
                    return Err("map_type");
                };
                for (key, child) in pairs {
                    let Value::Text(key) = key else {
                        return Err("field_type");
                    };
                    let descriptor = if let Some(entries) = field.get("entries") {
                        entries.get(*key).ok_or("unknown_field")?
                    } else {
                        field.get("values").ok_or("registry_unresolved")?
                    };
                    self.walk_field(descriptor, child, context, check)?;
                }
            }
            "bytes" => {
                if let Some(name) = field["encoded_schema_ref"].as_str() {
                    let Value::Bytes(raw) = value else {
                        return Err("field_type");
                    };
                    if !(field["allow_empty"] == true && raw.is_empty()) {
                        let nested = self.decode(raw, name, context, raw.len() as u64 + 1)?;
                        self.walk_rules(name, &nested, context, check)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}
