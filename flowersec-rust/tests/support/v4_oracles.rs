//! Test-only digest/member composition; no trust, admission or winner authority.
use super::cbor::{Error, Value};
use super::registry;
use super::shape::{Context, Shape, integer, lookup};
use super::text::Text;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub fn encoded(value: &Value<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.encode(&mut bytes);
    bytes
}

pub fn single_map_hash(
    name: &str,
    schema: &str,
    projection: &str,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    static DOMAINS: OnceLock<Json> = OnceLock::new();
    let domains =
        DOMAINS.get_or_init(|| serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).unwrap());
    let domain = domains
        .as_array()
        .ok_or("registry_unresolved")?
        .iter()
        .find(|d| d["name"] == name)
        .ok_or("registry_unresolved")?;
    let parts = domain["input_schema"]["parts"]
        .as_array()
        .ok_or("domain_projection")?;
    if domain["operation"] != "sha256"
        || domain["output_length"] != 32
        || parts.len() != 1
        || parts[0]["encoding"] != "lp-map"
        || parts[0]["schema_ref"] != schema
        || parts[0]["projection"] != projection
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
    let length = u32::try_from(input.len()).map_err(|_| "map_size")?;
    let mut hash = Sha256::new();
    hash.update(label);
    hash.update(length.to_be_bytes());
    hash.update(input);
    Ok(hash.finalize().to_vec())
}

impl Shape {
    pub fn named_field(&self, name: &str, field: &str) -> Result<(u64, &Json), Error> {
        let (id, descriptor) = self.descriptor(name)?["fields"]
            .as_object()
            .ok_or("registry_unresolved")?
            .iter()
            .find(|(_, entry)| entry["name"] == field)
            .ok_or("unknown_field")?;
        Ok((id.parse().map_err(|_| "registry_unresolved")?, descriptor))
    }

    pub fn named_value<'v, 'a>(
        &self,
        name: &str,
        value: &'v Value<'a>,
        field: &str,
    ) -> Result<Option<&'v Value<'a>>, Error> {
        Ok(lookup(value, self.named_field(name, field)?.0))
    }

    // Issuer construction orders generated field IDs, never received indices.
    pub fn named_map<'a, 'f>(
        &self,
        name: &str,
        fields: impl IntoIterator<Item = (&'f str, Option<Value<'a>>)>,
    ) -> Result<Value<'a>, Error> {
        let mut entries = Vec::new();
        for (field, value) in fields {
            let id = self.named_field(name, field)?.0;
            if let Some(value) = value {
                entries.push((id, value));
            }
        }
        entries.sort_by_key(|entry| entry.0);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err("duplicate_field");
        }
        Ok(Value::Map(
            entries
                .into_iter()
                .map(|(id, value)| (Value::Unsigned(id), value))
                .collect(),
        ))
    }

    // The caller validates the full OPEN before invoking its digest projection.
    pub fn open_digest(&self, value: &Value<'_>) -> Result<Vec<u8>, Error> {
        let id = self.named_field("OPEN_STREAM", "open_digest")?.0;
        let Value::Map(entries) = value else {
            return Err("map_type");
        };
        if lookup(value, id).is_none() {
            return Err("missing_field");
        }
        let unsigned = Value::Map(
            entries
                .iter()
                .filter(|(key, _)| key != &Value::Unsigned(id))
                .cloned()
                .collect(),
        );
        single_map_hash(
            "open_digest",
            "OPEN_STREAM",
            "without_open_digest",
            &encoded(&unsigned),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolMember {
    pub index: u64,
    pub candidate_id: Vec<u8>,
    pub route_digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolProjection {
    pub encoded: Vec<u8>,
    pub artifact_digest: Vec<u8>,
    pub candidate_set_digest: Vec<u8>,
    pub route_set_digest: Vec<u8>,
    pub members: Vec<PoolMember>,
}

impl Text {
    pub fn project_candidate<'a>(&self, candidate: &Value<'a>) -> Result<Value<'a>, Error> {
        let projection = self.shape.registry["map_projections"]
            .get("candidate_route")
            .ok_or("projection_unresolved")?;
        let source = projection["source"]
            .as_str()
            .ok_or("projection_unresolved")?;
        let target = projection["target"]
            .as_str()
            .ok_or("projection_unresolved")?;
        let input = encoded(candidate);
        self.wire_map(&input, source, &Context::default(), input.len() as u64)?;
        let fields = projection["fields"]
            .as_array()
            .ok_or("projection_unresolved")?
            .iter()
            .map(|field| {
                let field = field.as_str().ok_or("projection_unresolved")?;
                Ok((
                    field,
                    self.shape.named_value(source, candidate, field)?.cloned(),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let result = self.shape.named_map(target, fields)?;
        let input = encoded(&result);
        self.wire_map(&input, target, &Context::default(), input.len() as u64)?;
        Ok(result)
    }

    pub fn derive_pool(
        &self,
        input: &[u8],
        indices: &[u64],
        owner_cap: u64,
    ) -> Result<PoolProjection, Error> {
        let artifact = self.wire_map(input, "Artifact", &Context::default(), owner_cap)?;
        let (_, field) = self
            .shape
            .named_field("PoolSelectionRef", "candidate_indices")?;
        // Check the entire list bound before allocating per-index state.
        if (indices.len() as u64) < integer(&field["min_items"])?
            || indices.len() as u64 > integer(&field["max_items"])?
        {
            return Err("array_length");
        }
        let Some(Value::Array(candidates)) =
            self.shape
                .named_value("Artifact", &artifact, "candidates")?
        else {
            return Err("field_type");
        };
        let mut members = Vec::with_capacity(indices.len());
        for (position, &index) in indices.iter().enumerate() {
            self.shape.field(
                &field["items"],
                &Value::Unsigned(index),
                &Context::default(),
            )?;
            if position > 0 && indices[position - 1] >= index {
                return Err("array_order");
            }
            let candidate = usize::try_from(index)
                .ok()
                .and_then(|index| candidates.get(index))
                .ok_or("pool_index_membership")?;
            let route = self.project_candidate(candidate)?;
            let route_digest = single_map_hash("route_digest", "Route", "full", &encoded(&route))?;
            let Some(Value::Bytes(id)) =
                self.shape
                    .named_value("Candidate", candidate, "candidate_id")?
            else {
                return Err("field_type");
            };
            // Copy public IDs; no returned value retains secret Artifact backing.
            members.push(PoolMember {
                index,
                candidate_id: id.to_vec(),
                route_digest,
            });
        }
        let artifact_digest = single_map_hash("artifact_digest", "Artifact", "full", input)?;
        let entries = members
            .iter()
            .map(|member| {
                self.shape.named_map(
                    "PoolRouteRef",
                    [
                        ("candidate_index", Some(Value::Unsigned(member.index))),
                        ("candidate_id", Some(Value::Bytes(&member.candidate_id))),
                        ("route_digest", Some(Value::Bytes(&member.route_digest))),
                    ],
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let selection = self.shape.named_map(
            "PoolSelectionSet",
            [
                ("artifact_digest", Some(Value::Bytes(&artifact_digest))),
                ("entries", Some(Value::Array(entries))),
            ],
        )?;
        let encoded = encoded(&selection);
        self.wire_map(
            &encoded,
            "PoolSelectionSet",
            &Context::default(),
            encoded.len() as u64,
        )?;
        let candidate_set_digest =
            single_map_hash("candidate_set_digest", "PoolSelectionSet", "full", &encoded)?;
        let route_set_digest =
            single_map_hash("route_set_digest", "PoolSelectionSet", "full", &encoded)?;
        Ok(PoolProjection {
            encoded,
            artifact_digest,
            candidate_set_digest,
            route_set_digest,
            members,
        })
    }

    pub fn verify_pool_set(
        &self,
        artifact: &[u8],
        indices: &[u64],
        received: &[u8],
        owner_cap: u64,
    ) -> Result<PoolProjection, Error> {
        self.wire_map(received, "PoolSelectionSet", &Context::default(), owner_cap)?;
        let result = self.derive_pool(artifact, indices, owner_cap)?;
        if result.encoded != received {
            return Err("pool_set_membership");
        }
        Ok(result)
    }
}
