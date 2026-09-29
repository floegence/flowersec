//! The shared proxy application schema over the existing strict CBOR codec.
//! HTTP octets use an exact Latin-1 projection at Rust's string boundary.

use crate::codec_v4::{self as codec, Limits, StateLimits, Value};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value as Json};
use std::sync::OnceLock;

type Result<T> = std::result::Result<T, &'static str>;
pub(crate) fn policy() -> &'static Json {
    static POLICY: OnceLock<Json> = OnceLock::new();
    POLICY.get_or_init(|| {
        serde_json::from_str(codec::proxy_policy_json()).expect("generated proxy policy")
    })
}
fn maximum() -> usize {
    policy()["max_metadata_bytes"].as_u64().unwrap() as usize
}
fn property(name: &str) -> &str {
    if name == "version" { "v" } else { name }
}
fn octet(byte: u8) -> bool {
    byte == b'\t' || byte >= 32 && byte != 127
}
fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
fn semantics(schema: &str, value: &Map<String, Json>) -> Result<()> {
    if schema == "ProxyField" {
        let name = value["name"].as_str().ok_or("proxy_field")?;
        if !token(name) || name != name.to_ascii_lowercase() {
            return Err("proxy_field");
        }
    } else {
        for item in value.values().filter_map(Json::as_str) {
            if !item.bytes().all(|b| (32..=126).contains(&b)) {
                return Err("proxy_ascii");
            }
        }
    }
    if schema == "ProxyHTTPRequest" && !value["method"].as_str().is_some_and(token) {
        return Err("proxy_method");
    }
    if matches!(schema, "ProxyHTTPResponse" | "ProxyWebSocketResponse") {
        let success = value["ok"].as_bool().ok_or("proxy_variant")?;
        let fields: &[&str] = if schema == "ProxyHTTPResponse" {
            &["status", "headers"]
        } else {
            &["protocol"]
        };
        if success == value.contains_key("error")
            || fields
                .iter()
                .any(|name| success != value.contains_key(*name))
        {
            return Err("proxy_variant");
        }
    }
    Ok(())
}
fn decode_field(value: Value<'_>, field: &Json) -> Result<Json> {
    match field["type"].as_str().ok_or("proxy_type")? {
        "uint8" | "uint16" | "uint32" | "uint64" => Ok(Json::from(value.uint()?)),
        "bool" => Ok(Json::from(value.boolean()?)),
        "bytes" => {
            let bytes = value.bytes()?;
            if !bytes.iter().copied().all(octet) {
                return Err("proxy_octets");
            }
            Ok(Json::from(
                bytes.iter().copied().map(char::from).collect::<String>(),
            ))
        }
        "map" => decode_map(value, field["schema_ref"].as_str().ok_or("proxy_map")?),
        "array" => Ok(Json::Array(
            value
                .children()?
                .map(|v| decode_field(v?, &field["items"]))
                .collect::<Result<_>>()?,
        )),
        _ => Err("proxy_type"),
    }
}
fn decode_map(value: Value<'_>, schema: &str) -> Result<Json> {
    let definition = codec::proxy_schema(schema)?;
    let mut result = Map::new();
    for field in definition["fields"]
        .as_object()
        .ok_or("proxy_map")?
        .values()
    {
        let name = field["name"].as_str().ok_or("proxy_field")?;
        if let Some(item) = value.optional(schema, name)? {
            result.insert(property(name).to_owned(), decode_field(item, field)?);
        }
    }
    semantics(schema, &result)?;
    Ok(Json::Object(result))
}
pub(crate) fn decode_value(schema: &str, bytes: &[u8]) -> Result<Json> {
    let value = codec::decode(
        bytes,
        schema,
        Limits {
            bytes: maximum(),
            nodes: bytes.len().saturating_mul(3),
        },
        Some(StateLimits {
            bytes: maximum() as u64,
            issuers: 0,
            certificates: 0,
            leases: 0,
            segments: 0,
        }),
    )?;
    decode_map(value, schema)
}
pub(crate) fn decode<T: DeserializeOwned>(schema: &str, bytes: &[u8]) -> Result<T> {
    serde_json::from_value(decode_value(schema, bytes)?).map_err(|_| "proxy_projection")
}

fn encode_field(out: &mut Vec<u8>, value: &Json, field: &Json) -> Result<()> {
    match field["type"].as_str().ok_or("proxy_type")? {
        "uint8" | "uint16" | "uint32" | "uint64" => {
            codec::encode_head(out, 0, value.as_u64().ok_or("proxy_integer")?)
        }
        "bool" => out.push(if value.as_bool().ok_or("proxy_boolean")? {
            245
        } else {
            244
        }),
        "bytes" => {
            let value = value.as_str().ok_or("proxy_octets")?;
            let count = value.chars().count();
            if count > maximum() {
                return Err("proxy_capacity");
            }
            codec::encode_head(out, 2, count as u64);
            for character in value.chars() {
                let b = u8::try_from(character as u32).map_err(|_| "proxy_octets")?;
                if !octet(b) {
                    return Err("proxy_octets");
                }
                out.push(b);
            }
        }
        "map" => encode_map(out, value, field["schema_ref"].as_str().ok_or("proxy_map")?)?,
        "array" => {
            let items = value.as_array().ok_or("proxy_array")?;
            if items.len() > policy()["max_field_count"].as_u64().unwrap() as usize {
                return Err("proxy_capacity");
            }
            codec::encode_head(out, 4, items.len() as u64);
            for item in items {
                encode_field(out, item, &field["items"])?;
            }
        }
        _ => return Err("proxy_type"),
    }
    if out.len() > maximum() {
        return Err("proxy_capacity");
    }
    Ok(())
}
fn encode_map(out: &mut Vec<u8>, value: &Json, schema: &str) -> Result<()> {
    let object = value.as_object().ok_or("proxy_map")?;
    semantics(schema, object)?;
    let definition = codec::proxy_schema(schema)?;
    let fields = definition["fields"].as_object().ok_or("proxy_map")?;
    let mut ordered = fields
        .iter()
        .map(|(id, f)| (id.parse::<u64>().unwrap(), f))
        .collect::<Vec<_>>();
    ordered.sort_unstable_by_key(|(id, _)| *id);
    if object.keys().any(|key| {
        !fields
            .values()
            .any(|f| f["name"].as_str().is_some_and(|n| property(n) == key))
    }) {
        return Err("proxy_unknown_field");
    }
    codec::encode_head(out, 5, object.len() as u64);
    for (id, field) in ordered {
        let name = property(field["name"].as_str().ok_or("proxy_field")?);
        if let Some(item) = object.get(name) {
            codec::encode_head(out, 0, id);
            encode_field(out, item, field)?;
        }
    }
    Ok(())
}
pub(crate) fn encode(schema: &str, value: &impl Serialize) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value).map_err(|_| "proxy_projection")?;
    if value["ok"] == true {
        if schema == "ProxyHTTPResponse" {
            value
                .as_object_mut()
                .ok_or("proxy_map")?
                .entry("headers")
                .or_insert_with(|| Json::Array(vec![]));
        }
        if schema == "ProxyWebSocketResponse" {
            value
                .as_object_mut()
                .ok_or("proxy_map")?
                .entry("protocol")
                .or_insert_with(|| Json::from(""));
        }
    }
    let mut out = Vec::new();
    encode_map(&mut out, &value, schema)?;
    // Validate the same required/optional fields and values as a received map.
    let _ = codec::decode(
        &out,
        schema,
        Limits {
            bytes: maximum(),
            nodes: out.len().saturating_mul(3),
        },
        Some(StateLimits {
            bytes: maximum() as u64,
            issuers: 0,
            certificates: 0,
            leases: 0,
            segments: 0,
        }),
    )?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_proxy_matches_shared_wire_corpus() {
        let corpus: Json =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        let mut count = 0;
        for v in corpus["vectors"].as_array().unwrap() {
            let schema = v["schema"].as_str().unwrap_or("");
            if !schema.starts_with("Proxy") {
                continue;
            }
            let bytes = v["hex"]
                .as_str()
                .unwrap()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            let decoded = decode_value(schema, &bytes);
            if v.get("expected_error").is_some() {
                assert!(decoded.is_err(), "{}", v["id"])
            } else {
                let encoded = encode(schema, &decoded.unwrap()).unwrap();
                assert_eq!(encoded, bytes, "{}", v["id"])
            }
            count += 1;
        }
        assert_eq!(count, 8);
    }
}
