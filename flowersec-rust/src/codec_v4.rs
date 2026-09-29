//! Bounded canonical CBOR views and generated schema validation. Views borrow
//! their original immutable input; parsing builds no peer-sized object graph.

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar, traits::IsIdentity};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use zeroize::Zeroize;

#[allow(dead_code)]
#[path = "protocol_v4_registry_generated.rs"]
mod registry;

pub(crate) type Error = &'static str;
pub(crate) type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Value<'a> {
    raw: &'a [u8],
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) bytes: usize,
    pub(crate) nodes: usize,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Context {
    path_kind: Option<u64>,
    pub(crate) activation_source: Option<ActivationSource>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "The native v4 material sources are not yet wired")
)]
pub(crate) enum ActivationSource {
    LiveAuthority,
    PreauthorizedPool,
}
impl Context {
    pub(crate) fn with_activation_source(source: ActivationSource) -> Self {
        Self {
            activation_source: Some(source),
            ..Self::default()
        }
    }
    fn selector(self, name: &str) -> Result<&'static str> {
        match name {
            "path_kind" => match self.path_kind {
                Some(0) => Ok("direct"),
                Some(1) => Ok("tunnel"),
                _ => Err("context_unresolved"),
            },
            "activation_source_profile" => match self.activation_source {
                Some(ActivationSource::LiveAuthority) => Ok("live_authority"),
                Some(ActivationSource::PreauthorizedPool) => Ok("preauthorized_pool"),
                None => Err("context_unresolved"),
            },
            _ => Err("context_unresolved"),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct StateLimits {
    pub(crate) bytes: u64,
    pub(crate) issuers: u64,
    pub(crate) certificates: u64,
    pub(crate) leases: u64,
    pub(crate) segments: u64,
}
impl StateLimits {
    fn get(self, name: &str) -> Result<u64> {
        match name {
            "max_proxy_fields" => Ok(65535),
            "max_state_encoded_bytes" => Ok(self.bytes),
            "max_revoked_issuers" => Ok(self.issuers.min(self.bytes / 65)),
            "max_revoked_certificates" => Ok(self.certificates.min(self.bytes / 40)),
            "max_revoked_leases" => Ok(self.leases.min(self.bytes / 76)),
            "max_cohort_policy_segments" => Ok(self.segments.min(self.bytes / 7)),
            "max_revoked_issuer_authorizations" => Ok(self.bytes / 44),
            _ => Err("limit_unresolved"),
        }
    }
}
fn schema() -> &'static Json {
    static SCHEMA: OnceLock<Json> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(registry::CBOR_REGISTRY_JSON).expect("generated CBOR registry")
    })
}
pub(crate) fn proxy_policy_json() -> &'static str {
    registry::PROXY_APPLICATION_REGISTRY_JSON
}
pub(crate) fn proxy_schema(name: &str) -> Result<&'static Json> {
    if !name.starts_with("Proxy") {
        return Err("unknown_schema");
    }
    schema()["frame_maps"].get(name).ok_or("unknown_schema")
}
fn domains() -> &'static Json {
    static DOMAINS: OnceLock<Json> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).expect("generated domains")
    })
}
pub(crate) fn registry_backing_bound() -> u64 {
    // Immutable generated input only. Charge a conservative bound for serde's
    // node/string/container allocation at Environment construction.
    (registry::CBOR_REGISTRY_JSON.len() + registry::DOMAIN_REGISTRY_JSON.len()) as u64 * 64
}
fn descriptor(name: &str) -> Result<&'static Json> {
    schema()["frame_maps"].get(name).ok_or("unknown_schema")
}
fn number(value: &Json) -> Result<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse().ok())
        .ok_or("registry_unresolved")
}
fn header(raw: &[u8]) -> Result<(u8, u64, usize)> {
    let first = *raw.first().ok_or("truncated")?;
    let major = first >> 5;
    let ai = first & 31;
    if ai < 24 {
        return Ok((major, u64::from(ai), 1));
    }
    if ai > 27 {
        return Err("invalid_header");
    }
    let width = 1usize << (ai - 24);
    let bytes = raw.get(1..=width).ok_or("truncated")?;
    let n = bytes.iter().fold(0u64, |n, b| n << 8 | u64::from(*b));
    if n < [24, 256, 65536, 4294967296][usize::from(ai - 24)] {
        return Err("non_shortest_integer");
    }
    Ok((major, n, width + 1))
}
fn scan(raw: &[u8], depth: usize, remaining: &mut usize) -> Result<usize> {
    if depth > 8 || *remaining == 0 {
        return Err("decoder_capacity");
    }
    *remaining -= 1;
    let (major, n, mut offset) = header(raw)?;
    match major {
        0 => {}
        2 | 3 => {
            let bytes = usize::try_from(n).map_err(|_| "map_size")?;
            offset = offset
                .checked_add(bytes)
                .filter(|n| *n <= raw.len())
                .ok_or("truncated")?;
            if major == 3 {
                std::str::from_utf8(&raw[header(raw)?.2..offset]).map_err(|_| "invalid_utf8")?;
            }
        }
        4 | 5 => {
            if major == 5 && n > 128 {
                return Err("map_limit");
            }
            let children = n
                .checked_mul(if major == 5 { 2 } else { 1 })
                .ok_or("array_limit")?;
            if children > *remaining as u64 || children > (raw.len() - offset) as u64 {
                return Err("decoder_capacity");
            }
            let mut previous = None;
            for i in 0..children {
                let child = raw.get(offset..).ok_or("truncated")?;
                let size = scan(child, depth + 1, remaining)?;
                if major == 5 && i % 2 == 0 {
                    let (kind, id, _) = header(child)?;
                    if !matches!(kind, 0 | 3) || (kind == 0 && id > u16::MAX.into()) {
                        return Err("field_id_type");
                    }
                    let key = &child[..size];
                    if previous.is_some_and(|old: &[u8]| (key.len(), key) <= (old.len(), old)) {
                        return Err("map_order");
                    }
                    previous = Some(key);
                }
                offset += size;
            }
        }
        7 if matches!(n, 20..=22) && offset == 1 => {}
        _ => return Err("unsupported_type"),
    }
    Ok(offset)
}
impl<'a> Value<'a> {
    pub(crate) fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub(crate) fn uint(self) -> Result<u64> {
        let (major, n, _) = header(self.raw)?;
        if major == 0 {
            Ok(n)
        } else {
            Err("integer_type")
        }
    }
    pub(crate) fn bytes(self) -> Result<&'a [u8]> {
        let (major, _, start) = header(self.raw)?;
        if major == 2 {
            Ok(&self.raw[start..])
        } else {
            Err("field_type")
        }
    }
    pub(crate) fn text(self) -> Result<&'a str> {
        let (major, _, start) = header(self.raw)?;
        if major == 3 {
            std::str::from_utf8(&self.raw[start..]).map_err(|_| "invalid_utf8")
        } else {
            Err("field_type")
        }
    }
    pub(crate) fn is_null(self) -> bool {
        self.raw == [0xf6]
    }
    pub(crate) fn boolean(self) -> Result<bool> {
        match self.raw {
            [0xf4] => Ok(false),
            [0xf5] => Ok(true),
            _ => Err("boolean_type"),
        }
    }
    pub(crate) fn children(self) -> Result<Items<'a>> {
        let (major, n, offset) = header(self.raw)?;
        if !matches!(major, 4 | 5) {
            return Err("field_type");
        }
        Ok(Items {
            raw: &self.raw[offset..],
            count: n * if major == 5 { 2 } else { 1 },
        })
    }
    pub(crate) fn len(self) -> Result<usize> {
        usize::try_from(header(self.raw)?.1).map_err(|_| "field_length")
    }
    pub(crate) fn field(self, name: &str, field: &str) -> Result<Self> {
        self.optional(name, field)?.ok_or("missing_field")
    }
    pub(crate) fn optional(self, name: &str, field: &str) -> Result<Option<Self>> {
        let map = descriptor(name)?;
        let id = map["fields"]
            .as_object()
            .ok_or("registry_unresolved")?
            .iter()
            .find(|(_, d)| d["name"] == field)
            .ok_or("unknown_field")?
            .0
            .parse::<u64>()
            .map_err(|_| "registry_unresolved")?;
        let mut children = self.children()?;
        while let Some(key) = children.next() {
            let key = key?.uint()?;
            let value = children.next().ok_or("truncated")??;
            if key == id {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
    pub(crate) fn at(self, index: usize) -> Result<Self> {
        self.children()?.nth(index).ok_or("field_length")?
    }
    pub(crate) fn u(self, name: &str, field: &str) -> Result<u64> {
        self.field(name, field)?.uint()
    }
    pub(crate) fn b<const N: usize>(self, name: &str, field: &str) -> Result<[u8; N]> {
        self.field(name, field)?
            .bytes()?
            .try_into()
            .map_err(|_| "field_length")
    }
}
#[derive(Debug)]
pub(crate) struct Items<'a> {
    raw: &'a [u8],
    count: u64,
}
impl<'a> Iterator for Items<'a> {
    type Item = Result<Value<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        let mut remaining = self.raw.len();
        match scan(self.raw, 0, &mut remaining) {
            Ok(n) => {
                let value = Value {
                    raw: &self.raw[..n],
                };
                self.raw = &self.raw[n..];
                Some(Ok(value))
            }
            Err(error) => {
                self.count = 0;
                Some(Err(error))
            }
        }
    }
}
pub(crate) fn decode<'a>(
    raw: &'a [u8],
    name: &str,
    cap: Limits,
    state: Option<StateLimits>,
) -> Result<Value<'a>> {
    decode_context(raw, name, cap, state, Context::default())
}
pub(crate) fn decode_context<'a>(
    raw: &'a [u8],
    name: &str,
    cap: Limits,
    state: Option<StateLimits>,
    context: Context,
) -> Result<Value<'a>> {
    if raw.is_empty() || raw.len() > cap.bytes || cap.nodes == 0 {
        return Err("map_size");
    }
    let mut remaining = cap.nodes;
    if scan(raw, 0, &mut remaining)? != raw.len() {
        return Err("trailing_bytes");
    }
    let value = Value { raw };
    check_map(value, name, state, 0, &mut remaining, context)?;
    Ok(value)
}
fn bounded(n: u64, field: &Json, min: &str, max: &str, exact: &str) -> Result<()> {
    if field
        .get(min)
        .is_some_and(|v| number(v).is_ok_and(|v| n < v))
        || field
            .get(max)
            .is_some_and(|v| number(v).is_ok_and(|v| n > v))
        || field
            .get(exact)
            .is_some_and(|v| number(v).is_ok_and(|v| n != v))
    {
        return Err("field_range");
    }
    Ok(())
}
fn check_map(
    value: Value<'_>,
    name: &str,
    state: Option<StateLimits>,
    depth: usize,
    remaining: &mut usize,
    mut context: Context,
) -> Result<()> {
    if depth > 8 || header(value.raw)?.0 != 5 {
        return Err("map_type");
    }
    let map = descriptor(name)?;
    if name == "Candidate" || name == "Route" {
        context.path_kind = Some(value.u(name, "path_kind")?);
    }
    bounded(
        value.raw.len() as u64,
        map,
        "min_encoded_bytes",
        "max_encoded_bytes",
        "encoded_bytes",
    )?;
    if let Some(key) = map["max_encoded_bytes_ref"].as_str()
        && value.raw.len() as u64 > state.ok_or("limit_unresolved")?.get(key)?
    {
        return Err("map_size");
    }
    let mut fields = value.children()?;
    while let Some(key) = fields.next() {
        let key = key?.uint()?;
        let child = fields.next().ok_or("truncated")??;
        let descriptor = map["fields"].get(key.to_string()).ok_or("unknown_field")?;
        check_field(child, descriptor, state, depth + 1, remaining, context)?;
    }
    for id in map["required"].as_array().ok_or("registry_unresolved")? {
        let field = &map["fields"][number(id)?.to_string()]["name"];
        value.field(name, field.as_str().ok_or("registry_unresolved")?)?;
    }
    for group in ["variant_rules", "relation_rules", "text_rules"] {
        if let Some(rules) = schema()[group][name].as_array() {
            for rule in rules {
                check_rule(value, name, rule, context)?;
            }
        }
    }
    Ok(())
}
fn check_field(
    value: Value<'_>,
    field: &Json,
    state: Option<StateLimits>,
    depth: usize,
    remaining: &mut usize,
    context: Context,
) -> Result<()> {
    if depth > 8 {
        return Err("depth_limit");
    }
    let kind = field["type"].as_str().ok_or("registry_unresolved")?;
    if kind == "context_variant" {
        let selected = context.selector(field["context"].as_str().ok_or("registry_unresolved")?)?;
        return check_field(
            value,
            &field["cases"][selected],
            state,
            depth,
            remaining,
            context,
        );
    }
    if kind == "uint64" && field["nullable"] == true && value.is_null() {
        return Ok(());
    }
    match kind {
        "bool" => {
            value.boolean()?;
        }
        "uint8" | "uint16" | "uint32" | "uint64" => {
            let n = value.uint()?;
            let width: u32 = kind[4..].parse().map_err(|_| "registry_unresolved")?;
            if width < 64 && n >= 1u64 << width {
                return Err("integer_range");
            }
            bounded(n, field, "min", "max", "const")?;
            if let Some(values) = field["enum"].as_object()
                && !values.values().any(|v| number(v) == Ok(n))
            {
                return Err("enum_value");
            }
            if let Some(bits) = field.get("bitmask")
                && n & !number(bits)? != 0
            {
                return Err("unknown_bits");
            }
        }
        "text" => {
            let text = value.text()?;
            bounded(text.len() as u64, field, "min_bytes", "max_bytes", "length")?;
            if let Some(reference) = field["const_ref"].as_str() {
                if schema()["field_registries"][reference].as_str() != Some(text) {
                    return Err("constant_mismatch");
                }
            } else if let Some(pattern) = field["pattern_ref"].as_str() {
                if pattern == "metadata_namespace" {
                    let valid = |part: &str| {
                        !part.is_empty()
                            && part.len() <= 32
                            && (part.as_bytes()[0].is_ascii_lowercase()
                                || part.as_bytes()[0].is_ascii_digit())
                            && part.bytes().all(|b| {
                                b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                            })
                    };
                    if !text
                        .split_once('/')
                        .is_some_and(|(owner, name)| valid(owner) && valid(name))
                        || text.starts_with("flowersec/")
                    {
                        return Err("text_pattern");
                    }
                } else if pattern != "security_id"
                    || text.is_empty()
                    || text.len() > 128
                    || !text.as_bytes()[0].is_ascii_lowercase()
                        && !text.as_bytes()[0].is_ascii_digit()
                    || !text.bytes().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || b"._:/@-".contains(&c)
                    })
                {
                    return Err("text_pattern");
                }
            } else if let Some(name) = field["text_enum_ref"].as_str() {
                let values = &schema()["field_registries"][name];
                if values.get(text).is_none()
                    && !values
                        .as_array()
                        .is_some_and(|v| v.iter().any(|v| v == text))
                {
                    return Err("enum_value");
                }
            } else if let Some(format) = field["text_format"].as_str() {
                check_text(format, text)?;
            } else if !matches!(
                field["name"].as_str(),
                Some("path" | "alpn" | "subprotocol" | "kind")
            ) {
                return Err("text_schema_unavailable");
            }
        }
        "bytes" => {
            let bytes = value.bytes()?;
            bounded(
                bytes.len() as u64,
                field,
                "min_bytes",
                "max_bytes",
                "length",
            )?;
            if field["nonzero"] == true && bytes.iter().all(|b| *b == 0) {
                return Err("field_nonzero");
            }
            if let Some(name) = field["encoded_schema_ref"].as_str() {
                if bytes.is_empty() && field["allow_empty"] == true {
                    return Ok(());
                }
                if scan(bytes, depth, remaining)? != bytes.len() {
                    return Err("trailing_bytes");
                }
                check_map(Value { raw: bytes }, name, state, depth, remaining, context)?;
            }
        }
        "text_map" => {
            use unicode_normalization::UnicodeNormalization;
            if header(value.raw)?.0 != 5 {
                return Err("field_type");
            }
            bounded(
                value.len()? as u64,
                field,
                "min_items",
                "max_items",
                "length",
            )?;
            let mut children = value.children()?;
            while let Some(key) = children.next() {
                let key = key?.text()?;
                bounded(
                    key.len() as u64,
                    &field["keys"],
                    "min_bytes",
                    "max_bytes",
                    "length",
                )?;
                if !key.nfc().eq(key.chars()) {
                    return Err("text_noncanonical");
                }
                let bytes = children.next().ok_or("truncated")??.bytes()?;
                bounded(
                    bytes.len() as u64,
                    &field["values"],
                    "min_bytes",
                    "max_bytes",
                    "length",
                )?;
            }
        }
        "map" => check_map(
            value,
            field["schema_ref"].as_str().ok_or("registry_unresolved")?,
            state,
            depth,
            remaining,
            context,
        )?,
        "array" | "array<uint64>" => {
            if header(value.raw)?.0 != 4 {
                return Err("array_type");
            }
            bounded(
                value.len()? as u64,
                field,
                "min_items",
                "max_items",
                "length",
            )?;
            if let Some(key) = field["max_items_ref"].as_str()
                && value.len()? as u64 > state.ok_or("limit_unresolved")?.get(key)?
            {
                return Err("array_limit");
            }
            for child in value.children()? {
                let child = child?;
                if kind == "array<uint64>" {
                    child.uint()?;
                } else {
                    check_field(child, &field["items"], state, depth + 1, remaining, context)?;
                }
            }
        }
        _ => return Err("schema_type_unavailable"),
    }
    Ok(())
}
fn check_text(format: &str, text: &str) -> Result<()> {
    match format {
        "host" | "loopback_host" => {
            if text.is_empty()
                || text.len() > 253
                || !text.is_ascii()
                || text.bytes().any(|b| {
                    b.is_ascii_uppercase() || b <= 32 || b >= 127 || b"[]%\\/?#@".contains(&b)
                })
            {
                return Err("host_syntax");
            }
            let loopback = if text.contains(':') {
                let ip: std::net::Ipv6Addr = text.parse().map_err(|_| "host_ipv6")?;
                // IPv4-mapped addresses retain IPv6 family and hex-only spelling.
                let words = ip.segments();
                let (mut best, mut length, mut i) = (None, 1, 0);
                while i < 8 {
                    if words[i] != 0 {
                        i += 1;
                        continue;
                    }
                    let mut end = i + 1;
                    while end < 8 && words[end] == 0 {
                        end += 1;
                    }
                    if end - i > length {
                        best = Some(i);
                        length = end - i;
                    }
                    i = end;
                }
                let words = words.map(|n| format!("{n:x}"));
                let canonical = match best {
                    Some(start) => format!(
                        "{}::{}",
                        words[..start].join(":"),
                        words[start + length..].join(":")
                    ),
                    None => words.join(":"),
                };
                if canonical != text {
                    return Err("host_noncanonical");
                }
                ip.is_loopback()
            } else if text.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                let ip: std::net::Ipv4Addr = text.parse().map_err(|_| "host_ipv4")?;
                if ip.to_string() != text {
                    return Err("host_noncanonical");
                }
                ip.is_loopback()
            } else {
                let last = text.rsplit('.').next().ok_or("host_syntax")?;
                if last.bytes().all(|b| b.is_ascii_digit())
                    || last
                        .strip_prefix("0x")
                        .is_some_and(|v| v.bytes().all(|b| b.is_ascii_hexdigit()))
                    || crate::idna_v3::lookup_ascii(text).as_deref() != Ok(text)
                {
                    return Err("host_noncanonical");
                }
                false
            };
            if format == "loopback_host" && !loopback {
                return Err("host_loopback");
            }
            Ok(())
        }
        "origin" => origin_parts(text).map(|_| ()),
        _ => Err("text_format_unavailable"),
    }
}
fn origin_parts(text: &str) -> Result<(&str, &str, u16)> {
    if text.len() > 320 || !text.bytes().all(|b| (33..=126).contains(&b)) {
        return Err("origin_syntax");
    }
    let (scheme, authority) = text.split_once("://").ok_or("origin_syntax")?;
    let default = number(&schema()["field_registries"]["origin_schemes"][scheme]["default_port"])?;
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or("origin_syntax")?;
        if !host.contains(':') {
            return Err("origin_syntax");
        }
        (
            host,
            if rest.is_empty() {
                None
            } else {
                Some(rest.strip_prefix(':').ok_or("origin_syntax")?)
            },
        )
    } else if let Some((host, port)) = authority.split_once(':') {
        (host, Some(port))
    } else {
        (authority, None)
    };
    check_text("host", host)?;
    let port = match port {
        Some(raw) => {
            if raw.is_empty()
                || !raw.bytes().all(|b| b.is_ascii_digit())
                || raw.len() > 1 && raw.starts_with('0')
            {
                return Err("origin_port");
            }
            let port: u16 = raw.parse().map_err(|_| "origin_port")?;
            if port == 0 || u64::from(port) == default {
                return Err("origin_port");
            }
            port
        }
        None => u16::try_from(default).map_err(|_| "registry_unresolved")?,
    };
    Ok((scheme, host, port))
}
fn path<'a>(
    value: Value<'a>,
    name: &str,
    text: &str,
    context: Context,
) -> Result<Option<Value<'a>>> {
    let mut value = value;
    let mut name = name;
    let mut descriptor: Option<&Json> = None;
    for part in text.split('.') {
        if header(value.raw)?.0 == 4 {
            value = value.at(part.parse().map_err(|_| "rule_path")?)?;
            descriptor = descriptor.map(|d| &d["items"]);
        } else {
            let fields = &crate::codec_v4::descriptor(name)?["fields"];
            let field = fields
                .as_object()
                .ok_or("registry_unresolved")?
                .values()
                .find(|d| d["name"] == part)
                .ok_or("rule_path")?;
            let Some(child) = value.optional(name, part)? else {
                return Ok(None);
            };
            value = child;
            descriptor = Some(field);
        }
        if let Some(mut field) = descriptor {
            if field["type"] == "context_variant" {
                field = &field["cases"]
                    [context.selector(field["context"].as_str().ok_or("rule_path")?)?];
                descriptor = Some(field);
            }
            if let Some(next) = field["schema_ref"].as_str() {
                name = next;
            } else if let Some(next) = field["encoded_schema_ref"].as_str() {
                value = Value {
                    raw: value.bytes()?,
                };
                name = next;
            }
        }
    }
    Ok(Some(value))
}
fn raw_matches(value: Value<'_>, expected: &Json) -> bool {
    if let Some(b) = expected.as_bool() {
        return value.boolean() == Ok(b);
    }
    if let Some(n) = expected.as_u64() {
        return value.uint() == Ok(n);
    }
    if let Some(t) = expected.as_str() {
        return value.text() == Ok(t);
    }
    false
}
fn check_branch(value: Value<'_>, name: &str, branch: &Json, context: Context) -> Result<()> {
    let get = |field: &str| path(value, name, field, context)?.ok_or("rule_missing");
    for (key, instruction) in branch.as_object().ok_or("registry_unresolved")? {
        match key.as_str() {
            "op" | "when" | "discriminator" | "value" => {}
            "required" | "absent" => {
                for field in instruction.as_array().ok_or("registry_unresolved")? {
                    if path(
                        value,
                        name,
                        field.as_str().ok_or("registry_unresolved")?,
                        context,
                    )?
                    .is_some()
                        != (key == "required")
                    {
                        return Err("variant_fields");
                    }
                }
            }
            "constants" => {
                for (field, expected) in instruction.as_object().ok_or("registry_unresolved")? {
                    if !raw_matches(get(field)?, expected) {
                        return Err("variant_constant");
                    }
                }
            }
            "enum_values" => {
                for (field, allowed) in instruction.as_object().ok_or("registry_unresolved")? {
                    if !allowed
                        .as_array()
                        .ok_or("registry_unresolved")?
                        .iter()
                        .any(|v| number(v) == get(field).and_then(Value::uint))
                    {
                        return Err("variant_enum");
                    }
                }
            }
            "equal" | "less_or_equal" => {
                for pair in instruction.as_array().ok_or("registry_unresolved")? {
                    let a = get(pair[0].as_str().ok_or("registry_unresolved")?)?;
                    let b = get(pair[1].as_str().ok_or("registry_unresolved")?)?;
                    if if key == "equal" {
                        a.raw != b.raw
                    } else {
                        a.uint()? > b.uint()?
                    } {
                        return Err("field_relation");
                    }
                }
            }
            "nonzero" | "zero_bytes" => {
                for field in instruction.as_array().ok_or("registry_unresolved")? {
                    let value = get(field.as_str().ok_or("registry_unresolved")?)?;
                    let nonzero = if let Ok(n) = value.uint() {
                        n != 0
                    } else {
                        value.bytes()?.iter().any(|b| *b != 0)
                    };
                    if nonzero != (key == "nonzero") {
                        return Err("variant_nonzero");
                    }
                }
            }
            "byte_lengths" => {
                for (field, n) in instruction.as_object().ok_or("registry_unresolved")? {
                    if get(field)?.bytes()?.len() as u64 != number(n)? {
                        return Err("field_length");
                    }
                }
            }
            "byte_prefixes" => {
                for (field, expected) in instruction.as_object().ok_or("registry_unresolved")? {
                    let hex = expected.as_str().ok_or("registry_unresolved")?;
                    let bytes = get(field)?.bytes()?;
                    if hex.len() % 2 != 0 || bytes.len() < hex.len() / 2 {
                        return Err("field_prefix");
                    }
                    for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
                        if bytes[i]
                            != u8::from_str_radix(
                                std::str::from_utf8(pair).map_err(|_| "registry_unresolved")?,
                                16,
                            )
                            .map_err(|_| "registry_unresolved")?
                        {
                            return Err("field_prefix");
                        }
                    }
                }
            }
            "registered" => {
                for (field, registry) in instruction.as_object().ok_or("registry_unresolved")? {
                    let n = get(field)?.uint()?;
                    if !schema()["field_registries"]
                        [registry.as_str().ok_or("registry_unresolved")?]
                    .as_object()
                    .ok_or("registry_unresolved")?
                    .values()
                    .any(|v| number(v) == Ok(n))
                    {
                        return Err("enum_value");
                    }
                }
            }
            _ => return Err("branch_unavailable"),
        }
    }
    Ok(())
}
fn check_rule(value: Value<'_>, name: &str, rule: &Json, context: Context) -> Result<()> {
    let get = |field: &str| -> Result<Value<'_>> {
        path(value, name, field, context)?.ok_or("rule_missing")
    };
    let text = |key: &str| rule[key].as_str().ok_or("registry_unresolved");
    if let Some(when) = rule.get("when") {
        let applies = if let Some(selector) = when["context"].as_str() {
            when["value"].as_str() == Some(context.selector(selector)?)
        } else {
            raw_matches(
                get(when["field"].as_str().ok_or("rule_context")?)?,
                &when["value"],
            )
        };
        if !applies {
            return Ok(());
        }
    }
    match text("op")? {
        "less_than" | "less_or_equal" | "equal" | "not_equal" | "bit_subset" | "max_difference" => {
            let left = get(text("left")?)?;
            let right = get(text("right")?)?;
            let ok = match text("op")? {
                "less_than" => left.uint()? < right.uint()?,
                "less_or_equal" => left.uint()? <= right.uint()?,
                "not_equal" => left.raw != right.raw,
                "bit_subset" => left.uint()? & !right.uint()? == 0,
                "max_difference" => right
                    .uint()?
                    .checked_sub(left.uint()?)
                    .is_some_and(|n| number(&rule["max"]).is_ok_and(|cap| n <= cap)),
                _ => left.raw == right.raw,
            };
            if !ok {
                return Err("field_relation");
            }
        }
        "is_null" => {
            if !get(text("field")?)?.is_null() {
                return Err("field_relation");
            }
        }
        "at_least_one" => {
            let fields = rule["fields"].as_array().ok_or("registry_unresolved")?;
            if !fields.iter().any(|f| {
                f.as_str()
                    .is_some_and(|f| path(value, name, f, context).is_ok_and(|v| v.is_some()))
            }) {
                return Err("field_relation");
            }
        }
        "variant" => {
            // A discriminator belonging to another union arm is absent. The
            // enclosing schema and applicable arm enforce required fields.
            let discriminator = path(value, name, text("discriminator")?, context)?;
            if !discriminator.is_some_and(|value| raw_matches(value, &rule["value"])) {
                return Ok(());
            }
            check_branch(value, name, rule, context)?;
        }
        "context_variant" => {
            check_branch(
                value,
                name,
                &rule["cases"][context.selector(text("context")?)?],
                context,
            )?;
        }
        "range" => {
            let n = get(text("field")?)?.uint()?;
            if n < number(&rule["min"])? || n > number(&rule["max"])? {
                return Err("field_range");
            }
        }
        "profile_algorithm" => {
            let profile = get(text("profile")?)?.text()?;
            if number(&schema()["field_registries"]["crypto_profiles"][profile]["dh_algorithm"])?
                != get(text("algorithm")?)?.uint()?
            {
                return Err("profile_algorithm");
            }
        }
        "feature_bit" => {
            let bit =
                number(&schema()["field_registries"]["feature_registry"][text("feature")?]["bit"])?;
            if bit >= 64
                || (get(text("field")?)?.uint()? & (1u64 << bit) != 0)
                    != rule["present"].as_bool().ok_or("registry_unresolved")?
            {
                return Err("feature_bit");
            }
        }
        "exclusive_item" => {
            let array = get(text("field")?)?;
            let item_name = descriptor(name)?["fields"]
                .as_object()
                .ok_or("registry_unresolved")?
                .values()
                .find(|f| f["name"] == rule["field"])
                .and_then(|f| f["items"]["schema_ref"].as_str())
                .ok_or("rule_path")?;
            for item in array.children()? {
                if path(item?, item_name, text("item_field")?, context)?
                    .is_some_and(|v| raw_matches(v, &rule["value"]))
                    && array.len()? != 1
                {
                    return Err("exclusive_item");
                }
            }
        }
        "allowed_tuples" => {
            let fields = rule["fields"].as_array().ok_or("registry_unresolved")?;
            let mut found = false;
            for row in rule["rows"].as_array().ok_or("registry_unresolved")? {
                if row.as_array().ok_or("registry_unresolved")?.len() != fields.len() {
                    return Err("registry_unresolved");
                }
                let mut matched = true;
                for (field, expected) in fields
                    .iter()
                    .zip(row.as_array().ok_or("registry_unresolved")?)
                {
                    matched &=
                        raw_matches(get(field.as_str().ok_or("registry_unresolved")?)?, expected);
                }
                found |= matched;
            }
            if !found {
                return Err("tuple_invalid");
            }
        }
        "registry_tuple" => {
            let mut entry = &schema()["field_registries"][text("registry")?];
            for selector in rule["selectors"].as_array().ok_or("registry_unresolved")? {
                let selected = if let Some(field) = selector["field"].as_str() {
                    let n = get(field)?.uint()?;
                    let enum_map = descriptor(name)?["fields"]
                        .as_object()
                        .ok_or("registry_unresolved")?
                        .values()
                        .find(|f| f["name"] == field)
                        .ok_or("rule_path")?["enum"]
                        .as_object()
                        .ok_or("registry_unresolved")?;
                    enum_map
                        .iter()
                        .find(|(_, v)| number(v) == Ok(n))
                        .map(|(k, _)| k.as_str())
                        .ok_or("enum_value")?
                } else {
                    context.selector(selector["context"].as_str().ok_or("registry_unresolved")?)?
                };
                entry = entry.get(selected).ok_or("registry_unresolved")?;
            }
            for field in rule["fields"].as_array().ok_or("registry_unresolved")? {
                let field = field.as_str().ok_or("registry_unresolved")?;
                if !raw_matches(get(field)?, entry.get(field).ok_or("registry_unresolved")?) {
                    return Err("tuple_invalid");
                }
            }
        }
        "text_format" => check_text(text("format")?, get(text("field")?)?.text()?)?,
        "origin_endpoint" => {
            let (scheme, host, port) = origin_parts(get(text("origin")?)?.text()?)?;
            if scheme != text("scheme")?
                || host != get(text("host")?)?.text()?
                || u64::from(port) != get(text("port")?)?.uint()?
            {
                return Err("origin_endpoint");
            }
        }
        "increasing" | "increasing_scopes" => {
            let mut previous = None;
            for child in get(text("field")?)?.children()? {
                let child = child?;
                let n = if let Some(id) = rule.get("item_field_id") {
                    let id = number(id)?;
                    let mut pairs = child.children()?;
                    let mut selected = None;
                    while let Some(key) = pairs.next() {
                        let value = pairs.next().ok_or("truncated")??;
                        if key?.uint()? == id {
                            selected = Some(value.uint()?);
                        }
                    }
                    selected.ok_or("rule_missing")?
                } else {
                    child.uint()?
                };
                if previous.is_some_and(|p| p >= n) {
                    return Err("array_order");
                }
                previous = Some(n);
            }
        }
        "increasing_bytes" => {
            let Some(array) = path(value, name, text("field")?, context)? else {
                return Ok(());
            };
            let id = number(&rule["item_field_id"])?;
            let mut previous: Option<&[u8]> = None;
            for item in array.children()? {
                let item = item?;
                let mut pairs = item.children()?;
                let mut bytes = None;
                while let Some(key) = pairs.next() {
                    let child = pairs.next().ok_or("truncated")??;
                    if key?.uint()? == id {
                        bytes = Some(child.bytes()?);
                    }
                }
                let bytes = bytes.ok_or("rule_missing")?;
                if previous.is_some_and(|p| p >= bytes) {
                    return Err("array_order");
                }
                previous = Some(bytes);
            }
        }
        "increasing_cbor" => {
            let mut previous: Option<&[u8]> = None;
            for child in get(text("field")?)?.children()? {
                let child = child?;
                if previous.is_some_and(|p| p >= child.raw) {
                    return Err("array_order");
                }
                previous = Some(child.raw);
            }
        }
        "increasing_tuple" | "unique_by" => {
            let array = get(text("field")?)?;
            let array_field = descriptor(name)?["fields"]
                .as_object()
                .ok_or("registry_unresolved")?
                .values()
                .find(|f| f["name"] == rule["field"])
                .ok_or("rule_path")?;
            let item_name = array_field["items"]["schema_ref"]
                .as_str()
                .ok_or("registry_unresolved")?;
            let keys = rule["item_fields"]
                .as_array()
                .ok_or("registry_unresolved")?;
            let compare = |earlier: Value<'_>, child: Value<'_>| -> Result<std::cmp::Ordering> {
                for key in keys {
                    let key = key.as_str().ok_or("registry_unresolved")?;
                    let order = earlier
                        .field(item_name, key)?
                        .raw
                        .cmp(child.field(item_name, key)?.raw);
                    if order != std::cmp::Ordering::Equal {
                        return Ok(order);
                    }
                }
                Ok(std::cmp::Ordering::Equal)
            };
            let mut previous = None;
            for (i, child) in array.children()?.enumerate() {
                let child = child?;
                if text("op")? == "increasing_tuple" {
                    if let Some(earlier) = previous
                        && compare(earlier, child)? != std::cmp::Ordering::Less
                    {
                        return Err("array_order");
                    }
                    previous = Some(child);
                } else {
                    // The generated TrustConfig unique-by sets have a fixed
                    // maximum of 64 entries; no peer-sized hash/tree is built.
                    if i >= 64 {
                        return Err("array_limit");
                    }
                    for earlier in array.children()?.take(i) {
                        if compare(earlier?, child)? == std::cmp::Ordering::Equal {
                            return Err("array_order");
                        }
                    }
                }
            }
        }
        _ => return Err("rule_unavailable"),
    }
    Ok(())
}
fn domain(name: &str) -> Result<&'static Json> {
    domains()
        .as_array()
        .ok_or("registry_unresolved")?
        .iter()
        .find(|d| d["name"] == name)
        .ok_or("domain_unavailable")
}
fn label<'a>(domain: &Json, buffer: &'a mut [u8; 128]) -> Result<&'a [u8]> {
    let text = domain["label_bytes"]
        .as_str()
        .ok_or("registry_unresolved")?;
    if text.len() % 2 != 0 || text.len() / 2 > buffer.len() {
        return Err("registry_unresolved");
    }
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        buffer[i] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| "registry_unresolved")?,
            16,
        )
        .map_err(|_| "registry_unresolved")?;
    }
    Ok(&buffer[..text.len() / 2])
}
pub(crate) fn digest(name: &str, value: Value<'_>) -> Result<[u8; 32]> {
    let domain = domain(name)?;
    if domain["operation"] != "sha256" || domain["input_schema"]["parts"][0]["projection"] != "full"
    {
        return Err("domain_projection");
    }
    let mut buffer = [0; 128];
    let label = label(domain, &mut buffer)?;
    let mut hash = Sha256::new();
    hash.update(label);
    hash.update(
        u32::try_from(value.raw.len())
            .map_err(|_| "map_size")?
            .to_be_bytes(),
    );
    hash.update(value.raw);
    Ok(hash.finalize().into())
}
pub(crate) fn verify_signature(
    name: &str,
    value: Value<'_>,
    key: &[u8; 32],
    message: &mut Vec<u8>,
) -> Result<()> {
    let signature_id = number(&descriptor(name)?["signature_field"])?;
    let domain = domains()
        .as_array()
        .ok_or("registry_unresolved")?
        .iter()
        .find(|d| {
            d["operation"] == "ed25519" && d["input_schema"]["parts"][0]["schema_ref"] == name
        })
        .ok_or("signature_schema")?;
    let mut buffer = [0; 128];
    let label = label(domain, &mut buffer)?;
    let needed = value
        .raw
        .len()
        .checked_add(label.len() + 4)
        .ok_or("map_size")?;
    if needed > message.capacity() {
        return Err("decoder_capacity");
    }
    message.as_mut_slice().zeroize();
    message.clear();
    message.extend_from_slice(label);
    message.extend_from_slice(&[0; 4]);
    let map_start = message.len();
    encode_head(
        message,
        5,
        value.len()?.checked_sub(1).ok_or("map_type")? as u64,
    );
    let mut signature = None;
    let mut fields = value.children()?;
    while let Some(field) = fields.next() {
        let field = field?;
        let child = fields.next().ok_or("truncated")??;
        if field.uint()? == signature_id {
            signature = Some(child.bytes()?);
        } else {
            message.extend_from_slice(field.raw);
            message.extend_from_slice(child.raw);
        }
    }
    let size = u32::try_from(message.len() - map_start).map_err(|_| "map_size")?;
    message[label.len()..map_start].copy_from_slice(&size.to_be_bytes());
    let signature = signature.ok_or("signature_missing")?;
    if !strict_verify(signature, message, key) {
        return Err("signature_invalid");
    }
    Ok(())
}
pub(crate) fn strict_verify(signature: &[u8], message: &[u8], key: &[u8; 32]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    for raw in [key.as_slice(), &signature[..32]] {
        let Ok(encoded) = <[u8; 32]>::try_from(raw) else {
            return false;
        };
        if !valid_ed25519_key(&encoded) {
            return false;
        }
    }
    let Ok(scalar) = <[u8; 32]>::try_from(&signature[32..]) else {
        return false;
    };
    bool::from(Scalar::from_canonical_bytes(scalar).is_some())
        && UnparsedPublicKey::new(&ED25519, key)
            .verify(message, signature)
            .is_ok()
}
pub(crate) fn valid_ed25519_key(encoded: &[u8; 32]) -> bool {
    CompressedEdwardsY(*encoded)
        .decompress()
        .is_some_and(|point| {
            point.compress().to_bytes() == *encoded
                && !point.is_identity()
                && point.is_torsion_free()
        })
}
pub(crate) fn encode_head(out: &mut Vec<u8>, major: u8, n: u64) {
    if n < 24 {
        out.push(major << 5 | n as u8);
        return;
    }
    let (ai, width) = if n <= 255 {
        (24, 1)
    } else if n <= 65535 {
        (25, 2)
    } else if n <= u32::MAX.into() {
        (26, 4)
    } else {
        (27, 8)
    };
    out.push(major << 5 | ai);
    out.extend_from_slice(&n.to_be_bytes()[8 - width..]);
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) fn schema_revision() -> &'static str {
        static SCHEMA: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
        SCHEMA.get_or_init(|| {
            serde_json::from_str(include_str!("../../stability/transport_v4_schema.json")).unwrap()
        })["schema_revision"]
            .as_str()
            .unwrap()
    }

    use super::*;
    pub(crate) fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    pub(crate) fn encode_map(fields: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_head(&mut out, 5, fields.len() as u64);
        for (id, v) in fields {
            encode_head(&mut out, 0, *id);
            out.extend_from_slice(v);
        }
        out
    }
    pub(crate) fn u(n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_head(&mut out, 0, n);
        out
    }
    pub(crate) fn b(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_head(&mut out, 2, b.len() as u64);
        out.extend_from_slice(b);
        out
    }
    pub(crate) fn t(t: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_head(&mut out, 3, t.len() as u64);
        out.extend_from_slice(t.as_bytes());
        out
    }
    pub(crate) fn array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_head(&mut out, 4, items.len() as u64);
        for v in items {
            out.extend_from_slice(v);
        }
        out
    }
    pub(crate) fn sign(
        name: &str,
        fields: &[(u64, Vec<u8>)],
        key: &ring::signature::Ed25519KeyPair,
    ) -> Vec<u8> {
        let unsigned = encode_map(fields);
        let domain = domains()
            .as_array()
            .unwrap()
            .iter()
            .find(|d| {
                d["operation"] == "ed25519" && d["input_schema"]["parts"][0]["schema_ref"] == name
            })
            .unwrap();
        let mut buffer = [0; 128];
        let mut message = label(domain, &mut buffer).unwrap().to_vec();
        message.extend_from_slice(&(unsigned.len() as u32).to_be_bytes());
        message.extend_from_slice(&unsigned);
        let mut fields = fields.to_vec();
        fields.push((
            number(&descriptor(name).unwrap()["signature_field"]).unwrap(),
            b(key.sign(&message).as_ref()),
        ));
        fields.sort_by_key(|v| v.0);
        encode_map(&fields)
    }
    #[test]
    fn production_namespace_shape_and_original_byte_views() {
        let corpus: Json =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        let mut count = 0;
        for vector in corpus["vectors"].as_array().unwrap() {
            let name = vector["schema"].as_str().unwrap_or("");
            if !matches!(
                name,
                "TrustConfig" | "FreshnessHead" | "RevocationState" | "TrustBootstrapResponse"
            ) {
                continue;
            }
            let input = hex(vector["hex"].as_str().unwrap());
            let limits = &vector["limits"];
            let state = StateLimits {
                bytes: limits["max_state_encoded_bytes"]
                    .as_u64()
                    .unwrap_or(1 << 20),
                issuers: limits["max_revoked_issuers"].as_u64().unwrap_or(256),
                certificates: limits["max_revoked_certificates"].as_u64().unwrap_or(256),
                leases: limits["max_revoked_leases"].as_u64().unwrap_or(256),
                segments: limits["max_cohort_policy_segments"].as_u64().unwrap_or(256),
            };
            let result = decode(
                &input,
                name,
                Limits {
                    bytes: 1 << 20,
                    nodes: 1 << 20,
                },
                Some(state),
            );
            if vector.get("expected_error").is_none() {
                assert_eq!(
                    result
                        .unwrap_or_else(|e| panic!("{}: {e}", vector["id"]))
                        .raw(),
                    input
                );
                count += 1;
            } else {
                assert!(result.is_err(), "{} accepted", vector["id"]);
            }
        }
        assert!(count >= 8);
    }
    #[test]
    fn production_strict_signature_acceptance_matches_shared_corpus() {
        let corpus: Json = serde_json::from_str(include_str!(
            "../../testdata/transport_v4/strict_signatures.json"
        ))
        .unwrap();
        for v in corpus["vectors"].as_array().unwrap() {
            let key = hex(v["public_key_hex"].as_str().unwrap());
            let sig = hex(v["signature_hex"].as_str().unwrap());
            let message = hex(v["message_hex"].as_str().unwrap());
            let accept = key
                .as_slice()
                .try_into()
                .is_ok_and(|key| strict_verify(&sig, &message, key));
            assert_eq!(accept, v["accept"].as_bool().unwrap(), "{}", v["id"]);
        }
    }
    #[test]
    fn production_credential_codec_matches_stateless_shared_corpus() {
        let corpus: Json =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        let mut accepted = 0;
        for vector in corpus["vectors"].as_array().unwrap() {
            let name = vector["schema"].as_str().unwrap_or("");
            if !matches!(
                name,
                "Artifact"
                    | "IdentityCertificate"
                    | "ActivationAuthorization"
                    | "PoolSelectionSet"
                    | "FSB4"
                    | "FSA4"
                    | "Route"
                    | "Leg"
                    | "OriginPolicy"
                    | "TLSPolicy"
                    | "TLSPin"
                    | "Candidate"
            ) || vector["expected_error"] == "pool_set_membership"
            {
                continue;
            }
            let input = hex(vector["hex"].as_str().unwrap());
            let context = Context {
                path_kind: match vector["limits"]["path_kind"].as_str() {
                    Some("direct") => Some(0),
                    Some("tunnel") => Some(1),
                    _ => None,
                },
                activation_source: match vector["limits"]["activation_source_profile"].as_str() {
                    Some("preauthorized_pool") => Some(ActivationSource::PreauthorizedPool),
                    _ => Some(ActivationSource::LiveAuthority),
                },
            };
            let result = decode_context(
                &input,
                name,
                Limits {
                    bytes: 1 << 20,
                    nodes: 1 << 20,
                },
                None,
                context,
            );
            if vector.get("expected_error").is_none() {
                assert_eq!(
                    result
                        .unwrap_or_else(|e| panic!("{}: {e}", vector["id"]))
                        .raw(),
                    input
                );
                accepted += 1;
            } else {
                assert!(result.is_err(), "{} accepted", vector["id"]);
            }
        }
        assert!(accepted >= 40);
    }
    #[test]
    fn parser_rejects_capacity_and_noncanonical_input_before_shape() {
        for raw in [
            &[0xbf, 0xff][..],
            &[0xa1, 0x18, 0x00, 0x01][..],
            &[0xa2, 0x00, 0x01, 0x00, 0x01][..],
            &[0xa0, 0x00][..],
        ] {
            assert!(
                decode(
                    raw,
                    "FreshnessHead",
                    Limits {
                        bytes: 100,
                        nodes: 100
                    },
                    None
                )
                .is_err()
            );
        }
        assert!(
            decode(
                &[0xa0],
                "FreshnessHead",
                Limits { bytes: 0, nodes: 1 },
                None
            )
            .is_err()
        );
        let mut nested = vec![0x81; 10];
        nested.push(0);
        assert!(scan(&nested, 0, &mut 100).is_err());
    }
}
