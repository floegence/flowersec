//! Signed host/Origin syntax only; real DNS, TLS and HTTP admission are separate.
use super::cbor::{Error, Value};
use super::idna::Idna;
use super::shape::{Context, Shape, integer};
use regex_lite::Regex;
use serde::Deserialize;
use serde_json::Value as Json;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
};

pub struct Text {
    pub shape: Shape,
    pub idna: Idna,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TextRule {
    op: String,
    field: String,
    format: String,
    host: String,
    port: String,
    origin: String,
    scheme: String,
    when: Option<Json>,
}

fn forbidden_host(cp: char) -> bool {
    matches!(cp, '\u{9}'..='\u{d}' | '\u{2000}'..='\u{200a}' | ' ' | '[' | ']' | '%' | '\\' | '/' | '?' | '#' | '@'
        | '\u{a0}' | '\u{1680}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

fn ipv6_hex(address: Ipv6Addr) -> String {
    let words = address.segments();
    let text: Vec<String> = words.iter().map(|n| format!("{n:x}")).collect();
    let (mut best, mut length, mut index) = (None, 1, 0);
    while index < words.len() {
        if words[index] != 0 {
            index += 1;
            continue;
        }
        let mut end = index + 1;
        while end < words.len() && words[end] == 0 {
            end += 1;
        }
        if end - index > length {
            best = Some(index);
            length = end - index;
        }
        index = end;
    }
    match best {
        Some(start) => format!(
            "{}::{}",
            text[..start].join(":"),
            text[start + length..].join(":")
        ),
        None => text.join(":"),
    }
}

impl Text {
    pub fn new(registry: &str) -> Self {
        Self {
            shape: Shape::new(registry),
            idna: Idna::new(registry),
        }
    }

    pub fn issuer_host(&self, input: &str) -> Result<String, Error> {
        if input.is_empty() {
            return Err("host_text");
        }
        if input.chars().any(forbidden_host) {
            return Err("host_syntax");
        }
        if input.contains(':') {
            // Preserve IPv4-mapped address family and bits, with hex-only output.
            let addr: Ipv6Addr = input.parse().map_err(|_| "host_ipv6")?;
            return Ok(ipv6_hex(addr));
        }
        if input.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            let addr: Ipv4Addr = input.parse().map_err(|_| "host_ipv4")?;
            return Ok(addr.to_string());
        }
        let dns = self.idna.issuer_dns(input)?;
        let last = dns.rsplit('.').next().ok_or("host_text")?;
        if last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("host_numeric_final_label");
        }
        Ok(dns)
    }

    pub fn wire_host(&self, input: &str) -> Result<(), Error> {
        if input.is_empty() || !input.is_ascii() {
            return Err("host_wire_ascii");
        }
        if self.issuer_host(input)? != input {
            return Err("host_noncanonical");
        }
        Ok(())
    }

    fn default_port(&self, scheme: &str) -> Result<u64, Error> {
        let entry = self
            .shape
            .field_registry("origin_schemes")?
            .get(scheme)
            .ok_or("origin_scheme_unregistered")?;
        integer(&entry["default_port"])
    }

    pub fn wire_origin(&self, input: &str) -> Result<(), Error> {
        if input.is_empty() || !input.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err("origin_ascii");
        }
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        let pattern = PATTERN.get_or_init(|| {
            Regex::new(r"^([a-z][a-z0-9+.-]*)://(\[[0-9a-f:]+\]|[^:/?#@\\\[\]]+)(?::([0-9]+))?$")
                .unwrap()
        });
        let parts = pattern.captures(input).ok_or("origin_syntax")?;
        let default = self.default_port(parts.get(1).unwrap().as_str())?;
        let mut host = parts.get(2).unwrap().as_str();
        if host.starts_with('[') {
            host = &host[1..host.len() - 1];
            if !host.contains(':') {
                return Err("origin_syntax");
            }
        }
        self.wire_host(host)?;
        if let Some(port) = parts.get(3) {
            let port = port.as_str();
            if port.len() > 1 && port.starts_with('0') {
                return Err("origin_port");
            }
            let port: u16 = port.parse().map_err(|_| "origin_port")?;
            if u64::from(port) == default {
                return Err("origin_default_port");
            }
        }
        Ok(())
    }

    fn format(&self, format: &str, input: &str) -> Result<(), Error> {
        match format {
            "host" => self.wire_host(input),
            "origin" => self.wire_origin(input),
            "loopback_host" => {
                self.wire_host(input)?;
                if input == "::1"
                    || input
                        .parse::<Ipv4Addr>()
                        .is_ok_and(|a| a.octets()[0] == 127)
                {
                    Ok(())
                } else {
                    Err("host_loopback")
                }
            }
            _ => Err("text_format_unresolved"),
        }
    }

    fn field_formats(
        &self,
        field: &Json,
        value: &Value<'_>,
        context: &Context,
    ) -> Result<(), Error> {
        let field = self.shape.selected_field(field, context)?;
        if let Some(format) = field["text_format"].as_str() {
            let Value::Text(text) = value else {
                return Err("field_type");
            };
            return self.format(format, text);
        }
        match field["type"].as_str().ok_or("registry_unresolved")? {
            "array" => {
                let Value::Array(items) = value else {
                    return Err("field_type");
                };
                for item in items {
                    self.field_formats(&field["items"], item, context)?;
                }
            }
            "text_map" => {
                let Value::Map(pairs) = value else {
                    return Err("map_type");
                };
                for (key, value) in pairs {
                    self.field_formats(&field["keys"], key, context)?;
                    let Value::Text(text) = key else {
                        return Err("field_type");
                    };
                    let child = if let Some(entries) = field.get("entries") {
                        entries.get(*text).ok_or("unknown_field")?
                    } else {
                        field.get("values").ok_or("registry_unresolved")?
                    };
                    self.field_formats(child, value, context)?;
                }
            }
            _ => {}
        }
        // Map and embedded children are visited by the common scoped walker.
        Ok(())
    }

    fn check_map(&self, name: &str, value: &Value<'_>, context: &Context) -> Result<(), Error> {
        let Value::Map(pairs) = value else {
            return Err("map_type");
        };
        let descriptor = self.shape.descriptor(name)?;
        for (key, child) in pairs {
            let Value::Unsigned(id) = key else {
                return Err("field_id_type");
            };
            self.field_formats(
                descriptor["fields"]
                    .get(id.to_string())
                    .ok_or("unknown_field")?,
                child,
                context,
            )?;
        }
        let Some(rules) = self.shape.registry["text_rules"].get(name) else {
            return Ok(());
        };
        for rule in rules.as_array().ok_or("rule_unresolved")? {
            let rule: TextRule =
                serde_json::from_value(rule.clone()).map_err(|_| "rule_unresolved")?;
            if !self
                .shape
                .rule_applies(name, value, rule.when.as_ref(), context)?
            {
                continue;
            }
            let get = |path: &str| {
                self.shape
                    .rule_path(name, value, path, context)?
                    .ok_or("unknown_rule_field")
            };
            match rule.op.as_str() {
                "text_format" => {
                    let Value::Text(text) = get(&rule.field)? else {
                        return Err("field_type");
                    };
                    self.format(&rule.format, text)?;
                }
                "origin_endpoint" => {
                    let (Value::Text(host), Value::Unsigned(port), Value::Text(origin)) =
                        (get(&rule.host)?, get(&rule.port)?, get(&rule.origin)?)
                    else {
                        return Err("field_type");
                    };
                    let host = if host.contains(':') {
                        format!("[{host}]")
                    } else {
                        host.into()
                    };
                    let mut expected = format!("{}://{host}", rule.scheme);
                    if port != self.default_port(&rule.scheme)? {
                        expected.push_str(&format!(":{port}"));
                    }
                    if expected != origin {
                        return Err("origin_endpoint");
                    }
                }
                _ => return Err("rule_unresolved"),
            }
        }
        Ok(())
    }

    pub fn wire_map<'a>(
        &self,
        input: &'a [u8],
        name: &str,
        context: &Context,
        cap: u64,
    ) -> Result<Value<'a>, Error> {
        let value = self.shape.relations(input, name, context, cap)?;
        if !name.is_empty() {
            self.shape
                .walk_rules(name, &value, context, &|name, value, context| {
                    self.check_map(name, value, context)
                })?;
        }
        Ok(value)
    }
}
