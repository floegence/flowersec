//! Independent test-only syntax reader. No signature, field/variant semantics,
//! live reservations or production receiver qualification is established here.
use super::unicode::Nfc;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub type Limits = BTreeMap<String, u64>;
pub type Error = &'static str;

#[derive(Default, Deserialize)]
pub struct Field {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    schema_ref: String,
    #[serde(default)]
    encoded_schema_ref: String,
    #[serde(default)]
    allow_empty: bool,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    max_items_ref: String,
    items: Option<Box<Field>>,
    values: Option<Box<Field>>,
    #[serde(default)]
    entries: BTreeMap<String, Field>,
}

#[derive(Deserialize)]
struct Map {
    fields: BTreeMap<String, Field>,
    max_encoded_bytes: Option<u64>,
    #[serde(default)]
    max_encoded_bytes_ref: String,
}

#[derive(Deserialize)]
struct Encoding {
    max_depth: usize,
    max_map_entries: u64,
    ordinary_array_items: u64,
    max_field_id: u64,
}

#[derive(Deserialize)]
struct DataSource {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct Unicode {
    nfc_data: DataSource,
}

#[derive(Deserialize)]
struct Registry {
    encoding: Encoding,
    frame_maps: BTreeMap<String, Map>,
    unicode: Unicode,
}

pub struct Reference {
    registry: Registry,
    pub nfc: Nfc,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Value<'a> {
    Unsigned(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    Map(Vec<(Value<'a>, Value<'a>)>),
    Bool(bool),
    Null,
}

impl Value<'_> {
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Unsigned(n) => head(out, 0, *n),
            Self::Bytes(raw) => {
                head(out, 2, raw.len() as u64);
                out.extend_from_slice(raw);
            }
            Self::Text(text) => {
                head(out, 3, text.len() as u64);
                out.extend_from_slice(text.as_bytes());
            }
            Self::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.encode(out);
                }
            }
            Self::Map(pairs) => {
                head(out, 5, pairs.len() as u64);
                for (key, value) in pairs {
                    key.encode(out);
                    value.encode(out);
                }
            }
            Self::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            Self::Null => out.push(0xf6),
        }
    }
}

pub fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    if n < 24 {
        out.push(major << 5 | n as u8);
    } else {
        let (ai, width) = if n <= u8::MAX.into() {
            (24, 1)
        } else if n <= u16::MAX.into() {
            (25, 2)
        } else if n <= u32::MAX.into() {
            (26, 4)
        } else {
            (27, 8)
        };
        out.push(major << 5 | ai);
        out.extend_from_slice(&n.to_be_bytes()[8 - width..]);
    }
}

impl Reference {
    pub fn new(json: &str) -> Self {
        let registry: Registry = serde_json::from_str(json).unwrap();
        let data = &registry.unicode.nfc_data;
        let nfc = Nfc::load(&data.path, &data.sha256);
        Self { registry, nfc }
    }

    pub fn decode<'a>(
        &self,
        input: &'a [u8],
        schema: &str,
        limits: &Limits,
        owner_cap: u64,
    ) -> (Result<Value<'a>, Error>, usize) {
        let mut nodes = 0;
        let result = self.document(input, schema, limits, owner_cap, &mut nodes);
        (result, nodes)
    }

    fn document<'a>(
        &self,
        input: &'a [u8],
        schema: &str,
        limits: &Limits,
        mut cap: u64,
        nodes: &mut usize,
    ) -> Result<Value<'a>, Error> {
        if cap == 0 {
            return Err("limit_unresolved");
        }
        let descriptor = if schema.is_empty() {
            None
        } else {
            let map = self
                .registry
                .frame_maps
                .get(schema)
                .ok_or("unknown_schema")?;
            if let Some(bound) = map.max_encoded_bytes {
                cap = cap.min(bound);
            }
            if !map.max_encoded_bytes_ref.is_empty() {
                let bound = limits
                    .get(&map.max_encoded_bytes_ref)
                    .copied()
                    .filter(|&n| n > 0)
                    .ok_or("limit_unresolved")?;
                cap = cap.min(bound);
            }
            Some(Field {
                kind: "map".into(),
                schema_ref: schema.into(),
                ..Field::default()
            })
        };
        // No parsed nodes or backing copy before this caller/schema envelope check.
        if input.len() as u64 > cap {
            return Err("map_size");
        }
        let mut reader = Reader {
            reference: self,
            input,
            offset: 0,
            nodes,
            limits,
        };
        let value = reader.item(0, descriptor.as_ref())?;
        if reader.offset != input.len() {
            return Err("trailing_bytes");
        }
        Ok(value)
    }
}

struct Reader<'r, 'a> {
    reference: &'r Reference,
    input: &'a [u8],
    offset: usize,
    nodes: &'r mut usize,
    limits: &'r Limits,
}

impl<'a> Reader<'_, 'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8], Error> {
        if n > (self.input.len() - self.offset) as u64 {
            return Err("truncated");
        }
        // Conversion and addition are safe only after the remaining-input check.
        let start = self.offset;
        self.offset += n as usize;
        Ok(&self.input[start..self.offset])
    }

    fn item(&mut self, depth: usize, field: Option<&Field>) -> Result<Value<'a>, Error> {
        let reference = self.reference;
        let policy = &reference.registry.encoding;
        if depth > policy.max_depth {
            return Err("depth_limit");
        }
        let byte = self.take(1)?[0];
        let (major, ai) = (byte >> 5, byte & 31);
        if ai == 31 {
            return Err("indefinite_length");
        }
        if major == 7 {
            let value = match ai {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 if field.is_some_and(|f| f.kind == "uint64" && f.nullable) => Value::Null,
                _ => return Err("unsupported_type"),
            };
            *self.nodes += 1;
            return Ok(value);
        }
        if !matches!(major, 0 | 2 | 3 | 4 | 5) {
            return Err("unsupported_type");
        }
        if ai > 27 {
            return Err("invalid_header");
        }
        let n = if ai < 24 {
            u64::from(ai)
        } else {
            let width = 1 << (ai - 24);
            let raw = self.take(width)?;
            let n = raw.iter().fold(0u64, |n, &b| n << 8 | u64::from(b));
            let minimum = [24, 256, 65536, 4294967296][usize::from(ai - 24)];
            if n < minimum {
                return Err("non_shortest_integer");
            }
            n
        };
        match major {
            0 => {
                *self.nodes += 1;
                Ok(Value::Unsigned(n))
            }
            2 | 3 => {
                let raw = self.take(n)?;
                let value = if major == 3 {
                    let text = std::str::from_utf8(raw).map_err(|_| "invalid_utf8")?;
                    if !text.chars().all(|c| reference.nfc.assigned(c)) {
                        return Err("unassigned_code_point");
                    }
                    if reference.nfc.normalize(text) != text {
                        return Err("non_canonical_text");
                    }
                    Value::Text(text)
                } else {
                    if let Some(f) = field
                        && !f.encoded_schema_ref.is_empty()
                        && !(f.allow_empty && raw.is_empty())
                    {
                        // An encoded byte string is its own document; preserve
                        // its original bytes while validating at root depth.
                        reference.document(
                            raw,
                            &f.encoded_schema_ref,
                            self.limits,
                            raw.len() as u64 + 1,
                            self.nodes,
                        )?;
                    }
                    Value::Bytes(raw)
                };
                *self.nodes += 1;
                Ok(value)
            }
            4 => {
                let mut cap = policy.ordinary_array_items;
                if let Some(f) = field
                    && !f.max_items_ref.is_empty()
                {
                    cap = self
                        .limits
                        .get(&f.max_items_ref)
                        .copied()
                        .filter(|&n| n <= u32::MAX.into())
                        .ok_or("limit_unresolved")?;
                }
                if n > cap {
                    return Err("array_limit");
                }
                if n > (self.input.len() - self.offset) as u64 {
                    return Err("truncated");
                }
                *self.nodes += 1;
                let mut items = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    items.push(self.item(depth + 1, field.and_then(|f| f.items.as_deref()))?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                if n > policy.max_map_entries {
                    return Err("map_limit");
                }
                if n > ((self.input.len() - self.offset) / 2) as u64 {
                    return Err("truncated");
                }
                *self.nodes += 1;
                let mut pairs = Vec::with_capacity(n as usize);
                let mut keys = BTreeSet::new();
                let mut previous: Option<&[u8]> = None;
                let text_map = field.is_some_and(|f| f.kind == "text_map");
                for _ in 0..n {
                    let start = self.offset;
                    let key = self.item(depth + 1, None)?;
                    let child = match (&key, text_map) {
                        (Value::Unsigned(id), false) if *id <= policy.max_field_id => field
                            .and_then(|f| reference.registry.frame_maps.get(&f.schema_ref))
                            .and_then(|map| map.fields.get(&id.to_string())),
                        (Value::Text(text), true) => {
                            field.and_then(|f| f.entries.get(*text).or(f.values.as_deref()))
                        }
                        _ => return Err("field_id_type"),
                    };
                    let encoded = &self.input[start..self.offset];
                    if !keys.insert(encoded) {
                        return Err("duplicate_key");
                    }
                    if previous.is_some_and(|last| (last.len(), last) >= (encoded.len(), encoded)) {
                        return Err("map_order");
                    }
                    previous = Some(encoded);
                    let value = self.item(depth + 1, child)?;
                    pairs.push((key, value));
                }
                Ok(Value::Map(pairs))
            }
            _ => unreachable!(),
        }
    }
}
