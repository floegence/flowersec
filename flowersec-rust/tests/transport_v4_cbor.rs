//! Independent canonical syntax/NFC reference, not a production receiver.
#[path = "support/v4_cbor.rs"]
mod cbor;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "support/v4_unicode.rs"]
mod unicode;

use cbor::{Limits, Reference, Value};
use proptest::prelude::*;
use serde::Deserialize;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::OnceLock};

fn reference() -> &'static Reference {
    static REFERENCE: OnceLock<Reference> = OnceLock::new();
    REFERENCE.get_or_init(|| Reference::new(registry::CBOR_REGISTRY_JSON))
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    kind: String,
    hex: String,
    #[serde(default)]
    schema: String,
    #[serde(default)]
    expected_error: String,
    #[serde(default)]
    decimal: String,
    #[serde(default)]
    limits: std::collections::BTreeMap<String, Json>,
}

impl Vector {
    fn limits(&self) -> Limits {
        self.limits
            .iter()
            .filter_map(|(key, value)| value.as_u64().map(|n| (key.clone(), n)))
            .collect()
    }
}

fn corpus() -> &'static Vec<Vector> {
    static CORPUS: OnceLock<Vec<Vector>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        #[derive(Deserialize)]
        struct Corpus {
            schema_sha256: String,
            vectors: Vec<Vector>,
        }
        let corpus: Corpus =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        assert_eq!(corpus.schema_sha256, registry::SCHEMA_SHA256);
        corpus.vectors
    })
}

fn unhex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn encode(value: &Value<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.encode(&mut bytes);
    bytes
}

// v4.rust_cbor.corpus
#[test]
fn shared_syntax_corpus() {
    let mut counts = [0, 0];
    for vector in corpus() {
        if !vector.expected_error.is_empty()
            && !matches!(
                vector.expected_error.as_str(),
                "non_canonical_text"
                    | "unassigned_code_point"
                    | "invalid_utf8"
                    | "unsupported_type"
                    | "array_limit"
                    | "duplicate_key"
                    | "non_shortest_integer"
                    | "map_order"
                    | "truncated"
                    | "trailing_bytes"
                    | "field_id_type"
                    | "indefinite_length"
                    | "depth_limit"
                    | "invalid_header"
                    | "map_limit"
            )
        {
            continue;
        }
        let input = unhex(&vector.hex);
        let before = input.clone();
        let (result, nodes) = reference().decode(
            &input,
            &vector.schema,
            &vector.limits(),
            input.len() as u64 + 1,
        );
        assert!(
            nodes <= input.len(),
            "{}: node count exceeds input",
            vector.id
        );
        assert_eq!(input, before);
        if vector.expected_error.is_empty() {
            counts[0] += 1;
            let value = result.unwrap_or_else(|err| panic!("{}: {err}", vector.id));
            assert_eq!(encode(&value), input, "{}", vector.id);
            if !vector.decimal.is_empty() {
                assert_eq!(
                    value,
                    Value::Unsigned(vector.decimal.parse().unwrap()),
                    "{}",
                    vector.id
                );
            }
        } else {
            counts[1] += 1;
            let err = result.expect_err(&vector.id);
            // Explicit syntax fixtures pin error precedence. A complete syntax
            // pass can reject before the semantic oracle for other fixtures.
            if vector.kind == "cbor_syntax" {
                assert_eq!(err, vector.expected_error, "{}", vector.id);
            }
        }
    }
    assert!(counts.iter().all(|&n| n > 0));
    println!(
        "{} positive and {} syntax-negative cases; field semantics excluded",
        counts[0], counts[1]
    );
}

// v4.rust_cbor.limits
#[test]
fn allocation_and_capacity_boundaries() {
    let r = reference();
    let limits = Limits::new();
    for hex in [
        "5bffffffffffffffff",
        "7bffffffffffffffff",
        "9bffffffffffffffff",
        "bbffffffffffffffff",
        "99040b",
        "b880",
    ] {
        let bytes = unhex(hex);
        let (result, nodes) = r.decode(&bytes, "", &limits, 64);
        assert!(result.is_err(), "{hex}");
        assert_eq!(nodes, 0, "{hex}");
    }
    assert_eq!(
        r.decode(&[0xff, 0xff], "", &limits, 1),
        (Err("map_size"), 0)
    );
    assert_eq!(r.decode(&[], "", &limits, 0), (Err("limit_unresolved"), 0));
    assert_eq!(
        r.decode(&[0], "RevocationState", &limits, 1),
        (Err("limit_unresolved"), 0)
    );
    assert_eq!(
        r.decode(&[0], "Unregistered", &limits, 1),
        (Err("unknown_schema"), 0)
    );

    let registry: Json = serde_json::from_str(registry::CBOR_REGISTRY_JSON).unwrap();
    let map_max = registry["encoding"]["max_map_entries"].as_u64().unwrap();
    let array_max = registry["encoding"]["ordinary_array_items"]
        .as_u64()
        .unwrap();
    for (major, count) in [(5, map_max), (4, array_max)] {
        let mut bytes = Vec::new();
        cbor::head(&mut bytes, major, count);
        for i in 0..count {
            if major == 5 {
                cbor::head(&mut bytes, 0, i);
            }
            bytes.push(0);
        }
        let (value, _) = r.decode(&bytes, "", &limits, bytes.len() as u64);
        assert_eq!(encode(&value.unwrap()), bytes);
        let mut over = Vec::new();
        cbor::head(&mut over, major, count + 1);
        assert!(r.decode(&over, "", &limits, 64).0.is_err());
    }
}

// v4.rust_cbor.context
#[test]
fn schema_scoped_nullable_text_and_large_arrays() {
    let r = reference();
    let limits = Limits::new();
    assert!(r.decode(&[0xf6], "", &limits, 1).0.is_err());
    let registry: Json = serde_json::from_str(registry::CBOR_REGISTRY_JSON).unwrap();
    let vector = corpus()
        .iter()
        .find(|v| v.id == "revoked_issuer_minimum")
        .unwrap();
    let input = unhex(&vector.hex);
    let mut limits = Limits::from([
        ("max_state_encoded_bytes".into(), 1 << 20),
        ("max_revoked_issuer_authorizations".into(), 1036),
    ]);
    let mut value = r
        .decode(&input, &vector.schema, &limits, 1 << 20)
        .0
        .unwrap();
    let fields = registry["frame_maps"][&vector.schema]["fields"]
        .as_object()
        .unwrap();
    let array_id: u64 = fields
        .iter()
        .find(|(_, f)| f["max_items_ref"] == "max_revoked_issuer_authorizations")
        .unwrap()
        .0
        .parse()
        .unwrap();
    let Value::Map(pairs) = &mut value else {
        panic!("expected map")
    };
    let (_, Value::Array(items)) = pairs
        .iter_mut()
        .find(|(k, _)| k == &Value::Unsigned(array_id))
        .unwrap()
    else {
        panic!("expected capacity array")
    };
    // Deliberate repetition tests syntax capacity only; uniqueness is semantic.
    *items = vec![items[0].clone(); 1036];
    let large = encode(&value);
    assert_eq!(
        encode(
            &r.decode(&large, &vector.schema, &limits, large.len() as u64)
                .0
                .unwrap()
        ),
        large
    );
    limits.insert("max_revoked_issuer_authorizations".into(), 1035);
    assert_eq!(
        r.decode(&large, &vector.schema, &limits, large.len() as u64)
            .0,
        Err("array_limit")
    );
    limits.insert("max_revoked_issuer_authorizations".into(), 1 << 32);
    assert_eq!(
        r.decode(&large, &vector.schema, &limits, large.len() as u64)
            .0,
        Err("limit_unresolved")
    );
    limits.insert("max_revoked_issuer_authorizations".into(), 1036);
    limits.insert("max_state_encoded_bytes".into(), large.len() as u64 - 1);
    assert_eq!(
        r.decode(&large, &vector.schema, &limits, large.len() as u64),
        (Err("map_size"), 0)
    );

    // Text keys require their declared metadata-values slot, even when the
    // exact same map is valid inside an ordinary metadata fixture.
    let text_map = encode(&Value::Map(vec![(Value::Text("a"), Value::Text("b"))]));
    assert_eq!(
        r.decode(&text_map, "", &Limits::new(), 64).0,
        Err("field_id_type")
    );
}

// v4.rust_cbor.unicode
#[test]
fn pinned_unicode_conformance_and_part1_complement() {
    let nfc = &reference().nfc;
    let raw = include_str!("../../testdata/unicode15_1/NormalizationTest.txt");
    assert_eq!(
        Sha256::digest(raw.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        nfc.conformance_sha256
    );
    let mut part_one = false;
    let mut covered = BTreeSet::new();
    let mut count = 0;
    for raw_line in raw.lines() {
        let line = raw_line.split('#').next().unwrap().trim();
        if line.starts_with('@') {
            part_one = line.starts_with("@Part1");
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let columns: Vec<String> = line
            .split(';')
            .take(5)
            .map(|column| {
                column
                    .split_whitespace()
                    .map(|n| char::from_u32(u32::from_str_radix(n, 16).unwrap()).unwrap())
                    .collect()
            })
            .collect();
        assert_eq!(columns.len(), 5);
        if part_one {
            covered.extend(columns[0].chars());
        }
        for (i, input) in columns.iter().enumerate() {
            assert_eq!(
                nfc.normalize(input),
                columns[if i < 3 { 1 } else { 3 }],
                "case {count}, column {i}"
            );
        }
        count += 1;
    }
    assert_eq!(count, 19074);
    for cp in 0..=0x10ffff {
        if let Some(c) = char::from_u32(cp)
            && !covered.contains(&c)
        {
            assert_eq!(nfc.normalize(&c.to_string()), c.to_string(), "U+{cp:04X}");
        }
    }
    assert!(!nfc.assigned('\u{1cc00}'));
    assert!(!nfc.assigned('\u{0378}'));
    let long = format!("A{}", "\u{0315}\u{0300}".repeat(10000));
    let normalized = nfc.normalize(&long);
    assert_eq!(nfc.normalize(&normalized), normalized);
}

// v4.rust_cbor.properties
proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn arbitrary_input_is_rejected_or_round_trips(input in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let (result, nodes) = reference().decode(&input, "", &Limits::new(), 4096);
        prop_assert!(nodes <= input.len());
        if input.len() > 4096 { prop_assert_eq!(&result, &Err("map_size")); prop_assert_eq!(nodes, 0); }
        if let Ok(value) = result { prop_assert_eq!(encode(&value), input); }
    }

    #[test]
    fn mutated_registered_inputs_preserve_original_bytes(index in any::<usize>(), offset in any::<usize>(), byte in any::<u8>()) {
        let vector = &corpus()[index % corpus().len()];
        let mut input = unhex(&vector.hex);
        if !input.is_empty() { let at = offset % input.len(); input[at] ^= byte; }
        let original = input.clone();
        let (result, nodes) = reference().decode(&input, &vector.schema, &vector.limits(), input.len() as u64 + 1);
        prop_assert!(nodes <= input.len());
        if let Ok(value) = result { prop_assert_eq!(encode(&value), original); }
    }
}
