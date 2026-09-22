//! Generated stateless relations; signed facts still require authentication.
#[path = "support/v4_cbor.rs"]
mod cbor;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "support/v4_relations.rs"]
mod relations;
#[path = "support/v4_rules.rs"]
mod rules;
#[path = "support/v4_shape.rs"]
mod shape;
#[allow(dead_code)]
#[path = "support/v4_unicode.rs"]
mod unicode;
#[path = "support/v4_variants.rs"]
mod variants;

use cbor::Value;
use proptest::prelude::*;
use serde_json::Value as Json;
use shape::{Context, Shape, integer};
use std::sync::OnceLock;

fn reference() -> &'static Shape {
    static REFERENCE: OnceLock<Shape> = OnceLock::new();
    REFERENCE.get_or_init(|| Shape::new(registry::CBOR_REGISTRY_JSON))
}

fn corpus() -> &'static Vec<Json> {
    static CORPUS: OnceLock<Vec<Json>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let json: Json =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        assert_eq!(json["schema_sha256"], registry::SCHEMA_SHA256);
        json["vectors"].as_array().unwrap().clone()
    })
}

fn seed(id: &str) -> &'static Json {
    corpus().iter().find(|v| v["id"] == id).unwrap()
}

fn context(vector: &Json) -> Context {
    let mut context = Context::default();
    if let Some(limits) = vector["limits"].as_object() {
        for (key, value) in limits {
            if let Some(n) = value.as_u64() {
                context.limits.insert(key.clone(), n);
            }
            if let Some(text) = value.as_str() {
                context.selectors.insert(key.clone(), text.into());
            }
        }
    }
    context
}

fn bytes(vector: &Json) -> Vec<u8> {
    let hex = vector["hex"].as_str().unwrap().as_bytes();
    assert!(hex.len().is_multiple_of(2));
    hex.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn encode(value: &Value<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode(&mut out);
    out
}

fn set_field<'a>(name: &str, value: &mut Value<'a>, field: &str, replacement: Value<'a>) {
    let id: u64 = reference().registry["frame_maps"][name]["fields"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, f)| f["name"] == field)
        .unwrap()
        .0
        .parse()
        .unwrap();
    let Value::Map(pairs) = value else {
        panic!("expected map")
    };
    pairs
        .iter_mut()
        .find(|(k, _)| k == &Value::Unsigned(id))
        .unwrap()
        .1 = replacement;
}

// v4.rust_relations.corpus
#[test]
fn shared_stateless_relation_corpus() {
    let mut counts = [0, 0, 0];
    for vector in corpus() {
        let error = vector["expected_error"].as_str().unwrap_or("");
        // Host/Origin/IDNA and external pool/open-digest oracles are separate.
        if matches!(
            error,
            "host_noncanonical"
                | "host_loopback"
                | "origin_endpoint"
                | "origin_default_port"
                | "origin_syntax"
                | "pool_set_membership"
                | "open_digest_mismatch"
        ) {
            counts[2] += 1;
            continue;
        }
        let input = bytes(vector);
        let ctx = context(vector);
        let before = ctx.selectors.clone();
        let result = reference().relations(
            &input,
            vector["schema"].as_str().unwrap_or(""),
            &ctx,
            input.len() as u64 + 1,
        );
        assert_eq!(ctx.selectors, before);
        if error.is_empty() {
            counts[0] += 1;
            assert_eq!(
                encode(&result.unwrap_or_else(|e| panic!("{}: {e}", vector["id"]))),
                input
            );
        } else {
            counts[1] += 1;
            assert!(result.is_err(), "{} accepted ({error})", vector["id"]);
        }
        assert_eq!(input, bytes(vector));
    }
    assert_eq!(counts, [337, 816, 12]);
    println!(
        "{} positives, {} negatives, {} separate text/external-oracle cases",
        counts[0], counts[1], counts[2]
    );
}

// v4.rust_relations.full_width_windows
#[test]
fn duration_checks_preserve_full_uint64_and_check_order_before_subtraction() {
    let r = reference();
    let vector = seed("tls_pin_full_window");
    let input = bytes(vector);
    let ctx = context(vector);
    let original = r.relations(&input, "TLSPin", &ctx, 65536).unwrap();
    let limit = integer(
        &r.registry["relation_rules"]["TLSPin"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["op"] == "max_difference")
            .unwrap()["max"],
    )
    .unwrap();
    for (before, after, expected) in [
        (u64::MAX - limit, u64::MAX, None),
        (u64::MAX - limit - 1, u64::MAX, Some("field_duration")),
        (u64::MAX, 1, Some("field_order")),
    ] {
        let mut value = original.clone();
        set_field(
            "TLSPin",
            &mut value,
            "not_before_ms",
            Value::Unsigned(before),
        );
        set_field("TLSPin", &mut value, "not_after_ms", Value::Unsigned(after));
        let wire = encode(&value);
        r.variants(&wire, "TLSPin", &ctx, 65536).unwrap();
        let result = r.relations(&wire, "TLSPin", &ctx, 65536);
        if let Some(error) = expected {
            assert_eq!(result, Err(error));
        } else {
            assert_eq!(encode(&result.unwrap()), wire);
        }
    }
    assert_eq!(input, bytes(vector));
}

// v4.rust_relations.signed_bytes
#[test]
fn embedded_certificate_digest_includes_the_original_signature() {
    let r = reference();
    let vector = seed("hop_endpoint_hello_fields");
    let input = bytes(vector);
    let ctx = context(vector);
    let mut hello = r.relations(&input, "HOP_AUTH_HELLO", &ctx, 65536).unwrap();
    let Some(Value::Bytes(certificate)) = r
        .rule_path("HOP_AUTH_HELLO", &hello, "identity_certificate", &ctx)
        .unwrap()
    else {
        panic!("certificate")
    };
    let mut certificate = r
        .decode(certificate, "IdentityCertificate", &ctx, 65536)
        .unwrap();
    let Some(Value::Bytes(signature)) = r
        .rule_path("IdentityCertificate", &certificate, "signature", &ctx)
        .unwrap()
    else {
        panic!("signature")
    };
    let mut signature = signature.to_vec();
    signature[0] ^= 1;
    set_field(
        "IdentityCertificate",
        &mut certificate,
        "signature",
        Value::Bytes(&signature),
    );
    let certificate = encode(&certificate);
    set_field(
        "HOP_AUTH_HELLO",
        &mut hello,
        "identity_certificate",
        Value::Bytes(&certificate),
    );
    let wire = encode(&hello);
    r.variants(&wire, "HOP_AUTH_HELLO", &ctx, 65536).unwrap();
    assert_eq!(
        r.relations(&wire, "HOP_AUTH_HELLO", &ctx, 65536),
        Err("map_digest_mismatch")
    );
    assert_eq!(input, bytes(vector));
    // This verifies complete digest input, not certificate signature validity.
}

// v4.rust_relations.properties
proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn mutated_relations_reject_or_preserve_bytes(index in any::<usize>(), at in any::<usize>(), byte in any::<u8>()) {
        let vector = &corpus()[index % corpus().len()];
        let mut input = bytes(vector);
        if !input.is_empty() { let at = at % input.len(); input[at] ^= byte; }
        let ctx = context(vector);
        let before = ctx.selectors.clone();
        let result = reference().relations(&input, vector["schema"].as_str().unwrap_or(""), &ctx, input.len() as u64 + 1);
        prop_assert_eq!(ctx.selectors, before);
        if let Ok(value) = result { prop_assert_eq!(encode(&value), input); }
    }
}
