//! Independent field validation over the generated registry, not runtime authority.
#[path = "support/v4_cbor.rs"]
mod cbor;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "support/v4_shape.rs"]
mod shape;
#[allow(dead_code)]
#[path = "support/v4_unicode.rs"]
mod unicode;

use cbor::Value;
use proptest::prelude::*;
use serde_json::Value as Json;
use shape::{Context, Shape, integer};
use std::{collections::BTreeSet, sync::OnceLock};

fn reference() -> &'static Shape {
    static SHAPE: OnceLock<Shape> = OnceLock::new();
    SHAPE.get_or_init(|| Shape::new(registry::CBOR_REGISTRY_JSON))
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
    let hex = vector["hex"].as_str().unwrap();
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .as_chunks::<2>()
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

// v4.rust_shape.corpus
#[test]
fn shared_field_shape_corpus() {
    let mut counts = [0, 0];
    for vector in corpus() {
        let expected = vector["expected_error"].as_str().unwrap_or("");
        // These two names overlap with field errors but require map variants.
        if matches!(
            vector["id"].as_str().unwrap(),
            "admission_rejected_unknown_code" | "context_auth_exporter_bytes"
        ) {
            continue;
        }
        if !expected.is_empty()
            && !matches!(
                expected,
                "unknown_field"
                    | "missing_field"
                    | "integer_type"
                    | "integer_range"
                    | "constant_mismatch"
                    | "field_type"
                    | "field_length"
                    | "field_nonzero"
                    | "text_pattern"
                    | "reserved_namespace"
                    | "enum_value"
                    | "unknown_bits"
                    | "map_type"
                    | "map_length"
                    | "array_length"
                    | "map_size"
            )
        {
            continue;
        }
        let input = bytes(vector);
        let result = reference().decode(
            &input,
            vector["schema"].as_str().unwrap_or(""),
            &context(vector),
            input.len() as u64 + 1,
        );
        if expected.is_empty() {
            counts[0] += 1;
            let value = result.unwrap_or_else(|e| panic!("{}: {e}", vector["id"]));
            assert_eq!(encode(&value), input, "{}", vector["id"]);
        } else {
            counts[1] += 1;
            assert!(result.is_err(), "{} accepted", vector["id"]);
        }
    }
    assert!(counts.iter().all(|&n| n > 0));
    println!(
        "{} positive and {} field-negative cases",
        counts[0], counts[1]
    );
}

// v4.rust_shape.required_unknown
#[test]
fn every_corpus_root_rejects_missing_and_unknown_fields() {
    let mut seen = BTreeSet::new();
    for vector in corpus() {
        let Some(name) = vector["schema"].as_str() else {
            continue;
        };
        if vector.get("expected_error").is_some() || !seen.insert(name) {
            continue;
        }
        let input = bytes(vector);
        let context = context(vector);
        let original = reference()
            .decode(&input, name, &context, input.len() as u64 + 1)
            .unwrap();
        let Value::Map(pairs) = original else {
            panic!("map expected")
        };
        let descriptor = &reference().registry["frame_maps"][name];
        for id in descriptor["required"].as_array().unwrap() {
            let id = integer(id).unwrap();
            let modified = Value::Map(
                pairs
                    .iter()
                    .filter(|(k, _)| k != &Value::Unsigned(id))
                    .cloned()
                    .collect(),
            );
            assert!(
                reference().check_map(name, &modified, &context).is_err(),
                "{name} missing {id}"
            );
        }
        assert!(descriptor["fields"].get("65535").is_none());
        let mut modified = pairs.clone();
        modified.push((Value::Unsigned(65535), Value::Unsigned(0)));
        assert_eq!(
            reference().check_map(name, &Value::Map(modified), &context),
            Err("unknown_field"),
            "{name}"
        );
    }
    assert!(!seen.is_empty());
    println!("{} distinct root maps", seen.len());
}

// v4.rust_shape.context_boundaries
#[test]
fn explicit_context_and_full_width_boundaries() {
    let r = reference();
    let seed = |id: &str| corpus().iter().find(|v| v["id"] == id).unwrap();
    let field_id = |name: &str, field: &str| -> u64 {
        r.registry["frame_maps"][name]["fields"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, f)| f["name"] == field)
            .unwrap()
            .0
            .parse()
            .unwrap()
    };
    let rekey = seed("rekey_init_fields");
    let input = bytes(rekey);
    assert_eq!(
        r.decode(&input, "REKEY_INIT", &Context::default(), 65536),
        Err("context_unresolved")
    );
    let mut ctx = context(rekey);
    ctx.selectors
        .insert("crypto_profile_id".into(), "unknown".into());
    assert_eq!(
        r.decode(&input, "REKEY_INIT", &ctx, 65536),
        Err("context_unresolved")
    );
    let p256 = r.registry["field_registries"]["crypto_profiles"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, profile)| profile["dh_algorithm"] == 1)
        .unwrap()
        .0;
    ctx.selectors
        .insert("crypto_profile_id".into(), p256.clone());
    assert_eq!(
        r.decode(&input, "REKEY_INIT", &ctx, 65536),
        Err("field_length")
    );
    let mut value = r
        .decode(&input, "REKEY_INIT", &context(rekey), 65536)
        .unwrap();
    let Value::Map(pairs) = &mut value else {
        panic!("map expected")
    };
    let key_id = field_id("REKEY_INIT", "client_ephemeral");
    let pair = pairs
        .iter_mut()
        .find(|(k, _)| k == &Value::Unsigned(key_id))
        .unwrap();
    let mut public = vec![
        0u8;
        integer(&r.registry["field_registries"]["crypto_profiles"][p256]["dh_public_bytes"])
            .unwrap() as usize
    ];
    public[0] = 3;
    pair.1 = Value::Bytes(&public);
    assert_eq!(r.check_map("REKEY_INIT", &value, &ctx), Err("field_prefix"));
    // A correct prefix/length is only a field shape, never a curve-validity claim.
    let mut valid_prefix = public.clone();
    valid_prefix[0] = 4;
    let mut valid_shape = value.clone();
    let Value::Map(pairs) = &mut valid_shape else {
        unreachable!()
    };
    pairs
        .iter_mut()
        .find(|(k, _)| k == &Value::Unsigned(key_id))
        .unwrap()
        .1 = Value::Bytes(&valid_prefix);
    assert_eq!(r.check_map("REKEY_INIT", &valid_shape, &ctx), Ok(()));

    let pool = bytes(seed("activation_pool_fields"));
    assert_eq!(
        r.decode(&pool, "ActivationAuthorization", &Context::default(), 65536),
        Err("context_unresolved")
    );
    let mut wrong = context(seed("activation_pool_fields"));
    wrong
        .selectors
        .insert("activation_source_profile".into(), "live_authority".into());
    assert!(
        r.decode(&pool, "ActivationAuthorization", &wrong, 65536)
            .is_err()
    );

    let owner = seed("topup_owner_proof_fields");
    let owner_bytes = bytes(owner);
    let original = r
        .decode(&owner_bytes, "OwnerFenceProof", &Context::default(), 65536)
        .unwrap();
    let tenant_id = field_id("OwnerFenceProof", "tenant_id");
    for text in ["Tenant", "tenant\n", "tenant\0", "ténant"] {
        let mut changed = original.clone();
        let Value::Map(pairs) = &mut changed else {
            unreachable!()
        };
        pairs
            .iter_mut()
            .find(|(k, _)| k == &Value::Unsigned(tenant_id))
            .unwrap()
            .1 = Value::Text(text);
        assert_eq!(
            r.check_map("OwnerFenceProof", &changed, &Context::default()),
            Err("text_pattern")
        );
    }
    let expiry_id = field_id("OwnerFenceProof", "expires_at_ms");
    let mut changed = original;
    let Value::Map(pairs) = &mut changed else {
        unreachable!()
    };
    pairs
        .iter_mut()
        .find(|(k, _)| k == &Value::Unsigned(expiry_id))
        .unwrap()
        .1 = Value::Unsigned(u64::MAX);
    let wire = encode(&changed);
    assert_eq!(
        r.decode(&wire, "OwnerFenceProof", &Context::default(), 65536)
            .unwrap(),
        changed
    );
}

// v4.rust_shape.properties
proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn mutated_shapes_reject_or_preserve_exact_bytes(index in any::<usize>(), at in any::<usize>(), byte in any::<u8>()) {
        let vector = &corpus()[index % corpus().len()];
        let mut input = bytes(vector);
        if !input.is_empty() { let at = at % input.len(); input[at] ^= byte; }
        let ctx = context(vector);
        let before = ctx.selectors.clone();
        let result = reference().decode(&input, vector["schema"].as_str().unwrap_or(""), &ctx, input.len() as u64 + 1);
        prop_assert_eq!(ctx.selectors, before);
        if let Ok(value) = result { prop_assert_eq!(encode(&value), input); }
    }
}
