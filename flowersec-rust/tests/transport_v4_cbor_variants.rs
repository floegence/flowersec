//! Independent closed-variant reference consuming generated definitions.
#[path = "support/v4_cbor.rs"]
mod cbor;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
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
use shape::{Context, Shape};
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

// v4.rust_variants.corpus
#[test]
fn shared_closed_variant_corpus() {
    let mut counts = [0, 0];
    for vector in corpus() {
        let error = vector["expected_error"].as_str().unwrap_or("");
        let variant_error = error.starts_with("variant_")
            || matches!(error, "field_range" | "field_prefix")
            || matches!(
                vector["id"].as_str().unwrap(),
                "admission_rejected_unknown_code" | "context_auth_exporter_bytes"
            );
        if !error.is_empty() && !variant_error {
            continue;
        }
        let input = bytes(vector);
        let ctx = context(vector);
        let original_context = ctx.selectors.clone();
        let result = reference().variants(
            &input,
            vector["schema"].as_str().unwrap_or(""),
            &ctx,
            input.len() as u64 + 1,
        );
        assert_eq!(ctx.selectors, original_context);
        if error.is_empty() {
            counts[0] += 1;
            assert_eq!(
                encode(&result.unwrap_or_else(|e| panic!("{}: {e}", vector["id"]))),
                input
            );
        } else {
            counts[1] += 1;
            assert!(result.is_err(), "{} accepted", vector["id"]);
        }
        assert_eq!(input, bytes(vector));
    }
    assert_eq!(counts, [337, 133]);
    println!(
        "{} positive and {} variant-negative cases",
        counts[0], counts[1]
    );
}

// v4.rust_variants.scoped_paths
#[test]
fn containing_and_external_contexts_preserve_scope() {
    let r = reference();
    for id in [
        "route_direct_fields",
        "route_tunnel_mixed_fields",
        "activation_live_fields",
        "activation_pool_fields",
    ] {
        let vector = seed(id);
        let input = bytes(vector);
        let name = vector["schema"].as_str().unwrap();
        let mut ctx = context(vector);
        if name == "Route" {
            ctx.selectors
                .insert("path_kind".into(), "invalid-caller-selector".into());
        }
        let original = ctx.selectors.clone();
        r.variants(&input, name, &ctx, input.len() as u64 + 1)
            .unwrap();
        assert_eq!(ctx.selectors, original);
        if name == "ActivationAuthorization" {
            assert_eq!(
                r.variants(&input, name, &Context::default(), 65536),
                Err("context_unresolved")
            );
            ctx.selectors
                .insert("activation_source_profile".into(), "unknown".into());
            assert_eq!(
                r.variants(&input, name, &ctx, 65536),
                Err("context_unresolved")
            );
        }
    }
    let fsb = seed("fsb_fields");
    let input = bytes(fsb);
    let ctx = context(fsb);
    let value = r.variants(&input, "FSB4", &ctx, 65536).unwrap();
    assert_eq!(
        r.rule_path("FSB4", &value, "client_certificate.role", &ctx),
        Ok(Some(Value::Unsigned(0)))
    );
    assert_eq!(
        r.rule_path("FSB4", &value, "not_registered", &ctx),
        Err("unknown_rule_field")
    );
    let grant = seed("grant_fields");
    let input = bytes(grant);
    let ctx = context(grant);
    let value = r.variants(&input, "Grant", &ctx, 65536).unwrap();
    assert_eq!(
        r.rule_path("Grant", &value, "legs.1.logical_role", &ctx),
        Ok(Some(Value::Unsigned(1)))
    );
    assert_eq!(
        r.rule_path(
            "Grant",
            &value,
            "legs.18446744073709551615.logical_role",
            &ctx
        ),
        Ok(None)
    );
    assert_eq!(
        r.rule_path("Grant", &value, "legs.invalid.logical_role", &ctx),
        Err("unknown_rule_field")
    );
}

// v4.rust_variants.shape_preserving_mutations
#[test]
fn field_valid_inputs_still_require_branch_and_range_checks() {
    let r = reference();
    let vector = seed("grant_certificate_maximum_fields");
    let input = bytes(vector);
    let ctx = context(vector);
    let mut value = r
        .variants(&input, "IdentityCertificate", &ctx, 65536)
        .unwrap();
    let mut key = r
        .rule_path(
            "IdentityCertificate",
            &value,
            "noise_static_public_key",
            &ctx,
        )
        .unwrap()
        .unwrap();
    let Some(Value::Bytes(public)) = r
        .rule_path(
            "IdentityCertificate",
            &value,
            "noise_static_public_key.public_key_bytes",
            &ctx,
        )
        .unwrap()
    else {
        panic!("missing public key")
    };
    let mut changed = public.to_vec();
    changed[0] ^= 1;
    set_field(
        "NoiseStaticPublicKey",
        &mut key,
        "public_key_bytes",
        Value::Bytes(&changed),
    );
    set_field(
        "IdentityCertificate",
        &mut value,
        "noise_static_public_key",
        key,
    );
    let wire = encode(&value);
    r.decode(&wire, "IdentityCertificate", &ctx, 65536).unwrap();
    assert_eq!(
        r.variants(&wire, "IdentityCertificate", &ctx, 65536),
        Err("field_prefix")
    );

    let vector = corpus()
        .iter()
        .find(|v| v["schema"] == "OPEN_STREAM" && v.get("expected_error").is_none())
        .unwrap();
    let input = bytes(vector);
    let ctx = context(vector);
    let original = r.variants(&input, "OPEN_STREAM", &ctx, 65536).unwrap();
    for scope in [0, 1 << 63, u64::MAX] {
        let mut value = original.clone();
        set_field("OPEN_STREAM", &mut value, "scope", Value::Unsigned(scope));
        let wire = encode(&value);
        r.decode(&wire, "OPEN_STREAM", &ctx, 65536).unwrap();
        assert_eq!(
            r.variants(&wire, "OPEN_STREAM", &ctx, 65536),
            Err("field_range")
        );
    }
    let mut value = original;
    set_field(
        "OPEN_STREAM",
        &mut value,
        "scope",
        Value::Unsigned((1 << 63) - 1),
    );
    let wire = encode(&value);
    r.variants(&wire, "OPEN_STREAM", &ctx, 65536).unwrap();
    // stream_id equality/open digest belong to the subsequent relation layer.

    let vector = seed("fsb_fields");
    let input = bytes(vector);
    let ctx = context(vector);
    let mut value = r.variants(&input, "FSB4", &ctx, 65536).unwrap();
    let Some(Value::Bytes(certificate)) = r
        .rule_path("FSB4", &value, "client_certificate", &ctx)
        .unwrap()
    else {
        panic!("missing embedded certificate")
    };
    let mut certificate = r
        .decode(certificate, "IdentityCertificate", &ctx, 65536)
        .unwrap();
    set_field(
        "IdentityCertificate",
        &mut certificate,
        "role",
        Value::Unsigned(1),
    );
    let certificate = encode(&certificate);
    set_field(
        "FSB4",
        &mut value,
        "client_certificate",
        Value::Bytes(&certificate),
    );
    let wire = encode(&value);
    r.decode(&wire, "FSB4", &ctx, 65536).unwrap();
    assert_eq!(r.variants(&wire, "FSB4", &ctx, 65536), Err("field_range"));

    let vector = seed("grant_fields");
    let input = bytes(vector);
    let ctx = context(vector);
    let mut value = r.variants(&input, "Grant", &ctx, 65536).unwrap();
    let Some(Value::Array(mut legs)) = r.rule_path("Grant", &value, "legs", &ctx).unwrap() else {
        panic!("missing grant legs")
    };
    set_field(
        "GrantLegRef",
        &mut legs[1],
        "logical_role",
        Value::Unsigned(0),
    );
    set_field("Grant", &mut value, "legs", Value::Array(legs));
    let wire = encode(&value);
    r.decode(&wire, "Grant", &ctx, 65536).unwrap();
    assert_eq!(r.variants(&wire, "Grant", &ctx, 65536), Err("field_range"));

    let vector = corpus()
        .iter()
        .find(|v| v["schema"] == "STREAM_ACK_DRAINED" && v.get("expected_error").is_none())
        .unwrap();
    let input = bytes(vector);
    let ctx = context(vector);
    let mut value = r
        .variants(&input, "STREAM_ACK_DRAINED", &ctx, 65536)
        .unwrap();
    let mut terminal = r
        .rule_path("STREAM_ACK_DRAINED", &value, "terminal_tuple", &ctx)
        .unwrap()
        .unwrap();
    let mut observed = terminal.clone();
    set_field(
        "terminal_tuple",
        &mut terminal,
        "next_sequence",
        Value::Unsigned(u64::MAX - 1),
    );
    set_field(
        "terminal_tuple",
        &mut observed,
        "next_sequence",
        Value::Unsigned(u64::MAX),
    );
    set_field("STREAM_ACK_DRAINED", &mut value, "terminal_tuple", terminal);
    set_field("STREAM_ACK_DRAINED", &mut value, "observed_tuple", observed);
    set_field(
        "STREAM_ACK_DRAINED",
        &mut value,
        "outcome",
        Value::Unsigned(1),
    );
    let wire = encode(&value);
    r.decode(&wire, "STREAM_ACK_DRAINED", &ctx, 65536).unwrap();
    assert_eq!(
        r.variants(&wire, "STREAM_ACK_DRAINED", &ctx, 65536),
        Err("field_order")
    );
    set_field(
        "STREAM_ACK_DRAINED",
        &mut value,
        "outcome",
        Value::Unsigned(0),
    );
    let wire = encode(&value);
    assert_eq!(
        r.variants(&wire, "STREAM_ACK_DRAINED", &ctx, 65536),
        Err("field_equality")
    );
}

// v4.rust_variants.properties
proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn mutated_variants_reject_or_preserve_bytes(index in any::<usize>(), at in any::<usize>(), byte in any::<u8>()) {
        let vector = &corpus()[index % corpus().len()];
        let mut input = bytes(vector);
        if !input.is_empty() { let at = at % input.len(); input[at] ^= byte; }
        let ctx = context(vector);
        let before = ctx.selectors.clone();
        let result = reference().variants(&input, vector["schema"].as_str().unwrap_or(""), &ctx, input.len() as u64 + 1);
        prop_assert_eq!(ctx.selectors, before);
        if let Ok(value) = result { prop_assert_eq!(encode(&value), input); }
    }
}
