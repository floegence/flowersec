//! Independent domain input construction using shared public fixtures only.
#[allow(dead_code)]
#[path = "support/v4_cbor.rs"]
mod cbor;
#[path = "support/v4_domains.rs"]
mod domains;
#[allow(dead_code)]
#[path = "support/v4_idna.rs"]
mod idna;
#[allow(dead_code)]
#[path = "support/v4_oracles.rs"]
mod oracles;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[allow(dead_code)]
#[path = "support/v4_relations.rs"]
mod relations;
#[allow(dead_code)]
#[path = "support/v4_rules.rs"]
mod rules;
#[allow(dead_code)]
#[path = "support/v4_shape.rs"]
mod shape;
#[allow(dead_code)]
#[path = "support/v4_text.rs"]
mod text;
#[allow(dead_code)]
#[path = "support/v4_unicode.rs"]
mod unicode;
#[allow(dead_code)]
#[path = "support/v4_variants.rs"]
mod variants;

use cbor::Value;
use domains::{Argument, Arguments, Output, descriptors, fixed_unsigned};
use oracles::encoded;
use proptest::prelude::*;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde_json::Value as Json;
use shape::Context;
use std::{collections::BTreeSet, sync::OnceLock};
use text::Text;

const CAP: u64 = 1 << 20;
fn reference() -> &'static Text {
    static REFERENCE: OnceLock<Text> = OnceLock::new();
    REFERENCE.get_or_init(|| Text::new(registry::CBOR_REGISTRY_JSON))
}
fn corpus() -> &'static Vec<Json> {
    static CORPUS: OnceLock<Vec<Json>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let corpus: Json =
            serde_json::from_str(include_str!("../../testdata/transport_v4/domains.json")).unwrap();
        assert_eq!(corpus["schema_sha256"], registry::SCHEMA_SHA256);
        corpus["vectors"].as_array().unwrap().clone()
    })
}
fn hex(value: &Json) -> Vec<u8> {
    domains::hex(value.as_str().unwrap()).unwrap()
}
fn args(vector: &Json) -> Arguments {
    vector["inputs"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| {
            let argument = if value.get("$bytes").is_some() {
                Argument::Bytes(hex(&value["$bytes"]))
            } else if let Some(integer) = value["$uint"].as_str() {
                Argument::UInt(integer.parse().unwrap())
            } else if let Some(text) = value.as_str() {
                Argument::Text(text.into())
            } else if let Some(n) = value.as_u64().filter(|n| *n <= 9_007_199_254_740_991) {
                Argument::UInt(u128::from(n))
            } else {
                Argument::Invalid
            };
            (name.clone(), argument)
        })
        .collect()
}
fn context(vector: &Json) -> Context {
    let mut context = Context::default();
    if let Some(fields) = vector["context"].as_object() {
        for (name, value) in fields {
            if let Some(n) = value.as_u64() {
                context.limits.insert(name.clone(), n);
            }
            if let Some(text) = value.as_str() {
                context.selectors.insert(name.clone(), text.into());
            }
        }
    }
    context
}
fn seed(name: &str) -> &'static Json {
    corpus()
        .iter()
        .find(|v| v["domain"] == name && v.get("expected_error").is_none())
        .unwrap()
}
fn expected(vector: &Json) -> Output {
    let value = &vector["result"];
    Output {
        label: hex(&value["label_hex"]),
        input: hex(&value["input_hex"]),
        output: value.get("output_hex").map(hex),
        salt: value.get("salt_hex").map(hex),
        ikm: value.get("ikm_hex").map(hex),
        output_length: value["output_length"].as_u64(),
    }
}

// v4.rust_domains.corpus
#[test]
fn complete_domain_corpus() {
    let r = reference();
    let (mut positive, mut negative) = (0, 0);
    let mut covered = BTreeSet::new();
    for vector in corpus() {
        let input = args(vector);
        let context = context(vector);
        let before = input.clone();
        let original_context = context.clone();
        let name = vector["domain"].as_str().unwrap();
        let result = r.evaluate_domain(name, &input, &context, CAP);
        if let Some(error) = vector["expected_error"].as_str() {
            negative += 1;
            let actual = result.unwrap_err();
            if error.starts_with("domain_") {
                assert_eq!(actual, error, "{}", vector["id"]);
            }
        } else {
            positive += 1;
            covered.insert(name);
            assert_eq!(
                result.unwrap_or_else(|e| panic!("{}: {e}", vector["id"])),
                expected(vector),
                "{}",
                vector["id"]
            );
        }
        assert_eq!(input, before);
        assert_eq!(context.selectors, original_context.selectors);
        assert_eq!(context.limits, original_context.limits);
    }
    assert_eq!((positive, negative, covered.len()), (107, 52, 58));
    for descriptor in descriptors() {
        assert!(covered.contains(descriptor["name"].as_str().unwrap()));
    }
}

// v4.rust_domains.signing_inputs
#[test]
fn rebuilt_inputs_consume_real_signatures() {
    let r = reference();
    let signatures: Json =
        serde_json::from_str(include_str!("../../testdata/transport_v4/signatures.json")).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&hex(&signatures["signing_seed_hex"])).unwrap();
    let mut covered = BTreeSet::new();
    for vector in signatures["vectors"].as_array().unwrap() {
        if vector["accept"] != true || !vector["domain_vector"].is_string() {
            continue;
        }
        let fixture = corpus()
            .iter()
            .find(|v| v["id"] == vector["domain_vector"])
            .unwrap();
        let name = vector["domain"].as_str().unwrap();
        let result = r
            .evaluate_domain(name, &args(fixture), &context(fixture), CAP)
            .unwrap();
        assert_eq!(result.input, hex(&vector["message_hex"]));
        assert!(result.output.is_none());
        let signature = key.sign(&result.input);
        assert_eq!(signature.as_ref(), hex(&vector["signature_hex"]));
        UnparsedPublicKey::new(&ED25519, hex(&vector["public_key_hex"]))
            .verify(&result.input, signature.as_ref())
            .unwrap();
        covered.insert(name);
    }
    for domain in descriptors().iter().filter(|d| d["operation"] == "ed25519") {
        assert!(covered.contains(domain["name"].as_str().unwrap()));
    }
}

// v4.rust_domains.arguments
#[test]
fn closed_arguments_and_context() {
    let r = reference();
    assert_eq!(
        r.evaluate_domain("missing", &Arguments::new(), &Context::default(), CAP)
            .unwrap_err(),
        "domain_unknown"
    );
    for domain in descriptors() {
        let name = domain["name"].as_str().unwrap();
        let vector = seed(name);
        let input = args(vector);
        let context = context(vector);
        let original_context = context.clone();
        let mut extra = input.clone();
        extra.insert("extra".into(), Argument::Invalid);
        for invalid in [&Arguments::new(), &extra] {
            assert_eq!(
                r.evaluate_domain(name, invalid, &context, CAP).unwrap_err(),
                "domain_arguments"
            );
        }
        for field in input.keys() {
            let mut invalid = input.clone();
            invalid.remove(field);
            assert_eq!(
                r.evaluate_domain(name, &invalid, &context, CAP)
                    .unwrap_err(),
                "domain_arguments"
            );
            invalid.insert(field.clone(), Argument::Invalid);
            assert!(r.evaluate_domain(name, &invalid, &context, CAP).is_err());
        }
        assert_eq!(context.selectors, original_context.selectors);
        assert_eq!(context.limits, original_context.limits);
    }
}

// v4.rust_domains.projections
#[test]
fn exact_projections_and_owned_outputs() {
    let r = reference();
    let (mut full, mut excluded, mut raw) = (0, 0, 0);
    for vector in corpus()
        .iter()
        .filter(|v| v.get("expected_error").is_none())
    {
        let name = vector["domain"].as_str().unwrap();
        let input = args(vector);
        let context = context(vector);
        let original = r.evaluate_domain(name, &input, &context, CAP).unwrap();
        let domain = descriptors().iter().find(|d| d["name"] == name).unwrap();
        for part in domain["input_schema"]["parts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["encoding"] == "lp-map")
        {
            let argument = part["name"].as_str().unwrap();
            let selector;
            let schema = if let Some(name) = part["schema_ref"].as_str() {
                name
            } else {
                let Argument::UInt(n) = input[part["selector"].as_str().unwrap()] else {
                    panic!("selector")
                };
                selector = n.to_string();
                part["schema_cases"][&selector].as_str().unwrap()
            };
            let descriptor = r.shape.descriptor(schema).unwrap();
            let field = if part["projection"] == "without_mac" {
                descriptor["mac_field"].as_u64()
            } else {
                descriptor["signature_field"].as_u64()
            };
            let Some(field) = field else {
                continue;
            };
            let Argument::Bytes(bytes) = &input[argument] else {
                panic!("map bytes")
            };
            let mut value = r.wire_map(bytes, schema, &context, CAP).unwrap();
            let Value::Map(pairs) = &mut value else {
                panic!("map")
            };
            let slot = &mut pairs
                .iter_mut()
                .find(|(key, _)| key == &Value::Unsigned(field))
                .unwrap()
                .1;
            let Value::Bytes(original_bytes) = slot else {
                panic!("signature bytes")
            };
            let mut mutation = original_bytes.to_vec();
            mutation[0] ^= 1;
            *slot = Value::Bytes(&mutation);
            let mut changed = input.clone();
            changed.insert(argument.into(), Argument::Bytes(encoded(&value)));
            let actual = r.evaluate_domain(name, &changed, &context, CAP).unwrap();
            if part["projection"] == "full" {
                full += 1;
                assert_ne!(actual.input, original.input);
            } else {
                excluded += 1;
                assert_eq!(actual, original);
            }
        }
        if ["topup_request_digest", "topup_response_digest"].contains(&name) {
            raw += 1;
            assert!(original.label.is_empty());
            assert!(
                r.shape
                    .syntax
                    .decode(&original.input, "", &Default::default(), CAP)
                    .0
                    .is_ok()
            );
        }
        let mut source = input.clone();
        let owned = r.evaluate_domain(name, &source, &context, CAP).unwrap();
        for arg in source.values_mut() {
            if let Argument::Bytes(bytes) = arg {
                bytes.fill(0);
            }
        }
        assert_eq!(owned, original);
    }
    assert!(full > 0 && excluded > 0);
    assert_eq!(raw, 2);
}

// v4.rust_domains.widths_and_exporters
#[test]
fn exact_integer_and_exporter_boundaries() {
    assert_eq!(
        fixed_unsigned(&Argument::UInt(u128::from(u64::MAX)), 8).unwrap(),
        vec![255; 8]
    );
    for width in [1, 4, 8] {
        assert_eq!(
            fixed_unsigned(&Argument::UInt(1u128 << (8 * width)), width).unwrap_err(),
            "domain_integer_range"
        );
        assert_eq!(
            fixed_unsigned(&Argument::Invalid, width).unwrap_err(),
            "domain_integer_type"
        );
    }
    let r = reference();
    for name in ["tls_exporter_raw", "tls_exporter_wt"] {
        let vector = seed(name);
        let mut input = args(vector);
        let context = context(vector);
        let result = r.evaluate_domain(name, &input, &context, CAP).unwrap();
        assert!(result.output.is_none());
        assert_eq!(result.output_length, Some(32));
        if name == "tls_exporter_raw" {
            assert_eq!(result.label, b"EXPORTER-flowersec-v4");
            assert_eq!(result.input.len(), 32);
        } else {
            assert_eq!(result.label, b"EXPORTER-WebTransport");
            assert_eq!(result.input.len(), 63);
            assert_eq!(&result.input[8..31], b"\x15EXPORTER-flowersec-v4\x20");
            input.insert(
                "connect_stream_id".into(),
                Argument::UInt((1u128 << 62) - 4),
            );
            assert_eq!(
                &r.evaluate_domain(name, &input, &context, CAP)
                    .unwrap()
                    .input[..8],
                &((1u64 << 62) - 4).to_be_bytes()
            );
            for id in [1, (1u128 << 62) - 1, 1u128 << 62, 1u128 << 64] {
                input.insert("connect_stream_id".into(), Argument::UInt(id));
                assert!(r.evaluate_domain(name, &input, &context, CAP).is_err());
            }
        }
    }
}

// v4.rust_domains.properties
proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]
    #[test]
    fn arbitrary_input_mutations(index in any::<usize>(), field_index in any::<usize>(), offset in any::<usize>(), mask in any::<u64>()) {
        let positives = corpus().iter().filter(|v| v.get("expected_error").is_none()).collect::<Vec<_>>();
        let vector = positives[index % positives.len()]; let mut input = args(vector); let context = context(vector); let before_context = context.clone(); let name = vector["domain"].as_str().unwrap();
        let keys = input.keys().cloned().collect::<Vec<_>>(); let key = &keys[field_index % keys.len()];
        match input.get_mut(key).unwrap() {
            Argument::Bytes(raw) if !raw.is_empty() => { let index = offset % raw.len(); raw[index] ^= mask as u8; },
            Argument::UInt(n) => *n ^= u128::from(mask),
            Argument::Text(text) => text.push('x'),
            _ => {},
        }
        let original = input.clone(); let r = reference(); let result = r.evaluate_domain(name,&input,&context,CAP);
        prop_assert_eq!(&input,&original); prop_assert_eq!(&context.selectors,&before_context.selectors); prop_assert_eq!(&context.limits,&before_context.limits);
        if let Ok(result) = result {
            prop_assert_eq!(r.evaluate_domain(name,&input,&context,CAP).unwrap(),result.clone());
            let snapshot = result.clone(); for arg in input.values_mut() { if let Argument::Bytes(raw) = arg { raw.fill(0); } }
            prop_assert_eq!(result,snapshot);
        }
    }
}
