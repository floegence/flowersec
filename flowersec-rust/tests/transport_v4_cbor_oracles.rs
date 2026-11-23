//! Independent external OPEN and pool composition over canonical received maps.
#[path = "support/v4_cbor.rs"]
mod cbor;
#[path = "support/v4_composition.rs"]
mod composition;
#[path = "support/v4_composition_tests.rs"]
mod composition_tests;
#[allow(dead_code)]
#[path = "support/v4_idna.rs"]
mod idna;
#[path = "support/v4_oracles.rs"]
mod oracles;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "support/v4_relations.rs"]
mod relations;
#[path = "support/v4_rules.rs"]
mod rules;
#[path = "support/v4_shape.rs"]
mod shape;
#[path = "support/v4_text.rs"]
mod text;
#[allow(dead_code)]
#[path = "support/v4_unicode.rs"]
mod unicode;
#[allow(dead_code)]
#[path = "support/v4_variants.rs"]
mod variants;

use cbor::{Error, Value};
use oracles::{encoded, single_map_hash};
use proptest::prelude::*;
use serde_json::Value as Json;
use shape::Context;
use std::sync::OnceLock;
use text::Text;

fn reference() -> &'static Text {
    static REFERENCE: OnceLock<Text> = OnceLock::new();
    REFERENCE.get_or_init(|| Text::new(registry::CBOR_REGISTRY_JSON))
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

fn bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
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

fn pool_seed(id: &str) -> (Vec<u8>, Vec<u64>) {
    let derivation = &seed(id)["pool_derivation"];
    (
        bytes(derivation["artifact_hex"].as_str().unwrap()),
        derivation["indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap())
            .collect(),
    )
}

fn field_mut<'v, 'a>(name: &str, value: &'v mut Value<'a>, field: &str) -> &'v mut Value<'a> {
    let id = reference().shape.named_field(name, field).unwrap().0;
    let Value::Map(pairs) = value else {
        panic!("not a map")
    };
    &mut pairs
        .iter_mut()
        .find(|(key, _)| key == &Value::Unsigned(id))
        .unwrap()
        .1
}

fn first_candidate<'v, 'a>(value: &'v mut Value<'a>) -> &'v mut Value<'a> {
    let Value::Array(candidates) = field_mut("Artifact", value, "candidates") else {
        panic!("not candidates")
    };
    &mut candidates[0]
}

fn receive<'a>(input: &'a [u8], vector: &Json) -> Result<Value<'a>, Error> {
    let r = reference();
    let name = vector["schema"].as_str().unwrap_or("");
    let value = r.wire_map(input, name, &context(vector), input.len() as u64 + 1)?;
    if let Some(pool) = vector.get("pool_derivation") {
        assert_eq!(name, "PoolSelectionSet");
        let artifact = bytes(pool["artifact_hex"].as_str().unwrap());
        let indices: Vec<u64> = pool["indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap())
            .collect();
        r.verify_pool_set(
            &artifact,
            &indices,
            input,
            artifact.len().max(input.len()) as u64 + 1,
        )?;
    }
    if name == "OPEN_STREAM" {
        let digest = r.shape.open_digest(&value)?;
        if r.shape.named_value(name, &value, "open_digest")? != Some(&Value::Bytes(&digest)) {
            return Err("open_digest_mismatch");
        }
    }
    Ok(value)
}

// v4.rust_oracles.corpus
#[test]
fn complete_corpus_with_external_composition() {
    let (mut positive, mut negative, mut pools, mut opens) = (0, 0, 0, 0);
    for vector in corpus() {
        let input = bytes(vector["hex"].as_str().unwrap());
        let result = receive(&input, vector);
        if let Some(error) = vector["expected_error"].as_str() {
            negative += 1;
            assert!(result.is_err(), "{} accepted: {error}", vector["id"]);
            if matches!(error, "pool_set_membership" | "open_digest_mismatch") {
                assert_eq!(result.unwrap_err(), error, "{}", vector["id"]);
            }
        } else {
            positive += 1;
            assert_eq!(
                encoded(&result.unwrap_or_else(|e| panic!("{}: {e}", vector["id"]))),
                input
            );
        }
        pools += usize::from(vector.get("pool_derivation").is_some());
        opens += usize::from(vector["schema"] == "OPEN_STREAM");
    }
    assert_eq!((positive, negative), (337, 828));
    assert!(pools > 0 && opens > 0);
}

// v4.rust_oracles.open_digest
#[test]
fn open_digest_covers_exact_generated_projection() {
    let r = reference();
    let vector = seed("open_fields");
    let input = bytes(vector["hex"].as_str().unwrap());
    let value = receive(&input, vector).unwrap();
    let digest = r.shape.open_digest(&value).unwrap();
    for descriptor in r.shape.registry["frame_maps"]["OPEN_STREAM"]["fields"]
        .as_object()
        .unwrap()
        .values()
    {
        let name = descriptor["name"].as_str().unwrap();
        let mut changed = value.clone();
        let slot = field_mut("OPEN_STREAM", &mut changed, name);
        let mut data = Vec::new();
        match slot {
            Value::Unsigned(n) => *n ^= 1,
            Value::Bytes(raw) => {
                data.extend_from_slice(raw);
                data.push(b'x');
                *slot = Value::Bytes(&data);
            }
            Value::Text(_) => *slot = Value::Text("changed"),
            _ => panic!("uncovered OPEN field"),
        }
        // Deliberately isolate hashing; mutated values may fail earlier gates.
        assert_eq!(
            r.shape.open_digest(&changed).unwrap() == digest,
            name == "open_digest",
            "{name}"
        );
    }
    for (domain, schema, projection) in [
        ("open_digest", "OPEN_STREAM", "full"),
        ("route_digest", "Artifact", "full"),
        ("artifact_signature", "Artifact", "full"),
    ] {
        assert_eq!(
            single_map_hash(domain, schema, projection, &input),
            Err("domain_projection")
        );
    }
}

// v4.rust_oracles.pool_domains
#[test]
fn independent_pool_domains_match_six_shared_outputs() {
    let domains: Json =
        serde_json::from_str(include_str!("../../testdata/transport_v4/domains.json")).unwrap();
    assert_eq!(domains["schema_sha256"], registry::SCHEMA_SHA256);
    let mut comparisons = 0;
    for id in ["pool_set_one", "pool_set_two", "pool_set_sixteen"] {
        let (artifact, indices) = pool_seed(id);
        let result = reference()
            .derive_pool(&artifact, &indices, artifact.len() as u64)
            .unwrap();
        assert_ne!(result.candidate_set_digest, result.route_set_digest);
        assert_eq!(result.encoded, bytes(seed(id)["hex"].as_str().unwrap()));
        for (name, digest) in [
            ("candidate_set_digest", &result.candidate_set_digest),
            ("route_set_digest", &result.route_set_digest),
        ] {
            let matching: Vec<_> = domains["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| {
                    v["domain"] == name
                        && bytes(v["inputs"]["selection"]["$bytes"].as_str().unwrap())
                            == result.encoded
                })
                .collect();
            assert_eq!(matching.len(), 1);
            assert_eq!(
                *digest,
                bytes(matching[0]["result"]["output_hex"].as_str().unwrap())
            );
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 6);
}

// v4.rust_oracles.pool_boundaries
#[test]
fn pool_indices_membership_and_owned_public_results() {
    let r = reference();
    let (mut artifact, indices) = pool_seed("pool_set_two");
    let cap = artifact.len() as u64;
    let result = r.derive_pool(&artifact, &indices, cap).unwrap();
    for invalid in [
        vec![],
        vec![0, 0],
        vec![1, 0],
        vec![2],
        vec![16],
        vec![u64::MAX],
        vec![0; 17],
    ] {
        let original = invalid.clone();
        assert!(r.derive_pool(&artifact, &invalid, cap).is_err());
        assert_eq!(invalid, original);
    }
    assert_eq!(r.derive_pool(&artifact, &indices, cap - 1), Err("map_size"));
    assert_eq!(
        r.verify_pool_set(
            &artifact,
            &indices,
            &result.encoded,
            result.encoded.len() as u64 - 1
        ),
        Err("map_size")
    );
    for &index in &indices {
        assert!(r.derive_pool(&artifact, &[index], cap).is_ok());
        assert_eq!(
            r.verify_pool_set(&artifact, &[index], &result.encoded, cap),
            Err("pool_set_membership")
        );
    }
    for field in ["artifact_digest", "candidate_id", "route_digest"] {
        let mut selection = r
            .wire_map(
                &result.encoded,
                "PoolSelectionSet",
                &Context::default(),
                cap,
            )
            .unwrap();
        let (name, root) = if field == "artifact_digest" {
            ("PoolSelectionSet", &mut selection)
        } else {
            let Value::Array(entries) = field_mut("PoolSelectionSet", &mut selection, "entries")
            else {
                panic!()
            };
            ("PoolRouteRef", &mut entries[0])
        };
        let slot = field_mut(name, root, field);
        let Value::Bytes(raw) = slot else { panic!() };
        let mut data = raw.to_vec();
        data[0] ^= 0x80;
        *slot = Value::Bytes(&data);
        let changed = encoded(&selection);
        assert!(
            r.wire_map(&changed, "PoolSelectionSet", &Context::default(), cap)
                .is_ok()
        );
        assert_eq!(
            r.verify_pool_set(&artifact, &indices, &changed, cap),
            Err("pool_set_membership")
        );
    }
    for field in ["signature", "priority", "port"] {
        let mut value = r
            .wire_map(&artifact, "Artifact", &Context::default(), cap)
            .unwrap();
        let slot = match field {
            "signature" => field_mut("Artifact", &mut value, field),
            "priority" => {
                let Value::Array(candidates) = field_mut("Artifact", &mut value, "candidates")
                else {
                    panic!()
                };
                field_mut("Candidate", candidates.last_mut().unwrap(), field)
            }
            _ => field_mut(
                "Leg",
                field_mut("Candidate", first_candidate(&mut value), "direct_leg"),
                field,
            ),
        };
        let mut data = Vec::new();
        match slot {
            Value::Bytes(raw) => {
                data.extend_from_slice(raw);
                data[0] ^= 1;
                *slot = Value::Bytes(&data);
            }
            Value::Unsigned(n) => *n += 1,
            _ => panic!(),
        }
        let changed = encoded(&value);
        let derived = r
            .derive_pool(&changed, &indices, changed.len() as u64)
            .unwrap();
        assert_ne!(derived.artifact_digest, result.artifact_digest);
        assert_eq!(
            derived.members[0].route_digest != result.members[0].route_digest,
            field == "port"
        );
        assert_eq!(
            r.verify_pool_set(&changed, &indices, &result.encoded, changed.len() as u64),
            Err("pool_set_membership")
        );
    }
    let snapshot = result.clone();
    artifact.fill(0);
    assert_eq!(result, snapshot);
}

// v4.rust_oracles.properties
proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]
    #[test]
    fn mutated_artifacts_and_indices_preserve_or_reject(
        seed_index in 0usize..3, at in any::<usize>(), byte in any::<u8>(),
        index_bytes in prop::collection::vec(any::<u8>(), 0..18),
        mutate in any::<bool>(), replace_indices in any::<bool>(),
    ) {
        let (mut artifact, original_indices) = pool_seed(["pool_set_one", "pool_set_two", "pool_set_sixteen"][seed_index]);
        if mutate { let at = at % artifact.len(); artifact[at] ^= byte; }
        let indices: Vec<u64> = if replace_indices { index_bytes.iter().map(|&n| n as u64).collect() } else { original_indices };
        let result = reference().derive_pool(&artifact, &indices, 1 << 16);
        if let Ok(result) = result {
            let verified = reference().verify_pool_set(&artifact, &indices, &result.encoded, 1 << 16).map_err(TestCaseError::fail)?;
            prop_assert_eq!(&result, &verified);
            prop_assert_eq!(result.members.iter().map(|m| m.index).collect::<Vec<_>>(), indices);
            let snapshot = result.clone();
            artifact.fill(0);
            prop_assert_eq!(result, snapshot);
        }
    }
    #[test]
    fn mutated_corpus_rejects_or_preserves_bytes(index in any::<usize>(), at in any::<usize>(), byte in any::<u8>()) {
        let vector = &corpus()[index % corpus().len()];
        let mut input = bytes(vector["hex"].as_str().unwrap());
        if !input.is_empty() { let at = at % input.len(); input[at] ^= byte; }
        if let Ok(value) = receive(&input, vector) { prop_assert_eq!(encoded(&value), input); }
    }
}
