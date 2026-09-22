//! Independent test-only composition over the shared synthetic resource corpus.
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "support/v4_resource_costs.rs"]
mod resource_costs;
#[path = "support/v4_resources.rs"]
mod resources;
use serde_json::{Value, json};

#[test]
fn resource_partial_cost_corpus() {
    let spec: Value = serde_json::from_str(registry::RESOURCE_FORMULA_REGISTRY_JSON).unwrap();
    let corpus: Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v4/resource_costs.json"
    ))
    .unwrap();
    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 18);
    for vector in vectors {
        let before = vector["input"].clone();
        let actual = resource_costs::costs(&spec, &vector["input"]);
        if let Some(error) = vector["expected_error"].as_str() {
            assert_eq!(actual, Err(error), "{}", vector["id"]);
        } else {
            assert_eq!(actual, Ok(vector["expected"].clone()), "{}", vector["id"]);
        }
        assert_eq!(vector["input"], before);
    }
    for bad in [
        json!(true),
        json!("1"),
        json!(0.5),
        json!(-1),
        json!(4294967296u64),
        json!(null),
    ] {
        let input = json!({"max_frame_bytes":131072,"small_auth_slots":bad,"application_profile":"transport"});
        assert_eq!(
            resource_costs::costs(&spec, &input),
            Err("resource_auth_slots")
        );
    }
}

fn reference() -> resources::Resources {
    resources::Resources::new(
        registry::RESOURCE_COMPOSITION_REGISTRY_JSON,
        registry::CBOR_REGISTRY_JSON,
    )
}
fn vectors() -> Vec<Value> {
    let corpus: Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/resources.json")).unwrap();
    corpus["vectors"].as_array().unwrap().clone()
}
fn basic() -> Value {
    vectors()
        .into_iter()
        .find(|v| v["id"] == "resources_empty_features")
        .unwrap()["input"]
        .clone()
}

#[test]
fn resource_shared_corpus() {
    let reference = reference();
    let cases = vectors();
    assert_eq!(cases.len(), 19);
    for vector in cases {
        let input = &vector["input"];
        let original = input.clone();
        let result = reference.minimum(input);
        if let Some(error) = vector["expected_error"].as_str() {
            assert_eq!(result, Err(error), "{}", vector["id"]);
        } else {
            assert_eq!(
                result,
                Ok(vector["expected_ready_min"].clone()),
                "{}",
                vector["id"]
            );
        }
        assert_eq!(*input, original);
    }
}
#[test]
fn resource_checked_arithmetic() {
    for dimension in ["bytes", "work", "items"] {
        for bad in [
            json!(1),
            json!("01"),
            json!("-1"),
            json!("18446744073709551616"),
            json!(null),
        ] {
            let mut input = basic();
            input["base"]["transport_core"][0]["vector"][dimension] = bad;
            assert_eq!(reference().minimum(&input), Err("resource_quantity"));
        }
        let mut input = basic();
        let mut second = input["base"]["transport_core"][0].clone();
        second["owner_instance_id"] = json!("other");
        second["vector"][dimension] = json!("1");
        input["base"]["transport_core"][0]["vector"][dimension] = json!("18446744073709551615");
        input["base"]["actual_shared_refs"] = json!([second]);
        assert_eq!(reference().minimum(&input), Err("resource_sum_overflow"));
    }
}
#[test]
fn resource_exact_identity_and_binding() {
    let registry: Value =
        serde_json::from_str(registry::RESOURCE_COMPOSITION_REGISTRY_JSON).unwrap();
    for field in registry["owner_key_fields"].as_array().unwrap() {
        let mut input = basic();
        let mut second = input["base"]["transport_core"][0].clone();
        second[field.as_str().unwrap()] = json!("other");
        input["base"]["actual_shared_refs"] = json!([second]);
        assert_eq!(
            reference().minimum(&input).unwrap()["sdk_owned"]["bytes"],
            "200"
        );
    }
    for field in registry["binding_fields"].as_array().unwrap() {
        let mut input = basic();
        let mut second = input["base"]["transport_core"][0].clone();
        second[field.as_str().unwrap()] = json!("other");
        input["base"]["actual_shared_refs"] = json!([second]);
        assert_eq!(reference().minimum(&input), Err("resource_owner_conflict"));
    }
    let mut input = basic();
    input["base"]["transport_core"][0]["environment_id"] = json!("é");
    let mut second = input["base"]["transport_core"][0].clone();
    second["environment_id"] = json!("e\u{301}");
    input["base"]["actual_shared_refs"] = json!([second]);
    assert_eq!(
        reference().minimum(&input).unwrap()["sdk_owned"]["bytes"],
        "200"
    );
}
