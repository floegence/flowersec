//! Independent test-only charges, not input eligibility or usage reservation.
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
use serde_json::{Value, json};

fn charge(
    spec: &Value,
    profiles: &Value,
    profile: &str,
    input: &Value,
) -> Result<Value, &'static str> {
    if spec["profiles"].get(profile).is_none() {
        return Err("crypto_usage_profile");
    }
    let fields = spec["charge_fields"].as_array().unwrap();
    let object = input.as_object().ok_or("crypto_usage_input")?;
    if object.len() != fields.len()
        || object
            .keys()
            .any(|key| !fields.iter().any(|f| f.as_str() == Some(key)))
    {
        return Err("crypto_usage_fields");
    }
    let operation = input["operation"]
        .as_str()
        .ok_or("crypto_usage_operation")?;
    if !spec["operations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some(operation))
    {
        return Err("crypto_usage_operation");
    }
    let maximum = spec["quantity_max"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let integer = |value: &Value| -> Result<u64, &'static str> {
        let s = value.as_str().ok_or("crypto_usage_integer")?;
        if s.is_empty()
            || s.len() > spec["quantity_max"].as_str().unwrap().len()
            || s.len() > 1 && s.starts_with('0')
            || !s.bytes().all(|c| c.is_ascii_digit())
        {
            return Err("crypto_usage_integer");
        }
        let n = s.parse::<u64>().map_err(|_| "crypto_usage_integer")?;
        if n > maximum {
            return Err("crypto_usage_integer");
        }
        Ok(n)
    };
    let aad = integer(&input["aad_bytes"])?;
    let bytes = integer(&input["input_bytes"])?;
    let tag = profiles[profile]["tag_bytes"].as_u64().unwrap();
    let (payload, ciphertext) = if operation == "seal" {
        (
            bytes,
            bytes.checked_add(tag).ok_or("crypto_usage_overflow")?,
        )
    } else {
        (
            bytes.checked_sub(tag).ok_or("crypto_usage_ciphertext")?,
            bytes,
        )
    };
    let block = spec["authentication_block_bytes"].as_u64().unwrap();
    let blocks = aad
        .div_ceil(block)
        .checked_add(payload.div_ceil(block))
        .and_then(|n| n.checked_add(spec["length_blocks"].as_u64().unwrap()))
        .ok_or("crypto_usage_overflow")?;
    if ciphertext > maximum || blocks > maximum {
        return Err("crypto_usage_overflow");
    }
    Ok(
        json!({"calls":"1","authentication_blocks":blocks.to_string(),"ciphertext_bytes":ciphertext.to_string()}),
    )
}
fn spec() -> (Value, Value) {
    (
        serde_json::from_str(registry::CRYPTO_USAGE_REGISTRY_JSON).unwrap(),
        serde_json::from_str(registry::CRYPTO_PROFILES_JSON).unwrap(),
    )
}
#[test]
fn all_shared_usage_vectors() {
    let (spec, profiles) = spec();
    let corpus: Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v4/crypto_usage.json"
    ))
    .unwrap();
    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 28);
    for v in vectors {
        let original = v["input"].clone();
        let actual = charge(&spec, &profiles, v["profile"].as_str().unwrap(), &original);
        if let Some(error) = v["expected_error"].as_str() {
            assert_eq!(actual, Err(error), "{}", v["id"]);
        } else {
            assert_eq!(actual, Ok(v["expected"].clone()), "{}", v["id"]);
        }
        assert_eq!(original, v["input"]);
    }
}
#[test]
fn block_boundaries_and_strict_quantities() {
    let (spec, profiles) = spec();
    for profile in spec["profiles"].as_object().unwrap().keys() {
        for aad in 0u64..=33 {
            for payload in 0u64..=33 {
                let seal=charge(&spec,&profiles,profile,&json!({"operation":"seal","aad_bytes":aad.to_string(),"input_bytes":payload.to_string()})).unwrap();
                let open=charge(&spec,&profiles,profile,&json!({"operation":"open","aad_bytes":aad.to_string(),"input_bytes":(payload+16).to_string()})).unwrap();
                assert_eq!(seal, open);
                assert_eq!(
                    seal["authentication_blocks"],
                    json!((aad.div_ceil(16) + payload.div_ceil(16) + 1).to_string())
                );
            }
        }
        for bad in [
            json!(1),
            json!(true),
            Value::Null,
            json!(""),
            json!("01"),
            json!("-1"),
            json!("+1"),
            json!("1.0"),
            json!("1\n"),
            json!("١"),
            json!("18446744073709551616"),
        ] {
            assert_eq!(
                charge(
                    &spec,
                    &profiles,
                    profile,
                    &json!({"operation":"seal","aad_bytes":bad,"input_bytes":"0"})
                ),
                Err("crypto_usage_integer")
            );
        }
    }
}
