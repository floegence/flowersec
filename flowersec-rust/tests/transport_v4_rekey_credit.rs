//! Independent test arithmetic; no live INIT/ACK owner or service reservation.
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[allow(dead_code)]
#[path = "support/v4_time.rs"]
mod time;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

fn compute(profile: &str, operation: &str, input: &Value) -> Result<Value, &'static str> {
    let spec: Value = serde_json::from_str(registry::REKEY_CREDIT_REGISTRY_JSON).unwrap();
    let usage: Value = serde_json::from_str(registry::CRYPTO_USAGE_REGISTRY_JSON).unwrap();
    let time_spec: Value = serde_json::from_str(registry::TIME_ARITHMETIC_REGISTRY_JSON).unwrap();
    let profile = usage["profiles"]
        .get(profile)
        .ok_or("rekey_credit_profile")?;
    let fields = spec["operations"][operation]
        .as_array()
        .ok_or("rekey_credit_operation")?;
    let object = input.as_object().ok_or("rekey_credit_input")?;
    if object.len() != fields.len()
        || object
            .keys()
            .any(|k| !fields.iter().any(|f| f.as_str() == Some(k)))
    {
        return Err("rekey_credit_fields");
    }
    let mut values = BTreeMap::new();
    for field in fields {
        let key = field.as_str().unwrap();
        let s = object[key].as_str().ok_or("rekey_credit_integer")?;
        if s.is_empty()
            || s.len() > spec["quantity_max"].as_str().unwrap().len()
            || s.len() > 1 && s.starts_with('0')
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("rekey_credit_integer");
        }
        values.insert(
            key,
            s.parse::<u64>().map_err(|_| "rekey_credit_integer")? as u128,
        );
    }
    let v = |key: &str| values[key];
    let cap = "configuration_capacity";
    let wide = spec["intermediate_max"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap();
    let mul = |a: u128, b: u128| a.checked_mul(b).filter(|n| *n <= wide).ok_or(cap);
    for field in spec["envelope_fields"].as_object().unwrap().values() {
        let key = field["name"].as_str().unwrap();
        if let Some(n) = values.get(key) {
            let bits = field["type"].as_str().unwrap()[4..].parse::<u32>().unwrap();
            if *n < field["min"].as_u64().unwrap() as u128 || *n >= (1u128 << bits) {
                return Err(cap);
            }
        }
    }
    let (b, r) = (v("burst_rounds"), v("refill_period_ms"));
    let capacity = mul(b, r)?;
    let epochs = profile["max_epochs"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap();
    if b >= epochs {
        return Err(cap);
    }
    if operation == "service" {
        let (n, d, q) = (
            v("rate_numerator"),
            v("rate_denominator"),
            v("quantization_ms"),
        );
        if d == 0 || n >= d || v("issued_at_ms") >= v("session_not_after_ms") {
            return Err(cap);
        }
        let (dm, dp, duration) = (d - n, d + n, v("session_not_after_ms") - v("issued_at_ms"));
        let max_error = (r - 1) / b;
        if max_error == 0 || q > mul(max_error - 1, dm)? / mul(2, d)? {
            return Err(cap);
        }
        let e = mul(mul(2, q)?, d)?.div_ceil(dm) + 1;
        let period = r.checked_sub(mul(b, e)?).filter(|x| *x > 0).ok_or(cap)?;
        let (denominator, initial, rate) = (mul(period, dm)?, mul(capacity, dm)?, mul(b, dp)?);
        let limit = mul(epochs, denominator)?;
        if initial >= limit || duration > (limit - 1 - initial) / rate {
            return Err(cap);
        }
        let numerator = initial
            .checked_add(mul(rate, duration)?)
            .filter(|n| *n <= wide)
            .ok_or(cap)?;
        let rounds = numerator / denominator;
        if rounds == 0 || rounds >= epochs {
            return Err(cap);
        }
        return Ok(
            json!({"service_ms":duration.to_string(),"error_allowance_ms":e.to_string(),
            "denominator_ms":period.to_string(),"capacity_credit":capacity.to_string(),
            "max_rounds":rounds.to_string(),"required_epochs":(rounds+1).to_string()}),
        );
    }
    let mut available = capacity;
    if operation != "initial_credit" {
        let base = v("base_credit");
        if base > capacity {
            return Err(cap);
        }
        let input: Map<String, Value> = [
            "delta_ms",
            "rate_numerator",
            "rate_denominator",
            "quantization_ms",
        ]
        .into_iter()
        .map(|k| (k.to_owned(), json!(v(k).to_string())))
        .collect();
        let elapsed = time::compute(&time_spec, "elapsed", &Value::Object(input))?;
        let bound = spec["elapsed_bound"][operation].as_str().unwrap();
        let u = elapsed[bound].as_str().unwrap().parse::<u128>().unwrap();
        if u < r {
            let refill = mul(b, u)?;
            if refill < capacity - base {
                available = base + refill;
            }
        }
    }
    let post = available.checked_sub(r).map(|n| n.to_string());
    Ok(
        json!({"capacity_credit":capacity.to_string(),"available_credit":available.to_string(),"post_charge_credit":post}),
    )
}

#[test]
fn every_shared_rekey_credit_vector() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v4/rekey_credit.json"
    ))
    .unwrap();
    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 48);
    for v in vectors {
        let before = v["input"].clone();
        let result = compute(
            v["profile"].as_str().unwrap(),
            v["operation"].as_str().unwrap(),
            &before,
        );
        if let Some(error) = v["expected_error"].as_str() {
            assert_eq!(result, Err(error), "{}", v["id"]);
        } else {
            assert_eq!(result, Ok(v["expected"].clone()), "{}", v["id"]);
        }
        assert_eq!(before, v["input"]);
    }
}

#[test]
fn floor_boundaries_partial_credit_and_strict_inputs() {
    for duration in 1u64..=120 {
        let result = compute(registry::DH_PROFILE_X25519,"service",&json!({"burst_rounds":"2","refill_period_ms":"30",
            "request_start_budget_ms":"5","issued_at_ms":"0","session_not_after_ms":duration.to_string(),
            "rate_numerator":"1","rate_denominator":"2","quantization_ms":"2"})).unwrap();
        let n = result["max_rounds"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(n * 12 <= 60 + 6 * duration && (n + 1) * 12 > 60 + 6 * duration);
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
            compute(
                registry::DH_PROFILE_X25519,
                "initial_credit",
                &json!({"burst_rounds":bad,"refill_period_ms":"30"})
            ),
            Err("rekey_credit_integer")
        );
    }
    let mut input = json!({"burst_rounds":"2","refill_period_ms":"30","base_credit":"10","delta_ms":"9",
        "rate_numerator":"0","rate_denominator":"1","quantization_ms":"0"});
    for _ in 0..50 {
        let peek = compute(registry::DH_PROFILE_X25519, "client_credit", &input).unwrap();
        assert_eq!(peek["available_credit"], "28");
        assert!(peek["post_charge_credit"].is_null());
    }
    input["delta_ms"] = json!("10");
    assert_eq!(
        compute(registry::DH_PROFILE_X25519, "client_credit", &input).unwrap()["post_charge_credit"],
        "0"
    );
}
