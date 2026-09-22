//! Shared vectors plus independent outward-rounding and inverse checks.
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "support/v4_time.rs"]
mod time;
use serde_json::{Value, json};

fn spec() -> Value {
    serde_json::from_str(registry::TIME_ARITHMETIC_REGISTRY_JSON).unwrap()
}

#[test]
fn all_time_vectors() {
    let registry = spec();
    let corpus: Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v4/time_arithmetic.json"
    ))
    .unwrap();
    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 37);
    for vector in vectors {
        let original = vector["input"].clone();
        let result = time::compute(&registry, vector["operation"].as_str().unwrap(), &original);
        if let Some(error) = vector["expected_error"].as_str() {
            assert_eq!(result, Err(error), "{}", vector["id"]);
        } else {
            assert_eq!(result, Ok(vector["expected"].clone()), "{}", vector["id"]);
        }
        assert_eq!(original, vector["input"]);
    }
}

#[test]
fn rounding_and_inverse_extrema() {
    let registry = spec();
    for d in 1..=8 {
        for n in 0..d {
            for gap in 1..=20 {
                for q in 0..=2 {
                    let run = |op: &str, fields: &[(&str, u64)], output: &str| -> u64 {
                        time::compute(&registry, op, &time::input(n, d, q, fields)).unwrap()[output]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap()
                    };
                    let elapsed = |delta, output| run("elapsed", &[("delta_ms", delta)], output);
                    let lo = elapsed(gap, "elapsed_lower_ms");
                    let hi = elapsed(gap, "elapsed_upper_ms");
                    assert!(lo * (d + n) <= gap.saturating_sub(q) * d);
                    assert!(hi * (d - n) >= (gap + q) * d);
                    if q <= gap * (d - n) / d {
                        let delta = run(
                            "deadline_delta",
                            &[("upper_ms", 0), ("deadline_ms", gap)],
                            "delta_ms",
                        );
                        assert!(elapsed(delta, "elapsed_upper_ms") <= gap);
                        assert!(elapsed(delta + 1, "elapsed_upper_ms") > gap);
                    }
                    let delta = run(
                        "prove_delta",
                        &[("lower_ms", 0), ("bound_ms", gap)],
                        "delta_ms",
                    );
                    assert!(elapsed(delta, "elapsed_lower_ms") >= gap);
                    assert!(elapsed(delta - 1, "elapsed_lower_ms") < gap);
                }
            }
        }
    }
}

#[test]
fn strict_input_types_and_bounds() {
    let registry = spec();
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
        let mut input = time::input(0, 1, 0, &[("delta_ms", 1)]);
        input["delta_ms"] = bad;
        assert_eq!(
            time::compute(&registry, "elapsed", &input),
            Err("time_integer")
        );
    }
    assert_eq!(
        time::compute(&registry, "other", &Value::Null),
        Err("time_operation")
    );
    assert_eq!(
        time::compute(&registry, "elapsed", &Value::Null),
        Err("time_input_object")
    );
    let mut input = time::input(0, 1, 0, &[("delta_ms", 1)]);
    input["extra"] = json!("1");
    assert_eq!(
        time::compute(&registry, "elapsed", &input),
        Err("time_input_fields")
    );
}
