//! Independent test-only arithmetic; no clock, source, owner or timer authority.
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

fn check(value: u128, maximum: u128) -> Result<u128, &'static str> {
    if value > maximum {
        Err("time_overflow")
    } else {
        Ok(value)
    }
}
fn ceil(a: u128, b: u128) -> u128 {
    a.div_ceil(b)
}

pub fn compute(spec: &Value, operation: &str, input: &Value) -> Result<Value, &'static str> {
    let fields = spec["operations"][operation]
        .as_array()
        .ok_or("time_operation")?;
    let object = input.as_object().ok_or("time_input_object")?;
    if object.len() != fields.len()
        || object
            .keys()
            .any(|k| !fields.iter().any(|f| f.as_str() == Some(k)))
    {
        return Err("time_input_fields");
    }
    let maximum = spec["quantity_max"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap();
    let wide = spec["intermediate_max"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap();
    let mut values = BTreeMap::new();
    for field in fields {
        let key = field.as_str().unwrap();
        let text = object[key].as_str().ok_or("time_integer")?;
        if text.is_empty()
            || text.len() > spec["quantity_max"].as_str().unwrap().len()
            || text.len() > 1 && text.starts_with('0')
            || !text.bytes().all(|c| c.is_ascii_digit())
        {
            return Err("time_integer");
        }
        let n = text.parse::<u64>().map_err(|_| "time_integer")? as u128;
        if n > maximum {
            return Err("time_integer");
        }
        values.insert(key, n);
    }
    let v = |key: &str| values[key];
    let (n, d, q) = (
        v("rate_numerator"),
        v("rate_denominator"),
        v("quantization_ms"),
    );
    if d == 0 || n >= d {
        return Err("time_rate");
    }
    let elapsed = || -> Result<(u128, u128), &'static str> {
        let lower_product = check(
            v("delta_ms")
                .saturating_sub(q)
                .checked_mul(d)
                .ok_or("time_overflow")?,
            wide,
        )?;
        let upper_product = check(
            check(v("delta_ms") + q, maximum)?
                .checked_mul(d)
                .ok_or("time_overflow")?,
            wide,
        )?;
        let lower = lower_product / (d + n);
        let upper = check(ceil(upper_product, d - n), maximum)?;
        Ok((lower, upper))
    };
    let interval = |lower: u128, upper: u128| -> Result<Value, &'static str> {
        check(lower, maximum)?;
        check(upper, maximum)?;
        if lower > upper {
            return Err("time_interval");
        }
        if v("max_width_ms") == 0 || upper - lower > v("max_width_ms") {
            return Err("time_width");
        }
        Ok(json!({"lower_ms":lower.to_string(), "upper_ms":upper.to_string()}))
    };
    match operation {
        "elapsed" => {
            let (lower, upper) = elapsed()?;
            Ok(json!({"elapsed_lower_ms":lower.to_string(), "elapsed_upper_ms":upper.to_string()}))
        }
        "network_anchor" => {
            let (_, upper) = elapsed()?;
            if v("max_round_trip_ms") == 0 || upper > v("max_round_trip_ms") {
                return Err("time_round_trip");
            }
            interval(
                v("sample_ms")
                    .checked_sub(v("source_error_ms"))
                    .ok_or("time_overflow")?,
                v("sample_ms") + v("source_error_ms") + upper,
            )
        }
        "advance_anchor" => {
            if v("lower_ms") > v("upper_ms") {
                return Err("time_interval");
            }
            let (lower, upper) = elapsed()?;
            if v("max_age_ms") == 0 || upper > v("max_age_ms") {
                return Err("time_anchor_age");
            }
            interval(v("lower_ms") + lower, v("upper_ms") + upper)
        }
        "deadline_delta" => {
            if v("upper_ms") >= v("deadline_ms") {
                return Err("time_expired");
            }
            let slack = v("deadline_ms") - v("upper_ms");
            let product = check(slack.checked_mul(d - n).ok_or("time_overflow")?, wide)?;
            let available = (product / d)
                .checked_sub(q)
                .ok_or("time_deadline_unrepresentable")?;
            Ok(json!({"delta_ms":check(available,maximum)?.to_string()}))
        }
        "prove_delta" => {
            if v("bound_ms") <= v("lower_ms") {
                return Ok(json!({"delta_ms":"0"}));
            }
            let gap = v("bound_ms") - v("lower_ms");
            let product = check(gap.checked_mul(d + n).ok_or("time_overflow")?, wide)?;
            Ok(
                json!({"delta_ms":check(ceil(product,d).checked_add(q).ok_or("time_overflow")?,maximum)?.to_string()}),
            )
        }
        _ => Err("time_operation"),
    }
}

pub fn input(n: u64, d: u64, q: u64, fields: &[(&str, u64)]) -> Value {
    let map: Map<String, Value> = [
        ("rate_numerator", n),
        ("rate_denominator", d),
        ("quantization_ms", q),
    ]
    .into_iter()
    .chain(fields.iter().copied())
    .map(|(key, value)| (key.to_owned(), json!(value.to_string())))
    .collect();
    Value::Object(map)
}
