//! Independent partial byte costs; no reservation, frame-fit or RSS authority.
use serde_json::{Value, json};

fn mul(values: &[u64]) -> Result<u64, &'static str> {
    values.iter().try_fold(1u64, |a, b| {
        a.checked_mul(*b).ok_or("resource_cost_overflow")
    })
}
fn add(values: &[u64]) -> Result<u64, &'static str> {
    values.iter().try_fold(0u64, |a, b| {
        a.checked_add(*b).ok_or("resource_cost_overflow")
    })
}
fn integer(value: &Value, min: u64, max: u64, code: &'static str) -> Result<u64, &'static str> {
    value
        .as_u64()
        .filter(|n| *n >= min && *n <= max)
        .ok_or(code)
}

pub fn costs(spec: &Value, input: &Value) -> Result<Value, &'static str> {
    let fields = [
        "max_frame_bytes",
        "small_auth_slots",
        "application_profile",
        "rpc_max_general_outstanding",
    ];
    let c = input.as_object().ok_or("resource_object")?;
    if c.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("resource_field");
    }
    if fields[..3].iter().any(|key| !c.contains_key(*key)) {
        return Err("resource_missing_field");
    }
    let codec = &spec["codec"];
    let app = &spec["application"];
    let bitmap = &spec["bitmap"];
    // These are trusted generated constants, never peer declarations.
    let n = |value: &Value| value.as_u64().unwrap();
    let frame = integer(
        &input["max_frame_bytes"],
        1,
        n(&spec["max_frame_bytes"]),
        "resource_frame_limit",
    )?;
    let small_slots = integer(
        &input["small_auth_slots"],
        0,
        n(&codec["small_slots_max"]),
        "resource_auth_slots",
    )?;
    let name = input["application_profile"]
        .as_str()
        .ok_or("resource_application_profile")?;
    let p = app["profiles"]
        .get(name)
        .ok_or("resource_application_profile")?;
    let rpc = n(&p["rpc_channels"]);
    if c.contains_key("rpc_max_general_outstanding") != (rpc > 0) {
        return Err("resource_rpc_limit_presence");
    }
    let k = if rpc > 0 {
        integer(
            &input["rpc_max_general_outstanding"],
            n(&spec["rpc_general_limit"]["min"]),
            n(&spec["rpc_general_limit"]["max"]),
            "resource_rpc_limit",
        )?
    } else {
        0
    };
    let full = mul(&[
        n(&codec["full_body_slots"]),
        n(&codec["buffers_per_slot"]),
        frame,
    ])?;
    let small = mul(&[
        small_slots,
        n(&codec["buffers_per_slot"]),
        frame.min(n(&codec["small_body_ceiling_bytes"])),
    ])?;
    let bits = mul(&[
        n(&spec["common_scope_ordinals"]),
        n(&bitmap["roles"]),
        n(&bitmap["bits_per_scope"]),
    ])?;
    let internal = add(&[rpc, n(&p["notify_channels"])])?;
    let management = n(&p["management_channels"]);
    let reply = if rpc > 0 {
        add(&[k, n(&app["query_slots"])])?
    } else {
        0
    };
    let associations = if rpc > 0 {
        mul(&[k, n(&app["fragment_associations_per_general"])])?
    } else {
        0
    };
    let promise = mul(&[
        add(&[internal, management])?,
        n(&app["channel_direction_bytes"]),
    ])?;
    let amounts = [
        ("reply_slots", mul(&[reply, n(&app["reply_slot_bytes"])])?),
        (
            "fragment_associations",
            mul(&[associations, n(&app["fragment_association_bytes"])])?,
        ),
        (
            "query_reserve",
            if rpc > 0 {
                n(&app["query_reserve_bytes"])
            } else {
                0
            },
        ),
        (
            "rpc_error_output",
            mul(&[rpc, n(&app["rpc_error_output_bytes_per_channel"])])?,
        ),
        ("internal_receive", promise),
        ("internal_send", promise),
    ];
    let mut bytes = serde_json::Map::new();
    let mut total = 0;
    for (key, value) in amounts {
        bytes.insert(key.into(), json!(value.to_string()));
        total = add(&[total, value])?;
    }
    bytes.insert("total".into(), json!(total.to_string()));
    Ok(json!({
        "codec_body_bytes": {"full_slots":full.to_string(),"small_slots":small.to_string(),"total":add(&[full,small])?.to_string()},
        "permanent_bitmap_bytes": (bits / n(&bitmap["bits_per_byte"])).to_string(),
        "application_counts": {"internal_active":internal,"management_active":management,"reply_slots":reply,"fragment_associations":associations},
        "application_bytes": bytes,
    }))
}
