//! Public fixed transactions only. Expected-byte matching is not a receiver
//! codec, barrier proof, epoch installation, clock or single-publisher gate.
#[path = "../src/profile_dh_v4_reference.rs"]
mod dh;
// Reuse the independent record helpers and retain their authentication tests.
#[path = "transport_v4_records.rs"]
mod records;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use records::registry;
use records::{domain, integer, key, layout, text, unhex};
use ring::aead::{Aad, Nonce};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn hex(b: &[u8]) -> Value {
    Value::String(b.iter().map(|n| format!("{n:02x}")).collect())
}
fn expand(key: &[u8], info: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 32];
    Hkdf::<Sha256>::from_prk(key)
        .unwrap()
        .expand(info, &mut out)
        .unwrap();
    out
}
fn mac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    m.update(bytes);
    m.finalize().into_bytes().to_vec()
}
fn head(major: u8, n: u64) -> Vec<u8> {
    if n < 24 {
        return vec![major << 5 | n as u8];
    }
    for (width, ai) in [(1, 24), (2, 25), (4, 26), (8, 27)] {
        if width == 8 || n < 1u64 << (width * 8) {
            return [vec![major << 5 | ai], n.to_be_bytes()[8 - width..].to_vec()].concat();
        }
    }
    unreachable!()
}
fn encode(
    reg: &Value,
    profiles: &Value,
    name: &str,
    profile: &str,
    values: &Value,
    unsigned: bool,
) -> Option<Vec<u8>> {
    let def = reg.get(name)?;
    let mut fields: Vec<_> = def["fields"]
        .as_object()?
        .iter()
        .filter(|(id, _)| !unsigned || id.parse::<u64>().ok() != def["mac_field"].as_u64())
        .collect();
    fields.sort_by_key(|(id, _)| id.parse::<u64>().unwrap());
    let mut out = head(5, fields.len() as u64);
    for (id, f) in fields {
        out.extend(head(0, id.parse().ok()?));
        let v = values.get(text(&f["name"]))?;
        let kind = text(&f["type"]);
        if let Some(bits) = kind.strip_prefix("uint") {
            let n = v.as_u64().or_else(|| v.as_str()?.parse().ok())?;
            let bits: u32 = bits.parse().ok()?;
            if (bits < 64 && n >= 1u64 << bits)
                || f.get("const").is_some_and(|c| c.as_u64() != Some(n))
            {
                return None;
            }
            out.extend(head(0, n));
        } else if kind == "bytes" {
            let b = unhex(v);
            let len = if f["profile_public_key"] == true {
                profiles[profile]["dh_public_bytes"].as_u64()?
            } else {
                f["length"].as_u64()?
            };
            if b.len() as u64 != len {
                return None;
            }
            out.extend(head(2, len));
            out.extend(b);
        } else if kind == "array" {
            let list = v.as_array()?;
            out.extend(head(4, list.len() as u64));
            for item in list {
                out.extend(encode(
                    reg,
                    profiles,
                    text(&f["items"]["schema_ref"]),
                    profile,
                    item,
                    false,
                )?);
            }
        } else {
            return None;
        }
    }
    Some(out)
}
fn rekey_domain(
    domains: &Value,
    name: &str,
    c: &Value,
    phase: u64,
    role: u64,
    extra: &[(&str, &[u8])],
) -> Vec<u8> {
    let hash = unhex(&c["handshake_hash_hex"]);
    let digest = unhex(&c["context_digest_hex"]);
    let id = unhex(&c["rekey_id_hex"]);
    let mut values = vec![
        ("profile", text(&c["profile"]).as_bytes()),
        ("handshake_hash", &hash),
        ("context_digest", &digest),
        ("rekey_id", &id),
    ];
    values.extend_from_slice(extra);
    domain(
        domains,
        name,
        &values,
        &json!({"epoch":c["epoch"],"next_epoch":c["next_epoch"],"phase":phase,"role":role}),
    )
}
fn message(
    reg: &Value,
    profiles: &Value,
    domains: &Value,
    c: &Value,
    p: &Value,
    base: &[u8],
    values: &Value,
) -> Option<(Vec<u8>, Value)> {
    if integer(&c["next_epoch"]) != integer(&c["epoch"]) + 1
        || integer(&c["next_epoch"]) > u32::MAX as u64
        || base.len() != 32
    {
        return None;
    }
    let name = text(&p["schema"]);
    let phase = integer(&p["phase"]);
    let role = integer(&reg[name]["sender_role"]);
    let mut v = values.clone();
    v["phase"] = p["phase"].clone();
    v["next_epoch"] = c["next_epoch"].clone();
    v["rekey_id"] = c["rekey_id_hex"].clone();
    let unsigned = encode(reg, profiles, name, text(&c["profile"]), &v, true)?;
    let info = rekey_domain(domains, "rekey_confirm_key", c, phase, role, &[]);
    let k = expand(base, &info);
    let input = rekey_domain(
        domains,
        "rekey_confirm_mac",
        c,
        phase,
        role,
        &[("message", &unsigned)],
    );
    let confirmation = mac(&k, &input);
    v["confirmation_mac"] = hex(&confirmation);
    Some((
        encode(reg, profiles, name, text(&c["profile"]), &v, false)?,
        json!({"unsigned_hex":hex(&unsigned),"key_info_hex":hex(&info),"key_hex":hex(&k),"mac_message_hex":hex(&input),"confirmation_mac_hex":hex(&confirmation)}),
    ))
}

#[test]
fn shared_rekey_composition_and_fixed_transaction_rejection() {
    let corpus: Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/rekey.json")).unwrap();
    let reg: Value = serde_json::from_str(registry::REKEY_REGISTRY_JSON).unwrap();
    let records: Value = serde_json::from_str(registry::RECORD_REGISTRY_JSON).unwrap();
    let domains: Value = serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).unwrap();
    assert_eq!(corpus["schema_sha256"], registry::SCHEMA_SHA256);
    let rounds = corpus["rounds"].as_array().unwrap();
    assert_eq!(rounds.len(), 4);
    let mut previous = HashMap::new();
    let mut phases = HashMap::new();
    for r in rounds {
        let c = &r["context"];
        let profile = text(&c["profile"]);
        let input = &r["input"];
        if integer(&c["epoch"]) > 0 {
            assert_eq!(previous[profile], r["old_root_hex"]);
        }
        let cp = dh::public(profile, &unhex(&input["client_private_hex"])).unwrap();
        let sp = dh::public(profile, &unhex(&input["server_private_hex"])).unwrap();
        let shared = dh::derive(profile, &unhex(&input["client_private_hex"]), &sp).unwrap();
        assert_eq!(
            shared,
            dh::derive(profile, &unhex(&input["server_private_hex"]), &cp).unwrap()
        );
        assert_eq!(hex(&shared), r["dh_hex"]);
        let secret = expand(
            &unhex(&r["old_root_hex"]),
            &rekey_domain(&domains, "rekey_secret", c, 0, 0, &[]),
        );
        assert_eq!(hex(&secret), r["secret_hex"]);
        let mut values = [
            json!({"client_ephemeral":hex(&cp),"client_barrier":input["client_barrier"]}),
            json!({"server_ephemeral":hex(&sp),"server_barrier":input["server_barrier"]}),
            json!({}),
            json!({}),
        ];
        let mut init = vec![];
        let mut reply = vec![];
        let mut root = vec![];
        let mut t = vec![];
        for (i, p) in r["phases"].as_array().unwrap().iter().enumerate() {
            if i == 1 {
                values[i]["init_digest"] = hex(&Sha256::digest(rekey_domain(
                    &domains,
                    "rekey_init_digest",
                    c,
                    0,
                    0,
                    &[("init", &init)],
                )));
                assert_eq!(values[i]["init_digest"], r["init_digest_hex"]);
            }
            if i == 2 {
                t = Sha256::digest(rekey_domain(
                    &domains,
                    "rekey_transcript",
                    c,
                    0,
                    0,
                    &[("init", &init), ("reply", &reply)],
                ))
                .to_vec();
                assert_eq!(hex(&t), r["transcript_hex"]);
                let prk = mac(&secret, &shared);
                assert_eq!(hex(&prk), r["prk_hex"]);
                root = expand(
                    &prk,
                    &rekey_domain(
                        &domains,
                        "rekey_root",
                        c,
                        0,
                        0,
                        &[("transcript_digest", &t)],
                    ),
                );
                assert_eq!(hex(&root), r["new_root_hex"]);
            }
            let side = if p["role"] == 0 { "client" } else { "server" };
            let old_sequence = integer(&input[format!("{side}_old_sequence")]);
            if i >= 2 {
                values[i]["transcript_digest"] = hex(&t);
                values[i]["old_maintenance_next_sequence"] = json!(old_sequence + 1);
            }
            let base = if i < 2 { &secret } else { &root };
            assert_eq!(hex(base), p["base_hex"]);
            let (wire, material) =
                message(&reg, &records["profiles"], &domains, c, p, base, &values[i]).unwrap();
            assert_eq!(hex(&wire), p["message_hex"]);
            for (k, v) in material.as_object().unwrap() {
                assert_eq!(v, &p[k], "{} {k}", p["id"]);
            }
            if i == 0 {
                init = wire.clone();
            }
            if i == 1 {
                reply = wire.clone();
            }
            phases.insert(text(&p["id"]), (c, p, values[i].clone()));
            let epoch = if i < 2 { &c["epoch"] } else { &c["next_epoch"] };
            let sequence = if i < 2 { old_sequence } else { 0 };
            assert_eq!(&p["record"]["epoch"], epoch);
            assert_eq!(integer(&p["record"]["sequence"]), sequence);
            assert_eq!(
                p["record"]["direction"],
                reg[text(&p["schema"])]["sender_role"]
            );
            let ints =
                json!({"epoch":epoch,"sequence":sequence,"sequence_scope":0,"direction":p["role"]});
            let header = layout(&records["header"], &ints);
            let nonce = layout(&records["nonce"], &ints);
            let envelope = layout(
                &records["envelope"]["layout"],
                &json!({"payload_length":header.len()+wire.len()+integer(&records["profiles"][profile]["tag_bytes"]) as usize,"frame_type":registry::FRAME_REKEY}),
            );
            let hash = unhex(&c["handshake_hash_hex"]);
            let old = unhex(&r["old_root_hex"]);
            let k = expand(
                if i < 2 { &old } else { &root },
                &domain(
                    &domains,
                    "record_key",
                    &[("profile", profile.as_bytes()), ("handshake_hash", &hash)],
                    &ints,
                ),
            );
            let aad = domain(
                &domains,
                "record_aad",
                &[
                    ("profile", profile.as_bytes()),
                    ("envelope_header", &envelope),
                    ("record_header", &header),
                ],
                &ints,
            );
            let cipher = key(text(&records["profiles"][profile]["record_aead"]), &k);
            let mut sealed = wire.clone();
            cipher
                .seal_in_place_append_tag(
                    Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                    Aad::from(&aad),
                    &mut sealed,
                )
                .unwrap();
            assert_eq!(
                hex(&[&envelope[..], &header[..], &sealed[..]].concat()),
                p["record"]["wire_hex"]
            );
            assert_eq!(
                cipher
                    .open_in_place(
                        Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                        Aad::from(&aad),
                        &mut sealed
                    )
                    .unwrap(),
                wire
            );
        }
        previous.insert(profile, r["new_root_hex"].clone());
    }
    let negatives = corpus["negatives"].as_array().unwrap();
    assert!(!negatives.is_empty());
    for n in negatives {
        let (c, p, values) = &phases[text(&n["source"])];
        let mut c = (*c).clone();
        let mut values = values.clone();
        c.as_object_mut()
            .unwrap()
            .extend(n["context_patch"].as_object().unwrap().clone());
        values
            .as_object_mut()
            .unwrap()
            .extend(n["expected"].as_object().unwrap().clone());
        let result = message(
            &reg,
            &records["profiles"],
            &domains,
            &c,
            p,
            &unhex(&n["base_hex"]),
            &values,
        );
        assert!(
            result.is_none_or(|(wire, _)| wire != unhex(&n["message_hex"])),
            "{}",
            n["id"]
        );
    }
}
