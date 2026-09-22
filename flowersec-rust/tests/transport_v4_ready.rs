//! Public fixtures only; no credential trust or one-shot dual-READY authority.
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "../src/strict_ed25519_v4_reference.rs"]
mod strict;

use hkdf::Hkdf;
use ring::hmac;
use serde_json::{Value, json};
use sha2::Sha256;

fn unhex(value: &Value) -> Option<Vec<u8>> {
    let text = value.as_str()?;
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn head(major: u8, value: u64) -> Vec<u8> {
    if value < 24 {
        return vec![major << 5 | value as u8];
    }
    for (width, ai) in [(1, 24), (2, 25), (4, 26), (8, 27)] {
        if width == 8 || value < 1_u64 << (width * 8) {
            return [&[major << 5 | ai][..], &value.to_be_bytes()[8 - width..]].concat();
        }
    }
    unreachable!()
}

struct Reference {
    maps: Value,
    domains: Value,
    profiles: Value,
}
impl Reference {
    fn fields(&self, name: &str) -> Vec<(u64, &Value)> {
        let mut fields: Vec<_> = self.maps[name]["fields"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(id, f)| (id.parse::<u64>().unwrap(), f))
            .collect();
        fields.sort_by_key(|(id, _)| *id);
        fields
    }
    fn encode(&self, name: &str, context: &Value) -> Option<Vec<u8>> {
        let fields = self.fields(name);
        let mut out = head(5, fields.len() as u64);
        for (id, f) in fields {
            out.extend(head(0, id));
            let name = f["name"].as_str()?;
            match f["type"].as_str()? {
                "bytes" => {
                    let value = unhex(&context[format!("{name}_hex")])?;
                    if value.len() as u64 != f["length"].as_u64()? {
                        return None;
                    }
                    out.extend(head(2, value.len() as u64));
                    out.extend(value);
                }
                "text" => {
                    let value = context[name].as_str()?;
                    self.profiles.get(value)?;
                    out.extend(head(3, value.len() as u64));
                    out.extend(value.as_bytes());
                }
                kind @ ("uint8" | "uint64") => {
                    let value = context[name].as_u64()?;
                    if kind == "uint8" && value > 255 {
                        return None;
                    }
                    if let Some(mask) = f.get("bitmask")
                        && value & !mask.as_u64()? != 0
                    {
                        return None;
                    }
                    if let Some(allowed) = f.get("enum")
                        && !allowed
                            .as_object()?
                            .values()
                            .any(|v| v.as_u64() == Some(value))
                    {
                        return None;
                    }
                    out.extend(head(0, value));
                }
                _ => return None,
            }
        }
        Some(out)
    }
    fn decode(&self, mut wire: &[u8]) -> Option<Value> {
        let fields = self.fields("READY");
        wire = wire.strip_prefix(head(5, fields.len() as u64).as_slice())?;
        let mut out = json!({});
        for (id, f) in fields {
            if f["type"] != "bytes" {
                return None;
            }
            let length = usize::try_from(f["length"].as_u64()?).ok()?;
            wire = wire.strip_prefix(head(0, id).as_slice())?;
            wire = wire.strip_prefix(head(2, length as u64).as_slice())?;
            let value = wire.get(..length)?;
            out[format!("{}_hex", f["name"].as_str()?)] = hex(value).into();
            wire = &wire[length..];
        }
        wire.is_empty().then_some(out)
    }
    fn domain(&self, name: &str, values: &[(&str, &[u8])], role: u64) -> Option<Vec<u8>> {
        let spec = self
            .domains
            .as_array()?
            .iter()
            .find(|d| d["name"] == name)?;
        let mut out = unhex(&spec["label_bytes"])?;
        for part in spec["input_schema"]["parts"].as_array()? {
            match part["encoding"].as_str()? {
                "u8" => {
                    if let Some(allowed) = part.get("enum")
                        && !allowed.as_array()?.contains(&json!(role))
                    {
                        return None;
                    }
                    out.push(u8::try_from(role).ok()?);
                }
                "lp-map" | "lp-ascii" | "lp-bytes" => {
                    let value = values
                        .iter()
                        .find(|(key, _)| Some(*key) == part["name"].as_str())?
                        .1;
                    if let Some(length) = part.get("length")
                        && value.len() as u64 != length.as_u64()?
                    {
                        return None;
                    }
                    out.extend(u32::try_from(value.len()).ok()?.to_be_bytes());
                    out.extend(value);
                }
                _ => return None,
            }
        }
        Some(out)
    }
    fn material(&self, context: &Value, proof: &[u8]) -> Option<Value> {
        let role = context["role"].as_u64()?;
        let proof_input = self.encode("ReadyProofInput", context)?;
        let message = self.domain("ready_identity", &[("proof", &proof_input)], role)?;
        let info = self.domain(
            "ready_key",
            &[
                ("profile", context["crypto_profile_id"].as_str()?.as_bytes()),
                ("handshake_hash", &unhex(&context["handshake_hash_hex"])?),
                (
                    "context_digest",
                    &unhex(&context["transport_context_digest_hex"])?,
                ),
            ],
            role,
        )?;
        let root = unhex(&context["epoch_root_hex"])?;
        if root.len() != 32 {
            return None;
        }
        let mut key = [0; 32];
        Hkdf::<Sha256>::from_prk(&root)
            .ok()?
            .expand(&info, &mut key)
            .ok()?;
        let mut values = context.clone();
        values["identity_proof_hex"] = hex(proof).into();
        let mac_input = self.encode("ReadyMACInput", &values)?;
        let mac_message = self.domain("ready_mac", &[("mac_input", &mac_input)], role)?;
        let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &mac_message);
        Some(
            json!({"proof_input_hex":hex(&proof_input),"signature_message_hex":hex(&message),
            "key_info_hex":hex(&info),"key_hex":hex(&key),"mac_input_hex":hex(&mac_input),
            "mac_message_hex":hex(&mac_message),"confirmation_mac_hex":hex(mac.as_ref())}),
        )
    }
    fn verify(&self, context: &Value, wire: &[u8]) -> bool {
        (|| {
            let received = self.decode(wire)?;
            let proof = unhex(&received["identity_proof_hex"])?;
            let material = self.material(context, &proof)?;
            let mac = unhex(&received["confirmation_mac_hex"])?;
            hmac::verify(
                &hmac::Key::new(hmac::HMAC_SHA256, &unhex(&material["key_hex"])?),
                &unhex(&material["mac_message_hex"])?,
                &mac,
            )
            .ok()?;
            Some(strict::verify(
                &proof,
                &unhex(&material["signature_message_hex"])?,
                &unhex(&context["public_key_hex"])?,
            ))
        })()
        .unwrap_or(false)
    }
}

#[test]
fn shared_ready_composition_and_rejection() {
    let corpus: Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/ready.json")).unwrap();
    let r = Reference {
        maps: serde_json::from_str(registry::READY_REGISTRY_JSON).unwrap(),
        domains: serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).unwrap(),
        profiles: serde_json::from_str(registry::CRYPTO_PROFILES_JSON).unwrap(),
    };
    let record: Value = serde_json::from_str(registry::RECORD_REGISTRY_JSON).unwrap();
    assert_eq!(corpus["schema_sha256"], registry::SCHEMA_SHA256);
    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 8);
    for v in vectors {
        let proof = unhex(&v["identity_proof_hex"]).unwrap();
        let m = r.material(&v["context"], &proof).unwrap();
        for (key, value) in m.as_object().unwrap() {
            assert_eq!(value, &v[key], "{} {key}", v["id"]);
        }
        assert_eq!(
            strict::sign(
                &unhex(&m["signature_message_hex"]).unwrap(),
                &unhex(&v["signing_seed_hex"]).unwrap()
            )
            .unwrap(),
            proof
        );
        let ready=r.encode("READY",&json!({"identity_proof_hex":hex(&proof),"confirmation_mac_hex":m["confirmation_mac_hex"]})).unwrap();
        let values = json!({"payload_length":ready.len(),"frame_type":registry::FRAME_READY});
        let mut envelope = Vec::new();
        for f in record["envelope"]["layout"].as_array().unwrap() {
            let value = f
                .get("const")
                .unwrap_or(&values[f["name"].as_str().unwrap()])
                .as_u64()
                .unwrap();
            let width = match f["type"].as_str().unwrap() {
                "uint8" => 1,
                "uint16_be" => 2,
                "uint32_be" => 4,
                _ => panic!("envelope"),
            };
            assert!(value < 1_u64 << (width * 8));
            envelope.extend(&value.to_be_bytes()[8 - width..]);
        }
        assert_eq!(hex(&ready), v["ready_hex"]);
        assert_eq!(hex(&envelope), v["envelope_header_hex"]);
        assert_eq!(hex(&[envelope, ready.clone()].concat()), v["wire_hex"]);
        assert!(r.verify(&v["context"], &ready));
    }
    let negatives = corpus["negatives"].as_array().unwrap();
    assert!(!negatives.is_empty());
    for n in negatives {
        assert_eq!(n["expected_error"], "ready_rejected");
        let source = vectors.iter().find(|v| v["id"] == n["source"]).unwrap();
        let mut context = source["context"].clone();
        for (key, value) in n["context_patch"].as_object().unwrap() {
            context[key] = value.clone();
        }
        assert!(
            !r.verify(&context, &unhex(&n["ready_hex"]).unwrap()),
            "{}",
            n["id"]
        );
    }
}
