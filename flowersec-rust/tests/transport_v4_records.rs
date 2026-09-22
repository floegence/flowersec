//! Fixed public bytes only; no runtime READY, epoch/scope, replay or key-use authority.
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
pub(crate) mod registry;

use hkdf::Hkdf;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde_json::{Value, json};
use sha2::Sha256;

pub(crate) fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

pub(crate) fn unhex(value: &Value) -> Vec<u8> {
    let value = text(value);
    assert!(value.len().is_multiple_of(2));
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

pub(crate) fn integer(value: &Value) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| text(value).parse().unwrap())
}

pub(crate) fn layout(fields: &Value, values: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields.as_array().unwrap() {
        let width = match text(&field["type"]) {
            "uint8" => 1,
            "uint16_be" => 2,
            "uint32_be" => 4,
            "uint64_be" => 8,
            _ => panic!("unknown integer layout"),
        };
        let value = integer(field.get("const").unwrap_or(&values[text(&field["name"])]));
        assert!(width == 8 || value < 1 << (width * 8));
        if let Some(max) = field.get("max") {
            assert!(value <= integer(max));
        }
        out.extend_from_slice(&value.to_be_bytes()[8 - width..]);
    }
    out
}

pub(crate) fn domain(
    domains: &Value,
    name: &str,
    bytes: &[(&str, &[u8])],
    integers: &Value,
) -> Vec<u8> {
    let spec = domains
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .unwrap();
    let mut out = unhex(&spec["label_bytes"]);
    for part in spec["input_schema"]["parts"].as_array().unwrap() {
        let name = text(&part["name"]);
        match text(&part["encoding"]) {
            encoding @ ("raw" | "lp-bytes" | "lp-ascii" | "lp-map") => {
                let value = bytes.iter().find(|(key, _)| *key == name).unwrap().1;
                if let Some(length) = part.get("length") {
                    assert_eq!(value.len() as u64, integer(length));
                }
                if encoding == "lp-ascii" {
                    assert!(value.is_ascii());
                }
                if encoding != "raw" {
                    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
                }
                out.extend_from_slice(value);
            }
            encoding @ ("u8" | "u32" | "u64") => {
                if let Some(allowed) = part.get("enum") {
                    assert!(allowed.as_array().unwrap().contains(&integers[name]));
                }
                let kind = match encoding {
                    "u8" => "uint8",
                    "u32" => "uint32_be",
                    _ => "uint64_be",
                };
                out.extend(layout(&json!([{ "name": name, "type": kind }]), integers));
            }
            _ => panic!("unknown record domain"),
        }
    }
    out
}

pub(crate) fn key(algorithm: &str, bytes: &[u8]) -> LessSafeKey {
    let algorithm = match algorithm {
        "chacha20-poly1305" => &aead::CHACHA20_POLY1305,
        "aes-256-gcm" => &aead::AES_256_GCM,
        _ => panic!("unknown record algorithm"),
    };
    LessSafeKey::new(UnboundKey::new(algorithm, bytes).unwrap())
}

#[test]
fn shared_record_bytes_and_authentication() {
    let corpus: Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/records.json")).unwrap();
    let registry: Value = serde_json::from_str(registry::RECORD_REGISTRY_JSON).unwrap();
    let domains: Value = serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).unwrap();
    assert_eq!(corpus["schema_sha256"], registry::SCHEMA_SHA256);
    let vectors = corpus["vectors"].as_array().unwrap();
    let negatives = corpus["negatives"].as_array().unwrap();
    assert!(!vectors.is_empty() && !negatives.is_empty());
    for vector in vectors {
        let profile = text(&vector["profile"]);
        let algorithm = text(&registry["profiles"][profile]["record_aead"]);
        assert_eq!(vector["algorithm"], algorithm);
        let header = layout(&registry["header"], vector);
        let nonce = layout(&registry["nonce"], vector);
        let plain = unhex(&vector["plaintext_hex"]);
        let envelope = layout(
            &registry["envelope"]["layout"],
            &json!({
                "payload_length": header.len() + plain.len() + integer(&registry["profiles"][profile]["tag_bytes"]) as usize,
                "frame_type": vector["frame_type"],
            }),
        );
        let hash = unhex(&vector["handshake_hash_hex"]);
        let info = domain(
            &domains,
            "record_key",
            &[("profile", profile.as_bytes()), ("handshake_hash", &hash)],
            vector,
        );
        let mut derived = [0_u8; 32];
        Hkdf::<Sha256>::from_prk(&unhex(&vector["epoch_root_hex"]))
            .unwrap()
            .expand(&info, &mut derived)
            .unwrap();
        let aad = domain(
            &domains,
            "record_aad",
            &[
                ("profile", profile.as_bytes()),
                ("envelope_header", &envelope),
                ("record_header", &header),
            ],
            vector,
        );
        let cipher = key(algorithm, &derived);
        let mut ciphertext = plain.clone();
        cipher
            .seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                Aad::from(&aad),
                &mut ciphertext,
            )
            .unwrap();
        let wire = [&envelope[..], &header[..], &ciphertext[..]].concat();
        for (actual, expected) in [
            (&header[..], "record_header_hex"),
            (&nonce[..], "nonce_hex"),
            (&envelope[..], "envelope_header_hex"),
            (&info[..], "key_info_hex"),
            (&derived[..], "key_hex"),
            (&aad[..], "aad_hex"),
            (&ciphertext[..], "ciphertext_hex"),
            (&wire[..], "wire_hex"),
        ] {
            assert_eq!(
                actual,
                unhex(&vector[expected]),
                "{} {expected}",
                vector["id"]
            );
        }
        let mut received = ciphertext;
        assert_eq!(
            cipher
                .open_in_place(
                    Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                    Aad::from(&aad),
                    &mut received
                )
                .unwrap(),
            plain
        );
    }
    for negative in negatives {
        let original = vectors
            .iter()
            .find(|v| v["id"] == negative["source"])
            .unwrap();
        assert_eq!(negative["expected_error"], "record_authentication_failed");
        assert!(["key", "nonce", "aad", "ciphertext"].contains(&text(&negative["field"])));
        let mut vector = original.clone();
        vector[format!("{}_hex", text(&negative["field"]))] = negative["value_hex"].clone();
        let cipher = key(text(&vector["algorithm"]), &unhex(&vector["key_hex"]));
        let nonce = unhex(&vector["nonce_hex"]);
        let aad = unhex(&vector["aad_hex"]);
        let mut ciphertext = unhex(&vector["ciphertext_hex"]);
        // Tentative in-place contents remain private on error; no delivery.
        assert!(
            cipher
                .open_in_place(
                    Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                    Aad::from(&aad),
                    &mut ciphertext
                )
                .is_err(),
            "{}",
            negative["id"]
        );
        ciphertext.fill(0);
    }
}
