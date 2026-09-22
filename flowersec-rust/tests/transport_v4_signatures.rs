//! Public-fixture signature primitives, not credential or runtime qualification.
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::Deserialize;
use std::collections::HashSet;

#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;

#[derive(Deserialize)]
struct Corpus {
    schema_sha256: String,
    signing_seed_hex: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    domain: Option<String>,
    message_hex: String,
    public_key_hex: String,
    signature_hex: String,
    accept: bool,
}

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn v4_signature_vectors() {
    let corpus: Corpus =
        serde_json::from_str(include_str!("../../testdata/transport_v4/signatures.json")).unwrap();
    assert_eq!(corpus.schema_sha256, registry::SCHEMA_SHA256);
    let key = Ed25519KeyPair::from_seed_unchecked(&hex(&corpus.signing_seed_hex)).unwrap();
    let mut covered = HashSet::new();
    for vector in &corpus.vectors {
        let message = hex(&vector.message_hex);
        let public = hex(&vector.public_key_hex);
        let signature = hex(&vector.signature_hex);
        assert_eq!(
            UnparsedPublicKey::new(&ED25519, &public)
                .verify(&message, &signature)
                .is_ok(),
            vector.accept,
            "{}",
            vector.id
        );
        if vector.accept {
            assert_eq!(key.public_key().as_ref(), public, "{}", vector.id);
            assert_eq!(key.sign(&message).as_ref(), signature, "{}", vector.id);
            covered.insert(vector.domain.clone());
        }
    }
    let domains: Vec<serde_json::Value> =
        serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).unwrap();
    for domain in domains {
        if domain["operation"] == "ed25519" {
            assert!(covered.contains(&Some(domain["name"].as_str().unwrap().to_owned())));
        }
    }
    assert!(covered.contains(&None), "missing external known answer");
}
