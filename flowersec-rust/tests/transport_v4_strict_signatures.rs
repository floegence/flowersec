//! Shared strict corpus through Dalek public point APIs and ring verification.
use serde::Deserialize;

#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "../src/strict_ed25519_v4_reference.rs"]
mod strict;

#[derive(Deserialize)]
struct Vector {
    id: String,
    message_hex: String,
    public_key_hex: String,
    signature_hex: String,
    accept: bool,
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn strict_acceptance_and_signer_output_gate() {
    #[derive(Deserialize)]
    struct Corpus {
        schema_sha256: String,
        policy_revision: u64,
        vectors: Vec<Vector>,
    }
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../testdata/transport_v4/strict_signatures.json"
    ))
    .unwrap();
    let policy: serde_json::Value =
        serde_json::from_str(registry::STRICT_ED25519_POLICY_JSON).unwrap();
    assert_eq!(corpus.schema_sha256, registry::SCHEMA_SHA256);
    assert_eq!(Some(corpus.policy_revision), policy["revision"].as_u64());
    assert!(!corpus.vectors.is_empty());
    for vector in corpus.vectors {
        let message = hex(&vector.message_hex);
        let key = hex(&vector.public_key_hex);
        let signature = hex(&vector.signature_hex);
        assert_eq!(
            strict::verify(&signature, &message, &key),
            vector.accept,
            "{}",
            vector.id
        );
        let mut calls = 0;
        let result = strict::sign_once(&message, || {
            calls += 1;
            Ok((key.clone(), signature.clone()))
        });
        assert_eq!(calls, 1, "{}", vector.id);
        if vector.accept {
            assert_eq!(result.unwrap(), signature, "{}", vector.id);
        } else {
            assert_eq!(
                result.unwrap_err(),
                registry::STRICT_ED25519_SIGNING_FAILURE,
                "{}",
                vector.id
            );
        }
    }
}

#[test]
fn public_fixture_signing_and_stable_failures() {
    #[derive(Deserialize)]
    struct Corpus {
        signing_seed_hex: String,
        vectors: Vec<Vector>,
    }
    let corpus: Corpus =
        serde_json::from_str(include_str!("../../testdata/transport_v4/signatures.json")).unwrap();
    let seed = hex(&corpus.signing_seed_hex);
    for vector in corpus.vectors.iter().filter(|v| v.accept) {
        assert_eq!(
            strict::sign(&hex(&vector.message_hex), &seed).unwrap(),
            hex(&vector.signature_hex),
            "{}",
            vector.id
        );
    }
    for length in [0, 31, 33, 64] {
        assert_eq!(
            strict::sign(b"message", &vec![0; length]).unwrap_err(),
            registry::STRICT_ED25519_SIGNING_FAILURE
        );
    }
    let mut calls = 0;
    let result = strict::sign_once(b"message", || {
        calls += 1;
        Err("provider detail")
    });
    assert_eq!(calls, 1);
    assert_eq!(
        result.unwrap_err(),
        registry::STRICT_ED25519_SIGNING_FAILURE
    );
}
