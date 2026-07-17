use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use flowersec::controlplane::issuer::{IssuerError, Keyset};
use serde::Deserialize;
use std::{collections::HashMap, fs, path::PathBuf};

#[derive(Deserialize)]
struct RotationVectors {
    keys: Vec<RotationKey>,
    stages: Vec<RotationStage>,
}

#[derive(Deserialize)]
struct RotationKey {
    kid: String,
    seed_b64u: String,
    public_key_b64u: String,
}

#[derive(Deserialize)]
struct RotationStage {
    name: String,
    active_kid: String,
    verification_kids: Vec<String>,
}

#[test]
fn issuer_rotation_matches_shared_contract() {
    let vectors = load_vectors();
    let keys = vectors
        .keys
        .iter()
        .map(|key| (key.kid.clone(), decode_key(key)))
        .collect::<HashMap<_, _>>();
    let k1 = keys.get("k1").expect("k1");
    let k2 = keys.get("k2").expect("k2");
    let issuer = Keyset::new("k1", SigningKey::from_bytes(&k1.0)).expect("issuer");

    assert_stage(&issuer, &vectors.stages[0]);
    assert_eq!(
        issuer
            .rotate("k2", SigningKey::from_bytes(&k2.0))
            .expect_err("rotation must require prepublication"),
        IssuerError::MissingVerificationKey
    );

    issuer
        .add_verification_key("k2", k2.1)
        .expect("prepublish k2");
    assert_stage(&issuer, &vectors.stages[1]);
    assert_eq!(
        issuer
            .add_verification_key("k2", k1.1)
            .expect_err("conflicting key"),
        IssuerError::VerificationKeyConflict
    );

    issuer
        .rotate("k2", SigningKey::from_bytes(&k2.0))
        .expect("activate k2");
    assert_stage(&issuer, &vectors.stages[2]);
    assert_eq!(
        issuer
            .retire_verification_key("k2")
            .expect_err("active key cannot be retired"),
        IssuerError::ActiveVerificationKey
    );

    issuer.retire_verification_key("k1").expect("retire k1");
    assert_stage(&issuer, &vectors.stages[3]);
    assert_eq!(
        issuer
            .retire_verification_key("missing")
            .expect_err("missing key"),
        IssuerError::MissingVerificationKey
    );

    let mut snapshot = issuer.public_keys().expect("public keys");
    snapshot.clear();
    assert_stage(&issuer, &vectors.stages[3]);

    let exported: serde_json::Value =
        serde_json::from_slice(&issuer.export_tunnel_keyset().expect("export"))
            .expect("keyset json");
    assert_eq!(exported["keys"][0]["kid"], "k2");
}

fn load_vectors() -> RotationVectors {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testdata")
        .join("issuer_rotation_vectors.json");
    serde_json::from_slice(&fs::read(path).expect("read vectors")).expect("parse vectors")
}

fn decode_key(key: &RotationKey) -> ([u8; 32], VerifyingKey) {
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&key.seed_b64u)
        .expect("decode seed")
        .try_into()
        .expect("seed length");
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&key.public_key_b64u)
        .expect("decode public key")
        .try_into()
        .expect("public key length");
    (
        seed,
        VerifyingKey::from_bytes(&public).expect("valid public key"),
    )
}

fn assert_stage(issuer: &Keyset, expected: &RotationStage) {
    assert_eq!(
        issuer.current_kid().expect("current kid"),
        expected.active_kid,
        "stage {}",
        expected.name
    );
    let mut kids = issuer
        .public_keys()
        .expect("public keys")
        .into_keys()
        .collect::<Vec<_>>();
    kids.sort();
    assert_eq!(kids, expected.verification_kids, "stage {}", expected.name);
}
