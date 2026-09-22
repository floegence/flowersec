use serde::Deserialize;

#[path = "../src/profile_dh_v4_reference.rs"]
mod dh;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;

#[derive(Deserialize)]
struct Vector {
    id: String,
    profile: String,
    private_hex: String,
    public_hex: Option<String>,
    shared_hex: Option<String>,
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
fn shared_profile_dh_corpus() {
    #[derive(Deserialize)]
    struct Corpus {
        schema_sha256: String,
        policy_revision: u64,
        vectors: Vec<Vector>,
        keys: Vec<Vector>,
    }
    let corpus: Corpus =
        serde_json::from_str(include_str!("../../testdata/transport_v4/profile_dh.json")).unwrap();
    let policy: serde_json::Value = serde_json::from_str(registry::DH_POLICY_JSON).unwrap();
    assert_eq!(corpus.schema_sha256, registry::SCHEMA_SHA256);
    assert_eq!(Some(corpus.policy_revision), policy["revision"].as_u64());
    assert!(!corpus.vectors.is_empty() && !corpus.keys.is_empty());
    for (key_only, vectors) in [(false, corpus.vectors), (true, corpus.keys)] {
        for v in vectors {
            let private = hex(&v.private_hex);
            let public = hex(v.public_hex.as_deref().unwrap_or(""));
            let result = if key_only {
                dh::public(&v.profile, &private)
            } else {
                dh::derive(&v.profile, &private, &public)
            };
            if v.accept {
                let expected = if key_only {
                    public
                } else {
                    hex(v.shared_hex.as_deref().unwrap())
                };
                assert_eq!(result.unwrap(), expected, "{}", v.id);
            } else {
                assert_eq!(result.unwrap_err(), registry::DH_FAILURE, "{}", v.id);
            }
        }
    }
    assert_eq!(
        dh::derive("unregistered", &[0; 32], &[0; 32]).unwrap_err(),
        registry::DH_FAILURE
    );
}
