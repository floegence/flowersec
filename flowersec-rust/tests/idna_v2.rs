use flowersec::idna_v2::{UNICODE_VERSION, lookup_ascii};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    unicode_version: String,
    positive: Vec<PositiveVector>,
    negative: Vec<NegativeVector>,
}

#[derive(Debug, Deserialize)]
struct PositiveVector {
    id: String,
    input: String,
    ascii: String,
}

#[derive(Debug, Deserialize)]
struct NegativeVector {
    id: String,
    input: String,
}

#[test]
fn lookup_ascii_uses_frozen_unicode_15_1_uts46() {
    let fixture = fixture();
    assert_eq!(fixture.unicode_version, UNICODE_VERSION);
    for vector in fixture.positive {
        assert_eq!(
            lookup_ascii(&vector.input).as_deref(),
            Ok(vector.ascii.as_str()),
            "{}",
            vector.id
        );
    }
}

#[test]
fn lookup_ascii_rejects_invalid_and_post_15_1_hosts() {
    for vector in fixture().negative {
        assert!(lookup_ascii(&vector.input).is_err(), "{}", vector.id);
    }
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../testdata/transport_v2/idna_vectors.json"
    ))
    .expect("decode IDNA vectors")
}
