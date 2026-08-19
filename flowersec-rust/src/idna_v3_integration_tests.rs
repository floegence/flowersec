use crate::{
    artifact_v3::{CarrierWireV3, normalize_url_v3},
    idna_v3::{UNICODE_VERSION, lookup_ascii},
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    unicode_version: String,
    positive: Vec<PositiveVector>,
    negative: Vec<NegativeVector>,
    url_normalization: URLNormalizationVectors,
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

#[derive(Debug, Deserialize)]
struct URLNormalizationVectors {
    positive: Vec<URLPositiveVector>,
    negative: Vec<URLNegativeVector>,
}

#[derive(Debug, Deserialize)]
struct URLPositiveVector {
    id: String,
    carrier: CarrierWireV3,
    path_kind: String,
    input: String,
    normalized: String,
}

#[derive(Debug, Deserialize)]
struct URLNegativeVector {
    id: String,
    carrier: CarrierWireV3,
    path_kind: String,
    input: String,
    error_code: String,
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

#[test]
fn artifact_url_normalizer_consumes_every_shared_vector() {
    let vectors = fixture().url_normalization;
    assert!(!vectors.positive.is_empty());
    assert!(!vectors.negative.is_empty());
    for vector in vectors.positive {
        assert_eq!(
            normalize_url_v3(&vector.path_kind, vector.carrier, &vector.input).as_deref(),
            Ok(vector.normalized.as_str()),
            "{}",
            vector.id
        );
    }
    for vector in vectors.negative {
        assert_eq!(vector.error_code, "invalid_artifact", "{}", vector.id);
        assert!(
            normalize_url_v3(&vector.path_kind, vector.carrier, &vector.input).is_err(),
            "{}",
            vector.id
        );
    }
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../testdata/transport_v3/idna_vectors.json"
    ))
    .expect("decode IDNA vectors")
}
