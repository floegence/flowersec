use flowersec::Artifact;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    positive: Vec<Positive>,
    negative: Vec<Negative>,
}
#[derive(Deserialize)]
struct Positive {
    artifact_json: String,
}
#[derive(Deserialize)]
struct Negative {
    kind: String,
    value: String,
}

#[test]
fn artifact_v2_shared_vectors() {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../testdata/transport_v2/artifact_vectors.json"
    ))
    .unwrap();
    for vector in vectors.positive {
        let artifact = Artifact::parse(&vector.artifact_json).unwrap();
        let debug = format!("{artifact:?}");
        assert_eq!(debug, "Artifact { <opaque> }");
        assert!(!debug.contains("routing-token"));
    }
    for vector in vectors
        .negative
        .into_iter()
        .filter(|v| v.kind == "artifact_json")
    {
        assert!(Artifact::parse(vector.value).is_err());
    }
}

#[test]
fn artifact_v2_rejects_nested_duplicate_and_unknown_fields() {
    let raw = include_str!("../../testdata/transport_v2/artifact_vectors.json");
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();
    let valid = value["positive"][0]["artifact_json"].as_str().unwrap();
    let nested_duplicate = valid.replace(
        "\"channel_id\":\"channel-1\"",
        "\"channel_id\":\"channel-1\",\"channel_id\":\"channel-1\"",
    );
    let top_level_duplicate = valid.replace("\"v\":2", "\"v\":2,\"profile\":\"flowersec/2\"");
    let array_nested_duplicate = valid.replace(
        "\"id\":\"w1\",\"carrier\":\"websocket\"",
        "\"id\":\"w1\",\"id\":\"w1\",\"carrier\":\"websocket\"",
    );
    let unknown = valid.replace(
        "\"channel_id\":\"channel-1\"",
        "\"channel_id\":\"channel-1\",\"secret\":true",
    );
    assert!(Artifact::parse(top_level_duplicate).is_err());
    assert!(Artifact::parse(nested_duplicate).is_err());
    assert!(Artifact::parse(array_nested_duplicate).is_err());
    assert!(Artifact::parse(unknown).is_err());
    assert!(Artifact::parse(format!("{valid} null")).is_err());
}
