use flowersec::ConnectArtifact;
use serde::Deserialize;
use serde_json::Value;
use std::{fs, path::PathBuf};

#[derive(Debug, Deserialize)]
struct Manifest {
    version: u32,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    id: String,
    input: String,
    ok: bool,
    normalized: Option<String>,
}

#[test]
fn shared_connect_artifact_fixtures() {
    let root = fixture_root();
    let manifest: Manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest.version, 1);

    for case in manifest.cases {
        let input = fs::read(root.join(&case.input)).expect("read fixture input");
        let result = ConnectArtifact::from_json(&input);
        assert_eq!(
            result.is_ok(),
            case.ok,
            "fixture {} returned {result:?}",
            case.id
        );
        let Some(expected_path) = case.normalized else {
            continue;
        };
        let artifact = result.expect("valid fixture");
        let actual: Value = serde_json::from_slice(&artifact.to_json().expect("encode artifact"))
            .expect("parse encoded artifact");
        let expected: Value = read_json(&root.join(expected_path));
        assert_eq!(actual, expected, "normalized fixture {}", case.id);
    }
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testdata")
        .join("connect_artifact_cases")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    serde_json::from_slice(&fs::read(path).expect("read JSON fixture")).expect("parse JSON fixture")
}
