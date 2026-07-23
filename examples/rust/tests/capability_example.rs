use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn artifact_subcommand_keeps_the_unspent_artifact_opaque() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../testdata/transport_v2/artifact_vectors.json"
    ))
    .unwrap();
    let artifact = fixture["positive"][0]["artifact_json"].as_str().unwrap();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "flowersec-rust-v2-example-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&base).unwrap();
    let artifact_path = base.join("artifact.json");
    fs::write(&artifact_path, artifact).unwrap();

    let output = run_artifact(&artifact_path);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "artifact=Artifact { <opaque> }\nspend_committed=false\n"
    );

    fs::remove_dir_all(base).unwrap();
}

fn run_artifact(artifact_path: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_flowersec-rust-client-example"))
        .args(["artifact-v2"])
        .arg(artifact_path)
        .output()
        .unwrap()
}
