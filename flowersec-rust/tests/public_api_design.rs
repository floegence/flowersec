use flowersec::{
    ArtifactLease, ArtifactSource, ArtifactSourceError, ConnectionController,
    ConnectionControllerOptions, ConnectorOptions, RetryDisposition, RpcPeer, RpcPeerExt,
    SessionError, SessionTermination, StreamMetadata, StreamMetadataError, connect,
};
use serde::{Deserialize, Serialize};
use std::{fs, num::NonZeroU64, path::Path, process::Command, sync::Arc};

#[derive(Serialize)]
struct TypedRequest {
    value: String,
}

#[derive(Deserialize)]
struct TypedResponse {
    accepted: bool,
}

async fn compile_public_api(lease: &mut ArtifactLease, peer: &dyn RpcPeer) {
    let options = ConnectorOptions::new(vec![vec![1]]).expect("explicit trust roots");
    let _ = connect(lease, options).await;
    let response = peer
        .call_typed::<TypedRequest, TypedResponse>(
            7,
            &TypedRequest {
                value: "request".into(),
            },
        )
        .await;
    if let Ok(response) = response {
        let _ = response.accepted;
    }
}

#[test]
fn exposes_explicit_options_and_typed_rpc() {
    let _ = compile_public_api;
}

#[test]
fn connection_controller_requires_a_refreshable_artifact_source() {
    fn compile_controller(source: Arc<dyn ArtifactSource>) -> ConnectionController {
        let connector = ConnectorOptions::new(vec![vec![1]]).expect("explicit trust roots");
        ConnectionController::new(
            source,
            ConnectionControllerOptions::new(connector)
                .with_maximum_attempts(NonZeroU64::new(2).expect("nonzero")),
        )
    }
    let _ = compile_controller;
}

#[test]
fn artifact_source_failures_require_structured_dispositions() {
    assert_eq!(
        ArtifactSourceError::terminal().disposition(),
        RetryDisposition::Terminal
    );
    assert_eq!(
        ArtifactSourceError::retryable().disposition(),
        RetryDisposition::Retryable
    );
}

#[test]
fn public_error_codes_expose_direct_stable_strings() {
    let connect_error = ConnectorOptions::new(vec![]).expect_err("empty trust roots are invalid");
    assert_eq!(connect_error.as_str(), "invalid_input");
    assert_eq!(SessionError::Timeout.as_str(), "timeout");
    assert_eq!(SessionError::GoingAway.as_str(), "going_away");
    assert_eq!(SessionError::StreamRejected.as_str(), "stream_rejected");
}

#[test]
fn stream_metadata_is_validated_before_opening_a_stream() {
    let metadata = StreamMetadata::try_from(serde_json::json!({"purpose": "health", "attempt": 1}))
        .expect("valid metadata");
    assert_eq!(metadata.values()["purpose"], "health");
    assert!(matches!(
        StreamMetadata::try_from(serde_json::json!({"fraction": 1.5})),
        Err(StreamMetadataError::InvalidValue)
    ));
    assert!(StreamMetadata::empty().values().is_empty());
}

#[test]
fn artifact_lease_does_not_expose_spend_state() {
    let source = include_str!("../src/artifact_v2.rs");
    assert!(!source.contains("pub fn is_committed"));
}

#[test]
fn artifact_lease_does_not_expose_its_artifact() {
    let fixture = tempfile::tempdir().expect("create lease API probe directory");
    let crate_path = env!("CARGO_MANIFEST_DIR").replace('\\', "\\\\");
    fs::write(
        fixture.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"flowersec-lease-opacity-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nflowersec = {{ path = \"{crate_path}\" }}\n"
        ),
    )
    .expect("write lease API probe manifest");
    fs::create_dir(fixture.path().join("src")).expect("create lease API probe source directory");
    fs::write(
        fixture.path().join("src/main.rs"),
        "use flowersec::ArtifactLease;\n\nfn inspect(lease: &ArtifactLease) { let _ = lease.artifact(); }\nfn main() {}\n",
    )
    .expect("write lease API probe source");

    let output = Command::new("rustup")
        .args(["run", "1.88.0", "cargo", "check", "--offline", "--quiet"])
        .current_dir(fixture.path())
        .env("CARGO_TARGET_DIR", fixture.path().join("target"))
        .output()
        .expect("run lease API probe");
    assert!(
        !output.status.success(),
        "ArtifactLease unexpectedly exposes its artifact"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("artifact"),
        "lease opacity probe failed for an unrelated reason:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn rustdoc_uses_real_unversioned_portable_types() {
    let fixture = tempfile::tempdir().expect("create rustdoc target directory");
    let output = Command::new("rustup")
        .args([
            "run",
            "1.88.0",
            "cargo",
            "doc",
            "--no-deps",
            "--quiet",
            "--target-dir",
        ])
        .arg(fixture.path())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("generate public rustdoc");
    assert!(
        output.status.success(),
        "cargo doc failed:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let mut pages = Vec::new();
    collect_html(&fixture.path().join("doc/flowersec"), &mut pages);
    assert!(!pages.is_empty(), "cargo doc produced no Flowersec pages");
    for page in pages {
        if matches!(
            page.file_name().and_then(|name| name.to_str()),
            Some("index.html" | "all.html" | "sidebar-items.js")
        ) {
            continue;
        }
        let source = fs::read_to_string(&page).expect("read rustdoc page");
        for name in [
            "SessionV2",
            "ByteStreamV2",
            "IncomingStreamV2",
            "RpcPeerV2",
            "UnreliableMessageChannelV2",
            "JsonObjectV2",
        ] {
            assert!(
                !source.contains(name),
                "public rustdoc {} leaked {name}",
                page.display(),
            );
        }
    }
}

fn collect_html(directory: &Path, pages: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(directory).expect("read rustdoc directory") {
        let path = entry.expect("read rustdoc entry").path();
        if path.is_dir() {
            collect_html(&path, pages);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "html")
        {
            pages.push(path);
        }
    }
}

#[test]
fn session_termination_is_a_stable_value() {
    let termination = SessionTermination {
        error: SessionError::Closed,
    };
    assert_eq!(termination.error, SessionError::Closed);
}

#[test]
fn session_error_names_cover_portable_session_states() {
    assert_eq!(SessionError::GoingAway.as_str(), "going_away");
    assert_eq!(SessionError::StreamRejected.as_str(), "stream_rejected");
    assert_eq!(SessionError::StreamReset.as_str(), "stream_reset");
    assert_eq!(SessionError::RekeyFailed.as_str(), "rekey_failed");
    assert_eq!(SessionError::LivenessFailed.as_str(), "liveness_failed");
}

#[test]
fn default_public_api_does_not_expose_fuzzing() {
    let fixture = tempfile::tempdir().expect("create default API probe directory");
    let crate_path = env!("CARGO_MANIFEST_DIR").replace('\\', "\\\\");
    fs::write(
        fixture.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"flowersec-default-api-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nflowersec = {{ path = \"{crate_path}\" }}\n"
        ),
    )
    .expect("write default API probe manifest");
    fs::create_dir(fixture.path().join("src")).expect("create default API probe source directory");
    fs::write(
        fixture.path().join("src/main.rs"),
        "use flowersec::fuzzing;\n\nfn main() { let _ = fuzzing::parse_protocol; }\n",
    )
    .expect("write default API probe source");

    let output = Command::new("cargo")
        .args(["check", "--offline", "--quiet"])
        .current_dir(fixture.path())
        .env("CARGO_TARGET_DIR", fixture.path().join("target"))
        .output()
        .expect("run default API probe");

    assert!(
        !output.status.success(),
        "default crate unexpectedly exposes fuzzing:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fuzzing"),
        "default API probe failed for an unrelated reason:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}
