use flowersec::{Artifact, ArtifactLease, ArtifactSpendError, Connector, ConnectorOptions};
use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("artifact-v2") => {
            let artifact_path = required_argument(arguments.next(), "artifact JSON path")?;
            if arguments.next().is_some() {
                return Err("artifact-v2 accepts exactly one path".into());
            }
            inspect_opaque_artifact(Path::new(&artifact_path))
        }
        Some("connect-v2") => {
            let artifact_path = required_argument(arguments.next(), "artifact JSON path")?;
            let trust_root_path = required_argument(arguments.next(), "trust root DER path")?;
            let receipt_path = required_argument(arguments.next(), "spend receipt path")?;
            if arguments.next().is_some() {
                return Err("connect-v2 accepts exactly three paths".into());
            }
            connect_opaque_artifact(
                Path::new(&artifact_path),
                Path::new(&trust_root_path),
                PathBuf::from(receipt_path),
            )
            .await
        }
        _ => Err(usage().into()),
    }
}

fn inspect_opaque_artifact(artifact_path: &Path) -> Result<(), Box<dyn Error>> {
    let artifact = Artifact::parse(std::fs::read(artifact_path)?)?;
    let lease = ArtifactLease::new(artifact, || async { Ok(()) });
    println!("artifact={:?}", lease.artifact());
    println!("spend_committed={}", lease.is_committed());
    Ok(())
}

async fn connect_opaque_artifact(
    artifact_path: &Path,
    trust_root_path: &Path,
    receipt_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let artifact = Artifact::parse(std::fs::read(artifact_path)?)?;
    let mut lease = ArtifactLease::new(artifact, move || {
        let receipt_path = receipt_path.clone();
        async move { write_spend_receipt(receipt_path).await }
    });
    let connector = Connector::new(ConnectorOptions {
        trust_roots_der: vec![std::fs::read(trust_root_path)?],
        connect_timeout: Duration::from_secs(15),
    })?;
    let session = connector
        .connect(&mut lease, CancellationToken::new())
        .await
        .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
    println!("session=ready");
    println!("liveness={:?}", session.probe_liveness().await?);
    session.close().await?;
    Ok(())
}

async fn write_spend_receipt(receipt_path: PathBuf) -> Result<(), ArtifactSpendError> {
    tokio::task::spawn_blocking(move || {
        let mut receipt = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&receipt_path)
            .map_err(|_| ArtifactSpendError::CommitFailed)?;
        receipt
            .write_all(b"flowersec-v2-artifact-spent\n")
            .and_then(|()| receipt.sync_all())
            .map_err(|_| ArtifactSpendError::CommitFailed)
    })
    .await
    .map_err(|_| ArtifactSpendError::CommitFailed)?
}

fn required_argument(value: Option<String>, name: &str) -> Result<String, Box<dyn Error>> {
    value.ok_or_else(|| format!("missing {name}; {}", usage()).into())
}

fn usage() -> &'static str {
    "usage: flowersec-rust-client-example artifact-v2 <artifact-json> | connect-v2 <artifact-json> <trust-root-der> <spend-receipt>"
}
