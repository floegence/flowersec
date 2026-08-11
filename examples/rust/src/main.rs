use flowersec::{Artifact, ArtifactLease, ArtifactSpendError, ConnectorOptions, connect};
use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
};

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
    println!("artifact={artifact:?}");
    let _lease = ArtifactLease::new(artifact, || async { Ok(()) });
    Ok(())
}

async fn connect_opaque_artifact(
    artifact_path: &Path,
    trust_root_path: &Path,
    receipt_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let artifact = Artifact::parse(std::fs::read(artifact_path)?)?;
    let lease = ArtifactLease::new(artifact, move || {
        let receipt_path = receipt_path.clone();
        async move { write_spend_receipt(receipt_path).await }
    });
    let options = ConnectorOptions::new(vec![std::fs::read(trust_root_path)?])?;
    let session = match connect(lease, options).await {
        Ok(session) => session,
        Err(error) => {
            eprintln!("connection_error={}", error.as_str());
            return Err(error.to_string().into());
        }
    };
    println!("session=ready");
    match session.probe_liveness().await {
        Ok(round_trip) => println!("liveness={round_trip:?}"),
        Err(error) => {
            eprintln!("session_error={}", error.as_str());
            return Err(error.to_string().into());
        }
    }
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
            .map_err(|_| ArtifactSpendError::CommitFailed)?;
        drop(receipt);
        sync_parent_directory(&receipt_path).map_err(|_| ArtifactSpendError::CommitFailed)
    })
    .await
    .map_err(|_| ArtifactSpendError::CommitFailed)?
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "receipt path has no parent"))?;
    let directory = std::fs::File::open(parent)?;
    directory.sync_all()
}

fn required_argument(value: Option<String>, name: &str) -> Result<String, Box<dyn Error>> {
    value.ok_or_else(|| format!("missing {name}; {}", usage()).into())
}

fn usage() -> &'static str {
    "usage: flowersec-rust-client-example artifact-v2 <artifact-json> | connect-v2 <artifact-json> <trust-root-der> <spend-receipt>"
}
