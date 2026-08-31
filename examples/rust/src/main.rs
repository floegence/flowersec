use bytes::{Bytes, BytesMut};
use flowersec::{
    Artifact, ArtifactLease, ArtifactSpendError, ConnectorOptions, RpcPeerExt, Session,
    StreamMetadata, connect,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
};

const ECHO_RPC_TYPE_ID: u32 = 7_001;
const NOTIFICATION_TYPE_ID: u32 = 7_002;
const ECHO_STREAM_KIND: &str = "parity.echo";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ValuePayload {
    value: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("artifact-v3") => {
            let artifact_path = required_argument(arguments.next(), "artifact JSON path")?;
            if arguments.next().is_some() {
                return Err("artifact-v3 accepts exactly one path".into());
            }
            inspect_opaque_artifact(Path::new(&artifact_path))
        }
        Some("connect-v3") => {
            let artifact_path = required_argument(arguments.next(), "artifact JSON path")?;
            let trust_root_path = required_argument(arguments.next(), "trust root DER path")?;
            let receipt_path = required_argument(arguments.next(), "spend receipt path")?;
            if arguments.next().is_some() {
                return Err("connect-v3 accepts exactly three paths".into());
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
    let origin = env::var("FSEC_ORIGIN").map_err(|_| "FSEC_ORIGIN is required")?;
    let options = ConnectorOptions::new()
        .with_trust_roots_der(vec![std::fs::read(trust_root_path)?])?
        .with_websocket_origin(origin)?;
    let session = match connect(lease, options).await {
        Ok(session) => session,
        Err(error) => {
            eprintln!("connection_error={}", error.as_str());
            return Err(error.to_string().into());
        }
    };
    println!("session=ready");
    match run_application_workflow(session.as_ref()).await {
        Ok(()) => {}
        Err(error) => {
            eprintln!("session_error={}", error.as_str());
            return Err(error.to_string().into());
        }
    }
    session.close().await?;
    Ok(())
}

async fn run_application_workflow(session: &dyn Session) -> Result<(), flowersec::SessionError> {
    let request = ValuePayload {
        value: "ping".to_owned(),
    };
    let response: ValuePayload = session
        .rpc()
        .call_typed(ECHO_RPC_TYPE_ID, &request)
        .await
        .map_err(rpc_call_session_error)?;
    if response != request {
        return Err(flowersec::SessionError::OperationFailed);
    }
    session
        .rpc()
        .notify(NOTIFICATION_TYPE_ID, serde_json::json!({"value": "notify"}))
        .await?;
    let stream_cell = env::var("FSEC_EXAMPLE_STREAM_CELL").unwrap_or_else(|_| "direct".to_owned());
    let metadata = StreamMetadata::try_from(serde_json::json!({"cell": stream_cell}))
        .map_err(|_| flowersec::SessionError::OperationFailed)?;
    let stream = session.open_stream(ECHO_STREAM_KIND, metadata).await?;
    write_all(stream.as_ref(), Bytes::from_static(b"hello")).await?;
    stream.close_write().await?;
    let mut response = BytesMut::new();
    while let Some(chunk) = stream.read().await? {
        response.extend_from_slice(&chunk);
    }
    if response.as_ref() != b"world" {
        return Err(flowersec::SessionError::OperationFailed);
    }

    let round_trip = session.probe_liveness().await?;
    println!("rpc=ok notification=ok stream=ok liveness={round_trip:?}");
    Ok(())
}

async fn write_all(
    stream: &dyn flowersec::ByteStream,
    mut payload: Bytes,
) -> Result<(), flowersec::SessionError> {
    while !payload.is_empty() {
        let written = stream.write(payload.clone()).await?;
        if written == 0 || written > payload.len() {
            return Err(flowersec::SessionError::OperationFailed);
        }
        payload = payload.slice(written..);
    }
    Ok(())
}

fn rpc_call_session_error(error: flowersec::RpcCallError) -> flowersec::SessionError {
    match error {
        flowersec::RpcCallError::Session(error) => error,
        flowersec::RpcCallError::Application(_) => flowersec::SessionError::OperationFailed,
    }
}

async fn write_spend_receipt(receipt_path: PathBuf) -> Result<(), ArtifactSpendError> {
    tokio::task::spawn_blocking(move || {
        let mut receipt = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&receipt_path)
            .map_err(|_| ArtifactSpendError::CommitFailed)?;
        receipt
            .write_all(b"flowersec-v3-artifact-spent\n")
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
    "usage: flowersec-rust-client-example artifact-v3 <artifact-json> | connect-v3 <artifact-json> <trust-root-der> <spend-receipt>"
}
