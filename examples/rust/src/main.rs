mod capacity;
mod large_rpc;
mod listener;
mod parity;
use bytes::Bytes;
use flowersec::{
    Artifact, ArtifactLease, ArtifactSpendError, ConnectError, ConnectorOptions, RpcCallError,
    RpcPeerExt, Session, SessionError, StreamMetadata, connect,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const ECHO_RPC_TYPE_ID: u32 = 7_001;
const NOTIFICATION_TYPE_ID: u32 = 7_002;
const ECHO_STREAM_KIND: &str = "parity.echo";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ValuePayload {
    value: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", failure_message(error.as_ref()));
            ExitCode::FAILURE
        }
    }
}

fn failure_message(error: &(dyn Error + 'static)) -> String {
    if let Some(error) = error.downcast_ref::<ConnectError>() {
        return format!("connection_error={}", error.as_str());
    }
    if let Some(error) = error.downcast_ref::<RpcCallError>() {
        return match error {
            RpcCallError::Session(error) => format!("session_error={}", error.as_str()),
            RpcCallError::Application(error) => format!("rpc_error={}", error.code()),
        };
    }
    if let Some(error) = error.downcast_ref::<SessionError>() {
        return format!("session_error={}", error.as_str());
    }
    error.to_string()
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    if env::var_os("FSEC_REQUIRE_FRESH_LEG_PROOF").is_some() {
        return Err("unsupported: flowersec/5 cannot prove possession by a designated peer on a fresh challenge for this leg".into());
    }
    if env::var_os("FSEC_REQUIRE_ROLLBACK_PROTECTION").is_some() {
        return Err(
            "unsupported: the local receipt store has no independent rollback history".into(),
        );
    }
    match arguments.next().as_deref() {
        Some("capacity-v5") if arguments.next().is_none() => {
            capacity::run().await.map_err(Into::into)
        }
        Some("listen-v5") => listener::serve(arguments).await,
        Some("artifact-v5") => {
            let artifact_path = required_argument(arguments.next(), "artifact JSON path")?;
            if arguments.next().is_some() {
                return Err("artifact-v5 accepts exactly one path".into());
            }
            inspect_opaque_artifact(Path::new(&artifact_path))
        }
        Some(mode @ ("connect-v5" | "echo-v5" | "serve-tunnel-v5")) => {
            let artifact_path = required_argument(arguments.next(), "artifact JSON path")?;
            let trust_root_path = required_argument(arguments.next(), "trust root DER path")?;
            let receipt_path = required_argument(arguments.next(), "spend receipt path")?;
            if arguments.next().is_some() {
                return Err("connect-v5 accepts exactly three paths".into());
            }
            connect_opaque_artifact(
                Path::new(&artifact_path),
                Path::new(&trust_root_path),
                PathBuf::from(receipt_path),
                mode,
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
    mode: &str,
) -> Result<(), Box<dyn Error>> {
    let artifact = Artifact::parse(std::fs::read(artifact_path)?)?;
    let lease = ArtifactLease::new(artifact, move || {
        let receipt_path = receipt_path.clone();
        async move { write_spend_receipt(receipt_path).await }
    });
    let mut options =
        ConnectorOptions::new().with_trust_roots_der(vec![std::fs::read(trust_root_path)?])?;
    if let Ok(origin) = env::var("FSEC_ORIGIN") {
        options = options.with_websocket_origin(origin)?;
    }
    if let Some(ingress) = env::var_os("FSEC_TUNNEL_INGRESS") {
        options = options.with_tunnel_ingress(ingress.to_str().ok_or("invalid local ingress")?)?;
    }
    let tunnel_server = mode == "serve-tunnel-v5";
    if tunnel_server && env::var_os("FSEC_TUNNEL_INGRESS").is_none() {
        return Err("FSEC_TUNNEL_INGRESS is required for serve-tunnel-v5".into());
    }
    let default_role = if tunnel_server {
        large_rpc::Role::Serve
    } else {
        large_rpc::Role::Call
    };
    let large = large_rpc::Role::configured(default_role)?;
    let serving = large.map_or(tunnel_server, |role| role == large_rpc::Role::Serve);
    let accepted =
        (large == Some(large_rpc::Role::Serve)).then(|| Arc::new(AtomicBool::new(false)));
    let (signal, completion) = if parity::wide_workload() && !serving {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    if serving || large.is_some() || parity::wide_workload() {
        let binary = accepted.clone().map(large_rpc::BinaryEcho::observed);
        options = options.with_rpc_handlers(listener::echo_handlers(signal, binary)?);
    }
    if let Some(limit) = frame_limit(large.is_some())? {
        options = options.with_rpc_frame_limit(limit);
    }
    if let Some(limit) = concurrency()? {
        options = options.with_rpc_concurrency(limit);
    }
    let serving_streams = if serving {
        let mut handlers = flowersec::StreamHandlers::new(Default::default())?;
        handlers.handle_stream(ECHO_STREAM_KIND, listener::EchoStream)?;
        Some(handlers)
    } else {
        None
    };
    let session = connect(lease, options).await?;
    println!("session=ready");
    let result: Result<(), Box<dyn Error>> = async {
        if let Some(mut streams) = serving_streams {
            let stop = tokio_util::sync::CancellationToken::new();
            let outbound = async {
                if parity::wide_workload()
                    && let Err(error) = listener::serve_wide(session.as_ref()).await
                {
                    stop.cancel();
                    return Err(error as Box<dyn Error>);
                }
                Ok(())
            };
            let serving =
                async { tokio::join!(outbound, streams.serve(session.as_ref(), stop.clone())) };
            let (result, served) = if accepted.is_some() {
                tokio::time::timeout(large_rpc::TIMEOUT, serving).await?
            } else {
                serving.await
            };
            result?;
            match served {
                Ok(()) | Err(flowersec::SessionError::Closed) => (),
                Err(error) => return Err(error.into()),
            }
            if let Some(accepted) = &accepted
                && !accepted.load(Ordering::Acquire)
            {
                return Err("peer closed without an authorized 32 MiB echo".into());
            }
        } else {
            if let Some(done) = completion {
                tokio::time::timeout(std::time::Duration::from_secs(120), async {
                    parity::exercise_wide(session.as_ref()).await?;
                    tokio::select! {
                        biased;
                        result = done => result?,
                        end = session.wait_termination() => return Err(end.error.into()),
                    }
                    Ok::<_, Box<dyn Error + Send + Sync>>(())
                })
                .await?
                .map_err(|e| e as Box<dyn Error>)?;
            }
            if large == Some(large_rpc::Role::Call) {
                large_rpc::call(session.as_ref()).await?;
            } else if mode == "echo-v5" {
                echo(session.as_ref()).await?;
            } else {
                run_application_workflow(session.as_ref()).await?;
            }
        }
        Ok(())
    }
    .await;
    let closed = session.close().await;
    result?;
    closed?;
    if let Some(role) = large {
        let outcome = if role == large_rpc::Role::Call {
            "verified"
        } else {
            "accepted"
        };
        println!("binary_echo={outcome} session=closed");
    } else if mode == "echo-v5" {
        println!("echo=ok session=closed");
    }
    Ok(())
}

async fn echo(session: &dyn Session) -> Result<(), RpcCallError> {
    let request = ValuePayload {
        value: "ping".to_owned(),
    };
    let response: ValuePayload = session.rpc().call_typed(ECHO_RPC_TYPE_ID, &request).await?;
    if response != request {
        return Err(SessionError::OperationFailed.into());
    }
    Ok(())
}

fn frame_limit(large: bool) -> Result<Option<flowersec::RpcFrameLimit>, Box<dyn Error>> {
    let Some(value) = env::var_os("FSEC_RPC_FRAME_BYTES") else {
        if large {
            return Err("large RPC requires FSEC_RPC_FRAME_BYTES on both endpoints".into());
        }
        return Ok(None);
    };
    let bytes = value.to_str().ok_or("invalid RPC frame limit")?.parse()?;
    if large && bytes < large_rpc::MIN_FRAME_BYTES {
        return Err(format!(
            "32 MiB echo needs FSEC_RPC_FRAME_BYTES >= {}",
            large_rpc::MIN_FRAME_BYTES
        )
        .into());
    }
    Ok(Some(
        flowersec::RpcFrameLimit::new(bytes).ok_or("invalid RPC frame limit")?,
    ))
}

fn concurrency() -> Result<Option<std::num::NonZeroU16>, Box<dyn Error>> {
    let Some(value) = env::var_os("FSEC_RPC_CONCURRENT_REQUESTS") else {
        return Ok(None);
    };
    let limit: std::num::NonZeroU16 = value.to_str().ok_or("invalid RPC concurrency")?.parse()?;
    if parity::wide_workload() && limit.get() < 2 {
        return Err("wide RPC needs FSEC_RPC_CONCURRENT_REQUESTS >= 2".into());
    }
    Ok(Some(limit))
}

async fn run_application_workflow(session: &dyn Session) -> Result<(), Box<dyn Error>> {
    echo(session).await?;
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
    read_exact_message(stream.as_ref(), b"world").await?;

    let round_trip = session.probe_liveness().await?;
    println!("rpc=ok notification=ok stream=ok liveness={round_trip:?}");
    Ok(())
}

async fn read_exact_message(
    stream: &dyn flowersec::ByteStream,
    mut expected: &[u8],
) -> Result<(), flowersec::SessionError> {
    while let Some(bytes) = stream.read().await? {
        expected = expected
            .strip_prefix(bytes.as_ref())
            .ok_or(flowersec::SessionError::OperationFailed)?;
    }
    if expected.is_empty() {
        Ok(())
    } else {
        Err(flowersec::SessionError::OperationFailed)
    }
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

async fn write_spend_receipt(receipt_path: PathBuf) -> Result<(), ArtifactSpendError> {
    tokio::task::spawn_blocking(move || {
        let mut receipt = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&receipt_path)
            .map_err(|_| ArtifactSpendError::CommitFailed)?;
        receipt
            .write_all(b"flowersec-v5-artifact-spent\n")
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
    "usage: flowersec-rust-client-example artifact-v5 <artifact-json> | connect-v5|echo-v5|serve-tunnel-v5 <artifact-json> <trust-root-der> <spend-receipt> | listen-v5 <bind-address> <certificate-der> <key-der> <approval-directory>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_session_codes_and_keeps_application_errors_separate() {
        assert_eq!(
            failure_message(&SessionError::Closed),
            "session_error=closed"
        );
        let interrupted = RpcCallError::Session(SessionError::StreamReset);
        assert_eq!(failure_message(&interrupted), "session_error=stream_reset");
        let denied = flowersec::RpcError::new(403, Some("private detail".into())).unwrap();
        assert_eq!(
            failure_message(&RpcCallError::Application(denied)),
            "rpc_error=403"
        );
    }
}
