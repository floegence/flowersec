use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use flowersec::{
    Acceptor, AcceptorOptions, Artifact, ArtifactLease, ByteStream, Connector, ConnectorOptions,
    JsonObject, Session, SessionError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use tokio::{sync::Semaphore, task::JoinSet};
use tokio_util::sync::CancellationToken;

#[global_allocator]
static GLOBAL: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Server(ServerRequest),
    Client(ClientRequest),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerRequest {
    connections: Vec<ServerConnection>,
    certificate_chain_der_b64: Vec<String>,
    private_key_der_b64: String,
    max_inbound_streams: u16,
    accept_timeout_ms: u64,
    ready_path: PathBuf,
    plan: WorkloadPlan,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientRequest {
    artifacts_json: Vec<String>,
    trust_roots_der_b64: Vec<String>,
    connect_timeout_ms: u64,
    control_directory: Option<PathBuf>,
    plan: WorkloadPlan,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConnection {
    artifact_json: String,
    bind_address: SocketAddr,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadPlan {
    cold_operations: usize,
    cold_max_inflight: usize,
    cold_start_rate_per_second: u32,
    cold_operation_timeout_ms: u64,
    cold_phase_timeout_ms: u64,
    request_operations: usize,
    request_workers: usize,
    request_bytes: usize,
    request_operation_timeout_ms: u64,
    request_phase_timeout_ms: u64,
    bulk_warmup_bytes_per_direction: usize,
    bulk_score_bytes_per_direction: usize,
    bulk_phase_timeout_ms: u64,
    cleanup_timeout_ms: u64,
}

impl WorkloadPlan {
    fn validate(&self, connection_count: usize) -> Result<(), AnyError> {
        if self.cold_operations == 0
            || connection_count != self.cold_operations + 1
            || self.cold_max_inflight == 0
            || self.cold_max_inflight > self.cold_operations
            || self.cold_start_rate_per_second == 0
            || self.cold_operation_timeout_ms == 0
            || self.cold_phase_timeout_ms == 0
            || self.request_operations == 0
            || self.request_workers == 0
            || self.request_workers > self.request_operations
            || self.request_bytes < 2
            || self.request_operation_timeout_ms == 0
            || self.request_phase_timeout_ms == 0
            || self.bulk_warmup_bytes_per_direction == 0
            || self.bulk_score_bytes_per_direction == 0
            || self.bulk_phase_timeout_ms == 0
            || self.cleanup_timeout_ms == 0
        {
            return Err("release workload plan is invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
enum RoleResult {
    Server {
        resource: ResourceMeasurement,
        phases: Vec<PhaseMeasurement>,
        outbound_bulk: Vec<BulkPhaseDirection>,
    },
    Client {
        cold: Vec<ConnectOperation>,
        request_response: Vec<Operation>,
        bulk: ClientBulkResult,
        cleanup_duration_ns: i64,
        resource: ResourceMeasurement,
        phases: Vec<PhaseMeasurement>,
    },
}

#[derive(Clone, Copy, Debug, Serialize)]
struct ResourceSnapshot {
    at_unix_ns: i64,
    rss_bytes: u64,
    cpu_nanoseconds: u64,
    allocated_bytes: u64,
    open_fds: usize,
    runtime_threads: usize,
    tasks: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct ResourceMeasurement {
    started_at_unix_ns: i64,
    finished_at_unix_ns: i64,
    cpu_nanoseconds: u64,
    allocated_bytes: u64,
    start: ResourceSnapshot,
    finish: ResourceSnapshot,
}

#[derive(Debug, Serialize)]
struct PhaseMeasurement {
    phase: &'static str,
    resource: ResourceMeasurement,
    active_streams: usize,
}

#[derive(Debug, Serialize)]
struct ConnectOperation {
    ordinal: usize,
    scheduled_at_unix_ns: i64,
    started_at_unix_ns: i64,
    duration_ns: i64,
    cleanup_duration_ns: i64,
    commit_count: usize,
}

#[derive(Debug, Serialize)]
struct Operation {
    ordinal: usize,
    scheduled_at_unix_ns: i64,
    started_at_unix_ns: i64,
    duration_ns: i64,
    input_bytes: usize,
    output_bytes: usize,
    payload_sha256: [u8; 32],
}

#[derive(Clone, Debug, Serialize)]
struct BulkPhaseDirection {
    phase: &'static str,
    direction: &'static str,
    scheduled_at_unix_ns: i64,
    started_at_unix_ns: i64,
    duration_ns: i64,
    bytes: usize,
    payload_sha256: [u8; 32],
}

#[derive(Debug, Serialize)]
struct ClientBulkResult {
    outbound: Vec<BulkPhaseDirection>,
    bytes_per_direction: usize,
    active_streams: usize,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("transport release runner failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), AnyError> {
    let mut input = Vec::new();
    std::io::stdin().take(1 << 20).read_to_end(&mut input)?;
    let request: Request = serde_json::from_slice(&input)?;
    let result = match request {
        Request::Server(request) => run_server(request).await?,
        Request::Client(request) => run_client(request).await?,
    };
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    Ok(())
}

async fn run_server(request: ServerRequest) -> Result<RoleResult, AnyError> {
    request.plan.validate(request.connections.len())?;
    let certificate_chain = decode_der_list(&request.certificate_chain_der_b64)?;
    let private_key = decode_der(&request.private_key_der_b64)?;
    let accept_timeout = Duration::from_millis(request.accept_timeout_ms);
    if accept_timeout.is_zero() {
        return Err("server accept timeout is invalid".into());
    }
    let overall_start = capture_resource_snapshot()?;
    let mut registrations = Vec::with_capacity(request.connections.len());
    for connection in request.connections {
        let artifact = Artifact::parse(connection.artifact_json.as_bytes())?;
        let acceptor = Acceptor::bind(AcceptorOptions {
            bind_address: connection.bind_address,
            certificate_chain_der: certificate_chain.clone(),
            private_key_der: private_key.clone(),
            max_inbound_streams: request.max_inbound_streams,
            accept_timeout,
        })?;
        registrations.push((acceptor, artifact));
    }
    write_ready(&request.ready_path)?;

    let mut phases = Vec::with_capacity(4);
    let cold_start = capture_resource_snapshot()?;
    let persistent = registrations
        .pop()
        .ok_or("server has no persistent connection")?;
    let mut cold_tasks = JoinSet::new();
    for (acceptor, artifact) in registrations {
        cold_tasks.spawn(async move {
            let session = acceptor.accept(&artifact, CancellationToken::new()).await?;
            accept_orderly_session_close(session.wait_closed().await)?;
            Ok::<(), AnyError>(())
        });
    }
    tokio::time::timeout(
        Duration::from_millis(request.plan.cold_phase_timeout_ms),
        async {
            while let Some(result) = cold_tasks.join_next().await {
                result??;
            }
            Ok::<(), AnyError>(())
        },
    )
    .await
    .map_err(|_| "server cold phase timed out")??;
    phases.push(finish_phase("cold", cold_start, 0)?);

    let request_start = capture_resource_snapshot()?;
    let (persistent_acceptor, persistent_artifact) = persistent;
    let session = persistent_acceptor
        .accept(&persistent_artifact, CancellationToken::new())
        .await?;
    tokio::time::timeout(
        Duration::from_millis(request.plan.request_phase_timeout_ms),
        serve_request_response(session.clone(), &request.plan),
    )
    .await
    .map_err(|_| "server request-response phase timed out")??;
    phases.push(finish_phase("rpc", request_start, 0)?);

    let bulk_start = capture_resource_snapshot()?;
    let outbound_bulk = tokio::time::timeout(
        Duration::from_millis(request.plan.bulk_phase_timeout_ms),
        run_bulk_server(session.clone(), &request.plan),
    )
    .await
    .map_err(|_| "server bulk phase timed out")??;
    phases.push(finish_phase("bulk", bulk_start, 2)?);

    let cleanup_start = capture_resource_snapshot()?;
    tokio::time::timeout(
        Duration::from_millis(request.plan.cleanup_timeout_ms),
        async {
            finish_release_server(session.clone()).await?;
            accept_orderly_session_close(session.wait_closed().await)?;
            Ok::<(), AnyError>(())
        },
    )
    .await
    .map_err(|_| "server cleanup timed out")??;
    phases.push(finish_phase("cleanup", cleanup_start, 0)?);
    let overall_finish = capture_resource_snapshot()?;
    Ok(RoleResult::Server {
        resource: complete_resource_measurement(overall_start, overall_finish)?,
        phases,
        outbound_bulk,
    })
}

async fn run_client(request: ClientRequest) -> Result<RoleResult, AnyError> {
    request.plan.validate(request.artifacts_json.len())?;
    let trust_roots = decode_der_list(&request.trust_roots_der_b64)?;
    let connect_timeout = Duration::from_millis(request.connect_timeout_ms);
    if connect_timeout.is_zero() {
        return Err("client connect timeout is invalid".into());
    }
    let overall_start = capture_resource_snapshot()?;
    let mut artifacts = request.artifacts_json;
    let persistent_artifact = artifacts.pop().ok_or("client has no persistent artifact")?;
    let mut phases = Vec::with_capacity(4);

    signal_phase(request.control_directory.as_deref(), "cold", "start").await?;
    let cold_start = capture_resource_snapshot()?;
    let cold = tokio::time::timeout(
        Duration::from_millis(request.plan.cold_phase_timeout_ms),
        run_cold_client(
            artifacts,
            trust_roots.clone(),
            connect_timeout,
            &request.plan,
        ),
    )
    .await
    .map_err(|_| "client cold phase timed out")??;
    let cold_phase = finish_phase("cold", cold_start, 0)?;
    signal_phase(request.control_directory.as_deref(), "cold", "finish").await?;
    phases.push(cold_phase);

    signal_phase(request.control_directory.as_deref(), "rpc", "start").await?;
    let request_start = capture_resource_snapshot()?;
    let (session, commits) =
        connect_artifact(&persistent_artifact, trust_roots, connect_timeout).await?;
    if commits.load(Ordering::SeqCst) != 1 {
        return Err("persistent artifact commit count is invalid".into());
    }
    let request_response = tokio::time::timeout(
        Duration::from_millis(request.plan.request_phase_timeout_ms),
        run_request_response_client(session.clone(), &request.plan),
    )
    .await
    .map_err(|_| "client request-response phase timed out")??;
    let request_phase = finish_phase("rpc", request_start, 0)?;
    signal_phase(request.control_directory.as_deref(), "rpc", "finish").await?;
    phases.push(request_phase);

    signal_phase(request.control_directory.as_deref(), "bulk", "start").await?;
    let bulk_start = capture_resource_snapshot()?;
    let outbound = tokio::time::timeout(
        Duration::from_millis(request.plan.bulk_phase_timeout_ms),
        run_bulk_client(session.clone(), &request.plan),
    )
    .await
    .map_err(|_| "client bulk phase timed out")??;
    let bulk_phase = finish_phase("bulk", bulk_start, 2)?;
    signal_phase(request.control_directory.as_deref(), "bulk", "finish").await?;
    phases.push(bulk_phase);

    signal_phase(request.control_directory.as_deref(), "cleanup", "start").await?;
    let cleanup_start = capture_resource_snapshot()?;
    let cleanup_started = Instant::now();
    tokio::time::timeout(
        Duration::from_millis(request.plan.cleanup_timeout_ms),
        async {
            finish_release_client(session.clone()).await?;
            accept_orderly_session_close(session.close().await)?;
            Ok::<(), AnyError>(())
        },
    )
    .await
    .map_err(|_| "client cleanup timed out")??;
    let cleanup_duration_ns = duration_ns(cleanup_started.elapsed())?;
    let cleanup_phase = finish_phase("cleanup", cleanup_start, 0)?;
    signal_phase(request.control_directory.as_deref(), "cleanup", "finish").await?;
    phases.push(cleanup_phase);
    let overall_finish = capture_resource_snapshot()?;
    Ok(RoleResult::Client {
        cold,
        request_response,
        bulk: ClientBulkResult {
            outbound,
            bytes_per_direction: request.plan.bulk_score_bytes_per_direction,
            active_streams: 2,
        },
        cleanup_duration_ns,
        resource: complete_resource_measurement(overall_start, overall_finish)?,
        phases,
    })
}

async fn run_cold_client(
    artifacts: Vec<String>,
    trust_roots: Vec<Vec<u8>>,
    connect_timeout: Duration,
    plan: &WorkloadPlan,
) -> Result<Vec<ConnectOperation>, AnyError> {
    let semaphore = Arc::new(Semaphore::new(plan.cold_max_inflight));
    let phase_instant = tokio::time::Instant::now();
    let phase_unix_ns = unix_ns()?;
    let interval = Duration::from_secs_f64(1.0 / f64::from(plan.cold_start_rate_per_second));
    let operation_timeout = Duration::from_millis(plan.cold_operation_timeout_ms);
    let mut tasks = JoinSet::new();
    for (index, artifact) in artifacts.into_iter().enumerate() {
        let offset = interval.mul_f64(index as f64);
        tokio::time::sleep_until(phase_instant + offset).await;
        let permit = semaphore.clone().acquire_owned().await?;
        let roots = trust_roots.clone();
        let scheduled_at = phase_unix_ns
            .checked_add(duration_ns(offset)?)
            .ok_or("cold schedule overflow")?;
        tasks.spawn(async move {
            let _permit = permit;
            let started_at = unix_ns()?;
            let started = Instant::now();
            let (session, commits) = tokio::time::timeout(
                operation_timeout,
                connect_artifact(&artifact, roots, connect_timeout),
            )
            .await
            .map_err(|_| "cold connect timed out")??;
            let duration = duration_ns(started.elapsed())?;
            let cleanup_started = Instant::now();
            tokio::time::timeout(operation_timeout, async {
                accept_orderly_session_close(session.close().await)
            })
            .await
            .map_err(|_| "cold cleanup timed out")??;
            Ok::<ConnectOperation, AnyError>(ConnectOperation {
                ordinal: index + 1,
                scheduled_at_unix_ns: scheduled_at,
                started_at_unix_ns: started_at,
                duration_ns: duration,
                cleanup_duration_ns: duration_ns(cleanup_started.elapsed())?,
                commit_count: commits.load(Ordering::SeqCst),
            })
        });
    }
    let mut operations = Vec::with_capacity(plan.cold_operations);
    while let Some(result) = tasks.join_next().await {
        operations.push(result??);
    }
    operations.sort_by_key(|operation| operation.ordinal);
    if operations.len() != plan.cold_operations
        || operations.iter().any(|operation| {
            operation.duration_ns <= 0
                || operation.cleanup_duration_ns <= 0
                || operation.started_at_unix_ns < operation.scheduled_at_unix_ns
                || operation.commit_count != 1
        })
    {
        return Err("cold operation evidence is incomplete".into());
    }
    Ok(operations)
}

async fn connect_artifact(
    artifact_json: &str,
    trust_roots: Vec<Vec<u8>>,
    connect_timeout: Duration,
) -> Result<(Arc<dyn Session>, Arc<AtomicUsize>), AnyError> {
    let artifact = Artifact::parse(artifact_json.as_bytes())?;
    let commits = Arc::new(AtomicUsize::new(0));
    let commit_counter = commits.clone();
    let mut lease = ArtifactLease::new(artifact, move || {
        let counter = commit_counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    });
    let connector = Connector::new(ConnectorOptions {
        trust_roots_der: trust_roots,
        connect_timeout,
    })?;
    let session = connector
        .connect(&mut lease, CancellationToken::new())
        .await?;
    if !lease.is_committed() || commits.load(Ordering::SeqCst) != 1 {
        return Err("artifact spend was not committed exactly once".into());
    }
    Ok((session, commits))
}

async fn serve_request_response(
    session: Arc<dyn Session>,
    plan: &WorkloadPlan,
) -> Result<(), AnyError> {
    let mut tasks = JoinSet::new();
    for _ in 0..plan.request_operations {
        let incoming = session.accept_stream().await?;
        if incoming.kind() != "release-request-response" {
            return Err("unexpected request-response stream kind".into());
        }
        tasks.spawn(async move {
            let stream = incoming.into_stream();
            let payload = read_to_end(stream.as_ref()).await?;
            write_all(stream.as_ref(), &payload).await?;
            stream.close_write().await?;
            Ok::<(), AnyError>(())
        });
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    Ok(())
}

async fn run_request_response_client(
    session: Arc<dyn Session>,
    plan: &WorkloadPlan,
) -> Result<Vec<Operation>, AnyError> {
    let payload = Arc::new(
        std::iter::once(b'"')
            .chain(std::iter::repeat_n(b'x', plan.request_bytes - 2))
            .chain(std::iter::once(b'"'))
            .collect::<Vec<_>>(),
    );
    let payload_hash: [u8; 32] = Sha256::digest(payload.as_slice()).into();
    let semaphore = Arc::new(Semaphore::new(plan.request_workers));
    let phase_instant = tokio::time::Instant::now();
    let phase_unix_ns = unix_ns()?;
    let operation_timeout = Duration::from_millis(plan.request_operation_timeout_ms);
    let mut tasks = JoinSet::new();
    for index in 0..plan.request_operations {
        let offset = Duration::from_millis(index as u64);
        tokio::time::sleep_until(phase_instant + offset).await;
        let permit = semaphore.clone().acquire_owned().await?;
        let session = session.clone();
        let payload = payload.clone();
        let scheduled_at = phase_unix_ns
            .checked_add(duration_ns(offset)?)
            .ok_or("request schedule overflow")?;
        tasks.spawn(async move {
            let _permit = permit;
            tokio::time::timeout(operation_timeout, async move {
                let started_at = unix_ns()?;
                let started = Instant::now();
                let stream = session
                    .open_stream("release-request-response", JsonObject::new())
                    .await?;
                write_all(stream.as_ref(), payload.as_slice()).await?;
                stream.close_write().await?;
                let response = read_to_end(stream.as_ref()).await?;
                if response != payload.as_slice() {
                    return Err("request-response payload mismatch".into());
                }
                Ok::<Operation, AnyError>(Operation {
                    ordinal: index + 1,
                    scheduled_at_unix_ns: scheduled_at,
                    started_at_unix_ns: started_at,
                    duration_ns: duration_ns(started.elapsed())?,
                    input_bytes: payload.len(),
                    output_bytes: response.len(),
                    payload_sha256: payload_hash,
                })
            })
            .await
            .map_err(|_| "request-response operation timed out")?
        });
    }
    let mut operations = Vec::with_capacity(plan.request_operations);
    while let Some(result) = tasks.join_next().await {
        operations.push(result??);
    }
    operations.sort_by_key(|operation| operation.ordinal);
    if operations.len() != plan.request_operations
        || operations.iter().any(|operation| {
            operation.duration_ns <= 0
                || operation.started_at_unix_ns < operation.scheduled_at_unix_ns
                || operation.input_bytes != plan.request_bytes
                || operation.output_bytes != plan.request_bytes
                || operation.payload_sha256 != payload_hash
        })
    {
        return Err("request-response evidence is incomplete".into());
    }
    Ok(operations)
}

async fn run_bulk_server(
    session: Arc<dyn Session>,
    plan: &WorkloadPlan,
) -> Result<Vec<BulkPhaseDirection>, AnyError> {
    let warmup = bulk_role_phase(
        session.clone(),
        "warmup",
        "server-to-client",
        plan.bulk_warmup_bytes_per_direction,
        0x5a,
        0xa5,
    )
    .await?;
    let score = bulk_role_phase(
        session,
        "score",
        "server-to-client",
        plan.bulk_score_bytes_per_direction,
        0x5a,
        0xa5,
    )
    .await?;
    Ok(vec![warmup, score])
}

async fn run_bulk_client(
    session: Arc<dyn Session>,
    plan: &WorkloadPlan,
) -> Result<Vec<BulkPhaseDirection>, AnyError> {
    let warmup = bulk_role_phase(
        session.clone(),
        "warmup",
        "client-to-server",
        plan.bulk_warmup_bytes_per_direction,
        0xa5,
        0x5a,
    )
    .await?;
    let score = bulk_role_phase(
        session,
        "score",
        "client-to-server",
        plan.bulk_score_bytes_per_direction,
        0xa5,
        0x5a,
    )
    .await?;
    Ok(vec![warmup, score])
}

async fn finish_release_server(session: Arc<dyn Session>) -> Result<(), AnyError> {
    let incoming = session.accept_stream().await?;
    if incoming.kind() != "release-complete" {
        return Err("unexpected release completion stream kind".into());
    }
    let stream = incoming.into_stream();
    if read_to_end(stream.as_ref()).await? != b"done" {
        return Err("release completion payload is invalid".into());
    }
    write_all(stream.as_ref(), b"ok").await?;
    stream.close_write().await?;
    Ok(())
}

async fn finish_release_client(session: Arc<dyn Session>) -> Result<(), AnyError> {
    let stream = session
        .open_stream("release-complete", JsonObject::new())
        .await?;
    write_all(stream.as_ref(), b"done").await?;
    stream.close_write().await?;
    if read_to_end(stream.as_ref()).await? != b"ok" {
        return Err("release completion acknowledgement is invalid".into());
    }
    Ok(())
}

async fn bulk_role_phase(
    session: Arc<dyn Session>,
    phase: &'static str,
    outbound_direction: &'static str,
    bytes: usize,
    outbound_fill: u8,
    inbound_fill: u8,
) -> Result<BulkPhaseDirection, AnyError> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "direction".to_owned(),
        serde_json::Value::String(outbound_direction.to_owned()),
    );
    let metadata: JsonObject = metadata.into_iter().collect();
    let (outbound, incoming) = tokio::try_join!(
        session.open_stream("release-bulk", metadata),
        session.accept_stream(),
    )?;
    if incoming.kind() != "release-bulk" {
        return Err("unexpected bulk stream kind".into());
    }
    let inbound_direction = incoming
        .metadata()
        .get("direction")
        .and_then(serde_json::Value::as_str)
        .ok_or("bulk direction metadata is missing")?;
    let expected_inbound = if outbound_direction == "client-to-server" {
        "server-to-client"
    } else {
        "client-to-server"
    };
    if inbound_direction != expected_inbound {
        return Err("bulk direction metadata is invalid".into());
    }
    let scheduled_at = unix_ns()?;
    let started_at = scheduled_at;
    let started = Instant::now();
    let outbound_task = async {
        let payload = vec![outbound_fill; bytes];
        write_all(outbound.as_ref(), &payload).await?;
        outbound.close_write().await?;
        if read_to_end(outbound.as_ref()).await? != b"ok" {
            return Err("bulk acknowledgement is invalid".into());
        }
        Ok::<[u8; 32], AnyError>(Sha256::digest(&payload).into())
    };
    let inbound_stream = incoming.into_stream();
    let inbound_task = async {
        let payload = read_to_end(inbound_stream.as_ref()).await?;
        if payload.len() != bytes || payload.iter().any(|byte| *byte != inbound_fill) {
            return Err("bulk inbound payload is invalid".into());
        }
        write_all(inbound_stream.as_ref(), b"ok").await?;
        inbound_stream.close_write().await?;
        Ok::<(), AnyError>(())
    };
    let (payload_sha256, ()) = tokio::try_join!(outbound_task, inbound_task)?;
    Ok(BulkPhaseDirection {
        phase,
        direction: outbound_direction,
        scheduled_at_unix_ns: scheduled_at,
        started_at_unix_ns: started_at,
        duration_ns: duration_ns(started.elapsed())?,
        bytes,
        payload_sha256,
    })
}

async fn write_all(stream: &dyn ByteStream, payload: &[u8]) -> Result<(), AnyError> {
    let mut written = 0;
    while written < payload.len() {
        let count = stream
            .write(Bytes::copy_from_slice(&payload[written..]))
            .await?;
        if count == 0 || count > payload.len() - written {
            return Err("stream write made invalid progress".into());
        }
        written += count;
    }
    Ok(())
}

async fn read_to_end(stream: &dyn ByteStream) -> Result<Vec<u8>, AnyError> {
    let mut output = Vec::new();
    while let Some(chunk) = stream.read().await? {
        output.extend_from_slice(&chunk);
        if output.len() > 16 << 20 {
            return Err("stream read exceeds the release evidence bound".into());
        }
    }
    Ok(output)
}

fn decode_der_list(values: &[String]) -> Result<Vec<Vec<u8>>, AnyError> {
    if values.is_empty() {
        return Err("DER list is empty".into());
    }
    values.iter().map(|value| decode_der(value)).collect()
}

fn decode_der(value: &str) -> Result<Vec<u8>, AnyError> {
    let decoded = STANDARD.decode(value)?;
    if decoded.is_empty() {
        return Err("DER value is empty".into());
    }
    Ok(decoded)
}

fn write_ready(path: &Path) -> Result<(), AnyError> {
    if !path.is_absolute() || path.file_name() == Some(OsStr::new("")) {
        return Err("ready path must be absolute".into());
    }
    let parent = path.parent().ok_or("ready path has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("ready path parent is invalid".into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(b"ready\n")?;
    file.sync_all()?;
    Ok(())
}

async fn signal_phase(
    directory: Option<&Path>,
    phase: &'static str,
    boundary: &'static str,
) -> Result<(), AnyError> {
    let Some(directory) = directory else {
        return Ok(());
    };
    if !directory.is_absolute() {
        return Err("phase control directory must be absolute".into());
    }
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("phase control directory is invalid".into());
    }
    let marker = directory.join(format!("{phase}-{boundary}"));
    let acknowledgement = directory.join(format!("{phase}-{boundary}.ack"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)?;
    file.write_all(b"sample\n")?;
    file.sync_all()?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match fs::symlink_metadata(&acknowledgement) {
                Ok(value) if value.is_file() && !value.file_type().is_symlink() => {
                    if fs::read(&acknowledgement)? != b"ack\n" {
                        return Err("phase acknowledgement is invalid".into());
                    }
                    return Ok::<(), AnyError>(());
                }
                Ok(_) => return Err("phase acknowledgement is not a regular file".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| "phase acknowledgement timed out")?
}

fn finish_phase(
    phase: &'static str,
    start: ResourceSnapshot,
    active_streams: usize,
) -> Result<PhaseMeasurement, AnyError> {
    Ok(PhaseMeasurement {
        phase,
        resource: complete_resource_measurement(start, capture_resource_snapshot()?)?,
        active_streams,
    })
}

fn complete_resource_measurement(
    start: ResourceSnapshot,
    finish: ResourceSnapshot,
) -> Result<ResourceMeasurement, AnyError> {
    if finish.at_unix_ns < start.at_unix_ns
        || finish.cpu_nanoseconds < start.cpu_nanoseconds
        || finish.allocated_bytes < start.allocated_bytes
    {
        return Err("resource counters moved backwards".into());
    }
    Ok(ResourceMeasurement {
        started_at_unix_ns: start.at_unix_ns,
        finished_at_unix_ns: finish.at_unix_ns,
        cpu_nanoseconds: finish.cpu_nanoseconds - start.cpu_nanoseconds,
        allocated_bytes: finish.allocated_bytes - start.allocated_bytes,
        start,
        finish,
    })
}

#[cfg(target_os = "linux")]
fn capture_resource_snapshot() -> Result<ResourceSnapshot, AnyError> {
    let status = fs::read_to_string("/proc/self/status")?;
    let rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .ok_or("VmRSS is unavailable")?
        .parse::<u64>()?;
    let schedstat = fs::read_to_string("/proc/self/schedstat")?;
    let cpu_nanoseconds = schedstat
        .split_whitespace()
        .next()
        .ok_or("schedstat runtime is unavailable")?
        .parse::<u64>()?;
    let open_fds = fs::read_dir("/proc/self/fd")?.count();
    let tasks = fs::read_dir("/proc/self/task")?.count();
    let allocation = INSTRUMENTED_SYSTEM.stats();
    Ok(ResourceSnapshot {
        at_unix_ns: unix_ns()?,
        rss_bytes: rss_kib.checked_mul(1024).ok_or("RSS overflow")?,
        cpu_nanoseconds,
        allocated_bytes: u64::try_from(allocation.bytes_allocated)?,
        open_fds,
        runtime_threads: tasks,
        tasks,
    })
}

#[cfg(not(target_os = "linux"))]
fn capture_resource_snapshot() -> Result<ResourceSnapshot, AnyError> {
    Err("release resource evidence requires Linux".into())
}

fn unix_ns() -> Result<i64, AnyError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    i64::try_from(elapsed.as_nanos()).map_err(Into::into)
}

fn duration_ns(value: Duration) -> Result<i64, AnyError> {
    i64::try_from(value.as_nanos()).map_err(Into::into)
}

fn accept_orderly_session_close(result: Result<(), SessionError>) -> Result<(), SessionError> {
    match result {
        Ok(()) | Err(SessionError::Closed) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orderly_peer_close_is_success_but_other_failures_propagate() {
        assert_eq!(accept_orderly_session_close(Ok(())), Ok(()));
        assert_eq!(
            accept_orderly_session_close(Err(SessionError::Closed)),
            Ok(())
        );
        for error in [
            SessionError::Canceled,
            SessionError::InvalidInput,
            SessionError::Rejected,
            SessionError::ResourceExhausted,
            SessionError::Reset,
            SessionError::TimedOut,
            SessionError::Failed,
        ] {
            assert_eq!(accept_orderly_session_close(Err(error)), Err(error));
        }
    }
}
