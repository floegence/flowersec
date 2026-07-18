#![deny(unused_must_use)]
#![deny(clippy::let_underscore_must_use)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    Client, ConnectArtifact,
    client::{ConnectOptions, connect_direct, connect_tunnel as connect_client_tunnel},
    e2ee::{Secret32, ServerHandshakeOptions, Suite},
    endpoint::{
        DirectAcceptOptions, EndpointOptions, Session, accept_direct,
        connect_tunnel as connect_endpoint_tunnel,
    },
    generated::flowersec::{
        controlplane::v1::{ChannelInitGrant, Role as ControlRole, Suite as ControlSuite},
        direct::v1::{DirectConnectInfo, Suite as DirectSuite},
        rpc::v1::RpcError as WireRpcError,
    },
    proxy::{
        ContractOptions, HTTP1_KIND, HttpRequest, ProxyClient, ProxyServer, ServerOptions,
        WEBSOCKET_KIND, WebSocketFrame, WebSocketOp,
    },
    reconnect::{
        ArtifactSource, ArtifactSourceError, ConnectionStatus, ReconnectConfig, ReconnectManager,
        ReconnectSettings,
    },
    rpc::{Router, RpcCallOptions, RpcError, Server as RpcServer},
    streamhello,
    transport::TungsteniteTransport,
    transport_security::TransportSecurityPolicy,
    yamux::{YamuxError, YamuxStream},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    io::{self, Write as _},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    net::TcpListener,
    task::{JoinError, JoinSet},
};
use tokio_util::sync::CancellationToken;

const VERSION: u32 = 1;
const SATURATION_GATE_KIND: &str = "interop-rpc-saturation-gate";
const MIXED_ECHO_KIND: &str = "interop-mixed-echo";
const CASES: [&str; 9] = [
    "connect",
    "rekey",
    "streams",
    "rpc",
    "liveness",
    "proxy",
    "reconnect",
    "limits",
    "diagnostics",
];
const LIMIT_CASES: [&str; 6] = [
    "active_streams",
    "inbound_streams",
    "frame",
    "stream_receive",
    "session_receive",
    "proxy_body",
];

type HarnessResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    v: u32,
    event: String,
    request_id: String,
    profile: String,
    transport: String,
    suite: String,
    deadline_ms: u64,
    origin: String,
    upstream_url: String,
    workload: Workload,
    reconnect_artifacts: Vec<StrictClientArtifact>,
    limit_artifacts: Vec<StrictLimitArtifact>,
    limit_case: String,
    direct_info: Option<StrictDirectInfo>,
    direct_credential: Option<DirectCredential>,
    tunnel_grant: Option<StrictChannelInitGrant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictClientArtifact {
    direct_info: Option<StrictDirectInfo>,
    tunnel_grant: Option<StrictChannelInitGrant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictLimitArtifact {
    name: String,
    direct_info: Option<StrictDirectInfo>,
    tunnel_grant: Option<StrictChannelInitGrant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictDirectInfo {
    ws_url: String,
    channel_id: String,
    e2ee_psk_b64u: String,
    channel_init_expire_at_unix_s: i64,
    default_suite: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectCredential {
    channel_id: String,
    suite: u16,
    e2ee_psk_b64u: String,
    init_expires_at_unix_s: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictChannelInitGrant {
    tunnel_url: String,
    channel_id: String,
    channel_init_expire_at_unix_s: i64,
    idle_timeout_seconds: i32,
    role: u8,
    token: String,
    e2ee_psk_b64u: String,
    allowed_suites: Vec<u16>,
    default_suite: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    streams: StreamWorkload,
    rekey: RekeyWorkload,
    liveness_probes: usize,
    rpc: RpcWorkload,
    proxy: ProxyWorkload,
    reconnect_cycles: usize,
    limit_checks: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamWorkload {
    concurrent: usize,
    bytes_per_stream: usize,
    chunk_bytes: usize,
    slow_readers: usize,
    churn: usize,
    fin: usize,
    reset: usize,
    mixed_concurrent: usize,
    mixed_bytes_per_stream: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RekeyWorkload {
    client: usize,
    server: usize,
    concurrent: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcWorkload {
    calls: usize,
    notifications: usize,
    cancellations: usize,
    timeouts: usize,
    saturation_active: usize,
    saturation_queued: usize,
    saturation_rejected: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyWorkload {
    http_requests: usize,
    http_body_bytes: usize,
    streaming_http_body_bytes: usize,
    websocket_frames: usize,
    websocket_frame_bytes: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Metrics {
    sessions: usize,
    rekeys: usize,
    streams: usize,
    slow_readers: usize,
    fins: usize,
    resets: usize,
    bytes_written: usize,
    bytes_read: usize,
    rpc_calls: usize,
    rpc_notifications: usize,
    rpc_cancellations: usize,
    rpc_timeouts: usize,
    rpc_queue_rejections: usize,
    limit_checks: usize,
    backpressure_checks: usize,
    http_requests: usize,
    websocket_frames: usize,
    reconnects: usize,
    liveness_probes: usize,
    resource_rejections: usize,
}

#[derive(Clone, Debug, Serialize)]
struct Diagnostic {
    case: String,
    path: String,
    stage: String,
    code: String,
}

struct ClientOutcome {
    metrics: Metrics,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stop {
    v: u32,
    event: String,
    request_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerTaskKind {
    Rpc,
    Stream,
}

struct ServerTaskOutcome {
    kind: ServerTaskKind,
    result: HarnessResult,
}

#[tokio::main]
async fn main() {
    let request_id = Arc::new(std::sync::Mutex::new(None::<String>));
    if let Err(error) = run(request_id.clone()).await {
        let id = request_id
            .lock()
            .expect("request ID mutex poisoned")
            .clone();
        if let Err(emit_error) = emit(&json!({
            "v": VERSION,
            "event": "fatal",
            "request_id": id,
            "stage": "harness",
            "code": "rust_harness_failed",
            "message": error.to_string(),
        })) {
            eprintln!("failed to emit Rust harness fatal event: {emit_error}");
        }
        std::process::exit(1);
    }
}

async fn run(request_id: Arc<std::sync::Mutex<Option<String>>>) -> HarnessResult {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments != ["--protocol"] {
        return Err("Rust interop harness requires exactly --protocol".into());
    }
    emit(&json!({
        "v": VERSION,
        "event": "hello",
        "language": "rust",
        "roles": ["client", "server"],
        "cases": CASES,
    }))?;

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let command: Command = read_event(&mut lines).await?;
    *request_id.lock().expect("request ID mutex poisoned") = Some(command.request_id.clone());
    command.validate()?;
    let deadline = Duration::from_millis(command.deadline_ms);
    tokio::time::timeout(deadline, async {
        match command.event.as_str() {
            "run_client" => {
                let outcome = exercise_client(&command).await?;
                emit_result(&command.request_id, &outcome.metrics, &outcome.diagnostics)?;
            }
            "serve" => serve(&command, &mut lines).await?,
            _ => return Err("event must be run_client or serve".into()),
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "Rust interop harness deadline exceeded")??;
    Ok(())
}

impl Command {
    fn validate(&self) -> HarnessResult {
        if self.v != VERSION || self.request_id.is_empty() || self.profile.is_empty() {
            return Err("invalid command envelope".into());
        }
        if !matches!(self.transport.as_str(), "direct" | "tunnel")
            || !matches!(self.suite.as_str(), "x25519" | "p256")
            || self.deadline_ms == 0
            || self.origin.is_empty()
            || self.upstream_url.is_empty()
        {
            return Err("invalid command transport, suite, deadline, origin, or upstream".into());
        }
        let client = self.event == "run_client";
        let direct = self.transport == "direct";
        let expected = match (client, direct) {
            (true, true) => (true, false, false),
            (true, false) => (false, false, true),
            (false, true) => (false, true, false),
            (false, false) => (false, false, true),
        };
        let actual = (
            self.direct_info.is_some(),
            self.direct_credential.is_some(),
            self.tunnel_grant.is_some(),
        );
        if actual != expected {
            return Err("command contains an invalid credential field set".into());
        }
        if client {
            if self.reconnect_artifacts.len() != self.workload.reconnect_cycles + 1 {
                return Err(
                    "client command requires one fresh artifact per reconnect session".into(),
                );
            }
            for artifact in &self.reconnect_artifacts {
                artifact.validate(&self.transport)?;
            }
            let expected_limits = self.workload.limit_checks.saturating_sub(1);
            if !self.limit_case.is_empty() || self.limit_artifacts.len() != expected_limits {
                return Err("client command contains an invalid limit plan".into());
            }
            for (index, artifact) in self.limit_artifacts.iter().enumerate() {
                if LIMIT_CASES.get(index) != Some(&artifact.name.as_str()) {
                    return Err("client limit artifacts must follow the canonical order".into());
                }
                artifact.client_artifact().validate(&self.transport)?;
            }
        } else if !self.reconnect_artifacts.is_empty() {
            return Err("server command must not contain client reconnect artifacts".into());
        } else if !self.limit_artifacts.is_empty()
            || (!self.limit_case.is_empty() && !LIMIT_CASES.contains(&self.limit_case.as_str()))
        {
            return Err("server command contains an invalid limit plan".into());
        }
        self.workload.validate()
    }
}

impl StrictLimitArtifact {
    fn client_artifact(&self) -> StrictClientArtifactRef<'_> {
        StrictClientArtifactRef {
            direct_info: self.direct_info.as_ref(),
            tunnel_grant: self.tunnel_grant.as_ref(),
        }
    }

    fn connect_artifact(&self) -> HarnessResult<ConnectArtifact> {
        match (&self.direct_info, &self.tunnel_grant) {
            (Some(info), None) => Ok(ConnectArtifact::Direct {
                info: info.try_into()?,
                scoped: Vec::new(),
                correlation: None,
            }),
            (None, Some(grant)) => Ok(ConnectArtifact::Tunnel {
                grant: grant.try_into()?,
                scoped: Vec::new(),
                correlation: None,
            }),
            _ => Err("ambiguous limit artifact".into()),
        }
    }
}

struct StrictClientArtifactRef<'a> {
    direct_info: Option<&'a StrictDirectInfo>,
    tunnel_grant: Option<&'a StrictChannelInitGrant>,
}

impl StrictClientArtifactRef<'_> {
    fn validate(&self, transport: &str) -> HarnessResult {
        let valid = match transport {
            "direct" => self.direct_info.is_some() && self.tunnel_grant.is_none(),
            "tunnel" => self.tunnel_grant.is_some() && self.direct_info.is_none(),
            _ => false,
        };
        if !valid {
            return Err(format!("invalid {transport} limit artifact").into());
        }
        Ok(())
    }
}

impl StrictClientArtifact {
    fn validate(&self, transport: &str) -> HarnessResult {
        let valid = match transport {
            "direct" => self.direct_info.is_some() && self.tunnel_grant.is_none(),
            "tunnel" => self.tunnel_grant.is_some() && self.direct_info.is_none(),
            _ => false,
        };
        if !valid {
            return Err(format!("invalid {transport} reconnect artifact").into());
        }
        Ok(())
    }

    fn connect_artifact(&self) -> HarnessResult<ConnectArtifact> {
        match (&self.direct_info, &self.tunnel_grant) {
            (Some(info), None) => Ok(ConnectArtifact::Direct {
                info: info.try_into()?,
                scoped: Vec::new(),
                correlation: None,
            }),
            (None, Some(grant)) => Ok(ConnectArtifact::Tunnel {
                grant: grant.try_into()?,
                scoped: Vec::new(),
                correlation: None,
            }),
            _ => Err("ambiguous reconnect artifact".into()),
        }
    }
}

impl Workload {
    fn validate(&self) -> HarnessResult {
        let positive = [
            self.streams.concurrent,
            self.streams.bytes_per_stream,
            self.streams.chunk_bytes,
            self.streams.slow_readers,
            self.streams.churn,
            self.streams.fin,
            self.streams.reset,
            self.rekey.client,
            self.rekey.server,
            self.liveness_probes,
            self.rpc.calls,
            self.rpc.notifications,
            self.rpc.cancellations,
            self.rpc.timeouts,
            self.rpc.saturation_active,
            self.rpc.saturation_queued,
            self.rpc.saturation_rejected,
            self.proxy.http_requests,
            self.proxy.http_body_bytes,
            self.proxy.websocket_frames,
            self.proxy.websocket_frame_bytes,
            self.reconnect_cycles,
            self.limit_checks,
        ];
        if positive.contains(&0) || self.rpc.saturation_rejected != 1 {
            return Err(
                "workload values must be positive and saturation_rejected must be one".into(),
            );
        }
        if (self.streams.mixed_concurrent == 0) != (self.streams.mixed_bytes_per_stream == 0) {
            return Err("invalid mixed stream workload".into());
        }
        Ok(())
    }
}

async fn exercise_client(command: &Command) -> HarnessResult<ClientOutcome> {
    let mut options = ConnectOptions {
        origin: Some(command.origin.clone()),
        transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
        ..ConnectOptions::default()
    };
    options.observer = None;
    let client = Arc::new(if command.transport == "direct" {
        connect_direct(command.direct_info.as_ref().unwrap().try_into()?, options).await?
    } else {
        connect_client_tunnel(command.tunnel_grant.as_ref().unwrap().try_into()?, options).await?
    });
    let mut diagnostics = Vec::with_capacity(command.workload.limit_checks);
    let result = exercise_connected_client(client.clone(), command, &mut diagnostics).await;
    let close_result = client.close().await;
    let mut metrics = match (result, close_result) {
        (Ok(metrics), Ok(())) => metrics,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error.into()),
        (Err(error), Err(close_error)) => {
            return Err(
                format!("client exercise failed: {error}; close failed: {close_error}").into(),
            );
        }
    };
    exercise_reconnect(command, &mut metrics)
        .await
        .map_err(|error| format!("reconnect workload failed: {error}"))?;
    exercise_limits(command, &mut metrics, &mut diagnostics)
        .await
        .map_err(|error| format!("limit workload failed: {error}"))?;
    Ok(ClientOutcome {
        metrics,
        diagnostics,
    })
}

async fn exercise_limits(
    command: &Command,
    metrics: &mut Metrics,
    diagnostics: &mut Vec<Diagnostic>,
) -> HarnessResult {
    for artifact in &command.limit_artifacts {
        let mut options = ConnectOptions {
            origin: Some(command.origin.clone()),
            transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
            ..ConnectOptions::default()
        };
        if artifact.name == "active_streams" {
            options.yamux_limits.max_active_streams = 2;
            options.yamux_limits.max_inbound_streams = 1;
        }
        let client = Arc::new(
            flowersec::client::connect(artifact.connect_artifact()?, options)
                .await
                .map_err(|error| format!("limit {} connect failed: {error}", artifact.name))?,
        );
        let result = exercise_limit_action(&client, &artifact.name).await;
        let close_result = client.close().await;
        let backpressure = match (result, close_result) {
            (Ok(backpressure), Ok(())) => backpressure,
            (Ok(backpressure), Err(error))
                if destructive_limit_case(&artifact.name)
                    && error.code.as_str() == flowersec::ErrorCode::NOT_CONNECTED =>
            {
                backpressure
            }
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error.into()),
            (Err(error), Err(close_error)) => {
                return Err(format!(
                    "limit {} failed: {error}; close failed: {close_error}",
                    artifact.name
                )
                .into());
            }
        };
        metrics.sessions += 1;
        metrics.limit_checks += 1;
        if backpressure {
            metrics.backpressure_checks += 1;
        } else {
            metrics.resource_rejections += 1;
        }
        diagnostics.push(diagnostic_for(&artifact.name, &command.transport)?);
    }
    Ok(())
}

fn destructive_limit_case(name: &str) -> bool {
    matches!(name, "inbound_streams" | "frame" | "session_receive")
}

fn expected_client_destructive_error(name: &str, error: &flowersec::FlowersecError) -> bool {
    destructive_limit_case(name)
        && matches!(
            error.code.as_str(),
            flowersec::ErrorCode::RESOURCE_EXHAUSTED | flowersec::ErrorCode::NOT_CONNECTED
        )
}

async fn exercise_limit_action(client: &Arc<Client>, name: &str) -> HarnessResult<bool> {
    match name {
        "active_streams" => {
            let held = client.open_stream("hold").await?;
            let error = match client.open_stream("hold").await {
                Ok(_) => return Err("active stream limit accepted the second user stream".into()),
                Err(error) => error,
            };
            if error.code.as_str() != flowersec::ErrorCode::RESOURCE_EXHAUSTED {
                return Err(format!("active stream limit returned {error}").into());
            }
            held.reset().await?;
            rpc_control(client, 5).await?;
            Ok(false)
        }
        "inbound_streams" | "frame" => {
            let stream = match client.open_stream("hold").await {
                Ok(stream) => stream,
                Err(error) if expected_client_destructive_error(name, &error) => {
                    return Ok(false);
                }
                Err(error) => return Err(error.into()),
            };
            if name == "frame" {
                match stream.write(&vec![b'f'; 2048]).await {
                    Ok(()) => {}
                    Err(
                        YamuxError::Reset
                        | YamuxError::Closed
                        | YamuxError::StreamClosed
                        | YamuxError::Transport(_),
                    ) => {
                        return Ok(false);
                    }
                    Err(error) => {
                        return Err(format!("frame limit write returned {error}").into());
                    }
                }
            }
            match tokio::time::timeout(Duration::from_secs(1), stream.read()).await {
                Ok(Err(YamuxError::Reset | YamuxError::Closed | YamuxError::StreamClosed))
                | Ok(Ok(None)) => {
                    if name == "inbound_streams" {
                        rpc_control(client, 5).await?;
                    }
                    Ok(false)
                }
                Ok(Err(error)) => Err(format!("{name} stream returned {error}").into()),
                Ok(Ok(Some(_))) => Err(format!("{name} stream unexpectedly produced data").into()),
                Err(_) => Err(format!("{name} stream did not fail before the deadline").into()),
            }
        }
        "stream_receive" => {
            let stream = client.open_stream("hold").await?;
            let payload = vec![b'b'; (256 * 1024) + 1];
            let mut write = Box::pin(stream.write(&payload));
            tokio::select! {
                result = &mut write => {
                    return Err(format!("stream receive boundary did not apply backpressure: {result:?}").into());
                }
                () = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            stream.reset().await?;
            match write.await {
                Err(YamuxError::Reset | YamuxError::Closed | YamuxError::StreamClosed) => {}
                Err(error) => {
                    return Err(format!("backpressured write returned {error} after reset").into());
                }
                Ok(()) => {
                    return Err("reset released the backpressured write without an error".into());
                }
            }
            rpc_control(client, 5).await?;
            Ok(true)
        }
        "session_receive" => {
            let first = match client.open_stream("hold").await {
                Ok(stream) => stream,
                Err(error) if expected_client_destructive_error(name, &error) => {
                    return Ok(false);
                }
                Err(error) => return Err(error.into()),
            };
            let second = match client.open_stream("hold").await {
                Ok(stream) => stream,
                Err(error) if expected_client_destructive_error(name, &error) => {
                    return Ok(false);
                }
                Err(error) => return Err(error.into()),
            };
            let payload = vec![b's'; 256 * 1024];
            let writes = async { tokio::join!(first.write(&payload), second.write(&payload)) };
            if let Ok((Ok(()), Ok(()))) = tokio::time::timeout(Duration::from_secs(1), writes).await
            {
                return Err("session receive limit allowed both writes to complete".into());
            }
            match client.probe_liveness(Duration::from_secs(1)).await {
                Err(error) if error.code.as_str() == flowersec::ErrorCode::PING_FAILED => {}
                Err(error) => return Err(format!("session receive probe returned {error}").into()),
                Ok(_) => return Err("session receive limit did not terminate the session".into()),
            }
            Ok(false)
        }
        "proxy_body" => {
            let proxy = ProxyClient::new(client.clone(), ContractOptions::default())?;
            let result = proxy
                .request(HttpRequest {
                    method: "POST".to_owned(),
                    path: "/http".to_owned(),
                    headers: Vec::new(),
                    external_origin: None,
                    timeout: None,
                    body: vec![b'p'; 1025],
                })
                .await;
            match result {
                Err(flowersec::proxy::ProxyError::Remote { code, .. })
                    if code == "request_body_too_large" => {}
                Err(error) => return Err(format!("proxy body limit returned {error}").into()),
                Ok(_) => return Err("proxy body limit unexpectedly accepted the request".into()),
            }
            rpc_control(client, 5).await?;
            Ok(false)
        }
        _ => Err(format!("unknown limit case {name}").into()),
    }
}

async fn exercise_reconnect(command: &Command, metrics: &mut Metrics) -> HarnessResult {
    let artifacts = command
        .reconnect_artifacts
        .iter()
        .map(StrictClientArtifact::connect_artifact)
        .collect::<HarnessResult<VecDeque<_>>>()?;
    let artifacts = Arc::new(Mutex::new(artifacts));
    let source = ArtifactSource::refreshable({
        let artifacts = artifacts.clone();
        move |_| {
            let artifact = artifacts
                .lock()
                .map_err(|_| ArtifactSourceError::Acquire("artifact queue lock poisoned".into()))
                .and_then(|mut artifacts| {
                    artifacts.pop_front().ok_or_else(|| {
                        ArtifactSourceError::Acquire("reconnect artifact sequence exhausted".into())
                    })
                });
            async move { artifact }
        }
    });
    let manager = ReconnectManager::new();
    let mut options = ConnectOptions {
        origin: Some(command.origin.clone()),
        transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
        ..ConnectOptions::default()
    };
    options.observer = None;
    let operation: HarnessResult = async {
        manager
            .connect(ReconnectConfig {
                source,
                connect: options,
                reconnect: ReconnectSettings {
                    enabled: true,
                    max_attempts: 1,
                    initial_delay: Duration::ZERO,
                    max_delay: Duration::ZERO,
                    factor: 1.0,
                    jitter_ratio: 0.0,
                },
            })
            .await?;
        metrics.sessions += 1;
        for index in 0..command.workload.reconnect_cycles {
            let previous = manager
                .state()
                .client
                .ok_or("reconnect manager has no connected client")?;
            rpc_control(&previous, 6).await?;
            let connected = wait_for_reconnect_client(&manager, &previous).await?;
            rpc_echo(&connected, index, false).await?;
            metrics.sessions += 1;
            metrics.reconnects += 1;
        }
        let final_client = manager
            .state()
            .client
            .ok_or("reconnect manager lost the final client")?;
        rpc_control(&final_client, 5).await?;
        if !artifacts
            .lock()
            .map_err(|_| "artifact queue lock poisoned")?
            .is_empty()
        {
            return Err("reconnect artifact sequence was not consumed exactly".into());
        }
        Ok(())
    }
    .await;
    let cleanup = manager.disconnect().await;
    match (operation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(operation), Err(cleanup)) => {
            Err(format!("reconnect workload failed: {operation}; cleanup failed: {cleanup}").into())
        }
    }
}

async fn wait_for_reconnect_client(
    manager: &ReconnectManager,
    previous: &Arc<Client>,
) -> HarnessResult<Arc<Client>> {
    let mut states = manager.subscribe();
    loop {
        let state = states.borrow().clone();
        match state.status {
            ConnectionStatus::Connected => {
                if let Some(client) = state.client {
                    if !Arc::ptr_eq(&client, previous) {
                        return Ok(client);
                    }
                }
            }
            ConnectionStatus::Error => {
                return Err(state.error.ok_or("reconnect manager failed")?.into());
            }
            ConnectionStatus::Disconnected => return Err("reconnect manager disconnected".into()),
            ConnectionStatus::Connecting => {}
        }
        states
            .changed()
            .await
            .map_err(|_| "reconnect state stream closed")?;
    }
}

async fn exercise_connected_client(
    client: Arc<Client>,
    command: &Command,
    diagnostics: &mut Vec<Diagnostic>,
) -> HarnessResult<Metrics> {
    let mut metrics = Metrics {
        sessions: 1,
        ..Metrics::default()
    };
    let notifications = Arc::new(AtomicUsize::new(0));
    let invalid_notification = Arc::new(AtomicBool::new(false));
    let _subscription = client.rpc().on_notify_typed::<Value, _, _>(2, {
        let notifications = notifications.clone();
        let invalid_notification = invalid_notification.clone();
        move |payload| {
            let notifications = notifications.clone();
            let invalid_notification = invalid_notification.clone();
            async move {
                if payload != json!({ "hello": "world" }) {
                    invalid_notification.store(true, Ordering::SeqCst);
                } else {
                    notifications.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    });

    for index in 0..command.workload.rekey.client {
        client.rekey().await?;
        metrics.rekeys += 1;
        rpc_echo(&client, index, false).await?;
    }
    for _ in 0..command.workload.rekey.server {
        rpc_control(&client, 3).await?;
        metrics.rekeys += 1;
    }
    for _ in 0..command.workload.rekey.concurrent {
        let (local, remote) = tokio::join!(client.rekey(), rpc_control(&client, 3));
        local?;
        remote?;
        metrics.rekeys += 2;
    }

    exercise_streams(&client, &command.workload.streams, &mut metrics)
        .await
        .map_err(|error| format!("stream workload failed: {error}"))?;
    exercise_mixed_streams_and_rpc(&client, &command.workload.streams, &mut metrics)
        .await
        .map_err(|error| format!("mixed RPC/stream workload failed: {error}"))?;
    for _ in 0..command.workload.liveness_probes {
        client.probe_liveness(Duration::from_secs(2)).await?;
        metrics.liveness_probes += 1;
    }
    for index in 0..command.workload.rpc.calls {
        rpc_echo(&client, index, index < command.workload.rpc.notifications).await?;
        metrics.rpc_calls += 1;
    }
    let queue_rejections = exercise_rpc_saturation(&client, &command.workload.rpc).await?;
    metrics.rpc_queue_rejections += queue_rejections;
    metrics.resource_rejections += queue_rejections;
    metrics.limit_checks += 1;
    diagnostics.push(diagnostic_for("rpc_queue", &command.transport)?);
    for _ in 0..command.workload.rpc.cancellations {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result: Result<Value, RpcError> = client
            .rpc()
            .call_typed_with_options(
                4,
                &json!({}),
                RpcCallOptions {
                    timeout: None,
                    cancellation: Some(cancellation),
                },
            )
            .await;
        if !matches!(result, Err(RpcError::Canceled)) {
            return Err(format!("RPC cancellation returned {result:?}").into());
        }
        metrics.rpc_cancellations += 1;
    }
    for _ in 0..command.workload.rpc.timeouts {
        let result: Result<Value, RpcError> = client
            .rpc()
            .call_typed_with_options(
                4,
                &json!({}),
                RpcCallOptions {
                    timeout: Some(Duration::from_millis(1)),
                    cancellation: None,
                },
            )
            .await;
        if !matches!(result, Err(RpcError::Timeout)) {
            return Err(format!("RPC timeout returned {result:?}").into());
        }
        metrics.rpc_timeouts += 1;
    }
    wait_for_notifications(
        &notifications,
        &invalid_notification,
        command.workload.rpc.notifications,
    )
    .await?;
    metrics.rpc_notifications = command.workload.rpc.notifications;
    exercise_proxy(&client, &command.workload.proxy, &mut metrics)
        .await
        .map_err(|error| format!("proxy workload failed: {error}"))?;
    rpc_control(&client, 5).await?;
    Ok(metrics)
}

async fn exercise_streams(
    client: &Arc<Client>,
    workload: &StreamWorkload,
    metrics: &mut Metrics,
) -> HarnessResult {
    let mut tasks = JoinSet::new();
    for index in 0..workload.concurrent {
        let client = client.clone();
        let bytes_per_stream = workload.bytes_per_stream;
        let chunk_bytes = workload.chunk_bytes;
        let slow_readers = workload.slow_readers;
        tasks.spawn(async move {
            let stream = client.open_stream("echo").await?;
            let payload = vec![(index % 251) as u8; bytes_per_stream];
            for chunk in payload.chunks(chunk_bytes) {
                stream.write(chunk).await?;
            }
            let slow_reader = index < slow_readers;
            if slow_reader {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let echoed = stream.read_exact(payload.len()).await?;
            if echoed != payload {
                return Err::<_, Box<dyn std::error::Error + Send + Sync>>(
                    "echo payload mismatch".into(),
                );
            }
            stream.close().await?;
            Ok((payload.len(), echoed.len(), slow_reader))
        });
    }
    while let Some(outcome) = tasks.join_next().await {
        let (written, read, slow_reader) = join_task(outcome)??;
        metrics.streams += 1;
        metrics.bytes_written += written;
        metrics.bytes_read += read;
        metrics.slow_readers += usize::from(slow_reader);
    }
    for _ in 0..workload.churn {
        let stream = client.open_stream("churn").await?;
        if stream.read().await?.is_some() {
            return Err("churn stream produced data before FIN".into());
        }
        stream.close().await?;
        metrics.streams += 1;
    }
    for _ in 0..workload.fin {
        let stream = client.open_stream("echo").await?;
        stream.close().await?;
        if stream.read().await?.is_some() {
            return Err("FIN stream produced data after FIN".into());
        }
        metrics.streams += 1;
        metrics.fins += 1;
    }
    for _ in 0..workload.reset {
        let stream = client.open_stream("echo").await?;
        stream.reset().await?;
        metrics.streams += 1;
        metrics.resets += 1;
    }
    Ok(())
}

enum MixedOutcome {
    Stream { written: usize, read: usize },
    Rpc,
}

async fn exercise_mixed_streams_and_rpc(
    client: &Arc<Client>,
    workload: &StreamWorkload,
    metrics: &mut Metrics,
) -> HarnessResult {
    let mut tasks = JoinSet::new();
    for index in 0..workload.mixed_concurrent {
        let client = client.clone();
        let bytes_per_stream = workload.mixed_bytes_per_stream;
        let chunk_bytes = workload.chunk_bytes;
        tasks.spawn(async move {
            if index % 2 == 1 {
                rpc_echo(&client, index, false).await?;
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(MixedOutcome::Rpc);
            }
            let stream = client.open_stream(MIXED_ECHO_KIND).await?;
            let payload = vec![(index % 251) as u8; bytes_per_stream];
            let write = async {
                for chunk in payload.chunks(chunk_bytes) {
                    stream.write(chunk).await?;
                }
                Ok::<_, YamuxError>(())
            };
            let (write_result, read_result) = tokio::join!(write, stream.read_exact(payload.len()));
            write_result?;
            let echoed = read_result?;
            if echoed != payload {
                return Err("mixed echo payload mismatch".into());
            }
            stream.close().await?;
            Ok(MixedOutcome::Stream {
                written: payload.len(),
                read: echoed.len(),
            })
        });
    }
    while let Some(outcome) = tasks.join_next().await {
        match join_task(outcome)?? {
            MixedOutcome::Stream { written, read } => {
                metrics.streams += 1;
                metrics.bytes_written += written;
                metrics.bytes_read += read;
            }
            MixedOutcome::Rpc => metrics.rpc_calls += 1,
        }
    }
    Ok(())
}

async fn exercise_rpc_saturation(
    client: &Arc<Client>,
    workload: &RpcWorkload,
) -> HarnessResult<usize> {
    let total = workload
        .saturation_active
        .saturating_add(workload.saturation_queued)
        .saturating_add(workload.saturation_rejected);
    let gate = Arc::new(tokio::sync::Mutex::new(Some(
        client.open_stream(SATURATION_GATE_KIND).await?,
    )));
    let mut tasks = JoinSet::new();
    for _ in 0..total {
        let client = client.clone();
        let gate = gate.clone();
        tasks.spawn(async move {
            let outcome = client.rpc().call_typed::<_, Value>(7, &json!({})).await;
            if matches!(
                &outcome,
                Err(RpcError::ResourceExhausted | RpcError::Call { code: 429, .. })
            ) {
                let stream = gate.lock().await.take();
                if let Some(stream) = stream {
                    stream.write(&[1]).await?;
                    stream.close().await?;
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(outcome)
        });
    }
    let mut succeeded = 0;
    let mut rejected = 0;
    let run_result: HarnessResult = async {
        while let Some(outcome) = tasks.join_next().await {
            match join_task(outcome)?? {
                Ok(value) if value == json!({ "ok": true }) => succeeded += 1,
                Ok(value) => {
                    return Err(format!("invalid saturation RPC response: {value}").into());
                }
                Err(RpcError::ResourceExhausted | RpcError::Call { code: 429, .. }) => {
                    rejected += 1;
                }
                Err(error) => return Err(format!("saturation RPC failed: {error}").into()),
            }
        }
        Ok(())
    }
    .await;
    let unreleased = gate.lock().await.take();
    if let Some(stream) = unreleased {
        let reset_result = stream.reset().await;
        return match (run_result, reset_result) {
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(reset_error)) => Err(format!(
                "RPC saturation failed: {error}; gate cleanup failed: {reset_error}"
            )
            .into()),
            (Ok(()), Ok(())) => Err("RPC saturation completed without a queue rejection".into()),
            (Ok(()), Err(reset_error)) => Err(format!(
                "RPC saturation completed without a queue rejection; gate cleanup failed: {reset_error}"
            )
            .into()),
        };
    }
    run_result?;
    if succeeded != workload.saturation_active + workload.saturation_queued
        || rejected != workload.saturation_rejected
    {
        return Err(
            format!("RPC saturation got {succeeded} successes and {rejected} rejections").into(),
        );
    }
    Ok(rejected)
}

async fn exercise_proxy(
    client: &Arc<Client>,
    workload: &ProxyWorkload,
    metrics: &mut Metrics,
) -> HarnessResult {
    let proxy = ProxyClient::new(client.clone(), ContractOptions::default())?;
    let body = vec![b'p'; workload.http_body_bytes];
    for _ in 0..workload.http_requests {
        let response = proxy
            .request(HttpRequest {
                method: "POST".to_owned(),
                path: "/http".to_owned(),
                headers: Vec::new(),
                external_origin: None,
                timeout: None,
                body: body.clone(),
            })
            .await?;
        if response.status != 200 || response.body != body {
            return Err("proxy HTTP response mismatch".into());
        }
        metrics.http_requests += 1;
    }
    if workload.streaming_http_body_bytes > 0 {
        let streaming_body = vec![b's'; workload.streaming_http_body_bytes];
        let response = proxy
            .request(HttpRequest {
                method: "POST".to_owned(),
                path: "/http".to_owned(),
                headers: Vec::new(),
                external_origin: None,
                timeout: None,
                body: streaming_body.clone(),
            })
            .await?;
        if response.status != 200 || response.body != streaming_body {
            return Err("streaming proxy HTTP response mismatch".into());
        }
        metrics.http_requests += 1;
    }
    let websocket = proxy.open_websocket("/ws", Vec::new()).await?;
    let payload = vec![b'w'; workload.websocket_frame_bytes];
    for _ in 0..workload.websocket_frames {
        websocket
            .send(WebSocketFrame {
                op: WebSocketOp::Text,
                payload: payload.clone(),
            })
            .await?;
        let received = websocket.receive().await?;
        if received.op != WebSocketOp::Text || received.payload != payload {
            return Err("proxy WebSocket response mismatch".into());
        }
        metrics.websocket_frames += 1;
    }
    websocket.close(None, "").await?;
    Ok(())
}

async fn serve(
    command: &Command,
    lines: &mut tokio::io::Lines<BufReader<tokio::io::Stdin>>,
) -> HarnessResult {
    let cancellation = CancellationToken::new();
    let (session, listener) = if command.transport == "direct" {
        let credential = command.direct_credential.as_ref().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        emit(&json!({
            "v": VERSION,
            "event": "ready",
            "request_id": command.request_id,
            "direct_info": {
                "ws_url": format!("ws://{address}"),
                "channel_id": credential.channel_id,
                "e2ee_psk_b64u": credential.e2ee_psk_b64u,
                "channel_init_expire_at_unix_s": credential.init_expires_at_unix_s,
                "default_suite": credential.suite,
            },
        }))?;
        let (tcp, _) = listener.accept().await?;
        let transport = TungsteniteTransport::accept(tcp).await?;
        let mut handshake = ServerHandshakeOptions::new(
            decode_psk(&credential.e2ee_psk_b64u)?,
            parse_suite(credential.suite)?,
            credential.init_expires_at_unix_s,
        );
        handshake.channel_id = Some(credential.channel_id.clone());
        let mut accept_options = DirectAcceptOptions::new(handshake);
        accept_options.yamux_limits = server_yamux_limits(command);
        let session = accept_direct(Arc::new(transport), accept_options).await?;
        (Arc::new(session), Some(listener))
    } else {
        let grant: ChannelInitGrant = command.tunnel_grant.as_ref().unwrap().try_into()?;
        let options = EndpointOptions {
            origin: Some(command.origin.clone()),
            transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
            yamux_limits: server_yamux_limits(command),
            ..EndpointOptions::default()
        };
        let connection = tokio::spawn(connect_endpoint_tunnel(grant, options));
        emit(&json!({
            "v": VERSION,
            "event": "ready",
            "request_id": command.request_id,
        }))?;
        (Arc::new(join_task(connection.await)??), None)
    };
    let metrics = Arc::new(tokio::sync::Mutex::new(Metrics {
        sessions: 1,
        ..Metrics::default()
    }));
    let mut serve_task = tokio::spawn(serve_session(
        session.clone(),
        command.upstream_url.clone(),
        cancellation.clone(),
        metrics.clone(),
        command.workload.rpc.saturation_active,
        command.workload.rpc.saturation_queued,
        command.limit_case.clone(),
    ));
    let stop: Stop = tokio::select! {
        stop = read_event(lines) => stop?,
        outcome = &mut serve_task => {
            match join_task(outcome)? {
                Ok(()) => return Err("server task ended before stop".into()),
                Err(error) => return Err(error),
            }
        }
    };
    if stop.v != VERSION || stop.event != "stop" || stop.request_id != command.request_id {
        cancellation.cancel();
        serve_task.abort();
        return Err("invalid stop event".into());
    }
    cancellation.cancel();
    let close_result = session.close().await;
    let serve_result = join_task(serve_task.await)?;
    drop(listener);
    match (serve_result, close_result) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => return Err(error),
        (Ok(()), Err(error)) => return Err(error.into()),
        (Err(error), Err(close_error)) => {
            return Err(format!("server task failed: {error}; close failed: {close_error}").into());
        }
    }
    emit_result(&command.request_id, &metrics.lock().await.clone(), &[])?;
    Ok(())
}

async fn serve_session(
    session: Arc<Session>,
    upstream_url: String,
    cancellation: CancellationToken,
    metrics: Arc<tokio::sync::Mutex<Metrics>>,
    rpc_saturation_active: usize,
    rpc_saturation_queued: usize,
    limit_case: String,
) -> HarnessResult {
    let (kind, rpc_stream) = match session.accept_stream().await {
        Ok(accepted) => accepted,
        Err(error) if expected_destructive_limit_error(&limit_case, &error) => {
            cancellation.cancelled().await;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if kind != streamhello::RPC_KIND {
        return Err("first stream must be RPC".into());
    }
    let router = Router::default();
    let mut rpc_server = RpcServer::new(router.clone());
    rpc_server.max_concurrent_requests = rpc_saturation_active;
    rpc_server.max_queued_requests = rpc_saturation_queued;
    rpc_server.max_queued_notifications = rpc_saturation_queued;
    let rpc = Arc::new(rpc_server);
    let peer_complete = CancellationToken::new();
    let force_disconnect = CancellationToken::new();
    let saturation_gate = CancellationToken::new();
    router
        .register(1, {
            let rpc = Arc::downgrade(&rpc);
            move |payload: Value| {
                let rpc = rpc.clone();
                async move {
                    let value = payload
                        .get("value")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| wire_error(400, "missing integer value"))?;
                    if payload.get("notify") == Some(&Value::Bool(true)) {
                        let rpc = rpc
                            .upgrade()
                            .ok_or_else(|| wire_error(500, "RPC server stopped"))?;
                        rpc.notify_typed(2, &json!({ "hello": "world" }))
                            .await
                            .map_err(|error| wire_error(500, error.to_string()))?;
                    }
                    Ok(json!({ "value": value }))
                }
            }
        })
        .await;
    router
        .register(3, {
            let session = session.clone();
            let metrics = metrics.clone();
            move |_: Value| {
                let session = session.clone();
                let metrics = metrics.clone();
                async move {
                    session
                        .rekey()
                        .await
                        .map_err(|error| wire_error(500, error.to_string()))?;
                    metrics.lock().await.rekeys += 1;
                    Ok(json!({ "ok": true }))
                }
            }
        })
        .await;
    router
        .register(4, |_: Value| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(json!({ "ok": true }))
        })
        .await;
    router
        .register(5, {
            let peer_complete = peer_complete.clone();
            move |_: Value| {
                let peer_complete = peer_complete.clone();
                async move {
                    peer_complete.cancel();
                    Ok(json!({ "ok": true }))
                }
            }
        })
        .await;
    router
        .register(6, {
            let force_disconnect = force_disconnect.clone();
            move |_: Value| {
                let force_disconnect = force_disconnect.clone();
                async move {
                    force_disconnect.cancel();
                    Ok(json!({ "ok": true }))
                }
            }
        })
        .await;
    router
        .register(7, {
            let saturation_gate = saturation_gate.clone();
            move |_: Value| {
                let saturation_gate = saturation_gate.clone();
                async move {
                    saturation_gate.cancelled().await;
                    Ok(json!({ "ok": true }))
                }
            }
        })
        .await;

    let mut proxy_contract = ContractOptions::default();
    if limit_case == "proxy_body" {
        proxy_contract.max_body_bytes = 1024;
    }
    let proxy = ProxyServer::new(ServerOptions {
        upstream: upstream_url.clone(),
        upstream_origin: upstream_url,
        allowed_upstream_hosts: Vec::new(),
        contract: proxy_contract,
        default_timeout: None,
        max_timeout: None,
        max_concurrent_streams: flowersec::defaults::PROXY_MAX_CONCURRENT_STREAMS,
    })?;
    let mut tasks: JoinSet<ServerTaskOutcome> = JoinSet::new();
    tasks.spawn({
        let rpc = rpc.clone();
        async move {
            ServerTaskOutcome {
                kind: ServerTaskKind::Rpc,
                result: rpc.serve(rpc_stream).await.map_err(Into::into),
            }
        }
    });
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                break;
            }
            () = peer_complete.cancelled() => {
                cancellation.cancelled().await;
                break;
            }
            () = force_disconnect.cancelled() => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                session.close().await?;
                cancellation.cancelled().await;
                break;
            }
            outcome = tasks.join_next(), if !tasks.is_empty() => {
                let task = match outcome {
                    Some(outcome) => join_task(outcome)?,
                    None => return Err("server task set ended unexpectedly".into()),
                };
                if let Err(error) = task.result {
                    if expected_destructive_session_termination(&limit_case, &session).await {
                        cancellation.cancelled().await;
                        break;
                    }
                    return Err(error);
                }
                if task.kind == ServerTaskKind::Rpc {
                    return Err("RPC server task ended before stop".into());
                }
            }
            accepted = session.accept_stream() => {
                let (kind, stream) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if has_yamux_reset(&error) => {
                        metrics.lock().await.resets += 1;
                        continue;
                    }
                    Err(error) if expected_destructive_limit_error(&limit_case, &error) => {
                        cancellation.cancelled().await;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
                match kind.as_str() {
                    "echo" | MIXED_ECHO_KIND => {
                        let metrics = metrics.clone();
                        tasks.spawn(async move { ServerTaskOutcome {
                            kind: ServerTaskKind::Stream,
                            result: echo(stream, metrics).await,
                        } })
                    }
                    "churn" => {
                        tasks.spawn(async move { ServerTaskOutcome {
                            kind: ServerTaskKind::Stream,
                            result: stream.close().await.map_err(Into::into),
                        } })
                    }
                    "hold" => {
                        let cancellation = cancellation.clone();
                        tasks.spawn(async move { ServerTaskOutcome {
                            kind: ServerTaskKind::Stream,
                            result: async {
                                cancellation.cancelled().await;
                                Ok(())
                            }.await,
                        } })
                    }
                    SATURATION_GATE_KIND => {
                        let saturation_gate = saturation_gate.clone();
                        tasks.spawn(async move {
                            let result = async {
                                let signal = stream.read_exact(1).await?;
                                if signal != [1] {
                                    return Err("invalid RPC saturation gate signal".into());
                                }
                                saturation_gate.cancel();
                                stream.close().await?;
                                Ok(())
                            }
                            .await;
                            ServerTaskOutcome {
                                kind: ServerTaskKind::Stream,
                                result,
                            }
                        })
                    }
                    HTTP1_KIND | WEBSOCKET_KIND => {
                        let proxy = proxy.clone();
                        tasks.spawn(async move {
                            let result = proxy.serve_stream(&kind, stream).await.map_err(Into::into);
                            if let Err(error) = &result {
                                eprintln!("proxy stream task failed: {error}");
                            }
                            ServerTaskOutcome {
                                kind: ServerTaskKind::Stream,
                                result,
                            }
                        })
                    }
                    _ => {
                        stream.reset().await?;
                        return Err(format!("unsupported stream kind {kind}").into());
                    }
                };
            }
        }
    }
    saturation_gate.cancel();
    tasks.abort_all();
    while let Some(outcome) = tasks.join_next().await {
        match outcome {
            Err(error) if error.is_cancelled() => {}
            other => {
                let task = join_task(other)?;
                if let Err(error) = task.result {
                    let rpc_stopped_by_control = task.kind == ServerTaskKind::Rpc
                        && (peer_complete.is_cancelled() || force_disconnect.is_cancelled());
                    if !rpc_stopped_by_control
                        && !expected_destructive_session_termination(&limit_case, &session).await
                    {
                        return Err(error);
                    }
                }
            }
        }
    }
    Ok(())
}

fn expected_destructive_limit_error(limit_case: &str, error: &flowersec::FlowersecError) -> bool {
    destructive_limit_case(limit_case)
        && error.code.as_str() == flowersec::ErrorCode::RESOURCE_EXHAUSTED
}

async fn expected_destructive_session_termination(limit_case: &str, session: &Session) -> bool {
    if !destructive_limit_case(limit_case) {
        return false;
    }
    matches!(
        session.termination_error().await,
        Some(error) if error.code.as_str() == flowersec::ErrorCode::RESOURCE_EXHAUSTED
    )
}

async fn echo(stream: YamuxStream, metrics: Arc<tokio::sync::Mutex<Metrics>>) -> HarnessResult {
    loop {
        match stream.read().await {
            Ok(Some(payload)) => {
                stream.write(&payload).await?;
                let mut metrics = metrics.lock().await;
                metrics.bytes_read += payload.len();
                metrics.bytes_written += payload.len();
            }
            Ok(None) => {
                stream.close().await?;
                return Ok(());
            }
            Err(YamuxError::Reset) => {
                metrics.lock().await.resets += 1;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn rpc_echo(client: &Client, value: usize, notify: bool) -> HarnessResult {
    let response: Value = client
        .rpc()
        .call_typed(1, &json!({ "value": value, "notify": notify }))
        .await?;
    if response != json!({ "value": value }) {
        return Err("invalid RPC echo response".into());
    }
    Ok(())
}

async fn rpc_control(client: &Client, type_id: u32) -> HarnessResult {
    let response: Value = client.rpc().call_typed(type_id, &json!({})).await?;
    if response != json!({ "ok": true }) {
        return Err(format!("invalid control RPC response for {type_id}").into());
    }
    Ok(())
}

async fn wait_for_notifications(
    notifications: &AtomicUsize,
    invalid: &AtomicBool,
    expected: usize,
) -> HarnessResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if invalid.load(Ordering::SeqCst) {
            return Err("invalid notification payload".into());
        }
        if notifications.load(Ordering::SeqCst) >= expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("notification deadline exceeded".into());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn parse_suite(value: u16) -> HarnessResult<Suite> {
    match value {
        1 => Ok(Suite::X25519HkdfSha256Aes256Gcm),
        2 => Ok(Suite::P256HkdfSha256Aes256Gcm),
        _ => Err(format!("unsupported suite {value}").into()),
    }
}

fn server_yamux_limits(command: &Command) -> flowersec::yamux::YamuxLimits {
    let mixed_transfers = command.workload.streams.mixed_concurrent.saturating_add(1) / 2;
    let required = command
        .workload
        .streams
        .concurrent
        .max(mixed_transfers)
        .saturating_add(1);
    let mut limits = flowersec::yamux::YamuxLimits {
        max_active_streams: 64.max(required),
        max_inbound_streams: 32.max(required),
        ..flowersec::yamux::YamuxLimits::default()
    };
    match command.limit_case.as_str() {
        "inbound_streams" => limits.max_inbound_streams = 1,
        "frame" => {
            limits.max_frame_bytes = 1024;
            limits.preferred_outbound_frame_bytes = 1024;
        }
        "session_receive" => limits.max_session_receive_bytes = 256 * 1024,
        _ => {}
    }
    limits
}

fn parse_control_suite(value: u16) -> HarnessResult<ControlSuite> {
    match value {
        1 => Ok(ControlSuite::X25519HkdfSha256Aes256Gcm),
        2 => Ok(ControlSuite::P256HkdfSha256Aes256Gcm),
        _ => Err(format!("unsupported controlplane suite {value}").into()),
    }
}

fn decode_psk(value: &str) -> HarnessResult<Secret32> {
    let decoded = URL_SAFE_NO_PAD.decode(value)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "E2EE PSK must contain exactly 32 bytes")?;
    Ok(Secret32::new(bytes))
}

impl TryFrom<&StrictDirectInfo> for DirectConnectInfo {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_from(value: &StrictDirectInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            ws_url: value.ws_url.clone(),
            channel_id: value.channel_id.clone(),
            e2ee_psk_b64u: value.e2ee_psk_b64u.clone(),
            channel_init_expire_at_unix_s: value.channel_init_expire_at_unix_s,
            default_suite: match value.default_suite {
                1 => DirectSuite::X25519HkdfSha256Aes256Gcm,
                2 => DirectSuite::P256HkdfSha256Aes256Gcm,
                other => return Err(format!("unsupported direct suite {other}").into()),
            },
        })
    }
}

impl TryFrom<&StrictChannelInitGrant> for ChannelInitGrant {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_from(value: &StrictChannelInitGrant) -> Result<Self, Self::Error> {
        let role = match value.role {
            1 => ControlRole::Client,
            2 => ControlRole::Server,
            other => return Err(format!("unsupported tunnel role {other}").into()),
        };
        let allowed_suites = value
            .allowed_suites
            .iter()
            .copied()
            .map(parse_control_suite)
            .collect::<HarnessResult<Vec<_>>>()?;
        Ok(Self {
            tunnel_url: value.tunnel_url.clone(),
            channel_id: value.channel_id.clone(),
            channel_init_expire_at_unix_s: value.channel_init_expire_at_unix_s,
            idle_timeout_seconds: value.idle_timeout_seconds,
            role,
            token: value.token.clone(),
            e2ee_psk_b64u: value.e2ee_psk_b64u.clone(),
            allowed_suites,
            default_suite: parse_control_suite(value.default_suite)?,
        })
    }
}

async fn read_event<T: DeserializeOwned>(
    lines: &mut tokio::io::Lines<BufReader<tokio::io::Stdin>>,
) -> HarnessResult<T> {
    let line = lines
        .next_line()
        .await?
        .ok_or("protocol stdin reached EOF")?;
    Ok(serde_json::from_str(&line)?)
}

fn emit_result(request_id: &str, metrics: &Metrics, diagnostics: &[Diagnostic]) -> io::Result<()> {
    emit(&json!({
        "v": VERSION,
        "event": "result",
        "request_id": request_id,
        "metrics": metrics,
        "diagnostics": diagnostics,
    }))
}

fn diagnostic_for(case_name: &str, path: &str) -> HarnessResult<Diagnostic> {
    let (stage, code) = match case_name {
        "rpc_queue" => ("rpc", "resource_exhausted"),
        "active_streams" | "inbound_streams" | "frame" | "stream_receive" | "session_receive" => {
            ("yamux", "resource_exhausted")
        }
        "proxy_body" => ("rpc", "resource_exhausted"),
        _ => return Err(format!("unknown diagnostic case {case_name}").into()),
    };
    Ok(Diagnostic {
        case: case_name.to_owned(),
        path: path.to_owned(),
        stage: stage.to_owned(),
        code: code.to_owned(),
    })
}

fn emit(value: &Value) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn wire_error(code: u32, message: impl Into<String>) -> WireRpcError {
    WireRpcError {
        code,
        message: Some(message.into()),
    }
}

fn join_task<T>(outcome: Result<T, JoinError>) -> HarnessResult<T> {
    outcome.map_err(|error| format!("supervised task failed: {error}").into())
}

fn has_yamux_reset(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(value) = current {
        if matches!(value.downcast_ref::<YamuxError>(), Some(YamuxError::Reset)) {
            return true;
        }
        current = value.source();
    }
    false
}
