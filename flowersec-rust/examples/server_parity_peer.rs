#![recursion_limit = "256"]

use std::{
    env,
    io::{self, BufRead, Read, Write},
    net::{SocketAddr, TcpListener, UdpSocket},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use flowersec::{ByteStream, SessionError, UnreliableSendOutcome};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[path = "server_parity/current_application.rs"]
mod current_application;
#[path = "server_parity/current_live_deployment.rs"]
mod current_live_deployment;
#[path = "server_parity/current_tunnel.rs"]
mod current_tunnel;

const CURRENT_PROFILE: &str = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
const ECHO_RPC: u32 = 7001;
const NOTIFY_RPC: u32 = 7002;
const COMPLETE_RPC: u32 = 7003;
const DATAGRAM_READY_RPC: u32 = 7005;

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct TunnelTopology {
    id: String,
    endpoint_a: String,
    endpoint_b: String,
    tunnel_runtime: String,
    ingress_carrier_a: String,
    ingress_carrier_b: String,
}

/// Current engineering material is a JSON projection of complete signed v4
/// maps. Byte strings use canonical base64 in JSON, matching Go and TS peers.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
struct CurrentNamespaceRecord {
    tenant: String,
    authority: String,
    generation: u64,
    root_key_id: String,
    root_public_key: String,
    bootstrap_url: String,
    state_url: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CurrentGeneration {
    source: String,
    generation: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct CurrentTunnelMaterial {
    candidate_index: u64,
    role: u8,
    #[serde(default)]
    grant: Option<String>,
    #[serde(default)]
    live_grant: Option<CurrentLiveGrantMaterial>,
    relay_certificate: String,
    grant_namespace: u8,
    relay_namespace: u8,
}

#[derive(Clone, Debug, Deserialize)]
struct CurrentLiveGrantMaterial {
    authority: String,
    issuer_key_id: String,
    audience: String,
    service: String,
    revocation_policy_id: String,
    revocation_policy_revision: String,
    max_not_after_ms: String,
}
#[derive(Clone, Deserialize)]
struct CurrentMaterial {
    wire_revision: u8,
    profile: String,
    source: String,
    generation: CurrentGeneration,
    role: u8,
    artifact: String,
    #[serde(deserialize_with = "current_activation")]
    activation: String,
    client_certificate: String,
    server_certificate: String,
    route: String,
    route_digest: String,
    activation_signing_key_id: String,
    identity_seed: String,
    dh_seed: String,
    namespaces: Vec<CurrentNamespaceRecord>,
    tunnels: Vec<CurrentTunnelMaterial>,
    #[serde(default)]
    live_control_base_url: Option<String>,
}

fn current_activation<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<String, D::Error> {
    // Go represents an unissued live activation as null. Only this field may
    // decode that way; source validation still requires a nonempty pool proof.
    Ok(Option::<String>::deserialize(decoder)?.unwrap_or_default())
}

impl std::fmt::Debug for CurrentMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentMaterial { <opaque> }")
    }
}
impl Drop for CurrentMaterial {
    fn drop(&mut self) {
        self.artifact.zeroize();
        self.identity_seed.zeroize();
        self.dh_seed.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
struct CurrentTunnelAuthorization {
    candidate_index: u64,
    role: u8,
    grant: String,
    endpoint_certificate: String,
    relay_certificate: String,
    grant_namespace: u8,
    endpoint_namespace: u8,
    relay_namespace: u8,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct CurrentRelayEndpoint {
    carrier: String,
    address: String,
    endpoint_url: String,
    server_certificate_der: String,
    #[serde(default)]
    server_private_key_pkcs8: Option<String>,
}

impl std::fmt::Debug for CurrentRelayEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentRelayEndpoint { <opaque> }")
    }
}
impl Drop for CurrentRelayEndpoint {
    fn drop(&mut self) {
        if let Some(key) = &mut self.server_private_key_pkcs8 {
            key.zeroize();
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct CurrentIssuerResponse {
    wire_revision: u8,
    artifact_json: Option<String>,
    endpoint_a_artifact_json: Option<String>,
    endpoint_b_artifact_json: Option<String>,
    #[serde(default)]
    server_material_json: Option<String>,
    #[serde(default)]
    lifecycle: Option<String>,
    #[serde(default)]
    endpoint_address: Option<String>,
    #[serde(default)]
    endpoint_url: Option<String>,
    #[serde(default)]
    relay_endpoints: Vec<CurrentRelayEndpoint>,
    #[serde(default)]
    server_certificate_der: Option<String>,
    #[serde(default)]
    server_private_key_pkcs8: Option<String>,
    #[serde(default)]
    authorizations: Vec<CurrentTunnelAuthorization>,
    #[serde(default)]
    verification_records: Vec<CurrentNamespaceRecord>,
    trust_pem: String,
    origin: String,
    #[serde(default)]
    relay_identity_seed: Option<String>,
    #[serde(default)]
    client_tls_certificate_pem: String,
    #[serde(default)]
    client_tls_private_key_pem: String,
    #[serde(default)]
    server_tls_certificate_pem: String,
    #[serde(default)]
    server_tls_private_key_pem: String,
}

impl std::fmt::Debug for CurrentIssuerResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentIssuerResponse { <opaque> }")
    }
}
impl Drop for CurrentIssuerResponse {
    fn drop(&mut self) {
        for wire in [
            &mut self.artifact_json,
            &mut self.endpoint_a_artifact_json,
            &mut self.endpoint_b_artifact_json,
            &mut self.server_material_json,
            &mut self.server_private_key_pkcs8,
            &mut self.relay_identity_seed,
        ]
        .into_iter()
        .flatten()
        {
            wire.zeroize();
        }
        self.client_tls_private_key_pem.zeroize();
        self.server_tls_private_key_pem.zeroize();
        for endpoint in &mut self.relay_endpoints {
            if let Some(key) = &mut endpoint.server_private_key_pkcs8 {
                key.zeroize();
            }
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct CurrentReady {
    #[serde(rename = "type")]
    message_type: String,
    runtime: String,
    carrier: String,
    path: String,
    wire_revision: u8,
    artifact_json: String,
    trust_pem: String,
    origin: String,
    profile: String,
    source: String,
}

impl std::fmt::Debug for CurrentReady {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentReady { <opaque> }")
    }
}
impl Drop for CurrentReady {
    fn drop(&mut self) {
        self.artifact_json.zeroize();
    }
}

#[derive(Serialize)]
struct CurrentResultMessage<'a> {
    #[serde(rename = "type")]
    message_type: &'a str,
    runtime: &'a str,
    carrier: &'a str,
    path: &'a str,
    wire_revision: u8,
    profile: &'a str,
    source: &'a str,
    cases: Vec<&'a str>,
}

/// The original pipe reader clears consumed material immediately and owns
/// one fixed backing until drop. Generic BufReader scratch would retain an
/// issued secret even after the complete protocol line had been cleared.
struct CurrentProtocolReader<R> {
    source: R,
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
    end: usize,
}
impl<R> CurrentProtocolReader<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            bytes: Zeroizing::new(vec![0; 8192]),
            position: 0,
            end: 0,
        }
    }
}
impl<R: Read> Read for CurrentProtocolReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let available = self.fill_buf()?;
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}
impl<R: Read> BufRead for CurrentProtocolReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position == self.end {
            self.bytes.as_mut_slice().zeroize();
            self.position = 0;
            self.end = 0;
            self.end = self.source.read(self.bytes.as_mut_slice())?;
        }
        Ok(&self.bytes[self.position..self.end])
    }
    fn consume(&mut self, amount: usize) {
        let next = self.position + amount.min(self.end - self.position);
        self.bytes[self.position..next].zeroize();
        self.position = next;
    }
}

struct PersistentIssuer {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<CurrentProtocolReader<ChildStdout>>,
    capture_digest: Option<[u8; 32]>,
}
impl PersistentIssuer {
    fn start(request: &Value) -> (Self, CurrentIssuerResponse) {
        Self::start_with_prepared(request, None)
    }
    fn start_with_prepared(
        request: &Value,
        prepared: Option<&dyn Fn(&Value)>,
    ) -> (Self, CurrentIssuerResponse) {
        let mut child = Command::new("go")
            .args([
                "-C",
                "flowersec-go",
                "run",
                "./internal/cmd/parity-artifact-issuer",
            ])
            .env("FLOWERSEC_SERVER_PARITY_PEER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start current v4 issuer deployment");
        let mut input = child.stdin.take().expect("issuer stdin");
        serde_json::to_writer(&mut input, request).expect("write current issuer request");
        input
            .write_all(b"\n")
            .expect("finish current issuer request");
        let mut output = CurrentProtocolReader::new(child.stdout.take().expect("issuer stdout"));
        let mut line = read_current_protocol_line(&mut output);
        if let Some(prepared) = prepared {
            let message: Value =
                serde_json::from_str(&line).expect("original registered relay preparation");
            prepared(&message);
            print_current_protocol_message(&message);
            line.zeroize();
            line = read_current_protocol_line(&mut output);
        }
        let response: CurrentIssuerResponse =
            serde_json::from_str(&line).expect("decode current issuer response");
        assert_eq!(
            response.wire_revision, 4,
            "current issuer response must be v4"
        );
        assert_eq!(
            response.lifecycle.as_deref(),
            Some("persistent"),
            "current issuer must retain its deployment"
        );
        let capture_digest = request
            .get("relay_owner_handoff")
            .and_then(Value::as_bool)
            .filter(|value| *value)
            .map(|_| Sha256::digest(line.strip_suffix('\n').unwrap_or(&line).as_bytes()).into());
        zeroize::Zeroize::zeroize(&mut line);
        (
            Self {
                child,
                input: Some(input),
                output: Some(output),
                capture_digest,
            },
            response,
        )
    }

    fn serve_original_winner(
        &mut self,
        mut original: flowersec::OriginalRelayPoolWinner,
    ) -> tokio::task::JoinHandle<(ChildStdin, CurrentProtocolReader<ChildStdout>)> {
        assert!(
            self.capture_digest.is_none(),
            "original relay capture must precede winner continuation"
        );
        let mut input = self
            .input
            .take()
            .expect("original relay continuation stdin");
        let mut output = self
            .output
            .take()
            .expect("original relay continuation stdout");
        tokio::task::spawn_blocking(move || {
            let line = read_current_protocol_line(&mut output);
            assert!(
                line.len() <= 16384,
                "original winner control exceeds its bound"
            );
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request {
                #[serde(rename = "type")]
                kind: String,
                lease: String,
                projection: String,
            }
            let request: Request =
                serde_json::from_str(&line).expect("decode one original winner continuation");
            assert_eq!(request.kind, "original-winner-continue");
            let lease = current_bytes(&request.lease, 161, None);
            let projection = current_bytes(&request.projection, 8192, None);
            original
                .match_original(&lease, &projection)
                .expect("match the winner actually claimed by this original Rust HOP");
            let digest: [u8; 32] =
                Sha256::digest(line.strip_suffix('\n').unwrap_or(&line).as_bytes()).into();
            serde_json::to_writer(&mut input, &serde_json::json!({"type":"original-winner-matched", "digest":STANDARD.encode(digest)}))
                .expect("acknowledge exact original winner continuation");
            input
                .write_all(b"\n")
                .expect("finish original winner acknowledgement");
            drop(original);
            (input, output)
        })
    }

    fn acknowledge_original_capture(&mut self) {
        let digest = self
            .capture_digest
            .take()
            .expect("one original relay handoff acknowledgement");
        assert!(
            self.child
                .try_wait()
                .expect("original issuer process state")
                .is_none(),
            "original issuer exited before capture"
        );
        let input = self
            .input
            .as_mut()
            .expect("original issuer continuation input");
        serde_json::to_writer(
            &mut *input,
            &serde_json::json!({"type":"original-relay-captured","digest":STANDARD.encode(digest)}),
        )
        .expect("acknowledge exact original relay capture");
        input
            .write_all(b"\n")
            .expect("finish original relay capture acknowledgement");
    }

    fn shutdown(mut self) {
        if let Some(mut input) = self.input.take() {
            serde_json::to_writer(&mut input, &serde_json::json!({"type":"shutdown"}))
                .expect("write current issuer shutdown");
            input
                .write_all(b"\n")
                .expect("finish current issuer shutdown");
        }
        self.output.take();
        let status =
            wait_for_issuer_exit(&mut self.child).expect("wait for current issuer shutdown");
        assert!(
            status.success(),
            "current issuer deployment did not shut down cleanly"
        );
    }
}
fn wait_for_issuer_exit(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                child.kill()?;
                return child.wait();
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    }
}
impl Drop for PersistentIssuer {
    fn drop(&mut self) {
        if let Some(mut input) = self.input.take() {
            let _ = serde_json::to_writer(&mut input, &serde_json::json!({"type":"shutdown"}));
            let _ = input.write_all(b"\n");
        }
        self.output.take();
        let _ = wait_for_issuer_exit(&mut self.child);
    }
}

#[derive(Debug)]
struct CurrentParityLease;
#[async_trait]
impl flowersec::ApplicationAuthorizationLease for CurrentParityLease {
    fn close(&self) {}
    async fn wait_cleanup(&self) -> Result<flowersec::CleanupStatus, flowersec::ServeError> {
        Ok(flowersec::CleanupStatus {
            complete: true,
            cleanup_incomplete: false,
            pending_callbacks: 0,
        })
    }
}

#[derive(Debug)]
struct CurrentParityCallbacks {
    plan: flowersec::HandlerPlan,
    application: Option<Arc<current_application::Application>>,
}
#[async_trait]
impl flowersec::ServeCallbacks for CurrentParityCallbacks {
    async fn authorize_request(
        &self,
        _context: flowersec::ServeRequestContext,
    ) -> Result<flowersec::RequestAuthorization, flowersec::ServeError> {
        Ok(flowersec::RequestAuthorization { allowed: true })
    }
    async fn resolve_handlers(
        &self,
        _context: flowersec::AuthenticatedRequestContext,
    ) -> Result<flowersec::HandlerPlan, flowersec::ServeError> {
        Ok(self.plan.clone())
    }
    async fn authorize_application(
        &self,
        context: flowersec::AuthenticatedRequestContext,
        handlers: flowersec::HandlerPlan,
    ) -> Result<flowersec::AuthorizeApplicationResult, flowersec::ServeError> {
        context.reserve_lease(context.binding(), Arc::new(CurrentParityLease))?;
        Ok(flowersec::AuthorizeApplicationResult::Authorized { handlers })
    }
    async fn on_session(
        &self,
        session: flowersec::Session,
        context: flowersec::AuthenticatedRequestContext,
    ) -> Result<flowersec::SessionAcceptance, flowersec::ServeError> {
        if let Some(application) = &self.application {
            application.published(
                session,
                context
                    .services()
                    .expect("original published service graph"),
            );
        }
        Ok(flowersec::SessionAcceptance::Queue)
    }
    async fn release(
        &self,
        _context: flowersec::ServeReleaseContext,
    ) -> Result<flowersec::CleanupStatus, flowersec::ServeError> {
        Ok(flowersec::CleanupStatus {
            complete: true,
            cleanup_incomplete: false,
            pending_callbacks: 0,
        })
    }
}

#[derive(Debug)]
struct CurrentAcceptedSource {
    credential: flowersec::PoolCredentialBytes,
}
#[async_trait]
impl flowersec::AcceptedMaterialSource for CurrentAcceptedSource {
    async fn resolve(
        &self,
        _client_hello: &[u8],
        cancellation: CancellationToken,
    ) -> Result<flowersec::PoolCredentialBytes, flowersec::TransportConnectError> {
        if cancellation.is_cancelled() {
            return Err(flowersec::TransportConnectError::Canceled);
        }
        Ok(flowersec::PoolCredentialBytes {
            artifact: self.credential.artifact.clone(),
            client_certificate: self.credential.client_certificate.clone(),
            server_certificate: self.credential.server_certificate.clone(),
            activation: self.credential.activation.clone(),
        })
    }
}

#[derive(Clone, Debug, Default)]
struct ExecutionLedger {
    cases: Arc<Mutex<Vec<&'static str>>>,
}

impl ExecutionLedger {
    fn record(&self, case_ids: &[&'static str]) {
        let mut cases = self.cases.lock().expect("execution ledger lock poisoned");
        for case_id in case_ids {
            if !cases.contains(case_id) {
                cases.push(case_id);
            }
        }
    }

    fn snapshot(&self) -> Vec<&'static str> {
        self.cases
            .lock()
            .expect("execution ledger lock poisoned")
            .clone()
    }
}

#[derive(Debug)]
struct CurrentClock {
    epoch: Duration,
    started: tokio::time::Instant,
}
impl flowersec::TrustedTimeSource for CurrentClock {
    fn sample(&self) -> Result<flowersec::TrustedTimeSample, flowersec::EnvironmentError> {
        self.sample_at(tokio::time::Instant::now())
    }
}
impl CurrentClock {
    fn sample_at(
        &self,
        now: tokio::time::Instant,
    ) -> Result<flowersec::TrustedTimeSample, flowersec::EnvironmentError> {
        let elapsed = now.saturating_duration_since(self.started);
        if elapsed > Duration::from_secs(30 * 60) {
            return Err(flowersec::EnvironmentError::TimeUnavailable);
        }
        let age = u64::try_from(elapsed.as_nanos().div_ceil(1_000_000))
            .map_err(|_| flowersec::EnvironmentError::TimeUnavailable)?;
        // Preserve the anchor's fractional millisecond so independent wall
        // and monotonic quantization cannot delay a freshly issued credential.
        let lower = u64::try_from(
            self.epoch
                .checked_add(elapsed)
                .ok_or(flowersec::EnvironmentError::TimeUnavailable)?
                .as_millis(),
        )
        .map_err(|_| flowersec::EnvironmentError::TimeUnavailable)?;
        Ok(flowersec::TrustedTimeSample {
            lower_ms: lower,
            upper_ms: lower
                .checked_add(2)
                .ok_or(flowersec::EnvironmentError::TimeUnavailable)?,
            monotonic_sample: now,
            clock_incarnation: 1,
            anchor_age_upper_ms: age,
        })
    }
}
fn current_environment() -> flowersec::TransportEnvironment {
    current_environment_for_role(false, false, None)
}
fn current_relay_environment() -> flowersec::TransportEnvironment {
    current_environment_for_role(true, false, None)
}
fn current_environment_for_role(
    relay: bool,
    concurrent_server_registration: bool,
    relay_provider_bytes: Option<u64>,
) -> flowersec::TransportEnvironment {
    assert_eq!(
        env::var("FLOWERSEC_SERVER_PARITY_PEER").as_deref(),
        Ok("1"),
        "current parity peers require explicit engineering authority enablement"
    );
    // The test deployment installs one host-time anchor before any namespace
    // bootstrap. Every later sample projects only this original monotonic clock.
    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("engineering time anchor");
    let started = tokio::time::Instant::now();
    let mut options = flowersec::TransportEnvironmentOptions {
        clock: Some(Arc::new(CurrentClock { epoch, started })),
        time_profile: flowersec::TrustedTimeProfile {
            max_anchor_age_ms: 30 * 60 * 1000,
            ..flowersec::TrustedTimeProfile::default()
        },
        ..flowersec::TransportEnvironmentOptions::default()
    };
    // The shared NamespaceCapacity fixture permits all three 1024-entry
    // revocation classes. Reserve enough per-session SDK space for that
    // complete bounded verifier before constructing a signed source.
    options.session_limits.sdk_bytes = 64 << 20;
    options.session_limits.provider_bytes = 64 << 20;
    options.session_limits.items = 32_768;
    options.session_limits.work_slots = 512;
    options.session_limits.tasks = 512;
    options.session_limits.timers = 8_192;
    options.session_limits.native_handles = 64;
    options.root_limits.sdk_bytes = 512 << 20;
    options.root_limits.provider_bytes = 512 << 20;
    options.tenant_limits.sdk_bytes = 128 << 20;
    options.tenant_limits.provider_bytes = 128 << 20;
    if concurrent_server_registration {
        // Dialed live B must keep its original mTLS registration and native
        // carrier TLS preparation in flight together until both owners join.
        options.session_limits.tls_handshakes = 2;
    }
    if relay {
        // Each leg prepays 54 mapping positions, their two bounded queues,
        // four workers per position and the native provider window. Both legs
        // coexist in the same tenant until physical forwarding has joined.
        options.session_limits.sdk_bytes = 128 << 20;
        options.session_limits.provider_bytes = 128 << 20;
        options.session_limits.work_slots = 2048;
        options.session_limits.tasks = 2048;
        options.session_limits.native_handles = 1024;
        options.tenant_limits.sdk_bytes = 256 << 20;
        options.tenant_limits.provider_bytes = 256 << 20;
        options.tenant_limits.work_slots = 8192;
        options.tenant_limits.tasks = 8192;
        options.tenant_limits.native_handles = 4096;
        options.root_limits.work_slots = 8192;
        options.root_limits.tasks = 8192;
        options.root_limits.native_handles = 4096;
        if let Some(bytes) = relay_provider_bytes {
            options.root_limits.provider_bytes = bytes;
        }
    }
    if env::var("FLOWERSEC_PARITY_HOP_CAPACITY_PROBE").as_deref() == Ok("insufficient") {
        // Pool facts, tunnel material and server Allow each retain one item.
        // Source verification temporarily adds one item, for a peak of four;
        // EndpointHop needs three more retained items, for a total of six.
        // Leave one item less than HOP requires while preserving the ordinary
        // SDK byte budget for verification. Source capture and Acquire must
        // succeed before HOP preparation fails, before pool spend or exchange.
        options.session_limits.items = 1 + 1 + 1 + 3 - 1;
    }
    flowersec::TransportEnvironment::with_options(options)
        .expect("install original engineering Environment clock")
}

fn current_bytes(value: &str, maximum: usize, exact: Option<usize>) -> Vec<u8> {
    assert!(
        value.len() <= maximum.div_ceil(3) * 4,
        "current byte string exceeds its encoded bound"
    );
    let bytes = STANDARD.decode(value).expect("decode current base64 bytes");
    assert!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "current byte string is empty or oversized"
    );
    assert!(
        exact.is_none_or(|size| size == bytes.len()),
        "current byte string has the wrong size"
    );
    assert_eq!(
        STANDARD.encode(&bytes),
        value,
        "current byte string is not canonical base64"
    );
    bytes
}

#[derive(Debug)]
enum CurrentCborValue {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CurrentCborValue>),
    Map(Vec<(CurrentCborValue, CurrentCborValue)>),
    Bool(bool),
    Null,
}

fn current_cbor_argument(input: &[u8], cursor: &mut usize, additional: u8) -> Option<u64> {
    match additional {
        0..=23 => Some(u64::from(additional)),
        24 => {
            let value = *input.get(*cursor)?;
            *cursor += 1;
            Some(u64::from(value))
        }
        25 => {
            let bytes = input.get(*cursor..*cursor + 2)?;
            *cursor += 2;
            Some(u64::from(u16::from_be_bytes(bytes.try_into().ok()?)))
        }
        26 => {
            let bytes = input.get(*cursor..*cursor + 4)?;
            *cursor += 4;
            Some(u64::from(u32::from_be_bytes(bytes.try_into().ok()?)))
        }
        27 => {
            let bytes = input.get(*cursor..*cursor + 8)?;
            *cursor += 8;
            Some(u64::from_be_bytes(bytes.try_into().ok()?))
        }
        _ => None,
    }
}

fn current_cbor_value(input: &[u8], cursor: &mut usize, depth: usize) -> Option<CurrentCborValue> {
    if depth > 32 {
        return None;
    }
    let head = *input.get(*cursor)?;
    *cursor += 1;
    let major = head >> 5;
    let additional = head & 0x1f;
    let length = current_cbor_argument(input, cursor, additional)?;
    match major {
        0 => Some(CurrentCborValue::Uint(length)),
        1 => Some(CurrentCborValue::Uint(u64::MAX.saturating_sub(length))),
        2 => {
            let size = usize::try_from(length).ok()?;
            let bytes = input.get(*cursor..*cursor + size)?.to_vec();
            *cursor += size;
            Some(CurrentCborValue::Bytes(bytes))
        }
        3 => {
            let size = usize::try_from(length).ok()?;
            let value = std::str::from_utf8(input.get(*cursor..*cursor + size)?)
                .ok()?
                .to_owned();
            *cursor += size;
            Some(CurrentCborValue::Text(value))
        }
        4 => {
            let count = usize::try_from(length).ok()?;
            let mut values = Vec::with_capacity(count.min(256));
            for _ in 0..count {
                values.push(current_cbor_value(input, cursor, depth + 1)?);
            }
            Some(CurrentCborValue::Array(values))
        }
        5 => {
            let count = usize::try_from(length).ok()?;
            let mut values = Vec::with_capacity(count.min(256));
            for _ in 0..count {
                values.push((
                    current_cbor_value(input, cursor, depth + 1)?,
                    current_cbor_value(input, cursor, depth + 1)?,
                ));
            }
            Some(CurrentCborValue::Map(values))
        }
        7 if additional == 20 || additional == 21 => Some(CurrentCborValue::Bool(additional == 21)),
        7 if additional == 22 => Some(CurrentCborValue::Null),
        7 => {
            let _ = length;
            Some(CurrentCborValue::Null)
        }
        _ => None,
    }
}

fn current_encode_cbor(value: &CurrentCborValue, output: &mut Vec<u8>) {
    fn head(output: &mut Vec<u8>, major: u8, value: u64) {
        let prefix = major << 5;
        match value {
            0..=23 => output.push(prefix | value as u8),
            24..=255 => {
                output.push(prefix | 24);
                output.push(value as u8);
            }
            256..=65535 => {
                output.push(prefix | 25);
                output.extend_from_slice(&(value as u16).to_be_bytes());
            }
            65536..=4294967295 => {
                output.push(prefix | 26);
                output.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                output.push(prefix | 27);
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
    match value {
        CurrentCborValue::Uint(value) => head(output, 0, *value),
        CurrentCborValue::Bytes(value) => {
            head(output, 2, value.len() as u64);
            output.extend_from_slice(value);
        }
        CurrentCborValue::Text(value) => {
            head(output, 3, value.len() as u64);
            output.extend_from_slice(value.as_bytes());
        }
        CurrentCborValue::Array(values) => {
            head(output, 4, values.len() as u64);
            for value in values {
                current_encode_cbor(value, output);
            }
        }
        CurrentCborValue::Map(values) => {
            head(output, 5, values.len() as u64);
            for (key, value) in values {
                current_encode_cbor(key, output);
                current_encode_cbor(value, output);
            }
        }
        CurrentCborValue::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        CurrentCborValue::Null => output.push(0xf6),
    }
}

fn current_cbor_map_field(
    fields: &[(CurrentCborValue, CurrentCborValue)],
    id: u64,
) -> Option<&CurrentCborValue> {
    fields.iter().find_map(|(key, value)| {
        matches!(key, CurrentCborValue::Uint(value) if *value == id).then_some(value)
    })
}

fn current_route_endpoint(encoded: &[u8], role: u8) -> (u8, String, u16, String, Option<String>) {
    let mut cursor = 0;
    let root = current_cbor_value(encoded, &mut cursor, 0).expect("decode current Route CBOR");
    let CurrentCborValue::Map(route) = root else {
        panic!("current Route is not a map")
    };
    let path_kind = match current_cbor_map_field(&route, 0).expect("current Route path kind") {
        CurrentCborValue::Uint(value) => *value,
        _ => panic!("current Route path kind type"),
    };
    let leg_id = if path_kind == 0 {
        2
    } else if role == 0 {
        3
    } else {
        4
    };
    let CurrentCborValue::Map(leg) =
        current_cbor_map_field(&route, leg_id).expect("current Route leg")
    else {
        panic!("current Route leg type")
    };
    let carrier = match current_cbor_map_field(leg, 5).expect("current Leg carrier") {
        CurrentCborValue::Uint(value) => u8::try_from(*value).expect("current Leg carrier range"),
        _ => panic!("current Leg carrier type"),
    };
    let host = match current_cbor_map_field(leg, 6).expect("current Leg host") {
        CurrentCborValue::Text(value) => value.clone(),
        _ => panic!("current Leg host type"),
    };
    let port = match current_cbor_map_field(leg, 7).expect("current Leg port") {
        CurrentCborValue::Uint(value) => u16::try_from(*value).expect("current Leg port range"),
        _ => panic!("current Leg port type"),
    };
    let path = match current_cbor_map_field(leg, 8).expect("current Leg path") {
        CurrentCborValue::Text(value) => value.clone(),
        _ => panic!("current Leg path type"),
    };
    let origin = current_cbor_map_field(leg, 13).and_then(|value| match value {
        CurrentCborValue::Text(value) => Some(value.clone()),
        _ => None,
    });
    (carrier, host, port, path, origin)
}

fn current_certificate_digest(certificate: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"flowersec/v4/certificate-digest\0");
    hash.update(
        u32::try_from(certificate.len())
            .expect("bounded certificate map")
            .to_be_bytes(),
    );
    hash.update(certificate);
    hash.finalize().into()
}

fn current_artifact_binding(encoded: &[u8]) -> (String, [u8; 16], String) {
    let mut cursor = 0;
    let root = current_cbor_value(encoded, &mut cursor, 0).expect("decode current Artifact CBOR");
    assert_eq!(
        cursor,
        encoded.len(),
        "current Artifact has trailing CBOR bytes"
    );
    let CurrentCborValue::Map(fields) = root else {
        panic!("current Artifact is not a CBOR map")
    };
    let mut tenant = None;
    let mut issuer = None;
    let mut audience = None;
    for (key, value) in fields {
        let CurrentCborValue::Uint(key) = key else {
            continue;
        };
        match key {
            4 => {
                if let CurrentCborValue::Text(value) = value {
                    tenant = Some(value);
                }
            }
            5 => {
                if let CurrentCborValue::Bytes(value) = value {
                    issuer = Some(value);
                }
            }
            11 => {
                if let CurrentCborValue::Text(value) = value {
                    audience = Some(value);
                }
            }
            _ => {}
        }
    }
    let issuer: [u8; 16] = issuer
        .expect("current Artifact issuer key id")
        .try_into()
        .expect("current Artifact issuer key id length");
    (
        tenant.expect("current Artifact tenant"),
        issuer,
        audience.expect("current Artifact audience"),
    )
}

fn parse_current_material(wire: &str, expected_role: u8) -> CurrentMaterial {
    assert!(
        wire.len() <= 1_048_576,
        "current material exceeds its envelope bound"
    );
    let material: CurrentMaterial =
        serde_json::from_str(wire).expect("decode current signed material envelope");
    assert_eq!(
        material.wire_revision, 4,
        "current material has the wrong wire revision"
    );
    assert_eq!(
        material.role, expected_role,
        "current material has the wrong logical endpoint role"
    );
    assert!(
        matches!(
            material.profile.as_str(),
            "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1"
                | "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"
        ),
        "unsupported current session profile"
    );
    assert!(
        matches!(
            material.source.as_str(),
            "preauthorized_pool" | "live_authority"
        ),
        "unsupported current authorization source"
    );
    current_bytes(&material.artifact, 65_536, None);
    current_bytes(&material.route, 16_384, None);
    current_bytes(&material.route_digest, 32, Some(32));
    current_bytes(&material.client_certificate, 16_384, None);
    current_bytes(&material.server_certificate, 16_384, None);
    current_bytes(&material.identity_seed, 32, Some(32));
    current_bytes(&material.dh_seed, 32, Some(32));
    if material.source == "preauthorized_pool" {
        current_bytes(&material.activation, 65_536, None);
    } else {
        assert!(
            material.activation.is_empty(),
            "live current material must leave activation with its authority"
        );
    }
    current_bytes(&material.generation.source, 64, None);
    assert!(
        material.generation.generation > 0,
        "invalid current material generation"
    );
    assert!(
        !material.activation_signing_key_id.is_empty()
            && material.activation_signing_key_id.len() <= 128,
        "invalid current activation key id"
    );
    assert!(
        !material.namespaces.is_empty() && material.namespaces.len() <= 16,
        "current material needs bounded namespace pins"
    );
    for tunnel in &material.tunnels {
        assert!(
            tunnel.candidate_index < 16 && tunnel.role < 2,
            "invalid current tunnel slot"
        );
        current_bytes(&tunnel.relay_certificate, 8192, None);
        if let Some(grant) = &tunnel.grant {
            current_bytes(grant, 65_536, None);
        }
        assert!(
            usize::from(tunnel.grant_namespace) < material.namespaces.len(),
            "invalid current Grant namespace index"
        );
        assert!(
            usize::from(tunnel.relay_namespace) < material.namespaces.len(),
            "invalid current relay namespace index"
        );
    }
    material
}

async fn current_https_post(url: &str, trust_pem: &str, body: &[u8], maximum: usize) -> Vec<u8> {
    let parsed = url::Url::parse(url).expect("parse current authority URL");
    assert_eq!(
        parsed.scheme(),
        "https",
        "current namespace endpoints require HTTPS"
    );
    assert!(
        parsed.username().is_empty() && parsed.password().is_none() && parsed.fragment().is_none(),
        "invalid current authority URL"
    );
    let host = parsed.host_str().expect("current authority URL host");
    assert!(
        matches!(host, "localhost" | "127.0.0.1" | "::1"),
        "current engineering authority must be local"
    );
    let port = parsed
        .port_or_known_default()
        .expect("current authority URL port");
    let address = tokio::net::TcpStream::connect((host, port))
        .await
        .expect("connect current authority");
    let mut roots = rustls::RootCertStore::empty();
    let mut root_count = 0;
    for certificate in CertificateDer::pem_slice_iter(trust_pem.as_bytes()) {
        let certificate = certificate.expect("parse current bootstrap trust PEM");
        roots
            .add(certificate)
            .expect("install current bootstrap trust certificate");
        root_count += 1;
    }
    assert!(root_count > 0, "current bootstrap trust roots are required");
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .expect("current authority server name");
    let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, address)
        .await
        .expect("verify current authority TLS");
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write current authority request");
    stream
        .write_all(body)
        .await
        .expect("write current authority body");
    stream
        .flush()
        .await
        .expect("flush current authority request");
    let mut response = Vec::new();
    stream
        .take((maximum + 16384) as u64)
        .read_to_end(&mut response)
        .await
        .expect("read current authority response");
    assert!(
        response.len() <= maximum + 16384,
        "current authority response exceeds its bound"
    );
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("current HTTP response headers");
    let headers =
        std::str::from_utf8(&response[..split]).expect("current HTTP response header encoding");
    assert!(
        headers
            .lines()
            .next()
            .is_some_and(|line| line.contains(" 200 ")),
        "current authority rejected bootstrap"
    );
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    let mut payload = response[split + 4..].to_vec();
    if let Some(length) = content_length {
        assert_eq!(
            payload.len(),
            length,
            "truncated current authority response"
        );
    } else if headers.lines().any(|line| {
        line.to_ascii_lowercase().starts_with("transfer-encoding:")
            && line.to_ascii_lowercase().contains("chunked")
    }) {
        let mut decoded = Vec::new();
        let mut cursor = 0;
        loop {
            let line_end = payload[cursor..]
                .windows(2)
                .position(|window| window == b"\r\n")
                .expect("current chunk size");
            let size_text = std::str::from_utf8(&payload[cursor..cursor + line_end])
                .expect("current chunk size encoding");
            let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16)
                .expect("current chunk size");
            cursor += line_end + 2;
            if size == 0 {
                break;
            }
            assert!(
                decoded.len().saturating_add(size) <= maximum,
                "current authority payload exceeds its bound"
            );
            decoded.extend_from_slice(&payload[cursor..cursor + size]);
            cursor += size;
            assert_eq!(
                &payload[cursor..cursor + 2],
                b"\r\n",
                "invalid current chunk terminator"
            );
            cursor += 2;
        }
        payload = decoded;
    }
    assert!(
        payload.len() <= maximum,
        "current authority payload exceeds its bound"
    );
    payload
}

#[derive(Debug)]
struct CurrentContinuity;
impl flowersec::SQLitePoolContinuity for CurrentContinuity {
    fn check(
        &self,
        _identity: &flowersec::SQLitePoolIdentity,
        _epoch: u64,
        _provisioning: bool,
    ) -> Result<(), flowersec::PoolStoreError> {
        Ok(())
    }
}

struct CurrentPoolStore {
    store: Arc<flowersec::SQLitePoolStore>,
    backing: flowersec::SQLitePoolBacking,
    directory: std::path::PathBuf,
}
impl Drop for CurrentPoolStore {
    fn drop(&mut self) {
        self.store.close();
        if self.store.cleanup_complete() {
            std::fs::remove_dir_all(&self.directory)
                .expect("remove original closed engineering pool files");
            self.backing
                .release_removed()
                .expect("release physically removed engineering pool backing");
        }
    }
}

fn current_pool_store(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    artifact: &[u8],
) -> CurrentPoolStore {
    current_pool_store_named(environment, material, artifact, "pool")
}

fn current_pool_store_named(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    artifact: &[u8],
    name: &str,
) -> CurrentPoolStore {
    let (tenant, issuer, audience) = current_artifact_binding(artifact);
    let artifact_root = std::env::var_os("FLOWERSEC_TASK_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .expect("resolve current parity directory")
                .parent()
                .expect("resolve repository parent")
                .join("flowersec-current-rust-artifacts")
        });
    assert!(
        !artifact_root
            .starts_with(std::env::current_dir().expect("resolve current parity directory")),
        "current pool artifacts must stay outside the repository"
    );
    let root = artifact_root.join(format!(
        "flowersec-current-rust-{}-{}-{name}",
        std::process::id(),
        material.role
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create current pool directory");
    let path = std::fs::canonicalize(&root)
        .expect("canonicalize current pool directory")
        .join("pool.sqlite");
    let generation_source = current_bytes(&material.generation.source, 64, None);
    let source = Sha256::digest(&generation_source);
    let mut store_id = [0u8; 32];
    store_id.copy_from_slice(&source);
    let backing = environment
        .sqlite_pool_backing(
            path,
            flowersec::SQLitePoolLimits {
                max_pages: 128,
                max_records: 16,
                max_record_bytes: 65_536,
                provider_runtime_bytes: 262_144,
                disk_overhead_bytes: 65_536,
            },
        )
        .expect("create current pool backing");
    let options = flowersec::SQLitePoolOptions {
        identity: flowersec::SQLitePoolIdentity {
            // These are the independent engineering installation mappings;
            // signed once authority fields must match them inside the SDK.
            authority: match name {
                "pool" => "spend-1",
                "parent" => "winner-1",
                "accepted" => "local.consumer",
                _ => panic!("unknown original engineering ledger role"),
            }
            .into(),
            store_id,
            generation: material.generation.generation,
        },
        continuity: Arc::new(CurrentContinuity),
        bindings: vec![flowersec::SQLitePoolBinding { tenant, issuer }],
        create: true,
    };
    assert!(!audience.is_empty(), "current Artifact audience is empty");
    let store = backing.open(options).expect("open current pool store");
    CurrentPoolStore {
        store,
        backing,
        directory: root,
    }
}

fn current_provider_options(
    material: &CurrentMaterial,
    trust_pem: &str,
    role: u8,
    expected_carrier: &str,
    configured_origin: &str,
) -> flowersec::WssConnectOptions {
    let (carrier, host, _port, path, route_origin) =
        current_route_endpoint(&current_bytes(&material.route, 16_384, None), role);
    let expected = match expected_carrier {
        "raw-quic" => 0,
        "websocket" => 1,
        "webtransport" => 2,
        _ => panic!("unsupported current carrier"),
    };
    assert_eq!(
        carrier, expected,
        "current signed Route carrier differs from the requested carrier"
    );
    assert!(
        matches!(
            path.as_str(),
            "" | "/flowersec/v4/direct"
                | "/flowersec/v4/tunnel"
                | "/flowersec/webtransport/v4/direct"
                | "/flowersec/webtransport/v4/tunnel"
        ),
        "invalid current carrier path"
    );
    let remote_address = host.parse().unwrap_or_else(|_| {
        if host == "localhost" {
            "127.0.0.1".parse().unwrap()
        } else {
            panic!("current route host is not a numeric local address")
        }
    });
    let ca_certificates_der = CertificateDer::pem_slice_iter(trust_pem.as_bytes())
        .map(|certificate| {
            certificate
                .expect("parse current route trust certificate")
                .to_vec()
        })
        .collect::<Vec<_>>();
    assert!(
        !ca_certificates_der.is_empty(),
        "current route trust roots are required"
    );
    flowersec::WssConnectOptions {
        binding_mode: flowersec::BindingMode::AuthenticatedContext,
        remote_address,
        // The signed Route carries the origin policy; the deployment's
        // independently configured origin supplies the request value.
        origin: (carrier != 0)
            .then(|| route_origin.unwrap_or_else(|| configured_origin.to_owned())),
        ca_certificates_der,
        timeout: Duration::from_secs(10),
        publication_timeout: Duration::from_secs(5),
        queue_messages: 16,
        prepare_bytes: 65_536,
        native_runtime_bytes: if carrier == 1 { 1 << 20 } else { 32 << 20 },
    }
}

fn current_identity(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
) -> flowersec::IdentityKeys {
    let signing_seed = Zeroizing::new(current_bytes(&material.identity_seed, 32, Some(32)));
    let dh_seed = Zeroizing::new(current_bytes(&material.dh_seed, 32, Some(32)));
    environment
        .import_identity_keys(
            &material.profile,
            signing_seed.as_slice().try_into().unwrap(),
            dh_seed.as_slice().try_into().unwrap(),
        )
        .expect("import current original engineering identity keys")
}
fn current_identity_and_credential(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
) -> (flowersec::IdentityKeys, flowersec::PoolCredentialBytes) {
    assert_eq!(
        material.source, "preauthorized_pool",
        "current pool credential construction cannot consume live material"
    );
    let identity = current_identity(environment, material);
    let credential = flowersec::PoolCredentialBytes {
        artifact: current_bytes(&material.artifact, 65_536, None),
        client_certificate: current_bytes(&material.client_certificate, 16_384, None),
        server_certificate: current_bytes(&material.server_certificate, 16_384, None),
        activation: if material.activation.is_empty() {
            Vec::new()
        } else {
            current_bytes(&material.activation, 65_536, None)
        },
    };
    (identity, credential)
}

async fn bootstrap_current_namespaces(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    trust_pem: &str,
) -> Vec<Arc<flowersec::Namespace>> {
    assert!(
        !material.namespaces.is_empty() && material.namespaces.len() <= 16,
        "current material needs bounded namespace pins"
    );
    let mut namespaces = Vec::with_capacity(material.namespaces.len());
    for record in &material.namespaces {
        assert_eq!(
            record.tenant, material.namespaces[0].tenant,
            "current material spans tenants"
        );
        let key_id: [u8; 16] = current_bytes(&record.root_key_id, 16, Some(16))
            .try_into()
            .unwrap();
        let public_key: [u8; 32] = current_bytes(&record.root_public_key, 32, Some(32))
            .try_into()
            .unwrap();
        let namespace = environment
            .namespace(
                flowersec::NamespaceTrustRoot {
                    tenant: record.tenant.clone(),
                    authority: record.authority.clone(),
                    key_id,
                    public_key,
                    // Engineering authorities project their canonical finite
                    // trust lifetime into the shared epoch domain. Keep this
                    // local pin aligned with Go/TypeScript parity fixtures;
                    // the peer response never selects this policy value.
                    max_lifetime_ms: 30_000_000,
                },
                65_536,
                131_072,
            )
            .expect("create current namespace verifier");
        namespace
            .bootstrap_from(|original| async move {
                let request = serde_json::to_vec(&serde_json::json!({
                    "tenant": record.tenant,
                    "authority": record.authority,
                    "nonce": STANDARD.encode(original.nonce()),
                }))
                .unwrap();
                let wire =
                    current_https_post(&record.bootstrap_url, trust_pem, &request, 65_536).await;
                #[derive(Deserialize)]
                struct BootstrapReply {
                    response: String,
                    state: String,
                }
                let reply: BootstrapReply =
                    serde_json::from_slice(&wire).expect("decode current bootstrap response");
                let signed = current_bytes(&reply.response, 65_536, None);
                let state = current_bytes(&reply.state, 4096, None);
                Ok::<_, flowersec::EnvironmentError>((signed, state))
            })
            .await
            .expect("verify current namespace bootstrap");
        namespaces.push(namespace);
    }
    namespaces
}

fn current_ready(
    material_json: String,
    issuer: &CurrentIssuerResponse,
    carrier: &str,
    path: &str,
    profile: &str,
    source: &str,
) -> CurrentReady {
    assert_eq!(
        issuer.wire_revision, 4,
        "current issuer response must be v4"
    );
    assert!(
        !issuer.trust_pem.is_empty() && !issuer.origin.is_empty(),
        "current ready message lacks trust or origin"
    );
    CurrentReady {
        message_type: "ready".into(),
        runtime: "rust".into(),
        carrier: carrier.into(),
        path: path.into(),
        wire_revision: 4,
        artifact_json: material_json,
        trust_pem: issuer.trust_pem.clone(),
        origin: issuer.origin.clone(),
        profile: profile.into(),
        source: source.into(),
    }
}

fn print_current_result(
    message_type: &str,
    carrier: &str,
    path: &str,
    profile: &str,
    source: &str,
    executed: &ExecutionLedger,
) {
    println!(
        "{}",
        serde_json::to_string(&CurrentResultMessage {
            message_type,
            runtime: "rust",
            carrier,
            path,
            wire_revision: 4,
            profile,
            source,
            cases: executed.snapshot()
        })
        .unwrap()
    );
}

fn current_issuer_request(
    mode: &str,
    carrier: &str,
    origin: &str,
    endpoint_address: Option<&str>,
    persist: bool,
) -> Value {
    serde_json::json!({
        "mode": mode,
        "wire_revision": 4,
        "carrier": carrier,
        "profile": CURRENT_PROFILE,
        "origin": origin,
        "endpoint_address": endpoint_address,
        "persist": persist,
    })
}

#[allow(dead_code)]
fn current_tunnel_issuer_request(
    carrier: &str,
    server_carrier: &str,
    origin: &str,
    topology_id: &str,
    endpoint_addresses: [Option<&str>; 2],
    endpoint_listeners: [bool; 2],
) -> Value {
    let addresses = endpoint_addresses.map(|address| address.unwrap_or_default());
    serde_json::json!({
        "mode": "tunnel",
        "wire_revision": 4,
        "carrier": carrier,
        "server_carrier": server_carrier,
        "profile": CURRENT_PROFILE,
        "origin": origin,
        "topology_id": topology_id,
        "endpoint_addresses": addresses,
        "endpoint_listeners": endpoint_listeners,
        "persist": true,
    })
}

#[allow(dead_code)]
fn validate_current_tunnel_issuer_response(
    issued: &CurrentIssuerResponse,
    carrier: &str,
    server_carrier: &str,
    endpoint_addresses: [Option<SocketAddr>; 2],
    endpoint_listeners: [bool; 2],
) {
    assert_eq!(
        issued.wire_revision, 4,
        "current tunnel issuer returned a non-v4 envelope"
    );
    assert_eq!(
        issued.lifecycle.as_deref(),
        Some("persistent"),
        "current tunnel issuer must retain original ownership until shutdown"
    );
    assert!(
        !issued.trust_pem.is_empty() && !issued.origin.is_empty(),
        "current tunnel response lacks trust or origin"
    );
    assert_eq!(
        issued.relay_endpoints.len(),
        2,
        "current tunnel issuance must return both physical relay endpoints"
    );
    for (side, endpoint) in issued.relay_endpoints.iter().enumerate() {
        let expected_carrier = if side == 0 { carrier } else { server_carrier };
        assert_eq!(
            endpoint.carrier, expected_carrier,
            "current tunnel relay endpoint carrier mismatch"
        );
        let address: SocketAddr = endpoint
            .address
            .parse()
            .expect("parse current relay endpoint address");
        assert!(
            address.ip().is_loopback() && address.port() != 0,
            "current relay endpoint must use its reported loopback address"
        );
        assert!(
            endpoint.endpoint_url.starts_with("wss://")
                || endpoint.endpoint_url.starts_with("quic://")
                || endpoint.endpoint_url.starts_with("https://"),
            "current relay endpoint URL has an unsupported scheme"
        );
        current_bytes(&endpoint.server_certificate_der, 16_384, None);
        if endpoint_listeners[side] {
            let expected = endpoint_addresses[side]
                .expect("original endpoint listener must have a prebound address");
            assert_eq!(
                address, expected,
                "issuer changed the address of an original endpoint listener"
            );
            assert!(
                endpoint
                    .server_private_key_pkcs8
                    .as_deref()
                    .is_some_and(|key| !key.is_empty()),
                "original endpoint listener response lacks its TLS private key"
            );
        } else {
            assert!(
                endpoint.server_private_key_pkcs8.is_none(),
                "issuer exposed TLS private key for a relay-owned listener"
            );
        }
    }
    assert!(
        issued
            .endpoint_a_artifact_json
            .as_deref()
            .is_some_and(|material| !material.is_empty()),
        "current tunnel response lacks endpoint A material"
    );
    assert!(
        issued
            .endpoint_b_artifact_json
            .as_deref()
            .is_some_and(|material| !material.is_empty()),
        "current tunnel response lacks endpoint B material"
    );
}

fn current_metadata(path: &str) -> flowersec::Metadata {
    let values = std::collections::BTreeMap::from([(
        "cell".to_owned(),
        Bytes::from(serde_json::to_vec(path).expect("encode parity cell metadata")),
    )]);
    flowersec::Metadata::new("application/json", 1, &values)
        .expect("capture v4 parity stream metadata")
}

async fn current_server_streams(
    session: &flowersec::Session,
    path: &'static str,
    executed: &ExecutionLedger,
) {
    let echo = session
        .next_open()
        .await
        .expect("accept current echo stream");
    assert_eq!(echo.kind(), "parity.echo");
    assert_eq!(echo.metadata().namespace(), Some("application/json"));
    let metadata_values = echo.metadata().byte_values();
    assert_eq!(
        metadata_values.get("cell").map(Bytes::as_ref),
        Some(serde_json::to_vec(path).unwrap().as_slice())
    );
    let stream = echo.accept(65_536).expect("accept current echo stream");
    executed.record(&["stream-metadata"]);
    assert_eq!(
        stream.read().await.unwrap(),
        Some(Bytes::from_static(b"hello"))
    );
    assert_eq!(stream.read().await.unwrap(), None);
    stream.write(Bytes::from_static(b"world")).await.unwrap();
    stream.close_write().await.unwrap();
    executed.record(&["stream-fin"]);

    let reset = session
        .next_open()
        .await
        .expect("accept current reset stream");
    assert_eq!(reset.kind(), "parity.reset");
    let reset = reset.accept(65_536).expect("accept current reset stream");
    assert_eq!(
        reset.read().await.unwrap(),
        Some(Bytes::from_static(b"reset"))
    );
    assert_eq!(reset.read().await.unwrap(), None);
    reset.reset().await.unwrap();
    executed.record(&["stream-reset"]);
}

async fn current_datagram_exchange(
    session: &flowersec::Session,
    initiator: bool,
    executed: &ExecutionLedger,
) {
    let channel = session
        .unreliable_messages()
        .expect("current native Session exposes its selected datagram capability");
    let request = Bytes::from_static(&[1, 2, 3]);
    let response = Bytes::from_static(&[3, 2, 1]);
    if initiator {
        let outcome = channel
            .send(&request, SystemTime::now() + Duration::from_secs(2))
            .await
            .expect("submit current v4 datagram");
        assert_eq!(
            outcome,
            UnreliableSendOutcome::Accepted,
            "current v4 provider did not accept the datagram"
        );
        let received = tokio::time::timeout(Duration::from_secs(2), channel.receive())
            .await
            .expect("current v4 datagram response deadline")
            .expect("receive current v4 datagram");
        assert_eq!(received, response, "current v4 datagram response mismatch");
    } else {
        let received = tokio::time::timeout(Duration::from_secs(2), channel.receive())
            .await
            .expect("current v4 datagram request deadline")
            .expect("receive current v4 datagram");
        assert_eq!(received, request, "current v4 datagram request mismatch");
        let outcome = channel
            .send(&response, SystemTime::now() + Duration::from_secs(2))
            .await
            .expect("submit current v4 datagram response");
        assert_eq!(
            outcome,
            UnreliableSendOutcome::Accepted,
            "current v4 provider did not accept the datagram response"
        );
    }
    executed.record(&["datagram"]);
}

async fn current_client_streams(
    session: &flowersec::Session,
    path: &'static str,
    executed: &ExecutionLedger,
) {
    let stream = session
        .open_stream("parity.echo", current_metadata(path), 65_536)
        .await
        .unwrap();
    stream.write(Bytes::from_static(b"hello")).await.unwrap();
    stream.close_write().await.unwrap();
    assert_eq!(
        stream.read().await.unwrap(),
        Some(Bytes::from_static(b"world"))
    );
    assert_eq!(stream.read().await.unwrap(), None);
    stream.finish().await.unwrap();
    executed.record(&["stream-metadata", "stream-fin"]);

    let reset = session
        .open_stream("parity.reset", flowersec::Metadata::empty(), 65_536)
        .await
        .unwrap();
    reset.write(Bytes::from_static(b"reset")).await.unwrap();
    reset.close_write().await.unwrap();
    assert!(reset.read().await.is_err());
    executed.record(&["stream-reset"]);
}

async fn run_current_server(carrier: &str) {
    run_current_server_with_proxy(carrier, None).await;
}

pub async fn run_current_proxy_server(upstream: Url) {
    run_current_server_with_proxy("websocket", Some(upstream)).await;
}

async fn run_current_server_with_proxy(carrier: &str, proxy_upstream: Option<Url>) {
    assert!(
        matches!(carrier, "websocket" | "raw-quic" | "webtransport"),
        "unsupported current Rust Serve carrier"
    );
    let origin = parity_origin();
    enum OriginalListener {
        Tcp(TcpListener),
        Udp(UdpSocket),
    }
    let listener = match carrier {
        "websocket" => OriginalListener::Tcp(
            TcpListener::bind(("127.0.0.1", 0)).expect("bind original Rust WSS listener"),
        ),
        "raw-quic" | "webtransport" => OriginalListener::Udp(
            UdpSocket::bind(("127.0.0.1", 0)).expect("bind original Rust UDP listener"),
        ),
        _ => unreachable!(),
    };
    let local = match &listener {
        OriginalListener::Tcp(listener) => listener
            .local_addr()
            .expect("read original WSS listener address"),
        OriginalListener::Udp(socket) => socket
            .local_addr()
            .expect("read original UDP listener address"),
    };
    let environment = current_environment();
    let request =
        current_issuer_request("direct", carrier, &origin, Some(&local.to_string()), true);
    let (issuer_process, issued) = PersistentIssuer::start(&request);
    assert_eq!(
        issued.endpoint_address.as_deref(),
        Some(local.to_string().as_str()),
        "issuer route must retain Rust's original listener address"
    );
    let material_json = issued
        .artifact_json
        .clone()
        .expect("current v4 direct material");
    let material = parse_current_material(&material_json, 0);
    assert_eq!(
        material.profile, "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",
        "Rust current Serve requires the original X25519 deployment profile"
    );
    assert_eq!(material.source, "preauthorized_pool");
    let server_material_json = issued
        .server_material_json
        .as_deref()
        .expect("issuer must provide the original Role 1 server material");
    let server_material = parse_current_material(server_material_json, 1);
    assert!(
        current_bytes(&server_material.artifact, 65_536, None)
            == current_bytes(&material.artifact, 65_536, None),
        "issuer Role 1 material must bind the same Artifact"
    );
    let (carrier_id, route_host, route_port, route_path, route_origin) =
        current_route_endpoint(&current_bytes(&material.route, 16_384, None), 0);
    let expected_carrier = match carrier {
        "raw-quic" => 0,
        "websocket" => 1,
        "webtransport" => 2,
        _ => unreachable!(),
    };
    assert_eq!(
        carrier_id, expected_carrier,
        "current Rust direct Serve carrier differs from the signed Route"
    );
    assert_eq!(
        route_port,
        local.port(),
        "signed Route port differs from the prebound listener"
    );
    let expected_path = match carrier {
        "websocket" => "/flowersec/v4/direct",
        "webtransport" => "/flowersec/webtransport/v4/direct",
        "raw-quic" => "",
        _ => unreachable!(),
    };
    assert_eq!(route_path, expected_path);
    if carrier != "raw-quic" {
        assert!(
            route_origin
                .as_deref()
                .is_none_or(|route_origin| route_origin == origin),
            "signed Route origin must be absent or match the configured deployment origin"
        );
    }
    let namespaces =
        bootstrap_current_namespaces(&environment, &server_material, &issued.trust_pem).await;
    let (_, credential) = current_identity_and_credential(&environment, &material);
    let identity_seed = current_bytes(&server_material.identity_seed, 32, Some(32));
    let dh_seed = current_bytes(&server_material.dh_seed, 32, Some(32));
    let keys = environment
        .import_identity_keys(
            &server_material.profile,
            identity_seed.try_into().expect("server identity seed"),
            dh_seed.try_into().expect("server DH seed"),
        )
        .expect("import current server identity keys");
    let pool = current_pool_store_named(&environment, &material, &credential.artifact, "accepted");
    let parent_pool =
        current_pool_store_named(&environment, &material, &credential.artifact, "parent");
    let (tenant, issuer, audience) = current_artifact_binding(&credential.artifact);
    let mut server_identity_digest = [0u8; 32];
    server_identity_digest
        .copy_from_slice(&current_certificate_digest(&credential.server_certificate));
    let admission = flowersec::SQLiteAdmissionAuthority::new(
        pool.store.clone(),
        parent_pool.store.clone(),
        vec![flowersec::SQLiteAdmissionBinding {
            tenant,
            issuer,
            server_identity_digest,
            audience,
        }],
    )
    .expect("create current direct SQLite admission authority");
    let proxy = proxy_upstream.map(|upstream| {
        let mut options = flowersec::ProxyServerOptions::new(upstream.clone(), upstream);
        options.allowed_upstream_hosts = vec!["127.0.0.1".into()];
        options.allowed_origins = vec![
            "https://app.example"
                .parse()
                .expect("valid browser proxy origin"),
        ];
        options.max_concurrent_streams = 4;
        options.max_metadata_bytes = 4096;
        options.max_chunk_bytes = 8;
        options.max_body_bytes = 8;
        options.max_websocket_frame_bytes = 32;
        options.default_http_request_timeout = Duration::from_secs(5);
        options.max_http_request_timeout = Duration::from_secs(5);
        options.extra_request_headers =
            vec!["cookie".into(), "origin".into(), "x-request-id".into()];
        options.extra_response_headers = vec!["x-visible".into()];
        options.blocked_response_headers = vec!["location".into()];
        options.extra_websocket_headers = vec!["x-request-id".into()];
        options.forbidden_cookie_names = vec!["secret".into()];
        options.forbidden_cookie_name_prefixes = vec!["private_".into()];
        flowersec::ProxyServer::new(options).expect("create current Rust proxy server")
    });
    let streams = match proxy.as_ref() {
        Some(proxy) => flowersec::StreamDispatch::Registered(
            proxy
                .stream_registrations()
                .expect("capture current proxy registrations"),
        ),
        None => flowersec::StreamDispatch::Manual,
    };
    let executed = ExecutionLedger::default();
    let application = current_application::Application::new(executed.clone());
    let plan = if proxy.is_some() {
        environment
            .handler_plan(flowersec::HandlerPlanOptions {
                streams,
                application_bytes: 65_536,
            })
            .expect("capture current proxy handler plan")
    } else {
        current_application::plan(&environment, application.clone())
    };
    let callbacks = Arc::new(CurrentParityCallbacks {
        plan: plan.clone(),
        application: proxy.is_none().then_some(application.clone()),
    });
    let certificate = current_bytes(
        issued
            .server_certificate_der
            .as_deref()
            .expect("persistent issuer must provide the TLS certificate for its retained listener"),
        16_384,
        None,
    );
    let private_key = current_bytes(
        issued
            .server_private_key_pkcs8
            .as_deref()
            .expect("persistent issuer must provide the TLS private key for its retained listener"),
        4096,
        None,
    );
    let serve_options = flowersec::WssServeOptions {
        callbacks,
        application_limits: flowersec::ApplicationLimits {
            ordinary_callbacks: 8,
            ordinary_callback_bytes: 65_536,
            control_callback_bytes: 65_536,
        },
        cancellation: CancellationToken::new(),
        binding_mode: flowersec::BindingMode::AuthenticatedContext,
        listen_address: local,
        host: route_host,
        origin: (carrier != "raw-quic").then(|| route_origin.unwrap_or_else(|| origin.clone())),
        max_connections: 4,
        max_frame_bytes: 1 << 20,
        handshake_timeout: Duration::from_secs(10),
        publication_timeout: Duration::from_secs(5),
        queue_messages: 16,
        prepare_bytes: 65_536,
        native_runtime_bytes: 32 << 20,
    };
    let identity = flowersec::WssServerIdentity {
        certificate_chain_der: vec![certificate],
        private_key_der: private_key,
    };
    let source = Arc::new(CurrentAcceptedSource { credential });
    let serve = match listener {
        OriginalListener::Tcp(listener) => {
            environment
                .serve_wss_on_listener(
                    listener,
                    namespaces,
                    keys,
                    source,
                    admission,
                    identity,
                    serve_options,
                )
                .await
        }
        OriginalListener::Udp(socket) if carrier == "raw-quic" => {
            environment
                .serve_raw_quic_on_socket(
                    socket,
                    namespaces,
                    keys,
                    source,
                    admission,
                    identity,
                    serve_options,
                )
                .await
        }
        OriginalListener::Udp(socket) => {
            environment
                .serve_webtransport_on_socket(
                    socket,
                    namespaces,
                    keys,
                    source,
                    admission,
                    identity,
                    serve_options,
                )
                .await
        }
    }
    .expect("start current v4 Rust Serve on the original prebound listener");
    if proxy.is_some() {
        print_current_protocol_message(&CurrentProxyReady {
            runtime: "rust",
            wire_revision: 4,
            artifact_json: &material_json,
            origin: &origin,
            trust_pem: &issued.trust_pem,
        });
    } else {
        print_current_protocol_message(&current_ready(
            material_json,
            &issued,
            carrier,
            "direct",
            &material.profile,
            &material.source,
        ));
    }

    let session = serve
        .accept()
        .await
        .expect("accept current direct v4 session");
    executed.record(&["admission"]);
    if proxy.is_some() {
        session.wait_termination().await;
    } else {
        current_application::server(&session, &application, "direct", carrier != "websocket").await;
    }
    session.close();
    let session_cleanup = session.wait_cleanup().await;
    assert!(
        session_cleanup.complete,
        "current direct session cleanup did not finish"
    );
    serve.close();
    let serve_cleanup = serve
        .wait_cleanup()
        .await
        .expect("wait for current Serve cleanup");
    assert!(
        serve_cleanup.complete,
        "current Serve cleanup did not finish"
    );
    if let Some(proxy) = proxy {
        proxy.close().await;
    }
    drop(session);
    drop(serve);
    drop(application);
    plan.close();
    drop(plan);
    drop(pool);
    drop(parent_pool);
    assert!(
        environment.close().await.unwrap().complete,
        "current direct server retained original Environment ownership"
    );
    issuer_process.shutdown();
    executed.record(&["close", "cleanup"]);
    print_current_result(
        "server-result",
        carrier,
        "direct",
        &material.profile,
        &material.source,
        &executed,
    );
}

#[allow(dead_code)]
fn issue_current(
    mode: &str,
    carrier: &str,
    server_carrier: &str,
    profile: &str,
    origin: &str,
    topology_id: Option<&str>,
) -> CurrentIssuerResponse {
    let endpoint = (mode == "direct").then(|| match carrier {
        "websocket" => "wss://127.0.0.1:0/flowersec/v4/direct".to_owned(),
        "raw-quic" => "quic://127.0.0.1:0".to_owned(),
        "webtransport" => "https://127.0.0.1:0/flowersec/webtransport/v4/direct".to_owned(),
        _ => panic!("unsupported current carrier"),
    });
    let mut child = Command::new("go")
        .args([
            "-C",
            "flowersec-go",
            "run",
            "./internal/cmd/parity-artifact-issuer",
        ])
        .env("FLOWERSEC_SERVER_PARITY_PEER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start current v4 parity issuer");
    serde_json::to_writer(
        child.stdin.as_mut().expect("issuer stdin"),
        &serde_json::json!({
            "mode": mode,
            "wire_revision": 4,
            "endpoint": endpoint,
            "topology_id": topology_id,
            "carrier": carrier,
            "server_carrier": server_carrier,
            "profile": profile,
            "origin": origin,
        }),
    )
    .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .expect("wait for current v4 parity issuer");
    if !output.status.success() {
        panic!(
            "current v4 parity issuer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let response: CurrentIssuerResponse =
        serde_json::from_slice(&output.stdout).expect("decode current v4 parity issuer output");
    assert_eq!(
        response.wire_revision, 4,
        "current issuer returned a non-v4 envelope"
    );
    response
}

async fn run_current_client(carrier: &str, ready: CurrentReady) {
    assert_eq!(
        ready.message_type, "ready",
        "current peer did not receive a ready message"
    );
    assert!(
        matches!(ready.runtime.as_str(), "go" | "rust" | "node-typescript"),
        "current Rust client received an unsupported peer runtime"
    );
    assert_eq!(
        ready.path, "direct",
        "current Rust direct client received a non-direct path"
    );
    assert_eq!(
        ready.wire_revision, 4,
        "current peer requires wire revision 4"
    );

    let material = parse_current_material(&ready.artifact_json, 0);
    assert_eq!(
        material.profile, ready.profile,
        "current material profile differs from ready metadata"
    );
    assert_eq!(
        material.source, ready.source,
        "current material source differs from ready metadata"
    );

    let environment = current_environment();
    let namespaces = if material.source == "live_authority" {
        current_live_deployment::bootstrap_namespaces(&environment, &material, &ready.trust_pem)
            .await
    } else {
        bootstrap_current_namespaces(&environment, &material, &ready.trust_pem).await
    };
    let (source, pool) = if material.source == "live_authority" {
        let configuration = current_live_deployment::source_configuration(
            &environment,
            &material,
            namespaces,
            &ready.trust_pem,
            carrier,
        );
        (
            flowersec::LocalDirectMaterialSource::live_authority(&environment, configuration)
                .expect("capture original live direct source"),
            None,
        )
    } else {
        let (identity, credential) = current_identity_and_credential(&environment, &material);
        let pool = current_pool_store(&environment, &material, &credential.artifact);
        let source = flowersec::LocalDirectMaterialSource::preauthorized_pool(
            &environment,
            flowersec::PreauthorizedPoolSourceConfiguration {
                namespaces,
                identity,
                credentials: vec![credential],
                spend_ledger: pool.store.clone(),
                provider: current_provider_options(
                    &material,
                    &ready.trust_pem,
                    0,
                    carrier,
                    &ready.origin,
                ),
                application_profile: flowersec::ApplicationProfile::Services,
            },
        )
        .expect("capture current direct source");
        (source, Some(pool))
    };
    let executed = ExecutionLedger::default();
    let application = current_application::Application::new(executed.clone());
    let plan = current_application::plan(&environment, application.clone());
    let session = flowersec::connect(
        &environment,
        &source,
        flowersec::ConnectionRequest {
            requirements: flowersec::ConnectionRequirements {
                application_profile: Some("services".into()),
                ..flowersec::ConnectionRequirements::default()
            },
            handlers: Some((
                plan.clone(),
                flowersec::ApplicationLimits {
                    ordinary_callbacks: 8,
                    ordinary_callback_bytes: 65_536,
                    control_callback_bytes: 65_536,
                },
            )),
        },
        CancellationToken::new(),
    )
    .await
    .expect("connect current direct session through its original source");
    plan.close();
    executed.record(&["admission"]);
    current_application::client(&session, &application, "direct", carrier != "websocket").await;
    let termination = session.wait_termination().await;
    assert_eq!(
        termination.error,
        SessionError::Closed,
        "current direct close did not terminate the session"
    );
    let cleanup = session.wait_cleanup().await;
    assert!(
        cleanup.complete,
        "current direct session cleanup is incomplete"
    );
    executed.record(&["close", "cleanup"]);
    source.close();
    drop(session);
    drop(source);
    drop(application);
    drop(plan);
    drop(pool);
    assert!(
        environment.close().await.unwrap().complete,
        "current direct client retained original Environment ownership"
    );
    print_current_result(
        "client-result",
        carrier,
        "direct",
        &ready.profile,
        &ready.source,
        &executed,
    );
}

fn parity_origin() -> String {
    env::var("FLOWERSEC_PARITY_ORIGIN").unwrap_or_else(|_| "https://client.example".into())
}

struct CurrentProtocolOutput {
    bytes: Zeroizing<Vec<u8>>,
}
impl Write for CurrentProtocolOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|size| size > 1_048_576)
        {
            return Err(io::Error::other(
                "current protocol output exceeds its bound",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn print_current_protocol_message(message: &impl Serialize) {
    // Serialization keeps one fixed original backing and clears it even if
    // encoding or output fails. Partial output never reissues the material.
    let mut output = CurrentProtocolOutput {
        bytes: Zeroizing::new(Vec::with_capacity(1_048_576)),
    };
    serde_json::to_writer(&mut output, message).expect("encode bounded current protocol output");
    output
        .write_all(b"\n")
        .expect("finish bounded current protocol output");
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&output.bytes)
        .expect("write original current protocol output");
    stdout
        .flush()
        .expect("flush original current protocol output");
}
#[derive(Serialize)]
struct CurrentProxyReady<'a> {
    runtime: &'static str,
    wire_revision: u8,
    artifact_json: &'a str,
    origin: &'a str,
    trust_pem: &'a str,
}

fn read_current_protocol_line(reader: &mut impl BufRead) -> Zeroizing<String> {
    // A fixed backing avoids releasing a secret-bearing allocation during
    // growth. The returned original line also clears on parse or caller failure.
    let mut bytes = Zeroizing::new(Vec::with_capacity(1_048_576));
    loop {
        let available = reader
            .fill_buf()
            .expect("read current bounded protocol input");
        assert!(!available.is_empty(), "missing current protocol command");
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        assert!(
            bytes.len() + count <= 1_048_576,
            "current protocol input exceeds its bound"
        );
        let complete = available[count - 1] == b'\n';
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if complete {
            return match String::from_utf8(std::mem::take(&mut *bytes)) {
                Ok(line) => Zeroizing::new(line),
                Err(error) => {
                    error.into_bytes().zeroize();
                    panic!("current protocol input must be UTF-8");
                }
            };
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut args = env::args().skip(1);
    let role = args
        .next()
        .expect("expected server, proxy-server, client, relay, or tunnel endpoint role");
    let mut carrier = None;
    let mut server_carrier = None;
    let mut deployment = None;
    let mut endpoint_listeners = [false, true];
    while let Some(flag) = args.next() {
        let value = args.next().expect("parity option requires a value");
        match flag.as_str() {
            "--carrier" => {
                assert!(carrier.is_none(), "duplicate carrier option");
                carrier = Some(value);
            }
            "--deployment" => {
                assert!(
                    role == "relay" && deployment.is_none(),
                    "one original relay deployment option is required"
                );
                deployment = Some(value);
            }
            "--server-carrier" => {
                assert!(server_carrier.is_none(), "duplicate server carrier option");
                server_carrier = Some(value);
            }
            "--client-listener" | "--server-listener" => {
                let side = usize::from(flag == "--server-listener");
                endpoint_listeners[side] = match value.as_str() {
                    "endpoint" => true,
                    "relay" => false,
                    _ => panic!("listener must be endpoint or relay"),
                };
            }
            _ => panic!("unknown parity option: {flag}"),
        }
    }
    let carrier = carrier.expect("carrier option is required");
    assert!(
        matches!(carrier.as_str(), "websocket" | "raw-quic" | "webtransport"),
        "unsupported carrier"
    );
    let server_carrier = server_carrier.unwrap_or_else(|| carrier.clone());
    assert!(
        matches!(
            server_carrier.as_str(),
            "websocket" | "raw-quic" | "webtransport"
        ),
        "unsupported server carrier"
    );
    match role.as_str() {
        "server" => run_current_server(&carrier).await,
        "proxy-server" => {
            assert_eq!(
                carrier, "websocket",
                "Rust ProxyServer parity peer currently serves WSS"
            );
            let upstream = env::var("FLOWERSEC_PROXY_UPSTREAM")
                .expect("proxy upstream environment")
                .parse::<Url>()
                .expect("valid proxy upstream URL");
            run_current_proxy_server(upstream).await;
        }
        "client" => {
            let input = read_current_protocol_line(&mut io::stdin().lock());
            let ready: CurrentReady =
                serde_json::from_str(&input).expect("decode current direct ready message");
            assert_eq!(
                ready.wire_revision, 4,
                "current client requires wire revision 4"
            );
            drop(input);
            run_current_client(&carrier, ready).await;
        }
        "relay" => {
            current_tunnel::relay(
                &carrier,
                &server_carrier,
                endpoint_listeners,
                deployment.as_deref(),
            )
            .await
        }
        "tunnel-endpoint-a" => current_tunnel::endpoint_a(&carrier).await,
        "tunnel-endpoint-b" => current_tunnel::endpoint_b(&carrier).await,
        _ => panic!("invalid role"),
    }
}

#[cfg(test)]
mod material_tests {
    use super::*;
    use serde_json::{Value, json};

    // These bytes exercise envelope decoding only. Credential verification is
    // performed separately against independently installed namespace owners.
    fn envelope(source: &str, activation: Value) -> Value {
        json!({
            "wire_revision": 4,
            "profile": CURRENT_PROFILE,
            "source": source,
            "generation": { "source": STANDARD.encode([1; 16]), "generation": 1 },
            "role": 1,
            "artifact": STANDARD.encode([2]),
            "activation": activation,
            "client_certificate": STANDARD.encode([3]),
            "server_certificate": STANDARD.encode([4]),
            "route": STANDARD.encode([5]),
            "route_digest": STANDARD.encode([6; 32]),
            "activation_signing_key_id": "activation-key",
            "identity_seed": STANDARD.encode([7; 32]),
            "dh_seed": STANDARD.encode([8; 32]),
            "namespaces": [{
                "tenant": "tenant", "authority": "authority", "generation": 1,
                "root_key_id": STANDARD.encode([9; 16]),
                "root_public_key": STANDARD.encode([10; 32]),
                "bootstrap_url": "https://localhost/bootstrap",
                "state_url": "https://localhost/state"
            }],
            "tunnels": [],
            "live_control_base_url": "https://localhost/flowersec/control/tunnel"
        })
    }

    #[test]
    fn material_live_accepts_null_or_empty_unissued_activation() {
        for activation in [Value::Null, json!("")] {
            let material =
                parse_current_material(&envelope("live_authority", activation).to_string(), 1);
            assert!(material.activation.is_empty());
        }
    }

    #[test]
    fn material_pool_still_requires_nonempty_activation() {
        let proof = STANDARD.encode([11]);
        let material =
            parse_current_material(&envelope("preauthorized_pool", json!(proof)).to_string(), 1);
        assert_eq!(material.activation, proof);
        for activation in [Value::Null, json!("")] {
            let wire = envelope("preauthorized_pool", activation).to_string();
            assert!(std::panic::catch_unwind(|| parse_current_material(&wire, 1)).is_err());
        }
    }

    #[test]
    fn material_live_rejects_imported_activation() {
        let wire = envelope("live_authority", json!(STANDARD.encode([11]))).to_string();
        assert!(std::panic::catch_unwind(|| parse_current_material(&wire, 1)).is_err());
    }

    #[test]
    fn material_null_activation_does_not_relax_required_fields_or_types() {
        for field in [
            "artifact",
            "client_certificate",
            "server_certificate",
            "route",
        ] {
            let mut wire = envelope("live_authority", Value::Null);
            wire[field] = Value::Null;
            assert!(serde_json::from_value::<CurrentMaterial>(wire).is_err());
        }
        for activation in [json!(1), json!([]), json!({})] {
            assert!(
                serde_json::from_value::<CurrentMaterial>(envelope("live_authority", activation))
                    .is_err()
            );
        }
        let mut wire = envelope("live_authority", Value::Null);
        wire.as_object_mut().unwrap().remove("activation");
        assert!(serde_json::from_value::<CurrentMaterial>(wire).is_err());
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    #[test]
    fn engineering_clock_preserves_fractional_anchor_and_construction_elapsed() {
        let started = tokio::time::Instant::now();
        let clock = CurrentClock {
            epoch: Duration::from_micros(1_000_900),
            started,
        };
        let sample = clock
            .sample_at(started + Duration::from_micros(250_200))
            .unwrap();
        assert_eq!(sample.lower_ms, 1_251);
        assert_eq!(sample.upper_ms, 1_253);
        assert_eq!(sample.anchor_age_upper_ms, 251);
        assert_eq!(
            sample.monotonic_sample,
            started + Duration::from_micros(250_200)
        );
        assert!(matches!(
            clock.sample_at(started + Duration::from_secs(1_801)),
            Err(flowersec::EnvironmentError::TimeUnavailable)
        ));
    }
}
