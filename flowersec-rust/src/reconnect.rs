//! Refreshable artifact sources and supervised reconnect state.

use crate::{
    ConnectArtifact, FlowersecError, Path, Stage,
    client::{self, Client, ConnectOptions},
    controlplane::client::{
        ConnectArtifactRequestConfig, EntryConnectArtifactRequestConfig, request_connect_artifact,
        request_entry_connect_artifact,
    },
    defaults,
    observability::{DiagnosticCodeDomain, DiagnosticEvent, DiagnosticResult, SharedObserver},
};
use rand::Rng as _;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

type ArtifactFuture =
    Pin<Box<dyn Future<Output = Result<ConnectArtifact, ArtifactSourceError>> + Send>>;
type ArtifactAcquire = dyn Fn(ArtifactAcquireContext) -> ArtifactFuture + Send + Sync;

#[derive(Clone, Debug)]
pub struct ArtifactAcquireContext {
    pub trace_id: Option<String>,
    pub cancellation: CancellationToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactSourceKind {
    Once,
    Refreshable,
}

#[derive(Clone)]
pub struct ArtifactSource {
    kind: ArtifactSourceKind,
    acquire: Arc<ArtifactAcquire>,
}

impl std::fmt::Debug for ArtifactSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtifactSource")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactSourceError {
    #[error("one-time artifact source has already been consumed")]
    OnceConsumed,
    #[error("artifact acquisition was canceled")]
    Canceled,
    #[error("artifact acquisition failed: {0}")]
    Acquire(String),
}

impl ArtifactSource {
    pub fn once(artifact: ConnectArtifact) -> Self {
        let artifact = Arc::new(Mutex::new(Some(artifact)));
        Self {
            kind: ArtifactSourceKind::Once,
            acquire: Arc::new(move |_| {
                let result = artifact
                    .lock()
                    .map_err(|_| ArtifactSourceError::Acquire("artifact lock is poisoned".into()))
                    .and_then(|mut artifact| {
                        artifact.take().ok_or(ArtifactSourceError::OnceConsumed)
                    });
                Box::pin(async move { result })
            }),
        }
    }

    pub fn refreshable<F, Fut>(acquire: F) -> Self
    where
        F: Fn(ArtifactAcquireContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ConnectArtifact, ArtifactSourceError>> + Send + 'static,
    {
        Self {
            kind: ArtifactSourceKind::Refreshable,
            acquire: Arc::new(move |context| Box::pin(acquire(context))),
        }
    }

    pub fn controlplane(config: ConnectArtifactRequestConfig) -> Self {
        Self::refreshable(move |context| {
            let mut config = config.clone();
            if context.trace_id.is_some() {
                config.trace_id.clone_from(&context.trace_id);
            }
            async move {
                tokio::select! {
                    _ = context.cancellation.cancelled() => Err(ArtifactSourceError::Canceled),
                    artifact = request_connect_artifact(config) => artifact
                        .map_err(|error| ArtifactSourceError::Acquire(error.to_string())),
                }
            }
        })
    }

    pub fn entry_controlplane(config: EntryConnectArtifactRequestConfig) -> Self {
        Self::refreshable(move |context| {
            let mut config = config.clone();
            if context.trace_id.is_some() {
                config.request.trace_id.clone_from(&context.trace_id);
            }
            async move {
                tokio::select! {
                    _ = context.cancellation.cancelled() => Err(ArtifactSourceError::Canceled),
                    artifact = request_entry_connect_artifact(config) => artifact
                        .map_err(|error| ArtifactSourceError::Acquire(error.to_string())),
                }
            }
        })
    }

    pub fn kind(&self) -> ArtifactSourceKind {
        self.kind
    }

    pub async fn acquire(
        &self,
        context: ArtifactAcquireContext,
    ) -> Result<ConnectArtifact, ArtifactSourceError> {
        (self.acquire)(context).await
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReconnectSettings {
    pub enabled: bool,
    pub max_attempts: usize,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub factor: f64,
    pub jitter_ratio: f64,
}

impl Default for ReconnectSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            max_attempts: defaults::RECONNECT_MAX_ATTEMPTS,
            initial_delay: defaults::RECONNECT_INITIAL_DELAY,
            max_delay: defaults::RECONNECT_MAX_DELAY,
            factor: defaults::RECONNECT_FACTOR,
            jitter_ratio: defaults::RECONNECT_JITTER_RATIO,
        }
    }
}

impl ReconnectSettings {
    fn normalized(&self) -> Result<Self, ReconnectError> {
        if !self.factor.is_finite()
            || self.factor < 1.0
            || !self.jitter_ratio.is_finite()
            || !(0.0..=1.0).contains(&self.jitter_ratio)
        {
            return Err(ReconnectError::InvalidConfig);
        }
        let mut settings = self.clone();
        settings.max_attempts = if settings.enabled {
            settings.max_attempts.max(1)
        } else {
            1
        };
        Ok(settings)
    }

    pub fn delay_for_retry(&self, failed_attempt_index: usize) -> Duration {
        let exponent = i32::try_from(failed_attempt_index).unwrap_or(i32::MAX);
        let base_seconds = self.initial_delay.as_secs_f64() * self.factor.powi(exponent);
        let capped_seconds = base_seconds.min(self.max_delay.as_secs_f64());
        let jitter = if self.jitter_ratio == 0.0 {
            0.0
        } else {
            rand::thread_rng().gen_range(-self.jitter_ratio..=self.jitter_ratio)
        };
        Duration::from_secs_f64((capped_seconds * (1.0 + jitter)).max(0.0))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Clone, Debug)]
pub struct ReconnectState {
    pub status: ConnectionStatus,
    pub error: Option<ReconnectError>,
    pub client: Option<Arc<Client>>,
}

impl Default for ReconnectState {
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            error: None,
            client: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReconnectError {
    #[error("automatic reconnect requires a refreshable artifact source")]
    RefreshableSourceRequired,
    #[error("invalid reconnect configuration")]
    InvalidConfig,
    #[error("reconnect was canceled")]
    Canceled,
    #[error("artifact acquisition failed: {0}")]
    Artifact(ArtifactSourceError),
    #[error("connection failed at {path:?}/{stage:?}/{code}: {message}")]
    Connect {
        path: Path,
        stage: Stage,
        code: String,
        message: String,
    },
    #[error("connection terminated unexpectedly")]
    Terminated,
    #[error("reconnect attempts exhausted after {attempts} attempts: {last}")]
    Exhausted { attempts: usize, last: String },
}

impl ReconnectError {
    fn from_connect(error: &FlowersecError) -> Self {
        Self::Connect {
            path: error.path,
            stage: error.stage,
            code: error.code.as_str().to_owned(),
            message: error.message.clone(),
        }
    }

    pub fn is_terminal(&self) -> bool {
        match self {
            Self::RefreshableSourceRequired | Self::InvalidConfig | Self::Canceled => true,
            Self::Artifact(ArtifactSourceError::OnceConsumed | ArtifactSourceError::Canceled) => {
                true
            }
            Self::Connect { code, .. } => matches!(
                code.as_str(),
                "invalid_input"
                    | "invalid_option"
                    | "role_mismatch"
                    | "transport_policy_denied"
                    | "invalid_psk"
                    | "invalid_suite"
                    | "missing_grant"
                    | "missing_connect_info"
                    | "missing_tunnel_url"
                    | "missing_ws_url"
                    | "missing_channel_id"
                    | "missing_token"
                    | "missing_init_exp"
            ),
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReconnectConfig {
    pub source: ArtifactSource,
    pub connect: ConnectOptions,
    pub reconnect: ReconnectSettings,
}

#[derive(Debug)]
struct ManagerInner {
    state: watch::Sender<ReconnectState>,
    cancellation: Mutex<CancellationToken>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone, Debug)]
pub struct ReconnectManager {
    inner: Arc<ManagerInner>,
}

impl Default for ReconnectManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconnectManager {
    pub fn new() -> Self {
        let (state, _) = watch::channel(ReconnectState::default());
        Self {
            inner: Arc::new(ManagerInner {
                state,
                cancellation: Mutex::new(CancellationToken::new()),
                task: Mutex::new(None),
            }),
        }
    }

    pub fn state(&self) -> ReconnectState {
        self.inner.state.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<ReconnectState> {
        self.inner.state.subscribe()
    }

    pub async fn connect(&self, config: ReconnectConfig) -> Result<(), ReconnectError> {
        self.disconnect().await;
        let settings = config.reconnect.normalized()?;
        if settings.enabled && config.source.kind() != ArtifactSourceKind::Refreshable {
            let error = ReconnectError::RefreshableSourceRequired;
            self.set_state(ConnectionStatus::Error, Some(error.clone()), None);
            return Err(error);
        }
        let cancellation = CancellationToken::new();
        *self
            .inner
            .cancellation
            .lock()
            .expect("reconnect cancellation lock poisoned") = cancellation.clone();
        self.set_state(ConnectionStatus::Connecting, None, None);
        let (first_result_tx, first_result_rx) = oneshot::channel();
        let inner = self.inner.clone();
        let task = tokio::spawn(run_supervisor(
            inner,
            config,
            settings,
            cancellation,
            Some(first_result_tx),
        ));
        *self
            .inner
            .task
            .lock()
            .expect("reconnect task lock poisoned") = Some(task);
        first_result_rx
            .await
            .unwrap_or(Err(ReconnectError::Canceled))
    }

    pub async fn connect_if_needed(&self, config: ReconnectConfig) -> Result<(), ReconnectError> {
        match self.state().status {
            ConnectionStatus::Connected => Ok(()),
            ConnectionStatus::Connecting => self.wait_until_settled().await,
            ConnectionStatus::Disconnected | ConnectionStatus::Error => self.connect(config).await,
        }
    }

    pub async fn disconnect(&self) {
        let cancellation = self
            .inner
            .cancellation
            .lock()
            .expect("reconnect cancellation lock poisoned")
            .clone();
        cancellation.cancel();
        if let Some(client) = self.state().client {
            let _ = client.close().await;
        }
        let task = self
            .inner
            .task
            .lock()
            .expect("reconnect task lock poisoned")
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
        self.set_state(ConnectionStatus::Disconnected, None, None);
    }

    async fn wait_until_settled(&self) -> Result<(), ReconnectError> {
        let mut receiver = self.subscribe();
        loop {
            let state = receiver.borrow().clone();
            match state.status {
                ConnectionStatus::Connected => return Ok(()),
                ConnectionStatus::Error => {
                    return Err(state.error.unwrap_or(ReconnectError::Terminated));
                }
                ConnectionStatus::Disconnected => return Err(ReconnectError::Canceled),
                ConnectionStatus::Connecting => {}
            }
            if receiver.changed().await.is_err() {
                return Err(ReconnectError::Canceled);
            }
        }
    }

    fn set_state(
        &self,
        status: ConnectionStatus,
        error: Option<ReconnectError>,
        client: Option<Arc<Client>>,
    ) {
        self.inner.state.send_replace(ReconnectState {
            status,
            error,
            client,
        });
    }
}

impl Drop for ReconnectManager {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner
                .cancellation
                .lock()
                .expect("reconnect cancellation lock poisoned")
                .cancel();
        }
    }
}

async fn run_supervisor(
    inner: Arc<ManagerInner>,
    config: ReconnectConfig,
    settings: ReconnectSettings,
    cancellation: CancellationToken,
    mut first_result: Option<oneshot::Sender<Result<(), ReconnectError>>>,
) {
    let mut attempt_seq = 0_u64;
    let mut trace_id = config.connect.trace_id.clone();
    loop {
        let mut last_error = ReconnectError::Terminated;
        for attempt in 1..=settings.max_attempts {
            if cancellation.is_cancelled() {
                send_first(&mut first_result, Err(ReconnectError::Canceled));
                return;
            }
            attempt_seq = attempt_seq.saturating_add(1);
            let started = Instant::now();
            emit(
                config.connect.observer.as_ref(),
                if attempt == 1 {
                    "reconnect_attempt"
                } else {
                    "reconnect_retry_attempt"
                },
                DiagnosticResult::Retry,
                attempt_seq,
                trace_id.clone(),
                started,
            );
            let artifact = config
                .source
                .acquire(ArtifactAcquireContext {
                    trace_id: trace_id.clone(),
                    cancellation: cancellation.child_token(),
                })
                .await;
            let artifact = match artifact {
                Ok(artifact) => artifact,
                Err(error) => {
                    last_error = ReconnectError::Artifact(error);
                    if finish_or_schedule(
                        &inner,
                        &config,
                        &settings,
                        &cancellation,
                        &mut first_result,
                        &last_error,
                        attempt,
                        attempt_seq,
                        trace_id.clone(),
                        started,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }
            };
            if let Some(correlation) = artifact.correlation() {
                if correlation.trace_id.is_some() {
                    trace_id.clone_from(&correlation.trace_id);
                }
            }
            let mut options = config.connect.clone();
            options.attempt_seq = attempt_seq;
            options.trace_id.clone_from(&trace_id);
            let connected = tokio::select! {
                _ = cancellation.cancelled() => Err(ReconnectError::Canceled),
                result = client::connect(artifact, options) => result
                    .map(Arc::new)
                    .map_err(|error| ReconnectError::from_connect(&error)),
            };
            match connected {
                Ok(client) => {
                    inner.state.send_replace(ReconnectState {
                        status: ConnectionStatus::Connected,
                        error: None,
                        client: Some(client.clone()),
                    });
                    emit(
                        config.connect.observer.as_ref(),
                        "reconnect_connected",
                        DiagnosticResult::Ok,
                        attempt_seq,
                        trace_id.clone(),
                        started,
                    );
                    send_first(&mut first_result, Ok(()));
                    tokio::select! {
                        _ = cancellation.cancelled() => {
                            let _ = client.close().await;
                            return;
                        }
                        _ = client.terminated() => {
                            last_error = ReconnectError::Terminated;
                            inner.state.send_replace(ReconnectState {
                                status: ConnectionStatus::Connecting,
                                error: Some(last_error.clone()),
                                client: None,
                            });
                        }
                    }
                    break;
                }
                Err(error) => {
                    last_error = error;
                    if finish_or_schedule(
                        &inner,
                        &config,
                        &settings,
                        &cancellation,
                        &mut first_result,
                        &last_error,
                        attempt,
                        attempt_seq,
                        trace_id.clone(),
                        started,
                    )
                    .await
                    {
                        return;
                    }
                }
            }
        }
        if !settings.enabled {
            let error = ReconnectError::Exhausted {
                attempts: 1,
                last: last_error.to_string(),
            };
            inner.state.send_replace(ReconnectState {
                status: ConnectionStatus::Error,
                error: Some(error.clone()),
                client: None,
            });
            send_first(&mut first_result, Err(error));
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_or_schedule(
    inner: &ManagerInner,
    config: &ReconnectConfig,
    settings: &ReconnectSettings,
    cancellation: &CancellationToken,
    first_result: &mut Option<oneshot::Sender<Result<(), ReconnectError>>>,
    error: &ReconnectError,
    attempt: usize,
    attempt_seq: u64,
    trace_id: Option<String>,
    started: Instant,
) -> bool {
    let exhausted = !settings.enabled || attempt >= settings.max_attempts || error.is_terminal();
    if exhausted {
        let final_error = if error.is_terminal() {
            error.clone()
        } else {
            ReconnectError::Exhausted {
                attempts: attempt,
                last: error.to_string(),
            }
        };
        inner.state.send_replace(ReconnectState {
            status: ConnectionStatus::Error,
            error: Some(final_error.clone()),
            client: None,
        });
        emit(
            config.connect.observer.as_ref(),
            "reconnect_exhausted",
            DiagnosticResult::Fail,
            attempt_seq,
            trace_id,
            started,
        );
        send_first(first_result, Err(final_error));
        return true;
    }
    inner.state.send_replace(ReconnectState {
        status: ConnectionStatus::Connecting,
        error: Some(error.clone()),
        client: None,
    });
    emit(
        config.connect.observer.as_ref(),
        "reconnect_scheduled",
        DiagnosticResult::Retry,
        attempt_seq,
        trace_id,
        started,
    );
    let delay = settings.delay_for_retry(attempt - 1);
    tokio::select! {
        _ = cancellation.cancelled() => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

fn send_first(
    sender: &mut Option<oneshot::Sender<Result<(), ReconnectError>>>,
    result: Result<(), ReconnectError>,
) {
    if let Some(sender) = sender.take() {
        let _ = sender.send(result);
    }
}

fn emit(
    observer: Option<&SharedObserver>,
    code: &str,
    result: DiagnosticResult,
    attempt_seq: u64,
    trace_id: Option<String>,
    started: Instant,
) {
    if let Some(observer) = observer {
        observer.on_diagnostic(&DiagnosticEvent {
            v: 1,
            namespace: "connect".to_owned(),
            path: Path::Auto,
            stage: Stage::Reconnect,
            code_domain: DiagnosticCodeDomain::Event,
            code: code.to_owned(),
            result,
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
            attempt_seq,
            trace_id,
            session_id: None,
            resource: None,
            current: None,
            limit: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::flowersec::direct::v1::{DirectConnectInfo, Suite};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn artifact() -> ConnectArtifact {
        ConnectArtifact::Direct {
            info: DirectConnectInfo {
                ws_url: "wss://example.test/direct".to_owned(),
                channel_id: "channel-test".to_owned(),
                channel_init_expire_at_unix_s: 1_700_000_000,
                e2ee_psk_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                default_suite: Suite::X25519HkdfSha256Aes256Gcm,
            },
            scoped: Vec::new(),
            correlation: None,
        }
    }

    #[tokio::test]
    async fn once_source_is_consumed_exactly_once() {
        let source = ArtifactSource::once(artifact());
        let context = || ArtifactAcquireContext {
            trace_id: None,
            cancellation: CancellationToken::new(),
        };
        source.acquire(context()).await.expect("first acquire");
        assert_eq!(
            source.acquire(context()).await.expect_err("consumed"),
            ArtifactSourceError::OnceConsumed
        );
    }

    #[tokio::test]
    async fn refreshable_source_receives_updated_context() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(None));
        let source = ArtifactSource::refreshable({
            let calls = calls.clone();
            let observed = observed.clone();
            move |context| {
                calls.fetch_add(1, Ordering::SeqCst);
                observed
                    .lock()
                    .expect("trace lock")
                    .clone_from(&context.trace_id);
                async { Ok(artifact()) }
            }
        });
        source
            .acquire(ArtifactAcquireContext {
                trace_id: Some("trace-test".to_owned()),
                cancellation: CancellationToken::new(),
            })
            .await
            .expect("acquire");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            observed.lock().expect("trace lock").as_deref(),
            Some("trace-test")
        );
    }

    #[test]
    fn terminal_errors_are_not_retried() {
        assert!(
            ReconnectError::Connect {
                path: Path::Direct,
                stage: Stage::Validate,
                code: "invalid_psk".to_owned(),
                message: "invalid".to_owned(),
            }
            .is_terminal()
        );
        assert!(
            !ReconnectError::Connect {
                path: Path::Direct,
                stage: Stage::Connect,
                code: "dial_failed".to_owned(),
                message: "failed".to_owned(),
            }
            .is_terminal()
        );
    }

    #[test]
    fn zero_jitter_backoff_is_deterministic() {
        let settings = ReconnectSettings {
            enabled: true,
            max_attempts: 5,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            factor: 2.0,
            jitter_ratio: 0.0,
        };
        assert_eq!(settings.delay_for_retry(0), Duration::from_millis(500));
        assert_eq!(settings.delay_for_retry(1), Duration::from_secs(1));
        assert_eq!(settings.delay_for_retry(9), Duration::from_secs(10));
    }
}
