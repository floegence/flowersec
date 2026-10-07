//! Explicit HTTP-agent Cookie scope. Private associations are always checked
//! together with the original authenticated Stream and trusted registration.
use crate::environment_v4::{EnvironmentCharge, EnvironmentRoot, ResourceLimits};
use crate::{ApplicationBinding, CleanupStatus, TransportEnvironment};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::Cookie;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProxyCredentialMode {
    #[default]
    None,
    External,
    UpstreamCookieSession,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProxyCredentialError {
    #[error("credential_scope_unavailable")]
    ScopeUnavailable,
    #[error("credential_update_failed")]
    UpdateFailed,
    #[error("credential_operation_conflict")]
    OperationConflict,
    #[error("credential_configuration_invalid")]
    Configuration,
}
type Result<T> = std::result::Result<T, ProxyCredentialError>;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyCredentialScope {
    pub tenant: String,
    pub principal: String,
    pub policy_revision: String,
    pub surface_owner: [u8; 16],
    pub content_origin: Url,
    pub scope_not_after_ms: u64,
    pub idle_timeout: Duration,
    pub delegated_first_party: bool,
}
#[async_trait]
pub trait ProxyCredentialAuthorizer: fmt::Debug + Send + Sync + 'static {
    async fn resolve_scope(
        &self,
        authentication: ApplicationBinding,
        surface_owner: [u8; 16],
    ) -> Result<ProxyCredentialScope>;
    async fn authorize(
        &self,
        authentication: ApplicationBinding,
        scope: &ProxyCredentialScope,
    ) -> Result<()>;
    async fn external_headers(
        &self,
        _authentication: ApplicationBinding,
        _upstream: &Url,
    ) -> Result<Vec<(String, String)>> {
        Err(ProxyCredentialError::ScopeUnavailable)
    }
}
/// Trusted deployment policy. Content cannot select this mode or grant a scope.
#[derive(Clone)]
pub struct ProxyCredentialPolicy {
    pub mode: ProxyCredentialMode,
    pub environment: Arc<TransportEnvironment>,
    pub authorizer: Arc<dyn ProxyCredentialAuthorizer>,
    pub allow_websocket: bool,
    pub max_owners: usize,
    pub max_total_cookie_bytes: u64,
}
impl fmt::Debug for ProxyCredentialPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCredentialPolicy { <opaque> }")
    }
}
pub(crate) struct CredentialRuntime {
    policy: ProxyCredentialPolicy,
    upstream: Url,
    root: Arc<EnvironmentRoot>,
    jars: Mutex<HashMap<String, Arc<Jar>>>,
    controls: Mutex<HashMap<[u8; 16], ControlRecord>>,
    total_cookie_bytes: AtomicUsize,
    owners: AtomicUsize,
    closed: CancellationToken,
    #[cfg(test)]
    lifecycle_hook: Mutex<Option<CredentialLifecycleHook>>,
}
#[cfg(test)]
type CredentialLifecycleHook = Arc<dyn Fn(&'static str) + Send + Sync>;
impl fmt::Debug for CredentialRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCredentialRuntime { <opaque> }")
    }
}
struct ControlRecord {
    scope: ProxyCredentialScope,
    operation: String,
    action: u8,
    original: String,
    result: Option<Result<CredentialControlOutcome>>,
    busy: bool,
    _charge: EnvironmentCharge,
}
#[derive(Clone, Debug)]
pub(crate) struct CredentialControlOutcome {
    pub(crate) context: Option<String>,
    pub(crate) invalidated: bool,
    pub(crate) error: Option<ProxyCredentialError>,
}
struct StoredCookie {
    runtime: Weak<CredentialRuntime>,
    name: String,
    value: String,
    domain: String,
    path: String,
    host_only: bool,
    secure: bool,
    expires: Option<u64>,
    created: u64,
    bytes: usize,
    _charge: EnvironmentCharge,
}
struct JarState {
    cookies: Vec<Arc<StoredCookie>>,
    bytes: usize,
    generation: u64,
    closed: bool,
    requests: usize,
    last_used: Instant,
    order: u64,
    invalid_cookies: [u64; 8],
}
struct Jar {
    runtime: Weak<CredentialRuntime>,
    scope: ProxyCredentialScope,
    association: String,
    state: Mutex<JarState>,
    stop: CancellationToken,
    changed: Notify,
    _charge: EnvironmentCharge,
}
impl Drop for Jar {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.owners.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
impl Drop for StoredCookie {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
        if let Some(runtime) = self.runtime.upgrade() {
            runtime
                .total_cookie_bytes
                .fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}
/// Borrowed original private association. Its Debug output never includes a Cookie or binding.
#[derive(Clone)]
pub struct ProxyCookieSession {
    owner: Arc<Jar>,
}
impl fmt::Debug for ProxyCookieSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCookieSession { <opaque> }")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyServerInvalidation {
    NotAttempted,
    Confirmed,
    Unknown,
}
#[derive(Clone, Debug)]
pub struct ProxyCredentialClearResult {
    pub server_invalidation: ProxyServerInvalidation,
    pub replacement: Option<ProxyCookieSession>,
    pub cleanup: CleanupStatus,
    pub error: Option<ProxyCredentialError>,
}
impl ProxyCookieSession {
    /// For the trusted dispatcher only. The value is not bearer authority and
    /// must never be copied into content HTTP headers or public diagnostics.
    pub fn attachment(&self) -> Result<String> {
        let runtime = self
            .owner
            .runtime
            .upgrade()
            .ok_or(ProxyCredentialError::ScopeUnavailable)?;
        let state = self
            .owner
            .state
            .lock()
            .expect("original credential association");
        runtime.check_jar(&self.owner, &state)?;
        Ok(self.owner.association.clone())
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let state = self
            .owner
            .state
            .lock()
            .expect("credential cleanup snapshot");
        let pending = state.requests as u64;
        let complete = state.closed && pending == 0;
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: pending,
        }
    }
    pub async fn wait_cleanup(&self, cancellation: &CancellationToken) -> Result<CleanupStatus> {
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ProxyCredentialError::ScopeUnavailable) }
        }
    }
    pub fn close(&self) {
        if let Some(runtime) = self.owner.runtime.upgrade() {
            runtime.invalidate(&self.owner);
        }
    }
}
pub(crate) struct CredentialRequest {
    runtime: Arc<CredentialRuntime>,
    jar: Option<Arc<Jar>>,
    generation: u64,
    receive: bool,
    pub(crate) headers: Vec<(String, String)>,
    stop: CancellationToken,
    _charge: Option<EnvironmentCharge>,
    _cookies: Vec<Arc<StoredCookie>>,
}
impl fmt::Debug for CredentialRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCredentialRequest { <opaque> }")
    }
}
impl Drop for CredentialRequest {
    fn drop(&mut self) {
        #[cfg(test)]
        self.runtime.lifecycle_checkpoint("before_backing_release");
        // The request's frozen headers, Cookie references and allowance retire
        // before its original association can publish complete cleanup.
        drop(std::mem::take(&mut self.headers));
        drop(std::mem::take(&mut self._cookies));
        drop(self._charge.take());
        if let Some(jar) = &self.jar {
            jar.state
                .lock()
                .expect("credential request retirement")
                .requests -= 1;
            jar.changed.notify_waiters();
        }
    }
}
impl CredentialRequest {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.stop.clone()
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.stop.is_cancelled() || self.runtime.closed.is_cancelled() {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        if let Some(jar) = &self.jar {
            let state = jar.state.lock().expect("original credential request gate");
            self.runtime.check_jar(jar, &state)?;
            if state.generation != self.generation {
                return Err(ProxyCredentialError::ScopeUnavailable);
            }
        }
        Ok(())
    }
    pub(crate) fn managed(&self) -> bool {
        self.jar.is_some()
    }
    pub(crate) fn receive_cookies(&self, headers: &http::HeaderMap, path: &str) -> Result<()> {
        self.check()?;
        if !self.receive {
            return Ok(());
        }
        let Some(jar) = &self.jar else {
            return Ok(());
        };
        let now = self
            .runtime
            .root
            .sample()
            .map_err(|_| ProxyCredentialError::ScopeUnavailable)?;
        let host = self
            .runtime
            .upstream
            .host_str()
            .ok_or(ProxyCredentialError::Configuration)?;
        let secure = self.runtime.upstream.scheme() == "https";
        let mut state = jar.state.lock().expect("original Set-Cookie commit gate");
        self.runtime.check_jar(jar, &state)?;
        if state.generation != self.generation {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        // The candidate retains every old backing until all valid replacements
        // and their complete budget have been obtained. No active Cookie eviction.
        let mut candidate = state
            .cookies
            .iter()
            .filter(|cookie| cookie.expires.is_none_or(|end| now.upper_ms < end))
            .cloned()
            .collect::<Vec<_>>();
        let mut order = state.order;
        for raw in headers.get_all(http::header::SET_COOKIE) {
            let Ok(raw) = raw.to_str() else {
                reject_cookie(&mut state, 1);
                continue;
            };
            if raw.len() > 4096 {
                reject_cookie(&mut state, 0);
                continue;
            }
            let Ok(parsed) = Cookie::parse(raw) else {
                reject_cookie(&mut state, 1);
                continue;
            };
            if parsed.partitioned() == Some(true) {
                reject_cookie(&mut state, 2);
                continue;
            }
            if !cookie_token(parsed.name())
                || parsed
                    .value()
                    .bytes()
                    .any(|byte| byte < 0x21 || byte == 0x7f || b"\";,\\".contains(&byte))
            {
                reject_cookie(&mut state, 1);
                continue;
            }
            let Some((domain, host_only)) = cookie_domain(host, parsed.domain()) else {
                reject_cookie(&mut state, 4);
                continue;
            };
            let cookie_path = parsed
                .path()
                .filter(|path| path.starts_with('/'))
                .map(str::to_owned)
                .unwrap_or_else(|| default_path(path));
            if parsed.secure() == Some(true) && !secure {
                reject_cookie(&mut state, 3);
                continue;
            }
            if parsed.name().starts_with("__Secure-") && (!secure || parsed.secure() != Some(true))
                || parsed.name().starts_with("__Host-")
                    && (!secure
                        || parsed.secure() != Some(true)
                        || parsed.domain().is_some()
                        || parsed.path() != Some("/"))
                || parsed.name().starts_with("__Http-")
                    && (!secure
                        || parsed.secure() != Some(true)
                        || parsed.http_only() != Some(true))
                || parsed.name().starts_with("__Host-Http-") && parsed.http_only() != Some(true)
            {
                reject_cookie(&mut state, 5);
                continue;
            }
            if parsed.same_site() == Some(cookie::SameSite::None) && parsed.secure() != Some(true) {
                reject_cookie(&mut state, 3);
                continue;
            }
            let expiry = if let Some(max_age) = parsed.max_age() {
                if max_age.whole_seconds() <= 0 {
                    Some(0)
                } else {
                    Some(
                        u64::try_from(max_age.whole_milliseconds())
                            .ok()
                            .and_then(|duration| now.lower_ms.checked_add(duration))
                            .unwrap_or(jar.scope.scope_not_after_ms),
                    )
                }
            } else if let Some(expires) = parsed.expires_datetime() {
                u64::try_from(expires.unix_timestamp())
                    .ok()
                    .and_then(|seconds| seconds.checked_mul(1000))
                    .or(Some(0))
            } else {
                None
            };
            let expiry = Some(
                expiry
                    .unwrap_or(jar.scope.scope_not_after_ms)
                    .min(jar.scope.scope_not_after_ms),
            );
            let old = candidate.iter().position(|cookie| {
                cookie.name == parsed.name()
                    && cookie.domain == domain
                    && cookie.path == cookie_path
            });
            if expiry.is_some_and(|end| end <= now.upper_ms) {
                if let Some(index) = old {
                    candidate.remove(index);
                }
                continue;
            }
            order = order
                .checked_add(1)
                .ok_or(ProxyCredentialError::UpdateFailed)?;
            let created = old.map_or(order, |index| candidate[index].created);
            let bytes =
                parsed.name().len() + parsed.value().len() + domain.len() + cookie_path.len() + 256;
            let charge = self
                .runtime
                .root
                .reserve_environment(ResourceLimits {
                    sdk_bytes: bytes as u64,
                    items: 1,
                    ..ResourceLimits::default()
                })
                .map_err(|_| ProxyCredentialError::UpdateFailed)?;
            self.runtime
                .total_cookie_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| {
                    total
                        .checked_add(bytes)
                        .filter(|total| *total as u64 <= self.runtime.policy.max_total_cookie_bytes)
                })
                .map_err(|_| ProxyCredentialError::UpdateFailed)?;
            let cookie = Arc::new(StoredCookie {
                runtime: Arc::downgrade(&self.runtime),
                name: parsed.name().to_owned(),
                value: parsed.value().to_owned(),
                domain,
                path: cookie_path,
                host_only,
                secure: parsed.secure() == Some(true),
                expires: expiry,
                created,
                bytes,
                _charge: charge,
            });
            if let Some(index) = old {
                candidate[index] = cookie;
            } else {
                candidate.push(cookie);
            }
            let candidate_bytes = candidate.iter().map(|cookie| cookie.bytes).sum::<usize>();
            if candidate.len() > 64 || candidate_bytes > 512 * 1024 {
                return Err(ProxyCredentialError::UpdateFailed);
            }
        }
        let new_bytes = candidate.iter().map(|cookie| cookie.bytes).sum::<usize>();
        state.cookies = candidate;
        state.bytes = new_bytes;
        state.order = order;
        Ok(())
    }
}
impl CredentialRuntime {
    pub(crate) fn new(policy: ProxyCredentialPolicy, upstream: &Url) -> Result<Arc<Self>> {
        if policy.mode == ProxyCredentialMode::None
            || policy.max_owners == 0
            || policy.max_owners > 64
            || policy.max_total_cookie_bytes == 0
            || policy.max_total_cookie_bytes > 8 * 1024 * 1024
        {
            return Err(ProxyCredentialError::Configuration);
        }
        Ok(Arc::new(Self {
            root: policy.environment.root().clone(),
            policy,
            upstream: upstream.clone(),
            jars: Mutex::new(HashMap::new()),
            controls: Mutex::new(HashMap::new()),
            total_cookie_bytes: AtomicUsize::new(0),
            owners: AtomicUsize::new(0),
            closed: CancellationToken::new(),
            #[cfg(test)]
            lifecycle_hook: Mutex::new(None),
        }))
    }
    #[cfg(test)]
    pub(crate) fn set_lifecycle_hook(&self, hook: CredentialLifecycleHook) {
        *self
            .lifecycle_hook
            .lock()
            .expect("credential lifecycle hook") = Some(hook);
    }
    #[cfg(test)]
    fn lifecycle_checkpoint(&self, stage: &'static str) {
        let hook = self
            .lifecycle_hook
            .lock()
            .expect("credential lifecycle hook")
            .clone();
        if let Some(hook) = hook {
            hook(stage);
        }
    }
    pub(crate) fn close(&self) {
        self.closed.cancel();
        self.controls
            .lock()
            .expect("closed credential controls")
            .clear();
        let jars =
            std::mem::take(&mut *self.jars.lock().expect("closed proxy credential registry"));
        for jar in jars.into_values() {
            self.invalidate(&jar);
        }
    }
    fn new_jar(self: &Arc<Self>, scope: ProxyCredentialScope) -> Result<ProxyCookieSession> {
        let now = self
            .root
            .sample()
            .map_err(|_| ProxyCredentialError::ScopeUnavailable)?;
        if self.closed.is_cancelled()
            || !scope.delegated_first_party
            || scope.scope_not_after_ms <= now.upper_ms
            || scope.idle_timeout.is_zero()
            || scope.idle_timeout > Duration::from_secs(3600)
            || scope.surface_owner == [0; 16]
            || [
                scope.tenant.as_str(),
                scope.principal.as_str(),
                scope.policy_revision.as_str(),
            ]
            .iter()
            .any(|value| value.is_empty() || value.len() > 128)
            || !matches!(scope.content_origin.scheme(), "http" | "https")
            || scope.content_origin.host_str().is_none()
            || scope.content_origin.path() != "/"
            || scope.content_origin.query().is_some()
            || scope.content_origin.fragment().is_some()
            || !scope.content_origin.username().is_empty()
            || scope.content_origin.password().is_some()
        {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        let charge = self
            .root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 8192,
                items: 1,
                timers: 1,
                tasks: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| ProxyCredentialError::UpdateFailed)?;
        let mut random = [0; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| ProxyCredentialError::ScopeUnavailable)?;
        let association = URL_SAFE_NO_PAD.encode(random);
        self.owners
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.policy.max_owners).then_some(count + 1)
            })
            .map_err(|_| ProxyCredentialError::UpdateFailed)?;
        let jar = Arc::new(Jar {
            runtime: Arc::downgrade(self),
            scope,
            association: association.clone(),
            state: Mutex::new(JarState {
                cookies: Vec::new(),
                bytes: 0,
                generation: 1,
                closed: false,
                requests: 0,
                last_used: Instant::now(),
                order: 0,
                invalid_cookies: [0; 8],
            }),
            stop: CancellationToken::new(),
            changed: Notify::new(),
            _charge: charge,
        });
        self.jars
            .lock()
            .expect("explicit credential binding installation")
            .insert(association, jar.clone());
        let original = Arc::downgrade(&jar);
        let runtime = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(jar) = original.upgrade() else {
                    return;
                };
                let stop = jar.stop.clone();
                if stop.is_cancelled() {
                    return;
                }
                let Some(runtime) = runtime.upgrade() else {
                    return;
                };
                let remaining = {
                    let state = jar
                        .state
                        .lock()
                        .expect("original credential finite deadline");
                    match runtime.root.sample() {
                        Ok(now) if !state.closed => Duration::from_millis(
                            jar.scope.scope_not_after_ms.saturating_sub(now.upper_ms),
                        )
                        .min(
                            jar.scope
                                .idle_timeout
                                .saturating_sub(state.last_used.elapsed()),
                        )
                        .min(Duration::from_millis(100)),
                        _ => Duration::ZERO,
                    }
                };
                if remaining.is_zero() {
                    runtime.invalidate(&jar);
                    return;
                }
                drop(jar);
                drop(runtime);
                tokio::select! { _ = stop.cancelled() => return, _ = tokio::time::sleep(remaining) => {} }
            }
        });
        Ok(ProxyCookieSession { owner: jar })
    }
    pub(crate) async fn control(
        self: &Arc<Self>,
        authentication: ApplicationBinding,
        surface: [u8; 16],
        operation: &str,
        action: u8,
        association: &str,
        content_origin: &str,
    ) -> Result<CredentialControlOutcome> {
        let scope = self
            .policy
            .authorizer
            .resolve_scope(authentication, surface)
            .await?;
        if scope.surface_owner != surface
            || action == 1 && scope.content_origin.origin().ascii_serialization() != content_origin
        {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        self.policy
            .authorizer
            .authorize(authentication, &scope)
            .await?;
        {
            let now = self
                .root
                .sample()
                .map_err(|_| ProxyCredentialError::ScopeUnavailable)?;
            let mut controls = self
                .controls
                .lock()
                .expect("original bounded credential control gate");
            controls
                .retain(|_, record| record.busy || record.scope.scope_not_after_ms > now.upper_ms);
            if let Some(result) =
                Self::prior_control(&controls, &scope, surface, operation, action, association)
            {
                return result;
            }
        }
        // Authorize the original jar before accepting this control operation.
        // Once busy is published, invalidation and its stored outcome must not
        // yield to request cancellation or a response deadline.
        let original = if matches!(action, 2 | 3) {
            let jar = self.lookup(association)?;
            if jar.scope.surface_owner != surface {
                return Err(ProxyCredentialError::ScopeUnavailable);
            }
            self.policy
                .authorizer
                .authorize(authentication, &jar.scope)
                .await?;
            Some(jar)
        } else {
            None
        };
        let now = self
            .root
            .sample()
            .map_err(|_| ProxyCredentialError::ScopeUnavailable)?;
        // Retain the bounded record and its charge through the whole accepted
        // operation, including concurrent runtime close and result publication.
        let mut controls = self
            .controls
            .lock()
            .expect("credential control acceptance after authorization");
        if let Some(result) =
            Self::prior_control(&controls, &scope, surface, operation, action, association)
        {
            return result;
        }
        if self.closed.is_cancelled() || scope.scope_not_after_ms <= now.upper_ms {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        if !controls.contains_key(&surface) && controls.len() >= self.policy.max_owners {
            return Err(ProxyCredentialError::UpdateFailed);
        }
        let charge = self
            .root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 2048,
                items: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| ProxyCredentialError::UpdateFailed)?;
        controls.insert(
            surface,
            ControlRecord {
                scope: scope.clone(),
                operation: operation.to_owned(),
                action,
                original: association.to_owned(),
                result: None,
                busy: true,
                _charge: charge,
            },
        );
        let result = match action {
            1 if scope.content_origin.origin().ascii_serialization() == content_origin => {
                self.new_jar(scope).and_then(|session| {
                    session
                        .attachment()
                        .map(|context| CredentialControlOutcome {
                            context: Some(context),
                            invalidated: false,
                            error: None,
                        })
                })
            }
            2 => self
                .clear_authorized(original.expect("accepted Clear owns its authorized jar"))
                .map(|result| {
                    let invalidated =
                        result.server_invalidation == ProxyServerInvalidation::Confirmed;
                    let context = match result.error {
                        Some(error) => Err(error),
                        None => result
                            .replacement
                            .ok_or(ProxyCredentialError::ScopeUnavailable)
                            .and_then(|replacement| replacement.attachment()),
                    };
                    match context {
                        Ok(context) => CredentialControlOutcome {
                            context: Some(context),
                            invalidated,
                            error: None,
                        },
                        Err(error) => CredentialControlOutcome {
                            context: None,
                            invalidated,
                            error: Some(error),
                        },
                    }
                }),
            3 => {
                self.invalidate(&original.expect("accepted Dispose owns its authorized jar"));
                Ok(CredentialControlOutcome {
                    context: None,
                    invalidated: true,
                    error: None,
                })
            }
            _ => Err(ProxyCredentialError::ScopeUnavailable),
        };
        if let Some(record) = controls
            .get_mut(&surface)
            .filter(|record| record.operation == operation)
        {
            record.busy = false;
            record.result = Some(result.clone());
        }
        result
    }
    fn prior_control(
        controls: &HashMap<[u8; 16], ControlRecord>,
        scope: &ProxyCredentialScope,
        surface: [u8; 16],
        operation: &str,
        action: u8,
        association: &str,
    ) -> Option<Result<CredentialControlOutcome>> {
        let record = controls.get(&surface)?;
        if &record.scope != scope {
            return Some(Err(ProxyCredentialError::ScopeUnavailable));
        }
        if record.operation == operation {
            if record.action != action || record.original != association {
                return Some(Err(ProxyCredentialError::OperationConflict));
            }
            return Some(
                record
                    .result
                    .clone()
                    .unwrap_or(Err(ProxyCredentialError::OperationConflict)),
            );
        }
        if record.busy
            || action == 1
                && record.result.as_ref().is_some_and(|result| {
                    result
                        .as_ref()
                        .is_ok_and(|outcome| outcome.context.is_some())
                })
        {
            return Some(Err(ProxyCredentialError::OperationConflict));
        }
        None
    }
    pub(crate) async fn bind(
        self: &Arc<Self>,
        authentication: ApplicationBinding,
        surface: [u8; 16],
        content_origin: &str,
    ) -> Result<ProxyCookieSession> {
        if self.policy.mode != ProxyCredentialMode::UpstreamCookieSession {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        let scope = self
            .policy
            .authorizer
            .resolve_scope(authentication, surface)
            .await?;
        if scope.surface_owner != surface
            || scope.content_origin.origin().ascii_serialization() != content_origin
        {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        self.policy
            .authorizer
            .authorize(authentication, &scope)
            .await?;
        self.new_jar(scope)
    }
    pub(crate) async fn clear(
        self: &Arc<Self>,
        authentication: ApplicationBinding,
        surface: [u8; 16],
        association: &str,
    ) -> Result<ProxyCredentialClearResult> {
        let original = self.lookup(association)?;
        if original.scope.surface_owner != surface {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        self.policy
            .authorizer
            .authorize(authentication, &original.scope)
            .await?;
        self.clear_authorized(original)
    }
    fn clear_authorized(
        self: &Arc<Self>,
        original: Arc<Jar>,
    ) -> Result<ProxyCredentialClearResult> {
        let state = original
            .state
            .lock()
            .expect("credential Clear original owner");
        self.check_jar(&original, &state)?;
        drop(state);
        let replacement = self.new_jar(original.scope.clone());
        self.invalidate(&original);
        let (replacement, error) = match replacement {
            Ok(replacement) => (Some(replacement), None),
            Err(error) => (None, Some(error)),
        };
        Ok(ProxyCredentialClearResult {
            server_invalidation: ProxyServerInvalidation::Confirmed,
            replacement,
            error,
            cleanup: ProxyCookieSession { owner: original }.cleanup_status(),
        })
    }
    fn lookup(&self, association: &str) -> Result<Arc<Jar>> {
        if association.len() != 43
            || URL_SAFE_NO_PAD
                .decode(association)
                .ok()
                .is_none_or(|value| value.len() != 32)
        {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        self.jars
            .lock()
            .expect("original private credential registry")
            .get(association)
            .cloned()
            .ok_or(ProxyCredentialError::ScopeUnavailable)
    }
    fn check_jar(&self, jar: &Jar, state: &JarState) -> Result<()> {
        let now = self
            .root
            .sample()
            .map_err(|_| ProxyCredentialError::ScopeUnavailable)?;
        if self.closed.is_cancelled()
            || jar.stop.is_cancelled()
            || state.closed
            || now.upper_ms >= jar.scope.scope_not_after_ms
            || state.last_used.elapsed() >= jar.scope.idle_timeout
        {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        Ok(())
    }
    fn invalidate(&self, jar: &Arc<Jar>) {
        let mut state = jar
            .state
            .lock()
            .expect("per-incarnation credential invalidation gate");
        if !state.closed {
            state.closed = true;
            state.generation = state.generation.saturating_add(1);
            jar.stop.cancel();
            state.bytes = 0;
            state.cookies.clear();
        }
        drop(state);
        self.jars
            .lock()
            .expect("credential association retirement")
            .remove(&jar.association);
        jar.changed.notify_waiters();
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Credential selection independently binds authentication, association, origin, path and request headers."
    )]
    pub(crate) async fn request(
        self: &Arc<Self>,
        authentication: Option<ApplicationBinding>,
        association: &str,
        credentials: &str,
        origin: &str,
        path: &str,
        supplied: &[(String, String)],
        websocket: bool,
    ) -> Result<CredentialRequest> {
        let authentication = authentication.ok_or(ProxyCredentialError::ScopeUnavailable)?;
        if self.closed.is_cancelled()
            || supplied.iter().any(|(name, _)| {
                name.eq_ignore_ascii_case("cookie") || name.eq_ignore_ascii_case("authorization")
            })
        {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        if self.policy.mode == ProxyCredentialMode::External {
            if !association.is_empty() {
                return Err(ProxyCredentialError::ScopeUnavailable);
            }
            let headers = self
                .policy
                .authorizer
                .external_headers(authentication, &self.upstream)
                .await?;
            if headers.len() > 32
                || headers.iter().any(|(name, value)| {
                    !cookie_token(name)
                        || value.len() > 8192
                        || value.bytes().any(|byte| byte < 32 || byte == 127)
                })
            {
                return Err(ProxyCredentialError::Configuration);
            }
            return Ok(CredentialRequest {
                runtime: self.clone(),
                jar: None,
                generation: 0,
                receive: false,
                headers,
                stop: self.closed.child_token(),
                _charge: None,
                _cookies: Vec::new(),
            });
        }
        if websocket && !self.policy.allow_websocket {
            return Err(ProxyCredentialError::ScopeUnavailable);
        }
        let jar = self.lookup(association)?;
        self.policy
            .authorizer
            .authorize(authentication, &jar.scope)
            .await?;
        let mut state = jar
            .state
            .lock()
            .expect("freeze original request Cookie vector");
        self.check_jar(&jar, &state)?;
        let receive = match credentials {
            "omit" => false,
            "include" => true,
            "same-origin" => origin == jar.scope.content_origin.origin().ascii_serialization(),
            _ => return Err(ProxyCredentialError::ScopeUnavailable),
        };
        let now = self
            .root
            .sample()
            .map_err(|_| ProxyCredentialError::ScopeUnavailable)?;
        let host = self
            .upstream
            .host_str()
            .ok_or(ProxyCredentialError::Configuration)?
            .trim_start_matches('[')
            .trim_end_matches(']');
        let mut cookies = if receive {
            state
                .cookies
                .iter()
                .filter(|cookie| {
                    domain_matches(host, &cookie.domain, cookie.host_only)
                        && (!cookie.secure || self.upstream.scheme() == "https")
                        && path_matches(path, &cookie.path)
                        && cookie.expires.is_none_or(|end| now.upper_ms < end)
                })
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        cookies.sort_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then(left.created.cmp(&right.created))
        });
        let bytes = cookies
            .iter()
            .map(|cookie| cookie.name.len() + cookie.value.len() + 3)
            .sum::<usize>();
        let charge = self
            .root
            .reserve_environment(ResourceLimits {
                sdk_bytes: bytes as u64 + 1024,
                items: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| ProxyCredentialError::UpdateFailed)?;
        let header = cookies
            .iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>()
            .join("; ");
        let headers = if header.is_empty() {
            Vec::new()
        } else {
            vec![("cookie".to_owned(), header)]
        };
        state.last_used = Instant::now();
        let generation = state.generation;
        // Admission, invalidation and cleanup observe the same original gate.
        // No closed association can appear complete between capture and charge.
        state.requests = state
            .requests
            .checked_add(1)
            .ok_or(ProxyCredentialError::UpdateFailed)?;
        let request = CredentialRequest {
            runtime: self.clone(),
            generation,
            receive,
            headers,
            stop: jar.stop.child_token(),
            jar: Some(jar.clone()),
            _charge: Some(charge),
            _cookies: cookies,
        };
        drop(state);
        #[cfg(test)]
        self.lifecycle_checkpoint("after_admission_unlock");
        Ok(request)
    }
}
fn reject_cookie(state: &mut JarState, reason: usize) {
    state.invalid_cookies[reason] = state.invalid_cookies[reason].saturating_add(1);
}
fn domain_matches(host: &str, domain: &str, host_only: bool) -> bool {
    host.eq_ignore_ascii_case(domain)
        || !host_only
            && host.parse::<std::net::IpAddr>().is_err()
            && host
                .strip_suffix(domain)
                .is_some_and(|prefix| prefix.ends_with('.'))
}
fn cookie_domain(host: &str, supplied: Option<&str>) -> Option<(String, bool)> {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let Some(supplied) = supplied.filter(|domain| !domain.is_empty()) else {
        return Some((host, true));
    };
    let supplied = supplied.strip_prefix('.').unwrap_or(supplied);
    if supplied.is_empty() || supplied.ends_with('.') || supplied.starts_with('.') {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return (supplied.parse::<std::net::IpAddr>().ok() == Some(ip)).then_some((host, true));
    }
    let domain = idna::domain_to_ascii_strict(supplied)
        .ok()?
        .to_ascii_lowercase();
    if !domain_matches(&host, &domain, false) || psl::suffix_str(&domain) == Some(domain.as_str()) {
        return None;
    }
    Some((domain, false))
}
fn cookie_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}
fn default_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or("/");
    match path.rfind('/') {
        Some(index) if index > 0 => path[..index].to_owned(),
        _ => "/".to_owned(),
    }
}
fn path_matches(request: &str, cookie: &str) -> bool {
    let path = request.split('?').next().unwrap_or("/");
    path == cookie
        || path.starts_with(cookie)
            && (cookie.ends_with('/') || path.as_bytes().get(cookie.len()) == Some(&b'/'))
}
