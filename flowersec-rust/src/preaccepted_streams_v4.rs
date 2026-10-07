//! One original Session directory for exact empty accepted business Streams.
//! Checkout transfers a physical scope once; replenishment always opens a new ID.
use crate::{
    application_tails_v4::ApplicationTail,
    crypto_v4::{Metadata, Session, SessionLink},
    environment_v4::{ResourceAccount, ResourceCharge, ResourceLimits},
    rpc_stream_messages_v4::StreamMessages,
    service_contract::{MethodDefinition, ServiceError, ServiceFailure},
    service_peer_v4::PeerInner,
};
use std::{
    fmt,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
const IDLE_TTL: Duration = Duration::from_secs(30);
const MAX_TARGETS: usize = 8;
const MAX_SERVICE_TARGETS: usize = 2;

/// Omitting a requirement keeps pooling disabled. RequiredForDispatch pays for
/// one simultaneously ready empty accepted Stream at normal binding; OnUse only
/// checks out a compatible existing entry and never initiates replenishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamingPoolPolicy {
    RequiredForDispatch,
    OnUse,
}
#[derive(Clone, Debug)]
pub struct StreamingPoolRequirement {
    pub method: MethodDefinition,
    pub policy: StreamingPoolPolicy,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PoolTarget {
    pub(crate) namespace: String,
    pub(crate) type_id: u32,
    pub(crate) contract: [u8; 32],
    pub(crate) kind: String,
    pub(crate) metadata: Metadata,
    pub(crate) limit: usize,
}
#[derive(Default)]
pub(crate) struct PoolDirectory {
    targets: Mutex<Vec<Weak<Pool>>>,
}
impl PoolDirectory {
    pub(crate) fn demand(
        &self,
        session: &Session,
        peer: &Arc<PeerInner>,
        target: PoolTarget,
        policy: StreamingPoolPolicy,
    ) -> Result<Option<PoolDemand>> {
        self.demand_many(session, peer, vec![(target, policy)])
            .map(|mut demands| demands.pop().flatten())
    }
    pub(crate) fn demand_many(
        &self,
        session: &Session,
        peer: &Arc<PeerInner>,
        requested: Vec<(PoolTarget, StreamingPoolPolicy)>,
    ) -> Result<Vec<Option<PoolDemand>>> {
        session
            .with_stream_pool_admission(|| ())
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let mut targets = self
            .targets
            .lock()
            .expect("Session accepted Stream pool directory");
        targets.retain(|target| {
            target
                .upgrade()
                .is_some_and(|pool| !pool.state.lock().expect("accepted Stream pool target").done)
        });
        let existing: Vec<_> = targets.iter().filter_map(Weak::upgrade).collect();
        let mut new_targets: Vec<&PoolTarget> = Vec::new();
        for (target, policy) in &requested {
            if *policy == StreamingPoolPolicy::RequiredForDispatch
                && !existing.iter().any(|pool| pool.target == *target)
                && !new_targets.iter().any(|old| **old == *target)
            {
                new_targets.push(target);
            }
        }
        if existing.len() + new_targets.len() > MAX_TARGETS
            || new_targets.iter().any(|target| {
                existing
                    .iter()
                    .filter(|pool| pool.target.namespace == target.namespace)
                    .count()
                    + new_targets
                        .iter()
                        .filter(|new| new.namespace == target.namespace)
                        .count()
                    > MAX_SERVICE_TARGETS
            })
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let mut demands = Vec::with_capacity(requested.len());
        let mut starting = Vec::with_capacity(new_targets.len());
        for (target, policy) in requested {
            if let Some(pool) = targets
                .iter()
                .filter_map(Weak::upgrade)
                .find(|pool| pool.target == target)
            {
                if policy == StreamingPoolPolicy::RequiredForDispatch {
                    let mut state = pool.state.lock().expect("accepted Stream pool target");
                    if state.closed {
                        return Err(failure(ServiceFailure::ServiceUnavailable));
                    }
                    state.demands = state
                        .demands
                        .checked_add(1)
                        .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
                }
                pool.changed.notify_waiters();
                demands.push(Some(PoolDemand(Arc::new(Demand {
                    pool,
                    required: policy == StreamingPoolPolicy::RequiredForDispatch,
                }))));
                continue;
            }
            if policy == StreamingPoolPolicy::OnUse {
                demands.push(None);
                continue;
            }
            let account = session.application_account();
            let mut charge = account.reserve(ResourceLimits {
                sdk_bytes: 8192,
                items: 2,
                tasks: 1,
                timers: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            })?;
            let active_charge = charge.split(ResourceLimits {
                tasks: 1,
                timers: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            })?;
            let tail = session
                .application_tail()
                .map_err(|_| failure(ServiceFailure::Closed))?;
            let cancellation = tail.cancellation();
            // Every initial complete graph is reserved before any new target
            // submits OPEN. Partial configuration failure spends no physical ID.
            let (messages, preparation) =
                StreamMessages::prepare(session, &peer.channel, target.limit, None)?;
            messages.retain_peer(peer);
            let pool = Arc::new(Pool {
                target,
                account,
                session: session.link(),
                peer: Arc::downgrade(peer),
                initial: Mutex::new(Some((Arc::new(messages), preparation))),
                state: Mutex::new(State {
                    demands: 1,
                    idle: None,
                    closed: false,
                    failure: None,
                    done: false,
                }),
                cancellation,
                peer_cancel: peer.cancellation(),
                peer_worker: Mutex::new(Some(peer.retain_worker())),
                session_changed: session.stream_pool_changed(),
                changed: Notify::new(),
                active_charge: Mutex::new(Some(active_charge)),
                _capture_charge: charge,
            });
            targets.push(Arc::downgrade(&pool));
            starting.push((pool.clone(), tail));
            demands.push(Some(PoolDemand(Arc::new(Demand {
                pool,
                required: true,
            }))));
        }
        drop(targets);
        for (worker, tail) in starting {
            tokio::spawn(async move {
                worker.run(tail).await;
            });
        }
        Ok(demands)
    }
}
struct Entry {
    messages: Arc<StreamMessages>,
    expires: Instant,
}
struct State {
    demands: usize,
    idle: Option<Entry>,
    closed: bool,
    failure: Option<ServiceFailure>,
    done: bool,
}
struct Pool {
    target: PoolTarget,
    account: ResourceAccount,
    session: SessionLink,
    peer: Weak<PeerInner>,
    initial: Mutex<Option<(Arc<StreamMessages>, crate::crypto_v4::StreamPreparation)>>,
    state: Mutex<State>,
    cancellation: CancellationToken,
    peer_cancel: CancellationToken,
    peer_worker: Mutex<Option<crate::service_peer_v4::PeerWorker>>,
    session_changed: Arc<Notify>,
    changed: Notify,
    active_charge: Mutex<Option<ResourceCharge>>,
    _capture_charge: ResourceCharge,
}
struct Demand {
    pool: Arc<Pool>,
    required: bool,
}
impl Drop for Demand {
    fn drop(&mut self) {
        if self.required {
            let mut state = self.pool.state.lock().expect("accepted Stream pool target");
            state.demands -= 1;
            let last = state.demands == 0;
            drop(state);
            if last {
                self.pool.cancellation.cancel();
            }
            self.pool.changed.notify_waiters();
        }
    }
}
#[derive(Clone)]
pub(crate) struct PoolDemand(Arc<Demand>);
impl fmt::Debug for PoolDemand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcceptedStreamPoolDemand { <opaque> }")
    }
}
impl PoolDemand {
    pub(crate) async fn wait_ready(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        loop {
            let changed = self.0.pool.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.0.pool.account.check()?;
            {
                let state = self
                    .0
                    .pool
                    .state
                    .lock()
                    .expect("accepted Stream pool target");
                if let Some(error) = state.failure {
                    return Err(failure(error));
                }
                if state.closed {
                    return Err(failure(ServiceFailure::Closed));
                }
                if state
                    .idle
                    .as_ref()
                    .is_some_and(|entry| Instant::now() < entry.expires)
                {
                    return Ok(());
                }
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)),
            _ = self.0.pool.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
            _ = self.0.pool.peer_cancel.cancelled() => return Err(failure(ServiceFailure::Closed)) }
        }
    }
    pub(crate) fn checkout(&self) -> Result<Arc<StreamMessages>> {
        let session = self
            .0
            .pool
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::DependencyUnavailable))?;
        let entry = session
            .with_stream_pool_admission(|| {
                let mut state = self
                    .0
                    .pool
                    .state
                    .lock()
                    .expect("accepted Stream pool target");
                if state.closed {
                    return None;
                }
                state.idle.take()
            })
            .map_err(|_| failure(ServiceFailure::DependencyUnavailable))?
            .ok_or_else(|| failure(ServiceFailure::DependencyUnavailable))?;
        self.0.pool.changed.notify_waiters();
        if Instant::now() >= entry.expires || !entry.messages.pool_ready() {
            entry.messages.close();
            return Err(failure(ServiceFailure::DependencyUnavailable));
        }
        Ok(entry.messages)
    }
}
impl Pool {
    async fn retire(messages: Arc<StreamMessages>) {
        messages.close();
        while !messages.cleanup_status().complete {
            let _ = messages.wait_cleanup().await;
        }
    }
    async fn run(self: Arc<Self>, tail: ApplicationTail) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let session_changed = self.session_changed.notified();
            tokio::pin!(session_changed);
            session_changed.as_mut().enable();
            let accepting = self
                .session
                .session()
                .ok()
                .is_some_and(|session| session.with_stream_pool_admission(|| ()).is_ok());
            let (stop, old, fill, expires) = {
                let mut state = self.state.lock().expect("accepted Stream pool target");
                let stop = !accepting
                    || state.closed
                    || state.demands == 0
                    || self.cancellation.is_cancelled()
                    || self.peer_cancel.is_cancelled();
                let expired = state
                    .idle
                    .as_ref()
                    .is_some_and(|entry| Instant::now() >= entry.expires);
                let old = if stop || expired {
                    state.idle.take()
                } else {
                    None
                };
                (
                    stop,
                    old,
                    !stop && state.idle.is_none(),
                    state.idle.as_ref().map(|entry| entry.expires),
                )
            };
            if let Some(entry) = old {
                Self::retire(entry.messages).await;
            }
            if stop {
                break;
            }
            if fill {
                let opening = async {
                    self.account.check()?;
                    let session = self
                        .session
                        .session()
                        .map_err(|_| failure(ServiceFailure::Closed))?;
                    let peer = self
                        .peer
                        .upgrade()
                        .ok_or_else(|| failure(ServiceFailure::Closed))?;
                    peer.check()?;
                    let initial = self
                        .initial
                        .lock()
                        .expect("accepted Stream initial preparation")
                        .take();
                    let (messages, preparation) = match initial {
                        Some(initial) => initial,
                        None => {
                            let (messages, preparation) = StreamMessages::prepare(
                                &session,
                                &peer.channel,
                                self.target.limit,
                                None,
                            )?;
                            messages.retain_peer(&peer);
                            (Arc::new(messages), preparation)
                        }
                    };
                    let attach = messages.clone();
                    let opened = tokio::select! {
                        result = session.open_stream_prepared(&self.target.kind, self.target.metadata.clone(), 16384, preparation,
                            move |stream| attach.attach(stream)) => result.map(|_| ()).map_err(|_| failure(ServiceFailure::ServiceUnavailable)),
                        _ = self.cancellation.cancelled() => Err(failure(ServiceFailure::Closed)),
                        _ = self.peer_cancel.cancelled() => Err(failure(ServiceFailure::Closed)),
                    };
                    if let Err(error) = opened {
                        Self::retire(messages).await;
                        return Err(error);
                    }
                    Ok(Entry {
                        messages,
                        expires: Instant::now() + IDLE_TTL,
                    })
                };
                match opening.await {
                    Ok(entry) => {
                        let abandoned = {
                            let mut state = self.state.lock().expect("accepted Stream pool target");
                            if state.demands == 0
                                || state.closed
                                || self.cancellation.is_cancelled()
                            {
                                Some(entry)
                            } else {
                                state.idle = Some(entry);
                                None
                            }
                        };
                        if let Some(entry) = abandoned {
                            Self::retire(entry.messages).await;
                        }
                        self.changed.notify_waiters();
                    }
                    Err(error) => {
                        self.state
                            .lock()
                            .expect("accepted Stream pool target")
                            .failure = Some(error.0);
                        self.changed.notify_waiters();
                        break;
                    }
                }
                continue;
            }
            tokio::select! { _ = changed => {}, _ = session_changed => {}, _ = self.cancellation.cancelled() => {}, _ = self.peer_cancel.cancelled() => {},
            _ = self.account.security_changed() => {},
            _ = tokio::time::sleep_until(expires.unwrap_or_else(|| Instant::now() + IDLE_TTL)) => {} }
        }
        let idle = {
            let mut state = self.state.lock().expect("accepted Stream pool target");
            state.closed = true;
            state.idle.take()
        };
        if let Some(entry) = idle {
            Self::retire(entry.messages).await;
        }
        let initial = self
            .initial
            .lock()
            .expect("accepted Stream initial preparation")
            .take();
        if let Some((messages, _preparation)) = initial {
            Self::retire(messages).await;
        }
        self.active_charge
            .lock()
            .expect("accepted Stream pool task charge")
            .take();
        tail.finish();
        self.peer_worker
            .lock()
            .expect("accepted Stream peer worker")
            .take();
        self.state.lock().expect("accepted Stream pool target").done = true;
        self.changed.notify_waiters();
    }
}
