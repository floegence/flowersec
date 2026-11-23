//! Product endpoint for the original Direct and Tunnel capacity coordinators.
#[path = "capacity_business.rs"]
mod business;
#[path = "capacity_tunnel.rs"]
mod tunnel;
use super::{listener::ApprovalStore, parity};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flowersec::{
    Acceptor, AcceptorOptions, Artifact, ArtifactLease, ConnectorOptions, DirectAuthorizer,
    DirectHandlers, NotificationHandler, NotificationSubscription, RpcError, RpcHandler, Session,
    SessionHandlerOptions, SessionHandlers, connect_with_cancellation,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    num::{NonZeroU16, NonZeroUsize},
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, String>;
type End = Arc<dyn Session>;
const COUNT: usize = 1000;
const SUCCESSORS: usize = 4;
const MAX_FRAME: usize = 8192;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn path(var: &str) -> Result<PathBuf> {
    let p = std::env::var_os(var)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {var}"))?;
    if !p.is_absolute() {
        return Err(format!("{var} must be absolute"));
    }
    Ok(p)
}
fn number(v: &Value, k: &str) -> Result<usize> {
    v[k].as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| format!("invalid {k}"))
}

struct Method;
#[async_trait]
impl RpcHandler for Method {
    async fn call(&self, id: u32, p: Value) -> std::result::Result<Value, RpcError> {
        if !matches!(id, 7001 | 7003 | 7005) || !p.is_object() {
            return Err(RpcError::new(400, None).unwrap());
        }
        Ok(p)
    }
    async fn notify(&self, _: u32, _: Value) -> std::result::Result<(), RpcError> {
        Err(RpcError::new(400, None).unwrap())
    }
}
#[async_trait]
impl NotificationHandler for Method {
    async fn handle_notification(&self, id: u32, p: Value) -> std::result::Result<(), RpcError> {
        if id == 7002 && p.is_object() {
            Ok(())
        } else {
            Err(RpcError::new(400, None).unwrap())
        }
    }
}

struct Store {
    approvals: ApprovalStore,
    pending: Mutex<HashMap<String, oneshot::Sender<End>>>,
}
#[async_trait]
impl DirectAuthorizer for Store {
    async fn lookup(&self, id: &str) -> Option<(ArtifactLease, DirectHandlers)> {
        if id.is_empty() || !id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')) {
            return None;
        }
        let approved = self.approvals.directory.join(format!("{id}.json"));
        let spent = approved.with_extension("spent");
        let released = approved.with_extension("released");
        let material = tokio::task::spawn_blocking({
            let approved = approved.clone();
            move || super::listener::read_approval(&approved)
        }).await.ok()?.ok()?;
        let artifact = Artifact::parse(&material).ok()?;
        let envelope: Value = serde_json::from_slice(&material).ok()?;
        if envelope["session"]["channel_id"].as_str()? != id {
            return None;
        }
        let expiry = envelope["session"]["init_expire_at_unix_s"].as_u64()?;
        let consumed = spent.clone();
        let lease = ArtifactLease::new_with_release(artifact, move || async move {
            tokio::task::spawn_blocking(move || {
                let failed = flowersec::ArtifactSpendError::CommitFailed;
                std::fs::hard_link(approved, &spent).map_err(|_| failed)?;
                std::fs::File::open(&spent).and_then(|file| file.sync_all())
                    .and_then(|()| super::sync_parent_directory(&spent)).map_err(|_| failed)?;
                if super::listener::read_approval(&spent).map_err(|_| failed)? != material ||
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| failed)?.as_secs() >= expiry {
                    return Err(failed);
                }
                Ok(())
            }).await.map_err(|_| flowersec::ArtifactSpendError::CommitFailed)?
        }, move || async move {
            tokio::task::spawn_blocking(move || {
                std::fs::hard_link(consumed, &released)
                    .and_then(|()| super::sync_parent_directory(&released))
                    .map_err(|_| flowersec::ArtifactSpendError::CommitFailed)
            }).await.map_err(|_| flowersec::ArtifactSpendError::CommitFailed)?
        });
        Some((lease, self.approvals.handlers.clone()))
    }
    async fn connected(&self, id: &str, s: End) {
        let tx = self.pending.lock().unwrap().remove(id);
        if let Some(tx) = tx {
            if let Err(s) = tx.send(s) {
                let _ = s.close().await;
            }
        } else {
            let _ = s.close().await;
        }
    }
}

struct Pair {
    generation: usize,
    a: End,
    b: End,
    _subscriptions: [Binding; 2],
    watchers: [JoinHandle<()>; 2],
    down: [Arc<AtomicBool>; 2],
}
struct Binding {
    _subscription: NotificationSubscription,
    _receiver: Option<mpsc::Receiver<Value>>,
}
struct Installation {
    options: ConnectorOptions,
    invitations: PathBuf,
    spent: PathBuf,
    transport: Transport,
    live: Mutex<HashMap<String, Pair>>,
    closing: Mutex<HashMap<String, watch::Receiver<Option<Result<usize>>>>>,
    replacement: bool,
    overlap: Option<Mutex<HashSet<usize>>>,
    used: Mutex<HashSet<usize>>,
    stop: CancellationToken,
    serving: Mutex<Option<JoinHandle<std::result::Result<(), flowersec::AcceptError>>>>,
    events: mpsc::Sender<Value>,
    prepared: AtomicBool,
    closed: AtomicBool,
    completed: AtomicUsize,
}
enum Transport {
    Direct(Arc<Store>),
    Tunnel(tunnel::Legs),
}
impl Installation {
    fn start(q: &Value, events: mpsc::Sender<Value>) -> Result<(Self, Value)> {
        let o = &q["options"];
        if o["nativeSDK"] != "rust"
            || o["carrier"] != "raw-quic"
            || number(o, "sessions")? != COUNT
            || number(o, "streamsPerSession")? != 0
        {
            return Err("requires the original 1000-pair Rust raw QUIC case".into());
        }
        let mut replacement = false;
        for (option, applicable) in [
            ("directReplacement", o["serverCarrier"].is_null()),
            ("tunnelReplacement", !o["serverCarrier"].is_null()),
        ] {
            match o.get(option) {
                None | Some(Value::Bool(false)) => (),
                Some(Value::Bool(true)) if applicable => replacement = true,
                _ => return Err("configuration".into()),
            }
        }
        let overlap = match o.get("overlapSuccessors") {
            None => None,
            Some(_) if !cfg!(unix) => {
                return Err("capacity overlap requires Unix receipt identities".into());
            }
            Some(n) if n.as_u64() == Some(SUCCESSORS as u64) && !replacement => {
                Some(Mutex::new(HashSet::new()))
            }
            _ => return Err("configuration".into()),
        };
        let timeout = Duration::from_millis(
            o["operationTimeoutMS"]
                .as_u64()
                .filter(|v| *v > 0)
                .ok_or("invalid operation timeout")?,
        );
        let mut methods = parity::Registrations::default();
        for id in [7001, 7003, 7005] {
            methods.call(id, Method).map_err(err)?
        }
        methods.notification(7002, Method).map_err(err)?;
        let methods = methods.finish().map_err(err)?;
        let limit = NonZeroU16::new(2).unwrap();
        let options = ConnectorOptions::new()
            .with_rpc_concurrency(limit)
            .with_connect_timeout(timeout)
            .map_err(err)?
            .with_rpc_handlers(methods.clone());
        let options = if overlap.is_some() {
            options.with_rpc_frame_limit(business::frame_limit())
        } else {
            options
        };
        let spent = PathBuf::from(
            o["storeDirectory"]
                .as_str()
                .ok_or("missing spend directory")?,
        );
        if !spent.is_absolute() || !spent.is_dir() {
            return Err("missing private spend directory".into());
        }
        let stop = CancellationToken::new();
        let (transport, options, invitations, serving, reply) = if !o["serverCarrier"].is_null() {
            if o["serverCarrier"] != "raw-quic" {
                return Err("requires two raw QUIC Tunnel legs".into());
            }
            let (legs, options, invitations, reply) = tunnel::initialize(options)?;
            (Transport::Tunnel(legs), options, invitations, None, reply)
        } else {
            let cert = std::fs::read(path("FLOWERSEC_V5_CERT_DER")?).map_err(err)?;
            let root = std::fs::read(path("FLOWERSEC_V5_CA_DER")?).map_err(err)?;
            let mut chain = vec![cert];
            if chain[0] != root {
                chain.push(root.clone());
            }
            let b = Acceptor::bind(AcceptorOptions {
                bind_address: "127.0.0.1:0".parse().unwrap(),
                certificate_chain_der: chain,
                private_key_der: std::fs::read(path("FLOWERSEC_V5_KEY_DER")?).map_err(err)?,
                max_inbound_streams: 32,
                accept_timeout: timeout,
            })
            .map_err(err)?
            .with_rpc_concurrency(limit);
            let address = b.local_address().map_err(err)?;
            let b = if overlap.is_some() {
                b.with_rpc_frame_limit(business::frame_limit())
            } else {
                b
            };
            let options = options.with_trust_roots_der(vec![root]).map_err(err)?;
            let mut handlers = SessionHandlers::new(SessionHandlerOptions::default())
                .map_err(err)?
                .with_rpc_handlers(methods);
            if overlap.is_some() {
                handlers
                    .handle_stream(business::DIRECT, business::Server)
                    .map_err(err)?;
            }
            let store = Arc::new(Store {
                approvals: ApprovalStore {
                    directory: path("FLOWERSEC_V5_APPROVAL_DIR")?,
                    handlers: DirectHandlers::new(handlers),
                    call_large_echo: false,
                },
                pending: Mutex::new(HashMap::new()),
            });
            let invitations = path("FLOWERSEC_V5_INVITATION_DIR")?;
            if !store.approvals.directory.is_dir() || !invitations.is_dir() {
                return Err("missing private run directories".into());
            }
            let serving = tokio::spawn(b.serve(
                store.clone(),
                NonZeroUsize::new(COUNT + if overlap.is_some() { SUCCESSORS } else { 0 }).unwrap(),
                stop.clone(),
            ));
            (
                Transport::Direct(store),
                options,
                invitations,
                Some(serving),
                json!({"endpointAddress":address.to_string()}),
            )
        };
        Ok((
            Self {
                options,
                invitations,
                spent,
                transport,
                live: Mutex::default(),
                closing: Mutex::default(),
                replacement,
                overlap,
                used: Mutex::default(),
                stop,
                serving: Mutex::new(serving),
                events,
                prepared: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                completed: AtomicUsize::new(0),
            },
            reply,
        ))
    }

    async fn connect(&self, index: usize, token: CancellationToken) -> Result<Value> {
        if index >= COUNT
            || !self.prepared.load(Ordering::Acquire)
            || !self.used.lock().unwrap().insert(index)
        {
            return Err("invalid or already consumed position".into());
        }
        self.establish(format!("p{index}"), 1, token).await
    }

    async fn replace(&self, q: &Value, token: CancellationToken, tunnel: bool) -> Result<Value> {
        let index = number(q, "index")?;
        let generation = number(q, "generation")?;
        if !self.replacement
            || matches!(self.transport, Transport::Tunnel(_)) != tunnel
            || index >= COUNT
            || generation < 2
        {
            return Err("configuration".into());
        }
        let previous = generation - 1;
        let old = if previous == 1 {
            format!("p{index}")
        } else {
            format!("p{index}-g{previous}")
        };
        let next = format!("p{index}-g{generation}");
        if q["session"] != old || q["expectedSession"] != next {
            return Err("configuration".into());
        }
        {
            let mut closing = self.closing.lock().unwrap();
            let receipt = closing.get(&old).ok_or("configuration")?;
            if receipt.borrow().as_ref() != Some(&Ok(previous)) {
                return Err("configuration".into());
            }
            closing.remove(&old);
        }
        self.establish(next, generation, token).await
    }

    async fn connect_successor(&self, q: &Value, token: CancellationToken) -> Result<Value> {
        let slots = self.overlap.as_ref().ok_or("configuration")?;
        let index = number(q, "index")?;
        let old = format!("p{index}");
        let next = format!("{old}-g2");
        if index >= COUNT || q["session"] != old || q["expectedSession"] != next {
            return Err("configuration".into());
        }
        {
            let live = self.live.lock().unwrap();
            let mut slots = slots.lock().unwrap();
            let pair = live.get(&old).ok_or("configuration")?;
            if slots.len() >= SUCCESSORS
                || live.len() != COUNT + slots.len()
                || pair.generation != 1
                || pair.down.iter().any(|end| end.load(Ordering::Acquire))
                || !slots.insert(index)
            {
                return Err("configuration".into());
            }
        }
        // An interrupted admission may already have consumed its invitation.
        // Keep the reservation until this installation is torn down.
        self.establish(next, 2, token).await
    }

    async fn establish(
        &self,
        id: String,
        generation: usize,
        token: CancellationToken,
    ) -> Result<Value> {
        let (a, b, credential) = match &self.transport {
            Transport::Tunnel(legs) => legs.connect(self, &id, &token).await?,
            Transport::Direct(store) => self.direct(store, &id, &token).await?,
        };
        let result = tokio::select! { r=exercise(&id,&a,&b,matches!(self.transport, Transport::Tunnel(_)))=>r,_=token.cancelled()=>Err("application setup canceled".into()) };
        let (subscriptions, client_binding, server_binding) =
            match result.and_then(|subscriptions| {
                let client = a
                    .admission_binding()
                    .ok_or("client admission binding unavailable")?;
                let server = b
                    .admission_binding()
                    .ok_or("server admission binding unavailable")?;
                if matches!(self.transport, Transport::Direct(_)) != (client == server) {
                    return Err("unexpected authenticated leg binding relationship".into());
                }
                Ok((subscriptions, client, server))
            }) {
                Ok(out) => out,
                Err(e) => {
                    let _ = tokio::join!(a.close(), b.close());
                    return Err(e);
                }
            };
        self.record_pair(
            id,
            generation,
            [a, b],
            subscriptions,
            credential,
            [client_binding, server_binding],
        )
    }

    async fn direct(
        &self,
        store: &Store,
        id: &str,
        token: &CancellationToken,
    ) -> Result<(End, End, String)> {
        let input = self.invitations.join(format!("{id}.json"));
        let spend = self.spent.join(format!("{id}.spent"));
        let bytes = tokio::task::spawn_blocking(move || super::listener::read_approval(&input))
            .await
            .map_err(err)?
            .map_err(err)?;
        let artifact = Artifact::parse(bytes).map_err(err)?;
        let credential = artifact.credential_lookup_key();
        let (tx, rx) = oneshot::channel();
        store.pending.lock().unwrap().insert(id.to_owned(), tx);
        let lease = ArtifactLease::new(artifact, move || super::write_spend_receipt(spend));
        let a = match connect_with_cancellation(lease, self.options.clone(), token.clone()).await {
            Ok(s) => s,
            Err(e) => {
                store.pending.lock().unwrap().remove(id);
                return Err(err(e));
            }
        };
        let b = tokio::select! {r=rx=>r.map_err(|_|"server accept ended".to_string()),_=token.cancelled()=>Err("server accept canceled".into()),_=a.wait_termination()=>Err("client terminated before accept".into())};
        let b = match b {
            Ok(s) => s,
            Err(e) => {
                store.pending.lock().unwrap().remove(id);
                let _ = a.close().await;
                return Err(e);
            }
        };
        Ok((a, b, credential))
    }

    fn record_pair(
        &self,
        id: String,
        generation: usize,
        [a, b]: [End; 2],
        subscriptions: [Binding; 2],
        credential: String,
        [client_binding, server_binding]: [[u8; 32]; 2],
    ) -> Result<Value> {
        let down = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let first_loss = (self.replacement
            || self.overlap.is_some()
            || matches!(self.transport, Transport::Tunnel(_)))
        .then(|| Arc::new(AtomicBool::new(false)));
        let watchers = [(0, a.clone()), (1, b.clone())].map(|(i, s)| {
            let down = down[i].clone();
            let first_loss = first_loss.clone();
            let id = id.clone();
            let events = self.events.clone();
            tokio::spawn(async move {
                s.wait_termination().await;
                down.store(true, Ordering::Release);
                if first_loss
                    .as_ref()
                    .map_or(i == 0, |sent| !sent.swap(true, Ordering::AcqRel))
                {
                    let _ = events
                        .send(json!({"event":"terminated","session":id}))
                        .await;
                }
            })
        });
        let mut live = self.live.lock().unwrap();
        live.insert(
            id.clone(),
            Pair {
                generation,
                a,
                b,
                _subscriptions: subscriptions,
                watchers,
                down,
            },
        );
        self.completed.fetch_add(1, Ordering::Release);
        Ok(
            json!({"id":id,"generation":generation,"lookupKey":credential,"verifiedContractsPerEndpoint":4,"admissionProfile":"flowersec/5","clientAdmission":STANDARD.encode(client_binding),"serverAdmission":STANDARD.encode(server_binding)}),
        )
    }
    fn snapshot(&self) -> Result<Value> {
        let live = self.live.lock().unwrap();
        let ends = [0, 1].map(|i| {
            live.values()
                .filter(|p| !p.down[i].load(Ordering::Acquire))
                .count()
        });
        let (active, retained) = live
            .values()
            .flat_map(|p| [&p.a, &p.b])
            .try_fold((0usize, 0usize), |(a, b), s| {
                s.business_stream_counts().map(|(x, y)| (a + x, b + y))
            })
            .ok_or("application stream observation unavailable")?;
        Ok(
            json!({"positions":COUNT,"acquired":self.used.lock().unwrap().len(),"bound":live.len(),"liveEnds":ends,"activeSessions":ends[0],"activeStreams":active,"residualStreams":retained,"terminated":self.completed.load(Ordering::Acquire)-ends[0],"closed":self.closed.load(Ordering::Acquire)}),
        )
    }
    async fn close_pair(&self, id: &str) -> Result<usize> {
        let mut outcome = {
            let mut closing = self.closing.lock().unwrap();
            if let Some(outcome) = closing.get(id) {
                outcome.clone()
            } else {
                let pair = self
                    .live
                    .lock()
                    .unwrap()
                    .remove(id)
                    .ok_or(if self.replacement {
                        "configuration"
                    } else {
                        "unknown live session"
                    })?;
                let (sender, outcome) = watch::channel(None);
                closing.insert(id.to_owned(), outcome.clone());
                tokio::spawn(async move {
                    let generation = pair.generation;
                    sender.send_replace(Some(Self::finish_pair(pair).await.map(|()| generation)));
                });
                outcome
            }
        };
        let generation = outcome
            .wait_for(Option::is_some)
            .await
            .map_err(|_| "pair close task ended without a result")?
            .as_ref().unwrap().clone()?;
        #[cfg(unix)]
        if let Transport::Direct(store) = &self.transport {
            let approved = store.approvals.directory.join(format!("{id}.json"));
            tokio::task::spawn_blocking(move || -> Result<()> {
                use std::os::unix::fs::MetadataExt;
                let spent = std::fs::symlink_metadata(approved.with_extension("spent")).map_err(err)?;
                let released = std::fs::symlink_metadata(approved.with_extension("released")).map_err(err)?;
                if !spent.is_file() || !released.is_file() || (spent.dev(), spent.ino()) != (released.dev(), released.ino()) {
                    return Err("direct release did not retain its consumed authorization".into());
                }
                Ok(())
            }).await.map_err(err)??;
        }
        Ok(generation)
    }

    async fn finish_pair(pair: Pair) -> Result<()> {
        let (a, b) = tokio::join!(pair.a.close(), pair.b.close());
        let [first, second] = pair.watchers;
        let (first, second) = tokio::join!(first, second);
        match (a, b) {
            (Err(a), Err(b)) => {
                return Err(format!("endpoint A close: {a}; endpoint B close: {b}"));
            }
            (Err(e), _) => return Err(format!("endpoint A close: {e}")),
            (_, Err(e)) => return Err(format!("endpoint B close: {e}")),
            _ => (),
        }
        first.map_err(err)?;
        second.map_err(err)?;
        if [&pair.a, &pair.b]
            .into_iter()
            .any(|end| end.business_stream_counts() != Some((0, 0)))
        {
            return Err("endpoint retained a business stream after shutdown".into());
        }
        Ok(())
    }
    async fn close(&self) -> Result<()> {
        let ids = {
            let closing = self.closing.lock().unwrap();
            let live = self.live.lock().unwrap();
            closing
                .keys()
                .chain(live.keys())
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut failures = Vec::new();
        for id in ids {
            if let Err(e) = self.close_pair(&id).await {
                failures.push(e)
            }
        }
        self.stop.cancel();
        let task = self.serving.lock().unwrap().take();
        if let Some(task) = task {
            task.await.map_err(err)?.map_err(err)?
        }
        self.closed.store(true, Ordering::Release);
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

async fn exercise(id: &str, a: &End, b: &End, tunnel: bool) -> Result<[Binding; 2]> {
    let subscribe = |s: &End| {
        let (tx, rx) = mpsc::channel(2);
        let sub = s
            .rpc()
            .subscribe_notification(
                7002,
                Arc::new(move |v| {
                    let _ = tx.try_send(v);
                }),
            )
            .map_err(err)?;
        Ok::<_, String>((sub, rx))
    };
    let (sa, mut ra) = subscribe(a)?;
    let (sb, mut rb) = subscribe(b)?;
    if tunnel {
        tokio::try_join!(parity::verify(a.as_ref()), parity::verify(b.as_ref())).map_err(err)?;
        return Ok([
            Binding {
                _subscription: sa,
                _receiver: Some(ra),
            },
            Binding {
                _subscription: sb,
                _receiver: Some(rb),
            },
        ]);
    }
    async fn direction(id: &str, side: &str, s: &dyn Session) -> Result<Value> {
        parity::verify(s).await.map_err(err)?;
        let value = json!({"channel":id,"from":side});
        for method in [7001, 7003, 7005] {
            if s.rpc().call(method, value.clone()).await.map_err(err)? != value {
                return Err("parity RPC payload differs".into());
            }
        }
        s.rpc().notify(7002, value.clone()).await.map_err(err)?;
        Ok(value)
    }
    let (sent_a, sent_b) = tokio::try_join!(
        direction(id, "A", a.as_ref()),
        direction(id, "B", b.as_ref())
    )?;
    if parity::wide_workload() {
        tokio::try_join!(
            parity::exercise_wide(a.as_ref()),
            parity::exercise_wide(b.as_ref())
        )
        .map_err(err)?;
    }
    if ra.recv().await != Some(sent_b) || rb.recv().await != Some(sent_a) {
        return Err("session notification crossed an endpoint or changed".into());
    }
    Ok([
        Binding {
            _subscription: sa,
            _receiver: None,
        },
        Binding {
            _subscription: sb,
            _receiver: None,
        },
    ])
}

async fn op(
    state: Arc<OnceLock<Installation>>,
    q: Value,
    token: CancellationToken,
    events: mpsc::Sender<Value>,
) -> Result<Value> {
    let op = q["op"].as_str().ok_or("missing operation")?;
    if op == "initialize" {
        let (s, v) = Installation::start(&q, events)?;
        state.set(s).map_err(|_| "duplicate initialization")?;
        return Ok(v);
    }
    let s = state.get().ok_or("not initialized")?;
    match op {
        "prepare" if number(&q, "count")? == COUNT && !s.prepared.swap(true, Ordering::AcqRel) => {
            Ok(json!({}))
        }
        "connect" => s.connect(number(&q, "index")?, token).await,
        "connect_successor" => s.connect_successor(&q, token).await,
        "business" if s.overlap.is_some() => business::run(s, &q, token).await,
        "replace_direct" | "replace_tunnel" => s.replace(&q, token, op == "replace_tunnel").await,
        "probe" => {
            let id = q["session"].as_str().ok_or("missing session")?;
            let (client, server, generation) = s
                .live
                .lock()
                .unwrap()
                .get(id)
                .map(|pair| {
                    (
                        pair.a.clone(),
                        (pair.generation > 1).then(|| pair.b.clone()),
                        pair.generation,
                    )
                })
                .ok_or(if s.replacement {
                    "configuration"
                } else {
                    "unknown session"
                })?;
            let probe = async {
                if let Some(server) = server {
                    tokio::try_join!(client.probe_liveness(), server.probe_liveness())
                        .map_err(err)?;
                    Ok(
                        json!({"id":id,"generation":generation,"complete":true,"outcome":"Responsive","responsiveEnds":2}),
                    )
                } else {
                    client.probe_liveness().await.map_err(err)?;
                    Ok(json!({"complete":true,"outcome":"Responsive"}))
                }
            };
            tokio::select! {r=probe=>r,_=token.cancelled()=>Err("probe canceled".into())}
        }
        "check_live" => {
            if (s.replacement || s.overlap.is_some())
                && let Some(session) = q.get("session")
            {
                let live = s.live.lock().unwrap();
                let pair = live
                    .get(session.as_str().ok_or("configuration")?)
                    .ok_or("configuration")?;
                if pair.down.iter().any(|end| end.load(Ordering::Acquire)) {
                    return Err("endpoint terminated".into());
                }
                return Ok(json!({"id":session,"generation":pair.generation,"liveEnds":[1,1]}));
            }
            let v = s.snapshot()?;
            let count = number(&q, "count")?;
            if v["liveEnds"] != json!([count, count]) || v["bound"] != count {
                return Err("live endpoint or binding count differs".into());
            }
            if matches!(s.transport, Transport::Tunnel(_)) {
                let live = s.live.lock().unwrap();
                let distinct: HashSet<_> = live
                    .values()
                    .flat_map(|p| [&p.a, &p.b])
                    .map(|end| Arc::as_ptr(end) as *const ())
                    .collect();
                if distinct.len() != 2 * count {
                    return Err("duplicate Tunnel session object".into());
                }
            }
            Ok(v)
        }
        "close_session" => {
            let id = q["session"].as_str().ok_or("missing session")?;
            let generation = s.close_pair(id).await?;
            if s.replacement || s.overlap.is_some() {
                Ok(json!({"id":id,"generation":generation,"closed":true}))
            } else {
                Ok(json!({}))
            }
        }
        "open_streams" if number(&q, "count")? == 0 => Ok(json!({})),
        "quiesce" => Ok(json!({})),
        "snapshot" => s.snapshot(),
        "close" => {
            s.close().await?;
            Ok(json!({}))
        }
        _ => Err("unsupported original capacity operation".into()),
    }
}

async fn next_frame(
    reader: &mut BufReader<tokio::io::Stdin>,
    pending: &mut Vec<u8>,
) -> Result<Option<Value>> {
    loop {
        let next = reader.fill_buf().await.map_err(err)?;
        if next.is_empty() {
            return if pending.is_empty() {
                Ok(None)
            } else {
                Err("truncated coordinator frame".into())
            };
        }
        let n = next
            .iter()
            .position(|c| *c == b'\n')
            .map_or(next.len(), |n| n + 1);
        if pending.len() + n > MAX_FRAME {
            return Err("oversized coordinator frame".into());
        }
        let done = next[n - 1] == b'\n';
        pending.extend_from_slice(&next[..n]);
        reader.consume(n);
        if done {
            let q = serde_json::from_slice(pending).map_err(err)?;
            pending.clear();
            return Ok(Some(q));
        }
    }
}

pub async fn run() -> Result<()> {
    let state = Arc::new(OnceLock::new());
    let (tx, mut rx) = mpsc::channel::<Value>(128);
    let output = tokio::spawn(async move {
        while let Some(v) = rx.recv().await {
            let mut buf = serde_json::to_vec(&v).map_err(io::Error::other)?;
            buf.push(b'\n');
            tokio::task::spawn_blocking(move || {
                let mut stdout = io::stdout().lock();
                stdout.write_all(&buf)?;
                stdout.flush()
            })
            .await??;
        }
        Ok::<_, io::Error>(())
    });
    let mut tasks = JoinSet::new();
    let mut active = HashMap::<u64, CancellationToken>::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut pending = Vec::new();
    let mut last = 0;
    let mut stopping = false;
    loop {
        tokio::select! {
            biased;
            result = tasks.join_next(), if !tasks.is_empty() => {
                let (id, close) = result.unwrap().map_err(err)?;
                active.remove(&id);
                if close {
                    if next_frame(&mut reader, &mut pending).await?.is_some() {
                        return Err("request after close".into());
                    }
                    break;
                }
            },
            r = next_frame(&mut reader, &mut pending) => {
                let Some(q) = r? else { break };
                if let Some(id) = q["cancel"].as_u64() {
                    if let Some(token) = active.get(&id) { token.cancel(); }
                    continue;
                }
                let id = q["id"].as_u64().filter(|value| *value > last)
                    .ok_or("invalid request id")?;
                last = id;
                let timeout = q["timeoutMS"].as_u64().filter(|value| (1..=86_400_000).contains(value))
                    .ok_or("invalid original operation deadline")?;
                let name = q["op"].as_str().ok_or("missing operation")?;
                let close = name == "close";
                if stopping && !matches!(name, "close" | "snapshot") {
                    return Err("request after quiesce".into());
                }
                if matches!(name, "quiesce" | "close") {
                    stopping = true;
                    for token in active.values() { token.cancel(); }
                    while let Some(result) = tasks.join_next().await { result.map_err(err)?; }
                    active.clear();
                }
                if active.len() >= COUNT + 16 {
                    return Err("original command concurrency exceeded".into());
                }
                let token = CancellationToken::new();
                active.insert(id, token.clone());
                let sender = tx.clone();
                let state = state.clone();
                let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout);
                tasks.spawn(async move {
                    let work = op(state, q, token.clone(), sender.clone());
                    tokio::pin!(work);
                    let result = tokio::select! {
                        result = &mut work => result,
                        _ = tokio::time::sleep_until(deadline) => {
                            token.cancel();
                            let _ = work.await;
                            Err("original capacity deadline".into())
                        }
                    };
                    let ok = result.is_ok();
                    let reply = match result {
                        Ok(value) => json!({"id":id,"result":value}),
                        Err(error) => json!({"id":id,"error":error}),
                    };
                    let _ = sender.send(reply).await;
                    (id, close && ok)
                });
            }
        }
    }
    for t in active.values() {
        t.cancel()
    }
    while let Some(r) = tasks.join_next().await {
        r.map_err(err)?;
    }
    if let Some(s) = state.get() {
        s.close().await?
    }
    drop(state);
    drop(tx);
    output.await.map_err(err)?.map_err(err)
}
