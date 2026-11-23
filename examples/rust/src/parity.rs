use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flowersec::{
    HandlerRegistrationError, NotificationHandler, RpcError, RpcHandler, RpcHandlers, Session,
};
use serde::Deserialize;
use serde_json::{Value, json};

pub const IDS: [u32; 4] = [7001, 7002, 7003, 7005];
pub const LARGE_ECHO_METHOD: u32 = 7010;
const WIDE_IDS: std::ops::Range<u32> = 8000..8256;

pub fn wide_workload() -> bool {
    std::env::var("FLOWERSEC_PARITY_WIDE_RPC").as_deref() == Ok("1")
}

#[derive(Deserialize)]
struct Declaration {
    namespace: String,
    query_type_id: u32,
    contracts: BTreeMap<u32, String>,
}

fn declaration() -> &'static Declaration {
    static DATA: OnceLock<Declaration> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../../parity-contracts.json"))
            .expect("valid parity declarations")
    })
}

/// Applications can atomically publish a current policy file; each dispatch
/// reads it again. Missing, oversized or malformed policies deny access.
#[derive(Clone)]
enum Authority {
    Session,
    File(Arc<PathBuf>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grants {
    execute: BTreeSet<u32>,
    disclose: BTreeSet<u32>,
}

impl Authority {
    fn configured() -> Self {
        std::env::var_os("FLOWERSEC_PARITY_POLICY_FILE")
            .map(|p| Self::File(Arc::new(p.into())))
            .unwrap_or(Self::Session)
    }
    async fn can_execute(&self, id: u32) -> Result<bool, RpcError> {
        match self {
            Self::Session => {
                Ok(IDS.contains(&id) || WIDE_IDS.contains(&id) || id == LARGE_ECHO_METHOD)
            }
            Self::File(_) => Ok(self.grants().await?.execute.contains(&id)),
        }
    }
    async fn grants(&self) -> Result<Grants, RpcError> {
        match self {
            Self::Session => Ok(Grants {
                execute: IDS.into(),
                disclose: IDS.into(),
            }),
            Self::File(path) => {
                let path = path.clone();
                tokio::task::spawn_blocking(move || {
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    std::fs::File::open(path.as_ref())
                        .ok()?
                        .take(4097)
                        .read_to_end(&mut bytes)
                        .ok()?;
                    if bytes.len() > 4096 {
                        return None;
                    }
                    serde_json::from_slice(&bytes).ok()
                })
                .await
                .ok()
                .flatten()
                .ok_or_else(denied)
            }
        }
    }
}

fn denied() -> RpcError {
    RpcError::new(403, Some("parity permission denied".into())).unwrap()
}

struct Unary<H>(Authority, H);
#[async_trait]
impl<H: RpcHandler> RpcHandler for Unary<H> {
    async fn call(&self, id: u32, payload: Value) -> Result<Value, RpcError> {
        if !self.0.can_execute(id).await? {
            return Err(denied());
        }
        self.1.call(id, payload).await
    }
    async fn notify(&self, _: u32, _: Value) -> Result<(), RpcError> {
        Err(denied())
    }
}

struct Notification<H>(Authority, H);
#[async_trait]
impl<H: NotificationHandler> NotificationHandler for Notification<H> {
    async fn handle_notification(&self, id: u32, payload: Value) -> Result<(), RpcError> {
        if !self.0.can_execute(id).await? {
            return Err(denied());
        }
        self.1.handle_notification(id, payload).await
    }
}

pub struct Registrations {
    handlers: RpcHandlers,
    installed: BTreeMap<u32, &'static str>,
    authority: Authority,
}

impl Default for Registrations {
    fn default() -> Self {
        Self {
            handlers: RpcHandlers::new(),
            installed: BTreeMap::new(),
            authority: Authority::configured(),
        }
    }
}

impl Registrations {
    pub fn call(
        &mut self,
        id: u32,
        handler: impl RpcHandler,
    ) -> Result<(), HandlerRegistrationError> {
        if id == LARGE_ECHO_METHOD {
            return self
                .handlers
                .handle_rpc(id, Unary(self.authority.clone(), handler));
        }
        if !matches!(id, 7001 | 7003 | 7005) {
            return Err(HandlerRegistrationError::Invalid);
        }
        let contract = declaration()
            .contracts
            .get(&id)
            .ok_or(HandlerRegistrationError::Invalid)?;
        self.handlers
            .handle_rpc(id, Unary(self.authority.clone(), handler))?;
        self.installed.insert(id, contract);
        Ok(())
    }

    pub fn notification(
        &mut self,
        id: u32,
        handler: impl NotificationHandler,
    ) -> Result<(), HandlerRegistrationError> {
        if id != 7002 {
            return Err(HandlerRegistrationError::Invalid);
        }
        let contract = declaration()
            .contracts
            .get(&id)
            .ok_or(HandlerRegistrationError::Invalid)?;
        self.handlers
            .handle_notification(id, Notification(self.authority.clone(), handler))?;
        self.installed.insert(id, contract);
        Ok(())
    }

    pub fn finish(mut self) -> Result<RpcHandlers, HandlerRegistrationError> {
        if wide_workload() {
            for id in WIDE_IDS {
                self.handlers
                    .handle_rpc(id, Unary(self.authority.clone(), WideEcho(id)))?;
            }
        }
        self.handlers.handle_rpc(
            declaration().query_type_id,
            Query(self.installed, self.authority),
        )?;
        Ok(self.handlers)
    }
}

struct WideEcho(u32);
#[async_trait]
impl RpcHandler for WideEcho {
    async fn call(&self, method: u32, payload: Value) -> Result<Value, RpcError> {
        if method != self.0 {
            return Err(denied());
        }
        Ok(json!({"method": self.0, "value": payload}))
    }
    async fn notify(&self, _: u32, _: Value) -> Result<(), RpcError> {
        Err(denied())
    }
}

pub async fn exercise_wide(
    session: &dyn Session,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::try_join!(verify(session), verify(session))?;
    for round in 0..2 {
        let call = |id| async move {
            let result = session.rpc().call(id, json!(round)).await?;
            if result != json!({"method":id,"value":round}) {
                return Err("incorrect method response".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        for first in WIDE_IDS.step_by(2) {
            tokio::try_join!(call(first), call(first + 1))?;
        }
    }
    Ok(())
}

struct Query(BTreeMap<u32, &'static str>, Authority);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    namespace: String,
    type_ids: Vec<u32>,
}

#[async_trait]
impl RpcHandler for Query {
    async fn call(&self, _: u32, request: Value) -> Result<Value, RpcError> {
        let invalid = || RpcError::new(400, Some("invalid parity query".into())).unwrap();
        let unavailable = || RpcError::new(404, Some("contract unavailable".into())).unwrap();
        let request: Request = serde_json::from_value(request).map_err(|_| invalid())?;
        if request.namespace != declaration().namespace {
            return Err(unavailable());
        }
        if request.type_ids.is_empty() || request.type_ids.len() > IDS.len() {
            return Err(invalid());
        }
        let grants = self.1.grants().await?;
        if !request
            .type_ids
            .iter()
            .all(|id| grants.disclose.contains(id))
        {
            return Err(unavailable());
        }
        let contracts = request
            .type_ids
            .iter()
            .map(|id| self.0.get(id).copied().ok_or_else(unavailable))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({"contracts": contracts}))
    }

    async fn notify(&self, _: u32, _: Value) -> Result<(), RpcError> {
        Err(RpcError::new(400, Some("query requires a response".into())).unwrap())
    }
}

pub async fn verify(session: &dyn Session) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        contracts: Vec<String>,
    }
    let expected = declaration();
    let reply = session
        .rpc()
        .call(
            expected.query_type_id,
            json!({"namespace": expected.namespace, "type_ids": IDS}),
        )
        .await?;
    let reply: Reply = serde_json::from_value(reply)?;
    if reply.contracts.len() != IDS.len() {
        return Err("incomplete parity response".into());
    }
    for (id, contract) in IDS.into_iter().zip(reply.contracts) {
        if STANDARD.decode(contract)? != STANDARD.decode(&expected.contracts[&id])? {
            return Err("parity contract mismatch".into());
        }
    }
    Ok(())
}
