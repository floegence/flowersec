use super::parity::LARGE_ECHO_METHOD;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flowersec::{RpcCallError, RpcError, RpcHandler, Session, SessionError};
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const SIZE: usize = 32 * 1024 * 1024;
const ENCODED: usize = SIZE.div_ceil(3) * 4;
// Request and response have the same overhead: at most one nonzero 53-bit ID.
pub const MIN_FRAME_BYTES: usize = ENCODED
    + br#"{"type_id":7010,"request_id":9007199254740991,"response_to":0,"payload":""}"#.len();

pub const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Call,
    Serve,
}

impl Role {
    pub fn configured(default: Self) -> Result<Option<Self>, &'static str> {
        use std::env::{VarError, var};
        let role = match var("FSEC_EXAMPLE_LARGE_RPC").as_deref() {
            Err(VarError::NotPresent) | Ok("0") => return Ok(None),
            Ok("1") => default,
            Ok("call") => Self::Call,
            Ok("serve") => Self::Serve,
            _ => return Err("FSEC_EXAMPLE_LARGE_RPC must be 0, 1, call, or serve"),
        };
        if role != default && super::parity::wide_workload() {
            return Err("the bilateral wide RPC workflow requires the default endpoint roles");
        }
        Ok(Some(role))
    }
}

fn byte_at(offset: usize) -> u8 {
    (offset ^ (offset >> 8) ^ (offset >> 16)) as u8
}

fn valid(value: &Value, check_bytes: bool) -> bool {
    let Some(text) = value.as_str().filter(|text| text.len() == ENCODED) else {
        return false;
    };
    let mut decoded = [0u8; 3072];
    let mut offset = 0;
    for encoded in text.as_bytes().chunks(4096) {
        let Ok(count) = STANDARD.decode_slice(encoded, &mut decoded) else {
            return false;
        };
        if count != (SIZE - offset).min(decoded.len())
            || check_bytes
                && decoded[..count]
                    .iter()
                    .enumerate()
                    .any(|(index, &byte)| byte != byte_at(offset + index))
        {
            return false;
        }
        offset += count;
    }
    offset == SIZE
}

#[derive(Default)]
pub struct BinaryEcho {
    accepted: Option<Arc<AtomicBool>>,
}

impl BinaryEcho {
    pub fn observed(accepted: Arc<AtomicBool>) -> Self {
        Self {
            accepted: Some(accepted),
        }
    }
}

#[async_trait]
impl RpcHandler for BinaryEcho {
    async fn call(&self, _: u32, request: Value) -> Result<Value, RpcError> {
        if !valid(&request, false) {
            return Err(RpcError::new(400, Some("invalid binary payload".into())).unwrap());
        }
        if let Some(accepted) = &self.accepted {
            accepted.store(true, Ordering::Release);
        }
        Ok(request)
    }
    async fn notify(&self, _: u32, _: Value) -> Result<(), RpcError> {
        Err(RpcError::new(400, Some("binary echo requires a reply".into())).unwrap())
    }
}

pub async fn call(session: &dyn Session) -> Result<(), RpcCallError> {
    let data: Vec<u8> = (0..SIZE).map(byte_at).collect();
    let request = Value::String(STANDARD.encode(data));
    let reply = tokio::time::timeout(TIMEOUT, session.rpc().call(LARGE_ECHO_METHOD, request))
        .await
        .map_err(|_| SessionError::Timeout)??;
    if !valid(&reply, true) {
        return Err(SessionError::OperationFailed.into());
    }
    Ok(())
}
