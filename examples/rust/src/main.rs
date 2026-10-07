//! Runnable public SDK consumer for the explicitly selected acceptance host.
mod engineering_material;
use bytes::Bytes;
use engineering_material::EngineeringClient;
use flowersec::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Clone)]
struct ValueCodec(MessageDefinition);
impl MessageCodec<Value> for ValueCodec {
    fn definition(&self) -> &MessageDefinition {
        &self.0
    }
    fn encode(
        &self,
        value: &Value,
        destination: &mut [u8],
    ) -> std::result::Result<usize, ServiceError> {
        let encoded =
            serde_json::to_vec(value).map_err(|_| ServiceError(ServiceFailure::EncodeFailed))?;
        if encoded.len() > destination.len() {
            return Err(ServiceError(ServiceFailure::EncodeFailed));
        }
        destination[..encoded.len()].copy_from_slice(&encoded);
        Ok(encoded.len())
    }
    fn decode(&self, source: &[u8]) -> std::result::Result<Value, ServiceError> {
        if source.len() > 4096 {
            return Err(ServiceError(ServiceFailure::DecodeFailed));
        }
        let value: Value = serde_json::from_slice(source)
            .map_err(|_| ServiceError(ServiceFailure::DecodeFailed))?;
        if value.as_object().is_none_or(|object| {
            object.len() != 1 || object.get("value").is_none_or(|value| !value.is_string())
        }) {
            return Err(ServiceError(ServiceFailure::DecodeFailed));
        }
        Ok(value)
    }
    fn application_bytes(&self) -> u64 {
        8192
    }
}
fn method(
    id: u32,
    shape: ServiceShape,
    message: &MessageDefinition,
) -> std::result::Result<MethodDefinition, ServiceError> {
    MethodDefinition::new(MethodDefinitionOptions {
        type_id: id,
        shape,
        semantics: if shape == ServiceShape::Notify {
            ServiceSemantics::Observation
        } else {
            ServiceSemantics::Transient
        },
        request: message.clone(),
        response: if shape == ServiceShape::Notify {
            None
        } else {
            Some(message.clone())
        },
        response_revision: "1".into(),
        request_max_bytes: 4096,
        min_response_limit_bytes: 0,
        max_response_bytes: if shape == ServiceShape::Notify {
            0
        } else {
            4096
        },
        require_durable: false,
        checkpoint_format: None,
        restart_flush_deadline_ms: None,
        streaming: None,
        content: None,
        errors: Vec::new(),
    })
}
#[derive(Default)]
struct ExchangeOwners {
    service: Option<ServiceClient>,
    peer: Option<ServicePeer>,
    notifications: Option<NotificationPeer>,
    rpc: Option<UnaryOperation<Value>>,
    notify: Option<NotificationOperation>,
    stream: Option<Stream>,
}
impl ExchangeOwners {
    fn close(&self) {
        if let Some(rpc) = &self.rpc {
            rpc.close();
        }
        if let Some(notify) = &self.notify {
            notify.close();
        }
        if let Some(service) = &self.service {
            service.close();
        }
        if let Some(peer) = &self.peer {
            peer.close();
        }
        if let Some(notifications) = &self.notifications {
            notifications.close();
        }
    }
    async fn cleanup(&self, failed: bool) -> bool {
        self.close();
        if failed {
            if let Some(stream) = &self.stream {
                let _ = stream.reset().await;
            }
        }
        let timeout = Duration::from_secs(5);
        let mut complete = true;
        if let Some(rpc) = &self.rpc {
            complete &= rpc.wait_cleanup().await.complete;
        }
        if let Some(notify) = &self.notify {
            complete &= notify.wait_cleanup(timeout).await.complete;
        }
        if let Some(service) = &self.service {
            complete &= service.wait_cleanup().await.complete;
        }
        if let Some(peer) = &self.peer {
            complete &= peer.wait_cleanup().await.complete;
        }
        if let Some(notifications) = &self.notifications {
            complete &= notifications.wait_cleanup(timeout).await.complete;
        }
        if let Some(stream) = &self.stream {
            complete &= tokio::time::timeout(timeout, stream.wait_cleanup())
                .await
                .is_ok_and(|status| status.complete);
        }
        complete
    }
}
impl Drop for ExchangeOwners {
    fn drop(&mut self) {
        self.close();
    }
}
async fn exchange(session: &Session) -> Result<()> {
    let mut owners = ExchangeOwners::default();
    let outcome: Result<()> = async {
    let schema = br#"{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"type":"object"}"#;
    let message = MessageDefinition::new(Sha256::digest(schema).into(), "1".into(), 4096)?;
    let codec = Arc::new(ValueCodec(message.clone()));
    let echo = method(7001, ServiceShape::Unary, &message)?;
    let notification = method(7002, ServiceShape::Notify, &message)?;
    let definition = ServiceDefinition::new("flowersec.parity".into(), vec![
        ServiceMethod { name: "Echo".into(), export_name: "echo".into(), method: echo.clone() },
        ServiceMethod { name: "Publish".into(), export_name: "publish".into(), method: notification.clone() },
    ])?;
    let mut digest = [0; 32]; digest[0] = 9;
    let peer = session.services(FixedContractQuery { type_id: 7, contract_digest: digest }, Vec::new())?;
    owners.peer = Some(peer.clone());
    let options = [echo.clone(), notification.clone()].into_iter().map(|method| ServiceBindingOptions {
        method, acceptance: ContractAcceptance::exact(), response_limit: ResponseLimitPolicy::FollowContractMaximum,
        execution_reference_identity: None, streaming: None, resume: None,
    }).collect();
    let service = peer.bind(definition, options, Duration::from_secs(10), CancellationToken::new()).await?;
    owners.service = Some(service.clone());
    let request = json!({ "value": "ping" });
    let rpc = service.prepare_unary(&echo, &request, codec.clone(), codec.clone(), UnaryPrepareOptions {
        timeout: Duration::from_secs(10), response_limit_bytes: Some(4096), ..UnaryPrepareOptions::default()
    })?;
    owners.rpc = Some(rpc.clone());
    rpc.start()?;
    let response = rpc.wait_typed(CancellationToken::new()).await?;
    if !matches!(response.value, TypedUnaryValue::Response(value) if value == request) {
        return Err(std::io::Error::other("unexpected typed RPC response").into());
    }
    let notifications = session.notifications(Vec::new())?;
    owners.notifications = Some(notifications.clone());
    let notify = service.prepare_notification(&notifications, &notification, Arc::new(json!({ "value": "notify" })), codec,
        NotificationPrepareOptions { timeout: Duration::from_secs(10), ..NotificationPrepareOptions::default() }, CancellationToken::new()).await?;
    owners.notify = Some(notify.clone());
    notify.start()?; let publication = notify.wait_submission(&CancellationToken::new()).await?;
    if publication.publication != ServicePublication::Committed || publication.error.is_some()
        || !publication.submitted || publication.accepted_bytes != publication.requested_bytes {
        return Err(std::io::Error::other("notification publication did not commit").into());
    }
    let cell = std::env::var("FSEC_EXAMPLE_STREAM_CELL").unwrap_or_else(|_| "direct".into());
    let metadata = Metadata::new("flowersec.parity", 1, &BTreeMap::from([("cell".into(), Bytes::from(cell))]))?;
    let stream = session.open_stream("parity.echo", metadata, 65536).await?;
    owners.stream = Some(stream.clone());
    let mut pending = Bytes::from_static(b"hello");
    while !pending.is_empty() {
        let accepted = stream.write(pending.clone()).await?;
        if accepted == 0 || accepted > pending.len() { return Err(std::io::Error::other("incomplete Stream write").into()); }
        pending = pending.slice(accepted..);
    }
    stream.close_write().await?;
    let mut response = Vec::new();
    loop {
        let result = stream.read_result(4096).await?;
        if response.len() + result.data.len() > 65536 { return Err(std::io::Error::other("Stream response exceeds bound").into()); }
        if result.error.is_some() || matches!(result.stream_status, ReadStreamStatus::Aborted | ReadStreamStatus::Error) {
            return Err(std::io::Error::other("reliable Stream read failed").into());
        }
        response.extend_from_slice(&result.data);
        if result.stream_status == ReadStreamStatus::Eof { break; }
    }
    if response != b"world" { return Err(std::io::Error::other("unexpected Stream response").into()); }
    stream.finish().await?;
    let probe = session.probe_liveness(Duration::from_secs(5)).await?;
    if !probe.complete || !probe.submitted || probe.outcome != ProbeOutcome::Responsive {
        return Err(std::io::Error::other("Session liveness probe did not confirm responsiveness").into());
    }
    println!("session=ready\nrpc=ok notification=ok stream=ok liveness_ms={}", probe.elapsed.map_or(0, |elapsed| elapsed.as_millis()));
    Ok(())
    }.await;
    let complete = owners.cleanup(outcome.is_err()).await;
    if !complete {
        eprintln!("application_cleanup_incomplete");
        if outcome.is_ok() {
            return Err(std::io::Error::other("application cleanup remains incomplete").into());
        }
    }
    outcome
}
#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.len() != 5 || arguments[1] != "connect" {
        return Err(std::io::Error::other(
            "usage: flowersec-rust-client-example connect MATERIAL_JSON TRUST_DER SPEND_RECEIPT",
        )
        .into());
    }
    let client = EngineeringClient::open(
        Path::new(&arguments[2]),
        Path::new(&arguments[3]),
        Path::new(&arguments[4]),
    )
    .await?;
    let outcome = async {
        let session = client.connect().await?;
        // SQLite's original consume COMMIT precedes this READY delivery. This
        // receipt projects that fact and grants no connection or replay rights.
        let result = async {
            client.commit_spend_receipt(Path::new(&arguments[4]))?;
            exchange(&session).await
        }
        .await
        .map_err(|error| {
            eprintln!("session_error={error}");
            error
        });
        session.close();
        let cleanup = session.wait_cleanup().await;
        drop(session);
        if !cleanup.complete || cleanup.cleanup_incomplete {
            eprintln!(
                "session_cleanup_incomplete pending_callbacks={}",
                cleanup.pending_callbacks
            );
            if result.is_ok() {
                return Err(std::io::Error::other("Session cleanup remains incomplete").into());
            }
        }
        result
    }
    .await;
    let cleanup = client.close().await;
    if let Err(error) = &cleanup {
        eprintln!("environment_cleanup_error={error}");
    }
    outcome.and(cleanup)
}
