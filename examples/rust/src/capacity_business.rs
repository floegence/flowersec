use super::{Installation, Result, Transport, err, number};
use async_trait::async_trait;
use bytes::Bytes;
use flowersec::{
    ByteStream, IncomingStream, RpcFrameLimit, SessionError, StreamHandler, StreamMetadata,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

pub(super) const DIRECT: &str = "public-release-roundtrip";
const TUNNEL: &str = "release-tunnel-bulk";
const LARGE: usize = 1 << 20;
pub(super) fn frame_limit() -> RpcFrameLimit {
    // The full 1 MiB ASCII payload plus the public RPC record envelope.
    RpcFrameLimit::new(LARGE + 256).unwrap()
}

async fn respond(
    incoming: &IncomingStream,
    kind: &str,
) -> std::result::Result<usize, SessionError> {
    if incoming.kind() != kind
        || incoming.metadata().values().get("direction") != Some(&json!("client-to-server"))
    {
        return Err(SessionError::OperationFailed);
    }
    let stream = incoming.stream();
    let mut n = 0usize;
    while let Some(part) = stream.read().await? {
        if part.len() > LARGE - n || part.iter().any(|&byte| byte != 0x5a) {
            return Err(SessionError::OperationFailed);
        }
        n += part.len();
    }
    if !matches!(n, 256 | LARGE) {
        return Err(SessionError::OperationFailed);
    }
    crate::write_all(stream, Bytes::from(vec![0x37; n])).await?;
    Ok(n)
}

pub(super) struct Server;
#[async_trait]
impl StreamHandler for Server {
    async fn handle(
        &self,
        incoming: &IncomingStream,
        token: CancellationToken,
    ) -> std::result::Result<(), SessionError> {
        // SessionHandlers sends FIN after a successful handler and resets on failure.
        token
            .run_until_cancelled(respond(incoming, DIRECT))
            .await
            .ok_or(SessionError::Canceled)??;
        Ok(())
    }
}

async fn send(stream: &dyn ByteStream, n: usize) -> std::result::Result<(), SessionError> {
    crate::write_all(stream, Bytes::from(vec![0x5a; n])).await?;
    stream.close_write().await?;
    crate::read_exact_message(stream, &vec![0x37; n]).await
}

pub(super) async fn run(s: &Installation, q: &Value, token: CancellationToken) -> Result<Value> {
    let id = q["session"].as_str().ok_or("missing session")?;
    let op = q["operation"].as_str().ok_or("missing operation")?;
    let n = number(q, "bytes")?;
    if !matches!(n, 256 | LARGE) {
        return Err("invalid capacity business size".into());
    }
    let (a, b) = {
        let live = s.live.lock().unwrap();
        let p = live
            .get(id)
            .filter(|p| p.generation == 1)
            .ok_or("unknown original session")?;
        (p.a.clone(), p.b.clone())
    };
    let tunnel = matches!(s.transport, Transport::Tunnel(_));
    let kind = if tunnel { TUNNEL } else { DIRECT };
    let actual = match op {
        "echo" => {
            let request = json!({"payload":"Z".repeat(n)});
            let got = token
                .run_until_cancelled(a.rpc().call(7001, request.clone()))
                .await
                .ok_or("echo canceled")?
                .map_err(err)?;
            if got != request {
                return Err("remote RPC echo payload differs".into());
            }
            got["payload"].as_str().unwrap().len()
        }
        "raw" => {
            let client = async {
                let metadata = StreamMetadata::try_from(json!({"direction":"client-to-server"}))
                    .map_err(err)?;
                let stream = token
                    .run_until_cancelled(a.open_stream(kind, metadata))
                    .await
                    .ok_or("raw open canceled")?
                    .map_err(err)?;
                let result = token
                    .run_until_cancelled(send(stream.as_ref(), n))
                    .await
                    .ok_or_else(|| "raw client canceled".to_owned())
                    .and_then(|r| r.map_err(err));
                if result.is_err() {
                    let _ = stream.reset().await;
                }
                result
            };
            let server = async {
                if !tunnel {
                    return Ok(());
                }
                let incoming = token
                    .run_until_cancelled(b.accept_stream())
                    .await
                    .ok_or("raw accept canceled")?
                    .map_err(err)?;
                let work = async {
                    let got = respond(&incoming, kind).await?;
                    if got != n {
                        return Err(SessionError::OperationFailed);
                    };
                    incoming.stream().close_write().await
                };
                let result = token
                    .run_until_cancelled(work)
                    .await
                    .ok_or_else(|| "raw server canceled".to_owned())
                    .and_then(|r| r.map_err(err));
                if result.is_err() {
                    let _ = incoming.stream().reset().await;
                }
                result
            };
            let (left, right) = tokio::join!(
                async {
                    let r = client.await;
                    if r.is_err() {
                        token.cancel()
                    };
                    r
                },
                async {
                    let r = server.await;
                    if r.is_err() {
                        token.cancel()
                    };
                    r
                }
            );
            left?;
            right?;
            n
        }
        _ => return Err("invalid capacity operation".into()),
    };
    Ok(
        json!({"id":id,"generation":1,"operation":op,"requestBytes":n,"responseBytes":actual,"verified":true}),
    )
}
