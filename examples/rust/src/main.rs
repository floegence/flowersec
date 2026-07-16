use flowersec::{
    ConnectOptions, connect,
    controlplane::client::{ConnectArtifactRequestConfig, request_connect_artifact},
    proxy::{ContractOptions, HttpRequest, ProxyClient, WebSocketFrame, WebSocketOp},
    transport_security::TransportSecurityPolicy,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

#[derive(Serialize)]
struct PingRequest {}

#[derive(Deserialize)]
struct PingResponse {
    ok: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = required("FSEC_CONTROLPLANE_BASE_URL")?;
    let endpoint_id = std::env::var("FSEC_ENDPOINT_ID").unwrap_or_else(|_| "server-1".to_owned());
    let mut request = ConnectArtifactRequestConfig::new(endpoint_id);
    request.base_url = base_url;
    request.trace_id = Some("rust-install-example".to_owned());
    let artifact = request_connect_artifact(request).await?;
    let client = Arc::new(
        connect(
            artifact,
            ConnectOptions {
                origin: Some(
                    std::env::var("FSEC_ORIGIN")
                        .unwrap_or_else(|_| "http://127.0.0.1:5173".to_owned()),
                ),
                transport_security_policy:
                    TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..ConnectOptions::default()
            },
        )
        .await?,
    );

    let response: PingResponse = client.rpc().call_typed(1, &PingRequest {}).await?;
    if !response.ok {
        return Err("RPC ping was not acknowledged".into());
    }

    let stream = client.open_stream("echo").await?;
    stream.write(b"flowersec-rust-example").await?;
    let echoed = stream.read_exact(22).await?;
    println!("stream={}", String::from_utf8_lossy(&echoed));
    stream.close().await?;
    client.probe_liveness(Duration::from_secs(2)).await?;

    let proxy = ProxyClient::new(client.clone(), ContractOptions::default())?;
    let response = proxy.request(HttpRequest::get("/http")).await?;
    println!("http_status={} body={}", response.status, String::from_utf8_lossy(&response.body));
    let websocket = proxy.open_websocket("/ws", Vec::new()).await?;
    websocket
        .send(WebSocketFrame {
            op: WebSocketOp::Text,
            payload: b"flowersec-rust-example".to_vec(),
        })
        .await?;
    println!("websocket={:?}", websocket.receive().await?);
    websocket.close(Some(1000), "done").await?;
    client.close().await?;
    Ok(())
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name)
        .map_err(|_| format!("{name} is required").into())
}
