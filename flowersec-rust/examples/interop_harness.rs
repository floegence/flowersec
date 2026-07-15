use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    e2ee::{Secret32, ServerHandshakeOptions, Suite},
    endpoint::{DirectAcceptOptions, EndpointOptions, Session, accept_direct, connect_tunnel},
    generated::flowersec::controlplane::v1::ChannelInitGrant,
    generated::flowersec::direct::v1::{DirectConnectInfo, Suite as DirectSuite},
    proxy::{ContractOptions, HTTP1_KIND, ProxyServer, ServerOptions, WEBSOCKET_KIND},
    rpc::{Router, Server as RpcServer},
    streamhello,
    transport::TungsteniteTransport,
    transport_security::TransportSecurityPolicy,
};
use futures_util::{SinkExt as _, StreamExt as _};
use rand::{RngCore as _, rngs::OsRng};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    io::{self, Write as _},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::tungstenite::Message;

#[derive(Serialize)]
struct Ready {
    v: u32,
    event: &'static str,
    direct_info: DirectConnectInfo,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_address = start_http_upstream().await?;
    let websocket_address = start_websocket_upstream().await?;
    let mut arguments = std::env::args().skip(1);
    if let Some(argument) = arguments.next() {
        if argument != "--tunnel-grant-json" {
            return Err(format!("unknown argument: {argument}").into());
        }
        let grant: ChannelInitGrant = serde_json::from_str(
            &arguments
                .next()
                .ok_or("--tunnel-grant-json requires a JSON value")?,
        )?;
        println!("{}", json!({ "v": 1, "event": "attaching" }));
        io::stdout().flush()?;
        let session = connect_tunnel(
            grant,
            EndpointOptions {
                origin: Some("https://app.redeven.com".to_owned()),
                transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
                ..EndpointOptions::default()
            },
        )
        .await?;
        serve_session(session, http_address, websocket_address).await?;
        return Ok(());
    }
    let direct_listener = TcpListener::bind("127.0.0.1:0").await?;
    let direct_address = direct_listener.local_addr()?;
    let mut psk = [0_u8; 32];
    OsRng.fill_bytes(&mut psk);
    let expires = unix_now() + 300;

    tokio::spawn(async move {
        while let Ok((tcp, _)) = direct_listener.accept().await {
            tokio::spawn(serve_direct(
                tcp,
                psk,
                expires,
                http_address,
                websocket_address,
            ));
        }
    });

    serde_json::to_writer(
        io::stdout(),
        &Ready {
            v: 1,
            event: "ready",
            direct_info: DirectConnectInfo {
                ws_url: format!("ws://{direct_address}/flowersec"),
                channel_id: "rust-interop-endpoint".to_owned(),
                e2ee_psk_b64u: URL_SAFE_NO_PAD.encode(psk),
                channel_init_expire_at_unix_s: expires,
                default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
            },
        },
    )?;
    println!();
    io::stdout().flush()?;
    std::future::pending::<()>().await;
    Ok(())
}

async fn serve_direct(
    tcp: TcpStream,
    psk: [u8; 32],
    expires: i64,
    http_address: std::net::SocketAddr,
    websocket_address: std::net::SocketAddr,
) {
    let result = async {
        let websocket = tokio_tungstenite::accept_async(tcp).await?;
        let mut handshake = ServerHandshakeOptions::new(
            Secret32::new(psk),
            Suite::X25519HkdfSha256Aes256Gcm,
            expires,
        );
        handshake.channel_id = Some("rust-interop-endpoint".to_owned());
        let session = accept_direct(
            Arc::new(TungsteniteTransport::new(websocket)),
            DirectAcceptOptions::new(handshake),
        )
        .await?;
        serve_session(session, http_address, websocket_address).await
    }
    .await;
    if let Err(error) = result {
        eprintln!("Rust interop session failed: {error}");
    }
}

async fn serve_session(
    session: Session,
    http_address: std::net::SocketAddr,
    websocket_address: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let (kind, rpc_stream) = session.accept_stream().await?;
    if kind != streamhello::RPC_KIND {
        return Err("first stream is not RPC".into());
    }
    let router = Router::default();
    let rpc = Arc::new(RpcServer::new(router.clone()));
    router
        .register(1, {
            let rpc = Arc::downgrade(&rpc);
            move |_: Value| {
                let rpc = rpc.clone();
                async move {
                    if let Some(rpc) = rpc.upgrade() {
                        rpc.notify_typed(2, &json!({ "hello": "world" }))
                            .await
                            .map_err(|error| {
                                flowersec::generated::flowersec::rpc::v1::RpcError {
                                    code: 500,
                                    message: Some(error.to_string()),
                                }
                            })?;
                    }
                    Ok(json!({ "ok": true }))
                }
            }
        })
        .await;
    let rpc_task = tokio::spawn(rpc.serve(rpc_stream));
    let http_proxy = ProxyServer::new(ServerOptions {
        upstream: format!("http://{http_address}"),
        upstream_origin: format!("http://{http_address}"),
        allowed_upstream_hosts: Vec::new(),
        contract: ContractOptions::default(),
        default_timeout: None,
        max_timeout: None,
    })?;
    let websocket_proxy = ProxyServer::new(ServerOptions {
        upstream: format!("http://{websocket_address}"),
        upstream_origin: "http://127.0.0.1:5173".to_owned(),
        allowed_upstream_hosts: Vec::new(),
        contract: ContractOptions::default(),
        default_timeout: None,
        max_timeout: None,
    })?;

    loop {
        let (kind, stream) = match session.accept_stream().await {
            Ok(accepted) => accepted,
            Err(_) => {
                rpc_task.abort();
                return Ok(());
            }
        };
        match kind.as_str() {
            "echo" => {
                tokio::spawn(async move {
                    while let Ok(Some(payload)) = stream.read().await {
                        if stream.write(&payload).await.is_err() {
                            return;
                        }
                    }
                    let _ = stream.close().await;
                });
            }
            HTTP1_KIND => {
                let proxy = http_proxy.clone();
                tokio::spawn(async move {
                    let _ = proxy.serve_stream(HTTP1_KIND, stream).await;
                });
            }
            WEBSOCKET_KIND => {
                let proxy = websocket_proxy.clone();
                tokio::spawn(async move {
                    let _ = proxy.serve_stream(WEBSOCKET_KIND, stream).await;
                });
            }
            _ => {
                let _ = stream.reset().await;
            }
        }
    }
}

async fn start_http_upstream() -> io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while let Ok(read) = socket.read(&mut chunk).await {
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nConnection: close\r\n\r\nflowersec-rust-proxy-ok";
                let _ = socket.write_all(response).await;
            });
        }
    });
    Ok(address)
}

async fn start_websocket_upstream() -> io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut websocket) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                while let Some(Ok(message)) = websocket.next().await {
                    match message {
                        Message::Text(text) => {
                            let _ = websocket.send(Message::Text(text)).await;
                        }
                        Message::Binary(payload) => {
                            let _ = websocket.send(Message::Binary(payload)).await;
                        }
                        Message::Ping(payload) => {
                            let _ = websocket.send(Message::Pong(payload)).await;
                        }
                        Message::Close(frame) => {
                            let _ = websocket.send(Message::Close(frame)).await;
                            return;
                        }
                        Message::Pong(_) | Message::Frame(_) => {}
                    }
                }
            });
        }
    });
    Ok(address)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64
}
