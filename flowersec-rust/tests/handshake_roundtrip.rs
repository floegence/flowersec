use async_trait::async_trait;
use flowersec::{
    e2ee::{
        ClientHandshakeOptions, Secret32, ServerHandshakeCache, ServerHandshakeOptions, Suite,
        client_handshake, server_handshake,
    },
    transport::{WebSocketMessage, WebSocketTransport},
};
use std::{
    io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, mpsc};

#[tokio::test]
async fn client_and_server_handshake_round_trip_both_suites() {
    for suite in [
        Suite::X25519HkdfSha256Aes256Gcm,
        Suite::P256HkdfSha256Aes256Gcm,
    ] {
        let (client_transport, server_transport) = transport_pair();
        let psk = [0x42_u8; 32];
        let cache = Arc::new(ServerHandshakeCache::default());
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs() as i64
            + 60;

        let server = {
            let cache = cache.clone();
            tokio::spawn(async move {
                let mut options = ServerHandshakeOptions::new(Secret32::new(psk), suite, expires);
                options.channel_id = Some("channel-rust-test".to_owned());
                server_handshake(server_transport, &cache, options)
                    .await
                    .expect("server handshake")
            })
        };

        let client = client_handshake(
            client_transport,
            ClientHandshakeOptions::new(Secret32::new(psk), suite, "channel-rust-test"),
        )
        .await
        .expect("client handshake");
        let server = server.await.expect("server task");

        client
            .write(b"hello from client")
            .await
            .expect("client write");
        assert_eq!(
            server.read().await.expect("server read"),
            b"hello from client"
        );

        server.rekey().await.expect("server rekey");
        server.ping().await.expect("server ping");
        server
            .write(b"hello from server")
            .await
            .expect("server write");
        assert_eq!(
            client.read().await.expect("client read"),
            b"hello from server"
        );
    }
}

#[derive(Debug)]
struct MemoryTransport {
    incoming: Mutex<mpsc::Receiver<WebSocketMessage>>,
    outgoing: mpsc::Sender<WebSocketMessage>,
}

#[async_trait]
impl WebSocketTransport for MemoryTransport {
    async fn receive(&self) -> io::Result<Option<WebSocketMessage>> {
        Ok(self.incoming.lock().await.recv().await)
    }

    async fn send(&self, message: WebSocketMessage) -> io::Result<()> {
        self.outgoing
            .send(message)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer closed"))
    }

    async fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

fn transport_pair() -> (Arc<MemoryTransport>, Arc<MemoryTransport>) {
    let (client_tx, server_rx) = mpsc::channel(32);
    let (server_tx, client_rx) = mpsc::channel(32);
    (
        Arc::new(MemoryTransport {
            incoming: Mutex::new(client_rx),
            outgoing: client_tx,
        }),
        Arc::new(MemoryTransport {
            incoming: Mutex::new(server_rx),
            outgoing: server_tx,
        }),
    )
}
