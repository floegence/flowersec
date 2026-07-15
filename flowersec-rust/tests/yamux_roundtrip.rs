use async_trait::async_trait;
use flowersec::yamux::{ByteDuplex, Mode, YamuxError, YamuxLimits, YamuxSession};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc};

#[tokio::test]
async fn yamux_streams_and_acknowledged_ping_round_trip() {
    let (client_connection, server_connection) = duplex_pair();
    let client = YamuxSession::new(client_connection, Mode::Client, YamuxLimits::default())
        .expect("client session");
    let server = YamuxSession::new(server_connection, Mode::Server, YamuxLimits::default())
        .expect("server session");

    let client_stream = client.open_stream().await.expect("open client stream");
    let server_stream = tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
        .await
        .expect("accept timeout")
        .expect("accept stream");
    assert_eq!(client_stream.id(), server_stream.id());
    assert_eq!(client_stream.id() % 2, 1);

    let payload = vec![0x5a; 700_000];
    let server_read = {
        let server_stream = server_stream.clone();
        tokio::spawn(async move {
            let mut received = Vec::new();
            while received.len() < payload.len() {
                received.extend(server_stream.read().await.expect("read").expect("data"));
            }
            received
        })
    };
    client_stream
        .write(&vec![0x5a; 700_000])
        .await
        .expect("large write");
    assert_eq!(
        server_read.await.expect("server reader"),
        vec![0x5a; 700_000]
    );

    server_stream.write(b"reply").await.expect("server write");
    assert_eq!(
        client_stream.read().await.expect("client read"),
        Some(b"reply".to_vec())
    );

    let rtt = client
        .probe_liveness(Duration::from_secs(1))
        .await
        .expect("ping");
    assert!(rtt < Duration::from_secs(1));

    client_stream.close().await.expect("client close");
    assert_eq!(server_stream.read().await.expect("server eof"), None);
    server_stream.close().await.expect("server close");
    client.close().await.expect("client session close");
    server.close().await.expect("server session close");
}

#[derive(Debug)]
struct MemoryDuplex {
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

#[async_trait]
impl ByteDuplex for MemoryDuplex {
    async fn read(&self) -> Result<Vec<u8>, YamuxError> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(YamuxError::Closed)
    }

    async fn write(&self, bytes: &[u8]) -> Result<(), YamuxError> {
        self.outgoing
            .send(bytes.to_vec())
            .await
            .map_err(|_| YamuxError::Closed)
    }

    async fn close(&self) -> Result<(), YamuxError> {
        Ok(())
    }
}

fn duplex_pair() -> (Arc<MemoryDuplex>, Arc<MemoryDuplex>) {
    let (client_tx, server_rx) = mpsc::channel(64);
    let (server_tx, client_rx) = mpsc::channel(64);
    (
        Arc::new(MemoryDuplex {
            incoming: Mutex::new(client_rx),
            outgoing: client_tx,
        }),
        Arc::new(MemoryDuplex {
            incoming: Mutex::new(server_rx),
            outgoing: server_tx,
        }),
    )
}
